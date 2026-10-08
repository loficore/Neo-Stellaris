// predicate_hook.zig — C2 detour on donor predicate functions.
//
// The engine calls [vptr+0x98] (effect) or [vptr+0x80] (trigger) after writing
// {token_id, name} into the object. We detour these predicate functions to:
//   1. Read token_id from the object
//   2. Check if it's one of our registered keywords
//   3. If yes, patch [obj+0] (vtable pointer) to our custom vtable
//   4. Call the original predicate
//
// After the patch, subsequent virtual calls go through our custom vtable.
// The predicate itself is called only once per object instantiation, so the
// detour overhead is minimal.
//
// Target RVAs (from offsets.zig):
//   Effect predicate:  0x3B1420 (base impl at [vptr+0x98])
//   Trigger predicate: 0x349230 (base impl at [vptr+0x80])

const std = @import("std");
const builtin = @import("builtin");
const detour_mod = @import("../hooking/detour.zig");
const windows = @import("../hooking/windows.zig");
const handler = @import("handler.zig");
const vtable = @import("vtable.zig");
const offsets = @import("../shared/offsets.zig");

const is_windows = builtin.os.tag == .windows;

// ---------------------------------------------------------------------------
// Target RVAs
// ---------------------------------------------------------------------------

// Effect predicate: base impl called from [vptr+0x98].
// From offsets.zig: DONOR_EFFECT_VTABLE covers +0x98 = 0x3B1420.
const RVA_EFFECT_PREDICATE: usize = 0x3B1420;

// Trigger predicate: base impl called from [vptr+0x80].
// From offsets.zig: DONOR_TRIGGER_VTABLE covers +0x80 = 0x349230.
const RVA_TRIGGER_PREDICATE: usize = 0x349230;

// ---------------------------------------------------------------------------
// Detour state
// ---------------------------------------------------------------------------

const PredFn = *const fn (self: u64) callconv(.c) bool;

var orig_effect_pred: ?*anyopaque = null;
var orig_trigger_pred: ?*anyopaque = null;
var effect_hook: ?detour_mod.Hook = null;
var trigger_hook: ?detour_mod.Hook = null;
var effect_installed: bool = false;
var trigger_installed: bool = false;

// ---------------------------------------------------------------------------
// Safe memory access
// ---------------------------------------------------------------------------

fn plausible(p: usize) bool {
    return p >= 0x10000 and p <= 0x00007FFF_FFFF_0000 and (p & 7) == 0;
}

fn readU32(addr: usize, comptime off: usize) u32 {
    if (!plausible(addr)) return 0;
    const base: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u32, base[off..][0..4], .little);
}

fn writeU64(addr: usize, val: u64) void {
    if (!plausible(addr)) return;
    const dst: *u64 = @ptrFromInt(addr);
    dst.* = val;
}

// ---------------------------------------------------------------------------
// Detour functions
// ---------------------------------------------------------------------------

/// Effect predicate detour. Called by engine at [vptr+0x98] after writing token_id.
fn neoEffectPredicate(self: u64) callconv(.c) bool {
    // Read token_id from [self + 0x20].
    const token_id = readU32(self, offsets.keyword_reg.EFFECT_OBJECT_TOKEN_ID);

    // Check if this is one of our registered keywords.
    if (token_id != 0) {
        if (handler.findHandler(token_id)) |h| {
            if (h.kind == .effect) {
                // Patch vtable pointer at [self + 0] to our custom effect vtable.
                if (vtable.getEffectVtablePtr()) |vtbl_ptr| {
                    writeU64(self, @intFromPtr(vtbl_ptr));
                }
            }
        }
    }

    // Call original predicate.
    const orig: PredFn = @ptrCast(orig_effect_pred orelse return true);
    return orig(self);
}

/// Trigger predicate detour. Called by engine at [vptr+0x80] after writing token_id.
fn neoTriggerPredicate(self: u64) callconv(.c) bool {
    // Read token_id from [self + 0x38].
    const token_id = readU32(self, offsets.keyword_reg.TRIGGER_OBJECT_TOKEN_ID);

    // Check if this is one of our registered keywords.
    if (token_id != 0) {
        if (handler.findHandler(token_id)) |h| {
            if (h.kind == .trigger) {
                // Patch vtable pointer at [self + 0] to our custom trigger vtable.
                if (vtable.getTriggerVtablePtr()) |vtbl_ptr| {
                    writeU64(self, @intFromPtr(vtbl_ptr));
                }
            }
        }
    }

    // Call original predicate.
    const orig: PredFn = @ptrCast(orig_trigger_pred orelse return true);
    return orig(self);
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

pub const State = struct {
    effect_installed: bool = false,
    trigger_installed: bool = false,
};

pub fn isInstalled() State {
    return .{
        .effect_installed = effect_installed,
        .trigger_installed = trigger_installed,
    };
}

/// Install detours on both effect and trigger predicate functions.
/// Must be called after vtable.buildVtables() and handler.setContext().
pub fn install() !void {
    if (!is_windows) return;

    // Install effect predicate detour.
    if (!effect_installed) {
        const effect_target = try windows.moduleFunction(RVA_EFFECT_PREDICATE);
        if (!detour_mod.isHooked(effect_target)) {
            const hook = try detour_mod.installHookArmed(effect_target, @ptrCast(@constCast(&neoEffectPredicate)), &orig_effect_pred);
            effect_hook = hook;
            effect_installed = true;
            std.log.info("c2.predicate_hook: installed effect predicate detour at 0x{x}", .{RVA_EFFECT_PREDICATE});
        }
    }

    // Install trigger predicate detour.
    if (!trigger_installed) {
        const trigger_target = try windows.moduleFunction(RVA_TRIGGER_PREDICATE);
        if (!detour_mod.isHooked(trigger_target)) {
            const hook = try detour_mod.installHookArmed(trigger_target, @ptrCast(@constCast(&neoTriggerPredicate)), &orig_trigger_pred);
            trigger_hook = hook;
            trigger_installed = true;
            std.log.info("c2.predicate_hook: installed trigger predicate detour at 0x{x}", .{RVA_TRIGGER_PREDICATE});
        }
    }
}

/// Remove detours. Only safe while no game thread is inside the predicate functions.
pub fn uninstall() !void {
    if (effect_hook) |h| {
        detour_mod.removeHook(&h) catch {};
        effect_hook = null;
        effect_installed = false;
        orig_effect_pred = null;
        std.log.info("c2.predicate_hook: uninstalled effect predicate detour", .{});
    }

    if (trigger_hook) |h| {
        detour_mod.removeHook(&h) catch {};
        trigger_hook = null;
        trigger_installed = false;
        orig_trigger_pred = null;
        std.log.info("c2.predicate_hook: uninstalled trigger predicate detour", .{});
    }
}

// ---------------------------------------------------------------------------
// Exported entry points (injector-facing)
// ---------------------------------------------------------------------------

export fn C2PredicateHookInstall() callconv(.c) i32 {
    if (!is_windows) return -2;
    install() catch |err| return switch (err) {
        else => -1,
    };
    return 0;
}

export fn C2PredicateHookUninstall() callconv(.c) i32 {
    if (!is_windows) return -2;
    uninstall() catch return -1;
    return 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "predicate RVAs are in .text" {
    const text_end: usize = 0x2392000;
    try std.testing.expect(RVA_EFFECT_PREDICATE < text_end);
    try std.testing.expect(RVA_TRIGGER_PREDICATE < text_end);
}

test "plausible rejects bad pointers" {
    try std.testing.expect(!plausible(0));
    try std.testing.expect(!plausible(0x1234));
    try std.testing.expect(!plausible(0xffff_8000_0000_0000));
}

test "readU32 returns 0 for bad address" {
    try std.testing.expectEqual(@as(u32, 0), readU32(0, 0));
}

test "State initially not installed" {
    const state = isInstalled();
    try std.testing.expect(!state.effect_installed);
    try std.testing.expect(!state.trigger_installed);
}
