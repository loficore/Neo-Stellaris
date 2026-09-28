// lookup_hook.zig — Stage-1 detour of the 4.4.4 scripted effect/trigger lookups.
//
// Live-verified targets (Stellaris 4.4.4, Frida at base 0x7ff74a630000):
//   RVA 0x89F960 — GetScriptedEffect
//   RVA 0x8A0450 — GetScriptedTrigger
// Both prologues contain no RIP-relative instruction inside the first 14
// bytes, so detour.installHook's copy-based trampoline is safe unmodified.
//
// Calling convention (from prologue + sentinel caller at RVA 0x1D7CE0):
//   rcx = out   — hidden MSVC x64 sret pointer to the ref object (see ScriptedRef)
//   edx = id    — int32 requested id (-1 for name-based lookups)
//   r8  = name  — pointer to an MSVC std::wstring (SSO when capacity < 0x10)
// The callee fills `out` with { vtable +0x00, id +0x08, wstrings +0x10/+0x28
// /+0x40 }. A miss overwrites +0x00/+0x40 with "null template" vtables (see
// 0x1D7CE0), so hit/miss is judged from `out`, not a return flag.
//
// A Zig `callconv(.c)` fn on Windows x64 receives rcx/rdx/r8 as its first
// three integer args, so the detour needs no asm stub: record the request,
// forward to the trampoline, record what the original filled.
//
// STAGE 1 = forward-and-log only. Stage 2 will replace null-template results
// with registry-provided templates. Install/remove only via explicit injector
// command (never DllMain), while the game thread is not mid-lookup.

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const detour_mod = @import("../hooking/detour.zig");
const windows = @import("../hooking/windows.zig");

const is_windows = builtin.os.tag == .windows;

// ---------------------------------------------------------------------------
// Object layouts (verified 4.4.4)
// ---------------------------------------------------------------------------

/// MSVC std::wstring: 16-byte inline buffer (aliasing the heap-pointer slot),
/// +0x10 size, +0x18 capacity. SSO while capacity < 0x10.
pub const WString = extern struct {
    data: [16]u8 = [_]u8{0} ** 16,
    size: usize = 0,
    capacity: usize = 0,

    /// UTF-16 view, length-clamped to `max`. Returns empty for implausible
    /// sizes so a corrupt pointer cannot make us read arbitrarily far.
    pub fn view(self: *const WString, max: usize) []const u16 {
        const len = self.size;
        if (len > max) return &[_]u16{};
        const ptr: [*]const u16 = if (self.capacity < 0x10)
            @ptrCast(&self.data)
        else blk: {
            const heap = std.mem.readInt(usize, self.data[0..8], .little);
            if (heap == 0) return &[_]u16{};
            break :blk @as([*]const u16, @ptrFromInt(heap));
        };
        return ptr[0..len];
    }
};

comptime {
    if (@sizeOf(WString) != 32) @compileError("WString must be 32 bytes");
    if (@offsetOf(WString, "size") != 0x10) @compileError("WString.size must sit at +0x10");
}

/// The ref object GetScripted* fills through its sret pointer.
/// Verified field positions: vtable +0x00, id +0x08, template-name wstring
/// +0x40 (size +0x50, capacity +0x58 — matches the miss-path init writing
/// cap 0xf there). The +0x10..+0x40 region holds a second key-like object
/// whose internal layout is not yet pinned; treated as opaque.
pub const ScriptedRef = extern struct {
    vtable: usize = 0,
    id: i32 = 0,
    pad0: u32 = 0,
    opaque_10: [0x30]u8 = [_]u8{0} ** 0x30,
    name: WString = .{},
};

comptime {
    if (@offsetOf(ScriptedRef, "name") != 0x40) @compileError("name must sit at +0x40");
}

// ---------------------------------------------------------------------------
// Recording ring
// ---------------------------------------------------------------------------

pub const KIND_EFFECT: u8 = 1;
pub const KIND_TRIGGER: u8 = 2;
pub const RING_LEN: usize = 512;
const NAME_MAX: usize = 56;

/// One lookup record. `filled` flips to 1 (release) only after the original
// function has run, so a drain never reads a half-populated record.
pub const Entry = extern struct {
    kind: u8 = 0,
    filled: u8 = 0,
    req_len: u16 = 0,
    out_len: u16 = 0,
    pad: u16 = 0,
    req_id: i32 = 0,
    out_id: i32 = 0,
    out_vtable: usize = 0,
    req_name: [NAME_MAX]u16 = [_]u16{0} ** NAME_MAX,
    out_name: [NAME_MAX]u16 = [_]u16{0} ** NAME_MAX,

    pub fn reqName(self: *const Entry) []const u16 {
        return self.req_name[0..self.req_len];
    }

    pub fn outName(self: *const Entry) []const u16 {
        return self.out_name[0..self.out_len];
    }
};

var ring: [RING_LEN]Entry = undefined;
var seq = std.atomic.Value(u32).init(0);

/// Write the request half of a record; returns the ring slot index.
fn recordRequest(kind: u8, id: i32, name: []const u16) usize {
    const idx = seq.fetchAdd(1, .monotonic) % RING_LEN;
    const e = &ring[idx];
    filledPtr(e).* = 0;
    e.kind = kind;
    e.req_id = id;
    e.out_id = 0;
    e.out_vtable = 0;
    const n = @min(name.len, NAME_MAX);
    @memcpy(e.req_name[0..n], name[0..n]);
    e.req_len = @intCast(n);
    e.out_len = 0;
    return idx;
}

/// Write the result half after the original ran.
fn recordResult(idx: usize, out: *const ScriptedRef) void {
    const e = &ring[idx % RING_LEN];
    e.out_vtable = out.vtable;
    e.out_id = out.id;
    const name = out.name.view(NAME_MAX);
    const n = @min(name.len, NAME_MAX);
    @memcpy(e.out_name[0..n], name[0..n]);
    e.out_len = @intCast(n);
    _ = @atomicRmw(u8, &e.filled, .Xchg, 1, .release);
}

fn filledPtr(e: *const Entry) *volatile u8 {
    return @constCast(@ptrCast(&e.filled));
}

// ---------------------------------------------------------------------------
// Detours
// ---------------------------------------------------------------------------

const OrigFn = *const fn (out: *ScriptedRef, id: i32, name: *const WString) callconv(.c) void;

var orig_effect: ?OrigFn = null;
var orig_trigger: ?OrigFn = null;

fn forward(out: *ScriptedRef, id: i32, name: *const WString, kind: u8, orig: ?OrigFn) void {
    const f = orig orelse return;
    const idx = recordRequest(kind, id, name.view(NAME_MAX));
    f(out, id, name);
    recordResult(idx, out);
}

pub fn effectDetour(out: *ScriptedRef, id: i32, name: *const WString) callconv(.c) void {
    forward(out, id, name, KIND_EFFECT, orig_effect);
}

pub fn triggerDetour(out: *ScriptedRef, id: i32, name: *const WString) callconv(.c) void {
    forward(out, id, name, KIND_TRIGGER, orig_trigger);
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

pub const State = struct {
    effect_hook: ?detour_mod.Hook = null,
    trigger_hook: ?detour_mod.Hook = null,
    installed: bool = false,
};

var state = State{};

pub fn isInstalled() bool {
    return state.installed;
}

/// Install both lookup detours. Call only from an explicit injector command
/// against a confirmed 4.4.4 build; RVAs differ across game versions.
pub fn install() !void {
    if (state.installed) return;

    const eff_target = try windows.moduleFunction(offsets.scripted_db.RVA_GET_SCRIPTED_EFFECT);
    const trig_target = try windows.moduleFunction(offsets.scripted_db.RVA_GET_SCRIPTED_TRIGGER);
    if (detour_mod.isHooked(eff_target) or detour_mod.isHooked(trig_target)) return error.AlreadyHooked;

    const h1 = try detour_mod.installHook(eff_target, @constCast(@ptrCast(&effectDetour)));
    orig_effect = @ptrCast(h1.trampoline);
    const h2 = detour_mod.installHook(trig_target, @constCast(@ptrCast(&triggerDetour))) catch |err| {
        try detour_mod.removeHook(&h1);
        orig_effect = null;
        return err;
    };
    orig_trigger = @ptrCast(h2.trampoline);

    state = .{ .effect_hook = h1, .trigger_hook = h2, .installed = true };
}

/// Remove both detours. Only safe while no game thread is inside a lookup.
pub fn uninstall() void {
    if (state.effect_hook) |h| {
        detour_mod.removeHook(&h) catch {};
        orig_effect = null;
    }
    if (state.trigger_hook) |h| {
        detour_mod.removeHook(&h) catch {};
        orig_trigger = null;
    }
    state = .{};
}

// ---------------------------------------------------------------------------
// Exported entry points (injector-facing)
// ---------------------------------------------------------------------------

export fn LookupHookInstall() callconv(.c) i32 {
    if (!is_windows) return -2;
    install() catch return -1;
    return 0;
}

export fn LookupHookUninstall() callconv(.c) i32 {
    if (!is_windows) return -2;
    uninstall();
    return 0;
}

/// Copy up to `max` completed records into `buf` (Entry-sized slots) and
/// reset the ring. Returns the number of records copied.
export fn LookupHookDrain(buf: [*]Entry, max: u32) callconv(.c) u32 {
    const total = seq.load(.monotonic);
    var copied: u32 = 0;
    var i: u32 = 0;
    while (i < total and copied < max) : (i += 1) {
        const idx = i % RING_LEN;
        const e = &ring[idx];
        if (filledPtr(e).* == 1) {
            buf[copied] = e.*;
            copied += 1;
        }
    }
    seq.store(0, .monotonic);
    return copied;
}

// ---------------------------------------------------------------------------
// Tests (layout + recorder logic; install path is Windows-runtime only)
// ---------------------------------------------------------------------------

test "ScriptedRef layout" {
    try std.testing.expectEqual(@as(usize, 0x00), @offsetOf(ScriptedRef, "vtable"));
    try std.testing.expectEqual(@as(usize, 0x08), @offsetOf(ScriptedRef, "id"));
    try std.testing.expectEqual(@as(usize, 0x40), @offsetOf(ScriptedRef, "name"));
}

test "WString SSO view" {
    var w = WString{};
    const s = [_]u16{ 'a', 'b', 'c' };
    @memcpy(w.data[0..6], std.mem.asBytes(&s));
    w.size = 3;
    w.capacity = 15;
    const got = try std.unicode.utf16LeToUtf8Alloc(std.testing.allocator, w.view(56));
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("abc", got);
}

test "WString heap view guard" {
    var w = WString{};
    w.capacity = 0x17;
    w.size = 0x7fffffff; // implausible → view must clamp to empty
    try std.testing.expectEqual(@as(usize, 0), w.view(56).len);
}

test "record round trip" {
    seq.store(0, .monotonic);
    var out = ScriptedRef{};
    out.vtable = 0x1122334455;
    out.id = 77;
    const nm = [_]u16{ 'x', 'y' };
    const idx = recordRequest(KIND_EFFECT, -1, &nm);
    recordResult(idx, &out);
    var buf: [4]Entry = undefined;
    const n = LookupHookDrain(&buf, 4);
    try std.testing.expectEqual(@as(u32, 1), n);
    try std.testing.expectEqual(KIND_EFFECT, buf[0].kind);
    try std.testing.expectEqual(@as(i32, -1), buf[0].req_id);
    try std.testing.expectEqual(@as(i32, 77), buf[0].out_id);
    try std.testing.expectEqual(@as(usize, 0x1122334455), buf[0].out_vtable);
    const got = try std.unicode.utf16LeToUtf8Alloc(std.testing.allocator, buf[0].reqName());
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("xy", got);
}
