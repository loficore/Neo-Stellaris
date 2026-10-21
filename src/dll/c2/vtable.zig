// vtable.zig — C2 custom vtable construction.
//
// Builds DLL-owned vtables that redirect ExecuteActual to JS dispatch.
// The engine instantiates objects via donor create() and writes {token_id, name}
// into them. Before the first virtual call, predicate_hook.zig patches [obj+0]
// to point at our custom vtable. From then on, ExecuteActual routes through
// handler.zig's dispatch functions.
//
// Vtable layout (from offsets.zig):
//   Effect:  25 slots through +0x98 (200 bytes)
//   Trigger: 17 slots through +0x80 (136 bytes)
//
// We copy ALL slots from the donor vtable, then override:
//   +0x10 (ExecuteActual): JS dispatch bridge
//   +0x98 / +0x80 (predicate): passthrough (vtable already patched)

const std = @import("std");
const handler = @import("handler.zig");
const offsets = @import("../shared/offsets.zig");

// ---------------------------------------------------------------------------
// Vtable slot counts
// ---------------------------------------------------------------------------

// Effect vtable: through +0x98 = 25 slots (0x98 / 8 + 1)
const EFFECT_VTBL_SLOTS: usize = 25;

// Trigger vtable: through +0x80 = 17 slots (0x80 / 8 + 1)
const TRIGGER_VTBL_SLOTS: usize = 17;

// ---------------------------------------------------------------------------
// Custom vtables (DLL .bss, function pointers only)
// ---------------------------------------------------------------------------

var effect_vtable: [EFFECT_VTBL_SLOTS]u64 align(16) = undefined;
var trigger_vtable: [TRIGGER_VTBL_SLOTS]u64 align(16) = undefined;
var vtables_initialized: bool = false;

// ---------------------------------------------------------------------------
// Custom ExecuteActual implementations
// ---------------------------------------------------------------------------

/// Effect ExecuteActual: called by base Execute (0x1D08520) via call [rax+0x10].
/// Args: self (CEffect*), scope (CEventScope*), a3, a4 (unused).
/// Returns void (u64 for ABI compatibility).
fn neoEffectExecuteActual(self: u64, scope: u64, a3: u64, a4: u64) callconv(.c) u64 {
    _ = a3;
    _ = a4;

    // Read token_id from [self + 0x20] (written by engine before Execute).
    const token_id = readU32(self, offsets.keyword_reg.EFFECT_OBJECT_TOKEN_ID);
    if (token_id == 0) {
        std.log.warn("c2.vtable: effect ExecuteActual with token_id=0", .{});
        return 0;
    }

    handler.dispatchEffect(token_id, scope);
    return 0;
}

/// Trigger ExecuteActual: called by base Execute via call [rax+0x10].
/// Returns bool in al (u64 for ABI compatibility).
fn neoTriggerExecuteActual(self: u64, scope: u64, a3: u64, a4: u64) callconv(.c) u64 {
    _ = a3;
    _ = a4;

    // Read token_id from [self + 0x38] (written by engine before Execute).
    const token_id = readU32(self, offsets.keyword_reg.TRIGGER_OBJECT_TOKEN_ID);
    if (token_id == 0) {
        std.log.warn("c2.vtable: trigger ExecuteActual with token_id=0", .{});
        return 0;
    }

    const result = handler.dispatchTrigger(token_id, scope);
    return @intFromBool(result);
}

/// Effect predicate passthrough: called after vtable is patched.
/// Just returns true (donor predicate semantics for hidden_effect).
fn neoEffectPredicatePassthrough(self: u64) callconv(.c) bool {
    _ = self;
    return true;
}

/// Trigger predicate passthrough: called after vtable is patched.
/// Returns true (donor predicate semantics for has_crisis_perk).
fn neoTriggerPredicatePassthrough(self: u64) callconv(.c) bool {
    _ = self;
    return true;
}

// ---------------------------------------------------------------------------
// Safe memory reads
// ---------------------------------------------------------------------------

fn plausible(p: usize) bool {
    return p >= 0x10000 and p <= 0x00007FFF_FFFF_0000 and (p & 7) == 0;
}

fn readU32(addr: usize, comptime off: usize) u32 {
    if (!plausible(addr)) return 0;
    const base: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u32, base[off..][0..4], .little);
}

fn readU64(addr: usize) ?u64 {
    if (!plausible(addr)) return null;
    return @as(*align(8) const u64, @ptrFromInt(addr)).*;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build custom vtables from donor vtables in engine memory.
/// Must be called once before any predicate hook fires.
pub fn buildVtables(game_base: usize) void {
    if (vtables_initialized) return;

    // Read donor effect vtable from engine .rdata.
    const donor_effect_vtbl_addr = game_base + offsets.keyword_reg.DONOR_EFFECT_VTABLE;
    if (readU64(donor_effect_vtbl_addr)) |first_slot| {
        _ = first_slot;
        const donor_effect_vtbl: [*]const u64 = @ptrFromInt(donor_effect_vtbl_addr);
        @memcpy(&effect_vtable, donor_effect_vtbl[0..EFFECT_VTBL_SLOTS]);
    } else {
        std.log.err("c2.vtable: cannot read donor effect vtable at 0x{x}", .{donor_effect_vtbl_addr});
        return;
    }

    // Override ExecuteActual (+0x10) and predicate (+0x98).
    effect_vtable[0x10 / 8] = @intFromPtr(&neoEffectExecuteActual);
    effect_vtable[0x98 / 8] = @intFromPtr(&neoEffectPredicatePassthrough);

    // Read donor trigger vtable from engine .rdata.
    const donor_trigger_vtbl_addr = game_base + offsets.keyword_reg.DONOR_TRIGGER_VTABLE;
    if (readU64(donor_trigger_vtbl_addr)) |first_slot| {
        _ = first_slot;
        const donor_trigger_vtbl: [*]const u64 = @ptrFromInt(donor_trigger_vtbl_addr);
        @memcpy(&trigger_vtable, donor_trigger_vtbl[0..TRIGGER_VTBL_SLOTS]);
    } else {
        std.log.err("c2.vtable: cannot read donor trigger vtable at 0x{x}", .{donor_trigger_vtbl_addr});
        return;
    }

    // Override ExecuteActual (+0x10) and predicate (+0x80).
    trigger_vtable[0x10 / 8] = @intFromPtr(&neoTriggerExecuteActual);
    trigger_vtable[0x80 / 8] = @intFromPtr(&neoTriggerPredicatePassthrough);

    vtables_initialized = true;
    std.log.info("c2.vtable: built custom vtables (effect={d} slots, trigger={d} slots)", .{ EFFECT_VTBL_SLOTS, TRIGGER_VTBL_SLOTS });
}

/// Get pointer to the custom effect vtable. Returns null if not initialized.
pub fn getEffectVtablePtr() ?*const [EFFECT_VTBL_SLOTS]u64 {
    if (!vtables_initialized) return null;
    return &effect_vtable;
}

/// Get pointer to the custom trigger vtable. Returns null if not initialized.
pub fn getTriggerVtablePtr() ?*const [TRIGGER_VTBL_SLOTS]u64 {
    if (!vtables_initialized) return null;
    return &trigger_vtable;
}

/// Check if vtables are initialized.
pub fn isInitialized() bool {
    return vtables_initialized;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "vtable slot counts" {
    try std.testing.expectEqual(@as(usize, 25), EFFECT_VTBL_SLOTS);
    try std.testing.expectEqual(@as(usize, 17), TRIGGER_VTBL_SLOTS);
}

test "vtable sizes in bytes" {
    try std.testing.expectEqual(@as(usize, 200), EFFECT_VTBL_SLOTS * 8);
    try std.testing.expectEqual(@as(usize, 136), TRIGGER_VTBL_SLOTS * 8);
}

test "vtables initially uninitialized" {
    // Reset state for test.
    vtables_initialized = false;
    try std.testing.expect(!isInitialized());
    try std.testing.expectEqual(@as(?*const [EFFECT_VTBL_SLOTS]u64, null), getEffectVtablePtr());
    try std.testing.expectEqual(@as(?*const [TRIGGER_VTBL_SLOTS]u64, null), getTriggerVtablePtr());
}

test "plausible rejects bad pointers" {
    try std.testing.expect(!plausible(0));
    try std.testing.expect(!plausible(0x1234));
    try std.testing.expect(!plausible(0xffff_8000_0000_0000));
    try std.testing.expect(!plausible(0x7ff7_4a63_0001)); // misaligned
    try std.testing.expect(plausible(0x7ff7_4a63_0000));
}

test "readU32 returns 0 for bad address" {
    try std.testing.expectEqual(@as(u32, 0), readU32(0, 0));
}

test "readU32 reads from valid address" {
    var obj: [64]u8 align(8) = [_]u8{0} ** 64;
    std.mem.writeInt(u32, obj[0x20..0x24], 0xDEADBEEF, .little);
    const addr = @intFromPtr(&obj);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), readU32(addr, 0x20));
}
