// vtable.zig — C4: DLL-owned copy of the donor effect vtable.
//
// §52 design (all VERIFIED 4.4.4 STATIC): `0x3B01A0` (effect instantiate)
// writes the token at [child+0x20], then calls `[child_vptr+0x98]` (predicate)
// and finally `[child_vptr+0x08]` — slot[1], the virtual Execute entry. Base
// `0x1D08520` is merely that slot's default body; hidden_effect overrides it
// with `0x3AFD30`, whose live behavior would re-parse the script text (the
// plan keeps that chain OFF, §52). This module copies the donor vtable
// `0x2606FE0` (25 slots, through +0xC0 — a safe lower bound that still
// includes the predicate at +0x98) into DLL `.data` and replaces ONLY slot[1]
// with the bridge below. The copy is never freed: patched objects point into
// this module's data.
//
// Effect ABI visible here:
//   slot[1]  +0x08  Execute      (self, ctx, a3) -> void   [bridge]
//   slot[15] +0x78  donor helper (copied untouched)
//   slot[19] +0x98  predicate    (child, parent) -> bool    (copied untouched;
//                   predicate_hook.zig's detour patches only our token)

const std = @import("std");
const offsets = @import("../shared/offsets.zig");

pub const SlotCount: usize = offsets.keyword_reg.EFFECT_VTBL_COPY_SLOTS;

var slots: [SlotCount]u64 align(16) = [_]u64{0} ** SlotCount;
var built = false;
var donor_execute_addr: u64 = 0;
var chain_enabled = false;

extern fn C2ExecCall(token: u32, ctx_word: u64) c_int;

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

pub fn buildFromSlots(donor: []const u64) !void {
    if (donor.len < SlotCount) return error.ShortDonor;
    const donor_exec = donor[offsets.keyword_reg.EFFECT_VTBL_EXECUTE / 8];
    if (!plausible(donor_exec)) return error.BadDonorExecute;
    @memcpy(&slots, donor[0..SlotCount]);
    donor_execute_addr = donor_exec;
    slots[offsets.keyword_reg.EFFECT_VTBL_EXECUTE / 8] = @intFromPtr(&effectExecute);
    built = true;
}

/// Read the donor table straight out of the loaded game image (engine memory).
pub fn buildFromGame(game_base: usize) !void {
    const addr = game_base + offsets.keyword_reg.DONOR_EFFECT_VTABLE;
    if (!plausible(addr)) return error.BadDonorPointer;
    const donor: [*]const u64 = @ptrFromInt(addr);
    try buildFromSlots(donor[0..SlotCount]);
}

/// slot[1] of the copy. The engine calls this with (self, ctx, a3); we read the
/// token the instantiate path wrote, hand it to the C bridge, and only chain to
/// the donor's own Execute on a proven sentinel. Chain is OFF for the live shot.
fn effectExecute(self: u64, ctx: u64, a3: u64) callconv(.c) u64 {
    const token = readU32(self, offsets.keyword_reg.EFFECT_OBJECT_TOKEN_ID);
    if (token == 0) return 0;
    const rc = C2ExecCall(token, ctx);
    if (rc == 1 and chain_enabled and donor_execute_addr != 0) {
        const donor: *const fn (u64, u64, u64) callconv(.c) u64 = @ptrFromInt(donor_execute_addr);
        return donor(self, ctx, a3);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// State accessors
// ---------------------------------------------------------------------------

pub fn getVtable() ?*const [SlotCount]u64 {
    return if (built) &slots else null;
}

pub fn donorExecute() u64 {
    return donor_execute_addr;
}

pub fn setChainEnabled(on: bool) void {
    chain_enabled = on;
}

pub fn chainEnabled() bool {
    return chain_enabled;
}

pub fn isBuilt() bool {
    return built;
}

pub fn resetForTest() void {
    slots = [_]u64{0} ** SlotCount;
    built = false;
    donor_execute_addr = 0;
    chain_enabled = false;
}

// ---------------------------------------------------------------------------
// Compatibility adapters (ledger P3) — removed when the last consumer is
// rewritten: predicate_hook.zig in Task 4 (getEffect*Ptr) and exports.zig in
// Task 6 (buildVtables/isInitialized). They keep the tree compiling and
// behaving the same in between; they add no second vtable.
// ---------------------------------------------------------------------------

pub fn buildVtables(game_base: usize) void {
    buildFromGame(game_base) catch |err| {
        std.log.err("c2.vtable: cannot build from donor at base 0x{x}: {s}", .{ game_base, @errorName(err) });
    };
}

pub fn isInitialized() bool {
    return built;
}

pub fn getEffectVtablePtr() ?*const [SlotCount]u64 {
    return getVtable();
}

/// The trigger table is no longer built (the C4 path does not touch triggers);
/// the old predicate hook is rewritten in Task 4 and never installs it.
pub fn getTriggerVtablePtr() ?*const [17]u64 {
    return null;
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "vtable slot count matches the donor copy contract" {
    try std.testing.expectEqual(@as(usize, 25), SlotCount);
    try std.testing.expectEqual(@as(usize, 200), SlotCount * 8);
    try std.testing.expect(SlotCount > offsets.keyword_reg.EFFECT_VTBL_INSTANTIATE_PREDICATE / 8);
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
