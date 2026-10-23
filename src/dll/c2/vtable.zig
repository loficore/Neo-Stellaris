// vtable.zig — C4: DLL-owned copy of the donor effect vtable.
//
// §52 design (all VERIFIED 4.4.4 STATIC): `0x3B01A0` (effect instantiate)
// writes the token at [child+0x20], then calls `[child_vptr+0x98]` (predicate)
// and finally `[child_vptr+0x08]` — slot[1], the virtual Execute entry. Base
// `0x1D08520` is merely that slot's default body; hidden_effect overrides it
// with `0x3AFD30`, whose live behavior re-parses the script text. §52 shipped
// that chain OFF (capture only); C4 apply now chains it for tier >= 1, and
// only then (wire.zig onExecute). This module copies the donor vtable
// `0x2606FE0` (25 slots, through +0xC0 — a safe lower bound that still
// includes the predicate at +0x98) into DLL `.data`, replaces slot[1] with the
// bridge below, and wraps slot[2] (the donor's `0x3B01A0`) in a counting
// forwarder (§54.6). The copy is never freed: patched objects point into this
// module's data.
//
// Effect ABI visible here:
//   slot[1]  +0x08  Execute      (self, ctx, a3) -> void   [bridge]
//   slot[15] +0x78  donor helper (copied untouched)
//   slot[19] +0x98  predicate    (child, parent) -> bool    (copied untouched;
//                   predicate_hook.zig's detour patches only our token)

const std = @import("std");
const offsets = @import("../shared/offsets.zig");
const wire = @import("wire.zig");

pub const SlotCount: usize = offsets.keyword_reg.EFFECT_VTBL_COPY_SLOTS;

var slots: [SlotCount]u64 align(16) = [_]u64{0} ** SlotCount;
var built = false;
var donor_execute_addr: u64 = 0;
var chain_enabled = false;

// §54.6 discriminant: slot[2] is the donor's 0x3B01A0 ("build the next
// sub-effect"), the one slot a per-system body execution can reach through
// our copy without passing slot[1]. The thunk only counts and forwards.
var slot2_donor_addr: u64 = 0;
var slot2_calls: u64 = 0;
pub const SLOT2_STATS_SIZE: usize = 16;

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
    slot2_donor_addr = donor[offsets.keyword_reg.EFFECT_VTBL_INSTANTIATE / 8];
    slots[offsets.keyword_reg.EFFECT_VTBL_INSTANTIATE / 8] = @intFromPtr(&effectInstantiate);
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
/// the donor's own Execute when the bridge says so: wire apply mode for tier
/// >= 1, or the legacy `chain_enabled` flag for the off-mode sentinel path.
fn effectExecute(self: u64, ctx: u64, a3: u64) callconv(.c) u64 {
    const token = readU32(self, offsets.keyword_reg.EFFECT_OBJECT_TOKEN_ID);
    if (token == 0) return 0;
    if (wire.mode() != .off) {
        if (wire.onExecute(token, self, ctx, a3) and donor_execute_addr != 0) {
            const donor: *const fn (u64, u64, u64) callconv(.c) u64 = @ptrFromInt(donor_execute_addr);
            return donor(self, ctx, a3);
        }
        return 0;
    }
    const rc = C2ExecCall(token, ctx);
    if (rc == 1 and chain_enabled and donor_execute_addr != 0) {
        const donor: *const fn (u64, u64, u64) callconv(.c) u64 = @ptrFromInt(donor_execute_addr);
        return donor(self, ctx, a3);
    }
    return 0;
}

/// slot[2] of the copy: count the entry, then forward all four register
/// arguments unchanged to the donor slot the engine would have called.
fn effectInstantiate(a1: u64, a2: u64, a3: u64, a4: u64) callconv(.c) u64 {
    _ = @atomicRmw(u64, &slot2_calls, .Add, 1, .monotonic);
    const target = slot2_donor_addr;
    if (!plausible(target)) return 0;
    const donor: *const fn (u64, u64, u64, u64) callconv(.c) u64 = @ptrFromInt(target);
    return donor(a1, a2, a3, a4);
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

pub fn slot2Calls() u64 {
    return @atomicLoad(u64, &slot2_calls, .monotonic);
}

pub fn slot2Target() u64 {
    return slot2_donor_addr;
}

/// Read-only snapshot for the driver: <QQ> = slot[2] entries, forwarded target.
pub fn slot2StatsInto(out: []u8) bool {
    if (out.len < SLOT2_STATS_SIZE) return false;
    std.mem.writeInt(u64, out[0..][0..8], slot2Calls(), .little);
    std.mem.writeInt(u64, out[8..][0..8], slot2_donor_addr, .little);
    return true;
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
    slot2_donor_addr = 0;
    slot2_calls = 0;
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
