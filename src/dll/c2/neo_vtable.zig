// neo_vtable.zig — C5-ADD:让引擎按星系调用我们注册的 `neo_action`。
//
// 与 C4 的 `vtable.zig` 的区别(2026-11-02 静态复核):
//   * `vtable.zig` 换的是 slot[1](`+0x08`,Execute)与 slot[2](`+0x10`,instantiate),
//     那条链是「捕获/放行一个已经被引擎解释的效果」;
//   * 这里换的是 **slot[9](`+0x48`)**,即 §91.6/§91.7 实机钉死的**逐系统派发入口**:
//     `0x3B0F80` 先 `call [rax+0xa8]`(scope 门),再 `call [rax+0x48]`(子效果执行体)。
//     `log` 效果的 vtable `0x25FC340` 的 `+0x48` 正是 `0x185BF60`(§90.4 的锚),
//     `caller_rva=0x3B101F` 的 787 条读数就是从这个槽进来的。
//
// 所以:donor `0x2606FE0` 的 25 个槽原样复制,只把 +0x48 换成我们的实现;
// 其余槽(含 +0xA8 的 scope 门、+0x98 的谓词)保持引擎自己的 —— 我们的对象仍然
// 是一个**良构的官方类实例**,只是逐系统那一步的动作换成了我们写的。
//
// 只读 scope、不写引擎内存、不重指向任何引擎对象的 `[self]` 之外的东西:
// `[self]` 由 C4 的 predicate hook 在实例化时换成本表的地址。永不 FreeLibrary。

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const windows = @import("../hooking/windows.zig");
const predicate_hook = @import("predicate_hook.zig");
const neo_effect = @import("neo_effect.zig");

const is_windows = builtin.os.tag == .windows;

pub const SlotCount: usize = offsets.keyword_reg.EFFECT_VTBL_COPY_SLOTS;

/// §80.2 的 scope 形状(`0x7f7f20` 那一类指针):`+0x08` mask、`+0x10` id。
pub const SCOPE_MASK_OFF: usize = 0x08;
pub const SCOPE_ID_OFF: usize = 0x10;

/// §90.4 — 我们自己要调的那个官方 `log` 实现。
pub const RVA_LOG_EFFECT_EXEC: usize = offsets.keyword_reg.RVA_LOG_EFFECT_EXEC;

pub const RULE_HITS: usize = 64;
pub const STATS_SIZE: usize = 512;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var slots: [SlotCount]u64 align(16) = [_]u64{0} ** SlotCount;
var built = false;
var log_effect_addr: usize = 0;

var install_attempted = false;

var stat_calls: u64 = 0;
var stat_matched: u64 = 0;
var stat_log_calls: u64 = 0;
var stat_null_scope: u64 = 0;
var last_id: u32 = 0;

var hit_count: u64 = 0;
var hits: [RULE_HITS]u32 = undefined;

// ---------------------------------------------------------------------------
// The per-system body
// ---------------------------------------------------------------------------

fn plausible(p: usize) bool {
    return p >= 0x10000 and p <= 0x00007FFF_FFFF_0000 and (p & 7) == 0;
}

fn readU32(addr: usize, comptime off: usize) u32 {
    if (!plausible(addr)) return 0;
    const base: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u32, base[off..][0..4], .little);
}

fn scopeReadable(scope: usize) bool {
    if (!plausible(scope)) return false;
    if (!is_windows) return true;
    return windows.isCommitted(scope);
}

fn recordHit(id: u32) void {
    const nth = @atomicRmw(u64, &hit_count, .Add, 1, .monotonic);
    if (nth < RULE_HITS) hits[@intCast(nth)] = id;
}

/// slot[9] of our copy. Called by `0x3B0F80` once per dispatched system.
///
/// Order is load-bearing (plan Task 2 Step 3): count → scope gate → read id →
/// rule → compose → count → call. Nothing here writes engine memory; the only
/// engine call is the official `log` implementation with a stack object.
fn neoActionExecute(self: u64, scope: u64, a3: u64) callconv(.c) u64 {
    _ = self; // the synthesized object is ours; the engine's instance is untouched
    _ = @atomicRmw(u64, &stat_calls, .Add, 1, .monotonic);
    if (!scopeReadable(@intCast(scope))) {
        _ = @atomicRmw(u64, &stat_null_scope, .Add, 1, .monotonic);
        return 0;
    }
    const id = readU32(@intCast(scope), SCOPE_ID_OFF);
    @atomicStore(u32, &last_id, id, .monotonic);
    if (!neo_effect.matches(id)) return 0;
    if (log_effect_addr == 0) return 0;
    _ = @atomicRmw(u64, &stat_matched, .Add, 1, .monotonic);
    recordHit(id);

    // MSVC std::string at +0x38 of a zeroed 0xF0 block — `0x185BF60` reads
    // three cells there (+0x38 text, +0xd0 empty string, +0xe0 previous length)
    // and never dereferences `[self]`, so no vtable is required.
    var obj: [0xF0]u8 = [_]u8{0} ** 0xF0;
    var text: [32]u8 = undefined;
    const line = neo_effect.formatText(&text, id);
    neo_effect.writeSso(@ptrCast(&obj[0x38]), line);

    _ = @atomicRmw(u64, &stat_log_calls, .Add, 1, .monotonic);
    const log_fn: *const fn (u64, u64, u64) callconv(.c) u64 = @ptrFromInt(log_effect_addr);
    return log_fn(@intFromPtr(&obj), scope, a3);
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

pub fn buildFromSlots(donor: []const u64) !void {
    if (donor.len < SlotCount) return error.ShortDonor;
    @memcpy(&slots, donor[0..SlotCount]);
    slots[offsets.keyword_reg.EFFECT_VTBL_DISPATCH_IN_SCOPE / 8] = @intFromPtr(&neoActionExecute);
    built = true;
}

/// Copy the donor table straight out of the loaded image and remember the
/// resolved `log` entry in the same shot.
pub fn buildFromGame(game_base: usize) !void {
    const addr = game_base + offsets.keyword_reg.DONOR_EFFECT_VTABLE;
    if (!plausible(addr)) return error.BadDonorPointer;
    const donor: [*]const u64 = @ptrFromInt(addr);
    try buildFromSlots(donor[0..SlotCount]);
    log_effect_addr = game_base + RVA_LOG_EFFECT_EXEC;
}

pub fn getVtable() ?*const [SlotCount]u64 {
    return if (built) &slots else null;
}

pub fn isBuilt() bool {
    return built;
}

pub fn logEffect() usize {
    return log_effect_addr;
}

// ---------------------------------------------------------------------------
// Readouts
// ---------------------------------------------------------------------------

pub fn statsInto(out: []u8) usize {
    const hit_n: u32 = @intCast(@min(@atomicLoad(u64, &hit_count, .monotonic), RULE_HITS));
    const written = std.fmt.bufPrint(
        out,
        "calls={d} matched={d} log_calls={d} last_id={d} rule_hits={d} installed={d} verify={d}\n",
        .{
            @atomicLoad(u64, &stat_calls, .monotonic),
            @atomicLoad(u64, &stat_matched, .monotonic),
            @atomicLoad(u64, &stat_log_calls, .monotonic),
            @atomicLoad(u32, &last_id, .monotonic),
            hit_n,
            @intFromBool(predicate_hook.isInstalled()),
            verify(),
        },
    ) catch return 0;
    return written.len;
}

/// `[count: u32][ids: u32 × RULE_HITS]` — same shape as §92's decision record.
pub fn ruleHitsInto(out: [*]u8) u32 {
    const count: u32 = @intCast(@min(@atomicLoad(u64, &hit_count, .monotonic), RULE_HITS));
    const dst: [*]u32 = @ptrCast(@alignCast(out));
    dst[0] = count;
    var i: u32 = 0;
    while (i < count) : (i += 1) dst[1 + i] = hits[i];
    return count;
}

/// 0 = consistent | -1 hook lost | -2 engine bytes differ | -3 never installed.
pub fn verify() i32 {
    if (!install_attempted) return -3;
    return predicate_hook.verify();
}

pub fn nullScope() u64 {
    return @atomicLoad(u64, &stat_null_scope, .monotonic);
}

pub fn markInstallAttempted() void {
    install_attempted = true;
}

pub fn resetForTest() void {
    slots = [_]u64{0} ** SlotCount;
    built = false;
    log_effect_addr = 0;
    install_attempted = false;
    stat_calls = 0;
    stat_matched = 0;
    stat_log_calls = 0;
    stat_null_scope = 0;
    last_id = 0;
    hit_count = 0;
    @memset(std.mem.asBytes(&hits), 0);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "buildFromSlots replaces only the per-system dispatch slot" {
    resetForTest();
    var donor = [_]u64{0} ** SlotCount;
    for (&donor, 0..) |*slot, i| slot.* = 0x140001000 + i * 0x100;
    try buildFromSlots(&donor);
    try std.testing.expect(isBuilt());
    const vt = getVtable().?;
    const dispatch = offsets.keyword_reg.EFFECT_VTBL_DISPATCH_IN_SCOPE / 8;
    try std.testing.expectEqual(@as(u64, 9), dispatch);
    try std.testing.expect(vt[dispatch] != donor[dispatch]);
    // Execute (slot[1]), instantiate (slot[2]) and the scope gate (slot[21])
    // stay engine-native: our object must remain a well-formed donor instance.
    try std.testing.expectEqual(donor[1], vt[1]);
    try std.testing.expectEqual(donor[2], vt[2]);
    try std.testing.expectEqual(donor[21], vt[21]);
}

test "buildFromSlots rejects a short donor" {
    resetForTest();
    const donor = [_]u64{1} ** (SlotCount - 1);
    try std.testing.expectError(error.ShortDonor, buildFromSlots(&donor));
    try std.testing.expect(!isBuilt());
}

test "verify is -3 before the first install attempt" {
    resetForTest();
    try std.testing.expectEqual(@as(i32, -3), verify());
}

test "statsInto writes the seven keys in the driver's order" {
    resetForTest();
    var buf: [STATS_SIZE]u8 = undefined;
    const n = statsInto(&buf);
    const expected = "calls=0 matched=0 log_calls=0 last_id=0 rule_hits=0 installed=0 verify=-3\n";
    try std.testing.expectEqualStrings(expected, buf[0..n]);
}

test "rule hits are recorded in call order and capped" {
    resetForTest();
    var i: u32 = 0;
    while (i < RULE_HITS + 5) : (i += 1) recordHit(100 + i);
    var buf: [4 + RULE_HITS * 4]u8 align(8) = undefined;
    try std.testing.expectEqual(@as(u32, RULE_HITS), ruleHitsInto(&buf));
    const words: [*]const u32 = @ptrCast(@alignCast(&buf));
    try std.testing.expectEqual(@as(u32, 100), words[1]);
    try std.testing.expectEqual(@as(u32, 100 + RULE_HITS - 1), words[RULE_HITS]);
}

test "the scope offsets are the ones the dispatch site documents" {
    try std.testing.expectEqual(@as(usize, 0x10), SCOPE_ID_OFF);
    try std.testing.expectEqual(@as(usize, 0x08), SCOPE_MASK_OFF);
    try std.testing.expectEqual(@as(usize, 0x185BF60), RVA_LOG_EFFECT_EXEC);
}
