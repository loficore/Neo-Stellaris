// neo_vtable.zig — C5-ADD 的 body:一个星系一行 `Neo: system <id>`。
//
// **这个模块不装任何东西。** 2026-11-02 第一发否定了「换对象 vtable」那条路
// (§93.2:解析出来的 effect 树不经谓词,`pred_patched=0`),现在的挂载点是
// `neo_dispatch.zig` 在逐系统派发入口 `0x3B0F80` 上的 token detour,它在 token
// 命中时直接调本模块的 `runBody`。
//
// body 只做四件事:读 scope 的 `+0x10`(星系 id)→ 规则筛 → 在栈上合成一个
// `0xF0` 零块、把文案写成 `+0x38` 的 MSVC 短串 → 调官方 `log` 的实现
// `0x185BF60`。`0x185BF60` 只读 `+0x38`/`+0xd0`/`+0xe0`,**不读 `[self]`**,
// 所以不需要虚表;那三格之外的内容它看不到。
//
// 不写引擎内存、不改对象 `[self]`、不 FreeLibrary。

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const windows = @import("../hooking/windows.zig");
const neo_effect = @import("neo_effect.zig");
const neo_state = @import("neo_state.zig");

const is_windows = builtin.os.tag == .windows;

/// §80.2 的 scope 形状(`0x7f7f20` 那一类指针):`+0x08` mask、`+0x10` id。
pub const SCOPE_MASK_OFF: usize = 0x08;
pub const SCOPE_ID_OFF: usize = 0x10;

/// §90.4 — 我们自己要调的那个官方 `log` 实现。
pub const RVA_LOG_EFFECT_EXEC: usize = offsets.keyword_reg.RVA_LOG_EFFECT_EXEC;

/// C5-WRITE — `set_variable` 的 per-scope body(`0x25EA560` 的 slot[9]/`+0x48`)。
pub const RVA_STATE_BODY: usize = 0x188E1D0;
/// 同一个类的 vtable;官方 `create` 把它写进 `[obj+0]`。
pub const RVA_STATE_VTABLE: usize = 0x25EA560;

pub const RULE_HITS: usize = 64;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var log_effect_addr: usize = 0;
var state_body_addr: usize = 0;
var state_vtable_addr: usize = 0;

/// 0 = 只写日志(C5-ADD 的原行为),1 = 日志 + 写系统变量(C5-WRITE)。
/// 与 `rule_bits` 一样是单个原子 u32:dispatch 线程永远读不到半更新值。
var act_mode: u32 = 0;

var stat_calls: u64 = 0;
var stat_matched: u64 = 0;
var stat_log_calls: u64 = 0;
var stat_writes: u64 = 0;
var stat_skipped: u64 = 0;
var stat_null_scope: u64 = 0;
var stat_non_system_scope: u64 = 0;
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

/// §80.2/§91.7 — the `every_system` loop stamps `mask = 0x80` on the scope it
/// hands to each child.  That cell is the only *type* signal we have; an id in
/// `0..786` is an observation, `mask == 0x80` is the engine saying "system
/// scope" (review M-1).
pub fn isSystemScope(mask: u32) bool {
    return mask == 0x80;
}

fn recordHit(id: u32) void {
    const nth = @atomicRmw(u64, &hit_count, .Add, 1, .monotonic);
    if (nth < RULE_HITS) hits[@intCast(nth)] = id;
}

/// C5-WRITE 的动作分支:`set_variable` 的官方 body 收 `(self, scope)`。
/// 合成对象在栈上、vtable 由我们摆;写进引擎的是**官方 body 自己**做的。
/// 返回是否真的调了 body —— 地址没解析到时是 `false`(计 `skipped`)。
fn writeState(id: u32, scope: u64) bool {
    if (state_body_addr == 0 or state_vtable_addr == 0) return false;
    var obj: [neo_state.OBJECT_SIZE]u8 align(8) = undefined;
    neo_state.layoutNumber(&obj, neo_state.VAR_NAME, id);
    std.mem.writeInt(u64, obj[0..8], state_vtable_addr, .little);
    const body: *const fn (u64, u64) callconv(.c) void = @ptrFromInt(state_body_addr);
    body(@intFromPtr(&obj), scope);
    return true;
}

/// The per-system body. Order is load-bearing (plan Task 2 Step 3): count →
/// scope gate → read id → rule → compose → count → call. Nothing here writes
/// engine memory; the only engine call is the official `log` implementation
/// with a stack object.
pub fn runBody(scope: u64, a3: u64) u64 {
    _ = @atomicRmw(u64, &stat_calls, .Add, 1, .monotonic);
    if (!scopeReadable(@intCast(scope))) {
        _ = @atomicRmw(u64, &stat_null_scope, .Add, 1, .monotonic);
        return 0;
    }
    if (!isSystemScope(readU32(@intCast(scope), SCOPE_MASK_OFF))) {
        _ = @atomicRmw(u64, &stat_non_system_scope, .Add, 1, .monotonic);
        return 0;
    }
    const id = readU32(@intCast(scope), SCOPE_ID_OFF);
    @atomicStore(u32, &last_id, id, .monotonic);
    if (!neo_effect.matches(id)) return 0;
    if (log_effect_addr == 0) return 0;
    _ = @atomicRmw(u64, &stat_matched, .Add, 1, .monotonic);
    recordHit(id);

    // C5-WRITE:先写状态,再写日志 —— 两个读数在同一次命中里成对出现。
    if (@atomicLoad(u32, &act_mode, .monotonic) == 1) {
        if (writeState(id, scope)) {
            _ = @atomicRmw(u64, &stat_writes, .Add, 1, .monotonic);
        } else {
            _ = @atomicRmw(u64, &stat_skipped, .Add, 1, .monotonic);
        }
    }

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
// Resolution
// ---------------------------------------------------------------------------

/// Resolve the engine base into the one address the body needs. The donor-vtable
/// copy this module used to build is gone: nothing ever installed it (§93.2).
pub fn resolveFromGame(game_base: usize) !void {
    const addr = game_base + RVA_LOG_EFFECT_EXEC;
    if (!plausible(addr)) return error.BadLogEffectPointer;
    log_effect_addr = addr;

    // C5-WRITE 的两个地址独立解析:拿不到就只记 `skipped`,不连累 C5-ADD 的日志路径。
    const body = game_base + RVA_STATE_BODY;
    const vtable = game_base + RVA_STATE_VTABLE;
    state_body_addr = if (plausible(body)) body else 0;
    state_vtable_addr = if (plausible(vtable)) vtable else 0;
}

/// `0` = 只写日志 | `1` = 日志 + 写系统变量。其它值按「开」处理吗?
/// 不 —— 只有精确的 1 开写,其余一律关,免得上层传错常量时悄悄改世界。
pub fn setAct(mode: u32) void {
    @atomicStore(u32, &act_mode, mode, .monotonic);
}

// ---------------------------------------------------------------------------
// Readouts (the stats line lives in neo_dispatch.zig, which owns the hook state)
// ---------------------------------------------------------------------------

pub fn calls() u64 {
    return @atomicLoad(u64, &stat_calls, .monotonic);
}

pub fn matched() u64 {
    return @atomicLoad(u64, &stat_matched, .monotonic);
}

pub fn logCalls() u64 {
    return @atomicLoad(u64, &stat_log_calls, .monotonic);
}

/// 我们真的调了官方 `set_variable` body 的次数(= `matched` 中开写的那部分)。
pub fn writes() u64 {
    return @atomicLoad(u64, &stat_writes, .monotonic);
}

/// 该写但 body/vtable 地址没解析到的次数 ⇒ `writes=0 skipped>0` 时查 `resolveFromGame`。
pub fn skipped() u64 {
    return @atomicLoad(u64, &stat_skipped, .monotonic);
}

pub fn lastId() u32 {
    return @atomicLoad(u32, &last_id, .monotonic);
}

pub fn ruleHitsRecorded() u32 {
    return @intCast(@min(@atomicLoad(u64, &hit_count, .monotonic), RULE_HITS));
}

pub fn nullScope() u64 {
    return @atomicLoad(u64, &stat_null_scope, .monotonic);
}

pub fn nonSystemScopes() u64 {
    return @atomicLoad(u64, &stat_non_system_scope, .monotonic);
}

pub fn resetForTest() void {
    log_effect_addr = 0;
    state_body_addr = 0;
    state_vtable_addr = 0;
    act_mode = 0;
    stat_calls = 0;
    stat_matched = 0;
    stat_log_calls = 0;
    stat_writes = 0;
    stat_skipped = 0;
    stat_null_scope = 0;
    stat_non_system_scope = 0;
    last_id = 0;
    hit_count = 0;
    @memset(std.mem.asBytes(&hits), 0);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "rule hits are recorded in call order and capped" {
    resetForTest();
    var i: u32 = 0;
    while (i < RULE_HITS + 5) : (i += 1) recordHit(100 + i);
    try std.testing.expectEqual(@as(u32, RULE_HITS), ruleHitsRecorded());
    try std.testing.expectEqual(@as(u32, 100), hits[0]);
    try std.testing.expectEqual(@as(u32, 100 + RULE_HITS - 1), hits[RULE_HITS - 1]);
}

test "resetForTest zeroes the counters but keeps nothing else" {
    resetForTest();
    stat_calls = 3;
    stat_matched = 2;
    stat_log_calls = 1;
    recordHit(7);
    resetForTest();
    try std.testing.expectEqual(@as(u64, 0), calls());
    try std.testing.expectEqual(@as(u64, 0), matched());
    try std.testing.expectEqual(@as(u64, 0), logCalls());
    try std.testing.expectEqual(@as(u32, 0), ruleHitsRecorded());
    try std.testing.expectEqual(@as(usize, 0), log_effect_addr);
}

test "the scope offsets are the ones the dispatch site documents" {
    try std.testing.expectEqual(@as(usize, 0x10), SCOPE_ID_OFF);
    try std.testing.expectEqual(@as(usize, 0x08), SCOPE_MASK_OFF);
    try std.testing.expectEqual(@as(usize, 0x185BF60), RVA_LOG_EFFECT_EXEC);
}

test "the C5-WRITE body and vtable are the load-bearing RVAs" {
    try std.testing.expectEqual(@as(usize, 0x188E1D0), RVA_STATE_BODY);
    try std.testing.expectEqual(@as(usize, 0x25EA560), RVA_STATE_VTABLE);
    resetForTest();
    try std.testing.expectEqual(@as(u64, 0), writes());
    try std.testing.expectEqual(@as(u64, 0), skipped());
}

test "the system-scope marker is 0x80" {
    try std.testing.expect(isSystemScope(0x80));
    try std.testing.expect(!isSystemScope(0));
    try std.testing.expect(!isSystemScope(0x81));
}
