// graph_trigger.zig — M5:图驱动的 trigger(`neo_is_chokepoint`)的纯逻辑面。
//
// 分工:`c2/graph_probe.zig` 管"怎么把活体里的边表读出来",`c2/chokepoint_dynamic.zig`
// 管"给定边表怎么算三组度量";本模块管**一次求值的判据** —— 什么 scope 才该重算、什么时候
// 缓存可以复用、分数怎么变成一个布尔、以及每个结局各记到哪个计数器上。
//
// 全部是纯函数(没有 `@ptrFromInt`,没有 `ReadProcessMemory`):谓词体只做参数解包与调用,
// 于是"重算/缓存/fail-closed"这三件事能在 Linux 上被测死。
//
// **缓存键是容器指纹,不是时间**(计划 Review Focus #1):指纹 = 每个活槽 `+0x59C` 的
// dword **和**。它便宜(788 次 4 B 读,亚毫秒),而且**顺序无关**。已知盲点:同一次 tick 里
// 先加边再删同一条边,和会回到原值 ⇒ 缓存不被刷新。这条盲点写进 `reason` 之外的
// detail(驱动侧),**不许**用 TTL 掩盖 —— 时间缓存会把"没重算"伪装成"重算了"。
//
// **fail-closed**:读失败(`read_ok == false`)返回 false 且 `score = 0`,但**不清空**分数
// 数组 —— 清空会让下一次求值把"这一次读失败"读成"全图零分"。调用方只在 `shouldRecompute`
// 为真且 `readAt` 成功时才覆盖分数。

const std = @import("std");

/// 引擎的 system scope 类型字(§1.2 `0x3939f0` 的第一条比较:`[scope+8] == 0x80`)。
pub const SYSTEM_SCOPE_KIND: u32 = 0x80;

/// 交通要道的分数门槛。与 C5-SCORE 的 tier-2 同口径(取证卷 §95 的 `NEO_TIER2`:≥200)。
pub const CHOKEPOINT_SCORE: u16 = 200;

/// 系统 id 的端点空间(u16)。超过它的 id 不查表、直接 false。
pub const MAX_SYSTEMS: usize = 1 << 16;

pub const Reason = enum {
    ok,
    /// 不是 system scope(`[scope+8] != 0x80`):不重算、不缓存、返回 false。
    non_system_scope,
    /// id 超出 u16 空间或超出分数表:返回 false,不许越界索引(Debug 构建会 panic)。
    out_of_range,
    /// 这一趟读图失败:返回 false,保留上一份分数,计 `read_failed`。
    read_failed,
};

pub const Decision = struct {
    is_chokepoint: bool,
    score: u16,
    /// 这一次求值**真的**跑了 `chokepoint_dynamic.analyze`(不是命中缓存)。
    recomputed: bool,
    reason: Reason,
};

/// 一趟读图的结果摘要。`fingerprint == 0` 保留给"没读到",所以它不能是一个合法的空图指纹
/// (空图没有边 ⇒ 和恒 0;那种情况下也不该有系统被求值)。
pub const Snapshot = struct {
    kind_ok: bool = false,
    id_in_range: bool = false,
    fingerprint: u64 = 0,
    read_ok: bool = false,
    /// 调用方是否刚刚跑过重算(与 `shouldRecompute` 的答案一致)。
    recomputed: bool = false,
};

/// 容器指纹:每个活槽 `+0x59C` 的 dword 和(wrapping)。
/// 顺序无关、空切片 = 0;比按槽序拼接更稳(槽序在两次读之间不应改变,但没必要依赖它)。
pub fn fingerprint(counts: []const u32) u64 {
    var sum: u64 = 0;
    for (counts) |c| sum +%= c;
    return sum;
}

/// `now == 0` 表示这一趟没读到指纹 ⇒ 不重算(保留上一份分数,fail-closed)。
pub fn shouldRecompute(last: u64, now: u64) bool {
    return now != 0 and now != last;
}

/// 一次求值的答案。判据顺序即失效顺序:scope 门 → id 门 → 读门 → 查表。
pub fn decide(
    scope_kind: u32,
    scope_id: u32,
    snap: Snapshot,
    scores: []const u16,
    threshold: u16,
) Decision {
    if (scope_kind != SYSTEM_SCOPE_KIND) {
        return .{ .is_chokepoint = false, .score = 0, .recomputed = false, .reason = .non_system_scope };
    }
    if (scope_id > std.math.maxInt(u16) or scope_id >= scores.len) {
        return .{ .is_chokepoint = false, .score = 0, .recomputed = false, .reason = .out_of_range };
    }
    if (!snap.read_ok or !snap.kind_ok or !snap.id_in_range) {
        return .{ .is_chokepoint = false, .score = 0, .recomputed = false, .reason = .read_failed };
    }
    const score = scores[scope_id];
    return .{
        .is_chokepoint = score >= threshold,
        .score = score,
        .recomputed = snap.recomputed,
        .reason = .ok,
    };
}

/// 谓词体与导出共用的六个计数器。`evaluated` 只数**真的走到判据**的求值
/// (非 system scope 不算),否则"每系统一次"会被范围外的调用稀释。
pub const Stats = struct {
    evaluated: u64 = 0,
    recomputed: u64 = 0,
    cached_hits: u64 = 0,
    non_system_scope: u64 = 0,
    out_of_range: u64 = 0,
    read_failed: u64 = 0,
};

pub fn count(stats: *Stats, decision: Decision) void {
    switch (decision.reason) {
        .non_system_scope => stats.non_system_scope +%= 1,
        .out_of_range => stats.out_of_range +%= 1,
        .read_failed => stats.read_failed +%= 1,
        .ok => {
            stats.evaluated +%= 1;
            if (decision.recomputed) stats.recomputed +%= 1 else stats.cached_hits +%= 1;
        },
    }
}
