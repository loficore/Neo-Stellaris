// scripted_tests.zig — test root for the detour modules.
//
// exec_hook.zig and lookup_hook.zig import ../hooking/*, which a module rooted at
// src/dll/scripted cannot reach (Zig rejects imports escaping the module path). Rooting
// here keeps every import inside src/dll and avoids main.zig's QuickJS C linkage.

const std = @import("std");

const lookup = @import("scripted/lookup_hook.zig");
const exec = @import("scripted/exec_hook.zig");
const detour = @import("hooking/detour.zig");
const windows = @import("hooking/windows.zig");
const graph_trigger = @import("scripted/graph_trigger.zig");

comptime {
    _ = lookup;
    _ = exec;
    _ = detour;
    _ = windows;
    _ = graph_trigger;
}

test {
    _ = std.testing.refAllDecls(@This());
}

// ---------------------------------------------------------------------------
// graph_trigger: M5 的纯逻辑面(指纹 / 缓存 / 阈值 / scope 解包 / 计数)
//
// 与 c2 的读图器分开:那里是"怎么读",这里是"读到的数怎么变成一次求值的答案"。
// 全部纯函数 —— 谓词体(Windows 侧)只做参数解包与调用,判据都在这里被钉住。
// ---------------------------------------------------------------------------

const gt = graph_trigger;

test "graph_trigger: the fingerprint is position sensitive, so a degree migration is visible" {
    // 空切片仍是 0(0 保留给「这一趟没读到」)。
    try std.testing.expectEqual(@as(u64, 0), gt.fingerprint(&[_]u32{}));
    // 同一张图两次 ⇒ 同一个指纹(确定性,缓存才可能命中)。
    try std.testing.expectEqual(gt.fingerprint(&[_]u32{ 3, 0, 4 }), gt.fingerprint(&[_]u32{ 3, 0, 4 }));
    // 度在槽之间迁移:总和同为 7,分布不同 ⇒ 必须不同。旧的「求和」实现会漏掉这一类
    // (issue #46 的表:同一窗口里 A 少一条、B 多一条)。
    try std.testing.expect(gt.fingerprint(&[_]u32{ 3, 0, 4 }) != gt.fingerprint(&[_]u32{ 3, 4, 0 }));
    try std.testing.expect(gt.fingerprint(&[_]u32{ 2, 0 }) != gt.fingerprint(&[_]u32{ 1, 1 }));
    try std.testing.expect(gt.fingerprint(&[_]u32{ 1, 2 }) != gt.fingerprint(&[_]u32{ 1, 3 }));
}

test "graph_trigger: only a non-zero, different fingerprint asks for a recompute" {
    try std.testing.expect(!gt.shouldRecompute(7, 7));
    try std.testing.expect(gt.shouldRecompute(7, 8));
    // 0 = 这一趟没读到(读失败)⇒ 不许刷新缓存,否则下一次求值会把失败读成"全图变了"
    try std.testing.expect(!gt.shouldRecompute(7, 0));
}

test "graph_trigger: a non-system scope never recomputes and never scores" {
    var scores = [_]u16{ 0, 250, 10 };
    const d = gt.decide(0x40, 1, .{ .kind_ok = true, .id_in_range = true, .fingerprint = 9, .read_ok = true, .recomputed = true }, &scores, gt.CHOKEPOINT_SCORE);
    try std.testing.expectEqual(gt.Reason.non_system_scope, d.reason);
    try std.testing.expect(!d.is_chokepoint);
    try std.testing.expectEqual(@as(u16, 0), d.score);
    try std.testing.expect(!d.recomputed);
}

test "graph_trigger: an out-of-range id is false, not a panic" {
    var scores = [_]u16{ 0, 1, 2 };
    const ok = gt.Snapshot{ .kind_ok = true, .id_in_range = true, .fingerprint = 9, .read_ok = true };
    // id 3 == scores.len
    try std.testing.expectEqual(gt.Reason.out_of_range, gt.decide(0x80, 3, ok, &scores, 200).reason);
    // id > u16 空间
    try std.testing.expectEqual(gt.Reason.out_of_range, gt.decide(0x80, 0x10000, ok, &scores, 200).reason);
    try std.testing.expect(!gt.decide(0x80, 3, ok, &scores, 200).is_chokepoint);
}

test "graph_trigger: the threshold is inclusive at 200" {
    var scores = [_]u16{ 200, 199 };
    const ok = gt.Snapshot{ .kind_ok = true, .id_in_range = true, .fingerprint = 9, .read_ok = true, .recomputed = true };
    try std.testing.expect(gt.decide(0x80, 0, ok, &scores, gt.CHOKEPOINT_SCORE).is_chokepoint);
    try std.testing.expect(!gt.decide(0x80, 1, ok, &scores, gt.CHOKEPOINT_SCORE).is_chokepoint);
    try std.testing.expectEqual(@as(u16, 199), gt.decide(0x80, 1, ok, &scores, gt.CHOKEPOINT_SCORE).score);
}

test "graph_trigger: counters separate the four fates the verdict reads" {
    var stats = gt.Stats{};
    const scores = [_]u16{300};
    const ok = gt.Snapshot{ .kind_ok = true, .id_in_range = true, .fingerprint = 5, .read_ok = true, .recomputed = true };
    gt.count(&stats, gt.decide(0x80, 0, ok, &scores, 200)); // evaluated + recomputed
    gt.count(&stats, gt.decide(0x80, 0, .{ .kind_ok = true, .id_in_range = true, .fingerprint = 5, .read_ok = true }, &scores, 200)); // cached
    gt.count(&stats, gt.decide(0x40, 0, ok, &scores, 200)); // non_system_scope
    gt.count(&stats, gt.decide(0x80, 9, ok, &scores, 200)); // out_of_range
    gt.count(&stats, gt.decide(0x80, 0, .{ .read_ok = false }, &scores, 200)); // read_failed
    // 两次走到判据(一重算一缓存);非 system scope / 越界 / 读失败都不算 `evaluated`,
    // 否则"每系统一次"会被范围外的求值稀释(计划 Review Focus #2)。
    try std.testing.expectEqual(@as(u64, 2), stats.evaluated);
    try std.testing.expectEqual(@as(u64, 1), stats.recomputed);
    try std.testing.expectEqual(@as(u64, 1), stats.cached_hits);
    try std.testing.expectEqual(@as(u64, 1), stats.non_system_scope);
    try std.testing.expectEqual(@as(u64, 1), stats.out_of_range);
    try std.testing.expectEqual(@as(u64, 1), stats.read_failed);
}

// ---------------------------------------------------------------------------
// graph_trigger: 边集内容哈希(issue #46 方案 3)
//
// 指纹回答"边条目总数 / 度分布变没变"(成本开关),哈希回答"边集是否逐条相同"
// (正确性)。四条判据来自计划:同图两次相等、换一条边必变、(a,b)==(b,a)、
// 空集是常量且不为 0(0 保留给"这一趟没读到")。
// ---------------------------------------------------------------------------

const Edge = gt.Edge;

test "graph_trigger: the same edge set hashes the same twice" {
    const rows = [_]Edge{ .{ .a = 5, .b = 9 }, .{ .a = 1, .b = 2 } };
    const rows_again = [_]Edge{ .{ .a = 5, .b = 9 }, .{ .a = 1, .b = 2 } };
    try std.testing.expectEqual(gt.hashEdges(&rows), gt.hashEdges(&rows_again));
    try std.testing.expectEqual(gt.hashEdges(&rows), gt.hashEdges(&rows));
}

test "graph_trigger: the edge hash does not depend on the order rows arrive in" {
    // `graph_probe.rows()` returns the container in slot-enumeration order; a
    // neighbour list rewritten by the engine (add one edge, remove it) can
    // enumerate the SAME set in a different order.  A hash over the sequence
    // would then report "the graph changed" on an identical edge set.
    const forward = [_]Edge{ .{ .a = 1, .b = 2 }, .{ .a = 3, .b = 4 }, .{ .a = 5, .b = 9 } };
    const reversed = [_]Edge{ .{ .a = 5, .b = 9 }, .{ .a = 3, .b = 4 }, .{ .a = 1, .b = 2 } };
    const shuffled = [_]Edge{ .{ .a = 3, .b = 4 }, .{ .a = 5, .b = 9 }, .{ .a = 1, .b = 2 } };
    try std.testing.expectEqual(gt.hashEdges(&forward), gt.hashEdges(&reversed));
    try std.testing.expectEqual(gt.hashEdges(&forward), gt.hashEdges(&shuffled));
}

test "graph_trigger: the edge hash is undirected, so (a,b) equals (b,a)" {
    const ab = [_]Edge{.{ .a = 5, .b = 9 }};
    const ba = [_]Edge{.{ .a = 9, .b = 5 }};
    try std.testing.expectEqual(gt.hashEdges(&ab), gt.hashEdges(&ba));
}

test "graph_trigger: one changed edge changes the hash" {
    const before = [_]Edge{ .{ .a = 5, .b = 9 }, .{ .a = 1, .b = 2 } };
    // 端点换了 / 少一条 / 多一条 —— 三种都是"图变了",指纹里的和可能都是 0 差。
    const reconnected = [_]Edge{ .{ .a = 5, .b = 10 }, .{ .a = 1, .b = 2 } };
    const dropped = [_]Edge{.{ .a = 5, .b = 9 }};
    const added = [_]Edge{ .{ .a = 5, .b = 9 }, .{ .a = 1, .b = 2 }, .{ .a = 3, .b = 4 } };
    try std.testing.expect(gt.hashEdges(&before) != gt.hashEdges(&reconnected));
    try std.testing.expect(gt.hashEdges(&before) != gt.hashEdges(&dropped));
    try std.testing.expect(gt.hashEdges(&before) != gt.hashEdges(&added));
}

test "graph_trigger: an empty edge set is a constant, and it is not zero" {
    // 0 是"这一趟没读到"的哨兵,所以"读到了、零条边"必须是另一个值。
    try std.testing.expectEqual(gt.EMPTY_EDGE_HASH, gt.hashEdges(&[_]Edge{}));
    try std.testing.expect(gt.EMPTY_EDGE_HASH != 0);
}

test "graph_trigger: the live hash follows the read that produced it" {
    gt.resetLive();
    try std.testing.expectEqual(@as(u64, 0), gt.liveHashSnapshot().hash); // 没读过
    try std.testing.expectEqual(@as(u32, 0), gt.liveHashSnapshot().edges);
    const rows = [_]Edge{ .{ .a = 7, .b = 3 }, .{ .a = 2, .b = 8 } };
    gt.recordEdges(&rows);
    try std.testing.expectEqual(gt.hashEdges(&rows), gt.liveHashSnapshot().hash);
    try std.testing.expectEqual(@as(u32, 2), gt.liveHashSnapshot().edges);
    gt.resetLive();
    try std.testing.expectEqual(@as(u64, 0), gt.liveHashSnapshot().hash);
}

// ---------------------------------------------------------------------------
// graph_trigger: 缓存策略的选择(issue #46 方案 3)
//
// 「指纹变了就重算」是成本开关;「每 N 次求值核对一次内容哈希」是正确性通路。
// 两者合成一个三分支决策,全部纯函数 —— 调度行为在这里被测死,liveScore 只照做。
// ---------------------------------------------------------------------------

test "graph_trigger: chooseAction prefers a changed fingerprint over a scheduled verify" {
    try std.testing.expectEqual(gt.CacheAction.recompute, gt.chooseAction(true, 0, 256));
    try std.testing.expectEqual(gt.CacheAction.recompute, gt.chooseAction(true, 999, 256));
}

test "graph_trigger: chooseAction schedules a verify even when the fingerprint matches" {
    try std.testing.expectEqual(gt.CacheAction.verify, gt.chooseAction(false, 256, 256));
    try std.testing.expectEqual(gt.CacheAction.verify, gt.chooseAction(false, 300, 256));
    try std.testing.expectEqual(gt.CacheAction.reuse, gt.chooseAction(false, 255, 256));
}

test "graph_trigger: verify every 0 disables the scheduled verify entirely" {
    try std.testing.expectEqual(gt.CacheAction.reuse, gt.chooseAction(false, 10_000, 0));
    try std.testing.expect(!gt.shouldVerify(10_000, 0));
}

// ---------------------------------------------------------------------------
// graph_trigger: live 源的三支结局与计数(Task 2)
//
// 计数器是判词面:`recomputed` 是我们真的跑了 analyze,`verified` 是核对通过、
// `cached_hits` 是连核对都没做。`verify_failed` 只属于「核对这一趟读失败」。
// ---------------------------------------------------------------------------

test "graph_trigger: the four live fates are counted separately" {
    var s = gt.Stats{};
    gt.recordLiveFate(&s, .reuse, false);
    gt.recordLiveFate(&s, .verify, true);
    gt.recordLiveFate(&s, .verify, false);
    gt.recordLiveFate(&s, .recompute, false);
    try std.testing.expectEqual(@as(u64, 1), s.cached_hits);
    try std.testing.expectEqual(@as(u64, 1), s.verified);
    try std.testing.expectEqual(@as(u64, 2), s.recomputed);
    try std.testing.expectEqual(@as(u64, 0), s.verify_failed);
}

test "graph_trigger: resetLive clears the cached hash and the new counters" {
    gt.resetLive();
    try std.testing.expectEqual(@as(u64, 0), gt.liveHashSnapshot().hash);
    try std.testing.expectEqual(@as(u32, 0), gt.liveHashSnapshot().edges);
    try std.testing.expectEqual(@as(u64, 0), gt.liveSnapshot().stats.verified);
    try std.testing.expectEqual(@as(u64, 0), gt.liveSnapshot().stats.verify_failed);
}

// ---------------------------------------------------------------------------
// graph_trigger: #46 的验收夹具 —— 度相同、图不同
//
// 指纹按槽号加权,所以「度在系统之间迁移」可见;但同一组槽内部换邻居仍然看不见
// (度序列完全相同)。这一格只有内容哈希能判 —— 下面的夹具就是 issue #46 表里
// 「总和相同、图不同」那一行。
// ---------------------------------------------------------------------------

test "graph_trigger: a rewiring that preserves every degree is still visible to the hash" {
    // 两条互不相邻的边 vs 一个四元环的一半:A-D 度序列完全相同({1,1,1,1}),
    // 但边集不同。
    const matching = [_]Edge{ .{ .a = 1, .b = 2 }, .{ .a = 3, .b = 4 } };
    const crossed = [_]Edge{ .{ .a = 1, .b = 3 }, .{ .a = 2, .b = 4 } };
    const counts_matching = [_]u32{ 0, 1, 1, 1, 1 };
    const counts_crossed = [_]u32{ 0, 1, 1, 1, 1 };
    try std.testing.expectEqual(gt.fingerprint(&counts_matching), gt.fingerprint(&counts_crossed));
    try std.testing.expect(gt.hashEdges(&matching) != gt.hashEdges(&crossed));
}

test "graph_trigger: the same picture twice is a cache hit, never a recompute" {
    const before = [_]Edge{ .{ .a = 1, .b = 2 }, .{ .a = 2, .b = 3 } };
    const h = gt.hashEdges(&before);
    try std.testing.expectEqual(gt.CacheAction.reuse, gt.chooseAction(false, 0, 256));
    try std.testing.expectEqual(h, gt.hashEdges(&before));
}
