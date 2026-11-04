// graph_trigger.zig — M5:图驱动的 trigger(`neo_is_chokepoint`)的纯逻辑面。
//
// 分工:`c2/graph_probe.zig` 管"怎么把活体里的边表读出来",`c2/chokepoint_dynamic.zig`
// 管"给定边表怎么算三组度量";本模块管**一次求值的判据** —— 什么 scope 才该重算、什么时候
// 缓存可以复用、分数怎么变成一个布尔、以及每个结局各记到哪个计数器上。
//
// 全部是纯函数(没有 `@ptrFromInt`,没有 `ReadProcessMemory`):谓词体只做参数解包与调用,
// 于是"重算/缓存/fail-closed"这三件事能在 Linux 上被测死。
//
// **缓存键是容器指纹,不是时间**(计划 Review Focus #1):指纹 = `Σ(count[slot] × mix(slot))`,
// 每个活槽一次 4 B 读(788 次,亚毫秒)。**按槽号加权**而不是直接求和,是为了让"度在系统之间
// 迁移"也能被看见 —— 纯求和时 A 少一条、B 多一条会抵消(issue #46 的表)。
//
// 它仍然**不是哈希**:同一系统内部换邻居(度不变、邻居变了)照样漏。真保证只有"读出边集再
// 对内容做哈希",代价是整趟读。这一层只为挡住绝大多数"没变",盲点写进 §7 的"不能说",
// **不许**用 TTL 掩盖 —— 时间缓存会把"没重算"伪装成"重算了"。
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

/// 每个槽号的权重:64 位 splitmix 的常量混合,结果强制为奇数。
/// 只要 `counts` 的下标语义是"槽号",权重就随机但**确定**——两次求值对同一个槽拿到同一个数。
pub fn mixWeight(slot: usize) u64 {
    var x: u64 = @as(u64, @intCast(slot)) +% 0x9E3779B97F4A7C15;
    x ^= x >> 30;
    x *%= 0xBF58476D1CE4E5B9;
    x ^= x >> 27;
    x *%= 0x94D049BB133111EB;
    x ^= x >> 31;
    return x | 1;
}

/// 逐个累加:`acc + count[slot] × mixWeight(slot)`(wrapping)。
/// 活体路径用它避免为 1,024 个槽再开一块缓冲。
pub fn accumulate(acc: u64, slot: usize, edges: u32) u64 {
    return acc +% mixWeight(slot) *% @as(u64, edges);
}

/// 容器指纹:`Σ(count[slot] × mixWeight(slot))`,空切片 = 0。
/// **按槽号加权**,所以"度在系统之间迁移"不会再抵消;同一系统内部换邻居仍看不见(见文件头)。
pub fn fingerprint(counts: []const u32) u64 {
    var acc: u64 = 0;
    for (counts, 0..) |c, slot| acc = accumulate(acc, slot, c);
    return acc;
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

// ---------------------------------------------------------------------------
// 活体分数(M5 v1 的载体:effect 体内重算)
//
// 调用方是 C5-SCORE 的写手(`neo_vtable.writeScore`):它原本读
// `chokepoint_table.zig` 里那张**烘焙表**,现在多一个 live 源 —— 每次求值先从活体
// 容器的计数和得到指纹,指纹变了才整趟重读 + 重算(§93 的 effect 路径已证明我们的
// 代码真的按星系被调用,这里只换"分数从哪来")。
// ---------------------------------------------------------------------------

const graph_probe = @import("../c2/graph_probe.zig");
const cd = @import("../c2/chokepoint_dynamic.zig");
const gg = @import("../c2/galaxy_graph.zig");
const graph = @import("../shared/offsets.zig").graph;
const windows = @import("../hooking/windows.zig");

// ---------------------------------------------------------------------------
// 边集内容哈希(issue #46 方案 3)
//
// 指纹(`fingerprint`)回答"总数/度分布变没变",只配当**成本**开关;它抓不到
// "同一窗口里 A 少一条、B 多一条"这类度数抵消。哈希回答的是**正确性**:
// 这一趟读出来的边集逐条相同吗。输入必须是同一趟读的结果(Review Focus #5)。
//
// 0 保留给"这个进程还没成功读过一次图",所以空边集是 FNV-1a 的初值,不是 0。
// ---------------------------------------------------------------------------

pub const Edge = cd.Edge;

pub const EDGE_HASH_OFFSET: u64 = 0xcbf29ce484222325;
pub const EDGE_HASH_PRIME: u64 = 0x100000001b3;
/// 空边集(读成功、零条边)的哈希。**不是 0** —— 0 是"没读到"的哨兵。
pub const EMPTY_EDGE_HASH: u64 = EDGE_HASH_OFFSET;

/// 排序暂存(见 `hashEdges`)。大小与读图器的边表上限同一个常量。
var hash_scratch: [graph_probe.MAX_EDGES]u32 = undefined;

/// 一条边的规范词 `min<<16 | max`:无向图里 `(a,b)` 与 `(b,a)` 是同一条边。
pub fn edgeWord(a: u16, b: u16) u32 {
    const lo: u32 = @min(a, b);
    const hi: u32 = @max(a, b);
    return (lo << 16) | hi;
}

/// FNV-1a(64)吸一个 4 字节词,小端序。
fn absorbWord(acc: u64, word: u32) u64 {
    var h = acc;
    var shift: u6 = 0;
    while (shift < 32) : (shift += 8) {
        h ^= (word >> @intCast(shift)) & 0xff;
        h *%= EDGE_HASH_PRIME;
    }
    return h;
}

/// 边集哈希。行必须来自同一趟读(调用方保证);`(min,max)` 归一化让方向无关,
/// **排序**让枚举顺序无关 —— `graph_probe.rows()` 给的是容器的槽枚举顺序,引擎改过
/// 邻居表之后同一张图可以换顺序枚举出来(否则"加一条再删一条"会让哈希假报变化)。
///
/// 暂存是模块级静态:边数上限与读图器同一个常量,所以不存在"装不下"的输入;
/// 调用方与 `liveScore` 同线程(单写者),与 `live_scores` 等静态缓冲同一条纪律。
pub fn hashEdges(rows: []const Edge) u64 {
    const n = @min(rows.len, hash_scratch.len);
    for (rows[0..n], 0..) |e, i| hash_scratch[i] = edgeWord(e.a, e.b);
    const words = hash_scratch[0..n];
    std.mem.sort(u32, words, {}, std.sort.asc(u32));
    var h = EDGE_HASH_OFFSET;
    for (words) |word| h = absorbWord(h, word);
    return h;
}


/// `neo_score` 的两个来源。0 = 烘焙表(C5-SCORE 原行为),1 = 活体重算(本计划)。
pub const SCORE_SOURCE_TABLE: u32 = 0;
pub const SCORE_SOURCE_LIVE: u32 = 1;

var live_scores: [MAX_SYSTEMS]u16 = undefined;
var live_art: [MAX_SYSTEMS]u8 = undefined;
var live_bridge: [MAX_SYSTEMS]u8 = undefined;
var live_count: usize = 0;
var live_fingerprint: u64 = 0;
/// 上一趟成功读到的边集的哈希与条数。`hash == 0` = 本进程还没成功读过。
var live_hash: u64 = 0;
var live_edge_count: u32 = 0;
/// live 源自己的计数(与烘焙表的计数器分开:混在一起会分不清是哪条路写进去的)。
pub var live_stats: Stats = .{};

pub const HashSnapshot = struct {
    hash: u64 = 0,
    edges: u32 = 0,
};

pub fn liveHashSnapshot() HashSnapshot {
    return .{ .hash = live_hash, .edges = live_edge_count };
}

/// 记下"这一趟读出来的边集":哈希 + 条数。只在 `readAt` 成功后调用 ——
/// 跨两次读拼出来的哈希没有意义(计划 Review Focus #5),所以读失败时**不更新**
/// (上一份描述的是上一次成功读,0 表示一次都没读过)。
pub fn recordEdges(rows: []const Edge) void {
    live_hash = hashEdges(rows);
    live_edge_count = @intCast(rows.len);
}

/// 活体分数。`null` = 这一趟拿不到(读失败/越界/空图),调用方按 `score_skipped` 处理 ——
/// **绝不**回退到烘焙表:两条源混用会让 §7 的判词失去意义。
pub fn liveScore(id: u32) ?u16 {
    if (id > std.math.maxInt(u16)) return null;

    const module_base = @intFromPtr(windows.moduleFunction(0) catch return null);
    const global = std.math.add(usize, module_base, graph.RVA_SYSTEM_INDEX_GLOBAL) catch return null;
    var buf: [@sizeOf(usize)]u8 = undefined;
    if (!windows.readProcessMemory(global, &buf)) return null;
    const index = std.mem.readInt(usize, &buf, .little);
    if (index == 0) return null;

    const mem = Memory{ .ctx = undefined, .read = memRead };
    const bound = readDword(mem, gg.addAddr(index, graph.INDEX_BOUND_OFF) orelse {
        live_stats.read_failed +%= 1;
        return null;
    }) orelse {
        live_stats.read_failed +%= 1;
        return null;
    };
    const table = readPtr(mem, gg.addAddr(index, graph.INDEX_TABLE_OFF) orelse {
        live_stats.read_failed +%= 1;
        return null;
    }) orelse {
        live_stats.read_failed +%= 1;
        return null;
    };
    if (table == 0 or bound == 0 or bound > graph.MAX_TABLE_SLOTS) {
        live_stats.read_failed +%= 1;
        return null;
    }

    // 指纹:`Σ(count[slot] × mixWeight(slot))`。**任何一个槽读不到**就把指纹打成 0
    // (= 「这一趟没读到」),于是 `shouldRecompute` 为假、上一份分数保留 —— fail-closed。
    var sum: u64 = 0;
    var unreadable = false;
    var slot: usize = 0;
    while (slot < bound) : (slot += 1) {
        const entry = readPtr(mem, gg.elemAddr(table, slot, graph.TABLE_RECORD_SIZE, graph.TABLE_SLOT_PTR_OFF) orelse {
            unreadable = true;
            break;
        }) orelse {
            unreadable = true;
            break;
        };
        if (entry == 0) continue;
        const edges_here = readDword(mem, gg.addAddr(entry, graph.EDGE_COUNT_OFF) orelse {
            unreadable = true;
            break;
        }) orelse {
            unreadable = true;
            break;
        };
        sum = accumulate(sum, slot, edges_here);
    }
    const now: u64 = if (unreadable) 0 else sum;

    if (!shouldRecompute(live_fingerprint, now)) {
        if (id >= live_count) return null;
        live_stats.evaluated +%= 1;
        live_stats.cached_hits +%= 1;
        return live_scores[id];
    }

    graph_probe.readAt(mem, index) catch {
        live_stats.read_failed +%= 1;
        return null;
    };
    const stats = graph_probe.lastStats();
    const max_id = stats.max_id orelse {
        live_stats.read_failed +%= 1;
        return null;
    };
    const n: usize = @as(usize, max_id) + 1;
    if (n == 0 or n > MAX_SYSTEMS) {
        live_stats.read_failed +%= 1;
        return null;
    }
    cd.analyze(std.heap.page_allocator, graph_probe.rows(), n, .{
        .scores = live_scores[0..n],
        .articulation = live_art[0..n],
        .bridge_endpoint = live_bridge[0..n],
    }) catch {
        live_stats.read_failed +%= 1;
        return null;
    };

    live_count = n;
    live_fingerprint = now;
    // 哈希与分数取自**同一次** `readAt`:跨两次读拼接出来的边集从未同时存在过。
    recordEdges(graph_probe.rows());
    live_stats.evaluated +%= 1;
    live_stats.recomputed +%= 1;
    return if (id < n) live_scores[id] else null;
}

pub fn liveSnapshot() struct { count: usize, fingerprint: u64, stats: Stats } {
    return .{ .count = live_count, .fingerprint = live_fingerprint, .stats = live_stats };
}

pub fn resetLive() void {
    live_count = 0;
    live_fingerprint = 0;
    live_hash = 0;
    live_edge_count = 0;
    live_stats = .{};
}

/// 与 `galaxy_graph.Memory` 是同一个形状(读图器的入参),这里只是本地别名 ——
/// 不重定义第二个结构,免得两边调用的不相容。
const Memory = gg.Memory;

fn memRead(_: *anyopaque, addr: usize, len: usize, buf: []u8) bool {
    _ = len;
    return windows.readProcessMemory(addr, buf);
}

fn readDword(mem: Memory, addr: usize) ?u32 {
    var buf: [4]u8 = undefined;
    if (!mem.read(mem.ctx, addr, buf.len, &buf)) return null;
    return std.mem.readInt(u32, &buf, .little);
}

fn readPtr(mem: Memory, addr: usize) ?usize {
    var buf: [@sizeOf(usize)]u8 = undefined;
    if (!mem.read(mem.ctx, addr, buf.len, &buf)) return null;
    return std.mem.readInt(usize, &buf, .little);
}
