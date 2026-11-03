// chokepoint_dynamic.zig — 纯 Zig 的图度量:Brandes 介数中心性 + 迭代式 Tarjan。
//
// 口径与 scripts/chokepoint_scores.py 相同的地方:无权无向,每对无序点只计一次(`/2`),
// 归一化分母 `(n-1)(n-2)/2`,`score = round(1000 * normalized)` 后夹到 u16。
//
// **n 的定义是故意的差异,不是笔误**:本模块 `n = caller's system_count` —— 孤立系统
// 计入分母、拿到 score 0(它们同样进入割点/桥扫描,但不可能命中);离线工具的
// `n = len(adjacency)`(degree-0 节点既不在行集也不在分母)。两者**只要每个系统
// degree >= 1 就完全一致**,787 系统 fixture 正是如此 —— 所以 golden 逐项相等;
// 一旦有孤立系统,同一个图会得到不同分母(本模块 n 更大、分数更小)。
//
// 为了逐位复现 Python 的浮点结果,推导顺序也照抄:
//   * source 升序;每个 source 内邻居升序(BFS 队列 FIFO);
//   * predecessor 按发现顺序追加;依赖回代按栈的逆序、每个 predecessor 的内存顺序;
//   * 全程 f64 且按同一运算次序累加。
// 取整用 round-half-to-even(Python `int(round(x))` 的语义),而不是 Zig `@round`
// 的 half-away-from-zero —— 恰好落在 .5 的边界只有这一种差别。
//
// 与 Python 的另外两处**故意**差异(只影响脏输入,787 系统的真值表是干净的):
//   * 自环与重复边**忽略**(Python 那边 raise ValueError);
//   * 端点 >= system_count 返回 error,而不是 panic。
// 迭代式 Tarjan 避免 787 帧递归;桥两端都标 bridge_endpoint;根的割点规则 = DFS 子数 > 1。

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Edge = struct { a: u16, b: u16 };

pub const Metrics = struct {
    scores: []u16, // len = system_count
    articulation: []u8, // 0/1
    bridge_endpoint: []u8, // 0/1
};

pub const Error = error{
    /// `edges.len == 0`: 空边表没有可度量的图。
    NoEdges,
    /// 三个输出切片的长度必须都等于 `system_count`。
    LengthMismatch,
    /// 某条边的端点不在 `0..system_count` 内。
    EndpointOutOfRange,
};

/// 把 `edges` 度量进调用方提供的 `out`(三片长度均为 `system_count`;
/// `out.scores` 被夹到 u16)。scratch 只用 `allocator`,全部 defer-free。
pub fn analyze(
    allocator: Allocator,
    edges: []const Edge,
    system_count: usize,
    out: Metrics,
) (Error || Allocator.Error)!void {
    if (edges.len == 0) return error.NoEdges;
    if (out.scores.len != system_count or
        out.articulation.len != system_count or
        out.bridge_endpoint.len != system_count)
        return error.LengthMismatch;

    @memset(out.scores, 0);
    @memset(out.articulation, 0);
    @memset(out.bridge_endpoint, 0);

    const n = system_count;

    // --- 1) 规范化 (a<b) + 端点范围校验。 -------------------------------------
    const pairs = try allocator.alloc(Edge, edges.len);
    defer allocator.free(pairs);
    for (edges, 0..) |e, i| {
        if (@as(usize, e.a) >= n or @as(usize, e.b) >= n)
            return error.EndpointOutOfRange;
        pairs[i] = if (e.a < e.b) .{ .a = e.a, .b = e.b } else .{ .a = e.b, .b = e.a };
    }
    std.mem.sort(Edge, pairs, {}, edgeLess);

    // --- 2) 去自环 + 去重(排序后重复必相邻)。 --------------------------------
    var unique: usize = 0;
    for (pairs) |p| {
        if (p.a == p.b) continue;
        if (unique > 0 and pairs[unique - 1].a == p.a and pairs[unique - 1].b == p.b) continue;
        pairs[unique] = p;
        unique += 1;
    }
    const ue = pairs[0..unique];

    // --- 3) CSR(每个节点的邻居严格升序,与 Python 的 sorted(adjacency) 同序)。 --
    const offsets = try allocator.alloc(u32, n + 1);
    defer allocator.free(offsets);
    @memset(offsets, 0);
    for (ue) |p| {
        offsets[p.a] += 1;
        offsets[p.b] += 1;
    }
    {
        var running: u32 = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const d = offsets[i];
            offsets[i] = running;
            running += d;
        }
        offsets[n] = running;
    }
    const total: usize = offsets[n];
    const targets = try allocator.alloc(u32, total);
    defer allocator.free(targets);
    const fill = try allocator.alloc(u32, n);
    defer allocator.free(fill);
    @memcpy(fill, offsets[0..n]);
    // ue 已按 (a,b) 升序:节点 a 按 b 升序收邻居,节点 b 按 a 升序收邻居,
    // 两段都单调,合起来仍严格升序。
    for (ue) |p| {
        targets[fill[p.a]] = p.b;
        fill[p.a] += 1;
        targets[fill[p.b]] = p.a;
        fill[p.b] += 1;
    }

    // --- 4) Brandes 无权无向中心性(每对只算一次,事后 /2)。 -------------------
    const dist = try allocator.alloc(i32, n);
    defer allocator.free(dist);
    const paths = try allocator.alloc(f64, n);
    defer allocator.free(paths);
    const dep = try allocator.alloc(f64, n);
    defer allocator.free(dep);
    const stack = try allocator.alloc(u32, n);
    defer allocator.free(stack);
    const queue = try allocator.alloc(u32, n);
    defer allocator.free(queue);
    // predecessor 列表用侵入式单链(保持追加顺序 —— 累加次序影响浮点末位)。
    const pred_head = try allocator.alloc(i32, n);
    defer allocator.free(pred_head);
    const pred_tail = try allocator.alloc(i32, n);
    defer allocator.free(pred_tail);
    const pred_cap: usize = total + 1; // 每个 BFS 有向边至多贡献一个 predecessor 槽
    const pred_next = try allocator.alloc(i32, pred_cap);
    defer allocator.free(pred_next);
    const pred_node = try allocator.alloc(u32, pred_cap);
    defer allocator.free(pred_node);
    const betweenness = try allocator.alloc(f64, n);
    defer allocator.free(betweenness);
    @memset(betweenness, 0);

    var source: usize = 0;
    while (source < n) : (source += 1) {
        @memset(dist, -1);
        @memset(paths, 0);
        @memset(dep, 0);
        @memset(pred_head, -1);
        @memset(pred_tail, -1);
        var pred_len: usize = 0;

        dist[source] = 0;
        paths[source] = 1;
        var qh: usize = 0;
        var qt: usize = 0;
        queue[qt] = @intCast(source);
        qt += 1;
        var stack_len: usize = 0;

        while (qh < qt) {
            const node = queue[qh];
            qh += 1;
            stack[stack_len] = node;
            stack_len += 1;
            const dn = dist[node];
            var k: usize = offsets[node];
            const kend: usize = offsets[node + 1];
            while (k < kend) : (k += 1) {
                const nb = targets[k];
                if (dist[nb] < 0) {
                    dist[nb] = dn + 1;
                    queue[qt] = nb;
                    qt += 1;
                }
                if (dist[nb] == dn + 1) {
                    paths[nb] += paths[node];
                    const slot: i32 = @intCast(pred_len);
                    pred_node[pred_len] = node;
                    pred_next[pred_len] = -1;
                    if (pred_head[nb] < 0) {
                        pred_head[nb] = slot;
                    } else {
                        pred_next[@intCast(pred_tail[nb])] = slot;
                    }
                    pred_tail[nb] = slot;
                    pred_len += 1;
                }
            }
        }

        // 按栈的逆序回代依赖,与 Python 的 while stack: node=stack.pop() 同序。
        var i = stack_len;
        while (i > 0) {
            i -= 1;
            const node = stack[i];
            const pn = paths[node];
            var s = pred_head[node];
            while (s >= 0) {
                const prev = pred_node[@intCast(s)];
                dep[prev] += (paths[prev] / pn) * (1.0 + dep[node]);
                s = pred_next[@intCast(s)];
            }
            if (@as(usize, node) != source) betweenness[node] += dep[node];
        }
    }

    for (betweenness) |*b| b.* /= 2.0;

    // --- 5) 归一化 + 取整。 ---------------------------------------------------
    var denom: f64 = 0;
    if (n > 2) {
        const num: u64 = @as(u64, n - 1) * @as(u64, n - 2);
        denom = @as(f64, @floatFromInt(num)) / 2.0;
    }
    for (0..n) |node| {
        const normalized = if (denom > 0) betweenness[node] / denom else 0.0;
        out.scores[node] = roundScore(1000.0 * normalized);
    }

    // --- 6) 迭代式 Tarjan(割点 + 桥)。 --------------------------------------
    const disc = try allocator.alloc(i32, n);
    defer allocator.free(disc);
    const low = try allocator.alloc(i32, n);
    defer allocator.free(low);
    const parent = try allocator.alloc(i32, n);
    defer allocator.free(parent);
    const frame_node = try allocator.alloc(u32, n);
    defer allocator.free(frame_node);
    const frame_idx = try allocator.alloc(usize, n);
    defer allocator.free(frame_idx);
    @memset(disc, -1);

    var clock: i32 = 0;
    var root: usize = 0;
    while (root < n) : (root += 1) {
        if (disc[root] != -1) continue;
        parent[root] = -1;
        disc[root] = clock;
        low[root] = clock;
        clock += 1;
        var root_children: u32 = 0;

        var sp: usize = 0;
        frame_node[0] = @intCast(root);
        frame_idx[0] = 0;
        while (true) {
            const node = frame_node[sp];
            const kstart: usize = offsets[node];
            const kend: usize = offsets[node + 1];
            var i = frame_idx[sp];
            var descended = false;
            while (kstart + i < kend) {
                const nb = targets[kstart + i];
                i += 1;
                if (disc[nb] == -1) {
                    frame_idx[sp] = i;
                    parent[nb] = @intCast(node);
                    disc[nb] = clock;
                    low[nb] = clock;
                    clock += 1;
                    if (@as(usize, node) == root) root_children += 1;
                    sp += 1;
                    frame_node[sp] = nb;
                    frame_idx[sp] = 0;
                    descended = true;
                    break;
                }
                if (@as(i32, @intCast(nb)) != parent[node]) {
                    if (disc[nb] < low[node]) low[node] = disc[nb];
                }
            }
            if (descended) continue;
            if (sp == 0) break;
            sp -= 1;
            const pnode = frame_node[sp];
            if (low[node] < low[pnode]) low[pnode] = low[node];
            if (low[node] > disc[pnode]) {
                out.bridge_endpoint[@min(node, pnode)] = 1;
                out.bridge_endpoint[@max(node, pnode)] = 1;
            }
            if (pnode != @as(u32, @intCast(root)) and low[node] >= disc[pnode])
                out.articulation[pnode] = 1;
        }
        if (root_children > 1) out.articulation[root] = 1;
    }
}

fn edgeLess(_: void, l: Edge, r: Edge) bool {
    if (l.a != r.a) return l.a < r.a;
    return l.b < r.b;
}

/// `round(1000 * normalized)` 的 Python 语义:非负、half-to-even、夹到 u16。
fn roundScore(x: f64) u16 {
    const fl = @floor(x);
    const frac = x - fl;
    var rounded = fl;
    if (frac > 0.5) {
        rounded = fl + 1.0;
    } else if (frac == 0.5) {
        // 恰好 .5:取偶数(round-half-to-even)。fl 保持原值则不加。
        const fi: i64 = @intFromFloat(fl);
        if (@mod(fi, 2) != 0) rounded = fl + 1.0;
    }
    if (rounded <= 0) return 0;
    if (rounded >= 65535.0) return 65535;
    return @intFromFloat(rounded);
}
