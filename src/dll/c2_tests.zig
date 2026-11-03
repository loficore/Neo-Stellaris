// c2_tests.zig — test root for the c2/ read-only guards.
//
// The probes live in src/dll/c2 and import ../shared/offsets.zig and ../hooking/*, which a
// module rooted at src/dll/c2 cannot reach (Zig rejects imports escaping the module path).
// Rooting here keeps every import inside src/dll and avoids main.zig's QuickJS C linkage —
// the same reason `scripted_tests.zig` exists for src/dll/scripted.

const std = @import("std");

const trigger_eval = @import("c2/trigger_eval_probe.zig");
const per_system = @import("c2/per_system_probe.zig");
const neo_effect = @import("c2/neo_effect.zig");
const neo_vtable = @import("c2/neo_vtable.zig");
const neo_dispatch = @import("c2/neo_dispatch.zig");
const neo_state = @import("c2/neo_state.zig");
const chokepoint_dynamic = @import("c2/chokepoint_dynamic.zig");
const graph_fixture = @import("c2/graph_fixture.zig");
const galaxy_graph = @import("c2/galaxy_graph.zig");
const offsets = @import("shared/offsets.zig");

comptime {
    _ = trigger_eval;
    _ = per_system;
    _ = neo_effect;
    _ = neo_vtable;
    _ = neo_dispatch;
    _ = neo_state;
    _ = chokepoint_dynamic;
    _ = graph_fixture;
    _ = galaxy_graph;
    _ = offsets;
}

test {
    _ = std.testing.refAllDecls(@This());
}

// ---------------------------------------------------------------------------
// chokepoint_dynamic: pure Brandes + Tarjan graph metrics
// ---------------------------------------------------------------------------

const cd = chokepoint_dynamic;
const fx = graph_fixture;

test "chokepoint_dynamic: three-node chain centre outranks the ends" {
    var scores: [3]u16 = undefined;
    var art: [3]u8 = undefined;
    var bri: [3]u8 = undefined;
    var edges = [_]cd.Edge{ .{ .a = 0, .b = 1 }, .{ .a = 1, .b = 2 } };
    try cd.analyze(std.testing.allocator, &edges, 3, .{
        .scores = &scores,
        .articulation = &art,
        .bridge_endpoint = &bri,
    });
    // Brandes on a 3-chain: only the pair {0,2} runs through node 1, and the
    // denominator is (3-1)(3-2)/2 = 1, so score[1] = round(1000 * (1 / 1)) = 1000.
    try std.testing.expectEqual(@as(u16, 1000), scores[1]);
    try std.testing.expectEqual(@as(u16, 0), scores[0]);
    try std.testing.expectEqual(@as(u16, 0), scores[2]);
    try std.testing.expect(scores[1] > scores[0]);
    try std.testing.expect(scores[1] > scores[2]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 0 }, &art);
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 1 }, &bri);
}

test "chokepoint_dynamic: self-loops and duplicate edges are ignored" {
    var scores: [3]u16 = undefined;
    var art: [3]u8 = undefined;
    var bri: [3]u8 = undefined;

    // One real edge plus a reversed duplicate plus a self-loop must measure the
    // same as the single-edge graph (all three outputs).
    var noisy = [_]cd.Edge{ .{ .a = 0, .b = 1 }, .{ .a = 1, .b = 0 }, .{ .a = 1, .b = 1 } };
    var clean = [_]cd.Edge{.{ .a = 0, .b = 1 }};
    var ns: [3]u16 = undefined;
    var na: [3]u8 = undefined;
    var nb: [3]u8 = undefined;
    try cd.analyze(std.testing.allocator, &noisy, 3, .{
        .scores = &ns,
        .articulation = &na,
        .bridge_endpoint = &nb,
    });
    try cd.analyze(std.testing.allocator, &clean, 3, .{
        .scores = &scores,
        .articulation = &art,
        .bridge_endpoint = &bri,
    });
    try std.testing.expectEqualSlices(u16, &scores, &ns);
    try std.testing.expectEqualSlices(u8, &art, &na);
    try std.testing.expectEqualSlices(u8, &bri, &nb);

    // The same noise bolted onto the 3-chain leaves the chain result intact.
    var chain = [_]cd.Edge{ .{ .a = 0, .b = 1 }, .{ .a = 1, .b = 2 } };
    var chain_noisy = [_]cd.Edge{
        .{ .a = 0, .b = 1 },
        .{ .a = 1, .b = 2 },
        .{ .a = 1, .b = 0 },
        .{ .a = 1, .b = 1 },
    };
    var cs: [3]u16 = undefined;
    var ca: [3]u8 = undefined;
    var cb: [3]u8 = undefined;
    var xs: [3]u16 = undefined;
    var xa: [3]u8 = undefined;
    var xb: [3]u8 = undefined;
    try cd.analyze(std.testing.allocator, &chain, 3, .{
        .scores = &cs,
        .articulation = &ca,
        .bridge_endpoint = &cb,
    });
    try cd.analyze(std.testing.allocator, &chain_noisy, 3, .{
        .scores = &xs,
        .articulation = &xa,
        .bridge_endpoint = &xb,
    });
    try std.testing.expectEqualSlices(u16, &cs, &xs);
    try std.testing.expectEqualSlices(u8, &ca, &xa);
    try std.testing.expectEqualSlices(u8, &cb, &xb);
}

test "chokepoint_dynamic: an empty edge list is error.NoEdges" {
    var scores: [3]u16 = undefined;
    var art: [3]u8 = undefined;
    var bri: [3]u8 = undefined;
    try std.testing.expectError(error.NoEdges, cd.analyze(
        std.testing.allocator,
        &[_]cd.Edge{},
        3,
        .{ .scores = &scores, .articulation = &art, .bridge_endpoint = &bri },
    ));
}

test "chokepoint_dynamic: an endpoint outside the system range is an error" {
    var scores: [3]u16 = undefined;
    var art: [3]u8 = undefined;
    var bri: [3]u8 = undefined;
    var edges = [_]cd.Edge{.{ .a = 0, .b = 3 }};
    try std.testing.expectError(error.EndpointOutOfRange, cd.analyze(
        std.testing.allocator,
        &edges,
        3,
        .{ .scores = &scores, .articulation = &art, .bridge_endpoint = &bri },
    ));
}

test "chokepoint_dynamic: an isolated system counts toward the denominator and scores 0" {
    // n = system_count = 4 (this module's contract), NOT len(adjacency) = 3:
    // the denominator is (4-1)(4-2)/2 = 3, so score[1] = round(1000 * (1 / 3)) = 333.
    // The offline tool normalises by len(adjacency) = 3 and would print 1000 here —
    // the two agree only when every system has degree >= 1 (true for the fixture).
    var scores: [4]u16 = undefined;
    var art: [4]u8 = undefined;
    var bri: [4]u8 = undefined;
    var edges = [_]cd.Edge{ .{ .a = 0, .b = 1 }, .{ .a = 1, .b = 2 } };
    try cd.analyze(std.testing.allocator, &edges, 4, .{
        .scores = &scores,
        .articulation = &art,
        .bridge_endpoint = &bri,
    });
    try std.testing.expectEqualSlices(u16, &.{ 0, 333, 0, 0 }, &scores);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 0, 0 }, &art);
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 1, 0 }, &bri);
}

test "chokepoint_dynamic: output slices shorter than system_count are error.LengthMismatch" {
    var scores: [2]u16 = undefined;
    var art: [3]u8 = undefined;
    var bri: [3]u8 = undefined;
    var edges = [_]cd.Edge{.{ .a = 0, .b = 1 }};
    try std.testing.expectError(error.LengthMismatch, cd.analyze(
        std.testing.allocator,
        &edges,
        3,
        .{ .scores = &scores, .articulation = &art, .bridge_endpoint = &bri },
    ));
}

test "chokepoint_dynamic: synthetic fixture matches the offline scores" {
    const alloc = std.testing.allocator;
    const edges = try alloc.alloc(cd.Edge, fx.EDGE_COUNT);
    defer alloc.free(edges);
    for (fx.edges, 0..) |e, i| edges[i] = .{ .a = e[0], .b = e[1] };

    var scores: [fx.SYSTEM_COUNT]u16 = undefined;
    var art: [fx.SYSTEM_COUNT]u8 = undefined;
    var bri: [fx.SYSTEM_COUNT]u8 = undefined;
    try cd.analyze(alloc, edges, fx.SYSTEM_COUNT, .{
        .scores = &scores,
        .articulation = &art,
        .bridge_endpoint = &bri,
    });
    try std.testing.expectEqualSlices(u16, &fx.expected_scores, &scores);
    try std.testing.expectEqualSlices(u8, &fx.expected_articulation, &art);
    try std.testing.expectEqualSlices(u8, &fx.expected_bridge_endpoint, &bri);
}

// ---------------------------------------------------------------------------
// galaxy_graph: 只读读图器(合成内存镜像)
//
// 镜像是一个 little-endian 的字节区,边界检查得像真内存:任何越界读都会置
// `escaped`,于是测试能断言读图器从不走出结构(每一次解引用都经过 Memory.read)。
// 偏移全部取自 `offsets.graph`,所以镜像与读图器不会各走各的。
//
// 表项按 §1.11 的 **16 字节记录**布:记录 `+8` 是系统对象指针。
// 「诱饵位」`table + slot*8 + 8` 是 8 字节步长实现会读到的地方(见 `setDecoy`),
// 用专门的回归测试盯着它 —— 步长写错时,读图器会静默读到别的对象,而不报错。
// ---------------------------------------------------------------------------

const gg = galaxy_graph;
const gg_off = offsets.graph;

const Mirror = struct {
    const BASE: usize = 0x1_0000_0000;
    const SIZE: usize = 0x4_0000;
    /// 索引对象:`+0x18` 槽表指针、`+0x20` 槽数上界。
    const GALAXY: usize = BASE + 0x0000;
    /// 槽表:表头 8 字节(不是槽),之后每槽一个 qword。
    const TABLE: usize = BASE + 0x0100;
    /// 每个槽一份系统对象(要盖到 `+0x588` 的边容器)。
    const SYSOBJ: usize = BASE + 0x1000;
    const SYSOBJ_STRIDE: usize = 0x800;
    /// 每个槽一份边元素块(步长 0x20)。
    const EDGES: usize = BASE + 0x2_1000;
    const EDGE_BLOCK: usize = 0x200;
    /// 诱饵记录区(8 字节步长实现的陷阱),见 `setDecoy`。
    const DECOY: usize = BASE + 0x3_0000;
    const DECOY_STRIDE: usize = 0x100;

    buf: [SIZE]u8 = [_]u8{0} ** SIZE,
    /// 让这个地址上的读失败(0 = 不失败)。
    fail_at: usize = 0,
    /// 把所有边元素块整体平移:用来证明读图器没有缓存**指针**。
    edge_bump: usize = 0,
    /// 读出了镜像区域 —— 读图器走出了结构。
    escaped: bool = false,
    escaped_reads: usize = 0,

    fn read(ctx: *anyopaque, addr: usize, len: usize, buf: []u8) bool {
        const self: *Mirror = @ptrCast(@alignCast(ctx));
        if (addr < BASE or len > SIZE or addr - BASE > SIZE - len) {
            self.escaped = true;
            self.escaped_reads += 1;
            return false;
        }
        if (self.fail_at != 0 and addr == self.fail_at) return false;
        @memcpy(buf, self.buf[addr - BASE ..][0..len]);
        return true;
    }
};

fn mirrorMemory(m: *Mirror) gg.Memory {
    return .{ .ctx = @ptrCast(m), .read = Mirror.read };
}

fn objAddr(slot: usize) usize {
    return Mirror.SYSOBJ + slot * Mirror.SYSOBJ_STRIDE;
}

fn edgeAddr(slot: usize, k: usize) usize {
    return Mirror.EDGES + slot * Mirror.EDGE_BLOCK + k * gg_off.EDGE_STRIDE;
}

fn elemIdAddr(slot: usize, k: usize) usize {
    return edgeAddr(slot, k) + gg_off.EDGE_ID_OFF;
}

fn slotAddr(slot: usize) usize {
    // §1.11: records are 16 B; the entry pointer sits at record +8.
    return Mirror.TABLE + slot * gg_off.TABLE_RECORD_SIZE + gg_off.TABLE_SLOT_PTR_OFF;
}

/// 8 字节步长实现会读到的「诱饵位」:`table + slot*8 + 8`。
/// (只有奇数槽适用:偶数槽的 `slot*8+8` 正好压在真指针上。)
fn decoySlotAddr(slot: usize) usize {
    return Mirror.TABLE + slot * 8 + 8;
}

fn decoyObjAddr(k: usize) usize {
    return Mirror.DECOY + k * Mirror.DECOY_STRIDE;
}

/// 在 `table + slot*8 + 8` 放一个指针,指向 id 与 `slot` **不匹配**的记录。
/// 16 字节步长的正确实现永远不读这一格;8 字节步长的实现会读到它并因此算错。
fn setDecoy(m: *Mirror, slot: usize, k: usize, id: u32) void {
    putQword(m, decoySlotAddr(slot), decoyObjAddr(k));
    putDword(m, decoyObjAddr(k) + gg_off.SYSTEM_ID_OFF, id);
}

fn putBytes(m: *Mirror, addr: usize, bytes: []const u8) void {
    @memcpy(m.buf[addr - Mirror.BASE ..][0..bytes.len], bytes);
}

fn putDword(m: *Mirror, addr: usize, v: u32) void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    putBytes(m, addr, &b);
}

fn putQword(m: *Mirror, addr: usize, v: usize) void {
    var b: [@sizeOf(usize)]u8 = undefined;
    std.mem.writeInt(usize, &b, v, .little);
    putBytes(m, addr, &b);
}

fn setGalaxy(m: *Mirror, bound: u32, table: usize) void {
    putQword(m, Mirror.GALAXY + gg_off.INDEX_TABLE_OFF, table);
    putDword(m, Mirror.GALAXY + gg_off.INDEX_BOUND_OFF, bound);
}

/// 把 id 放进槽 `slot`,邻居写进它自己的边容器(§1.3/§2.2 的形状)。
fn setSystem(m: *Mirror, slot: usize, id: u32, neighbours: []const u32) void {
    const obj = objAddr(slot);
    putQword(m, slotAddr(slot), obj);
    putDword(m, obj + gg_off.SYSTEM_ID_OFF, id);
    putQword(m, obj + gg_off.EDGE_DATA_OFF, edgeAddr(slot, 0) + m.edge_bump);
    putDword(m, obj + gg_off.EDGE_CAPACITY_OFF, @intCast(neighbours.len));
    putDword(m, obj + gg_off.EDGE_COUNT_OFF, @intCast(neighbours.len));
    for (neighbours, 0..) |n, k| putDword(m, elemIdAddr(slot, k) + m.edge_bump, n);
}

fn expectEdges(expected: []const [2]u16, actual: []const gg.Edge) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |e, a| {
        try std.testing.expectEqual(e[0], a.a);
        try std.testing.expectEqual(e[1], a.b);
    }
}

test "galaxy_graph: three systems, two edges, read out of a synthetic mirror" {
    var m = Mirror{};
    setGalaxy(&m, 3, Mirror.TABLE);
    // 引擎的 add_hyperlane 是无向的:每条边在两端各存一次(§1.3)。
    setSystem(&m, 0, 0, &.{1});
    setSystem(&m, 1, 1, &.{ 0, 2 });
    setSystem(&m, 2, 2, &.{1});

    var out: [8]gg.Edge = undefined;
    const stats = try gg.readGraph(mirrorMemory(&m), Mirror.GALAXY, &out);

    try std.testing.expectEqual(@as(usize, 3), stats.systems);
    try std.testing.expectEqual(@as(usize, 2), stats.edges);
    try std.testing.expectEqual(@as(usize, 0), stats.skipped);
    try expectEdges(&.{ .{ 0, 1 }, .{ 1, 2 } }, out[0..stats.edges]);
    try std.testing.expect(!m.escaped);
}

test "galaxy_graph: an unreadable neighbour id is skipped, not fatal" {
    var m = Mirror{};
    setGalaxy(&m, 3, Mirror.TABLE);
    setSystem(&m, 0, 0, &.{1});
    setSystem(&m, 1, 1, &.{ 0, 2 });
    setSystem(&m, 2, 2, &.{1});

    var out: [8]gg.Edge = undefined;
    const baseline = try gg.readGraph(mirrorMemory(&m), Mirror.GALAXY, &out);
    try std.testing.expectEqual(@as(usize, 0), baseline.skipped);
    try std.testing.expectEqual(@as(usize, 2), baseline.edges);

    // 让系统 0 的第一个邻居 id 读不出来(别的地址不受影响)。
    m.fail_at = elemIdAddr(0, 0);
    var out2: [8]gg.Edge = undefined;
    const stats = try gg.readGraph(mirrorMemory(&m), Mirror.GALAXY, &out2);

    try std.testing.expectEqual(@as(usize, 1), stats.skipped);
    try std.testing.expectEqual(@as(usize, 3), stats.systems);
    // 边 0-1 仍然从系统 1 那一侧读到 —— 跳过的是**元素**,不是整条边。
    try std.testing.expectEqual(@as(usize, 2), stats.edges);
    try expectEdges(&.{ .{ 0, 1 }, .{ 1, 2 } }, out2[0..stats.edges]);
    try std.testing.expect(!m.escaped);
}

test "galaxy_graph: sparse ids resolve through the table, never as slot indices" {
    var m = Mirror{};
    // 43 个槽,只有 3 个活着 —— 稀疏表是引擎的常态(id 空间只增不减)。
    setGalaxy(&m, 43, Mirror.TABLE);
    setSystem(&m, 0, 0, &.{ 7, 20, 3 }); // 7 能解析;20 是空槽;3 命中陈旧表项
    setSystem(&m, 7, 7, &.{ 0, 42 });
    setSystem(&m, 42, 42, &.{7});
    // 槽 3 上放一个 id=5 的表项:5 自己查表会落到槽 5,落不到槽 3,
    // 所以引擎自己的 lookup 也永远返回不了它(§1.2 的 `entry+8 == id`)。
    setSystem(&m, 3, 5, &.{});

    var out: [8]gg.Edge = undefined;
    const stats = try gg.readGraph(mirrorMemory(&m), Mirror.GALAXY, &out);

    try std.testing.expectEqual(@as(usize, 3), stats.systems);
    try std.testing.expectEqual(@as(usize, 2), stats.edges);
    // 丢弃项:陈旧表项 1 个 + 解析不上的邻居 id 2 个(20、3)。
    try std.testing.expectEqual(@as(usize, 3), stats.skipped);
    try expectEdges(&.{ .{ 0, 7 }, .{ 7, 42 } }, out[0..stats.edges]);
    try std.testing.expect(!m.escaped);
}

test "galaxy_graph: no cross-call caching of edges or pointers" {
    var m = Mirror{};
    setGalaxy(&m, 3, Mirror.TABLE);
    setSystem(&m, 0, 0, &.{1});
    setSystem(&m, 1, 1, &.{ 0, 2 });
    setSystem(&m, 2, 2, &.{1});

    var out1: [8]gg.Edge = undefined;
    const first = try gg.readGraph(mirrorMemory(&m), Mirror.GALAXY, &out1);
    try std.testing.expectEqual(@as(usize, 2), first.edges);
    try expectEdges(&.{ .{ 0, 1 }, .{ 1, 2 } }, out1[0..first.edges]);

    // 把边 1-2 改成 0-2,并且**换一个边数组**(edge_bump 让数据指针也变):
    // 缓存过边值或缓存过指针的实现都会在这里露馅。
    m.edge_bump = 0x100;
    setSystem(&m, 0, 0, &.{ 1, 2 });
    setSystem(&m, 1, 1, &.{0});
    setSystem(&m, 2, 2, &.{0});

    var out2: [8]gg.Edge = undefined;
    const second = try gg.readGraph(mirrorMemory(&m), Mirror.GALAXY, &out2);
    try std.testing.expectEqual(@as(usize, 3), second.systems);
    try std.testing.expectEqual(@as(usize, 2), second.edges);
    try expectEdges(&.{ .{ 0, 1 }, .{ 0, 2 } }, out2[0..second.edges]);
    try std.testing.expect(!m.escaped);
}

test "galaxy_graph: a short out buffer is error.BufferTooSmall, not a silent truncation" {
    var m = Mirror{};
    setGalaxy(&m, 3, Mirror.TABLE);
    setSystem(&m, 0, 0, &.{1});
    setSystem(&m, 1, 1, &.{ 0, 2 });
    setSystem(&m, 2, 2, &.{1});

    var out: [1]gg.Edge = undefined;
    try std.testing.expectError(error.BufferTooSmall, gg.readGraph(
        mirrorMemory(&m),
        Mirror.GALAXY,
        &out,
    ));
    // 写下的那一段是枚举序的确定性前缀,不是"截断后当成成功"。
    try expectEdges(&.{.{ 0, 1 }}, &out);

    var exact: [2]gg.Edge = undefined;
    const stats = try gg.readGraph(mirrorMemory(&m), Mirror.GALAXY, &exact);
    try std.testing.expectEqual(@as(usize, 2), stats.edges);
    try expectEdges(&.{ .{ 0, 1 }, .{ 1, 2 } }, exact[0..stats.edges]);
}

test "galaxy_graph: an absurd edge count is capped, never walked" {
    var m = Mirror{};
    setGalaxy(&m, 2, Mirror.TABLE);
    setSystem(&m, 0, 0, &.{1});
    setSystem(&m, 1, 1, &.{0});
    // 容器头谎报 100_000 个邻居,而它的块里只有一个。
    putDword(&m, objAddr(0) + gg_off.EDGE_COUNT_OFF, 100_000);

    var out: [8]gg.Edge = undefined;
    const stats = try gg.readGraph(mirrorMemory(&m), Mirror.GALAXY, &out);

    try std.testing.expectEqual(@as(usize, 1), stats.skipped);
    try std.testing.expectEqual(@as(usize, 2), stats.systems);
    // 边仍然从系统 1 那一侧读到;走坏的那个容器整段被跳过。
    try expectEdges(&.{.{ 0, 1 }}, out[0..stats.edges]);
    try std.testing.expect(!m.escaped);
}

test "galaxy_graph: an unreadable index header is an error, not an empty graph" {
    var m = Mirror{};
    setGalaxy(&m, 3, Mirror.TABLE);
    var out: [8]gg.Edge = undefined;
    m.fail_at = Mirror.GALAXY + gg_off.INDEX_TABLE_OFF;
    try std.testing.expectError(error.UnreadableIndex, gg.readGraph(
        mirrorMemory(&m),
        Mirror.GALAXY,
        &out,
    ));
    try std.testing.expect(!m.escaped);
}

test "galaxy_graph: the table record stride is 16 bytes, not 8" {
    var m = Mirror{};
    setGalaxy(&m, 4, Mirror.TABLE);
    // 活着的槽取奇数(1 与 3):偶数槽的诱饵位 `slot*8+8` 正好压在真指针上,布不了诱饵。
    setSystem(&m, 1, 1, &.{3});
    setSystem(&m, 3, 3, &.{1});
    // 诱饵:8 字节步长的实现会读到 `table + slot*8 + 8`,拿到 id 不匹配的记录。
    setDecoy(&m, 1, 0, 0x1111);
    setDecoy(&m, 3, 1, 0x2222);

    var out: [8]gg.Edge = undefined;
    const stats = try gg.readGraph(mirrorMemory(&m), Mirror.GALAXY, &out);

    // 16 字节步长:槽 1 与槽 3 都活着,一条无向边 1-3,没有丢弃项。
    try std.testing.expectEqual(@as(usize, 2), stats.systems);
    try std.testing.expectEqual(@as(usize, 1), stats.edges);
    try std.testing.expectEqual(@as(usize, 0), stats.skipped);
    try expectEdges(&.{.{ 1, 3 }}, out[0..stats.edges]);
    // 8 字节步长的实现会在这里读到诱饵(两个槽都变成不匹配 ⇒ systems=0/edges=0/skipped=3)。
    try std.testing.expect(!m.escaped);
}

test "galaxy_graph: a null index object or a null table is error.UnreadableIndex" {
    var m = Mirror{};
    setGalaxy(&m, 3, Mirror.TABLE);
    var out: [8]gg.Edge = undefined;

    // galaxy == 0:连头部都不该去读(地址 0x20 不在镜像里,读了就会 escaped)。
    try std.testing.expectError(error.UnreadableIndex, gg.readGraph(
        mirrorMemory(&m),
        0,
        &out,
    ));
    // 表指针为空:索引对象在,但它没有表 —— 这不是「没有边」。
    setGalaxy(&m, 3, 0);
    try std.testing.expectError(error.UnreadableIndex, gg.readGraph(
        mirrorMemory(&m),
        Mirror.GALAXY,
        &out,
    ));
    try std.testing.expect(!m.escaped);
}

test "galaxy_graph: a zero slot bound is error.UnreadableIndex, not an empty graph" {
    var m = Mirror{};
    setGalaxy(&m, 0, Mirror.TABLE);
    var out: [8]gg.Edge = undefined;
    try std.testing.expectError(error.UnreadableIndex, gg.readGraph(
        mirrorMemory(&m),
        Mirror.GALAXY,
        &out,
    ));
    try std.testing.expect(!m.escaped);
}

test "galaxy_graph: a count beyond the container capacity is skipped, never walked" {
    var m = Mirror{};
    setGalaxy(&m, 3, Mirror.TABLE);
    // 系统 0 的容器头说 2 个元素,但只分配了 1 个(capacity = 1)。
    setSystem(&m, 0, 0, &.{1});
    setSystem(&m, 1, 1, &.{});
    setSystem(&m, 2, 2, &.{});
    putDword(&m, objAddr(0) + gg_off.EDGE_COUNT_OFF, 2);
    // 第二个元素**读不出来**:读图器若按 count 走,要么读到它、要么在此处失败,
    // 两者都会让下面的断言(edges == 0)不成立。
    m.fail_at = elemIdAddr(0, 1);

    var out: [8]gg.Edge = undefined;
    const stats = try gg.readGraph(mirrorMemory(&m), Mirror.GALAXY, &out);

    // 容器头与分配不自洽 ⇒ 整段跳过,不按 count 走过分配边界。
    try std.testing.expectEqual(@as(usize, 1), stats.skipped);
    try std.testing.expectEqual(@as(usize, 3), stats.systems);
    // 系统 0 是唯一可能的边来源,它被跳过 ⇒ 一条边都没有。
    try std.testing.expectEqual(@as(usize, 0), stats.edges);
    try std.testing.expect(!m.escaped);
}
