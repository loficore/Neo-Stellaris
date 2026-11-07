// graph_probe.zig — 4.4.4 运行时星连图的**实机**只读探针 + 两个改边导出。
//
// 与 `galaxy_graph.zig` 的分工:那一模块是「给定读函数与索引对象地址,边表长什么样」;
// 本模块是「在活体进程里把这两个东西接上引擎」—— 解析 `stellaris.exe` 模块基址、从
// `[module_base + 0x3260B98]` 取系统索引对象、用 `windows.readProcessMemory`(进程内)
// 当 `Memory.read`,再把结果编码成驱动能读的字节。
//
// **不挂钩子**:没有任何 detour、没有 trampoline、没有引擎字节改动。唯一触碰引擎的是
// 两个显式导出(`mutateAdd` / `mutateRemove`),而且它们只调引擎**自己的**例程:
//   * `module_base + 0x8BBAA0` = `add_hyperlane` 的加边例程(`rcx=self, rdx=other`,
//     一次只加一个方向;引擎自己的执行体调两次,§1.1);
//   * `module_base + 0x8BBC20` = `remove_hyperlane` 的删边例程(`rcx=self, rdx=&id`,
//     同样两次,§1.1)。
// 计划正文把加边写作 `0x8BAA0`,那是漏了一个 `B`;`0x8bbb53 lea rcx,[rdi+0x588]` 这个
// 自动取证站点落在 `0x8BBAA0` 体内(§1.1),AGENTS 的 RVA 表同样写 `0x8BBAA0`。
//
// 偏移唯一来源是 `src/dll/shared/offsets.zig` 的 `graph` 段;本文件不重复数字,只把
// `layoutInto` 的八个词摊给驱动对账 —— 任何一格不等,驱动判 `instrument_broken`。
//
// **只读发的写面为零**:`readOnce` 只做 `ReadProcessMemory`,连引擎的对象头都不写。
// 静态缓冲在**我们自己的** `.data` 里,引擎的生命周期与本模块无关。
//
// 清空语义(Review Focus #3):每次 `readAt`/`readOnce` 先把 `snapshot`/`addresses` 归零,
// 再整趟重读 —— 不存在跨调用缓存;调用方拿到的 stats 与行数必然来自同一次枚举。
// 否则「先读计数再读缓冲」会把两次枚举缝成一套从未同时存在的边。

const std = @import("std");

const gg = @import("galaxy_graph.zig");
const windows = @import("../hooking/windows.zig");
const graph = @import("../shared/offsets.zig").graph;

pub const Edge = gg.Edge;
pub const Memory = gg.Memory;

/// 布局版本:驱动侧 `C5GraphLayout` 对账的第一格。改偏移就改它。
pub const LAYOUT_VERSION: u32 = 1;
/// `C5GraphStatsInto` 写的字节数:八个 u64。
pub const STATS_SIZE: usize = 64;
/// 边表容量:离线表 1,217 条的 3.4 倍余量。超了返回 `-3` 而不是截断。
pub const MAX_EDGES: usize = 4096;

/// 一次读的统计快照。字段口径与 `galaxy_graph.ReadStats` 逐项相同,只是去掉默认构造
/// 参数之外的行为 —— 它是给驱动编码用的值,不是枚举状态机。
pub const StatsSnapshot = struct {
    systems: usize = 0,
    edges: usize = 0,
    skipped: usize = 0,
    max_id: ?u16 = null,
};

/// 一次读用到的绝对地址(诊断用,写进 artifact 的 `#meta`)。
pub const Addresses = struct {
    index: u64 = 0,
    table: u64 = 0,
    bound: u64 = 0,
    module: u64 = 0,
};

/// 上一次 `readAt`/`readOnce` 的边集。`rows()` 的切片长度 = `snapshot.edges`。
var edges: [MAX_EDGES]Edge = undefined;
var snapshot: StatsSnapshot = .{};
var addresses: Addresses = .{};

pub fn lastStats() StatsSnapshot {
    return snapshot;
}

pub fn lastAddresses() Addresses {
    return addresses;
}

/// 上一次读的边集(已按 `(a, b)` 升序,见 `drainSorted`)。
pub fn rows() []const Edge {
    return edges[0..snapshot.edges];
}

/// 清掉上一发的 stats 与行数。不碰边表字节本身 —— 行数归零就等于清空。
pub fn reset() void {
    snapshot = .{};
    addresses = .{};
}

// ---------------------------------------------------------------------------
// 纯逻辑面(Linux 单测直接调)
// ---------------------------------------------------------------------------

/// 八个布局词,顺序即驱动的对账契约:
/// `[version, RVA_SYSTEM_INDEX_GLOBAL, INDEX_TABLE_OFF, INDEX_BOUND_OFF,
///   TABLE_RECORD_SIZE, TABLE_SLOT_PTR_OFF, EDGE_COUNT_OFF, EDGE_STRIDE]`。
pub fn layoutInto(out: *[8]u32) u32 {
    out.* = .{
        LAYOUT_VERSION,
        @intCast(graph.RVA_SYSTEM_INDEX_GLOBAL),
        @intCast(graph.INDEX_TABLE_OFF),
        @intCast(graph.INDEX_BOUND_OFF),
        @intCast(graph.TABLE_RECORD_SIZE),
        @intCast(graph.TABLE_SLOT_PTR_OFF),
        @intCast(graph.EDGE_COUNT_OFF),
        @intCast(graph.EDGE_STRIDE),
    };
    return 8;
}

/// 八个 u64:`systems, edges, skipped, max_id, index_ptr, table_ptr, bound, module_base`。
/// `max_id` 为 `null` 时写 `u64` 最大值 —— 0 是一个**合法**的系统 id,不能拿它当哨兵。
pub fn encodeStats(out: *[64]u8, s: StatsSnapshot, a: Addresses) void {
    std.mem.writeInt(u64, out[0..8], @intCast(s.systems), .little);
    std.mem.writeInt(u64, out[8..16], @intCast(s.edges), .little);
    std.mem.writeInt(u64, out[16..24], @intCast(s.skipped), .little);
    std.mem.writeInt(u64, out[24..32], if (s.max_id) |m| @as(u64, m) else std.math.maxInt(u64), .little);
    std.mem.writeInt(u64, out[32..40], a.index, .little);
    std.mem.writeInt(u64, out[40..48], a.table, .little);
    std.mem.writeInt(u64, out[48..56], a.bound, .little);
    std.mem.writeInt(u64, out[56..64], a.module, .little);
}

/// 每行 4 B:`u16 a`、`u16 b`。`rows.len * 4 > out.len` ⇒ 返回 `0xFFFF_FFFF` 且
/// **一个字节都不写**(短缓冲是拒读,不是截断)。
pub fn drainInto(out: []u8, rows_in: []const Edge) u32 {
    if (rows_in.len > out.len / 4) return 0xFFFF_FFFF;
    for (rows_in, 0..) |e, i| {
        std.mem.writeInt(u16, out[i * 4 ..][0..2], e.a, .little);
        std.mem.writeInt(u16, out[i * 4 + 2 ..][0..2], e.b, .little);
    }
    return @intCast(rows_in.len);
}

/// 把上一次的边集按 `(a, b)` 升序排好再 drain —— artifact 的逐行对账要确定性顺序,
/// 而枚举顺序依赖槽号与邻居顺序。插入排序:上界 4,096 行,而且边集近乎有序。
pub fn drainSorted(out: []u8) u32 {
    const live = edges[0..snapshot.edges];
    var i: usize = 1;
    while (i < live.len) : (i += 1) {
        const cur = live[i];
        var j = i;
        while (j > 0 and less(cur, live[j - 1])) : (j -= 1) live[j] = live[j - 1];
        live[j] = cur;
    }
    return drainInto(out, live);
}

fn less(a: Edge, b: Edge) bool {
    if (a.a != b.a) return a.a < b.a;
    return a.b < b.b;
}

/// 写 `snapshot` + `addresses` 的 64 B。缓冲不足返回 0(驱动按 `instrument_broken` 处理)。
pub fn statsInto(out: []u8) i32 {
    if (out.len < STATS_SIZE) return 0;
    const buf: *[64]u8 = @ptrCast(out.ptr);
    encodeStats(buf, snapshot, addresses);
    return STATS_SIZE;
}

// ---------------------------------------------------------------------------
// 读一趟(镜像可注入,Linux 单测走这条)
// ---------------------------------------------------------------------------

/// `gg.readGraph` 的两个错误原样透传:`UnreadableIndex` = 索引对象不可读/越界;
/// `BufferTooSmall` = 边表超过 `MAX_EDGES`。
pub fn readAt(mem: Memory, index: usize) gg.Error!void {
    reset();
    if (index == 0) return error.UnreadableIndex;
    // 头部的两个字段由本模块自己再读一次:不进 artifact 就没法回答「哪个对象是索引」。
    const bound = readDword(mem, gg.addAddr(index, graph.INDEX_BOUND_OFF) orelse
        return error.UnreadableIndex) orelse return error.UnreadableIndex;
    const table = readPtr(mem, gg.addAddr(index, graph.INDEX_TABLE_OFF) orelse
        return error.UnreadableIndex) orelse return error.UnreadableIndex;
    if (table == 0) return error.UnreadableIndex;

    const stats = try gg.readGraph(mem, index, &edges);
    // 边集与统计值来自**同一次**枚举:readGraph 的返回值就是那一趟的 stats。
    snapshot = .{
        .systems = stats.systems,
        .edges = stats.edges,
        .skipped = stats.skipped,
        .max_id = stats.max_id,
    };
    addresses = .{ .index = index, .table = table, .bound = bound, .module = 0 };
}

// ---------------------------------------------------------------------------
// 实机读一发(只有 Windows 侧会走;Linux 单测不引用这些函数)
// ---------------------------------------------------------------------------

/// `0` 成功且 `skipped == 0`;`-1` 模块基址取不到;`-2` 索引对象不可读/越界;
/// `-3` 边表超过内部容量;`-4` 读成功但有 `skipped`(带欠账的证据,不是失败)。
pub fn readOnce() i32 {
    reset();
    const module_base = @intFromPtr(windows.moduleFunction(0) catch return -1);
    const global = std.math.add(usize, module_base, graph.RVA_SYSTEM_INDEX_GLOBAL) catch return -1;
    var buf: [@sizeOf(usize)]u8 = undefined;
    if (!windows.readProcessMemory(global, &buf)) return -2;
    const index = std.mem.readInt(usize, &buf, .little);
    if (index == 0) return -2;

    readAt(memAdapter(), index) catch |err| return switch (err) {
        error.UnreadableIndex => -2,
        error.BufferTooSmall => -3,
    };
    addresses.module = module_base;
    return if (snapshot.skipped == 0) 0 else -4;
}

// ---------------------------------------------------------------------------
// 改边:只经引擎自己的两个例程
// ---------------------------------------------------------------------------

/// `0x8BBAA0` — §1.1 `01874726 call 0x1408bbaa0`(`rcx=self, rdx=other`)。
const RVA_ADD_EDGE: usize = 0x8BBAA0;
/// `0x8BBC20` — §1.1 `01874ccd call 0x1408bbc20`(`rcx=self, rdx=&id`)。
const RVA_REMOVE_EDGE: usize = 0x8BBC20;

/// `0` 成功;`-1`/`-2` 解析失败(from / to);`-3` 任一 id 超出被承认的 u16 空间。
pub fn mutateAdd(from: u32, to: u32) i32 {
    return mutate(from, to, .add);
}

pub fn mutateRemove(from: u32, to: u32) i32 {
    return mutate(from, to, .remove);
}

const Mode = enum { add, remove };

const Context = struct {
    module: usize,
    table: usize,
    bound: u32,
};

fn mutate(from: u32, to: u32, mode: Mode) i32 {
    // 端点是 u16(`Edge.a/.b`),而引擎的槽号 = `id & 0xFFFFFF` —— 对被承认的 id,
    // 那个掩码恒等。超出 u16 的 id 我们既读不回来也不该写进图里。
    if (from > std.math.maxInt(u16) or to > std.math.maxInt(u16)) return -3;
    const ctx = resolveContext() orelse return -1;
    const self = resolveIn(ctx, from) orelse return -1;
    const other = resolveIn(ctx, to) orelse return -2;

    switch (mode) {
        .add => {
            const add: *const fn (*anyopaque, *anyopaque) callconv(.c) void =
                @ptrFromInt(ctx.module + RVA_ADD_EDGE);
            // §1.1:引擎自己的执行体对无向边调两次(`self -> other` 与 `other -> self`)。
            // 只调一次会留下引擎从不产生的单向边;读路径虽会去重,但我们不留这种状态。
            add(@ptrFromInt(self), @ptrFromInt(other));
            add(@ptrFromInt(other), @ptrFromInt(self));
        },
        .remove => {
            const remove: *const fn (*anyopaque, *const u32) callconv(.c) void =
                @ptrFromInt(ctx.module + RVA_REMOVE_EDGE);
            // §1.1 `01874cbd`:先 `self` 删「另一端的 id」,再 `other` 删「自己的 id」。
            var other_id: u32 = to;
            remove(@ptrFromInt(self), &other_id);
            var self_id: u32 = from;
            remove(@ptrFromInt(other), &self_id);
        },
    }
    return 0;
}

fn resolveContext() ?Context {
    const module_base = @intFromPtr(windows.moduleFunction(0) catch return null);
    const global = std.math.add(usize, module_base, graph.RVA_SYSTEM_INDEX_GLOBAL) catch return null;
    var buf: [@sizeOf(usize)]u8 = undefined;
    if (!windows.readProcessMemory(global, &buf)) return null;
    const index = std.mem.readInt(usize, &buf, .little);
    if (index == 0) return null;

    const mem = memAdapter();
    const bound = readDword(mem, gg.addAddr(index, graph.INDEX_BOUND_OFF) orelse return null) orelse
        return null;
    const table = readPtr(mem, gg.addAddr(index, graph.INDEX_TABLE_OFF) orelse return null) orelse
        return null;
    if (table == 0) return null;
    return .{ .module = module_base, .table = table, .bound = bound };
}

/// §1.2 的查表形状:`slot = id`(u16 门内掩码恒等)⇒ `slot < bound`;
/// `entry = qword[table + slot*16 + 8]`;`dword[entry+8] == id` 才算命中。
fn resolveIn(ctx: Context, id: u32) ?usize {
    const mem = memAdapter();
    const slot: usize = id;
    if (slot >= ctx.bound) return null;
    const addr = gg.elemAddr(ctx.table, slot, graph.TABLE_RECORD_SIZE, graph.TABLE_SLOT_PTR_OFF) orelse
        return null;
    const entry = readPtr(mem, addr) orelse return null;
    if (entry == 0) return null;
    const entry_id = readDword(mem, gg.addAddr(entry, graph.SYSTEM_ID_OFF) orelse return null) orelse
        return null;
    return if (entry_id == id) entry else null;
}

/// 一个系统的**度数**:边容器头 `+0x59C` 的原始条数(§1.3/§2.2 容器口径)。
///
/// Runtime JS 的 `s.degree` 用它。只读:同一套 §1.2 查表 + **进程内**
/// `readProcessMemory`,不缓存、不改引擎字节。解析不上(u16 外、陈旧表项、
/// 未解析模块基址)返回 `null` —— JS 侧拿到 0,而不是一个伪造的度数。
pub fn systemDegree(id: u32) ?u32 {
    const ctx = resolveContext() orelse return null;
    const obj = resolveIn(ctx, id) orelse return null;
    return readDword(memAdapter(), gg.addAddr(obj, graph.EDGE_COUNT_OFF) orelse return null);
}

// ---------------------------------------------------------------------------
// Phase 2 (Runtime JS A2): neighbors + system flags, read-only container walks
// ---------------------------------------------------------------------------

/// `s.neighbors` 的返回上限(计划 §A2:上限如 64,截断要记日志)。64 远大于 4.4.4
/// 活体最大度数;超了返回 `written < total`,调用方写一行 `NEO_JS_NEIGHBORS_TRUNC`。
pub const MAX_NEIGHBORS: usize = 64;

pub const NeighborRead = struct {
    /// 写进 `out` 的条数 = `min(count, MAX_NEIGHBORS)`。
    written: usize,
    /// 容器头里的原始条数(`+0x59c`);`total > written` 就是截断。
    total: u32,
};

/// 从一个系统对象读邻居 id 列表。与 `readSystemEdges` 同口径:数据 `+0x590`、计数
/// `+0x59c`、步长 `0x20`、元素 `+8` = 邻居 id;容量守卫(`count > capacity` ⇒ 拒读)
/// 也在同一格。只读,不缓存。
pub fn neighborsAt(mem: Memory, system: usize, out: *[MAX_NEIGHBORS]u32) ?NeighborRead {
    if (system == 0) return null;
    const count = readDword(mem, gg.addAddr(system, graph.EDGE_COUNT_OFF) orelse return null) orelse
        return null;
    if (count == 0) return .{ .written = 0, .total = 0 };
    if (count > graph.MAX_EDGE_COUNT) return null;
    const capacity = readDword(mem, gg.addAddr(system, graph.EDGE_CAPACITY_OFF) orelse return null) orelse
        return null;
    if (count > capacity) return null;
    const data = readPtr(mem, gg.addAddr(system, graph.EDGE_DATA_OFF) orelse return null) orelse
        return null;
    if (data == 0) return null;

    const n = @min(@as(usize, count), MAX_NEIGHBORS);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        out[i] = readDword(mem, gg.elemAddr(data, i, graph.EDGE_STRIDE, graph.EDGE_ID_OFF) orelse
            return null) orelse return null;
    }
    return .{ .written = n, .total = count };
}

/// `s.neighbors` 的生产入口:按 id 解析系统对象,读一趟邻居。
pub fn systemNeighbors(id: u32, out: *[MAX_NEIGHBORS]u32) ?NeighborRead {
    const ctx = resolveContext() orelse return null;
    const obj = resolveIn(ctx, id) orelse return null;
    return neighborsAt(memAdapter(), obj, out);
}

/// 系统 flag 容器里的 u16 flag token id 数组。写路径 `0x180f8e0` / `0x1bce180` 与
/// 删路径 `0x1bce270` 用的是同一格(`+0x5f8` 容器、`+0x10` 数组、`+0x1c` 计数);
/// 这里只扫描、不写。
pub fn hasFlagAt(mem: Memory, system: usize, flag_id: u16) ?bool {
    if (system == 0) return null;
    const container = gg.addAddr(system, graph.FLAG_SET_OFF) orelse return null;
    const count = readDword(mem, gg.addAddr(container, graph.FLAG_COUNT_OFF) orelse return null) orelse
        return null;
    if (count == 0) return false;
    if (count > graph.MAX_FLAG_COUNT) return null;
    const data = readPtr(mem, gg.addAddr(container, graph.FLAG_ID_ARRAY_OFF) orelse return null) orelse
        return null;
    if (data == 0) return null;

    const n: usize = count;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const addr = gg.elemAddr(data, i, graph.FLAG_ID_SIZE, 0) orelse return null;
        const got = readWord(mem, addr) orelse return null;
        if (got == flag_id) return true;
    }
    return false;
}

/// `s.hasStarFlag` 的生产入口。
pub fn systemHasFlag(id: u32, flag_id: u16) ?bool {
    const ctx = resolveContext() orelse return null;
    const obj = resolveIn(ctx, id) orelse return null;
    return hasFlagAt(memAdapter(), obj, flag_id);
}

// ---------------------------------------------------------------------------
// 进程内 Memory 适配
// ---------------------------------------------------------------------------

fn memRead(_: *anyopaque, addr: usize, len: usize, buf: []u8) bool {
    _ = len; // 以 `buf.len` 为准 —— 两个口径不该有两种长度
    return windows.readProcessMemory(addr, buf);
}

fn memAdapter() Memory {
    return .{ .ctx = undefined, .read = memRead };
}

fn readDword(mem: Memory, addr: usize) ?u32 {
    var buf: [4]u8 = undefined;
    if (!mem.read(mem.ctx, addr, buf.len, &buf)) return null;
    return std.mem.readInt(u32, &buf, .little);
}

fn readWord(mem: Memory, addr: usize) ?u16 {
    var buf: [2]u8 = undefined;
    if (!mem.read(mem.ctx, addr, buf.len, &buf)) return null;
    return std.mem.readInt(u16, &buf, .little);
}

fn readPtr(mem: Memory, addr: usize) ?usize {
    var buf: [@sizeOf(usize)]u8 = undefined;
    if (!mem.read(mem.ctx, addr, buf.len, &buf)) return null;
    return std.mem.readInt(usize, &buf, .little);
}

comptime {
    // `edges[4096]` 是静态缓冲:地址算术与 u16 端点都按 64 位进程写死。
    if (@sizeOf(usize) != 8) @compileError("graph_probe assumes a 64-bit target");
    // 两个改边例程的真 RVA(§1.1)。写成常量断言,免得手滑少一个字符。
    if (RVA_ADD_EDGE != 0x8BBAA0) @compileError("RVA_ADD_EDGE drifted from §1.1");
    if (RVA_REMOVE_EDGE != 0x8BBC20) @compileError("RVA_REMOVE_EDGE drifted from §1.1");
}

// ---------------------------------------------------------------------------
// Tests — the Phase 2 container walks against a synthetic image. No engine.
// ---------------------------------------------------------------------------

const testing = std.testing;

const TestMem = struct {
    bytes: [0x1000]u8 align(8) = [_]u8{0} ** 0x1000,
    base: usize = 0x1000_0000,

    fn read(ctx: *anyopaque, addr: usize, len: usize, buf: []u8) bool {
        const self: *TestMem = @ptrCast(@alignCast(ctx));
        if (addr < self.base) return false;
        const off = addr - self.base;
        if (off + len > self.bytes.len) return false;
        @memcpy(buf, self.bytes[off..][0..len]);
        return true;
    }

    fn mem(self: *TestMem) Memory {
        return .{ .ctx = @ptrCast(self), .read = TestMem.read };
    }

    fn writeU32(self: *TestMem, off: usize, v: u32) void {
        std.mem.writeInt(u32, self.bytes[off..][0..4], v, .little);
    }

    fn writeU64(self: *TestMem, off: usize, v: u64) void {
        std.mem.writeInt(u64, self.bytes[off..][0..8], v, .little);
    }

    fn writeU16(self: *TestMem, off: usize, v: u16) void {
        std.mem.writeInt(u16, self.bytes[off..][0..2], v, .little);
    }
};

const SYSTEM_OFF: usize = 0x100; // system object inside the synthetic image
const EDGE_DATA_OFF: usize = 0x200;
const FLAG_DATA_OFF: usize = 0x300;

fn armEdges(tm: *TestMem, count: u32, capacity: u32) void {
    tm.writeU64(SYSTEM_OFF + graph.EDGE_DATA_OFF, @as(u64, @intCast(tm.base + EDGE_DATA_OFF)));
    tm.writeU32(SYSTEM_OFF + graph.EDGE_CAPACITY_OFF, capacity);
    tm.writeU32(SYSTEM_OFF + graph.EDGE_COUNT_OFF, count);
}

test "neighborsAt walks the same +0x590/+0x59c container as readGraph" {
    var tm = TestMem{};
    armEdges(&tm, 3, 4);
    tm.writeU32(EDGE_DATA_OFF + 0 * graph.EDGE_STRIDE + graph.EDGE_ID_OFF, 11);
    tm.writeU32(EDGE_DATA_OFF + 1 * graph.EDGE_STRIDE + graph.EDGE_ID_OFF, 22);
    tm.writeU32(EDGE_DATA_OFF + 2 * graph.EDGE_STRIDE + graph.EDGE_ID_OFF, 33);

    var out: [MAX_NEIGHBORS]u32 = undefined;
    const r = neighborsAt(tm.mem(), tm.base + SYSTEM_OFF, &out).?;
    try testing.expectEqual(@as(usize, 3), r.written);
    try testing.expectEqual(@as(u32, 3), r.total);
    try testing.expectEqualSlices(u32, &.{ 11, 22, 33 }, out[0..3]);
}

test "neighborsAt truncates at MAX_NEIGHBORS and reports the raw count" {
    var tm = TestMem{};
    armEdges(&tm, MAX_NEIGHBORS + 5, MAX_NEIGHBORS + 10);
    var i: usize = 0;
    while (i < MAX_NEIGHBORS + 5) : (i += 1) {
        tm.writeU32(EDGE_DATA_OFF + i * graph.EDGE_STRIDE + graph.EDGE_ID_OFF, @intCast(i));
    }
    var out: [MAX_NEIGHBORS]u32 = undefined;
    const r = neighborsAt(tm.mem(), tm.base + SYSTEM_OFF, &out).?;
    try testing.expectEqual(MAX_NEIGHBORS, r.written);
    try testing.expectEqual(@as(u32, MAX_NEIGHBORS + 5), r.total);
    try testing.expectEqual(@as(u32, MAX_NEIGHBORS - 1), out[MAX_NEIGHBORS - 1]);
}

test "neighborsAt refuses a container whose count exceeds its capacity" {
    var tm = TestMem{};
    armEdges(&tm, 9, 8);
    var out: [MAX_NEIGHBORS]u32 = undefined;
    try testing.expectEqual(@as(?NeighborRead, null), neighborsAt(tm.mem(), tm.base + SYSTEM_OFF, &out));
    try testing.expectEqual(@as(?NeighborRead, null), neighborsAt(tm.mem(), 0, &out));
}

test "hasFlagAt scans the u16 id array the official set/remove bodies use" {
    var tm = TestMem{};
    const container = SYSTEM_OFF + graph.FLAG_SET_OFF;
    tm.writeU64(container + graph.FLAG_ID_ARRAY_OFF, @as(u64, @intCast(tm.base + FLAG_DATA_OFF)));
    tm.writeU32(container + graph.FLAG_COUNT_OFF, 3);
    tm.writeU16(FLAG_DATA_OFF + 0, 7);
    tm.writeU16(FLAG_DATA_OFF + 2, 9);
    tm.writeU16(FLAG_DATA_OFF + 4, 11);

    const mem = tm.mem();
    const obj = tm.base + SYSTEM_OFF;
    try testing.expectEqual(@as(?bool, true), hasFlagAt(mem, obj, 9));
    try testing.expectEqual(@as(?bool, true), hasFlagAt(mem, obj, 7));
    try testing.expectEqual(@as(?bool, true), hasFlagAt(mem, obj, 11));
    try testing.expectEqual(@as(?bool, false), hasFlagAt(mem, obj, 10));
    try testing.expectEqual(@as(?bool, false), hasFlagAt(mem, obj, 0));

    // Zero count is an empty set, not an unreadable container.
    tm.writeU32(container + graph.FLAG_COUNT_OFF, 0);
    try testing.expectEqual(@as(?bool, false), hasFlagAt(mem, obj, 9));
}

test "hasFlagAt fails closed on an unreadable container" {
    var tm = TestMem{};
    const container = SYSTEM_OFF + graph.FLAG_SET_OFF;
    tm.writeU32(container + graph.FLAG_COUNT_OFF, 3);
    // count > 0 but no data pointer.
    tm.writeU64(container + graph.FLAG_ID_ARRAY_OFF, 0);
    try testing.expectEqual(@as(?bool, null), hasFlagAt(tm.mem(), tm.base + SYSTEM_OFF, 7));
}
