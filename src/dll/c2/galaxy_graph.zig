// galaxy_graph.zig — 4.4.4 银河图**只读**读图器:把引擎的系统索引 + 每个系统的边容器
// 读成一张无向边表,交给 `chokepoint_dynamic.analyze` 度量。
//
// **这些偏移是静态推断,没有任何运行时读数。** 来源只有字节级静态取证:
//   * `evidence/analysis/runtime_444_graph_runtime.md` §1.2 —— id→系统对象解析器(`0x3939f0`)
//     与它读的两个 BSS 全局(`0x3260b98` 系统索引、`0x325d880` 回退);
//   * 同卷 §1.3 —— 系统对象 `+0x588` 的边容器(数据 `+0x590`、容量 `+0x598`、计数 `+0x59c`);
//   * 同卷 §2.2/§2.3/§2.4 —— trigger 侧三条**互相独立**的读路径,读到同一组
//     {`+0x590`, `+0x59c`}、同一 0x20 步长、同一「元素 `+8` = 系统 id」。
// 常量本体在 `src/dll/shared/offsets.zig` 的 `graph` 段,每个都带站点地址与基址来源。
//
// 本模块**只**通过 `Memory.read` 触碰内存:文件里没有一个 `@ptrFromInt`。这就是注入缝的
// 全部意义 —— 测试侧接合成镜像(见 `c2_tests.zig`),生产侧将来接真内存。
//
// **零发射契约(本任务)**:本模块不接任何真机内存。没有 `resolveFromGame` 之类的生产侧装配,
// `Memory.read` 的生产实现**不存在**,M4 之前不得拿真机指针调用它。这里交付的只是
// 「给定一个地址与一个读函数,边表长什么样」这一条可测的推论链。
//
// 参数约定:`galaxy` 是**系统索引对象**的绝对地址 —— 引擎在全局 RVA `0x3260B98` 处存的
// 那个指针的**值**(`0x393a0b mov rax,[rip+…]` 之后的 `[rax+0x18]`/`[rax+0x20]`)。
// 不是模块基址,不是那个全局槽自己的地址,也不是解析器的回退对象。该对象:
// `+0x18` = 槽表指针,`+0x20` = 槽数上界。
//
// 解析口径(§1.2,引擎自己那次查表;表项步长的勘误见 §1.11):
//   slot = id & 0xFFFFFF
//   slot >= bound        → 查不到
//   entry = qword[table + slot*16 + 8]  (记录 16 B,指针在记录 +8;见下)
//   entry == 0           → 查不到
//   dword[entry+8] != id → 查不到(引擎用这一条挡住陈旧/别名表项)
// **16 不是 8**:引擎在 `0x393a2f` 先 `add rcx,rcx` 把槽号翻倍,才 `0x393a32` 读
// `[rax + rcx*8 + 8]` ⇒ 步长是 16 B。按 8 B 步长读会落到记录的**头**上,静默读错对象。
// 枚举时没有「请求 id」,于是用同一不变量的另一面:表项可达 ⇔ (entry_id & 0xFFFFFF) == slot。
// 所以本模块**从不把系统 id 当槽位下标**(也不把槽位下标当系统 id);邻居 id 也是经同一次
// 表查核对(§2.2 的 `0xa6ab3b cmp dword ptr [rax+8], r8d`),而不是伪造端点。
//
// 读出来的边与 Task 5 的 `chokepoint_dynamic` 同口径:无向、规范化成 `a < b`、去自环、去重。
// 本模块**不做任何跨调用缓存** —— 不存指针、不存结果,每次调用都从 `galaxy` 重走一遍,
// 所以调用方可以在两次调用之间改图(Review Focus #3,见 c2_tests 的 no-cache 测试)。
//
// `skipped` = 因内存不可读或取值不可用而**丢弃**的枚举项数,逐项列举:
//   * 槽表项 qword 读失败;
//   * 表项的系统 id 读失败;
//   * 表项 id 与槽位不自洽(`id & 0xFFFFFF != slot`,陈旧/别名表项);
//   * 表项 id 超出 u16(`Edge` 装不下);
//   * 容器计数读失败,或计数 > `MAX_EDGE_COUNT`,或计数 > 0 而数据指针为空;
//   * 容器容量读失败,或 `count > capacity`(容器头与分配不自洽,拒绝走过分配边界);
//   * 邻居元素 id 读失败,或超出 u16,或经表查核对不上(`entry_id == id` 不成立)。
// 空槽位**不算**丢弃项(那是稀疏索引表的正常形态);自环与重复无向对是**过滤**、不计入。
//
// 短 `out`:唯一的多余错误是 `error.BufferTooSmall`。首次写不下时立刻返回,`out[0..k]` 是
// 枚举序的**确定性前缀** —— 不是静默截断后当成功。但**注意:走 error union 就丢掉了
// `ReadStats`**,所以那个前缀只是「给日志看」的信息;调用方若要拿到可续写的断点,必须先用
// 一趟只有计数意义的调用把 `out` 量好(或自己给足 `out.len`),不能指望从 `BufferTooSmall`
// 里读出 `k`。
// 索引对象头部读不到、或 `galaxy == 0`、`table == 0`、或 `+0x20` 的槽数为 0 或超防御上限
// → `error.UnreadableIndex`:拿不到银河对象就是拿不到图,返回空图会把「读不到」伪装成
// 「没有边」(I1/I2)。

const std = @import("std");
const cd = @import("chokepoint_dynamic.zig");
const graph = @import("../shared/offsets.zig").graph;

/// Task 5 的边类型 —— **复用**,不重定义(口径必须与 `analyze` 一致)。
pub const Edge = cd.Edge;

pub const Memory = struct {
    ctx: *anyopaque,
    /// 读取 addr 起 len 字节;不可读返回 false。生产侧接真内存,测试侧接合成镜像。
    read: *const fn (ctx: *anyopaque, addr: usize, len: usize, buf: []u8) bool,
};

pub const ReadStats = struct { systems: usize, edges: usize, skipped: usize };

pub const Error = error{
    /// `out` 装不下唯一边集;`out[0..k]` 是枚举序的确定性前缀(见文件头)。
    /// **统计值在 error union 里丢了** —— `k` 只对日志有意义;要续写断点请自己量好 `out`。
    BufferTooSmall,
    /// 索引对象头部(`+0x18` 表指针 / `+0x20` 槽数)读不到,或 `galaxy`/`table` 为空指针,
    /// 或槽数为 0,或槽数超出防御上限。
    UnreadableIndex,
};

/// `id & 0xFFFFFF`(§1.2 `0x393a20 and ecx, 0xffffff`)。
const MASK24: u32 = 0xFFFFFF;
/// `Edge` 的端点宽度(Task 5 复用)。
const MAX_ID: u32 = std.math.maxInt(u16);

/// 枚举 `galaxy` 指向的系统索引,把唯一的无向边写进 `out`。
/// 返回 `systems` = 表里活着的系统数,`edges` = 写进 `out` 的唯一边数,
/// `skipped` = 被丢弃的枚举项数(口径见文件头)。
pub fn readGraph(mem: Memory, galaxy: usize, out: []Edge) Error!ReadStats {
    // 空指针不是「空图」:判头部失败,别把「读不到」伪装成「没有边」(I1)。
    if (galaxy == 0) return error.UnreadableIndex;
    const bound = readDword(mem, galaxy + graph.INDEX_BOUND_OFF) orelse return error.UnreadableIndex;
    // 槽数为 0 只能是「头部读到了但内容不像索引对象」——同样按读不到处理(I2)。
    if (bound == 0) return error.UnreadableIndex;
    if (bound > graph.MAX_TABLE_SLOTS) return error.UnreadableIndex;
    const table = readPtr(mem, galaxy + graph.INDEX_TABLE_OFF) orelse return error.UnreadableIndex;
    if (table == 0) return error.UnreadableIndex;

    var stats = ReadStats{ .systems = 0, .edges = 0, .skipped = 0 };

    const slots: usize = bound;
    var slot: usize = 0;
    while (slot < slots) : (slot += 1) {
        const entry = readSlot(mem, table, slot) orelse {
            stats.skipped += 1;
            continue;
        };
        if (entry == 0) continue; // 空槽:稀疏索引表的正常形态,不是丢弃项
        const id = readDword(mem, entry + graph.SYSTEM_ID_OFF) orelse {
            stats.skipped += 1;
            continue;
        };
        // 可达性不变量:表项只有 (id & 0xFFFFFF) == slot 才可能被引擎自己的 lookup 命中。
        if ((id & MASK24) != @as(u32, @intCast(slot))) {
            stats.skipped += 1;
            continue;
        }
        if (id > MAX_ID) { // Edge.a/.b 是 u16,装不下
            stats.skipped += 1;
            continue;
        }
        stats.systems += 1;
        try readSystemEdges(mem, table, bound, entry, id, out, &stats);
    }
    return stats;
}

/// 读一个系统对象的边容器,把唯一边写进 `out`。
fn readSystemEdges(
    mem: Memory,
    table: usize,
    bound: u32,
    system: usize,
    system_id: u32,
    out: []Edge,
    stats: *ReadStats,
) Error!void {
    const count = readDword(mem, system + graph.EDGE_COUNT_OFF) orelse {
        stats.skipped += 1;
        return;
    };
    if (count == 0) return;
    if (count > graph.MAX_EDGE_COUNT) {
        stats.skipped += 1;
        return;
    }
    // 容量(`容器基址+0x10`,§1.3):`count > capacity` 说明容器头与分配不自洽,
    // 此时**不许**按 count 走 —— 那会走过分配边界。整段跳过并计数。
    // 口径注记:容量按**元素数**读;若引擎那边其实是字节口径,健康向量恒有
    // `capacity >= count`,本检查同样不会误伤。
    const capacity = readDword(mem, system + graph.EDGE_CAPACITY_OFF) orelse {
        stats.skipped += 1;
        return;
    };
    if (count > capacity) {
        stats.skipped += 1;
        return;
    }
    const data = readPtr(mem, system + graph.EDGE_DATA_OFF) orelse {
        stats.skipped += 1;
        return;
    };
    if (data == 0) {
        stats.skipped += 1;
        return;
    }

    const n: usize = count;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const neighbour = readDword(mem, data + i * graph.EDGE_STRIDE + graph.EDGE_ID_OFF) orelse {
            stats.skipped += 1;
            continue;
        };
        if (neighbour > MAX_ID) {
            stats.skipped += 1;
            continue;
        }
        if (neighbour == system_id) continue; // 自环:过滤,不计入 skipped
        // §2.2:邻居 id 也要经表查核对,解析不上的端点不伪造。
        if (!resolves(mem, table, bound, neighbour)) {
            stats.skipped += 1;
            continue;
        }
        const lo: u16 = @intCast(@min(system_id, neighbour));
        const hi: u16 = @intCast(@max(system_id, neighbour));
        if (pairPresent(out[0..stats.edges], lo, hi)) continue; // 无向去重
        if (stats.edges == out.len) return error.BufferTooSmall;
        out[stats.edges] = .{ .a = lo, .b = hi };
        stats.edges += 1;
    }
}

/// 引擎自己的查表形状(§1.2;步长见 §1.11):`id & 0xFFFFFF` 定槽,
/// `entry = qword[表 + slot*16 + 8]`,槽表项非空且 `entry_id == id`。
/// 这不是「按 id 取第几个系统」——槽位是算出来的,而且必须被表项自己确认。
fn resolves(mem: Memory, table: usize, bound: u32, id: u32) bool {
    const slot = id & MASK24;
    if (slot >= bound) return false;
    const entry = readSlot(mem, table, slot) orelse return false;
    if (entry == 0) return false;
    const entry_id = readDword(mem, entry + graph.SYSTEM_ID_OFF) orelse return false;
    return entry_id == id;
}

/// 读第 `slot` 号表项里的系统对象指针。
/// **表项步长是 16 B**(`0x393a2f add rcx,rcx` → `0x393a32 mov rax,[rax+rcx*8+8]`),
/// 指针在记录的 `+8` —— 不是一个 8 字节的 qword 数组(§1.11 勘误)。
fn readSlot(mem: Memory, table: usize, slot: usize) ?usize {
    const addr = table + slot * graph.TABLE_RECORD_SIZE + graph.TABLE_SLOT_PTR_OFF;
    return readPtr(mem, addr);
}

fn pairPresent(existing: []const Edge, a: u16, b: u16) bool {
    for (existing) |e| {
        if (e.a == a and e.b == b) return true;
    }
    return false;
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
