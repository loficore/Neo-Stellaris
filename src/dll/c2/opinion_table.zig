// opinion_table.zig — opinion 矩阵的**只读**读器(纯函数,注入 `Memory`)。
//
// 形状来自 `evidence/analysis/country_fields_4_4_4.md` §2(全部 A 级):
//
//   描述符 d = [[0x33794d0]]           `{ n: u32 @+0x00, base: int32* @+0x08 }`
//   键     idx = row * n + col         row/col 都是 **24 位截断**的国家 id
//   元素   4 B(int32),值就在元素里(value_offset = 0)
//   哨兵   0x7fffffff = **未计算**(引擎命中它才去调懒填计算器 `0x743bb0`)
//
// 纪律(计划 Global Constraints / Review Focus 1–2):
//   * **只读**。命中哨兵时返回 `NotComputed`,**绝不**调 `0x743bb0` —— 它会写缓存,
//     那是写路径。`null`/拒绝行比一个静默的错数字便宜。
//   * **每一维各自查界**:`row` 与 `col` 都 `>= n` 才算越界(两个 u32,一次乘法)。
//   * **表可能为空**:描述符为 0、`n == 0`、`base == 0`、读不到 —— 一律 `TableNull`,
//     不是 0 分。主菜单/未载入战役就是这一档。
//   * 地址算术全部带检查:出货 DLL 是 Debug 构建,一次整数溢出就是 `abort()` →
//     宿主被杀(AGENTS 约束 8)。
//
// **方向**:`opinion` 与 `their_opinion` 读的是互为**转置**的两格(A 级);
// 「哪一向 = 己对目标」只有 B 级(两个 docstring + 参数序两条单侧证人),
// 所以本模块**不**写 `us/them` 之类的名字 —— 名字按引擎的 keyword 取。
//
// 不写任何引擎内存、不分配、不缓存(每次 `value` 都重新读元素)。

const std = @import("std");

/// 引擎的「这一格还没算过」标记(`0x1ab05bf`,§2.2)。
pub const SENTINEL: i32 = 0x7fff_ffff;

/// 注入的读内存面。生产适配器用 host 的 `readU32Safe`/`readU64Safe`
/// (带 `isCommitted` 检查);测试用 `FakeMatrix` 的合成内存。
pub const Memory = struct {
    ctx: *anyopaque,
    read_u32: *const fn (ctx: *anyopaque, addr: u64) ?u32,
    read_u64: *const fn (ctx: *anyopaque, addr: u64) ?u64,
    read_i32: *const fn (ctx: *anyopaque, addr: u64) ?i32,
};

/// 描述符的**内容**(不是地址):`n` 行数(也是列数),`base` 矩阵基址。
pub const Table = struct { n: u32, base: u64 };

/// 三种失败各有一条具名理由(host 侧落 `NEO_JS_OPINION_REJECT reason=<name>`)。
pub const LookupError = error{
    /// 描述符 / `n` / `base` 读不到或为 0:表还没建(主菜单、未载入战役)。
    TableNull,
    /// `row >= n` 或 `col >= n`:引擎自己也是 `jae` 之后走回退,不是读越界。
    OutOfRange,
    /// 元素是 `0x7fffffff`:引擎没算过。**不许**当成 -1,也不许替它算。
    NotComputed,
};

/// 读描述符。`descriptor_addr` 是 `[[0x33794d0]]` 那个**全局格**的地址
/// (`offsets.country.OPINION_DESCRIPTOR`),不是描述符本身。
pub fn load(mem: Memory, descriptor_addr: u64) LookupError!Table {
    const d = mem.read_u64(mem.ctx, descriptor_addr) orelse return error.TableNull;
    if (d == 0) return error.TableNull;
    const n = mem.read_u32(mem.ctx, d) orelse return error.TableNull;
    const base_addr = std.math.add(u64, d, 8) catch return error.TableNull;
    const base = mem.read_u64(mem.ctx, base_addr) orelse return error.TableNull;
    if (n == 0 or base == 0) return error.TableNull;
    return .{ .n = n, .base = base };
}

/// 读一格。`row` 是乘 `n` 的那一个、`col` 是加上的那一个 —— 调用方决定
/// 哪一向(见文件头:方向只有 B 级)。
pub fn value(mem: Memory, table: Table, row: u32, col: u32) LookupError!i32 {
    if (row >= table.n or col >= table.n) return error.OutOfRange;
    const idx = std.math.mul(u64, row, table.n) catch return error.OutOfRange;
    const key = std.math.add(u64, idx, col) catch return error.OutOfRange;
    const offset = std.math.mul(u64, key, 4) catch return error.OutOfRange;
    const addr = std.math.add(u64, table.base, offset) catch return error.OutOfRange;
    const v = mem.read_i32(mem.ctx, addr) orelse return error.TableNull;
    if (v == SENTINEL) return error.NotComputed;
    return v;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// 合成矩阵:一块真实的 Zig 内存,三个区域(描述符格 / 描述符 / 元素)。
///
/// 读器只经 `Memory.read_*` 碰它,所以每次读都在这里查界 —— 读器走出结构
/// (`escaped > 0`)时测试会看见,而不是读到一个看似合理的垃圾值。
pub const FakeMatrix = struct {
    pub const MAX_N: u32 = 8;

    pub const Header = extern struct {
        n: u32 = 0,
        pad: u32 = 0,
        base: u64 = 0,
    };

    /// 描述符全局格:`load` 读的 qword。
    desc: u64 = 0,
    header: Header = .{},
    cells: [MAX_N * MAX_N]i32 = [_]i32{0} ** (MAX_N * MAX_N),
    /// 落在三个区域之外的读次数(测试断言它是 0)。
    escaped: usize = 0,

    pub fn init(n: u32) FakeMatrix {
        var m = FakeMatrix{};
        m.header.n = n;
        return m;
    }

    /// 把三个区域互相指好。实例必须有稳定地址(测试里用 `var` 放在栈上)。
    pub fn wire(self: *FakeMatrix) void {
        self.desc = @intFromPtr(&self.header);
        self.header.base = @intFromPtr(&self.cells);
    }

    /// 模拟「表还没建」:描述符格与 base 都清 0。
    pub fn clear(self: *FakeMatrix) void {
        self.desc = 0;
        self.header.base = 0;
    }

    pub fn descriptorAddr(self: *FakeMatrix) u64 {
        return @intFromPtr(&self.desc);
    }

    pub fn set(self: *FakeMatrix, row: u32, col: u32, v: i32) void {
        self.cells[row * self.header.n + col] = v;
    }

    pub fn get(self: *FakeMatrix, row: u32, col: u32) i32 {
        return self.cells[row * self.header.n + col];
    }

    pub fn memory(self: *FakeMatrix) Memory {
        return .{
            .ctx = @ptrCast(self),
            .read_u32 = read32,
            .read_u64 = read64,
            .read_i32 = readI32,
        };
    }

    fn read32(ctx: *anyopaque, addr: u64) ?u32 {
        var buf: [4]u8 = undefined;
        if (!readRange(ctx, addr, &buf)) return null;
        return std.mem.readInt(u32, &buf, .little);
    }

    fn read64(ctx: *anyopaque, addr: u64) ?u64 {
        var buf: [8]u8 = undefined;
        if (!readRange(ctx, addr, &buf)) return null;
        return std.mem.readInt(u64, &buf, .little);
    }

    fn readI32(ctx: *anyopaque, addr: u64) ?i32 {
        var buf: [4]u8 = undefined;
        if (!readRange(ctx, addr, &buf)) return null;
        return std.mem.readInt(i32, &buf, .little);
    }

    /// 只允许落在这三个区域里的读;越界读记 `escaped` 并失败(fail-closed)。
    fn readRange(ctx: *anyopaque, addr: u64, out: []u8) bool {
        const self: *FakeMatrix = @ptrCast(@alignCast(ctx));
        const regions = [_]struct { base: usize, len: usize }{
            .{ .base = @intFromPtr(&self.desc), .len = @sizeOf(u64) },
            .{ .base = @intFromPtr(&self.header), .len = @sizeOf(Header) },
            .{ .base = @intFromPtr(&self.cells), .len = @sizeOf([MAX_N * MAX_N]i32) },
        };
        for (regions) |r| {
            if (addr < r.base) continue;
            const off = addr - r.base;
            if (off + out.len > r.len) continue;
            @memcpy(out, @as([*]const u8, @ptrFromInt(@as(usize, @intCast(addr))))[0..out.len]);
            return true;
        }
        self.escaped += 1;
        return false;
    }
};

test "opinion_table reads row-major int32 with the row*n+col key" {
    var m = FakeMatrix.init(3);
    m.wire();
    // 键是 row*n+col:同一个格被两对 (row,col) 分开,(1,2) 与 (2,1) 不是同一格。
    m.set(1, 2, 77);
    m.set(2, 1, -5);

    const t = try load(m.memory(), m.descriptorAddr());
    try testing.expectEqual(@as(u32, 3), t.n);
    try testing.expectEqual(@as(u64, @intFromPtr(&m.cells)), t.base);

    try testing.expectEqual(@as(i32, 77), try value(m.memory(), t, 1, 2));
    try testing.expectEqual(@as(i32, -5), try value(m.memory(), t, 2, 1));
    try testing.expectEqual(@as(i32, 0), try value(m.memory(), t, 0, 0));
    // 键序是 row-major 而不是 col-major:元素 5 只在 cell(1,2) 上。
    try testing.expectEqual(@as(i32, 77), m.cells[1 * 3 + 2]);
    try testing.expectEqual(@as(usize, 0), m.escaped);
}

test "opinion_table rejects out-of-range rows and columns" {
    var m = FakeMatrix.init(3);
    m.wire();
    const t = try load(m.memory(), m.descriptorAddr());

    // 两个维度**各自**查界:row 越界、col 越界、两者都越界,都必须是 OutOfRange。
    try testing.expectError(error.OutOfRange, value(m.memory(), t, 3, 0));
    try testing.expectError(error.OutOfRange, value(m.memory(), t, 0, 3));
    try testing.expectError(error.OutOfRange, value(m.memory(), t, 3, 3));
    try testing.expectError(error.OutOfRange, value(m.memory(), t, 0xFFFF_FFFF, 0));
    // 界内最后一格是合法的。
    try testing.expectEqual(@as(i32, 0), try value(m.memory(), t, 2, 2));
    // 越界在读之前就判掉:一个字节都不该被读出去。
    try testing.expectEqual(@as(usize, 0), m.escaped);
}

test "opinion_table treats 0x7fffffff as not computed" {
    var m = FakeMatrix.init(2);
    m.wire();
    m.set(0, 0, SENTINEL);
    m.set(0, 1, -1); // 负值是**读数**,不是哨兵

    const t = try load(m.memory(), m.descriptorAddr());
    try testing.expectError(error.NotComputed, value(m.memory(), t, 0, 0));
    try testing.expectEqual(@as(i32, -1), try value(m.memory(), t, 0, 1));
}

test "opinion_table rejects a null descriptor or base" {
    var m = FakeMatrix.init(3);
    m.wire();

    // 描述符格 = 0(主菜单/未载入战役)。
    const good_desc = m.desc;
    m.desc = 0;
    try testing.expectError(error.TableNull, load(m.memory(), m.descriptorAddr()));
    m.desc = good_desc;

    // 描述符在,但 base = 0:表还没分配。
    const good_base = m.header.base;
    m.header.base = 0;
    try testing.expectError(error.TableNull, load(m.memory(), m.descriptorAddr()));
    m.header.base = good_base;

    // n = 0:空表。
    m.header.n = 0;
    try testing.expectError(error.TableNull, load(m.memory(), m.descriptorAddr()));
    m.header.n = 3;

    // 描述符格本身读不到(地址落在合成内存之外)。
    try testing.expectError(error.TableNull, load(m.memory(), 0x1000));
    // 描述符的内容读不到(指向合成内存之外)同样是 TableNull,不是猜测值。
    m.desc = 0x2000;
    try testing.expectError(error.TableNull, load(m.memory(), m.descriptorAddr()));
    try testing.expect(m.escaped > 0);

    // 元素读不到:fail-closed 成 TableNull,而不是一个 0 分。
    m.wire();
    const t = try load(m.memory(), m.descriptorAddr());
    var broken = t;
    broken.base = 0x3000;
    try testing.expectError(error.TableNull, value(m.memory(), broken, 0, 0));
}
