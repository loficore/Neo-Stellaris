// gamestate.zig — Game state access functions.
//
// Provides read access to Stellaris game objects (systems today; countries /
// planets / pops still unresolved) through the Clausewitz engine's own global
// databases.
//
// 每个函数只有两种合法状态(见 evidence/analysis/runtime_444_sdk_api_4_4_4.md):
//   ① 真实现 —— 有站点地址、有假内存测试,读的是引擎状态;
//   ② 未定形 —— 返回安全值,注释写明缺什么、缺在哪一节。
// 「看起来能用但其实返回常量」的中间态是禁止的(#55)。
//
// 2026-11-15 审计:旧版本留下的两个「GameState / CountryDB 全局」在 4.4.4 里
// **没有任何代码引用**(scripts/scratch/2026-11_dirty_bit/global_xrefs.py:
// 0x3287360 → 1 条 `<no decode>` 字节巧合,0x3287788 → 0 条;同宽度窗口
// 0x3286000..0x3287900 全零),已删。见
// evidence/analysis/runtime_444_sdk_api_4_4_4.md §1。
//
// Thread safety: the read path is a pure function of engine memory plus one
// test-only seam (`setProbe`); production code never changes the seam after
// init, so readers are safe to call from any thread.

const std = @import("std");
const offsets = @import("../shared/offsets.zig");
const windows = @import("../hooking/windows.zig");

const graph = offsets.graph;
const country_table = offsets.country_table;

// ---------------------------------------------------------------------------
// Game object types
// ---------------------------------------------------------------------------

/// Opaque handle to a game object. In production, this wraps the engine's
/// internal object pointer. For stubs, it's just a raw pointer.
pub const GameObjectHandle = *anyopaque;

/// Modifier representation: a name and integer value.
pub const Modifier = struct {
    name: []const u8,
    value: i64,
};

/// Variable representation: a name and integer value.
pub const Variable = struct {
    name: []const u8,
    value: i64,
};

// ---------------------------------------------------------------------------
// Index-table lookup — 系统与国家共用的一条通道(真实现)
// ---------------------------------------------------------------------------

/// 读入口由 `source()` 装配:
/// **生产** —— `windows.moduleFunction(0)` 取 stellaris.exe 模块基址(ASLR on,
/// 不能写死绝对地址),`windows.readProcessMemory` 读自己进程;
/// **测试** —— `setSystemSourceForTest` 注入合成镜像,所以 `getSystem` 的每一步都能
/// 在没有引擎的宿主上被验证。本模块**不**依赖实机就有测试覆盖(见文件尾用例)。
///
/// 读一个指针(usize)。读不到 ⇒ null。
fn readPtr(src: SystemSource, addr: usize) ?usize {
    var buf: [@sizeOf(usize)]u8 = undefined;
    if (!src.mem.read(src.mem.ctx, addr, buf.len, &buf)) return null;
    return std.mem.readInt(usize, &buf, .little);
}

/// 读一个 dword。读不到 ⇒ null。
fn readDword(src: SystemSource, addr: usize) ?u32 {
    var buf: [4]u8 = undefined;
    if (!src.mem.read(src.mem.ctx, addr, buf.len, &buf)) return null;
    return std.mem.readInt(u32, &buf, .little);
}

/// 检查加法:内存派生地址回绕 ⇒ null(回绕后的地址不是任何真实对象;
/// Debug 构建里未检查的 `+` 会 panic —— 约束 8)。
fn addAddr(base: usize, off: usize) ?usize {
    return std.math.add(usize, base, off) catch null;
}

/// 检查乘加:`base + idx * stride + off`,乘法与两次加法都不回绕。
fn elemAddr(base: usize, idx: usize, stride: usize, off: usize) ?usize {
    const scaled = std.math.mul(usize, idx, stride) catch return null;
    const rel = std.math.add(usize, scaled, off) catch return null;
    return addAddr(base, rel);
}

// ---------------------------------------------------------------------------
// System index reader (the only test seam; production uses the real process)
// ---------------------------------------------------------------------------

/// 只读内存抽象,与 `galaxy_graph.zig` / `graph_probe.zig` 的 `Memory` 同形状:
/// `ctx` 由读者自己解释(合成镜像在测试侧,进程内 `ReadProcessMemory` 在生产侧)。
pub const Memory = struct {
    ctx: *anyopaque,
    /// 读 `addr` 起 `len` 字节;不可读返回 false。
    read: *const fn (ctx: *anyopaque, addr: usize, len: usize, buf: []u8) bool,
};

/// 索引表读源。`base` 是 stellaris.exe 的模块基址(生产 = `moduleFunction(0)`;
/// 测试 = 合成镜像的基址),每张表自己再 `+RVA` 得到全局槽地址 —— 所以同一个读源
/// 能同时服务系统(`0x3260B98`)与国家(`0x3260FD8`)两张表。
pub const SystemSource = struct {
    mem: Memory,
    base: usize,
};

/// 测试专用注入口(生产恒为 `null`)。仅测试用它把合成镜像接进来。
/// 生产路径在 `source()` 里走 `windows.moduleFunction(0)` +
/// `windows.readProcessMemory` —— 本变量不是能力开关,也不对外暴露。
var test_source: ?SystemSource = null;

/// 仅测试调用:装上/复位合成读源。
pub fn setSystemSourceForTest(src: ?SystemSource) void {
    test_source = src;
}

/// 生产侧的进程内读适配器(忽略 ctx/len,以 `buf.len` 为准,见 `graph_probe.memRead`)。
fn prodRead(_: *anyopaque, addr: usize, len: usize, buf: []u8) bool {
    _ = len;
    return windows.readProcessMemory(addr, buf);
}

/// 当前可用的读源:测试注入优先;否则现场装配模块基址 + 进程内读。
/// 宿主(Linux)上 `moduleFunction` 直接 `error.ModuleNotFound` ⇒ 没有读源
/// ⇒ `getSystem` 返回 null(fail closed),不拿假地址去读。
fn source() ?SystemSource {
    if (test_source) |s| return s;
    const base = @intFromPtr(windows.moduleFunction(0) catch return null);
    return .{ .mem = .{ .ctx = undefined, .read = &prodRead }, .base = base };
}

/// 读一张「系统 / 国家同形」的索引表,失败一律 `null`(绝不 panic):
/// `[base+global_rva]` 全局槽 → 表对象(`+0x18` 表基址、`+0x20` 槽数)→ 槽号
/// `id & 0xFFFFFF` 越界即 null → `qword[表 + slot*16 + 8]` → 复核
/// `dword[对象 + id_off] == id`。
/// 系统与国家共用这条形状(offsets.zig 的测试钉住四个公共表偏移相等),唯一不同的是
/// 全局 RVA 与对象内的 id 偏移(系统 `+0x08` / 国家 `+0x20`)。
fn lookupTable(src: SystemSource, global_rva: usize, id_off: usize, id: u32) ?GameObjectHandle {
    const gslot = addAddr(src.base, global_rva) orelse return null;
    const table_obj = readPtr(src, gslot) orelse return null;
    if (table_obj == 0) return null;

    const bound = readDword(src, addAddr(table_obj, graph.INDEX_BOUND_OFF) orelse return null) orelse return null;
    if (bound == 0 or @as(usize, bound) > graph.MAX_TABLE_SLOTS) return null;
    const table = readPtr(src, addAddr(table_obj, graph.INDEX_TABLE_OFF) orelse return null) orelse return null;
    if (table == 0) return null;

    const slot: usize = id & 0xFFFFFF;
    if (slot >= bound) return null;

    const entry = readPtr(
        src,
        elemAddr(table, slot, graph.TABLE_RECORD_SIZE, graph.TABLE_SLOT_PTR_OFF) orelse return null,
    ) orelse return null;
    if (entry == 0) return null;

    const entry_id = readDword(src, addAddr(entry, id_off) orelse return null) orelse return null;
    if (entry_id != id) return null;

    return @ptrFromInt(entry);
}

// ---------------------------------------------------------------------------
// Read functions
// ---------------------------------------------------------------------------

/// Retrieve a country object by its numeric ID.
///
/// # Arguments
/// * `id` - Country ID (matches in-game country ID, e.g., from save files)
///
/// # Returns
/// Pointer to the country object, or null if not found.
///
/// **真实现**:与 `getSystem` 同一条查表形状(引擎自己的 `0x192c290` 与 `0x1e7b850`
/// 两个独立读者逐条对上),差别只有两处:全局是 `0x3260FD8`(系统 `0x3260B98`),
/// 对象自己的 id 字段是 `+0x20`(系统 `+0x08`)。取证:`country_scope_4_4_4.md` §7;
/// 本卷 §4。读不到 / 越界 / id 不符一律 `null`,不返回引擎的空对象回退(那是伪造对象)。
pub fn getCountry(id: u32) ?GameObjectHandle {
    const src = source() orelse return null;
    return lookupTable(src, country_table.RVA_GLOBAL, country_table.OBJECT_ID_OFF, id);
}

/// Retrieve a planet object by its numeric ID.
///
/// # Arguments
/// * `id` - Planet ID
///
/// # Returns
/// Pointer to the planet object, or null if not found.
///
/// 未定形 —— 见 evidence/analysis/runtime_444_sdk_api_4_4_4.md §4(缺:星球表的全局
/// 与步长;`AGENTS.md` 无锚点)。
pub fn getPlanet(id: u32) ?GameObjectHandle {
    _ = id;
    return null;
}

/// Retrieve a pop object by its numeric ID.
///
/// # Arguments
/// * `id` - Pop ID
///
/// # Returns
/// Pointer to the pop object, or null if not found.
///
/// 未定形 —— 见 evidence/analysis/runtime_444_sdk_api_4_4_4.md §4(缺:pop 表的全局
/// 与步长;`AGENTS.md` 无锚点)。
pub fn getPop(id: u32) ?GameObjectHandle {
    _ = id;
    return null;
}

/// Retrieve a star system (galactic object) by its numeric ID.
///
/// **真实现**(不是桩):走引擎自己那条查表,站点逐条对得上 ——
/// `0x393a0b`(`mov rax,[rip+…]` 取系统索引全局 `RVA 0x3260B98`)、
/// `0x393a26`(`cmp ecx,[rax+0x20]` 槽数上界)、`0x393a2b`(`[rax+0x18]` 槽表指针)、
/// `0x393a32`(`qword[表 + 槽*16 + 8]` = 对象指针,**步长 16 B**,§1.11 的勘误)、
/// `0x393a3c`(`dword[对象+8] == id` 复核;对象头的 `+8` 是 id,不是表项的那个 `+8`)。
/// 取证:`evidence/analysis/runtime_444_graph_runtime.md` §1.2/§1.11;
/// 本卷的取舍与边界:`evidence/analysis/runtime_444_sdk_api_4_4_4.md` §2。
///
/// 算法(每一步都 fail closed 返回 null,绝不 panic):
///   全局槽 → 0 则 null;槽数读不到 / 0 / 超 `MAX_TABLE_SLOTS` 则 null;
///   槽表指针读不到 / 0 则 null;`slot = id & 0xFFFFFF` 且 `slot >= 槽数` 则 null;
///   表项 qword 读不到 / 0 则 null;`dword[对象+8] != id` 则 null;否则返回对象指针。
///
/// **只覆盖系统**。国家走 `getCountry`(本卷 §4);星球 / pop 的表仍未定形(§4)。
/// 拿到错对象比返回 null 糟得多,所以 id 复核是硬条件,不是可选项。
///
/// # Arguments
/// * `id` - System/galactic object ID
///
/// # Returns
/// Pointer to the system object, or null if not found / not readable.
pub fn getSystem(id: u32) ?GameObjectHandle {
    const src = source() orelse return null;
    return lookupTable(src, graph.RVA_SYSTEM_INDEX_GLOBAL, graph.SYSTEM_ID_OFF, id);
}

/// Retrieve the current game date as a string.
///
/// # Returns
/// Pointer to the date string (engine-owned), or empty slice if unavailable.
///
/// 未定形 —— 见 evidence/analysis/runtime_444_sdk_api_4_4_4.md §3。
pub fn getGameDate() []const u8 {
    return "";
}

/// Retrieve the current game tick.
///
/// # Returns
/// Current tick count, or 0 if unavailable.
///
/// 未定形 —— 见 evidence/analysis/runtime_444_sdk_api_4_4_4.md §3。
pub fn getGameTick() i64 {
    return 0;
}

// ---------------------------------------------------------------------------
// Write functions
// ---------------------------------------------------------------------------

/// Set a variable value on a game object's scope.
///
/// # Arguments
/// * `name` - Variable name (e.g., "my_mod_var")
/// * `value` - New value
///
/// # Returns
/// true if the variable was set successfully, false otherwise.
pub fn setVariable(name: []const u8, value: i64) bool {
    _ = name;
    _ = value;
    return false;
}

/// Add a modifier to a game object (e.g., pop happiness modifier).
///
/// # Arguments
/// * `scope` - Target scope (game object)
/// * `modifier` - Modifier to apply
///
/// # Returns
/// true if the modifier was applied, false otherwise.
pub fn addModifier(scope: GameObjectHandle, modifier: Modifier) bool {
    _ = scope;
    _ = modifier;
    return false;
}

/// Trigger a game event by ID.
///
/// # Arguments
/// * `event_id` - The event ID (string key, e.g., "my_event.1")
/// * `scope` - The scope to trigger the event in
///
/// # Returns
/// true if the event was triggered, false otherwise.
pub fn triggerEvent(event_id: []const u8, scope: GameObjectHandle) bool {
    _ = event_id;
    _ = scope;
    return false;
}

/// Remove a modifier from a game object.
///
/// # Arguments
/// * `scope` - Target scope
/// * `modifier_name` - Name of the modifier to remove
///
/// # Returns
/// true if the modifier was removed, false otherwise.
pub fn removeModifier(scope: GameObjectHandle, modifier_name: []const u8) bool {
    _ = scope;
    _ = modifier_name;
    return false;
}

// =============================================================================
// Tests
// =============================================================================

test "getCountry: 宿主构建没有可用的读入口时返回 null(fail closed)" {
    defer clearSource();
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getCountry(0));
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getCountry(1));
}

test "getCountry resolves through the country table and verifies the object id at +0x20" {
    fake_mem.reset();
    defer clearSource();

    const module_base: usize = 0x1_4000_0000;
    const index: usize = 0x1_5800_0000;
    const table: usize = 0x1_6000_0000;
    const c0: usize = 0x1_7800_0000;
    const c7: usize = 0x1_7800_1000;

    // 8 槽:槽 0 → C0(id 0)、槽 1 → C7(id 7,槽位与 id 不自洽)、槽 7 → C7(id 7)。
    fake_mem.open(module_base + offsets.country_table.RVA_GLOBAL, 8);
    fake_mem.open(index, 0x28);
    fake_mem.open(table, 8 * offsets.country_table.RECORD_SIZE);
    fake_mem.open(c0, 0x28);
    fake_mem.open(c7, 0x28);

    fake_mem.putQword(module_base + offsets.country_table.RVA_GLOBAL, index);
    fake_mem.putQword(index + offsets.country_table.TABLE_OFF, table);
    fake_mem.putDword(index + offsets.country_table.BOUND_OFF, 8);

    fake_mem.putQword(table + 0 * offsets.country_table.RECORD_SIZE + offsets.country_table.SLOT_PTR_OFF, c0);
    fake_mem.putQword(table + 1 * offsets.country_table.RECORD_SIZE + offsets.country_table.SLOT_PTR_OFF, c7);
    fake_mem.putQword(table + 7 * offsets.country_table.RECORD_SIZE + offsets.country_table.SLOT_PTR_OFF, c7);
    fake_mem.putDword(c0 + offsets.country_table.OBJECT_ID_OFF, 0);
    fake_mem.putDword(c7 + offsets.country_table.OBJECT_ID_OFF, 7);

    installFakeSource(module_base);

    try std.testing.expectEqual(@as(?GameObjectHandle, @ptrFromInt(c0)), getCountry(0));
    try std.testing.expectEqual(@as(?GameObjectHandle, @ptrFromInt(c7)), getCountry(7));
    // 槽 1 里对象 id 是 7 —— 复核读的是对象 `+0x20`(不是系统的 `+0x08`),挡掉它。
    try expectNull(getCountry(1));
    // 空槽 / 越界。
    try expectNull(getCountry(2));
    try expectNull(getCountry(8));
}

/// 假内存(测试专用):按「区域」服务读请求。
///
/// 读源由 `setSystemSourceForTest` 注入(`Memory.ctx` 在本假装里不用,合成镜像挂
/// 文件级变量),每个用例开头 `fake_mem.reset()`,并用 `defer clearSource()` 把缝收回。
/// 单一区域上限 1 KiB 足够摆一张两槽的表 + 两个对象头。
const FakeMem = struct {
    const MAX_REGIONS = 8;
    const MAX_BYTES = 1024;

    const Region = struct {
        base: usize = 0,
        len: usize = 0,
        bytes: [MAX_BYTES]u8 = [_]u8{0} ** MAX_BYTES,
    };

    regions: [MAX_REGIONS]Region = [_]Region{.{}} ** MAX_REGIONS,
    count: usize = 0,

    fn reset(self: *FakeMem) void {
        self.count = 0;
    }

    /// 开一块全零的可读区。
    fn open(self: *FakeMem, base: usize, len: usize) void {
        std.debug.assert(self.count < MAX_REGIONS and len <= MAX_BYTES);
        const r = &self.regions[self.count];
        r.* = .{ .base = base, .len = len };
        self.count += 1;
    }

    /// 只服务**完全落在**某个区域内、且整块可读的请求 —— 与
    /// `windows.readProcessMemory` 的 `got == out.len` 契约同形。
    fn read(self: *const FakeMem, addr: usize, out: []u8) bool {
        for (self.regions[0..self.count]) |*r| {
            if (addr < r.base) continue;
            const off = addr - r.base;
            if (off > r.len or out.len > r.len - off) continue;
            @memcpy(out, r.bytes[off .. off + out.len]);
            return true;
        }
        return false;
    }

    fn put(self: *FakeMem, addr: usize, bytes: []const u8) void {
        for (self.regions[0..self.count]) |*r| {
            if (addr < r.base) continue;
            const off = addr - r.base;
            if (off > r.len or bytes.len > r.len - off) continue;
            @memcpy(r.bytes[off .. off + bytes.len], bytes);
            return;
        }
        std.debug.panic("FakeMem.put: 没有区域覆盖 0x{x}", .{addr});
    }

    fn putQword(self: *FakeMem, addr: usize, v: usize) void {
        var buf: [@sizeOf(usize)]u8 = undefined;
        std.mem.writeInt(usize, &buf, v, .little);
        self.put(addr, &buf);
    }

    fn putDword(self: *FakeMem, addr: usize, v: u32) void {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, v, .little);
        self.put(addr, &buf);
    }
};

var fake_mem: FakeMem = .{};

fn fakeRead(_: *anyopaque, addr: usize, len: usize, buf: []u8) bool {
    _ = len; // 以 `buf.len` 为准,与生产适配器同口径
    return fake_mem.read(addr, buf);
}

fn installFakeSource(module_base: usize) void {
    setSystemSourceForTest(.{
        .mem = .{ .ctx = undefined, .read = &fakeRead },
        .base = module_base,
    });
}

fn clearSource() void {
    setSystemSourceForTest(null);
}

fn expectNull(v: ?GameObjectHandle) !void {
    try std.testing.expectEqual(@as(?GameObjectHandle, null), v);
}

test "getSystem resolves a slot through the index table and verifies the id" {
    fake_mem.reset();
    defer clearSource();

    const module_base: usize = 0x1_4000_0000;
    const index: usize = 0x1_5000_0000;
    const table: usize = 0x1_6000_0000;
    const obj_a: usize = 0x1_7000_0000;
    const obj_b: usize = 0x1_7000_1000;
    const obj_stale: usize = 0x1_7000_2000;

    // 8 槽(sys §1.2:slot = id & 0xFFFFFF、slot < bound):
    //   槽 0 → A(id = 0)、槽 1 → stale(id = 7,槽位与 id 不自洽)、槽 7 → B(id = 7)。
    fake_mem.open(module_base + offsets.graph.RVA_SYSTEM_INDEX_GLOBAL, 8);
    fake_mem.open(index, 0x28);
    fake_mem.open(table, 8 * offsets.graph.TABLE_RECORD_SIZE);
    fake_mem.open(obj_a, 16);
    fake_mem.open(obj_b, 16);
    fake_mem.open(obj_stale, 16);

    fake_mem.putQword(module_base + offsets.graph.RVA_SYSTEM_INDEX_GLOBAL, index);
    fake_mem.putQword(index + offsets.graph.INDEX_TABLE_OFF, table);
    fake_mem.putDword(index + offsets.graph.INDEX_BOUND_OFF, 8);

    fake_mem.putQword(table + 0 * offsets.graph.TABLE_RECORD_SIZE + offsets.graph.TABLE_SLOT_PTR_OFF, obj_a);
    fake_mem.putQword(table + 1 * offsets.graph.TABLE_RECORD_SIZE + offsets.graph.TABLE_SLOT_PTR_OFF, obj_stale);
    fake_mem.putQword(table + 7 * offsets.graph.TABLE_RECORD_SIZE + offsets.graph.TABLE_SLOT_PTR_OFF, obj_b);
    fake_mem.putDword(obj_a + offsets.graph.SYSTEM_ID_OFF, 0);
    fake_mem.putDword(obj_b + offsets.graph.SYSTEM_ID_OFF, 7);
    fake_mem.putDword(obj_stale + offsets.graph.SYSTEM_ID_OFF, 7);

    installFakeSource(module_base);

    // 命中:槽与 id 自洽。
    try std.testing.expectEqual(@as(?GameObjectHandle, @ptrFromInt(obj_a)), getSystem(0));
    try std.testing.expectEqual(@as(?GameObjectHandle, @ptrFromInt(obj_b)), getSystem(7));

    // 槽 1 里的对象 id 是 7:引擎自己那条 `entry+8 == id` 会挡掉它。
    // **拿到错对象比返回 null 糟得多** —— 这一条就是那条判断的证据。
    try expectNull(getSystem(1));

    // bound = 8 之内的空槽。
    try expectNull(getSystem(2));

    // 越界:id >= bound(8),以及 dword 全宽的极端值。
    try expectNull(getSystem(8));
    try expectNull(getSystem(std.math.maxInt(u32)));
}

test "getSystem fails closed when the index global is null or unreadable" {
    defer clearSource();

    const module_base: usize = 0x1_4000_0000;
    const slot_addr = module_base + offsets.graph.RVA_SYSTEM_INDEX_GLOBAL;
    const index: usize = 0x1_5000_0000;
    const table: usize = 0x1_6000_0000;
    installFakeSource(module_base);

    // (a) 一个区域都没开:全局槽读不到 ⇒ null,不解引用、不 panic。
    fake_mem.reset();
    try expectNull(getSystem(0));

    // (b) 全局槽 = 0:载入战役前的 BSS 形态。
    fake_mem.reset();
    fake_mem.open(slot_addr, 8);
    try expectNull(getSystem(0));

    // (c) 索引对象头部读不到(只开了全局槽)。
    fake_mem.reset();
    fake_mem.open(slot_addr, 8);
    fake_mem.putQword(slot_addr, index);
    try expectNull(getSystem(0));

    // (d) 表指针为 0。
    fake_mem.reset();
    fake_mem.open(slot_addr, 8);
    fake_mem.open(index, 0x28);
    fake_mem.putQword(slot_addr, index);
    fake_mem.putQword(index + offsets.graph.INDEX_TABLE_OFF, 0);
    fake_mem.putDword(index + offsets.graph.INDEX_BOUND_OFF, 4);
    try expectNull(getSystem(0));

    // (e) 槽数为 0:头部读到了但内容不像索引对象。
    fake_mem.reset();
    fake_mem.open(slot_addr, 8);
    fake_mem.open(index, 0x28);
    fake_mem.putQword(slot_addr, index);
    fake_mem.putQword(index + offsets.graph.INDEX_TABLE_OFF, table);
    fake_mem.putDword(index + offsets.graph.INDEX_BOUND_OFF, 0);
    try expectNull(getSystem(0));

    // (f) 槽数超防御上限 ⇒ 按容器损坏处理,不按「大表」去读。
    fake_mem.reset();
    fake_mem.open(slot_addr, 8);
    fake_mem.open(index, 0x28);
    fake_mem.putQword(slot_addr, index);
    fake_mem.putQword(index + offsets.graph.INDEX_TABLE_OFF, table);
    fake_mem.putDword(index + offsets.graph.INDEX_BOUND_OFF, @intCast(offsets.graph.MAX_TABLE_SLOTS + 1));
    try expectNull(getSystem(0));

    // (g) 槽表项为空槽。
    fake_mem.reset();
    fake_mem.open(slot_addr, 8);
    fake_mem.open(index, 0x28);
    fake_mem.open(table, 4 * offsets.graph.TABLE_RECORD_SIZE);
    fake_mem.putQword(slot_addr, index);
    fake_mem.putQword(index + offsets.graph.INDEX_TABLE_OFF, table);
    fake_mem.putDword(index + offsets.graph.INDEX_BOUND_OFF, 4);
    try expectNull(getSystem(0));

    // (h) 内存派生地址溢出:索引指针贴近 usize 上界,`+0x18` 回绕 ⇒ 读不到。
    //     回绕后的地址不是任何真实对象;Debug 构建里未检查的 `+` 会 panic。
    fake_mem.reset();
    fake_mem.open(slot_addr, 8);
    fake_mem.putQword(slot_addr, std.math.maxInt(usize) - 4);
    try expectNull(getSystem(0));
}

test "getSystem: 宿主构建没有可用的读入口时返回 null(fail closed)" {
    defer clearSource();
    // 不注入任何读入口:Linux 测试宿主上 `windows.moduleFunction` 取不到模块
    // ⇒ 读入口不存在 ⇒ 必须返回 null,而不是拿假地址去读。
    try expectNull(getSystem(0));
    try expectNull(getSystem(255));
}

test "getPlanet: stub returns null" {
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getPlanet(0));
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getPlanet(100));
}

test "getPop: stub returns null" {
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getPop(0));
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getPop(999));
}

test "getGameDate: stub returns empty" {
    try std.testing.expectEqualStrings("", getGameDate());
}

test "getGameTick: stub returns zero" {
    try std.testing.expectEqual(@as(i64, 0), getGameTick());
}

test "setVariable: stub returns false" {
    try std.testing.expect(!setVariable("test_var", 42));
    try std.testing.expect(!setVariable("another_var", -1));
}

test "addModifier: stub returns false" {
    // Can't create a real GameObjectHandle in test, but we can test with a dummy pointer
    const dummy_handle: GameObjectHandle = @ptrFromInt(0x1000);
    const mod = Modifier{ .name = "happiness", .value = 10 };
    try std.testing.expect(!addModifier(dummy_handle, mod));
}

test "triggerEvent: stub returns false" {
    const dummy_handle: GameObjectHandle = @ptrFromInt(0x1000);
    try std.testing.expect(!triggerEvent("my_event.1", dummy_handle));
}

test "removeModifier: stub returns false" {
    const dummy_handle: GameObjectHandle = @ptrFromInt(0x1000);
    try std.testing.expect(!removeModifier(dummy_handle, "happiness"));
}
