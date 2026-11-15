// country_probe.zig — C3 国家侦察发（2026-11-08）的**纯只读**读器。
//
// 形状全部取自静态取证，本文件不自造偏移：
//
//   国家对象表   T = [0x3260FD8]              `country_scope_4_4_4.md` §7（B+）
//                bound = [T+0x20]、root = [T+0x18]
//                entry = [root + id*0x10 + 8]（步长 0x10，取 +8 那一格）
//                id 复核：`[entry+0x20] == id`（Review Focus 2）
//   经济持有者   E = [obj+0x2c68]             `country_fields_4_4_4.md` §1.3/§1.8（B）
//                vt = [E]；[vt+0x90] / [vt+0x98] = 两个槽目标（只读指针，**不调用**）
//                （C3 实机 2026-11-08 抓到：本文件原先读 [E+0x90]，那是对象字段；
//                 引擎在 0x1adf75d/0x1adf767 读的是 [[E]+0x90]，槽在 vtable 上）
//   资源库       db = [0x33746F0]             `country_fields_4_4_4.md` §1.4/§1.6
//                res_n = [db+0x14]；energy_obj = [db+0x20]；energy_idx = [energy_obj+0x18]
//   资源存量     `runtime_444_country_energy_4_4_4.md` §1.2/§2.4/§2.5（判决
//                `cached_scalar_named`）：容器 `[country+0x2c68]` → holder `+0x28`
//                → 向量对象 `{data@0x00, count@0x0C}`；三个研究资源走
//                `[[container+0x10]+0x1900/8/10]`。逐指令读链见 `stock()` 上方。
//
// 纪律（计划 Global Constraints / Review Focus 1–3）：
//   * **只读**：全部经注入的 `Memory.read_u32/read_u64`，不调用任何引擎虚函数
//     （`E->vfn[+0x90]` 会填充调用方向量，是**读容器**的唯一已知路径，但本发不碰它），
//     不写引擎内存、不改存档。`+0x90`/`+0x98` 只把**槽里的函数指针**读出来折算成 RVA。
//   * **不猜**：表/对象/持有者任何一格读不到或为 0 ⇒ 对应字段留空，不拿 0 当读数。
//   * **不越界**：`id >= bound` 与 `[obj+0x20] != id` 都在读 `econ` **之前**判掉；
//     地址算术全部用 `std.math.add/mul`（出货 DLL 是 Debug 构建，一次溢出 = `abort()`，
//     AGENTS 约束 8）。
//   * 地址是**绝对**值（`module_base + RVA` 由调用方算好），`module_base` 只用来把
//     指针折算成 RVA；折算不成立（指针不在 `[base, base+0x4000_0000)`）就留 0。

const std = @import("std");

/// 注入的读内存面。生产适配器用 host 的 `readU32Safe`/`readU64Safe`
/// （Windows 上带 `isCommitted`）；测试用合成镜像。
pub const Memory = struct {
    ctx: *anyopaque,
    read_u32: *const fn (ctx: *anyopaque, addr: u64) ?u32,
    read_u64: *const fn (ctx: *anyopaque, addr: u64) ?u64,
};

/// 两个全局**槽**的绝对地址（不是槽里装的值）。
pub const Addresses = struct {
    /// `0x3260FD8` —— 国家对象表。
    country_table: u64,
    /// `0x33746F0` —— 资源库。
    resource_db: u64,
};

pub const RVA_COUNTRY_TABLE: u64 = 0x3260FD8;
pub const RVA_RESOURCE_DB: u64 = 0x33746F0;

// ---------------------------------------------------------------------------
// 资源存量（2026-11-15）：`runtime_444_country_energy_4_4_4.md` §1.2/§2.4/§2.5
// ---------------------------------------------------------------------------
//
// 常量只有这一份（计划 Global Constraints）：host 侧不许出现第二个 `0x2c68`。

/// `[country+0x2c68]` = 0x48 B 的存量容器（布局 A：构造 `0x844ae0` / 克隆
/// `0x844890` / 释放 `0x844820` / 向量初始化器 `0x1760770` 四处互钉）。
pub const RESOURCE_CONTAINER_OFF: u64 = 0x2C68;
/// 容器里的**向量持有者**槽。`0x844215`（槽 `+0x90`）把它交给向量赋值
/// `0x410060`；初始化器在 `0x1760795` 把它写成 `container+0x30`。
pub const RESOURCE_VECTOR_HOLDER_OFF: u64 = 0x28;
/// 向量对象的 data（`0x41007d`、`0x1760780`）。**基准是向量对象（holder）**，不是容器：
/// 卷 §2.5 的常量表用容器相对口径，同一格写作 `+0x30`（初始化器 `0x1760795` 与克隆
/// `0x8448fe` 都保证 `holder == container+0x30`，两个口径在正常容器上同址）。
pub const RESOURCE_VECTOR_DATA_OFF: u64 = 0x00;
/// 向量对象的 count（`0x410085`、`0x176078a`）。**不是**容量（那在 `+0x08`）；
/// 容器相对口径 = `+0x3C`（同上：基准不同，不是两个不同的格）。
pub const RESOURCE_VECTOR_COUNT_OFF: u64 = 0x0C;
/// 容器里的**所有者对象**：三个研究资源的覆盖源（`0x844237`、`0x8442dc`）。
pub const RESOURCE_OWNER_OFF: u64 = 0x10;
/// 资源库里的三个研究资源对象（`[db+off]`），顺序与下面那张表逐项对应。
pub const RESOURCE_DB_RESEARCH_OFF = [_]u64{ 0x48, 0x50, 0x58 };
/// 三个研究资源在**所有者对象**上的字段（`0x844242`/`0x84425c`/`0x844279`）。
pub const OWNER_STORED_RESEARCH_OFF = [_]u64{ 0x1900, 0x1908, 0x1910 };
/// 资源对象自己的索引字段（`0x1adf774`、`0x843904`）：向量下标 = 这个数。
pub const RESOURCE_INDEX_OFF: u64 = 0x18;
/// 向量元素步长（8 B / 格）。
pub const RESOURCE_STRIDE: u64 = 8;
/// 存量的定点标度：`÷ 1e5`。只在存量路径证过（卷 §2.5 的档 B+）。
pub const RESOURCE_SCALE: i64 = 100_000;

/// 指针折算成 RVA 的上界：模块镜像远小于 1 GiB，超出就是「不是引擎指针」。与 host
/// `noteOtherScope` 的 vtable 折算同一口径。
const MODULE_SPAN: u64 = 0x4000_0000;

pub const Reading = struct {
    /// 对象表解析成功且 `[obj+0x20] == id`。资源库那一半与它无关。
    object_found: bool = false,
    econ: u64 = 0,
    econ_vtable_rva: u64 = 0,
    slot90_rva: u64 = 0,
    slot98_rva: u64 = 0,
    res_n: u32 = 0,
    energy_obj: u64 = 0,
    energy_idx: ?u32 = null,
};

pub fn collect(mem: Memory, addrs: Addresses, country_id: u32, module_base: u64) Reading {
    var r = Reading{};
    readObject(mem, addrs, country_id, module_base, &r);
    readResources(mem, addrs, &r);
    return r;
}

fn readObject(mem: Memory, addrs: Addresses, country_id: u32, module_base: u64, r: *Reading) void {
    const obj = countryObject(mem, addrs, country_id) orelse return;
    r.object_found = true;

    const econ_addr = add64(obj, RESOURCE_CONTAINER_OFF) orelse return;
    const econ = mem.read_u64(mem.ctx, econ_addr) orelse return;
    if (econ == 0) return;
    r.econ = econ;

    const vt = mem.read_u64(mem.ctx, econ) orelse 0;
    r.econ_vtable_rva = rva(vt, module_base);
    if (vt != 0) {
        r.slot90_rva = rva(mem.read_u64(mem.ctx, add64(vt, 0x90) orelse 0) orelse 0, module_base);
        r.slot98_rva = rva(mem.read_u64(mem.ctx, add64(vt, 0x98) orelse 0) orelse 0, module_base);
    }
}

/// 国家 id → 对象指针（`Reading.object_found` 与 `stock()` 共用这一条链）。
/// 三道门都在返回非空**之前**：表槽非零、`id < bound`、`[obj+0x20] == id`。
fn countryObject(mem: Memory, addrs: Addresses, country_id: u32) ?u64 {
    // 槽地址 0（模块基址没解析到）不是「表在 0 号地址」—— 连读都不读。
    if (addrs.country_table == 0) return null;
    const t = mem.read_u64(mem.ctx, addrs.country_table) orelse return null;
    if (t == 0) return null;

    const bound_addr = add64(t, 0x20) orelse return null;
    const bound = mem.read_u32(mem.ctx, bound_addr) orelse return null;
    if (country_id >= bound) return null;

    const root_addr = add64(t, 0x18) orelse return null;
    const root = mem.read_u64(mem.ctx, root_addr) orelse return null;
    if (root == 0) return null;

    const slot_off = mul64(@as(u64, country_id), 0x10) orelse return null;
    const entry_off = add64(root, slot_off) orelse return null;
    const entry_addr = add64(entry_off, 8) orelse return null;
    const obj = mem.read_u64(mem.ctx, entry_addr) orelse return null;
    if (obj == 0) return null;

    // Review Focus 2：表项可能指向空对象/已释放对象 —— id 不复核就不读 econ。
    const id_addr = add64(obj, 0x20) orelse return null;
    const obj_id = mem.read_u32(mem.ctx, id_addr) orelse return null;
    if (obj_id != country_id) return null;
    return obj;
}

/// 一个国家、一个资源索引的**存量原值**（定点，未除 1e5）。
///
/// `null` = fail-closed 之一（`0` 是「这个国家真有 0 单位」的合法读数，绝不用它
/// 表示失败）：无读源 / 国家对象解析失败 / `[obj+0x2c68]` 为 0 / 向量持有者为 0 /
/// 向量 data 为 0 / `index >= count` / 研究资源那一路的 owner 为 0。
///
/// **读链（Task 0 逐指令钉死，站点是 RVA，全在 `stellaris.exe` 4.4.4）：**
///
///     container = *(u64*)(obj + 0x2C68)     0x1adf73b（`has_country_resource` 取值体）
///                                           单资源 helper `0x843A00`：容器由**调用方**经 rcx 传入，
///                                           `0x843a9c` 是同一条惯用法里的 vtable 取值体
///                                           （`mov rax,[rcx]`），不是容器取点
///     holder    = *(u64*)(container + 0x28) 0x844215  lea rdx,[rcx+0x28]  ← 槽 +0x90 的原地址
///     vector    = holder                    0x41006a  mov rax,[rdx]      ← 一次 deref 得到向量对象
///     data      = *(u64*)(vector + 0x00)    0x41007d  mov rbp,[rax]
///     count     = *(u32*)(vector + 0x0C)    0x410085  movsxd rsi,[rax+0xc]
///     value     = *(i64*)(data + index*8)   0x843ab4..0x843acd（同一组指令的另一份）
///
/// 所以**是两跳**（容器 → holder → 向量对象），不是 `§2.5` 一行式看起来的一跳。
/// 两者在正常容器上同值：初始化器 `0x1760770` 在 `0x1760795` 把
/// `[container+0x28]` 写成 `container+0x30`（克隆 `0x8448fe` 同样直写），于是
/// `holder == container+0x30`、`data == [container+0x30]`。本实现走 holder：
/// 引擎自己的访问路径就是这条，且容器若换成堆上的向量只有这条还成立。
///
/// **两个读者不构成反例**：`0x1adf73b`/`0x843a9c` 都不直接摸容器，它们把
/// `&vec` 交给 vtable 槽 `+0x90`（`0x844200`），那个槽再 `lea rdx,[rcx+0x28]` 交给
/// 向量赋值 `0x410060` —— 同一个 holder。两个函数里的 `cmp idx,[vec+0xC]` 读的是
/// **复制出来的**向量（count = 资源条数），不是容器里的那份；本读器按容器的
/// `count` 兜界（每帧重取，不缓存 data 指针：`+0x98` 与克隆都可能重排它们）。
///
/// **三个研究资源是例外**（卷 §2.4）：槽 `+0x90` 在复制完缓存后，用
/// `[[container+0x10]+0x1900/0x1908/0x1910]` **覆盖** physics/society/engineering
/// 三格 —— 向量里那三格不是引擎读的值。识别方式不写死索引：读
/// `[db+0x48]/[db+0x50]/[db+0x58]` 三个资源对象各自的 `+0x18`，拿它比。
pub fn stock(mem: Memory, addrs: Addresses, country_id: u32, index: u32) ?i64 {
    const obj = countryObject(mem, addrs, country_id) orelse return null;

    const container_addr = add64(obj, RESOURCE_CONTAINER_OFF) orelse return null;
    const container = mem.read_u64(mem.ctx, container_addr) orelse return null;
    if (container == 0) return null;

    if (researchFieldOffset(mem, addrs, index)) |owner_off| {
        const owner_addr = add64(container, RESOURCE_OWNER_OFF) orelse return null;
        const owner = mem.read_u64(mem.ctx, owner_addr) orelse return null;
        if (owner == 0) return null;
        const field_addr = add64(owner, owner_off) orelse return null;
        const v = mem.read_u64(mem.ctx, field_addr) orelse return null;
        return @bitCast(v);
    }

    const holder_addr = add64(container, RESOURCE_VECTOR_HOLDER_OFF) orelse return null;
    const holder = mem.read_u64(mem.ctx, holder_addr) orelse return null;
    if (holder == 0) return null;

    const count_addr = add64(holder, RESOURCE_VECTOR_COUNT_OFF) orelse return null;
    const count = mem.read_u32(mem.ctx, count_addr) orelse return null;
    if (index >= count) return null;

    const data_addr = add64(holder, RESOURCE_VECTOR_DATA_OFF) orelse return null;
    const data = mem.read_u64(mem.ctx, data_addr) orelse return null;
    if (data == 0) return null;

    const stride = mul64(@as(u64, index), RESOURCE_STRIDE) orelse return null;
    const cell = add64(data, stride) orelse return null;
    const v = mem.read_u64(mem.ctx, cell) orelse return null;
    return @bitCast(v);
}

/// 若 `index` 是三个研究资源之一，返回它在**所有者对象**上的字段偏移。
///
/// 索引来自资源库自己的对象（`+0x18`），不写死 0/1/2：`energy_idx` 已经证过
/// 会随 `db_n` 变（mod 加资源就改编号）。资源库读不到 ⇒ 认不出来 ⇒ 返回 null，
/// 让调用方走向量那条（这时没有证据说它是研究资源）。
fn researchFieldOffset(mem: Memory, addrs: Addresses, index: u32) ?u64 {
    if (addrs.resource_db == 0) return null;
    const db = mem.read_u64(mem.ctx, addrs.resource_db) orelse return null;
    if (db == 0) return null;

    for (RESOURCE_DB_RESEARCH_OFF, 0..) |db_off, i| {
        const slot = add64(db, db_off) orelse continue;
        const resource = mem.read_u64(mem.ctx, slot) orelse continue;
        if (resource == 0) continue;
        const idx_addr = add64(resource, RESOURCE_INDEX_OFF) orelse continue;
        const resource_idx = mem.read_u32(mem.ctx, idx_addr) orelse continue;
        if (resource_idx == index) return OWNER_STORED_RESEARCH_OFF[i];
    }
    return null;
}

fn readResources(mem: Memory, addrs: Addresses, r: *Reading) void {
    if (addrs.resource_db == 0) return;
    const db = mem.read_u64(mem.ctx, addrs.resource_db) orelse return;
    if (db == 0) return;

    const count_addr = add64(db, 0x14) orelse return;
    r.res_n = mem.read_u32(mem.ctx, count_addr) orelse 0;

    const obj_addr = add64(db, 0x20) orelse return;
    const obj = mem.read_u64(mem.ctx, obj_addr) orelse return;
    if (obj == 0) return;
    r.energy_obj = obj;

    const idx_addr = add64(obj, RESOURCE_INDEX_OFF) orelse return;
    r.energy_idx = mem.read_u32(mem.ctx, idx_addr);
}

fn rva(ptr: u64, module_base: u64) u64 {
    if (module_base == 0) return 0;
    if (ptr < module_base) return 0;
    const off = ptr - module_base;
    return if (off < MODULE_SPAN) off else 0;
}

fn add64(a: u64, b: u64) ?u64 {
    return std.math.add(u64, a, b) catch null;
}

fn mul64(a: u64, b: u64) ?u64 {
    return std.math.mul(u64, a, b) catch null;
}

// ---------------------------------------------------------------------------
// Tests —— 合成镜像（一块真实字节区，所有读都经 Memory，越界即失败）
// ---------------------------------------------------------------------------

const testing = std.testing;

/// 镜像覆盖 `0x1000..0x9000`：地址布局照计划 Step 1 的四个用例。
/// 任何落在区外的读都算 `escaped` —— 读器走出结构时测试能看见，
/// 而不是读到一个看起来合理的垃圾值。
const Mirror = struct {
    const BASE: usize = 0x1000;
    const SIZE: usize = 0x8000;

    buf: [SIZE]u8 = [_]u8{0} ** SIZE,
    escaped: usize = 0,

    fn memory(self: *Mirror) Memory {
        return .{ .ctx = @ptrCast(self), .read_u32 = read32, .read_u64 = read64 };
    }

    fn read32(ctx: *anyopaque, addr: u64) ?u32 {
        var b: [4]u8 = undefined;
        if (!readRange(ctx, addr, &b)) return null;
        return std.mem.readInt(u32, &b, .little);
    }

    fn read64(ctx: *anyopaque, addr: u64) ?u64 {
        var b: [8]u8 = undefined;
        if (!readRange(ctx, addr, &b)) return null;
        return std.mem.readInt(u64, &b, .little);
    }

    fn readRange(ctx: *anyopaque, addr: u64, out: []u8) bool {
        const self: *Mirror = @ptrCast(@alignCast(ctx));
        const base: u64 = BASE;
        if (addr < base) {
            self.escaped += 1;
            return false;
        }
        const off = addr - base;
        if (off > SIZE or off + out.len > SIZE) {
            self.escaped += 1;
            return false;
        }
        @memcpy(out, self.buf[@intCast(off)..][0..out.len]);
        return true;
    }

    fn putQword(self: *Mirror, addr: usize, v: u64) void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        @memcpy(self.buf[addr - BASE ..][0..8], &b);
    }

    fn putDword(self: *Mirror, addr: usize, v: u32) void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        @memcpy(self.buf[addr - BASE ..][0..4], &b);
    }
};

test "country_probe resolves the object through the country table and reads the econ holder" {
    var m = Mirror{};
    // 0x1000: 全局槽 -> table 0x1100 = { root=0x2000 @+0x18, bound=4 @+0x20 }
    m.putQword(0x1000, 0x1100);
    m.putQword(0x1118, 0x2000);
    m.putDword(0x1120, 4);
    // 0x2000 + id*0x10 + 8 = 条目 -> 对象 0x3000
    m.putQword(0x2000 + 2 * 0x10 + 8, 0x3000);
    // 对象 +0x20 = id；+0x2c68 = 0x4000
    m.putDword(0x3020, 2);
    m.putQword(0x3000 + 0x2c68, 0x4000);
    // 0x4000 的 [0] = vtable 0x5000；槽在 vtable 上：[0x5000+0x90] / [+0x98]
    m.putQword(0x4000, 0x5000);
    m.putQword(0x5090, 0x1000 + 0x1234);
    m.putQword(0x5098, 0x1000 + 0x5678);

    const r = collect(m.memory(), .{ .country_table = 0x1000, .resource_db = 0 }, 2, 0x1000);

    try testing.expect(r.object_found);
    try testing.expectEqual(@as(u64, 0x4000), r.econ);
    try testing.expectEqual(@as(u64, 0x5000 - 0x1000), r.econ_vtable_rva);
    try testing.expectEqual(@as(u64, 0x1234), r.slot90_rva);
    try testing.expectEqual(@as(u64, 0x5678), r.slot98_rva);
    // 资源库槽是 0：读不到就是没有，不是 0 号资源。
    try testing.expectEqual(@as(u32, 0), r.res_n);
    try testing.expectEqual(@as(?u32, null), r.energy_idx);
    try testing.expectEqual(@as(usize, 0), m.escaped);
}

test "country_probe rejects an out-of-range id and an id mismatch" {
    var m = Mirror{};
    m.putQword(0x1000, 0x1100);
    m.putQword(0x1118, 0x2000);
    m.putDword(0x1120, 4);
    m.putQword(0x2000 + 2 * 0x10 + 8, 0x3000);
    m.putQword(0x3000 + 0x2c68, 0x4000);

    // 1) id == bound：越界，连表项都不该读。
    const oor = collect(m.memory(), .{ .country_table = 0x1000, .resource_db = 0 }, 4, 0x1000);
    try testing.expect(!oor.object_found);
    try testing.expectEqual(@as(u64, 0), oor.econ);

    // 2) 表项指向的对象 id 是 9，与请求的 2 不符：不复核就会读到别人的 econ。
    m.putDword(0x3020, 9);
    const mismatch = collect(m.memory(), .{ .country_table = 0x1000, .resource_db = 0 }, 2, 0x1000);
    try testing.expect(!mismatch.object_found);
    try testing.expectEqual(@as(u64, 0), mismatch.econ);
    try testing.expectEqual(@as(usize, 0), m.escaped);
}

test "country_probe reads the resource db count and the energy index" {
    var m = Mirror{};
    // resource_db 槽 = 0x6000；[0x6000] = 0x6100；[0x6100+0x14]=8；[0x6100+0x20]=0x6200；[0x6200+0x18]=3
    m.putQword(0x6000, 0x6100);
    m.putDword(0x6114, 8);
    m.putQword(0x6120, 0x6200);
    m.putDword(0x6218, 3);

    const r = collect(m.memory(), .{ .country_table = 0, .resource_db = 0x6000 }, 7, 0x1000);

    try testing.expect(!r.object_found);
    try testing.expectEqual(@as(u32, 8), r.res_n);
    try testing.expectEqual(@as(u64, 0x6200), r.energy_obj);
    try testing.expectEqual(@as(?u32, 3), r.energy_idx);
    try testing.expectEqual(@as(usize, 0), m.escaped);
}

test "country_probe tolerates a null econ holder and a null resource db" {
    var m = Mirror{};
    m.putQword(0x1000, 0x1100);
    m.putQword(0x1118, 0x2000);
    m.putDword(0x1120, 4);
    m.putQword(0x2000 + 1 * 0x10 + 8, 0x3000);
    m.putDword(0x3020, 1);
    // [obj+0x2c68] 留 0（未提交/未初始化）。
    m.putQword(0x3000 + 0x2c68, 0);

    const r = collect(m.memory(), .{ .country_table = 0x1000, .resource_db = 0 }, 1, 0x1000);

    try testing.expect(r.object_found);
    try testing.expectEqual(@as(u64, 0), r.econ);
    try testing.expectEqual(@as(u64, 0), r.econ_vtable_rva);
    try testing.expectEqual(@as(u64, 0), r.slot90_rva);
    try testing.expectEqual(@as(u64, 0), r.slot98_rva);
    // db = 0：res_n=0、energy_idx=null，且没有去读地址 0。
    try testing.expectEqual(@as(u32, 0), r.res_n);
    try testing.expectEqual(@as(?u32, null), r.energy_idx);
    try testing.expectEqual(@as(usize, 0), m.escaped);
}

// --- 资源存量（Task 1：四条合成镜像用例）------------------------------------

/// 表 → 对象那条链的三个新用例共用的开头：`0x1000` 全局槽 → 表 `0x1100`，
/// `id` 的条目指向 `obj`，`[obj+0x20] = id`，`[obj+0x2c68] = container`。
fn putCountry(m: *Mirror, id: u32, obj: usize, container: usize) void {
    m.putQword(0x1000, 0x1100);
    m.putQword(0x1118, 0x2000);
    m.putDword(0x1120, 4);
    m.putQword(0x2000 + @as(usize, id) * 0x10 + 8, obj);
    m.putDword(obj + 0x20, id);
    m.putQword(obj + 0x2c68, container);
}

/// 容器 → holder → 向量对象（data/count）。`holder` 就是 `container+0x30` 在
/// 真实引擎里的值；这里给两个不同地址，证明读器走的是 holder 那一跳。
fn putVector(m: *Mirror, container: usize, holder: usize, data: usize, count: u32) void {
    m.putQword(container + 0x28, holder);
    m.putQword(holder, data);
    m.putDword(holder + 0xC, count);
}

test "country_probe stock reads the container's vector cell" {
    var m = Mirror{};
    putCountry(&m, 2, 0x3000, 0x4000);
    putVector(&m, 0x4000, 0x4100, 0x4200, 4);
    m.putQword(0x4208, 1_234_567); // 下标 1

    const mem = m.memory();
    const addrs: Addresses = .{ .country_table = 0x1000, .resource_db = 0 };

    try testing.expectEqual(@as(?i64, 1_234_567), stock(mem, addrs, 2, 1));
    // 0 是合法读数（这个国家真有 0 单位），**不是**「不可用」。
    try testing.expectEqual(@as(?i64, 0), stock(mem, addrs, 2, 0));
    try testing.expectEqual(@as(?i64, 0), stock(mem, addrs, 2, 3));
    // 没有 id 就没有对象：同一个合成镜像里不存在 id 3。
    try testing.expectEqual(@as(?i64, null), stock(mem, addrs, 3, 1));
    try testing.expectEqual(@as(usize, 0), m.escaped);
}

test "country_probe stock fails closed past the count and on a null data pointer" {
    var m = Mirror{};
    putCountry(&m, 1, 0x3000, 0x4000);
    putVector(&m, 0x4000, 0x4100, 0x4200, 4);
    m.putQword(0x4218, @bitCast(@as(i64, -5))); // 下标 3 = -5（i64 原样，不钳零：钳零是写路径的事）

    const mem = m.memory();
    const addrs: Addresses = .{ .country_table = 0x1000, .resource_db = 0 };

    try testing.expectEqual(@as(?i64, -5), stock(mem, addrs, 1, 3));
    // count = 4 ⇒ 下标 4 越界，不是「读到 0」。
    try testing.expectEqual(@as(?i64, null), stock(mem, addrs, 1, 4));
    try testing.expectEqual(@as(?i64, null), stock(mem, addrs, 1, 0xFFFF_FFFF));

    // count 仍 > 0 但 data 为 0：没有可读的格子。
    m.putQword(0x4100, 0);
    try testing.expectEqual(@as(?i64, null), stock(mem, addrs, 1, 0));
    try testing.expectEqual(@as(usize, 0), m.escaped);
}

test "country_probe stock routes the three research resources around the vector" {
    var m = Mirror{};
    putCountry(&m, 2, 0x3000, 0x4000);
    putVector(&m, 0x4000, 0x4100, 0x4200, 8);
    m.putQword(0x4218, 999_999); // 向量第 3 格：**引擎不读这一格**
    m.putQword(0x4210, 42); // 向量第 2 格：普通资源，照旧读这里
    m.putQword(0x4000 + 0x10, 0x4300); // 所有者对象
    m.putQword(0x4300 + 0x1900, 424_242); // physics
    m.putQword(0x4300 + 0x1908, 555); // society
    m.putQword(0x4300 + 0x1910, 7); // engineering

    // 资源库：三个研究对象的**索引不写死**，这里故意用 3 / 5 / 6。
    m.putQword(0x6000, 0x6100);
    m.putQword(0x6148, 0x6200); // [db+0x48] physics_research
    m.putDword(0x6218, 3);
    m.putQword(0x6150, 0x6300); // [db+0x50] society_research
    m.putDword(0x6318, 5);
    m.putQword(0x6158, 0x6400); // [db+0x58] engineering_research
    m.putDword(0x6418, 6);

    const mem = m.memory();
    const addrs: Addresses = .{ .country_table = 0x1000, .resource_db = 0x6000 };

    // 三个索引各自取到所有者字段，而不是向量里的 999_999。
    try testing.expectEqual(@as(?i64, 424_242), stock(mem, addrs, 2, 3));
    try testing.expectEqual(@as(?i64, 555), stock(mem, addrs, 2, 5));
    try testing.expectEqual(@as(?i64, 7), stock(mem, addrs, 2, 6));
    // 别的索引照旧走向量（下标 3 的 999_999 仍然在那里，只是没人读它）。
    try testing.expectEqual(@as(?i64, 42), stock(mem, addrs, 2, 2));
    try testing.expectEqual(@as(usize, 0), m.escaped);
}

test "country_probe stock fails closed with no container or no research owner" {
    var m = Mirror{};

    // 1) [obj+0x2c68] 为 0：没有容器。
    putCountry(&m, 1, 0x3000, 0);
    const addrs0: Addresses = .{ .country_table = 0x1000, .resource_db = 0 };
    try testing.expectEqual(@as(?i64, null), stock(m.memory(), addrs0, 1, 0));

    // 2) 容器有、索引命中研究资源、但所有者对象为 0 ⇒ null（不是 0）。
    var m2 = Mirror{};
    putCountry(&m2, 1, 0x3000, 0x4000);
    putVector(&m2, 0x4000, 0x4100, 0x4200, 8);
    m2.putQword(0x4218, 111); // 向量第 3 格有个看起来合理的值
    m2.putQword(0x6000, 0x6100);
    m2.putQword(0x6148, 0x6200);
    m2.putDword(0x6218, 3);
    const addrs1: Addresses = .{ .country_table = 0x1000, .resource_db = 0x6000 };
    try testing.expectEqual(@as(?i64, null), stock(m2.memory(), addrs1, 1, 3));

    // 3) 不是研究资源、但 holder 为 0 ⇒ null。
    var m3 = Mirror{};
    putCountry(&m3, 1, 0x3000, 0x4000);
    m3.putQword(0x4000 + 0x28, 0);
    try testing.expectEqual(@as(?i64, null), stock(m3.memory(), addrs0, 1, 0));

    try testing.expectEqual(@as(usize, 0), m.escaped);
    try testing.expectEqual(@as(usize, 0), m2.escaped);
    try testing.expectEqual(@as(usize, 0), m3.escaped);
}
