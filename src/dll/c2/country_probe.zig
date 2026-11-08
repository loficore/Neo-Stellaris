// country_probe.zig — C3 国家侦察发（2026-11-08）的**纯只读**读器。
//
// 形状全部取自静态取证，本文件不自造偏移：
//
//   国家对象表   T = [0x3260FD8]              `country_scope_4_4_4.md` §7（B+）
//                bound = [T+0x20]、root = [T+0x18]
//                entry = [root + id*0x10 + 8]（步长 0x10，取 +8 那一格）
//                id 复核：`[entry+0x20] == id`（Review Focus 2）
//   经济持有者   E = [obj+0x2c68]             `country_fields_4_4_4.md` §1.3/§1.8（B）
//                [E] = vtable；[E+0x90] / [E+0x98] = 两个槽目标（只读指针，**不调用**）
//   资源库       db = [0x33746F0]             `country_fields_4_4_4.md` §1.4/§1.6
//                res_n = [db+0x14]；energy_obj = [db+0x20]；energy_idx = [energy_obj+0x18]
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
    // 槽地址 0（模块基址没解析到）不是「表在 0 号地址」—— 连读都不读。
    if (addrs.country_table == 0) return;
    const t = mem.read_u64(mem.ctx, addrs.country_table) orelse return;
    if (t == 0) return;

    const bound_addr = add64(t, 0x20) orelse return;
    const bound = mem.read_u32(mem.ctx, bound_addr) orelse return;
    if (country_id >= bound) return;

    const root_addr = add64(t, 0x18) orelse return;
    const root = mem.read_u64(mem.ctx, root_addr) orelse return;
    if (root == 0) return;

    const slot_off = mul64(@as(u64, country_id), 0x10) orelse return;
    const entry_off = add64(root, slot_off) orelse return;
    const entry_addr = add64(entry_off, 8) orelse return;
    const obj = mem.read_u64(mem.ctx, entry_addr) orelse return;
    if (obj == 0) return;

    // Review Focus 2：表项可能指向空对象/已释放对象 —— id 不复核就不读 econ。
    const id_addr = add64(obj, 0x20) orelse return;
    const obj_id = mem.read_u32(mem.ctx, id_addr) orelse return;
    if (obj_id != country_id) return;
    r.object_found = true;

    const econ_addr = add64(obj, 0x2c68) orelse return;
    const econ = mem.read_u64(mem.ctx, econ_addr) orelse return;
    if (econ == 0) return;
    r.econ = econ;

    const vt = mem.read_u64(mem.ctx, econ) orelse 0;
    r.econ_vtable_rva = rva(vt, module_base);
    r.slot90_rva = rva(mem.read_u64(mem.ctx, add64(econ, 0x90) orelse 0) orelse 0, module_base);
    r.slot98_rva = rva(mem.read_u64(mem.ctx, add64(econ, 0x98) orelse 0) orelse 0, module_base);
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

    const idx_addr = add64(obj, 0x18) orelse return;
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
    // 0x4000 的 [0] = vtable 0x5000；[0x90] = base+0x1234；[0x98] = base+0x5678
    m.putQword(0x4000, 0x5000);
    m.putQword(0x4090, 0x1000 + 0x1234);
    m.putQword(0x4098, 0x1000 + 0x5678);

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
