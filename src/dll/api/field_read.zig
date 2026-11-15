// field_read.zig — #46 的字段读通道:一次调用读回一块 `[对象 + 偏移]` 的**原始字节**。
//
// 分工与 `gamestate.zig` / `graph_probe.zig` 一致:本模块只搬字节 ——
// 解析请求头、查表(`gamestate.getSystem` / `getCountry`)、`ReadProcessMemory`、
// 回填**同一块**缓冲。**判据不在这里**:「这三格是不是 owner」「锁 + 两旗标形状对不对」
// 全在 `scripts/c46_field_read.py`(纯函数,离线可测);Zig 侧只返回六个状态码。
//
// 只读:没有 hook、不写引擎内存、不改任何页保护、不建/删引擎对象。
// 冻结的契约 = 本文件的 `LAYOUT` 八个词 + 296 B 缓冲布局 + 六个状态码;
// 驱动侧 `EXPECTED_LAYOUT` 与 `docs/offline-tooling.md` 的表格必须逐字一致
// (改一处就要同时改 `PROTOCOL_VERSION`)。
//
// 偏移唯一来源:`src/dll/shared/offsets.zig` 的 `system_owner` 段(静态推断,未验证);
// 本文件不写字面量偏移。

const std = @import("std");
const offsets = @import("../shared/offsets.zig");

// ---------------------------------------------------------------------------
// 协议(冻结)
// ---------------------------------------------------------------------------

pub const LAYOUT_VERSION: u32 = 1;

/// 一块缓冲 = 40 B 请求/回复头 + 256 B 数据。
pub const BUF_SIZE: usize = 296;

/// 请求头(驱动写进来的四个字段)。
pub const OFF_KIND: usize = 0; // u64
pub const OFF_SUBJECT: usize = 8; // u64
pub const OFF_OFF: usize = 16; // u32
pub const OFF_LEN: usize = 20; // u32

/// 回复头(DLL 写回去的三个字段)。`OFF_STATUS` 与请求头相邻,所以请求只占前 24 B。
pub const OFF_STATUS: usize = 24; // i32
pub const OFF_GOT: usize = 28; // u32
pub const OFF_RESOLVED: usize = 32; // u64

/// 数据区起点。
pub const OFF_DATA: usize = 40;

/// 一次能请求的最大字节数。`len = 0` 与 `len > MAX_LEN` 一律拒读(-3):
/// 截断后的「成功读数」是伪造证据,所以 DLL 侧不截断、不部分成功。
pub const MAX_LEN: u32 = 256;

/// `kind` 的合法值域:1 = 系统 id、2 = 国家 id、3 = 裸地址。其余一律 -5。
pub const KIND_SYSTEM: u64 = 1;
pub const KIND_COUNTRY: u64 = 2;
pub const KIND_RAW: u64 = 3;
pub const MAX_KIND: u32 = 3;

/// 六个状态码。**值域之外没有任何一层含义** —— 判词住在驱动里。
pub const StatusOk: i32 = 0;
/// 模块基址取不到:我们不在游戏进程里(不是某一次读失败)。
pub const StatusNoBase: i32 = -1;
/// `kind` 指的对象解析不上(系统/国家 id 在表里查不到;`kind=3` 的 `subject=0`)。
pub const StatusUnresolved: i32 = -2;
/// 请求的 `len` 越界(`0` 或 `> MAX_LEN`),或调用方给的缓冲短于 `BUF_SIZE`。
pub const StatusBadLen: i32 = -3;
/// 地址解析成功但读不回来(越界 / 不可读页)。
pub const StatusUnreadable: i32 = -4;
/// `kind` 不在 1..=3。
pub const StatusBadKind: i32 = -5;

/// 请求头(解码后的视图)。只有 `decode` 会填它。
pub const Request = struct {
    kind: u64,
    subject: u64,
    off: u32,
    len: u32,
};

/// 八个词的对账契约,顺序即驱动 `EXPECTED_LAYOUT` 的顺序:
/// `[version, BUF_SIZE, OFF_DATA, MAX_LEN, MAX_KIND, owner_off, owner_lock_off, id_mask]`。
pub const LAYOUT: [8]u32 = .{
    LAYOUT_VERSION,
    BUF_SIZE,
    OFF_DATA,
    MAX_LEN,
    MAX_KIND,
    @intCast(offsets.system_owner.OWNER_OFF),
    @intCast(offsets.system_owner.OWNER_LOCK_OFF),
    offsets.system_owner.ID_MASK,
};

// ---------------------------------------------------------------------------
// 读逻辑(纯函数面:Linux 单测直接调,生产导出在后面接上)
// ---------------------------------------------------------------------------

/// 一个只读内存抽象,与 `galaxy_graph.zig` / `graph_probe.zig` 的 `Memory` 同形:
/// `ctx` 由读者自己解释(合成镜像在测试侧,进程内 `ReadProcessMemory` 在生产侧)。
pub const Reader = struct {
    ctx: *anyopaque,
    /// 读 `addr` 起 `len` 字节;不可读返回 false(与 `readProcessMemory` 的
    /// `got == out.len` 契约同形 —— 少读一个字节就是没读到)。
    read: *const fn (ctx: *anyopaque, addr: usize, len: usize, buf: []u8) bool,
};

/// `kind + subject` → 对象绝对地址。解析不上返回 null(→ -2)。
/// **生产实现只查表**(`gamestate.getSystem` / `getCountry`);本模块不做任何引擎语义判断。
pub const Resolver = *const fn (kind: u64, subject: u64) ?usize;

/// 解一块协议缓冲的**请求头**。缓冲装不下整个头(含 `status`/`got`/`resolved`)⇒ null:
/// 一个连回复头都放不下的缓冲不是协议缓冲,serve 会在它上面越界写。
pub fn decode(buf: []const u8) ?Request {
    if (buf.len < OFF_DATA) return null;
    return .{
        .kind = std.mem.readInt(u64, buf[OFF_KIND..][0..8], .little),
        .subject = std.mem.readInt(u64, buf[OFF_SUBJECT..][0..8], .little),
        .off = std.mem.readInt(u32, buf[OFF_OFF..][0..4], .little),
        .len = std.mem.readInt(u32, buf[OFF_LEN..][0..4], .little),
    };
}

/// 把 `addr` 起 `out.len` 字节读进 `out`。`0 = StatusOk`、`-4 = StatusUnreadable`。
/// 失败时把 `out` 抹成 0:调用方拿到的永远是「这一次读到的」或「什么都没有」,
/// 不是上一发留下的字节。
pub fn plainRead(r: Reader, addr: usize, out: []u8) i32 {
    if (addr == 0 or out.len == 0) return StatusUnreadable;
    if (!r.read(r.ctx, addr, out.len, out)) {
        @memset(out, 0);
        return StatusUnreadable;
    }
    return StatusOk;
}

/// 就地服务一块 `BUF_SIZE` 缓冲:请求头进 → 解析 → 回填同一块缓冲 → 返回状态码。
///
/// 顺序是契约(Review Focus #1,半途读数):
///   ① 先把请求四格**拷出来**(否则下面的清零会把它自己抹掉);
///   ② 整块清零 —— 上一发的读数不可能活到这一次;
///   ③ 校验 `len`(`0` / `> MAX_LEN` ⇒ -3,**不截断**);
///   ④ `kind=3` 拿 `subject` 当地址;`kind=1/2` 走 `resolve`;其余 -5;
///   ⑤ 读失败 -4;
///   ⑥ 回填头 + 数据并返回 `status`。
///
/// 失败分支只回填**头**(`status`/`got = 0`/`resolved` 诊断值),数据区保持全 0:
/// 「部分成功」不是这个协议的合法输出。
pub fn serve(buf: []u8, r: Reader, resolve: Resolver) i32 {
    if (buf.len < BUF_SIZE) return StatusBadLen;
    const req = decode(buf) orelse return StatusBadLen;
    @memset(buf, 0);

    if (req.len == 0 or req.len > MAX_LEN) return reply(buf, req, StatusBadLen, 0, 0);

    var base: usize = undefined;
    if (req.kind == KIND_RAW) {
        if (req.subject == 0) return reply(buf, req, StatusUnresolved, 0, 0);
        if (req.subject > std.math.maxInt(usize)) return reply(buf, req, StatusUnresolved, 0, 0);
        base = @intCast(req.subject);
    } else if (req.kind == KIND_SYSTEM or req.kind == KIND_COUNTRY) {
        base = resolve(req.kind, req.subject) orelse return reply(buf, req, StatusUnresolved, 0, 0);
    } else {
        return reply(buf, req, StatusBadKind, 0, 0);
    }
    const resolved: u64 = @intCast(base);

    // 地址回绕不是「读到别处」:相加溢出 ⇒ 读不到(Debug 构建里未检查的 `+` 会 panic)。
    const addr = std.math.add(usize, base, @as(usize, req.off)) catch
        return reply(buf, req, StatusUnreadable, 0, resolved);

    const data = buf[OFF_DATA..][0..@as(usize, req.len)];
    const st = plainRead(r, addr, data);
    if (st != StatusOk) return reply(buf, req, st, 0, resolved);
    return reply(buf, req, StatusOk, req.len, resolved);
}

/// 回填头(请求四格原样回显 + 状态三格)。数据由 `serve` 自己写好了。
fn reply(buf: []u8, req: Request, status: i32, got: u32, resolved: u64) i32 {
    std.mem.writeInt(u64, buf[OFF_KIND..][0..8], req.kind, .little);
    std.mem.writeInt(u64, buf[OFF_SUBJECT..][0..8], req.subject, .little);
    std.mem.writeInt(u32, buf[OFF_OFF..][0..4], req.off, .little);
    std.mem.writeInt(u32, buf[OFF_LEN..][0..4], req.len, .little);
    std.mem.writeInt(i32, buf[OFF_STATUS..][0..4], status, .little);
    std.mem.writeInt(u32, buf[OFF_GOT..][0..4], got, .little);
    std.mem.writeInt(u64, buf[OFF_RESOLVED..][0..8], resolved, .little);
    return status;
}

// ---------------------------------------------------------------------------
// 生产侧:进程内读 + 两个查表解析器 + 两个导出用的入口
// ---------------------------------------------------------------------------

const windows = @import("../hooking/windows.zig");
const gamestate = @import("gamestate.zig");

/// 生产读实现:`ReadProcessMemory` 的薄包装。`len` 参数不用 —— 以 `buf.len` 为准,
/// 与 `graph_probe.memRead` / `gamestate.prodRead` 同口径(两个长度不该有两种含义)。
fn prodRead(_: *anyopaque, addr: usize, len: usize, buf: []u8) bool {
    _ = len;
    return windows.readProcessMemory(addr, buf);
}

fn prodReader() Reader {
    return .{ .ctx = undefined, .read = &prodRead };
}

/// 生产解析器:`kind=1` 走系统表、`kind=2` 走国家表 —— **同一条** 16 B 记录查表
/// (`gamestate.getSystem` / `getCountry`,站点与复核条件见那两处的 docstring)。
/// id 超出 u32 一律解析不上:截断后去查表会安静地读到另一个对象。
fn prodResolve(kind: u64, subject: u64) ?usize {
    if (subject > std.math.maxInt(u32)) return null;
    const id: u32 = @truncate(subject);
    const obj = switch (kind) {
        KIND_SYSTEM => gamestate.getSystem(id),
        KIND_COUNTRY => gamestate.getCountry(id),
        else => null,
    };
    return if (obj) |p| @intFromPtr(p) else null;
}

/// 就地服务一块 `BUF_SIZE` 缓冲,返回值 = header 的 `status`。
///
/// 模块基址取不到 ⇒ `-1`:那时我们不在游戏进程里,连 `kind=3` 的裸地址都不该读
/// (读到的任何字节都不是引擎状态,而是一个看起来像读数的假证据)。
pub fn readInto(buf: [*]u8) i32 {
    _ = windows.moduleFunction(0) catch return StatusNoBase;
    return serve(buf[0..BUF_SIZE], prodReader(), &prodResolve);
}

/// 写八个 layout 词,返回 `8`(驱动按这个数判断缓冲够不够)。
pub fn layoutInto(out: *[8]u32) u32 {
    out.* = LAYOUT;
    return 8;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "协议常量与 offsets 的 owner 段互相对得上" {
    const so = @import("../shared/offsets.zig").system_owner;
    try std.testing.expectEqual(@as(u32, 1), LAYOUT[0]); // PROTOCOL_VERSION
    try std.testing.expectEqual(@as(u32, 296), LAYOUT[1]); // BUF_SIZE
    try std.testing.expectEqual(@as(u32, 40), LAYOUT[2]); // OFF_DATA
    try std.testing.expectEqual(@as(u32, 256), LAYOUT[3]); // MAX_LEN
    try std.testing.expectEqual(@as(u32, 3), LAYOUT[4]); // MAX_KIND
    try std.testing.expectEqual(@as(u32, 0x1370), LAYOUT[5]); // so.OWNER_OFF
    try std.testing.expectEqual(@as(u32, 0x1374), LAYOUT[6]); // so.OWNER_LOCK_OFF
    try std.testing.expectEqual(@as(u32, 0x00FF_FFFF), LAYOUT[7]); // so.ID_MASK
    try std.testing.expectEqual(@as(usize, 0x1378), so.OWNER_FLAG_A_OFF);
    try std.testing.expectEqual(@as(usize, 0x1379), so.OWNER_FLAG_B_OFF);
    try std.testing.expectEqual(@as(u32, 0xFFFF_FFFF), so.NO_OWNER);
    // 头 + 数据恰好铺满一块缓冲:多一个字节就是协议漂了,少一个字节就是越界写。
    try std.testing.expectEqual(BUF_SIZE, OFF_DATA + MAX_LEN);
    // 六个状态码互不相同(驱动按值分派,重复值会把两档判词混成一档)。
    const codes = [_]i32{ StatusOk, StatusNoBase, StatusUnresolved, StatusBadLen, StatusUnreadable, StatusBadKind };
    for (codes, 0..) |a, i| {
        for (codes[i + 1 ..]) |b| try std.testing.expect(a != b);
    }
}

// ---------------------------------------------------------------------------
// 合成镜像(无引擎、无 Windows API):一块 8 KiB 的内存 + 一个固定偏移的「对象」
// ---------------------------------------------------------------------------
//
// **为什么是 8 KiB 而不是计划里写的 4 KiB**:`+0x1379` 是**真实**偏移(4,985),
// 4 KiB 镜像里连 owner 那一格都装不下。宁可放大镜像,也不把测试用的偏移改成假数字 ——
// 否则测试证明的是「假偏移能读」,不是「我们那一格能读」。

const testing = std.testing;

const IMAGE_BASE: usize = 0x1_0000_0000;
const IMAGE_LEN: usize = 0x2000;
/// 「系统对象」在镜像里的位置。`OBJECT_OFF + OWNER_FLAG_B_OFF` 必须落在镜像内。
const OBJECT_OFF: usize = 0x200;

var image: [IMAGE_LEN]u8 = @splat(0);

fn imageRead(_: *anyopaque, addr: usize, len: usize, buf: []u8) bool {
    if (addr < IMAGE_BASE) return false;
    const off = addr - IMAGE_BASE;
    if (off > IMAGE_LEN or len > IMAGE_LEN - off) return false;
    @memcpy(buf, image[off..][0..len]);
    return true;
}

fn imageReader() Reader {
    return .{ .ctx = undefined, .read = &imageRead };
}

/// `kind=1` 的 id 7 → 镜像里的那个对象;其他一律解析不上(测试要能看见 -2)。
fn imageResolve(kind: u64, subject: u64) ?usize {
    if (kind == KIND_SYSTEM and subject == 7) return IMAGE_BASE + OBJECT_OFF;
    return null;
}

fn armRequest(buf: []u8, kind: u64, subject: u64, off: u32, len: u32) void {
    @memset(buf, 0xA5); // 先用非零铺满:serve 必须自己清零,不能留上次的读数
    std.mem.writeInt(u64, buf[OFF_KIND..][0..8], kind, .little);
    std.mem.writeInt(u64, buf[OFF_SUBJECT..][0..8], subject, .little);
    std.mem.writeInt(u32, buf[OFF_OFF..][0..4], off, .little);
    std.mem.writeInt(u32, buf[OFF_LEN..][0..4], len, .little);
}

fn replyField(comptime T: type, buf: []const u8, off: usize) T {
    return std.mem.readInt(T, buf[off..][0..@sizeOf(T)], .little);
}

test "kind=1: 解析到对象后按 off/len 回填,状态与 got 一致" {
    image = @splat(0);
    const owner_addr = OBJECT_OFF + offsets.system_owner.OWNER_OFF;
    std.mem.writeInt(u32, image[owner_addr..][0..4], 0x0000_0007, .little);

    var buf: [BUF_SIZE]u8 = undefined;
    armRequest(&buf, KIND_SYSTEM, 7, @intCast(offsets.system_owner.OWNER_OFF), 4);
    const rc = serve(&buf, imageReader(), &imageResolve);

    try testing.expectEqual(StatusOk, rc);
    try testing.expectEqual(@as(i32, 0), replyField(i32, &buf, OFF_STATUS));
    try testing.expectEqual(@as(u32, 4), replyField(u32, &buf, OFF_GOT));
    try testing.expectEqual(@as(u64, IMAGE_BASE + OBJECT_OFF), replyField(u64, &buf, OFF_RESOLVED));
    try testing.expectEqualSlices(u8, &.{ 7, 0, 0, 0 }, buf[OFF_DATA..][0..4]);
    // 请求头原样回显:驱动靠它判「这块缓冲是这一发的」(Review Focus #1)。
    try testing.expectEqual(@as(u64, KIND_SYSTEM), replyField(u64, &buf, OFF_KIND));
    try testing.expectEqual(@as(u64, 7), replyField(u64, &buf, OFF_SUBJECT));
    try testing.expectEqual(@as(u32, 0x1370), replyField(u32, &buf, OFF_OFF));
    try testing.expectEqual(@as(u32, 4), replyField(u32, &buf, OFF_LEN));
    // 数据区之外一个字节都不许动(否则上一次的读数会从缝里漏出来)。
    try testing.expect(std.mem.allEqual(u8, buf[OFF_DATA + 4 ..], 0));
}

test "kind=3: 裸地址直读;subject=0 判 -2" {
    image = @splat(0);
    image[0x300] = 0xDE;
    image[0x301] = 0xAD;

    var buf: [BUF_SIZE]u8 = undefined;
    armRequest(&buf, KIND_RAW, IMAGE_BASE + 0x300, 0, 2);
    const rc = serve(&buf, imageReader(), &imageResolve);
    try testing.expectEqual(StatusOk, rc);
    try testing.expectEqual(@as(u32, 2), replyField(u32, &buf, OFF_GOT));
    try testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD }, buf[OFF_DATA..][0..2]);
    try testing.expectEqual(@as(u64, IMAGE_BASE + 0x300), replyField(u64, &buf, OFF_RESOLVED));

    // subject == 0 不是一个可读地址,是「没给地址」:判 -2,不许回退去读 0 页。
    armRequest(&buf, KIND_RAW, 0, 0, 4);
    const rc0 = serve(&buf, imageReader(), &imageResolve);
    try testing.expectEqual(StatusUnresolved, rc0);
    try testing.expectEqual(@as(i32, -2), replyField(i32, &buf, OFF_STATUS));
    try testing.expectEqual(@as(u32, 0), replyField(u32, &buf, OFF_GOT));
    try testing.expectEqual(@as(u64, 0), replyField(u64, &buf, OFF_RESOLVED));
    try testing.expect(std.mem.allEqual(u8, buf[OFF_DATA..], 0));
}

test "len=0 与 len=257 都判 -3:header.status 回填、got=0、数据区全 0" {
    image = @splat(0);
    var buf: [BUF_SIZE]u8 = undefined;

    for ([_]u32{ 0, MAX_LEN + 1 }) |bad_len| {
        armRequest(&buf, KIND_SYSTEM, 7, 0x1370, bad_len);
        const rc = serve(&buf, imageReader(), &imageResolve);
        try testing.expectEqual(StatusBadLen, rc);
        try testing.expectEqual(@as(i32, -3), replyField(i32, &buf, OFF_STATUS));
        try testing.expectEqual(@as(u32, 0), replyField(u32, &buf, OFF_GOT));
        // 截断后的「成功读数」是伪造证据:失败分支不许回填任何数据字节。
        try testing.expect(std.mem.allEqual(u8, buf[OFF_DATA..], 0));
    }
    try testing.expectEqual(@as(u32, 257), MAX_LEN + 1);

    // 短缓冲是**拒读**,不是一个可以部分服务的请求:一个字节都不写。
    var short: [BUF_SIZE - 1]u8 = @splat(0x5A);
    try testing.expectEqual(StatusBadLen, serve(&short, imageReader(), &imageResolve));
    try testing.expect(std.mem.allEqual(u8, &short, 0x5A));
}

test "越界地址判 -4,header.status 与返回值相等" {
    image = @splat(0);
    var buf: [BUF_SIZE]u8 = undefined;
    armRequest(&buf, KIND_SYSTEM, 7, 0x7FFF_FFF0, 4);
    const rc = serve(&buf, imageReader(), &imageResolve);
    try testing.expectEqual(StatusUnreadable, rc);
    try testing.expectEqual(rc, replyField(i32, &buf, OFF_STATUS));
    try testing.expectEqual(@as(u32, 0), replyField(u32, &buf, OFF_GOT));
    // 解析成功、读失败:`resolved` 仍然回填 —— 它是诊断,不是数据。
    try testing.expectEqual(@as(u64, IMAGE_BASE + OBJECT_OFF), replyField(u64, &buf, OFF_RESOLVED));
    try testing.expect(std.mem.allEqual(u8, buf[OFF_DATA..], 0));

    // 解析不上 ⇒ -2(与 -4 分开:一个是「哪个对象」,一个是「读不到」)。
    armRequest(&buf, KIND_SYSTEM, 8, 0x1370, 4);
    try testing.expectEqual(StatusUnresolved, serve(&buf, imageReader(), &imageResolve));
}

test "layoutInto 写八个词并返回 8(驱动按这个数判缓冲够不够)" {
    var words: [8]u32 = @splat(0xDEAD_BEEF);
    try testing.expectEqual(@as(u32, 8), layoutInto(&words));
    try testing.expectEqualSlices(u32, &LAYOUT, &words);
}

test "readInto: 宿主构建取不到模块基址时返回 -1(fail closed)" {
    // Linux 测试宿主上 `windows.moduleFunction` 直接 error.ModuleNotFound ⇒
    // 我们不在游戏进程里 ⇒ 连 kind=3 的裸地址都不读(读到的不是引擎状态)。
    var buf: [BUF_SIZE]u8 = @splat(0x5A);
    try testing.expectEqual(StatusNoBase, readInto(&buf));
    try testing.expect(std.mem.allEqual(u8, &buf, 0x5A));
}

test "prodResolve: 宿主的查表恒失败;id 超出 u32 一律解析不上" {
    try testing.expectEqual(@as(?usize, null), prodResolve(KIND_SYSTEM, 7));
    try testing.expectEqual(@as(?usize, null), prodResolve(KIND_COUNTRY, 41));
    // 未定形的 kind 与超宽 id 都不许走查表(截断后查表会读到另一个对象)。
    try testing.expectEqual(@as(?usize, null), prodResolve(KIND_RAW, 0x1_0000_0000));
    try testing.expectEqual(@as(?usize, null), prodResolve(9, 7));
}

test "kind=9 判 -5;decode 对 24 字节的短缓冲返回 null" {
    image = @splat(0);
    var buf: [BUF_SIZE]u8 = undefined;
    armRequest(&buf, 9, 7, 0x1370, 4);
    const rc = serve(&buf, imageReader(), &imageResolve);
    try testing.expectEqual(StatusBadKind, rc);
    try testing.expectEqual(@as(i32, -5), replyField(i32, &buf, OFF_STATUS));
    try testing.expectEqual(@as(u64, 9), replyField(u64, &buf, OFF_KIND));

    // decode 只认能装下整个头的缓冲:24 B(只有请求四格)与 39 B 都不算协议缓冲。
    var tiny: [24]u8 = @splat(0);
    std.mem.writeInt(u64, tiny[OFF_KIND..][0..8], KIND_RAW, .little);
    try testing.expectEqual(@as(?Request, null), decode(&tiny));
    var almost: [OFF_DATA - 1]u8 = @splat(0);
    try testing.expectEqual(@as(?Request, null), decode(&almost));

    var full: [OFF_DATA]u8 = @splat(0);
    std.mem.writeInt(u64, full[OFF_KIND..][0..8], KIND_COUNTRY, .little);
    std.mem.writeInt(u64, full[OFF_SUBJECT..][0..8], 41, .little);
    std.mem.writeInt(u32, full[OFF_OFF..][0..4], 0x1e88, .little);
    std.mem.writeInt(u32, full[OFF_LEN..][0..4], 4, .little);
    const req = decode(&full).?;
    try testing.expectEqual(KIND_COUNTRY, req.kind);
    try testing.expectEqual(@as(u64, 41), req.subject);
    try testing.expectEqual(@as(u32, 0x1e88), req.off);
    try testing.expectEqual(@as(u32, 4), req.len);
}
