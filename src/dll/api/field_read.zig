// field_read.zig — #46 的字段读通道:一次调用读回一块 `[对象 + 偏移]` 的**原始字节**。
//
// 分工与 `gamestate.zig` / `graph_probe.zig` 一致:本模块只搬字节 ——
// 解析请求头、查表(`gamestate.getSystem` / `getCountry`)、`ReadProcessMemory`、
// 回填**同一块**缓冲。**判据不在这里**:「这三格是不是 owner」「锁 + 两旗标形状对不对」
// 全在 `scripts/c46_field_read.py`(纯函数,离线可测);Zig 侧只返回六个状态码。
//
// 只读:没有 hook、没有 `WriteProcessMemory`、没有 `VirtualProtect`、不建/删引擎对象。
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
