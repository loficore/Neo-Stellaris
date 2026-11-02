// neo_state.zig — C5-WRITE:让 `neo_action` 在系统 scope 上写一个真实的游戏状态。
//
// Spec: docs/superpowers/specs/2026-11-02-c5-write-state-design.md
// 布局来源:evidence/disasm/set_variable_188e1d0.c(spec §3.1 的判决表)
//
// 本文件只放**纯函数**:对象布局与值编码。真正调官方 body 的地方在
// `neo_vtable.runBody`。合成对象是栈上的,不写引擎内存;官方 body 自己完成写。
//
// 布局(全部相对对象首字节;`0x18A6970` 的 `new(0x318)` 是官方尺寸):
//   +0x00  vtable        0x25EA560 —— **调用方摆**,这里留 0
//   +0x08  第二 vtable   0x25EA380 —— body 不读
//   +0xC0  名字包装      其 `+0x10` 才是 std::string(`0x7EEBF0` 入口 `add rdx,0x10`)
//   +0xD0  string 缓冲   16 B 内联
//   +0xE0  string size
//   +0xE8  string cap     必须 < 0x10 才走内联
//   +0xF0  值来源子对象  `0x188E1D0` 把它整块传给 `0x3515A0`
//   +0x300 `[src+0x210]` 必须为 0 ⇒ `0x3515A0` 短路直取 `+0x310`
//   +0x310 `[src+0x220]` 变量值(qword)

const std = @import("std");
const neo_effect = @import("neo_effect.zig");

/// 写进系统变量容器的名字。不是 keyword —— 不过 `c1_preflight` 那道门。
pub const VAR_NAME: []const u8 = "neo_mark";

/// `0x18A6970` 的 `new(0x318)`。
pub const OBJECT_SIZE: usize = 0x318;

/// 名字包装起点;`std::string` 在 `NAME_OFF + 0x10`。
pub const NAME_OFF: usize = 0xC0;
pub const NAME_STRING_OFF: usize = 0xD0;
/// 值来源子对象起点;真正的值格在 `+0x220` 处 = 绝对 `+0x310`。
pub const VALUE_OFF: usize = 0xF0;
pub const VALUE_CELL_OFF: usize = 0x310;

/// 值格是脚本的数字类型:`0x3515A0` 取回的 qword 按 **1e-5 定点**解释。
/// 2026-11-02 第一发把裸 id 写进去,存档里得到 `0.00786`(而官方变量是
/// `years_passed=52` 这样的整数)⇒ 要写整数 id,必须 `id × 100000`。
pub fn encodeValue(id: u32) u64 {
    return @as(u64, id) * 100_000;
}

/// 把一个零初始化对象摆成「解析出了 `value = <id>` 的 `set_variable`」。
/// **不摆 vtable**(调用方摆)、不动 `+0x300`(保持 0,这是短路的前提)。
pub fn layoutInto(obj: *[OBJECT_SIZE]u8, id: u32) void {
    @memset(obj, 0);
    neo_effect.writeSso(@ptrCast(&obj[NAME_STRING_OFF]), VAR_NAME);
    std.mem.writeInt(u64, obj[VALUE_CELL_OFF..][0..8], encodeValue(id), .little);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "layoutInto writes the name as an MSVC short string at +0xD0" {
    var obj: [OBJECT_SIZE]u8 = [_]u8{0} ** OBJECT_SIZE;
    layoutInto(&obj, 4242);
    try std.testing.expectEqualStrings(VAR_NAME, obj[NAME_STRING_OFF .. NAME_STRING_OFF + VAR_NAME.len]);
    // size 在 string 的 +0x10 = 绝对 +0xE0
    try std.testing.expectEqual(@as(u64, VAR_NAME.len),
        std.mem.readInt(u64, obj[NAME_STRING_OFF + 0x10 ..][0..8], .little));
    // capacity 在 string 的 +0x18 = 绝对 +0xE8;`0x7EEBF0` 要求它 < 0x10 才走内联
    try std.testing.expectEqual(@as(u64, 15),
        std.mem.readInt(u64, obj[NAME_STRING_OFF + 0x18 ..][0..8], .little));
}

test "layoutInto writes the encoded value at +0x310 as a qword" {
    var obj: [OBJECT_SIZE]u8 = [_]u8{0} ** OBJECT_SIZE;
    layoutInto(&obj, 4242);
    try std.testing.expectEqual(encodeValue(4242),
        std.mem.readInt(u64, obj[VALUE_CELL_OFF..][0..8], .little));
}

test "encodeValue scales the id to the engine's 1e-5 fixed point" {
    // 2026-11-02 shot 1: raw `786` landed in the save as `0.00786`, while
    // vanilla variables are plain integers (`years_passed=52`).  The value
    // cell is the script number type: internal = value × 100000.
    try std.testing.expectEqual(@as(u64, 100_000), encodeValue(1));
    try std.testing.expectEqual(@as(u64, 78_600_000), encodeValue(786));
}

test "layoutInto leaves the value-source presence flag at +0x300 zero" {
    // `0x3515A0` 只在 `[src+0x210] == 0`(绝对 +0x300)时走短路直取 +0x310;
    // 非零就把我们带进「需要 token 流」的解析路径(Risk #1)。
    var obj: [OBJECT_SIZE]u8 = [_]u8{0} ** OBJECT_SIZE;
    layoutInto(&obj, 7);
    try std.testing.expectEqual(@as(u64, 0),
        std.mem.readInt(u64, obj[VALUE_OFF + 0x210 ..][0..8], .little));
}

test "the vtable pointer stays zero — the caller installs it" {
    var obj: [OBJECT_SIZE]u8 = [_]u8{0} ** OBJECT_SIZE;
    layoutInto(&obj, 1);
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, obj[0..8], .little));
}

test "the object is the size the official create allocates" {
    try std.testing.expectEqual(@as(usize, 0x318), OBJECT_SIZE);
    try std.testing.expectEqual(@as(usize, 0xD0), NAME_STRING_OFF);
    try std.testing.expectEqual(@as(usize, 0x310), VALUE_CELL_OFF);
}
