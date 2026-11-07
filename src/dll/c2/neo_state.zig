// neo_state.zig — 一个「解析好的 `set_variable`」对象的布局,供 C5-WRITE/C5-SCORE 共用。
//
// Spec: docs/superpowers/specs/2026-11-02-c5-write-state-design.md(C5-WRITE)
//       docs/superpowers/specs/2026-11-02-c5-score-state-design.md(C5-SCORE)
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
/// C5-WRITE:星系 id(回归项);C5-SCORE:图分数。
pub const VAR_NAME: []const u8 = "neo_mark";
pub const SCORE_NAME: []const u8 = "neo_score";

/// `0x18A6970` 的 `new(0x318)`。
pub const OBJECT_SIZE: usize = 0x318;

/// MSVC `std::string` 内联缓冲(SSO)能装下的最大字节数。超过就会被**静默截断**
/// 成另一个变量名,所以调用方(以及 `neo_vtable.writeVariable`)必须在写之前拒绝。
pub const SSO_MAX: usize = 15;

/// 名字包装起点;`std::string` 在 `NAME_OFF + 0x10`。
pub const NAME_OFF: usize = 0xC0;
pub const NAME_STRING_OFF: usize = 0xD0;
/// 值来源子对象起点;真正的值格在 `+0x220` 处 = 绝对 `+0x310`。
pub const VALUE_OFF: usize = 0xF0;
pub const VALUE_CELL_OFF: usize = 0x310;

/// 值格是脚本的数字类型:`0x3515A0` 取回的 qword 按 **1e-5 定点**解释。
/// 2026-11-02 第一发把裸 id 写进去,存档里得到 `0.00786`(而官方变量是
/// `years_passed=52` 这样的整数)⇒ 要写整数,必须 `number × 100000`。
pub fn encodeNumber(number: u32) u64 {
    return @as(u64, number) * 100_000;
}

// ---------------------------------------------------------------------------
// Phase 2 A1: the official `set_star_flag` object (`s.setStarFlag`)
// ---------------------------------------------------------------------------
//
// class_info `0x2610e80` → create `0x1895620`: `new(0x298)` → memset → base ctor
// `0x1840700` → publish vtable at `[obj+0]`. The vtable's `+0x48` slot is `0x180f8e0`;
// that body takes the `[+0xE8] == 0` branch and reads the u16 flag token id from
// `[+0xC0]`, resolves the system through `[vptr+0xE0]` (`0x180f8d0` → `0x397490`)
// and calls the engine's own flag writer `0x1bce180`. Zeroing the object is the
// whole layout: the string form (`+0xC8`/`+0xF8`, gated by `+0xE8 != 0`) is unused.
pub const STAR_FLAG_OBJECT_SIZE: usize = 0x298;
pub const STAR_FLAG_VTABLE: usize = 0x26049B0;
pub const STAR_FLAG_ID_OFF: usize = 0xC0;
pub const STAR_FLAG_STRING_SIZE_OFF: usize = 0xE8;

/// 摆一个「解析出 `set_star_flag = <flag_id>`」的对象。vtable 由调用方摆
/// (`neo_vtable.setStarFlag`),与 `layoutNumber` 同一条纪律。
pub fn layoutStarFlag(obj: *[STAR_FLAG_OBJECT_SIZE]u8, flag_id: u16) void {
    @memset(obj, 0);
    std.mem.writeInt(u16, obj[STAR_FLAG_ID_OFF..][0..2], flag_id, .little);
}

/// 把一个零初始化对象摆成「解析出了 `which = <name>`、`value = <number>` 的
/// `set_variable`」。**不摆 vtable**(调用方摆)、不动 `+0x300`(保持 0,这是短路的前提)。
///
/// `name` 必须 **≤ 15 字节**:`writeSso` 走 MSVC 内联串,超长会被**静默截断**成一个
/// 不同的变量名(每个 tick 都写)。`neo_mark`/`neo_score` 是 8/9 字节,当前调用方安全。
pub fn layoutNumber(obj: *[OBJECT_SIZE]u8, name: []const u8, number: u32) void {
    @memset(obj, 0);
    neo_effect.writeSso(@ptrCast(&obj[NAME_STRING_OFF]), name);
    std.mem.writeInt(u64, obj[VALUE_CELL_OFF..][0..8], encodeNumber(number), .little);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "layoutNumber writes any name as an MSVC short string at +0xD0" {
    var obj: [OBJECT_SIZE]u8 = [_]u8{0} ** OBJECT_SIZE;
    layoutNumber(&obj, SCORE_NAME, 286);
    try std.testing.expectEqualStrings(SCORE_NAME, obj[NAME_STRING_OFF .. NAME_STRING_OFF + SCORE_NAME.len]);
    // size 在 string 的 +0x10 = 绝对 +0xE0
    try std.testing.expectEqual(@as(u64, SCORE_NAME.len), std.mem.readInt(u64, obj[NAME_STRING_OFF + 0x10 ..][0..8], .little));
    // capacity 在 string 的 +0x18 = 绝对 +0xE8;`0x7EEBF0` 要求它 < 0x10 才走内联
    try std.testing.expectEqual(@as(u64, 15), std.mem.readInt(u64, obj[NAME_STRING_OFF + 0x18 ..][0..8], .little));
}

test "encodeNumber scales any script number to the 1e-5 fixed point" {
    // 2026-11-02 shot 1: raw `786` landed in the save as `0.00786`, while
    // vanilla variables are plain integers (`years_passed=52`).  The value
    // cell is the script number type: internal = value × 100000.
    try std.testing.expectEqual(@as(u64, 100_000), encodeNumber(1));
    try std.testing.expectEqual(@as(u64, 28_600_000), encodeNumber(286));
}

test "layoutNumber writes the encoded number at +0x310" {
    var obj: [OBJECT_SIZE]u8 = [_]u8{0} ** OBJECT_SIZE;
    layoutNumber(&obj, VAR_NAME, 4242);
    try std.testing.expectEqual(encodeNumber(4242), std.mem.readInt(u64, obj[VALUE_CELL_OFF..][0..8], .little));
}

test "layoutNumber leaves +0x300 and the vtable zero" {
    // `0x3515A0` 只在 `[src+0x210] == 0`(绝对 +0x300)时走短路直取 +0x310;
    // 非零就把我们带进「需要 token 流」的解析路径(Risk #1)。
    var obj: [OBJECT_SIZE]u8 = [_]u8{0} ** OBJECT_SIZE;
    layoutNumber(&obj, SCORE_NAME, 7);
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, obj[VALUE_OFF + 0x210 ..][0..8], .little));
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, obj[0..8], .little));
}

test "the object is the size the official create allocates" {
    try std.testing.expectEqual(@as(usize, 0x318), OBJECT_SIZE);
    try std.testing.expectEqual(@as(usize, 0xD0), NAME_STRING_OFF);
    try std.testing.expectEqual(@as(usize, 0x310), VALUE_CELL_OFF);
}

test "layoutStarFlag puts the u16 token id at +0xC0 and leaves +0xE8 zero" {
    var obj: [STAR_FLAG_OBJECT_SIZE]u8 = [_]u8{0xFF} ** STAR_FLAG_OBJECT_SIZE;
    layoutStarFlag(&obj, 10139);
    try std.testing.expectEqual(@as(u16, 10139), std.mem.readInt(u16, obj[STAR_FLAG_ID_OFF..][0..2], .little));
    // The body only takes the direct-id branch when [obj+0xE8] == 0.
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, obj[STAR_FLAG_STRING_SIZE_OFF..][0..8], .little));
    // Nothing else is allowed to survive: a stale byte anywhere else could steer
    // the body into the string path or the resolver.
    for (obj, 0..) |b, i| {
        if (i == STAR_FLAG_ID_OFF or i == STAR_FLAG_ID_OFF + 1) continue;
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "the star-flag object is the size the official create allocates" {
    try std.testing.expectEqual(@as(usize, 0x298), STAR_FLAG_OBJECT_SIZE);
    try std.testing.expectEqual(@as(usize, 0x26049B0), STAR_FLAG_VTABLE);
    try std.testing.expectEqual(@as(usize, 0xC0), STAR_FLAG_ID_OFF);
}
