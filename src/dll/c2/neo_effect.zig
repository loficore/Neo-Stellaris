// neo_effect.zig — C5-ADD:让引擎按星系调用我们的效果。
//
// Spec: docs/superpowers/specs/2026-11-02-c5-add-effect-keyword-design.md
//
// 这一半是纯函数:文案格式化、MSVC std::string 的 SSO 写入、以及「哪些星系才动手」的规则。
// 执行体(读 scope、合成对象、调 `0x185BF60`)在铁的 / 实机那一侧,见本文件的 `execute`
// 一节 —— 它只调用下面这三个纯函数,所以正确性的大头在 `zig build test` 里就能证。

const std = @import("std");

// ---------------------------------------------------------------------------
// Pure functions
// ---------------------------------------------------------------------------

/// The one log line the game is asked to write, one per selected system.
/// Returns the written slice; an undersized buffer yields an empty slice rather
/// than a truncated line, so a bad caller shows up as "no line", not garbage.
pub fn formatText(dst: []u8, id: u32) []const u8 {
    return std.fmt.bufPrint(dst, "Neo: system {d}", .{id}) catch dst[0..0];
}

/// MSVC `std::string` layout in the engine: `{ buf[16] @ +0x00, size @ +0x10,
/// capacity @ +0x18 }`. `0x185BF60` reads `[self+0x38]` as that shape, so this
/// must be a byte-for-byte short string — no heap, capacity pinned at 15.
pub fn writeSso(dst: *[0x20]u8, text: []const u8) void {
    @memset(dst, 0);
    const n = @min(text.len, 15);
    @memcpy(dst[0..n], text[0..n]);
    std.mem.writeInt(u64, dst[0x10..0x18], n, .little);
    std.mem.writeInt(u64, dst[0x18..0x20], 15, .little);
}

/// §92's rule, same shape as `exec_caller_probe.ruleMatches`: act only on
/// systems whose id satisfies `id % mod == rem`. `mod == 0` disables the rule.
var rule_mod: u32 = 0;
var rule_rem: u32 = 0;

pub fn setRule(mod: u32, rem: u32) void {
    rule_mod = mod;
    rule_rem = if (mod == 0) 0 else rem % mod;
}

pub fn matches(id: u32) bool {
    if (rule_mod == 0) return false;
    return id % rule_mod == rule_rem;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "formatText writes Neo: system <id>" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Neo: system 123", formatText(&buf, 123));
}

test "writeSso lays out an MSVC short string" {
    var s: [0x20]u8 = [_]u8{0} ** 0x20;
    writeSso(&s, "abc");
    try std.testing.expectEqual(@as(u64, 3), std.mem.readInt(u64, s[0x10..0x18], .little));
    try std.testing.expectEqual(@as(u64, 15), std.mem.readInt(u64, s[0x18..0x20], .little));
    try std.testing.expectEqualStrings("abc", s[0..3]);
}

test "the rule is id % mod == rem, disabled at mod = 0" {
    setRule(100, 0);
    try std.testing.expect(matches(200));
    try std.testing.expect(!matches(201));
    setRule(0, 0);
    try std.testing.expect(!matches(0));
}
