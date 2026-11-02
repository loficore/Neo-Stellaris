// neo_dispatch.zig — C5-ADD 的真正机制:在**逐系统派发点**上换掉那个 effect。
//
// 为什么不是换对象的 vtable(2026-11-02 实机否定):
//   C4 的 predicate detour(`[vptr+0x98]`)只在**运行时实例化**的对象上跑过 —— §54.4
//   的 console 命令让 `pred_patched` 从 0 变 1。但脚本文件里解析出来的 effect 树
//   不走那条路:C5-ADD 第一发(`pred_calls=485,569`)里 `pred_patched=0`,而事件文件
//   直到 13:51:04 才注册(`setup.log`),注入 13:50:30 就完成了 —— 所以不是时序,
//   是「解析期建的对象不经谓词」。⇒ 换槽位的前提拿不到。
//
// 换成派发点:`0x3B0F80`(§91.6/§91.7 的 787 条读数全部从它的 `0x3B101C` 进来)。
// 它收 `(child_object, scope)`,先按 §91.6 读 `[child+0x20]` 的 token id,再
// `call [child_vptr+0xa8]`(scope 门)与 `call [child_vptr+0x48]`(body)。
// 我们的 detour 只做一件事:**token 是我们的**就不转发,直接跑 `neo_vtable.runBody`,
// 其余 token 原样 `jmp` 回原函数(`.always_tail`,因为 trampoline 是把目标的前 18 字节
//   逐字节抄过去再跳回;普通 `call` 会把 `rsp` 压低 8 字节,抄过去的 `[rsp+0x18]`
//   写点就错位 —— §91.1 那次三发全死的教训)。
//
// 只读 `[child+0x20]` 与 scope 的两个格子;不写引擎内存、不改对象 `[self]`。

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const windows = @import("../hooking/windows.zig");
const detour_mod = @import("../hooking/detour.zig");
const neo_vtable = @import("neo_vtable.zig");

const is_windows = builtin.os.tag == .windows;

/// §91.6 — 逐系统派发:`0x3B0F80..0x3B1155`,派发点是 `0x3B101C call [rax+0x48]`。
pub const RVA_DISPATCH: usize = 0x3B0F80;

pub const STATS_SIZE: usize = 512;

/// 19 B = 目标的前八条指令(`mov [rsp+0x18],rbx` / `push rbp` / `push rsi` /
/// `push rdi` / `push r14` / `push r15` / `sub rsp,0x20` / `mov rbp,rdx`)。
/// 全部是栈操作与寄存器搬移 ⇒ 抄进 trampoline 不需要重定位。detour.zig 的 14 B
/// JMP 会按整条指令向后补齐到 18 B。
pub const EXPECTED_CODE = [19]u8{
    0x48, 0x89, 0x5C, 0x24, 0x18, // mov [rsp+0x18], rbx
    0x55, // push rbp
    0x56, // push rsi
    0x57, // push rdi
    0x41, 0x56, // push r14
    0x41, 0x57, // push r15
    0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
    0x48, 0x8B, 0xEA, // mov rbp, rdx
};

const OBJECT_TOKEN_OFF: usize = offsets.keyword_reg.EFFECT_OBJECT_TOKEN_ID;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var armed_token: u32 = 0;
var installed = false;
var hook: ?detour_mod.Hook = null;
var orig: ?*anyopaque = null;
var target_addr: usize = 0;
var saved_code: [32]u8 = [_]u8{0} ** 32;

/// Every entry through the detour, and the subset whose token was ours.  The
/// pair is what separates "the hook is not on the path" from "it is, but the
/// keyword's object carries another id" — the two readings C5-ADD's first shot
/// could not tell apart.
var stat_seen: u64 = 0;
var stat_ours: u64 = 0;
var last_token: u32 = 0;

// ---------------------------------------------------------------------------
// Safe memory access
// ---------------------------------------------------------------------------

fn plausible(p: usize) bool {
    return p >= 0x10000 and p <= 0x00007FFF_FFFF_0000 and (p & 7) == 0;
}

fn readU32(addr: usize, comptime off: usize) u32 {
    if (!plausible(addr)) return 0;
    const base: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u32, base[off..][0..4], .little);
}

pub fn shouldRun(value: u32) bool {
    const armed = @atomicLoad(u32, &armed_token, .monotonic);
    return armed != 0 and value == armed;
}

// ---------------------------------------------------------------------------
// The detour
// ---------------------------------------------------------------------------

const OrigFn = *const fn (u64, u64, u64) callconv(.c) u64;

fn dispatchDetour(child: u64, scope: u64, a3: u64) callconv(.c) u64 {
    _ = @atomicRmw(u64, &stat_seen, .Add, 1, .monotonic);
    const child_token = readU32(@intCast(child), OBJECT_TOKEN_OFF);
    @atomicStore(u32, &last_token, child_token, .monotonic);
    if (shouldRun(child_token)) {
        _ = @atomicRmw(u64, &stat_ours, .Add, 1, .monotonic);
        return neo_vtable.runBody(scope, a3);
    }
    const f: OrigFn = @ptrCast(orig orelse return 0);
    // `.always_tail` is load-bearing — see the module header.
    return @call(.always_tail, f, .{ child, scope, a3 });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Arm the token C1 minted for `neo_action`. Rejects 0 (the engine never writes
/// it, so it would match every uninitialised object) and changes while installed.
pub fn setToken(value: u32) error{ InvalidToken, AlreadyInstalled }!void {
    if (value == 0) return error.InvalidToken;
    if (installed) return error.AlreadyInstalled;
    @atomicStore(u32, &armed_token, value, .monotonic);
}

pub fn clearToken() void {
    @atomicStore(u32, &armed_token, 0, .monotonic);
}

pub fn token() u32 {
    return @atomicLoad(u32, &armed_token, .monotonic);
}

pub fn install() !void {
    if (!is_windows) return error.Unsupported;
    if (installed) return error.AlreadyInstalled;

    const target = try windows.moduleFunction(RVA_DISPATCH);
    if (detour_mod.isHooked(target)) return error.AlreadyHooked;
    target_addr = @intFromPtr(target);

    const tb: [*]const u8 = @ptrCast(target);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return error.UnexpectedPrologue;
    }
    @memcpy(&saved_code, tb[0..saved_code.len]);

    const h = try detour_mod.installHookArmed(target, @ptrCast(@constCast(&dispatchDetour)), &orig);
    if (h.patch_size > saved_code.len) return error.PatchTooWide;
    hook = h;
    installed = true;
    std.log.info("c2.neo_dispatch: installed detour at 0x{x}", .{RVA_DISPATCH});
}

fn restoreTarget(len: usize) !void {
    var guard = try windows.ProtectGuard.change(@ptrFromInt(target_addr), len, .execute_readwrite);
    defer guard.deinit();
    const dst: [*]u8 = @ptrFromInt(target_addr);
    @memcpy(dst[0..len], saved_code[0..len]);
    windows.flushInstructionCache(@ptrFromInt(target_addr), len);
}

pub fn uninstall() !void {
    if (!installed) return;
    const h = hook orelse return;
    detour_mod.removeHook(&h) catch {};
    hook = null;
    installed = false;
    try restoreTarget(h.patch_size);
    orig = null;
    if (!fingerprintMatches()) return error.RestoreIncomplete;
    std.log.info("c2.neo_dispatch: uninstalled detour", .{});
}

pub fn fingerprintMatches() bool {
    if (target_addr == 0) return false;
    const tb: [*]const u8 = @ptrFromInt(target_addr);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return false;
    }
    return true;
}

/// 0 = consistent | -1 hook lost | -2 engine bytes differ | -3 never installed.
pub fn verify() i32 {
    if (target_addr == 0) return -3;
    const target: *anyopaque = @ptrFromInt(target_addr);
    if (installed) return if (detour_mod.isHooked(target)) 0 else -1;
    return if (fingerprintMatches()) 0 else -2;
}

pub fn isInstalled() bool {
    return installed;
}

pub fn dispatched() u64 {
    return @atomicLoad(u64, &stat_seen, .monotonic);
}

pub fn ours() u64 {
    return @atomicLoad(u64, &stat_ours, .monotonic);
}

pub fn lastToken() u32 {
    return @atomicLoad(u32, &last_token, .monotonic);
}

/// One line, fixed key order: the plan's seven keys followed by `dispatched` —
/// the entry count the detour saw, which is what makes `calls=0` readable.
pub fn statsInto(out: []u8) usize {
    const written = std.fmt.bufPrint(
        out,
        "calls={d} matched={d} log_calls={d} last_id={d} rule_hits={d} installed={d} verify={d} dispatched={d}\n",
        .{
            ours(),
            neo_vtable.matched(),
            neo_vtable.logCalls(),
            neo_vtable.lastId(),
            neo_vtable.ruleHitsRecorded(),
            @intFromBool(installed),
            verify(),
            dispatched(),
        },
    ) catch return 0;
    return written.len;
}

pub fn resetForTest() void {
    armed_token = 0;
    installed = false;
    hook = null;
    orig = null;
    target_addr = 0;
    saved_code = [_]u8{0} ** 32;
    stat_seen = 0;
    stat_ours = 0;
    last_token = 0;
    neo_vtable.resetForTest();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "EXPECTED_CODE pins the dispatch prologue's 19 bytes" {
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x48, 0x89, 0x5C, 0x24, 0x18, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xEA },
        EXPECTED_CODE[0..19],
    );
    try std.testing.expectEqual(@as(usize, 0x3B0F80), RVA_DISPATCH);
    try std.testing.expectEqual(@as(usize, 19), EXPECTED_CODE.len);
}

test "shouldRun matches only the armed token" {
    resetForTest();
    try std.testing.expect(!shouldRun(0));
    try setToken(19331);
    try std.testing.expect(shouldRun(19331));
    try std.testing.expect(!shouldRun(0));
    try std.testing.expect(!shouldRun(19330));
    try std.testing.expectError(error.InvalidToken, setToken(0));
    clearToken();
    try std.testing.expect(!shouldRun(19331));
}

test "verify is -3 before the first install" {
    resetForTest();
    try std.testing.expectEqual(@as(i32, -3), verify());
    try std.testing.expect(!fingerprintMatches());
}

test "statsInto keeps the driver's key order and appends dispatched" {
    resetForTest();
    var buf: [STATS_SIZE]u8 = undefined;
    const n = statsInto(&buf);
    const expected = "calls=0 matched=0 log_calls=0 last_id=0 rule_hits=0 " ++
        "installed=0 verify=-3 dispatched=0\n";
    try std.testing.expectEqualStrings(expected, buf[0..n]);
}
