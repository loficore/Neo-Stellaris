// trigger_pred_probe.zig — C5 数据面:触发谓词基体的**只读** guard(§75)。
//
// 三条诚实条款(顶部门,措辞来自 §75.5/§75.6,不要放宽):
//   ① `token_matched == 1` 只说「这个 trigger 在本窗口被实例化/求值了一次」,
//      **不**说「谓词是实例化期检查」;`token_matched ≈ systems` 只说「按系统各来一次」,
//      **不**说「X 就是那个系统的对象」。
//   ② X 的形态按 §75.5 是**解析上下文**(donor 求值槽把它直接喂给名字构造器 `0x1D0C9F0`),
//      所以本节记录的是「X 长什么样」,不是「X 是谁」。任何身份结论都要另一次读数。
//   ③ 谓词槽号只按 donor 表的 `+0x80` 推出;1,091 是「等于基体地址的 qword 个数」,
//      不是「1,091 张表的 slot[16]」(§75.4)。
//
// Target: RVA 0x349230 (offsets.keyword_reg.RVA_TRIGGER_PREDICATE, referenced here, never
// redefined) — §75 pinned it as the donor trigger vtable `0x268ED08` 的 slot[16] (`+0x80`),
// 72 B, 收 `(self, X)`: `if (!X) true; y = self->[vptr+0x70](); if (!y) true; return X != y;`
//
// 只读: the detour records and forwards. It never writes engine memory, never repoints
// `[self+0]` (unlike C4's predicate_hook), never touches registers. Engine bytes are written in
// exactly three places: the install-time JMP patch, removeHook's restore, and restoreTarget's
// copy of the saved prologue back over the patch.

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const detour_mod = @import("../hooking/detour.zig");
const windows = @import("../hooking/windows.zig");
const predicate_hook = @import("predicate_hook.zig");

const is_windows = builtin.os.tag == .windows;

/// §75 的靶:触发谓词基体。Reference only — the value lives in offsets.zig.
pub const RVA_TRIGGER_PREDICATE: usize = offsets.keyword_reg.RVA_TRIGGER_PREDICATE;

pub const RING_LEN: usize = 256;
pub const LAYOUT_VERSION: u32 = 1;

/// §23.2: the trigger consumer writes the token id at `[obj+0x38]`.
const TRIGGER_OBJECT_TOKEN_ID: usize = 0x38;

/// 32 B of 0x349230 read off the exe copy (scripts/scratch/2026-10_c5_data_plane/
/// trigger_path_readings.py, §75.4). The first 21 bytes are byte-identical to the effect
/// predicate `0x3B1420` — only offset 24..26 differs (`FF 50 70` vs `FF 50 78`), so a shorter
/// fingerprint cannot prove which of the two we patched.
pub const EXPECTED_CODE: [32]u8 = [32]u8{
    0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+0x8], rbx
    0x57, // push rdi
    0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
    0x48, 0x8B, 0xFA, // mov rdi, rdx      ; X
    0x48, 0x8B, 0xD9, // mov rbx, rcx      ; self
    0x48, 0x85, 0xD2, // test rdx, rdx
    0x74, 0x25, // je +0x25
    0x48, 0x8B, 0x01, // mov rax, [rcx]
    0xFF, 0x50, 0x70, // call qword ptr [rax+0x70]   ; 0x3B1420 says 0x78 here
    0x48, 0x85, 0xC0, // test rax, rax
    0x74, 0x1A, // je +0x1A
};

/// 40 B. The driver parses these offsets; `Entry` size and field order are the contract.
pub const Entry = extern struct {
    valid: u8 = 0,
    matched: u8 = 0, // 1 when [self+0x38] equalled the armed token
    pad0: [2]u8 = .{ 0, 0 },
    token: u32 = 0, // [self+0x38]
    self_vtable_rva: u32 = 0,
    x_vtable_rva: u32 = 0,
    reserved: u32 = 0,
    self_ptr: u64 = 0,
    x_ptr: u64 = 0,
};

pub const Stats = extern struct {
    calls: u64 = 0, // every call, matched or not — the frequency source (§57.4 discipline)
    token_matched: u64 = 0,
    x_null: u64 = 0,
    patch_size: u64 = 0,
    last_token: u32 = 0,
    pad: u32 = 0,
};

comptime {
    if (@sizeOf(Entry) != 40) @compileError("trigger pred Entry must be 40 bytes");
    if (@sizeOf(Stats) != 40) @compileError("trigger pred Stats must be 40 bytes");
}

var img_base: usize = 0;
var img_end: usize = 0;

var ring: [RING_LEN]Entry = undefined;
var seq = std.atomic.Value(u64).init(0);
var stats = Stats{};

// Guard state is private to this module — same discipline as the other four guards, so this one
// can be installed after them in the same process.
var installed = false;
var hook: ?detour_mod.Hook = null;
var orig: ?*anyopaque = null;
var target_addr: usize = 0;
var saved_code: [32]u8 = [_]u8{0} ** 32;
var armed_token: u32 = 0;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub fn setImageBounds(base: usize, end: usize) void {
    img_base = base;
    img_end = end;
}

/// 触发的 token 过滤器。与 predicate_hook 不同,这里**允许**安装后改值:
/// 它只决定「哪些调用落进统计」,不是补丁目标,换值不会让已装好的 hook 指错地方。
pub fn setToken(value: u32) void {
    @atomicStore(u32, &armed_token, value, .monotonic);
}

pub fn token() u32 {
    return @atomicLoad(u32, &armed_token, .monotonic);
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// 只有非零且等于 armed token 才算匹配。`0` 是「读不到 / 不是 trigger」,永不匹配。
pub fn classifyToken(obj_token: u32) bool {
    const armed = @atomicLoad(u32, &armed_token, .monotonic);
    return obj_token != 0 and obj_token == armed;
}

/// Same three-part bounds gate as predicate_hook.zig — every engine-memory read goes through it.
fn plausible(p: usize) bool {
    return p >= 0x10000 and p <= 0x00007FFF_FFFF_0000 and (p & 7) == 0;
}

fn readU64(addr: usize) ?u64 {
    if (!plausible(addr)) return null;
    return @as(*align(8) const u64, @ptrFromInt(addr)).*;
}

fn readU32(addr: usize, comptime off: usize) u32 {
    if (!plausible(addr)) return 0;
    const base: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u32, base[off..][0..4], .little);
}

/// Module-relative address of `abs`, or 0 when `abs` is outside stellaris.exe.
fn toRva(abs: usize) u32 {
    if (abs < img_base or abs >= img_end) return 0;
    const rva = abs - img_base;
    if (rva > std.math.maxInt(u32)) return 0;
    return @intCast(rva);
}

/// Ring occupancy, capped: the ring overwrites its oldest row past RING_LEN, so this is
/// 「现在能 drain 出几行」,not 「匹配了几次」(that is `token_matched`).
pub fn sampleCount() u32 {
    return @intCast(@min(seq.load(.monotonic), @as(u64, RING_LEN)));
}

pub const Snapshot = struct {
    calls: u64,
    token_matched: u64,
    samples: u32,
    x_null: u64,
};

pub fn snapshot() Snapshot {
    return .{
        .calls = @atomicLoad(u64, &stats.calls, .monotonic),
        .token_matched = @atomicLoad(u64, &stats.token_matched, .monotonic),
        .samples = sampleCount(),
        .x_null = @atomicLoad(u64, &stats.x_null, .monotonic),
    };
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

/// 一次谓词调用的记账。`token` 由调用方从 `[self+0x38]` 读出(纯函数可以喂假值)。
/// `calls` 恒计,匹配与环写只在 classifyToken 为真时发生 —— 频率读数不吃采样分母。
pub fn recordCall(obj_token: u32, self: usize, x: u64) void {
    _ = @atomicRmw(u64, &stats.calls, .Add, 1, .monotonic);
    if (!classifyToken(obj_token)) return;
    _ = @atomicRmw(u64, &stats.token_matched, .Add, 1, .monotonic);
    @atomicStore(u32, &stats.last_token, obj_token, .monotonic);
    if (x == 0) _ = @atomicRmw(u64, &stats.x_null, .Add, 1, .monotonic);

    const total = seq.fetchAdd(1, .monotonic);
    const slot: usize = @intCast(total % RING_LEN);
    const e = &ring[slot];
    e.* = .{};
    e.valid = 1;
    e.matched = 1;
    e.token = obj_token;
    e.self_ptr = self;
    e.x_ptr = x;
    if (readU64(self)) |v| e.self_vtable_rva = toRva(@intCast(v));
    if (readU64(@intCast(x))) |v| e.x_vtable_rva = toRva(@intCast(v));
}

// ---------------------------------------------------------------------------
// Injector-facing readouts
// ---------------------------------------------------------------------------

/// 六个布局词:[version, Entry size, RING_LEN, Stats size, target RVA, prologue length]。
pub fn layoutInto(out: *[6]u32) u32 {
    out.* = .{
        LAYOUT_VERSION,
        @intCast(@sizeOf(Entry)),
        @intCast(RING_LEN),
        @intCast(@sizeOf(Stats)),
        @intCast(RVA_TRIGGER_PREDICATE),
        @intCast(EXPECTED_CODE.len),
    };
    return 6;
}

/// One line, fixed key order — `scripts/c2_trigger_pred_probe.py`'s `STATS_KEYS` parses it.
pub fn statsInto(out: []u8) usize {
    const written = std.fmt.bufPrint(
        out,
        "calls={d} token_matched={d} samples={d} x_null={d} patch_size={d} installed={d} verify={d} last_token={d}\n",
        .{
            @atomicLoad(u64, &stats.calls, .monotonic),
            @atomicLoad(u64, &stats.token_matched, .monotonic),
            sampleCount(),
            @atomicLoad(u64, &stats.x_null, .monotonic),
            stats.patch_size,
            @intFromBool(installed),
            verify(),
            @atomicLoad(u32, &stats.last_token, .monotonic),
        },
    ) catch return 0;
    return written.len;
}

/// Copy the retained rows into `out` (8-aligned) oldest first, keeping only the last RING_LEN.
pub fn drainInto(out: [*]u8) u32 {
    const dst: [*]Entry = @ptrCast(@alignCast(out));
    const total = seq.load(.monotonic);
    const first: u64 = if (total > RING_LEN) total - RING_LEN else 0;
    var i: u64 = first;
    var copied: u32 = 0;
    while (i < total) : (i += 1) {
        dst[copied] = ring[@intCast(i % RING_LEN)];
        copied += 1;
    }
    return copied;
}

/// 清计数 + 环 + 镜像窗口;不卸载 hook(带活补丁清 calls 会把频率分母悄悄重置)。
pub fn reset() void {
    stats = .{};
    _ = seq.swap(0, .monotonic);
    @atomicStore(u32, &armed_token, 0, .monotonic);
    img_base = 0;
    img_end = 0;
}

// ---------------------------------------------------------------------------
// Assembly: fingerprint gate + install / uninstall / verify
// (shape copied from shim_witness_probe.zig — same-family prologue gate, saved_code
// snapshot, restoreTarget, flushInstructionCache)
// ---------------------------------------------------------------------------

pub const InstallError = error{
    Unsupported,
    AlreadyInstalled,
    PatchActive,
    ModuleNotFound,
    AlreadyHooked,
    UnexpectedPrologue,
    PatchTooWide,
    DetourUnavailable,
};

/// 装之前的两个拒绝:本 guard 已装,或 predicate detour 还 armed。
/// 后者是 §57.4 的理由 —— predicate armed 时 `[self+0]` 可能指向我们 DLL 的 vtable,
/// 这种状态下读到的自 vtable 不能当 engine 读数用。
pub fn preflightChecks(already_installed: bool, patch_active: bool) InstallError!void {
    if (already_installed) return error.AlreadyInstalled;
    if (patch_active) return error.PatchActive;
}

pub const OrigFn = *const fn (u64, u64) callconv(.c) bool;

/// 谓词体只读 rcx/rdx(§75.2 逐条),所以两参转发就是原样转发。
fn predDetour(self: u64, x: u64) callconv(.c) bool {
    const obj_token = readU32(@intCast(self), TRIGGER_OBJECT_TOKEN_ID);
    recordCall(obj_token, @intCast(self), x);
    const f: OrigFn = @ptrCast(orig orelse return true);
    return f(self, x);
}

pub fn install() InstallError!void {
    if (!is_windows) return error.Unsupported;
    try preflightChecks(installed, predicate_hook.isInstalled());

    const target = windows.moduleFunction(RVA_TRIGGER_PREDICATE) catch return error.ModuleNotFound;
    if (detour_mod.isHooked(target)) return error.AlreadyHooked;

    target_addr = @intFromPtr(target); // set before the gate so fingerprintMatches can re-check

    const tb: [*]const u8 = @ptrCast(target);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return error.UnexpectedPrologue;
    }
    @memcpy(&saved_code, tb[0..saved_code.len]);

    const base = @intFromPtr(target) - RVA_TRIGGER_PREDICATE;
    setImageBounds(base, base + 0x400_0000);

    const h = detour_mod.installHookArmed(target, @ptrCast(@constCast(&predDetour)), &orig) catch
        return error.DetourUnavailable;
    if (h.patch_size > saved_code.len) return error.PatchTooWide;
    hook = h;
    installed = true;
    stats.patch_size = h.patch_size;
    std.log.info("c2.trigger_pred_probe: installed detour at 0x{x}", .{RVA_TRIGGER_PREDICATE});
}

/// 把我们自己快照的前序拷回去。权威恢复:不依赖 removeHook 读的 trampoline 还完整。
fn restoreTarget(len: usize) !void {
    var guard = try windows.ProtectGuard.change(@ptrFromInt(target_addr), len, .execute_readwrite);
    defer guard.deinit();
    const dst: [*]u8 = @ptrFromInt(target_addr);
    @memcpy(dst[0..len], saved_code[0..len]);
    windows.flushInstructionCache(@ptrFromInt(target_addr), len);
}

/// Remove the detour. A no-op when not installed — the driver still calls it after a failed install.
pub fn uninstall() !void {
    if (!installed) return;
    const h = hook orelse return;
    detour_mod.removeHook(&h) catch {};
    hook = null;
    installed = false;
    try restoreTarget(h.patch_size);
    orig = null; // only once the engine bytes are ours again
    if (!fingerprintMatches()) return error.RestoreIncomplete;
    std.log.info("c2.trigger_pred_probe: uninstalled detour", .{});
}

/// True when the engine's own 32-byte prologue is present at the target.
fn fingerprintMatches() bool {
    if (target_addr == 0) return false;
    const tb: [*]const u8 = @ptrFromInt(target_addr);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return false;
    }
    return true;
}

/// 0 = consistent。装着:hook 必须还在 detour 表里;没装:本会话解析过靶且引擎字节完整。
/// -1 hook 丢了 | -2 字节不符 | -3 本会话从未解析到靶。
pub fn verify() i32 {
    if (target_addr == 0) return -3;
    const target: *anyopaque = @ptrFromInt(target_addr);
    if (installed) return if (detour_mod.isHooked(target)) 0 else -1;
    return if (fingerprintMatches()) 0 else -2;
}

pub fn isInstalled() bool {
    return installed;
}

pub fn resetForTest() void {
    stats = .{};
    _ = seq.swap(0, .monotonic);
    @atomicStore(u32, &armed_token, 0, .monotonic);
    ring = undefined;
    installed = false;
    hook = null;
    orig = null;
    target_addr = 0;
    saved_code = [_]u8{0} ** 32;
    img_base = 0;
    img_end = 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Entry is 40 bytes with the field order the driver parses" {
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(Entry));
    try std.testing.expectEqual(@as(usize, 24), @offsetOf(Entry, "self_ptr"));
    try std.testing.expectEqual(@as(usize, 32), @offsetOf(Entry, "x_ptr"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(Entry, "token"));
}

test "EXPECTED_CODE distinguishes 0x349230 from the effect predicate" {
    try std.testing.expectEqual(@as(usize, 32), EXPECTED_CODE.len);
    // 前 21 字节与 effect 谓词 0x3B1420 逐字节相同（§75.4）
    try std.testing.expectEqualSlices(u8, predicate_hook.EXPECTED_CODE[0..21], EXPECTED_CODE[0..21]);
    // 差别只在偏移 24..26 的调用槽：FF 50 70（+0x70）而不是 FF 50 78（+0x78）
    try std.testing.expectEqual(@as(u8, 0xFF), EXPECTED_CODE[24]);
    try std.testing.expectEqual(@as(u8, 0x50), EXPECTED_CODE[25]);
    try std.testing.expectEqual(@as(u8, 0x70), EXPECTED_CODE[26]);
}

test "classifyToken matches only the armed token and never 0" {
    resetForTest();
    setToken(0x4321);
    try std.testing.expect(classifyToken(0x4321));
    try std.testing.expect(!classifyToken(0));
    try std.testing.expect(!classifyToken(0x1234));
    resetForTest();
}

test "a non-matching call increments calls but neither token_matched nor samples" {
    resetForTest();
    setToken(0x4321);
    recordCall(0x1111, 0x1000, 0x2000);
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 1), s.calls);
    try std.testing.expectEqual(@as(u64, 0), s.token_matched);
    try std.testing.expectEqual(@as(u32, 0), s.samples);
    resetForTest();
}

test "a matching call with a null X records the row and counts x_null" {
    resetForTest();
    setToken(0x4321);
    recordCall(0x4321, 0x1000, 0);
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 1), s.token_matched);
    try std.testing.expectEqual(@as(u32, 1), s.samples);
    try std.testing.expectEqual(@as(u64, 1), s.x_null);
    resetForTest();
}

test "the ring drops past RING_LEN and never grows" {
    resetForTest();
    setToken(1);
    var i: usize = 0;
    while (i < RING_LEN + 4) : (i += 1) recordCall(1, 0x1000, 0x2000);
    try std.testing.expectEqual(@as(u32, @intCast(RING_LEN)), snapshot().samples);
    try std.testing.expectEqual(@as(u64, RING_LEN + 4), snapshot().token_matched);
    resetForTest();
}

test "statsInto writes one k=v line with all eight keys" {
    resetForTest();
    var buf: [512]u8 = undefined;
    const n = statsInto(&buf);
    const line = buf[0..n];
    for ([_][]const u8{
        "calls=",         "token_matched=", "samples=", "x_null=",
        "patch_size=",    "installed=",     "verify=",  "last_token=",
    }) |k| {
        try std.testing.expect(std.mem.indexOf(u8, line, k) != null);
    }
    resetForTest();
}

test "layoutInto reports six words and a stable entry size" {
    var words: [6]u32 = undefined;
    try std.testing.expectEqual(@as(u32, 6), layoutInto(&words));
    try std.testing.expectEqual(LAYOUT_VERSION, words[0]);
    try std.testing.expectEqual(@as(u32, 40), words[1]);
    try std.testing.expectEqual(@as(u32, @intCast(RING_LEN)), words[2]);
    try std.testing.expectEqual(@as(u32, @intCast(RVA_TRIGGER_PREDICATE)), words[4]);
}

test "plausible rejects bad pointers" {
    try std.testing.expect(!plausible(0));
    try std.testing.expect(!plausible(0x1234));
    try std.testing.expect(!plausible(0xffff_8000_0000_0000));
    try std.testing.expect(!plausible(0x7ff7_4a63_0001));
    try std.testing.expect(plausible(0x7ff7_4a63_0000));
}
