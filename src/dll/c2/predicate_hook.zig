// predicate_hook.zig — C2 detour on the effect predicate ([vptr+0x98]).
//
// 0x3B01A0 instantiates an effect, writes the token id into [child+0x20],
// calls the predicate at [vptr+0x98], then the virtual Execute at [vptr+0x08].
// We detour the predicate's base implementation once. Each call reads the
// child's token id and — only when it equals the token armed via setToken —
// repoints [child+0] at the DLL-owned vtable from vtable.zig. Objects for
// every other keyword keep their donor vtable untouched.
//
// The predicate itself is called once per instantiation, so the detour
// overhead is one indirect call plus a token comparison per effect.

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const detour_mod = @import("../hooking/detour.zig");
const windows = @import("../hooking/windows.zig");
const vtable = @import("vtable.zig");

const is_windows = builtin.os.tag == .windows;

const RVA_EFFECT_PREDICATE: usize = offsets.keyword_reg.RVA_EFFECT_PREDICATE;

const PredFn = *const fn (child: u64, parent: u64) callconv(.c) bool;

// 21-byte prologue of 0x3B1420:
//   mov [rsp+8], rbx / push rdi / sub rsp, 0x20 / mov rdi, rdx /
//   mov rbx, rcx / test rdx, rdx / je +0x25
// detour.zig's 14-byte JMP takes the first 16 bytes (5+1+4+3+3), so the
// conditional branch at 16..21 stays in place and the trampoline holds only
// position-independent instructions — no relocation needed.
pub const EXPECTED_CODE = [21]u8{
    0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
    0x57, // push rdi
    0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
    0x48, 0x8B, 0xFA, // mov rdi, rdx
    0x48, 0x8B, 0xD9, // mov rbx, rcx
    0x48, 0x85, 0xD2, // test rdx, rdx
    0x74, 0x25, // je +0x25
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var armed_token: u32 = 0;
var installed = false;
var hook: ?detour_mod.Hook = null;
var orig: ?*anyopaque = null;
var target_addr: usize = 0;
var saved_code: [32]u8 = [_]u8{0} ** 32;
var stat_calls: u64 = 0;
var stat_patched: u64 = 0;
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

fn writeU64(addr: usize, val: u64) void {
    if (!plausible(addr)) return;
    const dst: *u64 = @ptrFromInt(addr);
    dst.* = val;
}

// ---------------------------------------------------------------------------
// Detour
// ---------------------------------------------------------------------------

fn predDetour(child: u64, parent: u64) callconv(.c) bool {
    _ = @atomicRmw(u64, &stat_calls, .Add, 1, .monotonic);
    const obj_token = readU32(child, offsets.keyword_reg.EFFECT_OBJECT_TOKEN_ID);
    last_token = obj_token;
    if (shouldPatch(obj_token)) {
        if (vtable.getVtable()) |vt| {
            _ = patchObject(child, obj_token, @intFromPtr(vt));
        }
    }
    const orig_f: PredFn = @ptrCast(orig orelse return true);
    return orig_f(child, parent);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub const Stats = struct {
    calls: u64,
    patched: u64,
    last_token: u32,
    installed: bool,
};

pub fn getStats() Stats {
    return .{
        .calls = @atomicLoad(u64, &stat_calls, .monotonic),
        .patched = @atomicLoad(u64, &stat_patched, .monotonic),
        .last_token = last_token,
        .installed = installed,
    };
}

pub const STATS_SIZE: usize = 24;

/// Read-only snapshot for the driver: <QQII> = calls, patched, last_token,
/// installed (1/0). Returns false when the caller's buffer is too small.
pub fn statsInto(out: []u8) bool {
    if (out.len < STATS_SIZE) return false;
    const s = getStats();
    std.mem.writeInt(u64, out[0..][0..8], s.calls, .little);
    std.mem.writeInt(u64, out[8..][0..8], s.patched, .little);
    std.mem.writeInt(u32, out[16..][0..4], s.last_token, .little);
    std.mem.writeInt(u32, out[20..][0..4], if (s.installed) 1 else 0, .little);
    return true;
}

pub fn isInstalled() bool {
    return installed;
}

/// Arm the token whose instantiated objects get our vtable. Rejects 0 (the
/// engine never writes it, and it would match every unknown object) and any
/// change while the detour is installed.
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

pub fn shouldPatch(obj_token: u32) bool {
    const armed = @atomicLoad(u32, &armed_token, .monotonic);
    return obj_token != 0 and obj_token == armed;
}

/// Repoint [child+0] at `vtbl` when `obj_token` is the armed token.
/// Returns true only when the write happened.
pub fn patchObject(child: usize, obj_token: u32, vtbl: usize) bool {
    if (!shouldPatch(obj_token) or vtbl == 0 or !plausible(child)) return false;
    writeU64(child, vtbl);
    _ = @atomicRmw(u64, &stat_patched, .Add, 1, .monotonic);
    return true;
}

/// Install the detour against a confirmed 4.4.4 build.
pub fn install() !void {
    if (!is_windows) return error.Unsupported;
    if (installed) return;

    const target = try windows.moduleFunction(RVA_EFFECT_PREDICATE);
    if (detour_mod.isHooked(target)) return error.AlreadyHooked;

    target_addr = @intFromPtr(target); // set before the gate so fingerprintMatches can re-check

    const tb: [*]const u8 = @ptrCast(target);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return error.UnexpectedPrologue;
    }
    @memcpy(&saved_code, tb[0..saved_code.len]);

    const h = try detour_mod.installHookArmed(target, @ptrCast(@constCast(&predDetour)), &orig);
    if (h.patch_size > saved_code.len) return error.PatchTooWide;
    hook = h;
    installed = true;
    std.log.info("c2.predicate_hook: installed detour at 0x{x}", .{RVA_EFFECT_PREDICATE});
}

/// Copies our own snapshot of the original prologue back over the patch.
/// Authoritative restore: it does not depend on the trampoline bytes
/// removeHook reads still being intact.
fn restoreTarget(len: usize) !void {
    var guard = try windows.ProtectGuard.change(@ptrFromInt(target_addr), len, .execute_readwrite);
    defer guard.deinit();
    const dst: [*]u8 = @ptrFromInt(target_addr);
    @memcpy(dst[0..len], saved_code[0..len]);
    windows.flushInstructionCache(@ptrFromInt(target_addr), len);
}

/// Remove the detour. A no-op when not installed — the driver still calls
/// disarm after a failed C2ExecInstall.
pub fn uninstall() !void {
    if (!installed) return;
    const h = hook orelse return;
    detour_mod.removeHook(&h) catch {};
    hook = null;
    installed = false;
    try restoreTarget(h.patch_size);
    orig = null; // only once the engine bytes are ours again
    if (!fingerprintMatches()) return error.RestoreIncomplete;
    std.log.info("c2.predicate_hook: uninstalled detour", .{});
}

/// True when the engine's own 21-byte prologue is present at the target.
pub fn fingerprintMatches() bool {
    if (target_addr == 0) return false;
    const tb: [*]const u8 = @ptrFromInt(target_addr);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return false;
    }
    return true;
}

pub fn resetForTest() void {
    @atomicStore(u32, &armed_token, 0, .monotonic);
    installed = false;
    hook = null;
    orig = null;
    target_addr = 0;
    saved_code = [_]u8{0} ** 32;
    stat_calls = 0;
    stat_patched = 0;
    last_token = 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "predicate RVA and fingerprint are in .text" {
    const text_end: usize = 0x2392000;
    try std.testing.expect(RVA_EFFECT_PREDICATE < text_end);
    try std.testing.expectEqual(@as(usize, 21), EXPECTED_CODE.len);
    // The JMP patch covers 16 bytes; the conditional branch must start after it.
    try std.testing.expectEqual(@as(u8, 0x48), EXPECTED_CODE[16]);
    try std.testing.expectEqual(@as(u8, 0x74), EXPECTED_CODE[19]);
}

test "plausible rejects bad pointers" {
    try std.testing.expect(!plausible(0));
    try std.testing.expect(!plausible(0x1234));
    try std.testing.expect(!plausible(0xffff_8000_0000_0000));
}

test "readU32 returns 0 for bad address" {
    try std.testing.expectEqual(@as(u32, 0), readU32(0, 0));
}

test "resetForTest clears installation state" {
    resetForTest();
    try std.testing.expect(!isInstalled());
    try std.testing.expectEqual(@as(u32, 0), token());
    try std.testing.expect(!fingerprintMatches());
}

test "statsInto writes a 24-byte little-endian snapshot" {
    resetForTest();
    stat_calls = 7;
    stat_patched = 3;
    last_token = 0xABCD;
    var buf: [24]u8 = [_]u8{0} ** 24;
    try std.testing.expect(statsInto(&buf));
    try std.testing.expectEqual(@as(u64, 7), std.mem.readInt(u64, buf[0..8], .little));
    try std.testing.expectEqual(@as(u64, 3), std.mem.readInt(u64, buf[8..16], .little));
    try std.testing.expectEqual(@as(u32, 0xABCD), std.mem.readInt(u32, buf[16..20], .little));
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, buf[20..24], .little));
    var short: [23]u8 = [_]u8{0} ** 23;
    try std.testing.expect(!statsInto(&short));
    resetForTest();
}
