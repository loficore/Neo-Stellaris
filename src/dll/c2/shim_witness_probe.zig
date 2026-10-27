// shim_witness_probe.zig — 族外证人（§13 那七把各 2,090 次的 exec shim），只读，不转发 ≠ 不装。
//
// 三条诚实条款（顶部门，逐字；措辞来自 §71/§57.5/§13，不要放宽）:
//   ① `calls == 0` **不是** §57.4 第三档的正面证据 —— 它只说「本窗口没观测到」。
//   ② `calls > 0` 只证明**这个执行体在跑**，**不**证明它按 system 走
//      （structures :425 原话 `correlate this number against the live system count … before claiming it`）。
//   ③ 七张表的命中是**形状**判据，不是身份判据（§57.5 第 2 条）。「不在七张里」≠「族外没有另一份表」。
//
// Target: RVA 0xCC4220 (offsets.keyword_reg.RVA_SHIM_WITNESS_EXECUTE, referenced here, never
// redefined) — §71 pinned it offline as the `slot[2]` (`ExecuteActual`) of vtable `0x25460F0`,
// whose slot[1] is still base Execute `0x1D08520`. So it sits at the SAME dispatch slot as the
// family's donor `0x3AFD30` and witness `0x3B01A0` while its vtable is NOT one of the five
// family tables (§57.2 观测 4) — that difference is the whole point of this guard.
//
// 只读: the recording path never writes engine memory, never modifies registers or arguments,
// and always forwards to the original — 但「不转发」不等于「不装」: install is the same gated
// JMP patch as donor_exec_probe / instantiate_witness_probe, and uninstall is the same
// authoritative byte-for-byte restore of the saved prologue. Engine bytes are written in exactly
// three places: the install-time JMP patch, removeHook's restore, and restoreTarget's copy of the
// saved prologue back over the patch.
//
// Entry.ctx_ptr / a3 / a4 are recorded as VALUES only. §71.5 read this function's head off the
// exe copy: `rcx` is an object whose `[rcx+8]` byte is tested as a bool (`movzx edi, byte [rcx+8]`
// → `and dil,1` → `je`), `rdx` is a second argument copied to rbx. rdx/r8/r9 are never
// dereferenced here, because a stale pointer must only make one driver read return None — it must
// never fault the host (same reason as scope_probe.zig).
//
// Counters (table_hits/unmatched/invalid_self in capture(), samples behind the gate, calls in the
// detour) are per-call; only the ring write passes the shouldSample gate. That is §57.4's hot-path
// discipline: read the call frequency from the calls delta first, then pick the sampling
// denominator — the tier verdicts never depend on the denominator.

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const detour_mod = @import("../hooking/detour.zig");
const windows = @import("../hooking/windows.zig");
const predicate_hook = @import("predicate_hook.zig");

const is_windows = builtin.os.tag == .windows;

/// §13's out-of-family witness target: the first of the seven shims that each ran exactly
/// 2,090 times in the 2026-09-29 census. Reference only — the value lives in offsets.zig.
pub const RVA_SHIM_WITNESS: usize = offsets.keyword_reg.RVA_SHIM_WITNESS_EXECUTE; // = 0xCC4220

pub const RING_LEN: usize = 256;
pub const LAYOUT_VERSION: u32 = 1;

/// The seven vtables §13 tied to the seven 2,090-count shims (§71 段②). None of them is one of
/// the five family tables; classifyShim joins [self+0]'s RVA against THIS table.
pub const OUT_OF_FAMILY_VTABLES = [7]u32{
    0x25460F0, 0x250E188, 0x254FA18, 0x25531E8, 0x2551620, 0x2553178, 0x2553140,
};

/// 24-byte prologue of 0xCC4220, read off the exe copy byte-for-byte by
/// scripts/scratch/2026-10_c4_sentinel_window/pin_prologue.py and pinned by
/// scripts/test_c2_shim_probe.py against scripts/disrva.py (§71.5). install() refuses any other
/// bytes; same fingerprint-gate shape as instantiate_witness_probe.zig:57 and donor_exec_probe.zig:49.
/// 注意 pin_prologue 的 `24` 是十六进制 = 36 字节,前 24 恰好 6 条完整指令,指纹只吃这 24。
pub const EXPECTED_CODE: [24]u8 = [24]u8{
    0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+0x8], rbx
    0x48, 0x89, 0x6C, 0x24, 0x10, // mov [rsp+0x10], rbp
    0x48, 0x89, 0x74, 0x24, 0x18, // mov [rsp+0x18], rsi
    0x57, // push rdi
    0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
    0x0F, 0xB6, 0x79, 0x08, // movzx edi, byte [rcx+8]
};

pub const Entry = extern struct {
    valid: u8 = 0,
    matched: u8 = 0, // 1 + classifyShim's index; 0 = not one of the seven tables
    pad0: [2]u8 = [_]u8{0} ** 2,
    self_vtable_rva: u32 = 0,
    caller_rva: u32 = 0,
    self_ptr: u64 = 0,
    ctx_ptr: u64 = 0,
    a3: u64 = 0,
    a4: u64 = 0,
};

pub const Stats = extern struct {
    calls: u64 = 0,
    samples: u64 = 0,
    invalid_self: u64 = 0,
    patch_size: u64 = 0,
    table_hits: [7]u32 = [_]u32{0} ** 7,
    unmatched: u32 = 0,
};

comptime {
    if (@sizeOf(Entry) != 48) @compileError("shim witness Entry must be 48 bytes");
    if (@sizeOf(Stats) != 64) @compileError("shim witness Stats must be 64 bytes");
}

var img_base: usize = 0;
var img_end: usize = 0;
var sample_mask: u64 = 0;

var ring: [RING_LEN]Entry = undefined;
var seq = std.atomic.Value(u64).init(0);
var stats = Stats{};

// 本模块私有的 guard 状态 —— 不 import donor/证人的 installed/hook/orig，所以四把 guard 可以在
// 同一个进程里先后安装（spec §3 的同进程双 guard 合法性，本模块是第四把）。
var installed = false;
var hook: ?detour_mod.Hook = null;
var orig: ?*anyopaque = null;
var target_addr: usize = 0;
var saved_code: [32]u8 = [_]u8{0} ** 32;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Sets the module window used by toRva. Tests point it at host fake objects;
/// install() sets it from the real module base.
pub fn setImageBounds(base: usize, end: usize) void {
    img_base = base;
    img_end = end;
}

pub fn setSampleMask(mask: u64) void {
    @atomicStore(u64, &sample_mask, mask, .monotonic);
}

pub fn sampleMask() u64 {
    return @atomicLoad(u64, &sample_mask, .monotonic);
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Pure: does not read module state. mask == 0 records every call; mask == 0x1FF
/// records one in 512 (the call index must land on a zero bit).
pub fn shouldSample(calls: u64, mask: u64) bool {
    return (calls & mask) == 0;
}

pub fn classifyShim(vtable_rva: u32) ?u8 {
    for (OUT_OF_FAMILY_VTABLES, 0..) |rva, i| {
        if (rva == vtable_rva) return @intCast(i);
    }
    return null;
}

/// Same three-part bounds gate as predicate_hook.zig:60 — every engine-memory
/// read inside capture goes through it, no bare dereferences.
fn plausible(p: usize) bool {
    return p >= 0x10000 and p <= 0x00007FFF_FFFF_0000 and (p & 7) == 0;
}

fn readU64(addr: usize) ?u64 {
    if (!plausible(addr)) return null;
    return @as(*align(8) const u64, @ptrFromInt(addr)).*;
}

/// Module-relative address of `abs`, or 0 when `abs` is not inside stellaris.exe.
fn toRva(abs: usize) u32 {
    if (abs < img_base or abs >= img_end) return 0;
    const rva = abs - img_base;
    if (rva > std.math.maxInt(u32)) return 0;
    return @intCast(rva);
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

/// One call site's record. `calls` is the caller's 1-based call index, used only
/// for the sampling gate; every counter below is incremented per call, BEFORE
/// the gate, so the §57.4 tier verdicts do not depend on the sampling denominator.
/// Only the ring write is gated. The sole engine read is [self+0], via plausible().
pub fn capture(calls: u64, self: usize, ctx: usize, a3: u64, a4: u64, caller: usize) void {
    const vtbl = readU64(self) orelse {
        _ = @atomicRmw(u64, &stats.invalid_self, .Add, 1, .monotonic);
        return;
    };
    const vtbl_rva = toRva(vtbl);
    var matched: u8 = 0;
    if (classifyShim(vtbl_rva)) |idx| {
        matched = idx + 1;
        _ = @atomicRmw(u32, &stats.table_hits[@intCast(idx)], .Add, 1, .monotonic);
    } else {
        _ = @atomicRmw(u32, &stats.unmatched, .Add, 1, .monotonic);
    }

    if (!shouldSample(calls, sampleMask())) return;

    _ = @atomicRmw(u64, &stats.samples, .Add, 1, .monotonic);
    const slot: usize = @intCast(seq.fetchAdd(1, .monotonic) % @as(u64, RING_LEN));
    const e = &ring[slot];
    e.* = .{};
    e.valid = 1;
    e.matched = matched;
    e.self_vtable_rva = vtbl_rva;
    e.caller_rva = toRva(caller);
    e.self_ptr = self;
    e.ctx_ptr = ctx;
    e.a3 = a3;
    e.a4 = a4;
}

// ---------------------------------------------------------------------------
// Injector-facing readouts
// ---------------------------------------------------------------------------

/// Writes [Entry size, Stats size, RING_LEN, mask low 32, mask high 32, LAYOUT_VERSION].
/// mask is a u64, so it takes two words — same six-word layout as the donor/witness probes.
pub fn layoutInto(out: [*]u32) u32 {
    const mask = sampleMask();
    out[0] = @intCast(@sizeOf(Entry));
    out[1] = @intCast(@sizeOf(Stats));
    out[2] = @intCast(RING_LEN);
    out[3] = @truncate(mask);
    out[4] = @truncate(mask >> 32);
    out[5] = LAYOUT_VERSION;
    return 6;
}

/// One line, fixed key order (the driver parses these keys; see scripts/c2_shim_probe.py's
/// STATS_KEYS — 14 keys, h0..h6 in the middle).
/// `installed` renders this module's own install flag, maintained by install()/uninstall() below.
pub fn statsInto(out: []u8) usize {
    const written = std.fmt.bufPrint(
        out,
        "calls={d} samples={d} invalid_self={d} unmatched={d} h0={d} h1={d} h2={d} h3={d} h4={d} h5={d} h6={d} patch_size={d} installed={d} mask={x}\n",
        .{
            stats.calls,
            stats.samples,
            stats.invalid_self,
            stats.unmatched,
            stats.table_hits[0],
            stats.table_hits[1],
            stats.table_hits[2],
            stats.table_hits[3],
            stats.table_hits[4],
            stats.table_hits[5],
            stats.table_hits[6],
            stats.patch_size,
            @intFromBool(installed),
            sampleMask(),
        },
    ) catch return 0;
    return written.len;
}

/// Copy the retained records into `out` (8-aligned) oldest first, keeping only
/// the last RING_LEN entries (same rule as the donor/witness probes). Returns the count.
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

/// Clears counters, ring sequence, the sampling mask and the image window —
/// back to the module's initial state. Only before install or after uninstall.
/// It does NOT uninstall the hook: with a live patch a cleared calls counter
/// would silently restart the sampling denominator mid-shot.
pub fn reset() void {
    stats = .{};
    _ = seq.swap(0, .monotonic);
    setSampleMask(0);
    img_base = 0;
    img_end = 0;
}

// ---------------------------------------------------------------------------
// Assembly: fingerprint gate + install / uninstall / verify
// (shape copied line-for-line from instantiate_witness_probe.zig:262-388 /
// donor_exec_probe.zig:262-388 — same-family prologue gate, saved_code snapshot,
// restoreTarget, flushInstructionCache)
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

/// The two refusal checks install() runs before touching anything.
/// PatchActive rejection (§57.4): the predicate detour repoints instantiated objects' [child+0]
/// at our DLL-owned vtable, so a [self+0] read under an armed predicate detour can never land in
/// the seven-table join — readings taken in that state would be mislabeled "unmatched", so we
/// refuse instead. 族外证人不是 predicate 一族:本 guard 已装过 **或** predicate armed 都拒装。
/// Order is pinned by the tests: already_installed first, patch_active second.
pub fn preflightChecks(already_installed: bool, patch_active: bool) InstallError!void {
    if (already_installed) return error.AlreadyInstalled;
    if (patch_active) return error.PatchActive;
}

pub const OrigFn = *const fn (u64, u64, u64, u64) callconv(.c) u64;

/// §71.5 read 0xCC4220's head off the exe copy: `rcx` is an object (`[rcx+8]` tested as a bool),
/// `rdx` is a second argument. How many further parameters the real callee reads is NOT known
/// statically, so the detour takes all four register slots and forwards them unchanged —
/// forwarding three where the caller passed four would change the state the callee sees.
/// capture() gets no engine write — the calls increment here is the module's only counter owner.
fn shimDetour(self: u64, ctx: u64, a3: u64, a4: u64) callconv(.c) u64 {
    const calls = @atomicRmw(u64, &stats.calls, .Add, 1, .monotonic) + 1;
    capture(calls, @intCast(self), @intCast(ctx), a3, a4, @returnAddress());
    const f: OrigFn = @ptrCast(orig orelse return 0);
    return f(self, ctx, a3, a4);
}

/// Arm the recording detour on 0xCC4220.
/// The first statement must stay `if (!is_windows) return error.Unsupported;`:
/// the exports root links on the Linux host only because that guard lets the
/// comptime fold remove every kernel32 reference below it (windows.zig header).
pub fn install() InstallError!void {
    if (!is_windows) return error.Unsupported;
    try preflightChecks(installed, predicate_hook.isInstalled());

    const target = windows.moduleFunction(RVA_SHIM_WITNESS) catch return error.ModuleNotFound;
    if (detour_mod.isHooked(target)) return error.AlreadyHooked;

    target_addr = @intFromPtr(target); // set before the gate so fingerprintMatches can re-check

    const tb: [*]const u8 = @ptrCast(target);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return error.UnexpectedPrologue;
    }
    @memcpy(&saved_code, tb[0..saved_code.len]);

    // Same image-window algorithm as the donor/witness probes' install: the window is
    // published through the one existing accessor.
    const base = @intFromPtr(target) - RVA_SHIM_WITNESS;
    setImageBounds(base, base + 0x400_0000);

    const h = detour_mod.installHookArmed(target, @ptrCast(@constCast(&shimDetour)), &orig) catch
        return error.DetourUnavailable;
    if (h.patch_size > saved_code.len) return error.PatchTooWide;
    hook = h;
    installed = true;
    stats.patch_size = h.patch_size;
    std.log.info("c2.shim_witness_probe: installed detour at 0x{x}", .{RVA_SHIM_WITNESS});
}

/// Copies our own snapshot of the original prologue back over the patch.
/// Authoritative restore: it does not depend on the trampoline bytes
/// removeHook reads still being intact. Together with removeHook this is the
/// only path in this probe that writes engine memory; capture and verify stay
/// read-only.
fn restoreTarget(len: usize) !void {
    var guard = try windows.ProtectGuard.change(@ptrFromInt(target_addr), len, .execute_readwrite);
    defer guard.deinit();
    const dst: [*]u8 = @ptrFromInt(target_addr);
    @memcpy(dst[0..len], saved_code[0..len]);
    windows.flushInstructionCache(@ptrFromInt(target_addr), len);
}

/// Remove the detour. A no-op when not installed — the driver may still call
/// it after a failed install.
pub fn uninstall() !void {
    if (!installed) return;
    const h = hook orelse return;
    detour_mod.removeHook(&h) catch {};
    hook = null;
    installed = false;
    try restoreTarget(h.patch_size);
    orig = null; // only once the engine bytes are ours again
    if (!fingerprintMatches()) return error.RestoreIncomplete;
    std.log.info("c2.shim_witness_probe: uninstalled detour", .{});
}

/// True when the engine's own 24-byte prologue is present at the target.
fn fingerprintMatches() bool {
    if (target_addr == 0) return false;
    const tb: [*]const u8 = @ptrFromInt(target_addr);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return false;
    }
    return true;
}

/// Read-only state check, 0 = consistent, non-zero = not.
/// installed: the hook must still be registered in the detour table.
/// not installed: the target was resolved this session and the engine bytes
/// are intact. -1 hook lost, -2 bytes mismatched, -3 target never resolved.
pub fn verify() i32 {
    if (target_addr == 0) return -3;
    const target: *anyopaque = @ptrFromInt(target_addr);
    if (installed) return if (detour_mod.isHooked(target)) 0 else -1;
    return if (fingerprintMatches()) 0 else -2;
}

pub fn isInstalled() bool {
    return installed;
}

// ---------------------------------------------------------------------------
// Tests (module-local; the exports test root is what runs them)
// ---------------------------------------------------------------------------

test "Entry is 48 and Stats is 64" {
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(Entry));
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(Stats));
}

test "classify joins the seven out-of-family vtables" {
    reset();
    var obj: [0x20]u8 align(8) = std.mem.zeroes([0x20]u8);
    const win = @intFromPtr(&obj) & ~@as(usize, 0xfff);
    setImageBounds(win, win + 0x400_0000);
    for (OUT_OF_FAMILY_VTABLES, 0..) |rva, i| {
        std.mem.writeInt(u64, obj[0..8], win + rva, .little);
        capture(1, @intFromPtr(&obj), 0, 0, 0, win + 0x100);
        try std.testing.expectEqual(@as(u32, 1), stats.table_hits[i]);
    }
    var buf: [8]Entry = undefined;
    try std.testing.expectEqual(@as(u32, 7), drainInto(@ptrCast(&buf[0])));
    for (OUT_OF_FAMILY_VTABLES, 0..) |rva, i| {
        try std.testing.expectEqual(@as(u8, @intCast(i + 1)), buf[i].matched);
        try std.testing.expectEqual(rva, buf[i].self_vtable_rva);
    }
    // An eighth, unknown vtable is unmatched — the seven are not "everything".
    std.mem.writeInt(u64, obj[0..8], win + 0x2606FE0, .little);
    capture(8, @intFromPtr(&obj), 0, 0, 0, win + 0x100);
    try std.testing.expectEqual(@as(u32, 1), stats.unmatched);
}

test "classifyShim returns null for the family-five donor vtable" {
    // 0x2606FE0 is the family's own donor table — out of scope for this guard, and that must
    // stay visible as "unmatched" rather than being folded into one of the seven.
    try std.testing.expectEqual(@as(?u8, null), classifyShim(0x2606FE0));
    try std.testing.expectEqual(@as(?u8, 0), classifyShim(0x25460F0));
}

test "preflight rejects already_installed before patch_active" {
    // Review Focus 2: an armed predicate detour repoints instantiated objects' [child+0] at our
    // DLL-owned vtable, so a [self+0] read taken in that state would be mislabeled "unmatched".
    try std.testing.expectError(error.AlreadyInstalled, preflightChecks(true, false));
    try std.testing.expectError(error.AlreadyInstalled, preflightChecks(true, true));
    try std.testing.expectError(error.PatchActive, preflightChecks(false, true));
    try preflightChecks(false, false);
}

test "layoutInto is six words entry48 stats64 ring256 mask lo hi version1" {
    reset();
    var words: [6]u32 = [_]u32{0} ** 6;
    try std.testing.expectEqual(@as(u32, 6), layoutInto(&words));
    try std.testing.expectEqual(@as(u32, 48), words[0]);
    try std.testing.expectEqual(@as(u32, 64), words[1]);
    try std.testing.expectEqual(@as(u32, 256), words[2]);
    try std.testing.expectEqual(@as(u32, 0), words[3]);
    try std.testing.expectEqual(@as(u32, 0), words[4]);
    try std.testing.expectEqual(@as(u32, 1), words[5]);
    setSampleMask(0x1_0000_0002);
    _ = layoutInto(&words);
    try std.testing.expectEqual(@as(u32, 0x2), words[3]);
    try std.testing.expectEqual(@as(u32, 0x1), words[4]);
}

test "stats key order is calls..unmatched h0..h6 patch_size installed mask" {
    reset();
    var buf: [256]u8 = undefined;
    const n = statsInto(&buf);
    try std.testing.expectEqualStrings(
        "calls=0 samples=0 invalid_self=0 unmatched=0 h0=0 h1=0 h2=0 h3=0 h4=0 h5=0 h6=0 " ++
            "patch_size=0 installed=0 mask=0\n",
        buf[0..n],
    );
    setSampleMask(0x1FF);
    var obj: [0x20]u8 align(8) = std.mem.zeroes([0x20]u8);
    const win = @intFromPtr(&obj) & ~@as(usize, 0xfff);
    setImageBounds(win, win + 0x400_0000);
    std.mem.writeInt(u64, obj[0..8], win + OUT_OF_FAMILY_VTABLES[4], .little);
    capture(512, @intFromPtr(&obj), 0, 0, 0, win + 0x10);
    const n2 = statsInto(&buf);
    try std.testing.expectEqualStrings(
        "calls=0 samples=1 invalid_self=0 unmatched=0 h0=0 h1=0 h2=0 h3=0 h4=1 h5=0 h6=0 " ++
            "patch_size=0 installed=0 mask=1ff\n",
        buf[0..n2],
    );
}

test "shouldSample mask zero records every call and mask 0x1FF one in 512" {
    try std.testing.expect(shouldSample(7, 0));
    try std.testing.expect(shouldSample(512, 0x1FF));
    try std.testing.expect(!shouldSample(513, 0x1FF));
}

test "capture bumps table_hits even when the ring write is sampled out" {
    reset();
    var obj: [0x20]u8 align(8) = std.mem.zeroes([0x20]u8);
    const win = @intFromPtr(&obj) & ~@as(usize, 0xfff);
    setImageBounds(win, win + 0x400_0000);
    setSampleMask(0x1FF);
    std.mem.writeInt(u64, obj[0..8], win + OUT_OF_FAMILY_VTABLES[6], .little);

    // 513 & 0x1FF != 0 -- the ring write is sampled out, but the per-call
    // counters keep counting (§57.4 tier verdicts must not need the denominator).
    capture(513, @intFromPtr(&obj), 0xdead, 0xbeef, 0, win + 0x1234);
    try std.testing.expectEqual(@as(u32, 1), stats.table_hits[6]);
    try std.testing.expectEqual(@as(u64, 0), stats.samples);
    try std.testing.expectEqual(@as(u64, 0), stats.unmatched);
    var buf: [4]Entry = undefined;
    try std.testing.expectEqual(@as(u32, 0), drainInto(@ptrCast(&buf[0])));

    // 512 & 0x1FF == 0 -- same call shape, this time the record is retained.
    capture(512, @intFromPtr(&obj), 0xdead, 0xbeef, 0, win + 0x1234);
    try std.testing.expectEqual(@as(u32, 2), stats.table_hits[6]);
    try std.testing.expectEqual(@as(u64, 1), stats.samples);
    try std.testing.expectEqual(@as(u32, 1), drainInto(@ptrCast(&buf[0])));
    try std.testing.expectEqual(@as(u8, 1), buf[0].valid);
    try std.testing.expectEqual(@as(u8, 7), buf[0].matched); // 1 + index 6
    try std.testing.expectEqual(OUT_OF_FAMILY_VTABLES[6], buf[0].self_vtable_rva);
    try std.testing.expectEqual(@as(u32, 0x1234), buf[0].caller_rva);
    try std.testing.expectEqual(@as(u64, @intFromPtr(&obj)), buf[0].self_ptr);
    try std.testing.expectEqual(@as(u64, 0xdead), buf[0].ctx_ptr);
    try std.testing.expectEqual(@as(u64, 0xbeef), buf[0].a3);
}

test "capture counts invalid_self and writes no ring entry" {
    reset();
    var obj: [0x20]u8 align(8) = std.mem.zeroes([0x20]u8);
    const win = @intFromPtr(&obj) & ~@as(usize, 0xfff);
    setImageBounds(win, win + 0x400_0000); // self=0x1 is below the plausible floor
    capture(1, 0x1, 0, 0, 0, win + 0x77);
    try std.testing.expectEqual(@as(u64, 1), stats.invalid_self);
    try std.testing.expectEqual(@as(u64, 0), stats.samples);
    var buf: [4]Entry = undefined;
    try std.testing.expectEqual(@as(u32, 0), drainInto(@ptrCast(&buf[0])));
    capture(2, 0x1, 0, 0, 0, win + 0x77);
    try std.testing.expectEqual(@as(u64, 2), stats.invalid_self);
    try std.testing.expectEqual(@as(u32, 0), drainInto(@ptrCast(&buf[0])));
}

test "drainInto returns the last RING_LEN entries after wrap" {
    reset();
    var obj: [0x20]u8 align(8) = std.mem.zeroes([0x20]u8);
    const win = @intFromPtr(&obj) & ~@as(usize, 0xfff);
    setImageBounds(win, win + 0x400_0000);
    std.mem.writeInt(u64, obj[0..8], win + OUT_OF_FAMILY_VTABLES[0], .little);
    // 300 = RING_LEN + 44 sampled-in calls; mask 0 records every call.
    var i: usize = 0;
    while (i < RING_LEN + 44) : (i += 1) capture(i + 1, @intFromPtr(&obj), 0, 0, 0, win + i);
    var buf: [RING_LEN + 16]Entry = undefined;
    try std.testing.expectEqual(@as(u32, RING_LEN), drainInto(@ptrCast(&buf[0])));
    try std.testing.expectEqual(@as(u32, 300 - 256), buf[0].caller_rva); // first retained = #44
    try std.testing.expectEqual(@as(u32, RING_LEN + 43), buf[RING_LEN - 1].caller_rva);
    try std.testing.expectEqual(@as(u64, 300), stats.samples);
}
