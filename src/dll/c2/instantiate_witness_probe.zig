// instantiate_witness_probe.zig — 同族 slot[2] instantiate helper 证人（§57.4 第三档的独立证据），
// 只读，不转发 ≠ 不装。
//
// Target: RVA 0x3B01A0 (offsets.keyword_reg.RVA_EFFECT_DONOR_INSTANTIATE, referenced
// here, never redefined) — slot[2] (`+0x10`) of the five CEffect-family vtables
// named by §57.2 观测 4 (`0x1B4B30, 0x3AFD30, 0x3B01A0, 0x159730` = the first four
// slots) and listed again in §57.4. It is NOT the donor Execute override 0x3AFD30
// and NOT the base Execute 0x1D08520.
//
// 只读: the recording path never writes engine memory, never modifies registers or
// arguments, and always forwards to the original — 但「不转发」不等于「不装」: install
// is the same gated JMP patch as donor_exec_probe, and uninstall is the same
// authoritative byte-for-byte restore of the saved prologue. Engine bytes are
// written in exactly three places: the install-time JMP patch, removeHook's
// restore, and restoreTarget's copy of the saved prologue back over the patch.
//
// Entry.ctx_ptr / a3 / a4 are recorded as VALUES only. §52.6 documents this
// function's legal probe shape as `0x3B01A0(parent, ctx, token, 0)`, i.e. rcx is
// the effect-side object whose `[rcx+0]` we join against the five family tables;
// rdx/r8/r9 are never dereferenced here, because a stale pointer must only make
// one driver read return None — it must never fault the host (same reason as
// scope_probe.zig). §53.5 disproved the `[ctx+0x30]` chain; nothing is built on it.
//
// Counters (table_hits/unmatched/invalid_self in capture(), samples behind the
// gate, calls in the detour) are per-call; only the ring write passes the
// shouldSample gate. That is §57.4's hot-path discipline: read the call frequency
// from the calls delta first, then pick the sampling denominator — the tier
// verdicts never depend on the denominator.
//
// 诚实条款 (spec §2.3): calls == 0 here is NOT evidence for §57.4's tier 3. The
// instantiate helper may only run during parse / full-tree enumeration (§57.2
// 观测 4's enumerator calls `create` on every node), so "witness quiet" has two
// readings this instrument cannot separate.

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const detour_mod = @import("../hooking/detour.zig");
const windows = @import("../hooking/windows.zig");
const predicate_hook = @import("predicate_hook.zig");

const is_windows = builtin.os.tag == .windows;

/// §57.4's witness target: the family's shared slot[2] instantiate helper.
/// Reference only — the value lives in offsets.zig.
pub const RVA_WITNESS_INSTANTIATE: usize = offsets.keyword_reg.RVA_EFFECT_DONOR_INSTANTIATE; // = 0x3B01A0

pub const RING_LEN: usize = 256;
pub const LAYOUT_VERSION: u32 = 1;

/// The five CEffect-family vtables that share the 0x3B01A0 slot[2] (§57.2 观测 4).
/// classifyTable joins [self+0]'s RVA against this table.
pub const FAMILY_VTABLES = [5]u32{ 0x24B1D98, 0x24EAAC0, 0x25F4440, 0x2606F00, 0x2606FE0 };

/// 24-byte prologue of 0x3B01A0, read off the exe copy byte-for-byte by
/// scripts/scratch/2026-10_c4_sentinel_window/pin_prologue.py and pinned by
/// scripts/test_c2_witness_probe.py against scripts/disrva.py. install() refuses
/// any other bytes; same fingerprint-gate shape as donor_exec_probe.zig:49.
/// 注意 `sub rsp,0x5f0` 的大帧序在这 24 字节之外(它始于 +0x22),不在指纹里。
pub const EXPECTED_CODE: [24]u8 = [24]u8{
    0x48, 0x89, 0x5C, 0x24, 0x18, // mov [rsp+0x18], rbx
    0x4C, 0x89, 0x4C, 0x24, 0x20, // mov [rsp+0x20], r9
    0x48, 0x89, 0x4C, 0x24, 0x08, // mov [rsp+0x8], rcx
    0x55, // push rbp
    0x56, // push rsi
    0x57, // push rdi
    0x41, 0x54, // push r12
    0x41, 0x55, // push r13
    0x41, 0x56, // push r14
};

pub const Entry = extern struct {
    valid: u8 = 0,
    matched: u8 = 0, // 1 + classifyTable's index; 0 = not one of the five tables
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
    table_hits: [5]u32 = [_]u32{0} ** 5,
    unmatched: u32 = 0,
};

comptime {
    if (@sizeOf(Entry) != 48) @compileError("witness Entry must be 48 bytes");
    if (@sizeOf(Stats) != 56) @compileError("witness Stats must be 56 bytes");
}

var img_base: usize = 0;
var img_end: usize = 0;
var sample_mask: u64 = 0;

var ring: [RING_LEN]Entry = undefined;
var seq = std.atomic.Value(u64).init(0);
var stats = Stats{};

// 本模块私有的 guard 状态 —— 不 import donor 的 installed/hook/orig,所以证人可以和
// donor 探针在同一个进程里先后安装(spec §3 的同进程双 guard 合法性)。
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

pub fn classifyTable(vtable_rva: u32) ?u8 {
    for (FAMILY_VTABLES, 0..) |rva, i| {
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
    if (classifyTable(vtbl_rva)) |idx| {
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
/// mask is a u64, so it takes two words — same six-word layout as the donor probe.
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

/// One line, fixed key order (the driver parses these keys; see scripts/c2_witness_probe.py).
/// `installed` renders this module's own install flag, maintained by
/// install()/uninstall() below.
pub fn statsInto(out: []u8) usize {
    const written = std.fmt.bufPrint(
        out,
        "calls={d} samples={d} invalid_self={d} unmatched={d} h0={d} h1={d} h2={d} h3={d} h4={d} patch_size={d} installed={d} mask={x}\n",
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
            stats.patch_size,
            @intFromBool(installed),
            sampleMask(),
        },
    ) catch return 0;
    return written.len;
}

/// Copy the retained records into `out` (8-aligned) oldest first, keeping only
/// the last RING_LEN entries (same rule as the donor probe). Returns the count.
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
// (shape copied line-for-line from donor_exec_probe.zig:262-388 — same-family
// prologue gate, saved_code snapshot, restoreTarget, flushInstructionCache)
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
/// PatchActive rejection (§57.4): the predicate detour repoints instantiated
/// objects' [child+0] at our DLL-owned vtable, so a [self+0] read under an armed
/// predicate detour can never land in the five-table join — readings taken in
/// that state would be mislabeled "unmatched", so we refuse instead. 证人不是
/// predicate 一族:本 guard 已装过 **或** predicate armed 都拒装。
/// Order is pinned by the tests: already_installed first, patch_active second.
pub fn preflightChecks(already_installed: bool, patch_active: bool) InstallError!void {
    if (already_installed) return error.AlreadyInstalled;
    if (patch_active) return error.PatchActive;
}

pub const OrigFn = *const fn (u64, u64, u64, u64) callconv(.c) u64;

/// §52.6 documents `0x3B01A0(parent, ctx, token, 0)` — three real parameters, with
/// the fourth register slot (r9) existing in the call. The detour takes all four
/// register slots so nothing is invented and everything is forwarded unchanged:
/// forwarding three where the caller passed four would change the state the
/// callee sees. capture() gets no engine write — the calls increment here is the
/// module's only counter owner.
fn witnessDetour(self: u64, ctx: u64, a3: u64, a4: u64) callconv(.c) u64 {
    const calls = @atomicRmw(u64, &stats.calls, .Add, 1, .monotonic) + 1;
    capture(calls, @intCast(self), @intCast(ctx), a3, a4, @returnAddress());
    const f: OrigFn = @ptrCast(orig orelse return 0);
    return f(self, ctx, a3, a4);
}

/// Arm the recording detour on 0x3B01A0.
/// The first statement must stay `if (!is_windows) return error.Unsupported;`:
/// the exports root links on the Linux host only because that guard lets the
/// comptime fold remove every kernel32 reference below it (windows.zig header).
pub fn install() InstallError!void {
    if (!is_windows) return error.Unsupported;
    try preflightChecks(installed, predicate_hook.isInstalled());

    const target = windows.moduleFunction(RVA_WITNESS_INSTANTIATE) catch return error.ModuleNotFound;
    if (detour_mod.isHooked(target)) return error.AlreadyHooked;

    target_addr = @intFromPtr(target); // set before the gate so fingerprintMatches can re-check

    const tb: [*]const u8 = @ptrCast(target);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return error.UnexpectedPrologue;
    }
    @memcpy(&saved_code, tb[0..saved_code.len]);

    // Same image-window algorithm as the donor probe's install: the window is
    // published through the one existing accessor.
    const base = @intFromPtr(target) - RVA_WITNESS_INSTANTIATE;
    setImageBounds(base, base + 0x400_0000);

    const h = detour_mod.installHookArmed(target, @ptrCast(@constCast(&witnessDetour)), &orig) catch
        return error.DetourUnavailable;
    if (h.patch_size > saved_code.len) return error.PatchTooWide;
    hook = h;
    installed = true;
    stats.patch_size = h.patch_size;
    std.log.info("c2.instantiate_witness_probe: installed detour at 0x{x}", .{RVA_WITNESS_INSTANTIATE});
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
    std.log.info("c2.instantiate_witness_probe: uninstalled detour", .{});
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

test "witness Entry is 48 bytes and Stats is 56 bytes" {
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(Entry));
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(Stats));
}

test "classifyTable hits each of the five family vtables" {
    for (FAMILY_VTABLES, 0..) |rva, i| try std.testing.expectEqual(@as(u8, @intCast(i)), classifyTable(rva).?);
}

test "classifyTable returns null for an unknown vtable rva" {
    try std.testing.expectEqual(@as(?u8, null), classifyTable(0x2606FE8));
}

test "shouldSample mask zero records every call and mask 0x1FF one in 512" {
    try std.testing.expect(shouldSample(7, 0));
    try std.testing.expect(shouldSample(512, 0x1FF));
    try std.testing.expect(!shouldSample(513, 0x1FF));
}

test "capture bumps table_hits even when the ring write is sampled out" {
    reset();
    var obj: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    const win = @intFromPtr(&obj) & ~@as(usize, 0xfff);
    setImageBounds(win, win + 0x400_0000);
    setSampleMask(0x1FF);
    std.mem.writeInt(u64, obj[0..8], win + FAMILY_VTABLES[2], .little);

    // 513 & 0x1FF != 0 -- the ring write is sampled out, but the per-call
    // counters keep counting (§57.4 tier verdicts must not need the denominator).
    capture(513, @intFromPtr(&obj), 0xdead, 0xbeef, 0, win + 0x1234);
    try std.testing.expectEqual(@as(u32, 1), stats.table_hits[2]);
    try std.testing.expectEqual(@as(u64, 0), stats.samples);
    try std.testing.expectEqual(@as(u64, 0), stats.unmatched);
    var buf: [4]Entry = undefined;
    try std.testing.expectEqual(@as(u32, 0), drainInto(@ptrCast(&buf[0])));

    // 512 & 0x1FF == 0 -- same call shape, this time the record is retained.
    capture(512, @intFromPtr(&obj), 0xdead, 0xbeef, 0, win + 0x1234);
    try std.testing.expectEqual(@as(u32, 2), stats.table_hits[2]);
    try std.testing.expectEqual(@as(u64, 1), stats.samples);
    try std.testing.expectEqual(@as(u32, 1), drainInto(@ptrCast(&buf[0])));
    try std.testing.expectEqual(@as(u8, 1), buf[0].valid);
    try std.testing.expectEqual(@as(u8, 3), buf[0].matched); // 1 + index 2
    try std.testing.expectEqual(FAMILY_VTABLES[2], buf[0].self_vtable_rva);
    try std.testing.expectEqual(@as(u32, 0x1234), buf[0].caller_rva);
    try std.testing.expectEqual(@as(u64, @intFromPtr(&obj)), buf[0].self_ptr);
    try std.testing.expectEqual(@as(u64, 0xdead), buf[0].ctx_ptr);
    try std.testing.expectEqual(@as(u64, 0xbeef), buf[0].a3);
}

test "capture counts invalid_self and writes no ring entry" {
    reset();
    var obj: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    const win = @intFromPtr(&obj) & ~@as(usize, 0xfff);
    setImageBounds(win, win + 0x400_0000); // the window is elsewhere; self=0x1 is not readable
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
    var obj: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    const win = @intFromPtr(&obj) & ~@as(usize, 0xfff);
    setImageBounds(win, win + 0x400_0000);
    std.mem.writeInt(u64, obj[0..8], win + FAMILY_VTABLES[0], .little);
    // 300 = RING_LEN + 44 sampled-in calls; mask 0 records every call.
    var i: usize = 0;
    while (i < RING_LEN + 44) : (i += 1) capture(i + 1, @intFromPtr(&obj), 0, 0, 0, win + i);
    var buf: [RING_LEN + 16]Entry = undefined;
    try std.testing.expectEqual(@as(u32, RING_LEN), drainInto(@ptrCast(&buf[0])));
    try std.testing.expectEqual(@as(u32, 300 - 256), buf[0].caller_rva); // first retained = #44
    try std.testing.expectEqual(@as(u32, RING_LEN + 43), buf[RING_LEN - 1].caller_rva);
    try std.testing.expectEqual(@as(u64, 300), stats.samples);
}

test "preflightChecks rejects patch active" {
    // Review Focus 2: an armed predicate detour repoints instantiated objects'
    // [child+0] at our DLL-owned vtable, so a [self+0] read taken in that state
    // would be mislabeled "unmatched". The witness refuses instead of recording.
    try std.testing.expectError(error.PatchActive, preflightChecks(false, true));
    try std.testing.expectError(error.AlreadyInstalled, preflightChecks(true, false));
    try std.testing.expectError(error.AlreadyInstalled, preflightChecks(true, true));
    try preflightChecks(false, false);
}
