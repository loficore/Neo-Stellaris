// exec_hook.zig — Log-only (behavior-preserving) detour of the 4.4.4 base Execute.
//
// Target (Stellaris 4.4.4, live-verified, evidence/analysis/runtime_444_structures.md §7-§9):
//   RVA 0x1D08520 — the shared virtual Execute every keyword instance runs through
//   (~1.5M calls / 40 s of active simulation).
//
// Verified body (capstone over the shipped exe):
//   +00 mov  [rsp+8], rbx           arg1 (rcx) = keyword instance -> rdi
//   +05 push rdi                    arg2 (rdx) = exec context     -> rbx
//   +06 sub  rsp, 0x20
//   +0a mov  eax, [rdx+8]           ctx+0x08 = signed recursion counter
//   +0d mov  rbx, rdx
//   +10 mov  rdi, rcx
//   +13 guard-frame enter/leave calls around the dispatch (0x16FDC0, edx = 0x10/3/4)
//   +54 mov  rax, [rdi]
//   +57 call [rax+0x10]           -> vtable slot[2] = the per-keyword shim (rcx, rdx)
//   +5a dec  [rbx+8]
//   +8f ret                         rax is an internal leftover: no defined return
//
// Exactly two integer args, no r8/r9 use, no stack parameters — so a 4-arg u64
// signature that returns u64 forwards the call transparently (params 3/4 simply keep
// r8/r9 alive across our own frame).
//
// WHAT THIS DOES: count calls, histogram the shim each instance dispatches to (every call,
// so the counts are frequencies), and sample field-level records at 1/512. It never writes
// engine memory and never changes a register, argument, or the control flow of the original.
//
// PROVENANCE: addresses are for ONE game build. `install` refuses unless the first 32
// bytes at the target match the verified fingerprint below — those bytes contain no
// rel32/RIP displacements, so they are ASLR-invariant and a moved build cannot silently
// hook a different function in the hottest code path.
// Install/remove only via an explicit injector command, never from DllMain.

const std = @import("std");
const builtin = @import("builtin");
const detour_mod = @import("../hooking/detour.zig");
const windows = @import("../hooking/windows.zig");

const is_windows = builtin.os.tag == .windows;

// ---------------------------------------------------------------------------
// Verified target constants
// ---------------------------------------------------------------------------

/// RVA of the shared base Execute (descriptor vtable slot[1]).
pub const RVA_BASE_EXECUTE: usize = 0x1D08520;

/// The first 32 bytes of the verified target. installHook only relocates the first 16
/// (mov [rsp+8],rbx / push rdi / sub rsp,0x20 / mov eax,[rdx+8] / mov rbx,rdx), and none
/// of those is RIP-relative, so the copy-based trampoline is safe. The rest of the window
/// is checked but untouched — it is the identity proof for this build.
const EXPECTED_CODE = [_]u8{
    0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
    0x57,                         // push rdi
    0x48, 0x83, 0xEC, 0x20,       // sub rsp, 0x20
    0x8B, 0x42, 0x08,             // mov eax, [rdx+8]
    0x48, 0x8B, 0xDA,             // mov rbx, rdx
    0x48, 0x8B, 0xF9,             // mov rdi, rcx
    0x85, 0xC0,                   // test eax, eax
    0x78, 0x32,                   // js  +0x32
    0xBA, 0x10, 0x00, 0x00, 0x00, // mov edx, 0x10
    0x48, 0x8B, 0xCB,             // mov rcx, rbx
    0xE8,                         // call rel32 (displacement deliberately not pinned)
};

pub const VTBL_SLOT_EXECUTE: usize = 0x08; // descriptor slot[1] — this function
pub const VTBL_SLOT_SHIM: usize = 0x10; // descriptor slot[2] — per-keyword Execute shim

/// Instance fields from the §9 shim disassembly. **Not a general contract** — live
/// records show these offsets carry sentinels (0x7fff) or pointer halves for several
/// keyword classes, so they are per-class hints and must be re-derived per shim before
/// route B relies on any of them. Recorded verbatim, never interpreted.
pub const SELF_TOKEN_ID: usize = 0x08; // u32, was the token id in the 0x1BCD120 sample
pub const SELF_2ND_TOKEN: usize = 0x0c; // u16
pub const SELF_FLAG_12: usize = 0x12; // u16
pub const SELF_FLAG_14: usize = 0x14; // u8
pub const SELF_FLAG_16: usize = 0x16; // u8
pub const SELF_ARG: usize = 0x18; // u32 parameter token

/// Context fields.
pub const CTX_RECURSION: usize = 0x08; // i32 recursion counter, inc/dec around the shim call
pub const CTX_10: usize = 0x10;
pub const CTX_18: usize = 0x18;
pub const CTX_30: usize = 0x30; // slot5 (0x535070) also dereferences this

// ---------------------------------------------------------------------------
// Safe memory reads
// ---------------------------------------------------------------------------

/// Rejects null, the guard page, misaligned pointers and kernel space, so a stale or
/// unexpected argument can never make this hook fault inside the running game.
fn plausible(p: usize) bool {
    return p >= 0x10000 and p <= 0x00007FFF_FFFF_0000 and (p & 7) == 0;
}

fn readU64(addr: usize) ?u64 {
    if (!plausible(addr)) return null;
    return @as(*const align(8) u64, @ptrFromInt(addr)).*;
}

fn readU32(addr: usize, comptime off: usize) ?u32 {
    if (!plausible(addr)) return null;
    const base: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u32, base[off..][0..4], .little);
}

fn readU16(addr: usize, comptime off: usize) ?u16 {
    if (!plausible(addr)) return null;
    const base: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u16, base[off..][0..2], .little);
}

fn readU8(addr: usize, comptime off: usize) ?u8 {
    if (!plausible(addr)) return null;
    return @as([*]const u8, @ptrFromInt(addr))[off];
}

var img_base: usize = 0;
var img_end: usize = 0;

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

pub const RING_LEN: usize = 1024;
/// 1 in SAMPLE_MASK+1 calls gets a full ring record; the other calls only do the two
/// pointer reads the histogram needs. At the observed ~37k calls/s this keeps the hook's
/// added cost far below the engine's own.
const SAMPLE_MASK: u64 = 511;
/// Spill slots per shim key. Bounds the worst case for a call whose key is absent from an
/// almost-full table, so the always-on path can never degrade to a HIST_LEN walk.
const PROBE_LIMIT: usize = 32;
/// 34% of a 60 s capture overflowed a 128-slot table, so the shim population across one
/// scene is in the hundreds. 1024 slots is 16 KB of .bss — cheap next to the ring.
pub const HIST_LEN: usize = 1024;

/// One sampled invocation. `valid` == 0 means the instance pointer failed the
/// plausibility check (or its vtable did) and the fields are zero-filled.
pub const Entry = extern struct {
    valid: u8 = 0,
    pad0: [3]u8 = [_]u8{0} ** 3,
    self_vtable_rva: u32 = 0,
    shim_rva: u32 = 0,
    token_id: u32 = 0,
    second_token: u32 = 0,
    flag_12: u32 = 0,
    flag_14: u32 = 0,
    flag_16: u32 = 0,
    arg_token: u32 = 0,
    ctx_counter: i32 = 0,
    ctx_pad: i32 = 0,
    self_ptr: u64 = 0,
    ctx_ptr: u64 = 0,
    ctx_10: u64 = 0,
    ctx_18: u64 = 0,
    ctx_30: u64 = 0,
};

// The Frida driver (scripts/execspy.js) parses records at these byte offsets; a drift
// here must break the build, not silently misreport live captures.
comptime {
    if (@sizeOf(Entry) != 88) @compileError("Entry must be 88 bytes");
    for (.{
        .{ "self_vtable_rva", 4 },
        .{ "shim_rva", 8 },
        .{ "token_id", 12 },
        .{ "second_token", 16 },
        .{ "flag_12", 20 },
        .{ "flag_14", 24 },
        .{ "flag_16", 28 },
        .{ "arg_token", 32 },
        .{ "ctx_counter", 36 },
        .{ "self_ptr", 48 },
        .{ "ctx_ptr", 56 },
        .{ "ctx_10", 64 },
        .{ "ctx_18", 72 },
        .{ "ctx_30", 80 },
    }) |fld| {
        if (@offsetOf(Entry, fld[0]) != fld[1]) @compileError(fld[0] ++ " offset drifted");
    }
    if (@sizeOf(HistEntry) != 16 or @offsetOf(HistEntry, "count") != 8) @compileError("HistEntry layout drifted");
    if (@sizeOf(Stats) != 48) @compileError("Stats must be 48 bytes");
}

/// The instance's dispatch identity, read on EVERY call: which vtable the engine is about
/// to follow and which per-keyword shim slot[2] holds.
const Identity = struct {
    valid: bool = false,
    vtable_rva: u32 = 0,
    shim_rva: u32 = 0,
};

/// Which per-keyword shims ran, and how often — the list route B must cover. Counted over
/// all calls, not just samples, so `count` is a real call frequency. Slots are claimed by
/// the first call that sees a new shim; vtable_rva is that first instance's vtable, which
/// is a representative, not a proof that the shim belongs to only that class.
pub const HistEntry = extern struct {
    shim_rva: u32 = 0,
    vtable_rva: u32 = 0,
    count: u64 = 0,
};

pub const Stats = extern struct {
    /// Base-Execute invocations seen while installed.
    calls: u64 = 0,
    /// Ring records written — SAMPLE_MASK+1 times rarer than `calls`.
    samples: u64 = 0,
    /// Calls whose `self` failed plausible() or had an unreadable vtable. Counted on every
    /// call now, so this is comparable with `calls`, not with `samples`.
    invalid: u64 = 0,
    /// Calls whose shim key was neither found nor inserted within PROBE_LIMIT slots. A
    /// non-zero value means HIST_LEN is too small, not that the game misbehaved.
    hist_overflow: u64 = 0,
    img_base: u64 = 0,
    /// Bytes installHook actually relocated into the trampoline; must read 16.
    patch_size: u64 = 0,
};

var ring: [RING_LEN]Entry = undefined;
var hist: [HIST_LEN]HistEntry = undefined;
var stats = Stats{};
var seq = std.atomic.Value(u64).init(0);

/// Reads [self] -> vtable -> slot[2] and bumps the histogram. Two pointer loads plus an
/// atomic increment on the hot path; everything else stays behind the sample gate.
fn observe(self: usize) Identity {
    const vtbl = readU64(self) orelse {
        _ = @atomicRmw(u64, &stats.invalid, .Add, 1, .monotonic);
        return .{};
    };
    var id = Identity{ .valid = true, .vtable_rva = toRva(vtbl) };
    if (readU64(vtbl + VTBL_SLOT_SHIM)) |shim| id.shim_rva = toRva(shim);
    if (id.shim_rva != 0) histBump(id);
    return id;
}

/// Open-addressed histogram keyed on shim RVA. Game effect execution is not guaranteed
/// single-threaded, so slot claims use cmpxchg and counts use atomic adds: concurrent
/// writers can only duplicate a rarely-seen key into a second slot, never lose a call.
fn histBump(id: Identity) void {
    const start: usize = @intCast(@as(u32, id.shim_rva *% 0x9E37_79B1) % HIST_LEN);
    var i: usize = 0;
    while (i < PROBE_LIMIT) : (i += 1) {
        const h = &hist[(start + i) % HIST_LEN];
        const cur = @atomicLoad(u32, &h.shim_rva, .monotonic);
        if (cur == id.shim_rva) {
            _ = @atomicRmw(u64, &h.count, .Add, 1, .monotonic);
            return;
        }
        if (cur == 0) {
            if (@cmpxchgStrong(u32, &h.shim_rva, 0, id.shim_rva, .monotonic, .monotonic) != null) {
                // Lost the claim to another thread: honour whatever it stored.
                if (@atomicLoad(u32, &h.shim_rva, .monotonic) == id.shim_rva) {
                    _ = @atomicRmw(u64, &h.count, .Add, 1, .monotonic);
                    return;
                }
                continue;
            }
            h.vtable_rva = id.vtable_rva; // we own this slot
            _ = @atomicRmw(u64, &h.count, .Add, 1, .monotonic);
            return;
        }
    }
    _ = @atomicRmw(u64, &stats.hist_overflow, .Add, 1, .monotonic);
}

fn sample(self: usize, ctx: usize, id: Identity) void {
    const idx = @as(usize, @intCast(seq.fetchAdd(1, .monotonic) % @as(u64, RING_LEN)));
    const e = &ring[idx];
    e.* = .{};
    e.valid = if (id.valid) 1 else 0;
    e.self_vtable_rva = id.vtable_rva;
    e.shim_rva = id.shim_rva;
    e.self_ptr = self;
    e.ctx_ptr = ctx;
    if (!id.valid) return;

    if (readU32(self, SELF_TOKEN_ID)) |t| e.token_id = t;
    if (readU16(self, SELF_2ND_TOKEN)) |t| e.second_token = t;
    if (readU16(self, SELF_FLAG_12)) |f| e.flag_12 = f;
    if (readU8(self, SELF_FLAG_14)) |f| e.flag_14 = f;
    if (readU8(self, SELF_FLAG_16)) |f| e.flag_16 = f;
    if (readU32(self, SELF_ARG)) |a| e.arg_token = a;
    if (readU32(ctx, CTX_RECURSION)) |c| e.ctx_counter = @bitCast(c);
    e.ctx_10 = readU64(ctx + CTX_10) orelse 0;
    e.ctx_18 = readU64(ctx + CTX_18) orelse 0;
    e.ctx_30 = readU64(ctx + CTX_30) orelse 0;
}

// ---------------------------------------------------------------------------
// Detour
// ---------------------------------------------------------------------------

const OrigFn = *const fn (self: u64, ctx: u64, a3: u64, a4: u64) callconv(.c) u64;

/// Set before the JMP patch goes live (detour.installHook's `prearm`) and cleared only after
/// the original bytes are back, so a forwarded call is never dropped at either boundary.
var orig: ?*anyopaque = null;

fn execDetour(self: u64, ctx: u64, a3: u64, a4: u64) callconv(.c) u64 {
    const calls = @atomicRmw(u64, &stats.calls, .Add, 1, .monotonic) + 1;
    const id = observe(@intCast(self));
    if ((calls & SAMPLE_MASK) == 0) {
        _ = @atomicRmw(u64, &stats.samples, .Add, 1, .monotonic);
        sample(@intCast(self), @intCast(ctx), id);
    }
    const f: OrigFn = @ptrCast(orig orelse return 0);
    return f(self, ctx, a3, a4);
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

pub const State = struct {
    hook: ?detour_mod.Hook = null,
    installed: bool = false,
};

var state = State{};

/// Kept across uninstall so ExecHookVerify can re-read the target afterwards.
var target_addr: usize = 0;

/// The engine's own bytes, snapshotted at install before anything is overwritten, so
/// uninstall can restore without trusting the trampoline. Sized by the patch we predict
/// from the pinned fingerprint (16); install refuses a wider patch than this can hold.
var saved_code: [32]u8 = [_]u8{0} ** 32;

pub fn isInstalled() bool {
    return state.installed;
}

/// Compares the 32-byte fingerprint at the target. After uninstall this is direct proof the
/// engine's own bytes are back; while installed it must fail, since the head of the target is
/// our JMP patch.
pub fn fingerprintMatches() bool {
    if (target_addr == 0) return false;
    const tb: [*]const u8 = @ptrFromInt(target_addr);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return false;
    }
    return true;
}

/// Install the base-Execute detour against a confirmed 4.4.4 build.
pub fn install() !void {
    if (state.installed) return;

    const target = try windows.moduleFunction(RVA_BASE_EXECUTE);
    if (detour_mod.isHooked(target)) return error.AlreadyHooked;

    const base = @intFromPtr(target) - RVA_BASE_EXECUTE;
    img_base = base;
    img_end = base + 0x400_0000; // module span; the last section ends at RVA 0x39267cc
    target_addr = @intFromPtr(target); // set before the gate: ExecHookVerify doubles as a build check

    const tb: [*]const u8 = @ptrCast(target);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return error.UnexpectedPrologue;
    }
    @memcpy(&saved_code, tb[0..saved_code.len]);

    // The fingerprint fully determines installHook's decode: 5+1+4+3+3 = 16 bytes, all of
    // them position-independent, so exactly those 16 land in the trampoline. `&orig` is armed
    // inside installHookArmed before the patch goes in, so the forward path exists from the
    // first intercepted call.
    const hook = try detour_mod.installHookArmed(target, @constCast(@ptrCast(&execDetour)), &orig);
    if (hook.patch_size > saved_code.len) return error.PatchTooWide;
    stats.patch_size = hook.patch_size;
    state = .{ .hook = hook, .installed = true };
}

/// Copies our own snapshot of the original prologue back over the patch. This is the
/// authoritative restore: it does not depend on the trampoline bytes removeHook reads still
/// being intact, and it runs even when removeHook failed midway.
fn restoreTarget(len: usize) !void {
    var guard = try windows.ProtectGuard.change(@ptrFromInt(target_addr), len, .execute_readwrite);
    defer guard.deinit();
    const dst: [*]u8 = @ptrFromInt(target_addr);
    @memcpy(dst[0..len], saved_code[0..len]);
    windows.flushInstructionCache(@ptrFromInt(target_addr), len);
}

/// Remove the detour. Only safe while no game thread is inside base Execute.
/// Errors mean the engine bytes may still be patched — do not trust the process until
/// ExecHookVerify says otherwise.
pub fn uninstall() !void {
    const h = state.hook orelse return;
    // Trampoline cleanup + its own restore attempt; restoreTarget below decides the outcome.
    detour_mod.removeHook(&h) catch {};
    state = .{};
    try restoreTarget(h.patch_size);
    orig = null; // only once the engine bytes are ours again
    if (!fingerprintMatches()) return error.RestoreIncomplete;
}

// ---------------------------------------------------------------------------
// Exported entry points (injector-facing)
// ---------------------------------------------------------------------------

export fn ExecHookInstall() callconv(.c) i32 {
    if (!is_windows) return -2;
    install() catch |err| return switch (err) {
        error.AlreadyHooked => -3,
        error.UnexpectedPrologue => -4,
        error.PatchTooWide => -5,
        else => -1,
    };
    return 0;
}

/// 0 = detached and the engine bytes verified intact. -6 = the restore did not take: do not
/// trust the process, and never FreeLibrary this DLL with that result (the JMP would dangle).
export fn ExecHookUninstall() callconv(.c) i32 {
    if (!is_windows) return -2;
    uninstall() catch return -6;
    return 0;
}

/// 0 = the engine's bytes are intact at the target, -1 = fingerprint mismatch,
/// -2 = non-Windows, -3 = the target was never resolved this session.
export fn ExecHookVerify() callconv(.c) i32 {
    if (!is_windows) return -2;
    if (target_addr == 0) return -3;
    return if (fingerprintMatches()) 0 else -1;
}

/// Writes [Entry, HistEntry, Stats, ring_len, hist_len] so the Frida driver never sizes a
/// buffer or parses a layout this build did not intend. Five u32s, not a packed u64: JS
/// numbers cannot hold 2^58.
export fn ExecHookLayout(out: [*]u32) callconv(.c) u32 {
    out[0] = @sizeOf(Entry);
    out[1] = @sizeOf(HistEntry);
    out[2] = @sizeOf(Stats);
    out[3] = @intCast(RING_LEN);
    out[4] = @intCast(HIST_LEN);
    return 5;
}

export fn ExecHookStats(out: *Stats) callconv(.c) i32 {
    out.* = stats;
    out.img_base = img_base;
    return 0;
}

/// Copy the retained sampled records into `buf`, oldest first. Returns the count.
export fn ExecHookDrain(buf: [*]Entry, max: u32) callconv(.c) u32 {
    const total = seq.load(.monotonic);
    const first: u64 = if (total > RING_LEN) total - RING_LEN else 0;
    var i: u64 = first;
    var copied: u32 = 0;
    while (i < total and copied < max) : (i += 1) {
        buf[copied] = ring[@intCast(i % RING_LEN)];
        copied += 1;
    }
    return copied;
}

/// Copy the shim histogram into `buf` in table (hash-slot) order — the driver sorts by
/// count. Counts cover every call, not just the sampled ones. Does not clear (ExecHookReset).
export fn ExecHookHistogram(out: [*]HistEntry, max: u32) callconv(.c) u32 {
    var copied: u32 = 0;
    for (&hist) |*h| {
        if (h.shim_rva != 0 and copied < max) {
            out[copied] = h.*;
            copied += 1;
        }
    }
    return copied;
}

/// Clears counters, records and the histogram. patch_size is install metadata and stays.
export fn ExecHookReset() callconv(.c) void {
    stats = .{ .patch_size = stats.patch_size };
    _ = seq.swap(0, .monotonic);
    @memset(&hist, .{});
}

// ---------------------------------------------------------------------------
// Tests (read guards + recorder logic; install path is Windows-runtime only)
// ---------------------------------------------------------------------------

test "record sizes match the Frida driver's parsing" {
    var layout: [5]u32 = undefined;
    try std.testing.expectEqual(@as(u32, 5), ExecHookLayout(&layout));
    try std.testing.expectEqual(@as(u32, 88), layout[0]); // Entry
    try std.testing.expectEqual(@as(u32, 16), layout[1]); // HistEntry
    try std.testing.expectEqual(@as(u32, 48), layout[2]); // Stats
    try std.testing.expectEqual(@as(u32, @intCast(RING_LEN)), layout[3]);
    try std.testing.expectEqual(@as(u32, @intCast(HIST_LEN)), layout[4]);
}

test "plausible rejects bad pointers" {
    try std.testing.expect(!plausible(0));
    try std.testing.expect(!plausible(0x1234));
    try std.testing.expect(!plausible(0xffff_8000_0000_0000));
    try std.testing.expect(!plausible(0x7ff7_4a63_0001)); // misaligned
    try std.testing.expect(plausible(0x7ff7_4a63_0000));
}

test "read guards return null instead of faulting" {
    try std.testing.expectEqual(@as(?u64, null), readU64(0));
    var obj: [64]u8 align(8) = [_]u8{0} ** 64;
    std.mem.writeInt(u64, obj[0..8], 0x1122, .little);
    try std.testing.expectEqual(@as(?u64, 0x1122), readU64(@intFromPtr(&obj)));
}

/// A fake effect instance + exec context, laid out the way the shim hands them over. Must
/// stay in the caller's frame: the instance's vtable pointer is its own address.
const Fake = struct {
    obj: [0x20]u8 align(8) = [_]u8{0} ** 0x20,
    ctx: [0x40]u8 align(8) = [_]u8{0} ** 0x40,
    vtable: [0x18]u8 align(8) = [_]u8{0} ** 0x18,

    fn arm(f: *Fake, shim: u64, token: u32, arg: u32, counter: u32, ctx_30: u64) void {
        std.mem.writeInt(u64, f.vtable[VTBL_SLOT_SHIM..][0..8], shim, .little);
        std.mem.writeInt(u64, f.obj[0..8], @intFromPtr(&f.vtable), .little);
        std.mem.writeInt(u32, f.obj[SELF_TOKEN_ID..][0..4], token, .little);
        std.mem.writeInt(u32, f.obj[SELF_ARG..][0..4], arg, .little);
        std.mem.writeInt(u32, f.ctx[CTX_RECURSION..][0..4], counter, .little);
        std.mem.writeInt(u64, f.ctx[CTX_30..][0..8], ctx_30, .little);
    }
};

test "observe histograms every call, sample records only the sampled ones" {
    ExecHookReset();
    img_base = 0x1000_0000;
    img_end = 0x2000_0000;

    var f: Fake = .{};
    f.arm(0x1000_5000, 0x1f3, 0x2a, 2, 0x1000_7000);
    const self = @intFromPtr(&f.obj);
    const ctx = @intFromPtr(&f.ctx);

    // Three calls, one record: the detour takes this shape at the sample gate.
    var id = observe(self);
    id = observe(self);
    id = observe(self);
    sample(self, ctx, id);

    var buf: [4]Entry = undefined;
    try std.testing.expectEqual(@as(u32, 1), ExecHookDrain(&buf, 4));
    try std.testing.expectEqual(@as(u8, 1), buf[0].valid);
    try std.testing.expectEqual(@as(u32, 0x1f3), buf[0].token_id);
    try std.testing.expectEqual(@as(u32, 0x2a), buf[0].arg_token);
    try std.testing.expectEqual(@as(i32, 2), buf[0].ctx_counter);
    try std.testing.expectEqual(@as(u32, 0x5000), buf[0].shim_rva);
    // The fake image window cannot contain a host stack address, so the vtable pointer
    // itself is correctly classified as foreign. toRva's windowing has its own test.
    try std.testing.expectEqual(@as(u32, 0), buf[0].self_vtable_rva);
    try std.testing.expectEqual(@as(u64, 0x1000_7000), buf[0].ctx_30);

    var hb: [4]HistEntry = undefined;
    try std.testing.expectEqual(@as(u32, 1), ExecHookHistogram(&hb, 4));
    try std.testing.expectEqual(@as(u32, 0x5000), hb[0].shim_rva);
    try std.testing.expectEqual(@as(u64, 3), hb[0].count); // all three calls, not one sample
}

test "a foreign shim address is recorded but never histogrammed" {
    ExecHookReset();
    img_base = 0x1000_0000;
    img_end = 0x2000_0000;
    var f: Fake = .{};
    f.arm(0x7fff_0000_1000, 1, 0, 0, 0); // slot[2] outside the module
    const id = observe(@intFromPtr(&f.obj));
    try std.testing.expect(id.valid);
    try std.testing.expectEqual(@as(u32, 0), id.shim_rva);
    var hb: [4]HistEntry = undefined;
    try std.testing.expectEqual(@as(u32, 0), ExecHookHistogram(&hb, 4));
}

test "fingerprintMatches is the install gate and the post-uninstall proof" {
    var code: [EXPECTED_CODE.len]u8 = EXPECTED_CODE;
    img_base = 0;
    img_end = 0;
    target_addr = 0;
    try std.testing.expect(!fingerprintMatches()); // target never resolved
    target_addr = @intFromPtr(&code);
    try std.testing.expect(fingerprintMatches());
    code[0] = 0xFF; // what our JMP patch leaves behind if restore failed
    try std.testing.expect(!fingerprintMatches());
    target_addr = 0;
}

test "toRva windows module pointers and drops foreign ones" {
    img_base = 0x7ff7_4a63_0000; // live 4.4.4 base seen this session
    img_end = img_base + 0x400_0000;
    try std.testing.expectEqual(@as(u32, @intCast(RVA_BASE_EXECUTE)), toRva(img_base + RVA_BASE_EXECUTE));
    try std.testing.expectEqual(@as(u32, 0), toRva(img_base - 8));
    try std.testing.expectEqual(@as(u32, 0), toRva(img_end));
    img_end = img_base + 0x8_0000_0000; // span too wide for a u32 RVA
    try std.testing.expectEqual(@as(u32, 0), toRva(img_base + 0x1_0000_0000));
}

test "an unreadable instance is invalid and counted per call" {
    ExecHookReset();
    img_base = 0x1000_0000;
    img_end = 0x2000_0000;
    const id = observe(0);
    sample(0, 0, id);
    _ = observe(0); // invalid counts every call, not only the sampled one
    var buf: [4]Entry = undefined;
    try std.testing.expectEqual(@as(u32, 1), ExecHookDrain(&buf, 4));
    try std.testing.expectEqual(@as(u8, 0), buf[0].valid);
    var st = Stats{};
    _ = ExecHookStats(&st);
    try std.testing.expectEqual(@as(u64, 2), st.invalid);
}

test "drain returns the newest RING_LEN records" {
    ExecHookReset();
    img_base = 0x1000_0000;
    img_end = 0x2000_0000;
    var i: u64 = 0;
    while (i < RING_LEN + 5) : (i += 1) _ = seq.fetchAdd(1, .monotonic);
    var buf: [RING_LEN + 16]Entry = undefined;
    try std.testing.expectEqual(@as(u32, RING_LEN), ExecHookDrain(&buf, buf.len));
}
