// live_probe.zig — C4 one-shot trigger on the engine's base Execute.
//
// The C2 predicate detour repoints the registered keyword's instance at the
// DLL vtable, but nothing forces the engine to *evaluate* that effect. This
// probe sits on base Execute (0x1D08520 via exec_hook) and, on the first
// call whose context is usable, synthesizes one instantiate(0x3B01A0) of the
// armed token under a synthetic parse context. The engine's own call runs
// first, so the probe never changes what the game was doing; after the single
// fire it stays inert and only counts.

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const windows = @import("../hooking/windows.zig");
const exec_hook = @import("../scripted/exec_hook.zig");
const vtable = @import("vtable.zig");
const predicate_hook = @import("predicate_hook.zig");

const is_windows = builtin.os.tag == .windows;

const OrigFn = *const fn (self: u64, ctx: u64, a3: u64, a4: u64) callconv(.c) u64;
const InstantiateFn = *const fn (parent: u64, ctx: u64, token: u32, r9: u64) callconv(.c) u64;

var target_token: u32 = 0;
var instantiate_addr: usize = 0;
var fired: u32 = 0;
var calls: u64 = 0;
var ctx_skip: u64 = 0;
var invalid: u64 = 0;
var instantiate_rc: u64 = 0;

// [ctx+0x38] == 0xb marks the lexer path. Kept as an environment gate: the
// synthetic context below is what instantiate actually receives.
pub fn ctxUsable(word38: u32) bool {
    return word38 != 0xb;
}

// ---------------------------------------------------------------------------
// Synthetic parse context
// ---------------------------------------------------------------------------
// [VERIFIED 4.4.4 STATIC] instantiate's hit path (create != NULL -> 0x3B0984)
// reads exactly two real-context fields: [ctx+0x38] in the prologue and
// [ctx+0x30] inside the name builder 0x1D0C9F0. The builder takes
// A = [ctx+0x30], B = [A+8] and, with [B+0x70] == 0, only reads the ints at
// B+8/B+0xc and the std::string at B+0x30/B+0x40/B+0x48. A live event scope
// satisfies none of this: the 2026-10-23 shot threw std::length_error in the
// [B+0x70] != 0 branch. The probe therefore passes a zeroed B (safe branch)
// and leaves the live script tree untouched.
//
// arg1 is read as a container at [arg1+8] (0x3B0C3F: mov rcx,[rbp+0x530];
// add rcx,8) and handed to 0x22C4A0. That object is NOT a bare vector:
// +0x00 vptr, +0x08 begin, +0x10 capacity (u32), +0x14 size (u32). When
// size == capacity the grow branch calls [vptr+0x18] — the zeroed parent of
// the 2026-10-23 shot faulted reading 0x18 there. Pre-sizing begin/capacity
// keeps every append on the fast path (0x22C58B), which reads only begin and
// the two u32s. Capacity 16 leaves headroom: the probe fires at most once,
// and the engine never owns this container.

const SYNTH_CTX_LEN: usize = 0x300;
const SYNTH_B_LEN: usize = 0x80;
const SYNTH_PARENT_LEN: usize = 0x20;
pub const SYNTH_SLOT_COUNT: usize = 16;

var synth_ctx: [SYNTH_CTX_LEN]u8 align(16) = [_]u8{0} ** SYNTH_CTX_LEN;
var synth_a: [0x10]u8 align(16) = [_]u8{0} ** 0x10;
var synth_b: [SYNTH_B_LEN]u8 align(16) = [_]u8{0} ** SYNTH_B_LEN;
var synth_parent: [SYNTH_PARENT_LEN]u8 align(16) = [_]u8{0} ** SYNTH_PARENT_LEN;
var synth_slots: [SYNTH_SLOT_COUNT]u64 align(16) = [_]u64{0} ** SYNTH_SLOT_COUNT;

fn initSynthetic() void {
    @memset(&synth_ctx, 0);
    @memset(&synth_a, 0);
    @memset(&synth_b, 0);
    @memset(&synth_parent, 0);
    @memset(&synth_slots, 0);
    writeU64(&synth_a, 8, @intFromPtr(&synth_b));
    writeU64(&synth_ctx, 0x30, @intFromPtr(&synth_a));
    // container = parent+8: begin at parent+0x10, capacity +0x18, size +0x1c
    writeU64(&synth_parent, 0x10, @intFromPtr(&synth_slots));
    writeU32(&synth_parent, 0x18, @intCast(SYNTH_SLOT_COUNT));
    writeU32(&synth_parent, 0x1c, 0);
}

fn fireSynthetic(value: u32) u64 {
    initSynthetic();
    const f: InstantiateFn = @ptrFromInt(instantiate_addr);
    return f(@intFromPtr(&synth_parent), @intFromPtr(&synth_ctx), value, 0);
}

fn fireOnce() u64 {
    if (target_token == 0 or instantiate_addr == 0) {
        invalid += 1;
        return 0;
    }
    if (@cmpxchgStrong(u32, &fired, 0, 1, .monotonic, .monotonic) != null) return 0;
    instantiate_rc = fireSynthetic(target_token);
    return instantiate_rc;
}

pub fn syntheticCtxAddr() usize {
    return @intFromPtr(&synth_ctx);
}

pub fn syntheticParentAddr() usize {
    return @intFromPtr(&synth_parent);
}

pub fn setInstantiateForTest(addr: usize) void {
    instantiate_addr = addr;
}

pub fn fireOnceForTest() u64 {
    return fireOnce();
}

fn probeDetour(self: u64, ctx: u64, a3: u64, a4: u64) callconv(.c) u64 {
    _ = @atomicRmw(u64, &calls, .Add, 1, .monotonic);
    const orig: OrigFn = @ptrCast(exec_hook.original() orelse return 0);
    const rc = orig(self, ctx, a3, a4); // engine finishes what it was running FIRST
    if (target_token == 0 or instantiate_addr == 0) {
        invalid += 1;
        return rc;
    }
    if (!plausible(self) or !plausible(ctx)) {
        invalid += 1;
        return rc;
    }
    if (!ctxUsable(readU32(ctx, 0x38))) {
        ctx_skip += 1;
        return rc;
    }
    _ = fireOnce();
    return rc;
}

pub fn setToken(value: u32) error{ InvalidToken, AlreadyInstalled }!void {
    if (value == 0) return error.InvalidToken;
    if (exec_hook.isInstalled()) return error.AlreadyInstalled;
    target_token = value;
}

pub fn token() u32 {
    return target_token;
}

pub fn install() !void {
    if (!is_windows) return error.Unsupported;
    if (target_token == 0) return error.TokenUnset;
    if (exec_hook.isInstalled()) return error.AlreadyHooked;

    const target = try windows.moduleFunction(offsets.keyword_reg.RVA_EFFECT_INSTANTIATE);
    instantiate_addr = @intFromPtr(target);
    calls = 0;
    fired = 0;
    ctx_skip = 0;
    invalid = 0;
    instantiate_rc = 0;
    exec_hook.installWith(@ptrCast(@constCast(&probeDetour))) catch |err| {
        instantiate_addr = 0;
        return err;
    };
}

/// Inert first, then restore base Execute. A no-op when never installed —
/// the driver calls it unconditionally during cleanup.
pub fn uninstall() !void {
    instantiate_addr = 0;
    try exec_hook.uninstall();
}

pub fn isInstalled() bool {
    return exec_hook.isInstalled();
}

pub fn verify() i32 {
    return exec_hook.verifyState();
}

/// One line, every key exactly once (see scripts/c2_exec_probe.py).
pub fn statsInto(out: []u8) usize {
    const pred = predicate_hook.getStats();
    const written = std.fmt.bufPrint(
        out,
        "armed={d} token={d} calls={d} fired={d} ctx_skip={d} invalid={d} " ++
            "instantiate_rc={d} patch_size={d} installed={d} verified={d} " ++
            "vtable={d} chain={d} pred_installed={d} pred_calls={d} pred_patched={d}\n",
        .{
            @intFromBool(target_token != 0),
            target_token,
            calls,
            fired,
            ctx_skip,
            invalid,
            instantiate_rc,
            exec_hook.patchSize(),
            @intFromBool(exec_hook.isInstalled()),
            exec_hook.verifyState(),
            @intFromBool(vtable.isBuilt()),
            @intFromBool(vtable.chainEnabled()),
            @intFromBool(pred.installed),
            pred.calls,
            pred.patched,
        },
    ) catch return 0;
    return written.len;
}

pub fn resetForTest() void {
    target_token = 0;
    instantiate_addr = 0;
    fired = 0;
    calls = 0;
    ctx_skip = 0;
    invalid = 0;
    instantiate_rc = 0;
    initSynthetic();
}

// ---------------------------------------------------------------------------
// Helpers (vtable.zig keeps its copies private)
// ---------------------------------------------------------------------------

fn plausible(p: usize) bool {
    return p >= 0x10000 and p <= 0x00007FFF_FFFF_0000 and (p & 7) == 0;
}

fn readU32(addr: usize, comptime off: usize) u32 {
    if (!plausible(addr)) return 0;
    const base: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u32, base[off..][0..4], .little);
}

fn writeU64(buf: []u8, comptime off: usize, value: u64) void {
    std.mem.writeInt(u64, buf[off..][0..8], value, .little);
}

fn writeU32(buf: []u8, comptime off: usize, value: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], value, .little);
}
