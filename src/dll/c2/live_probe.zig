// live_probe.zig — C4 one-shot trigger on the engine's base Execute.
//
// The C2 predicate detour repoints the registered keyword's instance at the
// DLL vtable, but nothing forces the engine to *evaluate* that effect. This
// probe sits on base Execute (0x1D08520 via exec_hook) and, on the first
// call whose context is usable, synthesizes one instantiate(0x3B01A0) of the
// armed token under the same context. The engine's own call runs first, so
// the probe never changes what the game was doing; after the single fire it
// stays inert and only counts.

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

// [ctx+0x38] == 0xb marks the lexer path, where the context is not a real
// event scope and instantiate must not be called.
pub fn ctxUsable(word38: u32) bool {
    return word38 != 0xb;
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
    if (@cmpxchgStrong(u32, &fired, 0, 1, .monotonic, .monotonic) != null) return rc;
    const f: InstantiateFn = @ptrFromInt(instantiate_addr);
    instantiate_rc = f(self, ctx, target_token, 0);
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
