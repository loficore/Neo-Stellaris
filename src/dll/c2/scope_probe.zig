// scope_probe.zig — read-only recorder for the base-Execute execution frame.
//
// This probe only records: it never writes engine memory and never changes a
// register, argument, or the control flow of the original. The chain
// X=[ctx+0x30] -> S=[X+8] -> id=[S+8] / obj=[S+0x20] is NOT followed in-process;
// the Python driver follows it with ReadProcessMemory so a stale pointer cannot
// fault the host. The detour goes through exec_hook.installWith and always
// forwards to exec_hook.original().

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const windows = @import("../hooking/windows.zig");
const exec_hook = @import("../scripted/exec_hook.zig");

const is_windows = builtin.os.tag == .windows;

pub const RVA_BASE_EXECUTE: usize = offsets.keyword_reg.RVA_BASE_EXECUTE; // = 0x1D08520
pub const RING_LEN: usize = 256;
pub const SAMPLE_MASK: u64 = 511;
pub const LAYOUT_VERSION: u32 = 1;
pub const LEXER_SENTINEL: u32 = 0xb;
pub const CTX_X: usize = 0x30;
pub const SELF_TOKEN_ID: usize = 0x08;
pub const VTBL_SLOT_SHIM: usize = 0x10;

pub const Entry = extern struct {
    valid: u8 = 0,
    lexer: u8 = 0,
    pad0: [2]u8 = [_]u8{0} ** 2,
    self_vtable_rva: u32 = 0,
    shim_rva: u32 = 0,
    token_id: u32 = 0,
    caller_rva: u32 = 0,
    pad1: [4]u8 = [_]u8{0} ** 4,
    self_ptr: u64 = 0,
    ctx_ptr: u64 = 0,
    ctx_words: [8]u64 = [_]u64{0} ** 8,
};

pub const Stats = extern struct {
    calls: u64 = 0,
    samples: u64 = 0,
    invalid_self: u64 = 0, // the next five are per-sample, not per-call
    invalid_ctx: u64 = 0,
    lexer: u64 = 0,
    x_nonzero: u64 = 0,
    patch_size: u64 = 0,
};

comptime {
    if (@sizeOf(Entry) != 104) @compileError("Entry must be 104 bytes");
    if (@sizeOf(Stats) != 56) @compileError("Stats must be 56 bytes");
}

var img_base: usize = 0;
var img_end: usize = 0;

var ring: [RING_LEN]Entry = undefined;
var seq = std.atomic.Value(u64).init(0);
var stats = Stats{};
var installed: bool = false;

// ---------------------------------------------------------------------------
// Safe memory reads
// ---------------------------------------------------------------------------

fn plausible(p: usize) bool {
    return p >= 0x10000 and p <= 0x00007FFF_FFFF_0000 and (p & 7) == 0;
}

fn readU64(addr: usize) ?u64 {
    if (!plausible(addr)) return null;
    return @as(*align(8) const u64, @ptrFromInt(addr)).*;
}

fn readU32(addr: usize, comptime off: usize) ?u32 {
    if (!plausible(addr)) return null;
    const base: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u32, base[off..][0..4], .little);
}

/// Module-relative address of `abs`, or 0 when `abs` is not inside stellaris.exe.
fn toRva(abs: usize) u32 {
    if (abs < img_base or abs >= img_end) return 0;
    const rva = abs - img_base;
    if (rva > std.math.maxInt(u32)) return 0;
    return @intCast(rva);
}

// ---------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------

pub fn shouldSample(call_index: u64) bool {
    return (call_index & SAMPLE_MASK) == 0;
}

fn capture(self: usize, ctx: usize, caller: usize) void {
    const idx: usize = @intCast(seq.fetchAdd(1, .monotonic) % @as(u64, RING_LEN));
    const e = &ring[idx];
    e.* = .{};
    e.caller_rva = toRva(caller);

    if (readU64(self)) |vtbl| {
        e.self_ptr = self;
        e.self_vtable_rva = toRva(vtbl);
        if (readU32(self, SELF_TOKEN_ID)) |t| e.token_id = t;
        if (readU64(vtbl + VTBL_SLOT_SHIM)) |shim| e.shim_rva = toRva(shim);
    } else {
        _ = @atomicRmw(u64, &stats.invalid_self, .Add, 1, .monotonic);
        return;
    }

    if (!plausible(ctx)) {
        _ = @atomicRmw(u64, &stats.invalid_ctx, .Add, 1, .monotonic);
        return;
    }
    e.ctx_ptr = ctx;
    var i: usize = 0;
    while (i < 8) : (i += 1) e.ctx_words[i] = readU64(ctx + i * 8) orelse 0;
    e.valid = 1;
    if (@as(u32, @truncate(e.ctx_words[7])) == LEXER_SENTINEL) {
        e.lexer = 1;
        _ = @atomicRmw(u64, &stats.lexer, .Add, 1, .monotonic);
    }
    if (e.ctx_words[6] != 0) _ = @atomicRmw(u64, &stats.x_nonzero, .Add, 1, .monotonic);
}

// ---------------------------------------------------------------------------
// Detour
// ---------------------------------------------------------------------------

const OrigFn = *const fn (u64, u64, u64, u64) callconv(.c) u64;

fn scopeDetour(self: u64, ctx: u64, a3: u64, a4: u64) callconv(.c) u64 {
    const calls = @atomicRmw(u64, &stats.calls, .Add, 1, .monotonic) + 1;
    if (shouldSample(calls)) {
        _ = @atomicRmw(u64, &stats.samples, .Add, 1, .monotonic);
        capture(@intCast(self), @intCast(ctx), @returnAddress());
    }
    const f: OrigFn = @ptrCast(exec_hook.original() orelse return 0);
    return f(self, ctx, a3, a4);
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

pub fn install() !void {
    if (!is_windows) return error.Unsupported;
    if (installed) return error.AlreadyInstalled;
    if (exec_hook.isInstalled()) return error.ExecHookActive;

    const target = try windows.moduleFunction(RVA_BASE_EXECUTE);
    img_base = @intFromPtr(target) - RVA_BASE_EXECUTE;
    img_end = img_base + 0x400_0000;
    exec_hook.installWith(@ptrCast(@constCast(&scopeDetour))) catch |err| {
        img_base = 0;
        img_end = 0;
        return err;
    };
    installed = true;
    stats.patch_size = exec_hook.patchSize();
}

pub fn uninstall() !void {
    if (!installed) return;
    try exec_hook.uninstall();
    installed = false;
}

pub fn verify() i32 {
    return exec_hook.verifyState();
}

pub fn isInstalled() bool {
    return installed;
}

// ---------------------------------------------------------------------------
// Injector-facing readouts
// ---------------------------------------------------------------------------

/// Writes [Entry size, Stats size, ring length, sample mask, layout version].
pub fn layoutInto(out: [*]u32) u32 {
    out[0] = @sizeOf(Entry);
    out[1] = @sizeOf(Stats);
    out[2] = @intCast(RING_LEN);
    out[3] = @intCast(SAMPLE_MASK);
    out[4] = LAYOUT_VERSION;
    return 5;
}

/// One line, every driver key exactly once (see scripts/c2_scope_probe.py).
pub fn statsInto(out: []u8) usize {
    const written = std.fmt.bufPrint(
        out,
        "calls={d} samples={d} invalid_self={d} invalid_ctx={d} lexer={d} " ++
            "x_nonzero={d} patch_size={d} installed={d} verified={d}\n",
        .{
            stats.calls,
            stats.samples,
            stats.invalid_self,
            stats.invalid_ctx,
            stats.lexer,
            stats.x_nonzero,
            stats.patch_size,
            @intFromBool(installed),
            verify(),
        },
    ) catch return 0;
    return written.len;
}

/// Copy the retained records into `out` (8-aligned) oldest first. Returns the count.
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

/// Clears counters, records and the image window. Only before install or after uninstall.
pub fn reset() void {
    stats = .{};
    _ = seq.swap(0, .monotonic);
    installed = false;
    img_base = 0;
    img_end = 0;
}

test "entry layout is pinned for the Python decoder" {
    try std.testing.expectEqual(@as(usize, 104), @sizeOf(Entry));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(Entry, "valid"));
    try std.testing.expectEqual(@as(usize, 1), @offsetOf(Entry, "lexer"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(Entry, "self_vtable_rva"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(Entry, "shim_rva"));
    try std.testing.expectEqual(@as(usize, 12), @offsetOf(Entry, "token_id"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(Entry, "caller_rva"));
    try std.testing.expectEqual(@as(usize, 24), @offsetOf(Entry, "self_ptr"));
    try std.testing.expectEqual(@as(usize, 32), @offsetOf(Entry, "ctx_ptr"));
    try std.testing.expectEqual(@as(usize, 40), @offsetOf(Entry, "ctx_words"));
    var l: [5]u32 = undefined;
    try std.testing.expectEqual(@as(u32, 5), layoutInto(&l));
    try std.testing.expectEqual(@as(u32, 104), l[0]);
    try std.testing.expectEqual(@as(u32, 56), l[1]);
    try std.testing.expectEqual(@as(u32, 256), l[2]);
    try std.testing.expectEqual(@as(u32, 511), l[3]);
    try std.testing.expectEqual(@as(u32, 1), l[4]);
}

test "plausible rejects bad pointers" {
    try std.testing.expect(!plausible(0));
    try std.testing.expect(!plausible(0x1234));
    try std.testing.expect(!plausible(0xffff_8000_0000_0000));
    try std.testing.expect(plausible(0x7ff7_4a63_0000));
}

test "capture records identity, ctx words and caller rva" {
    reset();
    var f: Fake = .{};
    const win = @intFromPtr(&f) & ~@as(usize, 0xfff);
    img_base = win;
    img_end = win + 0x10_0000;
    f.arm(win + 0x1500, 0x1f3);
    std.mem.writeInt(u64, f.ctx[0x30..][0..8], 0x5000_0000_0000, .little);
    capture(@intFromPtr(&f.obj), @intFromPtr(&f.ctx), win + 0x1234);
    var buf: [4]Entry = undefined;
    try std.testing.expectEqual(@as(u32, 1), drainInto(@ptrCast(&buf[0])));
    try std.testing.expectEqual(@as(u8, 1), buf[0].valid);
    try std.testing.expectEqual(@as(u64, @intFromPtr(&f.obj)), buf[0].self_ptr);
    try std.testing.expectEqual(@as(u32, @intCast(@intFromPtr(&f.vtable) - win)), buf[0].self_vtable_rva);
    try std.testing.expectEqual(@as(u32, 0x1500), buf[0].shim_rva);
    try std.testing.expectEqual(@as(u32, 0x1f3), buf[0].token_id);
    try std.testing.expectEqual(@as(u32, 0x1234), buf[0].caller_rva);
    try std.testing.expectEqual(@as(u64, 0x5000_0000_0000), buf[0].ctx_words[6]);
    try std.testing.expectEqual(@as(u8, 0), buf[0].lexer);
}

test "capture marks bad self, bad ctx and the lexer sentinel" {
    reset();
    var f: Fake = .{};
    const win = @intFromPtr(&f) & ~@as(usize, 0xfff);
    img_base = win;
    img_end = win + 0x10_0000;
    f.arm(0, 0);
    const self = @intFromPtr(&f.obj);
    const ctx = @intFromPtr(&f.ctx);
    capture(self, 0, win + 0x77);                 // bad ctx
    capture(self, ctx, win + 0x88);               // normal
    std.mem.writeInt(u32, f.ctx[0x38..][0..4], LEXER_SENTINEL, .little);
    capture(self, ctx, win + 0x99);               // lexer
    capture(0, ctx, win + 0xAA);                  // bad self
    var buf: [4]Entry = undefined;
    try std.testing.expectEqual(@as(u32, 4), drainInto(@ptrCast(&buf[0])));
    try std.testing.expectEqual(@as(u8, 0), buf[0].valid);
    try std.testing.expectEqual(@as(u32, 0x77), buf[0].caller_rva);
    try std.testing.expectEqual(@as(u8, 1), buf[1].valid);
    try std.testing.expectEqual(@as(u8, 1), buf[2].lexer);
    try std.testing.expectEqual(@as(u8, 0), buf[3].valid);
    try std.testing.expectEqual(@as(u32, 0xAA), buf[3].caller_rva);
    try std.testing.expectEqual(@as(u64, 1), stats.invalid_ctx);
    try std.testing.expectEqual(@as(u64, 1), stats.invalid_self);
    try std.testing.expectEqual(@as(u64, 1), stats.lexer);
}

test "sample gate fires exactly once per 512 calls" {
    var hits: usize = 0;
    var i: u64 = 1;
    while (i <= 1024) : (i += 1) {
        if (shouldSample(i)) hits += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), hits);
    try std.testing.expect(shouldSample(512));
    try std.testing.expect(shouldSample(1024));
    try std.testing.expect(!shouldSample(513));
}

test "drain returns the newest RING_LEN records oldest first" {
    reset();
    img_base = 0x1000_0000;
    img_end = 0x2000_0000;
    var i: usize = 0;
    while (i < RING_LEN + 5) : (i += 1) capture(0, 0, 0x1000_0000 + i);
    var buf: [RING_LEN + 16]Entry = undefined;
    try std.testing.expectEqual(@as(u32, RING_LEN), drainInto(@ptrCast(&buf[0])));
    try std.testing.expectEqual(@as(u32, 5), buf[0].caller_rva);
    try std.testing.expectEqual(@as(u32, RING_LEN + 4), buf[RING_LEN - 1].caller_rva);
}

test "stats text renders every driver key exactly once" {
    reset();
    var buf: [512]u8 = undefined;
    const n = statsInto(&buf);
    const text = buf[0..n];
    for ([_][]const u8{
        "calls", "samples", "invalid_self", "invalid_ctx",
        "lexer", "x_nonzero", "patch_size", "installed", "verified",
    }) |key| try std.testing.expectEqual(@as(usize, 1), countExactKey(text, key));
}

const Fake = struct {
    obj: [0x20]u8 align(8) = [_]u8{0} ** 0x20,
    ctx: [0x40]u8 align(8) = [_]u8{0} ** 0x40,
    vtable: [0x18]u8 align(8) = [_]u8{0} ** 0x18,

    fn arm(f: *Fake, shim: u64, token: u32) void {
        std.mem.writeInt(u64, f.vtable[VTBL_SLOT_SHIM..][0..8], shim, .little);
        std.mem.writeInt(u64, f.obj[0..8], @intFromPtr(&f.vtable), .little);
        std.mem.writeInt(u32, f.obj[SELF_TOKEN_ID..][0..4], token, .little);
    }
};

fn countExactKey(text: []const u8, key: []const u8) usize {
    var n: usize = 0;
    var it = std.mem.tokenizeAny(u8, text, " \n");
    while (it.next()) |tok| {
        const eq = std.mem.indexOfScalar(u8, tok, '=') orelse continue;
        if (std.mem.eql(u8, tok[0..eq], key)) n += 1;
    }
    return n;
}
