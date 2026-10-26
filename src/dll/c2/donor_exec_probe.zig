// donor_exec_probe.zig — read-only recorder for the donor-family Execute override.
//
// Target: RVA 0x3AFD30 (offsets.keyword_reg.RVA_EFFECT_DONOR_EXECUTE, referenced
// here, never redefined) — the [vptr+0x08] Execute override shared by the five
// CEffect-family vtables named in evidence §57.4. It is NOT the base Execute
// 0x1D08520. This probe only records: it never writes engine memory, never
// modifies registers or arguments, and never changes control flow; the Task 2
// detour always forwards to the original.
//
// Entry.ctx_ptr / a3 / a4 are recorded as VALUES only — dereferencing them is
// the Python driver's ReadProcessMemory job, for the same reason scope_probe.zig
// gives: a stale pointer must only make one driver read return None, it must
// never fault the host. This probe deliberately does NOT read the eight qwords
// under ctx — §53.5 disproved the [ctx+0x30] chain; nothing new is built on it.
//
// Counters (table_hits/unmatched/invalid_self, and samples/calls on the Task 2
// side) are per-call; only the ring write passes the shouldSample gate. That is
// §57.4's hot-path discipline: measure the call frequency from the calls delta
// first, then pick the sampling denominator — the tier verdicts (matched /
// table_hits = tier 1, unmatched = tier 2) never depend on the denominator.

const std = @import("std");
const offsets = @import("../shared/offsets.zig");

/// §57.4's target: the shared donor-family Execute override (hidden_effect's
/// own [vptr+0x08], live since §52). Reference only — the value lives in offsets.zig.
pub const RVA_DONOR_EXECUTE: usize = offsets.keyword_reg.RVA_EFFECT_DONOR_EXECUTE; // = 0x3AFD30

pub const RING_LEN: usize = 256;
pub const LAYOUT_VERSION: u32 = 1;

/// The five CEffect-family vtables that share the 0x3AFD30 Execute override
/// (§57.4). classifyTable joins [self+0]'s RVA against this table.
pub const FAMILY_VTABLES = [5]u32{ 0x24B1D98, 0x24EAAC0, 0x25F4440, 0x2606F00, 0x2606FE0 };

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
    if (@sizeOf(Entry) != 48) @compileError("Entry must be 48 bytes");
    if (@sizeOf(Stats) != 56) @compileError("Stats must be 56 bytes");
}

var img_base: usize = 0;
var img_end: usize = 0;
var sample_mask: u64 = 0;

var ring: [RING_LEN]Entry = undefined;
var seq = std.atomic.Value(u64).init(0);
var stats = Stats{};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Sets the module window used by toRva. Tests point it at host fake objects;
/// Task 2's install sets it from the real module base.
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
/// mask is a u64, so it takes two words — do not copy scope_probe's 5-word layout.
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

/// One line, fixed key order (the driver parses these keys; see the Task 3 driver).
/// `installed` stays the constant 0 until Task 2 supplies install state + verify().
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
            @as(u8, 0), // installed: constant 0 until Task 2
            sampleMask(),
        },
    ) catch return 0;
    return written.len;
}

/// Copy the retained records into `out` (8-aligned) oldest first, keeping only
/// the last RING_LEN entries (same rule as scope_probe.drainInto). Returns the count.
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
pub fn reset() void {
    stats = .{};
    _ = seq.swap(0, .monotonic);
    setSampleMask(0);
    img_base = 0;
    img_end = 0;
}

test "donor probe Entry is 48 bytes and Stats is 56 bytes" {
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
