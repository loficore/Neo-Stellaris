// wire.zig — C4 §54 capture/apply core.
//
// The vtable slot[1] bridge calls onExecute() for every effect whose [obj+0x20]
// is the armed token. In `capture` mode this module records a bounded snapshot
// of (ctx, a3, self) — read through ReadProcessMemory on Windows, through an
// injectable reader in tests — plus one level of pointer windows, so the
// driver can find which context offset carries the system id. In `apply` mode
// it resolves that id through a packed Spec and hands it to the QuickJS scored
// bridge; tier >= 1 tells the vtable to chain to the donor Execute.
//
// This module never writes engine memory. The only writes in the whole apply
// path come from the engine's own donor Execute (log / set_name).

const std = @import("std");
const chokepoint_table = @import("chokepoint_table.zig");
const windows = @import("../hooking/windows.zig");

extern fn C2ExecCallScored(token: u32, system_id: u32) c_int;

pub const Mode = enum(u32) { off = 0, capture = 1, apply = 2 };
pub const RING_CAP: usize = 2048;
pub const CTX_LEN: usize = 944;
pub const A3_LEN: usize = 256;
pub const PTR_SLOTS: usize = 8;
pub const PTR_LEN: usize = 256;
pub const RECORD_SIZE: usize = 3368;
pub const STATS_SIZE: usize = 80;
pub const LAYOUT_VERSION: u32 = 1;
pub const Reader = *const fn (addr: usize, out: []u8) bool;

pub const Record = extern struct {
    valid: u32,
    token: u32,
    serial: u32,
    reserved0: u32,
    ctx_ptr: u64,
    a3_ptr: u64,
    self_ptr: u64,
    a3_len: u32,
    ptr_count: u32,
    ctx_len: u32,
    reserved1: u32,
    ctx: [CTX_LEN]u8,
    a3: [A3_LEN]u8,
    ptr_targets: [PTR_SLOTS]u64,
    ptr_windows: [PTR_SLOTS][PTR_LEN]u8,
};

pub const Spec = packed struct(u64) {
    blob: u8,
    deref: u8,
    off_a: u16,
    off_b: u16,
    reserved: u16 = 0,
};

/// Captured records sit in .bss; the driver drains them over ReadProcessMemory.
var ring: [RING_CAP]Record = undefined;
var ring_count: usize = 0;
var ring_cap: usize = RING_CAP;
var total_records: u32 = 0;
var dropped: u32 = 0;
var calls: u32 = 0;
var resolved: u32 = 0;
var unresolved: u32 = 0;
var tiers: [3]u32 = .{ 0, 0, 0 };
var js_err: u32 = 0;
var chained: u32 = 0;
var last_id: u32 = 0;
var last_tier: i32 = -1;
var armed_token: u32 = 0;
var current_mode: Mode = .off;
var spec_bits: u64 = 0;
var spec_set: bool = false;
var active_reader: Reader = &windows.readProcessMemory;

// ---------------------------------------------------------------------------
// Session / configuration
// ---------------------------------------------------------------------------

pub fn beginSession(token: u32) void {
    ring_count = 0;
    total_records = 0;
    dropped = 0;
    calls = 0;
    resolved = 0;
    unresolved = 0;
    tiers = .{ 0, 0, 0 };
    js_err = 0;
    chained = 0;
    last_id = 0;
    last_tier = -1;
    armed_token = token;
}

pub fn setMode(m: u32) bool {
    if (m > @intFromEnum(Mode.apply)) return false;
    current_mode = @enumFromInt(m);
    return true;
}

pub fn mode() Mode {
    return current_mode;
}

pub fn setSpecPacked(bits: u64) bool {
    const spec: Spec = @bitCast(bits);
    if (!specValid(spec)) return false;
    spec_bits = bits;
    spec_set = true;
    return true;
}

pub fn specPacked() u64 {
    return spec_bits;
}

pub fn setArmedToken(token: u32) void {
    armed_token = token;
}

pub fn setReaderForTest(reader: Reader) void {
    active_reader = reader;
}

pub fn setRingCapForTest(cap: usize) void {
    ring_cap = @min(cap, RING_CAP);
}

pub fn resetForTest() void {
    ring_count = 0;
    ring_cap = RING_CAP;
    total_records = 0;
    dropped = 0;
    calls = 0;
    resolved = 0;
    unresolved = 0;
    tiers = .{ 0, 0, 0 };
    js_err = 0;
    chained = 0;
    last_id = 0;
    last_tier = -1;
    armed_token = 0;
    current_mode = .off;
    spec_bits = 0;
    spec_set = false;
    active_reader = &windows.readProcessMemory;
}

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

pub fn captureWith(reader: Reader, self_ptr: u64, token: u32, ctx: u64, a3: u64) bool {
    calls += 1;
    if (token != armed_token) return false;
    if (ring_count >= ring_cap) {
        dropped += 1;
        return true;
    }

    var rec: Record = std.mem.zeroes(Record);
    rec.valid = 1;
    rec.token = token;
    rec.serial = total_records;
    rec.ctx_ptr = ctx;
    rec.a3_ptr = a3;
    rec.self_ptr = self_ptr;
    rec.ctx_len = @intCast(CTX_LEN);

    if (!readInto(reader, ctx, rec.ctx[0..])) return false;
    if (readInto(reader, a3, rec.a3[0..])) rec.a3_len = @intCast(A3_LEN);
    scanPointers(reader, &rec);

    ring[ring_count] = rec;
    ring_count += 1;
    total_records += 1;
    return true;
}

fn scanPointers(reader: Reader, rec: *Record) void {
    var n: usize = 0;
    const blobs = [2][]const u8{ rec.ctx[0..], rec.a3[0..@as(usize, rec.a3_len)] };
    outer: for (blobs) |blob| {
        var off: usize = 0;
        while (off + 8 <= blob.len) : (off += 8) {
            if (n == PTR_SLOTS) break :outer;
            const q = std.mem.readInt(u64, blob[off..].ptr[0..8], .little);
            if (!plausible(q)) continue;
            if (contains(rec.ptr_targets[0..n], q)) continue;
            const addr = std.math.cast(usize, q) orelse continue;
            var window: [PTR_LEN]u8 = undefined;
            if (!reader(addr, &window)) continue;
            rec.ptr_targets[n] = q;
            rec.ptr_windows[n] = window;
            n += 1;
        }
    }
    rec.ptr_count = @intCast(n);
}

fn contains(values: []const u64, v: u64) bool {
    for (values) |x| {
        if (x == v) return true;
    }
    return false;
}

fn readInto(reader: Reader, addr: u64, out: []u8) bool {
    const a = std.math.cast(usize, addr) orelse return false;
    return reader(a, out);
}

// ---------------------------------------------------------------------------
// Resolve
// ---------------------------------------------------------------------------

pub fn resolveWith(reader: Reader, spec: Spec, ctx: u64, a3: u64) ?u32 {
    if (!specValid(spec)) return null;
    const base: u64 = if (spec.blob == 0) ctx else a3;
    const blob_len: usize = if (spec.blob == 0) CTX_LEN else A3_LEN;

    // One read of the containing blob, then slice locally: the reader contract
    // only promises reads that start at the base address (see the FakeMem test
    // reader), and one 944-byte RPM is cheaper than chasing per-field offsets.
    var blob: [CTX_LEN]u8 = undefined;
    if (!readInto(reader, base, blob[0..blob_len])) return null;

    const found: ?u32 = if (spec.deref == 0)
        std.mem.readInt(u32, blob[spec.off_a..].ptr[0..4], .little)
    else blk: {
        const ptr = std.mem.readInt(u64, blob[spec.off_a..].ptr[0..8], .little);
        if (!plausible(ptr)) break :blk null;
        var window: [PTR_LEN]u8 = undefined;
        if (!readInto(reader, ptr, &window)) break :blk null;
        break :blk std.mem.readInt(u32, window[spec.off_b..].ptr[0..4], .little);
    };
    const id = found orelse return null;

    if (id >= chokepoint_table.SCORE_COUNT) return null;
    return id;
}

fn specValid(spec: Spec) bool {
    if (spec.reserved != 0) return false;
    if (spec.blob > 1 or spec.deref > 1) return false;
    if ((spec.off_a & 3) != 0 or (spec.off_b & 3) != 0) return false;
    const blob_len: u32 = if (spec.blob == 0) @intCast(CTX_LEN) else @intCast(A3_LEN);
    if (spec.deref == 0) {
        if (spec.off_b != 0) return false;
        return @as(u32, spec.off_a) + 4 <= blob_len;
    }
    return @as(u32, spec.off_a) + 8 <= blob_len and
        @as(u32, spec.off_b) + 4 <= @as(u32, @intCast(PTR_LEN));
}

const PTR_MIN: u64 = 0x10000;
const PTR_MAX: u64 = 0x00007FFF_FFFF_0000;

fn plausible(p: u64) bool {
    return p >= PTR_MIN and p < PTR_MAX and (p & 7) == 0;
}

// ---------------------------------------------------------------------------
// Execute routing
// ---------------------------------------------------------------------------

pub fn onExecuteWith(reader: Reader, token: u32, self_ptr: u64, ctx: u64, a3: u64) bool {
    switch (current_mode) {
        .off => return false,
        .capture => {
            _ = captureWith(reader, self_ptr, token, ctx, a3);
            return false;
        },
        .apply => {
            calls += 1;
            if (!spec_set) {
                unresolved += 1;
                return false;
            }
            const id = resolveWith(reader, @bitCast(spec_bits), ctx, a3) orelse {
                unresolved += 1;
                return false;
            };
            resolved += 1;
            last_id = id;

            const rc = C2ExecCallScored(token, id);
            if (rc < 0) {
                if (rc == -2 or rc == -3) js_err += 1;
                return false;
            }
            const idx: usize = @intCast(rc);
            tiers[idx] += 1;
            last_tier = rc;
            if (rc >= 1) {
                chained += 1;
                return true;
            }
            return false;
        },
    }
}

pub fn onExecute(token: u32, self_ptr: u64, ctx: u64, a3: u64) bool {
    return onExecuteWith(active_reader, token, self_ptr, ctx, a3);
}

// ---------------------------------------------------------------------------
// Readback
// ---------------------------------------------------------------------------

pub fn statsInto(out: []u8) bool {
    if (out.len < STATS_SIZE) return false;
    const spec: Spec = if (spec_set) @bitCast(spec_bits) else std.mem.zeroes(Spec);
    const words = [20]u32{
        @intFromEnum(current_mode),
        total_records,
        dropped,
        calls,
        resolved,
        unresolved,
        tiers[0],
        tiers[1],
        tiers[2],
        js_err,
        chained,
        last_id,
        @bitCast(last_tier),
        armed_token,
        spec.blob,
        spec.deref,
        spec.off_a,
        spec.off_b,
        0,
        0,
    };
    for (words, 0..) |w, i| {
        std.mem.writeInt(u32, out[i * 4 ..][0..4], w, .little);
    }
    return true;
}

pub fn drainInto(out: []u8) u32 {
    const n = ring_count;
    if (out.len < n * RECORD_SIZE) return 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        @memcpy(out[i * RECORD_SIZE ..][0..RECORD_SIZE], std.mem.asBytes(&ring[i]));
    }
    ring_count = 0;
    return @intCast(n);
}

pub fn layoutInto(out: *[8]u32) u32 {
    out.* = .{
        LAYOUT_VERSION,
        @intFromEnum(current_mode),
        @intCast(RECORD_SIZE),
        @intCast(RING_CAP),
        @intCast(CTX_LEN),
        @intCast(A3_LEN),
        @intCast(PTR_SLOTS),
        @intCast(PTR_LEN),
    };
    return 8;
}
