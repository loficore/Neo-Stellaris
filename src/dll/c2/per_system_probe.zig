// per_system_probe.zig — C5 数据面第三发:逐系统下发点 `0x3B1330` 的只读 guard(§81.1)。
//
// 这一发问的是什么(§80.4 hand-off 的三项读数):
//   * `every_system` 的循环在战役里**下发几次**(`matched`,按 `[self]` 的 vtable 过滤);
//   * 每次发送 = 一轮,所以「每轮次数 = matched / script_sends」;
//   * 下发带过去的那一格 id(`[scope+0x10]`)去重后有几种、是否两两不同。
//
// 靶 = base effect parse `0x3B1330`(所有 effect 类共用),过滤器 = `[self]` 等于
// `every_system` 的 vtable `0x26562D0`(§81.1 ②)。为什么是函数入口而不是循环头
// `0x1A762A0`:见取证卷 §81.1 ⑤ —— 循环体内部读写 `[rsp+…]` 与 `[rbp+0xC0]`,
// 而 C-ABI detour 让被调函数体跑在 detour 的帧上。
//
// 只读:detour 恒转发原函数,不写引擎内存、不重指向 `[self]`、不改寄存器。

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const windows = @import("../hooking/windows.zig");
const detour_mod = @import("../hooking/detour.zig");
const predicate_hook = @import("predicate_hook.zig");

const is_windows = builtin.os.tag == .windows;

/// §81.1 ③:循环体每轮 `mov rcx,r14 ; call 0x3B1330`。
pub const RVA_DISPATCH: usize = offsets.keyword_reg.RVA_EFFECT_BASE_PARSE;

/// §81.1 ②:`every_system` create 写出的 vtable。
pub const RVA_EVERY_SYSTEM_VTABLE: usize = offsets.keyword_reg.RVA_EVERY_SYSTEM_VTABLE;

pub const RING_LEN: usize = 2048;
pub const DISTINCT_SLOTS: usize = 4096;
pub const LAYOUT_VERSION: u32 = 1;

/// §80.2 的 scope 结构:`+0x08` mask(0x80)、`+0x10` id(4 B)、`+0x14` 对象指针。
pub const SCOPE_MASK_OFF: usize = 0x08;
pub const SCOPE_ID_OFF: usize = 0x10;
pub const SCOPE_OBJ_OFF: usize = 0x14;

/// 32 B off the exe copy(§81.1 ①)。前 15 B 就是补丁窗口。
pub const EXPECTED_CODE: [32]u8 = [32]u8{
    0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+0x8], rbx
    0x48, 0x89, 0x6C, 0x24, 0x10, // mov [rsp+0x10], rbp
    0x48, 0x89, 0x74, 0x24, 0x18, // mov [rsp+0x18], rsi
    0x57, // push rdi
    0x48, 0x83, 0xEC, 0x70, // sub rsp, 0x70
    0x49, 0x8B, 0xF8, // mov rdi, r8
    0x48, 0x8B, 0xEA, // mov rbp, rdx
    0x48, 0x8B, 0xF1, // mov rsi, rcx
    0x48, 0x8B, 0x01, // mov rax, [rcx]
};

/// 32 B. 驱动侧列序 = 字段序。
pub const Entry = extern struct {
    id: u32 = 0,
    mask: u32 = 0,
    self_vtable_rva: u32 = 0,
    occurrences: u32 = 0,
    obj: u64 = 0,
    scope_ptr: u64 = 0,
};

pub const Stats = extern struct {
    calls: u64 = 0, // 每 0x3B1330 调用,含未命中过滤器的
    matched: u64 = 0, // [self] == every_system vtable
    distinct_ids: u64 = 0, // 去重后的 id 个数(dedupe_full > 0 时是下界)
    dedupe_full: u64 = 0, // 表满后没记上的 distinct id 次数
    null_scope: u64 = 0, // scope 空 / 不可读
    patch_size: u64 = 0,
    last_id: u32 = 0,
    pad0: u32 = 0,
};

comptime {
    if (@sizeOf(Entry) != 32) @compileError("per-system Entry must be 32 bytes");
    if (@sizeOf(Stats) != 56) @compileError("per-system Stats must be 56 bytes");
}

// ---------------------------------------------------------------------------
// Image window + memory reads
// ---------------------------------------------------------------------------

var img_base: usize = 0;
var img_end: usize = 0;

pub fn setImageBounds(base: usize, end: usize) void {
    img_base = base;
    img_end = end;
}

/// Module-relative address of `abs`, or 0 when `abs` is outside the game image.
pub fn toRva(abs: usize) u32 {
    if (abs < img_base or abs >= img_end) return 0;
    const rva = abs - img_base;
    if (rva > std.math.maxInt(u32)) return 0;
    return @intCast(rva);
}

/// Same three-part gate as the sibling guards: every engine-memory read goes through it.
pub fn plausible(p: usize) bool {
    return p >= 0x10000 and p <= 0x00007FFF_FFFF_0000 and (p & 7) == 0;
}

fn readU64(addr: usize) ?u64 {
    if (!plausible(addr)) return null;
    if (!windows.isCommitted(addr)) return null;
    return @as(*align(8) const u64, @ptrFromInt(addr)).*;
}

fn readU32(addr: usize, comptime off: usize) u32 {
    if (!plausible(addr) or !windows.isCommitted(addr)) return 0;
    const base: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u32, base[off..][0..4], .little);
}

// ---------------------------------------------------------------------------
// The id dedupe table (pure, host-testable)
// ---------------------------------------------------------------------------

pub const InsertResult = enum { new, seen, full };

/// Open-addressed set of 4 B ids with linear probing. Pure data + pure methods: the host
/// tests drive it directly, no engine memory involved.
pub const IdTable = struct {
    pub const SLOTS: usize = DISTINCT_SLOTS;
    /// The row an id lives in, or `NO_ROW` when the id was never written to the ring.
    pub const NO_ROW: u16 = 0xFFFF;

    keys: [SLOTS]u32 = undefined,
    rows: [SLOTS]u16 = undefined,
    used: [SLOTS]bool = [_]bool{false} ** SLOTS,
    count: usize = 0,

    fn slot(key: u32) usize {
        const h = @as(u64, key) *% 0x9E3779B97F4A7C15;
        return @intCast(h >> 52); // top 12 bits -> 4096 slots
    }

    /// `new` = not seen before; `seen` = known (even when the table is full); `full` =
    /// full **and** unknown.
    pub fn insert(self: *IdTable, key: u32, row: u16) InsertResult {
        var idx = slot(key);
        var probes: usize = 0;
        while (probes < SLOTS) : (probes += 1) {
            if (!self.used[idx]) {
                if (self.count == SLOTS) return .full;
                self.used[idx] = true;
                self.keys[idx] = key;
                self.rows[idx] = row;
                self.count += 1;
                return .new;
            }
            if (self.keys[idx] == key) return .seen;
            idx = (idx + 1) % SLOTS;
        }
        return .full;
    }

    /// The ring row of `key`, if it is in the table (O(1) on average).
    pub fn rowOf(self: *const IdTable, key: u32) ?u16 {
        var idx = slot(key);
        var probes: usize = 0;
        while (probes < SLOTS) : (probes += 1) {
            if (!self.used[idx]) return null;
            if (self.keys[idx] == key) {
                const row = self.rows[idx];
                return if (row == NO_ROW) null else row;
            }
            idx = (idx + 1) % SLOTS;
        }
        return null;
    }

    pub fn len(self: *const IdTable) usize {
        return self.count;
    }
};

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

var ring: [RING_LEN]Entry = undefined;
var stats = Stats{};
var ids = IdTable{};

/// Rows are appended in first-seen order; the table slot of an id is not its row index.
var row_count: usize = 0;

/// The recording path is taken on engine threads: table + ring under one module-private
/// spinlock (the `detour.zig` shape — `std.Io.Mutex` needs an Io context hook code has not).
var rec_lock: u32 = 0;

fn lockRec() void {
    while (@atomicRmw(u32, &rec_lock, .Xchg, 1, .acquire) != 0) {}
}

fn unlockRec() void {
    _ = @atomicRmw(u32, &rec_lock, .Xchg, 0, .release);
}

pub const Snapshot = struct {
    calls: u64,
    matched: u64,
    distinct_ids: u64,
    dedupe_full: u64,
    null_scope: u64,
    last_id: u32,
    samples: u32,
};

pub fn snapshot() Snapshot {
    lockRec();
    const rows: u32 = @intCast(@min(row_count, RING_LEN));
    unlockRec();
    return .{
        .calls = @atomicLoad(u64, &stats.calls, .monotonic),
        .matched = @atomicLoad(u64, &stats.matched, .monotonic),
        .distinct_ids = @atomicLoad(u64, &stats.distinct_ids, .monotonic),
        .dedupe_full = @atomicLoad(u64, &stats.dedupe_full, .monotonic),
        .null_scope = @atomicLoad(u64, &stats.null_scope, .monotonic),
        .last_id = @atomicLoad(u32, &stats.last_id, .monotonic),
        .samples = rows,
    };
}

/// Pure bookkeeping: the filter, the counters and the ring. The host tests drive this
/// directly — the reads that feed it are `recordCall`'s job.
pub fn recordDispatch(self_vtable_rva: u32, id: u32, mask: u32, obj: u64, scope: u64) void {
    if (self_vtable_rva != RVA_EVERY_SYSTEM_VTABLE) return;
    _ = @atomicRmw(u64, &stats.matched, .Add, 1, .monotonic);
    @atomicStore(u32, &stats.last_id, id, .monotonic);

    lockRec();
    defer unlockRec();

    const row: u16 = if (row_count < RING_LEN) @as(u16, @intCast(row_count)) else IdTable.NO_ROW;
    switch (ids.insert(id, row)) {
        .seen => {
            if (ids.rowOf(id)) |r| {
                if (r < RING_LEN) ring[r].occurrences += 1;
            }
        },
        .full => {
            _ = @atomicRmw(u64, &stats.dedupe_full, .Add, 1, .monotonic);
        },
        .new => {
            _ = @atomicRmw(u64, &stats.distinct_ids, .Add, 1, .monotonic);
            if (row < RING_LEN) {
                row_count += 1;
                ring[row] = .{
                    .id = id,
                    .mask = mask,
                    .self_vtable_rva = self_vtable_rva,
                    .occurrences = 1,
                    .obj = obj,
                    .scope_ptr = scope,
                };
            }
        },
    }
}

/// One call to `0x3B1330`: count it, then read `[self]` and — only when the vtable matches —
/// the three scope cells. An uncommitted scope degrades to `null_scope` instead of a fault.
pub fn recordCall(self: usize, scope: usize) void {
    _ = @atomicRmw(u64, &stats.calls, .Add, 1, .monotonic);
    if (!plausible(self)) return;
    const vt = readU64(self) orelse return;
    const vt_rva = toRva(@intCast(vt));
    if (vt_rva != RVA_EVERY_SYSTEM_VTABLE) return;
    if (!plausible(scope)) {
        _ = @atomicRmw(u64, &stats.null_scope, .Add, 1, .monotonic);
        return;
    }
    const id = readU32(scope, SCOPE_ID_OFF);
    const mask = readU32(scope, SCOPE_MASK_OFF);
    const obj = readU64(scope + SCOPE_OBJ_OFF) orelse 0;
    recordDispatch(vt_rva, id, mask, obj, scope);
}

// ---------------------------------------------------------------------------
// Injector-facing readouts
// ---------------------------------------------------------------------------

/// Six layout words: [version, Entry size, RING_LEN, Stats size, target RVA, vtable RVA].
pub fn layoutInto(out: *[6]u32) u32 {
    out.* = .{
        LAYOUT_VERSION,
        @intCast(@sizeOf(Entry)),
        @intCast(RING_LEN),
        @intCast(@sizeOf(Stats)),
        @intCast(RVA_DISPATCH),
        @intCast(RVA_EVERY_SYSTEM_VTABLE),
    };
    return 6;
}

/// One line, fixed key order — the driver's `STATS_KEYS` parses it.
pub fn statsInto(out: []u8) usize {
    const written = std.fmt.bufPrint(
        out,
        "calls={d} matched={d} distinct_ids={d} dedupe_full={d} null_scope={d} patch_size={d} installed={d} verify={d} last_id={d}\n",
        .{
            @atomicLoad(u64, &stats.calls, .monotonic),
            @atomicLoad(u64, &stats.matched, .monotonic),
            @atomicLoad(u64, &stats.distinct_ids, .monotonic),
            @atomicLoad(u64, &stats.dedupe_full, .monotonic),
            @atomicLoad(u64, &stats.null_scope, .monotonic),
            stats.patch_size,
            @intFromBool(installed),
            verify(),
            @atomicLoad(u32, &stats.last_id, .monotonic),
        },
    ) catch return 0;
    return written.len;
}

/// Declared by the caller before `drainInto`: `call_remote_with_arg` can only pass one
/// register, so the capacity is a setter, not a second argument. Zero means "not declared".
var drain_cap: usize = 0;

pub fn setDrainCap(bytes: usize) void {
    drain_cap = bytes;
}

pub fn drainInto(out: [*]u8) u32 {
    const capacity = @min(drain_cap / @sizeOf(Entry), RING_LEN);
    if (capacity == 0) return 0;
    const dst: [*]Entry = @ptrCast(@alignCast(out));
    lockRec();
    defer unlockRec();
    var copied: u32 = 0;
    while (copied < capacity and copied < row_count) : (copied += 1) {
        dst[copied] = ring[copied];
    }
    return copied;
}

/// Clear counters + ring + table + drain capacity. Does not uninstall a hook (clearing
/// `calls` under a live patch would silently reset the frequency denominator), and does not
/// clear the image window (that is a property of the module, not of the counters).
pub fn reset() void {
    lockRec();
    defer unlockRec();
    @atomicStore(u64, &stats.calls, 0, .monotonic);
    @atomicStore(u64, &stats.matched, 0, .monotonic);
    @atomicStore(u64, &stats.distinct_ids, 0, .monotonic);
    @atomicStore(u64, &stats.dedupe_full, 0, .monotonic);
    @atomicStore(u64, &stats.null_scope, 0, .monotonic);
    @atomicStore(u64, &stats.patch_size, 0, .monotonic);
    @atomicStore(u32, &stats.last_id, 0, .monotonic);
    ids = IdTable{};
    row_count = 0;
    @memset(std.mem.asBytes(&ring), 0);
    drain_cap = 0;
}

pub fn resetForTest() void {
    reset();
    installed = false;
    target_addr = 0;
}

// ---------------------------------------------------------------------------
// Assembly: fingerprint gate + install / uninstall / verify
// (shape copied from trigger_eval_probe.zig — same family prologue gate, saved_code
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

/// Guard state is private to this module — same discipline as the other six guards.
var installed = false;
var hook: ?detour_mod.Hook = null;
var orig: ?*anyopaque = null;
var target_addr: usize = 0;
var saved_code: [32]u8 = [_]u8{0} ** 32;

/// Two refusals before installing: this guard is already in, or the predicate detour is
/// armed. With the predicate armed `[self+0]` may point at our own DLL's vtable copy, and a
/// self-vtable read in that state is not an engine reading.
pub fn preflightChecks(already_installed: bool, patch_active: bool) InstallError!void {
    if (already_installed) return error.AlreadyInstalled;
    if (patch_active) return error.PatchActive;
}

pub const OrigFn = *const fn (u64, u64, u64) callconv(.c) u64;

/// `0x3B1330` takes `(self, scope, a3)`. The one call site we read statically
/// (`0x1A76324`) discards the result, so forwarding the raw `rax` is the safe choice.
fn dispatchDetour(self: u64, scope: u64, a3: u64) callconv(.c) u64 {
    recordCall(@intCast(self), @intCast(scope));
    const f: OrigFn = @ptrCast(orig orelse return 0);
    return f(self, scope, a3);
}

pub fn install() InstallError!void {
    if (!is_windows) return error.Unsupported;
    // `objectsWerePatched()` is sticky: the predicate detour's uninstall restores the
    // target's prologue but never undoes its object writes.
    try preflightChecks(installed, predicate_hook.isInstalled() or predicate_hook.objectsWerePatched());

    const target = windows.moduleFunction(RVA_DISPATCH) catch return error.ModuleNotFound;
    if (detour_mod.isHooked(target)) return error.AlreadyHooked;

    target_addr = @intFromPtr(target);

    const tb: [*]const u8 = @ptrCast(target);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return error.UnexpectedPrologue;
    }
    @memcpy(&saved_code, tb[0..saved_code.len]);

    const base = @intFromPtr(target) - RVA_DISPATCH;
    setImageBounds(base, base + 0x400_0000);

    const h = detour_mod.installHookArmed(target, @ptrCast(@constCast(&dispatchDetour)), &orig) catch
        return error.DetourUnavailable;
    if (h.patch_size > saved_code.len) {
        detour_mod.removeHook(&h) catch {};
        restoreTarget(h.patch_size) catch {};
        orig = null;
        return error.PatchTooWide;
    }
    hook = h;
    installed = true;
    stats.patch_size = h.patch_size;
    std.log.info("c2.per_system_probe: installed detour at 0x{x}", .{RVA_DISPATCH});
}

/// Copy our own snapshot of the prologue back. The authoritative restore: it does not depend
/// on `removeHook` reading a trampoline that is still intact (that memory is retired).
fn restoreTarget(len: usize) !void {
    var guard = try windows.ProtectGuard.change(@ptrFromInt(target_addr), len, .execute_readwrite);
    defer guard.deinit();
    const dst: [*]u8 = @ptrFromInt(target_addr);
    @memcpy(dst[0..len], saved_code[0..len]);
    windows.flushInstructionCache(@ptrFromInt(target_addr), len);
}

/// A no-op when not installed — the driver still calls it after a failed install.
pub fn uninstall() !void {
    if (!installed) return;
    const h = hook orelse return;
    detour_mod.removeHook(&h) catch {};
    hook = null;
    installed = false;
    try restoreTarget(h.patch_size);
    orig = null; // only once the engine bytes are ours again
    if (!fingerprintMatches()) return error.RestoreIncomplete;
    std.log.info("c2.per_system_probe: uninstalled detour", .{});
}

fn fingerprintMatches() bool {
    if (target_addr == 0) return false;
    const tb: [*]const u8 = @ptrFromInt(target_addr);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return false;
    }
    return true;
}

/// 0 = consistent. Installed: the hook must still be in the detour table. Not installed: we
/// resolved the target this session and the engine bytes are intact.
/// -1 hook lost | -2 bytes differ | -3 the target was never resolved this session.
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
// Tests
// ---------------------------------------------------------------------------

test "Entry is 32 bytes with the driver's column order" {
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(Entry));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(Entry, "id"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(Entry, "self_vtable_rva"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(Entry, "obj"));
    try std.testing.expectEqual(@as(usize, 24), @offsetOf(Entry, "scope_ptr"));
}

test "Stats is 56 bytes" {
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(Stats));
}

test "layoutInto reports six words with the §81.1 target and vtable" {
    var words: [6]u32 = undefined;
    try std.testing.expectEqual(@as(u32, 6), layoutInto(&words));
    try std.testing.expectEqual(@as(u32, 1), words[0]);
    try std.testing.expectEqual(@as(u32, 32), words[1]);
    try std.testing.expectEqual(@as(u32, RING_LEN), words[2]);
    try std.testing.expectEqual(@as(u32, 56), words[3]);
    try std.testing.expectEqual(@as(u32, 0x3B1330), words[4]);
    try std.testing.expectEqual(@as(u32, 0x26562D0), words[5]);
}

test "EXPECTED_CODE pins the 15-byte patch window" {
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18 },
        EXPECTED_CODE[0..15],
    );
}

test "IdTable reports new, seen, and full" {
    var table = IdTable{};
    try std.testing.expectEqual(InsertResult.new, table.insert(7, 0));
    try std.testing.expectEqual(InsertResult.seen, table.insert(7, 1));
    var i: usize = 0;
    while (i < DISTINCT_SLOTS) : (i += 1) _ = table.insert(@intCast(1000 + i), 2);
    try std.testing.expectEqual(InsertResult.full, table.insert(999_999, 3));
}

test "IdTable counts every distinct id exactly once" {
    var table = IdTable{};
    _ = table.insert(1, 0);
    _ = table.insert(2, 1);
    _ = table.insert(1, 2);
    _ = table.insert(3, 3);
    try std.testing.expectEqual(@as(usize, 3), table.len());
}

test "a matching dispatch records one row per distinct id" {
    resetForTest();
    recordDispatch(0x26562D0, 42, 0x80, 0, 0x1000);
    recordDispatch(0x26562D0, 42, 0x80, 0, 0x1000);
    recordDispatch(0x26562D0, 42, 0x80, 0, 0x1000);
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 3), s.matched);
    try std.testing.expectEqual(@as(u64, 1), s.distinct_ids);
    try std.testing.expectEqual(@as(u32, 1), s.samples);

    setDrainCap(@sizeOf(Entry));
    var buf: [@sizeOf(Entry)]u8 align(8) = undefined;
    try std.testing.expectEqual(@as(u32, 1), drainInto(&buf));
    const row: *Entry = @ptrCast(@alignCast(&buf));
    try std.testing.expectEqual(@as(u32, 3), row.occurrences);
    try std.testing.expectEqual(@as(u32, 42), row.id);
    try std.testing.expectEqual(@as(u32, 0x80), row.mask);
    try std.testing.expectEqual(@as(u64, 0x1000), row.scope_ptr);
}

test "a non-matching vtable is counted in calls but records nothing" {
    resetForTest();
    recordDispatch(0x26562D0 + 0x10, 42, 0x80, 0, 0x1000);
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 0), s.calls); // recordDispatch never touches calls
    try std.testing.expectEqual(@as(u64, 0), s.matched);
    try std.testing.expectEqual(@as(u32, 0), s.samples);
}

test "the ring keeps the first RING_LEN distinct ids and never grows" {
    resetForTest();
    var i: u32 = 0;
    while (i < RING_LEN + 4) : (i += 1) recordDispatch(0x26562D0, 1 + i, 0x80, 0, 0x1000);
    const s = snapshot();
    try std.testing.expectEqual(@as(u32, RING_LEN), s.samples);
    try std.testing.expectEqual(@as(u64, RING_LEN + 4), s.distinct_ids);
}

test "statsInto writes one k=v line with all nine keys" {
    resetForTest();
    var buf: [512]u8 = undefined;
    const n = statsInto(&buf);
    const expected = "calls=0 matched=0 distinct_ids=0 dedupe_full=0 null_scope=0 " ++
        "patch_size=0 installed=0 verify=-3 last_id=0\n";
    try std.testing.expectEqualStrings(expected, buf[0..n]);
}

test "reset keeps the image window" {
    resetForTest();
    setImageBounds(0x140000000, 0x140000000 + 0x400_0000);
    reset();
    try std.testing.expectEqual(@as(u32, 0x3B1330), toRva(0x140000000 + 0x3B1330));
}

test "drain refuses when no capacity was declared" {
    resetForTest();
    var buf: [64]u8 align(8) = undefined;
    try std.testing.expectEqual(@as(u32, 0), drainInto(&buf));
}

test "preflight refuses a second install on the same process" {
    try std.testing.expectError(error.AlreadyInstalled, preflightChecks(true, false));
    try std.testing.expectError(error.PatchActive, preflightChecks(false, true));
}

test "preflight accepts a clean process" {
    try preflightChecks(false, false);
}

test "verify is -3 before the first install" {
    resetForTest();
    try std.testing.expectEqual(@as(i32, -3), verify());
    try std.testing.expect(!isInstalled());
}
