// exec_caller_probe.zig — 第八把 guard:谁在逐系统派发子效果(§90.4 定的锚)。
//
// 这一发问的是什么(C5 缺的那一格):
//   * `log` 效果的实现 `0x185BF60` 每次被调时,**返回地址**落在哪个函数里(= 谁在派发);
//   * 它的第二实参若是 scope(§80.2 的形状:`+0x08` mask、`+0x10` id),
//     那批 id 去重后是多少、是否 ⊆ 银河容器的 id 集、是否落在 `[1,N]`。
//
// 为什么是这个入口:§89.3 的实机读数证明它**每月跑 784 次**(12,544 = 16×784),
// 而 §90.1 证明 `+0x70` 那一族在那 16 个月里整族沉默。它是目前唯一确凿在**执行侧**的锚。
//
// 只读:detour 恒转发原函数,不写引擎内存、不重指向 `[self]`、不改寄存器。

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const windows = @import("../hooking/windows.zig");
const detour_mod = @import("../hooking/detour.zig");
const predicate_hook = @import("predicate_hook.zig");

const is_windows = builtin.os.tag == .windows;

/// §90.4:`log` 效果的实现入口(`effect_impl.cpp:21978` = `0x55DA` 唯一出现于 `0x185C454`)。
pub const RVA_TARGET: usize = offsets.keyword_reg.RVA_LOG_EFFECT_EXEC;

pub const RING_LEN: usize = 2048;
pub const DISTINCT_SLOTS: usize = 4096;
pub const LAYOUT_VERSION: u32 = 1;

/// §80.2 的 scope 形状。只在第二实参真的可读时才取;读不到记 `null_scope`。
pub const SCOPE_MASK_OFF: usize = 0x08;
pub const SCOPE_ID_OFF: usize = 0x10;

/// 32 B off the exe copy:入口前 15 B 就是补丁窗口(三条 `mov [rsp+..], reg`)。
pub const EXPECTED_CODE: [32]u8 = [32]u8{
    0x48, 0x89, 0x5C, 0x24, 0x10, // mov [rsp+0x10], rbx
    0x48, 0x89, 0x74, 0x24, 0x18, // mov [rsp+0x18], rsi
    0x48, 0x89, 0x7C, 0x24, 0x20, // mov [rsp+0x20], rdi
    0x55, // push rbp
    0x41, 0x56, // push r14
    0x41, 0x57, // push r15
    0x48, 0x8D, 0xAC, 0x24, 0xB0, 0xF3, 0xFF, 0xFF, // lea rbp, [rsp-0xCD0]
    0x48, 0x81, 0xEC, 0x50, // sub rsp, …
};

/// 32 B. 驱动侧列序 = 字段序。
pub const Entry = extern struct {
    caller_rva: u32 = 0, // `@returnAddress()` 落在镜像里时的 RVA;0 = 我们认不出来
    id: u32 = 0, // `[scope+0x10]`
    mask: u32 = 0, // `[scope+0x08]`
    occurrences: u32 = 0,
    self_ptr: u64 = 0,
    scope_ptr: u64 = 0,
};

pub const Stats = extern struct {
    calls: u64 = 0,
    distinct_ids: u64 = 0,
    dedupe_full: u64 = 0, // 去重表满后没记上的次数(distinct_ids 于是只是下界)
    null_scope: u64 = 0, // 第二实参空 / 不可读
    patch_size: u64 = 0,
    last_id: u32 = 0,
    pad0: u32 = 0,
};

comptime {
    if (@sizeOf(Entry) != 32) @compileError("exec-caller Entry must be 32 bytes");
    if (@sizeOf(Stats) != 48) @compileError("exec-caller Stats must be 48 bytes");
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

/// Open-addressed set of 4 B ids with linear probing. Pure data + pure methods.
pub const IdTable = struct {
    pub const SLOTS: usize = DISTINCT_SLOTS;
    pub const NO_ROW: u16 = 0xFFFF;

    keys: [SLOTS]u32 = undefined,
    rows: [SLOTS]u16 = undefined,
    used: [SLOTS]bool = [_]bool{false} ** SLOTS,
    count: usize = 0,

    fn slot(key: u32) usize {
        const h = @as(u64, key) *% 0x9E3779B97F4A7C15;
        return @intCast(h >> 52); // top 12 bits -> 4096 slots
    }

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
        .distinct_ids = @atomicLoad(u64, &stats.distinct_ids, .monotonic),
        .dedupe_full = @atomicLoad(u64, &stats.dedupe_full, .monotonic),
        .null_scope = @atomicLoad(u64, &stats.null_scope, .monotonic),
        .last_id = @atomicLoad(u32, &stats.last_id, .monotonic),
        .samples = rows,
    };
}

/// Pure bookkeeping: counters + ring. The host tests drive this directly.
pub fn recordDispatch(caller_rva: u32, id: u32, mask: u32, self_ptr: u64, scope: u64) void {
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
                    .caller_rva = caller_rva,
                    .id = id,
                    .mask = mask,
                    .occurrences = 1,
                    .self_ptr = self_ptr,
                    .scope_ptr = scope,
                };
            }
        },
    }
}

/// Diagnostic switch (§91.2). 0 = count only (no reads, no ring, no lock); 1 = count + the
/// two engine reads, still no ring/lock; 2 = full.  It exists because "the hook kills the
/// game" and "the recording path kills the game" look identical from outside (the process
/// disappears, no WER entry), and a count-only build survived where the full one died.
/// Ship with 2.
const RECORD_MODE: u8 = 2;

/// One call to the target: count it, resolve the caller RVA, then read the second argument's
/// two scope cells when it is a readable pointer. Unreadable degrades to `null_scope`.
pub fn recordCall(caller: usize, self: usize, scope: usize) void {
    _ = @atomicRmw(u64, &stats.calls, .Add, 1, .monotonic);
    if (RECORD_MODE == 0) return;
    const caller_rva = if (RECORD_MODE == 1) 0 else toRva(caller);
    if (RECORD_MODE == 1) {
        // Reads only: still no ring, no dedupe table, no spinlock.
        if (!plausible(scope) or readU64(scope) == null) {
            _ = @atomicRmw(u64, &stats.null_scope, .Add, 1, .monotonic);
            return;
        }
        @atomicStore(u32, &stats.last_id, readU32(scope, SCOPE_ID_OFF), .monotonic);
        return;
    }
    if (!plausible(scope)) {
        _ = @atomicRmw(u64, &stats.null_scope, .Add, 1, .monotonic);
        recordDispatch(caller_rva, 0, 0, @intCast(self), 0);
        return;
    }
    if (readU64(scope) == null) {
        _ = @atomicRmw(u64, &stats.null_scope, .Add, 1, .monotonic);
        recordDispatch(caller_rva, 0, 0, @intCast(self), @intCast(scope));
        return;
    }
    const id = readU32(scope, SCOPE_ID_OFF);
    const mask = readU32(scope, SCOPE_MASK_OFF);
    recordDispatch(caller_rva, id, mask, @intCast(self), @intCast(scope));
}

// ---------------------------------------------------------------------------
// Injector-facing readouts
// ---------------------------------------------------------------------------

/// Six layout words: [version, Entry size, RING_LEN, Stats size, target RVA, 0].
/// 第六格留 0:这一发没有 vtable 过滤器(和兄弟 guard 的区别,驱动会核它)。
pub fn layoutInto(out: *[6]u32) u32 {
    out.* = .{
        LAYOUT_VERSION,
        @intCast(@sizeOf(Entry)),
        @intCast(RING_LEN),
        @intCast(@sizeOf(Stats)),
        @intCast(RVA_TARGET),
        0,
    };
    return 6;
}

/// One line, fixed key order — the driver's `STATS_KEYS` parses it.
pub fn statsInto(out: []u8) usize {
    const written = std.fmt.bufPrint(
        out,
        "calls={d} distinct_ids={d} dedupe_full={d} null_scope={d} patch_size={d} installed={d} verify={d} last_id={d}\n",
        .{
            @atomicLoad(u64, &stats.calls, .monotonic),
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

/// Clear counters + ring + table + drain capacity. Does not uninstall a hook and does not
/// clear the image window (that is a property of the module, not of the counters).
pub fn reset() void {
    lockRec();
    defer unlockRec();
    @atomicStore(u64, &stats.calls, 0, .monotonic);
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

var installed = false;
var hook: ?detour_mod.Hook = null;
var orig: ?*anyopaque = null;
var target_addr: usize = 0;
var saved_code: [32]u8 = [_]u8{0} ** 32;

pub fn preflightChecks(already_installed: bool, patch_active: bool) InstallError!void {
    if (already_installed) return error.AlreadyInstalled;
    if (patch_active) return error.PatchActive;
}

pub const OrigFn = *const fn (u64, u64, u64) callconv(.c) u64;

fn dispatchDetour(self: u64, scope: u64, a3: u64) callconv(.c) u64 {
    // The hook is entered by `jmp [rip+0]` (detour.zig), so the top of the stack is still the
    // engine's return address: `@returnAddress()` is the dispatch site, not our trampoline.
    recordCall(@returnAddress(), @intCast(self), @intCast(scope));
    const f: OrigFn = @ptrCast(orig orelse return 0);
    // `.always_tail` is load-bearing, not a micro-optimisation (§91.1).  `detour.zig` builds
    // the trampoline by copying the target's prologue **verbatim** and appending a `jmp` back,
    // so the copied bytes see whatever `rsp` the caller of the trampoline left.  A plain `call`
    // puts `rsp` 8 bytes lower than the engine's own call did, and this target's prologue is
    // three `mov [rsp+0x10/0x18/0x20], reg` saves: shifted by 8 they restore `rbx`/`rsi`/`rdi`
    // from the wrong slots, which corrupts three callee-saved registers per call and kills the
    // game a few thousand dispatches later (2026-11-01: 3/3 shots died mid-burst).
    // A tail jump keeps `rsp` exactly as the engine left it, so the copied saves land where the
    // epilogue looks for them.  `.always_tail` makes the requirement a compile error rather
    // than a codegen coincidence.
    return @call(.always_tail, f, .{ self, scope, a3 });
}

pub fn install() InstallError!void {
    if (!is_windows) return error.Unsupported;
    try preflightChecks(installed, predicate_hook.isInstalled() or predicate_hook.objectsWerePatched());

    const target = windows.moduleFunction(RVA_TARGET) catch return error.ModuleNotFound;
    if (detour_mod.isHooked(target)) return error.AlreadyHooked;

    target_addr = @intFromPtr(target);

    const tb: [*]const u8 = @ptrCast(target);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return error.UnexpectedPrologue;
    }
    @memcpy(&saved_code, tb[0..saved_code.len]);

    const base = @intFromPtr(target) - RVA_TARGET;
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
    std.log.info("c2.exec_caller_probe: installed detour at 0x{x}", .{RVA_TARGET});
}

/// Copy our own snapshot of the prologue back (same discipline as the sibling guards).
fn restoreTarget(len: usize) !void {
    var guard = try windows.ProtectGuard.change(@ptrFromInt(target_addr), len, .execute_readwrite);
    defer guard.deinit();
    const dst: [*]u8 = @ptrFromInt(target_addr);
    @memcpy(dst[0..len], saved_code[0..len]);
    windows.flushInstructionCache(@ptrFromInt(target_addr), len);
}

pub fn uninstall() !void {
    if (!installed) return;
    const h = hook orelse return;
    detour_mod.removeHook(&h) catch {};
    hook = null;
    installed = false;
    try restoreTarget(h.patch_size);
    orig = null; // only once the engine bytes are ours again
    if (!fingerprintMatches()) return error.RestoreIncomplete;
    std.log.info("c2.exec_caller_probe: uninstalled detour", .{});
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
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(Entry, "caller_rva"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(Entry, "id"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(Entry, "mask"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(Entry, "self_ptr"));
    try std.testing.expectEqual(@as(usize, 24), @offsetOf(Entry, "scope_ptr"));
}

test "Stats is 48 bytes" {
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(Stats));
}

test "layoutInto reports six words with the §90.4 target and no vtable filter" {
    var words: [6]u32 = undefined;
    try std.testing.expectEqual(@as(u32, 6), layoutInto(&words));
    try std.testing.expectEqual(@as(u32, 1), words[0]);
    try std.testing.expectEqual(@as(u32, 32), words[1]);
    try std.testing.expectEqual(@as(u32, RING_LEN), words[2]);
    try std.testing.expectEqual(@as(u32, 48), words[3]);
    try std.testing.expectEqual(@as(u32, 0x185BF60), words[4]);
    try std.testing.expectEqual(@as(u32, 0), words[5]);
}

test "EXPECTED_CODE pins the 15-byte patch window" {
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20 },
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

test "one row per distinct id, occurrences counted on the same row" {
    resetForTest();
    recordDispatch(0x1D08520, 42, 0x80, 0xABC, 0x1000);
    recordDispatch(0x1D08520, 42, 0x80, 0xABC, 0x1000);
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 1), s.distinct_ids);
    try std.testing.expectEqual(@as(u32, 1), s.samples);

    setDrainCap(@sizeOf(Entry));
    var buf: [@sizeOf(Entry)]u8 align(8) = undefined;
    try std.testing.expectEqual(@as(u32, 1), drainInto(&buf));
    const row: *Entry = @ptrCast(@alignCast(&buf));
    try std.testing.expectEqual(@as(u32, 0x1D08520), row.caller_rva);
    try std.testing.expectEqual(@as(u32, 2), row.occurrences);
    try std.testing.expectEqual(@as(u32, 42), row.id);
    try std.testing.expectEqual(@as(u32, 0x80), row.mask);
    try std.testing.expectEqual(@as(u64, 0x1000), row.scope_ptr);
}

test "the ring keeps the first RING_LEN distinct ids and never grows" {
    resetForTest();
    var i: u32 = 0;
    while (i < RING_LEN + 4) : (i += 1) recordDispatch(0x1D08520, 1 + i, 0x80, 0, 0x1000);
    const s = snapshot();
    try std.testing.expectEqual(@as(u32, RING_LEN), s.samples);
    try std.testing.expectEqual(@as(u64, RING_LEN + 4), s.distinct_ids);
}

test "statsInto writes one k=v line with all eight keys" {
    resetForTest();
    var buf: [512]u8 = undefined;
    const n = statsInto(&buf);
    const expected = "calls=0 distinct_ids=0 dedupe_full=0 null_scope=0 " ++
        "patch_size=0 installed=0 verify=-3 last_id=0\n";
    try std.testing.expectEqualStrings(expected, buf[0..n]);
}

test "reset keeps the image window" {
    resetForTest();
    setImageBounds(0x140000000, 0x140000000 + 0x400_0000);
    reset();
    try std.testing.expectEqual(@as(u32, 0x185BF60), toRva(0x140000000 + 0x185BF60));
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
