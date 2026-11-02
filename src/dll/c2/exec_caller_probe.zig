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

comptime {
    if (@sizeOf(Entry) != 32) @compileError("exec-caller Entry must be 32 bytes");
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
// Recording — lock-free on purpose (§91.2)
// ---------------------------------------------------------------------------
//
// The 2026-11-01 bisect left exactly one suspect: the old record path (spinlock + dedupe
// table + ring under the lock) killed the game, while count-only and count-plus-reads both
// survived.  This version appends one 32 B record per call under a single atomic index and
// nothing else: no lock, no table, no nested calls on the engine thread.  Duplicate ids are
// folded by the **driver** (Linux side), where a bad fold costs a column, not the process.

var ring: [RING_LEN]Entry = undefined;

/// Monotonic append index. `head > RING_LEN` means the ring overflowed; `stats.dropped`
/// counts those samples so the artifact can say "this reading is truncated".
var head: u64 = 0;

pub const Stats = extern struct {
    calls: u64 = 0,
    dropped: u64 = 0, // samples that arrived after the ring filled (truncation marker)
    null_scope: u64 = 0, // second argument unreadable / not 8-aligned
    patch_size: u64 = 0,
    last_id: u32 = 0,
    last_caller: u32 = 0, // §91.3: single-slot caller capture (ring-free; the ring died 3/3)
};

/// Module-private state. `stats` is written from the engine thread, `head` is the ring index.
var stats = Stats{};

pub const Snapshot = struct {
    calls: u64,
    dropped: u64,
    null_scope: u64,
    last_id: u32,
    samples: u32,
};

pub fn snapshot() Snapshot {
    const h = @atomicLoad(u64, &head, .monotonic);
    return .{
        .calls = @atomicLoad(u64, &stats.calls, .monotonic),
        .dropped = @atomicLoad(u64, &stats.dropped, .monotonic),
        .null_scope = @atomicLoad(u64, &stats.null_scope, .monotonic),
        .last_id = @atomicLoad(u32, &stats.last_id, .monotonic),
        .samples = @intCast(@min(h, RING_LEN)),
    };
}

/// Ring capacity (§91.7).  It was capped at 8 while the crash was blamed on the recorder;
/// the game's own crash report then pinned the fault on the **driver** (`call_remote` without
/// the buffer argument), so the full ring is back.  `RING_CAP < RING_LEN` still works: the
/// recorder closes itself after `RING_CAP` samples.
pub const RING_ENABLED = true;
pub const RING_CAP: usize = RING_LEN;

/// One recorded call. Pure: the host tests drive it directly.
pub fn recordSample(caller_rva: u32, id: u32, mask: u32, self_ptr: u64, scope: u64) void {
    @atomicStore(u32, &stats.last_id, id, .monotonic);
    @atomicStore(u32, &stats.last_caller, caller_rva, .monotonic);
    if (!RING_ENABLED) return;
    // Closed recorder: one atomic load and we are out. Nothing is written after the cap.
    if (@atomicLoad(u64, &head, .monotonic) >= RING_CAP) return;
    const slot = @atomicRmw(u64, &head, .Add, 1, .monotonic);
    if (slot < RING_CAP) {
        ring[@intCast(slot)] = .{
            .caller_rva = caller_rva,
            .id = id,
            .mask = mask,
            .occurrences = 1,
            .self_ptr = self_ptr,
            .scope_ptr = scope,
        };
    } else {
        _ = @atomicRmw(u64, &stats.dropped, .Add, 1, .monotonic);
    }
}

/// One call to the target: count it, resolve the caller RVA, read the second argument's two
/// scope cells when it is a readable pointer, then append one sample. Unreadable degrades to
/// `null_scope` plus a zeroed sample (so the call still shows up in the ring).
pub fn recordCall(caller: usize, self: usize, scope: usize) void {
    _ = @atomicRmw(u64, &stats.calls, .Add, 1, .monotonic);
    const caller_rva = toRva(caller);
    if (!plausible(scope) or readU64(scope) == null) {
        _ = @atomicRmw(u64, &stats.null_scope, .Add, 1, .monotonic);
        recordSample(caller_rva, 0, 0, @intCast(self), @intCast(scope));
        return;
    }
    recordSample(caller_rva, readU32(scope, SCOPE_ID_OFF), readU32(scope, SCOPE_MASK_OFF),
                 @intCast(self), @intCast(scope));
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
        "calls={d} dropped={d} null_scope={d} patch_size={d} installed={d} verify={d} last_id={d} last_caller={d}\n",
        .{
            @atomicLoad(u64, &stats.calls, .monotonic),
            @atomicLoad(u64, &stats.dropped, .monotonic),
            @atomicLoad(u64, &stats.null_scope, .monotonic),
            stats.patch_size,
            @intFromBool(installed),
            verify(),
            @atomicLoad(u32, &stats.last_id, .monotonic),
            @atomicLoad(u32, &stats.last_caller, .monotonic),
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
    const have: usize = @intCast(@min(@atomicLoad(u64, &head, .monotonic), RING_LEN));
    var copied: u32 = 0;
    while (copied < capacity and copied < have) : (copied += 1) {
        dst[copied] = ring[copied];
    }
    return copied;
}

/// Clear counters + ring + table + drain capacity. Does not uninstall a hook and does not
/// clear the image window (that is a property of the module, not of the counters).
pub fn reset() void {
    @atomicStore(u64, &stats.calls, 0, .monotonic);
    @atomicStore(u64, &stats.dropped, 0, .monotonic);
    @atomicStore(u64, &stats.null_scope, 0, .monotonic);
    @atomicStore(u64, &stats.patch_size, 0, .monotonic);
    @atomicStore(u32, &stats.last_id, 0, .monotonic);
    @atomicStore(u32, &stats.last_caller, 0, .monotonic);
    @atomicStore(u64, &head, 0, .monotonic);
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

test "Stats is 40 bytes" {
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(Stats));
}

test "layoutInto reports six words with the §90.4 target and no vtable filter" {
    var words: [6]u32 = undefined;
    try std.testing.expectEqual(@as(u32, 6), layoutInto(&words));
    try std.testing.expectEqual(@as(u32, 1), words[0]);
    try std.testing.expectEqual(@as(u32, 32), words[1]);
    try std.testing.expectEqual(@as(u32, RING_LEN), words[2]);
    try std.testing.expectEqual(@as(u32, 40), words[3]);
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

test "bounded capture records the first RING_CAP calls and then closes" {
    resetForTest();
    var i: u32 = 0;
    while (i < RING_CAP + 4) : (i += 1) recordSample(0x1D08520, 100 + i, 0x80, 0xABC, 0x1000);
    const s = snapshot();
    try std.testing.expectEqual(@as(u32, RING_CAP), s.samples);
    // The closed recorder returns before touching any counter: `dropped` only counts a
    // sample that raced past the cap on another thread, so a single-threaded run leaves 0.
    try std.testing.expectEqual(@as(u64, 0), s.dropped);
    try std.testing.expectEqual(@as(u32, 0x1D08520),
        @atomicLoad(u32, &stats.last_caller, .monotonic));

    setDrainCap(RING_CAP * @sizeOf(Entry));
    var buf: [RING_CAP * @sizeOf(Entry)]u8 align(8) = undefined;
    try std.testing.expectEqual(@as(u32, RING_CAP), drainInto(&buf));
    const first: *Entry = @ptrCast(@alignCast(&buf));
    try std.testing.expectEqual(@as(u32, 0x1D08520), first.caller_rva);
    try std.testing.expectEqual(@as(u32, 100), first.id);
}

test "the recorder stops touching the ring once it is closed" {
    resetForTest();
    var i: u32 = 0;
    while (i < RING_CAP) : (i += 1) recordSample(0x1D08520, 1 + i, 0x80, 0, 0x1000);
    const before = @atomicLoad(u64, &head, .monotonic);
    recordSample(0xDEAD, 999, 0x80, 0, 0x1000);
    try std.testing.expectEqual(before, @atomicLoad(u64, &head, .monotonic));
}

test "statsInto writes one k=v line with all seven keys" {
    resetForTest();
    var buf: [512]u8 = undefined;
    const n = statsInto(&buf);
    const expected = "calls=0 dropped=0 null_scope=0 " ++
        "patch_size=0 installed=0 verify=-3 last_id=0 last_caller=0\n";
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
