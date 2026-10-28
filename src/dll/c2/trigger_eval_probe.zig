// trigger_eval_probe.zig — C5 数据面第二发:触发**求值**槽共用基体 `0x1A91A80` 的只读 guard(§77)。
//
// 这一发问的是什么(§76.6 给的靶,不是「scope 是谁」):
// 一个 trigger 在 `every_system` 的 limit 里被求值时,`[vptr+0x28]` 的共用实现被调**几次**,
// 它拿到的 `ctx` 有**几个不同的值**,以及 `ctx` 上那两格已被代码证实的字段长什么样:
//
//   * `ctx+0x158` —— 类型标签(§77.1 ③:必须是 1 或 0x426,读点在 `0x1A918E0`);
//   * `ctx+0x278` —— 被当对象传给下一层(`lea rdx,[rbx+0x278]`),它的首 qword 若是 vtable,
//     一格读数就给出「那个子对象是什么类型」,不用再猜偏移链(§59/§73 已经问完并判负)。
//
// 三条诚实条款(顶部门,措辞来自 §77.4,不要放宽):
//   ① `distinct_ctx` 是**去重后的 ctx 个数**,不是「系统数」—— 只有当它≈星系数时才能读成
//     「每系统一个 ctx」;相等与否由驱动按当次存档的分母判。
//   ② `dedupe_full != 0` 时 `distinct_ctx` 只是**下界**(去重表满了,后面的 distinct ctx 不再计数),
//     当次的分母判据作废。
//   ③ `[ctx+0x278]` 落在镜像外时 `sub_vtable_rva = 0` —— 那是「我们认不出来」,不是「没有 vtable」。
//
// Target: RVA 0x1A91A80 (offsets.keyword_reg.RVA_TRIGGER_EVAL, referenced here, never redefined)
// — §77 静态钉死:32 B 前序、尾部 `jmp [self_vtable+0x20]`(slot[4]),第二实参 = `&ctx[0x278]`。
//
// 只读: the detour records and forwards. It never writes engine memory, never repoints
// `[self+0]`, never touches registers. Engine bytes are written in exactly three places:
// the install-time JMP patch, removeHook's restore, and restoreTarget's copy of the saved
// prologue back over the patch.

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const detour_mod = @import("../hooking/detour.zig");
const windows = @import("../hooking/windows.zig");
const predicate_hook = @import("predicate_hook.zig");

const is_windows = builtin.os.tag == .windows;

/// §77 的靶:触发求值槽共用基体。Reference only — the value lives in offsets.zig.
pub const RVA_TRIGGER_EVAL: usize = offsets.keyword_reg.RVA_TRIGGER_EVAL;

pub const RING_LEN: usize = 256;
pub const DEDUPE_SLOTS: usize = 1024;
pub const LAYOUT_VERSION: u32 = 1;

/// §23.2: the trigger consumer writes the token id at `[obj+0x38]`.
pub const TRIGGER_OBJECT_TOKEN_ID: usize = 0x38;

/// §77.1 ③: the ctx type tag, read by `0x1A918E0` (must be 1 or 0x426).
pub const CTX_TAG_OFF: usize = 0x158;

/// §77.1 ②: `lea rdx, [rbx+0x278]` — the address of a sub-object handed to the next slot.
pub const CTX_SUB_OFF: usize = 0x278;

/// 32 B read off the exe copy (scripts/scratch/2026-10_eval_slot/shape_1a91a80.py, §77.1 ①).
/// The window ends **inside** the `E8 rel32` at +0x1C (its 5th byte is at +0x20), which is
/// enough: the first 10 bytes already differ from the trigger predicate base `0x349230`.
pub const EXPECTED_CODE: [32]u8 = [32]u8{
    0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+0x8], rbx
    0x48, 0x89, 0x74, 0x24, 0x10, // mov [rsp+0x10], rsi
    0x57, // push rdi
    0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
    0x48, 0x8B, 0xF9, // mov rdi, rcx   (self)
    0x49, 0x8B, 0xF0, // mov rsi, r8    (a3)
    0x48, 0x83, 0xC1, 0x78, // add rcx, 0x78
    0x48, 0x8B, 0xDA, // mov rbx, rdx   (ctx)
    0xE8, 0x3F, 0xFE, 0xFF, // call 0x1A918E0 (rel32, truncated by the window)
};

/// 48 B. The driver parses these offsets; `Entry` size and field order are the contract.
pub const Entry = extern struct {
    valid: u8 = 0,
    matched: u8 = 0, // 1 when [self+0x38] equalled the armed token
    pad0: [2]u8 = .{ 0, 0 },
    token: u32 = 0, // [self+0x38]
    ctx_tag: u32 = 0, // [ctx+0x158]
    sub_vtable_rva: u32 = 0, // [ctx+0x278] as an RVA; 0 when outside the image
    self_vtable_rva: u32 = 0, // [self]
    occurrences: u32 = 0, // how many calls carried this ctx
    ctx_ptr: u64 = 0,
    a3: u64 = 0,
    sub_obj: u64 = 0, // [ctx+0x278] raw
};

pub const Stats = extern struct {
    calls: u64 = 0, // every call, matched or not — the frequency source (§57.4 discipline)
    token_matched: u64 = 0,
    distinct_ctx: u64 = 0, // distinct ctx values seen (a LOWER bound once dedupe_full > 0)
    dedupe_full: u64 = 0, // distinct ctx values that did not fit the table
    ctx_null: u64 = 0,
    patch_size: u64 = 0,
    last_token: u32 = 0,
    last_tag: u32 = 0,
};

comptime {
    if (@sizeOf(Entry) != 48) @compileError("trigger eval Entry must be 48 bytes");
    if (@sizeOf(Stats) != 56) @compileError("trigger eval Stats must be 56 bytes");
}

var img_base: usize = 0;
var img_end: usize = 0;

var ring: [RING_LEN]Entry = undefined;
var stats = Stats{};

/// Guard state is private to this module — same discipline as the other four guards.
var installed = false;
var hook: ?detour_mod.Hook = null;
var orig: ?*anyopaque = null;
var target_addr: usize = 0;
var saved_code: [32]u8 = [_]u8{0} ** 32;
var armed_token: u32 = 0;

/// The token filter. Unlike `predicate_hook`, the value may change after install: it only
/// decides which calls land in the statistics, it is not a patch target.
pub fn setToken(value: u32) void {
    @atomicStore(u32, &armed_token, value, .monotonic);
}

pub fn token() u32 {
    return @atomicLoad(u32, &armed_token, .monotonic);
}

/// Only a non-zero token equal to the armed one matches. `0` never matches.
pub fn classifyToken(obj_token: u32) bool {
    const armed = @atomicLoad(u32, &armed_token, .monotonic);
    return obj_token != 0 and obj_token == armed;
}

/// Same three-part bounds gate as predicate_hook.zig — every engine-memory read goes through it.
pub fn plausible(p: usize) bool {
    return p >= 0x10000 and p <= 0x00007FFF_FFFF_0000 and (p & 7) == 0;
}

pub fn readU64(addr: usize) ?u64 {
    if (!plausible(addr)) return null;
    return @as(*align(8) const u64, @ptrFromInt(addr)).*;
}

pub fn readU32(addr: usize, comptime off: usize) u32 {
    if (!plausible(addr)) return 0;
    const base: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u32, base[off..][0..4], .little);
}

/// Module-relative address of `abs`, or 0 when `abs` is outside the game image.
pub fn toRva(abs: usize) u32 {
    if (abs < img_base or abs >= img_end) return 0;
    const rva = abs - img_base;
    if (rva > std.math.maxInt(u32)) return 0;
    return @intCast(rva);
}

pub fn setImageBounds(base: usize, end: usize) void {
    img_base = base;
    img_end = end;
}

// ---------------------------------------------------------------------------
// The ctx dedupe table (pure, host-testable)
// ---------------------------------------------------------------------------

pub const InsertResult = enum { new, seen, full };

/// Open-addressed set of ctx pointers with linear probing. Pure data + pure methods:
/// the host tests drive it directly, no engine memory involved.
pub const DedupeTable = struct {
    pub const SLOTS: usize = DEDUPE_SLOTS;

    keys: [SLOTS]u64 = undefined,
    used: [SLOTS]bool = [_]bool{false} ** SLOTS,
    count: usize = 0,

    fn slot(key: u64) usize {
        const h = key *% 0x9E3779B97F4A7C15;
        return @intCast(h >> 54); // top 10 bits -> 1024 slots
    }

    /// `new` = the key was not seen before, `seen` = it was, `full` = the table is full
    /// and the key is unknown (the caller must then treat it as an untracked distinct ctx).
    pub fn insert(self: *DedupeTable, key: u64) InsertResult {
        if (self.count == SLOTS) return .full;
        var idx = slot(key);
        var probes: usize = 0;
        while (probes < SLOTS) : (probes += 1) {
            if (!self.used[idx]) {
                self.used[idx] = true;
                self.keys[idx] = key;
                self.count += 1;
                return .new;
            }
            if (self.keys[idx] == key) return .seen;
            idx = (idx + 1) % SLOTS;
        }
        return .full;
    }

    /// The slot index of `key`, if it is in the table.
    pub fn indexOf(self: *const DedupeTable, key: u64) ?usize {
        var idx = slot(key);
        var probes: usize = 0;
        while (probes < SLOTS) : (probes += 1) {
            if (!self.used[idx]) return null;
            if (self.keys[idx] == key) return idx;
            idx = (idx + 1) % SLOTS;
        }
        return null;
    }

    /// How many distinct keys the table holds.
    pub fn len(self: *const DedupeTable) usize {
        return self.count;
    }
};

var dedupe = DedupeTable{};

/// Rows are appended in first-seen order; the table slot of a ctx is not its row index,
/// so the ring keeps its own insertion counter.
var row_count: usize = 0;

/// The recording path is taken on engine threads: the table + ring update happens under
/// one module-private spinlock (the `detour.zig` shape — `std.Io.Mutex` needs an Io context
/// that DLL hook code does not have). Counters stay atomic so a reader never blocks.
var rec_lock: u32 = 0;

fn lockRec() void {
    while (@atomicRmw(u32, &rec_lock, .Xchg, 1, .acquire) != 0) {}
}

fn unlockRec() void {
    _ = @atomicRmw(u32, &rec_lock, .Xchg, 0, .release);
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

pub const Snapshot = struct {
    calls: u64,
    token_matched: u64,
    distinct_ctx: u64,
    dedupe_full: u64,
    ctx_null: u64,
    samples: u32,
};

pub fn snapshot() Snapshot {
    return .{
        .calls = @atomicLoad(u64, &stats.calls, .monotonic),
        .token_matched = @atomicLoad(u64, &stats.token_matched, .monotonic),
        .distinct_ctx = @atomicLoad(u64, &stats.distinct_ctx, .monotonic),
        .dedupe_full = @atomicLoad(u64, &stats.dedupe_full, .monotonic),
        .ctx_null = @atomicLoad(u64, &stats.ctx_null, .monotonic),
        .samples = @intCast(@min(row_count, RING_LEN)),
    };
}

/// One evaluation's bookkeeping. `calls` counts every call; matching, the ctx read and the
/// row write happen only for the armed token — the frequency reading never depends on the
/// sampling denominator.
pub fn recordCall(obj_token: u32, self: usize, ctx: usize, a3: u64) void {
    _ = @atomicRmw(u64, &stats.calls, .Add, 1, .monotonic);
    if (!classifyToken(obj_token)) return;
    _ = @atomicRmw(u64, &stats.token_matched, .Add, 1, .monotonic);
    @atomicStore(u32, &stats.last_token, obj_token, .monotonic);

    if (ctx == 0) {
        _ = @atomicRmw(u64, &stats.ctx_null, .Add, 1, .monotonic);
        return;
    }

    // The two reads §77 pinned: the type tag and the sub-object's first qword. Both go
    // through the bounds gate — a plausible-but-unmapped value would fault the host.
    const tag = readU32(ctx, CTX_TAG_OFF);
    const sub = readU64(ctx + CTX_SUB_OFF) orelse 0;
    @atomicStore(u32, &stats.last_tag, tag, .monotonic);

    lockRec();
    defer unlockRec();

    switch (dedupe.insert(ctx)) {
        .seen => {
            // Same ctx again: bump the occurrence counter of its row, if it has one.
            if (dedupe.indexOf(ctx)) |slot| {
                if (dedupe_row(slot)) |r| ring[r].occurrences += 1;
            }
        },
        .full => {
            // The table is full: this ctx is distinct but untracked. `distinct_ctx` stays
            // put, so it becomes a LOWER bound (honest clause ②).
            _ = @atomicRmw(u64, &stats.dedupe_full, .Add, 1, .monotonic);
        },
        .new => {
            _ = @atomicRmw(u64, &stats.distinct_ctx, .Add, 1, .monotonic);
            if (row_count < RING_LEN) {
                const slot: usize = row_count;
                row_count += 1;
                var e: Entry = .{};
                e.valid = 1;
                e.matched = 1;
                e.token = obj_token;
                e.ctx_tag = tag;
                e.sub_vtable_rva = toRva(@intCast(sub));
                e.self_vtable_rva = toRva(@intCast(readU64(self) orelse 0));
                e.occurrences = 1;
                e.ctx_ptr = ctx;
                e.a3 = a3;
                e.sub_obj = sub;
                ring[slot] = e;
            }
        },
    }
}

/// The ring row of a dedupe slot. The table and the ring are filled together, so the n-th
/// distinct ctx is row n-1 until the ring is full; beyond that the table slot has no row.
fn dedupe_row(slot: usize) ?usize {
    if (row_count == 0) return null;
    const key = dedupe.keys[slot];
    var i: usize = 0;
    while (i < row_count) : (i += 1) {
        if (ring[i].ctx_ptr == key) return i;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Injector-facing readouts
// ---------------------------------------------------------------------------

/// Six layout words: [version, Entry size, RING_LEN, Stats size, target RVA, prologue length].
pub fn layoutInto(out: *[6]u32) u32 {
    out.* = .{
        LAYOUT_VERSION,
        @intCast(@sizeOf(Entry)),
        @intCast(RING_LEN),
        @intCast(@sizeOf(Stats)),
        @intCast(RVA_TRIGGER_EVAL),
        @intCast(EXPECTED_CODE.len),
    };
    return 6;
}

/// One line, fixed key order — `scripts/c2_trigger_eval_probe.py`'s `STATS_KEYS` parses it.
pub fn statsInto(out: []u8) usize {
    const written = std.fmt.bufPrint(
        out,
        "calls={d} token_matched={d} distinct_ctx={d} dedupe_full={d} ctx_null={d} patch_size={d} installed={d} verify={d} last_token={d} last_tag={d}\n",
        .{
            @atomicLoad(u64, &stats.calls, .monotonic),
            @atomicLoad(u64, &stats.token_matched, .monotonic),
            @atomicLoad(u64, &stats.distinct_ctx, .monotonic),
            @atomicLoad(u64, &stats.dedupe_full, .monotonic),
            @atomicLoad(u64, &stats.ctx_null, .monotonic),
            stats.patch_size,
            @intFromBool(installed),
            verify(),
            @atomicLoad(u32, &stats.last_token, .monotonic),
            @atomicLoad(u32, &stats.last_tag, .monotonic),
        },
    ) catch return 0;
    return written.len;
}

/// The caller's drain buffer size, declared with `setDrainCap` before `drainInto`.
/// `call_remote_with_arg` (ruling P4) can only pass one register, so the capacity cannot be
/// a second argument. Zero means "not declared" and `drainInto` refuses.
var drain_cap: usize = 0;

pub fn setDrainCap(bytes: usize) void {
    drain_cap = bytes;
}

/// Copy the retained rows into `out` oldest first. Clamped to the byte count declared by
/// `setDrainCap`; refuses (0 rows) when none was declared.
pub fn drainInto(out: [*]u8) u32 {
    const capacity = @min(drain_cap / @sizeOf(Entry), RING_LEN);
    if (capacity == 0) return 0;
    const dst: [*]Entry = @ptrCast(@alignCast(out));
    var copied: u32 = 0;
    while (copied < capacity and copied < row_count) : (copied += 1) {
        dst[copied] = ring[copied];
    }
    return copied;
}

/// Clear counters + ring + table + token + image window. Does not uninstall a hook (clearing
/// `calls` under a live patch would silently reset the frequency denominator).
pub fn reset() void {
    stats = .{};
    dedupe = DedupeTable{};
    row_count = 0;
    ring = undefined;
    @atomicStore(u32, &armed_token, 0, .monotonic);
    drain_cap = 0;
    img_base = 0;
    img_end = 0;
}

/// Reset everything the host tests share. The assembly section (install/uninstall) lands in
/// a later step; until then `verify` can only report "no target resolved".
pub fn resetForTest() void {
    reset();
    installed = false;
    hook = null;
    orig = null;
    target_addr = 0;
    saved_code = [_]u8{0} ** 32;
}

// ---------------------------------------------------------------------------
// Assembly: fingerprint gate + install / uninstall / verify
// (shape copied from trigger_pred_probe.zig — same-family prologue gate, saved_code
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

/// Two refusals before installing: this guard is already in, or the predicate detour is
/// armed. The second is §57.4's reason — with the predicate armed, `[self+0]` may point at
/// our own DLL's vtable copy, and a self vtable read in that state is not an engine reading.
pub fn preflightChecks(already_installed: bool, patch_active: bool) InstallError!void {
    if (already_installed) return error.AlreadyInstalled;
    if (patch_active) return error.PatchActive;
}

pub const OrigFn = *const fn (u64, u64, u64) callconv(.c) u64;

/// The evaluation slot takes `(self, ctx, a3)` (§77.1 ②). Its shared base tail-jumps to the
/// per-table slot[4], so the return convention belongs to that table; the one call site we
/// can read statically (`0x34A01B`) **discards** the result. Forwarding the raw `rax` is
/// therefore the safe choice: a void callee's rax is nobody's business, and a bool or
/// pointer callee keeps its value in rax.
fn evalDetour(self: u64, ctx: u64, a3: u64) callconv(.c) u64 {
    const obj_token = readU32(@intCast(self), TRIGGER_OBJECT_TOKEN_ID);
    recordCall(obj_token, @intCast(self), @intCast(ctx), a3);
    const f: OrigFn = @ptrCast(orig orelse return 0);
    return f(self, ctx, a3);
}

pub fn install() InstallError!void {
    if (!is_windows) return error.Unsupported;
    try preflightChecks(installed, predicate_hook.isInstalled());

    const target = windows.moduleFunction(RVA_TRIGGER_EVAL) catch return error.ModuleNotFound;
    if (detour_mod.isHooked(target)) return error.AlreadyHooked;

    target_addr = @intFromPtr(target); // set before the gate so fingerprintMatches can re-check

    const tb: [*]const u8 = @ptrCast(target);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return error.UnexpectedPrologue;
    }
    @memcpy(&saved_code, tb[0..saved_code.len]);

    const base = @intFromPtr(target) - RVA_TRIGGER_EVAL;
    setImageBounds(base, base + 0x400_0000);

    const h = detour_mod.installHookArmed(target, @ptrCast(@constCast(&evalDetour)), &orig) catch
        return error.DetourUnavailable;
    if (h.patch_size > saved_code.len) {
        // The patch is already live at this point: undo it here, or the process keeps a hook
        // this module can no longer reach (2026-10-28 review, Important 5).
        detour_mod.removeHook(&h) catch {};
        restoreTarget(h.patch_size) catch {};
        orig = null;
        return error.PatchTooWide;
    }
    hook = h;
    installed = true;
    stats.patch_size = h.patch_size;
    std.log.info("c2.trigger_eval_probe: installed detour at 0x{x}", .{RVA_TRIGGER_EVAL});
}

/// Copy our own snapshot of the prologue back. The authoritative restore: it does not depend
/// on `removeHook` reading a trampoline that is still intact (that memory is retired, never
/// freed — see `detour.zig`).
fn restoreTarget(len: usize) !void {
    var guard = try windows.ProtectGuard.change(@ptrFromInt(target_addr), len, .execute_readwrite);
    defer guard.deinit();
    const dst: [*]u8 = @ptrFromInt(target_addr);
    @memcpy(dst[0..len], saved_code[0..len]);
    windows.flushInstructionCache(@ptrFromInt(target_addr), len);
}

/// Remove the detour. A no-op when not installed — the driver still calls it after a failed install.
pub fn uninstall() !void {
    if (!installed) return;
    const h = hook orelse return;
    detour_mod.removeHook(&h) catch {};
    hook = null;
    installed = false;
    try restoreTarget(h.patch_size);
    orig = null; // only once the engine bytes are ours again
    if (!fingerprintMatches()) return error.RestoreIncomplete;
    std.log.info("c2.trigger_eval_probe: uninstalled detour", .{});
}

/// True when the engine's own 32-byte prologue is present at the target.
fn fingerprintMatches() bool {
    if (target_addr == 0) return false;
    const tb: [*]const u8 = @ptrFromInt(target_addr);
    for (EXPECTED_CODE, 0..) |byte, i| {
        if (tb[i] != byte) return false;
    }
    return true;
}

/// 0 = consistent. Installed: the hook must still be in the detour table; not installed: we
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

test "Entry is 48 bytes with the field order the driver parses" {
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(Entry));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(Entry, "token"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(Entry, "ctx_tag"));
    try std.testing.expectEqual(@as(usize, 12), @offsetOf(Entry, "sub_vtable_rva"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(Entry, "self_vtable_rva"));
    try std.testing.expectEqual(@as(usize, 20), @offsetOf(Entry, "occurrences"));
    try std.testing.expectEqual(@as(usize, 24), @offsetOf(Entry, "ctx_ptr"));
    try std.testing.expectEqual(@as(usize, 32), @offsetOf(Entry, "a3"));
    try std.testing.expectEqual(@as(usize, 40), @offsetOf(Entry, "sub_obj"));
}

test "Stats is 56 bytes" {
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(Stats));
}

test "DedupeTable reports new, seen, and full" {
    var table = DedupeTable{};
    try std.testing.expectEqual(InsertResult.new, table.insert(0x1000));
    try std.testing.expectEqual(InsertResult.seen, table.insert(0x1000));
    var i: usize = 0;
    while (i < DEDUPE_SLOTS) : (i += 1) _ = table.insert(0x2000 + i * 8);
    try std.testing.expectEqual(InsertResult.full, table.insert(0x9999_9999));
}

test "DedupeTable counts every distinct key exactly once" {
    var table = DedupeTable{};
    try std.testing.expectEqual(@as(usize, 0), table.len());
    _ = table.insert(1);
    _ = table.insert(2);
    _ = table.insert(1);
    _ = table.insert(3);
    try std.testing.expectEqual(@as(usize, 3), table.len());
}

test "a matching call records one row per distinct ctx" {
    resetForTest();
    setToken(0x4321);
    recordCall(0x4321, 0x1000, 0x2000, 0);
    recordCall(0x4321, 0x1000, 0x2000, 0);
    recordCall(0x4321, 0x1000, 0x2000, 0);
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 3), s.token_matched);
    try std.testing.expectEqual(@as(u64, 1), s.distinct_ctx);
    try std.testing.expectEqual(@as(u32, 1), s.samples);

    setDrainCap(@sizeOf(Entry));
    var buf: [@sizeOf(Entry)]u8 align(8) = undefined;
    const rows = drainInto(&buf);
    try std.testing.expectEqual(@as(u32, 1), rows);
    const row: *Entry = @ptrCast(@alignCast(&buf));
    try std.testing.expectEqual(@as(u32, 3), row.occurrences);
    try std.testing.expectEqual(@as(u64, 0x2000), row.ctx_ptr);
}

test "a non-matching call increments calls but records nothing" {
    resetForTest();
    setToken(0x4321);
    recordCall(0x1111, 0x1000, 0x2000, 0);
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 1), s.calls);
    try std.testing.expectEqual(@as(u64, 0), s.token_matched);
    try std.testing.expectEqual(@as(u64, 0), s.distinct_ctx);
    try std.testing.expectEqual(@as(u32, 0), s.samples);
}

test "ctx == 0 counts ctx_null and records no row" {
    resetForTest();
    setToken(0x4321);
    recordCall(0x4321, 0x1000, 0, 0);
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 1), s.ctx_null);
    try std.testing.expectEqual(@as(u64, 0), s.distinct_ctx);
    try std.testing.expectEqual(@as(u32, 0), s.samples);
}

test "the ring keeps the first RING_LEN distinct ctx and never grows" {
    resetForTest();
    setToken(1);
    var i: usize = 0;
    while (i < RING_LEN + 4) : (i += 1) recordCall(1, 0x1000, 0x2000 + i * 8, 0);
    const s = snapshot();
    try std.testing.expectEqual(@as(u32, @intCast(RING_LEN)), s.samples);
    try std.testing.expectEqual(@as(u64, RING_LEN + 4), s.distinct_ctx);
}

test "statsInto writes one k=v line with all ten keys" {
    resetForTest();
    var buf: [512]u8 = undefined;
    const n = statsInto(&buf);
    const expected = "calls=0 token_matched=0 distinct_ctx=0 dedupe_full=0 ctx_null=0 " ++
        "patch_size=0 installed=0 verify=-3 last_token=0 last_tag=0\n";
    try std.testing.expectEqualStrings(expected, buf[0..n]);
}

test "layoutInto reports six words and a stable entry size" {
    var words: [6]u32 = undefined;
    try std.testing.expectEqual(@as(u32, 6), layoutInto(&words));
    try std.testing.expectEqual(@as(u32, 1), words[0]);
    try std.testing.expectEqual(@as(u32, 48), words[1]);
    try std.testing.expectEqual(@as(u32, 256), words[2]);
    try std.testing.expectEqual(@as(u32, 56), words[3]);
    try std.testing.expectEqual(@as(u32, 0x1A91A80), words[4]);
    try std.testing.expectEqual(@as(u32, 32), words[5]);
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
