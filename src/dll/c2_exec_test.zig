// Native tests for the C4 execution wrapper. Root lives at src/dll/ because
// Zig imports may not escape the module root.

const std = @import("std");
const builtin = @import("builtin");
const vtable = @import("c2/vtable.zig");
const predicate_hook = @import("c2/predicate_hook.zig");
const exec_hook = @import("scripted/exec_hook.zig");
const live_probe = @import("c2/live_probe.zig");
const scope_probe = @import("c2/scope_probe.zig");
const donor_probe = @import("c2/donor_exec_probe.zig");
const wire = @import("c2/wire.zig");
const windows = @import("hooking/windows.zig");
const chokepoint_table = @import("c2/chokepoint_table.zig");

comptime {
    _ = scope_probe;
    _ = donor_probe;
}

extern fn C2DiagQuickJS(out_diag: [*]u8, diag_size: c_int) c_int;
extern fn C2ExecArmToken(token: u32, budget: u32) c_int;
extern fn C2ExecStats(out: [*]u8, out_size: c_int) c_int;
extern fn C2ExecDisarmState() c_int;
extern fn C2ExecArmScores(scores: ?[*]const u16, count: u32, token: u32, budget: u32, tier1_min: u32, tier2_min: u32) c_int;
extern fn C2ExecCallScored(token: u32, system_id: u32) c_int;
extern fn C2ExecScoredStats(out: [*]u8, out_size: c_int) c_int;
extern fn C2ExecArmSrcForTest(src: [*:0]const u8, token: u32, budget: u32) c_int;

var donor_calls: u32 = 0;

fn fakeDonor(self: u64, ctx: u64, a3: u64) callconv(.c) u64 {
    _ = self;
    _ = ctx;
    _ = a3;
    donor_calls += 1;
    return 0xD0;
}

var synth_capture: struct { parent: u64 = 0, ctx: u64 = 0, token: u32 = 0, r9: u64 = 0 } = .{};
var synth_calls: u32 = 0;

fn fakeInstantiate(parent: u64, ctx: u64, token: u32, r9: u64) callconv(.c) u64 {
    synth_capture = .{ .parent = parent, .ctx = ctx, .token = token, .r9 = r9 };
    synth_calls += 1;
    return 77;
}

fn readU32(addr: usize, off: usize) u32 {
    const p: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u32, p[off..][0..4], .little);
}

fn readU64(addr: usize, off: usize) u64 {
    const p: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u64, p[off..][0..8], .little);
}

fn liveCtx() !void {
    var diag: [512]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), C2DiagQuickJS(&diag, @intCast(diag.len)));
}

fn fakeDonorSlots() [vtable.SlotCount]u64 {
    var slots = [_]u64{0} ** vtable.SlotCount;
    for (&slots, 0..) |*s, i| s.* = 0x1000 + @as(u64, i) * 8;
    slots[1] = @intFromPtr(&fakeDonor);
    return slots;
}

test "buildFromSlots copies every donor slot and overrides slot[1] and slot[2]" {
    vtable.resetForTest();
    const donor = fakeDonorSlots();
    try vtable.buildFromSlots(donor[0..]);
    const vt = vtable.getVtable() orelse return error.NoVtable;
    try std.testing.expectEqual(donor[0], vt[0]);
    try std.testing.expect(donor[2] != vt[2]);
    try std.testing.expectEqual(donor[15], vt[15]);
    try std.testing.expectEqual(donor[19], vt[19]);
    try std.testing.expectEqual(donor[24], vt[24]);
    try std.testing.expect(vt[1] != donor[1]);
    try std.testing.expectEqual(@intFromPtr(&fakeDonor), vtable.donorExecute());
    try std.testing.expect(vtable.isBuilt());
}

var slot2_seen: [4]u64 = .{ 0, 0, 0, 0 };

fn fakeSlot2(a1: u64, a2: u64, a3: u64, a4: u64) callconv(.c) u64 {
    slot2_seen = .{ a1, a2, a3, a4 };
    return 0x5A5A;
}

test "slot[2] thunk counts and forwards every register argument unchanged" {
    vtable.resetForTest();
    var donor = fakeDonorSlots();
    donor[2] = @intFromPtr(&fakeSlot2);
    try vtable.buildFromSlots(donor[0..]);
    const vt = vtable.getVtable() orelse return error.NoVtable;
    try std.testing.expect(vt[2] != donor[2]);
    try std.testing.expectEqual(@intFromPtr(&fakeSlot2), vtable.slot2Target());
    try std.testing.expectEqual(@as(u64, 0), vtable.slot2Calls());

    const thunk: *const fn (u64, u64, u64, u64) callconv(.c) u64 = @ptrFromInt(vt[2]);
    try std.testing.expectEqual(@as(u64, 0x5A5A), thunk(0x11, 0x22, 0x33, 0x44));
    try std.testing.expectEqual([4]u64{ 0x11, 0x22, 0x33, 0x44 }, slot2_seen);
    try std.testing.expectEqual(@as(u64, 1), vtable.slot2Calls());
}

test "slot[2] thunk counts but does not jump to an implausible target" {
    vtable.resetForTest();
    const donor = fakeDonorSlots(); // slot[2] = 0x1010, below the plausible range
    try vtable.buildFromSlots(donor[0..]);
    const vt = vtable.getVtable() orelse return error.NoVtable;
    const thunk: *const fn (u64, u64, u64, u64) callconv(.c) u64 = @ptrFromInt(vt[2]);
    try std.testing.expectEqual(@as(u64, 0), thunk(1, 2, 3, 4));
    try std.testing.expectEqual(@as(u64, 1), vtable.slot2Calls());
}

test "slot2 stats blob is 16 bytes: calls then target" {
    vtable.resetForTest();
    var donor = fakeDonorSlots();
    donor[2] = @intFromPtr(&fakeSlot2);
    try vtable.buildFromSlots(donor[0..]);
    const vt = vtable.getVtable() orelse return error.NoVtable;
    const thunk: *const fn (u64, u64, u64, u64) callconv(.c) u64 = @ptrFromInt(vt[2]);
    _ = thunk(0, 0, 0, 0);
    var out: [vtable.SLOT2_STATS_SIZE]u8 = undefined;
    try std.testing.expect(vtable.slot2StatsInto(out[0..]));
    try std.testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, out[0..8], .little));
    try std.testing.expectEqual(
        @intFromPtr(&fakeSlot2), std.mem.readInt(u64, out[8..16], .little));
}

test "buildFromSlots rejects a short donor and a bad Execute slot" {
    vtable.resetForTest();
    const short = [_]u64{0x1000} ** 3;
    try std.testing.expectError(error.ShortDonor, vtable.buildFromSlots(short[0..]));
    try std.testing.expect(!vtable.isBuilt());

    var donor = fakeDonorSlots();
    donor[1] = 0;
    try std.testing.expectError(error.BadDonorExecute, vtable.buildFromSlots(donor[0..]));
    try std.testing.expect(!vtable.isBuilt());
}

test "chain is off by default and forwards only on a sentinel rc" {
    vtable.resetForTest();
    try std.testing.expect(!vtable.chainEnabled());

    _ = liveCtx() catch return error.NoContext;
    try std.testing.expectEqual(@as(c_int, 0), C2ExecArmToken(4242, 4));

    const donor = fakeDonorSlots();
    try vtable.buildFromSlots(donor[0..]);
    const vt = vtable.getVtable() orelse return error.NoVtable;
    const exec: *const fn (u64, u64, u64) callconv(.c) u64 = @ptrFromInt(vt[1]);

    var obj: [64]u8 align(8) = [_]u8{0} ** 64;
    std.mem.writeInt(u32, obj[0x20..0x24], 4242, .little);
    const self = @intFromPtr(&obj);

    donor_calls = 0;
    try std.testing.expectEqual(@as(u64, 0), exec(self, 0x1234, 0));
    var buf: [512]u8 = undefined;
    const n = C2ExecStats(&buf, @intCast(buf.len));
    try std.testing.expect(std.mem.indexOf(u8, buf[0..@intCast(n)], "js_ok=1") != null);
    try std.testing.expectEqual(@as(u32, 0), donor_calls);

    vtable.setChainEnabled(true);
    try std.testing.expect(vtable.chainEnabled());
    try std.testing.expectEqual(@as(u64, 0xD0), exec(self, 0x1234, 0));
    try std.testing.expectEqual(@as(u32, 1), donor_calls);

    std.mem.writeInt(u32, obj[0x20..0x24], 999, .little);
    try std.testing.expectEqual(@as(u64, 0), exec(self, 0x1234, 0));
    try std.testing.expectEqual(@as(u32, 1), donor_calls);

    _ = C2ExecDisarmState();
}

test "resetForTest clears build state, donor, chain and slot[2] counter" {
    vtable.resetForTest();
    const donor = fakeDonorSlots();
    try vtable.buildFromSlots(donor[0..]);
    vtable.setChainEnabled(true);
    vtable.resetForTest();
    try std.testing.expect(!vtable.isBuilt());
    try std.testing.expect(!vtable.chainEnabled());
    try std.testing.expectEqual(@as(u64, 0), vtable.donorExecute());
    try std.testing.expectEqual(@as(u64, 0), vtable.slot2Calls());
    try std.testing.expectEqual(@as(u64, 0), vtable.slot2Target());
    try std.testing.expectEqual(@as(?*const [vtable.SlotCount]u64, null), vtable.getVtable());
}

test "predicate setToken rejects zero and duplicate installs" {
    predicate_hook.resetForTest();
    try std.testing.expectError(error.InvalidToken, predicate_hook.setToken(0));
    try predicate_hook.setToken(4242);
    try std.testing.expectEqual(@as(u32, 4242), predicate_hook.token());
    predicate_hook.clearToken();
    try std.testing.expectEqual(@as(u32, 0), predicate_hook.token());
}

test "predicate patchObject rewrites [obj+0] only for the armed token" {
    predicate_hook.resetForTest();
    try predicate_hook.setToken(4242);

    var obj: [64]u8 align(8) = [_]u8{0} ** 64;
    const obj_addr = @intFromPtr(&obj);
    std.mem.writeInt(u64, obj[0..8], 0xAAAA, .little);
    std.mem.writeInt(u32, obj[0x20..0x24], 4242, .little);

    try std.testing.expect(predicate_hook.shouldPatch(4242));
    try std.testing.expect(!predicate_hook.shouldPatch(999));
    try std.testing.expect(!predicate_hook.shouldPatch(0));

    try std.testing.expect(predicate_hook.patchObject(obj_addr, 4242, 0xBEEF));
    try std.testing.expectEqual(@as(u64, 0xBEEF), std.mem.readInt(u64, obj[0..8], .little));

    std.mem.writeInt(u32, obj[0x20..0x24], 999, .little);
    try std.testing.expect(!predicate_hook.patchObject(obj_addr, 999, 0xCAFE));
    try std.testing.expectEqual(@as(u64, 0xBEEF), std.mem.readInt(u64, obj[0..8], .little));

    try std.testing.expectEqual(@as(u64, 1), predicate_hook.getStats().patched);
    predicate_hook.resetForTest();
}

/// Same exact-key rule as c2_diag_test.zig: `installed=` is a substring of
/// `pred_installed=`, `calls=` of `pred_calls=`.
fn countExactKey(text: []const u8, key: []const u8) usize {
    var n: usize = 0;
    var it = std.mem.tokenizeAny(u8, text, " \n");
    while (it.next()) |tok| {
        const eq = std.mem.indexOfScalar(u8, tok, '=') orelse continue;
        if (std.mem.eql(u8, tok[0..eq], key)) n += 1;
    }
    return n;
}

test "ctxUsable rejects only the lexer sentinel 0xb" {
    try std.testing.expect(live_probe.ctxUsable(0));
    try std.testing.expect(live_probe.ctxUsable(0xc));
    try std.testing.expect(!live_probe.ctxUsable(0xb));
}

test "synthetic parse context satisfies every hit-path context read" {
    live_probe.resetForTest();
    const ctx = live_probe.syntheticCtxAddr();
    try std.testing.expectEqual(@as(u32, 0), readU32(ctx, 0x38));
    try std.testing.expectEqual(@as(u32, 0), readU32(ctx, 0x278));
    const a = readU64(ctx, 0x30);
    try std.testing.expect(a != 0);
    const b = readU64(a, 8);
    try std.testing.expect(b != 0);
    try std.testing.expectEqual(@as(u64, 0), readU64(b, 0x70));
    try std.testing.expectEqual(@as(u32, 0), readU32(b, 8));
    try std.testing.expectEqual(@as(u32, 0), readU32(b, 0xc));
    try std.testing.expectEqual(@as(u64, 0), readU64(b, 0x40));
    try std.testing.expectEqual(@as(u64, 0), readU64(b, 0x48));
    const parent = live_probe.syntheticParentAddr();
    // Container lives at parent+8 (0x3B0C3F: mov rcx,[rbp+0x530]; add rcx,8).
    // +0x08 vptr is never read on the append fast path, +0x10 begin, +0x18
    // capacity, +0x1c size.
    try std.testing.expectEqual(@as(u64, 0), readU64(parent, 0x08));
    const begin = readU64(parent, 0x10);
    try std.testing.expect(begin != 0);
    try std.testing.expectEqual(@as(u64, 0), begin & 7);
    try std.testing.expectEqual(@as(u32, 0), readU32(parent, 0x1c));
    try std.testing.expect(readU32(parent, 0x18) > 0);
}

test "synthetic parent pre-sizes the effect container onto 0x22C4A0's fast path" {
    // 0x22C4A0 compares [container+0x14] (size) with [container+0x10]
    // (capacity) and only on equality takes the grow branch, whose first
    // engine instruction is `call [container_vptr+0x18]` — a null vptr is the
    // 0x18 access violation seen in the 2026-10-23 crash dump. Capacity must
    // therefore stay strictly above size for every append the probe can cause.
    live_probe.resetForTest();
    const parent = live_probe.syntheticParentAddr();
    const container = parent + 8;
    const begin = readU64(container, 8);
    const cap = readU32(container, 0x10);
    const size = readU32(container, 0x14);
    try std.testing.expectEqual(@as(u32, 0), size);
    try std.testing.expect(cap > size);
    // Simulate the fast-path store the helper performs: begin[size] = child.
    const slot: [*]u8 = @ptrFromInt(begin + @as(u64, size) * 8);
    std.mem.writeInt(u64, slot[0..8], 0xDEAD_BEEF, .little);
    try std.testing.expectEqual(@as(u64, 0xDEAD_BEEF), readU64(begin, 0));
    // The probe fires once, but leave headroom so a repeat fire would not grow.
    try std.testing.expect(cap >= 2);
}

test "synthetic fire passes fake parent/ctx and fires only once" {
    live_probe.resetForTest();
    try live_probe.setToken(68637);
    live_probe.setInstantiateForTest(@intFromPtr(&fakeInstantiate));
    synth_calls = 0;
    synth_capture = .{};
    const first = live_probe.fireOnceForTest();
    const second = live_probe.fireOnceForTest();
    try std.testing.expectEqual(@as(u64, 77), first);
    try std.testing.expectEqual(@as(u64, 0), second);
    try std.testing.expectEqual(@as(u32, 1), synth_calls);
    try std.testing.expectEqual(@as(u64, live_probe.syntheticParentAddr()), synth_capture.parent);
    try std.testing.expectEqual(@as(u64, live_probe.syntheticCtxAddr()), synth_capture.ctx);
    try std.testing.expectEqual(@as(u32, 68637), synth_capture.token);
    try std.testing.expectEqual(@as(u64, 0), synth_capture.r9);
    live_probe.resetForTest();
}

test "live probe setToken and non-Windows install" {
    live_probe.resetForTest();
    try std.testing.expectError(error.InvalidToken, live_probe.setToken(0));
    try live_probe.setToken(4242);
    try std.testing.expectEqual(@as(u32, 4242), live_probe.token());
    if (builtin.os.tag != .windows) {
        try std.testing.expectError(error.Unsupported, live_probe.install());
        try std.testing.expectEqual(@as(i32, -2), live_probe.verify());
    }
    live_probe.resetForTest();
}

test "live probe stats render every driver key exactly once" {
    live_probe.resetForTest();
    var buf: [512]u8 = undefined;
    const n = live_probe.statsInto(&buf);
    const text = buf[0..n];
    for ([_][]const u8{
        "armed",   "token",          "calls",          "fired",      "ctx_skip",
        "invalid", "instantiate_rc", "patch_size",     "installed",  "verified",
        "vtable",  "chain",          "pred_installed", "pred_calls", "pred_patched",
    }) |key| {
        try std.testing.expectEqual(@as(usize, 1), countExactKey(text, key));
    }
}

test "exec_hook exposes a never-installed verify state on non-Windows" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try std.testing.expectEqual(@as(i32, -2), exec_hook.verifyState());
    try std.testing.expectEqual(@as(?*anyopaque, null), exec_hook.original());
    try std.testing.expectEqual(@as(u32, 0), exec_hook.patchSize());
}

test "scored arm rejects bad tables, tokens and tier order" {
    try liveCtx();
    var t = [_]u16{0};
    try std.testing.expectEqual(@as(c_int, 4), C2ExecArmScores(null, 1, 77, 4, 100, 200));
    try std.testing.expectEqual(@as(c_int, 4), C2ExecArmScores(t[0..].ptr, 0, 77, 4, 100, 200));
    try std.testing.expectEqual(@as(c_int, 4), C2ExecArmScores(t[0..].ptr, 1, 0, 4, 100, 200));
    try std.testing.expectEqual(@as(c_int, 4), C2ExecArmScores(t[0..].ptr, 1, 77, 0, 100, 200));
    try std.testing.expectEqual(@as(c_int, 4), C2ExecArmScores(t[0..].ptr, 1, 77, 4, 201, 200));
    try std.testing.expectEqual(@as(c_int, 4), C2ExecArmScores(t[0..].ptr, 1, 77, 4, 100, 65536));
    var too_many: [2049]u16 = [_]u16{0} ** 2049;
    try std.testing.expectEqual(@as(c_int, 4), C2ExecArmScores(too_many[0..].ptr, 2049, 77, 4, 100, 200));
}

test "scored call maps the table to tiers and counts" {
    try liveCtx();
    var t = [_]u16{ 0, 99, 100, 199, 200, 286 };
    try std.testing.expectEqual(@as(c_int, 0), C2ExecArmScores(t[0..].ptr, @intCast(t.len), 77, 16, 100, 200));
    const want = [_]c_int{ 0, 0, 1, 1, 2, 2 };
    for (want, 0..) |tier, id| try std.testing.expectEqual(tier, C2ExecCallScored(77, @intCast(id)));
    try std.testing.expectEqual(@as(c_int, -1), C2ExecCallScored(999, 0)); // 错 token,不耗预算
    try std.testing.expectEqual(@as(c_int, -3), C2ExecCallScored(77, 6)); // 超范围,不耗预算
    var buf: [1024]u8 = undefined;
    const n = C2ExecScoredStats(&buf, @intCast(buf.len));
    const s = buf[0..@intCast(n)];
    for ([_][]const u8{
        "armed", "token",   "budget_left", "scored_calls", "skipped",
        "busy",  "js_err",  "invalid",     "tier0",        "tier1",
        "tier2", "last_id", "last_tier",
    }) |key| try std.testing.expectEqual(@as(usize, 1), countExactKey(s, key));
    for ([_][]const u8{
        "armed=1", "token=77",  "budget_left=10", "scored_calls=6", "skipped=1",
        "busy=0",  "js_err=0",  "invalid=1",      "tier0=2",        "tier1=2",
        "tier2=2", "last_id=5", "last_tier=2",
    }) |kv| try std.testing.expect(std.mem.indexOf(u8, s, kv) != null);
    _ = C2ExecDisarmState();
}

test "scored call reports budget exhaustion as a skip" {
    try liveCtx();
    var t = [_]u16{ 200, 200, 200 };
    try std.testing.expectEqual(@as(c_int, 0), C2ExecArmScores(t[0..].ptr, @intCast(t.len), 77, 2, 100, 200));
    try std.testing.expectEqual(@as(c_int, 2), C2ExecCallScored(77, 0));
    try std.testing.expectEqual(@as(c_int, 2), C2ExecCallScored(77, 1));
    try std.testing.expectEqual(@as(c_int, -1), C2ExecCallScored(77, 2));
    var buf: [1024]u8 = undefined;
    const n = C2ExecScoredStats(&buf, @intCast(buf.len));
    const s = buf[0..@intCast(n)];
    try std.testing.expect(std.mem.indexOf(u8, s, "budget_left=0") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "skipped=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "tier2=2") != null);
    _ = C2ExecDisarmState();
}

test "scored call reports a throwing script and re-arms" {
    try liveCtx();
    try std.testing.expectEqual(@as(c_int, 0), C2ExecArmSrcForTest("(function(){return function(t,id){throw 1;};})()", 77, 4));
    try std.testing.expectEqual(@as(c_int, -2), C2ExecCallScored(77, 0));
    var buf: [1024]u8 = undefined;
    const n = C2ExecScoredStats(&buf, @intCast(buf.len));
    try std.testing.expect(std.mem.indexOf(u8, buf[0..@intCast(n)], "js_err=1") != null);
    _ = C2ExecDisarmState();
    var t = [_]u16{0};
    try std.testing.expectEqual(@as(c_int, 0), C2ExecArmScores(t[0..].ptr, 1, 77, 4, 100, 200));
    try std.testing.expectEqual(@as(c_int, 0), C2ExecCallScored(77, 0));
    _ = C2ExecDisarmState();
}

test "scored table drives the shipped 787 scores" {
    try liveCtx();
    try std.testing.expectEqual(@as(c_int, 0), C2ExecArmScores(chokepoint_table.scores[0..].ptr, @intCast(chokepoint_table.SCORE_COUNT), 77, 787, 100, 200));
    try std.testing.expectEqual(@as(c_int, 0), C2ExecCallScored(77, 0));
    try std.testing.expectEqual(@as(c_int, 0), C2ExecCallScored(77, 1));
    try std.testing.expectEqual(@as(c_int, 1), C2ExecCallScored(77, 7));
    try std.testing.expectEqual(@as(c_int, 2), C2ExecCallScored(77, 239));
    try std.testing.expectEqual(@as(c_int, 2), C2ExecCallScored(77, 578));
    _ = C2ExecDisarmState();
}

const FakeMem = struct {
    ctx: [wire.CTX_LEN]u8 align(8) = [_]u8{0} ** wire.CTX_LEN,
    a3: [wire.A3_LEN]u8 align(8) = [_]u8{0} ** wire.A3_LEN,
    target: [wire.PTR_LEN]u8 align(8) = [_]u8{0} ** wire.PTR_LEN,
    fail_ctx: bool = false,
    fail_a3: bool = false,
    fail_target: bool = false,

    const CTX_ADDR: usize = 0x100000;
    const A3_ADDR: usize = 0x110000;
    const TARGET_ADDR: usize = 0x200000;

    fn read(self: *FakeMem, addr: usize, out: []u8) bool {
        var src: []const u8 = undefined;
        if (addr == CTX_ADDR) {
            if (self.fail_ctx) return false;
            src = &self.ctx;
        } else if (addr == A3_ADDR) {
            if (self.fail_a3) return false;
            src = &self.a3;
        } else if (addr == TARGET_ADDR) {
            if (self.fail_target) return false;
            src = &self.target;
        } else return false;
        if (out.len > src.len) return false;
        @memcpy(out, src[0..out.len]);
        return true;
    }
};

var fake_mem: FakeMem = .{};

fn fakeRead(addr: usize, out: []u8) bool {
    return fake_mem.read(addr, out);
}

fn readU32At(bytes: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, bytes[off..][0..4], .little);
}

test "wire record layout pins every driver offset" {
    try std.testing.expectEqual(@as(usize, 3368), @sizeOf(wire.Record));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(wire.Record, "valid"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(wire.Record, "ctx_ptr"));
    try std.testing.expectEqual(@as(usize, 56), @offsetOf(wire.Record, "ctx"));
    try std.testing.expectEqual(@as(usize, 1000), @offsetOf(wire.Record, "a3"));
    try std.testing.expectEqual(@as(usize, 1256), @offsetOf(wire.Record, "ptr_targets"));
    try std.testing.expectEqual(@as(usize, 1320), @offsetOf(wire.Record, "ptr_windows"));
    try std.testing.expectEqual(@as(usize, 80), wire.STATS_SIZE);
}

test "wire spec packs and rejects reserved or out-of-bounds bits" {
    wire.resetForTest();
    const p: u64 = (1 << 8) | (0x38 << 16) | (0x20 << 32);
    try std.testing.expect(wire.setSpecPacked(p));
    try std.testing.expectEqual(p, wire.specPacked());
    try std.testing.expect(!wire.setSpecPacked(1 << 63)); // reserved
    try std.testing.expect(!wire.setSpecPacked(2)); // blob=2
    try std.testing.expect(!wire.setSpecPacked(2 << 8)); // deref=2
    try std.testing.expect(!wire.setSpecPacked((4 << 16) | (1 << 32))); // 直读 off_b != 0
    try std.testing.expect(!wire.setSpecPacked(942 << 16)); // 未对齐
}

test "wire capture skips a record when ctx is unreadable" {
    wire.resetForTest();
    fake_mem = .{ .fail_ctx = true };
    wire.setReaderForTest(&fakeRead);
    wire.beginSession(4242);
    try std.testing.expect(!wire.captureWith(&fakeRead, 0, 4242, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    var stats: [wire.STATS_SIZE]u8 = undefined;
    try std.testing.expect(wire.statsInto(&stats));
    try std.testing.expectEqual(@as(u32, 1), readU32At(&stats, 12)); // calls
    try std.testing.expectEqual(@as(u32, 0), readU32At(&stats, 4)); // records
    var out: [wire.RECORD_SIZE]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 0), wire.drainInto(&out));
}

test "wire capture records a3 failure with a3_len zero" {
    wire.resetForTest();
    fake_mem = .{ .fail_a3 = true };
    wire.setReaderForTest(&fakeRead);
    wire.beginSession(4242);
    try std.testing.expect(wire.captureWith(&fakeRead, 0, 4242, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    var out: [wire.RECORD_SIZE]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 1), wire.drainInto(&out));
    try std.testing.expectEqual(@as(u32, 1), readU32At(&out, 0)); // valid
    try std.testing.expectEqual(@as(u32, 0), readU32At(&out, 40)); // a3_len
    try std.testing.expectEqual(@as(u32, 944), readU32At(&out, 48)); // ctx_len
}

test "wire capture stores one level of pointer windows and drops on ring full" {
    wire.resetForTest();
    fake_mem = .{};
    std.mem.writeInt(u64, fake_mem.ctx[0x10..0x18], FakeMem.TARGET_ADDR, .little);
    fake_mem.target[0] = 0xAB;
    wire.setReaderForTest(&fakeRead);
    wire.setRingCapForTest(1);
    wire.beginSession(4242);
    try std.testing.expect(wire.captureWith(&fakeRead, 0, 4242, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    try std.testing.expect(wire.captureWith(&fakeRead, 0, 4242, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    var stats: [wire.STATS_SIZE]u8 = undefined;
    try std.testing.expect(wire.statsInto(&stats));
    try std.testing.expectEqual(@as(u32, 1), readU32At(&stats, 4)); // records
    try std.testing.expectEqual(@as(u32, 1), readU32At(&stats, 8)); // dropped
    var out: [wire.RECORD_SIZE]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 1), wire.drainInto(&out));
    try std.testing.expectEqual(@as(u32, 0), readU32At(&out, 8)); // serial
    try std.testing.expectEqual(@as(u32, 1), readU32At(&out, 44)); // ptr_count
    try std.testing.expectEqual(FakeMem.TARGET_ADDR, std.mem.readInt(u64, out[1256..1264], .little));
    try std.testing.expectEqual(@as(u8, 0xAB), out[1320]); // 窗首字节
}

test "wire drain requires a full buffer and clears the ring" {
    wire.resetForTest();
    fake_mem = .{};
    wire.setReaderForTest(&fakeRead);
    wire.beginSession(4242);
    try std.testing.expect(wire.captureWith(&fakeRead, 0, 4242, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    try std.testing.expect(wire.captureWith(&fakeRead, 0, 4242, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    var one: [wire.RECORD_SIZE]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 0), wire.drainInto(&one));
    var two: [2 * wire.RECORD_SIZE]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 2), wire.drainInto(&two));
    try std.testing.expectEqual(@as(u32, 0), readU32At(&two, 8)); // 第一条 serial
    try std.testing.expectEqual(@as(u32, 1), readU32At(&two, 8 + 3368)); // 第二条 serial
    try std.testing.expectEqual(@as(u32, 0), wire.drainInto(&two));
}

test "wire resolveWith reads direct and one-level specs" {
    wire.resetForTest();
    fake_mem = .{};
    std.mem.writeInt(u32, fake_mem.ctx[0x38..0x3c], 200, .little);
    std.mem.writeInt(u64, fake_mem.ctx[0x10..0x18], FakeMem.TARGET_ADDR, .little);
    std.mem.writeInt(u32, fake_mem.target[0x20..0x24], 578, .little);
    const direct = wire.Spec{ .blob = 0, .deref = 0, .off_a = 0x38, .off_b = 0 };
    const deref = wire.Spec{ .blob = 0, .deref = 1, .off_a = 0x10, .off_b = 0x20 };
    try std.testing.expectEqual(@as(?u32, 200), wire.resolveWith(&fakeRead, direct, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    try std.testing.expectEqual(@as(?u32, 578), wire.resolveWith(&fakeRead, deref, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    fake_mem.fail_target = true;
    try std.testing.expectEqual(@as(?u32, null), wire.resolveWith(&fakeRead, deref, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    fake_mem.fail_target = false;
    std.mem.writeInt(u32, fake_mem.ctx[0x38..0x3c], 787, .little);
    try std.testing.expectEqual(@as(?u32, null), wire.resolveWith(&fakeRead, direct, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
}

test "wire capture never calls JS and never chains" {
    wire.resetForTest();
    fake_mem = .{};
    wire.setReaderForTest(&fakeRead);
    wire.beginSession(4242);
    try std.testing.expect(wire.setMode(1));
    try liveCtx();
    try std.testing.expectEqual(@as(c_int, 0), C2ExecArmScores(chokepoint_table.scores[0..].ptr, @intCast(chokepoint_table.SCORE_COUNT), 4242, 16, 100, 200));
    try std.testing.expect(!wire.onExecuteWith(&fakeRead, 4242, 0, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    var buf: [1024]u8 = undefined;
    const n = C2ExecScoredStats(&buf, @intCast(buf.len));
    try std.testing.expect(std.mem.indexOf(u8, buf[0..@intCast(n)], "scored_calls=0") != null);
    _ = C2ExecDisarmState();
}

test "wire stats and layout carry every field" {
    wire.resetForTest();
    fake_mem = .{};
    wire.setReaderForTest(&fakeRead);
    wire.beginSession(77);
    try std.testing.expect(wire.setMode(1));
    try std.testing.expect(wire.captureWith(&fakeRead, 0, 77, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    var stats: [wire.STATS_SIZE]u8 = undefined;
    try std.testing.expect(wire.statsInto(&stats));
    try std.testing.expectEqual(@as(u32, 1), readU32At(&stats, 0)); // mode=capture
    try std.testing.expectEqual(@as(u32, 1), readU32At(&stats, 4)); // records
    try std.testing.expectEqual(@as(u32, 1), readU32At(&stats, 12)); // calls
    try std.testing.expectEqual(@as(u32, 77), readU32At(&stats, 52)); // armed_token
    var layout: [8]u32 = undefined;
    try std.testing.expectEqual(@as(u32, 8), wire.layoutInto(&layout));
    try std.testing.expectEqualSlices(u32, &[_]u32{ 1, 1, 3368, 2048, 944, 256, 8, 256 }, &layout);
}

test "readProcessMemory is inert off Windows" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var b = [_]u8{0} ** 4;
    try std.testing.expect(!windows.readProcessMemory(@intFromPtr(&b), &b));
}

test "wire off mode keeps the legacy sentinel path" {
    vtable.resetForTest();
    wire.resetForTest();
    try liveCtx();
    try std.testing.expectEqual(@as(c_int, 0), C2ExecArmToken(4242, 4));
    const donor = fakeDonorSlots();
    try vtable.buildFromSlots(donor[0..]);
    const vt = vtable.getVtable() orelse return error.NoVtable;
    const exec: *const fn (u64, u64, u64) callconv(.c) u64 = @ptrFromInt(vt[1]);
    var obj: [64]u8 align(8) = [_]u8{0} ** 64;
    std.mem.writeInt(u32, obj[0x20..0x24], 4242, .little);
    const self = @intFromPtr(&obj);
    donor_calls = 0;
    try std.testing.expectEqual(@as(u64, 0), exec(self, 0x1234, 0));
    var buf: [512]u8 = undefined;
    const n = C2ExecStats(&buf, @intCast(buf.len));
    try std.testing.expect(std.mem.indexOf(u8, buf[0..@intCast(n)], "js_ok=1") != null);
    try std.testing.expectEqual(@as(u32, 0), donor_calls);
    vtable.setChainEnabled(true);
    try std.testing.expectEqual(@as(u64, 0xD0), exec(self, 0x1234, 0));
    try std.testing.expectEqual(@as(u32, 1), donor_calls);
    _ = C2ExecDisarmState();
}

test "wire capture mode records the call and never chains" {
    vtable.resetForTest();
    wire.resetForTest();
    try liveCtx();
    fake_mem = .{};
    wire.setReaderForTest(&fakeRead);
    wire.beginSession(4242);
    try std.testing.expect(wire.setMode(1));
    const donor = fakeDonorSlots();
    try vtable.buildFromSlots(donor[0..]);
    vtable.setChainEnabled(true); // chain 开关为真也不许在 capture 模式链
    const vt = vtable.getVtable() orelse return error.NoVtable;
    const exec: *const fn (u64, u64, u64) callconv(.c) u64 = @ptrFromInt(vt[1]);
    var obj: [64]u8 align(8) = [_]u8{0} ** 64;
    std.mem.writeInt(u32, obj[0x20..0x24], 4242, .little);
    donor_calls = 0;
    try std.testing.expectEqual(@as(u64, 0), exec(@intFromPtr(&obj), FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    var stats: [wire.STATS_SIZE]u8 = undefined;
    try std.testing.expect(wire.statsInto(&stats));
    try std.testing.expectEqual(@as(u32, 1), readU32At(&stats, 4)); // records
    try std.testing.expectEqual(@as(u32, 1), readU32At(&stats, 12)); // calls
    try std.testing.expectEqual(@as(u32, 0), donor_calls);
}

test "wire apply chains tier1 and tier2 but not tier0" {
    vtable.resetForTest();
    wire.resetForTest();
    try liveCtx();
    try std.testing.expectEqual(@as(c_int, 0), C2ExecArmScores(chokepoint_table.scores[0..].ptr, @intCast(chokepoint_table.SCORE_COUNT), 4242, 16, 100, 200));
    fake_mem = .{};
    wire.setReaderForTest(&fakeRead);
    wire.beginSession(4242);
    try std.testing.expect(wire.setSpecPacked(@as(u64, 0x38) << 16)); // 直读 ctx+0x38
    try std.testing.expect(wire.setMode(2));
    const donor = fakeDonorSlots();
    try vtable.buildFromSlots(donor[0..]); // chain_enabled 保持 false:apply 由 wire 决定
    const vt = vtable.getVtable() orelse return error.NoVtable;
    const exec: *const fn (u64, u64, u64) callconv(.c) u64 = @ptrFromInt(vt[1]);
    var obj: [64]u8 align(8) = [_]u8{0} ** 64;
    std.mem.writeInt(u32, obj[0x20..0x24], 4242, .little);
    const self = @intFromPtr(&obj);
    donor_calls = 0;
    const ids = [_]u32{ 0, 7, 578 };
    const want = [_]u64{ 0, 0xD0, 0xD0 };
    for (ids, want) |id, rc| {
        std.mem.writeInt(u32, fake_mem.ctx[0x38..0x3c], id, .little);
        try std.testing.expectEqual(rc, exec(self, FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    }
    try std.testing.expectEqual(@as(u32, 2), donor_calls);
    var stats: [wire.STATS_SIZE]u8 = undefined;
    try std.testing.expect(wire.statsInto(&stats));
    try std.testing.expectEqual(@as(u32, 3), readU32At(&stats, 16)); // resolved
    try std.testing.expectEqual(@as(u32, 0), readU32At(&stats, 20)); // unresolved
    try std.testing.expectEqual(@as(u32, 1), readU32At(&stats, 24)); // tier0
    try std.testing.expectEqual(@as(u32, 1), readU32At(&stats, 28)); // tier1
    try std.testing.expectEqual(@as(u32, 1), readU32At(&stats, 32)); // tier2
    try std.testing.expectEqual(@as(u32, 2), readU32At(&stats, 40)); // chain
    _ = C2ExecDisarmState();
}

test "wire rejects an invalid mode and an unset spec" {
    vtable.resetForTest();
    wire.resetForTest();
    try liveCtx();
    try std.testing.expect(!wire.setMode(3));
    try std.testing.expectEqual(wire.Mode.off, wire.mode());
    try std.testing.expectEqual(@as(c_int, 0), C2ExecArmScores(chokepoint_table.scores[0..].ptr, @intCast(chokepoint_table.SCORE_COUNT), 4242, 16, 100, 200));
    fake_mem = .{};
    wire.setReaderForTest(&fakeRead);
    wire.beginSession(4242);
    try std.testing.expect(wire.setMode(2));
    const donor = fakeDonorSlots();
    try vtable.buildFromSlots(donor[0..]);
    const vt = vtable.getVtable() orelse return error.NoVtable;
    const exec: *const fn (u64, u64, u64) callconv(.c) u64 = @ptrFromInt(vt[1]);
    var obj: [64]u8 align(8) = [_]u8{0} ** 64;
    std.mem.writeInt(u32, obj[0x20..0x24], 4242, .little);
    donor_calls = 0;
    try std.testing.expectEqual(@as(u64, 0), exec(@intFromPtr(&obj), FakeMem.CTX_ADDR, FakeMem.A3_ADDR));
    var stats: [wire.STATS_SIZE]u8 = undefined;
    try std.testing.expect(wire.statsInto(&stats));
    try std.testing.expectEqual(@as(u32, 1), readU32At(&stats, 20)); // unresolved
    try std.testing.expectEqual(@as(u32, 0), donor_calls);
    _ = C2ExecDisarmState();
}

test "donor install returns error.Unsupported off Windows" {
    try std.testing.expectError(error.Unsupported, donor_probe.install());
}

test "donor EXPECTED_CODE is the prologue bytes read from 0x3AFD30" {
    // Read off the exe copy with scripts/disrva.py and pinned by
    // scripts/test_c2_donor_probe.py — this array is the transcription, the
    // exe bytes are the authority.
    const expect = [24]u8{
        0x48, 0x89, 0x5C, 0x24, 0x10, // mov [rsp+0x10], rbx
        0x48, 0x89, 0x74, 0x24, 0x18, // mov [rsp+0x18], rsi
        0x48, 0x89, 0x7C, 0x24, 0x20, // mov [rsp+0x20], rdi
        0x55,                         // push rbp
        0x41, 0x54,                   // push r12
        0x41, 0x55,                   // push r13
        0x41, 0x56,                   // push r14
        0x41, 0x57,                   // push r15
    };
    try std.testing.expectEqual(@as(usize, 24), donor_probe.EXPECTED_CODE.len);
    try std.testing.expectEqualSlices(u8, &expect, &donor_probe.EXPECTED_CODE);
}

test "preflightChecks refuses when installed or when the patch is armed" {
    try donor_probe.preflightChecks(false, false);
    try std.testing.expectError(error.AlreadyInstalled, donor_probe.preflightChecks(true, false));
    try std.testing.expectError(error.PatchActive, donor_probe.preflightChecks(false, true));
    // installed is checked first: with both flags up the report is AlreadyInstalled.
    try std.testing.expectError(error.AlreadyInstalled, donor_probe.preflightChecks(true, true));
}
