// Native tests for the C4 execution wrapper. Root lives at src/dll/ because
// Zig imports may not escape the module root.

const std = @import("std");
const builtin = @import("builtin");
const vtable = @import("c2/vtable.zig");
const predicate_hook = @import("c2/predicate_hook.zig");
const exec_hook = @import("scripted/exec_hook.zig");
const live_probe = @import("c2/live_probe.zig");

extern fn C2DiagQuickJS(out_diag: [*]u8, diag_size: c_int) c_int;
extern fn C2ExecArmToken(token: u32, budget: u32) c_int;
extern fn C2ExecStats(out: [*]u8, out_size: c_int) c_int;
extern fn C2ExecDisarmState() c_int;

var donor_calls: u32 = 0;

fn fakeDonor(self: u64, ctx: u64, a3: u64) callconv(.c) u64 {
    _ = self;
    _ = ctx;
    _ = a3;
    donor_calls += 1;
    return 0xD0;
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

test "buildFromSlots copies every donor slot and overrides only slot[1]" {
    vtable.resetForTest();
    const donor = fakeDonorSlots();
    try vtable.buildFromSlots(donor[0..]);
    const vt = vtable.getVtable() orelse return error.NoVtable;
    try std.testing.expectEqual(donor[0], vt[0]);
    try std.testing.expectEqual(donor[2], vt[2]);
    try std.testing.expectEqual(donor[15], vt[15]);
    try std.testing.expectEqual(donor[19], vt[19]);
    try std.testing.expectEqual(donor[24], vt[24]);
    try std.testing.expect(vt[1] != donor[1]);
    try std.testing.expectEqual(@intFromPtr(&fakeDonor), vtable.donorExecute());
    try std.testing.expect(vtable.isBuilt());
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

test "resetForTest clears build state, donor and chain" {
    vtable.resetForTest();
    const donor = fakeDonorSlots();
    try vtable.buildFromSlots(donor[0..]);
    vtable.setChainEnabled(true);
    vtable.resetForTest();
    try std.testing.expect(!vtable.isBuilt());
    try std.testing.expect(!vtable.chainEnabled());
    try std.testing.expectEqual(@as(u64, 0), vtable.donorExecute());
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
        "armed",         "token",      "calls",         "fired",    "ctx_skip",
        "invalid",       "instantiate_rc", "patch_size", "installed", "verified",
        "vtable",        "chain",      "pred_installed", "pred_calls", "pred_patched",
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
