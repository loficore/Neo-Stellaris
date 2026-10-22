// Native tests for the C4 execution wrapper. Root lives at src/dll/ because
// Zig imports may not escape the module root.

const std = @import("std");
const vtable = @import("c2/vtable.zig");

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
