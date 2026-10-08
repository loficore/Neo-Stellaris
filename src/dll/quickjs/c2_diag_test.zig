// c2_diag_test.zig — Native execution test for the C2 QuickJS bootstrap step
// sequence. Runs the exact same steps that crashed the live game on
// 2026-10-08 (see evidence §32/§33): C2DiagQuickJS drives
// JS_NewRuntime2(custom mf) → opaque round-trip → JS_SetMaxStackSize →
// JS_SetMemoryLimit → JS_NewContextRaw + JS_FreeContext → JS_NewContextDiag,
// against the real vendored QuickJS compiled for this host.
//
// The externs below bind only the project's own quickjs_wrapper.c symbols
// (C2*/Get*), never QuickJS C symbols — PLAN §6 blocker 1 workaround holds.
//
// On non-Windows targets quickjs_wrapper.c falls back to a libc-backed
// GetProcessHeap/HeapAlloc shim (same allocator logic, same accounting), so
// this test validates the accounting/ordering bugs that matter on Windows
// (heap_free use-after-free → malloc_size underflow → QuickJS OOM) natively.

const std = @import("std");

extern fn C2SanityCheck() c_int;
extern fn C2TestQuickJS() c_int;
extern fn C2DiagQuickJS(out_diag: [*]u8, diag_size: c_int) c_int;
extern fn C2DiagGetLog() ?[*:0]const u8;
extern fn C2GetQuickJSPointers(out_rt: *?*anyopaque, out_ctx: *?*anyopaque) void;

test "C2SanityCheck returns 42" {
    try std.testing.expectEqual(@as(c_int, 42), C2SanityCheck());
}

test "C2DiagQuickJS completes the live-crash step sequence with rc=0" {
    var buf: [512]u8 = undefined;
    for (&buf) |*b| b.* = 0xAA;
    const rc = C2DiagQuickJS(&buf, @intCast(buf.len));

    // 0 means: heap ok, runtime created, opaque ok, raw ctx created+freed,
    // and all 11 intrinsics built. Any nonzero rc here reproduces the
    // bootstrap failure (2026-10-08: rc=2 = OOM from the heap_free
    // accounting underflow — see §33).
    try std.testing.expectEqual(@as(c_int, 0), rc);

    var rt: ?*anyopaque = null;
    var ctx: ?*anyopaque = null;
    C2GetQuickJSPointers(&rt, &ctx);
    try std.testing.expect(rt != null);
    try std.testing.expect(ctx != null);

    // The caller-supplied buffer must carry the log, NUL-terminated inside
    // the 512 bytes (the fixed strncpy contract).
    const written = std.mem.sliceTo(&buf, 0);
    const log = std.mem.span(C2DiagGetLog().?);
    try std.testing.expectEqualStrings(log, written);
    try std.testing.expect(std.mem.indexOf(u8, log, "raw_ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "diag_rc=0") != null);
}

test "C2TestQuickJS (sibling path) also reaches rc=0" {
    // Same sequence without the DLOG layer; historically returned 3 (opaque
    // mismatch) on 2026-10-07 from an older default-allocator build — this
    // now asserts the heap_mf path actually initializes fully.
    const rc = C2TestQuickJS();
    try std.testing.expectEqual(@as(c_int, 0), rc);
}
