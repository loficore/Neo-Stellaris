// c2_diag_test.zig — Native execution test for the C2 QuickJS bootstrap step
// sequence. Runs the exact same steps that crashed the live game on
// 2026-10-08 (see evidence §32/§33): C2DiagQuickJS drives
// JS_NewRuntime2(custom mf) → opaque round-trip → JS_SetMaxStackSize →
// JS_SetMemoryLimit → JS_NewContextRaw + JS_FreeContext → JS_NewContextDiag,
// against the real vendored QuickJS compiled for this host.
//
// The externs below bind only the project's own quickjs_wrapper.c symbols
// (C2*, C2Write*, and that file's own JS_FreeValue/JS_DupValue/JS_NewString
// wrappers), never QuickJS C symbols — PLAN §6 blocker 1 workaround holds.
//
// On non-Windows targets quickjs_wrapper.c falls back to a libc-backed
// GetProcessHeap/HeapAlloc shim (same allocator logic, same accounting), so
// this test validates the accounting/ordering bugs that matter on Windows
// (heap_free use-after-free → malloc_size underflow → QuickJS OOM) natively.

const std = @import("std");
const qjs = @import("bindings.zig");

extern fn C2SanityCheck() c_int;
extern fn C2TestQuickJS() c_int;
extern fn C2DiagQuickJS(out_diag: [*]u8, diag_size: c_int) c_int;
extern fn C2DiagGetLog() ?[*:0]const u8;
extern fn C2GetQuickJSPointers(out_rt: *?*anyopaque, out_ctx: *?*anyopaque) void;
extern fn C2WriteQuickJSPointersInto(out16: [*]u8) void;

// Task 6 (ruling P19): these three are quickjs_wrapper.c's OWN reimplementations
// of quickjs.h's static-inline helpers — they are our C symbols, not QuickJS C
// symbols, so binding them here does not violate the "bind QuickJS in C only"
// constraint (the bindings.zig equivalents are a separate Zig implementation).
extern fn JS_FreeValue(ctx: ?*qjs.JSContext, v: qjs.JSValue) void;
extern fn JS_DupValue(ctx: ?*qjs.JSContext, v: qjs.JSValue) qjs.JSValue;
extern fn JS_NewString(ctx: ?*qjs.JSContext, str: [*:0]const u8) qjs.JSValue;

// Task 6: our own wrapper symbol (quickjs_wrapper.c), never a QuickJS C symbol.
extern fn C2EvalProbe(src: [*:0]const u8) c_int;

/// Drive the full bootstrap sequence and hand back the LIVE context, so a
/// value-level test below has a real ctx (passing NULL would make the pre-fix
/// `__JS_FreeValue(ctx, v)` die on `ctx->rt` instead of on QuickJS's
/// `default: abort()`, which would hide the defect being pinned).
fn liveContext() !*qjs.JSContext {
    var diag: [512]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), C2DiagQuickJS(&diag, @intCast(diag.len)));
    var rt: ?*anyopaque = null;
    var ctx: ?*anyopaque = null;
    C2GetQuickJSPointers(&rt, &ctx);
    try std.testing.expect(rt != null);
    const c = ctx orelse return error.NoContext;
    return @ptrCast(c);
}

/// Prove the runtime/context survived the call under test: re-run the bootstrap
/// sequence on the same process and require rc=0 (a corrupted heap accounting or
/// an aborted runtime cannot produce that).
fn assertRuntimeStillHealthy() !void {
    try std.testing.expectEqual(@as(c_int, 0), C2TestQuickJS());
}

test "C2EvalProbe returns 0 while g_test_ctx is NULL (no init has run yet)" {
    // Task 6 review-focus guard: `if (!g_test_ctx) return 0;` must be the FIRST
    // thing the probe does, so a dispatch before C2Init reports "init not run"
    // instead of dereferencing NULL inside JS_Eval.
    //
    // DECLARATION ORDER IS LOAD-BEARING: this is deliberately the first test in
    // this file, because g_test_ctx is a DLL-static that nothing here frees —
    // once any later test runs an init path, the NULL state is gone for the rest
    // of the process. The live equivalent (brief Step 6 / ruling P22) injects a
    // SECOND copy of the same bytes under its own filename, which gets its own
    // zero-initialised statics; a single host process cannot, so this test stands
    // in for that and is only valid run first. The precondition below is asserted
    // rather than assumed: if the runner ever reorders, or a future test
    // initializes earlier, this fails loudly as an ordering violation instead of
    // silently passing with a live context. No other test depends on this one's
    // position — each drives its own init.
    var rt: ?*anyopaque = null;
    var ctx: ?*anyopaque = null;
    C2GetQuickJSPointers(&rt, &ctx);
    if (rt != null or ctx != null) {
        std.debug.print(
            "\nprecondition violated: an earlier test already ran an init path (rt={x} ctx={x})\n",
            .{ @intFromPtr(rt), @intFromPtr(ctx) },
        );
        return error.InitRanBeforeThisTest;
    }

    try std.testing.expectEqual(@as(c_int, 0), C2EvalProbe("1+1"));
}

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

test "C2WriteQuickJSPointersInto returns rt/ctx bit-identical to C2GetQuickJSPointers" {
    // Task 5 observation path (ruling P4): after a full rc=0 run, the 16-byte
    // buffer must carry the EXACT native-width pointers, not a low-32 shadow.
    // Equality against C2GetQuickJSPointers — the direct read of the same two
    // statics — is the real proof the observation path returns the actual
    // runtime/context; nonzero-of-a-truncated-value proves nothing.
    var diag: [512]u8 = undefined;
    const rc = C2DiagQuickJS(&diag, @intCast(diag.len));
    try std.testing.expectEqual(@as(c_int, 0), rc);

    var out16: [16]u8 align(@alignOf(usize)) = undefined;
    C2WriteQuickJSPointersInto(&out16);

    var rt: ?*anyopaque = null;
    var ctx: ?*anyopaque = null;
    C2GetQuickJSPointers(&rt, &ctx);
    try std.testing.expect(rt != null);
    try std.testing.expect(ctx != null);

    const rt_bits = std.mem.bytesToValue(usize, out16[0..@sizeOf(usize)]);
    const ctx_bits = std.mem.bytesToValue(usize, out16[@sizeOf(usize).. @sizeOf(usize) * 2]);
    try std.testing.expectEqual(@intFromPtr(rt), rt_bits);
    try std.testing.expectEqual(@intFromPtr(ctx), ctx_bits);
}

test "C2WriteQuickJSPointersInto writes exactly 16 bytes and nothing outside" {
    // The live caller VirtualAllocEx's exactly 16 bytes; an overwrite of a
    // neighbour would corrupt the injector's buffer, so 32 guard bytes flank
    // the window and must survive untouched. Pre-fill 0xAA throughout: all 16
    // written bytes must end up accounted for by the two pointers (they are
    // real non-NULL addresses, never an 0xAA pattern).
    var diag: [512]u8 = undefined;
    const rc = C2DiagQuickJS(&diag, @intCast(diag.len));
    try std.testing.expectEqual(@as(c_int, 0), rc);

    var region: [32 + 16 + 32]u8 align(@alignOf(usize)) = undefined;
    for (&region) |*b| b.* = 0xAA;
    const buf = region[32..48];
    C2WriteQuickJSPointersInto(buf.ptr);

    for (region[0..32]) |b| try std.testing.expectEqual(@as(u8, 0xAA), b);
    for (region[48..80]) |b| try std.testing.expectEqual(@as(u8, 0xAA), b);

    var rt: ?*anyopaque = null;
    var ctx: ?*anyopaque = null;
    C2GetQuickJSPointers(&rt, &ctx);
    const rt_bits = std.mem.bytesToValue(usize, buf[0..@sizeOf(usize)]);
    const ctx_bits = std.mem.bytesToValue(usize, buf[@sizeOf(usize).. @sizeOf(usize) * 2]);
    try std.testing.expectEqual(@intFromPtr(rt), rt_bits);
    try std.testing.expectEqual(@intFromPtr(ctx), ctx_bits);
}

// ---------------------------------------------------------------------------
// Ruling P19 — the two wrapper defects Task 6 must fix before it can dispatch.
//
// quickjs_wrapper.c hand-forwards QuickJS's 16-byte JSValue and re-implements
// quickjs.h's static-inline refcount helpers. Both reimplementations were wrong:
//
//   * `#define JS_VALUE_HAS_REF_COUNT(v) (((uint32_t)((v).tag)) >= (uint32_t)7)`
//     vs quickjs.h:287 `((unsigned)JS_VALUE_GET_TAG(v) >= (unsigned)JS_TAG_FIRST)`
//     with JS_TAG_FIRST = -9 (quickjs.h:77), i.e. true for tags -9..-1 ONLY.
//     `>= 7` wrongly admits JS_TAG_SHORT_BIG_INT (7) and JS_TAG_FLOAT64 (8)
//     (quickjs.h:93-94); for those, JS_VALUE_GET_PTR is the number's OWN bit
//     pattern read as an address, so JS_DupValue wrote a refcount through a wild
//     pointer (1.5 -> 0x3FF8000000000000 - 4).
//   * `JS_FreeValue` called `__JS_FreeValue(ctx, v)` unconditionally, with no
//     JS_VALUE_HAS_REF_COUNT guard and no decrement-to-zero test.
//     __JS_FreeValueRT (quickjs.c:6473) switches on the tag and ends in
//     `default: abort()` (quickjs.c:6571-6572), so freeing a JS_TAG_INT /
//     JS_TAG_EXCEPTION / JS_TAG_FLOAT64 value aborted the host process. Inside
//     stellaris.exe that is a self-inflicted game death — and JS_Eval("1+1")
//     returns exactly a JS_TAG_INT value, which Task 6's probe frees.
//
// These tests pin the CORRECTED behaviour at the value level against a live
// context, and were the RED step. Observed pre-fix (each run alone with
// `zig test --test-filter`, same command line as the build step):
//   * free test      -> the whole test binary "terminated with signal ABRT"
//                       (quickjs.c:6572 abort(), no Zig trace — a C-side abort).
//   * dup test       -> "General protection exception (no address available)"
//                       traced to `quickjs_wrapper.c:104:21 in JS_DupValue
//                       (p->ref_count++)`, then ABRT via Zig's signal handler.
//   * string test    -> clean assertion failure "expected 1, found 2": the
//                       unconditional free released a string whose header still
//                       counted 2 holders, and never decremented it.
// ---------------------------------------------------------------------------

test "P19: JS_FreeValue on non-refcounted tags returns instead of aborting" {
    const ctx = try liveContext();

    // Every tag quickjs.h classifies as NON-refcounted (0..8). JS_TAG_INT with
    // payload 2 is literally what `JS_Eval("1+1")` hands back.
    JS_FreeValue(ctx, qjs.JSValue.int32(2)); // tag 0
    JS_FreeValue(ctx, qjs.JSValue.boolVal(true)); // tag 1
    JS_FreeValue(ctx, qjs.JSValue.nullVal()); // tag 2
    JS_FreeValue(ctx, qjs.JSValue.undefinedVal()); // tag 3
    JS_FreeValue(ctx, qjs.JSValue{ .u = .{ .uint64 = 0 }, .tag = @intFromEnum(qjs.JSValueTag.exception) }); // tag 6
    JS_FreeValue(ctx, qjs.JSValue{ .u = .{ .short_big_int = 7 }, .tag = 7 }); // short bigint
    JS_FreeValue(ctx, qjs.JSValue.float64(1.5)); // tag 8

    // Reaching the line below is the assertion: pre-fix abort() fired inside the
    // first call. Prove the runtime is still usable afterwards.
    try assertRuntimeStillHealthy();
}

test "P19: JS_DupValue on JS_TAG_FLOAT64 / SHORT_BIG_INT writes outside nothing" {
    const ctx = try liveContext();

    // Pre-fix these two dups wrote through 0x3FF8000000000000-4 / 0x7-4: the
    // number's own bits as an address (SIGSEGV on the first, unmapped).
    const f = qjs.JSValue.float64(1.5);
    const df = JS_DupValue(ctx, f);
    try std.testing.expectEqual(@as(i64, 8), df.tag);
    try std.testing.expectEqual(f.u.uint64, df.u.uint64);

    const sbi = qjs.JSValue{ .u = .{ .short_big_int = 7 }, .tag = 7 };
    const dsbi = JS_DupValue(ctx, sbi);
    try std.testing.expectEqual(@as(i64, 7), dsbi.tag);
    try std.testing.expectEqual(@as(u64, 7), dsbi.u.uint64);

    // A dup that is a no-op must leave the value freeable: this is the exact
    // sequence JS_Eval("1.5") produces (a JS_TAG_FLOAT64 result that the caller
    // later frees). Pre-fix: dup corrupted memory, free aborted.
    JS_FreeValue(ctx, df);
    JS_FreeValue(ctx, dsbi);
    try assertRuntimeStillHealthy();
}

test "P19 fix keeps genuinely refcounted tags refcounted (real JS string)" {
    // Guards against over-correcting the macro bound: tag -7 (JS_TAG_STRING) is
    // refcounted and MUST still be duped/freed through the header 4 bytes before
    // the pointer (quickjs.h:682-685, mirrored by the wrapper's __js_rc).
    // Pre-fix this failed too: JS_FreeValue ignored the refcount and called
    // __JS_FreeValueRT outright, releasing a string that still had a holder.
    const ctx = try liveContext();

    const str = JS_NewString(ctx, "neo_stellaris_c2_probe");
    try std.testing.expect(str.u.ptr != null);
    try std.testing.expectEqual(@as(i64, -7), str.tag); // JS_TAG_STRING

    const rc: *u32 = @ptrFromInt(@intFromPtr(str.u.ptr.?) - 4);
    const initial = rc.*;
    try std.testing.expect(initial >= 1);

    _ = JS_DupValue(ctx, str);
    try std.testing.expectEqual(initial + 1, rc.*);

    JS_FreeValue(ctx, str); // 2 -> 1: must NOT free; the header is still readable
    try std.testing.expectEqual(initial, rc.*);

    JS_FreeValue(ctx, str); // 1 -> 0: now __JS_FreeValue releases it for real
    // `rc` points into the freed block from here on — never read it again.
    try assertRuntimeStillHealthy();
}

// ---------------------------------------------------------------------------
// Task 6 — C2EvalProbe: the C2 acceptance gate, natively.
//
// Contract (fixed by the brief, kept verbatim):
//   0         = g_test_ctx NULL (init not run)
//   1         = JS_Eval threw
//   2         = eval succeeded but the value is not an int32
//   n * 4 + 3 = eval succeeded and returned int32 n   (caller decodes (rc-3)/4)
// Ruling P20: `1+1` yields n = 2, so the expected rc is 11 — NOT the brief's
// "1*4+3 = 7", which came from reading the wrong value; the ENCODING is the
// contract and stands (n*4+3 is always 3 mod 4, so it cannot collide with 0/1/2).
// Ruling P21: this is the first code that hands a real JSValue (returned by
// JS_Eval) across the Zig<->C boundary by value in BOTH directions — through the
// wrapper's hand-forwarded 16-byte struct, since quickjs_wrapper.c includes no
// quickjs.h. These tests are that crossing's proof; the x86-64 non-NAN-boxed
// layout that makes it legal is pinned by the passing rc below.
//
// Note the Zig export C2EvalProbeOnePlusOne (src/dll/exports.zig) is a one-line
// forwarder to this C symbol with the fixed string "1+1"; it is NOT exercised
// here because exports.zig-rooted tests do not link on the Linux host (ledgered
// as P15) — its PE export name is verified by re-parsing the built DLL, and its
// behaviour by the live probe.
// ---------------------------------------------------------------------------

test "C2EvalProbe(\"1+1\") returns 11, decoding to int32 2" {
    var diag: [512]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), C2DiagQuickJS(&diag, @intCast(diag.len)));

    const rc = C2EvalProbe("1+1");
    try std.testing.expectEqual(@as(c_int, 11), rc);
    // The decode the harness performs, asserted on the same arithmetic:
    try std.testing.expectEqual(@as(c_int, 2), @divTrunc(rc - 3, 4));
    // Discriminant property from the contract: a decoded value never collides
    // with the 0/1/2 sentinels.
    try std.testing.expectEqual(@as(c_int, 3), @mod(rc, 4));
}

test "C2EvalProbe on a float result (JS_TAG_FLOAT64) is freed, not aborted" {
    // `1.5` evaluates to a JS_TAG_FLOAT64 value; JS_ToInt32 truncates it to 1,
    // and the probe then frees the FLOAT64. Pre-fix that free wrote through the
    // number's own bits as an address / reached quickjs.c's abort() (ruling P19).
    var diag: [512]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), C2DiagQuickJS(&diag, @intCast(diag.len)));

    const rc = C2EvalProbe("1.5");
    try std.testing.expectEqual(@as(c_int, 7), rc); // n = 1
    try std.testing.expectEqual(@as(c_int, 1), @divTrunc(rc - 3, 4));
}

test "C2EvalProbe on unparseable JS returns 1 and leaves the context usable" {
    var diag: [512]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), C2DiagQuickJS(&diag, @intCast(diag.len)));

    // JS_Eval returns the JS_TAG_EXCEPTION *marker* (tag 6) here. Pre-fix the
    // probe's JS_FreeValue handed that straight to __JS_FreeValueRT, whose
    // switch has no case for tag 6 -> default: abort().
    try std.testing.expectEqual(@as(c_int, 1), C2EvalProbe("this_is_not_valid_js ~~"));

    // The pending exception must not be left in the runtime either: the same
    // context has to serve the next eval, or this gate could be dispatched only
    // once per injection.
    try std.testing.expectEqual(@as(c_int, 11), C2EvalProbe("1+1"));
}

test "C2EvalProbe on a value JS_ToInt32 cannot convert returns 2" {
    var diag: [512]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), C2DiagQuickJS(&diag, @intCast(diag.len)));

    // An object whose valueOf throws: ToNumber propagates the exception, so
    // JS_ToInt32 returns -1 and the probe reports "not an int32" (rc 2) after
    // releasing the refcounted object (tag -1) it was handed.
    try std.testing.expectEqual(@as(c_int, 2), C2EvalProbe("({ valueOf() { throw 1; } })"));
    try std.testing.expectEqual(@as(c_int, 11), C2EvalProbe("1+1"));
}

// ---------------------------------------------------------------------------
// Cross-thread stack guard (final whole-branch review's Important finding).
//
// CONFIG_STACK_CHECK is compiled for every non-Emscripten target
// (quickjs.c:75-77). JS_NewRuntime2 captures rt->stack_top exactly once
// (quickjs.c:2116 -> JS_UpdateStackTop, quickjs.c:2897-2900) on WHICHEVER
// thread created the runtime, and JS_SetMaxStackSize(rt, 1 MiB) sets
// stack_limit = stack_top - 1 MiB (quickjs.c:2882-2895). js_check_stack_overflow
// (quickjs.c:2059-2064) then compares the EVALUATING thread's sp against that
// stale limit. The live C2 sequence dispatches C2Init on CreateRemoteThread A
// and C2EvalProbeOnePlusOne on a different CreateRemoteThread B — exactly the
// "changing thread" case quickjs.h:376-378 documents ("should be called when
// changing thread"), which only the public JS_UpdateStackTop can service.
//
// The refresh call itself lives in quickjs_wrapper.c (C, per the constraint
// that no Zig file binds a QuickJS C symbol — bindings.zig:345's declaration
// stays unused by the live path).
//
// What THIS test can and cannot prove:
//   * It IS a real two-thread reproduction: init on the main thread captures
//     the main stack top (~0x7ffc/0x7ffe.. here, 3/3 prototype runs);
//     std.Thread.spawn gives B a fresh mmap'd pthread stack (~0x7f.., a
//     100s-of-GB gap below main's top), so B's entry sp < stack_limit_stale
//     and the unfixed guard throws a spurious StackOverflow -> rc 1 (observed
//     RED). The precondition assert below pins that layout, so a libc that
//     ever placed B above main_top - 1 MiB fails loudly instead of passing
//     vacuously.
//   * The literal live order (A inits then EXITS, then B spawns) was tried
//     first and is VACUOUS on this host: every run lands B on A's exact stack
//     segment — B's thread-local address equalled A's 10/10 prototype runs,
//     even at unequal stack sizes (glibc cached-stack reuse, or an
//     indistinguishable same-address remap; the mechanism does not matter,
//     the address identity does) — so B inherits A's top and the stale guard
//     looks correct either way. That is a host-layout accident; on Windows the
//     freed thread stack is returned to the OS and B lands elsewhere — the
//     defect stands.
//   * The CROSS-THREAD CORRECTNESS argument (that refreshing to B's own sp is
//     the right fix) rests on the QuickJS API contract at quickjs.h:376-378,
//     not on this test; the test pins that the refresh links, runs before
//     JS_Eval (a call placed after it would leave rc 1), and does not break an
//     otherwise-successful evaluation.
// ---------------------------------------------------------------------------

test "C2EvalProbe on a lower-stack thread (runtime built on main) returns 11, not stale-guard 1" {
    var layout_delta: i64 = undefined;
    var rc: c_int = undefined;

    // Capture a main-thread stack address to compare against, then build the
    // runtime HERE so rt->stack_top belongs to the main thread.
    var main_local: u8 = 0;
    const main_addr = @intFromPtr(&main_local);

    var diag: [512]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), C2DiagQuickJS(&diag, @intCast(diag.len)));

    const t = try std.Thread.spawn(.{}, struct {
        fn threadFn(out_rc: *c_int, out_delta: *i64, anchor: usize) void {
            var b_local: u8 = 0;
            // Signed, so an inverted layout (B above anchor) reads NEGATIVE and
            // trips the precondition below instead of wrapping huge and passing
            // the test vacuously.
            out_delta.* = @as(i64, @bitCast(anchor)) -% @as(i64, @bitCast(@intFromPtr(&b_local)));
            out_rc.* = C2EvalProbe("1+1");
        }
    }.threadFn, .{ &rc, &layout_delta, main_addr });
    t.join();

    // Layout precondition (deterministic on Linux x86-64: main stack sits at
    // the top of the task address space, pthread stacks mmap far below). If
    // this ever trips, the test no longer reproduces anything — fail loudly.
    try std.testing.expect(layout_delta > 1024 * 1024);

    // The assertion proper: with the refresh, QuickJS re-anchors stack_top to
    // B's own frame and `1+1` evaluates (rc 11). Without it, JS_Eval throws a
    // spurious stack overflow and the probe reports sentinel rc 1 — the exact
    // wrong-diagnosis path SENTINEL_DIAGNOSIS[1] would have sent the human
    // partner down on the live shot.
    try std.testing.expectEqual(@as(c_int, 11), rc);

    // The same context still serves afterwards (refresh left it usable):
    try std.testing.expectEqual(@as(c_int, 11), C2EvalProbe("1+1"));
}
