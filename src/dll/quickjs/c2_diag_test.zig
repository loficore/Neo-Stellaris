// c2_diag_test.zig — Native execution test for the C2 QuickJS bootstrap step
// sequence. Runs the exact same steps that crashed the live game on
// 2026-10-08 (see evidence §32/§33): C2DiagQuickJS drives
// JS_NewRuntime2(custom mf) → opaque round-trip → JS_SetMaxStackSize →
// JS_SetMemoryLimit → JS_NewContextRaw + JS_FreeContext → JS_NewContextDiag,
// against the real vendored QuickJS compiled for this host.
//
// The externs below bind only the project's own quickjs_wrapper.c symbols
// (C2*, C2Write*, and that file's own JS_FreeValue/JS_DupValue/JS_NewString
// wrappers), never QuickJS C symbols — the "Zig extern fn binding a QuickJS C
// function crashes, so every QuickJS call goes through the C wrapper" constraint
// (docs/roadmap.md 段5) holds.
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

// Task 1 (allocator-record discrimination): the C ring recorder's renderer
// symbol (quickjs_wrapper.c), again OUR own symbol, never a QuickJS C symbol.
extern fn C2DiagMfRecords(out: [*]u8, out_size: c_int) c_int;

// Task 1 fix round: the test-only zero-size probe (quickjs_wrapper.c). Same
// precedent as the three wrappers above — it is this file's own C symbol, not a
// QuickJS C symbol, so binding it here does not violate the "bind QuickJS in C
// only" constraint. It is deliberately NOT a PE export and NOT declared in
// exports.zig: the injection channel cannot reach it (the plan's own
// C2ProbeMallocZero shape for Task 4, 「它不暴露给注入通道」), and it changes no
// allocator semantics — it only calls the existing static callbacks.
extern fn C2DiagMfProbeZeroSize() c_int;

/// Same-shape mirror of the PE export `C2DiagMfRecordsInto` (src/dll/exports.zig):
/// one pointer argument, the 4096-byte size baked into the contract and never
/// passed. The export itself cannot be what these tests call — exports.zig-rooted
/// tests do not link on the Linux host (ledgered as P15), so its symbol is not
/// present in this test binary — and the C file must not define a second
/// `C2DiagMfRecordsInto` either (duplicate link symbol with the Zig export, the
/// verified C2WriteQuickJSPointersInto precedent). This forwarder is the plan's
/// contract line for line, through the same C symbol the export delegates to.
fn C2DiagMfRecordsInto(out_diag: *[4096]u8) i32 {
    return C2DiagMfRecords(out_diag, 4096);
}

/// Ring capacity mirrored for the assertions below. The authority is the
/// `#define MF_REC_CAP 8` in quickjs_wrapper.c; it is deliberately NOT promised
/// as a Zig-visible symbol (Task 1 ruling 2), so this test declares it locally.
const MF_REC_CAP = 8;

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

// ---------------------------------------------------------------------------
// §36 (2026-10-21 live) — the two probe defects that made the shot unreadable.
//
// The live `C2Init rc = 3` could not be decoded, for two independent reasons,
// and both are pinned here:
//   (a) C2TestQuickJS wrote NO log. Only C2DiagQuickJS filled g_diag_log, and
//       C2Init does not go through it — so §32's "the log text is authoritative"
//       had nothing to point at. The step sequence is now one shared function
//       that always logs, and `C2CopyDiagLog` reads it back WITHOUT touching
//       QuickJS (a live read must not be another init dispatch in disguise).
//   (b) rc 2/3/4 meant two different things — the wrapper's own gates and
//       JS_NewContextDiag's intrinsic steps shared the numbers. The outer gates
//       moved to 100..104.
//
// Plus the reason the human partner asked about a pending exception: every
// failure branch of JS_NewContextDiag was `{ JS_FreeContext(ctx); return N; }`,
// so the context owning rt->current_exception was destroyed before any caller
// could look. The message is now captured INTO the caller's buffer before the
// free, and `C2DiagNewContextUnderMemoryLimit` exists so that path is testable
// natively instead of only on a live game.
// ---------------------------------------------------------------------------

extern fn C2CopyDiagLog(out: [*]u8) c_int;
extern fn C2DiagNewContextUnderMemoryLimit(mem_limit: usize, out_log: ?[*]u8, out_size: c_int) c_int;

/// A memory limit that lets `JS_NewContextRaw` succeed but starves the
/// evaluation of the base-object bootstrap source, so `JS_AddIntrinsicBaseObjects`
/// is the first step to fail — inner step 2. Our own `heap_malloc`
/// (quickjs_wrapper.c:162) returns NULL once `malloc_size + size > malloc_limit`,
/// which is what QuickJS turns into an out-of-memory exception.
///
/// Measured, not guessed (native sweep over this exact function, 4 KiB steps):
///   <= 92 KiB  step 1 — even JS_NewContextRaw cannot allocate
///   96..104    step 2 "BaseObjects: InternalError: out of memory"
///   108/112    step 2, tail "null" / "(exception not convertible to a string)"
///   116        step 2 again;  120/124 step 3;  128..136 step 10;  140 step 11
///   >= 256 KiB rc 0 (the whole intrinsic run fits)
/// 100 KiB sits in the middle of the step-2 band, so the assertions below hold
/// even if the allocator's per-step footprint shifts a little on another libc.
const OOM_MEM_LIMIT: usize = 100 * 1024;

test "C2TestQuickJS (the C2Init path) leaves a readable log — the §36.4 gap" {
    // Before §36 this function returned step codes and wrote nothing; the live
    // rc=3 therefore had no disambiguator. rc=0 still means success, and now the
    // log carries the same step text C2DiagQuickJS produces.
    try std.testing.expectEqual(@as(c_int, 0), C2TestQuickJS());

    var buf: [512]u8 = undefined;
    const n = C2CopyDiagLog(&buf);
    try std.testing.expect(n > 0);

    const log = std.mem.span(@as([*:0]const u8, @ptrCast(&buf)));
    try std.testing.expect(log.len > 0);
    // The success markers of the shared step sequence.
    try std.testing.expect(std.mem.indexOf(u8, log, "rt=") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "raw_ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "diag_rc=0") != null);
}

test "the shared sequence tags every step before the runtime exists" {
    // The 23:55 live shot polled the DLL's OWN g_diag_log static and found it empty
    // for the whole 6.9 s the host stayed readable, then unreadable at the instant
    // of death. A log whose first mark is `rt=` cannot separate "the thread never
    // ran" from "it died inside JS_NewRuntime2", so each operation before the
    // runtime exists has to leave its own mark — and the marks have to appear IN
    // ORDER, because the last one present is the answer the live probe is buying.
    try std.testing.expectEqual(@as(c_int, 0), C2TestQuickJS());

    var buf: [512]u8 = undefined;
    _ = C2CopyDiagLog(&buf);
    const log = std.mem.span(@as([*:0]const u8, @ptrCast(&buf)));

    const markers = [_][]const u8{
        "enter ",     "heap_ok ",   "alloc_ok ",  "free_ok ",
        "new_rt ",    "rt=",        "opaque_ok ", "limits_ok ",
        "new_raw ",   "raw_ok ",    "new_diag ",  "diag_rc=0",
    };
    var prev: ?usize = null;
    for (markers) |marker| {
        const at = std.mem.indexOf(u8, log, marker) orelse {
            std.debug.print("marker {s} absent from log: {s}\n", .{ marker, log });
            return error.MissingStepMarker;
        };
        if (prev) |p| {
            if (at <= p) {
                std.debug.print("marker {s} at {d} is not after the previous at {d}: {s}\n",
                               .{ marker, at, p, log });
                return error.StepMarkersOutOfOrder;
            }
        }
        prev = at;
    }
}

test "JS_NewRuntime2 calls back into heap_mf between new_rt and rt= (offline positive control)" {
    // heap_malloc is reached ONLY via the mf table (the sequence's own alloc_ok/
    // free_ok tags use HeapAlloc directly), so the first 'M' tag lands inside
    // JS_NewRuntime2. This offline run succeeds fully, so 'M' MUST appear after
    // the "new_rt " tag and before "rt=". That is the positive control the live
    // shot is interpreted against: alive, new_rt is followed by M; if the live
    // witness stops at "new_rt " with no M, JS_NewRuntime2 died in its own
    // prologue before the first allocation — a different target than "died
    // inside our allocator". Without this, a bare "new_rt " live read could just
    // as mean the instrumentation failed to compile in.
    try std.testing.expectEqual(@as(c_int, 0), C2TestQuickJS());

    var buf: [512]u8 = undefined;
    _ = C2CopyDiagLog(&buf);
    const log = std.mem.span(@as([*:0]const u8, @ptrCast(&buf)));

    const new_rt_at = std.mem.indexOf(u8, log, "new_rt ") orelse return error.MissingNewRtTag;
    const rt_at = std.mem.indexOf(u8, log, "rt=") orelse return error.MissingRtTag;
    try std.testing.expect(new_rt_at < rt_at);

    const between = log[new_rt_at + "new_rt ".len .. rt_at];
    try std.testing.expect(std.mem.indexOfScalar(u8, between, 'M') != null);

    // Review Focus 1 guard: the MF_TAG_CAP rate limit must keep the prefix
    // alive — if mf tagging overflowed the 512 buffer, "enter " would be gone
    // and the last tag read would be the buffer tail, not the death point.
    try std.testing.expect(std.mem.indexOf(u8, log, "enter ") != null);
    try std.testing.expect(std.mem.count(u8, between, "M") <= 8);
}

test "a completed heap_malloc always closes its M marker (offline no-dangling-M)" {
    // §42 read scheme: heap_malloc tags 'M' on entry and 'm' (returned a block)
    // or '!' (returned NULL) on exit. The live shot buys exactly one fact from
    // the tail — a DANGLING 'M' (nothing after it) means the host died inside
    // GetProcessHeap()/HeapAlloc, whereas 'Mm'/'M!' followed by more means the
    // allocation returned and death came later, inside QuickJS. That reading is
    // only sound if, on a run that does NOT die, no 'M' ever dangles — otherwise
    // a live dangling M could just be "the close tag is missing from the build".
    // Linux runs the whole JS_NewRuntime2 to completion, so here every M is
    // paired: assert the structural invariant, not counts (a malloc(0) returns
    // NULL and correctly yields M!).
    try std.testing.expectEqual(@as(c_int, 0), C2TestQuickJS());

    var buf: [512]u8 = undefined;
    _ = C2CopyDiagLog(&buf);
    const log = std.mem.span(@as([*:0]const u8, @ptrCast(&buf)));

    const new_rt_at = std.mem.indexOf(u8, log, "new_rt ") orelse return error.MissingNewRtTag;
    const rt_at = std.mem.indexOf(u8, log, "rt=") orelse return error.MissingRtTag;
    const between = log[new_rt_at + "new_rt ".len .. rt_at];
    try std.testing.expect(std.mem.indexOfScalar(u8, between, 'M') != null);

    var i: usize = 0;
    while (i < between.len) : (i += 1) {
        if (between[i] != 'M') continue;
        // An M at the very end of the window would be a dangling marker even on
        // a run that reaches rt= — impossible on the success path, so fail.
        if (i + 1 >= between.len) return error.DanglingMallocMarker;
        const nxt = between[i + 1];
        if (nxt != 'm' and nxt != '!') {
            std.debug.print("M at {d} followed by '{c}', expected m or !: {s}\n",
                            .{ i, nxt, between });
            return error.MallocMarkerNotClosed;
        }
    }
}

test "C2CopyDiagLog is a pure read: byte-identical to the buffer C2DiagQuickJS filled" {
    // The live read path must not re-run any QuickJS step: C2DiagQuickJS writes
    // out_diag from the same static this reads, so the two must agree exactly.
    var diag: [512]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), C2DiagQuickJS(&diag, @intCast(diag.len)));
    const from_call = std.mem.span(@as([*:0]const u8, @ptrCast(&diag)));

    var buf: [512]u8 = undefined;
    const n = C2CopyDiagLog(&buf);
    try std.testing.expect(n > 0);
    const from_read = std.mem.span(@as([*:0]const u8, @ptrCast(&buf)));

    try std.testing.expectEqualStrings(from_call, from_read);
    try std.testing.expectEqual(@as(c_int, @intCast(from_call.len)), n);

    // And the read left the runtime/context alone — a probe that re-initialized
    // would fail this, since re-init resets g_test_rt/g_test_ctx (§33/§34).
    try assertRuntimeStillHealthy();
    var rt: ?*anyopaque = null;
    var ctx: ?*anyopaque = null;
    C2GetQuickJSPointers(&rt, &ctx);
    try std.testing.expect(rt != null);
    try std.testing.expect(ctx != null);
}

test "JS_NewContextDiag hands back the failing stage plus the pending exception text" {
    // This is the whole point of the signature change: the message must survive
    // the JS_FreeContext in the failure branch.
    var log: [256]u8 = undefined;
    const rc = C2DiagNewContextUnderMemoryLimit(OOM_MEM_LIMIT, &log, @intCast(log.len));

    // Inner step 2 = JS_AddIntrinsicBaseObjects: the run got PAST this file's
    // outer gates (those read 100..104) and past step 1, the raw-context
    // allocation itself.
    try std.testing.expectEqual(@as(c_int, 2), rc);

    const msg = std.mem.span(@as([*:0]const u8, @ptrCast(&log)));
    try std.testing.expect(msg.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, msg, "BaseObjects: "));
    // Non-empty tail = QuickJS really had a pending exception and we caught it
    // before the context died. If the capture ran after JS_FreeContext, the tail
    // is empty (or the sentinel below) and this fails.
    const detail = msg["BaseObjects: ".len..];
    try std.testing.expect(detail.len > 0);
    try std.testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, detail, "(no pending exception)"));
}

test "JS_NewContextDiag still reports the step when the caller passes no buffer" {
    // The capture must not be load-bearing: a NULL out_log is the pre-§36 calling
    // convention (C2DiagQuickJS passes one, but a caller that cannot allocate a
    // buffer must still get the numeric step back, and must not crash).
    const rc = C2DiagNewContextUnderMemoryLimit(OOM_MEM_LIMIT, null, 0);
    try std.testing.expectEqual(@as(c_int, 2), rc);
}

// ---------------------------------------------------------------------------
// §38 (2026-10-21 live) — the diagnostic has to LEAVE the process.
//
// Both 2026-10-21 shots lost the host right after the remote thread returned its
// exit code, and the 22:47 one settled the question of how much read-back can be
// salvaged: it used the one-shot shape, so the log had already been copied into
// the caller's remote buffer *inside* the dispatch, and the very next
// ReadProcessMemory of that buffer returned ERROR_PARTIAL_COPY (gle 299). Text
// that lives in the dying address space is gone with it. So c2_diag_sequence now
// appends "rc=<n> <log>" to a per-pid file before returning, and the live probe
// deletes that file pre-dispatch and reads it afterwards — a channel that works
// whether or not the host is still there.
// ---------------------------------------------------------------------------

const DIAG_FILE_DIR = if (@import("builtin").os.tag == .windows) "C:/temp" else "/tmp";

fn diagFilePath(buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{s}/c2_diag_{d}.log", .{ DIAG_FILE_DIR, std.c.getpid() }) catch {
        @panic("diag file path does not fit in the caller's buffer");
    };
}

fn readWholeFile(io: std.Io, path: []const u8, out: []u8) ![]const u8 {
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    var total: usize = 0;
    while (total < out.len) {
        var bufs = [_][]u8{out[total..]};
        const n = file.readStreaming(io, &bufs) catch break; // EOF or short read: keep what we have
        if (n == 0) break;
        total += n;
    }
    return out[0..total];
}

fn countLines(text: []const u8) usize {
    if (text.len == 0) return 0;
    var n: usize = 1;
    for (text) |c| {
        if (c == '\n') n += 1;
    }
    // A trailing newline must not count as an extra (empty) line.
    if (text[text.len - 1] == '\n') n -= 1;
    return n;
}

test "the init sequence appends rc + log to the on-disk diag file, and the last line matches C2CopyDiagLog" {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    const io = threaded.io();

    var path_buf: [128]u8 = undefined;
    const path = diagFilePath(&path_buf);

    try std.testing.expectEqual(@as(c_int, 0), C2TestQuickJS());

    var content: [16 * 1024]u8 = undefined;
    const text = try readWholeFile(io, path, &content);
    try std.testing.expect(text.len > 0);

    const trimmed = std.mem.trimEnd(u8, text, "\n");
    const last_line = if (std.mem.lastIndexOfScalar(u8, trimmed, '\n')) |idx|
        trimmed[idx + 1 ..]
    else
        trimmed;
    try std.testing.expect(std.mem.startsWith(u8, last_line, "rc=0 "));

    var buf: [512]u8 = undefined;
    _ = C2CopyDiagLog(&buf);
    const log = std.mem.span(@as([*:0]const u8, @ptrCast(&buf)));
    try std.testing.expect(log.len > 0);
    // The file line is "rc=<n> " ++ g_diag_log, so what a surviving host would
    // read out of the remote buffer and what the dead host left on disk agree.
    try std.testing.expect(std.mem.endsWith(u8, last_line, log));
}

test "the diag file accumulates one line per sequence run, and pure reads add none" {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    const io = threaded.io();

    var path_buf: [128]u8 = undefined;
    const path = diagFilePath(&path_buf);
    var content: [16 * 1024]u8 = undefined;
    var buf: [512]u8 = undefined;

    // Guarantee the file exists regardless of test order; this run is the
    // baseline line whose presence the first test already checked.
    try std.testing.expectEqual(@as(c_int, 0), C2TestQuickJS());
    const before = countLines(std.mem.trimEnd(u8, try readWholeFile(io, path, &content), "\n"));

    _ = C2CopyDiagLog(&buf); // must stay a pure read of g_diag_log
    const after_read = countLines(std.mem.trimEnd(u8, try readWholeFile(io, path, &content), "\n"));

    try std.testing.expectEqual(@as(c_int, 0), C2DiagQuickJS(&buf, @intCast(buf.len))); // one more full sequence
    const after_seq = countLines(std.mem.trimEnd(u8, try readWholeFile(io, path, &content), "\n"));

    try std.testing.expectEqual(before, after_read);
    try std.testing.expectEqual(before + 1, after_seq);
}

// ---------------------------------------------------------------------------
// C2 allocator-record discrimination plan, Task 1 — the bounded ring recorder
// inside heap_malloc/heap_free/heap_realloc (quickjs_wrapper.c), rendered to
// text by the C symbol `C2DiagMfRecords` and read back through the
// `C2DiagMfRecordsInto` buffer contract. Observation only: the three callbacks
// gain entry/exit bookkeeping and nothing else; the 'M'/'m'/'!' marking and
// MF_TAG_CAP are byte-for-byte untouched, so every live reading recorded in
// §41–§44 still compares against the same text.
// ---------------------------------------------------------------------------

test "mf recorder renders kind size ptr state in fixed width" {
    // 裁定 1(brief Step 1 的省略处):环里要有记录必须先有回调跑过 —— 用既有的
    // liveContext()(c2_diag_test.zig:44)先驱动 bootstrap 序列(它自己断言 rc=0),
    // 序列的分配即落入环形记录器。
    _ = try liveContext();
    var rec: [4096]u8 = undefined;
    const n = C2DiagMfRecordsInto(&rec);
    try std.testing.expect(n > 0);
    // 至少一条 malloc 记录,且 size 与 ptr 都是定宽十六进制
    try std.testing.expect(std.mem.indexOf(u8, rec[0..@intCast(n)], "Mx size=") != null);
    // state 字段必须出现:候选 (c) 的判别依赖它
    try std.testing.expect(std.mem.indexOf(u8, rec[0..@intCast(n)], " st=") != null);
}

/// Parses the `size=` column of one rendered recorder row into its numeric value.
/// Pure, allocates nothing, used by the size assertions below; returns null when
/// the row is not the shape the C renderer promises (that is an error for the
/// caller, never a silent 0).
fn mfRowSize(row: []const u8) ?u64 {
    const at = std.mem.indexOf(u8, row, " size=") orelse return null;
    const digits = row[at + " size=".len ..];
    const end = std.mem.indexOfScalar(u8, digits, ' ') orelse return null;
    if (end == 0) return null;
    return std.fmt.parseInt(u64, digits[0..end], 16) catch return null;
}

/// Asserts the invariant Task 1 Step 4 turned into: every `M`/`R` row the ring
/// renders carries `size > 0`, i.e. a zero-size request *would* be visible. Also
/// requires at least one `M` row, so the claim is never vacuous.
fn assertNoZeroSizeMallocOrRealloc(text: []const u8) !void {
    var malloc_rows: usize = 0;
    var row_it = std.mem.splitScalar(u8, text, '\n');
    while (row_it.next()) |row| {
        if (row.len == 0) continue; // 末行 \n 之后的空段
        if (row[0] != 'M' and row[0] != 'R') continue;
        const sz = mfRowSize(row) orelse return error.MissingSizeColumn;
        if (row[0] == 'M') malloc_rows += 1;
        try std.testing.expect(sz > 0);
    }
    try std.testing.expect(malloc_rows > 0);
}

test "no zero-size request reaches mf on this vendored build, and the recorder would see one" {
    // 裁定 1(brief Step 4 的省略处):先经既有 helper 拿到活 ctx,再走下面的触发序列。
    const ctx = try liveContext();
    var rec: [4096]u8 = undefined;
    // 直接经导出序列走到 QuickJS 的零尺寸路径:JS_NewString(ctx, "") 在 vendored
    // 2025-09-13 上经 js_alloc_string_rt(rt, 0) → __js_malloc(&rt->malloc_ctx, 0)
    // ↑ 这条路径主张在 2026-10 离线读源中被逐层证伪。三层证据(行号是本仓库
    // libs/quickjs/quickjs.c,CONFIG_VERSION 2025-09-13):
    //   1. `js_new_string8_len`(:4014)对 `len <= 0` 短路
    //      `return JS_AtomToString(ctx, JS_ATOM_empty_string);`(:4018-4020)
    //      —— 零分配,brief 的路径主张在第一层就不成立;
    //   2. 即便走到 `js_alloc_string_rt(rt, max_len, is_wide)`(:2355),它请求的是
    //      `sizeof(JSString) + (max_len << is_wide) + 1 - is_wide`(:2358),
    //      max_len=0 时也是 sizeof(JSString)+1 ≠ 0;
    //   3. `__js_malloc(s, 0)`(:1549)在 `size == 0` 时直接返回内置
    //      `zero_size_block` 的 user_data(:1552-1554,取法 :1468-1470),
    //      **从不**把它转发给 `mf.js_malloc`;`__js_realloc`(:1636)同理对
    //      `size == 0` 走 `__js_free(s, ptr); return NULL;`(:1641-1643),也不转发。
    //      而 mf 的三个调用点都自带头部:arena `sizeof(JSMallocArena)+n_blocks*block_size`
    //      (:1505)、大块 `sizeof(JSMallocLargeBlockHeader)+size`(:1538)、
    //      realloc `sizeof(JSMallocLargeBlockHeader)+size`(:1655)⇒ 结构上恒 > 0。
    // 因此这条测试原样写下时永远不可能通过(每个后续任务都会继承一个红的
    // `zig build test`)。这里断言的是它**发现的那个不变式**:记录器看得见
    // size=0(见下面那条 probe 测试),而本机 vendored build 从不产生它。
    const v = JS_NewString(ctx, "");
    _ = v;
    const n = C2DiagMfRecordsInto(&rec);
    try std.testing.expect(n > 0);
    try assertNoZeroSizeMallocOrRealloc(rec[0..@intCast(n)]);

    // 触发器本身也要钉一次:JS_NewString(ctx, "") 之后再渲染,仍然没有任何 M/R 行
    // 是零尺寸 —— 上面第 1 层证据(零分配)在这台机器上是可观察的,而不只是读源结论。
    const n2 = C2DiagMfRecordsInto(&rec);
    try std.testing.expect(n2 > 0);
    try assertNoZeroSizeMallocOrRealloc(rec[0..@intCast(n2)]);
}

test "an unwritten recorder slot is empty, not a fake NULL return" {
    var rec: [4096]u8 = undefined;
    const n = C2DiagMfRecordsInto(&rec);
    // 渲染层必须把 filled=='\0' 的槽位画成 "M_ ...",而不是画一个 ptr=0
    try std.testing.expectEqual(@as(usize, MF_REC_CAP), std.mem.count(u8, rec[0..@intCast(n)], "\n"));
    const undrawn = std.mem.indexOf(u8, rec[0..@intCast(n)], " ptr=0") != null;
    try std.testing.expect(!undrawn or std.mem.indexOf(u8, rec[0..@intCast(n)], "x size=") != null);

    // Step 6 散文要求的实质断言(计划原片段末尾那个 or 只在有 filled 记录时成立,
    // 钉不住「未写槽位画成 unfilled 标记、既不泄露 0x1 哨兵也不画成假 ptr=0」这条)。
    // 逐行扫描渲染文本:filled 列只允许 'x'(走到出口)或 '_'(没走到出口,含
    // 从未写入);'_' 行的 ptr 列必须是 16 个 '-' 的占位 —— 存进去的 0x1 哨兵
    // 永远不许作为数字出现在 ptr 列,NULL(全零)更不许出现在未走到出口的行里,
    // 因为「返回了 NULL」正是本记录器要判别的事实,不能和「还没返回」混写。
    const text = rec[0..@intCast(n)];
    var row_it = std.mem.splitScalar(u8, text, '\n');
    var rows: usize = 0;
    while (row_it.next()) |row| {
        if (row.len == 0) continue; // 末行 \n 之后的空段
        rows += 1;
        // kind 列:'M'/'F'/'R'(已入口)或 '_'(从未写入)。
        try std.testing.expect(row[0] == 'M' or row[0] == 'F' or row[0] == 'R' or row[0] == '_');
        // filled 列:'x' = 走到出口;'_' = 没走到。
        try std.testing.expect(row[1] == 'x' or row[1] == '_');
        const ptr_at = std.mem.indexOf(u8, row, " ptr=") orelse return error.MissingPtrColumn;
        if (row[1] == '_') {
            // 未走到出口的槽位:ptr 列只许是 dash 占位,既不是哨兵也不是假 NULL。
            try std.testing.expectEqual(@as(u8, '-'), row[ptr_at + 5]);
        }
    }
    try std.testing.expectEqual(@as(usize, MF_REC_CAP), rows);
    // 哨兵若在 ptr 列漏出,渲染只会是 "ptr=1 st="(无补零);它必须不存在。
    try std.testing.expect(std.mem.indexOf(u8, text, "ptr=1 st=") == null);
}

test "mf recorder renderer stays inside the 4096-byte contract and never writes past" {
    // Step 7 / Review Focus 3:渲染层按 MF_REC_CAP × 定宽行自算上界(8 行恒画,
    // 含从未写入的槽位),返回字节数必须 <= 4095,且绝不越出调用方 buffer。
    _ = try liveContext(); // 完整记录 ⇒ 各列都是真实宽度,buffer 上界断言才有牙
    var rec: [4096]u8 = undefined;
    for (&rec) |*b| b.* = 0xAA;
    const n = C2DiagMfRecordsInto(&rec);
    try std.testing.expect(n > 0);
    const written: usize = @intCast(n);
    try std.testing.expect(written <= 4095);
    // 渲染以 rec[n] 处的 NUL 收尾;n+1 之后一个字节都不许被碰 —— 哨兵 0xAA 必须原样。
    try std.testing.expectEqual(@as(u8, 0), rec[written]);
    for (rec[written + 1 ..]) |b| try std.testing.expectEqual(@as(u8, 0xAA), b);
    // 8 行恒定齐备(上界自算,不看调用方长度)。
    try std.testing.expectEqual(@as(usize, MF_REC_CAP), std.mem.count(u8, rec[0..@intCast(n)], "\n"));
}

test "mf recorder renders a zero-size malloc and a zero-size realloc driven straight into the callbacks" {
    // Fix round 1 / Review Focus 1 的实质:该钉的是**记录器看得见**零尺寸请求,不是
    // QuickJS 会不会发出一个(后者已由上面那条测试的三层读源证据钉成「从不」)。
    // 手法 = 本计划给 Task 4 的 C2ProbeMallocZero 批的那类:一个只在测试期可达的
    // C 符号,拿调用方自有的 JSMallocState 去调用既有的 static 回调 —— 不 export、
    // exports.zig 里没有它的声明、注入通道碰不到,分配器语义一字不改(它只是**调用**)。
    // 两条偏离分别钉,不用 `or`:brief 说的是 malloc 与 realloc **两条**不同偏离。
    try std.testing.expectEqual(@as(c_int, 0), C2DiagMfProbeZeroSize()); // 残留记账为 0
    var rec: [4096]u8 = undefined;
    const n = C2DiagMfRecordsInto(&rec);
    try std.testing.expect(n > 0);
    const text = rec[0..@intCast(n)];
    // 偏离 1:heap_malloc(state, 0) —— 入口 size=0,出口 ptr=0(它的 size==0 分支返回 NULL)。
    try std.testing.expect(std.mem.indexOf(u8, text, "Mx size=0 ptr=0 st=") != null);
    // 偏离 2:heap_realloc(state, live block, 0) —— 走的是「释放并返回 NULL」那条分支,
    // 与 !ptr 委托给 malloc 的那条不是同一条;同样入口 size=0、出口 ptr=0。
    try std.testing.expect(std.mem.indexOf(u8, text, "Rx size=0 ptr=0 st=") != null);
    // 上面那条测试(不变式)说本机 build 从不产生这类行;这条说**若有**,环里就一定看得见。
    // 两条合起来才是 Review Focus 1 要的判据,任何一条单独存在都是空话。
}

test "mf recorder renderer stops cleanly in a caller buffer shorter than its own bound" {
    // Fix round 1 / Review Focus 3 的另一半:既有的 4096 那条离渲染器自算的 496 字节
    // 上界太远,`written + n > out_size - 1` 那条 break 路径从来没有被测过。这里给一个
    // 明确小于满环渲染的小 out_size(64 字节),走的就是那条 break。
    _ = try liveContext(); // 环里要有真实行,截断才有东西可截
    var full: [4096]u8 = undefined;
    const full_n = C2DiagMfRecordsInto(&full);
    try std.testing.expect(full_n > 0);

    const out_size: c_int = 64;
    var buf: [192]u8 = undefined;
    for (&buf) |*b| b.* = 0xAA;
    const n = C2DiagMfRecords(&buf, out_size);
    try std.testing.expect(n > 0);
    const written: usize = @intCast(n);
    // 返回的字节数严格小于调用方给的长度(NUL 槽留给 out[written] 自己)。
    try std.testing.expect(written < @as(usize, @intCast(out_size)));
    // 终结符必须是 NUL …
    try std.testing.expectEqual(@as(u8, 0), buf[written]);
    // … 且 written+1 起、一路到哨兵区末尾(含 out_size 内外)一个字节都不许被碰。
    for (buf[written + 1 ..]) |b| try std.testing.expectEqual(@as(u8, 0xAA), b);
    // break 真的走过了:只画得出完整行,行数 >= 1 且 < 满环的 MF_REC_CAP。
    const rows = std.mem.count(u8, buf[0..written], "\n");
    try std.testing.expect(rows >= 1);
    try std.testing.expect(rows < MF_REC_CAP);
    // 截断不改写内容:前 written 字节与满环渲染逐字相同(单线程进程,环在两次阅读之间不动)。
    try std.testing.expectEqualSlices(u8, full[0..written], buf[0..written]);
}

test "mf recorder renders the st column as exactly 12 hex digits" {
    // Fix round 1 / Review Focus:既有的断言只查 `" st="` 存在,宽度没有任何钉。brief 的
    // `st=<低 12 位十六进制>` 实现取的是 **12 个十六进制位**(state 指针的低 48 位,
    // `st=%012llx`),不是 12 **个位**(那只有 3 个十六进制位);改渲染字节被本任务的
    // 硬约束禁止(单线程输出必须逐字不变),所以这里钉的是实现的那个宽度 —— 防的正是
    // 「回退成不补零的可变长度」与「把整个指针画出来」两种退化。
    _ = try liveContext(); // 真实事件 ⇒ 每行的 st= 都是真实宽度
    var rec: [4096]u8 = undefined;
    const n = C2DiagMfRecordsInto(&rec);
    try std.testing.expect(n > 0);
    var row_it = std.mem.splitScalar(u8, rec[0..@intCast(n)], '\n');
    var rows: usize = 0;
    while (row_it.next()) |row| {
        if (row.len == 0) continue; // 末行 \n 之后的空段
        rows += 1;
        const st_at = std.mem.indexOf(u8, row, " st=") orelse return error.MissingStateColumn;
        const col = row[st_at + " st=".len ..];
        // st= 是最后一列,列尾就是行尾:宽度必须正好 12,多一字少一字都算退化。
        try std.testing.expectEqual(@as(usize, 12), col.len);
        for (col) |c| try std.testing.expect(std.ascii.isHex(c));
    }
    try std.testing.expectEqual(@as(usize, MF_REC_CAP), rows);
}
