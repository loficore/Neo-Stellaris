// exports.zig — DLL exports callable from the C++ loader.
//
// These symbols must be exported so the injected C++ loader (T1) can
// discover and call them after DLL load. In Zig, `export` functions
// use C calling convention by default and are visible to the linker.

const std = @import("std");
const main = @import("main.zig");
const keyword_registry = main.keyword_registry;

// ---------------------------------------------------------------------------
// Engine pointer storage
// ---------------------------------------------------------------------------

/// PushArgs matches the C++ struct in inject.cpp.
/// C++ loader packs applicationPtr and baseAddress into this struct
/// and passes a pointer to it via CreateRemoteThread.
const PushArgs = extern struct {
    appPtr: ?*anyopaque,
    base: usize,
};

/// Opaque pointer to the Stellaris CApplication instance.
/// Set once by the loader via PushCApplicationPtr, then read by the
/// QuickJS extension host whenever it needs engine access.
var engine_ptr: ?*anyopaque = null;

/// DLL module base address, set by PushCApplicationPtr.
/// Used by the extension host to resolve version-specific offsets.
var base_address: usize = 0;

/// C1 registration result — observable from the loader after C1Run returns.
/// token_id = 0 means not yet run or failed; check c1_error for the reason.
var c1_result: ?keyword_registry.Registration = null;
var c1_error: ?keyword_registry.RegisterError = null;

/// Retrieve the stored engine pointer. Returns null if not yet set.
pub fn getEnginePtr() ?*anyopaque {
    return engine_ptr;
}

/// Retrieve the stored DLL base address.
pub fn getBaseAddress() usize {
    return base_address;
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/// Called by the C++ loader immediately after DLL injection.
/// Stores the CApplication* for later use by the extension host.
export fn PushCApplicationPtr(args: *PushArgs) callconv(.c) void {
    engine_ptr = args.appPtr;
    base_address = args.base;
    std.log.info("stellaris_quickjs: CApplication ptr received @ {any}", .{args.appPtr});
    std.log.info("stellaris_quickjs: DLL base address @ {any}", .{args.base});
}

extern "kernel32" fn GetModuleHandleA(lpModuleName: [*:0]const u8) ?*anyopaque;
extern "kernel32" fn CreateThread(
    lpThreadAttributes: ?*anyopaque,
    dwStackSize: usize,
    lpStartAddress: *const fn (?*anyopaque) callconv(.c) u32,
    lpParameter: ?*anyopaque,
    dwCreationFlags: u32,
    lpThreadId: ?*u32,
) ?*anyopaque;
extern "kernel32" fn CreateFileA(
    lpFileName: [*:0]const u8,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: ?*anyopaque,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: ?*anyopaque,
) ?*anyopaque;
extern "kernel32" fn WriteFile(
    hFile: ?*anyopaque,
    lpBuffer: *const anyopaque,
    nNumberOfBytesToWrite: u32,
    lpNumberOfBytesWritten: ?*u32,
    lpOverlapped: ?*anyopaque,
) i32;
extern "kernel32" fn CloseHandle(hObject: ?*anyopaque) i32;

fn writeMarker() void {
    const path = "C:\\temp\\dll_loaded.txt";
    const msg = "DLL loaded OK\n";
    const h = CreateFileA(path, 0x40000000, 0, null, 2, 0x80, null);
    if (h == null) return;
    if (@intFromPtr(h) == @as(usize, @bitCast(@as(i64, -1)))) return;
    var written: u32 = 0;
    _ = WriteFile(h, msg.ptr, @intCast(msg.len), &written, null);
    _ = CloseHandle(h);
}

fn markerThreadMain(_: ?*anyopaque) callconv(.c) u32 {
    writeMarker();
    return 0;
}

// From quickjs_wrapper.c — diagnostic test and pointer retrieval.
extern fn C2SanityCheck() c_int;
extern fn C2TestQuickJS() c_int;
extern fn C2DiagQuickJS(out_diag: [*]u8, diag_size: c_int) c_int;
extern fn C2DiagGetLog() ?[*:0]const u8;
extern fn C2GetQuickJSPointers(out_rt: *?*anyopaque, out_ctx: *?*anyopaque) void;
extern fn C2WriteQuickJSPointersInto(out16: [*]u8) void;
extern fn C2EvalProbe(src: [*:0]const u8) c_int;

/// C2 diagnostic: test QuickJS init from C side. Returns 0=OK, 1=malloc fail, 2=runtime fail, 3=context fail.
export fn C2TestQJS() callconv(.c) i32 {
    const result = C2TestQuickJS();
    var buf: [128]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "C2TestQJS: result={d}\n", .{result}) catch "C2TestQJS: done\n";
    writeLogStatic("C:\\temp\\c2_testqjs.log", msg);
    return @intCast(result);
}

const GENERIC_WRITE: u32 = 0x40000000;
const CREATE_ALWAYS: u32 = 2;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE_VALUE: ?*anyopaque = @ptrFromInt(@as(usize, @bitCast(@as(i64, -1))));

/// C1: register a new trigger keyword into the live engine's BST.
/// PLAN §6 C1 — alias form, donor = has_crisis_perk (0x269CAA8).
/// Resolves the game's module base via GetModuleHandleA, so it does not
/// depend on PushCApplicationPtr being called first.
/// Can be invoked via CreateRemoteThread from the injector, or from DllMain.
///
/// Candidate name: "neo_effect" — cleared by scripts/c1_preflight.py
/// (no collision in 9,863 descriptors + 1,610 keyword names, case-folded).
/// Predicted token id: >= 18818 (larger if lazy accessors already minted during startup).
export fn C1Run() callconv(.c) u32 {
    const exe_name: [*:0]const u8 = "stellaris.exe";
    const game_base = @intFromPtr(GetModuleHandleA(exe_name));
    if (game_base == 0) {
        writeLogStatic("C:\\temp\\c1_result.log", "C1 FAIL: no game base\n");
        return 0;
    }

    const eng = keyword_registry.Engine.map(game_base);

    // Register trigger: neo_effect (already done, but do it again for completeness)
    const holder_trigger = keyword_registry.NameHolder.inlineSso("neo_effect");
    const info_trigger = keyword_registry.ClassInfo.triggerDonor(game_base);
    const trigger_result = keyword_registry.register(&eng, .triggers, &holder_trigger, info_trigger) catch |err| {
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "C1 trigger FAIL: error={d}\n", .{@intFromError(err)}) catch "C1 trigger FAIL\n";
        writeLogStatic("C:\\temp\\c1_result.log", msg);
        return 0;
    };

    // Register effect: neo_action (effect-side twin)
    const holder_effect = keyword_registry.NameHolder.inlineSso("neo_action");
    const info_effect = keyword_registry.ClassInfo.effectDonor(game_base);
    const effect_result = keyword_registry.register(&eng, .effects, &holder_effect, info_effect) catch |err| {
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "C1 effect FAIL: error={d}\n", .{@intFromError(err)}) catch "C1 effect FAIL\n";
        writeLogStatic("C:\\temp\\c1_result.log", msg);
        return 0;
    };

    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "C1 OK: trigger_id={d} effect_id={d}\n", .{ trigger_result.token_id, effect_result.token_id }) catch "C1 OK\n";
    writeLogStatic("C:\\temp\\c1_result.log", msg);
    return trigger_result.token_id;
}

// ---------------------------------------------------------------------------
// C2: QuickJS runtime integration
// ---------------------------------------------------------------------------

const c2_handler = main.c2_handler;
const c2_vtable = main.c2_vtable;
const c2_predicate_hook = main.c2_predicate_hook;
const c = @import("quickjs/bindings.zig");
const offsets = @import("shared/offsets.zig");

/// Sanity check: returns 42 if the new DLL code is loaded.
/// Pure Zig, no C wrapper — proves the DLL binary is correct.
export fn C2Sanity() callconv(.c) i32 {
    return 42;
}

/// C2: Initialize QuickJS, custom vtables, and predicate hooks.
/// Must be called after C1Run. QuickJS init is done here (not DllMain) because
/// DllMain runs under loader lock which can prevent QuickJS memory allocation.
/// Returns 0 on success, negative on error.
///
/// NOTE: writeLogStatic removed (2026-10-07) — suspected of crashing C2Init
/// while C2TestQJS (which also calls writeLogStatic but *after* the C fn) does not.
/// The CreateFileA/WriteFile calls may corrupt TLS or stack state in the
/// CreateRemoteThread context. Re-add only after blocker 3 is confirmed resolved.
export fn C2Init() callconv(.c) i32 {
    const r = C2TestQuickJS();
    return @intCast(r);
}

/// C2 extended diagnostic: narrows down why JS_NewContext returns NULL.
/// Return codes come from two overlapping sites — C2DiagQuickJS's outer steps
/// and JS_NewContextDiag's inner steps — so the log text is authoritative.
/// Outer (quickjs_wrapper.c): 10 = no process heap, 11 = test HeapAlloc failed,
///   2 = JS_NewRuntime2 NULL, 3 = runtime opaque mismatch, 4 = raw ctx NULL.
/// Inner (JS_NewContextDiag, echoed once the outer steps pass):
///   0 = success, 1 = JS_NewContextRaw alloc fail,
///   2-12 = first failing intrinsic (BaseObjects, Date, Eval, StringNormalize,
///   RegExp, JSON, Proxy, MapSet, TypedArrays, Promise, WeakRef).
/// Use C2DiagQJSInto to capture the log; C2DiagQJS's buffer is stack-local.
export fn C2DiagQJS() callconv(.c) i32 {
    var diag_buf: [512]u8 = undefined;
    const r = C2DiagQuickJS(&diag_buf, @intCast(diag_buf.len));
    return @intCast(r);
}

/// Returns the address of the diagnostic log buffer (for remote reading).
/// NOTE: unusable via CreateRemoteThread exit code — the pointer is 64-bit and
/// GetExitCodeThread truncates it (ruling P4). Use C2DiagQJSInto instead.
export fn C2DiagGetLogAddr() callconv(.c) usize {
    const p = C2DiagGetLog();
    return @intFromPtr(p);
}

/// C2 diagnostic that writes the log into a CALLER-SUPPLIED buffer, returning
/// only the 32-bit step code (ruling P4: no 64-bit pointer may cross the thread
/// exit code). Delegates to the existing C `C2DiagQuickJS`, which already has
/// the (out_diag, diag_size) signature and fills that buffer with the step log.
/// `out_diag` must be a remote buffer of at least 512 bytes, allocated by the
/// caller and passed as CreateRemoteThread lpParameter. Returns the same step
/// code as C2DiagQJS.
export fn C2DiagQJSInto(out_diag: [*]u8) callconv(.c) i32 {
    const r = C2DiagQuickJS(out_diag, 512);
    return @intCast(r);
}

/// C2 Task 5 observation export (ruling P4): writes the FULL native-width
/// `g_test_rt` / `g_test_ctx` pointers into a CALLER-SUPPLIED 16-byte remote
/// buffer — rt at out16+0, ctx at out16+8 (x86-64: pointers are 8 bytes) — so
/// the injector reads real addresses back with read_u64/read_memory. No
/// pointer ever crosses a 32-bit thread exit code (that is why
/// C2DiagGetLogAddr above is injector-unusable, and why the brief's low-32
/// truncation exports were rejected). `out16` must be at least 16 bytes,
/// allocated by the caller and passed as CreateRemoteThread lpParameter — one
/// argument only, the size is baked in, not passed. Delegates to OUR wrapper
/// symbol `C2WriteQuickJSPointersInto` in quickjs_wrapper.c (no new QuickJS C
/// bindings — global constraint); the C link name differs from this PE name
/// because `export fn` owns the link symbol `C2QuickJSPointersInto` in the
/// same namespace as the C objects (duplicate symbol otherwise, verified).
/// Read-only observation aid, not a permanent API (Task 5 brief).
export fn C2QuickJSPointersInto(out16: [*]u8) callconv(.c) void {
    C2WriteQuickJSPointersInto(out16);
}

/// C2 Task 6 acceptance gate (brief Step 2): evaluate the FIXED string "1+1" in
/// the QuickJS context `C2Init` built, and return the encoded int32 so a
/// CreateRemoteThread caller reads it back through the 32-bit thread exit code:
///   0 = C2Init has not run (g_test_ctx NULL), 1 = JS_Eval threw, 2 = the result
///   is not an int32, n*4+3 = the result was int32 n  →  decode (rc - 3) / 4.
/// So `1+1` returns 11 and decodes to 2 — ruling P20: the brief's "expected 7"
/// was an arithmetic slip (`1+1` is 2, not 1); the ENCODING is the contract, and
/// n*4+3 is always congruent to 3 (mod 4), which is what keeps it distinguishable
/// from the three sentinels. No remote marshalling: the source string is baked in
/// here; general JS text from the caller is deferred to C3.
///
/// Delegates to OUR wrapper symbol `C2EvalProbe` in quickjs_wrapper.c — no new
/// Zig `extern fn` binding to a QuickJS C symbol (global constraint: JS_Eval and
/// JS_ToInt32 are declared in C). Inside the DLL this is the first code to pass a
/// real JSValue by value across the boundary where one side (quickjs_wrapper.c)
/// hand-forwards the type without including quickjs.h (ruling P21); the crossing
/// is C wrapper ↔ QuickJS engine, and the native e2e test
/// (src/dll/quickjs/c2_diag_test.zig: rc == 11) is its executed proof — this Zig
/// export itself cannot run on the Linux host (exports-rooted tests do not link,
/// ledgered as P15), so its PE name is verified by re-parsing the built DLL.
/// Unlike Task 5's split (P17), the two names here simply differ — "C2EvalProbe"
/// is the C entry taking a source pointer, "C2EvalProbeOnePlusOne" is the fixed-
/// string PE export — so no duplicate-symbol collision had to be routed around.
export fn C2EvalProbeOnePlusOne() callconv(.c) i32 {
    const probe = "1+1"; // fixed string; no remote marshalling needed at this gate
    return @intCast(C2EvalProbe(probe.ptr));
}

/// C2 test: only build vtables, no hooks. For debugging.
export fn C2TestVtable() callconv(.c) i32 {
    writeLogStatic("C:\\temp\\c2_test.log", "C2Test: entry\n");

    const exe_name: [*:0]const u8 = "stellaris.exe";
    const game_base = @intFromPtr(GetModuleHandleA(exe_name));
    if (game_base == 0) {
        writeLogStatic("C:\\temp\\c2_test.log", "C2Test FAIL: no game base\n");
        return -1;
    }

    // Log game_base for diagnosis.
    var buf: [512]u8 = undefined;
    const hdr = std.fmt.bufPrint(&buf, "C2Test: game_base=0x{x}\n", .{game_base}) catch "C2Test: game_base ok\n";
    writeLogStatic("C:\\temp\\c2_test.log", hdr);

    c2_vtable.buildVtables(game_base);
    if (!c2_vtable.isInitialized()) {
        writeLogStatic("C:\\temp\\c2_test.log", "C2Test FAIL: vtable build failed\n");
        return -2;
    }

    writeLogStatic("C:\\temp\\c2_test.log", "C2Test OK: vtables built\n");
    return 0;
}

/// C2 diagnostic: step-by-step memory reads to find the exact crash point.
/// Tests reading the donor vtable addresses byte-by-byte.
export fn C2Diag() callconv(.c) i32 {
    var log_buf: [1024]u8 = undefined;
    var pos: usize = 0;

    const exe_name: [*:0]const u8 = "stellaris.exe";
    const game_base = @intFromPtr(GetModuleHandleA(exe_name));

    pos = appendFmt(&log_buf, pos, "C2Diag: game_base=0x{x}\n", .{game_base});
    if (game_base == 0) {
        writeLogStatic("C:\\temp\\c2_diag.log", log_buf[0..pos]);
        return -1;
    }

    // Test reading the donor effect vtable address.
    const donor_eff = game_base + offsets.keyword_reg.DONOR_EFFECT_VTABLE;
    pos = appendFmt(&log_buf, pos, "C2Diag: donor_eff_vtbl=0x{x}\n", .{donor_eff});

    // Check alignment.
    pos = appendFmt(&log_buf, pos, "C2Diag: donor_eff aligned={d}\n", .{@as(u32, @intCast((donor_eff & 7)))});

    // Try reading a single u64 from the donor effect vtable.
    if (donor_eff >= 0x10000 and donor_eff <= 0x00007FFF_FFFF_0000) {
        const p: [*]const u8 = @ptrFromInt(donor_eff);
        const val = std.mem.readInt(u64, p[0..8], .little);
        pos = appendFmt(&log_buf, pos, "C2Diag: eff[0]=0x{x}\n", .{val});

        // Check if it looks like a code pointer (within the game image).
        if (val >= game_base and val < game_base + 0x4000000) {
            pos = appendFmt(&log_buf, pos, "C2Diag: eff[0] looks like valid code ptr (offset=0x{x})\n", .{val - game_base});
        } else {
            pos = appendFmt(&log_buf, pos, "C2Diag: eff[0] DOES NOT look like code ptr!\n", .{});
        }

        // Read a few more slots.
        const val2 = std.mem.readInt(u64, p[8..16], .little);
        pos = appendFmt(&log_buf, pos, "C2Diag: eff[1]=0x{x}\n", .{val2});

        const val3 = std.mem.readInt(u64, p[16..24], .little);
        pos = appendFmt(&log_buf, pos, "C2Diag: eff[2]=0x{x}\n", .{val3});
    } else {
        pos = appendFmt(&log_buf, pos, "C2Diag: donor_eff OUT OF plausible range!\n", .{});
    }

    // Test reading the donor trigger vtable address.
    const donor_trig = game_base + offsets.keyword_reg.DONOR_TRIGGER_VTABLE;
    pos = appendFmt(&log_buf, pos, "C2Diag: donor_trig_vtbl=0x{x}\n", .{donor_trig});

    if (donor_trig >= 0x10000 and donor_trig <= 0x00007FFF_FFFF_0000) {
        const p: [*]const u8 = @ptrFromInt(donor_trig);
        const val = std.mem.readInt(u64, p[0..8], .little);
        pos = appendFmt(&log_buf, pos, "C2Diag: trig[0]=0x{x}\n", .{val});

        const val2 = std.mem.readInt(u64, p[8..16], .little);
        pos = appendFmt(&log_buf, pos, "C2Diag: trig[1]=0x{x}\n", .{val2});
    } else {
        pos = appendFmt(&log_buf, pos, "C2Diag: donor_trig OUT OF plausible range!\n", .{});
    }

    pos = appendFmt(&log_buf, pos, "C2Diag: DONE\n", .{});
    writeLogStatic("C:\\temp\\c2_diag.log", log_buf[0..pos]);
    return 0;
}

fn appendFmt(buf: []u8, pos: usize, comptime fmt: []const u8, args: anytype) usize {
    const remaining = buf[pos..];
    const written = std.fmt.bufPrint(remaining, fmt, args) catch return pos;
    return pos + written.len;
}

/// C2: Register a JavaScript handler for an effect keyword.
/// `name` is the keyword name (e.g., "neo_action").
/// `js_code` is the JavaScript function body (e.g., "function(scope) { ... }").
/// Returns the token_id on success, 0 on failure.
export fn C2RegisterEffect(name_ptr: [*:0]const u8, js_code_ptr: [*:0]const u8) callconv(.c) u32 {
    const name = std.mem.span(name_ptr);
    const js_code = std.mem.span(js_code_ptr);

    if (main.js_runtime) |*rt| {
        // Eval the JS code to get the function object.
        const result = rt.eval(js_code, "<c2_effect>");
        switch (result) {
            .ok => |func_val| {
                const handler_result = c2_handler.registerHandler(name, func_val, .effect) catch |err| {
                    var buf: [128]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, "C2 RegisterEffect FAIL: {d}\n", .{@intFromError(err)}) catch "C2 RegisterEffect FAIL\n";
                    writeLogStatic("C:\\temp\\c2_result.log", msg);
                    c.JS_FreeValue(rt.ctx, func_val);
                    return 0;
                };
                _ = handler_result;
                var buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "C2 RegisterEffect OK: {s}\n", .{name}) catch "C2 RegisterEffect OK\n";
                writeLogStatic("C:\\temp\\c2_result.log", msg);
                // Note: token_id will be set later by matching with C1 registration.
                return 1; // Success indicator
            },
            .err => |e| {
                var buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "C2 RegisterEffect FAIL: eval error: {s}\n", .{e.message}) catch "C2 RegisterEffect FAIL: eval error\n";
                writeLogStatic("C:\\temp\\c2_result.log", msg);
                return 0;
            },
        }
    }
    return 0;
}

/// C2: Register a JavaScript handler for a trigger keyword.
/// `name` is the keyword name (e.g., "neo_effect").
/// `js_code` is the JavaScript function body (e.g., "function(scope) { return true; }").
/// Returns the token_id on success, 0 on failure.
export fn C2RegisterTrigger(name_ptr: [*:0]const u8, js_code_ptr: [*:0]const u8) callconv(.c) u32 {
    const name = std.mem.span(name_ptr);
    const js_code = std.mem.span(js_code_ptr);

    if (main.js_runtime) |*rt| {
        const result = rt.eval(js_code, "<c2_trigger>");
        switch (result) {
            .ok => |func_val| {
                const handler_result = c2_handler.registerHandler(name, func_val, .trigger) catch |err| {
                    var buf: [128]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, "C2 RegisterTrigger FAIL: {d}\n", .{@intFromError(err)}) catch "C2 RegisterTrigger FAIL\n";
                    writeLogStatic("C:\\temp\\c2_result.log", msg);
                    c.JS_FreeValue(rt.ctx, func_val);
                    return 0;
                };
                _ = handler_result;
                var buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "C2 RegisterTrigger OK: {s}\n", .{name}) catch "C2 RegisterTrigger OK\n";
                writeLogStatic("C:\\temp\\c2_result.log", msg);
                return 1;
            },
            .err => |e| {
                var buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "C2 RegisterTrigger FAIL: eval error: {s}\n", .{e.message}) catch "C2 RegisterTrigger FAIL: eval error\n";
                writeLogStatic("C:\\temp\\c2_result.log", msg);
                return 0;
            },
        }
    }
    return 0;
}

fn writeLogStatic(path: [*:0]const u8, data: []const u8) void {
    const h = CreateFileA(path, GENERIC_WRITE, 0, null, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, null);
    if (h == null or h == INVALID_HANDLE_VALUE) return;
    var written: u32 = 0;
    _ = WriteFile(h, data.ptr, @intCast(data.len), &written, null);
    _ = CloseHandle(h);
}

/// Thread entry point that calls C1Run. Spawned from DllMain to avoid loader lock.
fn c1ThreadMain(_: ?*anyopaque) callconv(.c) u32 {
    return C1Run();
}

/// Standard Windows DLL entry point.
/// Writes a marker file to prove the DLL loaded.
export fn DllMain(
    hinstDLL: ?*anyopaque,
    fdwReason: u32,
    lpvReserved: ?*anyopaque,
) callconv(.c) i32 {
    _ = hinstDLL;
    _ = lpvReserved;
    if (fdwReason == 1) { // DLL_PROCESS_ATTACH
        writeMarker();
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PushCApplicationPtr stores pointer" {
    var args = PushArgs{
        .appPtr = @ptrFromInt(0xDEAD),
        .base = 0x140000000,
    };
    PushCApplicationPtr(&args);
    try std.testing.expectEqual(@as(?*anyopaque, @ptrFromInt(0xDEAD)), getEnginePtr());
    // Cleanup
    args.appPtr = null;
    PushCApplicationPtr(&args);
}

test "DllMain returns TRUE" {
    const result = DllMain(null, 1, null);
    try std.testing.expectEqual(@as(i32, 1), result);
    // Cleanup
    _ = DllMain(null, 0, null);
}

test "DllMain: DLL_PROCESS_DETACH clears engine_ptr" {
    // Set engine pointer
    var args = PushArgs{
        .appPtr = @ptrFromInt(0xDEAD),
        .base = 0x140000000,
    };
    PushCApplicationPtr(&args);
    try std.testing.expect(getEnginePtr() != null);

    // Detach should clear it
    _ = DllMain(null, 0, null);
    try std.testing.expectEqual(@as(?*anyopaque, null), getEnginePtr());
}

test "DllMain: DLL_THREAD_ATTACH does not clear engine_ptr" {
    var args = PushArgs{
        .appPtr = @ptrFromInt(0xBEEF),
        .base = 0x140000000,
    };
    PushCApplicationPtr(&args);

    // Thread attach (reason=2) should not clear the pointer
    _ = DllMain(null, 2, null);
    try std.testing.expect(getEnginePtr() != null);

    // Cleanup
    args.appPtr = null;
    PushCApplicationPtr(&args);
}

test "DllMain: DLL_THREAD_DETACH does not clear engine_ptr" {
    var args = PushArgs{
        .appPtr = @ptrFromInt(0xCAFE),
        .base = 0x140000000,
    };
    PushCApplicationPtr(&args);

    // Thread detach (reason=3) should not clear the pointer
    _ = DllMain(null, 3, null);
    try std.testing.expect(getEnginePtr() != null);

    // Cleanup
    args.appPtr = null;
    PushCApplicationPtr(&args);
}

test "getEnginePtr: returns null initially" {
    // Save and restore state
    const saved_ptr = getEnginePtr();
    const saved_base = getBaseAddress();
    defer {
        var restore_args = PushArgs{
            .appPtr = saved_ptr,
            .base = saved_base,
        };
        PushCApplicationPtr(&restore_args);
    }

    var args = PushArgs{
        .appPtr = null,
        .base = 0,
    };
    PushCApplicationPtr(&args);
    try std.testing.expectEqual(@as(?*anyopaque, null), getEnginePtr());
}

test "PushCApplicationPtr: can set and clear" {
    var args1 = PushArgs{
        .appPtr = @ptrFromInt(0x1000),
        .base = 0x140000000,
    };
    var args2 = PushArgs{
        .appPtr = @ptrFromInt(0x2000),
        .base = 0x150000000,
    };

    PushCApplicationPtr(&args1);
    try std.testing.expectEqual(@as(?*anyopaque, @ptrFromInt(0x1000)), getEnginePtr());

    PushCApplicationPtr(&args2);
    try std.testing.expectEqual(@as(?*anyopaque, @ptrFromInt(0x2000)), getEnginePtr());

    var null_args = PushArgs{
        .appPtr = null,
        .base = 0,
    };
    PushCApplicationPtr(&null_args);
    try std.testing.expectEqual(@as(?*anyopaque, null), getEnginePtr());
}

test "DllMain: all reason codes return TRUE" {
    // DLL_PROCESS_ATTACH = 1
    try std.testing.expectEqual(@as(i32, 1), DllMain(null, 1, null));
    // DLL_THREAD_ATTACH = 2
    try std.testing.expectEqual(@as(i32, 1), DllMain(null, 2, null));
    // DLL_THREAD_DETACH = 3
    try std.testing.expectEqual(@as(i32, 1), DllMain(null, 3, null));
    // DLL_PROCESS_DETACH = 0
    try std.testing.expectEqual(@as(i32, 1), DllMain(null, 0, null));

    // Cleanup
    _ = DllMain(null, 0, null);
}

test "engine_ptr: multiple PushCApplicationPtr calls" {
    // Save initial state
    const saved_ptr = getEnginePtr();
    const saved_base = getBaseAddress();
    defer {
        var restore_args = PushArgs{
            .appPtr = saved_ptr,
            .base = saved_base,
        };
        PushCApplicationPtr(&restore_args);
    }

    // Each call should overwrite the previous value
    var args1 = PushArgs{
        .appPtr = @ptrFromInt(0x100),
        .base = 0x140000000,
    };
    PushCApplicationPtr(&args1);
    try std.testing.expectEqual(@as(usize, 0x100), @intFromPtr(getEnginePtr().?));

    var args2 = PushArgs{
        .appPtr = @ptrFromInt(0x200),
        .base = 0x150000000,
    };
    PushCApplicationPtr(&args2);
    try std.testing.expectEqual(@as(usize, 0x200), @intFromPtr(getEnginePtr().?));

    var args3 = PushArgs{
        .appPtr = @ptrFromInt(0x300),
        .base = 0x160000000,
    };
    PushCApplicationPtr(&args3);
    try std.testing.expectEqual(@as(usize, 0x300), @intFromPtr(getEnginePtr().?));
}
