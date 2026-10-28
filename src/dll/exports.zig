// exports.zig — DLL exports callable from the C++ loader.
//
// These symbols must be exported so the injected C++ loader (T1) can
// discover and call them after DLL load. In Zig, `export` functions
// use C calling convention by default and are visible to the linker.

const std = @import("std");
const builtin = @import("builtin");
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
var c1_effect_id: u32 = 0;

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

/// Resolve the game module base via GetModuleHandleA("stellaris.exe").
/// Off Windows the comptime early-return cuts the kernel32 reference
/// entirely (same shape as hooking/windows.zig's wrappers) so the host
/// test root links; on Windows this is the original call, unchanged.
fn gameModuleBase() usize {
    // Off-Windows kernel32 cut — see hooking/windows.zig module header.
    if (comptime builtin.os.tag != .windows) return 0;
    return @intFromPtr(GetModuleHandleA("stellaris.exe"));
}

fn writeMarker() void {
    // Off-Windows kernel32 cut — see hooking/windows.zig module header.
    // No-op off Windows matches the existing tolerance for handle failures below.
    if (comptime builtin.os.tag != .windows) return;
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
extern fn C2CopyDiagLog(out: [*]u8) c_int;
extern fn C2GetQuickJSPointers(out_rt: *?*anyopaque, out_ctx: *?*anyopaque) void;
extern fn C2WriteQuickJSPointersInto(out16: [*]u8) void;
extern fn C2EvalProbe(src: [*:0]const u8) c_int;
extern fn C2EvalStress() c_int;
extern fn C2DiagMfRecords(out: [*]u8, out_size: c_int) c_int;

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
/// c1_validation §24/§24.6 — alias form, donor = has_crisis_perk (0x269CAA8).
/// Resolves the game's module base via GetModuleHandleA, so it does not
/// depend on PushCApplicationPtr being called first.
/// Can be invoked via CreateRemoteThread from the injector, or from DllMain.
///
/// Candidate name: "neo_effect" — cleared by scripts/c1_preflight.py
/// (no collision in 9,863 descriptors + 1,610 keyword names, case-folded).
/// Predicted token id: >= 18818 (larger if lazy accessors already minted during startup).
export fn C1Run() callconv(.c) u32 {
    const game_base = gameModuleBase();
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
    c1_effect_id = effect_result.token_id;
    return trigger_result.token_id;
}

/// The effect-side token from the last successful C1Run. 0 = never run/failed.
export fn C1EffectId() callconv(.c) u32 {
    return c1_effect_id;
}

// ---------------------------------------------------------------------------
// C2: QuickJS runtime integration
// ---------------------------------------------------------------------------

const c2_handler = main.c2_handler;
const c2_vtable = main.c2_vtable;
const c2_predicate_hook = main.c2_predicate_hook;
const c2_live_probe = main.c2_live_probe;
const c2_scope_probe = main.c2_scope_probe;
const c2_wire = main.c2_wire;
const chokepoint_table = @import("c2/chokepoint_table.zig");
const c2_donor_probe = @import("c2/donor_exec_probe.zig");
const c2_witness_probe = @import("c2/instantiate_witness_probe.zig");
const c2_shim_probe = @import("c2/shim_witness_probe.zig");
const c = @import("quickjs/bindings.zig");
const offsets = @import("shared/offsets.zig");

extern fn C2ExecArmToken(token: u32, budget: u32) c_int;
extern fn C2ExecArmScores(scores: ?[*]const u16, count: u32, token: u32, budget: u32, tier1_min: u32, tier2_min: u32) c_int;
extern fn C2ExecStats(out: [*]u8, out_size: c_int) c_int;
extern fn C2ExecScoredStats(out: [*]u8, out_size: c_int) c_int;
extern fn C2ExecDisarmState() c_int;
const C2EXEC_BUDGET: u32 = 64;
const C4WIRE_BUDGET: u32 = 4096;

/// Sanity check: returns 42 if the new DLL code is loaded.
/// Pure Zig, no C wrapper — proves the DLL binary is correct.
export fn C2Sanity() callconv(.c) i32 {
    return 42;
}

/// C2: Initialize QuickJS, custom vtables, and predicate hooks.
/// Must be called after C1Run. QuickJS init is done here (not DllMain) because
/// DllMain runs under loader lock which can prevent QuickJS memory allocation.
///
/// Returns the C2Init/C2DiagQJS step code table (see C2DiagQJS below): 0 = OK,
/// 1..12 = JS_NewContextDiag's inner step, 100..104 = quickjs_wrapper.c's outer
/// gates. Since §36 this path ALSO fills `g_diag_log` — it used to return codes
/// with no log at all, which is why the 2026-10-21 live `rc = 3` was unreadable.
/// Read the text afterwards with C2LogInto, which re-runs nothing.
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
/// Return codes come from two sites that NO LONGER OVERLAP (the 2026-10-21 live
/// shot could not be decoded because rc 2/3/4 meant two different things — §36.4):
/// Outer (quickjs_wrapper.c's own gates): 100 = no process heap,
///   101 = test HeapAlloc failed, 102 = JS_NewRuntime2 NULL,
///   103 = runtime opaque mismatch, 104 = raw ctx NULL.
/// Inner (JS_NewContextDiag, echoed once the outer gates pass):
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

/// C2 allocator-record read-back: render the last MF_REC_CAP heap_mf events
/// (kind, size, ptr, malloc_state) into a CALLER-SUPPLIED buffer as text and
/// return the byte length written (excluding the NUL terminator).
///
/// Why this exists: §45 pinned the crash to quickjs.c:1494's `container_of`
/// reading `ptr - 8`, but the VALUE of that pointer was only ever inferred. The
/// ring recorder in quickjs_wrapper.c turns that inference into data; this
/// export is its read channel. It formats on the C side through
/// `C2DiagMfRecords` — the same C-formats/Zig-forwards split as the existing
/// C2DiagQuickJS + C2CopyDiagLog pair — so no per-record marshalling crosses
/// into Zig and no QuickJS C symbol is bound here (global constraint).
///
/// Buffer contract: `out_diag` must be a caller-owned buffer of at least 4096
/// bytes, passed as CreateRemoteThread lpParameter — exactly one argument, the
/// size baked into the contract (4096) and never passed by the caller, the same
/// shape as C2DiagQJSInto above (ruling P4: nothing 64-bit crosses the exit
/// code; the returned length is a 32-bit count of how much of the buffer is
/// text). The C renderer bounds itself by MF_REC_CAP rows x a fixed row width
/// and never writes past the length it is handed.
export fn C2DiagMfRecordsInto(out_diag: [*]u8) callconv(.c) i32 {
    return @intCast(C2DiagMfRecords(out_diag, 4096));
}

/// §36 live read-back path: copy `g_diag_log` into a CALLER-SUPPLIED 512-byte
/// remote buffer and return its length, WITHOUT running any QuickJS step.
///
/// Why this exists next to C2DiagQJSInto, which already fills a buffer: that one
/// RE-RUNS the whole init sequence, so on the live host a "fetch the diagnostic"
/// dispatch is secretly a second QuickJS init — and §36.3 recorded that 2 of 2
/// shots which reached QuickJS init lost the game process. Reading the log must
/// not be able to change anything, so this delegates to `C2CopyDiagLog`, which
/// is a memcpy out of a static and touches no engine code (its native test asserts
/// byte-identity with what the init path wrote, and that the runtime is still
/// healthy afterwards).
///
/// `out` must be at least 512 bytes, allocated by the caller and passed as
/// CreateRemoteThread lpParameter — one argument, the size baked into the
/// contract, same shape as C2QuickJSPointersInto below (ruling P4: nothing
/// 64-bit crosses the exit code; the returned length is 32-bit and only tells
/// the caller how much of the buffer is text).
export fn C2LogInto(out: [*]u8) callconv(.c) i32 {
    return @intCast(C2CopyDiagLog(out));
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

/// §50 diagnostic export: evaluate the fixed stress script defined in
/// quickjs_wrapper.c (`C2EvalStress`) and return the same `n*4+3` encoding as
/// C2EvalProbeOnePlusOne. The script exercises the allocator paths §48
/// un-instrumented but no live probe had run — string-builder and array growth
/// (js_realloc2 → __js_realloc/__js_malloc_usable_size) plus per-round
/// refcount drops (__js_free). Expected result: n = 15904 → rc 63619, pinned by
/// the native test that calls C2EvalStress directly (the script lives in C
/// once). Same single-run/C2Init-first contract as the Task 6 gate.
export fn C2EvalStressOne() callconv(.c) i32 {
    return @intCast(C2EvalStress());
}

/// C2 test: only build vtables, no hooks. For debugging.
export fn C2TestVtable() callconv(.c) i32 {
    writeLogStatic("C:\\temp\\c2_test.log", "C2Test: entry\n");

    const game_base = gameModuleBase();
    if (game_base == 0) {
        writeLogStatic("C:\\temp\\c2_test.log", "C2Test FAIL: no game base\n");
        return -1;
    }

    // Log game_base for diagnosis.
    var buf: [512]u8 = undefined;
    const hdr = std.fmt.bufPrint(&buf, "C2Test: game_base=0x{x}\n", .{game_base}) catch "C2Test: game_base ok\n";
    writeLogStatic("C:\\temp\\c2_test.log", hdr);

    c2_vtable.buildFromGame(game_base) catch {
        writeLogStatic("C:\\temp\\c2_test.log", "C2Test FAIL: vtable build failed\n");
        return -2;
    };
    if (!c2_vtable.isBuilt()) {
        writeLogStatic("C:\\temp\\c2_test.log", "C2Test FAIL: vtable build failed\n");
        return -2;
    }

    writeLogStatic("C:\\temp\\c2_test.log", "C2Test OK: vtables built\n");
    return 0;
}

// ---------------------------------------------------------------------------
// C4 execution path (Task 6)
// ---------------------------------------------------------------------------

/// One-shot arming of the whole chain, in dependency order:
/// vtable → predicate token → predicate install → probe token → C bridge arm.
export fn C2ExecInstall(token: u32) callconv(.c) i32 {
    const game_base = gameModuleBase();
    if (token == 0 or game_base == 0) return -1;
    c2_vtable.buildFromGame(game_base) catch return -2;
    c2_predicate_hook.setToken(token) catch return -3;
    c2_predicate_hook.install() catch return -4;
    c2_live_probe.setToken(token) catch return -5;
    return switch (C2ExecArmToken(token, C2EXEC_BUDGET)) {
        0 => 0,
        1 => -6,
        2 => -7,
        3 => -8,
        5 => -9,
        6 => -10,
        else => -1,
    };
}

export fn C2ExecProbeInstall() callconv(.c) i32 {
    if (!c2_vtable.isBuilt() or !c2_predicate_hook.isInstalled()) return -1;
    c2_live_probe.install() catch return -2;
    return 0;
}

export fn C2ExecProbeUninstall() callconv(.c) i32 {
    c2_live_probe.uninstall() catch return -6;
    return 0;
}

export fn C2ExecProbeVerify() callconv(.c) i32 {
    return c2_live_probe.verify();
}

export fn C2ExecDisarm() callconv(.c) i32 {
    if (C2ExecDisarmState() < 0) return -1;
    c2_predicate_hook.clearToken();
    c2_predicate_hook.uninstall() catch return -6;
    return 0;
}

export fn C2ExecStatsInto(out: [*]u8) callconv(.c) i32 {
    return C2ExecStats(out, 1024);
}

export fn C2ExecProbeStatsInto(out: [*]u8) callconv(.c) i32 {
    return @intCast(c2_live_probe.statsInto(out[0..512]));
}

// ---------------------------------------------------------------------------
// C4 chokepoint wiring (Task 4): scored tier routing + capture readback
// ---------------------------------------------------------------------------

/// One-shot arming of the wire path, in dependency order:
/// vtable → predicate token → predicate install → scored table → capture session.
/// Return codes: 0 ok | -1 bad token/game base | -2 vtable build | -3 predicate
/// setToken | -4 predicate install | -5 no JS ctx | -6 arm eval threw | -7 not a
/// function | -8 bad args | -9 already armed | -10 lock busy.
export fn C4WireInstall(token: u32) callconv(.c) i32 {
    const game_base = gameModuleBase();
    if (token == 0 or game_base == 0) return -1;
    c2_vtable.buildFromGame(game_base) catch return -2;
    c2_predicate_hook.setToken(token) catch return -3;
    c2_predicate_hook.install() catch return -4;
    return switch (C2ExecArmScores(
        chokepoint_table.scores[0..].ptr,
        @intCast(chokepoint_table.SCORE_COUNT),
        token,
        C4WIRE_BUDGET,
        chokepoint_table.TIER1_MIN,
        chokepoint_table.TIER2_MIN,
    )) {
        0 => blk: {
            c2_wire.beginSession(token);
            _ = c2_wire.setMode(1);
            break :blk 0;
        },
        1 => -5,
        2 => -6,
        3 => -7,
        4 => -8,
        5 => -9,
        6 => -10,
        else => -1,
    };
}

export fn C4WireSetMode(m: u32) callconv(.c) i32 {
    return if (c2_wire.setMode(m)) 0 else -1;
}

export fn C4WireSetSpec(bits: u64) callconv(.c) i32 {
    return if (c2_wire.setSpecPacked(bits)) 0 else -1;
}

export fn C4WireStatsInto(out: [*]u8) callconv(.c) i32 {
    return if (c2_wire.statsInto(out[0..c2_wire.STATS_SIZE])) @intCast(c2_wire.STATS_SIZE) else 0;
}

/// Caller must allocate `RING_CAP * RECORD_SIZE` (6,897,664) bytes.
export fn C4WireDrainInto(out: [*]u8) callconv(.c) u32 {
    return c2_wire.drainInto(out[0 .. c2_wire.RING_CAP * c2_wire.RECORD_SIZE]);
}

export fn C4WireLayout(out: [*]u32) callconv(.c) u32 {
    const words: *[8]u32 = @ptrCast(@alignCast(out));
    return c2_wire.layoutInto(words);
}

/// Returns -1 when the C bridge lock was busy; clearToken + uninstall still run,
/// so the engine bytes are restored even then. -6 = uninstall failed: do NOT
/// FreeLibrary this process.
export fn C4WireDisarm() callconv(.c) i32 {
    _ = c2_wire.setMode(0);
    const was = C2ExecDisarmState();
    c2_predicate_hook.clearToken();
    c2_predicate_hook.uninstall() catch return -6;
    return if (was < 0) -1 else 0;
}

export fn C4ScoredStatsInto(out: [*]u8) callconv(.c) i32 {
    return C2ExecScoredStats(out, 1024);
}

export fn C4PredStatsInto(out: [*]u8) callconv(.c) i32 {
    return if (c2_predicate_hook.statsInto(out[0..c2_predicate_hook.STATS_SIZE]))
        @intCast(c2_predicate_hook.STATS_SIZE)
    else
        0;
}

/// Read-only: <QQ> = slot[2] entries, the donor target it forwards to.
export fn C4Slot2StatsInto(out: [*]u8) callconv(.c) i32 {
    return if (c2_vtable.slot2StatsInto(out[0..c2_vtable.SLOT2_STATS_SIZE]))
        @intCast(c2_vtable.SLOT2_STATS_SIZE)
    else
        0;
}

// ---------------------------------------------------------------------------
// C4 forensics: read-only execution-frame sampler (0x1D08520)
// ---------------------------------------------------------------------------

/// 只记录采样器(0x1D08520)。依赖码:0 OK | -1 其它 | -2 该进程已有 detour(换新进程)
/// | -3 stellaris.exe 未找到 | -4 目标已被 hook | -5 指纹不符 | -6 patch 过宽。
export fn C2ScopeProbeInstall() callconv(.c) i32 {
    c2_scope_probe.install() catch |err| return switch (err) {
        error.AlreadyInstalled, error.ExecHookActive => -2,
        error.ModuleNotFound => -3,
        error.AlreadyHooked => -4,
        error.UnexpectedPrologue => -5,
        error.PatchTooWide => -6,
        else => -1,
    };
    return 0;
}

/// 0 = 引擎字节已验证还原。-7 = 还原没成功:不要信任该进程,且**绝不 FreeLibrary**。
export fn C2ScopeProbeUninstall() callconv(.c) i32 {
    c2_scope_probe.uninstall() catch return -7;
    return 0;
}

export fn C2ScopeProbeVerify() callconv(.c) i32 {
    return c2_scope_probe.verify();
}

export fn C2ScopeProbeLayout(out: [*]u32) callconv(.c) u32 {
    return c2_scope_probe.layoutInto(out);
}

export fn C2ScopeProbeStatsInto(out: [*]u8) callconv(.c) i32 {
    return @intCast(c2_scope_probe.statsInto(out[0..512]));
}

export fn C2ScopeProbeDrainInto(out: [*]u8) callconv(.c) u32 {
    return c2_scope_probe.drainInto(out);
}

export fn C2ScopeProbeReset() callconv(.c) void {
    c2_scope_probe.reset();
}

// ---------------------------------------------------------------------------
// C4 forensics: read-only donor-family Execute sampler (0x3AFD30, §57.4)
//
// Thin fold layer only: every export calls the module and maps its errors to
// the negative codes the driver's docstring documents. No judgement lives here.
// ---------------------------------------------------------------------------

/// 只记录 donor 一族 Execute(0x3AFD30)。依赖码:0 OK | -1 其它 | -2 该进程已装好
/// 或 predicate detour 还 armed(§57.4:[self+0] 会指向我们 DLL 的 vtable,这种状态
/// 下读数不能要)| -3 stellaris.exe 未找到 | -4 目标已被 hook | -5 指纹不符
/// | -6 patch 过宽。一进程一次 install 额度,所以 -2 不重试。
export fn C4DonorProbeInstall() callconv(.c) i32 {
    c2_donor_probe.install() catch |err| return switch (err) {
        error.AlreadyInstalled, error.PatchActive => -2,
        error.ModuleNotFound => -3,
        error.AlreadyHooked => -4,
        error.UnexpectedPrologue => -5,
        error.PatchTooWide => -6,
        else => -1,
    };
    return 0;
}

/// 采样掩码。任何 u64 都是合法值,故**没有非法值档**:恒返回 0。
/// mask=0 是「每条都落环」的有语义取值,不是错误;mask=0x1FF 才是 1/512。
export fn C4DonorProbeSetMask(mask: u64) callconv(.c) i32 {
    c2_donor_probe.setSampleMask(mask);
    return 0;
}

/// 0 = 引擎字节已验证还原。-7 = RestoreIncomplete:还原没成功,不要信任该进程,
/// 且**绝不 FreeLibrary**(驱动打印 RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY)。
/// 未安装时是 no-op,所以 install 失败后也可以安全调用。
export fn C4DonorProbeUninstall() callconv(.c) i32 {
    c2_donor_probe.uninstall() catch |err| return switch (err) {
        error.RestoreIncomplete => -7,
        else => -1,
    };
    return 0;
}

/// 原样透传模块的有符号约定,不重新折叠:0 一致 | -1 装着但 hook 丢了 |
/// -2 已卸但引擎字节不符 | -3 本进程从未解析到目标。
export fn C4DonorProbeVerify() callconv(.c) i32 {
    return c2_donor_probe.verify();
}

/// 六个布局词:[48, 56, 256, mask_lo, mask_hi, version]。mask 是 u64,占两词。
export fn C4DonorProbeLayout(out: [*]u32) callconv(.c) u32 {
    return c2_donor_probe.layoutInto(out);
}

export fn C4DonorProbeStatsInto(out: [*]u8) callconv(.c) i32 {
    return @intCast(c2_donor_probe.statsInto(out[0..512]));
}

export fn C4DonorProbeDrainInto(out: [*]u8) callconv(.c) u32 {
    return c2_donor_probe.drainInto(out);
}

/// 清计数 + 环 + mask + 镜像窗口;不卸载 hook(带活补丁清 calls 会把采样分母
/// 悄悄重置回 0)。因此必须在 Install 之前调用。
export fn C4DonorProbeReset() callconv(.c) void {
    c2_donor_probe.reset();
}

// ---------------------------------------------------------------------------
// C4 forensics: read-only same-family slot[2] instantiate witness (0x3B01A0, §57.4 第三档)
//
// Thin fold layer only: every export calls the module and maps its errors to
// the negative codes the driver's docstring documents. No judgement lives here.
// ---------------------------------------------------------------------------

/// 只记录同族 slot[2] instantiate helper(0x3B01A0)。依赖码:0 OK | -1 其它 |
/// -2 该进程已装好本 guard 或 predicate detour 还 armed(§57.4:[self+0] 会指向我们
/// DLL 的 vtable,这种状态下读数不能要)| -3 stellaris.exe 未找到 | -4 目标已被 hook
/// | -5 指纹不符 | -6 patch 过宽。一进程一次 install 额度,所以 -2 不重试。
/// 本 guard 的状态是 instantiate_witness_probe.zig 私有的,和 C4DonorProbe* 互不相干
/// ⇒ 同一进程可以先装证人再装 donor(spec §3 的同进程双 guard)。
export fn C4WitnessProbeInstall() callconv(.c) i32 {
    c2_witness_probe.install() catch |err| return switch (err) {
        error.AlreadyInstalled, error.PatchActive => -2,
        error.ModuleNotFound => -3,
        error.AlreadyHooked => -4,
        error.UnexpectedPrologue => -5,
        error.PatchTooWide => -6,
        else => -1,
    };
    return 0;
}

/// 采样掩码。任何 u64 都是合法值,故**没有非法值档**:恒返回 0。
/// mask=0 是「每条都落环」的有语义取值,不是错误;mask=0x1FF 才是 1/512。
export fn C4WitnessProbeSetMask(mask: u64) callconv(.c) i32 {
    c2_witness_probe.setSampleMask(mask);
    return 0;
}

/// 0 = 引擎字节已验证还原。-7 = RestoreIncomplete:还原没成功,不要信任该进程,
/// 且**绝不 FreeLibrary**(驱动打印 RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY)。
/// 未安装时是 no-op,所以 install 失败后也可以安全调用。
export fn C4WitnessProbeUninstall() callconv(.c) i32 {
    c2_witness_probe.uninstall() catch |err| return switch (err) {
        error.RestoreIncomplete => -7,
        else => -1,
    };
    return 0;
}

/// 原样透传模块的有符号约定,不重新折叠:0 一致 | -1 装着但 hook 丢了 |
/// -2 已卸但引擎字节不符 | -3 本进程从未解析到目标。
export fn C4WitnessProbeVerify() callconv(.c) i32 {
    return c2_witness_probe.verify();
}

/// 六个布局词:[48, 56, 256, mask_lo, mask_hi, version]。mask 是 u64,占两词。
export fn C4WitnessProbeLayout(out: [*]u32) callconv(.c) u32 {
    return c2_witness_probe.layoutInto(out);
}

export fn C4WitnessProbeStatsInto(out: [*]u8) callconv(.c) i32 {
    return @intCast(c2_witness_probe.statsInto(out[0..512]));
}

export fn C4WitnessProbeDrainInto(out: [*]u8) callconv(.c) u32 {
    return c2_witness_probe.drainInto(out);
}

/// 清计数 + 环 + mask + 镜像窗口;不卸载 hook(带活补丁清 calls 会把采样分母
/// 悄悄重置回 0)。因此必须在 Install 之前调用。
export fn C4WitnessProbeReset() callconv(.c) void {
    c2_witness_probe.reset();
}

// ---------------------------------------------------------------------------
// C4 forensics: read-only OUT-OF-FAMILY exec-shim witness (0xCC4220, structures §13 / §71)
//
// Thin fold layer only: every export calls shim_witness_probe.zig and maps its
// errors to the negative codes the driver's docstring documents. No judgement
// lives here. 本 guard 的状态是 shim_witness_probe.zig 私有的,和 donor/证人互不相干。
// ---------------------------------------------------------------------------

/// 安装错误码折叠表(纯函数,测试逐档点名;导出只转调它)。0 OK | -1 其它 |
/// -2 该进程已装好本 guard 或 predicate detour 还 armed(§57.4:[self+0] 会指向我们
/// DLL 的 vtable,这种状态下读数不能要)| -3 stellaris.exe 未找到 | -4 目标已被 hook
/// | -5 指纹不符 | -6 patch 过宽。一进程一次 install 额度,所以 -2 不重试。
fn shimInstallCode(err: anyerror) i32 {
    return switch (err) {
        error.AlreadyInstalled, error.PatchActive => -2,
        error.ModuleNotFound => -3,
        error.AlreadyHooked => -4,
        error.UnexpectedPrologue => -5,
        error.PatchTooWide => -6,
        else => -1,
    };
}

/// 卸载折叠表:-7 = RestoreIncomplete,其余 -1。同 witness 段。
fn shimUninstallCode(err: anyerror) i32 {
    return switch (err) {
        error.RestoreIncomplete => -7,
        else => -1,
    };
}

/// 只记录 §13 那七把 2,090 次 shim 的族外证人(`0xCC4220`)。码表见 shimInstallCode。
export fn C4ShimProbeInstall() callconv(.c) i32 {
    c2_shim_probe.install() catch |err| return shimInstallCode(err);
    return 0;
}

/// 采样掩码。任何 u64 都是合法值,故**没有非法值档**:恒返回 0。
/// mask=0 是「每条都落环」的有语义取值,不是错误。
export fn C4ShimProbeSetMask(mask: u64) callconv(.c) i32 {
    c2_shim_probe.setSampleMask(mask);
    return 0;
}

/// 0 = 引擎字节已验证还原。-7 = RestoreIncomplete:还原没成功,不要信任该进程,
/// 且**绝不 FreeLibrary**。未安装时是 no-op。
export fn C4ShimProbeUninstall() callconv(.c) i32 {
    c2_shim_probe.uninstall() catch |err| return shimUninstallCode(err);
    return 0;
}

/// 原样透传模块的有符号约定:0 一致 | -1 装着但 hook 丢了 | -2 已卸但引擎字节不符 |
/// -3 本进程从未解析到目标。
export fn C4ShimProbeVerify() callconv(.c) i32 {
    return c2_shim_probe.verify();
}

/// 六个布局词:[48, 64, 256, mask_lo, mask_hi, version]。Stats 是 64 B(7 张表),
/// 与 donor/证人的 56 不同 —— 驱动的 LAYOUT 门就靠这一格认出是第几把 guard。
export fn C4ShimProbeLayout(out: [*]u32) callconv(.c) u32 {
    return c2_shim_probe.layoutInto(out);
}

export fn C4ShimProbeStatsInto(out: [*]u8) callconv(.c) i32 {
    return @intCast(c2_shim_probe.statsInto(out[0..512]));
}

export fn C4ShimProbeDrainInto(out: [*]u8) callconv(.c) u32 {
    return c2_shim_probe.drainInto(out);
}

/// 清计数 + 环 + mask + 镜像窗口;不卸载 hook(带活补丁清 calls 会把采样分母
/// 悄悄重置回 0)。因此必须在 Install 之前调用。
export fn C4ShimProbeReset() callconv(.c) void {
    c2_shim_probe.reset();
}

/// C2 diagnostic: step-by-step memory reads to find the exact crash point.
/// Tests reading the donor vtable addresses byte-by-byte.
export fn C2Diag() callconv(.c) i32 {
    var log_buf: [1024]u8 = undefined;
    var pos: usize = 0;

    const game_base = gameModuleBase();

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
    // Off-Windows kernel32 cut — see hooking/windows.zig module header.
    // No-op off Windows matches the existing tolerance for handle failures below.
    if (comptime builtin.os.tag != .windows) return;
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
    // The DETACH call below is an inert smoke call, not a cleanup: DllMain's
    // DETACH arm mutates nothing (see the DETACH invariant test), and this test
    // never touched engine_ptr, so there is no state to revert. It only proves
    // reason=0 does not fault from this call site.
    _ = DllMain(null, 0, null);
}

test "DllMain: DLL_PROCESS_DETACH leaves engine_ptr untouched" {
    // Awakened by issue #18 (this root first linked and ran on the Linux host
    // in Task 2). The original assertion — DETACH clears engine_ptr — was true
    // only of 12b8ad7's DllMain; d443986 dropped the clear when DllMain was
    // simplified to writeMarker-on-ATTACH, and the test never ran afterwards
    // because the exports root would not link. Task 3 adjudication: the
    // assertion does not hold on the x86_64-windows shipping path, so the test
    // is stale, not the code. What actually bears weight: engine_ptr changes
    // ONLY through PushCApplicationPtr — DllMain mutates nothing for any reason
    // code (consistent with the sibling tests below and with 永不 FreeLibrary:
    // the engine holds state past this DLL's lifetime, so DETACH must not
    // silently invalidate pointers the host still reads).
    var args = PushArgs{
        .appPtr = @ptrFromInt(0xDEAD),
        .base = 0x140000000,
    };
    PushCApplicationPtr(&args);
    try std.testing.expect(getEnginePtr() != null);

    // DETACH must not clear (nor otherwise touch) it.
    _ = DllMain(null, 0, null);
    try std.testing.expectEqual(@as(?*anyopaque, @ptrFromInt(0xDEAD)), getEnginePtr());

    // Cleanup
    args.appPtr = null;
    PushCApplicationPtr(&args);
}

test "DllMain: DLL_PROCESS_ATTACH leaves engine_ptr untouched" {
    // Issue #18 review gap: the DETACH test above (and its comment) asserts that
    // DllMain mutates nothing for ANY reason code, yet PROCESS_ATTACH (reason=1)
    // — the one arm with real code (writeMarker) — had only a return-value check.
    // writeMarker is a kernel32 no-op off Windows and a file write on Windows;
    // neither path touches engine_ptr, so the shipping (x86_64-windows) DllMain
    // leaves the pointer exactly as PushCApplicationPtr set it. This test closes
    // the coverage hole so the set is as strong as its comment claims; it is a
    // self-contained add (no ordering dependency), asserting bitwise equality
    // like the DETACH sibling.
    var args = PushArgs{
        .appPtr = @ptrFromInt(0xFEED),
        .base = 0x140000000,
    };
    PushCApplicationPtr(&args);
    try std.testing.expect(getEnginePtr() != null);

    // PROCESS_ATTACH must not clear (nor otherwise touch) it.
    _ = DllMain(null, 1, null);
    try std.testing.expectEqual(@as(?*anyopaque, @ptrFromInt(0xFEED)), getEnginePtr());

    // Cleanup
    args.appPtr = null;
    PushCApplicationPtr(&args);
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

test "DLL entry points are inert off Windows" {
    if (comptime builtin.os.tag == .windows) return;
    try std.testing.expectEqual(@as(usize, 0), gameModuleBase());
    try std.testing.expectEqual(@as(u32, 0), C1Run());
}

// ---------------------------------------------------------------------------
// Task 3 (plan 2026-10-27-live-window-out-of-family-witness): the install code
// table gets a pure function so every tier can be named by a test. The exports
// themselves only fold through it — no judgement lives in the export bodies.
// ---------------------------------------------------------------------------

test "C4ShimProbeInstall folds every install error to its documented code" {
    try std.testing.expectEqual(@as(i32, -2), shimInstallCode(error.AlreadyInstalled));
    try std.testing.expectEqual(@as(i32, -2), shimInstallCode(error.PatchActive));
    try std.testing.expectEqual(@as(i32, -3), shimInstallCode(error.ModuleNotFound));
    try std.testing.expectEqual(@as(i32, -4), shimInstallCode(error.AlreadyHooked));
    try std.testing.expectEqual(@as(i32, -5), shimInstallCode(error.UnexpectedPrologue));
    try std.testing.expectEqual(@as(i32, -6), shimInstallCode(error.PatchTooWide));
    try std.testing.expectEqual(@as(i32, -1), shimInstallCode(error.DetourUnavailable));
    try std.testing.expectEqual(@as(i32, -1), shimInstallCode(error.Unsupported));
    // Off Windows the real export takes the Unsupported branch — that is the only
    // tier the Linux host can reach, and it must fold to -1 (not to a false 0).
    if (comptime builtin.os.tag != .windows) {
        try std.testing.expectEqual(@as(i32, -1), C4ShimProbeInstall());
    }
}

test "C4ShimProbeUninstall folds RestoreIncomplete to -7 and nothing else" {
    try std.testing.expectEqual(@as(i32, -7), shimUninstallCode(error.RestoreIncomplete));
    try std.testing.expectEqual(@as(i32, -1), shimUninstallCode(error.OutOfMemory));
}
