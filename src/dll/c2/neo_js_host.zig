// neo_js_host.zig — Runtime JS host v1(Track A, Phase 1):native API + handler 调用 + 限额。
//
// **合同是冻结的**(`sdk/api.def` 是唯一权威,由 C1 的合同围栏核对):7 个 native
// 名字一个不加、一个不改;`apiVersion()` 恒为 1。TS 侧(`@neo/runtime`)只暴露
// `onSystem` / `System` / `graph` / `log` / `apiVersion`。
//
//   __neo_register_system(fn)                  handler 注册(bundle 顶层调用一次)
//   __neo_system_degree(id) -> u32             边容器 `+0x59C`
//   __neo_system_set_var(id, name, value)      官方 `set_variable` body(1e-5 定点)
//   __neo_graph_betweenness(id) -> u32         `neo_vtable.scoreFor(id)`(C5-SCORE 同源)
//   __neo_graph_is_chokepoint(id) -> bool      `score >= 200`(T2 阈值)
//   __neo_log(text)                            `C:/temp/neo_js.log`
//   __neo_api_version() -> u32                 1
//
// 纪律(计划 Review Focus,逐条落点):
//   1. **主线程**:runtime/context 只在 `ensureLoaded()` 里建,唯一调用方是 `onSystem`
//      (逐系统派发 = 游戏主线程)。**不复用** `main.js_runtime` —— 那是 `C2Init` 在
//      远程线程里建的,QuickJS 单线程。
//   2. **scope 指针不跨调用保存**:`onSystem` 把当次 scope 放进 `current_scope`,
//      handler 返回即清零。JS 只拿 id;`setVariable` 用当次 scope 调官方 body,并在
//      写之前核对 `scope+0x10 == id`(不一致就拒写,而不是写进另一个星系)。
//   3. **写只走官方 body**:`neo_vtable.writeVariable` —— 与 C5-WRITE / C5-SCORE
//      完全相同的对象布局、body(`0x188E1D0`)与 1e-5 定点编码。不写引擎内存。
//   4. **异常隔离**:JS 异常 / 超时只记日志、丢弃这一次调用;游戏继续。
//      每次 handler 调用有 10 ms 中断预算(`JS_SetInterruptHandler` 读我们自己的 deadline);
//      另有一道「一次调用里的 native 调用次数」上限,作为中断路径失效时的第二道闸。
//   5. **限额**:context 16 MiB、栈 1 MiB。
//   6. **永不 `FreeLibrary`**;runtime 与进程同生命周期(`deinit` 无人调用)。
//
// 日志口径(驱动/证据按行读):
//   NEO_JS_INIT_OK id=<mod> api=1 | NEO_JS_INIT_FAIL | NEO_JS_EVAL_FAIL | NEO_JS_NO_HANDLER
//   NEO_JS_NO_MOD / NEO_JS_MULTI_MOD n=<n> / NEO_JS_BAD_MANIFEST / NEO_JS_MISSING_ENTRY
//   NEO_JS_API_MISMATCH
//   NEO_JS_CALL id=<id>           每次 onSystem 一行(**先于** handler 是否存在的判断)
//   NEO_JS_WRITE id=<id> name=<name> | NEO_JS_WRITE_REJECT … reason=<tag>
//   NEO_JS_LOG <text>
//   NEO_JS_ERROR id=<id> <message> | NEO_JS_TIMEOUT id=<id>

const std = @import("std");
const builtin = @import("builtin");
const c = @import("../quickjs/bindings.zig");
const quickjs = @import("../quickjs/runtime.zig");
const windows = @import("../hooking/windows.zig");
const neo_vtable = @import("neo_vtable.zig");
const neo_state = @import("neo_state.zig");
const graph_probe = @import("graph_probe.zig");
const loader = @import("neo_js_loader.zig");

const is_windows = builtin.os.tag == .windows;

// ---------------------------------------------------------------------------
// Frozen contract
// ---------------------------------------------------------------------------

pub const API_VERSION: u32 = 1;

/// v1 的权限位。`packed struct` 是有意的:一个 u8 就能原子地描述整组权限,
/// loader 解析出它、host 只读它。
pub const Permissions = packed struct {
    graph_read: bool = false,
    variable_write: bool = false,
    log: bool = false,
};

pub const MAX_VAR_NAME: usize = neo_state.SSO_MAX;

/// C5-SCORE 的分数是 `0..1000` 的归一化介数;T2 的 `chokepoint` 判据是 `>= 200`
/// (计划 Global Constraints:`graph.isChokepoint(s)` = `score >= 200`)。**含 200**。
pub const CHOKEPOINT_THRESHOLD: u32 = 200;

/// 每次 handler 调用的中断预算。10 ms 是计划冻结值:一个 handler 做一次图查询/
/// 一次变量写,远小于此;超了就是 mod 的 bug(或死循环),丢掉这一次调用。
pub const CALL_BUDGET_NS: i128 = 10 * std.time.ns_per_ms;

/// context 内存与栈限额(计划冻结值)。
pub const CONTEXT_MEM_LIMIT: usize = 16 * 1024 * 1024;
pub const STACK_LIMIT: usize = 1024 * 1024;

/// 一次 handler 调用里的 native 调用次数上限。中断预算是第一道闸;万一
/// `JS_SetInterruptHandler` 那条路径没生效,这一道保证死循环仍然会结束。
pub const MAX_NATIVE_CALLS_PER_HANDLER: u32 = 100_000;

pub const LOG_PATH: [*:0]const u8 = "C:\\temp\\neo_js.log";

const NativeEntry = struct {
    name: [:0]const u8,
    func: c.JSCFunction,
    length: c_int,
};

/// 7 个 native —— 顺序即合同围栏的核对顺序(`sdk/api.def`)。
const native_table = [_]NativeEntry{
    .{ .name = "__neo_register_system", .func = nativeRegisterSystem, .length = 1 },
    .{ .name = "__neo_system_degree", .func = nativeSystemDegree, .length = 1 },
    .{ .name = "__neo_system_set_var", .func = nativeSystemSetVar, .length = 3 },
    .{ .name = "__neo_graph_betweenness", .func = nativeGraphBetweenness, .length = 1 },
    .{ .name = "__neo_graph_is_chokepoint", .func = nativeGraphIsChokepoint, .length = 1 },
    .{ .name = "__neo_log", .func = nativeLog, .length = 1 },
    .{ .name = "__neo_api_version", .func = nativeApiVersion, .length = 0 },
};

/// 合同名字的只读视图(C1 的围栏与测试都读它)。
pub const native_names = blk: {
    var names: [native_table.len][]const u8 = undefined;
    for (native_table, 0..) |n, i| names[i] = n.name;
    break :blk names;
};

// ---------------------------------------------------------------------------
// State (main thread only — Review Focus 1)
// ---------------------------------------------------------------------------

pub const Status = enum { idle, ready, failed };

var runtime: ?quickjs.Runtime = null;
var handler: c.JSValue = c.JS_UNDEFINED;
var state: Status = .idle;
var permissions: Permissions = .{};

/// 当次派发的 scope。只在 `onSystem` 的同步区间里非零 —— 不跨调用保存(Review Focus 2)。
var current_scope: u64 = 0;
/// 当次调用里已经用掉的 native 调用次数(第二道闸)。
var native_calls: u32 = 0;

var call_count: u64 = 0;
var write_count: u64 = 0;
var error_count: u64 = 0;
var timeout_count: u64 = 0;

// ---------------------------------------------------------------------------
// Clock + log sink (both injectable so the Linux tests read exact lines)
// ---------------------------------------------------------------------------

pub const Clock = struct {
    ctx: *anyopaque,
    now_ns: *const fn (ctx: *anyopaque) i128,
};

var clock: ?Clock = null;
var interrupt_deadline: i128 = 0;
var interrupt_fired: bool = false;

pub const Sink = struct {
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, line: []const u8) void,
};

var sink: ?Sink = null;

pub fn setSink(s: ?Sink) void {
    sink = s;
}

pub fn setClock(clk: ?Clock) void {
    clock = clk;
}

fn nowNs() i128 {
    if (clock) |clk| return clk.now_ns(clk.ctx);
    if (comptime is_windows) return @as(i128, GetTickCount64()) * std.time.ns_per_ms;
    return 0;
}

extern "kernel32" fn GetTickCount64() callconv(.c) u64;
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

const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;
const OPEN_ALWAYS: u32 = 4;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE_VALUE: usize = @bitCast(@as(i64, -1));

/// 追加一行到 `C:/temp/neo_js.log`。测试侧走 `sink` —— 文件写是 Windows-only,
/// 而 Linux 单测要逐字读这些行。
fn writeLine(line: []const u8) void {
    if (sink) |s| {
        s.write(s.ctx, line);
        return;
    }
    if (comptime is_windows) appendToFile(line);
}

fn appendToFile(line: []const u8) void {
    if (comptime !is_windows) return;
    const h = CreateFileA(LOG_PATH, FILE_APPEND_DATA, FILE_SHARE_READ_WRITE, null, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, null);
    const handle = h orelse return;
    if (@intFromPtr(handle) == INVALID_HANDLE_VALUE) return;
    var written: u32 = 0;
    _ = WriteFile(handle, line.ptr, @intCast(line.len), &written, null);
    _ = CloseHandle(handle);
}

fn emit(comptime fmt: []const u8, args: anytype) void {
    var buf: [384]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch return;
    writeLine(line);
}

fn clip(s: []const u8, max: usize) []const u8 {
    return if (s.len > max) s[0..max] else s;
}

/// 日志里的字符串先抹掉控制字符:mod 能给我们任意字节,而证据是按行读的。
fn sanitize(dst: []u8, src: []const u8) []const u8 {
    const n = @min(src.len, dst.len);
    for (src[0..n], 0..) |ch, i| dst[i] = if (ch < 0x20 or ch == 0x7F) '.' else ch;
    return dst[0..n];
}

// ---------------------------------------------------------------------------
// Pure-ish contract surface (tested without QuickJS)
// ---------------------------------------------------------------------------

pub fn apiVersion() u32 {
    return API_VERSION;
}

pub fn isChokepoint(score: u32) bool {
    return score >= CHOKEPOINT_THRESHOLD;
}

pub fn canSetVariable(p: Permissions) bool {
    return p.variable_write;
}

pub fn canReadGraph(p: Permissions) bool {
    return p.graph_read;
}

/// `graph.betweenness(s)` 的来源 = C5-SCORE 的同一个 `scoreFor`(烘焙表或 live 源)。
pub fn betweennessFor(p: Permissions, id: u32) u32 {
    if (!canReadGraph(p)) return 0;
    return neo_vtable.scoreFor(id) orelse 0;
}

pub fn chokepointFor(p: Permissions, id: u32) bool {
    if (!canReadGraph(p)) return false;
    return isChokepoint(neo_vtable.scoreFor(id) orelse 0);
}

/// 脚本数字 → C5-WRITE 的整数格(`neo_state.layoutNumber` 再按 1e-5 定点编码)。
/// NaN / inf / 负数 / 超出 u32 一律拒绝:出货 DLL 是 Debug 构建,一次
/// `@intFromFloat` 越界就是 `abort()` → 宿主被杀(AGENTS 约束 8)。
pub fn encodeScriptNumber(value: f64) ?u32 {
    if (!std.math.isFinite(value)) return null;
    if (value < 0 or value >= 4_294_967_296.0) return null;
    return @intFromFloat(value);
}

pub const WriteResult = enum {
    ok,
    no_permission,
    bad_name,
    bad_value,
    wrong_scope,
    no_engine,
};

/// `s.setVariable(name, value)` 的全部判定面(纯部分):权限 → 名字 → 值 →
/// 「这个 scope 是不是这个 id」→ 官方 body。真正触碰引擎的只有最后一步。
pub fn writeSystemVariable(p: Permissions, id: u32, name: []const u8, value: f64, scope: u64) WriteResult {
    if (!canSetVariable(p)) return .no_permission;
    if (name.len == 0 or name.len > MAX_VAR_NAME) return .bad_name;
    const number = encodeScriptNumber(value) orelse return .bad_value;
    // 写落在 scope 上,id 只是 JS 侧的镜像 —— 两者不一致就是「写进另一个星系」。
    const scope_id = neo_vtable.systemScopeId(scope) orelse return .wrong_scope;
    if (scope_id != id) return .wrong_scope;
    ensureWritePath();
    if (!neo_vtable.writeVariable(name, number, scope)) return .no_engine;
    _ = @atomicRmw(u64, &write_count, .Add, 1, .monotonic);
    return .ok;
}

/// 官方 `set_variable` body 的地址由 `C1Run` 解析;Runtime JS 不依赖那个时序,
/// 第一次要写时自己补一次(主线程、幂等、失败就 fail-closed 不写)。
fn ensureWritePath() void {
    if (neo_vtable.stateResolved()) return;
    const base = @intFromPtr(windows.moduleFunction(0) catch return);
    neo_vtable.resolveFromGame(base) catch return;
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

pub const Bundle = struct {
    /// mod 的 id(日志用;loader 保证它是安全的路径片段)。
    id: []const u8,
    /// bundle 的 JS 源码(必须是 sentinel 终止,`JS_Eval` 要 `[:0]const u8`)。
    source: [:0]const u8,
    permissions: Permissions,
};

/// 建(或复用)QuickJS context、注册 7 个 native、eval bundle、取回 handler。
///
/// **只建一次**:`runtime` 一旦存在就不重建(QuickJS 单线程,重建会丢 handler
/// 的 `JS_DupValue`)。测试里可以重复调用 —— 会复用同一个 context 重新 eval。
pub fn startSession(bundle: Bundle) bool {
    state = .failed;
    if (runtime == null) {
        runtime = quickjs.Runtime.initWithConfig(.{
            .mem_limit = CONTEXT_MEM_LIMIT,
            .max_stack_size = STACK_LIMIT,
        }) catch {
            emit("NEO_JS_INIT_FAIL", .{});
            return false;
        };
        c.JS_SetInterruptHandler(runtime.?.rt, interruptCb, null);
    }
    const rt = &runtime.?;
    const ctx = rt.ctx;

    permissions = bundle.permissions;
    // The bundle registers its handler *during* eval, i.e. also through a native.
    native_calls = 0;
    registerNatives(ctx);
    if (!handler.isUndefined()) {
        c.JS_FreeValue(ctx, handler);
        handler = c.JS_UNDEFINED;
    }

    const res = rt.eval(bundle.source, "<neo_mod>");
    switch (res) {
        .ok => |v| c.JS_FreeValue(ctx, v),
        .err => |e| {
            var line_buf: [160]u8 = undefined;
            emit("NEO_JS_EVAL_FAIL {s}", .{sanitize(&line_buf, clip(e.message, 150))});
            std.heap.page_allocator.free(e.message);
            return false;
        },
    }

    if (handler.isUndefined()) {
        emit("NEO_JS_NO_HANDLER", .{});
        return false;
    }
    state = .ready;
    emit("NEO_JS_INIT_OK id={s} api={d}", .{ bundle.id, API_VERSION });
    return true;
}

/// 第一次 `neo_action` 派发时调。失败只记一次日志,不重试(重试到崩是计划禁止的)。
fn ensureLoaded() void {
    if (state != .idle) return;
    state = .failed;
    const bundle = loadActive() orelse return;
    _ = startSession(bundle);
}

/// 活动 runtime mod 的来源:`C:/temp/neo_mods/<id>/neo/{mod.json,main.js}`。
/// 0 个 / 多个 mod 与每一种坏 manifest 都在这里变成一行具名日志后禁用(fail-closed,
/// 不重试)。off Windows 时 loader 没有文件系统,按「没有 mod」记 —— native 测试
/// 根走的就是这条路径。
fn loadActive() ?Bundle {
    const loaded = loader.loadActive() catch |err| {
        reportLoadError(err);
        return null;
    };
    return .{
        .id = loaded.manifest.id,
        .source = loaded.source,
        .permissions = loaded.manifest.permissions,
    };
}

/// loader 的失败面 → 日志词(计划 Review Focus 7:每一种都要能判读)。
fn reportLoadError(err: loader.LoadError) void {
    switch (err) {
        error.NoMod, error.NotWindows => emit("NEO_JS_NO_MOD", .{}),
        error.MultipleMods => emit("NEO_JS_MULTI_MOD n={d}", .{loader.lastModCount()}),
        error.EngineMismatch, error.RuntimeMismatch => emit("NEO_JS_API_MISMATCH", .{}),
        error.MissingEntry => emit("NEO_JS_MISSING_ENTRY", .{}),
        else => emit("NEO_JS_BAD_MANIFEST reason={s}", .{@errorName(err)}),
    }
}

fn registerNatives(ctx: ?*c.JSContext) void {
    const global = c.JS_GetGlobalObject(ctx);
    defer c.JS_FreeValue(ctx, global);
    for (native_table) |n| {
        const f = c.JS_NewCFunction2(ctx, n.func, n.name.ptr, n.length, c.JS_CFUNC_generic, 0);
        _ = c.JS_SetPropertyStr(ctx, global, n.name.ptr, f);
    }
}

// ---------------------------------------------------------------------------
// The per-system entry point
// ---------------------------------------------------------------------------

/// 每次 `neo_action` 的 per-system 派发(游戏主线程)。第一次调用懒加载;
/// ready 之后调一次 JS handler。任何失败都不向外抛 —— 游戏继续。
pub fn onSystem(id: u32, scope: u64) void {
    ensureLoaded();
    if (state != .ready) return;

    _ = @atomicRmw(u64, &call_count, .Add, 1, .monotonic);
    emit("NEO_JS_CALL id={d}", .{id});

    if (handler.isUndefined()) {
        emit("NEO_JS_NO_HANDLER", .{});
        return;
    }
    const rt = &runtime.?;
    const ctx = rt.ctx;

    native_calls = 0;
    current_scope = scope;
    defer current_scope = 0;

    var args = [_]c.JSValue{c.JSValue.int32(@intCast(@min(id, 0x7FFF_FFFF)))};
    interrupt_fired = false;
    interrupt_deadline = nowNs() + CALL_BUDGET_NS;
    const result = c.JS_Call(ctx, handler, c.JS_UNDEFINED, 1, &args);
    interrupt_deadline = 0;

    if (interrupt_fired) {
        _ = @atomicRmw(u64, &timeout_count, .Add, 1, .monotonic);
        emit("NEO_JS_TIMEOUT id={d}", .{id});
        // The interrupt leaves a pending exception; consume it so the next call
        // does not see a stale one.
        const exc = c.JS_GetException(ctx);
        c.JS_FreeValue(ctx, exc);
        return;
    }
    if (result.isException()) {
        _ = @atomicRmw(u64, &error_count, .Add, 1, .monotonic);
        reportException(ctx, id);
        return;
    }
    c.JS_FreeValue(ctx, result);
}

fn interruptCb(_: ?*c.JSRuntime, _: ?*anyopaque) callconv(.c) c_int {
    if (interrupt_deadline == 0) return 0;
    if (nowNs() < interrupt_deadline) return 0;
    interrupt_fired = true;
    return 1;
}

fn reportException(ctx: ?*c.JSContext, id: u32) void {
    const exc = c.JS_GetException(ctx);
    var len: usize = 0;
    const raw = c.JS_ToCStringLen2(ctx, &len, exc, false);
    if (raw) |msg| {
        var line_buf: [180]u8 = undefined;
        emit("NEO_JS_ERROR id={d} {s}", .{ id, sanitize(&line_buf, clip(msg[0..len], 160)) });
        c.JS_FreeCString(ctx, msg);
    } else {
        emit("NEO_JS_ERROR id={d} (unknown)", .{id});
    }
    c.JS_FreeValue(ctx, exc);
}

// ---------------------------------------------------------------------------
// Argument helpers (no throwing conversions: a bad arg is a value, not an abort)
// ---------------------------------------------------------------------------

fn argU32(argc: c_int, argv: [*]c.JSValue) ?u32 {
    if (argc < 1) return null;
    const v = argv[0];
    if (v.isInt32()) {
        const i = v.u.i32;
        return if (i < 0) null else @intCast(i);
    }
    if (v.isFloat64()) {
        const f = v.u.f64;
        if (!std.math.isFinite(f) or f < 0 or f >= 4_294_967_296.0) return null;
        return @intFromFloat(f);
    }
    return null;
}

fn argF64(argc: c_int, argv: [*]c.JSValue, idx: usize) ?f64 {
    if (argc <= idx) return null;
    const v = argv[idx];
    if (v.isInt32()) return @floatFromInt(v.u.i32);
    if (v.isFloat64()) return v.u.f64;
    return null;
}

fn argString(ctx: ?*c.JSContext, argc: c_int, argv: [*]c.JSValue, idx: usize, buf: []u8) ?[]const u8 {
    if (argc <= idx) return null;
    const v = argv[idx];
    if (!v.isString()) return null;
    var len: usize = 0;
    const p = c.JS_ToCStringLen2(ctx, &len, v, false) orelse return null;
    defer c.JS_FreeCString(ctx, p);
    const n = @min(len, buf.len);
    @memcpy(buf[0..n], p[0..n]);
    return buf[0..n];
}

/// 第二道闸:一次 handler 调用里的 native 调用次数。超了返回要抛的异常值。
fn charge(ctx: ?*c.JSContext) ?c.JSValue {
    if (native_calls >= MAX_NATIVE_CALLS_PER_HANDLER) {
        return c.JS_ThrowInternalError(ctx, "neo: native call budget exhausted");
    }
    native_calls += 1;
    return null;
}

// ---------------------------------------------------------------------------
// The seven natives
// ---------------------------------------------------------------------------

fn nativeRegisterSystem(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    if (argc < 1 or !c.JS_IsFunction(ctx, argv[0])) {
        return c.JS_ThrowTypeError(ctx, "onSystem expects a function");
    }
    if (!handler.isUndefined()) c.JS_FreeValue(ctx, handler);
    handler = c.JS_DupValue(ctx, argv[0]);
    return c.JS_UNDEFINED;
}

fn nativeSystemDegree(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    const id = argU32(argc, argv) orelse return c.JSValue.int32(0);
    if (!canReadGraph(permissions)) return c.JSValue.int32(0);
    const degree = graph_probe.systemDegree(id) orelse 0;
    return c.JSValue.int32(@intCast(@min(degree, 0x7FFF_FFFF)));
}

fn nativeSystemSetVar(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    const id = argU32(argc, argv) orelse return c.JS_UNDEFINED;
    var name_buf: [64]u8 = undefined;
    const name = argString(ctx, argc, argv, 1, &name_buf) orelse return c.JS_UNDEFINED;
    const value = argF64(argc, argv, 2) orelse return c.JS_UNDEFINED;

    const res = writeSystemVariable(permissions, id, name, value, current_scope);
    if (res == .ok) {
        var line_buf: [32]u8 = undefined;
        emit("NEO_JS_WRITE id={d} name={s}", .{ id, sanitize(&line_buf, name) });
    } else {
        var line_buf: [32]u8 = undefined;
        emit("NEO_JS_WRITE_REJECT id={d} name={s} reason={s}", .{
            id,
            sanitize(&line_buf, clip(name, 24)),
            @tagName(res),
        });
    }
    return c.JS_UNDEFINED;
}

fn nativeGraphBetweenness(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    const id = argU32(argc, argv) orelse return c.JSValue.int32(0);
    return c.JSValue.int32(@intCast(betweennessFor(permissions, id)));
}

fn nativeGraphIsChokepoint(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    const id = argU32(argc, argv) orelse return c.JSValue.boolVal(false);
    return c.JSValue.boolVal(chokepointFor(permissions, id));
}

fn nativeLog(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    if (!permissions.log) return c.JS_UNDEFINED;
    var text_buf: [256]u8 = undefined;
    const text = argString(ctx, argc, argv, 0, &text_buf) orelse text_buf[0..0];
    var line_buf: [256]u8 = undefined;
    emit("NEO_JS_LOG {s}", .{sanitize(&line_buf, clip(text, 250))});
    return c.JS_UNDEFINED;
}

fn nativeApiVersion(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = ctx;
    _ = this_val;
    _ = argc;
    _ = argv;
    return c.JSValue.int32(@intCast(API_VERSION));
}

// ---------------------------------------------------------------------------
// Readouts
// ---------------------------------------------------------------------------

pub fn status() Status {
    return state;
}

pub fn calls() u64 {
    return @atomicLoad(u64, &call_count, .monotonic);
}

pub fn writes() u64 {
    return @atomicLoad(u64, &write_count, .monotonic);
}

pub fn errors() u64 {
    return @atomicLoad(u64, &error_count, .monotonic);
}

pub fn timeouts() u64 {
    return @atomicLoad(u64, &timeout_count, .monotonic);
}

/// 只清状态机与计数,**不**释放 runtime / handler:`JS_DupValue` 的引用还挂在
/// `handler` 上,而且在 Windows 上这个 runtime 与进程同生命周期(永不 FreeLibrary)。
pub fn resetForTest() void {
    state = .idle;
    permissions = .{};
    current_scope = 0;
    native_calls = 0;
    interrupt_deadline = 0;
    interrupt_fired = false;
    clock = null;
    sink = null;
    @atomicStore(u64, &call_count, 0, .monotonic);
    @atomicStore(u64, &write_count, 0, .monotonic);
    @atomicStore(u64, &error_count, 0, .monotonic);
    @atomicStore(u64, &timeout_count, 0, .monotonic);
}

// ---------------------------------------------------------------------------
// Tests(Linux:真 vendored QuickJS,无引擎 —— 与 Phase 0 spike 同一条口径)
// ---------------------------------------------------------------------------

const testing = std.testing;

const Capture = struct {
    buf: [32768]u8 = undefined,
    len: usize = 0,

    /// 保留**尾部**:死循环那个用例会刷几千行,而判词要的是最后那行
    /// `NEO_JS_TIMEOUT`。前沿截断会让断言读到假阴性。
    fn write(ctx: *anyopaque, line: []const u8) void {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (line.len >= self.buf.len) {
            @memcpy(self.buf[0..], line[line.len - self.buf.len ..]);
            self.len = self.buf.len;
            return;
        }
        if (self.len + line.len > self.buf.len) {
            const drop = self.len + line.len - self.buf.len;
            std.mem.copyForwards(u8, self.buf[0 .. self.len - drop], self.buf[drop..self.len]);
            self.len -= drop;
        }
        @memcpy(self.buf[self.len..][0..line.len], line);
        self.len += line.len;
    }

    fn text(self: *Capture) []const u8 {
        return self.buf[0..self.len];
    }

    fn contains(self: *Capture, needle: []const u8) bool {
        return std.mem.indexOf(u8, self.text(), needle) != null;
    }
};

fn armCapture(cap: *Capture) void {
    cap.len = 0;
    setSink(.{ .ctx = @ptrCast(cap), .write = Capture.write });
}

const FakeClock = struct {
    ticks: i128 = 0,
    step: i128 = 20 * std.time.ns_per_ms,

    fn now(ctx: *anyopaque) i128 {
        const self: *FakeClock = @ptrCast(@alignCast(ctx));
        self.ticks += self.step;
        return self.ticks;
    }
};

var seen_body_calls: usize = 0;
var seen_name: [16]u8 = undefined;
var seen_value: u64 = 0;

fn stubBody(self_ptr: u64, scope: u64) callconv(.c) void {
    _ = scope;
    const base: [*]const u8 = @ptrFromInt(self_ptr);
    @memcpy(&seen_name, base[neo_state.NAME_STRING_OFF..][0..16]);
    seen_value = std.mem.readInt(u64, base[neo_state.VALUE_CELL_OFF..][0..8], .little);
    seen_body_calls += 1;
}

fn systemScope(id: u32) [0x20]u8 {
    var scope: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    std.mem.writeInt(u32, scope[neo_vtable.SCOPE_MASK_OFF..][0..4], 0x80, .little);
    std.mem.writeInt(u32, scope[neo_vtable.SCOPE_ID_OFF..][0..4], id, .little);
    return scope;
}

test "apiVersion is the frozen v1 contract value" {
    try testing.expectEqual(@as(u32, 1), apiVersion());
}

test "the seven native names are the frozen contract, in order" {
    const expected = [_][]const u8{
        "__neo_register_system",
        "__neo_system_degree",
        "__neo_system_set_var",
        "__neo_graph_betweenness",
        "__neo_graph_is_chokepoint",
        "__neo_log",
        "__neo_api_version",
    };
    try testing.expectEqual(expected.len, native_names.len);
    for (expected, 0..) |name, i| try testing.expectEqualStrings(name, native_names[i]);
    try testing.expectEqual(@as(usize, 7), native_table.len);
}

test "isChokepoint is the T2 threshold, inclusive at 200" {
    try testing.expect(isChokepoint(200));
    try testing.expect(!isChokepoint(199));
    try testing.expect(isChokepoint(1000));
    try testing.expect(!isChokepoint(0));
}

test "permission bits gate the write and the graph read independently" {
    const none = Permissions{};
    const write_only = Permissions{ .variable_write = true };
    const read_only = Permissions{ .graph_read = true };
    const full = Permissions{ .graph_read = true, .variable_write = true, .log = true };

    try testing.expect(!canSetVariable(none));
    try testing.expect(!canReadGraph(none));
    try testing.expect(canSetVariable(write_only));
    try testing.expect(!canReadGraph(write_only));
    try testing.expect(canReadGraph(read_only));
    try testing.expect(!canSetVariable(read_only));
    try testing.expect(canSetVariable(full) and canReadGraph(full));

    // No `graph.read` => 0/false even for an id the table knows.
    try testing.expectEqual(@as(u32, 0), betweennessFor(none, 0));
    try testing.expect(!chokepointFor(none, 0));
    // With `graph.read` the value is exactly C5-SCORE's `scoreFor`.
    const table_score = neo_vtable.scoreFor(0).?;
    try testing.expectEqual(@as(u32, table_score), betweennessFor(read_only, 0));
    try testing.expectEqual(isChokepoint(table_score), chokepointFor(read_only, 0));
}

test "encodeScriptNumber refuses anything a Debug build would abort on" {
    try testing.expectEqual(@as(?u32, 0), encodeScriptNumber(0));
    try testing.expectEqual(@as(?u32, 286), encodeScriptNumber(286));
    try testing.expectEqual(@as(?u32, 1000), encodeScriptNumber(1000.0));
    try testing.expectEqual(@as(?u32, null), encodeScriptNumber(-1));
    try testing.expectEqual(@as(?u32, null), encodeScriptNumber(std.math.nan(f64)));
    try testing.expectEqual(@as(?u32, null), encodeScriptNumber(std.math.inf(f64)));
    try testing.expectEqual(@as(?u32, null), encodeScriptNumber(4_294_967_296.0));
}

test "onSystem before a session loads logs NEO_JS_NO_MOD and never calls JS" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    onSystem(7, 0);

    try testing.expectEqual(Status.failed, status());
    try testing.expectEqual(@as(u64, 0), calls());
    try testing.expect(cap.contains("NEO_JS_NO_MOD"));
    try testing.expect(!cap.contains("NEO_JS_CALL"));
}

test "a session over a real bundle registers the handler and runs it per system" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    const ok = startSession(.{
        .id = "t1",
        .source = "__neo_register_system(function(id){ __neo_log('hit ' + id); });",
        .permissions = .{ .log = true },
    });
    try testing.expect(ok);
    try testing.expectEqual(Status.ready, status());

    onSystem(7, 0);
    onSystem(8, 0);

    try testing.expectEqual(@as(u64, 2), calls());
    try testing.expectEqual(@as(u64, 0), errors());
    try testing.expectEqual(@as(u64, 0), timeouts());
    try testing.expect(cap.contains("NEO_JS_INIT_OK id=t1 api=1"));
    try testing.expect(cap.contains("NEO_JS_CALL id=7"));
    try testing.expect(cap.contains("NEO_JS_LOG hit 7"));
    try testing.expect(cap.contains("NEO_JS_LOG hit 8"));
}

test "the bundle can read apiVersion through the native binding" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    const ok = startSession(.{
        .id = "api",
        .source = "__neo_register_system(function(id){ if (__neo_api_version() !== 1) throw new Error('api ' + __neo_api_version()); });",
        .permissions = .{},
    });
    try testing.expect(ok);
    onSystem(1, 0);
    try testing.expectEqual(@as(u64, 0), errors());
}

test "a bundle that does not parse is NEO_JS_EVAL_FAIL and never becomes ready" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    try testing.expect(!startSession(.{ .id = "bad", .source = "(function( {", .permissions = .{} }));
    try testing.expectEqual(Status.failed, status());
    try testing.expect(cap.contains("NEO_JS_EVAL_FAIL"));

    onSystem(1, 0);
    try testing.expectEqual(@as(u64, 0), calls());
}

test "a bundle that registers no handler is NEO_JS_NO_HANDLER" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    try testing.expect(!startSession(.{ .id = "noh", .source = "1 + 1;", .permissions = .{} }));
    try testing.expectEqual(Status.failed, status());
    try testing.expect(cap.contains("NEO_JS_NO_HANDLER"));
}

test "an exception inside the handler is NEO_JS_ERROR and the game keeps going" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    _ = startSession(.{
        .id = "throw",
        .source = "__neo_register_system(function(id){ throw new Error('boom'); });",
        .permissions = .{},
    });
    onSystem(3, 0);

    try testing.expectEqual(@as(u64, 1), calls());
    try testing.expectEqual(@as(u64, 1), errors());
    try testing.expectEqual(@as(u64, 0), timeouts());
    try testing.expect(cap.contains("NEO_JS_ERROR id=3"));
    try testing.expect(cap.contains("boom"));
}

test "an endless handler is stopped by the 10 ms budget and logs NEO_JS_TIMEOUT" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);
    var fake = FakeClock{};
    setClock(.{ .ctx = @ptrCast(&fake), .now_ns = FakeClock.now });

    _ = startSession(.{
        .id = "spin",
        .source = "__neo_register_system(function(id){ for(;;){ __neo_log('spin'); } });",
        .permissions = .{ .log = true },
    });
    onSystem(5, 0);

    try testing.expectEqual(@as(u64, 1), calls());
    try testing.expectEqual(@as(u64, 1), timeouts());
    try testing.expectEqual(@as(u64, 0), errors());
    try testing.expect(cap.contains("NEO_JS_TIMEOUT id=5"));

    // The next call is clean: the interrupt's pending exception was consumed.
    onSystem(6, 0);
    try testing.expect(cap.contains("NEO_JS_TIMEOUT id=6"));
    try testing.expectEqual(@as(u64, 0), errors());
}

test "setVariable without variable.write is rejected, not silently dropped" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);
    neo_vtable.armWritePathForTest(@intFromPtr(&stubBody), neo_vtable.RVA_STATE_VTABLE);
    seen_body_calls = 0;

    _ = startSession(.{
        .id = "noperm",
        .source = "__neo_register_system(function(id){ __neo_system_set_var(id, 'neo_score', 286); });",
        .permissions = .{},
    });
    const scope align(8) = systemScope(7);
    onSystem(7, @intFromPtr(&scope));

    try testing.expectEqual(@as(u64, 0), writes());
    try testing.expectEqual(@as(usize, 0), seen_body_calls);
    try testing.expect(cap.contains("NEO_JS_WRITE_REJECT id=7"));
    try testing.expect(cap.contains("reason=no_permission"));
}

test "setVariable writes through the official body with the C5-WRITE encoding" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);
    neo_vtable.armWritePathForTest(@intFromPtr(&stubBody), neo_vtable.RVA_STATE_VTABLE);
    seen_body_calls = 0;
    defer neo_vtable.resetForTest();

    _ = startSession(.{
        .id = "var",
        .source = "__neo_register_system(function(id){ __neo_system_set_var(id, 'neo_score', 286); });",
        .permissions = .{ .variable_write = true },
    });
    const scope align(8) = systemScope(7);
    onSystem(7, @intFromPtr(&scope));

    try testing.expectEqual(@as(u64, 1), writes());
    try testing.expectEqual(@as(usize, 1), seen_body_calls);
    try testing.expectEqualStrings("neo_score", seen_name[0.."neo_score".len]);
    // Same encoding as C5-WRITE: internal = value × 100000.
    try testing.expectEqual(neo_state.encodeNumber(286), seen_value);
    try testing.expect(cap.contains("NEO_JS_WRITE id=7 name=neo_score"));
}

test "setVariable refuses a scope whose id is not the id the JS handler saw" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);
    neo_vtable.armWritePathForTest(@intFromPtr(&stubBody), neo_vtable.RVA_STATE_VTABLE);
    seen_body_calls = 0;
    defer neo_vtable.resetForTest();

    _ = startSession(.{
        .id = "mismatch",
        .source = "__neo_register_system(function(id){ __neo_system_set_var(id, 'neo_score', 1); });",
        .permissions = .{ .variable_write = true },
    });
    // The dispatched scope says 9, the handler was called with 7.
    const scope align(8) = systemScope(9);
    onSystem(7, @intFromPtr(&scope));

    try testing.expectEqual(@as(u64, 0), writes());
    try testing.expectEqual(@as(usize, 0), seen_body_calls);
    try testing.expect(cap.contains("reason=wrong_scope"));
}

test "writeSystemVariable's gates are ordered: permission, name, value, scope, engine" {
    resetForTest();
    defer resetForTest();
    neo_vtable.armWritePathForTest(@intFromPtr(&stubBody), neo_vtable.RVA_STATE_VTABLE);
    seen_body_calls = 0;
    defer neo_vtable.resetForTest();

    const full = Permissions{ .variable_write = true };
    const scope align(8) = systemScope(7);
    const sp = @intFromPtr(&scope);

    try testing.expectEqual(WriteResult.no_permission, writeSystemVariable(.{}, 7, "neo_score", 1, sp));
    try testing.expectEqual(WriteResult.bad_name, writeSystemVariable(full, 7, "", 1, sp));
    try testing.expectEqual(WriteResult.bad_name, writeSystemVariable(full, 7, "0123456789abcdef", 1, sp));
    try testing.expectEqual(WriteResult.bad_value, writeSystemVariable(full, 7, "neo_score", -1, sp));
    try testing.expectEqual(WriteResult.wrong_scope, writeSystemVariable(full, 7, "neo_score", 1, 0));
    try testing.expectEqual(WriteResult.ok, writeSystemVariable(full, 7, "neo_score", 1, sp));
    try testing.expectEqual(@as(usize, 1), seen_body_calls);

    neo_vtable.armWritePathForTest(0, 0);
    try testing.expectEqual(WriteResult.no_engine, writeSystemVariable(full, 7, "neo_score", 1, sp));
}

test "log is gated by the log permission" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    _ = startSession(.{
        .id = "nolog",
        .source = "__neo_register_system(function(id){ __neo_log('should not appear'); });",
        .permissions = .{},
    });
    onSystem(1, 0);
    try testing.expect(!cap.contains("should not appear"));
    try testing.expect(!cap.contains("NEO_JS_LOG"));
}

test "resetForTest clears the state machine and the counters" {
    resetForTest();
    _ = startSession(.{ .id = "r", .source = "__neo_register_system(function(id){ });", .permissions = .{} });
    onSystem(1, 0);
    try testing.expect(calls() > 0);
    resetForTest();
    try testing.expectEqual(Status.idle, status());
    try testing.expectEqual(@as(u64, 0), calls());
    try testing.expectEqual(@as(u64, 0), writes());
    try testing.expectEqual(@as(u64, 0), errors());
    try testing.expectEqual(@as(u64, 0), timeouts());
    try testing.expectEqual(Permissions{}, permissions);
}
