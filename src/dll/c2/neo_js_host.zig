// neo_js_host.zig — Runtime JS host v1/v1.1(Track A):native API + handler 调用 + 限额。
//
// **Phase 1 的 7 个 native 是冻结合同**(`sdk/api.def` 是权威,由 C1 的合同围栏核对):
// 这 7 个名字一个不改;`apiVersion()` 恒为 1。v1.1 的新函数只**加**,并且放在
// `additive_native_table` 里(见下),冻结合同表保持原样。TS 侧(`@neo/runtime`)
// 的 v1 面只暴露 `onSystem` / `System` / `graph` / `log` / `apiVersion`。
//
//   __neo_register_system(fn)                  handler 注册(bundle 顶层调用一次)
//   __neo_system_degree(id) -> u32             边容器 `+0x59C`
//   __neo_system_set_var(id, name, value)      官方 `set_variable` body(1e-5 定点)
//   __neo_graph_betweenness(id) -> u32         `neo_vtable.scoreFor(id)`(C5-SCORE 同源)
//   __neo_graph_is_chokepoint(id) -> bool      `score >= 200`(T2 阈值)
//   __neo_log(text)                            `C:/temp/neo_js.log`
//   __neo_api_version() -> u32                 1
//
// Phase 2(v1.1,**加法**,`API_VERSION` 仍为 1)的 native 在 `additive_native_table`:
//   __neo_system_neighbors(id) -> array<u32>   系统边容器 `+0x588/+0x590/+0x59C`
//   __neo_system_set_flag(id, name)            官方 `set_star_flag` `+0x48` body
//   __neo_system_has_flag(id, name) -> bool    系统 flag 容器 `+0x5f8`
//   __neo_register_country(fn)                 country 派发 handler(`scope:["country"]`)
// `s.name` / `s.variable` 在 A1 静态侦察里是 deferred(没有可安全调用的官方
// read path),**不实现**。`sdk/api.def` 由 Track B 补齐;在那之前这 3 个名字只
// 存在于本文件的加法表里(冻结合同表仍是 7 个,见 `native_names`)。
//
// 多 mod(Task A3):每个 mod 一个 QuickJS runtime/context(`Session`),最多 8 个;
// 一个 session 的异常/超时/越权只禁用**它自己**,其它 session 继续。
//
// 纪律(计划 Review Focus,逐条落点):
//   1. **主线程**:runtime/context 只在 `startSession` 里建,唯一生产调用方是
//      `onSystem`(逐系统派发 = 游戏主线程)。**不复用** `main.js_runtime` —— 那是
//      `C2Init` 在远程线程里建的,QuickJS 单线程。
//   2. **scope 指针不跨调用保存**:`onSystem` 把当次 scope 放进 `current_scope`,
//      handler 返回即恢复。JS 只拿 id;写路径用当次 scope 调官方 body,并在写之前
//      核对 `scope+0x10 == id`(不一致就拒写,而不是写进另一个星系)。
//   3. **写只走官方 body**:`neo_vtable.writeVariable` —— 与 C5-WRITE / C5-SCORE
//      完全相同的对象布局、body(`0x188E1D0`)与 1e-5 定点编码。不写引擎内存。
//   4. **异常隔离**:JS 异常 / 超时 / 越权只把**该 session** `active=false`(A3/A4),
//      其它 session 继续;游戏继续。每次 handler 调用有 10 ms 中断预算
//      (`JS_SetInterruptHandler` 读我们自己的 deadline);另有一道「一次调用里的
//      native 调用次数」上限,作为中断路径失效时的第二道闸。
//   5. **限额**:每个 context 16 MiB、栈 1 MiB;最多 8 个 session。
//   6. **永不 `FreeLibrary`**;runtime 与进程同生命周期(生产路径不 deinit)。
//
// 日志口径(驱动/证据按行读):
//   NEO_JS_INIT_OK id=<mod> api=1 | NEO_JS_INIT_FAIL id=<mod> | NEO_JS_SESSION_LIMIT id=<mod>
//   NEO_JS_EVAL_FAIL id=<mod> <msg> | NEO_JS_NO_HANDLER id=<mod>
//   NEO_JS_NO_MOD / NEO_JS_TOO_MANY_MODS n=<n> / NEO_JS_MODS n=<n>
//   NEO_JS_BAD_MANIFEST / NEO_JS_MISSING_ENTRY / NEO_JS_API_MISMATCH
//   NEO_JS_CALL id=<id>           每次 onSystem 一行(不管几个 session)
//   NEO_JS_CALL_COUNTRY id=<id>   每次 onCountry 一行(mask==0x04 的派发)
//   NEO_JS_REGISTER_REJECT id=<mod> scope=country  bundle 没声明 country 却注册了 handler
//   NEO_JS_WRITE id=<id> name=<name> [kind=flag]
//   NEO_JS_WRITE_REJECT … reason=<tag> [kind=flag]
//   NEO_JS_FLAG_REJECT id=<id> name=<name> reason=no_permission|no_flag_token
//   NEO_JS_NEIGHBORS_REJECT id=<id> reason=no_permission
//   NEO_JS_NEIGHBORS_TRUNC id=<id> total=<n> written=<n>
//   NEO_JS_LOG <text>
//   NEO_JS_ERROR id=<id> mod=<mod> <message> | NEO_JS_TIMEOUT id=<id> mod=<mod>
//   NEO_SCOPE_OTHER mask=0x<mm> … vtable_rva/6×u32  非 system scope 的只读指纹(前 3 次)
//   NEO_SCOPE_OTHER_SEEN n=<n>                       之后每 500 次一行计数
//   NEO_C3_ECON id=<id> holder=0x<x> vt_rva=0x<x> s90=0x<x> s98=0x<x>
//       C3 国家侦察(前 3 个国家):[country+0x2c68] 经济持有者 + 两个槽目标(只读指针)
//   NEO_C3_RES db_n=<n> energy_obj=0x<x> energy_idx=<n|na>
//       资源库条数 / `[[0x33746F0]+0x20]` / 能量索引(与 ECON 同一行组,只打 3 国)
//   NEO_C3_OPINION self=<id> target=0 a=<n|na> b=<n|na>
//       opinion 双向(a = 引擎 `opinion`,b = `their_opinion`;前 40 个国家)
//   NEO_JS_OPINION_REJECT self=<s> target=<t> reason=<tag>
//       tag = no_permission | scope_mismatch | table_null | out_of_range | not_computed

const std = @import("std");
const builtin = @import("builtin");
const c = @import("../quickjs/bindings.zig");
const quickjs = @import("../quickjs/runtime.zig");
const windows = @import("../hooking/windows.zig");
const neo_vtable = @import("neo_vtable.zig");
const neo_state = @import("neo_state.zig");
const graph_probe = @import("graph_probe.zig");
const loader = @import("neo_js_loader.zig");
const flag_ids = @import("flag_ids.zig");
const offsets = @import("../shared/offsets.zig");
const opinion_table = @import("opinion_table.zig");
const country_probe = @import("country_probe.zig");

const is_windows = builtin.os.tag == .windows;

// ---------------------------------------------------------------------------
// Frozen contract
// ---------------------------------------------------------------------------

pub const API_VERSION: u32 = 1;

/// v1 的权限位。`packed struct` 是有意的:一个 u8 就能原子地描述整组权限,
/// loader 解析出它、host 只读它。Phase 2 只**加位**(v1.1 是加法):`variable.read`
/// / `flag.write` / `flag.read` 供 A1 resolved 的 API 用,旧 manifest 的三种权限
/// 语义不变。
pub const Permissions = packed struct {
    graph_read: bool = false,
    variable_write: bool = false,
    variable_read: bool = false,
    flag_write: bool = false,
    flag_read: bool = false,
    log: bool = false,
    /// v1.1(2026-11-08):只读 opinion 矩阵。**只有读**,没有任何写位 ——
    /// 写路径不开(计划 Global Constraints)。
    opinion_read: bool = false,
};

/// 一个 bundle 声明要接哪几种派发。`packed struct` 与 `Permissions` 同一个理由:
/// 一份位集就能原子地描述「这个 session 该被谁调用」。
///
/// 声明与 handler 必须匹配:只声明 `country` 的 bundle 不会被 `onSystem` 调用,
/// 反过来 `__neo_register_country` 在没有 `country` 声明的 session 里落一行
/// `NEO_JS_REGISTER_REJECT`(而不是静默待用 —— 那会让「为什么我的 handler 不跑」
/// 变成一条无法判读的静默失败)。
pub const Scopes = packed struct {
    system: bool = false,
    country: bool = false,
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

/// 合同名字的只读视图(C1 的围栏与测试都读它)。**只含 Phase 1 的 7 个冻结名**。
pub const native_names = blk: {
    var names: [native_table.len][]const u8 = undefined;
    for (native_table, 0..) |n, i| names[i] = n.name;
    break :blk names;
};

/// Phase 2 (v1.1) 的**加法** native。刻意与 `native_table` 分开:
/// `native_table`/`native_names` 是 Phase 1 的冻结合同,由
/// `scripts/test_runtime_js_contract.py` 与 `sdk/api.def` 逐项对照;本轨道按任务
/// 约束不改 `sdk/**`,而 v1.1 的 TS/mock/api.def 由 Track B(B1/B5)补齐。合并任务
/// (C1)把两边的名字对齐后,这张表才会进围栏。
///
/// 字段叫 `js_name` 而不是 `name` 也是这个分离的结果:围栏用
/// `.name = "(__neo_[a-z_]+)"` 抓合同表,加法表不在它的口径里。
pub const AdditiveEntry = struct {
    js_name: [:0]const u8,
    func: c.JSCFunction,
    length: c_int,
};

const additive_native_table = [_]AdditiveEntry{
    .{ .js_name = "__neo_system_neighbors", .func = nativeSystemNeighbors, .length = 1 },
    .{ .js_name = "__neo_system_set_flag", .func = nativeSystemSetFlag, .length = 2 },
    .{ .js_name = "__neo_system_has_flag", .func = nativeSystemHasFlag, .length = 2 },
    .{ .js_name = "__neo_register_country", .func = nativeRegisterCountry, .length = 1 },
    .{ .js_name = "__neo_country_opinion", .func = nativeCountryOpinion, .length = 2 },
    .{ .js_name = "__neo_country_their_opinion", .func = nativeCountryTheirOpinion, .length = 2 },
};

pub const additive_names = blk: {
    var names: [additive_native_table.len][]const u8 = undefined;
    for (additive_native_table, 0..) |n, i| names[i] = n.js_name;
    break :blk names;
};

// ---------------------------------------------------------------------------
// State (main thread only — Review Focus 1)
// ---------------------------------------------------------------------------

pub const Status = enum { idle, ready, failed };

/// Phase 2 (Task A3): 每个 mod 一个 QuickJS session(runtime + context)。最多 8 个;
/// 一个 session 的异常/超时/越权只把**它自己** `active=false`,其它照常跑。
pub const MAX_SESSIONS: usize = 8;

pub const Session = struct {
    /// mod id(日志用;loader 保证它是安全的路径片段)。
    id: []const u8,
    runtime: quickjs.Runtime,
    handler: c.JSValue = c.JS_UNDEFINED,
    /// `onCountry` 的 handler。`undefined` = 这个 session 没注册(不是错)。
    country_handler: c.JSValue = c.JS_UNDEFINED,
    permissions: Permissions = .{},
    /// bundle 声明的派发位集:只有声明了的那一族才会被调用。
    scopes: Scopes = .{ .system = true },
    /// `false` = 被禁用(异常/超时/越权/坏 bundle):`onSystem` 跳过它。
    active: bool = false,
    /// 一次 handler 调用里已经用掉的 native 调用次数(第二道闸)。
    native_calls: u32 = 0,
    sessions_calls: u64 = 0,
    sessions_writes: u64 = 0,
    sessions_errors: u64 = 0,
    sessions_timeouts: u64 = 0,
};

var sessions: [MAX_SESSIONS]Session = undefined;
var session_len: usize = 0;
/// 当前正在跑的 session 下标 —— native 从它读取 permissions / handler。
var active_index: usize = 0;
var state: Status = .idle;

/// 当次派发的 scope。只在 `onSystem` 的同步区间里非零 —— 不跨调用保存(Review Focus 2)。
var current_scope: u64 = 0;

var call_count: u64 = 0;
var write_count: u64 = 0;
var error_count: u64 = 0;
var timeout_count: u64 = 0;

fn currentSession() ?*Session {
    if (session_len == 0 or active_index >= session_len) return null;
    return &sessions[active_index];
}

fn currentPermissions() Permissions {
    if (currentSession()) |s| return s.permissions;
    return .{};
}

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

/// 一行日志的公共出口(host 的所有 `NEO_JS_*` 行共用)。
pub fn emit(comptime fmt: []const u8, args: anytype) void {
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

pub fn canReadVariable(p: Permissions) bool {
    return p.variable_read;
}

pub fn canWriteFlag(p: Permissions) bool {
    return p.flag_write;
}

pub fn canReadFlag(p: Permissions) bool {
    return p.flag_read;
}

pub fn canReadOpinion(p: Permissions) bool {
    return p.opinion_read;
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
    if (neo_vtable.stateResolved() and neo_vtable.flagsResolved()) return;
    const base = @intFromPtr(windows.moduleFunction(0) catch return);
    neo_vtable.resolveFromGame(base) catch return;
}

/// `s.setStarFlag(name)` 的判定面(纯部分):权限 → 名字 →「scope 是不是这个 id」→
/// **官方 flag 名表** → 官方 `set_star_flag` body。写落在 scope 上,id 只是 JS 侧的镜像。
///
/// 名字→u16 的解析走 `0x326D110` 那张 flag 表(`flag_ids.ensure`),**不是** lexer
/// token 表(`0x1D13270`)。P2-1b 两发实机证明后者发出来的号与官方脚本解析出的号
/// 永不相等(evidence/analysis/flag_store_4_4_4.md §2.3)。16 位上限属于 flag 表
/// 自己的号段,所以安装期预发号(`NEO_JS_PREMINT`)已删除。
pub const FlagResult = enum {
    ok,
    no_permission,
    bad_name,
    wrong_scope,
    no_flag_body,
    /// flag 表拿不到号:未解析到模块基址、名字非法、计数器为 0、或 `0xFFFF` 哨兵。
    no_flag_token,
};

pub fn setSystemFlag(p: Permissions, id: u32, name: []const u8, scope: u64) FlagResult {
    if (!canWriteFlag(p)) return .no_permission;
    if (name.len == 0 or name.len > MAX_VAR_NAME) return .bad_name;
    const scope_id = neo_vtable.systemScopeId(scope) orelse return .wrong_scope;
    if (scope_id != id) return .wrong_scope;
    ensureWritePath();
    if (!neo_vtable.flagsResolved()) return .no_flag_body;
    // ensure 可能往**引擎的** flag 表里插一个新名字;它排在 body 解析之后,
    // 这样「写不了」时不会留下一条只有号、没有 flag 的登记。
    const flag_id = flag_ids.ensure(name) orelse return .no_flag_token;
    if (!neo_vtable.setStarFlagId(flag_id, scope)) return .no_flag_body;
    _ = @atomicRmw(u64, &write_count, .Add, 1, .monotonic);
    return .ok;
}

/// `s.hasStarFlag(name)` 的只读面:权限 → 名字 → **flag 表 lookup(只读)** → 系统 flag
/// 容器扫描。`+0x5f8` 容器 / `+0x10` u16 数组 / `+0x1c` 计数(`offsets.graph.FLAG_*`)。
///
/// `null` = 这个名字在 flag 表里没有号(没声明、也没被写过);`false` = 有号但容器里
/// 没有它(容器读不到也按 false fail-closed)。读路径**永不**给名字发号。
pub fn readSystemFlag(p: Permissions, id: u32, name: []const u8) ?bool {
    if (!canReadFlag(p)) return null;
    if (name.len == 0 or name.len > MAX_VAR_NAME) return null;
    const flag_id = flag_ids.lookup(name) orelse return null;
    return graph_probe.systemHasFlag(id, flag_id) orelse false;
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
    /// 缺省 = 只接 system —— Phase 1/2 的旧调用点语义不变。
    scopes: Scopes = .{ .system = true },
};

/// 建一个 QuickJS session(context)、注册 native、eval bundle、取回 handler。
///
/// Phase 2(A3):每个 mod 一个 session,最多 `MAX_SESSIONS` 个。失败只影响这一个
/// (`active=false`),不重试。`resetForTest` 之前不会重建同一个 session。
pub fn startSession(bundle: Bundle) bool {
    if (session_len >= MAX_SESSIONS) {
        emit("NEO_JS_SESSION_LIMIT id={s}", .{bundle.id});
        state = .failed;
        return false;
    }
    const idx = session_len;
    var rt = quickjs.Runtime.initWithConfig(.{
        .mem_limit = CONTEXT_MEM_LIMIT,
        .max_stack_size = STACK_LIMIT,
    }) catch {
        emit("NEO_JS_INIT_FAIL id={s}", .{bundle.id});
        state = .failed;
        return false;
    };
    const ctx = rt.ctx;
    c.JS_SetInterruptHandler(rt.rt, interruptCb, null);
    sessions[idx] = .{
        .id = bundle.id,
        .runtime = rt,
        .permissions = bundle.permissions,
        .scopes = bundle.scopes,
        .active = false,
    };
    session_len = idx + 1;
    active_index = idx;

    // The bundle registers its handler *during* eval, i.e. also through a native.
    sessions[idx].native_calls = 0;
    registerNatives(ctx);

    const res = rt.eval(bundle.source, "<neo_mod>");
    switch (res) {
        .ok => |v| c.JS_FreeValue(ctx, v),
        .err => |e| {
            var line_buf: [160]u8 = undefined;
            emit("NEO_JS_EVAL_FAIL id={s} {s}", .{ bundle.id, sanitize(&line_buf, clip(e.message, 150)) });
            std.heap.page_allocator.free(e.message);
            state = .failed;
            return false;
        },
    }

    if (sessions[idx].handler.isUndefined() and sessions[idx].country_handler.isUndefined()) {
        emit("NEO_JS_NO_HANDLER id={s}", .{bundle.id});
        state = .failed;
        return false;
    }
    sessions[idx].active = true;
    state = .ready;
    emit("NEO_JS_INIT_OK id={s} api={d}", .{ bundle.id, API_VERSION });
    return true;
}

/// 第一次 `neo_action` 派发时调。失败只记一次日志,不重试(重试到崩是计划禁止的)。
fn ensureLoaded() void {
    if (state != .idle) return;
    state = .failed;
    const list = loader.loadActiveList() catch |err| {
        reportLoadError(err);
        return;
    };
    if (list.len == 0) {
        if (loader.lastListStats().skipped > 0) {
            emit("NEO_JS_BAD_MANIFEST n={d}", .{loader.lastListStats().skipped});
        } else {
            emit("NEO_JS_NO_MOD", .{});
        }
        return;
    }
    const stats = loader.lastListStats();
    if (stats.overflow > 0) emit("NEO_JS_TOO_MANY_MODS n={d}", .{stats.overflow});
    if (list.len > 1) emit("NEO_JS_MODS n={d}", .{list.len});
    var ready = false;
    for (list) |loaded| {
        const bundle = Bundle{
            .id = loaded.manifest.id,
            .source = loaded.source,
            .permissions = loaded.manifest.permissions,
            .scopes = loaded.manifest.scopes,
        };
        if (startSession(bundle)) ready = true;
    }
    state = if (ready) .ready else .failed;
}

/// loader 的失败面 → 日志词(计划 Review Focus 7:每一种都要能判读)。
fn reportLoadError(err: loader.LoadError) void {
    switch (err) {
        error.NoMod, error.NotWindows => emit("NEO_JS_NO_MOD", .{}),
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
    for (additive_native_table) |n| {
        const f = c.JS_NewCFunction2(ctx, n.func, n.js_name.ptr, n.length, c.JS_CFUNC_generic, 0);
        _ = c.JS_SetPropertyStr(ctx, global, n.js_name.ptr, f);
    }
}

// ---------------------------------------------------------------------------
// The per-system entry point
// ---------------------------------------------------------------------------

/// 每次 `neo_action` 的 per-system 派发(游戏主线程)。第一次调用懒加载;
/// ready 之后对**每个 active session** 调一次 handler。任何失败都不向外抛 ——
/// 游戏继续,且只禁用出错的那个 session(Task A3/A4)。
pub fn onSystem(id: u32, scope: u64) void {
    ensureLoaded();
    if (state != .ready) return;

    // C2: 引擎把 effect 派发进非 system scope（`every_country`）时落一行只读指纹。
    // 放在 session 循环之前 —— 判词是「scope 长什么样」，与有没有 mod 无关。
    noteOtherScope(scope);

    _ = @atomicRmw(u64, &call_count, .Add, 1, .monotonic);
    emit("NEO_JS_CALL id={d}", .{id});

    const saved_scope = current_scope;
    current_scope = scope;
    defer current_scope = saved_scope;

    var i: usize = 0;
    while (i < session_len) : (i += 1) {
        if (!sessions[i].active) continue;
        // 声明与派发必须匹配:只声明 `country` 的 bundle 不能接 system 派发。
        if (!sessions[i].scopes.system) continue;
        if (sessions[i].handler.isUndefined()) {
            emit("NEO_JS_NO_HANDLER id={d} mod={s}", .{ id, sessions[i].id });
            sessions[i].active = false;
            continue;
        }
        runSession(i, id);
    }
}

/// 一次 country 派发(游戏主线程,`mask == 0x04` 的那条路径)。
///
/// 与 `onSystem` 同形:一行 `NEO_JS_CALL_COUNTRY`,然后把当次 scope 放进
/// `current_scope`(natives 只在这条同步区间里读它),只调用**声明了 country**
/// 且注册了 handler 的 session。`id` 是引擎写在 `scope+0x10` 的那个值 ——
/// `opinion` 读器会拿它和 JS 传回来的 `self` 核对(不一致就拒读)。
pub fn onCountry(id: u32, scope: u64) void {
    ensureLoaded();
    if (state != .ready) return;

    _ = @atomicRmw(u64, &country_call_count, .Add, 1, .monotonic);
    emit("NEO_JS_CALL_COUNTRY id={d}", .{id});

    const saved_scope = current_scope;
    current_scope = scope;
    defer current_scope = saved_scope;

    var i: usize = 0;
    while (i < session_len) : (i += 1) {
        const s = &sessions[i];
        if (!s.active or !s.scopes.country) continue;
        if (s.country_handler.isUndefined()) continue; // 没注册不是错
        runCountrySession(i, id);
    }
}

var country_call_count: u64 = 0;

/// `onCountry` 的读数(诊断/测试)。
pub fn countryCalls() u64 {
    return @atomicLoad(u64, &country_call_count, .monotonic);
}

/// Slice 2 的**只读**诊断:引擎把我们注册的 effect 派发进一个**非 system** scope
/// (C2 的驱动 `every_country = { neo_action = { } }` 就是这一趟)时落一行。
///
/// 只读两个格子(`neo_vtable.scopeFields`),不写引擎内存、不改 scope、不调任何 body。
/// 拿不到就整行不打 —— 一行读错的数比没有更糟。
///
/// **判据只认 `mask`。** `mask=` 是这次要量的事实(引擎给这一趟的 scope 打了什么记号);
/// `id=` 是 `+0x10` 那个 u32 —— 对 system 一族它是系统 id,对**别的** scope 它只是同一格
/// 的值,所以「id 就是国家 id」这句话不在本行的判据里(取证卷
/// `country_scope_4_4_4.md` 的 unresolved 项)。
pub fn noteOtherScope(scope: u64) void {
    const fields = neo_vtable.scopeFields(scope) orelse return;
    if (neo_vtable.isSystemScope(fields[0])) return;

    // C3(2026-11-08): 国家派发(mask == 0x04)额外落三行只读读数。放在指纹闸门
    // **之前** —— 指纹只打前 3 次,而 opinion 行要打到前 40 个国家;放在闸门之后就
    // 会被 `seen >= OTHER_SCOPE_FINGERPRINTS` 的 return 吞掉(计划 Task 2 的 40 条
    // 上限测试正是盯着这一点)。
    if (fields[0] == offsets.country.SCOPE_MASK) emitCountryProbe(fields[1]);

    // C2(2026-11-08): 只看 mask 只能回答「scope 来了没有」,回答不了「字段在哪」。
    // 前 3 次落完整指纹(vtable + 6 个候选 u32),之后只落计数 —— 一个月的
    // `every_country` 会把这条路径跑几百次,逐次全打会把日志淹掉。
    const seen = @atomicRmw(u64, &other_scope_count, .Add, 1, .monotonic);
    if (seen >= OTHER_SCOPE_FINGERPRINTS) {
        if (seen % OTHER_SCOPE_SUMMARY_EVERY == 0) {
            emit("NEO_SCOPE_OTHER_SEEN n={d} mask=0x{x:0>2}", .{ seen + 1, fields[0] });
        }
        return;
    }

    const base: usize = if (windows.moduleFunction(0)) |fn_ptr| @intFromPtr(fn_ptr) else |_| 0;
    const vtable = readU64Safe(scope) orelse 0;
    const vtable_rva: u64 = if (base != 0 and vtable >= base and vtable - base < 0x4000_0000) vtable - base else 0;
    emit(
        "NEO_SCOPE_OTHER mask=0x{x:0>2} id={d} vtable_rva=0x{x} u08=0x{x:0>8} u10=0x{x:0>8} u18=0x{x:0>8} u20=0x{x:0>8} u28=0x{x:0>8}",
        .{
            fields[0],
            fields[1],
            vtable_rva,
            readU32Safe(scope + 0x08) orelse 0,
            readU32Safe(scope + 0x10) orelse 0,
            readU32Safe(scope + 0x18) orelse 0,
            readU32Safe(scope + 0x20) orelse 0,
            readU32Safe(scope + 0x28) orelse 0,
        },
    );
}

/// 前几次落完整指纹;之后每 N 次一行计数。数字是判据的一部分,不要随手改。
const OTHER_SCOPE_FINGERPRINTS: u64 = 3;
const OTHER_SCOPE_SUMMARY_EVERY: u64 = 500;

var other_scope_count: u64 = 0;

// ---------------------------------------------------------------------------
// C3(2026-11-08)— 国家侦察行(经济容器指纹 + 能量索引 + opinion 双向)
// ---------------------------------------------------------------------------
//
// 三行的上限是判据的一部分:完整经济行只打前 3 个国家(econ 持有者/槽目标对
// 大多数国家是同一个类,重复没有信息量),opinion 行只打前 40 个 —— 一个月的
// `every_country` 会跑「国家数 × 月数」次,不限就是 200+ 行一脉冲。
//
// 只读:全部经 `country_probe.collect`(仅 `read_u32/read_u64`),**不调用**任何
// 引擎虚函数(尤其不碰 `[econ+0x90]`,它会填充调用方向量)。

/// 前 3 个国家打完整经济行;之后不再打。
const C3_ECON_LIMIT: u64 = 3;
/// 前 40 个国家打 opinion 行;之后不再打。
const C3_OPINION_LIMIT: u64 = 40;

var c3_econ_count: u64 = 0;
var c3_opinion_count: u64 = 0;

/// 测试注入的读面/地址(非 Windows 上 `moduleBase()` 恒为 0,生产口径只能读 `na`)。
var c3_memory: ?country_probe.Memory = null;
var c3_addresses: ?country_probe.Addresses = null;

pub fn setCountryProbeForTest(mem: ?country_probe.Memory, addrs: ?country_probe.Addresses) void {
    c3_memory = mem;
    c3_addresses = addrs;
}

fn countryProbeMemory() country_probe.Memory {
    if (c3_memory) |m| return m;
    return .{
        .ctx = @ptrCast(&production_ctx),
        .read_u32 = productionReadU32,
        .read_u64 = productionReadU64,
    };
}

fn countryProbeAddresses() country_probe.Addresses {
    if (c3_addresses) |a| return a;
    const base = moduleBase();
    if (base == 0) return .{ .country_table = 0, .resource_db = 0 };
    return .{
        .country_table = std.math.add(u64, base, country_probe.RVA_COUNTRY_TABLE) catch 0,
        .resource_db = std.math.add(u64, base, country_probe.RVA_RESOURCE_DB) catch 0,
    };
}

/// 一个 opinion 格子的打印文本:`<n>` 或 `na`(任何失败 —— 空表/越界/哨兵/读不到)。
fn opinionText(buf: []u8, v: ?i32) []const u8 {
    const value = v orelse return "na";
    return std.fmt.bufPrint(buf, "{d}", .{value}) catch "na";
}

fn c3Opinion(row: u32, col: u32) ?i32 {
    const addr = descriptorAddr() orelse return null;
    const table = opinion_table.load(opinionMemory(), addr) catch return null;
    return opinion_table.value(opinionMemory(), table, row, col) catch null;
}

fn emitCountryProbe(id: u32) void {
    const reading = country_probe.collect(
        countryProbeMemory(),
        countryProbeAddresses(),
        id,
        moduleBase(),
    );

    if (@atomicRmw(u64, &c3_econ_count, .Add, 1, .monotonic) < C3_ECON_LIMIT) {
        emit("NEO_C3_ECON id={d} holder=0x{x} vt_rva=0x{x} s90=0x{x} s98=0x{x}", .{
            id,
            reading.econ,
            reading.econ_vtable_rva,
            reading.slot90_rva,
            reading.slot98_rva,
        });
        if (reading.energy_idx) |idx| {
            emit("NEO_C3_RES db_n={d} energy_obj=0x{x} energy_idx={d}", .{
                reading.res_n,
                reading.energy_obj,
                idx,
            });
        } else {
            emit("NEO_C3_RES db_n={d} energy_obj=0x{x} energy_idx=na", .{
                reading.res_n,
                reading.energy_obj,
            });
        }
    }

    if (@atomicRmw(u64, &c3_opinion_count, .Add, 1, .monotonic) < C3_OPINION_LIMIT) {
        // 引擎 `opinion` 的键序是 row = 目标、col = 我们(§2.3 A 级);target 固定取 0
        // —— 人类玩家在 C2 的实机读数里就是 id=0,这一发就是拿它与 AI 国对读。
        var a_buf: [16]u8 = undefined;
        var b_buf: [16]u8 = undefined;
        const a = opinionText(&a_buf, c3Opinion(0, id)); // opinion     = cell(target, self)
        const b = opinionText(&b_buf, c3Opinion(id, 0)); // their_opinion = cell(self, target)
        emit("NEO_C3_OPINION self={d} target=0 a={s} b={s}", .{ id, a, b });
    }
}

fn readU64Safe(addr: u64) ?u64 {
    const p: usize = @intCast(addr);
    if (!committed(p)) return null;
    return @as(*align(1) const u64, @ptrFromInt(p)).*;
}

fn readU32Safe(addr: u64) ?u32 {
    const p: usize = @intCast(addr);
    if (!committed(p)) return null;
    return @as(*align(1) const u32, @ptrFromInt(p)).*;
}

fn committed(addr: usize) bool {
    if (addr == 0) return false;
    if (comptime builtin.os.tag != .windows) return true;
    return windows.isCommitted(addr);
}

/// 跑一个 session 的 handler。异常/超时只禁用**这个** session。
fn runSession(index: usize, id: u32) void {
    runHandler(index, id, sessions[index].handler);
}

/// `onCountry` 的同形入口:只有 handler 不同。
fn runCountrySession(index: usize, id: u32) void {
    runHandler(index, id, sessions[index].country_handler);
}

fn runHandler(index: usize, id: u32, handler: c.JSValue) void {
    active_index = index;
    const s = &sessions[index];
    s.sessions_calls += 1;
    s.native_calls = 0;

    const ctx = s.runtime.ctx;
    var args = [_]c.JSValue{c.JSValue.int32(@intCast(@min(id, 0x7FFF_FFFF)))};
    interrupt_fired = false;
    interrupt_deadline = nowNs() + CALL_BUDGET_NS;
    const result = c.JS_Call(ctx, handler, c.JS_UNDEFINED, 1, &args);
    interrupt_deadline = 0;

    if (interrupt_fired) {
        s.sessions_timeouts += 1;
        s.active = false;
        _ = @atomicRmw(u64, &timeout_count, .Add, 1, .monotonic);
        emit("NEO_JS_TIMEOUT id={d} mod={s}", .{ id, s.id });
        // The interrupt leaves a pending exception; consume it so the next call
        // does not see a stale one.
        const exc = c.JS_GetException(ctx);
        c.JS_FreeValue(ctx, exc);
        return;
    }
    if (result.isException()) {
        s.sessions_errors += 1;
        s.active = false;
        _ = @atomicRmw(u64, &error_count, .Add, 1, .monotonic);
        reportException(ctx, id, s.id);
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

fn reportException(ctx: ?*c.JSContext, id: u32, mod_id: []const u8) void {
    const exc = c.JS_GetException(ctx);
    var len: usize = 0;
    const raw = c.JS_ToCStringLen2(ctx, &len, exc, false);
    if (raw) |msg| {
        var line_buf: [180]u8 = undefined;
        emit("NEO_JS_ERROR id={d} mod={s} {s}", .{ id, mod_id, sanitize(&line_buf, clip(msg[0..len], 160)) });
        c.JS_FreeCString(ctx, msg);
    } else {
        emit("NEO_JS_ERROR id={d} mod={s} (unknown)", .{ id, mod_id });
    }
    c.JS_FreeValue(ctx, exc);
}

// ---------------------------------------------------------------------------
// Argument helpers (no throwing conversions: a bad arg is a value, not an abort)
// ---------------------------------------------------------------------------

fn argU32(argc: c_int, argv: [*]c.JSValue) ?u32 {
    return argU32At(argc, argv, 0);
}

/// 按下标取一个 u32(逻辑与 `argU32` 相同)。`argc <= idx` 一律 null:
/// 少一个实参是「这次读不出来」,不是一个默认值。
fn argU32At(argc: c_int, argv: [*]c.JSValue, idx: usize) ?u32 {
    if (argc <= idx) return null;
    return valueU32(argv[idx]);
}

fn valueU32(v: c.JSValue) ?u32 {
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
    if (currentSession()) |s| {
        if (s.native_calls >= MAX_NATIVE_CALLS_PER_HANDLER) {
            return c.JS_ThrowInternalError(ctx, "neo: native call budget exhausted");
        }
        s.native_calls += 1;
    }
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
    const s = currentSession() orelse return c.JS_ThrowInternalError(ctx, "neo: no session");
    if (!s.handler.isUndefined()) c.JS_FreeValue(ctx, s.handler);
    s.handler = c.JS_DupValue(ctx, argv[0]);
    return c.JS_UNDEFINED;
}

/// Phase 2 C2 — `onCountry` 的注册 native。与 `nativeRegisterSystem` 同一套
/// Dup/释放口径,多一道「这个 bundle 声明了 country 吗」的门:
/// 没声明就落 `NEO_JS_REGISTER_REJECT … scope=country` 并返回 `undefined`
/// **但不处死 session** —— 声明不匹配是作者写错了 scope,不是越权。
fn nativeRegisterCountry(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    if (argc < 1 or !c.JS_IsFunction(ctx, argv[0])) {
        return c.JS_ThrowTypeError(ctx, "onCountry expects a function");
    }
    const s = currentSession() orelse return c.JS_ThrowInternalError(ctx, "neo: no session");
    if (!s.scopes.country) {
        emit("NEO_JS_REGISTER_REJECT id={s} scope=country", .{s.id});
        return c.JS_UNDEFINED;
    }
    if (!s.country_handler.isUndefined()) c.JS_FreeValue(ctx, s.country_handler);
    s.country_handler = c.JS_DupValue(ctx, argv[0]);
    return c.JS_UNDEFINED;
}

fn nativeSystemDegree(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    const id = argU32(argc, argv) orelse return c.JSValue.int32(0);
    if (!canReadGraph(currentPermissions())) return c.JSValue.int32(0);
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

    const res = writeSystemVariable(currentPermissions(), id, name, value, current_scope);
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
        // 越权 = 这个 session 不再被信任(A4:只禁用该 session,其它继续)。
        if (res == .no_permission) disableCurrent();
    }
    return c.JS_UNDEFINED;
}

/// Phase 2 A2 — `s.neighbors`: container walk, array<u32>. Permission is
/// `graph.read`; missing permission returns an empty array (same shape Phase 1's
/// `degree` uses: deny with 0, not an exception).
fn nativeSystemNeighbors(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    const arr = c.JS_NewArray(ctx);
    const id = argU32(argc, argv) orelse return arr;
    if (!canReadGraph(currentPermissions())) {
        emit("NEO_JS_NEIGHBORS_REJECT id={d} reason=no_permission", .{id});
        return arr;
    }
    var buf: [graph_probe.MAX_NEIGHBORS]u32 = undefined;
    const read = graph_probe.systemNeighbors(id, &buf) orelse return arr;
    var i: usize = 0;
    while (i < read.written) : (i += 1) {
        const nid = buf[i];
        _ = c.JS_SetPropertyUint32(ctx, arr, @intCast(i), c.JSValue.int32(@intCast(@min(nid, 0x7FFF_FFFF))));
    }
    if (read.total > read.written) {
        emit("NEO_JS_NEIGHBORS_TRUNC id={d} total={d} written={d}", .{ id, read.total, read.written });
    }
    return arr;
}

/// Phase 2 A2 — `s.setStarFlag(name)`: 官方 `set_star_flag` body,写落在当次 scope。
fn nativeSystemSetFlag(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    const id = argU32(argc, argv) orelse return c.JS_UNDEFINED;
    var name_buf: [64]u8 = undefined;
    const name = argString(ctx, argc, argv, 1, &name_buf) orelse return c.JS_UNDEFINED;

    const res = setSystemFlag(currentPermissions(), id, name, current_scope);
    if (res == .ok) {
        var line_buf: [32]u8 = undefined;
        emit("NEO_JS_WRITE id={d} name={s} kind=flag", .{ id, sanitize(&line_buf, name) });
    } else {
        var line_buf: [32]u8 = undefined;
        // `no_flag_token` = 官方 flag 表没给出号(模块未解析 / 名字非法 / 0 / 0xFFFF)。
        emit("NEO_JS_WRITE_REJECT id={d} name={s} reason={s} kind=flag", .{
            id,
            sanitize(&line_buf, clip(name, 24)),
            @tagName(res),
        });
        if (res == .no_permission) disableCurrent();
    }
    return c.JS_UNDEFINED;
}

/// Phase 2 A2 — `s.hasStarFlag(name)`: 只读系统 flag 容器(`+0x5f8`)。
fn nativeSystemHasFlag(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    const id = argU32(argc, argv) orelse return c.JSValue.boolVal(false);
    var name_buf: [64]u8 = undefined;
    const name = argString(ctx, argc, argv, 1, &name_buf) orelse return c.JSValue.boolVal(false);

    if (!canReadFlag(currentPermissions())) {
        var line_buf: [32]u8 = undefined;
        emit("NEO_JS_FLAG_REJECT id={d} name={s} reason=no_permission", .{ id, sanitize(&line_buf, clip(name, 24)) });
        disableCurrent();
        return c.JSValue.boolVal(false);
    }
    const maybe = readSystemFlag(currentPermissions(), id, name);
    if (maybe == null) {
        var line_buf: [32]u8 = undefined;
        // null 只有一种含义:这个名字在 flag 表里没有号(读路径不发号)。
        // 有号但容器读不到的读回 false —— 这里不再有 `no_flag_container` 这一档。
        emit("NEO_JS_FLAG_REJECT id={d} name={s} reason=no_flag_token", .{
            id,
            sanitize(&line_buf, clip(name, 24)),
        });
        return c.JSValue.boolVal(false);
    }
    return c.JSValue.boolVal(maybe.?);
}

fn nativeGraphBetweenness(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    const id = argU32(argc, argv) orelse return c.JSValue.int32(0);
    return c.JSValue.int32(@intCast(betweennessFor(currentPermissions(), id)));
}

fn nativeGraphIsChokepoint(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    const id = argU32(argc, argv) orelse return c.JSValue.boolVal(false);
    return c.JSValue.boolVal(chokepointFor(currentPermissions(), id));
}

fn nativeLog(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    if (!currentPermissions().log) return c.JS_UNDEFINED;
    var text_buf: [256]u8 = undefined;
    const text = argString(ctx, argc, argv, 0, &text_buf) orelse text_buf[0..0];
    var line_buf: [256]u8 = undefined;
    emit("NEO_JS_LOG {s}", .{sanitize(&line_buf, clip(text, 250))});
    return c.JS_UNDEFINED;
}

fn disableCurrent() void {
    if (currentSession()) |s| s.active = false;
}

fn nativeApiVersion(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = ctx;
    _ = this_val;
    _ = argc;
    _ = argv;
    return c.JSValue.int32(@intCast(API_VERSION));
}

// ---------------------------------------------------------------------------
// Phase 2 C2 — opinion 只读 native(哨兵/越界/空表/无权限一律 fail-closed)
// ---------------------------------------------------------------------------
//
// 两个 native 只有「哪一向当 row」这一处不同(§2.3:`opinion` 与 `their_opinion`
// 读互为**转置**的两格)。名字按引擎的 keyword 取,**不**按「我们/他们」取:
// 「哪一向 = 己对目标」只有 B 级证人,契约里不许写成事实。
//
// 只读面:不调懒填计算器 `0x743bb0`(它会写缓存),不改 scope,不写引擎内存。

/// 测试注入:合成矩阵的读面 + 描述符地址。非 Windows 上 `moduleBase()` 恒为 0,
/// 所以测试**必须**两个都注入,否则只能测到 `table_null` 这一档。
var opinion_memory: ?opinion_table.Memory = null;
var opinion_descriptor: ?u64 = null;

pub fn setOpinionTableForTest(mem: ?opinion_table.Memory, descriptor: ?u64) void {
    opinion_memory = mem;
    opinion_descriptor = descriptor;
}

/// 生产读面:host 自己的 `readU32Safe`/`readU64Safe`(Windows 上带 `isCommitted`)。
var production_ctx: u8 = 0;

fn productionReadU32(ctx: *anyopaque, addr: u64) ?u32 {
    _ = ctx;
    return readU32Safe(addr);
}

fn productionReadU64(ctx: *anyopaque, addr: u64) ?u64 {
    _ = ctx;
    return readU64Safe(addr);
}

fn productionReadI32(ctx: *anyopaque, addr: u64) ?i32 {
    _ = ctx;
    const v = readU32Safe(addr) orelse return null;
    return @bitCast(v);
}

fn opinionMemory() opinion_table.Memory {
    if (opinion_memory) |m| return m;
    return .{
        .ctx = @ptrCast(&production_ctx),
        .read_u32 = productionReadU32,
        .read_u64 = productionReadU64,
        .read_i32 = productionReadI32,
    };
}

/// 模块基址(绝对值)。非 Windows 返回 0 —— 读器于是拿不到描述符,只能 `table_null`。
fn moduleBase() u64 {
    if (comptime !is_windows) return 0;
    const p = windows.moduleFunction(0) catch return 0;
    return @intFromPtr(p);
}

fn descriptorAddr() ?u64 {
    if (opinion_descriptor) |a| return a;
    const base = moduleBase();
    if (base == 0) return null;
    return std.math.add(u64, base, offsets.country.OPINION_DESCRIPTOR) catch null;
}

/// `LookupError` → 日志里的 snake_case 理由词。**不用** `@errorName`:它的输出是
/// 错误标签原样(`NotComputed`),而日志口径是 `not_computed` —— 读数按行 grep,
/// 两种拼法会让「哨兵命中了没有」在日志里对不上。
fn lookupTag(e: opinion_table.LookupError) []const u8 {
    return switch (e) {
        error.TableNull => "table_null",
        error.OutOfRange => "out_of_range",
        error.NotComputed => "not_computed",
    };
}

/// 具名拒绝行:`reason` 取 `lookupTag`,外加两档纯 JS 侧的
/// `no_permission` / `scope_mismatch`。
fn opinionReject(self: u32, target: u32, reason: []const u8) void {
    emit("NEO_JS_OPINION_REJECT self={d} target={d} reason={s}", .{ self, target, reason });
}

/// 两个 native 的公共体。`swap` 只决定 row/col 的取法:
///   `opinion`        = base[(target, self)](引擎 `opinion` 那一格)
///   `their_opinion`  = base[(self, target)](引擎 `their_opinion` 那一格)
fn readOpinion(argc: c_int, argv: [*]c.JSValue, swap: bool) c.JSValue {
    const self = argU32At(argc, argv, 0) orelse return c.JS_UNDEFINED;
    const target = argU32At(argc, argv, 1) orelse return c.JS_UNDEFINED;

    // 只读越权**不**处死 session(与写路径相反:一次读没有副作用,
    // 而且写侧那一条是"这个 mod 想改世界",性质不同)。
    if (!canReadOpinion(currentPermissions())) {
        opinionReject(self, target, "no_permission");
        return c.JS_UNDEFINED;
    }

    // JS 传回来的 `self` 必须就是当次派发的那个国家,否则读的是别人的行。
    const scope = current_scope;
    if (scope == 0 or readU32Safe(scope + neo_vtable.SCOPE_ID_OFF) != self) {
        opinionReject(self, target, "scope_mismatch");
        return c.JS_UNDEFINED;
    }

    const addr = descriptorAddr() orelse {
        opinionReject(self, target, "table_null");
        return c.JS_UNDEFINED;
    };
    const table = opinion_table.load(opinionMemory(), addr) catch |e| {
        opinionReject(self, target, lookupTag(e));
        return c.JS_UNDEFINED;
    };

    const row = if (swap) target else self;
    const col = if (swap) self else target;
    const v = opinion_table.value(opinionMemory(), table, row, col) catch |e| {
        opinionReject(self, target, lookupTag(e));
        return c.JS_UNDEFINED;
    };
    return c.JSValue.int32(v);
}

fn nativeCountryOpinion(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    // 引擎 `opinion` 的键序是 row = 目标、col = 我们(§2.3 的 A 级读数),所以这里
    // 是 `swap = true` —— 换反了就是把转置那一格当成 `opinion` 的读数。
    return readOpinion(argc, argv, true);
}

fn nativeCountryTheirOpinion(ctx: ?*c.JSContext, this_val: c.JSValue, argc: c_int, argv: [*]c.JSValue) callconv(.c) c.JSValue {
    _ = this_val;
    if (charge(ctx)) |exc| return exc;
    return readOpinion(argc, argv, false);
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

/// 测试/诊断:当前 session 数与其中 active 的数量。
pub fn sessionCount() usize {
    return session_len;
}

pub fn activeSessions() usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < session_len) : (i += 1) {
        if (sessions[i].active) n += 1;
    }
    return n;
}

pub fn sessionErrors(index: usize) u64 {
    if (index >= session_len) return 0;
    return sessions[index].sessions_errors;
}

pub fn sessionTimeouts(index: usize) u64 {
    if (index >= session_len) return 0;
    return sessions[index].sessions_timeouts;
}

/// 只清状态机与计数。**Windows 上不释放 runtime**(`JS_DupValue` 的引用还挂在
/// handler 上,而且这个 runtime 与进程同生命周期,永不 FreeLibrary);宿主测试里
/// 释放掉,免得每个用例都留下 8 个 runtime。
pub fn resetForTest() void {
    other_scope_count = 0;
    c3_econ_count = 0;
    c3_opinion_count = 0;
    country_call_count = 0;
    if (comptime !is_windows) {
        var i: usize = 0;
        while (i < session_len) : (i += 1) {
            const s = &sessions[i];
            // The handler is a JS_DupValue reference; QuickJS asserts the GC list
            // is empty when the runtime is freed, so drop it first.
            if (!s.handler.isUndefined()) {
                c.JS_FreeValue(s.runtime.ctx, s.handler);
                s.handler = c.JS_UNDEFINED;
            }
            if (!s.country_handler.isUndefined()) {
                c.JS_FreeValue(s.runtime.ctx, s.country_handler);
                s.country_handler = c.JS_UNDEFINED;
            }
            s.runtime.deinit();
        }
    }
    session_len = 0;
    active_index = 0;
    state = .idle;
    current_scope = 0;
    interrupt_deadline = 0;
    interrupt_fired = false;
    clock = null;
    sink = null;
    flag_ids.resetCache();
    opinion_memory = null;
    opinion_descriptor = null;
    c3_memory = null;
    c3_addresses = null;
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

test "noteOtherScope logs mask+id for a non-system scope and is silent otherwise" {
    resetForTest();
    var cap = Capture{};
    armCapture(&cap);
    defer resetForTest();

    // A country scope: `0x04` is what the `every_country` loop writes into
    // `[scope+0x08]` (`0x1A7AF78`, the system twin writes `0x80` at `0x1A79928`).
    // The line reports what the engine wrote — the diagnostic never assumes it.
    var country: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    std.mem.writeInt(u32, country[neo_vtable.SCOPE_MASK_OFF..][0..4], 0x04, .little);
    std.mem.writeInt(u32, country[neo_vtable.SCOPE_ID_OFF..][0..4], 42, .little);
    // vtable + the candidate field cells: the fingerprint half of the line.
    std.mem.writeInt(u64, country[0..8], 0x140000000 + 0x1234, .little);
    // +0x08 is the mask itself and +0x10 is the id; the rest are free cells.
    std.mem.writeInt(u32, country[0x18..][0..4], 0xAAAA_0018, .little);
    noteOtherScope(@intFromPtr(&country));
    try testing.expect(cap.contains("NEO_SCOPE_OTHER mask=0x04 id=42"));
    try testing.expect(cap.contains("vtable_rva=0x0")); // off Windows there is no module base
    try testing.expect(cap.contains("u08=0x00000004"));
    try testing.expect(cap.contains("u10=0x0000002a")); // the id lives at +0x10
    try testing.expect(cap.contains("u18=0xaaaa0018"));

    // Only the first three are full fingerprints; the fourth is silent here
    // (the count line starts at 500).
    cap.len = 0;
    noteOtherScope(@intFromPtr(&country));
    noteOtherScope(@intFromPtr(&country));
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, cap.text(), "NEO_SCOPE_OTHER mask="));
    noteOtherScope(@intFromPtr(&country));
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, cap.text(), "NEO_SCOPE_OTHER mask="));

    // A system scope is the normal path: no diagnostic, ever.
    cap.len = 0;
    const system = systemScope(7);
    noteOtherScope(@intFromPtr(&system));
    try testing.expect(!cap.contains("NEO_SCOPE_OTHER"));

    // An unreadable pointer is silence, not a guessed line.
    cap.len = 0;
    noteOtherScope(0x1000);
    try testing.expect(!cap.contains("NEO_SCOPE_OTHER"));
}

test "onSystem logs NEO_SCOPE_OTHER when the dispatch carries a non-system scope" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);
    _ = startSession(.{
        .id = "probe",
        .source = "__neo_register_system(function(id){});",
        .permissions = .{},
    });

    var country: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    std.mem.writeInt(u32, country[neo_vtable.SCOPE_MASK_OFF..][0..4], 0x04, .little);
    std.mem.writeInt(u32, country[neo_vtable.SCOPE_ID_OFF..][0..4], 42, .little);
    onSystem(42, @intFromPtr(&country));

    try testing.expect(cap.contains("NEO_SCOPE_OTHER mask=0x04"));
    try testing.expect(cap.contains("NEO_JS_CALL id=42"));
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

    // Phase 2 bits are independent and default-deny.
    try testing.expect(!canReadVariable(none));
    try testing.expect(!canWriteFlag(none));
    try testing.expect(!canReadFlag(none));
    try testing.expect(canReadVariable(.{ .variable_read = true }));
    try testing.expect(canWriteFlag(.{ .flag_write = true }));
    try testing.expect(canReadFlag(.{ .flag_read = true }));
    try testing.expect(!canWriteFlag(.{ .flag_read = true }));
    try testing.expect(!canReadFlag(.{ .flag_write = true }));

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

test "an exception inside the handler is NEO_JS_ERROR and only that session is disabled" {
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
    try testing.expectEqual(@as(usize, 0), activeSessions());
    try testing.expectEqual(@as(u64, 1), sessionErrors(0));
    try testing.expect(cap.contains("NEO_JS_ERROR id=3"));
    try testing.expect(cap.contains("mod=throw"));
    try testing.expect(cap.contains("boom"));
}

test "an endless handler is stopped by the 10 ms budget and the session is disabled" {
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
    try testing.expectEqual(@as(usize, 0), activeSessions());
    try testing.expectEqual(@as(u64, 1), sessionTimeouts(0));
    try testing.expect(cap.contains("NEO_JS_TIMEOUT id=5"));
    try testing.expect(cap.contains("mod=spin"));

    // The next dispatch still logs NEO_JS_CALL, but the disabled session is not
    // entered again — and the interrupt's pending exception was consumed.
    onSystem(6, 0);
    try testing.expect(!cap.contains("NEO_JS_TIMEOUT id=6"));
    try testing.expectEqual(@as(u64, 1), timeouts());
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
    // 越权 = 该 session 被禁用(A4),不是每帧继续尝试。
    try testing.expectEqual(@as(usize, 0), activeSessions());
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
    try testing.expectEqual(@as(usize, 0), sessionCount());
    try testing.expectEqual(@as(usize, 0), activeSessions());
}

// ---------------------------------------------------------------------------
// Phase 2 A3/A4: multiple sessions and their isolation
// ---------------------------------------------------------------------------

fn countOccurrences(hay: []const u8, needle: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, hay, i, needle)) |pos| {
        n += 1;
        i = pos + needle.len;
    }
    return n;
}

test "two sessions both receive every dispatch" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    try testing.expect(startSession(.{
        .id = "a",
        .source = "__neo_register_system(function(id){ __neo_log('a' + id); });",
        .permissions = .{ .log = true },
    }));
    try testing.expect(startSession(.{
        .id = "b",
        .source = "__neo_register_system(function(id){ __neo_log('b' + id); });",
        .permissions = .{ .log = true },
    }));
    try testing.expectEqual(@as(usize, 2), sessionCount());

    onSystem(7, 0);

    // One NEO_JS_CALL per dispatch (Phase 1 kept), then one handler per session.
    try testing.expectEqual(@as(u64, 1), calls());
    try testing.expect(cap.contains("NEO_JS_LOG a7"));
    try testing.expect(cap.contains("NEO_JS_LOG b7"));
    try testing.expectEqual(@as(usize, 2), activeSessions());
}

test "a throwing session is disabled and the other keeps running" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    _ = startSession(.{
        .id = "bad",
        .source = "__neo_register_system(function(id){ throw new Error('boom'); });",
        .permissions = .{},
    });
    _ = startSession(.{
        .id = "good",
        .source = "__neo_register_system(function(id){ __neo_log('good' + id); });",
        .permissions = .{ .log = true },
    });

    onSystem(1, 0);
    onSystem(2, 0);

    try testing.expectEqual(@as(u64, 2), calls());
    try testing.expectEqual(@as(u64, 1), errors());
    try testing.expectEqual(@as(u64, 1), sessionErrors(0));
    try testing.expectEqual(@as(u64, 0), sessionErrors(1));
    try testing.expectEqual(@as(usize, 1), activeSessions());
    try testing.expectEqual(@as(usize, 2), countOccurrences(cap.text(), "NEO_JS_LOG good"));
    // The good session really did run twice, and the bad one only once.
    try testing.expect(cap.contains("NEO_JS_LOG good1"));
    try testing.expect(cap.contains("NEO_JS_LOG good2"));
    try testing.expectEqual(@as(usize, 1), countOccurrences(cap.text(), "NEO_JS_ERROR id="));
}

test "a timed-out session is disabled and the other keeps running" {
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
    _ = startSession(.{
        .id = "good",
        .source = "__neo_register_system(function(id){ __neo_log('good' + id); });",
        .permissions = .{ .log = true },
    });

    onSystem(4, 0);
    onSystem(5, 0);

    try testing.expectEqual(@as(u64, 1), timeouts());
    try testing.expectEqual(@as(u64, 1), sessionTimeouts(0));
    try testing.expectEqual(@as(u64, 0), sessionTimeouts(1));
    try testing.expectEqual(@as(usize, 1), activeSessions());
    // A tiny handler does not reach QuickJS's 10k-opcode interrupt poll, so the
    // healthy session survives the same dispatch the spinning one failed in.
    try testing.expect(cap.contains("NEO_JS_LOG good4"));
    try testing.expect(cap.contains("NEO_JS_LOG good5"));
}

test "a permission violation disables only the offending session" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    _ = startSession(.{
        .id = "nosy",
        .source = "__neo_register_system(function(id){ __neo_system_set_var(id, 'neo_score', 1); });",
        .permissions = .{},
    });
    _ = startSession(.{
        .id = "good",
        .source = "__neo_register_system(function(id){ __neo_log('good' + id); });",
        .permissions = .{ .log = true },
    });

    onSystem(7, 0);
    onSystem(8, 0);

    try testing.expect(cap.contains("NEO_JS_WRITE_REJECT id=7"));
    try testing.expect(cap.contains("reason=no_permission"));
    try testing.expectEqual(@as(usize, 1), activeSessions());
    try testing.expectEqual(@as(usize, 2), countOccurrences(cap.text(), "NEO_JS_LOG good"));
    // Only one rejection: the disabled session is not entered on the next dispatch.
    try testing.expectEqual(@as(usize, 1), countOccurrences(cap.text(), "NEO_JS_WRITE_REJECT"));
}

test "session slots are bounded: the ninth bundle is refused with a log" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    var i: usize = 0;
    while (i < MAX_SESSIONS) : (i += 1) {
        try testing.expect(startSession(.{
            .id = "ok",
            .source = "__neo_register_system(function(id){ });",
            .permissions = .{},
        }));
    }
    try testing.expect(!startSession(.{
        .id = "over",
        .source = "__neo_register_system(function(id){ });",
        .permissions = .{},
    }));
    try testing.expectEqual(MAX_SESSIONS, sessionCount());
    try testing.expect(cap.contains("NEO_JS_SESSION_LIMIT id=over"));
}

// ---------------------------------------------------------------------------
// Phase 2 A2: the additive natives (neighbors / set_flag / has_flag)
// ---------------------------------------------------------------------------

test "the additive v1.1 natives are registered separately from the frozen seven" {
    const expected = [_][]const u8{
        "__neo_system_neighbors",
        "__neo_system_set_flag",
        "__neo_system_has_flag",
        "__neo_register_country",
        "__neo_country_opinion",
        "__neo_country_their_opinion",
    };
    try testing.expectEqual(expected.len, additive_names.len);
    for (expected, 0..) |name, i| try testing.expectEqualStrings(name, additive_names[i]);
    // The Phase 1 contract table stays exactly seven names.
    try testing.expectEqual(@as(usize, 7), native_names.len);
    try testing.expectEqual(@as(usize, 6), additive_native_table.len);
}

var host_flag_calls: usize = 0;
var host_flag_id: u16 = 0;
var host_flag_scope: u64 = 0;

fn hostFlagBody(self_ptr: u64, scope: u64) callconv(.c) void {
    const base: [*]const u8 = @ptrFromInt(self_ptr);
    host_flag_id = std.mem.readInt(u16, base[neo_state.STAR_FLAG_ID_OFF..][0..2], .little);
    host_flag_scope = scope;
    host_flag_calls += 1;
}

test "a session can call setStarFlag through the additive native" {
    resetForTest();
    defer resetForTest();
    neo_vtable.resetForTest();
    defer neo_vtable.resetForTest();
    var cap = Capture{};
    armCapture(&cap);
    host_flag_calls = 0;
    neo_vtable.armFlagPathForTest(@intFromPtr(&hostFlagBody), 0x140000000 + 0x26049B0);
    var fake = flag_ids.FakeTable.init(&.{});
    flag_ids.setTableForTest(fake.table());
    defer flag_ids.setTableForTest(null);

    _ = startSession(.{
        .id = "flag",
        .source = "__neo_register_system(function(id){ __neo_system_set_flag(id, 'mod_flag'); });",
        .permissions = .{ .flag_write = true },
    });
    const scope align(8) = systemScope(7);
    onSystem(7, @intFromPtr(&scope));

    try testing.expectEqual(@as(u64, 0), errors());
    try testing.expectEqual(@as(u64, 1), writes());
    try testing.expectEqual(@as(usize, 1), host_flag_calls);
    // 空假表从 1 起(活进程里这张表启动时已装了几千个名字;0 在本模块按失败处理)。
    try testing.expectEqual(@as(u16, 1), host_flag_id);
    try testing.expectEqual(@as(usize, 1), fake.insert_calls);
    try testing.expectEqual(@as(u64, @intFromPtr(&scope)), host_flag_scope);
    try testing.expect(cap.contains("NEO_JS_WRITE id=7 name=mod_flag kind=flag"));
}

test "setStarFlag without flag.write is rejected and disables that session" {
    resetForTest();
    defer resetForTest();
    neo_vtable.resetForTest();
    defer neo_vtable.resetForTest();
    var cap = Capture{};
    armCapture(&cap);
    host_flag_calls = 0;
    neo_vtable.armFlagPathForTest(@intFromPtr(&hostFlagBody), 0x140000000 + 0x26049B0);

    _ = startSession(.{
        .id = "flag",
        .source = "__neo_register_system(function(id){ __neo_system_set_flag(id, 'mod_flag'); });",
        .permissions = .{},
    });
    const scope align(8) = systemScope(7);
    onSystem(7, @intFromPtr(&scope));

    try testing.expectEqual(@as(u64, 0), writes());
    try testing.expectEqual(@as(usize, 0), host_flag_calls);
    try testing.expect(cap.contains("reason=no_permission"));
    try testing.expectEqual(@as(usize, 0), activeSessions());
}

test "neighbors returns an array; without graph.read it is empty and logged" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    // Linux: no module base, so the container walk fails closed -> empty array.
    _ = startSession(.{
        .id = "graph",
        .source = "__neo_register_system(function(id){ const n = __neo_system_neighbors(id); if (n.length !== 0) throw new Error('len ' + n.length); });",
        .permissions = .{ .graph_read = true },
    });
    onSystem(2, 0);
    try testing.expectEqual(@as(u64, 0), errors());

    resetForTest();
    armCapture(&cap);
    _ = startSession(.{
        .id = "nograph",
        .source = "__neo_register_system(function(id){ const n = __neo_system_neighbors(id); if (n.length !== 0) throw new Error('len'); });",
        .permissions = .{},
    });
    onSystem(2, 0);
    try testing.expect(cap.contains("NEO_JS_NEIGHBORS_REJECT id=2 reason=no_permission"));
}

test "hasStarFlag without flag.read is rejected and disables that session" {
    resetForTest();
    defer resetForTest();
    neo_vtable.resetForTest();
    defer neo_vtable.resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    _ = startSession(.{
        .id = "flagread",
        .source = "__neo_register_system(function(id){ if (__neo_system_has_flag(id, 'mod_flag')) throw new Error('true'); });",
        .permissions = .{},
    });
    onSystem(9, 0);

    try testing.expect(cap.contains("NEO_JS_FLAG_REJECT id=9 name=mod_flag reason=no_permission"));
    try testing.expectEqual(@as(usize, 0), activeSessions());
}

test "hasStarFlag with flag.read fails closed (false) when the engine is absent" {
    resetForTest();
    defer resetForTest();
    neo_vtable.resetForTest();
    defer neo_vtable.resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    _ = startSession(.{
        .id = "flagread",
        .source = "__neo_register_system(function(id){ if (__neo_system_has_flag(id, 'mod_flag')) throw new Error('true'); });",
        .permissions = .{ .flag_read = true },
    });
    onSystem(9, 0);

    try testing.expectEqual(@as(u64, 0), errors());
    try testing.expectEqual(@as(usize, 1), activeSessions());
}

// ---------------------------------------------------------------------------
// flag 表接线:读走 lookup(不插表)、写走 ensure(可插入)
// ---------------------------------------------------------------------------

test "setSystemFlag resolves through the flag table, not the lexer mint" {
    resetForTest();
    defer resetForTest();
    neo_vtable.resetForTest();
    defer neo_vtable.resetForTest();
    var cap = Capture{};
    armCapture(&cap);
    host_flag_calls = 0;
    neo_vtable.armFlagPathForTest(@intFromPtr(&hostFlagBody), 0x140000000 + 0x26049B0);
    var fake = flag_ids.FakeTable.init(&.{});
    flag_ids.setTableForTest(fake.table());
    defer flag_ids.setTableForTest(null);

    const scope align(8) = systemScope(7);
    const p = Permissions{ .flag_write = true, .flag_read = true };
    try testing.expectEqual(FlagResult.ok, setSystemFlag(p, 7, "neo_hub", @intFromPtr(&scope)));
    try testing.expectEqual(@as(usize, 1), fake.insert_calls); // ensure 插入了新名字
    try testing.expectEqual(@as(usize, 1), fake.append_calls); // 并且只 append 一次
    try testing.expectEqual(@as(usize, 1), host_flag_calls);
    try testing.expectEqual(@as(u16, 1), host_flag_id); // 空假表首号(见 FakeTable.init)

    // 读:同一个名字现在能解析出号;Linux 上没有系统容器 ⇒ fail-closed 的 false,
    // 而不是「没有号」的 null —— 并且**不再插入**。
    try testing.expectEqual(@as(?bool, false), readSystemFlag(p, 7, "neo_hub"));
    try testing.expectEqual(@as(usize, 1), fake.insert_calls);

    // 已经写过的名字再写一次:命中,不再插入、也不再 append。
    host_flag_calls = 0;
    try testing.expectEqual(FlagResult.ok, setSystemFlag(p, 7, "neo_hub", @intFromPtr(&scope)));
    try testing.expectEqual(@as(usize, 1), fake.insert_calls);
    try testing.expectEqual(@as(usize, 1), fake.append_calls);
    try testing.expectEqual(@as(usize, 1), host_flag_calls);
}

test "an undeclared read does not pollute the table" {
    resetForTest();
    defer resetForTest();
    neo_vtable.resetForTest();
    defer neo_vtable.resetForTest();
    var fake = flag_ids.FakeTable.init(&.{});
    flag_ids.setTableForTest(fake.table());
    defer flag_ids.setTableForTest(null);

    const p = Permissions{ .flag_read = true };
    try testing.expectEqual(@as(?bool, null), readSystemFlag(p, 7, "never_set"));
    try testing.expectEqual(@as(usize, 0), fake.insert_calls);
    try testing.expectEqual(@as(usize, 0), fake.append_calls);
    try testing.expectEqual(@as(usize, 0), fake.placed);
}

test "a flag name the table refuses is no_flag_token, not a write" {
    resetForTest();
    defer resetForTest();
    neo_vtable.resetForTest();
    defer neo_vtable.resetForTest();
    var cap = Capture{};
    armCapture(&cap);
    host_flag_calls = 0;
    neo_vtable.armFlagPathForTest(@intFromPtr(&hostFlagBody), 0x140000000 + 0x26049B0);
    var exhausted = flag_ids.FakeTable.initExhausted(); // next_id = 0xFFFF
    flag_ids.setTableForTest(exhausted.table());
    defer flag_ids.setTableForTest(null);

    const scope align(8) = systemScope(7);
    const p = Permissions{ .flag_write = true };
    try testing.expectEqual(FlagResult.no_flag_token, setSystemFlag(p, 7, "neo_hub", @intFromPtr(&scope)));
    try testing.expectEqual(@as(usize, 0), host_flag_calls);
    try testing.expectEqual(@as(u64, 0), writes());
    // 16 字节的名字超过引擎 SSO 边界,同样拿不到号(不发号、不插表)。
    try testing.expectEqual(FlagResult.bad_name, setSystemFlag(p, 7, "0123456789abcdef", @intFromPtr(&scope)));
}

// ---------------------------------------------------------------------------
// country scope 派发(Task 1:多 scope + country 接线)
// ---------------------------------------------------------------------------

test "onCountry runs only country-scope sessions and logs CALL_COUNTRY once" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    // A 只声明 country:它的 handler 就是 country_handler,没有 system 那一只。
    try testing.expect(startSession(.{
        .id = "c",
        .source = "__neo_register_country(function(id){ __neo_log('country ' + id); });",
        .permissions = .{ .log = true },
        .scopes = .{ .country = true },
    }));
    // B 只声明 system,却也尝试注册 country —— 那一次落 REGISTER_REJECT,
    // session 本身继续活着(system handler 在)。
    try testing.expect(startSession(.{
        .id = "s",
        .source = "__neo_register_system(function(id){ __neo_log('system ' + id); }); __neo_register_country(function(id){ __neo_log('wrong ' + id); });",
        .permissions = .{ .log = true },
    }));
    try testing.expect(cap.contains("NEO_JS_REGISTER_REJECT id=s scope=country"));
    try testing.expectEqual(@as(usize, 2), activeSessions());

    var country: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    std.mem.writeInt(u32, country[neo_vtable.SCOPE_MASK_OFF..][0..4], 0x04, .little);
    std.mem.writeInt(u32, country[neo_vtable.SCOPE_ID_OFF..][0..4], 42, .little);
    onCountry(42, @intFromPtr(&country));

    try testing.expectEqual(@as(u64, 1), countryCalls());
    try testing.expectEqual(@as(usize, 1), countOccurrences(cap.text(), "NEO_JS_CALL_COUNTRY id=42"));
    try testing.expect(cap.contains("NEO_JS_LOG country 42"));
    // B 的 country 注册被拒 ⇒ 它的 'wrong' handler 不存在,一行都不该出现。
    try testing.expect(!cap.contains("NEO_JS_LOG wrong"));

    // 反过来:system 派发只喂 B,A 的 country handler 不被调用。
    cap.len = 0;
    const system = systemScope(7);
    onSystem(7, @intFromPtr(&system));
    try testing.expect(cap.contains("NEO_JS_LOG system 7"));
    try testing.expect(!cap.contains("NEO_JS_LOG country"));
}

test "registerCountry without the country scope logs a reject and leaves the session active" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    try testing.expect(startSession(.{
        .id = "sysonly",
        .source = "__neo_register_system(function(id){}); __neo_register_country(function(id){});",
        .permissions = .{},
    }));
    try testing.expectEqual(@as(usize, 1), activeSessions());
    try testing.expect(cap.contains("NEO_JS_REGISTER_REJECT id=sysonly scope=country"));
    // 声明不匹配是作者写错了 scope,不是越权:session 不被处死。
    try testing.expectEqual(@as(usize, 1), sessionCount());
    try testing.expectEqual(Status.ready, status());
}

// ---------------------------------------------------------------------------
// opinion 只读 native(Task 2:哨兵 / 越界 / scope 不一致 / 无权限)
// ---------------------------------------------------------------------------

fn countryScope(id: u32) [0x20]u8 {
    var scope: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    std.mem.writeInt(u32, scope[neo_vtable.SCOPE_MASK_OFF..][0..4], offsets.country.SCOPE_MASK, .little);
    std.mem.writeInt(u32, scope[neo_vtable.SCOPE_ID_OFF..][0..4], id, .little);
    return scope;
}

test "nativeCountryOpinion requires opinion.read and rejects a mismatched scope" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    var matrix = opinion_table.FakeMatrix.init(3);
    matrix.wire();
    matrix.set(0, 0, 11);
    setOpinionTableForTest(matrix.memory(), matrix.descriptorAddr());

    // 1) 没有 opinion.read:每次读都 undefined + no_permission,session **不被禁用**。
    try testing.expect(startSession(.{
        .id = "noperm",
        .source = "__neo_register_country(function(id){ if (__neo_country_opinion(id, id) !== undefined) throw new Error('value'); });",
        .permissions = .{},
        .scopes = .{ .country = true },
    }));
    const scope0 = countryScope(0);
    onCountry(0, @intFromPtr(&scope0));
    try testing.expectEqual(@as(u64, 0), errors());
    try testing.expectEqual(@as(usize, 1), activeSessions());
    try testing.expect(cap.contains("NEO_JS_OPINION_REJECT self=0 target=0 reason=no_permission"));

    // 2) 有权限,但 JS 传的 self 与当次派发的 scope 不是同一个国家。
    resetForTest();
    armCapture(&cap);
    setOpinionTableForTest(matrix.memory(), matrix.descriptorAddr());
    try testing.expect(startSession(.{
        .id = "scoped",
        .source = "__neo_register_country(function(id){ if (__neo_country_opinion(id, 1) !== undefined) throw new Error('value'); });",
        .permissions = .{ .opinion_read = true },
        .scopes = .{ .country = true },
    }));
    const wrong = countryScope(9); // 派发的 scope 说 9,JS 看到的是 7
    onCountry(7, @intFromPtr(&wrong));
    try testing.expectEqual(@as(u64, 0), errors());
    try testing.expect(cap.contains("NEO_JS_OPINION_REJECT self=7 target=1 reason=scope_mismatch"));

    // 3) 没注入表(等价于生产上拿不到描述符):table_null,不是 0 分。
    resetForTest();
    armCapture(&cap);
    try testing.expect(startSession(.{
        .id = "notable",
        .source = "__neo_register_country(function(id){ if (__neo_country_opinion(id, 1) !== undefined) throw new Error('value'); });",
        .permissions = .{ .opinion_read = true },
        .scopes = .{ .country = true },
    }));
    const scope1 = countryScope(1);
    onCountry(1, @intFromPtr(&scope1));
    try testing.expect(cap.contains("NEO_JS_OPINION_REJECT self=1 target=1 reason=table_null"));
    try testing.expectEqual(@as(u64, 0), errors());
}

test "nativeCountryOpinion returns undefined for sentinel and out-of-range" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    var matrix = opinion_table.FakeMatrix.init(3);
    matrix.wire();
    // opinion(1,2) 的键是 row=target=2、col=self=1(§2.3):哨兵放在 [2][1]。
    matrix.set(2, 1, opinion_table.SENTINEL);
    // 转置的两格:opinion(1,2)=[2][1]、their_opinion(1,2)=[1][2]。
    matrix.set(1, 2, -9);
    setOpinionTableForTest(matrix.memory(), matrix.descriptorAddr());

    // 哨兵 → undefined + not_computed。
    try testing.expect(startSession(.{
        .id = "sentinel",
        .source = "__neo_register_country(function(id){ if (__neo_country_opinion(id, 2) !== undefined) throw new Error('value'); });",
        .permissions = .{ .opinion_read = true },
        .scopes = .{ .country = true },
    }));
    const scope1 = countryScope(1);
    onCountry(1, @intFromPtr(&scope1));
    try testing.expectEqual(@as(u64, 0), errors());
    try testing.expect(cap.contains("NEO_JS_OPINION_REJECT self=1 target=2 reason=not_computed"));

    // row = n(=3) → out_of_range(界是逐维查的,不是只查乘积)。
    resetForTest();
    armCapture(&cap);
    setOpinionTableForTest(matrix.memory(), matrix.descriptorAddr());
    try testing.expect(startSession(.{
        .id = "range",
        .source = "__neo_register_country(function(id){ if (__neo_country_opinion(id, 0) !== undefined) throw new Error('value'); });",
        .permissions = .{ .opinion_read = true },
        .scopes = .{ .country = true },
    }));
    const scope3 = countryScope(3);
    onCountry(3, @intFromPtr(&scope3));
    try testing.expectEqual(@as(u64, 0), errors());
    try testing.expect(cap.contains("NEO_JS_OPINION_REJECT self=3 target=0 reason=out_of_range"));

    // 正读:两个 native 落在互为转置的两格(Review Focus 5 的本地落点)。
    resetForTest();
    armCapture(&cap);
    matrix.set(2, 1, 77);
    setOpinionTableForTest(matrix.memory(), matrix.descriptorAddr());
    try testing.expect(startSession(.{
        .id = "both",
        .source = "__neo_register_country(function(id){ var a = __neo_country_opinion(id, 2); var b = __neo_country_their_opinion(id, 2); if (a !== 77 || b !== -9) throw new Error('a=' + a + ' b=' + b); });",
        .permissions = .{ .opinion_read = true },
        .scopes = .{ .country = true },
    }));
    onCountry(1, @intFromPtr(&scope1));
    try testing.expectEqual(@as(u64, 0), errors());
    try testing.expectEqual(@as(usize, 1), activeSessions());
}

// ---------------------------------------------------------------------------
// C3(2026-11-08)— 国家侦察行(上限 3/40,只读)
// ---------------------------------------------------------------------------

test "a country dispatch emits the C3 econ and opinion lines and caps them" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    // opinion 的两格按 §2.3 的键序布:opinion = cell(target, self)、their_opinion = cell(self, target)。
    var matrix = opinion_table.FakeMatrix.init(3);
    matrix.wire();
    matrix.set(0, 1, 40);
    matrix.set(1, 0, 0);
    setOpinionTableForTest(matrix.memory(), matrix.descriptorAddr());

    var scope: [0x20]u8 align(8) = countryScope(1);
    noteOtherScope(@intFromPtr(&scope));
    try testing.expect(cap.contains("NEO_C3_ECON id=1"));
    try testing.expect(cap.contains("NEO_C3_RES"));
    try testing.expect(cap.contains("NEO_C3_OPINION self=1 target=0 a=40 b=0"));

    // 再打 39 次:OPINION 行恰好 40 条;第 41 次不再出现。
    var i: usize = 0;
    while (i < 39) : (i += 1) noteOtherScope(@intFromPtr(&scope));
    try testing.expectEqual(@as(usize, 40), countOccurrences(cap.text(), "NEO_C3_OPINION "));
    noteOtherScope(@intFromPtr(&scope));
    try testing.expectEqual(@as(usize, 40), countOccurrences(cap.text(), "NEO_C3_OPINION "));
}

test "the C3 econ line stops after three countries" {
    resetForTest();
    defer resetForTest();
    var cap = Capture{};
    armCapture(&cap);

    var id: u32 = 0;
    while (id < 4) : (id += 1) {
        var scope: [0x20]u8 align(8) = countryScope(id);
        noteOtherScope(@intFromPtr(&scope));
    }
    try testing.expectEqual(@as(usize, 3), countOccurrences(cap.text(), "NEO_C3_ECON "));
    try testing.expectEqual(@as(usize, 3), countOccurrences(cap.text(), "NEO_C3_RES "));
    // 第 4 个国家(id=3)没有完整经济行。
    try testing.expect(!cap.contains("NEO_C3_ECON id=3"));

    // system scope(mask 0x80)不进这条路径。
    var system: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    std.mem.writeInt(u32, system[neo_vtable.SCOPE_MASK_OFF..][0..4], 0x80, .little);
    noteOtherScope(@intFromPtr(&system));
    try testing.expectEqual(@as(usize, 3), countOccurrences(cap.text(), "NEO_C3_ECON "));
}
