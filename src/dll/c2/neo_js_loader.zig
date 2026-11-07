// neo_js_loader.zig — Runtime JS loader(Track A, Task A2):manifest + 权限 + 「一个 mod」。
//
// 目录契约(计划 Global Constraints,固定、不解析 `dlc_load.json`):
//   C:/temp/neo_mods/<id>/neo/mod.json
//   C:/temp/neo_mods/<id>/neo/main.js
// `loadActive()` 枚举 `neo_mods` 下的直接子目录,**恰好一个**带 `neo/mod.json` 的才算
// 活动 mod;0 个或多个都是可判读的失败(fail-closed,禁用,不重试)。
//
// 纪律:
//   * `api.def` 的 7 个 native 由 host 持有;本模块只交出「源码 + 权限」。
//   * **严格字段**:6 个字段全必填,未知字段 / 未知 permission / 非 system scope /
//     非 4.4.4 engine / 不满足的 runtime 都是具名错误 —— 每一种在 host 侧落一行日志
//     (计划 Review Focus 7:loader 的失败面必须可判读)。
//   * `id` 是**路径片段**:只允许 `[A-Za-z0-9_-]`,长度 1..64。`entry` v1 只认
//     `main.js`(目录写死,不接受任意路径)。
//   * Windows 文件 I/O 用 Phase 0 spike 的 `CreateFileA`/`ReadFile` 形状(Zig 0.16
//     的 `std.fs` 已并入 `std.Io`,注入线程里没有 Io 实例可用)。所有 Windows-only
//     分支都走 `if (comptime is_windows)`,native 测试根不分析它们,出货的
//     x86_64-windows 构建分析它们(exports.zig 钉住入口地址)。
//   * manifest 的切片活在一个静态 arena 里,下一次 `parseManifest`/`releaseManifest`
//     之前有效(loader 每个进程只跑一次,这个寿命足够,也避免测试里的泄漏检查)。
//
// 不写任何引擎内存;不 FreeLibrary。

const std = @import("std");
const builtin = @import("builtin");
const host = @import("neo_js_host.zig");

const loader = @This();

const is_windows = builtin.os.tag == .windows;

/// host 侧的类型,不是复制品 —— 合同漂移的第一道防线。
pub const Permissions = host.Permissions;

pub const MODS_ROOT = "C:/temp/neo_mods/";
pub const ENTRY_NAME = "main.js";
pub const EXPECTED_ENGINE = "4.4.4";
pub const EXPECTED_SCOPE = "system";

pub const MAX_ID_LEN: usize = 64;
pub const MAX_MANIFEST_BYTES: usize = 4096;
pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;

pub const Manifest = struct {
    id: []const u8,
    entry: []const u8,
    scope: []const u8,
    permissions: Permissions,
    engine: []const u8,
    runtime: []const u8,
};

pub const ParseError = error{
    NotJson,
    NotAnObject,
    MissingField,
    UnknownField,
    BadFieldType,
    DuplicateField,
    BadId,
    BadEntry,
    BadScope,
    UnknownPermission,
    EngineMismatch,
    RuntimeMismatch,
    OutOfMemory,
};

pub const LoadError = ParseError || error{
    NotWindows,
    NoMod,
    MultipleMods,
    NoManifest,
    MissingEntry,
    FileTooLarge,
    PathTooLong,
};

pub const Loaded = struct {
    manifest: Manifest,
    /// `neo/main.js` 的内容,哨兵终止(`JS_Eval` 要 `[:0]const u8`)。
    source: [:0]const u8,
};

// ---------------------------------------------------------------------------
// Manifest arena (static: one load per process; reset by the next parse)
// ---------------------------------------------------------------------------

var arena: ?std.heap.ArenaAllocator = null;

fn arenaAlloc() std.mem.Allocator {
    if (arena == null) arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    return arena.?.allocator();
}

/// 释放上一次 manifest 的字符串。`Manifest` 的切片在这之后都不再有效。
pub fn releaseManifest() void {
    if (arena) |*a| a.deinit();
    arena = null;
}

// ---------------------------------------------------------------------------
// Manifest parsing (pure — the whole failure surface is tested on the host)
// ---------------------------------------------------------------------------

pub fn parseManifest(bytes: []const u8) ParseError!Manifest {
    releaseManifest();
    if (bytes.len == 0 or bytes.len > MAX_MANIFEST_BYTES) return error.NotJson;

    const value = std.json.parseFromSliceLeaky(std.json.Value, arenaAlloc(), bytes, .{
        .allocate = .alloc_always,
    }) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.NotJson,
    };

    const obj = switch (value) {
        .object => |o| o,
        else => return error.NotAnObject,
    };

    // Strict field set: every key must be one of the six, once, and all six must exist.
    var seen = [_]bool{false} ** 6;
    var it = obj.iterator();
    while (it.next()) |entry| {
        const idx: ?usize = if (std.mem.eql(u8, entry.key_ptr.*, "id"))
            0
        else if (std.mem.eql(u8, entry.key_ptr.*, "entry"))
            1
        else if (std.mem.eql(u8, entry.key_ptr.*, "scope"))
            2
        else if (std.mem.eql(u8, entry.key_ptr.*, "permissions"))
            3
        else if (std.mem.eql(u8, entry.key_ptr.*, "engine"))
            4
        else if (std.mem.eql(u8, entry.key_ptr.*, "runtime"))
            5
        else
            return error.UnknownField;
        if (seen[idx.?]) return error.DuplicateField;
        seen[idx.?] = true;
    }
    for (seen) |present| {
        if (!present) return error.MissingField;
    }

    const id = try asString(obj.get("id").?);
    if (!validId(id)) return error.BadId;

    const entry = try asString(obj.get("entry").?);
    if (!std.mem.eql(u8, entry, ENTRY_NAME)) return error.BadEntry;

    const scope = try scopeName(obj.get("scope").?);
    if (!std.mem.eql(u8, scope, EXPECTED_SCOPE)) return error.BadScope;

    const permissions = try parsePermissions(obj.get("permissions").?);

    const engine = try asString(obj.get("engine").?);
    if (!std.mem.eql(u8, engine, EXPECTED_ENGINE)) return error.EngineMismatch;

    const runtime = try asString(obj.get("runtime").?);
    if (!runtimeSatisfies(runtime, host.API_VERSION)) return error.RuntimeMismatch;

    return .{
        .id = id,
        .entry = entry,
        .scope = scope,
        .permissions = permissions,
        .engine = engine,
        .runtime = runtime,
    };
}

fn asString(v: std.json.Value) ParseError![]const u8 {
    return switch (v) {
        .string => |s| s,
        else => error.BadFieldType,
    };
}

/// `"system"` 与 `["system"]` 都算合法。计划冻结的 `Manifest.scope` 是字符串,
/// 而 Track B 的示例 `mod.json` 写的是数组 —— 两种形状必须都能载入,否则示例在
/// 实机上会以「坏 manifest」失败。数组只允许**恰好一个**元素。
fn scopeName(v: std.json.Value) ParseError![]const u8 {
    return switch (v) {
        .string => |s| s,
        .array => |a| if (a.items.len == 1) asString(a.items[0]) else error.BadScope,
        else => error.BadScope,
    };
}

fn parsePermissions(v: std.json.Value) ParseError!Permissions {
    var p = Permissions{};
    switch (v) {
        .array => |a| {
            for (a.items) |item| {
                const name = try asString(item);
                if (std.mem.eql(u8, name, "graph.read")) {
                    p.graph_read = true;
                } else if (std.mem.eql(u8, name, "variable.write")) {
                    p.variable_write = true;
                } else if (std.mem.eql(u8, name, "log")) {
                    p.log = true;
                } else {
                    return error.UnknownPermission;
                }
            }
        },
        else => return error.BadFieldType,
    }
    return p;
}

fn validId(id: []const u8) bool {
    if (id.len == 0 or id.len > MAX_ID_LEN) return false;
    for (id) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-') return false;
    }
    // `.`/`..` are already excluded by the alphabet, but make the intent explicit:
    // `id` becomes a path segment under `C:/temp/neo_mods/`.
    if (std.mem.eql(u8, id, ".") or std.mem.eql(u8, id, "..")) return false;
    return true;
}

/// v1 只比较**主版本**:宿主实现 API 版本 `api`(`>=0.1` ⇒ 0 <= 1 满足)。
/// 形状错误(空、没有点、非数字)一律不满足 —— 宁可禁用,也不猜。
pub fn runtimeSatisfies(spec: []const u8, api: u32) bool {
    var body = std.mem.trim(u8, spec, " \t");
    if (std.mem.startsWith(u8, body, ">=")) {
        body = body[2..];
    } else if (std.mem.startsWith(u8, body, "~")) {
        body = body[1..];
    }
    const dot = std.mem.indexOfScalar(u8, body, '.') orelse return false;
    const major = std.fmt.parseInt(u32, std.mem.trim(u8, body[0..dot], " "), 10) catch return false;
    _ = std.fmt.parseInt(u32, std.mem.trim(u8, body[dot + 1 ..], " "), 10) catch return false;
    return major <= api;
}

// ---------------------------------------------------------------------------
// Disk: fixed dirs, kernel32 directly (no std.fs in Zig 0.16's injected thread)
// ---------------------------------------------------------------------------

const MAX_PATH: usize = 260;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 1;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const INVALID_HANDLE_VALUE: usize = @bitCast(@as(i64, -1));

const LARGE_INTEGER = extern struct { QuadPart: i64 };

const FILETIME = extern struct { dwLowDateTime: u32, dwHighDateTime: u32 };

/// `WIN32_FIND_DATAA`:44 B 头部 + `cFileName[260]` + `cAlternateFileName[14]` = 320 B。
/// 字段顺序与 MSDN 一致;`cFileName` 的偏移由 comptime 断言钉住。
const WIN32_FIND_DATAA = extern struct {
    dwFileAttributes: u32,
    ftCreationTime: FILETIME,
    ftLastAccessTime: FILETIME,
    ftLastWriteTime: FILETIME,
    nFileSizeHigh: u32,
    nFileSizeLow: u32,
    dwReserved0: u32,
    dwReserved1: u32,
    cFileName: [MAX_PATH]u8,
    cAlternateFileName: [14]u8,
};

extern "kernel32" fn CreateFileA(
    lpFileName: [*:0]const u8,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: ?*anyopaque,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: ?*anyopaque,
) ?*anyopaque;
extern "kernel32" fn ReadFile(
    hFile: ?*anyopaque,
    lpBuffer: *anyopaque,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: ?*u32,
    lpOverlapped: ?*anyopaque,
) i32;
extern "kernel32" fn GetFileSizeEx(hFile: ?*anyopaque, lpFileSize: *LARGE_INTEGER) i32;
extern "kernel32" fn CloseHandle(hObject: ?*anyopaque) i32;
extern "kernel32" fn FindFirstFileA(lpFileName: [*:0]const u8, lpFindFileData: *WIN32_FIND_DATAA) ?*anyopaque;
extern "kernel32" fn FindNextFileA(hFindFile: ?*anyopaque, lpFindFileData: *WIN32_FIND_DATAA) i32;
extern "kernel32" fn FindClose(hFindFile: ?*anyopaque) i32;

comptime {
    if (@sizeOf(WIN32_FIND_DATAA) != 320) @compileError("WIN32_FIND_DATAA layout drifted");
    if (@offsetOf(WIN32_FIND_DATAA, "cFileName") != 44) @compileError("cFileName offset drifted");
}

/// 把 `dir` + 固定尾巴拼进 `buf`,返回带 `:`0 的路径(Zig 侧用 `buf[0..len]` 记长度)。
fn joinPath(buf: []u8, parts: []const []const u8) ?[]const u8 {
    var len: usize = 0;
    for (parts) |part| {
        if (len + part.len > buf.len) return null;
        @memcpy(buf[len..][0..part.len], part);
        len += part.len;
    }
    return buf[0..len];
}

fn openRead(path: []const u8, path_buf: *[MAX_PATH]u8) ?*anyopaque {
    if (comptime !is_windows) return null;
    @memset(path_buf, 0);
    if (path.len + 1 > path_buf.len) return null;
    @memcpy(path_buf[0..path.len], path);
    const h = CreateFileA(@ptrCast(path_buf), GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null) orelse return null;
    if (@intFromPtr(h) == INVALID_HANDLE_VALUE) return null;
    return h;
}

/// 读整个文件到 `out`,返回字节数。超长(`size > out.len`)是 `error.FileTooLarge`
/// 而不是截断 —— 截断的 JS 会在 eval 处变成一条误导人的语法错误。
fn readFile(path: []const u8, out: []u8) LoadError!usize {
    if (comptime !is_windows) return error.NotWindows;
    var path_buf: [MAX_PATH]u8 = undefined;
    const h = openRead(path, &path_buf) orelse return error.NoManifest;
    defer _ = CloseHandle(h);

    var size: LARGE_INTEGER = .{ .QuadPart = 0 };
    if (GetFileSizeEx(h, &size) == 0) return error.NoManifest;
    if (size.QuadPart < 0) return error.NoManifest;
    const want: usize = @intCast(size.QuadPart);
    if (want > out.len) return error.FileTooLarge;

    var got: u32 = 0;
    if (ReadFile(h, out.ptr, @intCast(want), &got, null) == 0) return error.NoManifest;
    if (got != want) return error.NoManifest;
    return want;
}

/// `C:/temp/neo_mods/` 下**恰好一个**带 `neo/mod.json` 的直接子目录。
/// 返回的切片指向静态缓冲,在下一次调用前有效。
var mod_id: [MAX_ID_LEN]u8 = undefined;
var mod_id_len: usize = 0;
var mod_count: usize = 0;

/// 上一次枚举看到的候选 mod 数(`0`/`>1` 都是禁用理由;host 用它写
/// `NEO_JS_MULTI_MOD n=<n>`)。
pub fn lastModCount() usize {
    return mod_count;
}

fn modManifestExists(name: []const u8) bool {
    var buf: [MAX_PATH]u8 = undefined;
    const path = joinPath(&buf, &.{ MODS_ROOT, name, "/neo/mod.json" }) orelse return false;
    var path_buf: [MAX_PATH]u8 = undefined;
    const h = openRead(path, &path_buf) orelse return false;
    _ = CloseHandle(h);
    return true;
}

fn findActiveMod() LoadError![]const u8 {
    if (comptime is_windows) {
        mod_count = 0;
        mod_id_len = 0;
        var data: WIN32_FIND_DATAA = undefined;
        const h = FindFirstFileA("C:\\temp\\neo_mods\\*", &data) orelse return error.NoMod;
        if (@intFromPtr(h) == INVALID_HANDLE_VALUE) return error.NoMod;
        defer _ = FindClose(h);

        while (true) {
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) {
                const name = std.mem.sliceTo(&data.cFileName, 0);
                if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..") and modManifestExists(name)) {
                    mod_count += 1;
                    if (mod_count == 1) {
                        if (name.len > mod_id.len) return error.PathTooLong;
                        @memcpy(mod_id[0..name.len], name);
                        mod_id_len = name.len;
                    }
                }
            }
            if (FindNextFileA(h, &data) == 0) break;
        }
        if (mod_count == 0) return error.NoMod;
        if (mod_count > 1) return error.MultipleMods;
        return mod_id[0..mod_id_len];
    }
    return error.NotWindows;
}

/// 读 `<dir>/neo/main.js`。静态缓冲:`JS_Eval` 只在我们自己的一次加载里用它,
/// 而且它需要哨兵终止;每个进程只载一次,不值得为它做一条堆分配路径。
var source_buf: [MAX_SOURCE_BYTES]u8 = undefined;

/// `<dir>` 里的 `neo/mod.json` + `neo/main.js`。`<dir>` = `C:/temp/neo_mods/<id>`。
pub fn loadFromDir(dir: []const u8) LoadError!Loaded {
    var buf: [MAX_PATH]u8 = undefined;

    const manifest_path = joinPath(&buf, &.{ dir, "/neo/mod.json" }) orelse return error.PathTooLong;
    var manifest_buf: [MAX_MANIFEST_BYTES]u8 = undefined;
    const manifest_len = readFile(manifest_path, &manifest_buf) catch |err| return switch (err) {
        error.NoManifest => error.NoManifest,
        else => err,
    };
    const manifest = try parseManifest(manifest_buf[0..manifest_len]);

    const entry_path = joinPath(&buf, &.{ dir, "/neo/", manifest.entry }) orelse return error.PathTooLong;
    const source_len = readFile(entry_path, &source_buf) catch |err| return switch (err) {
        error.NoManifest => error.MissingEntry,
        else => err,
    };
    if (source_len >= source_buf.len) return error.FileTooLarge;
    source_buf[source_len] = 0;

    return .{ .manifest = manifest, .source = source_buf[0..source_len :0] };
}

/// 活动 mod:枚举根目录、要求恰好一个、然后按固定目录载入。
pub fn loadActive() LoadError!Loaded {
    const id = try findActiveMod();
    var buf: [MAX_PATH]u8 = undefined;
    const dir = joinPath(&buf, &.{ MODS_ROOT, id }) orelse return error.PathTooLong;
    return loadFromDir(dir);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const legal_array_scope =
    \\{
    \\  "id": "chokepoint",
    \\  "entry": "main.js",
    \\  "scope": ["system"],
    \\  "permissions": ["graph.read", "variable.write", "log"],
    \\  "engine": "4.4.4",
    \\  "runtime": ">=0.1"
    \\}
;

test "a legal manifest parses into all six fields" {
    defer releaseManifest();
    const m = try parseManifest(legal_array_scope);
    try testing.expectEqualStrings("chokepoint", m.id);
    try testing.expectEqualStrings("main.js", m.entry);
    try testing.expectEqualStrings("system", m.scope);
    try testing.expectEqualStrings("4.4.4", m.engine);
    try testing.expectEqualStrings(">=0.1", m.runtime);
    try testing.expect(m.permissions.graph_read);
    try testing.expect(m.permissions.variable_write);
    try testing.expect(m.permissions.log);
}

test "a string scope is accepted as well as the one-element array" {
    defer releaseManifest();
    const src =
        \\{"id":"a","entry":"main.js","scope":"system","permissions":[],"engine":"4.4.4","runtime":">=0.1"}
    ;
    const m = try parseManifest(src);
    try testing.expectEqualStrings("system", m.scope);
    try testing.expectEqual(Permissions{}, m.permissions);
}

test "every field is required" {
    const bodies = [_][]const u8{
        \\{"entry":"main.js","scope":["system"],"permissions":[],"engine":"4.4.4","runtime":">=0.1"}
        ,
        \\{"id":"a","scope":["system"],"permissions":[],"engine":"4.4.4","runtime":">=0.1"}
        ,
        \\{"id":"a","entry":"main.js","permissions":[],"engine":"4.4.4","runtime":">=0.1"}
        ,
        \\{"id":"a","entry":"main.js","scope":["system"],"engine":"4.4.4","runtime":">=0.1"}
        ,
        \\{"id":"a","entry":"main.js","scope":["system"],"permissions":[]}
    };
    for (bodies) |src| {
        defer releaseManifest();
        try testing.expectError(error.MissingField, parseManifest(src));
    }
}

test "an unknown permission is an error, not a silently dropped bit" {
    defer releaseManifest();
    const src =
        \\{"id":"a","entry":"main.js","scope":["system"],"permissions":["graph.read","filesystem.write"],"engine":"4.4.4","runtime":">=0.1"}
    ;
    try testing.expectError(error.UnknownPermission, parseManifest(src));
}

test "a non-system scope is an error" {
    const bodies = [_][]const u8{
        \\{"id":"a","entry":"main.js","scope":["fleet"],"permissions":[],"engine":"4.4.4","runtime":">=0.1"}
        ,
        \\{"id":"a","entry":"main.js","scope":["system","fleet"],"permissions":[],"engine":"4.4.4","runtime":">=0.1"}
        ,
        \\{"id":"a","entry":"main.js","scope":[],"permissions":[],"engine":"4.4.4","runtime":">=0.1"}
        ,
        \\{"id":"a","entry":"main.js","scope":"fleet","permissions":[],"engine":"4.4.4","runtime":">=0.1"}
    };
    for (bodies) |src| {
        defer releaseManifest();
        try testing.expectError(error.BadScope, parseManifest(src));
    }
}

test "unknown top-level fields are rejected" {
    defer releaseManifest();
    const src =
        \\{"id":"a","entry":"main.js","scope":["system"],"permissions":[],"engine":"4.4.4","runtime":">=0.1","surprise":1}
    ;
    try testing.expectError(error.UnknownField, parseManifest(src));
}

test "an id that could escape the mods directory is rejected" {
    const ids = [_][]const u8{ "../etc", "a/b", "a\\b", "", "..", "a b" };
    for (ids) |id| {
        defer releaseManifest();
        const src = try std.fmt.allocPrint(testing.allocator, "{{\"id\":\"{s}\",\"entry\":\"main.js\",\"scope\":[\"system\"],\"permissions\":[],\"engine\":\"4.4.4\",\"runtime\":\">=0.1\"}}", .{id});
        defer testing.allocator.free(src);
        try testing.expectError(error.BadId, parseManifest(src));
    }
}

test "v1 loads exactly neo/main.js and nothing else" {
    defer releaseManifest();
    const src =
        \\{"id":"a","entry":"other.js","scope":["system"],"permissions":[],"engine":"4.4.4","runtime":">=0.1"}
    ;
    try testing.expectError(error.BadEntry, parseManifest(src));
}

test "an engine other than 4.4.4 is an API mismatch" {
    defer releaseManifest();
    const src =
        \\{"id":"a","entry":"main.js","scope":["system"],"permissions":[],"engine":"4.4.3","runtime":">=0.1"}
    ;
    try testing.expectError(error.EngineMismatch, parseManifest(src));
}

test "a runtime requirement the host cannot satisfy is an API mismatch" {
    defer releaseManifest();
    const src =
        \\{"id":"a","entry":"main.js","scope":["system"],"permissions":[],"engine":"4.4.4","runtime":">=2.0"}
    ;
    try testing.expectError(error.RuntimeMismatch, parseManifest(src));
}

test "runtimeSatisfies reads the major version a v1 host can honour" {
    try testing.expect(runtimeSatisfies(">=0.1", 1));
    try testing.expect(runtimeSatisfies("0.1", 1));
    try testing.expect(runtimeSatisfies("1.0", 1));
    try testing.expect(!runtimeSatisfies(">=2.0", 1));
    try testing.expect(!runtimeSatisfies("", 1));
    try testing.expect(!runtimeSatisfies(">=x.y", 1));
}

test "a malformed document is NotJson, a non-object is NotAnObject" {
    defer releaseManifest();
    try testing.expectError(error.NotJson, parseManifest("{"));
    try testing.expectError(error.NotJson, parseManifest(""));
    try testing.expectError(error.NotAnObject, parseManifest("[]"));
}

test "off Windows there is no filesystem, so loadFromDir says so" {
    if (is_windows) return;
    try testing.expectError(error.NotWindows, loadFromDir("C:/temp/neo_mods/x"));
}

test "the loader's Permissions is the host's type, not a copy" {
    try testing.expect(Permissions == host.Permissions);
    var p = Permissions{ .log = true };
    try testing.expect(!host.canSetVariable(p));
    p.variable_write = true;
    try testing.expect(host.canSetVariable(p));
}
