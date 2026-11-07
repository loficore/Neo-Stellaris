// neo_js_loader.zig — Runtime JS loader(Track A):manifest + 权限 + 多 mod 列表。
//
// 目录契约(计划 Global Constraints,固定、不解析 `dlc_load.json`):
//   C:/temp/neo_mods/<id>/neo/mod.json
//   C:/temp/neo_mods/<id>/neo/main.js
// Phase 1 要求**恰好一个**带 `neo/mod.json` 的目录;Phase 2(Task A3)起支持
// 最多 `MAX_MODS`(8)个:每个目录一个 session,坏 manifest 的候选跳过并计数,
// 不影响其它 mod;超过 8 个的候选拒绝并计数。0 个仍是可判读的 `error.NoMod`
// (fail-closed,不重试)。
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
const neo_state = @import("neo_state.zig");
const keyword_registry = @import("../scripted/keyword_registry.zig");

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

/// P2-1b: 一份安装里最多预发的 flag 名数。`neo/mod.json` 的 `flags` 是可选的
/// 第 7 字段;超过这个数在 loader(这里)与 build 两侧都报错,不静默截断。
pub const MAX_FLAGS: usize = 32;

/// flag 名的字节上限 = `neo_state` 的 SSO 容量(`mintFlagTokenRaw` 的 holder
/// 是 15 B SSO 字符串,再长就要堆分配 —— 那条路不在本模块的纪律里)。
pub const MAX_FLAG_NAME: usize = neo_state.SSO_MAX;

/// Phase 2 (Task A3): 最多同时载入的 runtime mod 数。超过的**拒绝并日志**;
/// 静态数组,不分配。8 是计划冻结值。
pub const MAX_MODS: usize = 8;

/// `loadActiveList()` 的读数:调用方(host)用它写「跳过几个 / 拒绝几个」的日志。
pub const ListStats = struct {
    /// 目录里带 `neo/mod.json` 的候选 mod 数(含被拒绝的)。
    total: usize = 0,
    /// 成功载入的数 = `items.len`。
    loaded: usize = 0,
    /// 载入失败的候选数(坏 manifest / 缺 entry / 读文件失败)。
    skipped: usize = 0,
    /// 超过 `MAX_MODS` 而没有尝试载入的数。
    overflow: usize = 0,
};

pub const Manifest = struct {
    id: []const u8,
    entry: []const u8,
    scope: []const u8,
    permissions: Permissions,
    engine: []const u8,
    runtime: []const u8,
    /// P2-1b: 构建期声明的 flag 名(`neo build` 写入)。可选 —— 缺省是空列表,
    /// 旧的 Phase 1/2 manifest 仍然合法;那时 flag 调用 fail-closed(`no_premint`)。
    /// 切片活在 manifest arena 里(下一次 `parseManifest`/`releaseManifest` 之前有效)。
    flags: []const []const u8 = &.{},
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
    BadFlagName,
    TooManyFlags,
    OutOfMemory,
};

pub const LoadError = ParseError || error{
    NotWindows,
    NoMod,
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

/// 解析一个 manifest。会先释放上一次的 arena —— 单 mod/测试的入口。
/// 多 mod 载入走 `parseManifestRetained`(一次载入里所有 manifest 同时有效)。
pub fn parseManifest(bytes: []const u8) ParseError!Manifest {
    releaseManifest();
    return parseManifestRetained(bytes);
}

fn parseManifestRetained(bytes: []const u8) ParseError!Manifest {
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

    // Strict field set: every key must be one of the seven, once. The first six
    // are required; `flags` is optional (P2-1b: old manifests stay valid).
    var seen = [_]bool{false} ** 7;
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
        else if (std.mem.eql(u8, entry.key_ptr.*, "flags"))
            6
        else
            return error.UnknownField;
        if (seen[idx.?]) return error.DuplicateField;
        seen[idx.?] = true;
    }
    for (seen[0..6]) |present| {
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

    const flags = try parseFlags(obj.get("flags"));

    return .{
        .id = id,
        .entry = entry,
        .scope = scope,
        .permissions = permissions,
        .engine = engine,
        .runtime = runtime,
        .flags = flags,
    };
}

/// P2-1b: `flags` 是可选的第 7 字段。必须是 JSON array of string;每项过
/// `flagNameOk`;重复项**去重保序**(不是错误 —— 两份互相 import 的源码可以
/// 各自写同一个字面量);超过 `MAX_FLAGS` 是 `error.TooManyFlags`,不截断。
fn parseFlags(v: ?std.json.Value) ParseError![]const []const u8 {
    const value = v orelse return &.{};
    const items = switch (value) {
        .array => |a| a.items,
        else => return error.BadFieldType,
    };
    var list = std.ArrayList([]const u8).empty;
    const alloc = arenaAlloc();
    for (items) |item| {
        const name = try asString(item);
        if (!flagNameOk(name)) return error.BadFlagName;
        var dup = false;
        for (list.items) |seen| {
            if (std.mem.eql(u8, seen, name)) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        if (list.items.len >= MAX_FLAGS) return error.TooManyFlags;
        list.append(alloc, name) catch return error.OutOfMemory;
    }
    return list.toOwnedSlice(alloc) catch return error.OutOfMemory;
}

/// 与 `keyword_registry.NameCheck` 同一套(空 / 首字符 / 大小写),再加一条
/// SSO 长度上限。全小写是硬性的:`0x1D13270` 的查找会 case-fold,大小写混写
/// 正是「静默接管官方 keyword」的形状(AGENTS 约束 4)。
fn flagNameOk(name: []const u8) bool {
    if (name.len > MAX_FLAG_NAME) return false;
    return keyword_registry.NameCheck.check(name).ok;
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
                } else if (std.mem.eql(u8, name, "variable.read")) {
                    p.variable_read = true;
                } else if (std.mem.eql(u8, name, "flag.write")) {
                    p.flag_write = true;
                } else if (std.mem.eql(u8, name, "flag.read")) {
                    p.flag_read = true;
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

/// `C:/temp/neo_mods/` 下的候选 mod 目录(`neo/mod.json` 存在)。Phase 2 起支持
/// 多个:按 id 字节序排序以保证载入顺序确定,最多 `MAX_MODS` 个被载入。
var mod_ids: [MAX_MODS][MAX_ID_LEN]u8 = undefined;
var mod_id_lens: [MAX_MODS]usize = undefined;
var mod_count: usize = 0;
var list_stats: ListStats = .{};

/// 上一次枚举看到的候选 mod 数(所有带 manifest 的目录)。
pub fn lastModCount() usize {
    return mod_count;
}

/// 上一次 `loadActiveList` 的读数(host 用它写跳过/拒绝的日志)。
pub fn lastListStats() ListStats {
    return list_stats;
}

fn modManifestExists(name: []const u8) bool {
    var buf: [MAX_PATH]u8 = undefined;
    const path = joinPath(&buf, &.{ MODS_ROOT, name, "/neo/mod.json" }) orelse return false;
    var path_buf: [MAX_PATH]u8 = undefined;
    const h = openRead(path, &path_buf) orelse return false;
    _ = CloseHandle(h);
    return true;
}

/// 枚举候选目录名。返回前 `min(count, MAX_MODS)` 个;顺序按字节序,确定。
fn findModIds() LoadError![]const []const u8 {
    if (comptime !is_windows) return error.NotWindows;
    mod_count = 0;
    var data: WIN32_FIND_DATAA = undefined;
    const h = FindFirstFileA("C:\\temp\\neo_mods\\*", &data) orelse return error.NoMod;
    if (@intFromPtr(h) == INVALID_HANDLE_VALUE) return error.NoMod;
    defer _ = FindClose(h);

    while (true) {
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) {
            const name = std.mem.sliceTo(&data.cFileName, 0);
            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..") and modManifestExists(name)) {
                if (mod_count >= MAX_MODS) {
                    // 只记数量;继续枚举,拒绝的数 = 总数 - MAX_MODS。
                    mod_count += 1;
                } else {
                    if (name.len > MAX_ID_LEN) return error.PathTooLong;
                    @memcpy(mod_ids[mod_count][0..name.len], name);
                    mod_id_lens[mod_count] = name.len;
                    mod_count += 1;
                }
            }
        }
        if (FindNextFileA(h, &data) == 0) break;
    }
    if (mod_count == 0) return error.NoMod;

    // 排序前 `min(mod_count, MAX_MODS)` 个,按 id 字节序(插入排序,上界 8)。
    const n = @min(mod_count, MAX_MODS);
    var i: usize = 1;
    while (i < n) : (i += 1) {
        var j = i;
        while (j > 0) : (j -= 1) {
            const a = mod_ids[j - 1][0..mod_id_lens[j - 1]];
            const b = mod_ids[j][0..mod_id_lens[j]];
            if (std.mem.order(u8, a, b) != .gt) break;
            const tmp_id = mod_ids[j - 1];
            mod_ids[j - 1] = mod_ids[j];
            mod_ids[j] = tmp_id;
            const tmp_len = mod_id_lens[j - 1];
            mod_id_lens[j - 1] = mod_id_lens[j];
            mod_id_lens[j] = tmp_len;
        }
    }

    var out: [MAX_MODS][]const u8 = undefined;
    for (0..n) |k| out[k] = mod_ids[k][0..mod_id_lens[k]];
    // 静态返回数组:`mod_ids` 的切片在下一次 `loadActiveList` 前有效。
    for (0..n) |k| ids_view[k] = out[k];
    return ids_view[0..n];
}

var ids_view: [MAX_MODS][]const u8 = undefined;

/// P2-1b: 安装期要预发的 flag 名(`C2NeoInstall` → `premintFlags`)。
///
/// 只读 `C:/temp/neo_mods/<id>/neo/mod.json` 的 `flags` 字段 —— **不信 bundle 的
/// 运行时参数**:名字的唯一来源是 manifest(`neo check` 保证它与 bundle 字面量一致)。
/// 与 `findModIds` 用同一次目录枚举(同排序、同样最多 `MAX_MODS` 个),所以预发号
/// 覆盖的正是之后会被载入的那批 mod。坏 manifest 跳过并落一行 `NEO_JS_INSTALL_SKIP`。
///
/// `out` 里的切片指向 manifest arena(下一次 `releaseManifest` 之前有效);
/// 调用方(`premintFlags`)必须在同一趟里把字节复制走。非 Windows 返回 0。
pub fn flagNamesForInstall(out: *[MAX_FLAGS][]const u8) usize {
    if (comptime !is_windows) return 0;
    var count: usize = 0;
    const ids = findModIds() catch return 0;
    for (ids) |id| {
        var dir_buf: [MAX_PATH]u8 = undefined;
        const dir = joinPath(&dir_buf, &.{ MODS_ROOT, id }) orelse continue;
        var path_buf: [MAX_PATH]u8 = undefined;
        const manifest_path = joinPath(&path_buf, &.{ dir, "/neo/mod.json" }) orelse continue;
        var manifest_buf: [MAX_MANIFEST_BYTES]u8 = undefined;
        const manifest_len = readFile(manifest_path, &manifest_buf) catch {
            host.emit("NEO_JS_INSTALL_SKIP id={s}", .{id});
            continue;
        };
        const manifest = parseManifestRetained(manifest_buf[0..manifest_len]) catch {
            host.emit("NEO_JS_INSTALL_SKIP id={s}", .{id});
            continue;
        };
        for (manifest.flags) |name| {
            if (count >= MAX_FLAGS) break;
            var dup = false;
            for (out[0..count]) |seen| {
                if (std.mem.eql(u8, seen, name)) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;
            out[count] = name;
            count += 1;
        }
    }
    return count;
}

/// 每个 mod 一个源码缓冲(`JS_Eval` 要哨兵终止;载入后整个进程生命周期有效)。
var source_bufs: [MAX_MODS][MAX_SOURCE_BYTES]u8 = undefined;

/// `<dir>` 里的 `neo/mod.json` + `neo/main.js`,源码写进 `slot` 的静态缓冲。
/// `<dir>` = `C:/temp/neo_mods/<id>`。不释放 manifest arena(多 mod 共用)。
fn loadFromDirSlot(dir: []const u8, slot: usize) LoadError!Loaded {
    var buf: [MAX_PATH]u8 = undefined;

    const manifest_path = joinPath(&buf, &.{ dir, "/neo/mod.json" }) orelse return error.PathTooLong;
    var manifest_buf: [MAX_MANIFEST_BYTES]u8 = undefined;
    const manifest_len = readFile(manifest_path, &manifest_buf) catch |err| return switch (err) {
        error.NoManifest => error.NoManifest,
        else => err,
    };
    const manifest = try parseManifestRetained(manifest_buf[0..manifest_len]);

    const entry_path = joinPath(&buf, &.{ dir, "/neo/", manifest.entry }) orelse return error.PathTooLong;
    const out = &source_bufs[slot];
    const source_len = readFile(entry_path, out) catch |err| return switch (err) {
        error.NoManifest => error.MissingEntry,
        else => err,
    };
    if (source_len >= out.len) return error.FileTooLarge;
    out[source_len] = 0;

    return .{ .manifest = manifest, .source = out[0..source_len :0] };
}

/// 单 mod 入口(兼容 Phase 1 的调用方/测试):先释放 manifest arena,再载入。
pub fn loadFromDir(dir: []const u8) LoadError!Loaded {
    releaseManifest();
    return loadFromDirSlot(dir, 0);
}

var loaded_items: [MAX_MODS]Loaded = undefined;
var loaded_ok: [MAX_MODS]bool = undefined;

/// 活动 mod 列表。0 个候选 → `error.NoMod`;坏 manifest 的候选**跳过并计数**
/// (`ListStats.skipped`),不影响其它 mod;超过 `MAX_MODS` 的候选不载入
/// (`ListStats.overflow`),由 host 记一行拒绝日志。
pub fn loadActiveList() LoadError![]const Loaded {
    releaseManifest();
    list_stats = .{};
    const ids = try findModIds();
    list_stats.total = mod_count;
    list_stats.overflow = mod_count - ids.len;

    for (ids, 0..) |id, i| {
        var buf: [MAX_PATH]u8 = undefined;
        const dir = joinPath(&buf, &.{ MODS_ROOT, id }) orelse {
            loaded_ok[i] = false;
            list_stats.skipped += 1;
            continue;
        };
        loaded_items[i] = loadFromDirSlot(dir, i) catch {
            loaded_ok[i] = false;
            list_stats.skipped += 1;
            continue;
        };
        loaded_ok[i] = true;
        list_stats.loaded += 1;
    }
    // 跳过项会在 loaded_items 里留下空洞:把成功的项前移。
    var w: usize = 0;
    var r: usize = 0;
    while (r < ids.len) : (r += 1) {
        if (!loaded_ok[r]) continue;
        if (w != r) loaded_items[w] = loaded_items[r];
        w += 1;
    }
    return loaded_items[0..w];
}

/// 单 mod 兼容入口:列表的第一个;一个都载入不了就是 `error.NoMod`。
pub fn loadActive() LoadError!Loaded {
    const list = try loadActiveList();
    if (list.len == 0) return error.NoMod;
    return list[0];
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

// --- Phase 2 A3: multi-mod list surface ------------------------------------

test "MAX_MODS is the frozen Phase 2 bound" {
    try testing.expectEqual(@as(usize, 8), MAX_MODS);
    try testing.expectEqual(ListStats{}, lastListStats());
}

test "the Phase 2 permission bits parse from the manifest" {
    defer releaseManifest();
    const src =
        \\{"id":"a","entry":"main.js","scope":["system"],"permissions":["graph.read","variable.write","variable.read","flag.write","flag.read","log"],"engine":"4.4.4","runtime":">=0.1"}
    ;
    const m = try parseManifest(src);
    try testing.expect(m.permissions.graph_read);
    try testing.expect(m.permissions.variable_write);
    try testing.expect(m.permissions.variable_read);
    try testing.expect(m.permissions.flag_write);
    try testing.expect(m.permissions.flag_read);
    try testing.expect(m.permissions.log);
}

test "off Windows the multi-mod list has no filesystem either" {
    if (is_windows) return;
    try testing.expectError(error.NotWindows, loadActiveList());
}

// --- P2-1b: the optional `flags` field -------------------------------------

test "manifest flags are optional, unique, and name-checked" {
    defer releaseManifest();
    const m = try parseManifest(
        \\{"id":"a","entry":"main.js","scope":"system","permissions":[],"engine":"4.4.4","runtime":">=0.1",
        \\ "flags":["neo_hub","neo_hub","neo_choke"]}
    );
    try testing.expectEqual(@as(usize, 2), m.flags.len);
    try testing.expectEqualStrings("neo_hub", m.flags[0]);
    try testing.expectEqualStrings("neo_choke", m.flags[1]);

    const empty = try parseManifest(
        \\{"id":"a","entry":"main.js","scope":"system","permissions":[],"engine":"4.4.4","runtime":">=0.1"}
    );
    try testing.expectEqual(@as(usize, 0), empty.flags.len);

    try testing.expectError(error.BadFlagName, parseManifest(
        \\{"id":"a","entry":"main.js","scope":"system","permissions":[],"engine":"4.4.4","runtime":">=0.1","flags":["Neo_Hub"]}
    ));
    try testing.expectError(error.BadFlagName, parseManifest(
        \\{"id":"a","entry":"main.js","scope":"system","permissions":[],"engine":"4.4.4","runtime":">=0.1","flags":["3d"]}
    ));
    try testing.expectError(error.BadFlagName, parseManifest(
        \\{"id":"a","entry":"main.js","scope":"system","permissions":[],"engine":"4.4.4","runtime":">=0.1","flags":["sixteen_chars_xx"]}
    ));
    try testing.expectError(error.BadFieldType, parseManifest(
        \\{"id":"a","entry":"main.js","scope":"system","permissions":[],"engine":"4.4.4","runtime":">=0.1","flags":"neo_hub"}
    ));
    try testing.expectError(error.TooManyFlags, parseManifest(
        \\{"id":"a","entry":"main.js","scope":"system","permissions":[],"engine":"4.4.4","runtime":">=0.1","flags":["f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","f10","f11","f12","f13","f14","f15","f16","f17","f18","f19","f20","f21","f22","f23","f24","f25","f26","f27","f28","f29","f30","f31","f32"]}
    ));
}

test "flagNamesForInstall is a no-op off Windows" {
    if (builtin.os.tag == .windows) return;
    var out: [MAX_FLAGS][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 0), flagNamesForInstall(&out));
}
