// inject/main.zig — Windows DLL injector for stellaris_quickjs.dll.
//
// Usage:
//   inject.exe [pid | process-name] <dll-path>
//   inject.exe stellaris C:\ns\stellaris_quickjs.dll
//
// Classic CreateRemoteThread(LoadLibraryW) injection. Written in Zig so it
// cross-compiles with the same toolchain as the DLL — no MSVC needed on the
// target machine.

const std = @import("std");
const windows = std.os.windows;

extern "kernel32" fn GetProcAddress(hModule: ?*anyopaque, lpProcName: [*:0]const u8) ?*anyopaque;
extern "kernel32" fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) ?windows.HANDLE;
extern "kernel32" fn CloseHandle(hObject: windows.HANDLE) i32;
extern "kernel32" fn GetModuleHandleA(lpModuleName: [*:0]const u8) ?*anyopaque;
extern "kernel32" fn VirtualAllocEx(hProcess: windows.HANDLE, lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) ?*anyopaque;
extern "kernel32" fn WriteProcessMemory(hProcess: windows.HANDLE, lpBaseAddress: *anyopaque, lpBuffer: *const anyopaque, nSize: usize, nWritten: ?*usize) i32;
extern "kernel32" fn CreateRemoteThread(hProcess: windows.HANDLE, lpThreadAttributes: ?*anyopaque, dwStackSize: usize, lpStartAddress: *const anyopaque, lpParameter: ?*anyopaque, dwCreationFlags: u32, lpThreadId: ?*u32) ?windows.HANDLE;
extern "kernel32" fn WaitForSingleObject(hHandle: windows.HANDLE, dwMilliseconds: u32) u32;
extern "kernel32" fn GetExitCodeThread(hThread: windows.HANDLE, lpExitCode: ?*u32) i32;
extern "kernel32" fn GetLastError() u32;

const PROCESSENTRY32W = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [260]u16,
};

const HANDLE_ENTRY_SNAPSHOT32 = opaque {};

extern "kernel32" fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) ?*HANDLE_ENTRY_SNAPSHOT32;
extern "kernel32" fn Process32FirstW(hSnapshot: *HANDLE_ENTRY_SNAPSHOT32, lppe: *PROCESSENTRY32W) i32;
extern "kernel32" fn Process32NextW(hSnapshot: *HANDLE_ENTRY_SNAPSHOT32, lppe: *PROCESSENTRY32W) i32;

const TH32CS_SNAPPROCESS: u32 = 0x2;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PROCESS_ALL_ACCESS: u32 = 0x1F0FFF;
const INFINITE: u32 = 0xFFFFFFFF;

pub fn main(init: std.process.Init.Minimal) !void {
    const alloc = std.heap.page_allocator;
    var it = try init.args.iterateAllocator(alloc);
    defer it.deinit();

    var argv_buf: [8][]const u8 = undefined;
    var argc: usize = 0;
    while (it.next()) |arg| : (argc += 1) {
        if (argc < argv_buf.len) argv_buf[argc] = arg;
    }
    const argv = argv_buf[0..argc];

    if (argv.len < 3) {
        printErr("usage: inject.exe [pid | process-name] <dll-path>\n", .{});
        std.process.exit(1);
    }
    const target_spec = argv[1];
    const dll_path = argv[2];

    const pid = resolvePid(target_spec) catch |err| {
        printErr("cannot resolve target '{s}': {s}\n", .{ target_spec, @errorName(err) });
        std.process.exit(1);
    };
    printErr("target pid: {d}\n", .{pid});

    const hmodule_remote = injectDll(pid, dll_path) catch |err| {
        printErr("injection failed: {s} (last error {d})\n", .{ @errorName(err), GetLastError() });
        std.process.exit(2);
    };
    if (hmodule_remote == 0) {
        printErr("LoadLibraryW returned NULL — DLL failed to load (last error {d})\n", .{GetLastError()});
        std.process.exit(3);
    }
    printErr("injected OK, remote HMODULE=0x{x}\n", .{hmodule_remote});
}

fn resolvePid(spec: []const u8) !u32 {
    return std.fmt.parseInt(u32, spec, 10) catch findProcessByName(spec);
}

fn findProcessByName(sub: []const u8) !u32 {
    const snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) orelse return error.SnapshotFailed;
    if (@intFromPtr(snap) == @as(usize, @bitCast(@as(i64, -1)))) return error.SnapshotFailed;
    defer _ = CloseHandle(@ptrCast(snap));

    var entry: PROCESSENTRY32W = undefined;
    entry.dwSize = @sizeOf(PROCESSENTRY32W);
    if (Process32FirstW(snap, &entry) == 0) return error.NoProcessFound;

    while (true) {
        const name16 = std.mem.sliceTo(&entry.szExeFile, 0);
        var name_buf: [512]u8 = undefined;
        const name = utf16ToUtf8(name16, &name_buf) catch continue;
        if (containsIgnoreCase(name, sub)) return entry.th32ProcessID;
        if (Process32NextW(snap, &entry) == 0) break;
    }
    return error.NoProcessFound;
}

/// Injects the DLL and returns the low 32 bits of the LoadLibraryW return
/// value (the module base inside the target); 0 means LoadLibraryW failed.
fn injectDll(pid: u32, dll_path: []const u8) !u32 {
    const hproc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid) orelse
        return error.OpenProcessFailed;
    defer _ = CloseHandle(hproc);

    var wide_buf: [4096]u16 = undefined;
    const len = std.unicode.utf8ToUtf16Le(&wide_buf, dll_path) catch return error.PathTooLong;
    wide_buf[len] = 0;
    const payload = std.mem.sliceAsBytes(wide_buf[0 .. len + 1]);

    const remote = VirtualAllocEx(hproc, null, payload.len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) orelse
        return error.VirtualAllocExFailed;

    var written: usize = 0;
    if (WriteProcessMemory(hproc, remote, @ptrCast(payload.ptr), payload.len, &written) == 0 or
        written != payload.len) return error.WriteProcessMemoryFailed;

    const kernel32 = GetModuleHandleA("kernel32.dll") orelse return error.Kernel32NotFound;
    const load_library = GetProcAddress(kernel32, "LoadLibraryW") orelse return error.LoadLibraryWNotFound;

    const thread = CreateRemoteThread(hproc, null, 0, @ptrCast(load_library), remote, 0, null) orelse
        return error.CreateRemoteThreadFailed;
    defer _ = CloseHandle(thread);

    _ = WaitForSingleObject(thread, INFINITE);
    var exit_code: u32 = 0;
    if (GetExitCodeThread(thread, &exit_code) == 0) return error.GetExitCodeFailed;
    return exit_code;
}

fn utf16ToUtf8(src: []const u16, dst: []u8) ![]const u8 {
    var it = std.unicode.Utf16LeIterator.init(src);
    var w: usize = 0;
    while (try it.nextCodepoint()) |cp| {
        w += try std.unicode.utf8Encode(cp, dst[w..]);
    }
    return dst[0..w];
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}

extern "kernel32" fn GetStdHandle(dwWhichHandle: i32) ?windows.HANDLE;
extern "kernel32" fn WriteFile(hFile: windows.HANDLE, lpBuffer: *const anyopaque, nNumberOfBytesToWrite: u32, lpNumberOfBytesWritten: ?*u32, lpOverlapped: ?*anyopaque) i32;

fn printErr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    const stderr = GetStdHandle(-12) orelse return;
    _ = WriteFile(stderr, msg.ptr, @intCast(msg.len), null, null);
}
