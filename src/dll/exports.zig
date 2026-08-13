// exports.zig — DLL exports callable from the C++ loader.
//
// These symbols must be exported so the injected C++ loader (T1) can
// discover and call them after DLL load. In Zig, `export` functions
// use C calling convention by default and are visible to the linker.

const std = @import("std");
const main = @import("main.zig");

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

/// Standard Windows DLL entry point.
/// We do not perform meaningful work here — real initialization happens
/// when PushCApplicationPtr is called. This just satisfies the loader.
export fn DllMain(
    hinstDLL: ?*anyopaque,
    fdwReason: u32,
    lpvReserved: ?*anyopaque,
) callconv(.c) i32 {
    _ = hinstDLL;
    _ = lpvReserved;

    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    switch (fdwReason) {
        DLL_PROCESS_ATTACH => {
            std.log.info("stellaris_quickjs: DLL_PROCESS_ATTACH", .{});
            main.initializeQuickJS();
        },
        DLL_PROCESS_DETACH => {
            std.log.info("stellaris_quickjs: DLL_PROCESS_DETACH", .{});
            main.deinitializeQuickJS();
            engine_ptr = null;
            base_address = 0;
        },
        else => {},
    }

    // Return TRUE (1)
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
