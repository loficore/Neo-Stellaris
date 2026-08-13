// main.zig — DLL root source file.
//
// This module is the compilation root for the stellaris_quickjs shared library.
// It imports the exports module so that exported symbols (PushCApplicationPtr,
// DllMain) are reachable from the compilation root and linked into the final DLL.

const std = @import("std");

// Pull in the exports — reachable from root means the linker includes them.
pub const exports = @import("exports.zig");

// Force the export fn symbols (PushCApplicationPtr, DllMain) to be reachable
// from the compilation root. Without this, Zig's dead-code elimination removes
// them because nothing calls them directly — they're entry points called by
// the Windows loader, not by other Zig code.
comptime {
    _ = exports;
}

// QuickJS runtime integration.
pub const quickjs = @import("quickjs/runtime.zig");

// API Bridge - registers Stellaris.* functions in JS
pub const bridge = @import("api/bridge.zig");

// ---------------------------------------------------------------------------
// QuickJS lifecycle management
// ---------------------------------------------------------------------------

/// Global QuickJS runtime instance.
var js_runtime: ?quickjs.Runtime = null;

/// Initialize QuickJS and register all Stellaris API functions.
/// Called from DllMain DLL_PROCESS_ATTACH.
pub fn initializeQuickJS() void {
    // Create QuickJS runtime
    js_runtime = quickjs.Runtime.init() catch |err| {
        std.log.err("Failed to initialize QuickJS: {}", .{err});
        return;
    };

    if (js_runtime) |rt| {
        // Register all Stellaris API functions
        bridge.registerAllFunctions(rt.ctx);
        std.log.info("QuickJS initialized, Stellaris API registered", .{});
    }
}

/// Cleanup QuickJS runtime.
/// Called from DllMain DLL_PROCESS_DETACH.
pub fn deinitializeQuickJS() void {
    if (js_runtime) |*rt| {
        rt.deinit();
        js_runtime = null;
    }
}
