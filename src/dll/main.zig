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

// Scripted lookup detour (Stellaris 4.4.4) — referenced from the compilation
// root so its export fns (LookupHookInstall/Uninstall/Drain) land in the DLL.
pub const scripted = @import("scripted/lookup_hook.zig");

// Runtime base-Execute detour — the real 4.4.4 execution surface. Its export fns
// (ExecHookInstall/Uninstall/Drain/Histogram/Stats/Reset) are injector-facing.
pub const exec_hook = @import("scripted/exec_hook.zig");

// C1 keyword registration — mints a new token id and inserts into the engine's BST.
// Gated by authorize.c1_registration; the export fn C1Run in exports.zig is the
// injector-facing trigger.
pub const keyword_registry = @import("scripted/keyword_registry.zig");

// C2: QuickJS runtime integration — custom vtables + JS dispatch for registered keywords.
pub const c2_handler = @import("c2/handler.zig");
pub const c2_vtable = @import("c2/vtable.zig");
pub const c2_predicate_hook = @import("c2/predicate_hook.zig");
pub const c2_live_probe = @import("c2/live_probe.zig");

comptime {
    _ = scripted;
    _ = exec_hook;
    _ = keyword_registry;
    _ = c2_handler;
    _ = c2_vtable;
    _ = c2_predicate_hook;
    _ = c2_live_probe;
}

// ---------------------------------------------------------------------------
// QuickJS lifecycle management
// ---------------------------------------------------------------------------

/// Global QuickJS runtime instance.
pub var js_runtime: ?quickjs.Runtime = null;

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
