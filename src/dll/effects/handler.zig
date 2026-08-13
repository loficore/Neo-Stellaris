// handler.zig — JS callback routing for custom effects.
//
// Bridges the CEffect hook (ceffect.zig) to the QuickJS JavaScript runtime.
// When a custom effect is detected, this module:
//   1. Looks up the registered JS handler for the effect name
//   2. Constructs the appropriate JS arguments (effect name, scope info)
//   3. Invokes the JS handler and returns its result to the engine
//
// The handler registry maps effect names to JS function names. Modders register
// handlers via the stellaris_quickjs API:
//   Stellaris.registerEffect("my_effect", function(name, scope) { ... });
//
// Thread safety: The handler registry is protected by a mutex since effect
// execution can happen from multiple game threads.

const std = @import("std");
const c = @import("../quickjs/bindings.zig");
const runtime = @import("../quickjs/runtime.zig");
const offsets = @import("../shared/offsets.zig");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Handler entry: maps an effect name to a JS function name.
const HandlerEntry = struct {
    /// Effect name as it appears in game scripts (e.g., "my_custom_effect").
    effect_name: []const u8,

    /// JS function name to call (e.g., "handleMyEffect").
    js_function_name: []const u8,
};

/// Error types for the effect handler.
pub const HandlerError = error{
    /// No handler registered for this effect.
    NoHandler,
    /// QuickJS context is not initialized.
    RuntimeNotInitialized,
    /// JS function call failed (exception thrown).
    JSError,
    /// Memory allocation failed.
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// Handler registry
// ---------------------------------------------------------------------------

/// Maximum number of registered effect handlers.
const MAX_HANDLERS: usize = 256;

/// Global handler registry state.
var handler_mutex = std.Thread.Mutex{};
var handler_count: usize = 0;
var handlers: [MAX_HANDLERS]HandlerEntry = undefined;

/// Registered effect names (owned memory).
var handler_names: [MAX_HANDLERS][]const u8 = undefined;

/// Registered JS function names (owned memory).
var js_function_names: [MAX_HANDLERS][]const u8 = undefined;

/// Allocator for handler strings (set during init).
var handler_allocator: ?std.mem.Allocator = null;

// ---------------------------------------------------------------------------
// QuickJS runtime reference
// ---------------------------------------------------------------------------

/// Global reference to the QuickJS runtime (set during init).
var js_runtime: ?*runtime.Runtime = null;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the effect handler system.
///
/// Must be called before any effects are executed. Provides the QuickJS runtime
/// context for invoking JS handlers.
///
/// # Arguments
/// * `rt` - The QuickJS runtime instance
/// * `alloc` - Allocator for handler registry strings
pub fn init(rt: *runtime.Runtime, alloc: std.mem.Allocator) void {
    js_runtime = rt;
    handler_allocator = alloc;
    handler_count = 0;
    std.log.info("Effect handler initialized (capacity: {d})", .{MAX_HANDLERS});
}

/// Deinitialize the effect handler system.
///
/// Frees all registered handler strings and clears the registry.
pub fn deinit() void {
    if (handler_allocator) |alloc| {
        var i: usize = 0;
        while (i < handler_count) : (i += 1) {
            alloc.free(handler_names[i]);
            alloc.free(js_function_names[i]);
        }
    }
    handler_count = 0;
    js_runtime = null;
    handler_allocator = null;
    std.log.info("Effect handler deinitialized", .{});
}

/// Register a JS handler for a custom effect.
///
/// # Arguments
/// * `effect_name` - The effect name as used in game scripts
/// * `js_function_name` - The JS function to call when this effect executes
///
/// # Errors
/// Returns error if the registry is full or allocation fails.
pub fn registerHandler(effect_name: []const u8, js_function_name: []const u8) !void {
    handler_mutex.lock();
    defer handler_mutex.unlock();

    if (handler_count >= MAX_HANDLERS) return error.OutOfMemory;
    if (handler_allocator == null) return error.RuntimeNotInitialized;

    const alloc = handler_allocator.?;

    // Check for duplicate registration
    for (handlers[0..handler_count]) |entry| {
        if (std.mem.eql(u8, entry.effect_name, effect_name)) {
            // Update existing handler
            alloc.free(js_function_names[handler_count]);
            js_function_names[handler_count - 1] = try alloc.dupe(u8, js_function_name);
            std.log.info("Updated handler for effect '{s}' -> '{s}'", .{ effect_name, js_function_name });
            return;
        }
    }

    // New registration
    handler_names[handler_count] = try alloc.dupe(u8, effect_name);
    js_function_names[handler_count] = try alloc.dupe(u8, js_function_name);
    handlers[handler_count] = .{
        .effect_name = handler_names[handler_count],
        .js_function_name = js_function_names[handler_count],
    };
    handler_count += 1;

    std.log.info("Registered handler for effect '{s}' -> '{s}'", .{ effect_name, js_function_name });
}

/// Look up a handler by effect name.
///
/// Returns the JS function name if registered, null otherwise.
/// Caller must not free the returned string (owned by registry).
pub fn lookupHandler(effect_name: []const u8) ?[]const u8 {
    handler_mutex.lock();
    defer handler_mutex.unlock();

    for (handlers[0..handler_count]) |entry| {
        if (std.mem.eql(u8, entry.effect_name, effect_name)) {
            return entry.js_function_name;
        }
    }
    return null;
}

/// Get the number of registered handlers.
pub fn getHandlerCount() usize {
    handler_mutex.lock();
    defer handler_mutex.unlock();
    return handler_count;
}

// ---------------------------------------------------------------------------
// Custom effect execution
// ---------------------------------------------------------------------------

/// Handle execution of a custom effect.
///
/// Called by the CEffect hook when a scripted effect (ID > 4081) is detected.
/// Looks up the registered JS handler and invokes it with the effect name
/// and scope information.
///
/// # Arguments
/// * `effect_name` - The effect name from CEffect+56
/// * `effect_id` - The effect ID from CEffect+4080
/// * `ceventscope` - The CEventScope pointer (opaque to JS, passed as integer)
///
/// # Returns
/// The JS handler's return value as i64 (typically 0 for effects).
pub fn handleCustomEffect(
    effect_name: []const u8,
    effect_id: i32,
    ceventscope: *anyopaque,
) callconv(.c) i64 {
    // Look up the handler
    const js_func_name = lookupHandler(effect_name) orelse {
        std.log.warn(
            "No handler registered for custom effect '{s}' (ID: {d}), skipping",
            .{ effect_name, effect_id },
        );
        return 0;
    };

    // Get the QuickJS runtime
    const rt = js_runtime orelse {
        std.log.err("QuickJS runtime not initialized when handling effect '{s}'", .{effect_name});
        return 0;
    };

    // Call the JS handler
    return callJSHandler(rt, js_func_name, effect_name, effect_id, ceventscope) catch |err| {
        std.log.err(
            "Error executing JS handler for effect '{s}': {}",
            .{ effect_name, err },
        );
        return 0;
    };
}

/// Invoke the JS handler function.
///
/// Constructs the call: js_func_name(effect_name, effect_id, scope_ptr)
fn callJSHandler(
    rt: *runtime.Runtime,
    js_func_name: []const u8,
    effect_name: []const u8,
    effect_id: i32,
    ceventscope: *anyopaque,
) !i64 {
    // Get the global object
    const global = c.JS_GetGlobalObject(rt.ctx);
    defer c.JS_FreeValue(rt.ctx, global);

    // Look up the function by name
    const func_name_z = try rt.ctx.allocator.dupeZ(u8, js_func_name);
    defer rt.ctx.allocator.free(func_name_z);

    // For now, we use eval to call the function: func_name(effect_name, effect_id, scope_ptr)
    // This is a simple approach; a more optimized version would cache the function object.
    var buf: [1024]u8 = undefined;
    const call_code = std.fmt.bufPrint(
        &buf,
        "if (typeof {0s} === 'function') {{ {0s}('{1s}', {2}, {3}) }} else {{ 0 }}",
        .{ js_func_name, effect_name, effect_id, @intFromPtr(ceventscope) },
    ) catch return error.OutOfMemory;

    // Evaluate the call
    var result = rt.eval(call_code, "<effect_handler>");
    defer result.deinit(rt.ctx, std.heap.page_allocator);

    if (result.isError()) {
        std.log.err("JS handler '{s}' threw exception", .{js_func_name});
        return error.JSError;
    }

    // Extract return value (default to 0 if not an integer)
    // For now, return 0 as most effects don't have meaningful return values
    return 0;
}

// =============================================================================
// Tests
// =============================================================================

test "handler registry: init and deinit" {
    // Can't fully test without QuickJS runtime, but we can test the registry
    // by setting a dummy allocator
    handler_allocator = std.testing.allocator;
    defer {
        // Clean up any registered handlers
        var i: usize = 0;
        while (i < handler_count) : (i += 1) {
            std.testing.allocator.free(handler_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        handler_count = 0;
        handler_allocator = null;
    }

    // Reset state
    handler_count = 0;

    // Register a handler
    try registerHandler("test_effect", "handleTestEffect");

    // Verify registration
    try std.testing.expectEqual(@as(usize, 1), getHandlerCount());

    // Look up the handler
    const func_name = lookupHandler("test_effect");
    try std.testing.expect(func_name != null);
    try std.testing.expectEqualStrings("handleTestEffect", func_name.?);
}

test "handler registry: lookup returns null for unknown" {
    handler_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < handler_count) : (i += 1) {
            std.testing.allocator.free(handler_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        handler_count = 0;
        handler_allocator = null;
    }

    handler_count = 0;

    const func_name = lookupHandler("nonexistent_effect");
    try std.testing.expectEqual(@as(?[]const u8, null), func_name);
}

test "handler registry: update existing handler" {
    handler_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < handler_count) : (i += 1) {
            std.testing.allocator.free(handler_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        handler_count = 0;
        handler_allocator = null;
    }

    handler_count = 0;

    // Register initial handler
    try registerHandler("my_effect", "handler_v1");
    try std.testing.expectEqual(@as(usize, 1), getHandlerCount());

    // Update handler
    try registerHandler("my_effect", "handler_v2");
    try std.testing.expectEqual(@as(usize, 1), getHandlerCount());

    // Verify update
    const func_name = lookupHandler("my_effect");
    try std.testing.expect(func_name != null);
    try std.testing.expectEqualStrings("handler_v2", func_name.?);
}

test "handler registry: multiple handlers" {
    handler_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < handler_count) : (i += 1) {
            std.testing.allocator.free(handler_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        handler_count = 0;
        handler_allocator = null;
    }

    handler_count = 0;

    // Register multiple handlers
    try registerHandler("effect_a", "handleA");
    try registerHandler("effect_b", "handleB");
    try registerHandler("effect_c", "handleC");

    try std.testing.expectEqual(@as(usize, 3), getHandlerCount());

    // Verify all lookups work
    try std.testing.expectEqualStrings("handleA", lookupHandler("effect_a").?);
    try std.testing.expectEqualStrings("handleB", lookupHandler("effect_b").?);
    try std.testing.expectEqualStrings("handleC", lookupHandler("effect_c").?);
}

test "handler count starts at zero" {
    // Save state
    const saved_count = handler_count;
    defer handler_count = saved_count;

    handler_count = 0;
    try std.testing.expectEqual(@as(usize, 0), getHandlerCount());
}
