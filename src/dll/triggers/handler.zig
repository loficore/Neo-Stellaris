// handler.zig — JS callback routing for custom triggers.
//
// Bridges the CTrigger hook (ctrigger.zig) to the QuickJS JavaScript runtime.
// When a custom trigger is detected, this module:
//   1. Looks up the registered JS handler for the trigger name
//   2. Constructs the appropriate JS arguments (trigger name, scope info)
//   3. Invokes the JS handler and returns its boolean result to the engine
//
// The handler registry maps trigger names to JS function names. Modders register
// handlers via the stellaris_quickjs API:
//   Stellaris.registerTrigger("my_trigger", function(name, scope) { return true; });
//
// Thread safety: The handler registry is protected by a mutex since trigger
// evaluation can happen from multiple game threads.

const std = @import("std");
const c = @import("../quickjs/bindings.zig");
const runtime = @import("../quickjs/runtime.zig");
const offsets = @import("../shared/offsets.zig");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Handler entry: maps a trigger name to a JS function name.
const HandlerEntry = struct {
    /// Trigger name as it appears in game scripts (e.g., "my_custom_trigger").
    trigger_name: []const u8,

    /// JS function name to call (e.g., "handleMyTrigger").
    js_function_name: []const u8,
};

/// Error types for the trigger handler.
pub const HandlerError = error{
    /// No handler registered for this trigger.
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

/// Maximum number of registered trigger handlers.
const MAX_HANDLERS: usize = 256;

/// Global handler registry state.
var handler_mutex = std.Thread.Mutex{};
var handler_count: usize = 0;
var handlers: [MAX_HANDLERS]HandlerEntry = undefined;

/// Registered trigger names (owned memory).
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

/// Initialize the trigger handler system.
///
/// Must be called before any triggers are evaluated. Provides the QuickJS runtime
/// context for invoking JS handlers.
///
/// # Arguments
/// * `rt` - The QuickJS runtime instance
/// * `alloc` - Allocator for handler registry strings
pub fn init(rt: *runtime.Runtime, alloc: std.mem.Allocator) void {
    js_runtime = rt;
    handler_allocator = alloc;
    handler_count = 0;
    std.log.info("Trigger handler initialized (capacity: {d})", .{MAX_HANDLERS});
}

/// Deinitialize the trigger handler system.
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
    std.log.info("Trigger handler deinitialized", .{});
}

/// Register a JS handler for a custom trigger.
///
/// # Arguments
/// * `trigger_name` - The trigger name as used in game scripts
/// * `js_function_name` - The JS function to call when this trigger evaluates
///
/// # Errors
/// Returns error if the registry is full or allocation fails.
pub fn registerHandler(trigger_name: []const u8, js_function_name: []const u8) !void {
    handler_mutex.lock();
    defer handler_mutex.unlock();

    if (handler_count >= MAX_HANDLERS) return error.OutOfMemory;
    if (handler_allocator == null) return error.RuntimeNotInitialized;

    const alloc = handler_allocator.?;

    // Check for duplicate registration
    for (handlers[0..handler_count]) |entry| {
        if (std.mem.eql(u8, entry.trigger_name, trigger_name)) {
            // Update existing handler
            alloc.free(js_function_names[handler_count]);
            js_function_names[handler_count - 1] = try alloc.dupe(u8, js_function_name);
            std.log.info("Updated handler for trigger '{s}' -> '{s}'", .{ trigger_name, js_function_name });
            return;
        }
    }

    // New registration
    handler_names[handler_count] = try alloc.dupe(u8, trigger_name);
    js_function_names[handler_count] = try alloc.dupe(u8, js_function_name);
    handlers[handler_count] = .{
        .trigger_name = handler_names[handler_count],
        .js_function_name = js_function_names[handler_count],
    };
    handler_count += 1;

    std.log.info("Registered handler for trigger '{s}' -> '{s}'", .{ trigger_name, js_function_name });
}

/// Look up a handler by trigger name.
///
/// Returns the JS function name if registered, null otherwise.
/// Caller must not free the returned string (owned by registry).
pub fn lookupHandler(trigger_name: []const u8) ?[]const u8 {
    handler_mutex.lock();
    defer handler_mutex.unlock();

    for (handlers[0..handler_count]) |entry| {
        if (std.mem.eql(u8, entry.trigger_name, trigger_name)) {
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
// Custom trigger evaluation
// ---------------------------------------------------------------------------

/// Handle evaluation of a custom trigger.
///
/// Called by the CTrigger hook when a scripted trigger (ID > threshold) is detected.
/// Looks up the registered JS handler and invokes it with the trigger name
/// and scope information.
///
/// # Arguments
/// * `trigger_name` - The trigger name from CTrigger SSO string
/// * `trigger_id` - The trigger ID from CTrigger
/// * `ceventscope` - The CEventScope pointer (opaque to JS, passed as integer)
///
/// # Returns
/// The JS handler's boolean return value (true = trigger passes, false = fails).
pub fn handleCustomTrigger(
    trigger_name: []const u8,
    trigger_id: i32,
    ceventscope: *anyopaque,
) callconv(.c) bool {
    // Look up the handler
    const js_func_name = lookupHandler(trigger_name) orelse {
        std.log.warn(
            "No handler registered for custom trigger '{s}' (ID: {d}), defaulting to false",
            .{ trigger_name, trigger_id },
        );
        return false;
    };

    // Get the QuickJS runtime
    const rt = js_runtime orelse {
        std.log.err("QuickJS runtime not initialized when evaluating trigger '{s}'", .{trigger_name});
        return false;
    };

    // Call the JS handler
    return callJSHandler(rt, js_func_name, trigger_name, trigger_id, ceventscope) catch |err| {
        std.log.err(
            "Error executing JS handler for trigger '{s}': {}",
            .{ trigger_name, err },
        );
        return false;
    };
}

/// Invoke the JS handler function.
///
/// Constructs the call: js_func_name(trigger_name, trigger_id, scope_ptr)
/// and interprets the return value as a boolean.
fn callJSHandler(
    rt: *runtime.Runtime,
    js_func_name: []const u8,
    trigger_name: []const u8,
    trigger_id: i32,
    ceventscope: *anyopaque,
) !bool {
    // Get the global object
    const global = c.JS_GetGlobalObject(rt.ctx);
    defer c.JS_FreeValue(rt.ctx, global);

    // Look up the function by name
    const func_name_z = try rt.ctx.allocator.dupeZ(u8, js_func_name);
    defer rt.ctx.allocator.free(func_name_z);

    // Construct the call: func_name(trigger_name, trigger_id, scope_ptr)
    // This is a simple approach; a more optimized version would cache the function object.
    var buf: [1024]u8 = undefined;
    const call_code = std.fmt.bufPrint(
        &buf,
        "if (typeof {0s} === 'function') {{ !!{0s}('{1s}', {2}, {3}) }} else {{ false }}",
        .{ js_func_name, trigger_name, trigger_id, @intFromPtr(ceventscope) },
    ) catch return error.OutOfMemory;

    // Evaluate the call
    var result = rt.eval(call_code, "<trigger_handler>");
    defer result.deinit(rt.ctx, std.heap.page_allocator);

    if (result.isError()) {
        std.log.err("JS handler '{s}' threw exception", .{js_func_name});
        return error.JSError;
    }

    // Extract boolean return value
    // QuickJS boolean tag = 3, int32 tag = 4
    // We treat truthy values (non-zero, non-null, non-undefined) as true
    const val = result.ok;
    if (val.isBool()) {
        return val.u.i32 != 0;
    } else if (val.isInt32()) {
        return val.u.i32 != 0;
    } else if (val.isFloat64()) {
        return val.u.f64 != 0.0;
    } else if (val.isNull() or val.isUndefined()) {
        return false;
    }

    // Objects and strings are truthy
    return true;
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
    try registerHandler("test_trigger", "handleTestTrigger");

    // Verify registration
    try std.testing.expectEqual(@as(usize, 1), getHandlerCount());

    // Look up the handler
    const func_name = lookupHandler("test_trigger");
    try std.testing.expect(func_name != null);
    try std.testing.expectEqualStrings("handleTestTrigger", func_name.?);
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

    const func_name = lookupHandler("nonexistent_trigger");
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
    try registerHandler("my_trigger", "handler_v1");
    try std.testing.expectEqual(@as(usize, 1), getHandlerCount());

    // Update handler
    try registerHandler("my_trigger", "handler_v2");
    try std.testing.expectEqual(@as(usize, 1), getHandlerCount());

    // Verify update
    const func_name = lookupHandler("my_trigger");
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
    try registerHandler("trigger_a", "handleA");
    try registerHandler("trigger_b", "handleB");
    try registerHandler("trigger_c", "handleC");

    try std.testing.expectEqual(@as(usize, 3), getHandlerCount());

    // Verify all lookups work
    try std.testing.expectEqualStrings("handleA", lookupHandler("trigger_a").?);
    try std.testing.expectEqualStrings("handleB", lookupHandler("trigger_b").?);
    try std.testing.expectEqualStrings("handleC", lookupHandler("trigger_c").?);
}

test "handler count starts at zero" {
    // Save state
    const saved_count = handler_count;
    defer handler_count = saved_count;

    handler_count = 0;
    try std.testing.expectEqual(@as(usize, 0), getHandlerCount());
}
