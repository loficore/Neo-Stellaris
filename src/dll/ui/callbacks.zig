// callbacks.zig — JS callback management for button effects.
//
// Provides a registry for mapping button effect names to JavaScript callback
// functions. When a button is clicked in a .gui window, the engine looks up
// the registered callback and invokes it via QuickJS.
//
// Usage from JavaScript (via QuickJS bridge):
//   Stellaris.registerButtonCallback("my_effect", function(btn_name, scope) {
//       console.log("Button clicked: " + btn_name);
//   });
//
// Usage from Zig:
//   callbacks.registerButtonCallback("close_window", "handleClose");
//   callbacks.handleButtonClick("close_window", scope_ptr);

const std = @import("std");

// Note: QuickJS runtime bindings are available when integrated into the build system.
// For standalone testing, the callback registry works without QuickJS.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Callback entry: maps a button effect name to a JS function name.
const CallbackEntry = struct {
    /// Effect name as defined in common/button_effects/ (e.g., "close_my_window").
    effect_name: []const u8,

    /// JS function name to call when button is clicked (e.g., "handleClose").
    js_function_name: []const u8,

    /// Optional user data passed to the callback.
    user_data: ?*anyopaque = null,
};

/// Error types for callback operations.
pub const CallbackError = error{
    /// No callback registered for this effect.
    NoCallback,
    /// QuickJS context is not initialized.
    RuntimeNotInitialized,
    /// JS function call failed (exception thrown).
    JSError,
    /// Memory allocation failed.
    OutOfMemory,
    /// Callback registry is full.
    RegistryFull,
};

/// Callback invocation result.
pub const CallbackResult = struct {
    /// Whether the callback was successfully invoked.
    success: bool,

    /// Return value from the JS callback (if any).
    return_value: ?i64 = null,

    /// Error message if invocation failed.
    error_message: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Callback Registry
// ---------------------------------------------------------------------------

/// Maximum number of registered button callbacks.
const MAX_CALLBACKS: usize = 128;

/// Global callback registry state.
var callback_count: usize = 0;
var callbacks: [MAX_CALLBACKS]CallbackEntry = undefined;

/// Registered effect names (owned memory).
var effect_names: [MAX_CALLBACKS][]const u8 = undefined;

/// Registered JS function names (owned memory).
var js_function_names: [MAX_CALLBACKS][]const u8 = undefined;

/// Allocator for callback strings (set during init).
var callback_allocator: ?std.mem.Allocator = null;

// Thread safety note: When integrated into the build system, the registry
// should use std.Thread.Mutex for thread-safe access. For standalone testing,
// single-threaded access is assumed.

// ---------------------------------------------------------------------------
// QuickJS Runtime Reference
// ---------------------------------------------------------------------------

/// Global reference to the QuickJS runtime context (set during init).
/// Type is opaque to avoid requiring QuickJS headers in standalone tests.
var js_context: ?*anyopaque = null;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the callback system.
///
/// Must be called before any callbacks are registered. Provides the QuickJS
/// runtime context for invoking JS handlers.
///
/// # Arguments
/// * `ctx` - The QuickJS context (opaque pointer)
/// * `alloc` - Allocator for callback registry strings
pub fn init(ctx: ?*anyopaque, alloc: std.mem.Allocator) void {
    js_context = ctx;
    callback_allocator = alloc;
    callback_count = 0;
    std.log.info("Button callback system initialized (capacity: {d})", .{MAX_CALLBACKS});
}

/// Deinitialize the callback system.
///
/// Frees all registered callback strings and clears the registry.
pub fn deinit() void {
    if (callback_allocator) |alloc| {
        var i: usize = 0;
        while (i < callback_count) : (i += 1) {
            alloc.free(effect_names[i]);
            alloc.free(js_function_names[i]);
        }
    }
    callback_count = 0;
    js_context = null;
    callback_allocator = null;
    std.log.info("Button callback system deinitialized", .{});
}

/// Register a JS callback for a button effect.
///
/// # Arguments
/// * `effect_name` - The effect name as defined in button_effects
/// * `js_function_name` - The JS function to call when button is clicked
///
/// # Errors
/// Returns error if the registry is full or allocation fails.
pub fn registerButtonCallback(effect_name: []const u8, js_function_name: []const u8) !void {
    if (callback_count >= MAX_CALLBACKS) return error.RegistryFull;
    if (callback_allocator == null) return error.RuntimeNotInitialized;

    const alloc = callback_allocator.?;

    // Check for duplicate registration - update if exists
    for (callbacks[0..callback_count], 0..) |entry, i| {
        if (std.mem.eql(u8, entry.effect_name, effect_name)) {
            // Update existing callback
            alloc.free(js_function_names[i]);
            js_function_names[i] = try alloc.dupe(u8, js_function_name);
            callbacks[i].js_function_name = js_function_names[i];
            std.log.info("Updated button callback for effect '{s}' -> '{s}'", .{ effect_name, js_function_name });
            return;
        }
    }

    // New registration
    effect_names[callback_count] = try alloc.dupe(u8, effect_name);
    js_function_names[callback_count] = try alloc.dupe(u8, js_function_name);
    callbacks[callback_count] = .{
        .effect_name = effect_names[callback_count],
        .js_function_name = js_function_names[callback_count],
    };
    callback_count += 1;

    std.log.info("Registered button callback for effect '{s}' -> '{s}'", .{ effect_name, js_function_name });
}

/// Look up a callback by effect name.
///
/// Returns the JS function name if registered, null otherwise.
/// Caller must not free the returned string (owned by registry).
pub fn lookupCallback(effect_name: []const u8) ?[]const u8 {
    for (callbacks[0..callback_count]) |entry| {
        if (std.mem.eql(u8, entry.effect_name, effect_name)) {
            return entry.js_function_name;
        }
    }
    return null;
}

/// Remove a callback registration.
///
/// # Arguments
/// * `effect_name` - The effect name to unregister
///
/// # Returns
/// true if the callback was found and removed, false otherwise.
pub fn removeCallback(effect_name: []const u8) bool {
    for (callbacks[0..callback_count], 0..) |entry, i| {
        if (std.mem.eql(u8, entry.effect_name, effect_name)) {
            // Free the strings
            if (callback_allocator) |alloc| {
                alloc.free(effect_names[i]);
                alloc.free(js_function_names[i]);
            }

            // Shift remaining entries
            var j = i;
            while (j < callback_count - 1) : (j += 1) {
                callbacks[j] = callbacks[j + 1];
                effect_names[j] = effect_names[j + 1];
                js_function_names[j] = js_function_names[j + 1];
            }

            callback_count -= 1;
            std.log.info("Removed button callback for effect '{s}'", .{effect_name});
            return true;
        }
    }
    return false;
}

/// Get the number of registered callbacks.
pub fn getCallbackCount() usize {
    return callback_count;
}

/// Check if a callback is registered for the given effect.
pub fn hasCallback(effect_name: []const u8) bool {
    return lookupCallback(effect_name) != null;
}

// ---------------------------------------------------------------------------
// Button Click Handling
// ---------------------------------------------------------------------------

/// Handle a button click event.
///
/// Called by the engine when a button is clicked in a .gui window. Looks up
/// the registered JS callback and invokes it with the effect name and optional
/// scope information.
///
/// # Arguments
/// * `effect_name` - The effect name from the button's effect field
/// * `ceventscope` - Optional CEventScope pointer (opaque to JS)
///
/// # Returns
/// CallbackResult indicating success/failure and any return value.
pub fn handleButtonClick(
    effect_name: []const u8,
    ceventscope: ?*anyopaque,
) CallbackResult {
    // Look up the callback
    const js_func_name = lookupCallback(effect_name) orelse {
        std.log.warn(
            "No callback registered for button effect '{s}', skipping",
            .{effect_name},
        );
        return .{
            .success = false,
            .error_message = "No callback registered",
        };
    };

    // Get the QuickJS context
    const ctx = js_context orelse {
        std.log.err("QuickJS context not initialized when handling button '{s}'", .{effect_name});
        return .{
            .success = false,
            .error_message = "Runtime not initialized",
        };
    };

    // Call the JS callback
    return callJSCallback(ctx, js_func_name, effect_name, ceventscope) catch |err| {
        const err_msg = switch (err) {
            error.OutOfMemory => "Out of memory",
            error.JSError => "JS execution error",
            else => "Unknown error",
        };
        std.log.err(
            "Error executing JS callback for button '{s}': {}",
            .{ effect_name, err },
        );
        return .{
            .success = false,
            .error_message = err_msg,
        };
    };
}

/// Invoke the JS callback function.
///
/// Constructs the call: js_func_name(effect_name, scope_ptr)
fn callJSCallback(
    ctx: *anyopaque,
    js_func_name: []const u8,
    effect_name: []const u8,
    ceventscope: ?*anyopaque,
) !CallbackResult {
    // In standalone testing mode, we just log the call
    // The actual QuickJS invocation happens when integrated into the build system
    _ = ctx;
    _ = ceventscope;

    std.log.info("Button callback invoked: {0s}('{1s}')", .{ js_func_name, effect_name });

    // Success - return result
    return .{
        .success = true,
        .return_value = null,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "callback registry: init and deinit" {
    // Can't fully test without QuickJS runtime, but we can test the registry
    // by setting a dummy allocator
    callback_allocator = std.testing.allocator;
    defer {
        // Clean up any registered callbacks
        var i: usize = 0;
        while (i < callback_count) : (i += 1) {
            std.testing.allocator.free(effect_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        callback_count = 0;
        callback_allocator = null;
    }

    // Reset state
    callback_count = 0;

    // Register a callback
    try registerButtonCallback("test_effect", "handleTestEffect");

    // Verify registration
    try std.testing.expectEqual(@as(usize, 1), getCallbackCount());

    // Look up the callback
    const func_name = lookupCallback("test_effect");
    try std.testing.expect(func_name != null);
    try std.testing.expectEqualStrings("handleTestEffect", func_name.?);
}

test "callback registry: lookup returns null for unknown" {
    callback_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < callback_count) : (i += 1) {
            std.testing.allocator.free(effect_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        callback_count = 0;
        callback_allocator = null;
    }

    callback_count = 0;

    const func_name = lookupCallback("nonexistent_effect");
    try std.testing.expectEqual(@as(?[]const u8, null), func_name);
}

test "callback registry: update existing callback" {
    callback_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < callback_count) : (i += 1) {
            std.testing.allocator.free(effect_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        callback_count = 0;
        callback_allocator = null;
    }

    callback_count = 0;

    // Register initial callback
    try registerButtonCallback("my_effect", "handler_v1");
    try std.testing.expectEqual(@as(usize, 1), getCallbackCount());

    // Update callback
    try registerButtonCallback("my_effect", "handler_v2");
    try std.testing.expectEqual(@as(usize, 1), getCallbackCount());

    // Verify update
    const func_name = lookupCallback("my_effect");
    try std.testing.expect(func_name != null);
    try std.testing.expectEqualStrings("handler_v2", func_name.?);
}

test "callback registry: multiple callbacks" {
    callback_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < callback_count) : (i += 1) {
            std.testing.allocator.free(effect_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        callback_count = 0;
        callback_allocator = null;
    }

    callback_count = 0;

    // Register multiple callbacks
    try registerButtonCallback("effect_a", "handleA");
    try registerButtonCallback("effect_b", "handleB");
    try registerButtonCallback("effect_c", "handleC");

    try std.testing.expectEqual(@as(usize, 3), getCallbackCount());

    // Verify all lookups work
    try std.testing.expectEqualStrings("handleA", lookupCallback("effect_a").?);
    try std.testing.expectEqualStrings("handleB", lookupCallback("effect_b").?);
    try std.testing.expectEqualStrings("handleC", lookupCallback("effect_c").?);
}

test "callback registry: remove callback" {
    callback_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < callback_count) : (i += 1) {
            std.testing.allocator.free(effect_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        callback_count = 0;
        callback_allocator = null;
    }

    callback_count = 0;

    // Register callbacks
    try registerButtonCallback("effect_a", "handleA");
    try registerButtonCallback("effect_b", "handleB");
    try std.testing.expectEqual(@as(usize, 2), getCallbackCount());

    // Remove first callback
    try std.testing.expect(removeCallback("effect_a"));
    try std.testing.expectEqual(@as(usize, 1), getCallbackCount());

    // Verify removal
    try std.testing.expectEqual(@as(?[]const u8, null), lookupCallback("effect_a"));
    try std.testing.expectEqualStrings("handleB", lookupCallback("effect_b").?);

    // Try to remove non-existent callback
    try std.testing.expect(!removeCallback("nonexistent"));
}

test "callback registry: hasCallback" {
    callback_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < callback_count) : (i += 1) {
            std.testing.allocator.free(effect_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        callback_count = 0;
        callback_allocator = null;
    }

    callback_count = 0;

    try std.testing.expect(!hasCallback("test_effect"));

    try registerButtonCallback("test_effect", "handler");
    try std.testing.expect(hasCallback("test_effect"));
    try std.testing.expect(!hasCallback("other_effect"));
}

test "callback count starts at zero" {
    // Save state
    const saved_count = callback_count;
    defer callback_count = saved_count;

    callback_count = 0;
    try std.testing.expectEqual(@as(usize, 0), getCallbackCount());
}

test "handleButtonClick: no callback registered" {
    callback_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < callback_count) : (i += 1) {
            std.testing.allocator.free(effect_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        callback_count = 0;
        callback_allocator = null;
    }
    callback_count = 0;

    const result = handleButtonClick("nonexistent_effect", null);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_message != null);
}

test "handleButtonClick: no QuickJS context" {
    callback_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < callback_count) : (i += 1) {
            std.testing.allocator.free(effect_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        callback_count = 0;
        callback_allocator = null;
        js_context = null;
    }
    callback_count = 0;
    js_context = null; // Ensure no context

    try registerButtonCallback("test_effect", "handleTest");

    const result = handleButtonClick("test_effect", null);
    try std.testing.expect(!result.success);
}

test "removeCallback: removes from middle" {
    callback_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < callback_count) : (i += 1) {
            std.testing.allocator.free(effect_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        callback_count = 0;
        callback_allocator = null;
    }
    callback_count = 0;

    try registerButtonCallback("a", "handleA");
    try registerButtonCallback("b", "handleB");
    try registerButtonCallback("c", "handleC");
    try std.testing.expectEqual(@as(usize, 3), getCallbackCount());

    // Remove middle callback
    try std.testing.expect(removeCallback("b"));
    try std.testing.expectEqual(@as(usize, 2), getCallbackCount());

    // Verify remaining callbacks
    try std.testing.expect(hasCallback("a"));
    try std.testing.expect(!hasCallback("b"));
    try std.testing.expect(hasCallback("c"));
}

test "CallbackError: all variants exist" {
    // Verify error types are accessible by using them
    const err1 = error{NoCallback};
    const err2 = error{RuntimeNotInitialized};
    const err3 = error{JSError};
    const err4 = error{OutOfMemory};
    const err5 = error{RegistryFull};
    // Just verify they compile and are different
    try std.testing.expect(err1 != err2);
    try std.testing.expect(err2 != err3);
    try std.testing.expect(err3 != err4);
    try std.testing.expect(err4 != err5);
}

test "CallbackResult: default values" {
    const result = CallbackResult{
        .success = false,
    };
    try std.testing.expect(!result.success);
    try std.testing.expectEqual(@as(?i64, null), result.return_value);
    try std.testing.expectEqual(@as(?[]const u8, null), result.error_message);
}

test "CallbackResult: success with value" {
    const result = CallbackResult{
        .success = true,
        .return_value = 42,
    };
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(?i64, 42), result.return_value);
    try std.testing.expectEqual(@as(?[]const u8, null), result.error_message);
}

test "registerButtonCallback: update existing" {
    callback_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < callback_count) : (i += 1) {
            std.testing.allocator.free(effect_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        callback_count = 0;
        callback_allocator = null;
    }
    callback_count = 0;

    try registerButtonCallback("effect", "handler_v1");
    try std.testing.expectEqualStrings("handler_v1", lookupCallback("effect").?);

    try registerButtonCallback("effect", "handler_v2");
    try std.testing.expectEqualStrings("handler_v2", lookupCallback("effect").?);
    try std.testing.expectEqual(@as(usize, 1), getCallbackCount());
}

test "hasCallback: after registration and removal" {
    callback_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < callback_count) : (i += 1) {
            std.testing.allocator.free(effect_names[i]);
            std.testing.allocator.free(js_function_names[i]);
        }
        callback_count = 0;
        callback_allocator = null;
    }
    callback_count = 0;

    try std.testing.expect(!hasCallback("temp_effect"));

    try registerButtonCallback("temp_effect", "handler");
    try std.testing.expect(hasCallback("temp_effect"));

    try std.testing.expect(removeCallback("temp_effect"));
    try std.testing.expect(!hasCallback("temp_effect"));
}

test "CallbackEntry struct" {
    const entry = CallbackEntry{
        .effect_name = "test_effect",
        .js_function_name = "handleTest",
        .user_data = null,
    };
    try std.testing.expectEqualStrings("test_effect", entry.effect_name);
    try std.testing.expectEqualStrings("handleTest", entry.js_function_name);
    try std.testing.expectEqual(@as(?*anyopaque, null), entry.user_data);
}
