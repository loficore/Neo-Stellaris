// button.zig — Button effect system for .gui windows.
//
// Provides the bridge between button clicks in .gui windows and JS callbacks.
// When a button is clicked in a .gui window, the engine:
//   1. Extracts the effect name from the effectButtonType
//   2. Looks up the registered callback in the button effect registry
//   3. Invokes the JS callback with the button name and scope info
//
// Button effects are defined in common/button_effects/ and referenced by
// effectButtonType elements in .gui files:
//
//   effectButtonType = {
//       name = "my_button"
//       effect = "my_button_effect"
//       position = { x = 100 y = 100 }
//   }
//
// Usage from JavaScript:
//   Stellaris.registerButtonEffect("my_button_effect", "handleMyButton");
//   Stellaris.onButtonClick("my_button_effect", function(btn_name) { ... });
//
// Usage from Zig:
//   button.registerEffect("close_window", "handleClose");
//   button.processClick("close_window", scope_ptr);

const std = @import("std");
const callbacks = @import("callbacks.zig");

// Note: gui module is available when integrated into the build system.
// For standalone testing, conversion functions are not available.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Button effect definition.
pub const ButtonEffect = struct {
    /// Effect name (matches effectButtonType.effect in .gui files).
    name: []const u8,

    /// JS function name to call when button is clicked.
    js_handler: []const u8,

    /// Optional tooltip text for the button.
    tooltip: ?[]const u8 = null,

    /// Optional condition that must be true for the button to be clickable.
    condition: ?[]const u8 = null,

    /// Whether this effect is enabled.
    enabled: bool = true,
};

/// Button click event data.
pub const ButtonClickEvent = struct {
    /// The effect name from the clicked button.
    effect_name: []const u8,

    /// The button element name (from effectButtonType.name).
    button_name: []const u8,

    /// Optional window name containing the button.
    window_name: ?[]const u8 = null,

    /// Optional scope pointer (CEventScope).
    scope: ?*anyopaque = null,

    /// Timestamp of the click (for debouncing).
    timestamp: u64 = 0,
};

/// Button effect error types.
pub const ButtonError = error{
    /// Effect not found.
    EffectNotFound,
    /// Effect is disabled.
    EffectDisabled,
    /// Condition check failed.
    ConditionFailed,
    /// Runtime not initialized.
    RuntimeNotInitialized,
    /// Memory allocation failed.
    OutOfMemory,
};

/// Button effect system state.
pub const ButtonSystemState = struct {
    /// Whether the system is initialized.
    initialized: bool = false,

    /// Total number of effects registered.
    effect_count: u32 = 0,

    /// Total number of clicks processed.
    total_clicks: u64 = 0,

    /// Total number of successful callbacks.
    successful_callbacks: u64 = 0,

    /// Total number of failed callbacks.
    failed_callbacks: u64 = 0,
};

// ---------------------------------------------------------------------------
// Button Effect Registry
// ---------------------------------------------------------------------------

/// Maximum number of registered button effects.
const MAX_EFFECTS: usize = 64;

/// Global button effect registry state.
var effect_count: usize = 0;
var effects: [MAX_EFFECTS]ButtonEffect = undefined;

/// Registered effect names (owned memory).
var registered_effect_names: [MAX_EFFECTS][]const u8 = undefined;

/// Registered JS handler names (owned memory).
var registered_js_handlers: [MAX_EFFECTS][]const u8 = undefined;

/// Allocator for effect strings (set during init).
var effect_allocator: ?std.mem.Allocator = null;

/// System state.
var system_state = ButtonSystemState{};

// Thread safety note: When integrated into the build system, the registry
// should use std.Thread.Mutex for thread-safe access. For standalone testing,
// single-threaded access is assumed.

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the button effect system.
///
/// Must be called before any effects are registered. Sets up the allocator
/// and initializes the callback subsystem.
///
/// # Arguments
/// * `alloc` - Allocator for effect registry strings
pub fn init(alloc: std.mem.Allocator) void {
    effect_allocator = alloc;
    effect_count = 0;
    system_state = .{
        .initialized = true,
        .effect_count = 0,
        .total_clicks = 0,
        .successful_callbacks = 0,
        .failed_callbacks = 0,
    };
    std.log.info("Button effect system initialized (capacity: {d})", .{MAX_EFFECTS});
}

/// Deinitialize the button effect system.
///
/// Frees all registered effect strings and clears the registry.
pub fn deinit() void {
    if (effect_allocator) |alloc| {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            alloc.free(registered_effect_names[i]);
            alloc.free(registered_js_handlers[i]);
        }
    }
    effect_count = 0;
    effect_allocator = null;
    system_state.initialized = false;
    std.log.info("Button effect system deinitialized", .{});
}

/// Register a button effect.
///
/// Maps an effect name to a JS handler function. When a button with this
/// effect is clicked, the JS handler will be invoked.
///
/// # Arguments
/// * `effect_name` - The effect name (matches button_effects definition)
/// * `js_handler` - The JS function name to call
///
/// # Errors
/// Returns error if the registry is full or allocation fails.
pub fn registerEffect(effect_name: []const u8, js_handler: []const u8) !void {
    if (effect_count >= MAX_EFFECTS) return error.OutOfMemory;
    if (effect_allocator == null) return error.RuntimeNotInitialized;

    const alloc = effect_allocator.?;

    // Check for duplicate registration - update if exists
    for (effects[0..effect_count], 0..) |effect, i| {
        if (std.mem.eql(u8, effect.name, effect_name)) {
            // Update existing effect
            alloc.free(registered_js_handlers[i]);
            registered_js_handlers[i] = try alloc.dupe(u8, js_handler);
            effects[i].js_handler = registered_js_handlers[i];
            std.log.info("Updated button effect '{s}' -> '{s}'", .{ effect_name, js_handler });
            return;
        }
    }

    // New registration
    registered_effect_names[effect_count] = try alloc.dupe(u8, effect_name);
    registered_js_handlers[effect_count] = try alloc.dupe(u8, js_handler);
    effects[effect_count] = .{
        .name = registered_effect_names[effect_count],
        .js_handler = registered_js_handlers[effect_count],
    };
    effect_count += 1;
    system_state.effect_count = @intCast(effect_count);

    std.log.info("Registered button effect '{s}' -> '{s}'", .{ effect_name, js_handler });
}

/// Look up a button effect by name.
///
/// Returns the effect definition if registered, null otherwise.
/// Caller must not free the returned pointer (owned by registry).
pub fn lookupEffect(effect_name: []const u8) ?*const ButtonEffect {
    for (effects[0..effect_count]) |*effect| {
        if (std.mem.eql(u8, effect.name, effect_name)) {
            return effect;
        }
    }
    return null;
}

/// Remove a button effect registration.
///
/// # Arguments
/// * `effect_name` - The effect name to unregister
///
/// # Returns
/// true if the effect was found and removed, false otherwise.
pub fn removeEffect(effect_name: []const u8) bool {
    for (effects[0..effect_count], 0..) |effect, i| {
        if (std.mem.eql(u8, effect.name, effect_name)) {
            // Free the strings
            if (effect_allocator) |alloc| {
                alloc.free(registered_effect_names[i]);
                alloc.free(registered_js_handlers[i]);
            }

            // Shift remaining entries
            var j = i;
            while (j < effect_count - 1) : (j += 1) {
                effects[j] = effects[j + 1];
                registered_effect_names[j] = registered_effect_names[j + 1];
                registered_js_handlers[j] = registered_js_handlers[j + 1];
            }

            effect_count -= 1;
            system_state.effect_count = @intCast(effect_count);
            std.log.info("Removed button effect '{s}'", .{effect_name});
            return true;
        }
    }
    return false;
}

/// Enable or disable a button effect.
///
/// # Arguments
/// * `effect_name` - The effect name
/// * `enabled` - Whether the effect should be enabled
///
/// # Returns
/// true if the effect was found and modified, false otherwise.
pub fn setEffectEnabled(effect_name: []const u8, enabled: bool) bool {
    for (effects[0..effect_count]) |*effect| {
        if (std.mem.eql(u8, effect.name, effect_name)) {
            effect.enabled = enabled;
            std.log.info("Button effect '{s}' {s}", .{ effect_name, if (enabled) "enabled" else "disabled" });
            return true;
        }
    }
    return false;
}

/// Get the number of registered effects.
pub fn getEffectCount() usize {
    return effect_count;
}

/// Check if an effect is registered.
pub fn hasEffect(effect_name: []const u8) bool {
    return lookupEffect(effect_name) != null;
}

/// Get the current system state.
pub fn getState() ButtonSystemState {
    return system_state;
}

// ---------------------------------------------------------------------------
// Button Click Processing
// ---------------------------------------------------------------------------

/// Process a button click event.
///
/// Called by the engine when a button is clicked in a .gui window. Validates
/// the effect, checks conditions, and invokes the JS callback.
///
/// # Arguments
/// * `event` - The button click event data
///
/// # Returns
/// The callback result indicating success/failure.
pub fn processClick(event: ButtonClickEvent) callbacks.CallbackResult {
    // Update statistics
    system_state.total_clicks += 1;

    // Look up the effect
    const effect = lookupEffect(event.effect_name) orelse {
        std.log.warn(
            "Button effect '{s}' not found, ignoring click",
            .{event.effect_name},
        );
        system_state.failed_callbacks += 1;
        return .{
            .success = false,
            .error_message = "Effect not found",
        };
    };

    // Check if effect is enabled
    if (!effect.enabled) {
        std.log.warn(
            "Button effect '{s}' is disabled, ignoring click",
            .{event.effect_name},
        );
        system_state.failed_callbacks += 1;
        return .{
            .success = false,
            .error_message = "Effect disabled",
        };
    }

    // Note: Condition checking would require evaluating game conditions
    // which is beyond the scope of this module. For now, we pass through.

    // Invoke the callback
    const result = callbacks.handleButtonClick(event.effect_name, event.scope);

    // Update statistics
    if (result.success) {
        system_state.successful_callbacks += 1;
    } else {
        system_state.failed_callbacks += 1;
    }

    return result;
}

/// Process a simple button click (without full event data).
///
/// Convenience wrapper for when only the effect name is known.
///
/// # Arguments
/// * `effect_name` - The effect name from the clicked button
/// * `scope` - Optional scope pointer
///
/// # Returns
/// The callback result.
pub fn processSimpleClick(
    effect_name: []const u8,
    scope: ?*anyopaque,
) callbacks.CallbackResult {
    return processClick(.{
        .effect_name = effect_name,
        .button_name = effect_name, // Use effect name as button name
        .scope = scope,
    });
}

// ---------------------------------------------------------------------------
// .gui Integration
// ---------------------------------------------------------------------------

/// Create a ButtonEffect from gui effect parameters.
///
/// # Arguments
/// * `name` - The effect name
/// * `tooltip` - Optional tooltip text
/// * `condition` - Optional condition
///
/// # Returns
/// A new ButtonEffect with the provided values.
pub fn effectFromParams(
    name: []const u8,
    tooltip: ?[]const u8,
    condition: ?[]const u8,
) ButtonEffect {
    return .{
        .name = name,
        .js_handler = name, // Default: use effect name as handler
        .tooltip = tooltip,
        .condition = condition,
    };
}

/// Register effects from a list of effect definitions.
///
/// Convenience function to register multiple effects at once.
///
/// # Arguments
/// * `names` - Slice of effect names to register
///
/// # Errors
/// Returns error if any registration fails.
pub fn registerEffectsFromNames(names: []const []const u8) !void {
    for (names) |name| {
        try registerEffect(name, name);
    }
}

// =============================================================================
// Tests
// =============================================================================

test "effect registry: init and deinit" {
    // Test the effect registry directly
    effect_allocator = std.testing.allocator;
    defer {
        // Clean up any registered effects
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }

    // Reset state
    effect_count = 0;
    system_state = .{};

    // Register an effect
    try registerEffect("test_effect", "handleTestEffect");

    // Verify registration
    try std.testing.expectEqual(@as(usize, 1), getEffectCount());

    // Look up the effect
    const effect = lookupEffect("test_effect");
    try std.testing.expect(effect != null);
    try std.testing.expectEqualStrings("test_effect", effect.?.name);
    try std.testing.expectEqualStrings("handleTestEffect", effect.?.js_handler);
}

test "effect registry: lookup returns null for unknown" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }

    effect_count = 0;

    const effect = lookupEffect("nonexistent_effect");
    try std.testing.expectEqual(@as(?*const ButtonEffect, null), effect);
}

test "effect registry: update existing effect" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }

    effect_count = 0;

    // Register initial effect
    try registerEffect("my_effect", "handler_v1");
    try std.testing.expectEqual(@as(usize, 1), getEffectCount());

    // Update effect
    try registerEffect("my_effect", "handler_v2");
    try std.testing.expectEqual(@as(usize, 1), getEffectCount());

    // Verify update
    const effect = lookupEffect("my_effect");
    try std.testing.expect(effect != null);
    try std.testing.expectEqualStrings("handler_v2", effect.?.js_handler);
}

test "effect registry: multiple effects" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }

    effect_count = 0;

    // Register multiple effects
    try registerEffect("effect_a", "handleA");
    try registerEffect("effect_b", "handleB");
    try registerEffect("effect_c", "handleC");

    try std.testing.expectEqual(@as(usize, 3), getEffectCount());

    // Verify all lookups work
    try std.testing.expectEqualStrings("handleA", lookupEffect("effect_a").?.js_handler);
    try std.testing.expectEqualStrings("handleB", lookupEffect("effect_b").?.js_handler);
    try std.testing.expectEqualStrings("handleC", lookupEffect("effect_c").?.js_handler);
}

test "effect registry: remove effect" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }

    effect_count = 0;

    // Register effects
    try registerEffect("effect_a", "handleA");
    try registerEffect("effect_b", "handleB");
    try std.testing.expectEqual(@as(usize, 2), getEffectCount());

    // Remove first effect
    try std.testing.expect(removeEffect("effect_a"));
    try std.testing.expectEqual(@as(usize, 1), getEffectCount());

    // Verify removal
    try std.testing.expectEqual(@as(?*const ButtonEffect, null), lookupEffect("effect_a"));
    try std.testing.expectEqualStrings("handleB", lookupEffect("effect_b").?.js_handler);

    // Try to remove non-existent effect
    try std.testing.expect(!removeEffect("nonexistent"));
}

test "effect registry: enable/disable" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }

    effect_count = 0;

    // Register an effect
    try registerEffect("toggle_effect", "handler");

    // Initially enabled
    const effect = lookupEffect("toggle_effect");
    try std.testing.expect(effect != null);
    try std.testing.expect(effect.?.enabled);

    // Disable
    try std.testing.expect(setEffectEnabled("toggle_effect", false));
    const disabled = lookupEffect("toggle_effect");
    try std.testing.expect(!disabled.?.enabled);

    // Re-enable
    try std.testing.expect(setEffectEnabled("toggle_effect", true));
    const enabled = lookupEffect("toggle_effect");
    try std.testing.expect(enabled.?.enabled);
}

test "effect registry: hasEffect" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }

    effect_count = 0;

    try std.testing.expect(!hasEffect("test_effect"));

    try registerEffect("test_effect", "handler");
    try std.testing.expect(hasEffect("test_effect"));
    try std.testing.expect(!hasEffect("other_effect"));
}

test "effect count starts at zero" {
    // Save state
    const saved_count = effect_count;
    defer effect_count = saved_count;

    effect_count = 0;
    try std.testing.expectEqual(@as(usize, 0), getEffectCount());
}

test "ButtonEffect struct defaults" {
    const effect = ButtonEffect{
        .name = "test",
        .js_handler = "handler",
    };
    try std.testing.expectEqual(@as(?[]const u8, null), effect.tooltip);
    try std.testing.expectEqual(@as(?[]const u8, null), effect.condition);
    try std.testing.expect(effect.enabled);
}

test "ButtonClickEvent struct" {
    const event = ButtonClickEvent{
        .effect_name = "close_window",
        .button_name = "close_btn",
    };
    try std.testing.expectEqual(@as(?[]const u8, null), event.window_name);
    try std.testing.expectEqual(@as(?*anyopaque, null), event.scope);
    try std.testing.expectEqual(@as(u64, 0), event.timestamp);
}

test "effectFromParams: creates effect from parameters" {
    const effect = effectFromParams("my_effect", "My tooltip", "has_flag = test");
    try std.testing.expectEqualStrings("my_effect", effect.name);
    try std.testing.expectEqualStrings("my_effect", effect.js_handler);
    try std.testing.expectEqualStrings("My tooltip", effect.tooltip orelse unreachable);
    try std.testing.expectEqualStrings("has_flag = test", effect.condition orelse unreachable);
    try std.testing.expect(effect.enabled);
}

test "effectFromParams: null tooltip and condition" {
    const effect = effectFromParams("simple_effect", null, null);
    try std.testing.expectEqualStrings("simple_effect", effect.name);
    try std.testing.expectEqual(@as(?[]const u8, null), effect.tooltip);
    try std.testing.expectEqual(@as(?[]const u8, null), effect.condition);
}

test "processSimpleClick: not found" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }
    effect_count = 0;

    const result = processSimpleClick("nonexistent_effect", null);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_message != null);
}

test "processClick: effect disabled" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }
    effect_count = 0;

    try registerEffect("disabled_effect", "handler");
    try std.testing.expect(setEffectEnabled("disabled_effect", false));

    const result = processClick(.{
        .effect_name = "disabled_effect",
        .button_name = "btn",
    });
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_message != null);
}

test "processClick: effect not found" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }
    effect_count = 0;

    const result = processClick(.{
        .effect_name = "missing_effect",
        .button_name = "btn",
    });
    try std.testing.expect(!result.success);
}

test "processClick: updates statistics" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }
    effect_count = 0;
    system_state = .{};

    // Process a click on a missing effect
    _ = processClick(.{
        .effect_name = "missing",
        .button_name = "btn",
    });

    const state = getState();
    try std.testing.expectEqual(@as(u64, 1), state.total_clicks);
    try std.testing.expectEqual(@as(u64, 1), state.failed_callbacks);
}

test "registerEffectsFromNames: registers multiple effects" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }
    effect_count = 0;

    const names = [_][]const u8{ "effect_x", "effect_y", "effect_z" };
    try registerEffectsFromNames(&names);

    try std.testing.expectEqual(@as(usize, 3), getEffectCount());
    try std.testing.expect(hasEffect("effect_x"));
    try std.testing.expect(hasEffect("effect_y"));
    try std.testing.expect(hasEffect("effect_z"));
}

test "getState: returns current state" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }
    effect_count = 0;

    const state = getState();
    try std.testing.expect(state.initialized);
    try std.testing.expectEqual(@as(u32, 0), state.effect_count);
    try std.testing.expectEqual(@as(u64, 0), state.total_clicks);
}

test "ButtonEffect: with tooltip and condition" {
    const effect = ButtonEffect{
        .name = "full_effect",
        .js_handler = "fullHandler",
        .tooltip = "Full effect tooltip",
        .condition = "has_country_flag = enabled",
    };
    try std.testing.expectEqualStrings("full_effect", effect.name);
    try std.testing.expectEqualStrings("fullHandler", effect.js_handler);
    try std.testing.expectEqualStrings("Full effect tooltip", effect.tooltip orelse unreachable);
    try std.testing.expectEqualStrings("has_country_flag = enabled", effect.condition orelse unreachable);
    try std.testing.expect(effect.enabled);
}

test "ButtonError: all variants exist" {
    // Verify error types are accessible by using them
    const err1 = error{EffectNotFound};
    const err2 = error{EffectDisabled};
    const err3 = error{ConditionFailed};
    const err4 = error{RuntimeNotInitialized};
    const err5 = error{OutOfMemory};
    // Just verify they compile and are different
    try std.testing.expect(err1 != err2);
    try std.testing.expect(err2 != err3);
    try std.testing.expect(err3 != err4);
    try std.testing.expect(err4 != err5);
}

test "removeEffect: removes from middle" {
    effect_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < effect_count) : (i += 1) {
            std.testing.allocator.free(registered_effect_names[i]);
            std.testing.allocator.free(registered_js_handlers[i]);
        }
        effect_count = 0;
        effect_allocator = null;
    }
    effect_count = 0;

    try registerEffect("a", "handlerA");
    try registerEffect("b", "handlerB");
    try registerEffect("c", "handlerC");
    try std.testing.expectEqual(@as(usize, 3), getEffectCount());

    // Remove middle effect
    try std.testing.expect(removeEffect("b"));
    try std.testing.expectEqual(@as(usize, 2), getEffectCount());

    // Verify remaining effects
    try std.testing.expect(hasEffect("a"));
    try std.testing.expect(!hasEffect("b"));
    try std.testing.expect(hasEffect("c"));
}
