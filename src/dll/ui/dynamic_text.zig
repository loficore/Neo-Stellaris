// dynamic_text.zig — Scripted localisation system for .gui dynamic text.
//
// Provides a registry for mapping scripted_loc names to text providers.
// When the engine renders a .gui element with $SCRIPTED_LOC$ in its text,
// it calls into this system to resolve the current text based on game state.
//
// The system supports two text provider types:
//   1. Static scripted_loc definitions (Clausescript-style)
//   2. JS-based dynamic text generation (via QuickJS bridge)
//
// Scripted Loc Pattern (common/scripted_loc/custom_text.txt):
//   defined_text = {
//       name = get_custom_text
//       text = {
//           trigger = { has_country_flag = flag1 }
//           localisation_key = "TEXT_FLAG1"
//       }
//       text = {
//           trigger = { always = yes }
//           localisation_key = "TEXT_DEFAULT"
//       }
//   }
//
// .gui Integration:
//   effectButtonType = {
//       name = "my_button"
//       buttonText = "$CUSTOM_TEXT$"
//       effect = "my_effect"
//   }
//
// Usage from JavaScript:
//   Stellaris.registerTextProvider("get_resource_count", "getResourceCount");
//   Stellaris.registerTextProvider("get_status_text", "getStatusText");
//
// Usage from Zig:
//   dynamic_text.registerProvider("get_custom_text", .{ .js_function = "getCustomText" });
//   const text = dynamic_text.resolveText("get_custom_text", scope_ptr);

const std = @import("std");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Text provider type — how text is generated.
pub const ProviderType = enum {
    /// Static localisation key lookup (maps to engine's localisation system).
    static_loc,
    /// JavaScript function that returns text dynamically.
    js_function,
    /// Zig function pointer that returns text (for native code).
    zig_function,
};

/// A text provider definition.
pub const TextProvider = struct {
    /// Provider name (matches scripted_loc name, e.g., "get_custom_text").
    name: []const u8,

    /// Type of provider.
    provider_type: ProviderType,

    /// For static_loc: the localisation key to resolve.
    /// For js_function: the JS function name to call.
    /// For zig_function: unused (stored in function_pointer).
    value: []const u8,

    /// For zig_function: the function pointer.
    function_pointer: ?*const fn (*anyopaque) ?[]const u8 = null,

    /// Whether this provider is enabled.
    enabled: bool = true,

    /// Priority for text resolution (higher wins in conflicts).
    priority: i32 = 0,

    /// Optional fallback provider name.
    fallback: ?[]const u8 = null,
};

/// Text resolution context — information about the current scope.
pub const TextContext = struct {
    /// The CEventScope pointer (opaque to JS).
    scope: ?*anyopaque = null,

    /// The window name containing the text element.
    window_name: ?[]const u8 = null,

    /// The element name requesting text.
    element_name: ?[]const u8 = null,

    /// Cached text result (set by resolver).
    cached_text: ?[]const u8 = null,
};

/// Text resolution result.
pub const TextResult = struct {
    /// The resolved text string.
    text: []const u8,

    /// The provider that produced this text.
    provider_name: []const u8,

    /// Whether the text was resolved successfully.
    success: bool = true,

    /// Error message if resolution failed.
    error_message: ?[]const u8 = null,
};

/// Text provider error types.
pub const TextError = error{
    /// Provider not found.
    ProviderNotFound,
    /// Provider is disabled.
    ProviderDisabled,
    /// Text resolution failed.
    ResolutionFailed,
    /// Runtime not initialized.
    RuntimeNotInitialized,
    /// Memory allocation failed.
    OutOfMemory,
    /// Registry is full.
    RegistryFull,
};

/// System statistics.
pub const TextSystemStats = struct {
    /// Whether the system is initialized.
    initialized: bool = false,

    /// Total providers registered.
    provider_count: u32 = 0,

    /// Total text resolutions attempted.
    total_resolutions: u64 = 0,

    /// Total successful resolutions.
    successful_resolutions: u64 = 0,

    /// Total failed resolutions.
    failed_resolutions: u64 = 0,

    /// Total cache hits (same text returned without re-evaluation).
    cache_hits: u64 = 0,
};

// ---------------------------------------------------------------------------
// Text Provider Registry
// ---------------------------------------------------------------------------

/// Maximum number of registered text providers.
const MAX_PROVIDERS: usize = 128;

/// Global text provider registry state.
var provider_count: usize = 0;
var providers: [MAX_PROVIDERS]TextProvider = undefined;

/// Registered provider names (owned memory).
var provider_names: [MAX_PROVIDERS][]const u8 = undefined;

/// Registered provider values (owned memory).
var provider_values: [MAX_PROVIDERS][]const u8 = undefined;

/// Registered fallback names (owned memory).
var provider_fallbacks: [MAX_PROVIDERS]?[]const u8 = undefined;

/// Allocator for provider strings (set during init).
var provider_allocator: ?std.mem.Allocator = null;

/// System statistics.
var system_stats = TextSystemStats{};

// QuickJS runtime reference (for JS function invocation).
var js_context: ?*anyopaque = null;

// Text cache: maps element name -> last resolved text.
const CACHE_SIZE: usize = 64;
var cache_count: usize = 0;
var cache_keys: [CACHE_SIZE][]const u8 = undefined;
var cache_values: [CACHE_SIZE][]const u8 = undefined;

// ---------------------------------------------------------------------------
// Public API — Initialization
// ---------------------------------------------------------------------------

/// Initialize the dynamic text system.
///
/// Must be called before any providers are registered. Sets up the allocator
/// and initializes the text resolution subsystem.
///
/// # Arguments
/// * `alloc` - Allocator for provider registry strings
/// * `ctx` - Optional QuickJS context for JS-based text providers
pub fn init(alloc: std.mem.Allocator, ctx: ?*anyopaque) void {
    provider_allocator = alloc;
    provider_count = 0;
    cache_count = 0;
    js_context = ctx;
    system_stats = .{
        .initialized = true,
        .provider_count = 0,
        .total_resolutions = 0,
        .successful_resolutions = 0,
        .failed_resolutions = 0,
        .cache_hits = 0,
    };
    std.log.info("Dynamic text system initialized (capacity: {d})", .{MAX_PROVIDERS});
}

/// Deinitialize the dynamic text system.
///
/// Frees all registered provider strings and clears the registry.
pub fn deinit() void {
    if (provider_allocator) |alloc| {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            alloc.free(provider_names[i]);
            alloc.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                alloc.free(provider_fallbacks[i].?);
            }
        }
        // Free cache
        i = 0;
        while (i < cache_count) : (i += 1) {
            alloc.free(cache_keys[i]);
            alloc.free(cache_values[i]);
        }
    }
    provider_count = 0;
    cache_count = 0;
    provider_allocator = null;
    js_context = null;
    system_stats.initialized = false;
    std.log.info("Dynamic text system deinitialized", .{});
}

// ---------------------------------------------------------------------------
// Public API — Provider Registration
// ---------------------------------------------------------------------------

/// Register a text provider.
///
/// Maps a provider name to a text generation mechanism. When the engine
/// encounters `$NAME$` in a .gui element, it calls this system to resolve it.
///
/// # Arguments
/// * `name` - The provider name (e.g., "get_custom_text")
/// * `provider` - The text provider definition
///
/// # Errors
/// Returns error if the registry is full or allocation fails.
pub fn registerProvider(name: []const u8, provider: TextProvider) !void {
    if (provider_count >= MAX_PROVIDERS) return error.RegistryFull;
    if (provider_allocator == null) return error.RuntimeNotInitialized;

    const alloc = provider_allocator.?;

    // Check for duplicate registration - update if exists
    for (providers[0..provider_count], 0..) |existing, i| {
        if (std.mem.eql(u8, existing.name, name)) {
            // Free old values
            alloc.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                alloc.free(provider_fallbacks[i].?);
            }

            // Update with new values
            provider_values[i] = try alloc.dupe(u8, provider.value);
            providers[i].value = provider_values[i];
            providers[i].provider_type = provider.provider_type;
            providers[i].function_pointer = provider.function_pointer;
            providers[i].enabled = provider.enabled;
            providers[i].priority = provider.priority;

            if (provider.fallback) |fb| {
                provider_fallbacks[i] = try alloc.dupe(u8, fb);
                providers[i].fallback = provider_fallbacks[i];
            } else {
                provider_fallbacks[i] = null;
                providers[i].fallback = null;
            }

            std.log.info("Updated text provider '{s}'", .{name});
            return;
        }
    }

    // New registration
    provider_names[provider_count] = try alloc.dupe(u8, name);
    provider_values[provider_count] = try alloc.dupe(u8, provider.value);
    providers[provider_count] = provider;
    providers[provider_count].name = provider_names[provider_count];
    providers[provider_count].value = provider_values[provider_count];

    if (provider.fallback) |fb| {
        provider_fallbacks[provider_count] = try alloc.dupe(u8, fb);
        providers[provider_count].fallback = provider_fallbacks[provider_count];
    } else {
        provider_fallbacks[provider_count] = null;
    }

    provider_count += 1;
    system_stats.provider_count = @intCast(provider_count);

    std.log.info("Registered text provider '{s}' (type: {s})", .{ name, @tagName(provider.provider_type) });
}

/// Register a JS-based text provider (convenience function).
///
/// # Arguments
/// * `name` - The provider name
/// * `js_function` - The JS function name to call for text generation
///
/// # Errors
/// Returns error if registration fails.
pub fn registerJSProvider(name: []const u8, js_function: []const u8) !void {
    return registerProvider(name, .{
        .name = name,
        .provider_type = .js_function,
        .value = js_function,
    });
}

/// Register a static localisation key provider (convenience function).
///
/// # Arguments
/// * `name` - The provider name
/// * `loc_key` - The localisation key to resolve
///
/// # Errors
/// Returns error if registration fails.
pub fn registerStaticLocProvider(name: []const u8, loc_key: []const u8) !void {
    return registerProvider(name, .{
        .name = name,
        .provider_type = .static_loc,
        .value = loc_key,
    });
}

/// Register a Zig function provider (convenience function).
///
/// # Arguments
/// * `name` - The provider name
/// * `func` - The function pointer to call
///
/// # Errors
/// Returns error if registration fails.
pub fn registerZigProvider(
    name: []const u8,
    func: *const fn (*anyopaque) ?[]const u8,
) !void {
    return registerProvider(name, .{
        .name = name,
        .provider_type = .zig_function,
        .value = "",
        .function_pointer = func,
    });
}

// ---------------------------------------------------------------------------
// Public API — Provider Lookup
// ---------------------------------------------------------------------------

/// Look up a text provider by name.
///
/// Returns the provider definition if registered, null otherwise.
/// Caller must not free the returned pointer (owned by registry).
pub fn lookupProvider(name: []const u8) ?*const TextProvider {
    for (providers[0..provider_count]) |*provider| {
        if (std.mem.eql(u8, provider.name, name)) {
            return provider;
        }
    }
    return null;
}

/// Remove a text provider registration.
///
/// # Arguments
/// * `name` - The provider name to unregister
///
/// # Returns
/// true if the provider was found and removed, false otherwise.
pub fn removeProvider(name: []const u8) bool {
    for (providers[0..provider_count], 0..) |provider, i| {
        if (std.mem.eql(u8, provider.name, name)) {
            if (provider_allocator) |alloc| {
                alloc.free(provider_names[i]);
                alloc.free(provider_values[i]);
                if (provider_fallbacks[i] != null) {
                    alloc.free(provider_fallbacks[i].?);
                }
            }

            // Shift remaining entries
            var j = i;
            while (j < provider_count - 1) : (j += 1) {
                providers[j] = providers[j + 1];
                provider_names[j] = provider_names[j + 1];
                provider_values[j] = provider_values[j + 1];
                provider_fallbacks[j] = provider_fallbacks[j + 1];
            }

            provider_count -= 1;
            system_stats.provider_count = @intCast(provider_count);
            std.log.info("Removed text provider '{s}'", .{name});
            return true;
        }
    }
    return false;
}

/// Enable or disable a text provider.
///
/// # Arguments
/// * `name` - The provider name
/// * `enabled` - Whether the provider should be enabled
///
/// # Returns
/// true if the provider was found and modified, false otherwise.
pub fn setProviderEnabled(name: []const u8, enabled: bool) bool {
    for (providers[0..provider_count]) |*provider| {
        if (std.mem.eql(u8, provider.name, name)) {
            provider.enabled = enabled;
            std.log.info("Text provider '{s}' {s}", .{ name, if (enabled) "enabled" else "disabled" });
            return true;
        }
    }
    return false;
}

/// Get the number of registered providers.
pub fn getProviderCount() usize {
    return provider_count;
}

/// Check if a provider is registered.
pub fn hasProvider(name: []const u8) bool {
    return lookupProvider(name) != null;
}

/// Get the current system statistics.
pub fn getStats() TextSystemStats {
    return system_stats;
}

// ---------------------------------------------------------------------------
// Public API — Text Resolution
// ---------------------------------------------------------------------------

/// Resolve text for a provider name.
///
/// This is the main entry point for text resolution. It looks up the
/// provider, evaluates its conditions (if any), and returns the resolved text.
///
/// # Arguments
/// * `name` - The provider name (from $NAME$ in .gui)
/// * `context` - The resolution context (scope, window, element)
///
/// # Returns
/// TextResult with the resolved text, or error on failure.
pub fn resolveText(name: []const u8, context: *TextContext) TextError!TextResult {
    system_stats.total_resolutions += 1;

    // Check cache first
    if (context.element_name) |elem_name| {
        if (getCachedText(elem_name)) |cached| {
            system_stats.cache_hits += 1;
            return .{
                .text = cached,
                .provider_name = name,
                .success = true,
            };
        }
    }

    // Look up the provider
    const provider = lookupProvider(name) orelse {
        system_stats.failed_resolutions += 1;
        return .{
            .text = "",
            .provider_name = name,
            .success = false,
            .error_message = "Provider not found",
        };
    };

    // Check if provider is enabled
    if (!provider.enabled) {
        system_stats.failed_resolutions += 1;
        return .{
            .text = "",
            .provider_name = name,
            .success = false,
            .error_message = "Provider disabled",
        };
    }

    // Resolve text based on provider type
    const text = switch (provider.provider_type) {
        .static_loc => resolveStaticLoc(provider, context),
        .js_function => resolveJSFunction(provider, context),
        .zig_function => resolveZigFunction(provider, context),
    } catch |err| {
        system_stats.failed_resolutions += 1;

        // Try fallback if available
        if (provider.fallback) |fallback_name| {
            var fallback_ctx = TextContext{
                .scope = context.scope,
                .window_name = context.window_name,
                .element_name = context.element_name,
            };
            return resolveText(fallback_name, &fallback_ctx) catch {
                return .{
                    .text = "",
                    .provider_name = name,
                    .success = false,
                    .error_message = "Resolution failed",
                };
            };
        }

        const err_msg = switch (err) {
            else => "Resolution failed",
        };
        return .{
            .text = "",
            .provider_name = name,
            .success = false,
            .error_message = err_msg,
        };
    };

    // Cache the result
    if (context.element_name) |elem_name| {
        cacheText(elem_name, text);
    }

    system_stats.successful_resolutions += 1;
    return .{
        .text = text,
        .provider_name = name,
        .success = true,
    };
}

/// Resolve text from a $KEY$ reference in .gui text.
///
/// Extracts the key from $KEY$ syntax and resolves it.
///
/// # Arguments
/// * `gui_text` - The .gui text field (e.g., "Status: $STATUS_TEXT$")
/// * `context` - The resolution context
///
/// # Returns
/// The text with $KEY$ references resolved.
pub fn resolveGuiText(gui_text: []const u8, context: *TextContext) ![]const u8 {
    // Simple case: no $ references
    if (std.mem.indexOf(u8, gui_text, "$") == null) {
        return gui_text;
    }

    // Find all $KEY$ references and resolve them
    var result = std.ArrayList(u8).empty;
    var remaining = gui_text;
    const alloc = provider_allocator orelse return error.RuntimeNotInitialized;

    while (std.mem.indexOf(u8, remaining, "$")) |start_idx| {
        // Add text before the $
        if (start_idx > 0) {
            try result.appendSlice(alloc, remaining[0..start_idx]);
        }

        remaining = remaining[start_idx + 1 ..];

        // Find closing $
        if (std.mem.indexOf(u8, remaining, "$")) |end_idx| {
            const key = remaining[0..end_idx];
            remaining = remaining[end_idx + 1 ..];

            // Resolve the key
            var key_ctx = TextContext{
                .scope = context.scope,
                .window_name = context.window_name,
                .element_name = context.element_name,
            };
            const resolved = resolveText(key, &key_ctx) catch {
                // On error, keep the original $KEY$ reference
                try result.appendSlice(alloc, "$");
                try result.appendSlice(alloc, key);
                try result.appendSlice(alloc, "$");
                continue;
            };

            if (resolved.success) {
                try result.appendSlice(alloc, resolved.text);
            } else {
                // Keep original on failure
                try result.appendSlice(alloc, "$");
                try result.appendSlice(alloc, key);
                try result.appendSlice(alloc, "$");
            }
        } else {
            // No closing $, treat as literal
            try result.appendSlice(alloc, "$");
            try result.appendSlice(alloc, remaining);
        }
    }

    // Add any remaining text
    if (remaining.len > 0) {
        try result.appendSlice(alloc, remaining);
    }

    return try result.toOwnedSlice(alloc);
}

// ---------------------------------------------------------------------------
// Public API — Text Cache
// ---------------------------------------------------------------------------

/// Clear the text cache.
pub fn clearCache() void {
    if (provider_allocator) |alloc| {
        var i: usize = 0;
        while (i < cache_count) : (i += 1) {
            alloc.free(cache_keys[i]);
            alloc.free(cache_values[i]);
        }
    }
    cache_count = 0;
    std.log.info("Text cache cleared", .{});
}

/// Get cached text for an element.
fn getCachedText(element_name: []const u8) ?[]const u8 {
    for (cache_keys[0..cache_count], 0..) |key, i| {
        if (std.mem.eql(u8, key, element_name)) {
            return cache_values[i];
        }
    }
    return null;
}

/// Cache resolved text for an element.
fn cacheText(element_name: []const u8, text: []const u8) void {
    if (provider_allocator == null) return;
    const alloc = provider_allocator.?;

    // Check if already cached
    for (cache_keys[0..cache_count], 0..) |key, i| {
        if (std.mem.eql(u8, key, element_name)) {
            // Update existing cache entry
            alloc.free(cache_values[i]);
            cache_values[i] = alloc.dupe(u8, text) catch return;
            return;
        }
    }

    // Add new cache entry
    if (cache_count >= CACHE_SIZE) {
        // Evict oldest entry
        alloc.free(cache_keys[0]);
        alloc.free(cache_values[0]);
        var i: usize = 0;
        while (i < cache_count - 1) : (i += 1) {
            cache_keys[i] = cache_keys[i + 1];
            cache_values[i] = cache_values[i + 1];
        }
        cache_count -= 1;
    }

    cache_keys[cache_count] = alloc.dupe(u8, element_name) catch return;
    cache_values[cache_count] = alloc.dupe(u8, text) catch {
        alloc.free(cache_keys[cache_count]);
        return;
    };
    cache_count += 1;
}

// ---------------------------------------------------------------------------
// Internal Resolution Functions
// ---------------------------------------------------------------------------

/// Resolve text from a static localisation key.
fn resolveStaticLoc(
    provider: *const TextProvider,
    context: *TextContext,
) ![]const u8 {
    _ = context;

    // In production, this would call the engine's localisation system:
    //   localisation.getText(provider.value)
    // For now, return the key itself as a placeholder
    std.log.info("Static loc resolution: {s} -> {s}", .{ provider.name, provider.value });
    return provider.value;
}

/// Resolve text by calling a JavaScript function.
fn resolveJSFunction(
    provider: *const TextProvider,
    context: *TextContext,
) ![]const u8 {
    _ = context;

    // In production, this would call via QuickJS:
    //   JS_Call(js_context, js_func_name, scope_arg)
    // For now, return the function name as a placeholder
    std.log.info("JS function resolution: {s} -> {s}()", .{ provider.name, provider.value });
    return provider.value;
}

/// Resolve text by calling a Zig function pointer.
fn resolveZigFunction(
    provider: *const TextProvider,
    context: *TextContext,
) ![]const u8 {
    if (context.scope == null) {
        return error.ResolutionFailed;
    }

    const func = provider.function_pointer orelse {
        return error.ResolutionFailed;
    };

    return func(context.scope.?) orelse "";
}

// =============================================================================
// Tests
// =============================================================================

test "provider registry: init and deinit" {
    // Set up test allocator
    provider_allocator = std.testing.allocator;
    defer {
        // Clean up any registered providers
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        i = 0;
        while (i < cache_count) : (i += 1) {
            std.testing.allocator.free(cache_keys[i]);
            std.testing.allocator.free(cache_values[i]);
        }
        provider_count = 0;
        cache_count = 0;
        provider_allocator = null;
    }

    // Reset state
    provider_count = 0;
    cache_count = 0;
    system_stats = .{};

    // Register a provider
    try registerProvider("test_provider", .{
        .name = "test_provider",
        .provider_type = .static_loc,
        .value = "TEST_KEY",
    });

    // Verify registration
    try std.testing.expectEqual(@as(usize, 1), getProviderCount());

    // Look up the provider
    const provider = lookupProvider("test_provider");
    try std.testing.expect(provider != null);
    try std.testing.expectEqualStrings("test_provider", provider.?.name);
    try std.testing.expectEqual(ProviderType.static_loc, provider.?.provider_type);
    try std.testing.expectEqualStrings("TEST_KEY", provider.?.value);
}

test "provider registry: lookup returns null for unknown" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;

    const provider = lookupProvider("nonexistent_provider");
    try std.testing.expectEqual(@as(?*const TextProvider, null), provider);
}

test "provider registry: update existing provider" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;

    // Register initial provider
    try registerProvider("my_provider", .{
        .name = "my_provider",
        .provider_type = .static_loc,
        .value = "OLD_KEY",
    });
    try std.testing.expectEqual(@as(usize, 1), getProviderCount());

    // Update provider
    try registerProvider("my_provider", .{
        .name = "my_provider",
        .provider_type = .static_loc,
        .value = "NEW_KEY",
    });
    try std.testing.expectEqual(@as(usize, 1), getProviderCount());

    // Verify update
    const provider = lookupProvider("my_provider");
    try std.testing.expect(provider != null);
    try std.testing.expectEqualStrings("NEW_KEY", provider.?.value);
}

test "provider registry: multiple providers" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;

    // Register multiple providers
    try registerProvider("provider_a", .{
        .name = "provider_a",
        .provider_type = .static_loc,
        .value = "KEY_A",
    });
    try registerProvider("provider_b", .{
        .name = "provider_b",
        .provider_type = .js_function,
        .value = "getB",
    });
    try registerProvider("provider_c", .{
        .name = "provider_c",
        .provider_type = .static_loc,
        .value = "KEY_C",
    });

    try std.testing.expectEqual(@as(usize, 3), getProviderCount());

    // Verify all lookups work
    try std.testing.expectEqualStrings("KEY_A", lookupProvider("provider_a").?.value);
    try std.testing.expectEqualStrings("getB", lookupProvider("provider_b").?.value);
    try std.testing.expectEqualStrings("KEY_C", lookupProvider("provider_c").?.value);
}

test "provider registry: remove provider" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;

    // Register providers
    try registerProvider("provider_a", .{
        .name = "provider_a",
        .provider_type = .static_loc,
        .value = "KEY_A",
    });
    try registerProvider("provider_b", .{
        .name = "provider_b",
        .provider_type = .static_loc,
        .value = "KEY_B",
    });
    try std.testing.expectEqual(@as(usize, 2), getProviderCount());

    // Remove first provider
    try std.testing.expect(removeProvider("provider_a"));
    try std.testing.expectEqual(@as(usize, 1), getProviderCount());

    // Verify removal
    try std.testing.expectEqual(@as(?*const TextProvider, null), lookupProvider("provider_a"));
    try std.testing.expectEqualStrings("KEY_B", lookupProvider("provider_b").?.value);

    // Try to remove non-existent provider
    try std.testing.expect(!removeProvider("nonexistent"));
}

test "provider registry: enable/disable" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;

    // Register a provider
    try registerProvider("toggle_provider", .{
        .name = "toggle_provider",
        .provider_type = .static_loc,
        .value = "KEY",
    });

    // Initially enabled
    const provider = lookupProvider("toggle_provider");
    try std.testing.expect(provider != null);
    try std.testing.expect(provider.?.enabled);

    // Disable
    try std.testing.expect(setProviderEnabled("toggle_provider", false));
    const disabled = lookupProvider("toggle_provider");
    try std.testing.expect(!disabled.?.enabled);

    // Re-enable
    try std.testing.expect(setProviderEnabled("toggle_provider", true));
    const enabled = lookupProvider("toggle_provider");
    try std.testing.expect(enabled.?.enabled);
}

test "provider registry: hasProvider" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;

    try std.testing.expect(!hasProvider("test_provider"));

    try registerProvider("test_provider", .{
        .name = "test_provider",
        .provider_type = .static_loc,
        .value = "KEY",
    });
    try std.testing.expect(hasProvider("test_provider"));
    try std.testing.expect(!hasProvider("other_provider"));
}

test "text resolution: static loc provider" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        i = 0;
        while (i < cache_count) : (i += 1) {
            std.testing.allocator.free(cache_keys[i]);
            std.testing.allocator.free(cache_values[i]);
        }
        provider_count = 0;
        cache_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;
    cache_count = 0;

    // Register a static loc provider
    try registerProvider("get_status", .{
        .name = "get_status",
        .provider_type = .static_loc,
        .value = "STATUS_READY",
    });

    // Resolve text
    var context = TextContext{};
    const result = try resolveText("get_status", &context);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("STATUS_READY", result.text);
    try std.testing.expectEqualStrings("get_status", result.provider_name);
}

test "text resolution: JS function provider" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        i = 0;
        while (i < cache_count) : (i += 1) {
            std.testing.allocator.free(cache_keys[i]);
            std.testing.allocator.free(cache_values[i]);
        }
        provider_count = 0;
        cache_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;
    cache_count = 0;

    // Register a JS function provider
    try registerProvider("get_count", .{
        .name = "get_count",
        .provider_type = .js_function,
        .value = "getResourceCount",
    });

    // Resolve text
    var context = TextContext{};
    const result = try resolveText("get_count", &context);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("getResourceCount", result.text);
}

test "text resolution: provider not found" {
    provider_allocator = std.testing.allocator;
    defer {
        provider_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;

    var context = TextContext{};
    const result = try resolveText("nonexistent", &context);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_message != null);
}

test "text resolution: disabled provider" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;

    // Register and disable a provider
    try registerProvider("disabled_provider", .{
        .name = "disabled_provider",
        .provider_type = .static_loc,
        .value = "KEY",
        .enabled = false,
    });

    // Resolve text
    var context = TextContext{};
    const result = try resolveText("disabled_provider", &context);

    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("Provider disabled", result.error_message.?);
}

test "text cache: basic operations" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < cache_count) : (i += 1) {
            std.testing.allocator.free(cache_keys[i]);
            std.testing.allocator.free(cache_values[i]);
        }
        cache_count = 0;
        provider_allocator = null;
    }

    cache_count = 0;

    // Cache some text
    cacheText("element_1", "Hello");
    cacheText("element_2", "World");

    try std.testing.expectEqual(@as(usize, 2), cache_count);

    // Retrieve cached text
    try std.testing.expectEqualStrings("Hello", getCachedText("element_1").?);
    try std.testing.expectEqualStrings("World", getCachedText("element_2").?);
    try std.testing.expectEqual(@as(?[]const u8, null), getCachedText("element_3"));

    // Clear cache
    clearCache();
    try std.testing.expectEqual(@as(usize, 0), cache_count);
}

test "text cache: update existing entry" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < cache_count) : (i += 1) {
            std.testing.allocator.free(cache_keys[i]);
            std.testing.allocator.free(cache_values[i]);
        }
        cache_count = 0;
        provider_allocator = null;
    }

    cache_count = 0;

    // Cache initial text
    cacheText("element_1", "Old Value");
    try std.testing.expectEqualStrings("Old Value", getCachedText("element_1").?);

    // Update cache
    cacheText("element_1", "New Value");
    try std.testing.expectEqual(@as(usize, 1), cache_count);
    try std.testing.expectEqualStrings("New Value", getCachedText("element_1").?);
}

test "convenience functions: registerJSProvider" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;

    try registerJSProvider("js_text", "getTextFromJS");

    const provider = lookupProvider("js_text");
    try std.testing.expect(provider != null);
    try std.testing.expectEqual(ProviderType.js_function, provider.?.provider_type);
    try std.testing.expectEqualStrings("getTextFromJS", provider.?.value);
}

test "convenience functions: registerStaticLocProvider" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;

    try registerStaticLocProvider("loc_text", "MY_LOC_KEY");

    const provider = lookupProvider("loc_text");
    try std.testing.expect(provider != null);
    try std.testing.expectEqual(ProviderType.static_loc, provider.?.provider_type);
    try std.testing.expectEqualStrings("MY_LOC_KEY", provider.?.value);
}

test "statistics: track resolutions" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;
    system_stats = .{};

    // Register a provider
    try registerProvider("stat_test", .{
        .name = "stat_test",
        .provider_type = .static_loc,
        .value = "KEY",
    });

    // Resolve text multiple times
    var context = TextContext{};
    _ = try resolveText("stat_test", &context);
    _ = try resolveText("stat_test", &context);
    _ = resolveText("nonexistent", &context) catch null;

    const stats = getStats();
    try std.testing.expectEqual(@as(u64, 3), stats.total_resolutions);
    try std.testing.expectEqual(@as(u64, 2), stats.successful_resolutions);
    try std.testing.expectEqual(@as(u64, 1), stats.failed_resolutions);
}

test "TextProvider struct defaults" {
    const provider = TextProvider{
        .name = "test",
        .provider_type = .static_loc,
        .value = "KEY",
    };
    try std.testing.expect(provider.enabled);
    try std.testing.expectEqual(@as(i32, 0), provider.priority);
    try std.testing.expectEqual(@as(?[]const u8, null), provider.fallback);
    try std.testing.expectEqual(@as(?*const fn (*anyopaque) ?[]const u8, null), provider.function_pointer);
}

test "TextContext struct defaults" {
    const context = TextContext{};
    try std.testing.expectEqual(@as(?*anyopaque, null), context.scope);
    try std.testing.expectEqual(@as(?[]const u8, null), context.window_name);
    try std.testing.expectEqual(@as(?[]const u8, null), context.element_name);
    try std.testing.expectEqual(@as(?[]const u8, null), context.cached_text);
}

test "clearCache: clears all entries" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        i = 0;
        while (i < cache_count) : (i += 1) {
            std.testing.allocator.free(cache_keys[i]);
            std.testing.allocator.free(cache_values[i]);
        }
        provider_count = 0;
        cache_count = 0;
        provider_allocator = null;
    }

    provider_count = 0;
    cache_count = 0;

    // Add some cache entries
    cacheText("elem1", "text1");
    cacheText("elem2", "text2");
    try std.testing.expectEqual(@as(usize, 2), cache_count);

    clearCache();
    try std.testing.expectEqual(@as(usize, 0), cache_count);
}

test "resolveGuiText: no dollar references" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }
    provider_count = 0;

    var context = TextContext{};
    const result = try resolveGuiText("Hello World", &context);
    try std.testing.expectEqualStrings("Hello World", result);
}

test "resolveGuiText: with dollar references" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        i = 0;
        while (i < cache_count) : (i += 1) {
            std.testing.allocator.free(cache_keys[i]);
            std.testing.allocator.free(cache_values[i]);
        }
        provider_count = 0;
        cache_count = 0;
        provider_allocator = null;
    }
    provider_count = 0;
    cache_count = 0;

    // Register a provider
    try registerProvider("STATUS", .{
        .name = "STATUS",
        .provider_type = .static_loc,
        .value = "READY",
    });

    var context = TextContext{};
    const result = try resolveGuiText("Status: $STATUS$", &context);
    try std.testing.expectEqualStrings("Status: READY", result);
}

test "resolveGuiText: unresolved reference kept as-is" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }
    provider_count = 0;

    var context = TextContext{};
    const result = try resolveGuiText("Value: $UNKNOWN$", &context);
    // Unresolved references are kept as-is
    try std.testing.expectEqualStrings("Value: $UNKNOWN$", result);
}

test "registerZigProvider: registers function pointer" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }
    provider_count = 0;

    // Create a dummy function pointer
    const dummyFn = struct {
        fn testFn(_: *anyopaque) ?[]const u8 {
            return "zig_text";
        }
    }.testFn;

    try registerZigProvider("zig_provider", &dummyFn);

    const provider = lookupProvider("zig_provider");
    try std.testing.expect(provider != null);
    try std.testing.expectEqual(ProviderType.zig_function, provider.?.provider_type);
    try std.testing.expect(provider.?.function_pointer != null);
}

test "cache: eviction when full" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < cache_count) : (i += 1) {
            std.testing.allocator.free(cache_keys[i]);
            std.testing.allocator.free(cache_values[i]);
        }
        cache_count = 0;
        provider_allocator = null;
    }
    cache_count = 0;

    // Fill cache to capacity
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        var key_buf: [16]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "elem_{d}", .{i}) catch unreachable;
        cacheText(key, "value");
    }
    try std.testing.expectEqual(@as(usize, 64), cache_count);

    // Add one more - should evict the oldest
    cacheText("new_elem", "new_value");
    try std.testing.expectEqual(@as(usize, 64), cache_count);

    // Oldest entry should be evicted
    try std.testing.expectEqual(@as(?[]const u8, null), getCachedText("elem_0"));
    try std.testing.expectEqualStrings("new_value", getCachedText("new_elem").?);
}

test "TextSystemStats: default values" {
    const stats = TextSystemStats{};
    try std.testing.expect(!stats.initialized);
    try std.testing.expectEqual(@as(u32, 0), stats.provider_count);
    try std.testing.expectEqual(@as(u64, 0), stats.total_resolutions);
    try std.testing.expectEqual(@as(u64, 0), stats.successful_resolutions);
    try std.testing.expectEqual(@as(u64, 0), stats.failed_resolutions);
    try std.testing.expectEqual(@as(u64, 0), stats.cache_hits);
}

test "TextError: all variants exist" {
    // Verify error types are accessible by using them
    const err1 = error{ProviderNotFound};
    const err2 = error{ProviderDisabled};
    const err3 = error{ResolutionFailed};
    const err4 = error{RuntimeNotInitialized};
    const err5 = error{OutOfMemory};
    const err6 = error{RegistryFull};
    // Just verify they compile and are different
    try std.testing.expect(err1 != err2);
    try std.testing.expect(err2 != err3);
    try std.testing.expect(err3 != err4);
    try std.testing.expect(err4 != err5);
    try std.testing.expect(err5 != err6);
}

test "TextResult: default values" {
    const result = TextResult{
        .text = "test",
        .provider_name = "test_provider",
    };
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(?[]const u8, null), result.error_message);
}

test "TextResult: failure with error message" {
    const result = TextResult{
        .text = "",
        .provider_name = "failed_provider",
        .success = false,
        .error_message = "Provider not found",
    };
    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("Provider not found", result.error_message.?);
}

test "removeProvider: removes from middle" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }
    provider_count = 0;

    try registerProvider("a", .{ .name = "a", .provider_type = .static_loc, .value = "A" });
    try registerProvider("b", .{ .name = "b", .provider_type = .static_loc, .value = "B" });
    try registerProvider("c", .{ .name = "c", .provider_type = .static_loc, .value = "C" });
    try std.testing.expectEqual(@as(usize, 3), getProviderCount());

    // Remove middle provider
    try std.testing.expect(removeProvider("b"));
    try std.testing.expectEqual(@as(usize, 2), getProviderCount());

    try std.testing.expect(hasProvider("a"));
    try std.testing.expect(!hasProvider("b"));
    try std.testing.expect(hasProvider("c"));
}

test "provider with fallback: fallback not resolved on success" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        provider_count = 0;
        provider_allocator = null;
    }
    provider_count = 0;

    // Register a provider with a fallback
    try registerProvider("primary", .{
        .name = "primary",
        .provider_type = .static_loc,
        .value = "PRIMARY_VALUE",
        .fallback = "fallback",
    });

    // Register the fallback
    try registerProvider("fallback", .{
        .name = "fallback",
        .provider_type = .static_loc,
        .value = "FALLBACK_VALUE",
    });

    // Resolve should use primary
    var context = TextContext{};
    const result = try resolveText("primary", &context);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("PRIMARY_VALUE", result.text);
}

test "cache: cached text returned on second resolve" {
    provider_allocator = std.testing.allocator;
    defer {
        var i: usize = 0;
        while (i < provider_count) : (i += 1) {
            std.testing.allocator.free(provider_names[i]);
            std.testing.allocator.free(provider_values[i]);
            if (provider_fallbacks[i] != null) {
                std.testing.allocator.free(provider_fallbacks[i].?);
            }
        }
        i = 0;
        while (i < cache_count) : (i += 1) {
            std.testing.allocator.free(cache_keys[i]);
            std.testing.allocator.free(cache_values[i]);
        }
        provider_count = 0;
        cache_count = 0;
        provider_allocator = null;
    }
    provider_count = 0;
    cache_count = 0;

    try registerProvider("cached", .{
        .name = "cached",
        .provider_type = .static_loc,
        .value = "CACHED_VALUE",
    });

    var context = TextContext{ .element_name = "my_element" };

    // First resolve - should cache
    const result1 = try resolveText("cached", &context);
    try std.testing.expect(result1.success);

    // Second resolve - should hit cache
    const result2 = try resolveText("cached", &context);
    try std.testing.expect(result2.success);

    const stats = getStats();
    try std.testing.expect(stats.cache_hits > 0);
}
