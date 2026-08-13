// ceffect.zig — CEffect::ExecuteActual hook implementation.
//
// Hooks the CEffect::ExecuteActual virtual function at 0x14181B740 to intercept
// custom effects (scripted effects with ID > 4081) and route them to JS handlers.
// Original vanilla effects pass through to the trampoline unchanged.
//
// CEffect object layout (verified from IDA):
//   +0x038 (56)  — Effect name as SSO string { union { char inline[24]; char* ptr; }; u8 length; }
//   +0xFF0 (4080) — Effect ID as i32
//   +0x6A8 (1704) — vtable pointer
//
// The hook pattern:
//   1. Read effect ID from CEffect+4080
//   2. If ID > 4081 (scripted/custom effect), read name and route to JS
//   3. Otherwise, call through trampoline to original ExecuteActual

const std = @import("std");
const offsets = @import("../shared/offsets.zig");
const detour = @import("../hooking/detour.zig");
const handler = @import("handler.zig");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Address of CEffect::ExecuteActual in stellaris.exe (version 3.x).
const EXECUTE_ACTUAL_ADDR: usize = 0x14181B740;

/// CEffect+4080: effect ID field (i32).
const OFFSET_EFFECT_ID: usize = offsets.c_effect.OFFSET_EFFECT_ID;

/// CEffect+56: effect name SSO string.
const OFFSET_EFFECT_NAME: usize = offsets.c_effect.OFFSET_EFFECT_NAME;

/// Threshold: effects with ID > SCRIPTED_EFFECT_BASE are custom/scripted.
const SCRIPTED_EFFECT_BASE: i32 = offsets.known_effect_ids.SCRIPTED_EFFECT_BASE;

/// Maximum length for SSO string (inline buffer size).
const SSO_MAX_LEN: usize = 22;

// ---------------------------------------------------------------------------
// SSO string reading
// ---------------------------------------------------------------------------

/// SSO (Small String Optimization) string representation.
/// Matches the Clausewitz engine layout: { union { char inline[24]; char* ptr; }; u8 length; }
pub const SSOString = extern struct {
    /// Inline buffer or pointer to heap-allocated string.
    data: extern union {
        /// Inline string data (when length <= 22).
        inline_buf: [24]u8,
        /// Pointer to heap-allocated string (when length > 22).
        ptr: ?[*:0]const u8,
    } = .{ .inline_buf = [_]u8{0} ** 24 },

    /// Length of the string.
    length: u8 = 0,

    /// Get the string as a slice.
    /// If length <= 22, data is inline; otherwise, it's a pointer.
    pub fn asSlice(self: *const SSOString) []const u8 {
        if (self.length <= SSO_MAX_LEN) {
            // Inline: data is in the inline_buf
            return self.data.inline_buf[0..self.length];
        } else {
            // Pointer: dereference the ptr
            if (self.data.ptr) |ptr| {
                return ptr[0..self.length];
            }
            return &[_]u8{};
        }
    }
};

// ---------------------------------------------------------------------------
// Effect reading helpers
// ---------------------------------------------------------------------------

/// Read the effect ID from a CEffect object.
/// CEffect+4080 contains the effect ID as i32.
pub fn readEffectId(ceffect: *const anyopaque) i32 {
    const base: [*]const u8 = @ptrCast(ceffect);
    const id_ptr: *const i32 = @ptrCast(@alignCast(base + OFFSET_EFFECT_ID));
    return id_ptr.*;
}

/// Read the effect name from a CEffect object.
/// CEffect+56 contains the effect name as an SSO string.
/// Returns a slice into the object's memory (valid for the CEffect's lifetime).
pub fn readEffectName(ceffect: *const anyopaque) []const u8 {
    const base: [*]const u8 = @ptrCast(ceffect);
    const sso_ptr: *const SSOString = @ptrCast(@alignCast(base + OFFSET_EFFECT_NAME));
    return sso_ptr.asSlice();
}

/// Check if an effect ID represents a custom/scripted effect.
pub fn isCustomEffect(effect_id: i32) bool {
    return effect_id > SCRIPTED_EFFECT_BASE;
}

// ---------------------------------------------------------------------------
// Trampoline storage
// ---------------------------------------------------------------------------

/// Original ExecuteActual function pointer (set after hook installation).
/// Cast to: *const fn (*anyopaque, *anyopaque) callconv(.c) i64
var original_execute_actual: ?*const fn (*anyopaque, *anyopaque) callconv(.c) i64 = null;

/// Hook state for cleanup.
var effect_hook: ?detour.Hook = null;

// ---------------------------------------------------------------------------
// Hook function (detour target)
// ---------------------------------------------------------------------------

/// Replacement for CEffect::ExecuteActual.
///
/// This function is called for every effect execution. It checks if the effect
/// is custom (scripted) and routes it to the JS handler. Vanilla effects pass
/// through to the original function via the trampoline.
///
/// # Arguments
/// * `ceffect` - Pointer to the CEffect instance
/// * `ceventscope` - Pointer to the CEventScope (execution context)
///
/// # Returns
/// The effect's return value (typically i64, convention depends on effect type).
pub fn effectHook(ceffect: *anyopaque, ceventscope: *anyopaque) callconv(.c) i64 {
    // Read effect metadata
    const effect_id = readEffectId(ceffect);
    const effect_name = readEffectName(ceffect);

    // Check if this is a custom/scripted effect
    if (isCustomEffect(effect_id)) {
        // Route to JS handler
        return handler.handleCustomEffect(effect_name, effect_id, ceventscope);
    }

    // Original effect — call through trampoline
    if (original_execute_actual) |orig_fn| {
        return orig_fn(ceffect, ceventscope);
    }

    // Fallback: should not happen if hook is installed correctly
    std.log.err("CEffect hook: trampoline not set for vanilla effect {d}", .{effect_id});
    return 0;
}

// ---------------------------------------------------------------------------
// Installation / removal
// ---------------------------------------------------------------------------

/// Install the CEffect::ExecuteActual hook.
///
/// This must be called after the engine is initialized and CEffect objects
/// are being created. The hook intercepts all effect execution to check for
/// custom effects.
///
/// Returns the installed hook state, or an error if installation fails.
pub fn install() !void {
    // Install the detour hook
    const target_addr: *anyopaque = @ptrFromInt(EXECUTE_ACTUAL_ADDR);
    const detour_fn: *anyopaque = @ptrCast(&effectHook);

    effect_hook = try detour.installHook(target_addr, detour_fn);

    // Store the trampoline as the original function
    original_execute_actual = @ptrCast(effect_hook.?.trampoline);

    std.log.info(
        "CEffect::ExecuteActual hook installed at 0x{X}, trampoline @ {any}",
        .{ EXECUTE_ACTUAL_ADDR, effect_hook.?.trampoline },
    );
}

/// Remove the CEffect::ExecuteActual hook.
///
/// Restores the original function prologue and frees trampoline memory.
pub fn uninstall() !void {
    if (effect_hook) |*hook| {
        try detour.removeHook(hook);
        effect_hook = null;
        original_execute_actual = null;
        std.log.info("CEffect::ExecuteActual hook removed", .{});
    }
}

/// Check if the hook is currently installed.
pub fn isInstalled() bool {
    return effect_hook != null;
}

// =============================================================================
// Tests
// =============================================================================

test "SSOString: inline string (short)" {
    // Simulate an SSO string with inline data (length <= 22)
    var sso: SSOString = .{
        .data = .{ .inline_buf = [_]u8{
            't', 'e', 's', 't', '_', 'e', 'f', 'f',
            'e', 'c', 't', 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        } },
        .length = 11,
    };

    const slice = sso.asSlice();
    try std.testing.expectEqual(@as(usize, 11), slice.len);
    try std.testing.expectEqualStrings("test_effect", slice);
}

test "SSOString: empty string" {
    var sso: SSOString = .{
        .data = .{ .inline_buf = [_]u8{0} ** 24 },
        .length = 0,
    };

    const slice = sso.asSlice();
    try std.testing.expectEqual(@as(usize, 0), slice.len);
    try std.testing.expectEqualStrings("", slice);
}

test "SSOString: max inline length (22)" {
    var sso: SSOString = .{
        .data = .{ .inline_buf = [_]u8{
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
            'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
            'q', 'r', 's', 't', 'u', 'v', 0, 0,
        } },
        .length = 22,
    };

    const slice = sso.asSlice();
    try std.testing.expectEqual(@as(usize, 22), slice.len);
    try std.testing.expectEqualStrings("abcdefghijklmnopqrstuv", slice);
}

test "isCustomEffect: threshold check" {
    // Vanilla effects (ID <= 4081) are not custom
    try std.testing.expect(!isCustomEffect(0));
    try std.testing.expect(!isCustomEffect(4080));
    try std.testing.expect(!isCustomEffect(4081));

    // Scripted effects (ID > 4081) are custom
    try std.testing.expect(isCustomEffect(4082));
    try std.testing.expect(isCustomEffect(5000));
    try std.testing.expect(isCustomEffect(10000));
}

test "readEffectId: reads from memory" {
    // Create a mock CEffect object in memory
    var mock_ceffect: [8192]u8 = [_]u8{0} ** 8192;

    // Set effect ID at offset 4080
    const id_val: i32 = 4082;
    const id_bytes = std.mem.toBytes(id_val);
    @memcpy(mock_ceffect[OFFSET_EFFECT_ID .. OFFSET_EFFECT_ID + 4], &id_bytes);

    const effect_id = readEffectId(&mock_ceffect);
    try std.testing.expectEqual(@as(i32, 4082), effect_id);
}

test "readEffectName: reads SSO string from memory" {
    // Create a mock CEffect object
    var mock_ceffect: [8192]u8 = [_]u8{0} ** 8192;

    // Set effect name at offset 56 (SSO string)
    const name = "my_custom_effect";
    const name_len: u8 = @intCast(name.len);
    @memcpy(mock_ceffect[OFFSET_EFFECT_NAME .. OFFSET_EFFECT_NAME + name.len], name);
    mock_ceffect[OFFSET_EFFECT_NAME + 24] = name_len; // length byte after 24-byte data union

    const effect_name = readEffectName(&mock_ceffect);
    try std.testing.expectEqualStrings("my_custom_effect", effect_name);
}

test "effectHook: is not installed initially" {
    try std.testing.expect(!isInstalled());
}

test "offsets: constants match expected values" {
    try std.testing.expectEqual(@as(usize, 4080), OFFSET_EFFECT_ID);
    try std.testing.expectEqual(@as(usize, 56), OFFSET_EFFECT_NAME);
    try std.testing.expectEqual(@as(i32, 4081), SCRIPTED_EFFECT_BASE);
}
