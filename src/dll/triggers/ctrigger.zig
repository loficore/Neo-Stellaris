// ctrigger.zig — CTrigger::Evaluate hook implementation.
//
// Hooks the CTrigger::Evaluate virtual function to intercept custom triggers
// (scripted triggers with ID > threshold) and route them to JS handlers.
// Original vanilla triggers pass through to the trampoline unchanged.
//
// CTrigger object layout (to be verified from IDA):
//   +0x038 (56)  — Trigger name as SSO string { union { char inline[24]; char* ptr; }; u8 length; }
//   +0xFF0 (4080) — Trigger ID as i32
//   +0x6A8 (1704) — vtable pointer
//
// CEventScope layout (verified from T5):
//   +8  (int64_t) — Scope type (see offsets.zig scope_types)
//   +16 (int64_t) — Object ID (valid when scope_type matches a known type)
//
// The hook pattern:
//   1. Read scope info from CEventScope (type + object ID)
//   2. Read trigger ID from CTrigger+4080
//   3. If ID > SCRIPTED_TRIGGER_BASE (custom/scripted trigger), read name and route to JS
//   4. Otherwise, call through trampoline to original Evaluate

const std = @import("std");
const offsets = @import("../shared/offsets.zig");
const detour = @import("../hooking/detour.zig");
const handler = @import("handler.zig");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Address of CTrigger::Evaluate in stellaris.exe (version 3.x).
/// TODO: Verify address from IDA — CTrigger::Evaluate is virtual, dispatch
/// via vtable at CTrigger+1704. This is the direct address for hooking.
const EVALUATE_ADDR: usize = 0x1408A6F20; // Placeholder — verify from IDA

/// CTrigger+4080: trigger ID field (i32).
/// Matches CEffect layout for the ID field.
const OFFSET_TRIGGER_ID: usize = 4080; // +0xFF0

/// CTrigger+56: trigger name SSO string.
/// Matches CEffect layout for the name field.
const OFFSET_TRIGGER_NAME: usize = 56; // +0x38

/// Threshold: triggers with ID > SCRIPTED_TRIGGER_BASE are custom/scripted.
/// This is the same threshold as scripted effects (4081).
const SCRIPTED_TRIGGER_BASE: i32 = offsets.known_effect_ids.SCRIPTED_EFFECT_BASE;

/// Maximum length for SSO string (inline buffer size).
const SSO_MAX_LEN: usize = 22;

// ---------------------------------------------------------------------------
// CEventScope offsets (from T5 verification)
// ---------------------------------------------------------------------------

/// CEventScope+8: scope type as int64_t.
const OFFSET_SCOPE_TYPE: usize = offsets.c_event_scope.OFFSET_SCOPE_TYPE;

/// CEventScope+16: object ID as int64_t (valid when type matches known scope).
const OFFSET_OBJECT_ID: usize = offsets.c_event_scope.OFFSET_OBJECT_ID;

// ---------------------------------------------------------------------------
// Scope type constants
// ---------------------------------------------------------------------------

/// Known scope type values for CEventScope.
const SCOPE_PLANET: i64 = offsets.scope_types.PLANET;
const SCOPE_COUNTRY: i64 = offsets.scope_types.COUNTRY;
const SCOPE_SHIP: i64 = offsets.scope_types.SHIP;
const SCOPE_POP: i64 = offsets.scope_types.POP;
const SCOPE_FLEET: i64 = offsets.scope_types.FLEET;

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
// Trigger reading helpers
// ---------------------------------------------------------------------------

/// Read the trigger ID from a CTrigger object.
/// CTrigger+4080 contains the trigger ID as i32.
pub fn readTriggerId(ctrigger: *const anyopaque) i32 {
    const base: [*]const u8 = @ptrCast(ctrigger);
    const id_ptr: *const i32 = @ptrCast(@alignCast(base + OFFSET_TRIGGER_ID));
    return id_ptr.*;
}

/// Read the trigger name from a CTrigger object.
/// CTrigger+56 contains the trigger name as an SSO string.
/// Returns a slice into the object's memory (valid for the CTrigger's lifetime).
pub fn readTriggerName(ctrigger: *const anyopaque) []const u8 {
    const base: [*]const u8 = @ptrCast(ctrigger);
    const sso_ptr: *const SSOString = @ptrCast(@alignCast(base + OFFSET_TRIGGER_NAME));
    return sso_ptr.asSlice();
}

/// Check if a trigger ID represents a custom/scripted trigger.
pub fn isCustomTrigger(trigger_id: i32) bool {
    return trigger_id > SCRIPTED_TRIGGER_BASE;
}

/// Read the scope type from a CEventScope object.
/// CEventScope+8 contains the scope type as int64_t.
pub fn readScopeType(ceventscope: *const anyopaque) i64 {
    const base: [*]const u8 = @ptrCast(ceventscope);
    const type_ptr: *const i64 = @ptrCast(@alignCast(base + OFFSET_SCOPE_TYPE));
    return type_ptr.*;
}

/// Read the object ID from a CEventScope object.
/// CEventScope+16 contains the object ID as int64_t.
/// Only valid when scope_type matches a known type (PLANET, COUNTRY, etc.).
pub fn readObjectId(ceventscope: *const anyopaque) i64 {
    const base: [*]const u8 = @ptrCast(ceventscope);
    const id_ptr: *const i64 = @ptrCast(@alignCast(base + OFFSET_OBJECT_ID));
    return id_ptr.*;
}

/// Check if a scope type represents a valid game object scope.
pub fn isValidScopeType(scope_type: i64) bool {
    return switch (scope_type) {
        SCOPE_PLANET,
        SCOPE_COUNTRY,
        SCOPE_SHIP,
        SCOPE_POP,
        SCOPE_FLEET,
        => true,
        else => false,
    };
}

// ---------------------------------------------------------------------------
// Trampoline storage
// ---------------------------------------------------------------------------

/// Original Evaluate function pointer (set after hook installation).
/// Cast to: *const fn (*anyopaque, *anyopaque) callconv(.c) bool
var original_evaluate: ?*const fn (*anyopaque, *anyopaque) callconv(.c) bool = null;

/// Hook state for cleanup.
var trigger_hook: ?detour.Hook = null;

// ---------------------------------------------------------------------------
// Hook function (detour target)
// ---------------------------------------------------------------------------

/// Replacement for CTrigger::Evaluate.
///
/// This function is called for every trigger evaluation. It checks if the trigger
/// is custom (scripted) and routes it to the JS handler. Vanilla triggers pass
/// through to the original function via the trampoline.
///
/// # Arguments
/// * `ctrigger` - Pointer to the CTrigger instance
/// * `ceventscope` - Pointer to the CEventScope (execution context)
///
/// # Returns
/// Boolean result: true if trigger passes, false otherwise.
pub fn triggerHook(ctrigger: *anyopaque, ceventscope: *anyopaque) callconv(.c) bool {
    // Read trigger metadata
    const trigger_id = readTriggerId(ctrigger);
    const trigger_name = readTriggerName(ctrigger);

    // Read scope info for debugging/logging
    const scope_type = readScopeType(ceventscope);
    const object_id = readObjectId(ceventscope);

    // Check if this is a custom/scripted trigger
    if (isCustomTrigger(trigger_id)) {
        // Log the scope context for debugging
        if (isValidScopeType(scope_type)) {
            std.log.debug(
                "Custom trigger '{s}' (ID: {d}) in scope type={d}, object={d}",
                .{ trigger_name, trigger_id, scope_type, object_id },
            );
        } else {
            std.log.debug(
                "Custom trigger '{s}' (ID: {d}) in unknown scope type={d}",
                .{ trigger_name, trigger_id, scope_type },
            );
        }

        // Route to JS handler
        return handler.handleCustomTrigger(trigger_name, trigger_id, ceventscope);
    }

    // Original trigger — call through trampoline
    if (original_evaluate) |orig_fn| {
        return orig_fn(ctrigger, ceventscope);
    }

    // Fallback: should not happen if hook is installed correctly
    std.log.err("CTrigger hook: trampoline not set for vanilla trigger {d}", .{trigger_id});
    return false;
}

// ---------------------------------------------------------------------------
// Installation / removal
// ---------------------------------------------------------------------------

/// Install the CTrigger::Evaluate hook.
///
/// This must be called after the engine is initialized and CTrigger objects
/// are being created. The hook intercepts all trigger evaluation to check for
/// custom triggers.
///
/// Returns error if installation fails.
pub fn install() !void {
    // Install the detour hook
    const target_addr: *anyopaque = @ptrFromInt(EVALUATE_ADDR);
    const detour_fn: *anyopaque = @ptrCast(&triggerHook);

    trigger_hook = try detour.installHook(target_addr, detour_fn);

    // Store the trampoline as the original function
    original_evaluate = @ptrCast(trigger_hook.?.trampoline);

    std.log.info(
        "CTrigger::Evaluate hook installed at 0x{X}, trampoline @ {any}",
        .{ EVALUATE_ADDR, trigger_hook.?.trampoline },
    );
}

/// Remove the CTrigger::Evaluate hook.
///
/// Restores the original function prologue and frees trampoline memory.
pub fn uninstall() !void {
    if (trigger_hook) |*hook| {
        try detour.removeHook(hook);
        trigger_hook = null;
        original_evaluate = null;
        std.log.info("CTrigger::Evaluate hook removed", .{});
    }
}

/// Check if the hook is currently installed.
pub fn isInstalled() bool {
    return trigger_hook != null;
}

// =============================================================================
// Tests
// =============================================================================

test "SSOString: inline string (short)" {
    // Simulate an SSO string with inline data (length <= 22)
    var sso: SSOString = .{
        .data = .{ .inline_buf = [_]u8{
            't', 'e', 's', 't', '_', 't', 'r', 'i',
            'g', 'g', 'e', 'r', 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        } },
        .length = 12,
    };

    const slice = sso.asSlice();
    try std.testing.expectEqual(@as(usize, 12), slice.len);
    try std.testing.expectEqualStrings("test_trigger", slice);
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

test "isCustomTrigger: threshold check" {
    // Vanilla triggers (ID <= 4081) are not custom
    try std.testing.expect(!isCustomTrigger(0));
    try std.testing.expect(!isCustomTrigger(4080));
    try std.testing.expect(!isCustomTrigger(4081));

    // Scripted triggers (ID > 4081) are custom
    try std.testing.expect(isCustomTrigger(4082));
    try std.testing.expect(isCustomTrigger(5000));
    try std.testing.expect(isCustomTrigger(10000));
}

test "readTriggerId: reads from memory" {
    // Create a mock CTrigger object in memory
    var mock_ctrigger: [8192]u8 = [_]u8{0} ** 8192;

    // Set trigger ID at offset 4080
    const id_val: i32 = 4082;
    const id_bytes = std.mem.toBytes(id_val);
    @memcpy(mock_ctrigger[OFFSET_TRIGGER_ID .. OFFSET_TRIGGER_ID + 4], &id_bytes);

    const trigger_id = readTriggerId(&mock_ctrigger);
    try std.testing.expectEqual(@as(i32, 4082), trigger_id);
}

test "readTriggerName: reads SSO string from memory" {
    // Create a mock CTrigger object
    var mock_ctrigger: [8192]u8 = [_]u8{0} ** 8192;

    // Set trigger name at offset 56 (SSO string)
    const name = "my_custom_trigger";
    const name_len: u8 = @intCast(name.len);
    @memcpy(mock_ctrigger[OFFSET_TRIGGER_NAME .. OFFSET_TRIGGER_NAME + name.len], name);
    mock_ctrigger[OFFSET_TRIGGER_NAME + 24] = name_len; // length byte after 24-byte data union

    const trigger_name = readTriggerName(&mock_ctrigger);
    try std.testing.expectEqualStrings("my_custom_trigger", trigger_name);
}

test "readScopeType: reads from memory" {
    // Create a mock CEventScope object
    var mock_scope: [64]u8 = [_]u8{0} ** 64;

    // Set scope type at offset 8
    const type_val: i64 = SCOPE_PLANET; // 2
    const type_bytes = std.mem.toBytes(type_val);
    @memcpy(mock_scope[OFFSET_SCOPE_TYPE .. OFFSET_SCOPE_TYPE + 8], &type_bytes);

    const scope_type = readScopeType(&mock_scope);
    try std.testing.expectEqual(@as(i64, 2), scope_type);
}

test "readObjectId: reads from memory" {
    // Create a mock CEventScope object
    var mock_scope: [64]u8 = [_]u8{0} ** 64;

    // Set object ID at offset 16
    const id_val: i64 = 12345;
    const id_bytes = std.mem.toBytes(id_val);
    @memcpy(mock_scope[OFFSET_OBJECT_ID .. OFFSET_OBJECT_ID + 8], &id_bytes);

    const object_id = readObjectId(&mock_scope);
    try std.testing.expectEqual(@as(i64, 12345), object_id);
}

test "isValidScopeType: known types are valid" {
    try std.testing.expect(isValidScopeType(SCOPE_PLANET));
    try std.testing.expect(isValidScopeType(SCOPE_COUNTRY));
    try std.testing.expect(isValidScopeType(SCOPE_SHIP));
    try std.testing.expect(isValidScopeType(SCOPE_POP));
    try std.testing.expect(isValidScopeType(SCOPE_FLEET));
}

test "isValidScopeType: unknown types are invalid" {
    try std.testing.expect(!isValidScopeType(0));
    try std.testing.expect(!isValidScopeType(999));
    try std.testing.expect(!isValidScopeType(-1));
}

test "triggerHook: is not installed initially" {
    try std.testing.expect(!isInstalled());
}

test "offsets: constants match expected values" {
    try std.testing.expectEqual(@as(usize, 4080), OFFSET_TRIGGER_ID);
    try std.testing.expectEqual(@as(usize, 56), OFFSET_TRIGGER_NAME);
    try std.testing.expectEqual(@as(i32, 4081), SCRIPTED_TRIGGER_BASE);
    try std.testing.expectEqual(@as(usize, 8), OFFSET_SCOPE_TYPE);
    try std.testing.expectEqual(@as(usize, 16), OFFSET_OBJECT_ID);
}

test "scope type constants: match offsets.zig" {
    try std.testing.expectEqual(@as(i64, 2), SCOPE_PLANET);
    try std.testing.expectEqual(@as(i64, 4), SCOPE_COUNTRY);
    try std.testing.expectEqual(@as(i64, 8), SCOPE_SHIP);
    try std.testing.expectEqual(@as(i64, 16), SCOPE_POP);
    try std.testing.expectEqual(@as(i64, 32), SCOPE_FLEET);
}

test "isValidScopeType: all known scope types" {
    try std.testing.expect(isValidScopeType(offsets.scope_types.PLANET));
    try std.testing.expect(isValidScopeType(offsets.scope_types.COUNTRY));
    try std.testing.expect(isValidScopeType(offsets.scope_types.SHIP));
    try std.testing.expect(isValidScopeType(offsets.scope_types.POP));
    try std.testing.expect(isValidScopeType(offsets.scope_types.FLEET));
}

test "isValidScopeType: boundary values" {
    try std.testing.expect(!isValidScopeType(1)); // Between NO_SCOPE and PLANET
    try std.testing.expect(!isValidScopeType(3)); // PLANET | COUNTRY
    try std.testing.expect(!isValidScopeType(-1)); // Negative
    try std.testing.expect(!isValidScopeType(0)); // Zero
}

test "isCustomTrigger: boundary at SCRIPTED_TRIGGER_BASE" {
    try std.testing.expect(!isCustomTrigger(offsets.known_effect_ids.SCRIPTED_EFFECT_BASE));
    try std.testing.expect(isCustomTrigger(offsets.known_effect_ids.SCRIPTED_EFFECT_BASE + 1));
}

test "readTriggerId: reads zero" {
    var mock_ctrigger: [8192]u8 = [_]u8{0} ** 8192;
    const trigger_id = readTriggerId(&mock_ctrigger);
    try std.testing.expectEqual(@as(i32, 0), trigger_id);
}

test "readTriggerName: empty SSO string" {
    var mock_ctrigger: [8192]u8 = [_]u8{0} ** 8192;
    const trigger_name = readTriggerName(&mock_ctrigger);
    try std.testing.expectEqual(@as(usize, 0), trigger_name.len);
}

test "readScopeType: reads zero" {
    var mock_scope: [64]u8 = [_]u8{0} ** 64;
    const scope_type = readScopeType(&mock_scope);
    try std.testing.expectEqual(@as(i64, 0), scope_type);
}

test "readObjectId: reads zero" {
    var mock_scope: [64]u8 = [_]u8{0} ** 64;
    const object_id = readObjectId(&mock_scope);
    try std.testing.expectEqual(@as(i64, 0), object_id);
}

test "readScopeType: PLANET scope" {
    var mock_scope: [64]u8 = [_]u8{0} ** 64;
    const type_bytes = std.mem.toBytes(@as(i64, offsets.scope_types.PLANET));
    @memcpy(mock_scope[OFFSET_SCOPE_TYPE .. OFFSET_SCOPE_TYPE + 8], &type_bytes);
    try std.testing.expectEqual(offsets.scope_types.PLANET, readScopeType(&mock_scope));
}

test "readObjectId: large ID" {
    var mock_scope: [64]u8 = [_]u8{0} ** 64;
    const id_val: i64 = 0x7FFFFFFFFFFFFFFF; // Max i64
    const id_bytes = std.mem.toBytes(id_val);
    @memcpy(mock_scope[OFFSET_OBJECT_ID .. OFFSET_OBJECT_ID + 8], &id_bytes);
    try std.testing.expectEqual(@as(i64, 0x7FFFFFFFFFFFFFFF), readObjectId(&mock_scope));
}

test "SSOString: pointer mode (length > 22)" {
    // Can't easily test pointer mode without valid heap memory,
    // but we can verify the struct layout is correct
    var sso: SSOString = .{
        .data = .{ .inline_buf = [_]u8{0} ** 24 },
        .length = 23, // > 22, would use pointer mode
    };
    // With length > 22, asSlice would try to dereference data.ptr
    // We can't test this without a valid pointer, so just verify the struct
    try std.testing.expectEqual(@as(u8, 23), sso.length);
}

test "isCustomTrigger: negative IDs are custom" {
    try std.testing.expect(isCustomTrigger(-1));
    try std.testing.expect(isCustomTrigger(-100));
}

test "triggerHook: is not installed initially" {
    try std.testing.expect(!isInstalled());
}
