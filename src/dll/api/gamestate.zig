// gamestate.zig — Game state access functions (stubs).
//
// Provides read/write access to Stellaris game objects (countries, planets,
// pops, systems) via the Clausewitz engine's global databases. These are
// STUB implementations that return safe defaults until actual engine
// offsets and function calls are wired up in later tasks.
//
// The real implementations will use:
//   - GameState global (0x143287360) for top-level state
//   - CountryDB (0x143287788) for country lookups
//   - Virtual function calls on game objects for property access
//
// Thread safety: All functions in this module are stateless stubs.
// Future implementations must use appropriate locking for shared state.

const std = @import("std");
const offsets = @import("offsets");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Global address of the main GameState object (from IDA analysis).
const GAME_STATE_ADDR: usize = 0x143287360;

/// Global address of the Country database (from IDA analysis).
const COUNTRY_DB_ADDR: usize = 0x143287788;

// ---------------------------------------------------------------------------
// Game object types
// ---------------------------------------------------------------------------

/// Opaque handle to a game object. In production, this wraps the engine's
/// internal object pointer. For stubs, it's just a raw pointer.
pub const GameObjectHandle = *anyopaque;

/// Modifier representation: a name and integer value.
pub const Modifier = struct {
    name: []const u8,
    value: i64,
};

/// Variable representation: a name and integer value.
pub const Variable = struct {
    name: []const u8,
    value: i64,
};

// ---------------------------------------------------------------------------
// Read functions (stubs)
// ---------------------------------------------------------------------------

/// Retrieve a country object by its numeric ID.
///
/// # Arguments
/// * `id` - Country ID (matches in-game country ID, e.g., from save files)
///
/// # Returns
/// Pointer to the country object, or null if not found.
///
/// TODO: Implement actual CountryDB lookup via `qword_143287788`.
pub fn getCountry(id: u32) ?GameObjectHandle {
    _ = id;
    // Stub: return null (not found)
    return null;
}

/// Retrieve a planet object by its numeric ID.
///
/// # Arguments
/// * `id` - Planet ID
///
/// # Returns
/// Pointer to the planet object, or null if not found.
///
/// TODO: Implement actual planet lookup via galactic object database.
pub fn getPlanet(id: u32) ?GameObjectHandle {
    _ = id;
    return null;
}

/// Retrieve a pop object by its numeric ID.
///
/// # Arguments
/// * `id` - Pop ID
///
/// # Returns
/// Pointer to the pop object, or null if not found.
///
/// TODO: Implement actual pop lookup via pop database.
pub fn getPop(id: u32) ?GameObjectHandle {
    _ = id;
    return null;
}

/// Retrieve a star system (galactic object) by its numeric ID.
///
/// # Arguments
/// * `id` - System/galactic object ID
///
/// # Returns
/// Pointer to the system object, or null if not found.
///
/// TODO: Implement actual system lookup via galactic object database.
pub fn getSystem(id: u32) ?GameObjectHandle {
    _ = id;
    return null;
}

/// Retrieve the current game date as a string.
///
/// # Returns
/// Pointer to the date string (engine-owned), or empty slice if unavailable.
///
/// TODO: Read from GameState date field.
pub fn getGameDate() []const u8 {
    return "";
}

/// Retrieve the current game tick.
///
/// # Returns
/// Current tick count, or 0 if unavailable.
///
/// TODO: Read from GameState tick field.
pub fn getGameTick() i64 {
    return 0;
}

// ---------------------------------------------------------------------------
// Write functions (stubs)
// ---------------------------------------------------------------------------

/// Set a variable value on a game object's scope.
///
/// # Arguments
/// * `name` - Variable name (e.g., "my_mod_var")
/// * `value` - New value
///
/// # Returns
/// true if the variable was set successfully, false otherwise.
///
/// TODO: Implement via CEventScope variable storage.
pub fn setVariable(name: []const u8, value: i64) bool {
    _ = name;
    _ = value;
    // Stub: pretend it failed
    return false;
}

/// Add a modifier to a game object (e.g., pop happiness modifier).
///
/// # Arguments
/// * `scope` - Target scope (game object)
/// * `modifier` - Modifier to apply
///
/// # Returns
/// true if the modifier was applied, false otherwise.
///
/// TODO: Implement via engine modifier system.
pub fn addModifier(scope: GameObjectHandle, modifier: Modifier) bool {
    _ = scope;
    _ = modifier;
    return false;
}

/// Trigger a game event by ID.
///
/// # Arguments
/// * `event_id` - The event ID (string key, e.g., "my_event.1")
/// * `scope` - The scope to trigger the event in
///
/// # Returns
/// true if the event was triggered, false otherwise.
///
/// TODO: Implement via COnActionDatabase or event manager.
pub fn triggerEvent(event_id: []const u8, scope: GameObjectHandle) bool {
    _ = event_id;
    _ = scope;
    return false;
}

/// Remove a modifier from a game object.
///
/// # Arguments
/// * `scope` - Target scope
/// * `modifier_name` - Name of the modifier to remove
///
/// # Returns
/// true if the modifier was removed, false otherwise.
///
/// TODO: Implement via engine modifier system.
pub fn removeModifier(scope: GameObjectHandle, modifier_name: []const u8) bool {
    _ = scope;
    _ = modifier_name;
    return false;
}

// =============================================================================
// Tests
// =============================================================================

test "getCountry: stub returns null" {
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getCountry(0));
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getCountry(1));
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getCountry(42));
}

test "getPlanet: stub returns null" {
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getPlanet(0));
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getPlanet(100));
}

test "getPop: stub returns null" {
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getPop(0));
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getPop(999));
}

test "getSystem: stub returns null" {
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getSystem(0));
    try std.testing.expectEqual(@as(?GameObjectHandle, null), getSystem(255));
}

test "getGameDate: stub returns empty" {
    try std.testing.expectEqualStrings("", getGameDate());
}

test "getGameTick: stub returns zero" {
    try std.testing.expectEqual(@as(i64, 0), getGameTick());
}

test "setVariable: stub returns false" {
    try std.testing.expect(!setVariable("test_var", 42));
    try std.testing.expect(!setVariable("another_var", -1));
}

test "addModifier: stub returns false" {
    // Can't create a real GameObjectHandle in test, but we can test with a dummy pointer
    const dummy_handle: GameObjectHandle = @ptrFromInt(0x1000);
    const mod = Modifier{ .name = "happiness", .value = 10 };
    try std.testing.expect(!addModifier(dummy_handle, mod));
}

test "triggerEvent: stub returns false" {
    const dummy_handle: GameObjectHandle = @ptrFromInt(0x1000);
    try std.testing.expect(!triggerEvent("my_event.1", dummy_handle));
}

test "removeModifier: stub returns false" {
    const dummy_handle: GameObjectHandle = @ptrFromInt(0x1000);
    try std.testing.expect(!removeModifier(dummy_handle, "happiness"));
}

test "constants have expected values" {
    try std.testing.expectEqual(@as(usize, 0x143287360), GAME_STATE_ADDR);
    try std.testing.expectEqual(@as(usize, 0x143287788), COUNTRY_DB_ADDR);
}
