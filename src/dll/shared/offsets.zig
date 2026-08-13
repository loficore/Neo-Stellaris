// offsets.zig — Verified object offsets from IDA reverse engineering.
//
// These offsets are derived from the Clausewitz engine binary analysis
// (stellaris.exe, version 3.x, codename "augustus"). Each offset represents
// the byte offset from the start of the corresponding object to a specific
// field, verified against IDA decompilation and runtime memory inspection.
//
// All offsets are in bytes. The naming convention follows:
//   OFFSET_<OBJECT>_<FIELD>: <byte offset> (+hex) — <field description>

const std = @import("std");

/// CEffect object offsets.
/// CEffect is the base class for all effect implementations in the engine.
/// The effect ID is used in the dispatch switch-case at 0x14180B050.
pub const c_effect = struct {
    /// Effect ID field (int32). Used for dispatch in the main effect switch.
    /// Value range: 0–4080+ for vanilla, higher for scripted effects.
    pub const OFFSET_EFFECT_ID: usize = 4080; // +0xFF0

    /// Effect name as SSO (Small String Optimization) string.
    /// When length <= 22 bytes, the string data is inline in the object.
    /// The SSO string struct is: { union { char inline[24]; char* ptr; }; u8 length; }
    pub const OFFSET_EFFECT_NAME: usize = 56; // +0x38

    /// Virtual function table pointer.
    /// Each CEffect subclass has its own vtable with Execute/Serialize methods.
    pub const OFFSET_VTABLE: usize = 1704; // +0x6A8
};

/// CEventScope object offsets.
/// CEventScope is passed to effect/trigger execution functions.
/// It provides context about what game object the effect operates on.
pub const c_event_scope = struct {
    /// Scope type as int64_t. Determines which object ID field to use.
    /// See scope_types for known values.
    pub const OFFSET_SCOPE_TYPE: usize = 8; // +8

    /// Object ID field (int64_t). The actual game object identifier.
    /// Only valid when scope_type matches a known type.
    pub const OFFSET_OBJECT_ID: usize = 16; // +16
};

/// Known scope type values for CEventScope.
/// These are bit-flag values representing different game object types.
/// A scope can have multiple types set (e.g., a fleet member is both SHIP and FLEET).
pub const scope_types = struct {
    pub const PLANET: i64 = 2;
    pub const COUNTRY: i64 = 4;
    pub const SHIP: i64 = 8;
    pub const POP: i64 = 16;
    pub const FLEET: i64 = 32;
    pub const GALACTIC_OBJECT: i64 = 64;
    pub const LEADER: i64 = 128;
    pub const ARMY: i64 = 256;
    pub const AMBIENT_OBJECT: i64 = 512;
    pub const SPECIES: i64 = 1024;
    pub const NO_SCOPE: i64 = 1048576;
};

/// Known effect IDs for hardcoded effects.
/// These are the numeric IDs assigned to built-in effects in the engine.
/// Scripted effects get IDs starting from a higher base (typically 4081+).
pub const known_effect_ids = struct {
    // Built-in effect IDs (examples from the dispatch switch at 0x14180B050)
    pub const ADD_MONTHLY_INCOME: i32 = 0;
    pub const SET_NAME: i32 = 1;
    pub const ADD_OPINION: i32 = 2;
    pub const SET_COUNTRY_FLAG: i32 = 10;
    pub const CREATE_FLEET: i32 = 45;
    pub const SET_PLANET_SIZE: i32 = 89;
    pub const ADD_TRAIT: i32 = 156;
    pub const SET_TECHNOLOGY: i32 = 200;

    /// Base ID for scripted effects (first unused hardcoded ID).
    /// Scripted effect IDs are assigned sequentially from this base.
    pub const SCRIPTED_EFFECT_BASE: i32 = 4081;
};

test "offsets are consistent" {
    // Verify that known offsets are within reasonable bounds
    try std.testing.expect(c_effect.OFFSET_EFFECT_ID < 8192);
    try std.testing.expect(c_effect.OFFSET_EFFECT_NAME < 256);
    try std.testing.expect(c_effect.OFFSET_VTABLE < 8192);

    try std.testing.expect(c_event_scope.OFFSET_SCOPE_TYPE < 64);
    try std.testing.expect(c_event_scope.OFFSET_OBJECT_ID < 64);
}

test "scope types are power of 2" {
    // All scope types should be powers of 2 (bit flags)
    const types = [_]i64{
        scope_types.PLANET,
        scope_types.COUNTRY,
        scope_types.SHIP,
        scope_types.POP,
        scope_types.FLEET,
        scope_types.GALACTIC_OBJECT,
        scope_types.LEADER,
        scope_types.ARMY,
        scope_types.AMBIENT_OBJECT,
        scope_types.SPECIES,
    };

    for (types) |t| {
        try std.testing.expect(t > 0);
        try std.testing.expect((t & (t - 1)) == 0); // power of 2 check
    }
}

test "offset values: specific constants" {
    // CEffect offsets
    try std.testing.expectEqual(@as(usize, 4080), c_effect.OFFSET_EFFECT_ID);
    try std.testing.expectEqual(@as(usize, 56), c_effect.OFFSET_EFFECT_NAME);
    try std.testing.expectEqual(@as(usize, 1704), c_effect.OFFSET_VTABLE);

    // CEventScope offsets
    try std.testing.expectEqual(@as(usize, 8), c_event_scope.OFFSET_SCOPE_TYPE);
    try std.testing.expectEqual(@as(usize, 16), c_event_scope.OFFSET_OBJECT_ID);
}

test "scope type values: specific constants" {
    try std.testing.expectEqual(@as(i64, 2), scope_types.PLANET);
    try std.testing.expectEqual(@as(i64, 4), scope_types.COUNTRY);
    try std.testing.expectEqual(@as(i64, 8), scope_types.SHIP);
    try std.testing.expectEqual(@as(i64, 16), scope_types.POP);
    try std.testing.expectEqual(@as(i64, 32), scope_types.FLEET);
    try std.testing.expectEqual(@as(i64, 64), scope_types.GALACTIC_OBJECT);
    try std.testing.expectEqual(@as(i64, 128), scope_types.LEADER);
    try std.testing.expectEqual(@as(i64, 256), scope_types.ARMY);
    try std.testing.expectEqual(@as(i64, 512), scope_types.AMBIENT_OBJECT);
    try std.testing.expectEqual(@as(i64, 1024), scope_types.SPECIES);
    try std.testing.expectEqual(@as(i64, 1048576), scope_types.NO_SCOPE);
}

test "known effect IDs: specific constants" {
    try std.testing.expectEqual(@as(i32, 0), known_effect_ids.ADD_MONTHLY_INCOME);
    try std.testing.expectEqual(@as(i32, 1), known_effect_ids.SET_NAME);
    try std.testing.expectEqual(@as(i32, 2), known_effect_ids.ADD_OPINION);
    try std.testing.expectEqual(@as(i32, 10), known_effect_ids.SET_COUNTRY_FLAG);
    try std.testing.expectEqual(@as(i32, 45), known_effect_ids.CREATE_FLEET);
    try std.testing.expectEqual(@as(i32, 89), known_effect_ids.SET_PLANET_SIZE);
    try std.testing.expectEqual(@as(i32, 156), known_effect_ids.ADD_TRAIT);
    try std.testing.expectEqual(@as(i32, 200), known_effect_ids.SET_TECHNOLOGY);
    try std.testing.expectEqual(@as(i32, 4081), known_effect_ids.SCRIPTED_EFFECT_BASE);
}

test "scope types: no scope is much larger than game object types" {
    try std.testing.expect(scope_types.NO_SCOPE > scope_types.SPECIES);
    try std.testing.expect(scope_types.NO_SCOPE > scope_types.AMBIENT_OBJECT);
    try std.testing.expect(scope_types.NO_SCOPE > scope_types.ARMY);
}

test "scope types: can be combined with bitwise OR" {
    // A fleet member is both SHIP and FLEET
    const combined = scope_types.SHIP | scope_types.FLEET;
    try std.testing.expectEqual(@as(i64, 40), combined); // 8 | 32 = 40
}

test "effect IDs: SCRIPTED_EFFECT_BASE is larger than all built-in IDs" {
    try std.testing.expect(known_effect_ids.SCRIPTED_EFFECT_BASE > known_effect_ids.SET_TECHNOLOGY);
    try std.testing.expect(known_effect_ids.SCRIPTED_EFFECT_BASE > known_effect_ids.ADD_TRAIT);
    try std.testing.expect(known_effect_ids.SCRIPTED_EFFECT_BASE > known_effect_ids.SET_PLANET_SIZE);
}
