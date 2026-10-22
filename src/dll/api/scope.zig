// scope.zig — CEventScope access functions.
//
// Provides read access to CEventScope fields, which define the execution
// context for effects and triggers. The scope tells the engine what game
// object the current operation is targeting.
//
// CEventScope layout — [UNVERIFIED 3.x, and contradicted for the Execute argument]:
//   +0  (0)   — padding / vtable
//   +8  (8)   — claimed scope type (i64, bit flag)
//   +16 (16)  — claimed object ID (i64)
//
// NOT "verified from IDA". §26 disassembled the 4.4.4 base CEffect::Execute (0x1D08520) and found
// [arg2+8] incremented right before `call [vptr+0x10]` and decremented right after — a call-depth
// counter — so the object the engine passes around as its execution frame does not carry a scope type
// at +8. The real 4.4.4 chain reaches a keyword id through [[frame+0x30]+8]+8 (see §26.1).
// Until a genuine frame pointer arrives from the record-only detour, these getters describe an
// unconfirmed layout and their numbers must not be presented as a scope type or object id.
//
// Scope types are power-of-2 bit flags defined in offsets.zig:
//   PLANET=2, COUNTRY=4, SHIP=8, POP=16, FLEET=32, etc.
//
// Thread safety: These functions are read-only and operate on caller-owned
// scope pointers. No shared state is accessed.

const std = @import("std");
const offsets = @import("../shared/offsets.zig");

// ---------------------------------------------------------------------------
// Constants (3.x values, unconfirmed — see the header note before trusting any of them)
// ---------------------------------------------------------------------------

/// Byte offset to the scope type field in CEventScope.
/// UNCONFIRMED LAYOUT — §26 falsified this for the object `CEffect::Execute` receives: `[arg2+8]` there
/// is a call-depth counter. The value is our reader's assumption, not a confirmed 4.4.4 field.
const OFFSET_SCOPE_TYPE: usize = offsets.c_event_scope.OFFSET_SCOPE_TYPE; // 8

/// Byte offset to the object ID field in CEventScope.
/// UNCONFIRMED LAYOUT — never confirmed on 4.4.4 (§26.2 leaves the real frame object undecided); it is
/// 3.x inheritance, not a measured field.
const OFFSET_OBJECT_ID: usize = offsets.c_event_scope.OFFSET_OBJECT_ID; // 16

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Opaque pointer to a CEventScope in engine memory.
pub const ScopeHandle = *anyopaque;

/// Human-readable scope type name (for logging/debug).
pub const ScopeTypeName = enum {
    planet,
    country,
    ship,
    pop,
    fleet,
    galactic_object,
    leader,
    army,
    ambient_object,
    species,
    no_scope,
    unknown,

    /// Convert from numeric scope type bit flag.
    pub fn fromBitFlag(flag: i64) ScopeTypeName {
        if (flag == offsets.scope_types.PLANET) return .planet;
        if (flag == offsets.scope_types.COUNTRY) return .country;
        if (flag == offsets.scope_types.SHIP) return .ship;
        if (flag == offsets.scope_types.POP) return .pop;
        if (flag == offsets.scope_types.FLEET) return .fleet;
        if (flag == offsets.scope_types.GALACTIC_OBJECT) return .galactic_object;
        if (flag == offsets.scope_types.LEADER) return .leader;
        if (flag == offsets.scope_types.ARMY) return .army;
        if (flag == offsets.scope_types.AMBIENT_OBJECT) return .ambient_object;
        if (flag == offsets.scope_types.SPECIES) return .species;
        if (flag == offsets.scope_types.NO_SCOPE) return .no_scope;
        return .unknown;
    }

    /// Get string representation.
    pub fn name(self: ScopeTypeName) []const u8 {
        return switch (self) {
            .planet => "planet",
            .country => "country",
            .ship => "ship",
            .pop => "pop",
            .fleet => "fleet",
            .galactic_object => "galactic_object",
            .leader => "leader",
            .army => "army",
            .ambient_object => "ambient_object",
            .species => "species",
            .no_scope => "no_scope",
            .unknown => "unknown",
        };
    }
};

// ---------------------------------------------------------------------------
// Scope access functions
// ---------------------------------------------------------------------------

/// Read the scope type from a CEventScope.
///
/// UNCONFIRMED LAYOUT — §26 disassembled `0x1D08520` and found the `+8` dword incremented around
/// `call [vptr+0x10]`, so nothing observed so far establishes that this reads a scope type. The caller
/// decides which object to pass; until a real frame pointer arrives, the result is a raw i64 from the
/// caller's frame, not a verified engine field.
///
/// The scope type is a bit flag indicating what kind of game object
/// the scope represents. Multiple flags can be set simultaneously.
///
/// # Arguments
/// * `scope` - Pointer to the CEventScope object
///
/// # Returns
/// The scope type as an i64 bit flag.
pub fn getScopeType(scope: ScopeHandle) i64 {
    const base: [*]const u8 = @ptrCast(scope);
    const type_ptr: *const i64 = @ptrCast(@alignCast(base + OFFSET_SCOPE_TYPE));
    return type_ptr.*;
}

/// Read the object ID from a CEventScope.
///
/// UNCONFIRMED LAYOUT — `+16` is 3.x inheritance that §26 left unconfirmed for 4.4.4; the i64 returned
/// here has not been observed to be an object id on any engine-supplied frame.
///
/// The object ID is the numeric identifier for the game object
/// that the scope is targeting (e.g., planet ID, country ID).
///
/// # Arguments
/// * `scope` - Pointer to the CEventScope object
///
/// # Returns
/// The object ID as an i64.
pub fn getScopeObjectId(scope: ScopeHandle) i64 {
    const base: [*]const u8 = @ptrCast(scope);
    const id_ptr: *const i64 = @ptrCast(@alignCast(base + OFFSET_OBJECT_ID));
    return id_ptr.*;
}

/// Get a human-readable name for the scope type.
///
/// UNCONFIRMED LAYOUT — inherits `getScopeType`'s unconfirmed read, so `.unknown` here cannot
/// distinguish "not a scope type field" from "a scope type we do not enumerate".
///
/// # Arguments
/// * `scope` - Pointer to the CEventScope object
///
/// # Returns
/// The scope type as a ScopeTypeName enum value.
pub fn getScopeTypeName(scope: ScopeHandle) ScopeTypeName {
    const type_val = getScopeType(scope);
    return ScopeTypeName.fromBitFlag(type_val);
}

/// Check if the scope has a specific type flag set.
///
/// UNCONFIRMED LAYOUT — bit-masks whatever `getScopeType` read, so a `true` here is consistent with
/// our own constants but is not evidence that the frame carries a scope-type field at all.
///
/// # Arguments
/// * `scope` - Pointer to the CEventScope object
/// * `type_flag` - The type flag to check (from offsets.scope_types)
///
/// # Returns
/// true if the flag is set.
pub fn hasScopeType(scope: ScopeHandle, type_flag: i64) bool {
    const scope_type = getScopeType(scope);
    return (scope_type & type_flag) != 0;
}

// =============================================================================
// Tests
// =============================================================================

test "getScopeType: reads from memory" {
    // Create a mock CEventScope in memory
    var mock_scope: [64]u8 align(8) = [_]u8{0} ** 64;

    // Set scope type at offset 8 (COUNTRY = 4)
    const type_val: i64 = offsets.scope_types.COUNTRY;
    const type_bytes = std.mem.toBytes(type_val);
    @memcpy(mock_scope[OFFSET_SCOPE_TYPE .. OFFSET_SCOPE_TYPE + 8], &type_bytes);

    const scope_type = getScopeType(&mock_scope);
    try std.testing.expectEqual(@as(i64, 4), scope_type);
}

test "getScopeObjectId: reads from memory" {
    var mock_scope: [64]u8 align(8) = [_]u8{0} ** 64;

    // Set object ID at offset 16
    const id_val: i64 = 42;
    const id_bytes = std.mem.toBytes(id_val);
    @memcpy(mock_scope[OFFSET_OBJECT_ID .. OFFSET_OBJECT_ID + 8], &id_bytes);

    const object_id = getScopeObjectId(&mock_scope);
    try std.testing.expectEqual(@as(i64, 42), object_id);
}

test "getScopeTypeName: correct mapping" {
    var mock_scope: [64]u8 align(8) = [_]u8{0} ** 64;

    // Test PLANET
    const planet_bytes = std.mem.toBytes(@as(i64, offsets.scope_types.PLANET));
    @memcpy(mock_scope[OFFSET_SCOPE_TYPE .. OFFSET_SCOPE_TYPE + 8], &planet_bytes);
    try std.testing.expectEqual(ScopeTypeName.planet, getScopeTypeName(&mock_scope));

    // Test COUNTRY
    const country_bytes = std.mem.toBytes(@as(i64, offsets.scope_types.COUNTRY));
    @memcpy(mock_scope[OFFSET_SCOPE_TYPE .. OFFSET_SCOPE_TYPE + 8], &country_bytes);
    try std.testing.expectEqual(ScopeTypeName.country, getScopeTypeName(&mock_scope));

    // Test POP
    const pop_bytes = std.mem.toBytes(@as(i64, offsets.scope_types.POP));
    @memcpy(mock_scope[OFFSET_SCOPE_TYPE .. OFFSET_SCOPE_TYPE + 8], &pop_bytes);
    try std.testing.expectEqual(ScopeTypeName.pop, getScopeTypeName(&mock_scope));
}

test "hasScopeType: bit flag check" {
    var mock_scope: [64]u8 align(8) = [_]u8{0} ** 64;

    // Set scope type to COUNTRY (4)
    const type_bytes = std.mem.toBytes(@as(i64, offsets.scope_types.COUNTRY));
    @memcpy(mock_scope[OFFSET_SCOPE_TYPE .. OFFSET_SCOPE_TYPE + 8], &type_bytes);

    try std.testing.expect(hasScopeType(&mock_scope, offsets.scope_types.COUNTRY));
    try std.testing.expect(!hasScopeType(&mock_scope, offsets.scope_types.PLANET));
    try std.testing.expect(!hasScopeType(&mock_scope, offsets.scope_types.SHIP));
}

test "hasScopeType: multiple flags" {
    var mock_scope: [64]u8 align(8) = [_]u8{0} ** 64;

    // Set scope type to COUNTRY | PLANET (4 | 2 = 6)
    const combined: i64 = offsets.scope_types.COUNTRY | offsets.scope_types.PLANET;
    const type_bytes = std.mem.toBytes(combined);
    @memcpy(mock_scope[OFFSET_SCOPE_TYPE .. OFFSET_SCOPE_TYPE + 8], &type_bytes);

    try std.testing.expect(hasScopeType(&mock_scope, offsets.scope_types.COUNTRY));
    try std.testing.expect(hasScopeType(&mock_scope, offsets.scope_types.PLANET));
    try std.testing.expect(!hasScopeType(&mock_scope, offsets.scope_types.SHIP));
}

test "ScopeTypeName.fromBitFlag: unknown type" {
    const unknown_type = ScopeTypeName.fromBitFlag(999999);
    try std.testing.expectEqual(ScopeTypeName.unknown, unknown_type);
}

test "ScopeTypeName.name: correct strings" {
    try std.testing.expectEqualStrings("planet", ScopeTypeName.planet.name());
    try std.testing.expectEqualStrings("country", ScopeTypeName.country.name());
    try std.testing.expectEqualStrings("ship", ScopeTypeName.ship.name());
    try std.testing.expectEqualStrings("pop", ScopeTypeName.pop.name());
    try std.testing.expectEqualStrings("unknown", ScopeTypeName.unknown.name());
}

// 这条测试把两个常量与 offsets.c_event_scope 里的定义绑在一起,防止两边的数值各自漂移。
// 它不主张引擎的字段布局 —— §26 已证伪「+8 是 scope type」;这里断言的是「我们的读法匹配我们自己的
// 常量」,不是 4.4.4 的事实。数值 8/16 保持原样,要改它们的人必须先拿到实机帧指针(roadmap 段4)。
test "c_event_scope: our reader matches our own constants (layout unconfirmed, §26)" {
    try std.testing.expectEqual(@as(usize, 8), OFFSET_SCOPE_TYPE);
    try std.testing.expectEqual(@as(usize, 16), OFFSET_OBJECT_ID);
}
