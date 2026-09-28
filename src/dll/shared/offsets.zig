// offsets.zig — Engine constants for Stellaris 4.4.4 (x86_64-windows).
//
// Values fall into two tiers, marked on each item:
//   [VERIFIED 4.4.4] — confirmed by live Frida scan + disasm (see
//                      evidence/xrefs/anchors_4_4_4.md and
//                      evidence/analysis/runtime_444_structures.md).
//   [UNVERIFIED 3.x] — inherited from 3.x analysis, not reconfirmed for 4.4.4.
//                      Do NOT use for patching until runtime-verified.
//
// All addresses are module-relative RVAs: absolute = runtime base + RVA.
// The engine stores DB root pointers as ABSOLUTE addresses into its own
// low-address arena — never add the module base to a dereferenced global.

const std = @import("std");

/// Scripted effect/trigger lookup entry points and BST layout.
/// This is the real 4.4.4 extension surface (there is no central dispatch switch).
pub const scripted_db = struct {
    /// GetScriptedEffect(name): walks the effect BST, logs misses via scriptedeffect.cpp:33.
    pub const RVA_GET_SCRIPTED_EFFECT: usize = 0x89F960; // [VERIFIED 4.4.4]
    /// GetScriptedTrigger(name): twin of the effect lookup (scriptedtrigger.cpp:18).
    pub const RVA_GET_SCRIPTED_TRIGGER: usize = 0x8A0450; // [VERIFIED 4.4.4]

    /// Globals holding ABSOLUTE arena pointers to the DB objects.
    pub const RVA_EFFECT_DB_GLOBAL: usize = 0x33746E8; // [VERIFIED 4.4.4]
    pub const RVA_TRIGGER_DB_GLOBAL: usize = 0x32611C8; // [VERIFIED 4.4.4]

    /// Offset of the std::map head-sentinel pointer inside the DB object.
    pub const EFFECT_DB_HEAD_PTR: usize = 0x18; // [VERIFIED 4.4.4]
    pub const TRIGGER_DB_HEAD_PTR: usize = 0x88; // [VERIFIED 4.4.4]

    /// MSVC std::map _Tree_node layout. Confirmed by in-order walk yielding
    /// ascending keys (146, 227, 10000, 10001, ...) on the live effect DB.
    pub const NODE_LEFT: usize = 0x00;
    pub const NODE_PARENT: usize = 0x08; // the head's PARENT field is the tree root
    pub const NODE_RIGHT: usize = 0x10;
    pub const NODE_COLOR: usize = 0x18;
    pub const NODE_ISNIL: usize = 0x19;
    pub const NODE_KEY: usize = 0x20; // uint32 id/hash
    pub const NODE_VALUE: usize = 0x28; // pointer to the entry descriptor

    /// Effect DB object: u64 entry count at +0x20 (observed 1056 at 4.4.4 menu).
    pub const EFFECT_DB_SIZE: usize = 0x20;

    /// Scripted-effect template descriptor built by the lookup ctor path.
    pub const RVA_EFFECT_TEMPLATE_VTABLE: usize = 0x24B1990; // [VERIFIED 4.4.4]
    pub const TEMPLATE_VTABLE: usize = 0x00;
    pub const TEMPLATE_ID: usize = 0x08; // u32
    // std::string (SSO): ptr union at +0x10, size +0x20, capacity +0x28.
    // Exact base still [TBD] — string fragments confirmed present near this
    // offset but not yet cleanly decoded.
    pub const TEMPLATE_NAME: usize = 0x10;
};

/// CEffect object offsets.
/// [UNVERIFIED 3.x] 4.4.4 has NO central dispatch switch — effects are polymorphic
/// CEffect::Execute via vtable call (evidence/analysis/runtime_444_structures.md).
/// These offsets were never runtime-confirmed and must not be trusted for patching.
pub const c_effect = struct {
    pub const OFFSET_EFFECT_ID: usize = 4080; // +0xFF0 [UNVERIFIED 3.x]
    pub const OFFSET_EFFECT_NAME: usize = 56; // +0x38 [UNVERIFIED 3.x]
    pub const OFFSET_VTABLE: usize = 1704; // +0x6A8 [UNVERIFIED 3.x]
};

/// CEventScope object offsets.
/// [UNVERIFIED 3.x] AGENTS.md 3.x notes say objectid at +12 while code used +16.
/// Unresolved discrepancy — reconfirm against a live CEventScope before use.
pub const c_event_scope = struct {
    pub const OFFSET_SCOPE_TYPE: usize = 8; // +8 [UNVERIFIED 3.x]
    pub const OFFSET_OBJECT_ID: usize = 16; // +16 [UNVERIFIED 3.x]
};

/// Known scope type values for CEventScope (power-of-2 bit flags).
/// [UNVERIFIED 3.x] from stellarstellaris-win; not reconfirmed on 4.4.4.
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

/// Base for scripted-entry id allocation.
/// [UNVERIFIED] observed live keys are NOT a clean range: the effect DB contains
/// both small ids (146, 227) and 10000+ entries. New registrations must
/// collision-check against the live BST rather than assume this base is a
/// contiguous free space.
pub const known_effect_ids = struct {
    pub const SCRIPTED_EFFECT_BASE: i32 = 10000;
};

test "scripted_db layout: 4.4.4 verified bounds" {
    try std.testing.expect(scripted_db.NODE_VALUE > scripted_db.NODE_KEY);
    try std.testing.expect(scripted_db.RVA_GET_SCRIPTED_EFFECT < 0x2392000); // inside .text
    try std.testing.expect(scripted_db.RVA_GET_SCRIPTED_TRIGGER < 0x2392000);
    try std.testing.expect(scripted_db.RVA_EFFECT_DB_GLOBAL > 0x2954000); // inside .data/.rdata
    try std.testing.expect(scripted_db.RVA_TRIGGER_DB_GLOBAL > 0x2954000);
    try std.testing.expectEqual(@as(usize, 0x89F960), scripted_db.RVA_GET_SCRIPTED_EFFECT);
    try std.testing.expectEqual(@as(usize, 0x8A0450), scripted_db.RVA_GET_SCRIPTED_TRIGGER);
}

test "offsets are within reasonable bounds" {
    try std.testing.expect(c_effect.OFFSET_EFFECT_ID < 8192);
    try std.testing.expect(c_effect.OFFSET_EFFECT_NAME < 256);
    try std.testing.expect(c_effect.OFFSET_VTABLE < 8192);

    try std.testing.expect(c_event_scope.OFFSET_SCOPE_TYPE < 64);
    try std.testing.expect(c_event_scope.OFFSET_OBJECT_ID < 64);
}

test "scope types are power of 2" {
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
        try std.testing.expect((t & (t - 1)) == 0);
    }
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

test "scope types: no scope is much larger than game object types" {
    try std.testing.expect(scope_types.NO_SCOPE > scope_types.SPECIES);
    try std.testing.expect(scope_types.NO_SCOPE > scope_types.AMBIENT_OBJECT);
    try std.testing.expect(scope_types.NO_SCOPE > scope_types.ARMY);
}

test "scope types: can be combined with bitwise OR" {
    const combined = scope_types.SHIP | scope_types.FLEET;
    try std.testing.expectEqual(@as(i64, 40), combined); // 8 | 32
}
