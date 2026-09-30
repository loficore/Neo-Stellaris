// offsets.zig — Engine constants for Stellaris 4.4.4 (x86_64-windows).
//
// Values fall into two tiers, marked on each item:
//   [VERIFIED 4.4.4] — confirmed by live Frida scan + disasm (see
//                      evidence/xrefs/anchors_4_4_4.md and the three evidence volumes
//                      evidence/analysis/runtime_444_*.md, §1–§29).
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
    /// GetScriptedEffect: builds the ref object at `rcx` and WARNS when the name's
    /// token id is already in the effect BST ("scripted effect %s is overwriting an
    /// existing effect, rename it", scriptedeffect.cpp:33). It is not a getter whose
    /// result distinguishes hit from miss — see `scripted_lookup` below and §27.
    pub const RVA_GET_SCRIPTED_EFFECT: usize = 0x89F960; // [VERIFIED 4.4.4]
    /// GetScriptedTrigger: exact twin (scriptedtrigger.cpp:18).
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

/// What the two `GetScripted*` entry points actually do, field by field.
/// [VERIFIED 4.4.4 STATIC] `scripts/disrva.py 0x89F960` / `0x8A0450` / `0x1D7CE0`,
/// written up as §27 in evidence/analysis/runtime_444_c1_validation.md.
/// This block exists because the old reading of these two functions — "the lookup,
/// hit vs miss judged from the out object" — is falsified: the out object is filled
/// with CONSTANT vtables on every call, and the only thing that varies is whether the
/// duplicate-registration warning fires.
pub const scripted_lookup = struct {
    /// Calling convention, measured from the prologue (`lea rdi,[r8+0x10]`,
    /// `cmp qword[rdi+0x18],0x10`): `rcx` = out ref, `edx` = requested id (-1 = by
    /// name), `r8` = a holder whose std::wstring sits at `r8+0x10` — the same
    /// chars +0x10 / size +0x20 / cap +0x28 shape as §20's token-name holder.
    pub const HOLDER_STRING_OFFSET: usize = 0x10;
    /// Bytes of `out` the caller zeroes before the call (0x1D7D48: `0x2188170(out, 0, 0x118)`).
    pub const REF_SIZE: usize = 0x118;

    /// vtable both functions write to `out+0x00` (after briefly writing
    /// `scripted_db.RVA_EFFECT_TEMPLATE_VTABLE` there at 0x89F9CE / 0x8A04BE).
    pub const RVA_REF_VTABLE: usize = 0x25180A8;
    /// vtable both write to `out+0x40`: slot[1] of this one IS base `CEffect::Execute`
    /// (0x1D08520), so `+0x40` is an embedded CEffect sub-object — not a name string.
    pub const RVA_REF_CEFFECT_VTABLE: usize = 0x2518128;
    /// The pair the sentinel caller 0x1D7CE0 overwrites `out+0x00`/`out+0x40` with
    /// AFTER the call to force an empty ref. Neither lookup ever writes these, so
    /// "out holds the null-template vtable" is not evidence of a miss.
    pub const RVA_NULL_REF_VTABLE: usize = 0x24B9E80;
    pub const RVA_NULL_CEFFECT_VTABLE: usize = 0x24B9E40;

    /// Name → token id, resolved inside the lookups: `0x1D12C60()` then
    /// `call [[token_db]+0x10](token_db, chars)`. When that returns null the walk
    /// searches for this fixed key instead (0x89FA95 / 0x8A0585: `mov edx, 0xc`).
    /// 12 is a hole in the 9,863-entry descriptor table and absent from both keyword
    /// dbs, so an unminted name cannot raise the warning by accident.
    pub const UNMINTED_SEARCH_KEY: u32 = 12;

    /// The duplicate-registration warning, emitted through this logger when the
    /// `_Lbound` walk lands on a node whose key equals the name's token id.
    pub const RVA_LOG: usize = 0x1C91C30;
    pub const RVA_EFFECT_OVERWRITE_MSG: usize = 0x2518190; // "scripted effect %s is overwriting an existing effect, rename it"
    pub const RVA_TRIGGER_OVERWRITE_MSG: usize = 0x2518270; // "scripted trigger %s is overwriting an existing trigger, rename it"
    pub const RVA_EFFECT_SOURCE_FILE: usize = 0x25181D0; // ...\source\scriptedeffect.cpp, line 0x21 = 33
    pub const RVA_TRIGGER_SOURCE_FILE: usize = 0x25182C0; // ...\source\scriptedtrigger.cpp, line 0x12 = 18
};

/// Registration surface for a genuinely new hardcoded keyword — PLAN.md §6 C0/C1.
/// Every item here is [VERIFIED 4.4.4 STATIC]: read off the shipped exe with
/// `scripts/disrva.py`, field-by-field in evidence/analysis/runtime_444_keyword_pipeline.md §20.
/// None of it has been observed in a running process, which is what C1 is for.
pub const keyword_reg = struct {
    /// GetOrAddToken: `eax = 0x1D13270(rcx = *TokenNameHolder)`, rdx is dead (§20).
    /// Returns 0 when the name starts with '-' or a digit.
    pub const RVA_GET_OR_ADD_TOKEN: usize = 0x1D13270; // [VERIFIED 4.4.4]
    /// Meyers accessor for the token DB singleton; called by the allocator itself,
    /// so a caller does NOT have to construct anything first.
    pub const RVA_TOKEN_DB_ACCESSOR: usize = 0x1D12C60; // [VERIFIED 4.4.4]
    pub const RVA_TOKEN_DB_OBJECT: usize = 0x37347A0; // [VERIFIED 4.4.4]
    /// Shared slot writer: `0x1D158A0(rcx = slot, edx = id, r8 = chars, r9 = len)`.
    /// Both the compile-time driver and the runtime allocator funnel through it,
    /// which is the proof that a dynamic descriptor is shaped like a static one.
    pub const RVA_SLOT_WRITER: usize = 0x1D158A0; // [VERIFIED 4.4.4]
    /// Effect DB lazy ctor: `rax = 0x3AEBA0(new(0x70))` — a placement ctor over the
    /// block the CALLER allocated (thunk `0x1045B0`). Returns `this`.
    pub const RVA_DB_LAZY_CTOR: usize = 0x3AEBA0; // [VERIFIED 4.4.4]
    pub const EFFECT_DB_OBJECT_SIZE: u64 = 0x70; // [VERIFIED 4.4.4]
    /// BST insert: `0x3AEF60(rcx = db, edx = token id, r8 = *value_record)`.
    /// Keys on the raw 32-bit id with no range check (§18); walks `db + 0x18`.
    pub const RVA_BST_INSERT: usize = 0x3AEF60; // [VERIFIED 4.4.4]

    /// The TRIGGER db is NOT the same function pair. Thunk `0x100260`
    /// (`num_ships_in_debris`, token 11100) calls a no-arg ensure that `new(0x98)`s the
    /// object and publishes `[0x32611C8]` itself, then a twin insert walking `db + 0x88`.
    /// Sharing the effect insert here would key the wrong tree, so both pairs are pinned
    /// per-db rather than factored into one.
    pub const RVA_TRIGGER_DB_ENSURE: usize = 0x347BD0; // [VERIFIED 4.4.4]
    pub const RVA_TRIGGER_BST_INSERT: usize = 0x348150; // [VERIFIED 4.4.4]
    pub const TRIGGER_DB_OBJECT_SIZE: u64 = 0x98; // [VERIFIED 4.4.4]
    /// Base CEffect::Execute; dispatches `call [rax+0x10]` = instance vtable slot[2].
    pub const RVA_BASE_EXECUTE: usize = 0x1D08520; // [VERIFIED 4.4.4]

    /// `new(size)` / `delete(p)` — engine-side allocator, same one the registration
    /// thunks use (`0x2185218`). The thunks write the size into `ecx`, but the wrapper
    /// keeps the full `rcx` and forwards it, so pass a zero-extended u64: a u32 first
    /// parameter leaves the upper half undefined.
    pub const RVA_OPERATOR_NEW: usize = 0x2185218; // [VERIFIED 4.4.4]

    /// Token descriptor stride — both the 9,863-entry static array at `0x337B400`
    /// and every `new(0x120)` the allocator performs.
    pub const TOKEN_STRIDE: usize = 0x120; // [VERIFIED 4.4.4]
    pub const TOKEN_ID: usize = 0x00; // u32, written by 0x1D158A0
    pub const TOKEN_FLAG: usize = 0x04; // u8, always 0; +0x05..+0x07 are NEVER written
    pub const TOKEN_STR_VTABLE: usize = 0x08; // u64 -> RVA 0x247B078 (cstr vtable)
    pub const TOKEN_STR_BUF_PTR: usize = 0x10; // u64 -> the 0x120 block + 0x20
    pub const TOKEN_STR_CAP: usize = 0x18; // u32, 0x100
    pub const TOKEN_STR_SIZE: usize = 0x1C; // u32, strlen INCLUDING the terminator
    pub const TOKEN_STR_INLINE: usize = 0x20; // 0x100 bytes, name + NUL
    pub const RVA_CSTR_VTABLE: usize = 0x247B078; // [VERIFIED 4.4.4]

    /// MSVC `std::string` inside the name holder passed to GetOrAddToken.
    pub const HOLDER_NAME: usize = 0x10; // {chars at +0x10, size at +0x20, cap at +0x28}
    pub const HOLDER_SIZE: usize = 0x38; // observed stride between .data holder objects
    pub const HOLDER_STR_SIZE: usize = 0x20; // _Mysize
    pub const HOLDER_STR_CAP: usize = 0x28; // _Myres
    pub const SSO_MAX: usize = 0x0F; // cap < 0x10 keeps the chars inline

    /// The 16-byte BST value record a registration thunk builds: `{&class_info, &docstring}`.
    pub const VALUE_RECORD_SIZE: usize = 0x10;
    pub const VALUE_CLASS_INFO: usize = 0x00;
    pub const VALUE_DOCSTRING: usize = 0x08;

    /// 16-byte record `{deleter, create}` (worked example: `0x260ABD8`). NOT `{ctor, factory}` —
    /// the first field is a shared scalar deleting destructor, see §22.2.
    pub const CLASS_INFO_SIZE: usize = 0x10;
    pub const CLASS_INFO_DELETER: usize = 0x00;
    pub const CLASS_INFO_CREATE: usize = 0x08;
    /// The deleter every one of the 1,605 keyword class_infos uses. It frees a 0x10 block, which is
    /// `VALUE_RECORD_SIZE` — the record it is handed — so reusing it is sound only while step 2 keeps
    /// allocating 0x10. `create` takes no arguments in all 1,605 cases and returns the object in rax.
    pub const RVA_CLASS_INFO_DELETER: usize = 0x34C090; // [VERIFIED 4.4.4] §22

    /// The engine's own instantiation entry points — §23. These are the code that walks the db BST
    /// and calls `create`, found by shape (`scripts/createsites.py`) intersected with the db-global
    /// readers (`scripts/riprefs.py`), because `create` has zero address-xrefs by construction.
    /// `(ctx, parse_ctx, r8d = token id, ...)`; they read the db global, lazy-ctor it if null, walk
    /// the map, and on a hit call `[value_record[0] + 0x8]`.
    pub const RVA_EFFECT_INSTANTIATE: usize = 0x3B01A0; // [VERIFIED 4.4.4] §23
    pub const RVA_TRIGGER_INSTANTIATE: usize = 0x349AE0; // [VERIFIED 4.4.4] §23
    /// Whole-tree enumerators that also call `create`, one per node, then two virtuals on the
    /// result (`0x3AF130`/`0x348450`, called from `0x1BFD30`). Registering a keyword is therefore
    /// NOT inert: this path will construct whatever our `create` returns.
    pub const RVA_EFFECT_DB_DUMP: usize = 0x3AF130; // [VERIFIED 4.4.4] §23
    pub const RVA_TRIGGER_DB_DUMP: usize = 0x348450; // [VERIFIED 4.4.4] §23

    /// MSVC `_Tree` node layout the walk above reads. Node is `new(0x30)` (§21); the comparator is
    /// an inlined plain u32 `cmp`, so no key ever reaches a callback.
    pub const NODE_LEFT: usize = 0x00;
    pub const NODE_PARENT: usize = 0x08;
    pub const NODE_RIGHT: usize = 0x10;
    pub const NODE_ISNIL: usize = 0x19; // byte, alongside _Color at 0x18
    pub const NODE_KEY: usize = 0x20; // u32 token id
    pub const NODE_VALUE: usize = 0x28; // the VALUE_RECORD

    /// Fields the instantiate path writes into the object `create` returned, before it calls any
    /// virtual on it. The two dbs disagree here, which is why both are pinned.
    pub const EFFECT_OBJECT_TOKEN_ID: usize = 0x20;
    pub const EFFECT_OBJECT_NAME: usize = 0x28;
    pub const TRIGGER_OBJECT_TOKEN_ID: usize = 0x38;
    pub const TRIGGER_OBJECT_NAME: usize = 0x40;

    /// vtable slots the instantiate path calls on the created object. A `create` that returns an
    /// object without valid entries here does not degrade quietly — it is a call through null.
    /// `0x3B01A0` calls `+0x98` (a bool predicate whose base impl is `0x3B1420`), then `+0x78`.
    pub const EFFECT_VTBL_INSTANTIATE_PREDICATE: usize = 0x98;
    pub const TRIGGER_VTBL_READ: usize = 0x80; // triggers, bool in al
    /// The recursive effect-tree parse lives at `+0x70` (base impl `0x3B1330`, which is the only
    /// thing in the whole 1,581-vtable census that ever holds it — 723/723 at that exact offset).
    /// `0x3B01A0` does NOT call this slot; §23.1 originally conflated the two.
    pub const EFFECT_VTBL_READ_CHILDREN: usize = 0x70;

    /// §24 — C1 borrows an official `class_info` instead of fabricating an object, so these two
    /// donors are data, not code we write. Aliasing is a shape the shipped game already uses: 9
    /// keyword `class_info`s serve 2-3 token ids each (`if`/`else_if`/`else` on `0x269DC98`), every
    /// `create` body stays unique, and all 1,605 share the deleter `RVA_CLASS_INFO_DELETER`. Each
    /// keyword still gets its OWN `new(0x10)` value record, so no block is freed twice.
    /// Smallest objects on each side; both verified against the slots above by reading raw qwords.
    pub const DONOR_TRIGGER_CLASS_INFO: usize = 0x269CAA8; // has_crisis_perk + has_menace_perk, new(0x80)
    pub const DONOR_EFFECT_CLASS_INFO: usize = 0x2611070; // hidden_effect, new(0xc0)
    pub const DONOR_TRIGGER_CREATE: usize = 0x1B30450; // [VERIFIED 4.4.4] §24.3
    pub const DONOR_EFFECT_CREATE: usize = 0x1893130; // [VERIFIED 4.4.4] §24.3
    pub const DONOR_TRIGGER_VTABLE: usize = 0x268ED08; // covers +0x78 = 0x1B4550, +0x80 = 0x349230
    pub const DONOR_EFFECT_VTABLE: usize = 0x2606FE0; // covers +0x78 = 0x1596B0, +0x98 = 0x3B1420

    /// §24.6 — the value record's `+8` docstring, chosen conservatively: reuse the donor's OWN
    /// official `.rdata` string instead of shipping one from our DLL. The engine keeps this pointer
    /// for the lifetime of the db (the enumerate paths `0x3AF130`/`0x348450` read every node), and a
    /// DLL-resident string would dangle on FreeLibrary. The trade is documented, not hidden: the two
    /// keywords that already alias `0x269CAA8` carry *different* docstrings (`0x26C1BA0` vs
    /// `0x26C1B40`), so per-keyword text is the shipped shape and reusing the donor's is a cosmetic
    /// deviation — the cost is a wrong tooltip line, the alternative's is a use-after-free. Which of the
    /// donor's own two lines is picked is arbitrary (neither describes an aliased keyword); only that it
    /// addresses the exe image and stays stable matters.
    pub const DONOR_TRIGGER_DOCSTRING: usize = 0x26C1BA0; // "Checks if a country has a specific Crisis Perk unlocked."
    pub const DONOR_EFFECT_DOCSTRING: usize = 0x2616260; // "Prevents enclosed effects from being displayed in tooltip"
};

/// CEffect object offsets.
/// [FALSIFIED 3.x] 4.4.4 has NO central dispatch switch — effects are polymorphic
/// CEffect::Execute via vtable call (evidence/analysis/runtime_444_structures.md).
/// §26 additionally falsifies `OFFSET_VTABLE`: the factory publishes the vptr at `[obj+0]` in
/// 1,605/1,605 keyword classes, so nothing lives at +0x6A8 as a vtable pointer.
/// These were never runtime-confirmed and must not be used for patching.
pub const c_effect = struct {
    pub const OFFSET_EFFECT_ID: usize = 4080; // +0xFF0 [UNVERIFIED 3.x]
    pub const OFFSET_EFFECT_NAME: usize = 56; // +0x38 [UNVERIFIED 3.x]
    pub const OFFSET_VTABLE: usize = 1704; // +0x6A8 [FALSIFIED 3.x, §26/§24.4]
};

/// CEventScope object offsets.
/// [FALSIFIED for the Execute argument — §26] `0x1D08520` increments `[arg2+8]` immediately before
/// `call [vptr+0x10]` and decrements it right after, so on the object Execute actually receives that
/// dword is a call-depth counter, not a scope type. `api/scope.zig` reads `+8`/`+16` off a caller
/// supplied pointer and is linked into the DLL, so until a real frame pointer is handed to it from the
/// record-only detour, its numbers are not a scope type and object id — they are whatever the caller's
/// frame happens to hold. The 3.x `+12` vs code `+16` discrepancy is moot until then.
pub const c_event_scope = struct {
    pub const OFFSET_SCOPE_TYPE: usize = 8; // +8 [FALSIFIED for Execute's arg2, §26]
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

/// Lowest live id observed in the effect BST.
/// [OBSERVED, no consumer] live keys are NOT a clean range: the effect DB holds both small ids
/// (146, 227) and 10000+ entries. Kept as the measurement record only — nothing allocates from
/// this base any more, because C1 does not hand-pick ids: the engine's own `0x1D13270` mints them
/// (`id = [db+0x64] + [db+0x84] + 1`, §18/§19) and neither BST insert range-checks its key (§23).
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

test "scripted_lookup: the §27 constants are distinct and non-code" {
    const L = scripted_lookup;
    // Filled by the lookups vs installed afterwards by the sentinel — four different
    // addresses, and the difference is the whole point of §27.
    try std.testing.expect(L.RVA_REF_VTABLE != L.RVA_NULL_REF_VTABLE);
    try std.testing.expect(L.RVA_REF_CEFFECT_VTABLE != L.RVA_NULL_CEFFECT_VTABLE);
    try std.testing.expect(L.RVA_REF_VTABLE != L.RVA_REF_CEFFECT_VTABLE);
    // All four are .rdata, i.e. above the end of .text (0x2391710).
    for ([_]usize{ L.RVA_REF_VTABLE, L.RVA_REF_CEFFECT_VTABLE, L.RVA_NULL_REF_VTABLE, L.RVA_NULL_CEFFECT_VTABLE }) |vtable_rva| {
        try std.testing.expect(vtable_rva > 0x2392000);
    }
    for ([_]usize{ L.RVA_EFFECT_OVERWRITE_MSG, L.RVA_TRIGGER_OVERWRITE_MSG, L.RVA_EFFECT_SOURCE_FILE, L.RVA_TRIGGER_SOURCE_FILE }) |data_rva| {
        try std.testing.expect(data_rva > 0x2392000);
    }
    try std.testing.expect(L.RVA_LOG < 0x2392000); // the logger is code
    try std.testing.expectEqual(@as(u32, 12), L.UNMINTED_SEARCH_KEY);
    try std.testing.expectEqual(@as(usize, 0x10), L.HOLDER_STRING_OFFSET);
    try std.testing.expectEqual(@as(usize, 0x118), L.REF_SIZE);
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

test "keyword_reg: descriptor fills the stride exactly" {
    try std.testing.expectEqual(@as(usize, 0x20), keyword_reg.TOKEN_STR_INLINE);
    try std.testing.expectEqual(keyword_reg.TOKEN_STRIDE, keyword_reg.TOKEN_STR_INLINE + 0x100);
    try std.testing.expectEqual(keyword_reg.TOKEN_STR_SIZE, keyword_reg.TOKEN_STR_CAP + 4); // adjacent u32s
}

test "keyword_reg: anchors land in the sections they were read from" {
    const text_end: usize = 0x2392000; // .text, per the §10 PE section table
    try std.testing.expect(keyword_reg.RVA_GET_OR_ADD_TOKEN < text_end);
    try std.testing.expect(keyword_reg.RVA_TOKEN_DB_ACCESSOR < text_end);
    try std.testing.expect(keyword_reg.RVA_SLOT_WRITER < text_end);
    try std.testing.expect(keyword_reg.RVA_BST_INSERT < text_end);
    try std.testing.expect(keyword_reg.RVA_BASE_EXECUTE < text_end);
    // Data globals, not code — must NOT be confused with the .text range.
    try std.testing.expect(keyword_reg.RVA_TOKEN_DB_OBJECT > text_end);
    try std.testing.expect(keyword_reg.RVA_CSTR_VTABLE > text_end);
    try std.testing.expect(keyword_reg.RVA_CSTR_VTABLE < keyword_reg.RVA_TOKEN_DB_OBJECT);
}

test "keyword_reg: the two dbs are separate function pairs, not one shared pair" {
    // Found while wiring the executor. The trigger thunks do NOT tail into the effect insert:
    // `0x100260` (num_ships_in_debris) calls `0x347BD0` then `jmp 0x348150`, while `0x1045B0`
    // (add_modifier) inlines `new(0x70)` + `0x3AEBA0` then `jmp 0x3AEF60`. Reusing the effect
    // insert for a trigger would key the wrong tree, so both halves are pinned per db.
    try std.testing.expectEqual(@as(usize, 0x3AEF60), keyword_reg.RVA_BST_INSERT);
    try std.testing.expectEqual(@as(usize, 0x348150), keyword_reg.RVA_TRIGGER_BST_INSERT);
    try std.testing.expectEqual(@as(usize, 0x347BD0), keyword_reg.RVA_TRIGGER_DB_ENSURE);
    try std.testing.expect(keyword_reg.RVA_TRIGGER_DB_ENSURE != keyword_reg.RVA_DB_LAZY_CTOR);
    try std.testing.expectEqual(@as(u64, 0x70), keyword_reg.EFFECT_DB_OBJECT_SIZE);
    try std.testing.expectEqual(@as(u64, 0x98), keyword_reg.TRIGGER_DB_OBJECT_SIZE);
    // Each insert derefs exactly the map field the lookups already recorded: `0x3AEF60`
    // does `lea rdi, [rcx + 0x18]`, `0x348150` does `lea rdi, [rcx + 0x88]`.
    try std.testing.expectEqual(@as(usize, 0x18), scripted_db.EFFECT_DB_HEAD_PTR);
    try std.testing.expectEqual(@as(usize, 0x88), scripted_db.TRIGGER_DB_HEAD_PTR);
}

test "keyword_reg: class_info is {deleter, create} and the deleter frees the value record" {
    // §22.2: `0x34C090` — the field0 every one of the 1,605 keyword class_infos shares — ends with
    // `mov edx, 0x10; call 0x2185254`. The 0x10 is the size of the block it frees, which is the
    // value record, not the effect object. So reusing it is only sound while step 2 allocates 0x10;
    // this test is the guard against raising VALUE_RECORD_SIZE without noticing.
    try std.testing.expectEqual(@as(usize, 0x00), keyword_reg.CLASS_INFO_DELETER);
    try std.testing.expectEqual(@as(usize, 0x08), keyword_reg.CLASS_INFO_CREATE);
    try std.testing.expectEqual(keyword_reg.VALUE_RECORD_SIZE, keyword_reg.CLASS_INFO_SIZE);
    // The deleter is code, and it is not one of the two inserts.
    try std.testing.expect(keyword_reg.RVA_CLASS_INFO_DELETER < 0x2392000);
    try std.testing.expect(keyword_reg.RVA_CLASS_INFO_DELETER != keyword_reg.RVA_BST_INSERT);
}

test "keyword_reg: the instantiate path's node layout agrees with the pinned heads" {
    // §23 is the consumer side of §21's producer side, and the two were found independently:
    // `0x3B01A0` walks `[[0x33746E8] + 0x18]` and `0x349AE0` walks `[[0x32611C8] + 0x88]`, the same
    // globals and the same head offsets the inserts write — so a keyword registered through step 3
    // is reachable from step 4's consumer with nothing else to satisfy. (The head offsets themselves
    // are pinned against `scripted_db` in the test above.)
    try std.testing.expectEqual(scripted_db.RVA_EFFECT_DB_GLOBAL, @as(usize, 0x33746E8));
    try std.testing.expectEqual(scripted_db.RVA_TRIGGER_DB_GLOBAL, @as(usize, 0x32611C8));
    // A node is `new(0x30)`: the value at +0x28 must be the last qword, and the u32 key must sit
    // below it with the _Isnil byte below that.
    try std.testing.expectEqual(@as(usize, 0x30), keyword_reg.NODE_VALUE + @sizeOf(u64));
    try std.testing.expect(keyword_reg.NODE_KEY + @sizeOf(u32) <= keyword_reg.NODE_VALUE);
    try std.testing.expect(keyword_reg.NODE_ISNIL < keyword_reg.NODE_KEY);
    // The two consumers write the id/name at *different* offsets on the created object, so a
    // one-size-fits-all object layout assumption would be wrong for one of the two dbs.
    try std.testing.expect(keyword_reg.EFFECT_OBJECT_TOKEN_ID != keyword_reg.TRIGGER_OBJECT_TOKEN_ID);
    try std.testing.expect(keyword_reg.EFFECT_OBJECT_NAME != keyword_reg.TRIGGER_OBJECT_NAME);
    try std.testing.expect(keyword_reg.EFFECT_VTBL_INSTANTIATE_PREDICATE != keyword_reg.TRIGGER_VTBL_READ);
    // +0x70 (child read), +0x78 (dump string), +0x98 (instantiate predicate) are three different
    // slots; §23.1 originally called the third one the first.
    try std.testing.expectEqual(@as(usize, 0x70), keyword_reg.EFFECT_VTBL_READ_CHILDREN);
    try std.testing.expect(keyword_reg.EFFECT_VTBL_READ_CHILDREN < keyword_reg.EFFECT_VTBL_INSTANTIATE_PREDICATE);
    try std.testing.expect(keyword_reg.RVA_EFFECT_INSTANTIATE < 0x2392000);
    try std.testing.expect(keyword_reg.RVA_TRIGGER_INSTANTIATE < 0x2392000);
    // Dump pair and instantiate pair are distinct functions; conflating them would hide the fact
    // that registration is not inert (§23.3).
    try std.testing.expect(keyword_reg.RVA_EFFECT_INSTANTIATE != keyword_reg.RVA_EFFECT_DB_DUMP);
    try std.testing.expect(keyword_reg.RVA_TRIGGER_INSTANTIATE != keyword_reg.RVA_TRIGGER_DB_DUMP);
}

test "keyword_reg: the §24 alias donors are the census rows they claim to be" {
    // Aliasing is not a trick we invented: 9 of the 1,605 keyword class_infos already serve 2-3
    // token ids (`if`/`else_if`/`else` share `0x269DC98`), and each keyword still gets its own
    // `new(0x10)` value record, so the shared deleter never sees the same block twice (§24.1/§24.2).
    // These two are the smallest objects on their side of the file (§24.3).
    // A class_info is `.rdata`, a create is `.text` — mixing the two is the mistake §22.2 exists to
    // prevent, so the ranges are asserted rather than assumed.
    try std.testing.expect(keyword_reg.DONOR_TRIGGER_CLASS_INFO >= 0x2392000);
    try std.testing.expect(keyword_reg.DONOR_EFFECT_CLASS_INFO >= 0x2392000);
    try std.testing.expect(keyword_reg.DONOR_TRIGGER_CREATE < 0x2392000);
    try std.testing.expect(keyword_reg.DONOR_EFFECT_CREATE < 0x2392000);
    // The two donors are different classes for different dbs; §23's BST walk type-checks nothing,
    // so nothing at runtime would catch a pairing mistake — it has to be caught here.
    try std.testing.expect(keyword_reg.DONOR_TRIGGER_CLASS_INFO != keyword_reg.DONOR_EFFECT_CLASS_INFO);
    try std.testing.expect(keyword_reg.DONOR_TRIGGER_VTABLE != keyword_reg.DONOR_EFFECT_VTABLE);
}

test "keyword_reg: §24.6 the conservative docstring is a .rdata string, not a struct" {
    // The point of reusing the donor's docstring is that the pointer outlives our DLL, which only
    // holds if it addresses the exe image. Same range check §22.2 uses for class_info.
    try std.testing.expect(keyword_reg.DONOR_TRIGGER_DOCSTRING >= 0x2392000);
    try std.testing.expect(keyword_reg.DONOR_EFFECT_DOCSTRING >= 0x2392000);
    // The value record's two fields are `{&class_info, &docstring}` — both are pointers into .rdata,
    // so the section check above cannot tell them apart. Swapping them is the lea/load failure mode
    // §24.4 caught in the factory census, and the engine would print a vtable as tooltip text.
    try std.testing.expect(keyword_reg.DONOR_TRIGGER_DOCSTRING != keyword_reg.DONOR_TRIGGER_CLASS_INFO);
    try std.testing.expect(keyword_reg.DONOR_EFFECT_DOCSTRING != keyword_reg.DONOR_EFFECT_CLASS_INFO);
    try std.testing.expect(keyword_reg.DONOR_TRIGGER_DOCSTRING != keyword_reg.DONOR_TRIGGER_VTABLE);
    try std.testing.expect(keyword_reg.DONOR_EFFECT_DOCSTRING != keyword_reg.DONOR_EFFECT_VTABLE);
}

test "keyword_reg: holder exposes only the std::string at +0x10" {
    try std.testing.expectEqual(@as(usize, 0x10), keyword_reg.HOLDER_NAME);
    // The string needs +0x10..+0x2F (cap is the qword at +0x28); 0x38 is the observed
    // stride between the .data holder objects, i.e. it has 8 bytes of slack after that.
    try std.testing.expect(keyword_reg.HOLDER_NAME + 0x20 <= keyword_reg.HOLDER_SIZE);
    // An SSO string's chars live in the buffer field itself, so +0x10..+0x1F doubles as data.
    try std.testing.expect(keyword_reg.SSO_MAX < keyword_reg.HOLDER_SIZE - keyword_reg.HOLDER_NAME);
}
