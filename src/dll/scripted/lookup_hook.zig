// lookup_hook.zig — Stage-1 detour of the 4.4.4 scripted effect/trigger entry points.
//
// Live-verified targets (Stellaris 4.4.4, Frida at base 0x7ff74a630000):
//   RVA 0x89F960 — GetScriptedEffect
//   RVA 0x8A0450 — GetScriptedTrigger
// Both prologues contain no RIP-relative instruction inside the first 14
// bytes, so detour.installHook's copy-based trampoline is safe unmodified.
//
// Calling convention — RE-READ END TO END OFFLINE
// (evidence/analysis/runtime_444_c1_validation.md §27;
//  `scripts/disrva.py 0x89F960`, `0x8A0450`, `0x1D7CE0`):
//   rcx = out   — the ref object the callee fills (the caller zeroes 0x118 bytes first)
//   edx = id    — int32 requested id (-1 for name-based calls)
//   r8  = name holder — the std::string lives at **r8+0x10** (chars +0x10, size +0x20,
//                 cap +0x28), i.e. the same holder shape as §20's token-name holder.
//                 Reading r8 itself as the string is off by 0x10 and produced junk.
//   Chars are ONE BYTE each, not UTF-16: the callee measures with a byte-wise
//   `cmp byte[rdx+r8],0` loop and the empty .data holder carries cap == 15, which is
//   MSVC's std::string SSO bound (wstring/u16string would be 7).
//
// What the callee writes into `out` — and this is what §27 falsified:
//   +0x00 vtable 0x25180A8, +0x08 the requested id, +0x10 a copy of the name,
//   +0x40 vtable 0x2518128, whose slot[1] is base CEffect::Execute (0x1D08520) — so
//   +0x40 is an embedded CEffect sub-object, NOT a second name string (the old
//   `out_name` read it as one and recorded a vtable pointer plus whatever followed).
// Those four words are written on EVERY call. The walk over the db BST afterwards has
// no store back into `out`: it either falls through or emits
//   "scripted effect %s is overwriting an existing effect, rename it"   (scriptedeffect.cpp:33)
//   "scripted trigger %s is overwriting an existing trigger, rename it"  (scriptedtrigger.cpp:18)
// through the logger at 0x1C91C30 — i.e. it fires when the name's token id is ALREADY
// in the db. So: hit and miss are NOT observable from `out`, and the observable event
// is the duplicate-registration warning. `Shape` below classifies `out+0x00` against
// the image base, which is the most the return value can tell us.
//
// A Zig `callconv(.c)` fn on Windows x64 receives rcx/rdx/r8 as its first three
// integer args, so the detour needs no asm stub: record the request, forward to the
// trampoline, record what the original filled.
//
// STAGE 1 = forward-and-log only. Stage 2 needs a different target than these two,
// because these do not return the template (see §27). Install/remove only via explicit
// injector command (never DllMain), while the game thread is not mid-lookup.

const std = @import("std");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const detour_mod = @import("../hooking/detour.zig");
const windows = @import("../hooking/windows.zig");

const is_windows = builtin.os.tag == .windows;

// ---------------------------------------------------------------------------
// Object layouts (verified 4.4.4, §27)
// ---------------------------------------------------------------------------

/// MSVC std::string: 16-byte inline buffer (aliasing the heap-pointer slot),
/// +0x10 size, +0x18 capacity. SSO while capacity < 0x10, so the inline bound is 15
/// bytes — the value the empty holder at 0x2A02D68 carries in the shipped image.
pub const NameString = extern struct {
    data: [16]u8 = [_]u8{0} ** 16,
    size: usize = 0,
    capacity: usize = 0,

    /// Returns empty for implausible sizes so a corrupt pointer cannot make us read
    /// arbitrarily far.
    pub fn view(self: *const NameString, max: usize) []const u8 {
        const len = self.size;
        if (len > max) return &[_]u8{};
        const ptr: [*]const u8 = if (self.capacity < 0x10)
            &self.data
        else blk: {
            const heap = std.mem.readInt(usize, self.data[0..8], .little);
            if (heap == 0) return &[_]u8{};
            break :blk @as([*]const u8, @ptrFromInt(heap));
        };
        return ptr[0..len];
    }
};

comptime {
    if (@sizeOf(NameString) != 32) @compileError("NameString must be 32 bytes");
    if (@offsetOf(NameString, "size") != 0x10) @compileError("NameString.size must sit at +0x10");
}

/// The holder passed in `r8`: 0x10 bytes of something the callee ignores, then the
/// name. Mirrors §20's token-name holder, which is why the view reads `name`, not `self`.
pub const NameHolder = extern struct {
    pad: [offsets.scripted_lookup.HOLDER_STRING_OFFSET]u8 = [_]u8{0} ** offsets.scripted_lookup.HOLDER_STRING_OFFSET,
    name: NameString = .{},

    pub fn view(self: *const NameHolder, max: usize) []const u8 {
        return self.name.view(max);
    }
};

comptime {
    if (@offsetOf(NameHolder, "name") != 0x10) @compileError("NameHolder.name must sit at +0x10");
}

/// The ref object GetScripted* fills through `rcx`. Only the four words the callee
/// provably writes are modelled; the 0x118-byte object has more state we have not
/// pinned and never read.
pub const ScriptedRef = extern struct {
    vtable: usize = 0,
    id: i32 = 0,
    pad0: u32 = 0,
    name: NameString = .{},
    tail_30: [0x10]u8 = [_]u8{0} ** 0x10,
    /// Embedded CEffect sub-object: the callee writes its vtable here (0x2518128),
    /// and slot[1] of that vtable is base CEffect::Execute.
    ceffect_vtable: usize = 0,
};

comptime {
    if (@offsetOf(ScriptedRef, "name") != 0x10) @compileError("ref name must sit at +0x10");
    if (@offsetOf(ScriptedRef, "ceffect_vtable") != 0x40) @compileError("embedded CEffect vptr must sit at +0x40");
}

/// `out+0x00`, classified against the image base. Both lookups always produce `.ref`;
/// `.null_template` is what the sentinel caller at 0x1D7CE0 overwrites the object with
/// after the call, so seeing it in a drain means that path ran.
pub const Shape = enum(u8) {
    unknown = 0,
    ref = 1,
    null_template = 2,

    pub fn classify(out_vtable: usize, base: usize) Shape {
        if (out_vtable == 0 or base == 0) return .unknown;
        const rva = out_vtable -% base;
        if (rva == offsets.scripted_lookup.RVA_REF_VTABLE) return .ref;
        if (rva == offsets.scripted_lookup.RVA_NULL_REF_VTABLE) return .null_template;
        return .unknown;
    }
};

// ---------------------------------------------------------------------------
// Recording ring
// ---------------------------------------------------------------------------

pub const KIND_EFFECT: u8 = 1;
pub const KIND_TRIGGER: u8 = 2;
pub const RING_LEN: usize = 512;
/// Longest scripted name measured in the shipped image is 66 bytes (§21), so 80
/// holds every real name plus headroom; the ring is still under 100 KB.
const NAME_MAX: usize = 80;

/// One lookup record. `filled` flips to 1 (release) only after the original
/// function has run, so a drain never reads a half-populated record.
pub const Entry = extern struct {
    kind: u8 = 0,
    filled: u8 = 0,
    /// Shape of `out_vtable` — see `Shape.classify`. Stays `.unknown` until the
    /// image base is captured, which only happens on install.
    shape: u8 = @intFromEnum(Shape.unknown),
    pad: u8 = 0,
    req_len: u16 = 0,
    out_len: u16 = 0,
    req_id: i32 = 0,
    out_id: i32 = 0,
    out_vtable: usize = 0,
    ceffect_vtable: usize = 0,
    req_name: [NAME_MAX]u8 = [_]u8{0} ** NAME_MAX,
    out_name: [NAME_MAX]u8 = [_]u8{0} ** NAME_MAX,

    pub fn reqName(self: *const Entry) []const u8 {
        return self.req_name[0..self.req_len];
    }

    pub fn outName(self: *const Entry) []const u8 {
        return self.out_name[0..self.out_len];
    }
};

var ring: [RING_LEN]Entry = undefined;
/// Total requests recorded since load. Monotonic and NEVER reset — the reset this
/// used to do after a drain raced with game threads that had already computed a slot
/// index from the old value, and re-scanning from 0 re-copied every surviving slot
/// once per wrap. `cursor` is the drain's own read position.
var seq = std.atomic.Value(u32).init(0);
var cursor: usize = 0;
/// Records discarded because the ring wrapped over them before anyone drained.
var dropped = std.atomic.Value(u32).init(0);
/// Image base captured at install, so `out_vtable` can be turned back into an RVA.
var image_base: usize = 0;

/// Write the request half of a record; returns the ring slot index.
fn recordRequest(kind: u8, id: i32, name: []const u8) usize {
    const idx = seq.fetchAdd(1, .monotonic) % RING_LEN;
    const e = &ring[idx];
    filledPtr(e).* = 0;
    e.kind = kind;
    e.req_id = id;
    e.out_id = 0;
    e.out_vtable = 0;
    e.ceffect_vtable = 0;
    e.shape = @intFromEnum(Shape.unknown);
    const n = @min(name.len, NAME_MAX);
    @memcpy(e.req_name[0..n], name[0..n]);
    e.req_len = @intCast(n);
    e.out_len = 0;
    return idx;
}

/// Write the result half after the original ran.
fn recordResult(idx: usize, out: *const ScriptedRef) void {
    const e = &ring[idx % RING_LEN];
    e.out_vtable = out.vtable;
    e.ceffect_vtable = out.ceffect_vtable;
    e.out_id = out.id;
    e.shape = @intFromEnum(Shape.classify(out.vtable, image_base));
    const name = out.name.view(NAME_MAX);
    const n = @min(name.len, NAME_MAX);
    @memcpy(e.out_name[0..n], name[0..n]);
    e.out_len = @intCast(n);
    _ = @atomicRmw(u8, &e.filled, .Xchg, 1, .release);
}

fn filledPtr(e: *const Entry) *volatile u8 {
    return @ptrCast(@constCast(&e.filled));
}

// ---------------------------------------------------------------------------
// Detours
// ---------------------------------------------------------------------------

const OrigFn = *const fn (out: *ScriptedRef, id: i32, name: *const NameHolder) callconv(.c) void;

var orig_effect: ?OrigFn = null;
var orig_trigger: ?OrigFn = null;

fn forward(out: *ScriptedRef, id: i32, holder: *const NameHolder, kind: u8, orig: ?OrigFn) void {
    const f = orig orelse return;
    const idx = recordRequest(kind, id, holder.view(NAME_MAX));
    f(out, id, holder);
    recordResult(idx, out);
}

pub fn effectDetour(out: *ScriptedRef, id: i32, holder: *const NameHolder) callconv(.c) void {
    forward(out, id, holder, KIND_EFFECT, orig_effect);
}

pub fn triggerDetour(out: *ScriptedRef, id: i32, holder: *const NameHolder) callconv(.c) void {
    forward(out, id, holder, KIND_TRIGGER, orig_trigger);
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

pub const State = struct {
    effect_hook: ?detour_mod.Hook = null,
    trigger_hook: ?detour_mod.Hook = null,
    installed: bool = false,
};

var state = State{};

pub fn isInstalled() bool {
    return state.installed;
}

/// Install both lookup detours. Call only from an explicit injector command
/// against a confirmed 4.4.4 build; RVAs differ across game versions.
pub fn install() !void {
    if (state.installed) return;

    const eff_target = try windows.moduleFunction(offsets.scripted_db.RVA_GET_SCRIPTED_EFFECT);
    const trig_target = try windows.moduleFunction(offsets.scripted_db.RVA_GET_SCRIPTED_TRIGGER);
    if (detour_mod.isHooked(eff_target) or detour_mod.isHooked(trig_target)) return error.AlreadyHooked;

    // Captured for Shape.classify: the vtables the engine writes are absolute, so a
    // drain can only name them once we know where the image landed.
    const base = try windows.moduleFunction(0);

    const h1 = try detour_mod.installHook(eff_target, @ptrCast(@constCast(&effectDetour)));
    orig_effect = @ptrCast(h1.trampoline);
    const h2 = detour_mod.installHook(trig_target, @ptrCast(@constCast(&triggerDetour))) catch |err| {
        try detour_mod.removeHook(&h1);
        orig_effect = null;
        return err;
    };
    orig_trigger = @ptrCast(h2.trampoline);

    image_base = @intFromPtr(base);
    state = .{ .effect_hook = h1, .trigger_hook = h2, .installed = true };
}

/// Remove both detours. Only safe while no game thread is inside a lookup.
pub fn uninstall() void {
    if (state.effect_hook) |h| {
        detour_mod.removeHook(&h) catch {};
        orig_effect = null;
    }
    if (state.trigger_hook) |h| {
        detour_mod.removeHook(&h) catch {};
        orig_trigger = null;
    }
    image_base = 0;
    state = .{};
}

// ---------------------------------------------------------------------------
// Exported entry points (injector-facing)
// ---------------------------------------------------------------------------

export fn LookupHookInstall() callconv(.c) i32 {
    if (!is_windows) return -2;
    install() catch return -1;
    return 0;
}

export fn LookupHookUninstall() callconv(.c) i32 {
    if (!is_windows) return -2;
    uninstall();
    return 0;
}

/// Copy up to `max` completed records into `buf` (Entry-sized slots).
/// Advances a private cursor; never touches `seq`, so a concurrent recorder cannot
/// be pushed backwards by a drain. Records the ring wrapped over are counted in
/// `LookupHookDropped` rather than silently re-sent. Call from the injector thread
/// only — the cursor is not shared-state-safe by design.
export fn LookupHookDrain(buf: [*]Entry, max: u32) callconv(.c) u32 {
    const total: usize = seq.load(.acquire);
    if (total <= cursor) return 0;
    // The ring holds the newest RING_LEN records; anything older is gone.
    if (total - cursor > RING_LEN) {
        _ = dropped.fetchAdd(@intCast(total - cursor - RING_LEN), .monotonic);
        cursor = total - RING_LEN;
    }
    var copied: u32 = 0;
    while (cursor < total and copied < max) : (cursor += 1) {
        const e = &ring[cursor % RING_LEN];
        // A slot still carrying filled == 0 belongs to a lookup that is inside the
        // original right now. Stop rather than skip it: it will be full by the next
        // drain, and skipping would silently drop a record we already counted.
        if (filledPtr(e).* == 0) break;
        buf[copied] = e.*;
        copied += 1;
        // Consume it: a slot must never be sent twice if a second drain arrives
        // before the ring overwrites it.
        filledPtr(e).* = 0;
    }
    return copied;
}

/// Records lost to ring wrap since load.
export fn LookupHookDropped() callconv(.c) u32 {
    return dropped.load(.monotonic);
}

/// Requests recorded since load (monotonic; not reset by a drain).
export fn LookupHookTotal() callconv(.c) u32 {
    return seq.load(.acquire);
}

// ---------------------------------------------------------------------------
// Tests (layout + recorder logic; install path is Windows-runtime only)
// ---------------------------------------------------------------------------

/// Test-only: put the recorder back to an empty ring.
fn resetRing() void {
    seq.store(0, .monotonic);
    cursor = 0;
    dropped.store(0, .monotonic);
    image_base = 0;
}

test "ScriptedRef layout: the four words the callee provably writes" {
    try std.testing.expectEqual(@as(usize, 0x00), @offsetOf(ScriptedRef, "vtable"));
    try std.testing.expectEqual(@as(usize, 0x08), @offsetOf(ScriptedRef, "id"));
    // §27: the name copy is at +0x10, and +0x40 is an embedded CEffect's vptr — the
    // old struct had these the other way around.
    try std.testing.expectEqual(@as(usize, 0x10), @offsetOf(ScriptedRef, "name"));
    try std.testing.expectEqual(@as(usize, 0x30), @offsetOf(ScriptedRef, "tail_30"));
    try std.testing.expectEqual(@as(usize, 0x40), @offsetOf(ScriptedRef, "ceffect_vtable"));
}

/// The injector reads the ring as fixed-size `Entry` slots, so the record width is an
/// ABI: it was 248 bytes before §27 (two UTF-16 name buffers), 192 now.
pub const ENTRY_SIZE: usize = @sizeOf(Entry);

test "Entry width is the drain ABI" {
    try std.testing.expectEqual(@as(usize, 192), ENTRY_SIZE);
}

test "NameString is 1-byte MSVC std::string, SSO bound 15" {
    var s = NameString{};
    @memcpy(s.data[0..6], "hidden");
    s.size = 6;
    s.capacity = 15; // exactly what the empty .data holder at 0x2A02D68 carries
    try std.testing.expectEqualStrings("hidden", s.view(NAME_MAX));
}

test "NameString heap view reads the pointer, not the buffer" {
    const heap = "overwriting an existing effect";
    var s = NameString{};
    std.mem.writeInt(usize, s.data[0..8], @intFromPtr(heap.ptr), .little);
    s.size = heap.len;
    s.capacity = 0x1f; // >= 0x10 → the union holds a pointer
    try std.testing.expectEqualStrings(heap, s.view(NAME_MAX));
}

test "NameString view guards a corrupt size" {
    var s = NameString{};
    s.capacity = 0x17;
    s.size = 0x7fffffff; // implausible → must clamp to empty rather than read far
    try std.testing.expectEqual(@as(usize, 0), s.view(NAME_MAX).len);
    s.capacity = 0;
    s.data = [_]u8{0} ** 16;
    s.size = NAME_MAX + 1;
    try std.testing.expectEqual(@as(usize, 0), s.view(NAME_MAX).len);
}

test "NameHolder: the string is read at +0x10, not at the holder base" {
    var h = NameHolder{};
    h.pad = [_]u8{0xAA} ** 0x10; // junk where the old code used to read
    @memcpy(h.name.data[0..12], "add_modifier");
    h.name.size = 12;
    h.name.capacity = 15;
    try std.testing.expectEqualStrings("add_modifier", h.view(NAME_MAX));
}

test "Shape classify: absolute vtables against a captured image base" {
    const base: usize = 0x7ff6_0000_0000;
    const L = offsets.scripted_lookup;
    try std.testing.expectEqual(Shape.ref, Shape.classify(base + L.RVA_REF_VTABLE, base));
    try std.testing.expectEqual(Shape.null_template, Shape.classify(base + L.RVA_NULL_REF_VTABLE, base));
    try std.testing.expectEqual(Shape.unknown, Shape.classify(base + L.RVA_REF_CEFFECT_VTABLE, base));
    // Without a base nothing can be named — this is the pre-install state.
    try std.testing.expectEqual(Shape.unknown, Shape.classify(base + L.RVA_REF_VTABLE, 0));
    try std.testing.expectEqual(Shape.unknown, Shape.classify(0, base));
}

test "record round trip" {
    resetRing();
    image_base = 0x7ff6_0000_0000;
    const L = offsets.scripted_lookup;
    var out = ScriptedRef{};
    out.vtable = image_base + L.RVA_REF_VTABLE;
    out.ceffect_vtable = image_base + L.RVA_REF_CEFFECT_VTABLE;
    out.id = 77;
    @memcpy(out.name.data[0..6], "hidden");
    out.name.size = 6;
    out.name.capacity = 15;

    const idx = recordRequest(KIND_EFFECT, -1, "hidden");
    recordResult(idx, &out);

    var buf: [4]Entry = undefined;
    const n = LookupHookDrain(&buf, 4);
    try std.testing.expectEqual(@as(u32, 1), n);
    try std.testing.expectEqual(KIND_EFFECT, buf[0].kind);
    try std.testing.expectEqual(@as(i32, -1), buf[0].req_id);
    try std.testing.expectEqual(@as(i32, 77), buf[0].out_id);
    try std.testing.expectEqual(out.vtable, buf[0].out_vtable);
    try std.testing.expectEqual(out.ceffect_vtable, buf[0].ceffect_vtable);
    try std.testing.expectEqual(@intFromEnum(Shape.ref), buf[0].shape);
    try std.testing.expectEqualStrings("hidden", buf[0].reqName());
    try std.testing.expectEqualStrings("hidden", buf[0].outName());
    // Draining again must not re-send what was already consumed.
    try std.testing.expectEqual(@as(u32, 0), LookupHookDrain(&buf, 4));
}

test "drain keeps its own cursor and never rewinds the recorder" {
    resetRing();
    var out = ScriptedRef{};
    out.vtable = 0x1122334455;
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        const idx = recordRequest(KIND_TRIGGER, @intCast(i), "name");
        recordResult(idx, &out);
    }
    try std.testing.expectEqual(@as(u32, 4), LookupHookTotal());

    var buf: [2]Entry = undefined;
    try std.testing.expectEqual(@as(u32, 2), LookupHookDrain(&buf, 2));
    // The old code reset `seq` to 0 here, so the next request re-wrote slot 0 and the
    // following drain re-sent it. seq keeps climbing instead.
    const idx = recordRequest(KIND_TRIGGER, 99, "later");
    recordResult(idx, &out);
    try std.testing.expectEqual(@as(u32, 5), LookupHookTotal());

    // ids 2 and 3 were never consumed and come before the new one.
    var buf2: [8]Entry = undefined;
    try std.testing.expectEqual(@as(u32, 3), LookupHookDrain(&buf2, 8));
    try std.testing.expectEqual(@as(i32, 2), buf2[0].req_id);
    try std.testing.expectEqual(@as(i32, 3), buf2[1].req_id);
    try std.testing.expectEqual(@as(i32, 99), buf2[2].req_id);
    try std.testing.expectEqual(@as(u32, 0), LookupHookDrain(&buf2, 8));
}

test "an in-flight record stops the drain and is picked up when it completes" {
    resetRing();
    var out = ScriptedRef{};
    out.vtable = 7;
    const a = recordRequest(KIND_EFFECT, 1, "a");
    recordResult(a, &out);
    // b is inside the original function right now: request half written, result half not.
    const b = recordRequest(KIND_EFFECT, 2, "b");
    const c = recordRequest(KIND_EFFECT, 3, "c");
    recordResult(c, &out);

    var buf: [4]Entry = undefined;
    try std.testing.expectEqual(@as(u32, 1), LookupHookDrain(&buf, 4));
    try std.testing.expectEqual(@as(i32, 1), buf[0].req_id);

    recordResult(b, &out);
    try std.testing.expectEqual(@as(u32, 2), LookupHookDrain(&buf, 4));
    try std.testing.expectEqual(@as(i32, 2), buf[0].req_id);
    try std.testing.expectEqual(@as(i32, 3), buf[1].req_id);
}

test "drain counts records the ring wrapped over instead of re-sending them" {
    resetRing();
    var out = ScriptedRef{};
    out.vtable = 0x1;
    var i: u32 = 0;
    // RING_LEN + 10 requests with no drain in between: the oldest 10 are gone.
    while (i < RING_LEN + 10) : (i += 1) {
        const idx = recordRequest(KIND_EFFECT, @intCast(i), "n");
        recordResult(idx, &out);
    }
    var buf: [RING_LEN]Entry = undefined;
    const n = LookupHookDrain(&buf, RING_LEN);
    try std.testing.expectEqual(@as(u32, RING_LEN), n);
    try std.testing.expectEqual(@as(u32, 10), LookupHookDropped());
    // No duplicates: the surviving window is exactly the newest RING_LEN requests.
    try std.testing.expectEqual(@as(i32, 10), buf[0].req_id);
    try std.testing.expectEqual(@as(i32, @intCast(RING_LEN + 9)), buf[RING_LEN - 1].req_id);
}
