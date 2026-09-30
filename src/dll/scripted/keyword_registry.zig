// keyword_registry.zig — builds the 0x120 token descriptor the engine itself builds.
//
// PLAN.md §6 C0 item 2/3. Byte contract from evidence/analysis/runtime_444_keyword_pipeline.md
// §17 (layout), §18 (shared writer), §20 (the ctors' exact stores, decoded instruction by
// instruction). Reproduced here because it is the whole point of the module:
//
//   0x1D15270 (static, driver)  and  0x1D152D0 (dynamic, from GetOrAddToken) both do
//     [slot+0x04] = 0
//     [slot+0x08] = 0, [slot+0x10] = 0        (the movups pair)
//     [slot+0x18] = 0x100                     cap=0x100, and its high dword +0x1C = 0
//     [slot+0x08] = module + 0x247B078        the cstr vtable
//     [slot+0x10] = slot + 0x20               inline buffer
//   then both tail into 0x1D158A0(rcx=slot, edx=id, r8=chars, r9=len):
//     [slot+0x00] = id                        u32
//     [slot+0x1C] = len + 1                   size INCLUDING the terminator
//     memcpy([slot+0x10], chars, len); buffer[len] = 0
//
// Nothing else in the 0x120 block is ever written: +0x05..+0x07 and everything past the
// terminator keep whatever the allocation left behind. `init` zeroes the whole block, so
// what we hand the engine is the .data-shaped case (zeros), not the new(0x120)-shaped one.
// That is a deliberate choice — a freshly inserted descriptor must not carry stale bytes —
// and it is what makes the byte-for-byte oracle comparison in the tests decidable.
//
// The reserve at 0x1704B0 only runs when len + 1 > cap (0x100), i.e. for names of 0x100
// bytes or more, and then the buffer moves to the engine's heap and the layout above no
// longer holds. Hence maxNameLen.

const std = @import("std");
const offsets = @import("offsets");

const kr = offsets.keyword_reg;

pub const STRIDE: usize = kr.TOKEN_STRIDE;
/// Longest name whose descriptor stays fully inline (§20: cap is pre-set to 0x100 and
/// 0x1704B0 returns without touching the heap while `size <= cap`).
pub const max_name_len: usize = 0xFF;

pub const Error = error{
    NameTooLong,
    EmptyName,
    BadFirstChar,
};

/// §18/§20's only name restriction, checked here so a registration cannot silently
/// produce id = 0 from GetOrAddToken's error path.
pub fn firstCharRejected(c: u8) bool {
    return c == '-' or (c >= '0' and c <= '9');
}

/// §25.5's addition: token lookup case-FOLDS (scripts write `NOT`/`ICON`, the descriptor table holds
/// only `not`/`icon`), and `0x1D13270` is GetOrAddToken — so a name that is a case variant of a
/// shipped keyword does not mint, it returns THAT id, and `eax` cannot tell a mint from a collision.
/// This is why the executor requires an all-lowercase name: it collapses the ambiguous case into the
/// one the caller can check offline (`scripts/c1_preflight.py`) against the 9,863 descriptor names.
/// Rejecting uppercase is not a style rule; mixed case is the shape a silent hijack takes.
pub const NameReason = enum { fine, empty, leading_char, not_lowercase };

pub const NameCheck = struct {
    ok: bool,
    reason: NameReason,

    pub fn check(name: []const u8) NameCheck {
        if (name.len == 0) return .{ .ok = false, .reason = .empty };
        if (firstCharRejected(name[0])) return .{ .ok = false, .reason = .leading_char };
        for (name) |c| {
            if (c >= 'A' and c <= 'Z') return .{ .ok = false, .reason = .not_lowercase };
        }
        return .{ .ok = true, .reason = .fine };
    }
};

pub const Descriptor = struct {
    bytes: [STRIDE]u8,

    pub fn id(self: *const Descriptor) u32 {
        return std.mem.readInt(u32, self.bytes[kr.TOKEN_ID..][0..4], .little);
    }
    pub fn vtable(self: *const Descriptor) u64 {
        return std.mem.readInt(u64, self.bytes[kr.TOKEN_STR_VTABLE..][0..8], .little);
    }
    pub fn bufPtr(self: *const Descriptor) u64 {
        return std.mem.readInt(u64, self.bytes[kr.TOKEN_STR_BUF_PTR..][0..8], .little);
    }
    pub fn cap(self: *const Descriptor) u32 {
        return std.mem.readInt(u32, self.bytes[kr.TOKEN_STR_CAP..][0..4], .little);
    }
    pub fn size(self: *const Descriptor) u32 {
        return std.mem.readInt(u32, self.bytes[kr.TOKEN_STR_SIZE..][0..4], .little);
    }
    pub fn name(self: *const Descriptor) []const u8 {
        const buf = self.bytes[kr.TOKEN_STR_INLINE..];
        const end = std.mem.indexOfScalar(u8, buf, 0) orelse buf.len;
        return buf[0..end];
    }
};

/// Build the descriptor exactly as the engine's two ctors plus 0x1D158A0 would.
/// `slot_addr` is where this block will live: the engine's ctor points the string's
/// buffer field at `slot + 0x20`, so the value is self-referential and must be supplied.
pub fn buildDescriptor(id: u32, name: []const u8, slot_addr: usize, module_base: usize) Error!Descriptor {
    if (name.len == 0) return Error.EmptyName;
    if (name.len > max_name_len) return Error.NameTooLong;
    if (firstCharRejected(name[0])) return Error.BadFirstChar;

    var d = Descriptor{ .bytes = [_]u8{0} ** STRIDE };
    const b = &d.bytes;

    std.mem.writeInt(u32, b[kr.TOKEN_ID..][0..4], id, .little);
    b[kr.TOKEN_FLAG] = 0;
    std.mem.writeInt(u64, b[kr.TOKEN_STR_VTABLE..][0..8], module_base + kr.RVA_CSTR_VTABLE, .little);
    std.mem.writeInt(u64, b[kr.TOKEN_STR_BUF_PTR..][0..8], slot_addr + kr.TOKEN_STR_INLINE, .little);
    std.mem.writeInt(u32, b[kr.TOKEN_STR_CAP..][0..4], 0x100, .little);
    std.mem.writeInt(u32, b[kr.TOKEN_STR_SIZE..][0..4], @intCast(name.len + 1), .little);

    const buf = b[kr.TOKEN_STR_INLINE..];
    @memcpy(buf[0..name.len], name);
    buf[name.len] = 0;
    return d;
}

/// The value record `0x3AEF60` stores in the BST node: `{ &class_info, &docstring }`.
/// Kept as bytes for the same reason — so the offline tests can pin it against §17's thunk.
pub const ValueRecord = struct {
    bytes: [kr.VALUE_RECORD_SIZE]u8 align(8),

    pub fn init(class_info_addr: usize, docstring_addr: usize) ValueRecord {
        var r = ValueRecord{ .bytes = [_]u8{0} ** kr.VALUE_RECORD_SIZE };
        std.mem.writeInt(u64, r.bytes[kr.VALUE_CLASS_INFO..][0..8], class_info_addr, .little);
        std.mem.writeInt(u64, r.bytes[kr.VALUE_DOCSTRING..][0..8], docstring_addr, .little);
        return r;
    }
};

/// The name holder `GetOrAddToken` wants: an MSVC `std::string` at +0x10, everything
/// before it unread (§20). `chars` points at the inline buffer for len < 16, otherwise at
/// caller-owned heap memory — on Windows that must come from the engine's own allocator to
/// match how it frees, which is why nothing here allocates.
/// Layout is written as raw bytes on purpose: what matters is the engine's field offsets
/// (chars +0x10, size +0x20, cap +0x28), and a Zig struct would let declaration order and
/// padding decide them for us. A comptime check below pins the size instead.
pub const NameHolder = struct {
    bytes: [kr.HOLDER_SIZE]u8 align(8) = [_]u8{0} ** kr.HOLDER_SIZE,

    /// MSVC std::string field offsets, relative to the holder.
    const off_chars = kr.HOLDER_NAME; // 0x10
    const off_size = kr.HOLDER_STR_SIZE; // 0x20
    const off_cap = kr.HOLDER_STR_CAP; // 0x28
    const sso_cap: u64 = kr.SSO_MAX;

    pub fn inlineSso(name: []const u8) NameHolder {
        std.debug.assert(name.len <= kr.SSO_MAX);
        var h = NameHolder{};
        @memcpy(h.bytes[off_chars..][0..name.len], name);
        h.bytes[off_chars + name.len] = 0;
        std.mem.writeInt(u64, h.bytes[off_size..][0..8], name.len, .little);
        std.mem.writeInt(u64, h.bytes[off_cap..][0..8], sso_cap, .little);
        return h;
    }

    pub fn heap(name: []const u8, chars: [*]const u8, capacity: u64) NameHolder {
        std.debug.assert(name.len <= capacity);
        var h = NameHolder{};
        std.mem.writeInt(u64, h.bytes[off_chars..][0..8], @intFromPtr(chars), .little);
        std.mem.writeInt(u64, h.bytes[off_size..][0..8], name.len, .little);
        std.mem.writeInt(u64, h.bytes[off_cap..][0..8], capacity, .little);
        return h;
    }

    /// The engine's own test at 0x1d152fb: cap < 0x10 means the chars ARE the field.
    pub fn charsPtr(self: *const NameHolder) [*]const u8 {
        const cap = std.mem.readInt(u64, self.bytes[off_cap..][0..8], .little);
        return if (cap < 0x10)
            self.bytes[off_chars..].ptr
        else
            @ptrFromInt(std.mem.readInt(u64, self.bytes[off_chars..][0..8], .little));
    }

    pub fn nameLen(self: *const NameHolder) u64 {
        return std.mem.readInt(u64, self.bytes[off_size..][0..8], .little);
    }
};

comptime {
    if (@sizeOf(NameHolder) != kr.HOLDER_SIZE) {
        @compileError("NameHolder must be 0x38 bytes: only +0x10..+0x2F is read, but the " ++
            "engine allocates holders 0x38 apart (§20)");
    }
}

// ---------------------------------------------------------------------------
// The C1 executor: mint a token, make sure the db exists, publish a behaviour.
//
// This is the recipe of §17/§18/§19, and every call below reproduces an instruction
// sequence that `scripts/disrva.py` dumped off the shipped exe — the effect path from the
// `add_modifier` thunk `0x1045B0`, the trigger path from the `num_ships_in_debris` thunk
// `0x100260`. Every step is now measured, including `ClassInfo`'s convention and the consumer that
// calls it (§22, §23), and §24 decided how C1 satisfies it: alias an official `class_info` rather
// than construct an object, so `ClassInfo{ .class_info = <official address>, .docstring = ... }` is
// the whole of step 4 and nothing here has to guess a vtable.
//
// It is HARD-GATED: `authorize.c1_registration` is comptime false, so `register` returns
// error.NotAuthorized without touching a pointer, and enabling it is a deliberate source
// edit (PLAN.md §1: inserting into `0x33746E8`/`0x32611C8` is engine state, not recording).
// The gate is a runtime path, not @compileError, on purpose — it is what lets the call
// sequence be unit-tested offline against fake function pointers.
// ---------------------------------------------------------------------------

pub const authorize = struct {
    /// The single switch between "this module can only build bytes" and "this module can
    /// mutate the live engine". Flip it only with PLAN §6 C1 explicitly authorized.
    pub const c1_registration: bool = false;
};

/// The two behaviour databases, as the thunks use them. They are NOT twins: the effect db
/// is `new(0x70)` + placement ctor `0x3AEBA0` performed by every thunk, while the trigger
/// db has its own no-arg ensure `0x347BD0` that allocates `0x98` and publishes the global
/// itself. Same insert shape, different function and a different map field (`+0x18` vs
/// `+0x88`, which is exactly what `scripted_db` records for the lookups).
pub const Db = enum {
    effects,
    triggers,

    pub fn globalRva(self: Db) usize {
        return switch (self) {
            .effects => offsets.scripted_db.RVA_EFFECT_DB_GLOBAL,
            .triggers => offsets.scripted_db.RVA_TRIGGER_DB_GLOBAL,
        };
    }

    pub fn objectSize(self: Db) u64 {
        return switch (self) {
            // thunk 0x1045C2: `lea ecx, [rbx + 0x70]` with rbx known zero — i.e. new(0x70).
            .effects => kr.EFFECT_DB_OBJECT_SIZE,
            // 0x347BD0 does its own `mov ecx, 0x98; call new`; we never allocate this one.
            .triggers => kr.TRIGGER_DB_OBJECT_SIZE,
        };
    }

    /// Effects allocate and then placement-construct; triggers just call their ensure.
    pub fn allocatesExternally(self: Db) bool {
        return switch (self) {
            .effects => true,
            .triggers => false,
        };
    }
};

/// `0x2185218` keeps the full `rcx` and forwards it to the allocator, so the size is a u64
/// parameter even though the thunks only ever write `ecx`. It can return null (the wrapper
/// retries or throws at 0x2185242), so the result is nullable here.
const OperatorNew = *const fn (size: u64) callconv(.c) ?*align(16) anyopaque;
/// `eax = 0x1D13270(rcx = *NameHolder)`; rdx dead, returns 0 for a rejected name (§20).
const GetOrAddTokenFn = *const fn (holder: *const NameHolder) callconv(.c) u32;
/// `rax = 0x3AEBA0(rcx = mem)` — a placement ctor that returns the object.
const DbCtor = *const fn (mem: *align(16) anyopaque) callconv(.c) ?*align(16) anyopaque;
/// `0x347BD0()` — no args; writes `[0x32611C8]` itself (at 0x347D20).
const TriggerEnsure = *const fn () callconv(.c) void;
/// `0x3AEF60(rcx = db, edx = id, r8 = *ValueRecord)`, and its twin `0x348150`. Declared
/// `void` because rax is set but its meaning is unestablished and no thunk uses it.
const BstInsert = *const fn (db: *align(16) anyopaque, token_id: u32, value: *const ValueRecord) callconv(.c) void;

pub const RegisterError = error{
    NotAuthorized,
    OutOfMemory,
    TokenRejected,
    NameNotMintable,
    DbUninitialized,
} || Error;

/// Function pointers into a mapped engine, resolved from one base. Tests inject fakes here —
/// that is how the call sequence is verifiable offline. `Engine.map` is the real one, and it
/// is only meaningful inside the game process.
pub const Engine = struct {
    base: usize,
    new: OperatorNew,
    get_or_add_token: GetOrAddTokenFn,
    effect_db_ctor: DbCtor,
    trigger_db_ensure: TriggerEnsure,
    effect_insert: BstInsert,
    trigger_insert: BstInsert,

    pub fn map(base: usize) Engine {
        return .{
            .base = base,
            .new = addr(base, kr.RVA_OPERATOR_NEW, OperatorNew),
            .get_or_add_token = addr(base, kr.RVA_GET_OR_ADD_TOKEN, GetOrAddTokenFn),
            .effect_db_ctor = addr(base, kr.RVA_DB_LAZY_CTOR, DbCtor),
            .trigger_db_ensure = addr(base, kr.RVA_TRIGGER_DB_ENSURE, TriggerEnsure),
            .effect_insert = addr(base, kr.RVA_BST_INSERT, BstInsert),
            .trigger_insert = addr(base, kr.RVA_TRIGGER_BST_INSERT, BstInsert),
        };
    }

    fn addr(base: usize, rva: usize, comptime T: type) T {
        return @ptrFromInt(base + rva);
    }

    pub fn dbGlobal(self: Engine, db: Db) *align(8) usize {
        return @ptrFromInt(self.base +% db.globalRva());
    }

    pub fn insert(self: Engine, db: Db) BstInsert {
        return switch (db) {
            .effects => self.effect_insert,
            .triggers => self.trigger_insert,
        };
    }
};

/// §17 step 4, as §22 measured it. The record is 16 bytes of `{deleter, create}`, and it is a
/// pair of *function addresses*, not a constructor table:
///
/// * `deleter` is `0x34C090` in all 1,605 keyword records. It is a scalar deleting destructor that
///   frees a `0x10` block — the value record this struct points at, not the effect object — so it
///   is reusable verbatim only while step 2 keeps allocating `VALUE_RECORD_SIZE`.
/// * `create` is per keyword and its convention is now pinned, not guessed: a def/use pass over all
///   1,605 bodies, in entry-rsp coordinates, finds **none** reading `rcx`/`rdx`/`r8`/`r9` or any
///   incoming stack slot. It is `void *create(void)` returning the finished object in `rax`. What it
///   does internally is `new(size)` -> `memset` -> shared base ctor -> publish vpointers; §24.4
///   measured the publication and it is *not* uniformly `[obj+0]`/`[obj+8]` — `+0x8` is the effect
///   family's offset, the trigger family writes a global-copied pointer at `+0x78`, and 544 of the
///   1,605 factories publish one static address or none (the base ctor contributes the rest).
///
/// The consumer is §23, and it is what raises the bar on what `create` may return. `0x3B01A0`
/// (effects) and `0x349AE0` (triggers) read the db global, walk the BST by raw token id, and on a hit
/// execute `call [value[0] + 8]`. The engine then writes *into* the returned object — id at `[obj+0x20]`
/// and a name `std::string` at `[obj+0x28]` for effects, `+0x38`/`+0x40` for triggers — before calling
/// a virtual on it (`[vptr+0x98]` for effects, `[vptr+0x80]` for triggers, bool in `al`). Worse,
/// `0x3AF130`/`0x348450` enumerate the whole tree and `create` every node, so an inserted keyword is
/// constructed whether or not anything ever evaluates it. A stub whose vtable stops at `slot[2]` is not
/// a conservative choice, it is a call through a null slot. Both addresses therefore stay
/// caller-supplied, and this module never fabricates one.
///
/// **C1's decided form is the alias, not the fabrication** (§24): point the new value record's
/// `class_info` at an existing official one, so everything above is inherited instead of guessed.
/// That is not a workaround, it is a shape the shipped game uses — 9 keyword `class_info`s already
/// serve 2-3 token ids each (`if`/`else_if`/`else` share `0x269DC98`), and because each keyword gets
/// its own `new(0x10)` value record, sharing the `class_info` never shares the block `0x34C090` frees.
/// Donors in `offsets.keyword_reg`: `0x269CAA8` (triggers, `new(0x80)`) and `0x2611070` (effects,
/// `new(0xc0)`), both read at §23's consumer slots. Note what this proves and what it does not: the
/// alias validates mint -> insert -> tree hit -> `create`, and the keyword behaves as its donor class,
/// not as anything we wrote.
pub const ClassInfo = struct {
    /// Absolute address of the 16-byte `{deleter, create}` record — stored at value+0x00.
    class_info: usize,
    /// Absolute address of the docstring — stored at value+0x08.
    docstring: usize,

    /// §24.6's decided C1 payload: borrow the donor's `class_info` AND the donor's own `.rdata`
    /// docstring, so both fields of the value record address the shipped image and nothing we can
    /// unload. These are pure arithmetic on `module_base` — no engine state is touched — which is why
    /// they can be `pub` while `register` stays gated. Cross-pairing the two dbs is the mistake to
    /// catch here: nothing at runtime type-checks which donor a node came from (§23's walk).
    pub fn triggerDonor(module_base: usize) ClassInfo {
        return .{
            .class_info = module_base + kr.DONOR_TRIGGER_CLASS_INFO,
            .docstring = module_base + kr.DONOR_TRIGGER_DOCSTRING,
        };
    }

    pub fn effectDonor(module_base: usize) ClassInfo {
        return .{
            .class_info = module_base + kr.DONOR_EFFECT_CLASS_INFO,
            .docstring = module_base + kr.DONOR_EFFECT_DOCSTRING,
        };
    }
};

pub const Registration = struct {
    token_id: u32,
    db: *align(16) anyopaque,
    value: *align(16) ValueRecord,
};

/// Step 1: mint a token id for a brand-new name. `0x1D13270` calls the db singleton accessor
/// (`0x1D12C60`) at its own head, so there is nothing to set up first.
///
/// The caller owns the holder — `NameHolder` says why. Whether the name->id map at `[db+0x50]`
/// copies the string or retains the chars pointer is unestablished, so a caller that frees the
/// holder's backing is guessing; keep it alive for the process lifetime.
///
/// `eax` cannot tell a mint from a collision, and §25.5 measured that the lookup case-folds — so the
/// caller must clear the name against the shipped names BEFORE calling this (`scripts/c1_preflight.py`).
/// `NameCheck` enforces the part that is checkable without the table: emptiness, §20's leading char,
/// and lowercase, because mixed case is exactly the shape a silent id hijack takes.
fn getToken(eng: *const Engine, holder: *const NameHolder) RegisterError!u32 {
    const len = holder.nameLen();
    if (len == 0) return Error.EmptyName;
    if (!NameCheck.check(holder.charsPtr()[0..len]).ok) return RegisterError.NameNotMintable;
    const id = eng.get_or_add_token(holder);
    // 0 is the lexer.cpp error return — a name starting with '-' or a digit (§20).
    if (id == 0) return RegisterError.TokenRejected;
    return id;
}

/// Step 3's precondition: the db object has to exist before anything can be inserted (§17).
/// Both shapes are the ones the thunks actually use; nothing here invents a third.
fn ensureDb(eng: *const Engine, db: Db) RegisterError!*align(16) anyopaque {
    const global = eng.dbGlobal(db);
    if (global.* != 0) return @ptrFromInt(global.*);

    if (!db.allocatesExternally()) {
        // Triggers: 0x347BD0 allocates 0x98, constructs and publishes the global itself.
        eng.trigger_db_ensure();
        if (global.* == 0) return RegisterError.DbUninitialized;
        return @ptrFromInt(global.*);
    }

    // Effects: `new(0x70)` then placement-construct, which returns the object (thunk 0x1045C2).
    const mem = try alloc(eng, db.objectSize());
    const obj = eng.effect_db_ctor(mem) orelse return RegisterError.OutOfMemory;
    global.* = @intFromPtr(obj);
    return obj;
}

/// The recipe, in the order the official thunks perform it (§19: mint, ensure, insert inside
/// one call sequence — not two phases). Steps 1-3; step 4's factory stays caller-supplied
/// because its convention is unpinned, see `ClassInfo`.
pub fn register(
    eng: *const Engine,
    db: Db,
    holder: *const NameHolder,
    info: ClassInfo,
) RegisterError!Registration {
    if (!authorize.c1_registration) return RegisterError.NotAuthorized;
    return registerSequence(eng, db, holder, info);
}

/// Not `pub` on purpose: the gated wrapper above is the only way in from outside this file,
/// and the tests below are the only thing inside it. That is what makes the gate testable —
/// the sequence can be exercised against fake pointers without being reachable at run time.
fn registerSequence(
    eng: *const Engine,
    db: Db,
    holder: *const NameHolder,
    info: ClassInfo,
) RegisterError!Registration {
    const token_id = try getToken(eng, holder);
    const db_obj = try ensureDb(eng, db);

    // Step 2: `new(0x10){ &class_info, &docstring }` — thunk 0x1045E1..0x104602 verbatim.
    const value: *align(16) ValueRecord = @ptrCast(@alignCast(try alloc(eng, kr.VALUE_RECORD_SIZE)));
    value.* = ValueRecord.init(info.class_info, info.docstring);

    // Step 3: BST insert keyed by the raw 32-bit id, which the engine range-checks not at all
    // (§18), so a freshly minted dynamic id is a well-formed key.
    eng.insert(db)(db_obj, token_id, value);
    return .{ .token_id = token_id, .db = db_obj, .value = value };
}

fn alloc(eng: *const Engine, size: u64) RegisterError!*align(16) anyopaque {
    return eng.new(size) orelse RegisterError.OutOfMemory;
}

// ---------------------------------------------------------------------------
// tests — C0.3's offline acceptance, against oracle bytes produced by running
// the engine's own writers under an emulator (scripts/emu_desc.py).
// ---------------------------------------------------------------------------

const golden = @import("keyword_registry_golden.zig");

test "buildDescriptor matches the engine's own writers, byte for byte" {
    for (golden.vectors) |v| {
        const d = buildDescriptor(v.id, v.name, golden.slot, golden.module_base) catch
            return error.TestUnexpectedResult;
        try expectSha(d.bytes[0..], v.sha256, v.name);
    }
}

test "buildDescriptor: the add_modifier block equals the §20 dump" {
    const d = buildDescriptor(10104, "add_modifier", 0x5000_0000, 0x14000_0000) catch unreachable;
    const want = "782700000000000078b04742010000002000005000000000000100000d000000" ++
        "6164645f6d6f64696669657200000000";
    try std.testing.expectEqualStrings(want, &std.fmt.bytesToHex(d.bytes[0..0x30], .lower));
    try std.testing.expectEqual(@as(u32, 10104), d.id());
    try std.testing.expectEqual(@as(u32, 13), d.size()); // strlen("add_modifier") + 1
    try std.testing.expectEqualStrings("add_modifier", d.name());
    try std.testing.expectEqual(@as(u64, 0x5000_0020), d.bufPtr());
    try std.testing.expectEqual(@as(u64, 0x14000_0000 + 0x247B078), d.vtable());
}

test "buildDescriptor: bytes we must not invent" {
    const d = buildDescriptor(7, "a", 0x5000_0000, 0x14000_0000) catch unreachable;
    // +0x05..+0x07 is never written by either ctor, and neither is anything past the
    // terminator — both must read as the zero-fill, or our block is not .data-shaped.
    try std.testing.expectEqual(@as(u8, 0), d.bytes[4]);
    try std.testing.expect(std.mem.allEqual(u8, d.bytes[5..8], 0));
    try std.testing.expectEqual(@as(u8, 'a'), d.bytes[0x20]);
    try std.testing.expectEqual(@as(u8, 0), d.bytes[0x21]);
    try std.testing.expect(std.mem.allEqual(u8, d.bytes[0x22..], 0));
}

test "buildDescriptor: rejects names the engine would reject or reallocate for" {
    const long = [_]u8{'x'} ** 0x100;
    const edge = [_]u8{'y'} ** max_name_len;
    try std.testing.expectError(Error.BadFirstChar, buildDescriptor(1, "-negative", 0, 0));
    try std.testing.expectError(Error.BadFirstChar, buildDescriptor(1, "3d", 0, 0));
    try std.testing.expectError(Error.EmptyName, buildDescriptor(1, "", 0, 0));
    try std.testing.expectError(Error.NameTooLong, buildDescriptor(1, &long, 0, 0));
    // 0xFF is the last length that keeps the buffer inline (§20: size 0x100 == cap).
    _ = try buildDescriptor(1, &edge, 0, 0);
}

test "NameCheck: every branch, and the shapes the shipped table actually contains" {
    try std.testing.expectEqual(@as(NameReason, .fine), NameCheck.check("chokepoint_score").reason);
    try std.testing.expectEqual(@as(NameReason, .empty), NameCheck.check("").reason);
    try std.testing.expectEqual(@as(NameReason, .leading_char), NameCheck.check("3d").reason);
    try std.testing.expectEqual(@as(NameReason, .leading_char), NameCheck.check("-negative").reason);
    try std.testing.expectEqual(@as(NameReason, .not_lowercase), NameCheck.check("Add_Modifier").reason);
    try std.testing.expectEqual(@as(NameReason, .not_lowercase), NameCheck.check("chokepoint_SCORE").reason);

    // Digits are only forbidden FIRST (§20) — `level_2` is mintable, `2level` is not.
    try std.testing.expectEqual(@as(NameReason, .fine), NameCheck.check("level_2").reason);
    // The lowercase rule is deliberately stricter than the table: mixed-case names DO exist there
    // (`noOfFrames`, `fontName`, `xFile`), which is exactly why we may not mint one — the id would
    // be an existing keyword's. buildDescriptor keeps accepting them because it mirrors the engine's
    // byte layout for names already minted; only the MINT path is restricted.
    try std.testing.expect(!NameCheck.check("noOfFrames").ok);
    _ = try buildDescriptor(1, "noOfFrames", 0, 0);
}

test "NameHolder: only +0x10 chars, +0x20 size, +0x28 cap are meaningful" {
    const h = NameHolder.inlineSso("add_modifier");
    try std.testing.expectEqual(@as(usize, 0x38), @sizeOf(NameHolder));
    try std.testing.expectEqualStrings("add_modifier", h.bytes[0x10..][0..12]);
    try std.testing.expectEqual(@as(u64, 12), h.nameLen());
    // cap < 0x10 means the characters ARE the field — the engine reads them from +0x10.
    try std.testing.expectEqual(@as(usize, 0x10), @intFromPtr(h.charsPtr()) - @intFromPtr(&h));

    const heap_name = "a_name_that_is_quite_longindeed";
    const hh = NameHolder.heap(heap_name, heap_name.ptr, 31);
    try std.testing.expectEqual(@intFromPtr(heap_name.ptr), @intFromPtr(hh.charsPtr()));
    try std.testing.expectEqualStrings(heap_name, hh.charsPtr()[0..heap_name.len]);
    // The 0x10 bytes before the string are never read (§20), so they stay zeroed.
    try std.testing.expect(std.mem.allEqual(u8, h.bytes[0..0x10], 0));
}

test "ValueRecord matches §17's new(0x10){ &class_info, &docstring }" {
    const r = ValueRecord.init(0x14000_0000 + 0x260ABD8, 0x14000_0000 + 0x26380C0);
    try std.testing.expectEqual(@as(usize, 0x10), @sizeOf(ValueRecord));
    try std.testing.expectEqual(@as(u64, 0x14000_0000 + 0x260ABD8), std.mem.readInt(u64, r.bytes[0..8], .little));
    try std.testing.expectEqual(@as(u64, 0x14000_0000 + 0x26380C0), std.mem.readInt(u64, r.bytes[8..16], .little));
}

test "§24.6 donor ClassInfo: the trigger db is C1's first target" {
    // Field order is the contract here, not the arithmetic: value+0x00 must hold the class_info and
    // +0x08 the docstring, so reading the record back is what proves the helper isn't storing a
    // struct where the engine expects tooltip text. Base 0 keeps the assertions in RVA coordinates.
    const base: usize = 0x14000_0000;
    const trig = ClassInfo.triggerDonor(base);
    const eff = ClassInfo.effectDonor(base);

    const t_rec = ValueRecord.init(trig.class_info, trig.docstring);
    try std.testing.expectEqual(@as(u64, base + kr.DONOR_TRIGGER_CLASS_INFO), std.mem.readInt(u64, t_rec.bytes[0..8], .little));
    try std.testing.expectEqual(@as(u64, base + kr.DONOR_TRIGGER_DOCSTRING), std.mem.readInt(u64, t_rec.bytes[8..16], .little));

    // Two donors for two dbs. `0x348150` and `0x3AEF60` both take `(db, id, value)` and the tree
    // never re-checks which db a node lives in, so a copied-into-the-wrong-place donor is silent.
    try std.testing.expectEqual(@as(u64, base + kr.DONOR_EFFECT_CLASS_INFO), eff.class_info);
    try std.testing.expectEqual(@as(u64, base + kr.DONOR_EFFECT_DOCSTRING), eff.docstring);
    try std.testing.expect(trig.class_info != eff.class_info);
    try std.testing.expect(trig.docstring != eff.docstring);
}

test "substitution: changing (id, name) touches only the id and the name bytes" {
    // PLAN §6 C0.3's actual criterion, restated for an oracle we generate ourselves:
    // no byte may depend on the inputs except the id field and the name characters.
    const a = buildDescriptor(10104, "add_modifier", 0x5000_0000, 0x14000_0000) catch unreachable;
    const b = buildDescriptor(0x00FF_FFFF, "sub_modifier", 0x5000_0000, 0x14000_0000) catch unreachable;
    var diffs: usize = 0;
    for (a.bytes, b.bytes, 0..) |x, y, i| {
        if (x == y) continue;
        diffs += 1;
        const in_id = i < 4;
        const in_name = i >= kr.TOKEN_STR_INLINE and i <= kr.TOKEN_STR_INLINE + 15;
        try std.testing.expect(in_id or in_name);
    }
    try std.testing.expect(diffs > 0);
    // Equal-length names, so every derived field — cap, size, the self-referential buffer
    // pointer — must be bit-identical: only the id and the characters may differ.
    try std.testing.expectEqual(a.size(), b.size());
    try std.testing.expectEqual(a.cap(), b.cap());
    try std.testing.expectEqual(a.bufPtr(), b.bufPtr());
    try std.testing.expectEqual(a.vtable(), b.vtable());
}

fn expectSha(block: []const u8, want_hex: []const u8, label: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(block, &digest, .{});
    const hex: [64]u8 = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, hex[0..], want_hex)) {
        std.debug.print("descriptor mismatch for {s}: built {s}, engine {s}\n", .{ label, hex[0..], want_hex });
        return error.TestExpectedEqual;
    }
}

// ---------------------------------------------------------------------------
// executor tests — the C1 call sequence, run against fakes.
//
// `register` is gated shut, so the only way to exercise the sequence offline is that the
// fakes stand in for the engine's side of each call. `registerSequence` is file-private for
// exactly this reason: these tests can reach it, the DLL cannot.
// ---------------------------------------------------------------------------

const Op = enum(u8) { new, token, db_ctor, trigger_ensure, insert };

const Trace = struct {
    ops: [8]Op = undefined,
    args: [8]u64 = undefined,
    n: usize = 0,

    fn add(self: *Trace, op: Op, arg: u64) void {
        self.ops[self.n] = op;
        self.args[self.n] = arg;
        self.n += 1;
    }
};

var trace: Trace = .{};
var heap: [0x200]u8 align(16) = undefined;
var heap_used: usize = 0;
var fail_new: bool = false;
var minted_id: u32 = 0;
var fake_publishes = true;

/// The engine-side globals, at their real relative distance so `Engine.base` can be derived.
const Globals = struct {
    effect: usize align(16) = 0,
    trigger: usize align(16) = 0,
};
var globals: Globals = .{};

var db_storage: [0x98]u8 align(16) = undefined; // stands in for a constructed db object

const Insert = struct {
    db: usize = 0,
    id: u32 = 0,
    ci: u64 = 0,
    doc: u64 = 0,
    value: usize = 0,
    via_trigger_twin: bool = false,
};
var last_insert: Insert = .{};

fn reset() void {
    trace = .{};
    heap_used = 0;
    fail_new = false;
    fake_publishes = true;
    minted_id = 0x0012_3456;
    globals = .{};
    last_insert = .{};
}

fn fakeNew(size: u64) callconv(.c) ?*align(16) anyopaque {
    trace.add(.new, size);
    if (fail_new) return null;
    const off = heap_used;
    heap_used += (size + 15) & ~@as(u64, 15);
    if (heap_used > heap.len) return null;
    // off is always a multiple of 16, so the bump pointer keeps `heap`'s alignment.
    const base: [*]align(16) u8 = @ptrCast(&heap);
    return @ptrCast(@alignCast(base + off));
}

fn fakeToken(holder: *const NameHolder) callconv(.c) u32 {
    trace.add(.token, holder.nameLen());
    return minted_id;
}

fn fakeDbCtor(mem: *align(16) anyopaque) callconv(.c) ?*align(16) anyopaque {
    trace.add(.db_ctor, @intFromPtr(mem));
    return mem;
}

/// 0x347BD0 takes nothing and publishes the global itself (at 0x347D20) — mirrored here.
fn fakeTriggerEnsure() callconv(.c) void {
    trace.add(.trigger_ensure, 0);
    if (fake_publishes) globals.trigger = @intFromPtr(&db_storage);
}

fn recordInsert(db: *align(16) anyopaque, id: u32, value: *const ValueRecord, twin: bool) void {
    trace.add(.insert, id);
    last_insert = .{
        .db = @intFromPtr(db),
        .id = id,
        .ci = std.mem.readInt(u64, value.bytes[0..8], .little),
        .doc = std.mem.readInt(u64, value.bytes[8..16], .little),
        .value = @intFromPtr(value),
        .via_trigger_twin = twin,
    };
}

fn fakeEffectInsert(db: *align(16) anyopaque, id: u32, value: *const ValueRecord) callconv(.c) void {
    recordInsert(db, id, value, false);
}

fn fakeTriggerInsert(db: *align(16) anyopaque, id: u32, value: *const ValueRecord) callconv(.c) void {
    recordInsert(db, id, value, true);
}

fn fakeEngine(db: Db) Engine {
    const field: *align(16) usize = switch (db) {
        .effects => &globals.effect,
        .triggers => &globals.trigger,
    };
    return .{
        // Wrapping: the fake globals sit at low addresses in the test binary, below
        // the RVA span, so this subtraction only round-trips modulo 2**64.
        .base = @intFromPtr(field) -% db.globalRva(),
        .new = fakeNew,
        .get_or_add_token = fakeToken,
        .effect_db_ctor = fakeDbCtor,
        .trigger_db_ensure = fakeTriggerEnsure,
        .effect_insert = fakeEffectInsert,
        .trigger_insert = fakeTriggerInsert,
    };
}

fn expectOps(comptime want: []const Op) !void {
    try std.testing.expectEqual(want.len, trace.n);
    for (want, 0..) |op, i| try std.testing.expectEqual(op, trace.ops[i]);
}

test "gate: register refuses while c1_registration is false, touching nothing" {
    // A bogus base would crash if any pointer were deref'd, so returning an error is the proof.
    reset();
    try std.testing.expectEqual(false, authorize.c1_registration);
    const h = NameHolder.inlineSso("chokepoint");
    const eng = Engine.map(0);
    try std.testing.expectError(RegisterError.NotAuthorized, register(&eng, .effects, &h, .{ .class_info = 1, .docstring = 2 }));
    try std.testing.expectEqual(@as(usize, 0), trace.n);
}

test "registerSequence: effect path, db not yet built" {
    reset();
    const h = NameHolder.inlineSso("add_modifier");
    const eng = fakeEngine(.effects);
    const r = try registerSequence(&eng, .effects, &h, .{ .class_info = 0x14000_260ABD8, .docstring = 0x14000_26380C0 });

    // §19's order inside one iterator-registration function: mint, then ensure, then insert.
    try expectOps(&.{ .token, .new, .db_ctor, .new, .insert });
    try std.testing.expectEqual(@as(u64, 12), trace.args[0]); // holder name length
    try std.testing.expectEqual(kr.EFFECT_DB_OBJECT_SIZE, trace.args[1]); // new(0x70)
    try std.testing.expectEqual(kr.VALUE_RECORD_SIZE, trace.args[3]); // new(0x10)
    try std.testing.expectEqual(@as(u64, minted_id), trace.args[4]); // the id insert was keyed by
    // The ctor returns the object, and we publish exactly what it returned — here the block
    // that new(0x70) handed us (trace.args[2] is the ctor's `mem`).
    try std.testing.expectEqual(trace.args[2], globals.effect);
    try std.testing.expectEqual(globals.effect, last_insert.db);
    try std.testing.expectEqual(minted_id, r.token_id);
    try std.testing.expectEqual(@as(u64, 0x14000_260ABD8), last_insert.ci);
    try std.testing.expectEqual(@as(u64, 0x14000_26380C0), last_insert.doc);
    try std.testing.expectEqual(false, last_insert.via_trigger_twin);
}

test "registerSequence: an already-built db is reused, never re-allocated" {
    reset();
    globals.effect = @intFromPtr(&db_storage);
    const h = NameHolder.inlineSso("add_modifier");
    _ = try registerSequence(&fakeEngine(.effects), .effects, &h, .{ .class_info = 1, .docstring = 2 });
    try expectOps(&.{ .token, .new, .insert }); // no new(0x70), no ctor
}

test "registerSequence: trigger path uses the no-arg ensure and the trigger insert twin" {
    reset();
    const h = NameHolder.inlineSso("num_ships"); // SSO holder; the real name is 19 chars
    _ = try registerSequence(&fakeEngine(.triggers), .triggers, &h, .{ .class_info = 0xAA, .docstring = 0xBB });
    try expectOps(&.{ .token, .trigger_ensure, .new, .insert });
    // The ensure published it engine-side; we must read that back, not our own allocation.
    try std.testing.expectEqual(@intFromPtr(&db_storage), last_insert.db);
    try std.testing.expectEqual(true, last_insert.via_trigger_twin);
    try std.testing.expectEqual(@as(u64, 0xAA), last_insert.ci);
}

test "getToken: the name checks stop the sequence before the engine runs" {
    reset();
    const rejected = NameHolder.inlineSso("3d"); // §20's leading digit
    try std.testing.expectError(RegisterError.NameNotMintable, getToken(&fakeEngine(.effects), &rejected));
    try expectOps(&.{});

    reset();
    // §25.5: this is the hijack shape — it would fold onto add_modifier and RETURN 10104.
    const hijack = NameHolder.inlineSso("Add_Modifier");
    try std.testing.expectError(RegisterError.NameNotMintable, getToken(&fakeEngine(.effects), &hijack));
    try expectOps(&.{});

    // Same name one layer up: the sequence aborts before the db exists, so an official keyword's
    // id can never be keyed onto our value record.
    reset();
    try std.testing.expectError(RegisterError.NameNotMintable, registerSequence(&fakeEngine(.effects), .effects, &hijack, .{ .class_info = 1, .docstring = 2 }));
    try expectOps(&.{});
    try std.testing.expectEqual(@as(usize, 0), globals.effect);
    try std.testing.expectEqual(@as(usize, 0), last_insert.db);

    reset();
    const empty = NameHolder.inlineSso("");
    try std.testing.expectError(Error.EmptyName, getToken(&fakeEngine(.effects), &empty));
    try expectOps(&.{});
}

test "getToken: an engine rejection the name check cannot predict still stops the insert" {
    reset();
    // eax = 0 for a reason this side cannot see. NameCheck passes, so 0x1D13270 really runs
    // (hence the .token op) and its answer is what stops the sequence, not a pre-check.
    minted_id = 0;
    const h = NameHolder.inlineSso("chokepoint");
    try std.testing.expectError(RegisterError.TokenRejected, registerSequence(&fakeEngine(.effects), .effects, &h, .{ .class_info = 1, .docstring = 2 }));
    try std.testing.expectEqual(@as(usize, 1), trace.n);
    try expectOps(&.{.token});
    try std.testing.expectEqual(@as(usize, 0), globals.effect);
    try std.testing.expectEqual(@as(usize, 0), last_insert.db);
}

test "registerSequence: a long keyword name goes through the heap holder path" {
    // Real names exceed SSO — `chokepoint_score` is 16 — and the engine's own test at
    // 0x1d152fb then reads chars from the pointer at +0x10 instead of the inline field (§20).
    reset();
    const name = "chokepoint_score";
    var chars: [name.len + 1]u8 align(16) = undefined;
    @memcpy(chars[0..name.len], name);
    chars[name.len] = 0;
    const h = NameHolder.heap(name, &chars, name.len);
    _ = try registerSequence(&fakeEngine(.effects), .effects, &h, .{ .class_info = 7, .docstring = 8 });
    try expectOps(&.{ .token, .new, .db_ctor, .new, .insert });
    try std.testing.expectEqual(@as(u64, name.len), trace.args[0]);
    try std.testing.expectEqual(@intFromPtr(&chars), @intFromPtr(h.charsPtr()));
}

test "registerSequence: allocation failure stops before the insert" {
    reset();
    fail_new = true;
    const h = NameHolder.inlineSso("add_modifier");
    try std.testing.expectError(RegisterError.OutOfMemory, registerSequence(&fakeEngine(.effects), .effects, &h, .{ .class_info = 1, .docstring = 2 }));
    try std.testing.expectEqual(@as(usize, 0), last_insert.db);
}

test "registerSequence: a trigger ensure that fails to publish is an error, not a guess" {
    reset();
    fake_publishes = false;
    const h = NameHolder.inlineSso("add_modifier");
    try std.testing.expectError(RegisterError.DbUninitialized, registerSequence(&fakeEngine(.triggers), .triggers, &h, .{ .class_info = 1, .docstring = 2 }));
    try std.testing.expectEqual(@as(usize, 0), globals.trigger);
}
