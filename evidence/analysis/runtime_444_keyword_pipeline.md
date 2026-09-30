# 4.4.4 keyword registration pipeline — static evidence (§16–§23)

> **Volume 2 of 3.** This evidence log is split across three files; the `§` numbers are unique across them.
> §1–§15 — `runtime_444_structures.md` (live hot path, detours, CEffect class map, the falsified registration chain).
> §16–§23 — `runtime_444_keyword_pipeline.md` (the static registration pipeline: driver, descriptors, thunk arrays, token allocator, class_info, consumers).
> §24–§29 — `runtime_444_c1_validation.md` (the alias/donor decision, A5 cross-validation, ABI corrections, backlog).

## 16. The real keyword registration table, found statically (2026-09-29) — **A2 solved**

Everything below is from the offline exe copy only: no IDA, no running process, no Windows.
Reproduce with `python scripts/regscan.py all` (~4.5 min) and `python scripts/kwscan.py`.

### The driver is one 247 KB function
`.pdata` (the x64 exception directory) gives exact function bounds without any analysis —
new tool `scripts/pdata.py`. Querying it for any registration site returns:

**RVA `0x172E50`..`0x1AF1E7`, 246,679 bytes** (`0x3C397`). A full-`.text` decode finds
**9,863 calls to the registrar, and every single one is inside this function** — no second
segment, no scattered registrars.

This is the 4.4.4 instance of the 3.x entry in `AGENTS.md`:
`0x140173C30` "String-to-ID registration (**247 KB**), static init". Same size, same role,
re-anchored. §8's `0xCCCEB0` was never it.

### Per-keyword entry shape (compiler-generated, 25 bytes each)
```
lea  r8, [rip+name]          ; r8 = keyword name, a .rdata string
mov  edx, <token id>         ; edx = token id
lea  rcx, [rip+descriptor]   ; rcx = the descriptor slot
call 0x1D15270               ; THE REGISTRAR
```
Signature `rcx = descriptor slot, edx = token id, r8 = name ptr` — **§8 stated this
signature correctly but attributed it to `0xD150A0`; the real registrar is RVA `0x1D15270`.**

### The descriptor table is a fixed static array
* base **RVA `0x337B400`**, stride **`0x120` (288 bytes)**, 9,863 entries,
  ending `0x3630BE0`.
* All 9,862 adjacent deltas in the sorted set are exactly `0x120` — no holes, no aliases.
* Descriptor index **strictly increases with call order**, so
  `descriptor = 0x337B400 + 0x120 * registration_order`.
* **Token id is NOT the array index** (0/9863 match; `id - index` ranges `-0xE2..0x22FB`).
  The id comes from a separate allocator and is only *mostly* ordered: 101 order
  inversions (e.g. `0x30 → 0x1D5 → 0x31`), not 101 true gaps.

Corrects §9: the entry stride is **0x120, not 0x110**.

### The keyword name block
`.rdata` `0x247F480`..`0x2494070` holds **3,923 contiguous identifier strings**, first
`hidden_effect`, last `rally_point` → `evidence/strings/keyword_name_block_4_4_4.txt`.
First/last rows of the registration table show the array covers far more than effects:
`id=0xb "id"`, then GUI/settings names (`machineid`, `filelist`, `font`, `height`, `x`),
and it ends on triggers (`num_claims_on_system`, `hostile_military_power`, `num_owned_colonies`).
§8's "naming pool `0x2490000`" is a point *inside* this block, not a separate pool.

No static pointer array refers to these names (scanned `.rdata`/`.data`/`.pdata`/`_RDATA`/
`.rsrc`/`.reloc` for 8-byte aligned qwords in the block: 3 hits, all unrelated). The names
are reached **only** by the `lea r8` above.

### What this does NOT yet give us
The descriptors live at `0x337B400`, which is past `.data`'s raw size (`0xD9200`) but inside
its virtual size (`0xDE16D4`) — i.e. **BSS, zero in the file**. So the vtable pointer each
slot ends up with is **not** statically readable; something constructs it. `0x1D15270`
receives only (slot, id, name), so the class cannot come from its arguments — it must come
from a separate per-descriptor initializer, or the slot is written by the *caller's*
translation unit. **That is now the open question for A4**, and it is the last thing standing
between this table and "add a new hardcoded keyword".

### Falsified along the way: `0x337A844` is not a registration guard byte
Set at `0x1BCFD83` inside function `0x1BCFD40`, which unpacks a config dword read from
`[rcx+0x10]` into globals `0x2A00E30/34/38` and derives bit 4 → `0x337A844`, bit 5 →
`0x337A846`. Readers (`0x1BCC5F9`, `0x1BCC907`, `0x1BCC987`) each gate a trace call —
`0x1CA35D0` with format string `"%i"` at `0x25BDE70` — and `0x337A758` beside them is a
xorshift RNG state. **It is a trace-enable flag.** PLAN §6 C3's "register after `0xCCCEB0`
finished, keyed on guard byte `0x337A844`" is invalid and needs a new trigger.

Note `0x337A844` is only 0x144 bytes below the descriptor array base `0x337B400`; both sit in
the same BSS region, which is how §8 came to read the one as the other's guard.

## 17. A4 solved — the keyword→behaviour binding is static thunk arrays (2026-09-29, offline)

§16 left one question open: where does a keyword get its *behaviour*. Answer: not from the
descriptor array at all. Two more facts kill that hypothesis, then the real binding shows up as
`.rdata` arrays of one-shot registration thunks.

### The token array entry carries no behaviour
Disassembly of everything that touches `0x337B400 + 0x120*n` (scanned by `scripts/descscan.py`,
**19,727 refs total, all accounted for**):

| site | count | what |
|------|-------|------|
| driver `0x172E50..0x1AF1E7` | 9,863 | `lea rcx, [entry]` → registrar `0x1D15270` |
| `0x21CBFF0` onward | 9,863 | one 0x1b-byte thunk **per entry**: `push rbp; sub rsp,0x20; mov rbp,rdx; lea rcx,[entry]; call 0x170800; ret` |

Nothing else in the image refers to those slots, and no `.rdata`/`.data` qword holds one
(byte-searched `0x1433CC0A0`, `0x1433E04A0`, `0x14337B400` → 0 hits). So the array is closed.

`0x170800` is a **string destructor**, not a constructor of behaviour: it resets vtable
`0x247B078`, frees the heap buffer if `[+0x10] != &entry+0x20`, then sets vtable `0x247B098` and
zeroes length. Entry layout, now fully pinned:

```
+0x00 u32  token id          (written by 0x1D158A0 from edx)
+0x04 u8   flag              (cleared)
+0x08      string object: vtable ptr          -> 0x247B078 / 0x247B098
+0x10      buffer ptr          (= &+0x20 inline, or heap)
+0x18      capacity qword      (= 0x100)
+0x1C      length dword
+0x20      inline name buffer, 0x100 bytes
= 0x120 stride
```
i.e. `{id, name}` and nothing else. §8's `rcx/edx/r8` signature was right; `0x247B078` is the
**cstr vtable**, which is why it looked like it might be an effect vtable.

### A3 half-solved on the way: registration ids are compile-time immediates
The driver writes `mov edx, 0x2778` for `add_modifier` (10104), `mov edx, 0x3e21` (15905), etc.
**No allocator, no `gen<<24` field** — the generation-tagged handle is a *runtime lexer* concept;
registration ids are plain literals. Consequence: any static table may key on a token id, and
`scripts/idscan.py` can find those keys.

### The binding: `.rdata` arrays of ~106-byte registration thunks
Found by byte-searching for a *relocated qword pointing at a function start* and taking maximal
runs ≥ 40 (`scripts/thunkarrays.py`). The shape, from `0x1045B0` = `add_modifier`:

```
mov  rbx, [0x33746E8]              ; BST global, lazily created
test rbx, rbx
jne  +
  mov  ecx, 0xb0 / 0x10 ...        ; operator new
  call 0x3AEBA0                     ; db ctor
  mov  [0x33746E8], rax
mov  ecx, 0x10
call <operator new>                 ; p
lea  rcx, [0x26380C0]              ; docstring
mov  [p+8], rcx
lea  rcx, [0x260ABD8]              ; 16-byte class-info record
mov  [p+0], rcx
mov  r8,  p
mov  edx, 0x2778                    ; token id, compile-time
mov  rcx, rbx
jmp  0x3AEF60                       ; BST insert(key=edx, value=p)
```
The 16-byte class-info record is `{ctor 0x34C090, factory}`; `0x34C090` is shared by all and only
places the tiny 2-slot vtable `0x24C7C68` on the registry value itself.

Arrays and their target db (counts from `thunkarrays.py`):

| array | len | db global | meaning |
|-------|-----|-----------|---------|
| `.rdata 0x23AC600` | 754 | **`0x33746E8`** (739) | **effects** |
| `.rdata 0x23AF628` | 482 | `0x32611C8` (469) | **triggers** |
| `.rdata 0x23B0540` | 405 | `0x32611C8` (405) | triggers, second block |
| `.rdata 0x23AF260` | 113 | mixed (2) | mostly non-id thunks |
| `.rdata 0x24B04D0` | 647 | many one-offs | not keyword-keyed |
| `.rdata 0x2666068` | 965 | — | 0x70-byte thunks, ids present but different idiom |
| `.rdata 0x269C110` | 1736 | — | 0x25-byte entries, not registration |

Effect + trigger totals (740 + 875 keyed records) line up with the ~700 hardcoded effects and
~900 hardcoded triggers of 4.4.x. Full dump:
`evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`
(3,900 rows; columns array/index/thunk/db/token_id/keyword/class-info/docstring-首行/insert-fn).

### Closed chain, worked example
```
"add_modifier"  .rdata 0x247FCF8
  → driver 0x172E50 site 0x179EC9 → registrar 0x1D15270(slot 0x33CC0A0, id 10104, name)
    → token entry {10104, "add_modifier"}  (0x337B400 + 0x120*1149)
  → thunk array 0x23AC600[622] = 0x1045B0
    → BST insert @ 0x3AEF60, db 0x33746E8, key 10104,
      value = {0x260ABD8 → {0x34C090, factory 0x18A3340}, doc "Adds a specific modifier…"}
  → factory 0x18A3340:  operator new(0x528); call 0x18E6010
  → ctor 0x18E6010:     [obj]   = vtable 0x2641B38
                        [obj+8] = vtable 0x25EDEF0 (base sub-object)
  → vtable 0x2641B38:  slot[1] 0x18AA2F0 (Execute override, 0x4f bytes)
                       slot[2] 0x18E60C0 (ExecuteActual, 0x145 bytes)
```
**Side finding that corrects `ceffect_vtable_map_4_4_4.txt`**: that map selects vtables whose
*slot[1] is base Execute* `0x1D08520`. `add_modifier` overrides Execute, so it is **not** in the
1,805. The map is a floor on classes that reuse base Execute, not the class count.

### The recipe this finally gives
To introduce a genuinely new hardcoded keyword without touching official mod semantics, at
runtime, in load order before any script parse:

1. obtain a token for the name — the static array is fixed at 9,863 entries, so this needs the
   **dynamic** token path (the still-open half of A3). If it only appends to the runtime hash
   rather than the static array, no code patch is needed.
2. `new(0x10)` a value record `{&class_info, &docstring}` exactly as `0x1045B0` does.
3. insert it into `0x33746E8` (effects) / `0x32611C8` (triggers) via `0x3AEF60`, keyed by that
   token id.
4. make `class_info.factory` be `new(size); call ctor` returning an object whose vtable slot[2]
   is our `ExecuteActual` (base Execute `0x1D08520` dispatches `call [rax+0x10]`, so slot[1] may
   stay base).

Step 1 is the only remaining unknown, and it is now a narrow one. PLAN Phase C (QuickJS driving
`ExecuteActual`) has its entry point: the factory in step 4 is a plain `new + ctor` we control.

## 18. A3 second half SOLVED — dynamic tokens: the naming pool DOES grow (2026-09-29, offline)

**Trigger for the search**: a `.rdata` string sweep (not IDA) turned up
`0x26E50C8 = 'Creation of dynamic token "'` and, adjacent to it,
`0x26E5088 = 'C:\mnt\gsg\stellaris\augustus\clausewitz\pdx_parser\lexer.cpp'` plus
`0x26E50E8 = '" failed, keywords may not start with a digit or '-'.'`. `scripts/find_refs.py` gives
**exactly one** code ref to the message: `0x1D1341F`, inside function **`0x1D13270..0x1D1356D`**
(.pdata, 0x2FD bytes). That function is the runtime token allocator §17 step 1 needed.

### The allocator: `GetOrAddToken(rdi = lexer_ctx, name at rdi+0x10)` = RVA `0x1D13270`

```
rdi = 0x1D12C60()                       ; token DB singleton, object at RVA 0x37347A0
name = std::string at [rdi+0x10]        ; SSO: if cap([+0x18]) >= 0x10 use heap ptr [+0x00]
if name[0] == '-' or name[0] in '0'..'9'  -> error path 0x1D133E2 (the lexer.cpp message above)
call [[rdi]+0x10](rdi, name)            ; DB slot[2] = 0x1D14B20 lookup-by-name
  if found: return *node                ; the existing id, no allocation
--- miss: allocate ---
r14d = [rdi+0x64] + [rdi+0x84] + 1      ; new id = map_size + max_static_id + 1
rcx = 0x120; call 0x2185218             ; operator new(0x120)  <-- SAME stride as the static array
call 0x1D152D0(new_slot, edx=new_id, r8=rdi)         ; the DYNAMIC descriptor ctor
node = operator new(4); *node = new_id
call [[rdi]+0x30](rdi, name, node)      ; DB slot[6] insert into the name->id map at [rdi+0x50]
call 0x22D0E0(rdi+0x50, [rdi+0x64], &new_slot)
[rdi+0x80] = new_id + 1
return new_id
```

### The decisive shared writer

Both registration paths converge on **`0x1D158A0(rcx=slot, edx=id, r8=name chars, r9=len)`**:

```
0x1D158C7  mov  dword ptr [rcx], edx     ; slot+0x00 = token id
0x1D158C0  mov  byte ptr [rcx+4], 0
           ... assign the SSO string at slot+0x08 (vtable 0x247B078, buf slot+0x20, cap 0x100)
```

* static path: driver `0x172E50` → `0x1D15270(slot, id, name)` → `0x1D158A0`
* dynamic path: `0x1D13270` → `0x1D152D0(slot, id, ctx)` → `0x1D158A0`

So a runtime-created descriptor is **byte-for-byte the same structure** as a static one. §17's
layout is confirmed a second time, from the allocating side this time rather than from a ref census.

### Field map of the token DB (`0x37347A0`, ctor `0x1D13570`, guard byte `0x37347E8`)

| offset | meaning | evidence |
|--------|---------|----------|
| `+0x50` | name → id hash map | `[[db]+0x30]` insert; `0x22D0E0(db+0x50, …)` |
| `+0x64` | map size | seeded by the driver loop; read in the allocator |
| `+0x84` | **max static token id** | ctor `0x1D136E5` runs `max([slot+0])` over the array |
| `+0x80` | next free id | `= [db+0x84] + 1` after seeding; `= new_id+1` after each allocation |

The seeding loop bound is `rbx` stepping `+= 0x120` while `rbx < 0x2B57E0`, and
**`0x2B57E0 / 0x120 = 9,863`** — the exact entry count §17 measured from the reference census,
derived here independently from a compile-time immediate.

### Why the BST accepts a dynamic id

`0x3AEF60(db_global, edx = id, r8 = value)` walks the tree comparing
`cmp dword ptr [node+0x20], ebx` — the key is a **raw 32-bit token id**, with no range check against
the static table and no requirement that the id came from the compile-time driver. So inserting a
behaviour keyed by an id that `0x1D13270` just minted is well-formed by construction.

### Consequence: PLAN.md §4's completion criterion is now met

The §17 recipe had one open step. It is closed, and no binary patch of the static table is needed:

1. `0x1D13270` with the desired name → a fresh token id (name must not start with `-` or a digit).
2. `new(0x10)` a value record `{&class_info, &docstring}`.
3. `0x3AEF60(0x33746E8 | 0x32611C8, that_id, value)` after `0x3AEBA0` lazy-ctors the db.
4. `class_info.factory` = `new(size); call ctor` returning an object whose vtable slot[2] is our
   `ExecuteActual` (base Execute `0x1D08520` dispatches `call [rax+0x10]`).

Every step is now a real address in the shipping 4.4.4 binary, reached by a real call sequence that
the engine itself performs. **A new hardcoded keyword is reachable without patching any static table.**

### Still not established (honest limits)

* The DB singleton is a **Meyers-style lazy object guarded by `0x3734790`/`0x37347E8`**, so its
  address is a module global but its contents only exist after first use — the values above were
  read from the ctor, never observed live.
* `[[db]+0x10]` (`0x1D14B20`) and `[[db]+0x30]` are read as *slot offsets from the vtable
  `0x26E5180`*; the map's own internals (bucket type, allocator at `0x247A4D0`) were not mapped.
* The **order** between "engine allocates our token" and "engine has lazy-ctor'd the effect DB" is
  not yet pinned to a single hook point in the DLL; that is now a Phase C engineering question, not a
  reverse-engineering unknown.
* Nothing here was observed in a running process. Per §1's authorization boundary this stays
  record-only if it ever is.

## 19. When the engine mints dynamic tokens — all 567 call sites of `0x1D13270` bucketed (2026-09-29, offline)

§18 left one question open: *when* does the token id space grow? A naive full linear disassembly of
`.text` to answer it had run past 10 minutes without finishing, so the search was reformulated as a
**byte-level encoding match** instead: a direct `call`/`jmp` to a fixed RVA is only ever
`E8 rel32`, `FF 25 rip` or `FF 15 rip`. Matching those three encodings over the section's raw bytes
and resolving each hit through `.pdata` answers the same question in **2.6 s**.
Tool: `scripts/fastcalls.py <rva> [--top N]` → `evidence/xrefs/callers_<rva>_buckets.tsv`.
(Verified against a known-good capstone dump for the site count: **567 direct sites, 139 functions**.)

Two decode bugs found on the way, both worth remembering:

* x86 rip-relative lives in **`op.mem.base == X86_REG_RIP`**, not `op.reg` — `op.reg` is
  `X86_REG_INVALID` for a memory operand, so a `op.reg == X86_REG_RIP` test silently matches nothing.
* `__FILE__` in this binary is a full build-machine path with backslashes
  (`C:\mnt\gsg\stellaris\augustus\augustus\source\policy.cpp` at `0x24F8290`), so a filename regex
  over `[\w./+-]+` matches none of them. Match the **tail** instead. This also pins the source tree
  layout: `augustus/augustus/source/*.cpp`.

### The 139 buckets

| Sites | Functions | What they are |
|---|---|---|
| 505 (89 %) | 101, all `0x8f6`/`0x846` bytes, `0x1930e70..0x196d3e6` | **scope-iterator registration family** — one function per `each_*` keyword, each carrying its own docstring + keyword name (`"Iterate through each agreement"` @`0x2668D18` with `"agreement"` @`0x24A1100`; also `ambient_object`, `system_ambient_object`, `archaeological_site`, `owned_army`, `planet_army`, `ground_combat_attacker`, `astral_rift`, `bypass`, `owned_pop_group`, …) |
| 10 | 1: `0x3797c0..0x37b056` | **`mod_%s` modifier-name generator** (`%s_build_cost_mult`, `mod_ship_build_speed_mult`, …) |
| 9 (1 each) | `0x388130`…`0x389224`, all `0x34` bytes | **Meyers lazy token accessors** (see below) |
| 5 each | `0x543180`, `0x544163` | unnamed pair, same shape |
| 46 | 31 one-site functions | DB load code: `policy.cpp`, `technology.cpp` (`Child technology "%s" can't have children!`), `component.cpp` (`missing localization for component tag [%s]`), `situation_type.cpp`, `triggered_event_description.cpp` (`0x354e70`: `event_target:` / `parameter:`), `0xa8f550` (`GFX_` prefix synthesis), `0x1a92b70`/`0x1a92fa0` (`hidden:`), `0x115bb0`/`0x116090` (`Sums all pop amounts` / `Sums all workforce`) |

### Finding 1 — the parser never creates a token

Not one of the 139 buckets is lexer/parser code: no bucket references any tokenizer message, and the
`lexer.cpp` cluster itself only *hosts* the allocator. Additionally `0x1D13270` has **zero qword
references** anywhere in the image — it is never stored in a vtable or function-pointer table, so
every use is one of these 567 static direct calls.

**Consequence for Phase C:** a new word appearing in a mod's script does **not** acquire a token id
by being parsed. Minting one is therefore *mandatory work on the DLL side* (§18 step 1), not something
the engine will do for us. §18's recipe is upgraded from "sufficient" to "necessary and sufficient".

### Finding 2 — the engine's own new-keyword template is one function

Inside a single iterator-registration function the three §17/§18 primitives appear in order:

```
0x1930e70 (0x8f6 bytes):
   0x1d13270  x5   <-- GetOrAddToken        (mint the tokens this iterator's clauses need)
   0x3aeba0   x3   <-- db lazy-ctor
   0x3aef60   x3   <-- BST insert           (publish behaviour keyed by those ids)
   0x1cc4450  x18, 0x2185218 x8 (operator new), 0x15f770 x7
```

So one iterator publishes into **three** BSTs, and mint-then-insert is the same function's business,
not two phases. This is a copyable official template for `PLAN.md` C1.

These functions are reached from `.rdata` **pointer arrays** — `0x114ce0` is a 25-byte shim
(`call 0x1930e70; lea rcx,[0x236df20]; jmp 0x218556c`, i.e. register-then-tail-call atexit) with no
code xrefs at all; its address is stored at `0x23AF208`, its sibling at `0x23AF210`. That is the same
`.rdata` init-array region as §17's three behaviour arrays (`0x23AC600`, `0x23AF628`, `0x23B0540`).
**Timing: start-up static init.**

### Finding 3 — but the id space is not frozen after start-up

The nine `0x34`-byte accessors are Meyers lazy binding, not start-up:

```
0x388130:  cmp  qword ptr [rip+0x25f7884], 0   ; 0x297f9c0  "string constructed?"
           je   -> mov dword [0x3261824], 0    ; id cache stays 0
           lea  rcx, [rip+0x25f784c]           ; 0x297f9a0 = std::string obj (buf zero in .data)
           call 0x1d13270
           mov  dword ptr [rip+0x2ed96c5], eax ; 0x3261824 = the token id
```

The cache slots form a dword block at **`0x3261740..0x3261824`**; the name objects live in `.data`
(`0x297E780`, `0x297F9A0`, `0x297F9D8`, …) and are **zero in the file** — filled at run time, then
resolved on first use. So part of the id space is minted *lazily, on first touch*, indefinitely.

### Answer to the open question from §18

There is no single point after which "all dynamic ids exist". The correct invariant for our
registration hook is much weaker, and both halves are guaranteed by the allocator itself:

1. our token is minted by `0x1D13270`, which hands out `[db+0x64] + [db+0x84] + 1` and bumps
   `[db+0x80]` — unique against every static *and* every previously minted dynamic id, whenever we
   call it;
2. `0x3AEF60` keys the BST by the raw 32-bit id with no range check (§18), so a late insert is
   well-formed.

So `PLAN.md` C3 does **not** need a "script load finished" trigger for id safety. It only needs to
run after `0x3AEBA0` has lazy-ctor'd the target db (which we can force ourselves) and before any
script referencing our keyword is *evaluated* (not parsed — parsing never mints). Ordering against
other lazy minters is a non-issue.

### Limits

* Site attribution uses message/docstring text as the heuristic; 132/139 buckets carry no `__FILE__`
  constant, so per-file counts above are a floor, not a partition.
* `0x1930e70`'s exact role (per-iterator ctor vs a `register_iterator(...)` body) was read from its
  prologue (`lea rdx,[0x24A1100]; lea r8,[0x2668D18]; call 0x192B440`) and not verified by trace.
* The nine lazy accessors' keyword *names* could not be read statically — their `std::string` buffers
  are zero in the image. Knowing which keywords they bind needs a live read of `0x297F9A0` etc.
  Per §1 this is only worth doing under an explicit record-only authorization.
* Nothing here was observed in a running process.

## 20. C0.4 SOLVED — `0x1D13270` calling convention pinned, and the descriptor bytes are now derivable (2026-09-29, offline)

**Why this was open**: §18 wrote the allocator as `GetOrAddToken(rdi = lexer_ctx, name at rdi+0x10)`
while §19 observed every call site as `lea rcx, [&object]; call 0x1d13270` over objects 0x38 apart.
Zig cannot guess between those two. Decoded `0x1D13270..0x1D1356D` and both ctors it converges on,
with `scripts/disrva.py`; the contradiction resolves in favour of §19, and §18's `rdi+0x10` was the
*field* offset inside the argument, not a register.

```
0x1d13270  mov [rsp+0x18], rbx / mov [rsp+0x20], rsi / mov byte [rsp+0x10], dl   ; spills only
0x1d13292  mov rsi, rcx                       ; arg1 = the name holder  -> rsi
           ...  dl is NEVER read again (only re-defined at 0x1d134fc)   ; arg2 is dead
0x1d1329f  call 0x1d12c60 -> rdi = token DB singleton (0x37347a0)       ; no caller precondition
0x1d132a7  lea  rbx, [rsi+0x10]               ; the std::string lives at holder+0x10
0x1d132ae  mov  rdx, [rbx+0x18]               ; cap   at holder+0x28
           cmp  rdx, 0x10 / jb -> chars = rbx ; else  chars = [rbx]     ; chars at holder+0x10  = MSVC layout
0x1d132bb  cmp  byte [chars], '-'  -> 0x1d133e2
0x1d132d0  movsx eax, [chars]; add -0x30; cmp 9; jbe -> 0x1d133e2       ; leading-digit reject
0x1d132eb  rdx = chars, rcx = rdi; call [[rdi]+0x10](db, chars)         ; lookup takes RAW CHARS
0x1d132f9  hit:  eax = [node]                                           ; existing id
0x1d13300  miss: r14d = [rdi+0x84] + ([rdi+0x64] + 1); new(0x120)
0x1d13329  call 0x1d152d0(rcx = slot, edx = r14d, r8 = rsi = holder)
0x1d1334f  ... node = new(4); *node = r14d; slot[6](db, name_key, node)
0x1d133d4  [rdi+0x80] = r14d + 1
0x1d133da  eax = r14d                                                   ; return value in EAX
0x1d1354f  error path falls through with xor eax, eax                   ; invalid name -> 0
```

**Pinned signature** (Win64):

```
u32 eax = GetOrAddToken(rcx: *const TokenNameHolder)   // rdx unused; a dead callee-save spill
struct TokenNameHolder { /* +0x00..+0x0F */ char16 pad[16];   // 0x38 apart in .data, only +0x10 read
                          std::string name /* at +0x10: MSVC {ptr-or-inline +0x10, size +0x20, cap +0x28} */ }
```

Only `holder+0x10 … +0x2F` is read (chars, size, cap); everything else in the holder is ignored, so
the DLL may pass a stack-allocated holder with an SSO `std::string` at +0x10 and nothing else valid.
Names of length ≥ 0x100 make the descriptor buffer move to the heap (see the reserve below), so keep
keyword names < 0x100 bytes — in practice < 16 keeps everything inline and needs no allocator at all.

### The two ctors are byte-identical, and both funnel into `0x1D158A0`

```
0x1d15270 (static, from the 247KB driver)  rcx = slot, edx = compile-time id, r8 = char* name
0x1d152d0 (dynamic, from 0x1d13270)         rcx = slot, edx = minted id,       r8 = holder
   both:  mov byte [slot+4], 0
          movups qword[0] -> [slot+8], [slot+0x10]      ; zeroes vtable + buffer ptr
          mov  qword [slot+0x18], 0x100                 ; cap=0x100 AND size=0 (the high dword is +0x1C)
          mov  qword [slot+8],  0x247B078               ; the cstr vtable  (lea rip, both sites agree)
          mov  qword [slot+0x10], slot+0x20             ; inline buffer
   static: strlen(r8) -> r9 ;  dynamic: r9d = [holder+0x20] (std::string size), r8 = chars
   both:  call 0x1d158a0(rcx = slot, edx = id, r8 = chars, r9 = len)
```

`0x1D158A0` in full — this is the whole byte contract:

```
mov  dword [slot], edx              ; +0x00 id
mov  byte  [slot+4], 0              ; +0x04
mov  ebx, r9d + 1                   ; size INCLUDING terminator
cmp  ebx, [slot+0x1C]               ; vs current size
jle  +
  mov edx, ebx; rcx = slot+8; call 0x1704b0     ; reserve, only if ebx > cap
mov  dword [slot+0x1C], ebx         ; size = len+1
mov  rdi, [slot+0x10]                          ; buffer ptr
call 0x2187ac0(rdi, chars, len)                 ; memcpy, WITHOUT terminator
mov  byte [rdi + len], 0                        ; terminator
```

`0x1704B0(rcx = slot+8, edx = needed)` = `if (needed <= cap) return;` else grow to
`max(needed, (int)(cap * f))`, `operator new`, memcpy the old `size` bytes, free the old buffer via
**vtable slot[3]**, then store the new buffer and cap. Because the ctor pre-sets cap = 0x100, **any
name shorter than 0xFF bytes takes the no-op path and the descriptor never sees the heap.**

### The exact 0x120 byte block a registration produces (names < 0x100)

| offset | bytes | value | written by |
|---|---|---|---|
| `+0x00` | u32 | token id | `0x1D158A0` |
| `+0x04` | u8 | 0 | both ctor and writer |
| `+0x05..0x07` | 3 | **never written** | — (zero in `.data`, garbage after `new(0x120)`) |
| `+0x08` | u64 | vtable, RVA `0x247B078` | ctor |
| `+0x10` | u64 | buffer ptr = `slot+0x20` (absolute, ASLR) | ctor |
| `+0x18` | u32 | capacity = `0x100` | ctor (`mov qword,0x100`) |
| `+0x1C` | u32 | size = `strlen(name)+1` — **includes** the NUL | `0x1D158A0` |
| `+0x20` | `len+1` | name bytes then `0` | memcpy + terminator |
| `+0x21+len .. +0x120` | | **never written** | — |

§17 called `+0x1C` "length"; corrected here to **size including the terminator**, which is what
`0x1704B0` then uses as its memcpy length — the two only agree under that reading.

### Consequence for PLAN.md C0.3: the diff as written cannot run, and what replaces it

`scripts/pestr.py 0x337b400 0x120` returns **empty** — the whole `0x120 × 9,863` array is zero in the
file, because §17 proved it is filled at start-up by the driver, not by the linker. So there are no
"real entry bytes" in `stellaris.exe` to diff a hand-built descriptor against, and
`keyword_registration_table_4_4_4.tsv` carries id/name/`descriptor_rva` but no bytes.

The strongest test still available offline is the one this section makes possible: **replay the
engine's own instructions** — table entry (id, name) → the byte block above → and require our Zig
builder to reproduce it byte-for-byte, with the only permitted differences being the id and name
fields, plus a don't-care mask over `+0x05..0x07` and the never-written tail. That is
model-derived rather than observation-derived, so it proves our builder agrees with the disassembly,
not with a running game; the residual gap stays where §18 left it (live read, explicit authorization).

## 21. C0.3 measured, C0 item 2 written — and the two dbs are NOT twins (2026-09-29, offline)

### The oracle: §20's derived byte contract, replayed by the engine's own instructions

`scripts/emu_desc.py` maps the exe's image into unicorn at its preferred base, patches the two
externals it calls (`0x2187AC0` memcpy → host copy, `0x1704B0` reserve → host no-op that raises if
`needed > cap`), and jumps into the real ctors:

* static path: `0x1D15270(rcx = slot, edx = id, r8 = name)` — the driver's own call shape;
* dynamic path: `0x1D152D0(rcx = slot, edx = id, r8 = holder)` with an MSVC `std::string` at
  holder+`0x10`, in SSO state for `len < 0x10` and heap-pointing above it.

Run over **all 9,863 entries** of `keyword_registration_table_4_4_4.tsv`:

| measurement | result |
|---|---|
| entries emitted | 9,863 (`evidence/xrefs/descriptor_oracle_4_4_4.tsv`) |
| static vs dynamic `sha256(0x120 block)` | **identical for all 9,863, 0 divergences** |
| longest keyword name in the table | **66 chars** (`country_federation_fleet_contribution_naval_cap_reduction_discount`) — `0x100` is never approached |
| rows whose inline fields all match §20 (`cap 0x100`, buf `= slot+0x20`, vtable `= base+0x247B078`, `size = len+1`) | **9,863 / 9,863** — not one entry took the heap path |

So §18's "byte-for-byte identical" claim is now a **measurement**, not an inference: the same engine
writer produces the same 288 bytes whether the id came from the compile-time driver or from
`0x1D13270`. And no real name comes within a factor of three of the `0x100` cap, so `0x1704B0`'s heap path —
the one case where §20's inline layout would stop holding — never fires for a table entry. Our own
keywords would have to be pathological to reach it, which is why `max_name_len` rejects it outright
instead of implementing it.

**Residual gap, stated plainly**: the truth source here is the disassembly executed under an
emulator, not a running game. What the oracle cannot falsify is a wrong *model* of the ctors — it
guarantees our builder agrees with the engine's bytes, given that model. §20's field table came from
instruction-by-instruction decode, and the two paths converging on one writer is independent support.

The Zig builder (`src/dll/scripted/keyword_registry.zig`) is validated against **56** of those
engine-produced vectors (a mix of shortest, longest, boundary and representative names), by sha256 of
the whole `0x120` block. 56 rather than 9,863 because the vectors are compiled into the test binary;
the full table stays in the tsv.

### The correction: effects and triggers do not share the ensure/insert pair

Wiring step 3 against the thunks, rather than trusting §17's single-idiom summary:

`add_modifier`'s thunk `0x1045B0` (effects) — **allocates and constructs inline**:
```
001045b6  mov  rbx, [rip → 0x33746E8]      ; db global
001045c2  lea  ecx, [rbx + 0x70]           ; rbx is zero here ⇒ new(0x70)
001045c5  call 0x2185218                    ; operator new, size in ecx (forwards rcx)
001045cf  mov  rcx, rax
001045d2  call 0x3AEBA0                     ; placement ctor, returns this
001045da  mov  [0x33746E8], rax             ; we publish it
001045e1  mov  ecx, 0x10 / call 0x2185218   ; value = new(0x10)
001045f7  mov  [rax+8], docstring / mov [rax], &class_info
00104608  mov  edx, 0x2778 / mov rcx, rbx
00104615  jmp  0x3AEF60                     ; insert: walks [db + 0x18]
```
`num_ships_in_debris`'s thunk `0x100260` (triggers) — **delegates the whole db lifecycle**:
```
00100266  mov  rbx, [rip → 0x32611C8]
00100270  jne  +                            ; global set ⇒ nothing to do
00100272  call 0x347BD0                     ; no args: new(0x98) + ctor + [0x32611C8] = rdi
001002ad  jmp  0x348150                     ; insert: walks [db + 0x88]
```
`0x347BD0` ends at `0x347D20  mov [rip → 0x32611C8], rdi`, i.e. it publishes its own global;
`0x3AEBA0` is a placement ctor that needs the caller's `new(0x70)` and returns the object.

Three consequences, all now encoded in `keyword_reg` (`src/dll/shared/offsets.zig`) and in the
`Db` enum's per-variant methods:

1. `RVA_DB_LAZY_CTOR` alone is **not** "the db lazy ctor" — effects take
   `new(0x70)` + `0x3AEBA0`, triggers take the no-arg `0x347BD0`. Reusing the effect sequence for a
   trigger would double-allocate and leave the real db unpublished.
2. The inserts are different functions (`0x3AEF60` vs `0x348150`) hardcoding different map fields
   (`+0x18` vs `+0x88`) — which independently confirms `scripted_db.EFFECT_DB_HEAD_PTR`/
   `TRIGGER_DB_HEAD_PTR`, previously measured by walking the live trees.
3. `0x2185218` keeps the full `rcx` and forwards it to `0x21996e8`, so the thunk's
   `mov ecx, 0x70` is a zero-extended size and a u64 first parameter is ABI-safe; a u32 one would not
   be guaranteed to clear the upper half.

Counts, from `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv` by
`(db global, insert fn)`: **736 → `0x33746E8`/`0x3AEF60`**, **875 → `0x32611C8`/`0x348150`**.

### C0 item 2, as written

`keyword_registry.zig` now has both halves: the pure byte layer, and the executor
(`getToken` → `ensureDb` → `new(0x10)` → insert) matching §19's ordering — mint, ensure, insert inside
one sequence. It is hard-gated by `authorize.c1_registration = false`, and the sequence function is
deliberately **not `pub`**, so the gated wrapper is the only way in from outside the file. That shape
is what lets the sequence be tested at all while it is unusable: 7 executor tests run it against fake
function pointers and assert the exact call order, sizes (`new(0x70)`, `new(0x10)`), which insert twin
ran, and that every failure path (rejected name, failed allocation, an ensure that did not publish)
stops before the insert (8 of them: gate, effect path, db reuse, trigger twin, name rejection,
long-name holder, failed allocation, non-publishing ensure).

What the executor still refuses to invent: `ClassInfo` is a caller-supplied pair of addresses.
§17 step 4's factory convention — when and with what arguments the engine calls
`class_info.factory` — was the one part of the recipe that remained unestablished. **§22 settled it**
(nullary `create`, object in `rax`, shared deleter at field 0), and the unknown moved on to §22.4: the
engine code that walks the BST and calls `create` at all.

---

## 22. What a `class_info` record actually is, and the factory's calling convention (2026-09-29, offline)

Closes the last unknown §21 left open. Producer: `scripts/cinfo.py` →
`evidence/xrefs/class_info_census_4_4_4.tsv` (1,605 rows). It reads every distinct `field0_rva` in
`keyword_behaviour_registration_4_4_4.tsv` **whose `db_global_rva` is one of the two keyword dbs** and
decodes each `field1` target over its exact `.pdata` extent.

### §22.1 The filter matters — a contaminated census is a wrong census

The first run took all 3,900 tsv rows and reported 1,611 records with 6 divergent `field0` values and
71 "factories that read a parameter". Every one of those exceptions came from the **2,160 rows whose
`db_global_rva` is `None`** — the type-registry init arrays around `0x24B04D0`, a different structure
entirely. Two of those rows had `field1 == 0x1D08520`, i.e. base Execute, which is what a *vtable*
holds at `+0x08`. So for those rows the "class_info" address is a class vtable, not a record.

Scoped to the keyword dbs: **1,605 records, and `field0` is `0x34C090` in 1,605 of 1,605.** No
exceptions. The lesson is recorded in `cinfo.py`'s `KEYWORD_DBS` guard.

### §22.2 The pair is `{deleter, create}`, not `{ctor, factory}`

`0x34C090` in full:

```
34c090  push rbx; sub rsp,0x20
34c096  lea rax,[rip → 0x24C7C68]      ; a 2-slot table: [0] = 0x34C090, [1] = 0x2187370
34c09d  mov rbx, rcx
34c0a0  mov [rcx], rax                 ; publish its own vptr
34c0a3  test dl, 1                     ; the deleting-destructor flag
34c0a6  je  34c0b2
34c0a8  mov edx, 0x10
34c0ad  call 0x2185254                 ; sized operator delete(p, 0x10)
34c0b2  mov rax, rbx; …; ret
```

That is a **scalar deleting destructor for a 0x10-byte object**, and `0x10` is exactly
`VALUE_RECORD_SIZE` (§21) — the block the thunk allocates as `{&class_info, &docstring}`. So `field0`
is how the *registry* frees the value record; it was never a constructor of the effect class, and the
`{ctor, factory}` label in §17 and in AGENTS.md's recipe step 4 is wrong. It being byte-identical
across all 1,605 entries is the confirmation: nothing per-keyword about it.

**Consequence for us, and it is a good one:** reusing `0x34C090` verbatim is safe *because* our step-2
allocation is also `new(0x10)`. The deleter's constant and our record size agree by construction, not
by luck. (That the destructor writes a vptr into the block it is about to free, while the live object
holds `&class_info` there, is noted and not resolved — nothing observed calls it during play, and the
engine's own teardown ordering is not established.)

### §22.3 The factory is nullary — 1,605/1,605

`cinfo.py` runs a def/use pass over the four register parameters *and* over `[rsp+N]` with
`N >= 0x20`, in **entry-rsp coordinates** (every `push`/`sub rsp` tracked). The normalisation is not
cosmetic: unnormalised, 67 of 71 flags were the epilogue `mov rbx, [rsp+0x30]` reloading a spill the
prologue wrote at `[rsp+8]` *before* the frame was set up — same slot, different coordinate.

Result: **zero of 1,605 factories read an incoming argument.** Not one indirect call in any of them
either (`indirect calls present: 0`), so the bodies are fully static and the census sees everything.

The canonical body, e.g. `tooltip`'s `0x1893180`:

```
1893180  push rbx; sub rsp,0x20
1893186  mov ecx, 0xc0
189318b  call 0x2185218                 ; operator new
1893198  xor edx,edx; mov r8d,0xc0; mov rcx,rax
18931a3  call 0x2188170                 ; memset(obj, 0, size)   [1,307 of 1,605]
18931a8  mov rcx, rax
18931ab  call 0x3AFB40                  ; shared base ctor        [0x3488E0 / 0x353BD0 for others]
18931b0  lea rax,[→ 0x2606F00]; mov [rbx], rax      ; primary vptr
18931ba  lea rax,[→ 0x24B1D78]; mov [rbx+8], rax    ; secondary vptr — objects have TWO
18931c5  mov rax, rbx
18931c8  add rsp,0x20; pop rbx; ret
```

Aggregate over the census:

| measured | count |
|---|---|
| calls `operator new` | 1,605 / 1,605 |
| zeroes the block via `0x2188170` | 1,307 |
| publishes ≥ 2 rip-relative objects (two vptrs) | 1,224 — **over-counted, see §24.4** |
| allocates exactly one size | 1,596 (137 distinct sizes) |
| reads a parameter register or stack argument | **0** |
| contains an indirect call | **0** |

**(The "publishes ≥ 2 rip-relative objects" row above is superseded — see §24.4.1. It counted
`mov rax,[rip+X]` (a pointer copied from a global) identically to `lea rax,[rip+X]` (a vtable published),
so the 1,224 it replaced had already been inflated by the trigger family's `+0x78` copies.)**

So `void* create()` — no arguments, result in `rax`, object fully constructed with its vptr(s)
published by the factory itself. That is what `ClassInfo`/step 4 must supply. It also retires the §21
formulation `new(size); call ctor`: the official ones are `new → memset → base ctor → publish vptrs`,
four steps, and the two-vptr shape is the part that would have been missed. **§24.4.1 measures that last
claim and narrows it: `+0x8` is the effect family's offset, `+0x78` the trigger family's, and 544 of the
1,605 factories publish one or zero static addresses themselves.**

### §22.4 Both halves are reached only through the value record

`fastcalls.py 0x34C090` → 0 direct code sites. `fastcalls.py 0x18A3340` → 0. `find_refs.py 0x260ABD8
0x26380C0` → **one reference each**, both inside their own registration thunk. And all 2,138 references
to the db global `0x33746E8` are the thunks reading and publishing it — the engine never re-reads the
global from `.text`.

So the consumer reaches `class_info` by walking the BST and dereferencing `node+0x28` (the value
record), and nothing else. **Where that walk happens is still not pinned**, and it is now the only
open item before C1 means anything: §22.3 says what our factory must look like, not when the engine
calls it or what it does with the result.

*One premise above was wrong, and §23 is what corrected it*: "the engine never re-reads the global
from `.text`" is false. `0x349B12` reads `0x32611C8` and `0x3B032A` reads `0x33746E8`, each behind the
same inline lazy-ctor guard the thunks use. What is true is narrower — the *class_info addresses* are
unsearchable, because `create` is reached as `[class_info+8]` and never as an immediate. The db
globals, by contrast, are plain rip operands, and that is the thread §23 pulled on.

### §22.5 A trap for whoever copies a vtable

Tempting C1 shortcut: take `0x2606F00`, replace `+0x10` with our `ExecuteActual`, install it. Do not
do it from a byte-scan. "Run of code pointers" is **not** a reliable proxy for vtable extent here:
711 of the 1,805 CEffect vtables measure ≥ 256 slots that way, because this linker packs vtables back
to back and the run walks into the neighbour's entries. (`tooltip`'s reads 256+, `add_modifier`'s 28.)
If C1 needs a modified vtable, its extent has to come from what the ctors *store*, not from scanning
until a non-code qword appears.

---

## 23. The consumer is pinned: `0x3B01A0` / `0x349AE0` instantiate by token id and call `create` (2026-09-29, offline)

Closes §22.4. Three new tools, none of which touches the running game:

| tool | what it bought |
|---|---|
| `scripts/createsites.py` | finds every site that calls `create` **by shape**, since the address is unreachable: `mov r?,[r?+0x28]` (value record) within N insns of `call qword ptr [r?+8]`, in a function that also touches the key slot `[r?+0x20]` |
| `scripts/riprefs.py` | who reads/writes a **data global**, in ~5 s: matches the rip ModRM form (`mod=00, rm=101`) at byte level and resolves `disp32` arithmetically, `--verify` re-decodes each hit aligned to its `.pdata` start. `find_refs.py` answers the same question in ~15 min |
| `scripts/vtable.py` | dumps a vtable's slots with `.pdata` bounds + the strings each slot references |

`createsites.py` alone is too blunt (221 functions pass the shape test). What made it decisive was
intersecting it with `riprefs.py`'s reader list for the db global: exactly one function reads
`0x33746E8` **and** contains a `create`-shaped call. That function is `0x3B01A0`.

### §23.1 The effect-side instantiation path, `0x3B01A0` (`0x3b01a0..0x3b0f7e`)

```
003b01c9  mov r12d, r8d            ; r8d = token id  -- the same key the thunks insert under
003b01cc  mov r13,  rdx            ; parse context
003b01cf  mov r14,  rcx
003b01dc  cmp dword [rdx+0x38], 0xb                ; a context-type check, not a keyword check
003b032a  mov rdi, [rip+-> 0x33746e8]              ; THE global. read straight from .text.
003b0334  jne 0x3b0355                             ; else the thunk's own lazy-ctor sequence, inline:
003b0336    lea ecx,[rdi+0x70]; call new(0x70); mov rcx,rax; call 0x3aeba0; mov [0x33746e8], rax
003b0355  mov rdx, [rax + 0x18]                    ; EFFECT_DB_HEAD_PTR, as pinned
003b0359  mov rax, [rdx + 8]                       ; root = head->_Parent
003b0360  cmp byte [rax+0x19], 0                   ; _Isnil
003b0366  cmp [rax+0x20], r12d                     ; _Key  -- plain u32 compare, no comparator call
003b036c  mov rax, [rax+0x10]                      ; <  -> _Right
003b0372  mov rcx, rax; mov rax, [rax]             ; >= -> _Left, keep rcx
003b038b  cmp r12d, [rcx+0x20]; jl fail            ; equality test on the lower_bound result
003b0391  cmp rcx, rdx; je fail                    ; == head  -> not found
003b0396  mov rcx, [rcx+0x28]                      ; value record
003b039a  mov rax, [rcx]                           ; class_info
003b039d  call qword ptr [rax + 8]                 ; *** create() ***  (rcx = value record, ignored)
003b03a0  mov rsi, rax; test rax, rax; jne success ; NULL is a hard failure
```

That loop is textbook MSVC `_Tree::_Lbound` for a `std::map<u32, void*>`, and it confirms
independently what §21 measured from the insert side: the head is at `db+0x18`, the key is the raw
u32 at `node+0x20`, the value is at `node+0x28`, and **nothing range-checks the key**. A token id
minted at runtime by `0x1D13270` walks out of this loop exactly like id 10104 does.

Then, on success:

```
003b0984  mov [rsi+0x20], r12d                     ; engine writes the token id INTO the new object
003b0990  call 0x1d0c9f0(r13, &out)                ; name of the keyword, from the parse context
003b09b4  call 0x15f770(&[rsi+0x28], str, len)     ; engine writes the keyword name at object+0x28
003b09da  call qword ptr [rsi_vptr + 0x98]         ; virtual on OUR object, rdx = r14
003b0a16  call qword ptr [rsi_vptr + 0x78]         ; and another one, result used as a string
```

For `add_modifier`'s vtable `0x2641B38` those two slots are `0x3B1420` (`+0x98`) and `0x18879C0`
(`+0x78`). An earlier draft of this section said `+0x98` was `0x3B1330`; that was a slot-index mix-up —
`0x3B1330` sits at `+0x70` of the same vtable, and §24.4.2 re-derives both.

`0x3B1420` is 48 bytes of code and is *not* the parse entry: `if (!rdx) return true;`, else it calls
`[vptr+0x78](obj)` and returns `true` if that is NULL, otherwise it calls `[vptr+0x78](obj)` a second
time and returns `second_result != rdx` in `al`. So what `0x3B01A0` asks the freshly created object for
is a **bool predicate**, then a pointer from `[vptr+0x78]` that it treats as a string. The recursive build is the neighbouring slot: `0x3B1330` at `+0x70` calls `[vptr+0x68]` with a
context and an out-param, then walks the child vector at `[obj+0x10]`/`[obj+0x1c]`, handing each child
the same context — **that** is the effect-tree parse, and it has 3 call sites
(`0x17F5FC0`, `0x1A1B0E0`, `0x1A76130`), none of them `0x3B01A0`. So a keyword's body is parsed by the
object `create` returned, just not from inside the instantiate path.

### §23.2 The trigger twin, `0x349AE0` (`0x349ae0..0x34a020`) — same walk, different object layout

Reads `[rip -> 0x32611c8]` at `0x349b12`, lazy-ctors through `0x347BD0`, walks `[db+0x88]`
(TRIGGER_DB_HEAD_PTR) with the identical `_Lbound` loop, and calls `create` the same way at
`0x349b77`. Post-create it differs in the field offsets, which is the useful part:

```
00349c63  mov [rdi+0x38], r15d        ; id at +0x38   (effect: +0x20)
00349c92  call 0x15f770(&[rdi+0x40])  ; name at +0x40  (effect: +0x28)
00349cb7  call qword ptr [rdi_vptr + 0x80]   ; virtual at +0x80 (effect: +0x98)
```

`0x349AE0` has exactly **one** caller, `0x34B6E0..0x34B849`, and that function carries the string
`'An error occurred when reading trigger.h %s'` (`0x24c7860`, `trigger.cpp`) — so this is the trigger
read path, and the bool in `al` from `[vptr+0x80]` is what makes a trigger fail to read.

The effect side has 10 callers, all inside the CEffect subclass code (`0x17FED70`..`0x191F53E`), i.e.
this is how an effect instantiates its **sub-effects**. Example `0x18E3000`: it special-cases three
token ids (`0xe1`, `0x2995`, `0x2ca2`) and for everything else falls through to `call 0x3b01a0`.

### §23.3 A second consumer, and it matters for C1 safety

`0x3AF130` (effects) and `0x348450` (triggers), both called from `0x1BFD30`, walk the **whole tree**
from `_Leftmost` and call `create` on every node, then `[vptr+0x78]` on the result, then append the
node's docstring. This is a database dump/export. Consequence worth stating plainly: **inserting a
keyword is not inert**. Anything that enumerates the db will call our `create` and then two virtuals
on whatever it returns. A stub `create` returning a bare object with a one-slot vtable does not just
no-op, it dereferences `[vptr+0x78]` and calls it. So the minimum well-formed thing C1 can install is
an object whose vtable has valid entries at least through `+0x98`, not merely `slot[2]`.

### §23.4 What is still unknown after this

Not nothing, and it should be said precisely:
* `createsites.py` is a *shape* filter. 221 functions match the shape; we narrowed by db-global
  readers and got one. Other consumers that reach the db through a pointer they were handed (rather
  than the global) are outside that filter — the dump pair `0x3AF130`/`0x348450` is proof such
  consumers exist, since their callers read the global, not they.
* Which of `[vptr+0x98]` / `+0x78` / `+0x68` / `+0x80` is which CEffect/CTrigger method by name is
  not established; only their call order and argument shapes are.
* Nothing here says what the *evaluation* path (`Execute`/`ExecuteActual`) needs beyond §23.1's
  slot[2]; it says what *construction* needs.
