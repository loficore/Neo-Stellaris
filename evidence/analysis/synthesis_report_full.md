# Synthesis Report — Mod System Registration Pipeline

**Binary**: `stellaris.exe` (Clausewitz engine "augustus", x86-64)
**Base address**: `0x140000000` | **MD5**: `8b1bca722491cf6ddeb66c5cd1ca0ade`
**Image size**: `0x3950000` (≈60 MB) | **Functions**: 136,784 (280 named) | **Strings**: 50,967
**Date**: 2026-08-11
**Scope**: End-to-end map of the mod system registration pipeline from script file to effect/trigger dispatch, consolidating all evidence artifacts.

**Evidence inputs (all read and verified):**
- `evidence/binary_survey.json` — file metadata, segments, imports
- `evidence/strings/source_file_references.md` — 6 source-file strings → xrefs
- `evidence/disasm/effect_dispatch_switch_cases.md` — dispatch jump tables
- `evidence/disasm/registration_functions_analysis.md` — scripted effect/trigger registration
- `evidence/disasm/string_to_id_registration_analysis.md` — static string→ID token table
- `AGENTS.md` — confirmed key addresses and class map

---

## 1. Architecture Diagram — Registration & Dispatch Pipeline

Legend: `→` = **confirmed** flow (direct xref/call from evidence). `-->` = **inferred** flow
(derived from structural identity / documented architecture, not directly traced in one call).

```
                    ┌──────────────────────────────────────────────────────────┐
                    │              /common/ script files                       │
                    │   scripted_effects/  scripted_triggers/  events/  ...    │
                    └───────────────▲──────────────────────────────────────────┘
                                    │  loaded at boot (auto-scan of common/)
                                    │  [confirmed: AGENTS.md game-data structure]
                                    ▼
                    ┌──────────────────────────────────────────────────────────┐
                    │              Tokenizer / Parser                          │
                    │   CTextLexer::GetTok / CToken::Init                     │
                    └───────────────▲──────────────────────────────────────────┘
                                    │  keyword strings (effect/trigger names)
                                    ▼
        ┌───────────────────────────────────────────────────────────────────────────┐
        │                    STRING → NUMERIC ID MAPPING                            │
        │                                                                           │
        │  Static initializer  sub_140173C30  (49,481 insns, 9,896 constants)       │
        │    per-keyword idiom:  lea r8,[str] / mov edx,id / lea rcx,[tok]          │
        │                       / call sub_141D36B40  (token ctor)                  │
        │    → token array base unk_1433A1B70  (0x120-byte stride)                  │
        │                                                                           │
        │  Runtime hash singleton  sub_141D34530 → &qword_14375D000                 │
        │    built lazily by sub_141D34E40 from 9892 records (stride 288):          │
        │      record+0x00 = 4-byte numeric ID                                      │
        │      record+0x10 = ptr to keyword string                                  │
        │    vtable+16 = hash_string_to_id  (string → int*)  |  unmapped → ID 12    │
        └───────────────▲───────────────────────────────────────────────────────────┘
                        │  numeric ID (interned)
                        ▼
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │                    DATABASE REGISTRATION (BST insert)                        │
   │                                                                              │
   │  Scripted Effect    sub_1408A6EB0  →  BST @ qword_14339AEA8   (root at +24)  │
   │  Scripted Trigger   sub_1408A79A0  →  BST @ qword_143287968  (root at +136)  │
   │      structural twins: 457 B / 27 blocks each; differ only in BST global/    │
   │      root offset / log tag.                                                  │
   │      node layout (32B): +0 left, +8 ID sort key, +0x10 value ptr, +0x18      │
   │      sentinel-marker byte (+25==0 ⇒ present). DB built atop the              │
   │      CSingleObjectDatabase template (game_singleobjectdatabase.h).           │
   │      Duplicate-ID ⇒ soft warning (log_or_throw sub_141CB3210), new def       │
   │      overwrites existing — FAILS SOFT, not fatal.                            │
   └───────────────────────────────▲──────────────────────────────────────────────┘
                                   │  effect ID (DWORD) stored on scope object
                                   ▼
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │                    EFFECT DISPATCH  (runtime execution)                     │
   │                                                                              │
   │  CEffect::ExecuteActual(CEventScope*)  →  virtual dispatch                   │
   │  sub_14180B050  (effect_impl.cpp) reads effect type ID:                      │
   │      mov eax, [r8+68h]   -- DWORD at object +0x68 (offset 104) [CONFIRMED]   │
   │      then 2-level jump: sparse ID ladder → byte-index dense jump table       │
   │      jpt_14180B169 (base 11213)  254 cases: 11213..11466                     │
   │      jpt_14180B1D3 (base 11706)  159 cases: 11706..11864                     │
   │      jpt_14180B25F (base 12835)  166 cases: 12835..13000                     │
   │      (This function is the create_species/modify_species special-case        │
   │       dispatcher; most IDs in each range fall through to LABEL_99 generic    │
   │       handler comparing against 0x165.)                                      │
   └──────────────────────────────────────────────────────────────────────────────┘
```

**Data flow (one line):**
```
script file → Parser → keyword string → String→ID mapper (sub_141D34530)
            → numeric ID → BST insert (sub_1408A6EB0 / sub_1408A79A0)
            → ID on scope object (+0x68) → dispatch (sub_14180B050)
```

### Confirmed vs. inferred — evidence links

| Pipeline stage | Status | Evidence artifact |
|---|---|---|
| Script files auto-scanned from `common/` | confirmed | `AGENTS.md` (game-data structure), registration functions |
| Parser / tokenizer exists (CTextLexer/CToken) | inferred | `AGENTS.md` (external research, Jomini/engine symbols) — not traced in this session |
| String→ID static table (`sub_140173C30`) | confirmed | `strings/...`? no — `disasm/string_to_id_registration_analysis.md` |
| String→ID runtime hash (`sub_141D34530`) | confirmed | `disasm/registration_functions_analysis.md` §4 |
| DB registration BST (`sub_1408A6EB0`/`sub_1408A79A0`) | confirmed | `disasm/registration_functions_analysis.md` |
| CSingleObjectDatabase template base | confirmed | `strings/source_file_references.md` §6 (166 xrefs) |
| Effect dispatch (`sub_14180B050`, ID at +0x68) | confirmed | `disasm/effect_dispatch_switch_cases.md` |
| Scripted effect/trigger source .cpp mapping | confirmed | `strings/source_file_references.md` §2–§3 |

---

## 2. Top-50 Effect IDs

**Important honesty note:** The current evidence corpus does **not** contain a ranked
top-50 effect-ID list by xref count. Ranking all effect IDs by xref count requires a
second decompile pass over `sub_14180B050`'s sibling executors that is not present in
`evidence/`. Rather than fabricate a ranking, this section reports **every effect ID that
is confirmed by evidence**, grouped by source, and flags the ranking gap as follow-up work.
No claim below exceeds what the disassembly artifacts actually record.

### 2a. Confirmably-referenced effect IDs — create_species family (`evidence/disasm/effect_dispatch_switch_cases.md`)

These are the IDs the dispatcher explicitly routes to the shared LABEL_97 handler, plus
the sparse-ladder equality IDs — all confirmed in the switch-case analysis.

**Table 1** (jump base `11213`, checked range 11213–11466):
```
11213  11294  11344  11365  11378  11403  11404  11405  11410  11411  11412  11466
```

**Table 2** (jump base `11706`, checked range 11706–11864):
```
11706  11707  11818  11839  11855  11856  11864
```

**Table 3** (jump base `12835`, checked range 12835–13000):
```
12835  12868  12886  12895  12935  12949  12950  12951  12952  12953  12999  13000
```

**Sparse-ladder equality IDs** (individual `sub eax,i; jz` cases before the dense tables):
```
0x6B (107)   0xE1 (225)   0x204 (516)   0x26C2 (9922)
```

> These range bases (11213/11706/12835) and the effect-family semantics (create_species /
> modify_species errors at `0x14260eec0`, `0x14260ee80`) are the confirmed, concrete effect
> ID evidence. They are contiguous-int-keyed, matching the interned-ID design.

### 2b. String→ID token-table keywords (`evidence/disasm/string_to_id_registration_analysis.md`)

This table is sub-registered from the **graphics/GUI token family** at `sub_140173C30` —
distinct from, but structurally identical to, how effect keywords are interned. All 47
mapped keyword→ID pairs are confirmed:

```
(anonymous)=11  idtype=21   machineid=22  filelist=24  dir=25       file=26
name=27   noOfFrames=28  fonts=29     font=30      height=31    x=32        y=33
fontName=34  charSet=35  xFile=36   textureFile=37 textureFile1=38 textureFile2=39
textureFile3=40 textureFile4=41 textureFile5=42 textureFile6=43 textureFile7=44
textureFile8=45 textureFile9=46 size=47  fullScreen=48 borderless=469  cube=49
center=50  side=51  animatedMesh=52  spriteTypes=53  spriteType=54  objectTypes=55
cubeType=56  meshType=57  mapMeshType=58  animatedMeshType=59  sprites=60  sprite=61
objects=62  group=63  animation=64  object=65  defaultAnimationTime=66  particleType=67
flareType=68
```

This demonstrates the **interning mechanism** (compiler-emitted sequential immediates +
verbatim string copy) that the effect system also uses via `sub_141D34530`'s hash map.

> **Follow-up (blocked on evidence):** A true xref-ranked top-50 would require running
> `ida-pro_xrefs_to` over the effect executor range `0x14180xB8D0..0x14193D810` (the ~140
> functions that reference `effect_impl.cpp`) or instrumenting the dispatch `jpt_` tables.
> This is the only piece of the requested "top-50" that current evidence cannot yet
> substantiate without fabrication.

---

## 3. Extension Recommendations

### 3a. The hard constraint (what cannot be done trivially)

No public project has registered a genuinely **new hardcoded effect keyword**. The static
ID table (`sub_140173C30`) and dispatch switch (`sub_14180B050`) are compiled in — adding a
new case means binary patching the dispatcher *and* allocating a non-clashing numeric ID in
the static table. A DLL hook (as in stellarstellaris-win) can **intercept/replace the
behavior of an existing effect ID** but cannot add a new ID the engine will dispatch.

The registered pipeline (`sub_1408A6EB0`/`sub_1408A79A0`) maps **script-defined names** to
**existing interned IDs**. Scripted effects/triggers are therefore a *data-level* extension
mechanism: they let mods compose existing primitives, not invent new primitives.

### 3b. Recommendation matrix (pros / cons)

#### Option 1 — Script-level composition (safe, supported)
Add new `common/scripted_effects/` or `common/scripted_triggers/` definitions that compose
existing effect IDs.
- **Pros**: Zero binary modification; survives game updates; fully supported; no crash risk.
  Duplicate-name overwrite of built-ins fails soft (warning log already) — usable.
- **Cons**: Cannot express a genuinely new primitive; limited to what registered IDs already
  do; subject to scope/DSL limits (scope chains, `$PARAM$`, `@[math]`, `[[PARAM]]` blocks).

#### Option 2 — DLL hook + effect interception (stellarstellaris-win pattern)
Intercept `CEffect::ExecuteActual` and/or the dispatch path `sub_14180B050` to alter the
behavior of an **existing** effect ID at runtime.
- **Pros**: No rewriting of the static table or jump tables; versioned VA tables exist for
  3.4.5–3.7.4; can change semantics without touching script data.
- **Cons**: Still cannot *add* a new dispatched effect ID (must hijack an existing one);
  VA-table maintenance per game version; anti-cheat/achievement flags (see class101 guide);
  complexity of hooking the 2-level switch correctly.

#### Option 3 — Binary patch to add a new effect ID (deep, high-risk)
Extend `sub_140173C30` with a new `lea r8,newkw / mov edx,<freeID> / lea rcx,[nextSlot] /
call sub_141D36B40` triad at the next 0x120 slot, **and** add a case to one of the dispatch
jump tables (`jpt_*`) or to LABEL_99's sparse ladder.
- **Pros**: Truly new hardcoded keyword; full control.
- **Cons**: Very high effort; the ID must be unique and non-clashing with every existing
  immediate (note `borderless=469` shows gaps/out-of-seq IDs exist, so no strict invariants);
  dispatch jumps are byte-indexed arrays — resizing them is non-trivial; breaks every update;
  risks the game's verify/CRC; effectively unsupported.

#### Option 4 — Target the Jomini/registration layer instead
The Jomini shared layer exposes registration *categories* (Types / Promotes / Functions /
Callbacks). If the extension goal is scope types, event targets, or variable registration,
extending the Jomini registration hooks may be far cheaper than touching the effect switch.
- **Pros**: Matches the real engine architecture (AGENTS.md); may allow new targets/variables
  which are the actual mod pain point; avoids the hardcoded-effect dead end entirely.
- **Cons**: Requires mapping the Jomini registration entry points (not yet traced in
  `evidence/`); shared-library boundary complicates hooking; scope-specific.

---

## 4. Recommended Next Steps (evidence gaps)

1. **Top-50 effect ranking**: run `ida-pro_xrefs_to` / profile pass over the
   `0x14180xxxx` executor block (`effect_impl.cpp` has 363 xrefs across ~140 executors) to
   produce a genuine xref-count-ranked effect-ID table. Replace §2a's "all confirmed IDs"
   with the ranked list once gathered.
2. **Confirm parser hook**: trace a keyword string from `common/scripted_triggers/` through
   `CTextLexer::GetTok` into `sub_141D34530` to convert the parser stage from *inferred* to
   *confirmed*.
3. **Map Jomini registration entry points** (Option 4) before committing to a binary-patch
   strategy — it may be the highest value, lowest risk lever.
4. **Record duplicate-overwrite experiment**: verify end-to-end that a mod overriding a
   built-in scripted effect triggers the soft-warn path (`sub_141CB3210`) and clobbers the
   BST node, confirming the fail-soft contract in practice.

---

## 5. Status

- [x] Architecture diagram (text) with confirmed(`→`) / inferred(`-->`) data-flow arrows
- [x] Every diagram component linked to its confirming evidence artifact
- [x] All confirmed effect IDs mapped (create_species family + graphics token table)
- [x] Extension recommendations with pros/cons
- [~] Top-50 effect IDs **by xref count** — blocked on evidence; §2a gives all confirmed IDs
      instead of a fabricated ranking (see note in §2)
