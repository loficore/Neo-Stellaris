# 4.4.4 C1 validation and corrections — evidence (§24–§37)

> **Volume 3 of 3.** This evidence log is split across three files; the `§` numbers are unique across them.
> §1–§15 — `runtime_444_structures.md` (live hot path, detours, CEffect class map, the falsified registration chain).
> §16–§23 — `runtime_444_keyword_pipeline.md` (the static registration pipeline: driver, descriptors, thunk arrays, token allocator, class_info, consumers).
> §24–§30 — this volume (the alias/donor decision, A5 cross-validation, ABI corrections,
> backlog, the fallback settled as an error-view builder, and the token DB's `id → name` table).
> §31–§36 — also this volume: the C2 QuickJS bootstrap (harness, the `heap_free` use-after-free, the
> native Task 5/6 paths, and the 2026-10-21 live dispatch that ended with `C2Init rc = 3` and the game gone).
> §37 — the fix for the two probe defects §36.4 recorded (disjoint return-code ranges, the exception
> captured inside `JS_NewContextDiag`, a log read-back that re-runs nothing), natively proven but **not yet
> dispatched live**.

## §24 The alias approach is a natively shipped shape — donor chosen (2026-09-29)

Decision on record: **C1 will not fabricate an object.** The new token id's value record will point at
an *existing official* `class_info`, so `create` returns a genuine engine object and every question §22
and §23 raised about vtable depth, secondary vptrs and slot semantics is inherited rather than guessed.
This section is the static justification for that choice, the donor selection, and two corrections this
pass produced. Producer of the joins: `scripts/vptrslots.py` (new) over
`evidence/xrefs/class_info_census_4_4_4.tsv` x `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`.

### §24.1 Several token ids on one class_info is not a hack, it is in the shipped data

Joining the keyword rows of the two dbs (`db_global_rva in {0x33746e8, 0x32611c8}`) against the
`class_info` census:

| measured | value |
|---|---|
| keyword rows | **1,615** (plus 1 column-shifted artifact row, excluded — see below) |
| distinct `class_info` among them | **1,605** |
| `class_info` serving **more than one** keyword | **9** |
| duplicate `(db, token_id)` pairs | **0** |
| distinct `create` functions | 1,605 — one per class_info, **none shared** |
| `deleter` | `0x34C090` in **1,605 / 1,605** |

The 9, with the keywords they serve and what their `create` allocates:

| class_info | create | new size | keywords (db : token id) |
|---|---|---|---|
| `0x269dc98` | `0x1b27a60` | `0x188` | `if`[trig:10002], `else_if`[trig:10463], `else`[trig:18251] |
| `0x260fbb0` | `0x1899560` | `0x4c0` | `set_timed_fleet_flag`[eff:10228], `set_timed_ambient_object_flag`[eff:10293] |
| `0x269caa8` | `0x1b30450` | `0x80` | `has_crisis_perk`[trig:18644], `has_menace_perk`[trig:18645] |
| `0x269e0d8` | `0x1b26040` | `0x2a8` | `empire_size`[trig:11139], `empire_sprawl`[trig:11141] |
| `0x269f398` | `0x1b20c00` | `0x2a8` | `num_owned_colonies`[trig:18817], `num_owned_planets`[trig:18063] |
| `0x269da68` | `0x1b29d20` | `0x2a8` | `num_ascension_perks`[trig:18456], `num_ascension_perk_slots`[trig:18464] |
| `0x269f608` | `0x1b1f320` | `0x330` | `custom_tooltip_fail`[trig:18268], `fail_text`[trig:18374] |
| `0x269f618` | `0x1b1f370` | `0x330` | `custom_tooltip_success`[trig:18371], `success_text`[trig:18373] |
| `0x269f698` | `0x1b1f5c0` | `0x228` | `has_designation`[trig:11081], `colony_type`[trig:11082] |

`if` / `else_if` / `else` on one `class_info` is the strongest form of the precedent: three distinct
keywords, three distinct token ids, one `{deleter, create}` record. Sharing happens at the `class_info`
level only — every `create` body is unique — so "two ids, one class_info" is a deliberate alias, not one
factory emitted twice.

*The excluded row*: the tsv contains one column-shifted line (array `0x2610210`, index 54, `thunk_rva`
`0x3b01a0`) that survives a naive `db_global_rva` filter with `field0_rva = None`. It is a differently
shaped array, not a keyword registration, and it has no census entry. Quoting 1,616/1,606 without this
note makes the join look wrong by exactly one.

### §24.2 Code-level: N thunks may reference one class_info, but the value record stays per keyword

`scripts/riprefs.py` over the four rows above:

```
2 refs to 0x260fbb0 (.text)   in funcs fa6f0..fa75a, fa760..fa7ca     (one each)
3 refs to 0x269dc98 (.text)   in funcs 11f920, 11f980, 11f9e0          (one each)
1 ref  to 0x2610210 (.text)   in func  f8cb0..f8d1a
```

Exactly one rip-relative site per keyword, each inside its own ~106-byte registration thunk. And each
thunk independently does `new(0x10)` and publishes its **own** value record. So aliasing a `class_info`
does not alias the value record: two BST nodes hold two distinct 16-byte blocks that happen to carry the
same pointer at `+0x00`, and `0x34C090` is handed the block it must free, never a shared one. **No
double-free surface is introduced by the alias.** That was the main thing that could have made this
approach unsound, and it is settled statically.

### §24.3 Donor selection

Ranking by allocation size, since §23.3 guarantees our donor's `create` runs once per db dump *for the
lifetime of the insert*:

| db | smallest object | class_infos at that size |
|---|---|---|
| effects | `0xc0` (192 B) | 12 |
| triggers | `0x80` (128 B) | 130 |

All 12 effect candidates share one callee signature exactly — `new(0xc0)` via `0x2188170`, then
`memset`, then the shared base ctor `0x3AFB40`, then two published vptrs. 129 of the 130 trigger
candidates share `new(0x80)` + the base ctor `0x3488E0`, with the zeroing done inline (`xorps`/`movups`)
rather than by a `memset` call, and the 130th — `is_active_resolution`, `class_info 0x269CFD8`,
`create 0x1B2F220` — adds one extra callee `0x1C91C30`. Uniform fronts are what make either side a safe
pick. Two donors, one per db, both verified against §23's consumer slots by reading the raw qwords:

| role | class_info | create | primary vptr | `+0x78` | `+0x80` | `+0x98` |
|---|---|---|---|---|---|---|
| **trigger donor** | `0x269caa8` (`has_crisis_perk` + `has_menace_perk`) | `0x1b30450` | `0x268ed08` | `0x1B4550` | `0x349230` | — |
| **effect donor** | `0x2611070` (`hidden_effect`) | `0x1893130` | `0x2606fe0` | `0x1596B0` | — | `0x3B1420` |

The trigger donor is doubly apt. `0x80` is the **minimum allocation across all 1,605 factories** (129
class_infos sit at it, nothing is smaller), and those 129 cover 130 keyword rows — meaning exactly one
of them serves two keywords, and it is `0x269CAA8`, the donor. So the test lands on the smallest object
in the file *and* the only already-aliased one at that size, which is the shipped shape reproduced
rather than approximated. The effect donor is the smallest effect object and a container keyword. One
property of it has to be stated plainly rather than glossed:
**11 of the 12 candidates, `hidden_effect` and `tooltip` among them, carry `0x3B01A0` at `[vptr+0x10]`**
— the slot §17 names `ExecuteActual` on runtime effects, and here it is the generic instantiate entry
itself, i.e. "build my sub-effect from the next token". So an effect donor's `+0x10` re-enters the very
path §23 pinned, and `tooltip` is *not* a distinguishable alternative on that slot — its vtable front is
byte-identical to `hidden_effect`'s. The one candidate whose front differs is `stop_terraform_process`
(`class_info 0x2609d78`, vtable `0x25ee570`, `[+0x08]` and `[+0x10]` both `0x15DB30`). Nothing in the
alias test reaches those slots — §23.3's dump path calls `[vptr+0x78]`, and construction calls nothing —
but if a later test ever feeds the minted name into script text, that is the row to pick.

### §24.4 Two corrections this pass produced

**§24.4.1 §22.3's "publishes its TWO vpointers at `[obj+0]` and `[obj+8]`" is the effect-family habit,
not a factory invariant.** `0x1b30450` publishes at `[obj+0]` and `[obj+0x78]`, which is what sent the
question back to the data. The bug was in the *measurement*: `lea rax,[rip+X]` publishes the **address**
`X` (a vtable), while `mov rax,[rip+X]` copies the **value** at global `X` (not a vtable).
`scripts/vptrslots.py` now separates them across all 1,605 factories
(written out in full to `evidence/xrefs/vptr_publish_slots_4_4_4.txt`):

| measured over 1,605 factories | count |
|---|---|
| lea-sourced stores at `[obj+0x00]` | 1,972 stores (some factories write `+0` twice) |
| lea-sourced stores at `[obj+0x08]` | 771 stores, **726 distinct factories** |
| load-sourced stores at `[obj+0x78]` | 130 — the trigger family's global-pointer copy |
| factories by number of lea-sourced stores | `0`:24, `1`:520, `2`:942, `3`:51, `4`:59, `5`:8, `6`:1 |

So **24 factories publish no static address at all** and 520 publish exactly one; the second vptr of
those objects comes from the base ctor, not the factory. §22.3's *conclusion* survives — a one-slot
vtable is not what the engine hands back — but it survives because of §23, not because of this census:
the consumer writes `[obj+0x20]`/`[obj+0x28]` and calls `[vptr+0x98]`, so the object must be at least
that wide and that deep. **And the correction strengthens the alias decision**: the secondary pointer's
offset is per-family (`+0x8` effects, `+0x78` triggers) and the base ctor contributes slots the factory
never touches. Fabricating a well-formed object would require exactly the per-class layout knowledge we
do not have.

**§24.4.2 §23.1 attributed the parse entry to the wrong slot.** `+0x98` of `0x2641B38` is `0x3B1420`, not
`0x3B1330`; `0x3B1330` is at `+0x70`. Both are now read as machine code (see §23.1's rewrite). To check
whether that was a slot-index accident or a layout property, the primary vptr of every one of the 1,581
class_infos whose factory publishes one was read directly: **`0x3B1330` sits at `+0x70` in all 723
vtables that carry it, without exception.** So the index is stable and the mistake was purely mine, from
mapping a function to a slot from memory of a dump rather than from the dump. `0x3B1330` is the base
implementation of `+0x70` (`call [vptr+0x68]`, then walk the child vector at `[obj+0x10]`/`[obj+0x1c]`)
— the recursive effect-tree parse — and `0x3B01A0` calls neither it nor anything on `[obj+8]`; it calls
`+0x98`, then `+0x78`. The corrected reading also exposes something worth knowing on its own: `0x3B01A0`
is *itself* installed as a vtable target at `[vptr+0x10]` of the 12 smallest effect template classes, so
the engine reaches the instantiate entry both directly (3 sites) and through a slot.

Side finding for §22.5, which warned that vtable *extent* cannot be derived by scanning: here it failed in
the opposite direction. `scripts/vtable.py 0x2641b38` stops its listing at `+0x78` because `0x18879C0` is
not a `.pdata` function start, yet `+0x80`, `+0x88`, `+0x90`, `+0x98`, `+0xa0`, `+0xa8` all hold `.text`
addresses. Extent heuristics truncate as well as overrun; only the call sites define which slots exist.

### §24.5 What the alias test does *not* establish

It verifies mint (`0x1D13270`) -> `new(0x10)` -> lazy-ctor -> BST insert -> `_Lbound` hit -> `create` ->
engine writes id/name -> virtual call, on a keyword the engine never shipped. It does **not** produce
usable custom behaviour: the aliased keyword will do whatever the donor class does. Choosing a donor
whose `create` is small and whose virtuals are side-effect-free is what makes the test safe, and it is
also precisely why a passing alias test says nothing about the harder C2 ("our own class"). Still
C1-class work: it mutates engine state, and **it has not been authorized.**

### §24.6 The two C1 parameters are now decided — trigger db first, official docstring (2026-09-30)

Two open choices stood between §24.3's donor and an actual C1 call site. Both are decided; recording
them here because each is a measured trade, not a preference.

**(1) Which db C1 targets first: triggers (`0x32611C8`).** Independently of the donor question, the
trigger side is the shallower pipeline, and §21's table is the reason. Its bring-up is one no-arg call
— `0x347BD0` does `new(0x98)` + ctor + publishes `[0x32611C8]` itself — whereas the effect side makes
*us* allocate (`lea ecx,[rbx+0x70]; call 0x2185218; call 0x3AEBA0`) and publish, i.e. two more engine
addresses in the chain and an extra failure mode (a returned-null ctor we must not overwrite the global
with). The insert is one tail call either way (`0x348150` vs `0x3AEF60`). Worked reference thunk:
`0x127e60` (`has_menace_perk`, token id `18645` = `0x48D5`):

```
push rbx ; sub rsp, 0x20
mov  rbx, [rip -> 0x32611C8]   ; test rbx,rbx / jne 0x127e7e   — have_it
     call 0x347BD0                                          — bring the db up
     mov  rbx, [rip -> 0x32611C8]
mov  ecx, 0x10 ; call 0x2185218                              — our value record
lea  rcx, [rip -> 0x26C1B40]   ; docstring
mov  [rsp+0x30], rax ; mov r8, rax ; mov edx, 0x48D5         — token id 18645
mov  [rax+8], rcx                                            — store docstring
lea  rcx, [rip -> 0x269CAA8] ; mov [rax], rcx                — store class_info
mov  rcx, rbx ; add rsp, 0x20 ; pop rbx ; jmp 0x348150       — tail call, insert
```

**(2) The docstring field re-uses an official `.rdata` string, not one from our DLL.** The engine keeps
`value[+8]` for the lifetime of the db — the enumerate paths `0x3AF130`/`0x348450` read every node — and
PLAN §1 already forbids unloading while `ExecHookVerify != 0` precisely because engine state holds our
pointers. Re-using the donor's own string means *no new pointer of ours* enters the db, which makes C1's
memory-lifetime question identical to the pre-C1 situation. The cost is measured and honest: the two
keywords already sharing `0x269CAA8` carry **different** docstrings —

| token id | keyword | docstring rva | text |
|---|---|---|---|
| 18644 | `has_crisis_perk` | `0x26C1BA0` | `Checks if a country has a specific Crisis Perk unlocked.` |
| 18645 | `has_menace_perk` | `0x26C1B40` | `Checks if a country has a specific Menace Perk unlocked.` |

so per-keyword docstrings are the shipped pattern and aliasing one is a deviation. It is a *cosmetic*
deviation (a modder's tooltip line describes the donor, and CWTools-style validators reading the
docstring may quote the wrong sentence) traded against a use-after-free class risk. Both strings were
read back as plain NUL-terminated ASCII, confirming §17's field is a C string, not a `std::string`.
(The chosen constant is `0x26C1BA0`, the *Crisis* line — not the `0x26C1B40` in the reference thunk
above. With a borrowed `class_info` neither string describes our keyword, so picking between the donor's
two existing lines is arbitrary; what matters is that it is one of the exe's, and that it stays stable.)

Encoding: `offsets.keyword_reg.DONOR_TRIGGER_DOCSTRING = 0x26C1BA0` / `DONOR_EFFECT_DOCSTRING =
0x2616260` (the latter is `hidden_effect`'s own), and `keyword_registry.ClassInfo.triggerDonor(base)` /
`.effectDonor(base)` bundle `{class_info, docstring}` so the future C1 call site is one line. These
helpers are pure base-relative arithmetic — they touch no engine state, which is why they can be `pub`
while `registerSequence` stays non-`pub` behind `authorize.c1_registration = false`. **C1 authorization
has still not been given**; §24.6 is parameter selection, not a green light.


## §25 A5: the token space cross-checked against the shipped scripts (2026-09-30, offline)

PLAN A5 was "use the real script names to look tokens up, a pure offline cross-check", with a note that
the first design had been rejected. It is now done, and it produced one confirmation, one new
constraint on C1, and one new mechanism. Tool: `scripts/tokencorpus.py` ->
`evidence/xrefs/token_corpus_crosscheck_4_4_4.tsv` (25,656 rows: word, occurrences, files, token id,
class, match kind).

**Method, and the two ways it was wrong before being right.** The first pass matched `(\w+)\s*=`. That
is not a head token, it is every left-hand position *including the value side of nested assignments*,
and it reported 9,858/9,863 descriptors "present" — a number smooth enough to be an artifact of
measuring the wrong relation. The second pass matched only `WORD = {`, which is a head token but is
also *only* the block form, and that understated the other way: `has_crisis_perk` came back "unused"
because triggers in shipped scripts are written `has_crisis_perk = <scalar>`. The tool now keeps the two
regexes apart and says which question each answers: `HEAD` (`WORD = {`) for classification, because a
keyword head is distinguishable from an operand only by the block it opens; `ANYEQ` (any LHS) for the
usage counts in §25.3.

### §25.1 Two independent instruments agree on every keyword id

`descriptor_oracle_4_4_4.tsv` (9,863 rows) is the engine's own writers replayed under unicorn;
`keyword_behaviour_registration_4_4_4.tsv` (1,616 rows over the two keyword dbs) is `.rdata` thunk
arrays read by `thunkarrays.py`. Neither derives its numbers from the other, but the thunk's `edx` and
the descriptor's id field are the same value written by the same allocator, so they must agree:

| | |
|---|---|
| distinct keyword names | 1,610 |
| id **agrees** with the replayed descriptor | **1,609** |
| id **disagrees** | **0** |
| name absent from the 9,863 | 1 — the column-shifted artifact row already excluded in §24.1 (its name column is `?`) |

Zero disagreements is the useful result: the id space that C1's `0x1D13270` mints into has now been read
consistently by two unrelated instruments.

### §25.2 Coverage of the script corpus

2,181 files, 433,963 block-head occurrences.

- 1,777 distinct head words resolve to a descriptor, covering 383,849 of 433,963 occurrences (88.5%).
- Only **1,742 of the 9,863 descriptors are ever a head word** in `common/`+`events/`. So the descriptor
  array is *not* "the keyword list" — most of it is scope names, GUI fields, and data keys. The keyword
  list is §24.1's 1,605 `class_info`-bearing rows, a subset.
- the 23,879 head words with no descriptor classify as follows (all derived, none hand-listed):

| class | distinct | occurrences | resolved by |
|---|---|---|---|
| `db_entry_name` | 16,363 | 21,426 | a string-indexed db (army, name list, map mode) — the file is a list *of* these |
| `scripted_template` | 3,297 | 10,314 | **string**, through `0x89F960`/`0x8A0450` — the scripted_effects/triggers/loc name spaces |
| `runtime_built_name` | 186 | 7,089 | §25.4's concatenation, then minted |
| `iterator_name_parts_missing` | 97 | 6,141 | §19's iterator family by shape; mechanism NOT pinned (§25.4) |
| `UNEXPLAINED` | 3,723 | 4,923 | long tail, 1.3 occurrences each — nested db keys one indent deeper, `common/inline_scripts/` fragments |
| `string_special` | 213 | 221 | standalone exe string with no descriptor |

The `db_entry_name`/`scripted_template` discriminator is the **indent**: a keyword head is always nested
inside something, a db entry head is what the file lists, so it starts the line at column 0.

### §25.3 Both §24.6 C1 donors are live in shipped scripts

Of the 1,610 keyword-db names: 378 appear as a block head, 1,217 appear as some LHS, 393 appear in
neither. The 393 are not evidence of dead keywords — the corpus is only `common/` + `events/`, with no
`guarantees/`, no DLC-gated contexts and no mod scripts in it. What C1 needed to know is whether the
*chosen donors* are exercised, and they are: `has_crisis_perk` 14 occurrences, `has_menace_perk` 96,
`hidden_effect` 7,101. So the alias path lands on classes the shipped game actually evaluates.

### §25.4 New mechanism: iterator keyword names do not exist in the image as strings

The `count_*`/`any_*`/`every_*` family was the largest miss class, and it is not missing — it is
*assembled*. `0x195a580` (one of the §19 iterator init functions) builds two std::strings in place: 16
bytes from `0x266A620` = `owned_pop_amount`, 6 bytes from `0x266A818` = `count_` (a dword plus a word —
that is why a whole-name search finds nothing), appends through `0x15F420`, then frees both. The image
contains **zero** bytes of the string `count_owned_pop_amount`, and `count_` has exactly **104** rip
references, one per function in `0x195a580`..`0x19a7268`. `every_` is at `0x2668DD8`, `random_` at
`0x2668DD0`.

This is the strongest offline confirmation of §19's timing argument available: a keyword the parser
accepts as a head token can have **no static descriptor at all**, because `0x1D13270` mints it during
init. Our C1 sequence is the same shape one step later.

It also bounds the claim: `any_`, `all_` and `ordered_` never appear as standalone strings anywhere in
the image (`any_\0`: 0 hits), so those 97 names (6,141 occurrences) are not literal concatenation either.
The iterator family has a second naming mechanism, and this pass did not identify it.

### §25.5 New constraint on C1: token lookup is case-insensitive

Scripts write `NOT = {`, `OR`, `AND`, `NOR`, `NAND`, `IF`, `ROOT`, `FROM`, `ICON = 3` — and the
descriptor table holds **no uppercase entry for any of them**: it has lowercase `not` (1062), `or`
(16433), `and` (16431), `nor` (18358), `if` (10002), `icon` (181). 35 head words matched *only* after
case-folding. Meanwhile the table does keep mixed-case names as authored (`noOfFrames`, `fontName`,
`xFile`, `textureFile`) and contains **zero pairs differing only by case** — which is what a
case-insensitive key requires, not what a case-sensitive one would allow.

So the parser treats case variants as the same word. Whether `0x1D13270` folds the same way is **not
settled statically**: it delegates the lookup to a virtual at `[rax+0x10]` (`0x1d132f1`), one indirection
deeper than the code read in §20. Both possible answers are bad, and the mitigation is identical, which
is why it can be adopted without resolving that: a name differing from an official keyword only by case
is either a *silent reuse* of that id (`GetOrAddToken` returns the existing one, and nothing in `eax`
distinguishes a mint from a hit) or a *second id for one word* whose resolution order then depends on
which map the parser consults. **C1 pre-flight: the candidate name must be unique up to case folding
against all 9,863 descriptors and the 1,610 keyword names**, i.e. `tr name == tr existing` for no
existing name — one `awk` over `descriptor_oracle_4_4_4.tsv`, and §20's `-`/digit rule is *not*
sufficient on its own.

**Where that pre-flight now lives** (both sides, 2026-09-30):
* `scripts/c1_preflight.py --name X --db triggers` — offline, read-only, joins the oracle and the
  `.rdata` keyword census, FAILs on an exact or case-folded collision, applies §20's leading-char rule,
  WARNs on mixed case, and prints the predicted first id: `[db+0x84] 18817 + [db+0x64] 0 + 1 = 18818`.
  Reading rule for the live run: a **larger** id is normal (§19 — lazy accessors keep minting through
  start-up), a **smaller** one means precisely the collision this check exists for. Exit 0 = clear.
  Verified in both directions: `NOT` → collides with `not` (1062), `Add_Modifier` → `add_modifier`
  (10104), `-foo`/`2foo` → §20 rejection; `chokepoint_score` and `has_chokepoint_control` come back clean.
* `keyword_registry.NameCheck` + `getToken` — the same rule inside the executor, enforced *before*
  `0x1D13270` is called, so a colliding shape cannot reach the engine at all. It checks the three things
  knowable without the table (empty, §20's first char, all-lowercase) and returns
  `RegisterError.NameNotMintable`. `buildDescriptor` deliberately still accepts mixed case: it mirrors the
  engine's byte layout for names that are already minted (`noOfFrames` &co. exist in the table), whereas
  only the **mint** path is the hazard. The `eax == 0` branch is kept as the check for rejections this
  side cannot predict — a test drives it with a name `NameCheck` accepts, so the pre-check is proven not
  to mask the engine's own answer.

### §25.6 What A5 does not do

It does not read a live map, so the comparator question in §25.5 stays open, and it does not name the
`any_`/`all_`/`ordered_` mechanism. Neither blocks C1: the recipe never depends on either. And as
everywhere in §24-§25, this is all offline reading — **no engine state was touched, and C1 remains
unauthorized.**

## §26 The `Execute` argument is a call-depth frame, not a `CEventScope` — the 3.x `+8`/`+16` claim is falsified (2026-09-30, offline)

Found while clearing PLAN §7's "dead 3.x reference" item, which turned out not to be dead: the same
3.x offsets are **live in the shipped DLL** (`main.zig` → `api/bridge.zig` → `api/scope.zig` reads
`[handle+8]` as scope type and `[handle+16]` as object id, and `offsets.zig` labels both
`[UNVERIFIED 3.x]`). So the offsets were re-checked against the 4.4.4 code rather than inherited.

`python3 scripts/disrva.py 0x1D08520 60`, first 40 bytes of the base `CEffect::Execute`:

```
01d0852a  mov  eax, dword ptr [rdx + 8]     ; arg2 + 8
01d0852d  mov  rbx, rdx                     ; rbx = arg2
01d08530  mov  rdi, rcx                     ; rdi = this (the effect)
...
01d08566  mov  eax, dword ptr [rbx + 8]
01d08569  inc  eax
01d0856e  mov  dword ptr [rbx + 8], eax     ; ++  before the call
01d08574  mov  rax, qword ptr [rdi]
01d08577  call qword ptr [rax + 0x10]       ; ExecuteActual(this=rdi, arg2=rbx)
01d0857a  dec  dword ptr [rbx + 8]          ; --  after it
01d08585  cmp  dword ptr [rbx + 8], 0
01d08589  jl   ...
```

`[arg2+8]` is incremented immediately before `call [vptr+0x10]` and decremented immediately after, and
compared against 0 — that is a **recursion/call-depth counter**. A scope type is not something you
`inc`/`dec` around a virtual call. Independent confirmation from the callee: `0x1D116A0` (called with
the same `rbx` both before and after) starts `cmp byte [rcx+0x18],0` → `mov ebp,[rcx+8]` →
`test ebp,ebp; jle <skip>` → `call 0x1D12C60`, i.e. it reads the same dword as a *guard* and only then
touches the token DB singleton. So `arg2` is an execution frame carrying depth, and:

**`c_event_scope.OFFSET_SCOPE_TYPE = 8` is false for the object `CEffect::Execute` receives.** Whether
some other 4.4.4 object is the real `CEventScope` is a separate question — what is measured here is
that the value `api/scope.zig` would return for "scope type" is a call depth.

### §26.1 The chain that does reach a keyword id

`0x535070` (the sibling slot) is the pointer chase:

```
0053507f  mov  rax, [rdx + 0x30]     ; frame -> +0x30
00535089  mov  r8,  [rax + 8]        ; -> +8   (a current-scope pointer)
0053508d  mov  ebx, [r8 + 8]         ; -> +8   (a dword)
00535091  call 0x1D085B0
0053509c  call qword ptr [rax + 0x30]
005350a9  mov  r9,  [rax + 8]        ; same pointer again
005350b0  lea  rdx, [r9 + 0x20]      ; +0x20 -> passed BY ADDRESS
005350b4  mov  r9d, [r9 + 8]
005350c7  jmp  qword ptr [rax + 0x28]  ; -> 0x5350D0(this, &[x+0x20], id, id)
```

So the id reaches `0x5350D0` from `[[frame+0x30]+8]+8`, and the object it indexes into is
`[[frame+0x30]+8]+0x20`. `0x5350D0`'s compare chain is keyed on that dword — 45 id-bearing sites in
`evidence/xrefs/token_id_use_sites_4_4_4.tsv`, **22 distinct ids**:

```
27 name          66 defaultAnimationTime   80 attenuation   95 graphicsSettings   144 maxHeight
266 sendgame    644 contractOnLeave       717 template    10856 victory_year    11365 design
11430 no       11842 primitive           13446 ironman    13910 clustered      14069 crises
14707 random_advanced_empires  15258 num_hyperlanes  16230 logistic_ceiling    16314 yes
17230 cosmic_storm_early_game_spawn_chance_scale  17802 naval_capacity_mult   18109 habitability
```

**What that corrects in §7.** §7 called `0x5350D0` "the effect/trigger dispatch switch" and
"`trigger:` keyword evaluator", and its conclusion 2 named it "the real runtime extension surface".
The id set it actually dispatches on does not support that reading: alongside plain script keywords
(`template`, `victory_year`, `design`, `no`/`yes`, `primitive`, `clustered`, `habitability`,
`naval_capacity_mult`) it carries **GUI and engine-settings keys** — `defaultAnimationTime`,
`attenuation`, `graphicsSettings`, `maxHeight`, `sendgame`, `contractOnLeave`,
`cosmic_storm_early_game_spawn_chance_scale`. A trigger evaluator does not dispatch on `graphicsSettings`.
The reading that fits is the generic one: **`0x5350D0` = "read the value stored under this token id"**
for the object at `+0x20`, which is why a `trigger:` *key* lookup appears inside it (case `0x2cd` loads a
string from `template+0x288` and looks it up in `0x325EBA0`). That is a property getter over the token
space, not the keyword executor — so §7 conclusion 2 should not be used to justify detouring it. The
keyword executor remains what §23/§24 measured: `create()` on the BST node, then the class's own virtuals.

### §26.2 What is still not pinned

The frame layout is only known at the three offsets the code touches (`+8` depth, `+0x18` a byte guard,
`+0x30` a pointer); the object behind `+0x30` is named only by its two used fields (`+8`, `+0x20`). No
live read was taken — §26 is disassembly of the shipped image, and the names "current scope"/"frame" are
convenient, not established. What C2 needs before `api/scope.zig` can be trusted is the opposite of a
comment: a call site that hands a real `arg2` in, which is only obtainable from the record-only detour.
**No engine state was touched here; C1 and any new detour remain unauthorized.**

### §26.3 `ceffect.zig`'s layout is not just unverified, it is out of bounds

`src/dll/effects/ceffect.zig` claims "CEffect object layout (verified from IDA)" with name at `+0x38`,
id at `+0xFF0`, vtable at `+0x6A8`. Three independent measurements already in this file contradict all
three fields, and the second one can be settled arithmetically from the census:

* `+0xFF0` — joining `evidence/xrefs/class_info_census_4_4_4.tsv`'s `new_sizes` column against 0xFF0:
  **only 3 of the 1,605 keyword classes allocate enough for a field at +0xFF0 to exist** (largest is
  `0x1eb0`); the other 1,602 would read past the end of the object. An id field cannot live there.
* `+0x6A8` as the vtable — §24.4 measured the opposite in 1,605/1,605 factories: the vptr is published
  at `[obj+0]`, which is also what §23's consumers assume (`mov rax,[obj]; call [rax+0x98]`).
* the real 4.4.4 id/name pair on a keyword instance is measured in §23: the engine writes
  `{id at +0x20, name std::string at +0x28}` for effects (triggers `+0x38`/`+0x40`) — which is also why
  `OFFSET_EFFECT_NAME = 56` (`+0x38`) is *not* an effect name field: `+0x38` is the **trigger** id slot.

Status at the time of measurement: `ceffect.zig` and `triggers/ctrigger.zig` were not imported by
anything (`main.zig` → `exports`/`quickjs`/`api/bridge`/`scripted/{lookup_hook,exec_hook}`), and
`build.zig`'s effects/triggers handler steps are commented out with "SKIPPED", so neither was compiled
or tested. Proof they are not tested: `ceffect.zig`'s own `test "offsets: constants match expected
values"` asserted `SCRIPTED_EFFECT_BASE == 4081`, while `offsets.known_effect_ids.SCRIPTED_EFFECT_BASE`
has been `10000` since the 4.4.4 re-anchoring — if that test ran it would fail. Dead, wrong, and
silently excluded is the worst combination to leave in place.

**Decided and done (2026-09-30, user: 删除吧)**: both files deleted. Re-anchoring was rejected because
their hook *model* is what 4.4.4 invalidated — a single absolute `ExecuteActual`/`Evaluate` address to
detour does not exist when dispatch is `call [vptr+0x10]` per instance (§26) — so "keep the skeleton"
would have kept the wrong shape, not just wrong numbers. `zig build` and `zig build test` are unchanged
after the deletion (`270/270`, the DLL links), which is the confirmation that nothing depended on them.
**Consequence still open**: `effects/handler.zig` and `triggers/handler.zig` were imported only by these
two files, so they are now unreachable too; they are kept for the moment as the intended C3 JS-routing
layer, and README marks them as orphans.

## §27 `GetScriptedEffect`/`GetScriptedTrigger` are not getters — and the old detour read both name strings from the wrong place (2026-09-30, offline)

Raw output: `evidence/logs/lookup_probe_4_4_4.log` lists the commands; the decoded listings were produced
by `scripts/disrva.py` against the local exe copy, no process involved.

Why this matters now: `scripted/lookup_hook.zig` is the one live Stage-1 detour aimed at these two, and
PLAN §6 C1's pass criterion ② was written as "trigger lookup `0x8A0450` returns non-empty for the new
name". Reading the two functions end to end says that criterion is **not observable**, and that the
recorder was reading garbage.

### §27.1 The ABI: `r8` is a holder, the string is at `r8+0x10`, and the chars are one byte

Both prologues are identical apart from the globals they later touch:

```
0089f960  mov     [rsp+0x10], rbx
0089f965  mov     [rsp+8],  rcx        ; rcx = out
0089f975  mov     ebp, edx             ; edx = requested id (-1 = by name)
0089f977  mov     rsi, rcx
0089f97a  lea     rdi, [r8 + 0x10]     ; *** the string object is at r8+0x10 ***
0089f981  cmp     qword ptr [rdi + 0x18], 0x10
0089f988  mov     rdx, [rdi]           ; capacity >= 0x10 -> [rdi] is the heap pointer
...
0089fa20  inc     rbx
0089fa23  cmp     byte ptr [rdx + rbx], 0   ; byte-wise strlen -> one byte per char
```

So the holder shape is §20's again: chars `+0x10`, size `+0x20`, capacity `+0x28`, SSO below `0x10`.
Confirmed from the sentinel caller's argument, `lea r8, [rip+0x282b014]` → `0x2A02D68`, which is in
**.data** and all zero in the file except `+0x28 = 0x0F`. Fifteen, not seven: MSVC's `std::string` SSO
bound. A `std::wstring`/`u16string` would carry 7. **`lookup_hook` modelled this as UTF-16 and read it at
`r8+0x00`** — two independent errors; for the empty `.data` holder they cancelled out, which is exactly
why the SSO test passed while a real call would have recorded a name of length `chars[0..8]` interpreted
as a size.

### §27.2 What `out` receives is constant, and `+0x40` is a vtable, not a name

The callee writes exactly four things into the 0x118-byte object (0x118 = the size the sentinel `memset`s
it to, at `0x1D7D48` via `0x2188170(out, 0, 0x118)`):

```
0089f9ce  mov     [rsi], 0x24B1990        ; briefly: the CScriptedEffectTemplate vtable
0089f9d1  mov     [rsi+8], ebp            ; the REQUESTED id, not a resolved one
0089f9d9  movups  [rsi+0x10], ...         ; 0x30 bytes: a copy of the name it was handed
0089fa4c  mov     [rsi], 0x25180A8        ; overwritten before the walk with the ref vtable
0089fa56  mov     [rsi+0x40], 0x2518128   ; *** a vptr at +0x40 ***
```

`0x2518128`'s slot[1] is `0x1D08520` — base `CEffect::Execute` — and `0x24B9E40` has the same shape, so
`+0x40` is an **embedded CEffect sub-object**. The old `ScriptedRef` declared `name: WString` at `+0x40`
and `recordResult` called `.view()` on it: the ring's `out_name`/`out_len` were a vtable pointer plus the
eight bytes after it, read as a length. That is where the "size `+0x50`, capacity `+0x58` — matches the
miss-path init writing cap 0xf there" note in the old header came from: `0x2518128`'s neighbour field, not
a string capacity.

There is **no store to `out` after `0x89FA56`**. Both functions then walk the BST and return `out`
unconditionally (`0x89FB12: mov rax, rsi; ret` / `0x8A0602`). Hit and miss produce the same bytes.

### §27.3 The walk is a duplicate check, and the warning text is the finding

```
0089fa5a  mov     rbp, [0x33746E8]        ; effect db global; null -> return
0089fa77  call    0x1D12C60               ; token db accessor
0089fa7f  mov     r8, [[rax]+0x10]
0089fa89  call    r8                       ; name -> descriptor, or null
0089fa91  mov     edx, [rax]              ;   -> token id
0089fa95  mov     edx, 0xc                ;   -> fallback key 12
0089fa9a  mov     r8, [rbp+0x18]          ; effect tree head  (trigger: [rbp+0x88])
          ... inline _Lbound over the raw u32 at node+0x20, testing [node+0x19] as _Isnil ...
0089fac7  if (_Isnil) return              ; not found
0089fad0  if (key < [node+0x20]) return   ; landed on a larger key -> not found
0089fad5  if (node == head) return        ; empty tree
0089fad7  <build log record>  call 0x1C91C30
```

and the record it builds is

| effect | trigger |
|---|---|
| format `0x2518190` = `"scripted effect %s is overwriting an existing effect, rename it"` | `0x2518270` = `"scripted trigger %s is overwriting an existing trigger, rename it"` |
| source `0x25181D0` = `...\source\scriptedeffect.cpp`, line `0x21` = **33** | `0x25182C0` = `...\source\scriptedtrigger.cpp`, line `0x12` = **18** |

So the line number AGENTS cited as the *miss* log (`scriptedeffect.cpp:33`) is the **duplicate-registration
warning**: it fires when the name's token id is **already present** in the db. `0x1C91C30` is the engine
logger (it fetches a logger at `0x1C912F0`, checks a level guard against `0x3734460` under TLS), so the
message goes to the game log.

Three things follow, and they are the substance of this section:

1. **These functions are "build a ref for this name, and complain if the name is already taken"** — not
   "return the registered template". `0x89F960` never inserts; the sibling `0x89FDB0` carries
   `game_singleobjectdatabase.h`'s `"Object with key: %s already exists, using the one at %s"`, which is
   the actual add path. `fastcalls.py 0x89f960` finds only 3 callers, all in this same code family
   (`0x89FDB0`, `0x89FEC0`, and the sentinel `0x1D7CE0`) — nothing that looks like script evaluation.
2. **C1's criterion ② cannot be "the lookup returns non-empty"**, because the return object is identical
   either way. It has to be the consumer hit (`0x349AE0`/`0x3B01A0`, §23), which *does* branch — and now
   there is a second, sharper instrument: **the "is overwriting an existing" warning is exactly §25.5's
   case-fold hijack, made visible at run time.** If our minted keyword silently took an official id, this
   line appears in the game log. Zero such lines is a real pass condition.
3. The fallback key when a name has no token is **12**, and 12 is a hole: it is in neither the 9,863
   descriptor ids nor either keyword db (`evidence/xrefs/descriptor_oracle_4_4_4.tsv`,
   `keyword_behaviour_registration_4_4_4.tsv`). So an unminted name cannot raise the warning by accident —
   the check is sound, not just pretty.

### §27.4 Independent re-confirmations, and what the detour now does

* `[db+0x18]` for effects / `[db+0x88]` for triggers, reached from `.text` — §21's map offsets, third
  instrument.
* The tree node shape is §23's: raw u32 key at `+0x20`, `_Isnil` at `+0x19`, `_Left` at `+0x10`.
* The name→token hop is `[[token_db]+0x10]` on the object from `0x1D12C60` — the same accessor §20 uses.
* `0x24B1990` (the `CScriptedEffectTemplate` vtable in AGENTS' table) is written into `out+0x00` and then
  replaced by `0x25180A8` before the walk, which is why it looked like the template's own vtable from a
  prologue-only reading.

`scripted/lookup_hook.zig` now encodes all of this: `NameHolder`/`NameString` read the string at `+0x10`
as bytes, `ScriptedRef` puts `name` at `+0x10` and `ceffect_vtable` at `+0x40`, and a new `Shape.classify`
turns the recorded `out_vtable` back into `ref`/`null_template`/`unknown` against the image base captured
at install. The four vtables (`0x25180A8`, `0x2518128`, `0x24B9E80`, `0x24B9E40`), the log target
`0x1C91C30`, the two message/source-string RVAs, `REF_SIZE = 0x118`, `HOLDER_STRING_OFFSET = 0x10` and
`UNMINTED_SEARCH_KEY = 12` are in `offsets.scripted_lookup` with a comptime test.
Stage 2 was previously described as "replace null-template results with registry-provided templates" at
these two functions; §27.2 shows there is nothing here to replace, so Stage 2 needs a different target and
is not made harder by anything in this section.

### §27.5 The drain was losing and duplicating records, fixed while I was in the file

`LookupHookDrain` scanned `0..total` every call and then reset `seq` to 0. Two consequences, both now
covered by tests: after the ring wrapped once, every surviving slot was re-copied once per wrap; and the
reset raced with game threads that had already taken a slot index from the old `seq`, so their records
could land below the new cursor and never be read. The drain now keeps a private cursor, consumes slots
(`filled` back to 0), stops at a slot whose result half has not been written yet (that record is picked up
on the next drain instead of skipped forever), counts what the ring wrapped over in `LookupHookDropped`,
and exposes `LookupHookTotal`. `zig build test`: 293/293, 24/27 steps (the two QuickJS link steps still
cannot start on this host's glibc).

## §28 The `0x5350D0` family re-evaluated: a per-instance virtual getter, not a hook target (2026-09-30, offline)

This closes PLAN §7's last open backlog item ("re-evaluate the value of the `0x5350D0` family under §26's
new characterisation"). Raw commands and the rip operands: `evidence/logs/getter_probe_4_4_4.log`. Nothing
was attached, no engine state touched.

### §28.1 It is reached only through data, never called

`fastcalls.py 0x5350d0` → **0 direct `E8 rel32` / `FF 15` / `FF 25` sites in 37 MB of `.text`**. A
qword scan of `.rdata` finds **exactly one** reference, at data RVA `0x24F9940`, inside the pointer array
starting `0x24F9910`:

```
0x24f9910 +0x00 0x156540     +0x30 0x5350D0   <- the "switch"
0x24f9918 +0x08 0x156570     +0x38 0x15db30
0x24f9920 +0x10 0x533DB0     +0x40 0x15db30
0x24f9928 +0x18 0x1D08520    +0x48 0x538170
0x24f9930 +0x20 0x5345E0     +0x50 0x1D08520   <- base Execute again
0x24f9938 +0x28 0x535070     +0x58 0x15db30
```

So `0x5350D0` is a **virtual/member slot**, not a global dispatcher — the last thing that could have
rescued §7's "dispatch switch" reading. Its sibling `0x535070` has 1,652 `.rdata` references (it is
installed across a large class family) but `0x5350D0` has one, so the switch body is a *single* class's
implementation, not the shape of the subsystem.

### §28.2 Its content confirms §26's "property getter", down to the field offsets

Every case reads a *hardcoded field of the object in `rdx`*: `+0x120`, `+0x28`, `+0x288`, `+0x278`
(`0x5345E0`, the neighbouring slot, opens with `mov edx, 0x2cd` — it asks for id 717 `template` by
constant). Case `0x2cd` takes the C string at `[rdx+0x288]`, `0x15F770` assigns it into a `std::string`,
looks it up in the global `[0x325EBA0]` via `0x53B3E0`, stores the result into `[this+8]`, calls
`[result_vtable+0x38]`, and on false logs through `0x1C91C30` with source `0x24F8F70` line `0x16a`.
That is a *named-member* read, which is what §26 predicted from the id set (`graphicsSettings`,
`maxHeight`, `attenuation`, `defaultAnimationTime`, `sendgame` are data fields, not keywords).

### §28.3 Unknown ids are NOT dropped — they take a generic fallback

The compare chain's default (`0x535c68`) is `mov rcx, rdi; call 0x1D092C0`, and the function returns
void (`0x535ca1` is a plain `add rsp/pop/ret`, no value in `rax`). `0x1D092C0` is a
**widely-used generic helper: 429 direct sites across 394 functions**, and its caller buckets are
script-reader code (`'@ifdef'`/`'#endif'` block handling, `'Unexpected token'`, `'Unreadable String'`,
`'combat_%s'`, `ship_aura.cpp` `'Duplicate trigger at %s'`). Inside it: `new(0x20)`, two 16-byte templates
from `[0x2702680]` and `[0x26E4F00]` — the latter *is* the string `"Unexpected token"` — then
`0x1D09330`, which builds `std::string`s from `[obj+0x48]` and from the requested name at `[rsi+0x10]`
(the holder shape §20/§27 measured) and links a `new(0x80)` node into the list at
`[obj+0x10]`/`[obj+0x18]`/count `[obj+0x20]`, updating `[prev+0x70]`.

Consequence for C1: a freshly minted token id that ever reaches this family goes to the fallback, so
registering a keyword cannot "miss" here, and there is nothing here to teach the engine about a new
keyword. Whether the fallback is a by-name variable lookup or an error-view construction is **not
settled** — the `std::string` temporaries in `0x1D09330`'s stack frame were not fully disambiguated, and
`0x15F770` is an **assign** (`size = len; memcpy; buf[len] = 0`), not an append, so the concatenation story
§25.4 used for iterator names does not transfer here. Do not reuse this section as a premise.
> **Settled the next day by §30: error-view construction.** The disambiguation §28.3 asked for is done
> there, and it removes `0x1D092C0` from the candidate list rather than promoting it.

### §28.4 The slot-index question is left open on purpose

§7 recorded "`0x535070` … tail-jmp slot[5] = the switch". Read precisely: `0x535070` does
`mov rax,[rsi]` (this's own vptr) then `call [rax+0x30]` (= `0x5350D0` per the dump) and finally
`jmp [rax+0x28]` (= `0x535070` itself). Taken at face value that is infinite self-recursion, so one of the
three readings is wrong — most likely the array at `0x24F9910` is not the *published* vtable start (§22.5:
MSVC merges vtable segments back to back; and `riprefs.py 0x24F9910` finds **zero** `.text` sites
publishing that address, so some other start is what constructors actually store). The slot *index*
therefore stays unresolved. **It does not matter for the verdict in §28.5**, which only needs
"reachable via data, not via a call", and it is the reason this section reports the dump instead of a
conclusion about `0x24B1990`'s slot numbering.

### §28.5 Verdict — backlog closed as "no value as a hook surface"

1. `0x5350D0` is one class's virtual named-member getter with a generic fallback, reachable only through a
   data slot. Detouring it would intercept property reads, not keyword execution, and §7 conclusion 2
   ("the real runtime extension surface") is void — as §26 already said; this section supplies the
   mechanism behind it.
2. The keyword executor remains §23/§24: `create()` on the BST node, then the class's own virtuals. C1's
   four criteria (PLAN §6) are unchanged by anything here.
3. The residual value is documentary: the chain `[[frame+0x30]+8]+8 → id` and
   `[[frame+0x30]+8]+0x20 → object` (§26.1) now has a *purpose* attached to it, and ~~`0x1D092C0` is a
   candidate anchor for a future scope-variable bridge from QuickJS — **candidate only**, and if that
   bridge is ever built, §28.3's two unsettled points have to be pinned first~~ **§30 settled it: it is a
   parse-error appender, so it is not that anchor.** §28.3's first question is closed; the second
   (`0x24F9910`'s slot numbering) stays open and stays irrelevant to the verdict.

## §29 Backlog cleanup decided: `id_mapper.zig` retired, the two `handler.zig` files kept (2026-09-30)

Both were PLAN §7 items, and both were decided by the user (1. 删除 2. 留). Recorded here because the
*evidence* for the first one is the point, not the deletion.

**`src/dll/effects/id_mapper.zig` — deleted, with its `build.zig` test step.** The criterion in PLAN §7
was "retire it if it really has no use", and three measurements settled that, not taste:

* **Reachability**: `grep` over `src/` + `build.zig` found no importer — the only reference was the file's
  own dedicated test step. Unlike `ceffect.zig`/`ctrigger.zig` (§26.3) this one *did* run, which is why its
  21 tests were the only green thing in the file: they tested a hand-written `AutoHashMap`, not the engine.
* **Premise**: its header already conceded the built-in id table is "ILLUSTRATIVE ONLY … NOT read from the
  engine", because the 3.x `0x14180B050` switch it was said to come from does not exist in 4.4.4 (§3/§14).
* **Replacement, evaluated and rejected as speculative**: the real name↔id pairs exist offline —
  `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv` has 741 effect rows — so a repoint was
  feasible. Not taken, because there is no consumer: id space ownership is the engine's job (§18/§19,
  `0x1D13270` mints `id = [db+0x64]+[db+0x84]+1`), C1 hand-picks no ids, and §25.5's collision question is
  already answered by `scripts/c1_preflight.py` (offline) plus `keyword_registry.NameCheck` (runtime).
  Embedding 741 rows to serve nothing is exactly the speculative work this project keeps deleting.

`offsets.known_effect_ids.SCRIPTED_EFFECT_BASE = 10000` stays as the *observation* it is (live BST keys
are not a clean range: 146, 227, 10000+), re-marked `[OBSERVED, no consumer]` now that its only reader is
gone. `offsets.c_effect` was already in that state — zero users, kept as the falsification record (§26.3).

**`src/dll/effects/handler.zig` + `src/dll/triggers/handler.zig` — kept as orphans.** Same reachability
evidence as above (zero importers, `build.zig` steps commented out with "SKIPPED"), but the asymmetry is
deliberate: these two are the intended JS-routing layer for C3, so they are a *placeholder with a named
consumer*, whereas `id_mapper` was a *table with no consumer and a false premise*. README marks them
orphan in the tree. If C3 ends up routing through QuickJS differently, they are deleted then, not now.

**Counts after this**: `zig build test` → 22/25 steps, **272/272** tests passed (293 − 21 id_mapper tests,
2 steps removed); `zig build` still produces `zig-out/bin/stellaris_quickjs.dll` (7.1M). The two failing
steps remain the host's QuickJS/GLIBC mismatch. No hook behaviour changed anywhere; C1 stays unauthorized.

## §30 The `0x1D092C0` fallback settled offline — parse-error appender, and a token-DB `id → name` table (2026-09-30)

### §30.1 The fallback, read end to end

§28.3 left one question open and §28.5 left one candidate hanging on it — whether the generic fallback
reaches *by-name variable lookup* or *builds an error view*. Read end to end (`scripts/disrva.py
0x1D092C0 18`, `0x1D09330 120` + `0x1D09465 12`, `0x1D09130 64`, `0x1D0D320 64`,
`0x59D010 30`; `scripts/riprefs.py 0x337ACBC`; `scripts/fastcalls.py 0x1D09330`; command record
`evidence/logs/fallback_0x1d092c0.log`; `.pdata` bounds `0x1d092c0..0x1d0932f`,
`0x1d09330..0x1d094d0`, `0x1d09130..0x1d092b1`, `0x1d0d320..0x1d0d3f4`), it is the **second**.

**`0x1D092C0(rcx = parse object)`** — 0x6f bytes, one job: hand-build a `TokenNameHolder`-shaped local whose
`+0x10` `std::string` is `"Unexpected token"` (`0x26E4F00`), then call `0x1D09330(obj, &holder)`. The string
is deliberately on the **heap** branch: `new(0x20)` for the buffer, `{size, cap} = {16, 31}` copied as one
`movdqa` from a size/cap table at `0x2702680` (`(16,31),(17,31),(18,31),(19,31)…`), into holder+0x20/+0x28.
So this is an independent third confirmation of §20's holder shape — buf/ptr at `+0x00`, size `+0x10`,
cap `+0x18`, and `+0x00..+0x0F` of the holder itself ignored by the callee.

**`0x1D09330(rcx = obj, rdx = &holder)`** — assembles a 0x68-byte context on the stack and appends a node:

```
context+0x10  std::string  = the message template      (from holder+0x10)
context+0x30  u32          = [[obj+0x30]+8]+8          <- §26.1's keyword-id chain, now with a purpose
context+0x48  std::string  = [obj+0x48]                (a raw const char*, byte-strlen, no SSO decode)
new(0x80) -> 0x1D0D320(node, &context, old_tail)       node: +0x10 string, +0x30 u32, +0x38 string
push onto the std::list at [obj+0x10] head / [obj+0x18] tail / count [obj+0x20]; [prev+0x70] = node
mov byte [obj+0x28], 1                                 error flag
jmp 0x1D09130(obj)                                     parser advance, NOT an error raiser
```

Every stack offset is checked against its initializer: the three locals are opened with
`size = 0 / cap = 15` writes at `rbp-0x39`/`rbp-0x31`, `rbp-9`/`rbp-1`, `rbp+0x2f`/`rbp+0x37`, which land on
exactly the fields `0x1D0D320` reads through `rdx+0x10`, `rsi+0x30`, `rsi+0x48` once `rdx = rbp-0x29`.

**Why the verdict is error-view, not lookup.** All **22** direct callers of `0x1D09330`
(`evidence/xrefs/callers_0x1d09330_buckets.tsv`) open a *message* string and hand it in as the name field:
`'Unexpected token'` `0x26E4F00`, `'Unreadable String'` `0x26E4D40`, `'Unhandled Entry'` `0x2622630`,
`'Expected list start'` `0x252EF00`, and the `planet.cpp` / `dlc_metadata` paths. A variable lookup does not
take its key from a table of parser error texts. `0x1D09130` confirms the other half: it is the tokenizer
advance — `inc [0x337ACBC]` on entry and `dec` on the early-out (`0x1D0928d`), a balanced **recursion-depth**
global with exactly 2 refs and both inside this function, so it is not an error counter either — and it
recurses into itself (`0x1D09227`) after reading `[obj+0x30]`'s vtable slot `[rax+8]`.

**Consequences, three of them:**
1. **§28.5 item 3's candidate is withdrawn.** `0x1D092C0` is not the anchor for a QuickJS → scope-variable
   bridge; a bridge that intercepted it would collect parse errors, not read game state. The by-name
   *variable* path is still unpinned, but §30.2 turned up the token DB's `id → name` reverse table, which is
   the concrete thing we actually need from this family.
2. **§26.1's `[[frame+0x30]+8]+8 → token id` gains an independent witness.** Here that dword is loaded
   straight into a report field (`0x1D09396`..`0x1D0939E` → `[rbp+7]` → `node+0x30`), which is a second,
   different function arriving at the same field — the chain is no longer inferred from one call site.
3. **C1 gets a failure signature, and it is a *bad* one.** `0x5350D0`'s default branch lands here, so an id
   that reaches that getter without matching a case produces an `Unexpected token` entry plus
   `[obj+0x28] = 1`. Read only in the direction that matters: if a C1 keyword is *referenced by a script
   before our insert has run*, this is the path that records it — a script-visible parse error, not a silent
   miss. PLAN §6 C1's criterion ① ("官方 keyword 路径不受影响") should therefore also look for stray
   `Unexpected token` entries, and §28.3's "unknown ids are not dropped" stays true but is now known to mean
   "they are reported", not "they resolve".

### §30.2 What the search actually turned up: the token DB keeps an `id → name` reverse table

`0xb5f3c0` is the one caller in the §30.1 bucket set with no error text, and following it opened something
more useful than the question that led there. It maps a token **id** to its **name** through the token DB:

```
0xb5f3c0(rcx = context, rdx = obj, r8d = token id)     ; rcx is used only on the flag path
  rax = 0x59D010(&id)        ; token-id -> flag bitmask (ret 0x40000, 0x200000, 0x8000000000 …).
                             ;   3 callers, and it has NO .pdata entry (the preceding one ends at
                             ;   0x59cf1b), so its bounds are inferential, not measured.
  if rax != 0 -> dispatch on the flag value
  else: db = 0x1D12C60()
        if [db+0x7c] != [db+0x80] { call 0x1D12CD0 }        ; skip the refresh when they agree (0xb5f405 je)
        holder = [db+0x70] + id*0x30                         ; <- the reverse table, indexed by RAW id
        call 0x1D09330(obj, holder)
```

**`0x1D12CD0`** (bounds `0x1d12cd0..0x1d12de4`, no arguments — it reads the singleton itself) is the builder,
and it has exactly two loops, both writing through `0x15F770` (the §28.3 assign) into
`[db+0x70] + id*0x30 + 0x10`:

1. `0x1D12D43`..`0x1D12D8F` — the **static** half: `0x172E50()` (the §17 descriptor driver),
   `rsi += 0x120` while `rsi < 0x2B57E0` (9,863 entries again), id = `[entry+0x00]`,
   name chars = `[entry+0x10]`.
2. `0x1D12DA0`..`0x1D12DD9` — the **dynamic** half: walks `[db+0x58]` with stride 8 for `[db+0x64]` entries
   (the name→id map §18 recorded at `[db+0x50]`), id = `[rec+0x00]`, name = `[rec+0x10]`.

Before loop 1 it resizes through `0x391F90(rcx = db+0x68, edx = [db+0x80])` — sized to the **next free id**,
i.e. deliberately large enough to hold ids minted after start-up — and it first clears every existing
holder's string (`[h+0x20] = 0`, `[h+0x10][0] = 0`).

**The measured facts, and their limits.** The array's element is a `0x30`-byte holder whose `std::string`
lives at `+0x10` — §20's holder shape again, now seen from the other direction: not "what does the
allocator read" but "what does the engine write". `[db+0x70]`/`[db+0x7c]` are **new fields**, absent from
§18's field map (`+0x50`, `+0x64`, `+0x80`, `+0x84`). Unpinned, and deliberately not guessed here: whether
`[db+0x7c]` is a count or a `std::vector` end high-half (the code uses it as `count * 0x30`, which is the
reading §30.2 relies on); whether callers of `0x1D12CD0` (≈100 functions) are all read paths; and whether
the `[db+0x7c] != [db+0x80]` guard means "stale" in the sense that *our* mint bumps it — that requires a
live read.

**Why it matters for C1 — this is a readback instrument, not just documentation.** If the guard does trip on
our allocation, then after one call to `0x1D12CD0` the name at
`[[0x37347A0+0x70] + 18818*0x30 + 0x10]` should read back exactly the string we handed `0x1D13270`. That is
a **fifth** C1 observation, and unlike criterion ② it does not depend on the tree being walked by a script:
it confirms mint → name-pool → reverse-table in one read, before any evaluation. Read-only, so it stays
inside §1's boundary; it is recorded as a candidate because the guard's meaning is the live part.

**Counts for §30**: no code changed, `zig build test` untouched (22/25 steps, 272/272). New artifacts:
`evidence/logs/fallback_0x1d092c0.log` (every command from §30.1/§30.2, plus the raw `.rdata` dumps of
`0x26E4F00` and the `{size, cap}` table at `0x2702680`), `evidence/xrefs/callers_0x1d09330_buckets.tsv`
(22 callers), `evidence/xrefs/callers_0x1d12cd0_buckets.tsv`. C1's four criteria and its authorization
status are unchanged.

> **Correction pointer for §28.3's other open question** — `0x24F9910`'s slot numbering stays unresolved
> (§28.4), and §30 neither needed nor changed it.

## 31. C2 harness bootstrap (2026-10-08)

**What was confirmed live.** `scripts/c2_task2_load.py` (running on the Windows box, against the live
game PID 20564) injected `C:\temp\sqjs_c2.dll` via `LoadLibraryA` in a `CreateRemoteThread`, resolved
the module base from PowerShell `Get-Process | Modules | BaseAddress`, and called `C2Sanity`:

- **DLL base: `0x7ffa67210000`** — a genuine 64-bit address. An independent post-run read of the module
  list showed `sqjs_c2.dll` at decimal `140713448767488`, which is the identical value. The uploaded
  DLL was hash-verified before injecting (sha256 `fb7ec274…`, matching the fresh local build).
- MZ header check at base passed. `C2Sanity` RVA `0x44b410` came from a fresh PE reparse
  (`list_exports` on the Windows-side DLL), not a hard-coded table.
- **`C2Sanity` returned 42**, and `assert_game_alive` passed immediately after injection and after the
  remote call. The game was never restarted during this task.

**Root-cause position on the old crashes.** The earlier C2 remote-call failures were attributed to
`GetExitCodeThread` truncating the HMODULE to 32 bits (e.g. `0x41d20000`) and every subsequent
`CreateRemoteThread` then aiming at unmapped memory. This task did **not** re-run the old harness, so
the truncation crash was not reproduced; what we can now state directly is its complement: with the
base taken from the filename-keyed PowerShell query instead of the thread exit code, remote calls land
on mapped memory, return real values, and the game survives. The hypothesis is consistent with every
observation and the fixed path is proven; the old buggy path remains what we removed, not what we
re-measured.

**New defect found and fixed during this task (before any injection happened).**
`c2_harness.resolve_pid` built `tasklist /FI "IMAGENAME eq stellaris"`, but tasklist's IMAGENAME filter
is an **exact match including the extension**: `eq stellaris` returns "no tasks match" (exit 0), only
`eq stellaris.exe` returns the game. Every plan task calls `resolve_pid("stellaris")`, so the function
raised `RuntimeError('stellaris' is not running)` against a live, verifiable PID 20564 — the failure
mode is loud and pre-injection, but it made Task 2 unrunnable until fixed. Fix: normalize a bare name
to `name + ".exe"` before filtering and comparing, plus three host-runnable regression tests in
`scripts/test_c2_harness.py` (fake `tasklist` reproducing the exact-match semantics). This also
corrects the earlier suspicion that pywin32 was involved: it is not installed on the remote and the
harness does not use it.

**Counts for §31**: no engine addresses beyond those already recorded; `src/dll/**` untouched; C1 gate
untouched. `scripts/c2_harness.py` (resolve_pid only), `scripts/test_c2_harness.py` (+3 tests, 11/11
passing on the host), `scripts/c2_task2_load.py` created. Remote Python 3.13.2 AMD64; one injection
attempt total, no repeated guessing.

## 32. C2 QuickJS diagnostic — the diag call itself terminated the game (2026-10-08, live, BLOCKED)

**Goal.** PLAN §6 blocker 2 ("`JS_NewContext` returns NULL") needs the *failing step code* from
`C2DiagQuickJS` (wrapper `src/dll/quickjs/quickjs_wrapper.c:208`) which delegates to
`JS_NewContextDiag` (`libs/quickjs/quickjs.c:2669`). **This task did not obtain that code: the remote
call crashed `stellaris.exe` before any rc/log could be read back.** Per the hard safety rails the run
was STOPPED immediately — no restart, no re-injection, no repeated guessing. The human partner restarts
the game.

**What was built for this (ruling P4, so the harness never crosses a 64-bit pointer through the 32-bit
thread exit code).** Added one Zig export `C2DiagQJSInto(out_diag: [*]u8) callconv(.c) i32`
(`src/dll/exports.zig:226`) that delegates to the existing C routine `C2DiagQuickJS(out_diag, 512)` —
reusing its (buffer, size) logic rather than duplicating it or adding a same-named C pass-through
(which a Zig `extern fn`/`export fn` pair cannot share in one file anyway). It returns only the i32 step
code and writes the step log into the caller-supplied buffer. The old `C2DiagGetLogAddr` was annotated
as unusable-by-injector (64-bit pointer truncated by `GetExitCodeThread`). No QuickJS C symbol gained a
new Zig `extern` binding — this binds our own wrapper only (PLAN §6 blocker 1 workaround). Fresh build
`zig build` OK, sha256 `8c81d678e00ccf15a0f7efe51d8d2747b6aebeb5f1a59cb26b0ddd917700f42d`, export
`C2DiagQJSInto` RVA `0x44b270` confirmed by a host `list_exports` reparse (29 exports).

**Derived decode table (ruling P7 — built from the code, NOT the brief's table).**
Two return sites, and their value ranges OVERLAP, so a bare number is ambiguous; the log text is
authoritative:

`C2DiagQuickJS` outer path (`quickjs_wrapper.c`):

| rc | condition | log sentinel | line |
|----|-----------|--------------|------|
| 10 | `GetProcessHeap()` NULL | `no_process_heap` | :217 |
| 11 | test `HeapAlloc(256)` NULL | `heap_alloc_failed` | :219 |
| 2  | `JS_NewRuntime2` NULL | `runtime2_null` | :223 |
| 3  | runtime opaque write/read mismatch | `opaque_mismatch got=%p` | :228–230 |
| 4  | standalone `JS_NewContextRaw` NULL | `raw_ctx_null` | :236–237 |

`JS_NewContextDiag` inner path (`quickjs.c:2669-2691`), returned verbatim as the outer `result` once the
outer steps pass:

| rc | condition | line |
|----|-----------|------|
| 0  | raw ctx + all 11 intrinsics OK, `*out_ctx` set | :2689–2690 |
| 1  | `JS_NewContextRaw` failed (allocation) | :2675 |
| 2  | `JS_AddIntrinsicBaseObjects` failed | :2677 |
| 3  | `JS_AddIntrinsicDate` failed | :2678 |
| 4  | `JS_AddIntrinsicEval` failed | :2679 |
| 5  | `JS_AddIntrinsicStringNormalize` failed | :2680 |
| 6  | `JS_AddIntrinsicRegExp` failed | :2681 |
| 7  | `JS_AddIntrinsicJSON` failed | :2682 |
| 8  | `JS_AddIntrinsicProxy` failed | :2683 |
| 9  | `JS_AddIntrinsicMapSet` failed | :2684 |
| 10 | `JS_AddIntrinsicTypedArrays` failed | :2685 |
| 11 | `JS_AddIntrinsicPromise` failed | :2686 |
| 12 | `JS_AddIntrinsicWeakRef` failed | :2687 |

**How this differs from the brief's `DECODE`.** The brief (a) has **no entry for rc 1** even though 1 is
a real `JS_NewContextDiag` code; (b) **shifts every intrinsic by +3** (it labels 5–15 as the intrinsic
codes, but the code emits them at 2–12); (c) **omits the outer heap codes 10 and 11** entirely, and its
"10 = TypedArrays" collides with the outer "10 = no_process_heap" — the log text resolves that collision
but the brief's table cannot; (d) `exports.zig:199-204`'s docstring ("1 = malloc broken, 5–12 intrinsic,
98 = wait failed, 99 = thread creation failed") matches **neither** table — rc 1 is `JS_NewContextRaw`
(allocation) inside the diag, malloc/heap failure is 10/11, and this wrapper returns no 98/99. The
docstring is stale, not code-derived. If a future rc lands outside both tables it is a finding, not noise.

**What was run and observed.** `scripts/c2_task3_diag.py` (on Windows, `C:\temp`, bare-name import of
`c2_harness.py`; P5/P10). Uploaded under a NEW filename `C:\temp\sqjs_c3.dll` (P12: `sqjs_c2.dll` is
loaded + file-locked in PID 20564 and lacks the new export), hash-verified identical to the local build.

- Run 1 aborted **before any remote call** on a bad guard I had added (`assert buf >= 2**32`). That
  guard was wrong: `VirtualAllocEx` legitimately returned a sub-2^32 scratch address (`0xeb0000`), and the
  buffer address travels *inward* via `lpParameter` (full 64-bit), so its magnitude is not the P4 risk
  (P4 concerns a *returned* pointer). Guard removed; the crash had not yet occurred and no diag call had
  been made, so this did not consume the "one diag call per hypothesis."
- Run 2 (fixed script): injected `sqjs_c3.dll`, base **`0x7ffa3ec90000`** (a genuine 64-bit address, MZ
  header OK), buffer `0xec0000`, then dispatched `C2DiagQJSInto`. The **`assert_game_alive` immediately
  after that call raised `RuntimeError('game (pid 20564) is no longer alive')`** and the process was
  confirmed gone by `tasklist` (`IMAGENAME eq stellaris.exe` → "no tasks match"; `PID eq 20564` → no
  match; `Get-Process stellaris` → empty). **Exit code of the run: 1.** The **rc and log were never
  printed** (they are read after the alive check, which failed first) — so there is **no observed step
  code from this run**, by construction.

**Observed correlation, stated without invented causation (ruling P13).** The only new remote action in
run 2 versus run 1 was the `C2DiagQJSInto` dispatch; the game was alive through injection and
`remote_alloc` and died across that call. `call_remote_with_arg` returned (the remote thread handle
signalled, consistent with process teardown), then the alive check failed. We therefore record the fact:
**invoking the QuickJS context-creation diagnostic on an injected thread in the live game process is
associated with the game process terminating.** This run does **not** identify *why* (no rc, no log, no
faulting-module captured — the WER query returned nothing within the last 80 Application events), and no
second attempt was made. The PLAN hypothesis "blocker 2 = `JS_NewContext` returns NULL" is **neither
confirmed nor refuted**: the code path never reached a point where a NULL could be reported back, because
the process died first. A crash and a NULL return are different failure modes; this is a crash.

**Confounders a controlled retry must eliminate (Task 4, not done here — listed for completeness, no
action taken).** (1) Two DLL copies (`sqjs_c2`, `sqjs_c3`) are simultaneously resident; §31/P12 argued a
second load is inert (`DllMain` only `writeMarker`), but that verification predates a resident pair both
holding QuickJS globals. (2) A scratch `VirtualAllocEx` buffer and CreateRemoteThread stack context differ
from the game's own threads; `quickjs_wrapper.c` was written specifically because "Zig's libc malloc
doesn't work in DLL injection context" (its own header comment), and `C2Init` (`exports.zig:189-194`)
carries an open note that `writeLogStatic`/`CreateFileA` in the remote-thread context "may corrupt TLS or
stack state." None of these is *established* — each is a hypothesis for Task 4 to test with a method that
survives the call.

**Consequence for the plan.** §32 is now written down (this section), which is the gate for Task 4. But
Task 4 cannot pick a fix "from the number" because no number was captured: the plan's assumption that the
diagnostic is a safe read-only probe of the live process is **falsified by this run**. Task 4's first job
should be an observation method that returns a step code **without killing the host** (e.g. reproduce
`JS_NewContextDiag` in the native `zig build test`/glibc harness, or under a debugger/crash-dump
capturing the faulting module, before touching the live game again).

**Counts for §32**: `src/dll/**` changed only by the `C2DiagQJSInto` export + two docstring annotations
(no QuickJS C `extern` added, no keyword registered, C1 gate `authorize.c1_registration = false`
untouched, no hot-path detour). `scripts/c2_task3_diag.py` created. **Game crashed and was STOPPED per
safety rails; no restart, no re-injection after the crash; exactly one `C2DiagQJSInto` dispatch.**

---

## 33. Task 4 offline root-cause: use-after-free in `heap_free` corrupts `malloc_size` → QuickJS OOM (2026-10-08, native, DONE)

**Observed crash (restating §32 without new live data).** One `C2DiagQJSInto` dispatch on a
CreateRemoteThread in live `stellaris.exe` (pid 20564) terminated the process before any rc/log came
back. No new live observation was made in this task — everything below is native/offline.

**Native reproduction — achieved.** New test `src/dll/quickjs/c2_diag_test.zig` (wired into
`zig build test` via a dedicated `c2_diag_tests` native step in `build.zig`, same `linkQuickjs`
pattern as `qjs_tests`) calls the *production* entry `C2DiagQuickJS(buf, 512)` against the real
vendored QuickJS (`libs/quickjs/quickjs.c` @ CONFIG_VERSION "2025-09-13") plus the wrapper's own
`heap_mf`, i.e. the exact step sequence of the live call: GetProcessHeap → test HeapAlloc →
JS_NewRuntime2(&heap_mf) → opaque round-trip → JS_SetMaxStackSize(1 MiB) → JS_SetMemoryLimit(256 MiB)
→ JS_NewContextRaw + JS_FreeContext → JS_NewContextDiag. No new Zig `extern fn` to any QuickJS C
symbol was added (PLAN §6 blocker 1 respected) — the test externs only project wrapper symbols
(`C2SanityCheck`, `C2TestQuickJS`, `C2DiagQuickJS`, `C2DiagGetLog`, `C2GetQuickJSPointers`).

**Root cause (proven).** `heap_free` (HEAD `src/dll/quickjs/quickjs_wrapper.c:113`) freed the block
first (`HeapFree(heap, 0, h)` at :118) and *then* read the size-tracking header
(`s->malloc_size -= h->size;` at :121). That is a use-after-free read of allocator-owned memory.
Once the block is back in the heap, its first word carries allocator bookkeeping (free-list link on
glibc/Windows both), so `h->size` returns garbage and `malloc_size` (a `size_t`) underflows to
~2⁶⁴. gdb on the native repro at the OOM point: `malloc_size = 18446603336352331383`,
`malloc_count = 29`, `malloc_limit = 268435456`. Thereafter every `heap_malloc` fails the limit check
(wrapper :124 `if (s->malloc_size + size > s->malloc_limit) return NULL;`), so
`JS_AddIntrinsicBaseObjects` inside `JS_NewContextDiag` (`libs/quickjs/quickjs.c:2669`) returns -1
(Out of memory) → step 2 → rc=2. **Any js_free suffices to poison the counter — the temporary frees
inside `JS_NewContextRaw`'s own base-object setup already do it** (variant matrix below), which is why
the sequence fails even before the explicit `JS_FreeContext`.

**Variant isolation (native `/tmp/c2repro/variants.c`, flags: 1=skip raw-ctx step, 2=create raw ctx
but don't free it, 4=no JS_SetMaxStackSize, 8=no JS_SetMemoryLimit, 16=QuickJS default allocator):**

| flags | sequence | rc |
|---|---|---|
| 0 | full live sequence (heap_mf) | **2 (fail)** |
| 1 | skip raw-ctx create+free | 0 |
| 2 | raw ctx created, never freed | **2 (fail)** — internal frees alone poison |
| 4 | no SetMaxStackSize | 2 (fail) — stack-size call not the trigger |
| 8 | no SetMemoryLimit | 0 — counter still corrupts, but with the default unlimited `malloc_limit` the underflowed counter passes no gate, so nothing fails: confirms the *mechanism* is the limit check reading the corrupted counter |
| 14 | no raw free + no stack size + no mem limit | 0 — counter still corrupts, but with the default unlimited `malloc_limit` the underflowed counter passes no gate, so nothing fails: confirms the *mechanism* is the limit check reading the corrupted counter |
| 16 | **QuickJS default mf**, full sequence | 0 — decisive contrast |
| 18 | default mf, raw ctx not freed | 0 |

The default-allocator contrast is the historical delta too: QuickJS's built-in
`js_def_malloc/js_def_free` (`quickjs.c:2154+`) reads the usable size *before* calling `free`
(`_msize`/`malloc_usable_size`), so it never has this bug. The 2026-10-07 surviving run
(`C2TestQuickJS`, rc=3) predates `heap_mf` being wired into that path; the crashed run was the first
live exposure of `heap_mf`.

**Candidates cleared/condemned.**
- `heap_mf` `heap_free` read-after-free — **CONDEMNED (the root cause)**; gdb counter dump +
  valgrind: pre-fix binary reports "Invalid read of size 8 at heap_free", post-fix
  `valgrind --leak-check=no` on the identical test: `ERROR SUMMARY: 0 errors`.
- `heap_malloc_usable_size` / size header writes — cleared: reads/writes are of live blocks only;
  `AllocHeader` is written immediately after a successful HeapAlloc; no wild write found anywhere in
  the allocator (all accesses in-bounds).
- DLOG buffer arithmetic — **cleared as the 2026-10-08 crash cause, condemned as a latent bug.**
  Computed, not hand-waved: worst-case actual content of the current step log
  ("hp ok, alloc fail / rt null / op mismatch / raw ok / diag_rc=N" branches) is ≈90 bytes « 512, so
  `512 - pos` never went negative in the crashed run. Still fixed: `snprintf` returns the *would-be*
  length, so a future longer line could make `pos` overshoot 512 and then `512 - pos` (negative int →
  huge size_t) plus `g_diag_log + pos` past the array end. DLOG now clamps `pos` to ≤511.
- Process-wide exception/signal handlers in quickjs.c — cleared: no `AddVectoredExceptionHandler`,
  `SetUnhandledExceptionFilter`, `sigaction`/`signal` anywhere in `libs/quickjs/` or the wrapper;
  pthread/atomics code is gated behind `CONFIG_ATOMICS` (off in this build); the only `_WIN32` use
  near allocation is `_msize` in the *default* mf (not used).
- `JS_NewContextDiag` (WIP addition, quickjs.c:2669) — cleared line by line: `*out_ctx` is NULL on
  every failure path, no intrinsic is called with a NULL ctx, all step codes 1–12 match the
  intrinsic order in `JS_NewContext2`, freeing is balanced. It was never *run* before natively —
  it now is, and passes with rc=0 once the allocator is fixed. (The stale docstring above
  `C2DiagQJS` in `exports.zig` claiming 1=malloc broken/98/99 was wrong and is corrected to the real
  two-table decode.)
- JS_NewContextRaw + JS_FreeContext state shifting — cleared as *state* damage; the pair is what
  triggers a js_free, i.e. it only mattered as the delivery mechanism for the `heap_free` UAF.
- CreateRemoteThread stack vs `JS_SetMaxStackSize(1 MiB)` — not the cause of *this* failure (no JS
  is evaluated; `js_check_stack_overflow` is only consulted during evaluation/deep recursion), but it
  remains a **hypothesis/future hazard** for later tasks: `CONFIG_STACK_CHECK` is hardcoded on
  (quickjs.c:77) and captures `stack_top` from the calling frame on the remote thread; with
  `dwStackSize=0` the reserve comes from the exe header. When Task 6 evaluates JS on a remote thread
  this must be re-checked; for the init sequence observed on 2026-10-08 it is not implicated.

**Why the *process died* on Windows is still not fully explained (labelled honestly).** The proven
native consequence of this bug is QuickJS OOM → rc=2 → NULL ctx — a *clean failure*, not a crash.
For the live process to terminate, the post-free read of `h->size` must have faulted or tripped
something in *that* environment. **Hypothesis (unproven offline):** Windows heap bookkeeping on
low-fragmentation/segment-terminating blocks — after `HeapFree` of a tail block the segment can be
coalesced/decommitted, so the subsequent `h->size` load reads freed-or-unmapped memory; under
stellaris.exe's heap state that is a plausible access violation on the injected thread, and an
unhandled AV kills the process. Valgrind proves the invalid read happens (glibc); only a Windows run
can prove it *faults* there. No other candidate survived scrutiny for the death mechanism
(handlers: none installed; buffer overflow: arithmetically excluded; Zig side: unchanged from the run
that survived §31's sanity probe). **A wrong root cause costs another game crash — but here the fix
removes the only memory-safety violation in the path, which is also the only mechanism that can
produce an AV.**

**Fix (minimal, at the root).** `src/dll/quickjs/quickjs_wrapper.c::heap_free`: snapshot
`size_t freed = h->size;` *before* `HeapFree`, then `s->malloc_size -= freed;`. Nothing else in the
allocator changed; `heap_mf` stays live for the next Windows run. Two support edits in the same file:
(a) the Windows includes are now guarded by `#ifdef _WIN32` with libc-based shims for the native
test path (Windows build byte-identical in behavior; this is what makes the repro runnable in
`zig build test`), (b) DLOG clamp (latent-bug fix, described above). `src/dll/exports.zig`: corrected
the `C2DiagQJS` docstring to the actual two-table step-code decode (outer wrapper codes 10/11/2/3/4,
inner `JS_NewContextDiag` codes 0/1/2–12) — documentation only, `assert rc == 42` untouched, C1 gate
untouched.

**Native repro before/after, exact commands.**
- Before (HEAD state, pre-fix binary of the same test):
  `zig build test` → 2 failures in `c2_diag_test`: "C2DiagQuickJS completes the live-crash step
  sequence with rc=0…expected 0, found 2 / FAIL" and "C2TestQuickJS (sibling path) also reaches
  rc=0…expected 0, found 2 / FAIL". (The identical failures were captured in the suite *before* the
  fix was applied, then the fix was made and the suite re-run.)
- After:
  `zig build test` → `Build Summary: 22/25 steps succeeded (1 failed); 278/278 tests passed`. The 3
  c2_diag tests pass: `1/3 C2SanityCheck returns 42...OK / 2/3 C2DiagQuickJS … rc=0...OK / 3/3
  C2TestQuickJS … rc=0...OK`.
- `valgrind --leak-check=no <c2_diag test binary>` → `ERROR SUMMARY: 0 errors` (pre-fix: two
  "Invalid read of size 8" at `heap_free`). Remaining valgrind reports are leak records only,
  including the by-design still-alive global runtime (`g_test_rt` is intentionally never freed while
  the DLL is resident).
- `zig build` (Windows DLL) → exit 0, `stellaris_quickjs.dll` produced.

**Baseline composition note.** The documented task-start baseline was 254/254 tests + exactly 2
broken test steps (roots `runtime.zig` and `exports.zig`, both failing to *compile*
`quickjs_wrapper.c` on `<process.h>`). After this change: 278/278 tests pass and only **1** step
fails — `exports.zig`-rooted, now failing at **link** on undefined `CreateFileA/WriteFile/CloseHandle/
GetModuleHandleA` (pre-existing `extern "kernel32"` bindings, unavoidable on an ELF host). The
`runtime.zig` step was *revived* by the `#ifdef _WIN32` guards (+21 tests) and my new step adds 3.
No new failures were introduced; one pre-existing failure changed stage, one was fixed.
`zig build` (artifacts) unaffected.

**What is still unproven.** (1) The exact Windows kill mechanism (AV on the freed block vs. heap-
manager trip) — hypothesis above; only a live probe or a Windows-side crash dump can settle it.
(2) That `heap_mf` overall is safe under the Windows heap (the *other* three mf functions are read-
before-free-correct, but only one live run will confirm the whole table). (3) Remote-thread stack
adequacy for actual JS evaluation (Task 6 concern, not this call). (4) §32's confounder (1) — two
DLL copies resident — is untouched by this task and remains an open variable for the next run.

**What the next live probe must check (for the user to run; not executed here).** Fresh DLL filename
(e.g. `sqjs_c4.dll`, freshly built from this tree) after a human-restarted game; keep §31/§32 rails:
one `C2SanityCheck` (must still be 42 — proves the new image is loaded), then exactly one
`C2DiagQJSInto` dispatch with a liveness check immediately after. Expected on success: rc=**0**,
non-NULL ctx, and the 512-byte log containing `raw_ok` and `diag_rc=0`. If rc is nonzero the log's
outer code (10/11/2/3/4) or inner `diag_rc=N` (1=raw alloc, 2-12=first failing intrinsic) localizes
the step without ambiguity. If the process terminates *again* despite rc-path being clean, the
Windows kill mechanism is something else in the remote-thread context (stack/handler confounders),
and the probe should be repeated once under a crash-dump-capturing setup before any retry — do not
blind-reinject. `scripts/c2_task3_diag.py` behavior is unchanged by this task and needs only the new
DLL name to run this probe.

**Counts for §33**: changed `src/dll/quickjs/quickjs_wrapper.c` (heap_free UAF fix; `#ifdef _WIN32`
portability guards; DLOG clamp), `src/dll/exports.zig` (docstring correction only), `build.zig`
(new native test step), added `src/dll/quickjs/c2_diag_test.zig`. No new Zig extern bindings to
QuickJS C symbols; C1 gate, `assert rc == 42`, and `scripts/**` untouched; no `.dll`/`.pdb`
committed.

## 34. Task 5: the C2Init/pointer observation path — native RED→GREEN; live dispatch PENDING (2026-10-08, native only)

**Scope actually executed.** Offline side of Task 5 only: the observation export
(pair of full native-width pointers → caller-supplied 16-byte buffer), its Zig
export, native tests for it, the Windows-side probe script `scripts/c2_task5_init.py`,
host tests for its pure decoder. **Live dispatch pending: game down, awaiting human
restart + authorization; plan Steps 3–4 (scp/ssh/re-run-live) were NOT executed.**
This section does not claim Task 5 passed live; nothing below is a live observation.

**Ruling P4 implemented, with one verified deviation.** The brief's Step 2
(`C2GetRtPtrLow32`/`C2GetCtxPtrLow32` via `@truncate`, "non-zero proves not NULL")
was not implemented, per P4. What P4 itself mandates — the Zig export
`C2QuickJSPointersInto` and a same-named C symbol in `quickjs_wrapper.c`, extern'd
in `exports.zig` — was verified **unimplementable as literally worded**: a Zig
`export fn` takes its link symbol from its identifier, and `quickjs_wrapper.c` is
linked into the same DLL. Observed (scratch repros in /tmp, Zig 0.16.0):
- same file, `extern fn Sym` + `export fn Sym`: `error: duplicate struct member name 'Sym'`
- extern in one file, export in another, C object defining the same name:
  `error: duplicate symbol definition: Sym` (`defined by xfile.o` / `defined by sym.o`)

Resolution keeping every externally observable contract (PE export name, single
lpParameter, 16-byte buffer, rt at +0 / ctx at +8): the C symbol is named
`C2WriteQuickJSPointersInto` and the Zig export `C2QuickJSPointersInto` forwards to
it — the same naming split as the existing `C2DiagQJSInto` → `C2DiagQuickJS`.
No new Zig `extern fn` bindings to QuickJS C symbols were added (global constraint;
the new symbol is our own wrapper).

**TDD evidence (native).**
- Pre-change baseline: `zig build test` → `Build Summary: 22/25 steps succeeded
  (1 failed); 278/278 tests passed`. The 1 failure is pre-existing: the
  exports.zig-rooted step fails at **link** on undefined `CreateFileA/WriteFile/
  CloseHandle/GetModuleHandleA` (kernel32 bindings on an ELF host).
- RED (tests added, C function absent): `zig build test` →
  `Build Summary: 20/25 steps succeeded (2 failed); 275/275 tests passed`, new
  failure = the c2_diag step: `error: undefined symbol: C2WriteQuickJSPointersInto`
  (2 errors, each `referenced by c2_diag_test.o:c2_diag_test.test.C2WriteQuickJSPointersInto …`).
  Expected exactly this: the link step is where a missing C symbol surfaces.
  (275 not 278 because the whole 5-test c2_diag step — 3 old + 2 new — no longer links.)
- GREEN (C function + Zig export added): `zig build test` →
  `Build Summary: 22/25 steps succeeded (1 failed); 280/280 tests passed`.
  Failure count/mode unchanged from baseline (`grep "undefined symbol"` over the
  build output lists only the four pre-existing kernel32 symbols, ×2 each;
  no `C2Write*` among them).
  The two new tests:
  1. "returns rt/ctx **bit-identical** to `C2GetQuickJSPointers`" after a
     `C2DiagQuickJS` run reaching rc=0 — an equality check against the direct read
     of the same two statics, not a nonzero check.
  2. "writes exactly 16 bytes and nothing outside" — 0xAA-filled region with
     32-byte guards on both sides; guards must survive; all 16 buffer bytes must
     be accounted for by the two pointers. On the Linux host this exercises the
     libc-backed `GetProcessHeap/HeapAlloc` shim (`quickjs_wrapper.c:14-37`), i.e.
     the same accounting path that broke on Windows (§33).
- `zig build` (x86_64-windows DLL) → exit 0; `C2QuickJSPointersInto` links into
  the PE, confirming the rename clears the duplicate-symbol problem on COFF too.
- `python3 -m pytest scripts/test_c2_harness.py -q` → **20 passed** (baseline 16;
  +4 host tests for `parse_pointers`: realistic non-NULL pair, rt-live/ctx-NULL
  decoding to `(int, 0)` without raising, both-zero, wrong length (0/8/15/17
  bytes) → `ValueError`).

**Built artifact (host-side PE reparse with `c2_harness.list_exports`, no hard-coded
RVAs — P10).** `zig build` output `zig-out/bin/stellaris_quickjs.dll`:
- sha256 `d51c3fbd8c7a04a7235abf249027fc93968dbde31ae28e633e90b8a3843540d9`
- 30 exports, all RVAs distinct; the Task-5-relevant rows:
  `C2Sanity = 0x44b720`, `C2Init = 0x44b6a0`, `C2QuickJSPointersInto = 0x44b4e0`
  (context: `C2DiagQJSInto = 0x44b500`). These are RVAs of **this build**; the
  probe reparses the Windows-side copy at run time and never trusts them.
- Not committed (`.dll` excluded); recorded so the upload can be checked
  byte-identical (P12: upload under the NEW name `sqjs_c4.dll`).

**C2Init logic: untouched, no disproof found.** `exports.zig::C2Init` still
delegates to `C2TestQuickJS()` and returns its rc. Native `C2TestQuickJS`
returns rc=0 (§33 and re-run here), so nothing written or run this task showed
C2Init broken; whether the **live** C2Init returns 0 is exactly what the pending
dispatch will establish — hypothesis, neither confirmed nor refuted here (P13).

**Probe design facts** (`scripts/c2_task5_init.py`): gate first, verbatim
`c2_task3_diag.py:137-144` shape (inject once → alive → PowerShell 64-bit base →
MZ → `list_exports` of the injected copy → `C2Sanity == 42` + alive), then the
single `C2Init` dispatch (assert rc==0, alive), then `remote_alloc(16)` →
`call_remote_with_arg(C2QuickJSPointersInto, buf)` → alive → `read_memory(16)` →
`parse_pointers`. `C2DiagGetLogAddr` is never used (usize, injector-unusable). A
NULL result raises with the specific diagnosis of *which* pointer is NULL
(rt-only-NULL = wrong module copy called; ctx-NULL-with-live-rt = init got
partway; both-NULL = rc=0 set neither). `dispatch_c2_init_once` refuses a second
C2Init per session — §33 ledgered that re-dispatch resets `g_test_rt/g_test_ctx`
without freeing the previous runtime. The ~8-line sanity gate stays duplicated
per probe script; `c2_harness.py` not modified (controller ruling).

**Counts for §34**: changed `src/dll/quickjs/quickjs_wrapper.c` (+
`C2WriteQuickJSPointersInto`), `src/dll/exports.zig` (+extern decl +`C2QuickJSPointersInto`
export), `src/dll/quickjs/c2_diag_test.zig` (+2 tests), `scripts/test_c2_harness.py`
(+4 tests, 2 doc/list touch-ups), added `scripts/c2_task5_init.py`. No `.dll`/`.pdb`/
`C:\temp\*` committed; `build.zig` unchanged (the `c2_diag_tests` step already exists);
`src/dll/scripted/**`, C1 gate, and the `0x5350D0` constraint untouched.

## 35. Task 6: `JS_Eval("1+1")` through the wrapper — P19 defects fixed, native RED→GREEN; live dispatch PENDING (2026-10-08, native only)

**Scope actually executed.** Offline side of Task 6 only: the two P19 wrapper
defects fixed, `C2EvalProbe` in `quickjs_wrapper.c`, the `C2EvalProbeOnePlusOne`
Zig export, 8 new native tests, the Windows-side probe script
`scripts/c2_task6_e2e.py` (written, **never run**), host tests for its pure
decoder, and the carried Task 5 Minor. **Live dispatch PENDING: the game is down
and only the human partner restarts it. Plan Steps 3, 5 and 6 (re-upload + re-run
live, and the no-init live re-run) were NOT executed — no `ssh`, no `scp`, no
injection, no Windows-side command was run from this host.** Nothing below is a
live observation; the queued commands are listed verbatim at the end.

**Ruling P19 — the two defects, as found and as fixed** (`quickjs_wrapper.c`
hand-forwards QuickJS's `JSValue` and re-implements quickjs.h's static-inline
refcount helpers; both reimplementations were wrong and both were live in HEAD):

1. *Macro bound.* HEAD `quickjs_wrapper.c:60`:
   `#define JS_VALUE_HAS_REF_COUNT(v) (((uint32_t)((v).tag)) >= (uint32_t)7)`
   vs quickjs.h:287 `((unsigned)JS_VALUE_GET_TAG(v) >= (unsigned)JS_TAG_FIRST)`
   with `JS_TAG_FIRST = -9` (quickjs.h:77, comment at :76 "all tags with a
   reference count are negative"). `>= 7` wrongly admits
   `JS_TAG_SHORT_BIG_INT = 7` and `JS_TAG_FLOAT64 = 8` (quickjs.h:93-94), for
   which `JS_VALUE_GET_PTR(v)` is the number's own bit pattern: `JS_DupValue`
   then wrote a refcount through `0x3FF8000000000000 - 4` (the double 1.5).
   Fixed at `quickjs_wrapper.c:67-82` — `JS_TAG_FIRST` is defined as `(-9)` and
   the test is `((uint32_t)JS_VALUE_GET_TAG(v)) >= (uint32_t)JS_TAG_FIRST`, the
   exact unsigned form quickjs.h uses (negative tags wrap above `0xFFFFFFF6`, so
   every positive tag is rejected).
2. *Unguarded free.* HEAD `quickjs_wrapper.c:93-95`:
   `void JS_FreeValue(JSContext *ctx, JSValue v) { __JS_FreeValue(ctx, v); }` —
   no `JS_VALUE_HAS_REF_COUNT` guard and no decrement test.
   `__JS_FreeValueRT` (quickjs.c:6473) switches on the tag with cases only for
   the refcounted tags and ends in `default: abort()` (quickjs.c:6539-6540), so
   freeing a `JS_TAG_INT` (exactly what `JS_Eval("1+1")` returns), a
   `JS_TAG_EXCEPTION` marker or a `JS_TAG_FLOAT64` aborted the host process —
   inside `stellaris.exe` that is a self-inflicted game death. It also ignored
   the refcount entirely, releasing values that still had holders. Fixed at
   `quickjs_wrapper.c:114-133`, mirroring quickjs.h:687-695 (`<= 0` on a
   `uint32_t` count is this file's `== 0`; the two agree for every well-formed
   value and differ only for an already-zero count, where quickjs.h double-frees
   and this releases nothing).

Both defects were **dormant until Task 6**: nothing before it passed a real
`JSValue` by value through these wrappers, and `1+1`'s result is precisely the
tag that reaches `abort()`.

**Native RED evidence (observed, verbatim).** Reproduction method, recorded so
the output is trusted: the Task 6 tests were written first, then
`git show HEAD:src/dll/quickjs/quickjs_wrapper.c` was temporarily put back in
place (pre-fix sha256 `0489961d288cb76f77aa80cacf269c95689a21c5c00197c4d3136cb58f91ef52`)
and each test was run alone with the same command shape:

```
zig test --test-filter "<test name>" src/dll/quickjs/c2_diag_test.zig -lc -Ilibs/quickjs \
  -cflags '-DCONFIG_VERSION="2025-09-13"' -Wno-gnu-zero-variadic-macro-arguments -- \
  libs/quickjs/quickjs.c libs/quickjs/libregexp.c libs/quickjs/libunicode.c \
  libs/quickjs/cutils.c libs/quickjs/dtoa.c src/dll/quickjs/quickjs_wrapper.c
```

- free test (`P19: JS_FreeValue on non-refcounted tags returns instead of aborting`) —
  no Zig trace, a C-side abort:
  `error: the following test command terminated with signal ABRT:` (exit 1).
- dup test (`P19: JS_DupValue on JS_TAG_FLOAT64 / SHORT_BIG_INT writes outside nothing`):
  ```
  General protection exception (no address available)
  src/dll/quickjs/quickjs_wrapper.c:104:21: 0x153eb85 in JS_DupValue (src/dll/quickjs/quickjs_wrapper.c)
          p->ref_count++;
                      ^
  …/src/dll/quickjs/c2_diag_test.zig:238:27: … const df = JS_DupValue(ctx, f);
  error: the following test command terminated with signal ABRT:
  ```
- refcounted-string test (`P19 fix keeps genuinely refcounted tags refcounted (real JS string)`):
  `expected 1, found 2` / `FAIL (TestExpectedEqual)` at `c2_diag_test.zig:275`
  (`expectEqual(initial, rc.*)` after one free). Observed mechanism, which differs
  from the double-free crash predicted while writing it: `JS_TAG_STRING` is -7 and
  `(uint32_t)(-7) >= 7` is true, so dup *did* increment 1→2; the unconditional free
  then released the string **without decrementing**, so the (already freed) header
  still read 2. Recorded as observed (P13).
- probe tests before `C2EvalProbe` existed: `error: undefined symbol: C2EvalProbe`
  (`referenced by c2_diag_test.o:c2_diag_test.test.C2EvalProbe on a value JS_ToInt32
  cannot convert returns 2` … `referenced 3 more times`) — link stage, exactly where
  a missing C symbol surfaces (same failure mode as §34's P4 RED).

**GREEN.** The fixed wrapper was restored (`cp -f`, sha256 verified back to
`03e8f5bf6f77d8d5b1a7f3bace395d4150d447506cdfc42e760e0aab3786f7a7`, `git diff
--stat` → 119 insertions / 2 deletions) and the same command, unfiltered, gives:

```
1/13 …C2EvalProbe returns 0 while g_test_ctx is NULL (no init has run yet)...OK
7/13 …P19: JS_FreeValue on non-refcounted tags returns instead of aborting...OK
8/13 …P19: JS_DupValue on JS_TAG_FLOAT64 / SHORT_BIG_INT writes outside nothing...OK
9/13 …P19 fix keeps genuinely refcounted tags refcounted (real JS string)...OK
10/13 …C2EvalProbe("1+1") returns 11, decoding to int32 2...OK
11/13 …C2EvalProbe on a float result (JS_TAG_FLOAT64) is freed, not aborted...OK
12/13 …C2EvalProbe on unparseable JS returns 1 and leaves the context usable...OK
13/13 …C2EvalProbe on a value JS_ToInt32 cannot convert returns 2...OK
All 13 tests passed.    (exit 0)
```

Observations pinned by those tests, all against the real vendored QuickJS (no
mocks): `1+1` → rc **11**, `@divTrunc(11-3,4) == 2`, `11 % 4 == 3`; `1.5` → rc 7
(n = 1, i.e. `JS_ToInt32` truncates and the FLOAT64 is freed without aborting);
`this_is_not_valid_js ~~` → rc **1** and the *same* context then returns 11 for
`1+1` (the pending exception is moved out and released by `c2_clear_pending_exception`,
quickjs.c:7406-7413 — that release is leak prevention for the moved-out exception
value, not what makes the context re-dispatchable: a second `JS_Eval("1+1")` succeeds
even with an exception pending);
`({ valueOf() { throw 1; } })` → rc **2** (ToNumber propagates, `JS_ToInt32`
returns -1) and 11 again afterwards; `C2EvalProbe("1+1")` with no init at all →
rc **0**, the `if (!g_test_ctx) return 0;` guard (quickjs_wrapper.c:413) reached
before `JS_Eval`. The no-init test is **declared first** in `c2_diag_test.zig`
because nothing here frees `g_test_ctx` — its precondition (rt/ctx still NULL) is
asserted, so a reordering fails loudly as `error.InitRanBeforeThisTest` instead of
passing silently; the live equivalent is the second module instance (P22).

**Suite / build / host-test numbers.**
- `zig build test` → `Build Summary: 22/25 steps succeeded (1 failed); 288/288 tests passed`
  (§34 baseline 280/280, +8 Task 6 tests). The one failure is the **same
  pre-existing** exports.zig-rooted link failure — `undefined symbol: CreateFileA /
  WriteFile / CloseHandle / GetModuleHandleA` (kernel32 on an ELF host, ruling P15),
  8 errors, unchanged in mode and symbol set; `C2EvalProbe` is not among them.
- `zig build` (x86_64-windows) → exit 0.
- `python3 -m pytest scripts/test_c2_harness.py -q` → **26 passed** (§34 baseline 20;
  +6 host tests for `decode_probe_rc`: 11→`("int32", 2)`, the three sentinels, 3→n=0,
  negatives raise, non-congruent codes raise, the wrapped-unsigned `2**32-1` → `("int32", -1)`).
  `C2EvalProbeOnePlusOne` was added to `test_list_exports_recovers_all_known_names`.

**Ruling P20 — the brief's expected rc was wrong, corrected against real output.**
Plan Step 2/4 assert `rc == 7` ("`1*4 + 3 = 7`") and print "returned int32 1". The
encoding is `n*4+3` with `n` the *result* of the eval; `1+1` yields **n = 2**, so the
expected exit code is **11**, confirmed by native QuickJS above. `7` is exactly what
the same encoding produces for `n = 1` (the observed `1.5` case), which is where the
slip came from. The encoding itself stands and is collision-free: `n*4+3 ≡ 3 (mod 4)`
can never equal the sentinels 0/1/2. `scripts/c2_task6_e2e.py` asserts 11/2 and says
so in its failure text.

**Ruling P21 — first real by-value `JSValue` crossing.** `C2EvalProbe` is the first
code to receive a `JSValue` *by value from QuickJS* (`JS_Eval`'s result) and pass one
back (`JS_ToInt32`'s argument) through a TU that includes no `quickjs.h`. Legal
because quickjs.h:56-65 defines `JS_PTR64` whenever `INTPTR_MAX >= INT64_MAX`, which
*suppresses* `JS_NAN_BOXING`, so x86-64 uses the 16-byte `{JSValueUnion u; int64_t
tag;}` struct of quickjs.h:216-232 — byte-compatible with the hand-forwarded copy at
`quickjs_wrapper.c:43-53` (its union is 8 bytes either way). Test 10/13 (rc 11) is
this crossing's executed proof; a 32-bit or NaN-boxed target is where it would break.

**Deviations from the plan's Step 1/2 sketch (ruling P9).** The sketch's
`JS_ToInt32_`, `JS_IsException_`, `JS_FreeValue_` do not exist: `JS_Eval`
(quickjs.h:836), `JS_ToInt32` (:730) and `JS_GetException` (:669) are real exported
symbols and are extern'd at `quickjs_wrapper.c:372-375`, while `JS_IsException` (:641)
and `JS_FreeValue` (:687) are `static inline` with no linker symbol — the exception
test is therefore the tag comparison `JS_VALUE_GET_TAG(v) == JS_TAG_EXCEPTION` and the
free reuses this file's own (now guarded) `JS_FreeValue`. No QuickJS C symbol is bound
on the Zig side: `src/dll/exports.zig:110` externs only `C2EvalProbe`, our wrapper
(global constraint). `eval_flags 0` is `JS_EVAL_TYPE_GLOBAL` (quickjs.h:332). Unlike
Task 5's P17 there was no duplicate-symbol split here: the C symbol `C2EvalProbe` and
the PE name `C2EvalProbeOnePlusOne` simply differ (`exports.zig:278` is a one-line
forwarder with the fixed string `"1+1"`; remote string marshalling is deferred to C3).
`return (int)((uint32_t)n * 4u + 3u)` is modular, not signed-overflow UB — `n*4`
overflows int32 for `|n| >= 2^30`; the wrap preserves `(rc-3)/4` in two's complement
and is irrelevant for the fixed `1+1`, but C3's general-argument API must not reuse
this encoding without a range check (P20 deferred minor).

**Built artifact (host-side PE reparse with `c2_harness.list_exports`, no hard-coded
RVAs — P10).** `zig build` output `zig-out/bin/stellaris_quickjs.dll` (7 156 736 bytes):
- sha256 `3ad4433ea75fe893d5771e1f63e3ffed75a417f58f6190966077ff17b15a3cac`
- 31 exports (§34: 30, +1 = the new probe), all RVAs distinct. Task-6-relevant rows:
  `C2Sanity = 0x44bb20`, `C2Init = 0x44baa0`, `C2QuickJSPointersInto = 0x44b8e0`,
  **`C2EvalProbeOnePlusOne = 0x44b850`**. All four moved relative to §34 because the
  wrapper grew; the probes reparse at run time and never trust these.
- Not committed (`.dll`/`.pdb` excluded); recorded so the upload can be checked
  byte-identical. Per P22 the authorized live session uploads these bytes as
  `C:/temp/sqjs_c5.dll` **and** a second copy of the same bytes as
  `C:/temp/sqjs_c5_noinit.dll` (Windows loads per-path, so the second instance gets
  its own zero-initialised `g_test_ctx` — what makes Step 6 a real test rather than
  a state leak).
  **SUPERSEDED 2026-10-09**: this hash describes the pre-`JS_UpdateStackTop` build.
  The final whole-branch review found the cross-thread stack-guard defect recorded
  in the next subsection; the queued live dispatch block below now names the
  rebuilt artifact (`cef9fa056de2…`), and the hash/RVAs above must not be used to
  check the upload.

### Fix dispatch: cross-thread stack guard refresh — CONFIRMED BY CODE READING, NOT YET OBSERVED LIVE (2026-10-09)

**What this section is.** Per ruling P13 the ledger records observed facts only;
this is explicitly labelled: the defect below is a **confirmed defect from static
code reading plus a native reproduction, NOT a live measurement** — no game was
touched, and the spurious `rc == 1` has not been observed in the live session
(the live shot was still queued when the fix landed, so it never had the chance).

**The defect** (every line re-read and verified in `libs/quickjs` on 2026-10-09):
QuickJS's stack guard is compiled for every non-Emscripten target —
`CONFIG_STACK_CHECK` at quickjs.c:75-77. `JSRuntime` caches `uintptr_t stack_top`
and `uintptr_t stack_limit` (quickjs.c:349-350); `update_stack_limit()` computes
`stack_limit = stack_top - stack_size` (quickjs.c:2882-2889, the subtraction at
:2887) and `JS_SetMaxStackSize` calls it (quickjs.c:2891-2895, the call at :2894);
`js_check_stack_overflow()` is `return unlikely(sp < rt->stack_limit);`
(quickjs.c:2059-2064, the return at :2063). `rt->stack_top` is set only by
`JS_UpdateStackTop(rt)` (quickjs.c:2897-2900), declared public at quickjs.h:378
with the comment "should be called when changing thread" (:376-377) — and it is
called **exactly once**, inside `JS_NewRuntime2` (quickjs.c:2116; a grep over
`libs/quickjs` finds no call site in quickjs.c other than :2116). The live C2
sequence dispatches `C2Init` on `CreateRemoteThread` A — which captures **A's**
stack top, sets `stack_limit = top_A − 1 MiB` (`JS_SetMaxStackSize(g_test_rt,
1024*1024)`) — and then **exits**; `C2EvalProbeOnePlusOne` runs on a different
`CreateRemoteThread` B, and `JS_Eval` → `JS_CallInternal` compares **B's** sp
against the stale limit. If B's stack base lies below `top_A − 1 MiB` (likely:
Windows returns a freed thread stack to the OS and the next thread lands
elsewhere) QuickJS throws a spurious `StackOverflow`, `JS_Eval` returns the
exception marker, the probe reports sentinel `rc = 1`, and `SENTINEL_DIAGNOSIS[1]`
would steer the human partner toward "parser rejecting global code / missing base
intrinsics" — a wrong diagnosis on the single authorized live shot. If B's stack
lies above A's, the guard instead points at the wrong region (ineffective).
Either way it is wrong. The pre-existing native tests could not catch this by
construction: they run init and probe on one thread, so the cached top is always
the evaluator's.

**The fix** (`quickjs_wrapper.c`, two edits): `extern void
JS_UpdateStackTop(JSRuntime *rt);` declared alongside the file's other QuickJS
externs (after `JS_SetMemoryLimit`) — a genuine exported QuickJS function bound
**in C**, per the global constraint; no new Zig `extern fn` was added and
`bindings.zig:345`'s existing declaration remains unreferenced by the live path.
`C2EvalProbe` now calls `JS_UpdateStackTop(g_test_rt);` immediately after the
`if (!g_test_ctx) return 0;` early-return and before `JS_Eval` (ctx non-NULL
implies rt non-NULL: every init path sets both together and nothing frees
either). Refcount/`JS_FreeValue` handling untouched.

**Native evidence (observed, verbatim).** TDD order: the test was written first
and run against the UNFIXED wrapper (working-tree diff was `c2_diag_test.zig`
only, so no file restoration was needed to verify state):

```
1/1 …C2EvalProbe on a lower-stack thread (runtime built on main) returns 11, not stale-guard 1…
expected 11, found 1
FAIL (TestExpectedEqual)   (exit 1)
```

— the stale guard really does turn a cross-thread `1+1` into sentinel 1. After
the two-line C fix: filtered test GREEN 3/3 runs, whole file 14/14, suite
`zig build test` → `289/289 tests passed` with the same pre-existing
exports-rooted link failure (8 errors, symbols `CreateFileA/WriteFile/
CloseHandle/GetModuleHandleA`, ruling P15, unchanged); `python3 -m pytest
scripts/test_c2_harness.py -q` → 26 passed; `zig build` exit 0.

**What the test proves and what it does not** (stated honestly, as briefed). The
shipped test builds the runtime on the MAIN thread and evaluates on a spawned
`std.Thread` whose pthread stack lies hundreds of GB below main's top (measured
layout: main ~`0x7ffc/7ffe…`, pthread ~`0x7f…`, 3/3 prototype runs), pinning
that gap with a precondition assert so an inverted layout fails loudly instead of
passing vacuously. It pins: the symbol links and is callable with our runtime;
the refresh runs BEFORE `JS_Eval` (a call placed after it leaves rc 1 — exactly
the RED shown); and a refreshed guard does not break the `1+1` → rc 11 gate. The
**cross-thread correctness argument rests on the QuickJS API contract**
(quickjs.h:376-378), not on this test. The literal live order (A inits then
exits, B evals) was attempted first and is VACUOUS on this host: every run
lands B on A's exact stack segment — B's thread-local address equalled A's
10/10 prototype runs, even at unequal stack sizes (default-size A → 8 MiB B;
glibc cached-stack reuse or an indistinguishable same-address remap — the
observed fact is the address identity) — so the stale guard would look correct
either way. Reported per the brief rather than shipped as a test that asserts
nothing. That is a host-layout accident; on Windows the freed stack is returned
to the OS, which is why the live defect stands.

**Also changed**: `scripts/c2_task6_e2e.py` `SENTINEL_DIAGNOSIS[1]` gained one
clause — "or the cross-thread stack guard — see §35" — among the causes `rc == 1`
can mean (no structural change; the probe stays on its own thread so the
`--noinit` tripwire semantics of 93b1cda hold; the table is not host-tested, so
`test_c2_harness.py` is unchanged at 26 passed).

**Rebuilt artifact** (host-side `c2_harness.list_exports`, no hard-coded RVAs):
`zig-out/bin/stellaris_quickjs.dll`, 7 156 736 bytes (same size as the superseded
build, different content — check the hash, not the length):
- sha256 `cef9fa056de272c9acd6cef562b16c8167932259237b224a0beff6a1d27a1214`
- 31 exports, all RVAs distinct; `C2Sanity = 0x44bb30`, `C2Init = 0x44bab0`,
  `C2QuickJSPointersInto = 0x44b8f0`, **`C2EvalProbeOnePlusOne = 0x44b860`** —
  each exactly +0x10 from the superseded build, consistent with the wrapper
  growing by the declared extern and the refresh call.
- Not committed (`.dll`/`.pdb` excluded). Source identities at commit time:
  `quickjs_wrapper.c` sha256 `d4eb0d78cebe…`, `c2_diag_test.zig` sha256
  `06277cbee500…`, `scripts/c2_task6_e2e.py` sha256 `9ebd4572f477…`.

**Counts for this fix dispatch**: `src/dll/quickjs/quickjs_wrapper.c` (+1 extern,
+1 call + comments), `src/dll/quickjs/c2_diag_test.zig` (+1 two-thread test +
header block), `scripts/c2_task6_e2e.py` (one diagnosis clause), this §35
subsection + supersession notes. No new exports, no `c2_harness.py` change, no
C3 API, `keyword_registry.zig:211` gate state untouched.

**Task 5 deferred Minor carried.** `scripts/c2_task5_init.py`'s ctx-NULL-with-live-rt
diagnosis said "init got partway (runtime created, JS_NewContextDiag did not
complete)", which `assert rc == 0` makes unreachable: `JS_NewContextDiag`
(quickjs.c:2669) stores `*out_ctx = NULL` on entry and every failure path (rc 1..12)
frees the context and leaves it NULL, so rc 0 ⟹ `g_test_ctx` was set — a NULL ctx can
only mean the module that answered is not the module whose code produced rc 0.
Reworded at `c2_task5_init.py:133-137` to the `c2_task3_diag.py:105-109` shape — a
contradiction between rc and the observed pointer, pointing at a wrong/stale module
copy — diagnostic text only, no control-flow change. Its argv default moved from
`sqjs_c4.dll` to `sqjs_c5.dll` (code + docstring) per P22. §34's sentence
"ctx-NULL-with-live-rt = init got partway" describes the pre-fix text and is superseded
by this paragraph.

**Probe design facts** (`scripts/c2_task6_e2e.py`, written but not run): `main()`
parses `--noinit` and an optional dll path (default `C:\temp\sqjs_c5.dll`, or
`C:\temp\sqjs_c5_noinit.dll` with `--noinit`) and checks `os.path.isfile` on the dll
**before** touching the game. Gate order is the verbatim `c2_task3_diag.py` shape,
duplicated per probe rather than moved into the harness (ruling P18;
`scripts/c2_harness.py` not modified): inject once → alive → `resolve_base_address`
keyed on the exact filename injected (P8) → MZ check at that base →
`list_exports` of that same Windows-side file (P10) → `C2Sanity == 42` → alive. Only
then: `C2Init` (assert rc 0) → `C2EvalProbeOnePlusOne` → decode → alive.
`dispatch_once` refuses a second dispatch of either symbol (re-dispatch resets
`g_test_rt/g_test_ctx` without freeing the previous runtime, §33/§34), and no-init
mode carries a tripwire asserting `"C2Init" not in _dispatched`. The three sentinels
get three distinct diagnoses. `decode_probe_rc` is pure and host-tested; it exists as
a separate function because `GetExitCodeThread` yields a `DWORD` and
`c2_harness.call_remote` returns it as an **unsigned** Python int (`ctypes.c_uint`),
so a C-`int` negative would arrive wrapped (`-1` → `4294967295`): the helper re-biases
values above `0x7FFFFFFF` before matching, which keeps the decode exact instead of
reporting a wrong `n`.

### LIVE DISPATCH PENDING (Task 6 Steps 3, 5, 6 — queued, not run)

Blocked on: the game being down and the human partner restarting it. No command below
was executed. Order matters; each remote run needs `c2_harness.py` present in
`C:/temp/` (P5), and every script must be re-scp'd with this section's final content.

```sh
# 0. build + upload the §35 artifact under its NEW name (P12/P22), twice: once as the
#    live copy, once as the independent no-init instance.
zig build
scp zig-out/bin/stellaris_quickjs.dll Windows_Jiaolong:C:/temp/sqjs_c5.dll
scp zig-out/bin/stellaris_quickjs.dll Windows_Jiaolong:C:/temp/sqjs_c5_noinit.dll
scp scripts/c2_harness.py scripts/c2_task2_load.py scripts/c2_task3_diag.py \
    scripts/c2_task5_init.py scripts/c2_task6_e2e.py Windows_Jiaolong:C:/temp/

# 1. confirm the uploaded bytes are the ones hashed above.
ssh Windows_Jiaolong "certutil -hashfile C:\temp\sqjs_c5.dll SHA256"
#    expect: cef9fa056de272c9acd6cef562b16c8167932259237b224a0beff6a1d27a1214

# 2. Step 3 — load + sanity on the new copy (path passed as argv; P22).
ssh Windows_Jiaolong "python C:/temp/c2_task2_load.py C:/temp/sqjs_c5.dll"
#    expect: C2Sanity -> 42

# 3. Task 5's pending dispatch, now against the same bytes (argv default is sqjs_c5.dll).
ssh Windows_Jiaolong "python C:/temp/c2_task5_init.py"
#    expect: C2Init rc == 0 and both pointers non-NULL.

# 4. Step 5 — the C2 acceptance gate.
ssh Windows_Jiaolong "python C:/temp/c2_task6_e2e.py"
#    expect: `Task 6: 1+1 evaluated inside the game process and returned int32 2 (rc=11 = 2*4+3)`

# 5. Step 6 — the !g_test_ctx guard on a SECOND instance of the same bytes,
#    in a separate Python process (fresh _dispatched, own base, own reparse).
ssh Windows_Jiaolong "python C:/temp/c2_task6_e2e.py --noinit"
#    expect: `Task 6 (Step 6): C2EvalProbeOnePlusOne returned 0 with no C2Init in this
#    module copy — the !g_test_ctx guard holds and did not crash`
```

Expected outcome if the P19 fix is right: steps 4 and 5 above print their Task 6
lines with the game alive. Expected outcome if it is wrong: the game dies at step 4
(the abort is in the free that follows a successful eval) — that is the risk this
section records rather than measures. **Task 6 is not closed until these five commands
run in an authorized live session.**

**Counts for §35**: changed `src/dll/quickjs/quickjs_wrapper.c` (P19 macro + guarded
`JS_FreeValue`, + Task 6 block `C2EvalProbe`/`c2_clear_pending_exception`/3 externs),
`src/dll/exports.zig` (+extern `C2EvalProbe` +`export fn C2EvalProbeOnePlusOne`),
`src/dll/quickjs/c2_diag_test.zig` (+8 tests: 1 guard, 3 P19, 4 probe),
`scripts/test_c2_harness.py` (+6 tests, +1 known-export name, docstring),
`scripts/c2_task5_init.py` (diagnostic text + argv default only), added
`scripts/c2_task6_e2e.py`. No `.dll`/`.pdb`/`C:\temp\*` committed; `build.zig` and
`scripts/c2_harness.py` unchanged; no new Zig `extern fn` bound to a QuickJS C symbol;
`src/dll/scripted/**`, the C1 gate and the `0x5350D0` constraint untouched.

## 36. The §35 live dispatch was finally run — Task 2 PASS, Task 5 rc=3, and the game exited (2026-10-21, live)

**What was authorized and what was done.** The human partner asked to merge the two diverged lines and
run the §35 queue on the real machine. This section records the **observed** output of that session and
nothing else: no fix was implemented here, and the §35 stack-guard hypothesis was **neither confirmed nor
refuted** — the shot never reached the eval probe.

### 36.1 The merge, and why the §35 hash must not be used as the upload identity check (2026-10-21)

Two lines had diverged from `d443986` (2026-10-08): `worktree-c2-quickjs-bootstrap` (9 commits, §31–§35,
C2 up to the Task 6 native GREEN) and `launch-stellaris-bootstrap` (24 commits, `scripts/windows/`).

**Observed**: `git diff --name-only d443986 <c2-tip>` and the same against `<launch-tip>` share **zero
paths** — the C2 side owns `src/dll/**`, `build.zig`, `libs/quickjs/quickjs.c`, `evidence/**`, the
`scripts/c2_*` probes; the launcher side owns `scripts/windows/**`, two docs and `.gitignore`. The merge
(`48d4971`, branch `c2-live-integration`) was therefore a clean no-conflict join, and
`git diff HEAD worktree-c2-quickjs-bootstrap -- src libs build.zig` is **empty**: the DLL source is
byte-identical to the §35 tip, so the only thing the merge added to the module was nothing.

Native state of the merged tree, run before touching the machine (verbatim tails):

- `zig build` → exit 0; `zig-out/bin/stellaris_quickjs.dll` = **7,154,176 bytes**,
  sha256 `4f2e49b289a3ae963cb1906ebf8bc6dc7fce23dce44933fa122b5f18890fbf9f`.
- `zig build test` → `Build Summary: 22/25 steps succeeded (1 failed); 289/289 tests passed` — identical
  to the §35 record, same single pre-existing exports-rooted link failure (8 errors, `CreateFileA`,
  `WriteFile`, `CloseHandle`, `GetModuleHandleA`, ruling P15). No merge regression.
- `python3 -m pytest scripts/test_c2_harness.py -q` → **26 passed**.
- `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py -q` → **169 passed**
  on the Linux host.

**The §35 recorded artifact and this rebuild do not match byte-for-byte, and that is expected.** §35 recorded
`cef9fa056de2…` / 7,156,736 bytes for these same sources; tonight's rebuild is `4f2e49b2…` / 7,154,176.
A host-side `c2_harness.list_exports` reparse of the new file gives **the exact RVAs §35 recorded**:
31 exports, `C2Sanity = 0x44bb30`, `C2Init = 0x44bab0`, `C2QuickJSPointersInto = 0x44b8f0`,
`C2EvalProbeOnePlusOne = 0x44b860`. Same code layout, different container bytes → the Zig/LLD COFF link
is not reproducible (PE `TimeDateStamp`, debug-section sizing). **Consequence for every future live shot:
§35's hash is dead as an upload check; identity is (git-identical sources) + (export RVAs), which is also
what the probes themselves re-derive at run time (P10).**

### 36.2 LIVE — Task 2 Step: load + sanity on the rebuilt bytes: PASS

Remote state before the first dispatch: `stellaris.exe` PID **18292**, started 2026-10-21 **21:15:08**
(Steam chain `dowser.exe` 16176 → 8472 → 18292, AppID 281990), sitting at the main menu — its last log
write was `logs/time.log` at 21:15:39 (`Recalc cached data real time: 1028 ms`), i.e. ~40 min idle.

Both copies uploaded as §35 prescribed (`C:\temp\sqjs_c5.dll` and the independent
`C:\temp\sqjs_c5_noinit.dll`), and `certutil -hashfile … SHA256` on the Windows side returned
`4f2e49b289a3ae963cb1906ebf8bc6dc7fce23dce44933fa122b5f18890fbf9f` for **both** — matching the local file.

```
> python C:\temp\c2_task2_load.py C:\temp\sqjs_c5.dll
DLL base (real, 64-bit): 0x7ffcd05c0000
MZ header at base OK
C2Sanity RVA from PE reparse: 0x44bb30
C2Sanity -> 42
Task 2: PASS
```

This repeats §31's live result on new bytes: injection + `C2Sanity` is survivable.

### 36.3 LIVE — Task 5: `C2Init` rc = 3, and the game process disappeared

```
> python C:\temp\c2_task5_init.py C:\temp\sqjs_c5.dll
[task5] pid=18292  dll=C:\temp\sqjs_c5.dll
[task5] sqjs_c5.dll base (64-bit): 0x7ffcd05c0000
[task5] MZ header at base OK
[task5] C2Init RVA from PE reparse:                  0x44bab0
[task5] C2QuickJSPointersInto RVA from PE reparse:   0x44b8f0
[task5] C2Sanity == 42, game alive — C2Init dispatch authorized
Traceback (most recent call last):
  File "C:\temp\c2_task5_init.py", line 145, in <module>
    main()
  File "C:\temp\c2_task5_init.py", line 110, in main
    assert rc == 0, ...
AssertionError: C2Init rc = 3 (nonzero = failing step code, see §32/§33 decode tables)
```

The dispatch **returned** (rc came back through `GetExitCodeThread`, so the injected thread completed and
reported), the assert fired before `C2QuickJSPointersInto` was ever called, so **the rt/ctx pointer
observation was not taken** — we do not know from this shot which globals were set.

Then `stellaris.exe` was gone. Attribution, as observed evidence:

| Fact | Source |
|---|---|
| `Game process removed: AppID 281990 "…\Stellaris\dowser.exe", ProcID 18292` at **21:57:15** | `C:\Program Files (x86)\Steam\logs\console_log.txt` |
| `gameoverlay_ui.txt` / `gameoverlay_renderer.txt` last write 21:57:11 (overlay teardown) | same directory |
| **No** `Application Error` / `Application Hang` / `Windows Error Reporting` event in the Application log for the window (queried all levels, −45 min) | `Get-WinEvent` |
| **No** crash dump: `$env:LOCALAPPDATA\CrashDumps` empty in the window; no WER `ReportQueue`/`ReportArchive` directory for any app; no `WerFault` process | direct listing |
| **No** new line in the game's own `error.log` (last entry 21:15:36, pre-injection) or `debug.log` (21:15:26) | log tails |
| Nothing in the harness or `c2_task5_init.py` unloads or terminates: the only cleanup calls are `CloseHandle` on our own thread/process handles and `VirtualFreeEx` of our own remote buffer; no `FreeLibrary`, no `TerminateProcess`; the assert just unwinds | `scripts/c2_harness.py:378-495`, `scripts/c2_task5_init.py:77-144` |

**Inference, explicitly not observed**: the only side effect inside the death window was the `C2Init`
dispatch — `LoadLibrary` + `C2Sanity` had already been survived live twice (§31 and §36.2 above), and
§32 recorded the sibling QuickJS-init path (`C2DiagQJSInto`) terminating the game the same way. So
"QuickJS init inside the injected module kills the host on Windows" is the standing hypothesis, and it is
now **2 for 2 on the calls that reach QuickJS, 0 for 2 on the calls that don't**. It is not proven: we
have no exit code for PID 18292 and no dump, and WER appears to be disabled or its reports are elsewhere
on this box, so the absence of crash records is *silence*, not *evidence of a clean exit*.

### 36.4 The rc=3 we got cannot be decoded — and on this path there is no log to disambiguate it

§32 (ruling P7) established that the `C2DiagQuickJS` outer and inner step codes overlap and that "the log
text is authoritative". **That escape does not exist for `C2Init`**, which is the export the probe drives:
`exports.zig:196 C2Init` → `C2TestQuickJS` (`quickjs_wrapper.c:245`), a function that returns step codes
but **writes nothing into `g_diag_log`**. So tonight's `3` is irreducibly ambiguous between two mutually
exclusive states:

| Candidate | Site | Reached QuickJS state |
|---|---|---|
| runtime opaque write/read mismatch | `quickjs_wrapper.c:263` (`if (opaque != (void *)(uintptr_t)0xDEADBEEF) return 3;`) | returns **before** `JS_SetMaxStackSize`, `JS_SetMemoryLimit`, and any `JS_NewContextRaw` — **no context ever existed** |
| `JS_AddIntrinsicDate` failure | `libs/quickjs/quickjs.c:2678` → `return diag_rc;` at `quickjs_wrapper.c:276` | runtime configured, one raw ctx created and freed, one full ctx created and **freed on the failure path** |

`2` and `4` are ambiguous the same way (`JS_NewRuntime2` NULL vs BaseObjects; standalone raw-ctx NULL vs
Eval). **This is a probe defect, not a QuickJS finding**: the single authorized shot landed on a code with
two readings, exactly the failure mode §35 warned about for the sentinel `rc == 1`.

Note the second row matters for the direction the human partner proposed — checking for a pending
exception. Two facts fix that:

- `JS_GetContextProtocol` **does not exist in this vendored QuickJS**: zero hits across
  `libs/quickjs/quickjs.h` and `libs/quickjs/quickjs.c`. The APIs this tree has are
  `JS_GetException` (`quickjs.h:669`, defined `quickjs.c:7406`) and `JS_HasException`
  (`quickjs.h:670`, defined `quickjs.c:7415`).
- A pending exception **cannot be read by the caller** even with the right API, because every failure
  branch of `JS_NewContextDiag` is `{ JS_FreeContext(ctx); return N; }` — the context that owns
  `rt->current_exception` is destroyed before any code outside can query it. Any exception capture must
  therefore be inserted **inside `libs/quickjs/quickjs.c`, in the failing branch, before the free**.

### 36.5 Session state at the end of this § — what is and is not closed

- **Closed by observation**: Task 2 live on the merged, rebuilt bytes (sanity 42, base reparse, MZ check).
- **Open**: Task 5 live (`rc == 3`, pointer observation never taken), Task 6 Steps 5 and 6 (the eval probe
  and the `--noinit` guard) — **not run**. Running them now would prove nothing about §35's stack-guard
  fix: with `g_test_ctx` NULL the probe's first statement returns 0, which is the guard's expected output,
  not an eval result.
- The §35 stack-cross-thread defect is **still unobserved live**, exactly as its own heading says
  ("CONFIRMED BY CODE READING, NOT YET OBSERVED LIVE").
- Machine state: `stellaris.exe` is **down**; `steam.exe` (PID 9072) is up. The next shot needs a relaunch,
  which is precisely what `scripts/windows/launch_stellaris.py` was built for and what it did on
  2026-10-21 (full bridge run, exit 0, live PID after ~30 s observe).
- Remote scratch left in `C:\temp`: `sqjs_c5.dll`, `sqjs_c5_noinit.dll`, the five `c2_*.py` probes. The three
  read-only PowerShell probes written this session (`probe_crash_20261021.ps1`, `probe2_20261021.ps1`,
  `probe3_20261021.ps1`) were **deleted** once their output was transcribed above — they only ever read
  event logs, directory listings and the Steam log. Nothing under `C:\temp` is committed, per the standing
  rule; the DLL and the probes stay there because that is the session's working scratch and the next shot
  reuses the same names.

**Counts for §36**: this section only. No `.zig`/`.c`/`.py` source was changed to produce these
observations; `git diff --stat` against `worktree-c2-quickjs-bootstrap` for `src libs build.zig` is empty,
which is the point of §36.1.

## 37. The §36.4 probe defects are fixed and natively exercised — the next shot is decodable before it is fired (2026-10-21/22, host)

§36.4 closed with two **probe** defects (not QuickJS findings) that made the authorized live shot
unreadable, plus the observation that a pending exception could never have been read from outside.
This section records the fix, the native evidence for it, and the artifact identity for the next shot.
**Nothing here was run against the game** — the host is still down (§36.5) and no dispatch was made.

### 37.1 The three changes, and one deviation from the proposal recorded in §36.5

1. **Disjoint return-code ranges.** `C2TestQuickJS` and `C2DiagQuickJS` were two hand-copied sequences
   that drifted apart (only the diag copy logged) and whose outer codes `10/11/2/3/4` collided with
   `JS_NewContextDiag`'s inner `1..12`. They are now **one** C function,
   `c2_diag_sequence()` (`src/dll/quickjs/quickjs_wrapper.c:269`), with the outer gates renumbered to
   **100..104** (`:290, :292, :296, :303, :310`) and the inner steps left **1..12**
   (`libs/quickjs/quickjs.c:2725-2735`). `0` success, `1..12` inner, `100..104` outer — the ranges do not
   intersect, so an rc names its own path. `C2TestQuickJS` (`:327`) and `C2DiagQuickJS` (`:331`) are now
   one-line wrappers over the shared sequence, which means **the C2Init path finally writes `g_diag_log`**
   — the exact thing whose absence made tonight's `3` irreducible.
2. **The pending exception is captured where it still exists.** `JS_NewContextDiag` takes
   `(rt, out_ctx, err_buf, err_size)` now (`quickjs.c:2709`); every failing branch goes through
   `JS_DIAG_FAIL` (`:2714-2719`) → `js_diag_capture_exception` (`:2663`), which runs
   `JS_HasException` → `JS_GetException` → `JS_ToCString` → `JS_FreeCString` → `JS_FreeValue`
   **before** `JS_FreeContext`, and writes `"<Stage>: <message>"` into the caller's buffer. The
   wrapper surfaces it as ` err=[BaseObjects: InternalError: out of memory]`
   (`quickjs_wrapper.c:318`). The buffer is optional: `err_buf == NULL` leaves the numeric answer
   untouched, which is the pre-§36 calling convention (pinned natively, §37.2 test 4).
   This is also the correction to the direction proposed in §36.4 — the API named there,
   `JS_GetContextProtocol`, does not exist in this vendored copy; `JS_GetException`/`JS_HasException` do.
3. **A read-back that touches no engine code.** New C symbol `C2CopyDiagLog(out)`
   (`quickjs_wrapper.c:349`) — a memcpy of the static plus its length, no QuickJS call — exported over
   the PE as `C2LogInto` (`src/dll/exports.zig:261`, single `lpParameter`, 512-byte contract baked in,
   same shape as `C2QuickJSPointersInto`).

**Deviation from the proposal, on record.** The proposal said the read-back should be "a new zero-arg
export returning the log buffer's **RVA** so it fits the 32-bit thread exit code". Implemented as the
pure copy instead: an RVA return still leaves the caller to compute `base + rva` and read 512 bytes,
i.e. it keeps `VirtualAllocEx`/`read_memory` on the critical path while adding a *second* way to get the
address wrong; the copy needs the same remote buffer it was going to need anyway and returns a length
that cross-checks the text (`c2_task5_init.py:fetch_diag_log` warns on disagreement). Ruling P4 is
satisfied either way; the copy is the smaller live surface.

### 37.2 Native TDD transcript — RED, then the measured OOM band, then GREEN

**RED** (tests written first, `src/dll/quickjs/c2_diag_test.zig:481, :499, :524, :546`; the two symbols
did not exist yet):

```
error: undefined symbol: C2DiagNewContextUnderMemoryLimit
    note: referenced by c2_diag_test.o:c2_diag_test.test.JS_NewContextDiag still reports the step when the caller passes no buffer
    note: referenced by c2_diag_test.o:c2_diag_test.test.JS_NewContextDiag hands back the failing stage plus the pending exception text
error: undefined symbol: C2CopyDiagLog
    note: referenced by c2_diag_test.o:c2_diag_test.test.C2CopyDiagLog is a pure read: byte-identical to the buffer C2DiagQuickJS filled
    note: referenced by c2_diag_test.o:c2_diag_test.test.C2TestQuickJS (the C2Init path) leaves a readable log — the §36.4 gap
```

The first draft of the OOM test assumed `JS_NewContextRaw` is cheap and set the limit to 64 KiB. It was
**wrong about the engine**, and the wrongness is data, so the sweep that resolved it is kept here —
**condensed, not verbatim**: the rows below are band edges from a 4 KiB-step loop (64 KiB → 140 KiB) plus
a coarse pass (64/128/256 KiB … 32 MiB); the intermediate rows were measured but not transcribed. Native
`zig cc` harness over `C2DiagNewContextUnderMemoryLimit`, glibc + our `heap_mf` allocator — the same
`heap_malloc` limit check the Windows module uses (`quickjs_wrapper.c:165`):

```
limit=  64k rc= 1 log=[]
limit=  92k rc= 1 log=[]
limit=  96k rc= 2 log=[BaseObjects: InternalError: out of memory]
limit= 100k rc= 2 log=[BaseObjects: InternalError: out of memory]
limit= 104k rc= 2 log=[BaseObjects: InternalError: out of memory]
limit= 108k rc= 2 log=[BaseObjects: null]
limit= 112k rc= 2 log=[BaseObjects: (exception not convertible to a string)]
limit= 116k rc= 2 log=[BaseObjects: InternalError: out of memory]
limit= 120k rc= 3 log=[Date: null]
limit= 128k rc=10 log=[TypedArrays: InternalError: out of memory]
limit= 140k rc=11 log=[Promise: null]
limit= 256k rc= 0 log=[]        (and 384k, 512k, 1M, 2M, 4M, 8M, 16M, 32M all rc=0)
```

Readings that matter:
- **`JS_NewContextRaw` alone needs more than 92 KiB** of QuickJS-accounted heap; the full intrinsic run
  fits in under 256 KiB. Our live module sets 256 MiB (`JS_SetMemoryLimit`, `quickjs_wrapper.c:306-307`),
  so an OOM in the live process is **not** explainable by that limit — it would need the host's heap to
  refuse ~100 KiB, which is a different claim than "the limit is too small" and would show up as
  rc 1 / step-2-with-OOM text rather than silence.
- The capture path is proven against three distinct exception shapes in one band: a normal
  `InternalError: out of memory`, a **`null` exception value** (QuickJS genuinely had `null` pending),
  and a value that **cannot be converted to a string** (the conversion itself failing, which is what a
  starved heap does). The third one is the case a naive `JS_ToCString`-only implementation would have
  reported as an empty message.
- `OOM_MEM_LIMIT` in the test is therefore **100 KiB** (`c2_diag_test.zig:479`), the middle of the
  step-2 band, so the assertion holds even if the per-step footprint shifts a little under another libc.

**GREEN** after the implementation:

```
Build Summary: 22/25 steps succeeded (1 failed); 293/293 tests passed
```

The single failing step is the **pre-existing** exports-rooted link failure (8 errors: `CreateFileA`,
`WriteFile`, `CloseHandle`, `GetModuleHandleA`, ruling P15) — unchanged in kind and count from §35/§36,
and it is why the PE export names of the new `C2LogInto` are verified by re-parsing the built DLL
(§37.3) rather than by a Zig test.

Host-side suite: `python3 -m pytest scripts/test_c2_harness.py -q` → **37 passed** (was 32): the
`decode_init_rc` range table plus five new tests pinning `fetch_diag_log`'s argument order/buffer size,
its tolerance of a length disagreement, and `report_init_failure`'s three live shapes (inner code,
unmapped code, dead host — the last must **not** dispatch into a gone process). `test_c2_harness.py`'s
module docstring records the one deliberate exception to its "remote control flow is not mocked" rule.

### 37.3 Artifact identity for the next shot

Per §36.1 the hash is not an upload identity check (link is non-deterministic); identity is
git-clean sources + export RVAs. Recorded anyway so the operator can tell "stale copy" from "wrong build":

```
zig build            -> zig-out/bin/stellaris_quickjs.dll  (7,157,760 bytes)
sha256               -> ec5e157dab23670cdd01e194bdae29bf7ae5eadbd7b59c8001c64e9054ca2763
C2Sanity                     0x44C250   C2Init                             0x44C1D0
C2DiagQJS                    0x44C0D0   C2DiagQJSInto                      0x44C030
C2LogInto (NEW)              0x44BFB0   C2QuickJSPointersInto              0x44BF90
C2EvalProbeOnePlusOne        0x44BF00   C2TestQJS                          0x44EC50
```

`c2_task5_init.py` now reparses `C2LogInto` alongside the other two exports it needs, and
`c2_task3_diag.py`'s derived tables carry the new 100..104 outer codes with the current source lines.

### 37.4 What the next live shot can and cannot say

- A nonzero `C2Init` rc now arrives with: which **range** it came from (outer gate vs intrinsic —
  `decode_init_rc`), the shared step text (`rt=… raw_ok diag_rc=N ctx=…`), and, for an intrinsic
  failure, the captured exception message. The §36.4 ambiguity is gone by construction, not by hope.
- The read-back is dispatched **only on the failure path** (`c2_task5_init.py:239-246`), so a successful
  init pays no extra remote call, and a host that died with the rc never gets a second dispatch aimed at
  dead memory (`report_init_failure` reports "host gone before the read-back" instead).
- **Unchanged**: the §36.3 standing hypothesis — QuickJS init inside the injected module is 2-for-2 on
  calls that reach it, 0-for-2 on calls that don't — is still *inference, not measurement*. Nothing in
  this section changes it; it changes only whether the next shot can be read if the host dies again. If
  it dies, the log is now the discriminator: a shot that dies before writing `diag_rc=` is a different
  failure than one that dies after `rc = 2 err=[BaseObjects: …]`.
- Still **not** evidence: whether §35's cross-thread stack-guard defect is real live. Task 6 Steps 5/6
  remain unrun, and they stay meaningless until `C2Init` returns 0 on the box.

**Counts for §37**: `libs/quickjs/quickjs.c` (capture + signature), `src/dll/quickjs/quickjs_wrapper.c`
(shared sequence, 100..104, `C2CopyDiagLog`, `C2DiagNewContextUnderMemoryLimit`),
`src/dll/exports.zig` (`C2LogInto` + the code tables in the docs), `src/dll/quickjs/c2_diag_test.zig`
(4 new tests), `scripts/c2_task5_init.py` (`fetch_diag_log`, `report_init_failure`, wired into `main`),
`scripts/c2_task3_diag.py` (renumbered tables), `scripts/test_c2_harness.py` (5 new tests + docstring).
No live dispatch, no game relaunch.

## 38. The four observation channels settle the read-back race — and `rc = 3` stops proving anything (2026-10-21/22, live + host)

Times below are the game host's local time (UTC+8); the session timestamps in brackets are UTC. This
section is measurement, and each line is verbatim from a shot log on `Windows_Jiaolong`. Where a
sentence is not a measurement it says **inference**.

**Provenance of the copies.** §36/§37's shots ran on `sqjs_c37.dll`/`sqjs_c38.dll`; the two shots that
answered with a witness ran on **`C:/temp/sqjs_c39.dll`, sha256 `35b0fb1008c4af52d42a7bf3d43d2e6674bc3dc5dd38b76bae1d878c75d37fd0`
(7,163,392 bytes)** — the same value from the local `zig-out/bin/stellaris_quickjs.dll`, from
`/tmp/sqjs_c39.dll`, and from `Get-FileHash` on the host, so ruling P12's "which copy answered" is closed
by the MZ check + `C2Sanity == 42` + that sha triple, not by hope. The Python side is **not** the current
tree: at upload time `scripts/c2_harness.py` hashed
`4c668e298a4838fae2f5c4622eb4959b407223b01354d9d7b9857e2d39a6de06` (local and `remote c2_harness.py` both
agree), while the file on disk today hashes `b0524205…` — later edits that touched only the harness and
its test. So the numbers here are what **harness@4c668e29** measured; they are not a claim that today's
uncommitted harness would print them. `c2_task5_init.py` (`2e1a902f…`) and `c2_control_watch.py`
(`09fd0e03…`) are byte-identical to what ran.

### 38.1 The four shapes that lost the race, and how each lost it

Before the poll loop existed, every read-back happened **after** `WaitForSingleObject`, i.e. after the
host was already gone. Four dispatches, four different failures of the same idea:

- **22:40 [14:40] pid 17992, `sqjs_c37.dll`** — the read-back never got a chance:
  `[task5] C2Init rc = 3` / `[task5] diag log   = (host gone before the read-back: game (pid 17992) is no longer alive)`.
  The script still printed `decoded rc   = bucket=intrinsic name=Date`, which §38.5 retracts.
- **22:47 [14:47] pid 20284, `sqjs_c37.dll`** — the buffer was allocated up front
  (`log buffer @ 0xa90000 (allocated BEFORE the dispatch)`) and the post-wait read raised instead of
  returning: `RuntimeError: ReadProcessMemory @0xa90000 size=512 read 0 bytes (ok=0, gle=299)`.
  `gle=299` is `ERROR_PARTIAL_COPY`: the address is valid in a process that is no longer readable as a whole.
- **23:25 [15:25] pid 2264, `sqjs_c38.dll`** — polling, but with the **old five-strikes rule**: reads #1–#5
  all failed with `gle=299` inside roughly the first 10 ms, the loop gave up, and the thread reported
  `exit code = 259 (STILL_ACTIVE — the call had not returned)` → `decoded rc = UNMAPPED — rc=259 is not a
  C2Init code in this build (valid: 0, 1..12, 100..104) — wrong/stale module copy, or the exit code came
  from somewhere else`. 259 is `STILL_ACTIVE`, i.e. the harness's own sentinel, not a step code.
- **23:42 [15:42] pid 17516, `sqjs_c38.dll`** — five-strikes removed, the loop ran to the real end of the
  host: `poll: stop: process handle signalled — the host is gone after 88 failed read(s)` then
  `exit code = 3 (thread had returned)`, with `buffer log = ''` and `on-disk log = ''`.

What the last two lines of every shape have in common: the buffer was never read successfully **after**
the dispatch started, so "no bytes appeared" could not yet be distinguished from "we could not look".

### 38.2 The disk channel is a permanent negative, and why

`[task5] diag file = C:/temp/c2_diag_<pid>.log (absent before dispatch)` in every shot, and
`[task5] on-disk log = ''` in every shot. The script deletes any stale copy before dispatching
(`c2_task5_init.py:389`), so the empty read means the file was **never created**, not truncated. The cause
is structural: `c2_diag_write_file` is called from exactly one place, `quickjs_wrapper.c:406`, which sits
**after** the `finish:` label at `:404`; all failure branches reach it via `goto finish` (`:364`, `:367`,
`:374`, `:381`, `:391`). A remote thread that is terminated mid-sequence therefore never reaches the only
write. **Inference (mechanical, from the source layout, not from a measurement):** the disk channel cannot
discriminate a dying call; it only ever reports a call that returned.

### 38.3 Priming — the page is provably readable before anyone dies

`poll: primed 512 bytes @0xa30000: read back 512 bytes, all zero` (same line shape at `@0xa00000`,
`@0xa70000`, `@0xad0000`, `@0xaf0000`). The `remote_alloc` page is written by us and read back by us
**before** the dispatch, so its readability is not in question while the host is alive; when the same
address later fails with `gle=299` the target is the process, not the page. This is what turns
`buffer log = ''` in §38.4 from "we couldn't look" into "the callee never wrote".

### 38.4 The static witness: two shots where the only channel that worked was the module's own log

The witness is `g_diag_log` itself, addressed from a **truncated** return of `C2DiagGetLogAddr`
(ruling P4's one permitted exception): `C2DiagGetLogAddr — truncated 0xd01456f0 → g_diag_log rva 0x6a56f0
@ 0x7ffcd01456f0`. The address is *believed* because of what appeared at it, not because it was verified
in advance — an empty static reads zero whether or not the address is right, so pre-dispatch there is no
check. The shape of the arriving text (`enter heap_ok alloc_ok free_ok new_rt `, five known `DLOG` tags in
their source order) is the verification.

- **23:57 [15:57] pid 4248, `sqjs_c38.dll`, rva `0x6a4170`** — the split that named the problem: the static
  was readable from the first poll (`witness g_diag_log: readable at 0.1ms, text ''`, `oks=3000 fails=81`)
  while the buffer was unreadable throughout (`first_read_ms=0.085`, then
  `unreadable at 6917.9ms`, `the host is gone after 81 failed read(s) at 7105.5ms`). Same process, same
  moment, one channel readable and one not — so the buffer's silence was about the *buffer*, and the
  witness reads `''` because the sequence had not written yet at 0.1 ms.
- **00:02 [16:02] pid 21032, `sqjs_c39.dll`** — `witness g_diag_log: oks=3011 fails=81 text='enter heap_ok alloc_ok free_ok new_rt '`,
  `readable at 0.1ms`, `unreadable at 7018.9ms`, `exit code = 3 (thread had returned); process exit code =
  0x3, thread returned while process alive = False`, `buffer log = ''`, `on-disk log = ''`.
- **00:18 [16:18] pid 7820, `sqjs_c39.dll`, base `0x7ffccfaa0000`** — the same witness text, caught earlier:
  `readable at 107.1ms`, `unreadable at 7931.7ms`, `primed=512 reads=1792 failures=129
  first_read_ms=107.11959999753162 first_failure_ms=7931.668299999728`, `oks=1663 fails=129`,
  `the host is gone after 129 failed read(s) at 8263.0ms`, and again `buffer log = ''` / `on-disk log = ''`.

The disagreement **is** the finding: the callee's copy into our buffer never appeared, while the module's
own static carried the sequence up to and including `new_rt `. A `DLOG` into a caller-owned buffer that
never arrives, next to the same tags landing in the module's own memory, is what §39's memory series then
had to explain.

### 38.5 §36.4 retracted, plainly

`rc = 3` is **not** proven to be the Date intrinsic. Both c39 shots printed, verbatim:

```
[task5] poll report      = thread exit code=3 process exit code=0x3 thread_returned_while_alive=False
[task5] poll report      = WARNING: the thread never returned while the process was alive, so rc=3 is not proven to be a step code — a terminated thread reports the PROCESS exit code (here 0x3); treat decode_init_rc's answer as unconfirmed
```

A thread that never returned while its process was alive reports the **process** exit code, so 3 is a
property of how the process ended, and `decode_init_rc`'s `bucket=intrinsic name=Date` is decoration on a
number that was never a step code. Every earlier section that read an `rc` as a step (including §36.4) is
to be read through this caveat. The disambiguator that actually worked is the witness text in §38.4, which
needs no integer interpretation at all.

**Counts for §38**: four dispatch shapes (pids 17992, 20284, 2264, 17516) on `sqjs_c37`/`sqjs_c38`, three
witness shots (4248 on c38; 21032, 7820 on c39), one no-dispatch control (§39.3), 0 new exports, 0 new Zig
`extern fn`, 1 retraction (§36.4). Harness@4c668e29, DLL@35b0fb10.

## 39. The memory series rules out an allocation storm — the host releases its own commit before it goes (2026-10-21/22, live)

Sampler: `psutil 7.2.2 over pid 7820, every 250ms`, running **inside** the poll loop of
`dispatch_watching_buffer` (ruling: a monitoring channel may never cost the exit code, so an exception
from it is recorded once and the channel is dropped). `vms`/`private` are the process's commit, `rss` its
resident set; all three are read from outside the target, so nothing here depends on our module answering.

### 39.1 pid 7820 — 33 samples across the death, condensed

```
[task5] mem @      0.1ms = rss=3209316K vms=8159644K private=8159644K
[task5] mem @    251.2ms = rss=3208692K vms=8158532K private=8158532K
[task5] mem @   4773.7ms = rss=3208236K vms=8158532K private=8158532K
[task5] mem @   5024.1ms = rss=3208236K vms=8158532K private=8158516K
[task5] mem @   5275.1ms = rss=3179904K vms=8158332K private=8158332K
[task5] mem @   5525.7ms = rss=3117120K vms=7574180K private=7574180K
[task5] mem @   6528.0ms = rss=3116976K vms=6085216K private=6085216K
[task5] mem @   7281.6ms = rss=3116616K vms=4769204K private=4769204K
[task5] mem @   7785.2ms = rss=3110820K vms=3788488K private=3788488K
[task5] mem @   8035.6ms = rss=1981468K vms=2068988K private=NA
[task5] mem growth       = vms KiB: first=8159644 last=2068988 delta=-6090656 samples=33 window=8035.6ms
[task5] mem growth       = rss KiB: first=3209316 last=1981468 delta=-1227848 samples=33 window=8035.6ms
[task5] mem growth       = private KiB: first=8159644 last=3788488 delta=-4371156 samples=32 window=7785.2ms
```

The shape, stated exactly: for the first ~5 s the commit is **flat** — `vms` constant at `8,158,532K`
across 20 consecutive samples, `rss` drifting down by 1,080 KiB in total. Then `vms` falls monotonically
(`8,158,332 → 7,574,180 → 6,085,216 → 4,769,204 → 3,788,488 → 2,068,988K`) and `rss` follows
(`3,117,120 → 1,981,468K`). `private` goes `NA` on the final sample, i.e. the counter itself became
unreadable before the process did. Against §38.4's poll clock on the same pid: the witness was readable at
107.1 ms, the reads died at 7,931.7 ms — which lands between the `7,785.2 ms` (still readable, `vms`
3.79 GB) and `8,035.6 ms` samples — and the handle signalled at 8,263.0 ms.

### 39.2 pid 7812 — the same shape, independently

`StartTime 2026/10/22 0:24:21`, shot at 00:27 [16:27], same `sqjs_c39.dll`:

```
[task5] mem @      0.1ms = rss=3219328K vms=8172392K private=8172392K
[task5] mem @   4781.4ms = rss=3218724K vms=8171300K private=8171300K
[task5] mem @   5535.5ms = rss=3125536K vms=7588372K private=7555552K
[task5] mem @   7544.9ms = rss=3123012K vms=4022984K private=4003220K
[task5] mem @   8048.9ms = rss=154628K vms=129764K private=NA
[task5] mem growth       = vms KiB: first=8172392 last=129764 delta=-8042628 samples=33 window=8048.8ms
[task5] mem growth       = rss KiB: first=3219328 last=154628 delta=-3064700 samples=33 window=8048.8ms
```

`vms 8,171,300K → 129,764K` and `rss → 154,628K`, with the witness again readable (`readable at 85.5ms`,
`oks=1959 fails=97 text='enter heap_ok alloc_ok free_ok new_rt '`) and the reads dying at 7,820.6 ms
against a handle that signalled at 8,071.4 ms. Two processes, two pid values, one shape.

### 39.3 The no-dispatch control, verbatim

`scripts/c2_control_watch.py` at 00:26 [16:26] — the same sampler, the same poll loop, **zero bytes of our
module executed in the target** and no `C2Init`/`C2DiagQJSInto` dispatch at all:

```
[control] mem @   6121.2ms = rss=3220372K vms=8173524K private=8173524K
[control] mem @  19708.2ms = rss=3219768K vms=8173324K private=8173324K
[control] growth         = vms KiB: first=8173524 last=8173324 delta=-200 samples=59 window=19708.2ms
[control] growth         = rss KiB: first=3220216 last=3219768 delta=-448 samples=59 window=19708.2ms
[control] watched 20000ms, samples=59, init dispatch made=none, host alive=True
```

The control is what makes §39.1's baseline meaningful: **8.17 GB of commit is this game's steady state**,
unchanged to within 200 KiB over 19.7 s while the host stays alive. The dying shots start from the same
number and end near zero.

### 39.4 What this excludes, and what it only suggests

- **Excluded — an allocation storm inside `JS_NewRuntime2`.** No sample on either dying shot exceeds the
  pre-dispatch commit; `vms` is flat for five seconds and then falls. A call that OOMs or churns gigabytes
  would have to put an upward excursion somewhere in a 250 ms-resolution series that spans the whole
  death, and there is none. §33's `heap_free` use-after-free → "QuickJS OOM" reading is therefore not what
  these two shots show, and the earlier `rc = 3`-based framing is already retracted (§38.5).
- **Excluded — "the host was killed by our read-back".** The control runs the identical loop, reads the
  identical counters, and the host answers `alive=True` after 20 s with 59 samples.
- **Inference, not measurement — orderly teardown rather than an unhandled exception.** A process that
  releases ~8 GB of commit progressively over ~2.5 s, with `rss` following and the counters going `NA` only
  at the last sample, looks like a shutdown path unwinding rather than a fault that terminates immediately.
  Nothing observed here proves that: no stack, no Win32 error, no `WerFault` record was captured for these
  pids, and the alternative (a crash path that happens to run the same destructors) is not excluded by a
  memory series.
- **Still open.** Both dying shots stop at the same witness tag (`new_rt `, the tag that precedes
  `JS_NewRuntime2`), and the control that would separate *that call* from *a long remote thread* is
  `scripts/c2_control_sleep.py` — written, tested offline, not yet fired. See §40 for its verdict, which
  does not exist yet at the time of writing.

### 39.5 The pre-context tags are the first live result that reads as a location, not an integer

The two §39 shots each caught the static witness holding exactly

```
text='enter heap_ok alloc_ok free_ok new_rt '
```

(`oks=1663 fails=129` / `oks=3011 fails=81`; both shots then report `witness … unreadable` and
`process exit code = 0x3`). The tag before `JS_NewRuntime2` — `new_rt ` — is the **last one present in
both**. That is the whole finding: every step up to and including the `HeapFree` is proven to have run,
the runtime-creation call is the first whose completion is never marked, and the sequence is bounded at
a named operation rather than a bare `rc`.

Before this, the only live signal the C2Init path ever produced was the integer `rc = 3` (or `0x3`), which
§38.5 retracts as uninterpretable — the outer gates and the intrinsic steps shared the numbers, and
`C2TestQuickJS` originally wrote no log at all. These tags are the **first** live result that did not
depend on decoding a number: `native` order is now pinned by
`src/dll/quickjs/c2_diag_test.zig`'s `the shared sequence tags every step before the runtime exists`, which
walks the 12 markers (`enter `, `heap_ok `, `alloc_ok `, `free_ok `, `new_rt `, `rt=`, `opaque_ok `,
`limits_ok `, `new_raw `, `raw_ok `, `new_diag `, `diag_rc=0`) and rejects any offset `<=` its predecessor
with `error.StepMarkersOutOfOrder`. Dropping a tag from `c2_diag_sequence` turns that test red, so the live
disambiguator cannot silently rot.

What it does **not** buy: the tags bound the failure to "`JS_NewRuntime2` was entered and never returned",
not to "`JS_NewRuntime2` itself crashed" — that distinction is exactly the `Sleep(8000)` control in §40,
still pending.

**Counts for §39**: 2 dispatch shots with full series (7820, 7812; 33 samples each), 1 no-dispatch control
(59 samples), 0 new code paths measured, 1 hypothesis retired (allocation storm), 1 hypothesis left open
(teardown vs crash) and 1 discriminator pending (§40).

## 40. A kernel32-only long remote thread leaves the host alive — the death is specific to our sequence (2026-10-22, live)

This is the last discriminator between "the C2 init sequence crashes the game" and "any long remote thread
crashes the game." `scripts/c2_control_sleep.py` dispatches `kernel32!Sleep` — no QuickJS symbol, no engine
symbol — into pid 13076 (`sqjs_c39.dll` base `0x7ffbed580000`, `C2Sanity == 42` already answered), twice:
a 1 s calibration to prove the resolved address is a timer, then the measured 8 s dispatch.
`kernel32!Sleep` resolved `@ 0x7ffcb3798670`; witness `g_diag_log @ 0x7ffbedc256f0`.

### 40.1 The calibration gate cleared — the address really is a timer

```
[sleep] calib poll: exit code = 0 (thread had returned); process exit code = 0x103, thread returned while process alive = True
[sleep] calibration    = Sleep(1000) took 1002.8ms, rc=0
[sleep] calibration plausible, game alive — the address is a timer
```

The `plausible_sleep_ms` ±50 % band accepted 1002.8 ms, so the 8 s result below is about `Sleep`, not about
a misresolved symbol. This is the branch that, had it fired, would have stopped the shot (`AssertionError:
the resolved address did not behave like Sleep(1000)`) — it did not fire.

### 40.2 The 8 s dispatch, verbatim

```
[sleep] poll: primed 512 bytes @0xb00000: read back 512 bytes, all zero
[sleep] poll: witness g_diag_log: readable at 66.4ms, text ''
[sleep] poll: stop: thread finished, 0 bytes in view at 8002.5ms
[sleep] poll: exit code = 0 (thread had returned); process exit code = 0x103, thread returned while process alive = True
[sleep] Sleep(8000) rc=0 buffer='' wall=8002.7ms
[sleep] poll report      = primed=512 reads=2369 failures=0 first_read_ms=66.36100000105216 first_failure_ms=None
[sleep] poll report      = thread exit code=0 process exit code=0x103 thread_returned_while_alive=True
[sleep] poll report      = witness g_diag_log: oks=2369 fails=0 text=''
[sleep] mem growth       = private KiB: first=8146544 last=8146628 delta=+84 samples=32 window=7790.2ms
[sleep] mem growth       = rss KiB: first=3207060 last=3207188 delta=+128 samples=32 window=7790.2ms
[sleep] mem growth       = vms KiB: first=8146544 last=8146628 delta=+84 samples=32 window=7790.2ms
[sleep] VERDICT: a remote thread that executes only kernel32!Sleep for 8000ms left the host alive=True, thread_returned_while_alive=True
```

`process exit code = 0x103` is `STILL_ACTIVE`: the process was alive at the instant the thread handle
signalled. `reads=2369 failures=0` — the buffer and the static stayed readable for the full 8 s, the direct
contrast with §38, where the dying host's reads failed at ~7 s. The witness `text=''` is the control's own
design confirmed: the `Sleep` path never enters `c2_diag_sequence`, so no tags were written.

### 40.3 What this settles

- **A long remote thread is NOT sufficient to kill the game.** The reading that would have made every
  §36-style conclusion about the *thread* rather than QuickJS is dead: this thread ran 8 s of nothing and
  the host is still here — re-checked after the shot, pid 13076 alive, `StartTime` unchanged `11:21:44`.
- **The death is specific to our init sequence.** Combined with §39.5 (both §39 shots stop at the `new_rt `
  tag, the one immediately before `JS_NewRuntime2`), the next plan's target is `JS_NewRuntime2` itself, not
  "a remote thread exists."
- **First shot where an `rc` is the callee's own return value.** `thread exit code=0` here is `Sleep`
  finishing normally with the host demonstrably up, not a code read off a process already going away (the
  §36/§39 `0x3` case). The exit code is meaningful for the first time precisely because the process is
  still alive to produce it.

### 40.4 The engine did not notice us

Checked for this live pid after the dispatch: `AppData/Local/CrashDumps` has **no** `stellaris.exe` entry;
`Documents/Paradox Interactive/Stellaris/logs/error.log` stops at `[11:22:18]` (event-sound warnings,
unrelated to us) and `system.log` at `[11:21:47] "Done creating device."` — minutes before the dispatch,
nothing around it. The host's own logs record neither a foreign thread running `Sleep` inside it nor a
crash. This is the same absence §39 noted for the dead shots, here on a host that survived.

**Counts for §40**: 1 dispatch process (pid 13076), 1 calibration + 1 measured remote thread = 2 dispatches,
0 QuickJS symbols executed, host alive after both, 1 reading retired ("a long remote thread is sufficient"),
1 target named for the next plan (`JS_NewRuntime2`), 0 new exports, 0 new Zig files.

## 41. `JS_NewRuntime2` reaches our allocator three times, then the host goes unreadable — the death is inside the call, after the 3rd `heap_malloc` (2026-10-22, live)

§40 put the target on `JS_NewRuntime2` itself. This shot asks the one question §40 could not: **does the
death happen before `JS_NewRuntime2` ever calls back into our `heap_mf`, or after it starts?** The three
allocator callbacks (`heap_malloc`/`heap_free`/`heap_realloc`) now append a rate-limited tag (`M`/`F`/`R`,
cap 8) into the DLL's own `g_diag_log` — the same static the live poller reads (§38), so the tags are
captured incrementally even on a shot that dies. Full command + witness in `evidence/logs/c2_mf_instrument_4_4_4.log`.

### 41.1 The offline positive control is what makes the live read mean anything

On the Linux host the identical `c2_diag_sequence` runs to completion (`JS_NewRuntime2` returns), so the
allocator tags land without bound until the cap:

```
enter heap_ok alloc_ok free_ok new_rt MMMMMMMMrt=0x31b2648 opaque_ok limits_ok new_raw RFraw_ok new_diag RFFRFRFdiag_rc=0
```

Alive, `new_rt ` is followed by 8 `M` and then `rt=`. Without this, a live log stopping at `new_rt ` could
only mean "the tagging never compiled in." It is a real observation now (`c2_diag_test.zig` asserts it).

### 41.2 The live shot, verbatim

```
[task5] poll: witness g_diag_log: readable at 13.1ms, text 'enter heap_ok alloc_ok free_ok new_rt MMM'
[task5] poll: witness g_diag_log: unreadable at 1851.7ms — ReadProcessMemory @0x7ffbed5157f0 ... (ok=0, gle=299)
[task5] poll: stop: process handle signalled — the host is gone after 70 failed read(s) at 2018.7ms
[task5] poll report = witness g_diag_log: oks=731 fails=70 text='enter heap_ok alloc_ok free_ok new_rt MMM'
```

`new_rt ` then **three `M`, no `rt=`**. Reads die at 1851.7 ms; the process handle signalled at 2018.7 ms.
Memory falls monotonically across the window (vms 8,147,640K → 45,872K, `private` → NA at the last sample) —
the same self-release shape as §39, no upward excursion.

### 41.3 What this settles, and what it deliberately does not

- **§40's reading (a) is excluded.** `JS_NewRuntime2` did NOT die in its prologue before the first
  allocation: our `heap_malloc` was entered and returned **three times** (a live runtime does ≥8 before
  returning — §41.1). The allocator is demonstrably wired and working; §33's "our allocator is broken"
  family stays dead (and §38.5/§39 already retired it).
- **The target reproduces inside the call.** It is NOT reading (c) — `rt=` never appeared — so the death is
  still in `JS_NewRuntime2`, now narrowed to *after the 3rd mf allocation, before the call returns*.
- **"Stopped after 3 M" is a position, not a cause.** We do not know what in `JS_NewRuntime2`'s init past
  the third allocation faults in the injected environment, nor whether `3` is stable across shots (this is
  one shot; §40's budget rule bars a reflexive re-fire). The 3-allocation prefix is the new floor for the
  next probe.
- **`rc = 3` is still not a step code.** The thread never returned while the process was alive (§38.5
  retraction holds); `decoded rc = bucket=intrinsic name=Date` is the process exit code, not evidence of
  the Date intrinsic. The on-disk `C:/temp/c2_diag_13076.log` produced nothing (write only at `finish:`,
  never reached) and the caller buffer log was `''` — the static witness is the only channel that carried
  text, exactly as §38 designed.
- **C2 remains blocked.** This did not make `JS_NewRuntime2` survive; it moved the black box from "the whole
  call" to "the call's interior, past the third allocation."

**Counts for §41**: 1 dispatch (pid 13076, killed — authorized), 1 offline positive control (Linux, full
return), 3 `heap_malloc` entries reached before death (vs ≥8 alive), 1 §40 reading excluded (prologue
death), 1 target confirmed inside `JS_NewRuntime2` (not past `rt=`), 0 new capability (tags are read-only
`snprintf` into the DLL's own static), 0 new exports, 1 new Zig test block (P15 305→306).

## 42. All three allocations RETURN — the death is engine-side, after the 3rd `heap_malloc` returns and before a 4th is entered (2026-10-22, live)

§41 recorded `new_rt MMM` from an entry-only `M` tag, so it could NOT separate two cases that §36 framed as
the two competing hypotheses: **died inside the 3rd `HeapAlloc`** (heap/environment side — the allocator or
`GetProcessHeap` failed to return under the injected thread) vs **died in QuickJS's own code between two
allocations** (engine side). This shot closes that seam. `heap_malloc` now writes a *matched pair*: `M` on
entry, then `m` if `HeapAlloc` returned a block or `!` if it returned NULL. A `M` with nothing after it — a
**dangling `M`** — is the positive signature of "the allocation call never returned." Full command + witness
in `evidence/logs/c2_mf_threephase_4_4_4.log`; the tooling change is commit `c90a8e2`, the injected DLL is
`C:/temp/sqjs_c42.dll` (sha256 `863917f2579ae8c4472be13baeca4bed64dc2ccffc7b620fdb2b016134a86617`, verified
byte-identical on the box before the dispatch).

### 42.1 The offline positive control is what licenses the "dangling M" reading

The new `c2_diag_test.zig` block "a completed heap_malloc always closes its M marker" runs the whole
sequence on the Linux host (where `JS_NewRuntime2` returns) and asserts the structural invariant that
**every `M` between `new_rt ` and `rt=` is immediately followed by `m` or `!`** — no `M` dangles on a run
that completes. Without that, a live dangling `M` could just mean the close-tag never compiled in; with it,
a dangling `M` is a real observation. (P15 306→307; the +1 is this block, the step count is unchanged.)

### 42.2 The live shot, verbatim

```
[task5] poll: witness g_diag_log: readable at 72.4ms, text 'enter heap_ok alloc_ok free_ok new_rt MmMmMm'
[task5] poll: witness g_diag_log: unreadable at 6947.1ms — ReadProcessMemory @0x7ffbeeb457f0 size=512 read 0 bytes (ok=0, gle=299)
[task5] poll: stop: process handle signalled — the host is gone after 70 failed read(s) at 7135.8ms
[task5] poll report = witness g_diag_log: oks=1892 fails=70 text='enter heap_ok alloc_ok free_ok new_rt MmMmMm'
```

`new_rt ` then **`MmMmMm`** — three `heap_malloc` entries, **each closed by a lowercase `m`**, i.e. all three
`HeapAlloc` calls returned a block. No dangling `M`. The static did not advance past `MmMmMm` across 1892
successful polls spanning 72.4 ms → 6947.1 ms; reads die at 6947.1 ms, the handle signalled at 7135.8 ms.
Memory is **flat** at ~3.14 GB rss / ~8.19 GB private for samples 0.1 ms → 4770 ms, then falls (private
8.19 GB → 4.0 GB, rss collapses at 7024 ms) — the §39 self-release-at-teardown shape again, no upward
excursion. `buffer log` and the on-disk `C:/temp/c2_diag_8288.log` are both `''` (the file is written only at
`finish:`, never reached), so as designed the static is the only channel that carried text.

### 42.3 What this settles, and what it deliberately does not

- **§41's fork resolves to the engine side.** All three allocations *completed*: `HeapAlloc` handed back a
  block each time and returned cleanly through our accounting. A heap/environment-side death (our allocator
  or `GetProcessHeap` failing under the injected remote thread) is **excluded** — it would show a dangling
  `M`, and there is none. The death is in QuickJS's own code **after** the 3rd allocation returned and
  **before** it entered a 4th.
- **§39's "no allocation storm" is re-confirmed independently.** ~4.8 s of flat memory then teardown release;
  nothing in `JS_NewRuntime2`'s first 3 allocations grows the working set.
- **`rc = 3` is still not a step code.** The thread never returned while the process was alive (§38.5's
  retraction holds — the harness prints the same WARNING); `decoded rc = bucket=intrinsic name=Date` is the
  process exit code `0x3`, not evidence of the Date intrinsic.
- **The next probe crosses a capability line, and this shot cannot.** The window that matters now is between
  the 3rd allocation returning and the 4th being entered — and it is ~6.9 s of *zero allocation activity*,
  entirely inside QuickJS's own `JS_NewRuntime2` code. Our allocator only observes allocation boundaries, so
  read-only instrumentation has reached its ceiling: seeing what runs in that gap requires hooking QuickJS's
  own code, which is a capability escalation (升级授权), not something the current read-only level grants.
  A single shot also cannot establish whether "3" is stable across shots (§40's budget rule bars a reflexive
  re-fire).
- **C2 remains blocked.** The host still dies in `JS_NewRuntime2`; this narrowed *where within the call* —
  from §41's "past the 3rd allocation, before return" to "past the 3rd allocation returning intact, before
  any 4th." The suspect moved off our allocator and onto QuickJS's post-allocation code path.

**Counts for §42**: 1 dispatch (pid 8288, killed — authorized), 1 offline positive control (Linux, no
dangling `M`), 3 `heap_malloc` calls all returned (`MmMmMm`, no dangling `M`), 1 §36 branch excluded
(heap/environment-side death), 1 §39 finding re-confirmed (no allocation storm), 1 new ceiling named (the
6.9 s no-allocation window is inside QuickJS code → next probe needs 升级授权), 0 new capability (the third
phase is read-only writes into the DLL's own static), 0 new exports, 1 new Zig test block (P15 306→307).

## 43. Offline: the §42 window is a trivial straight-line span — the stack-guard suspect is ruled out, and the next observation is thread-state, not a QuickJS hook (2026-10-22, offline, no dispatch)

§42 narrowed the live death to "after the 3rd `heap_malloc` returned intact, before any 4th" and named the
ceiling ("that gap is QuickJS's own code; reading it needs 升级授权"). This section is the **offline** half of
that gap: it costs no machine time and no capability, and it sharpens §42 in two ways — it pins the gap to a
specific straight-line span inside `JS_InitAtoms`, and it eliminates the prime suspect §42's framing left
standing (the cross-thread stack guard). It also re-frames what the next probe must be.

**Method.** `scripts/scratch/2026-10_newrt_allocmap/allocmap.c` — a standalone Linux driver linking the SAME
vendored `quickjs.c` the shipped DLL builds (build.zig:9), with a **verbatim port of `quickjs_wrapper.c`'s
`heap_mf`** (same `AllocHeader` accounting, same `js_malloc_usable_size` = recorded size, same `MF_TAG_CAP=8`
and `M/m/!/F/R` tagging), and `backtrace()` on every callback resolved with `addr2line` to a `quickjs.c` line.
The faithful-mirror check is exact: the offline run completes `JS_NewRuntime2` with `g_diag_log ==`
`MmMmMmMmMmMmMmMm` — **byte-identical to §42's Linux positive control** — and emits **zero `F` and zero `R`
during `JS_NewRuntime2`** (every `F` is in `JS_FreeRuntime` afterwards), which is exactly the shape of the live
`MmMmMm` witness (no `F`/`R`). So the offline stream and the live stream are the same object truncated at
different points; the comparison below is sound.

**The ordered allocation map** (`#` = `mf.js_malloc` call index, size, `quickjs.c` site):

| # | bytes | path | site |
|---|---|---|---|
| 0 | 1440 | direct | `JS_NewRuntime2:2076` — the `JSRuntime` itself |
| 1 | 2056 | `js_mallocz_rt`→`js_malloc_large` | `JS_ResizeAtomHash:3146` (the 512-bucket `atom_hash`) |
| 2 | 4072 | `js_malloc_rt`→`js_alloc_string_rt`→`js_malloc_new_arena` | `__JS_NewAtomInit:3430` inside `JS_InitAtoms`' loop — **1st predefined-atom name string** |
| 3 | 5696 | `js_realloc_rt`→`__js_realloc:1640`→`js_malloc_large` | `__JS_NewAtom:3330` — **`atom_array` 711-entry pre-grow** |
| 4–7 | ~4072 | `js_alloc_string_rt`→`js_malloc_new_arena` | more predefined-atom name strings (`JS_InitAtoms:3191`) |
| 8 | 2528 | `js_realloc_rt`→`js_malloc_large` | `JS_NewClass1:3978` via `init_class_range:2035` (`class_array`) |
| 9 | 4072 | `js_mallocz_rt` | `init_shape_hash` reached from `JS_NewRuntime2:2112` |

The live witness reached `#0, #1, #2` (all three closed with `m`) and **never emitted the `M` for `#3`**. So
the §42 "post-3rd-allocation QuickJS window" is now: **inside the FIRST `__JS_NewAtomInit` call, between the
name-string allocation (`:3430`, malloc #2) and the `atom_array` grow (`:3330`, malloc #3)** — the span
`memcpy(p->u.str8, str, len)` + null-terminate + `hash_string` + one `atom_hash[h1]` load + `__JS_NewAtom`
entry. That is straight-line, bounded, trivial code operating on a handful of ASCII bytes.

### 43.1 Two QuickJS-internal hypotheses this eliminates

- **The cross-thread stack guard is NOT this death.** `c2_diag_test.zig:359-440` documents
  `CONFIG_STACK_CHECK`: `JS_NewRuntime2` captures `rt->stack_top` at `:2116` via `JS_UpdateStackTop`, and a
  different evaluating thread's `sp` is then checked against the stale `stack_limit`. But `:2116` runs
  **after** `JS_InitAtoms` (`:2096`); at the stall position (`:3430`→`:3330` of the first atom)
  `rt->stack_top`/`stack_limit` are not set yet, and `js_check_stack_overflow` is never invoked on the
  atom-init path. The guard remains a real hazard for the later `C2EvalProbe` (Task 6) — it just cannot
  explain a hang inside `JS_NewRuntime2`. This closes the one named suspect §42 left open.
- **A corrupted hash-bucket / free-index chain cannot loop here.** At the stall position `atom_hash` was just
  zeroed by `js_mallocz_rt` (#1), so `__JS_NewAtom`'s bucket walk (`:3295 while (i != 0)`) runs **0**
  iterations, and the `atom_free_index` chain (built at `:3354`) does not exist until after malloc #3. There
  is no list for it to walk off the end of yet.

### 43.2 What that leaves, and the actual next observation

§42 read "the gap is inside QuickJS code" as "the next probe must hook QuickJS." The offline read refines it:
the QuickJS **instructions** in that gap are trivial and finite, so a ~6.9 s stall there is **not explained by
QuickJS's control flow**. The live-vs-offline divergence at this exact point must come from something the
source cannot show — either (a) the injected remote thread is not permitted to *execute* those instructions
(host scheduling, a foreign-thread suspension, or `stellaris.exe`'s own SEH repeatedly re-dispatching on this
thread), or (b) an environment property of the block our `HeapAlloc` returned at #2. (b) only bites if a
read/write there faults and the host turns the fault into a retry rather than a kill — but §42 already showed
the three allocations' memory was used to completion (`m` after each), and a faulting span would AV-kill in
sub-ms, not stay readable for 6.9 s. That tilts toward (a).

**The discriminator is NOT a QuickJS code hook — it is sampling the remote thread's STATE across the death
window.** §39 sampled the process's memory counters; nothing so far has sampled the thread's instruction
pointer or CPU time. A handful of `GetThreadContext(hRemoteThread)` polls (its `Rip`) plus
`GetProcessTimes`/`GetThreadTimes` deltas, taken while the init dispatch runs, separate the two:
if `Rip` advances around `js_alloc_string_rt ↔ __JS_NewAtom` and CPU time burns → a genuine QuickJS-side stall,
and *then* a QuickJS code hook is the warranted 升级授权. If `Rip` parks in a wait outside our DLL, or CPU time
does not advance, or the thread is already terminated while the process lives → the stall is **host-driven**,
C2 is blocked by the environment rather than by QuickJS, and that is a different roadmap consequence (and no
QuickJS hook would help).

**Boundary and honesty.** This is offline source-reading + a faithful offline replay; it proves nothing about
what the live thread *does* during those 6.9 s — only that no QuickJS instruction sequence there can take that
long, which relocates the question from "what is QuickJS computing" to "is the thread computing at all." C2
stays blocked. Read-only DLOG tagging is confirmed at its ceiling (§42's conclusion holds), but the escalation
it pointed at ("hook QuickJS") is **premature**: the cheaper thread-state sample must run first, and that is a
new observation *kind* (thread context / timing), beyond the `ReadProcessMemory`-only level used so far, so it
needs 点名 before any live shot.

**Counts for §43**: 0 dispatch (pure offline), 1 scratch tool (`scripts/scratch/2026-10_newrt_allocmap`,
basename kept, one-time probe), `JS_NewRuntime2` mallocs #0–#9 mapped to `quickjs.c` lines, 1 offline-stream ==
§42-control faithfulness check (`MmMmMmMmMmMmMmMm`, 0 `F`/0 `R` in-create), 1 §42 window narrowed from
"post-3rd-alloc QuickJS code" to "first `__JS_NewAtomInit` iteration, `:3430`→`:3330`", 2 hypotheses ruled out
(cross-thread stack guard; corrupt hash/free-chain walk), 1 next observation named (live thread `Rip`+CPU-time
sample — read-only but a new kind, needs 点名) that pre-empts the premature "hook QuickJS" escalation, 0 code
change to the shipped DLL, 0 new Zig test, 0 new export.


## 44. The authorized thread-state shot: no Rip was ever available because the process was already terminating (2026-10-22, live, 单发射)

Transcript: `evidence/logs/c2_threadstate_4_4_4.log`. Authorization, in the human partner's words:
"授权开线程状态观测这一枪(单发射,只读 GetThreadContext/GetProcessTimes,不 hook、不改内存)". §43 named
this observation and said it needed 点名 before a live shot; the nod came, one dispatch was spent, and the
单发射 is now consumed — any further killed init dispatch needs a fresh 点名.

The DLL bytes did not change: sha256 `863917f2579ae8c4472be13baeca4bed64dc2ccffc7b620fdb2b016134a86617`,
§42's artifact, redeployed under a new name (`C:\temp\sqjs_s43.dll`, ruling P12) with local == remote
verified. Everything new is in the driver (`scripts/c2_harness.py`: `dispatch_watching_buffer(...,
thread_probe=)` and `capture_thread_state`), which per tick reads `GetThreadTimes` + `GetProcessTimes`,
then `SuspendThread` → `GetThreadContext` → `ResumeThread` (resume only if suspend succeeded; nothing
raises; no writes of any kind).

### 44.1 The witness is §42's, character for character

    witness g_diag_log: oks=133 fails=73 text='enter heap_ok alloc_ok free_ok new_rt MmMmMm'
    readable at 80.4 ms, unreadable at 2016.3 ms (gle=299), handle signalled at 2232.3 ms
    rc = 3, process exit code = 0x3, thread_returned_while_alive=False, WARNING (rc not a step code)
    buffer log = '' , on-disk log = ''

Three allocations, each entered and each returned a block, no dangling `M`, no `rt=`. The allocation
channel is saturated: it cannot say anything new, which is exactly why §43 asked for a different channel.

### 44.2 What the thread channel returned

22 captures, **0** with a readable `Rip`, every one carrying `err=SuspendThread gle=5` — including the
first, at 80.3 ms, i.e. the same tick in which the witness static first became readable. The two
counter columns behaved differently and are the actual result:

  - `pr_user_us` = 42,218,750 in **all 22 samples**. The process accrued zero user CPU for 2.1 s.
  - `th_user_us` = 0 in all 22, while `th_kernel_us` moved 0 → 15,625 → 125,000 → 218,750 µs. All the
    CPU movement in the whole process belongs to our remote thread, and all of it is kernel time.

Memory over the same window releases monotonically from the first sample: private 8,179,876 K → 2,156 K,
rss 3,210,344 K → 18,812 K, with no upward excursion anywhere. §39's teardown shape, from t = 0.

The driver's own verdict line was `VERDICT inconclusive: 0 of 22 captures yielded a readable Rip`, and
that is correct as a statement about the *design question* ("running vs blocked"). The series still
answers a question, just not that one.

### 44.3 Two controls, both zero-cost, plus a rights matrix

`SuspendThread gle=5` and "frozen user CPU" are each ambiguous: instrument failure or real stop. Both
were separated with observations that involve **no DLL, no injection, no dispatch**, against a freshly
launched untouched game (pid 3160):

  - `scripts/c2_control_cpuwatch.py` — 80 samples over 20,119.7 ms: user advanced **12,828,125 µs**,
    system 375,000 µs, 120 threads. VERDICT: an untouched game does accrue user CPU, so §44's frozen
    `pr_user_us` is a real stop, not idleness and not a dead counter.
  - `scripts/c2_control_suspendcap.py` — the same `OpenThread` + `capture_thread_state` path applied to
    12 of the game's own threads: **readable_rip=12/12, suspend_denied_gle5=0/12, openthread_failed=0/12**,
    host still running. The instrument works.
  - `scripts/scratch/2026-10_threadhandle_matrix/threadhandle_matrix.py` — a 2×2 matrix (created handle
    vs opened handle) × (thread alive vs exited) on a child running `kernel32!Sleep(8000)`: a live thread
    suspends and reads fine either way; an **exited** thread fails `SuspendThread` with
    `ERROR_ACCESS_DENIED (5)` whichever handle was used. gle=5 is therefore not a rights problem with
    our handle — it is the signature of a thread that can no longer be suspended.

### 44.4 Reading

A thread that cannot be suspended at t = 80 ms, in a process whose user CPU does not move by one
microsecond for 2.1 s and whose memory only ever decreases, is a thread in a process that **has already
begun terminating**. The ~2.2 s we were watching was not QuickJS thinking; it was teardown, and the death
had already happened by the first sample. §42's "~6.9 s zero-allocation stretch inside QuickJS's own
code" reads the same kind of series as execution; it is not.

That also collapses §36's fork. "Heap/environment side vs engine side" both presuppose a live host
executing our sequence while it died. §43's third branch — "the thread is already terminated while the
process lives → the stall is host-driven" — is the one the data picked, and even that was too generous:
§45 shows the termination was ours, not the host's.

Boundaries: rc=3 remains the process exit code, not a step code (§38.5 stands; `bucket=intrinsic
name=Date` means nothing); "already terminating at 80 ms" is an inference from three separately
controlled signals, not an observation of the termination moment; 22 samples of one thread in one shot;
the 单发射 is spent.

**Counts for §44**: 1 dispatch (the authorized 单发射, pid 13804 killed, now spent), 0 DLL change (§42's
bytes, local == remote verified), 1 new driver-side observation kind (`GetThreadContext` +
`GetThreadTimes`/`GetProcessTimes`, read-only, no new capability), 22 thread captures with 0 readable Rips
and 22/22 `SuspendThread gle=5`, 1 process-wide user-CPU delta of exactly 0 µs across 2.1 s, 1 memory
series monotonic from 8,179,876 K private → 2,156 K, 2 zero-cost controls (cpuwatch: untouched game
advances 12,828,125 µs user over 20,119.7 ms; suspendcap: 12/12 readable Rips on the game's own threads),
1 Win32 rights matrix pinning `SuspendThread gle=5` to "thread exited" (4/4 cells), 1 new public harness
helper pair (`open_process_handle`/`open_thread_handle` + `close_handle`), 11 new
`scripts/test_c2_harness.py` tests (131 passed), 0 code change to the shipped DLL, 0 new export.

## 45. The artifact terminates its own host — exit 3 is `abort()`, and the trap pins offline to `js_rc` (quickjs.c:1494) inside `__JS_NewAtomInit` (2026-10-22, no dispatch, no game)

Transcript: `evidence/logs/c2_selfabort_4_4_4.log`. §44 ended with a hypothesis that costs nothing to
test and needs no authorization: **load the same DLL bytes in a process this script owns and see whether
it dies without being touched.**

### 45.1 Status 3 is the abort() signature

Measured in child pythons on the Windows host: `ctypes.cdll.msvcrt.abort()` → returncode **3**, while
`os.abort()` → 3221226505 (0xC0000409, fastfail). So the `0x3` that §38, §40, §42 and §44 all reported is
the UCRT `abort()` exit status. `libs/quickjs/quickjs.c` calls plain `abort()` in 30 places and
`build.zig:8-14` compiles that file into the DLL, where Zig's own UBSan/panic runtime converts a safety
trip into exactly that.

### 45.2 The repro

    $ ssh Windows_Jiaolong "python C:\temp\dll_abort_repro.py"
    [repro] child returncode = 3 (0x3)
    [repro] child stdout = "BASE sqjs_s43.dll 0x7ffc138c0000 … SANITY 42 … WITNESS 'enter heap_ok alloc_ok free_ok new_rt MmMmMm'"
    [repro] child stderr = "thread 7632 panic: member access within null pointer of type 'JSMallocBlockHeader' (aka 'struct JSMallocBlockHeader')" + 8 in-DLL frames
    [repro] VERDICT: the DLL terminated its own host with exit status 3 — the abort() signature, reproduced with no game involved

No Stellaris. No injection. No dispatch. The witness text is the live text verbatim, `SURVIVED rc=` never
prints, and two runs under different ASLR bases (0x7ffbeb710000, 0x7ffc138c0000) produce an identical
in-DLL RVA set: `0x43bc, 0x55f5, 0xbd9b, 0x1ebde, 0xeede3, 0x31b9c8, 0x31cc05, 0x44d339`. Deterministic.

### 45.3 Pinning the site without symbols, without debug info, without a process

The DLL has no symbol table and no `.debug_*` sections, so Zig's panic printer can only say `???`. Two
artifacts inside the image still answer "where", and `scripts/scratch/2026-10_abortexit/ubsan_site.py`
reads both: every UBSan check carries a `TypeMismatchData` record in `.rdata` with its **source file,
line, column and type-descriptor name** (the same strings the panic printed), and `.pdata` is the x64
exception directory — `{BeginAddress, EndAddress}` per function, i.e. exact boundaries without names.

    $ python3 scripts/scratch/2026-10_abortexit/ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x18000bd9b
    [ubsan_site] function holding 0x18000bd9b: rva 0xbd70..0xbdf3 (131 bytes)
      libs/quickjs/quickjs.c:1494:12 member_access type='JSMallocBlockHeader' … record_rva=0x5aa430 loaded_at=0x18000bd8c

objdump agrees byte-for-byte: the `lea rcx,[rip+0x59e69d]` at 0x18000bd8c computes that record, the
following `call` ends at 0x18000bd9c (Zig prints `ip−1`, hence 0xbd9b), and `add rcx,0xfffffffffffffff8`
is the `ptr − 8`. So the trip is **quickjs.c:1494**, `js_rc`'s `container_of`, in the 131-byte function
holding it. The third frame resolves to a 500-byte function whose own records are at quickjs.c:3433/3434
on type `JSString` — reading those lines names it: `__JS_NewAtomInit` (quickjs.c:3427), the atom-string
allocator that `JS_InitAtoms` runs ~504 times, which is the *first* thing `JS_NewRuntime2` (quickjs.c:2067)
does after `js_malloc_init`. **§43's offline narrowing — "first `__JS_NewAtomInit` iteration, `:3430`→`:3330`"
— lands on the same function this symbolization resolves from the binary.** Two independent routes, one site.

The mechanism: QuickJS 2025-09-13 no longer uses the host allocator directly. `struct JSRuntime` begins
with `JSMallocContext malloc_ctx` (quickjs.c:317), its own arena holding its own `mf`/`malloc_state`, and
every refcounted object carries an 8-byte header in front of the user pointer, recovered by
`js_rc(ptr) = ptr − 8`. The check that fired tests the *header* pointer, so the user pointer handed to
`js_rc` was **8** — the value `__js_malloc` returns for `b->user_data` when its block header `b` is NULL
(quickjs.c:1588, 1618). `__JS_NewAtomInit`'s `if (!p)` guard cannot catch that: 8 is not NULL. This also
explains the allocation witness: `JS_NewRuntime2` calls our `heap_malloc` once for the JSRuntime and then
only for arenas and large blocks, so `MmMmMm` is three arena-phase allocations while the ~504 atom
strings never reach us at all.

### 45.4 What this retroactively changes

  1. **§36's fork was the wrong axis.** Neither "our allocator/`HeapAlloc` failed to return" nor "QuickJS's
     own code died in a live host" — the artifact aborts its own process. Nothing about `stellaris.exe` is
     needed to reproduce the death.
  2. **§42's 6.9 s engine-side stretch is void** (§44's memory series and gle=5-at-80 ms already said so):
     that window was teardown, not computation.
  3. **The 升级授权 §42 asked for is not needed.** "Seeing into that gap requires hooking QuickJS" was
     premised on a gap that does not exist. The site came from a file copy with read-only tooling. No hook
     was performed, and none is warranted by the next step.
  4. **`rc=3 → bucket=intrinsic name=Date` is retracted with a mechanism**, not merely flagged unproven as
     in §38.5.
  5. **C2 stays blocked, but the blocker moved** from "the host dies when our init sequence runs" to "our
     build's QuickJS trips a null-header member access in its own atom-init path and aborts". Everything
     §31–§43 measured inside the game was observing that abort, which is why it looked host-shaped.
  6. **The fix loop is now offline**: edit → `zig build` → scp under a new filename → `python
     C:\temp\dll_abort_repro.py`, no game, no dispatch, no 点名. Corollary worth stating: the deployed DLL
     is a **Debug** build (`build.zig`'s `standardOptimizeOption(.{})` default), so clang/Zig safety checks
     are compiled into the code that runs inside the host and any trip is a host kill. That property holds
     for every shot so far, independent of this defect.

### 45.5 Ranked open question

Why does the arena's block header come back NULL on Windows and not on Linux, where the same sequence
completes with 8 matched `Mm` pairs and `rt=`? Untested candidates, in the order the next offline step
should rank them: (a) our `AllocHeader` giving QuickJS an alignment the arena's `blocks[]` arithmetic
assumes it need not re-derive; (b) `heap_malloc`'s `size == 0 → NULL` against glibc's unique non-NULL
pointer (Linux never returns NULL there); (c) `malloc_limit`/`malloc_size` arithmetic split between the
`JSMallocState` we own and the one `JS_NewRuntime2` seeds locally (quickjs.c:2070-2076). (b) is the
cheapest to test and the only one where our own code deviates from C semantics.

Boundaries: the faulting pointer value was never observed — "8" is derived from what the emitted check
tests (`ptr − 8 == 0`) plus the source shape; the guard at 0x18000bd86 has an ambiguous `-O0` shape
(`xor eax,eax; test al,0x1; jne`), so no claim is made that clang proved nullness at compile time; frame
attribution is `.pdata` ranges plus record references, not link-time names, and the middle frame
(RVA 0xeede3, where `js_alloc_string_rt`/`js_malloc_rt` would sit) resolves to no entry — that parse
yields only 3,042 entries for a 0x4c8b86-byte `.text`, so absence proves nothing; the determinism claim
covers two runs of one artifact.

**Counts for §45**: 0 dispatch, 0 game process involved, 0 capability escalation (no hook, no patchCode,
0 DLL bytes changed — §42's artifact reused), 1 abort-status measurement (msvcrt `abort()` → 3,
`os.abort()` → 0xC0000409), 1 standalone child-process repro reproducing the live witness verbatim and
dying with status 3, determinism checked across 2 ASLR bases with an identical 8-RVA frame set, 1 new
offline probe (`ubsan_site.py`: `.pdata` ranges + UBSan `TypeMismatchData` records → 141 sites for
`JSMallocBlockHeader`, trap resolved to quickjs.c:1494:12 in a 131-byte function, frame 3 resolved to
`__JS_NewAtomInit` via quickjs.c:3433/3434), 1 §43→§45 independent-route agreement on the same function,
4 §36–§44 conclusions voided or retracted (fork axis, 6.9 s stretch, hook-QuickJS escalation, rc=3 decode),
1 roadmap consequence (C2 blocked on our artifact, offline-iterable), 3 named untested candidates for the
why, 0 code change to the shipped DLL, 0 new Zig test, 0 new export.

## 46. The ring hands back real sizes, pointers and `JSMallocState` addresses — and all three §45.5 candidates fail on them (2026-10-22, no dispatch, no game)

Transcript: `evidence/logs/c2_mfrecords_4_4_4.log`. §45.5 ranked three explanations of the Windows-only
null header, and its own boundary admitted the whole ranking rested on a value nobody had seen ("the
faulting pointer value was never observed"). Task 1's ring recorder exists to turn that value into text,
so this section is the first discrimination made **from data rather than from plausibility**.

### 46.1 What was run, and the sampling problem that nearly hid the data

`python C:\temp\c2_selfabort_repro.py C:\temp\sqjs_s46.dll` — the maintained §45 self-checker (promoted in
Task 2) against bytes rebuilt at `26589ac`: **77c0c35ec5b74abc8ccb849515621aaf53abd3fdc0a5e6ab8b9466acc0c11ad0**,
deliberately *not* §42/§44's `863917f2…86617`, because the recorder lives in `quickjs_wrapper.c`. The
rebuild is byte-reproducible (artifact moved aside, rebuilt, same digest), remote `certutil` agrees, and
the script itself had to be scp'd too (`C:\temp` did not contain it — plan Step 2 gap, closed by the
controller's ruling).

94 invocations, 84 real child runs: **84/84 died with returncode 3, 0 printed `SURVIVED`, one single
distinct in-DLL RVA set** (`0x43bc, 0x55f5, 0xbd9b, 0x1ebde, 0xeede3, 0x31b9c8, 0x31cc05, 0x44e399`),
witness text `enter heap_ok alloc_ok free_ok new_rt MmMmMm` — §45's text, verbatim, in bytes that
differ from §45's by the recorder. Five of the eight frames are the same RVA as §45's; only the outermost
moved, and `dll_ubsan_site.py` still resolves `0xbd9b` to `quickjs.c:1494:12` in the same 131-byte
function range with the same 141 sites. A read point moved no code.

The first 14 renders came back **empty** — eight rows of `__ size=0 ptr=---------------- st=000000000000`.
That is not "no data because the recorder is broken" (`RECORDER ok`, well-formed rows, digest matched) and
it is not judgment-table row 4 either; it is the reader poll losing a race: the recorder thread polls every
2 ms, and between the last `heap_malloc` returning and `abort()` there is a window small enough that the
0.2 ms witness thread always lands a sample in it while the 2 ms recorder thread almost never does. Forcing
CPU oversubscription (16–24 concurrent children on 16 logical processors) gave the existing reader a
timeslice and produced **5 data-bearing renders out of the 70 oversubscribed child runs** (80 invocations,
10 of which never started a child — see the log's run tally), with no change to the instrument. This is a
**property of the channel**, recorded as a concern: with the defect present, the ring is readable only if
the reader samples inside a sub-millisecond window, so the `post` rendering — the one Task 4's acceptance
reads — is the reliable half of this design.

### 46.2 The rows

Four of the five renders are complete ring states (3 events, 5 never-written slots), and they agree:

    row  kind  size    ptr            st             ptr%8  ptr%16   st − ptr(row1)
    1    Mx    0x5a0   0x154ba68 …    0x0000006dec18   0      0x8      —        (the runtime block)
    2    Mx    0x808   0x1884708 …    0x00000154be70   0      0x8      +0x408
    3    Mx    0xff0   0x1884f28 …    0x00000154be70   0      0x8      +0x408

13 event rows in total, every one of them `Mx` — a completed `heap_malloc`. No `Fx`, no `Rx`, and no
`<kind>_` row, i.e. **no allocator callback was in flight when the process died**. Sizes are the same
triple in the same order in all four complete renders; the pointers move with the heap (ASLR), the first
`st` does not.

### 46.3 Judgment table: the fourth row fires

  - **`size == 0` on an `M`/`R` row → (b): does not fire, and this run must not be credited for it.**
    `__js_malloc(s, 0)` is served by the embedded `zero_size_block` (`quickjs.c:1549-1556`) and
    `js_new_string8_len` short-circuits `len <= 0` (`:4018`), so a zero-size request never reaches
    `mf.js_malloc` on this revision — established offline before this read-back. Observing no zero-size row is
    **agreement with a known fact, not an exclusion produced by this run.** Candidate (b) stays excluded
    offline and is not booked here. (The pristine slots' `size=0` is a never-written marker; the table
    reads `M`/`R` rows only.)
  - **Alignment → (a): does not fire.** Evaluated as `ptr % 8 != 0` — the reading forced by
    `JS_MALLOC_ALIGN = 8` (`:243`) and `offsetof(JSMallocBlockHeader, user_data) == 8` (`:270-280`). All 13
    pointers are 8-aligned. They are all `≡ 8 (mod 16)`, which is what our one-`size_t` `AllocHeader` plus
    `return h + 1` over a 16-aligned `HeapAlloc` structurally produces, and it is also what the native
    (unbroken) sequence renders (`ptr=2dc2e18`, `ptr=2dc50a8`) — so **that shape cannot be the
    Windows/Linux differentiator**, and the plan clause "原生同一序列全是 16 对齐" is measured false ahead of
    this run. The trip we are chasing is *null pointer*, not misaligned, and nothing we handed QuickJS
    violates the alignment its own arithmetic needs.
  - **`st` → (c): does not fire, on a positively-matched healthy pattern.** Distinct `st` **per complete
    render = 2**, in 4/4 renders: one constant `0x6dec18` on the runtime row, one per-process value on the
    other two rows. `quickjs.c:2070-2082` requires exactly that: `JSMallocState ms` is a **stack local**, the
    first `js_malloc` carries `&ms`, and only `rt->malloc_ctx.malloc_state = ms` creates the heap copy every
    later call carries — so "any two rows differ in `st`" (the plan's literal row-3 wording) would fire on a
    *healthy* runtime and is not usable as written. Two independent confirmations that the second value is
    `&rt->malloc_ctx.malloc_state` and not a stray state: it equals the runtime block pointer **+ 0x408 in
    all four renders**, and 0x408 = 1032 = the computed `offsetof(JSMallocContext, malloc_state)`
    (`arena_list[31]`+`free_arena_list[31]`=992, `zero_size_block`=8 → 1000, `mf`=4 pointers → 1032) with
    `offsetof(JSRuntime, malloc_ctx) = 0`; and the stack value never reappears after the runtime row. No
    third `st`, no abandoned copy, and the `sizeof(JSRuntime)` row is present ⇒ no "first malloc never
    completed" case either.
  - **⇒ Row 4: all three candidates fail on the data.** Per the plan's own instruction the candidate table is
    declared **incomplete**, the raw `MFREC` text and the last record before the death go back to the
    human, and **this plan stops here — no fourth candidate is invented in this section.**

### 46.4 What the three rows are, and where the death sits relative to them

Read off the vendored source after the fact (arithmetic plus call order, not an observed label):
`0x5a0` = 1440 = `sizeof(JSRuntime)` — the `mf->js_malloc(&ms, sizeof(JSRuntime))` at `:2076`; `0x808` =
2056 = `sizeof(JSMallocLargeBlockHeader)(8) + 2048` = `js_mallocz_rt(sizeof(uint32_t) × 512)` inside
`JS_ResizeAtomHash(rt, 512)`, the first thing `JS_InitAtoms` does (`:3180`); `0xff0` = 4080 =
`sizeof(JSMallocArena)(40) + 101 × 40`, the new-arena request of the **40-byte block class** (unique to
that class among all 31). In `JS_InitAtoms` order that is runtime → atom hash → the arena created by the
**first** `__JS_NewAtomInit`'s name-string request (`js_alloc_string_rt(rt, len, 0)` at `:3430`). The ring
therefore puts the trip **after that arena was handed over successfully and before any further `mf` call** —
and the `atom_array` growth (which would have appeared as a `0x1640` large-block row, §43's other half) is
absent from every render. That is §43's window confirmed from the allocator side. The status of that second
endpoint is **excluded by non-observation, not by a positive sighting**: no `0x1640` row landed in any of the
four complete renders, and the witness's own `MmMmMm` (three mallocs, §42) corroborates the count
independently of the ring — but under the sampling race of 46.1/46.5, absence from a raced reader is a weaker
statement than observation, so 46.4 does not upgrade it to one.

### 46.5 The one render that must not be pooled

The fifth render prints a single `Mx size=ff0` row in its third slot with slots 0 and 1 pristine. No
sequential ring history can produce that ordering: it is the documented consequence of reading the cursor
once before the walk (`quickjs_wrapper.c:666-671`) while the writer advances — the cursor was read at 0, and
by the time the walk reached slot 2 the third event had landed, while slots 0 and 1 had already been read as
empty. The render shows an ordering that **was never a ring state**. Had its `st` been pooled with the
complete renders, the distinct-`st` count would have gone 2 → 6 and row 3 would have "selected" candidate
(c) from a reader artifact. Rule applied: **classify per render; a render whose row order is impossible for
the cursor value it must have read is excluded from counting** (its individual filled rows stay internally
consistent, so they still corroborate size and alignment).

Boundaries: the rows report the pointers and sizes **our callbacks returned**, at the moments the reader
sampled them — they are not the faulting value inside the arena, and §45's "`ptr − 8 == 0`" mechanism lives
on QuickJS's own derived pointers that the ring cannot see; nothing in this section observes the value that
`js_rc` was handed. The three-row identification in 46.4 is arithmetic plus source order, not a label
carried by the data; row 2's and row 3's *names* (atom hash, 40-byte arena) could be wrong even though their
sizes are unique. `sizeof(JSRuntime)`/offsets were computed by compiling this `quickjs.c` natively
(LP64); the Windows target (LLP64) was not asserted directly because `zig cc -target
x86_64-windows-gnu` has no CRT headers here — the carry-over rests on `JSRuntime` containing no
`long`/`time_t`/`wchar_t`, plus the observed 0x408 agreement. Whether a fourth `heap_malloc` entered after
the last sampled row and before `abort()` cannot be excluded from the ring alone; the witness (cap 8, and
it reads `MmMmMm`) and the identical 8-frame panic set make it unlikely, not impossible. The 5 data-bearing
renders come from the same artifact and the same host in one session, under deliberately heavy scheduling
load — determinism of the *death* is established (84/84, one RVA set), determinism of *which render lands*
is not: it is a race we leaned on, not a property we control.

**Counts for §46**: 0 dispatch, 0 game process, 0 injection, 0 `CreateRemoteThread`, 0 new capability, 0
edit to `src/` or to any top-level tool; 1 rebuild (byte-reproducible, `77c0c35e…c11ad0`, ≠ §42's
`863917f2…86617` as the plan predicted), 2 remote artifacts verified by digest (DLL by `certutil`, script by
`Get-FileHash`), 94 tool invocations / 84 real child runs / 84 status-3 deaths / 0 `SURVIVED` / 1 distinct
RVA set, 5 data-bearing renders (13 event rows: 13 `Mx`, 0 `Fx`, 0 `Rx`, 0 in-flight), 1 stale render
identified and excluded from counting, 3 judgment-table candidates evaluated (0 selected), 1 of them
explicitly *not* credited to this run because it was excluded offline, 4 independent confirmations of the
+0x408 `malloc_state` identity, 1 offline struct computation (`sizeof(JSRuntime)=1440`,
`offsetof(JSMallocContext, malloc_state)=1032`), 1 site re-pin on the new bytes (quickjs.c:1494:12, 141
sites, same function range), 1 window bound inferred from two reader cadences (≳0.2 ms, < 2 ms), 1 plan
outcome: **candidate table incomplete — the three §45.5 candidates are not the mechanism**, C2 stays
blocked, and the next move belongs to the human rather than to Task 4.

## 47. The trap's null report is a compile-time constant from the fallback offsetof — §45's "pointer was 8" is withdrawn (2026-10-22, no dispatch, no game)

Transcripts: `evidence/logs/c2_panicchain_4_4_4.log` (Task 1's eight-frame chain) and
`evidence/disasm/js_rc_trap_77c0c35e.md` (Task 2's 40-instruction listing of the 131 bytes).
Artifact: `zig-out/bin/stellaris_quickjs.dll`, sha256
`77c0c35ec5b74abc8ccb849515621aaf53abd3fdc0a5e6ab8b9466acc0c11ad0`, read as a file copy. Zero
dispatch, zero game, zero Windows channel, zero bytes changed.

The finding is narrow and it moves the question: the UBSan report that aborts is **not** about the
pointer `js_rc` was handed. It is the instrumentation of the **fallback `offsetof`** inside
`container_of` — a member access through a null pointer that exists only at compile time. Its
pointer operand is the literal **0**, so the report fires on every call to `js_rc`, whatever `str`
is. §45's "the user pointer was 8" is withdrawn; `str`'s value and source remain unobserved, which
is exactly the half §46's boundary kept.

### 47.1 The chain, frame by frame

| frame | printed rva (`ip − 1`) | `.pdata` span | offset | records / source cited | name |
|---:|---|---|---:|---|---|
| 1 | `0xbd9b` | `0xbd70..0xbdf3` (131 B) | +`0x2b` (43) | 1 `TypeMismatchData` `0x5ab430` at `quickjs.c:1494:12`; plus the `PointerOverflowData` `0x5ab450`, same location, not decoded by the maintained tool (hand-decoded in §47.2) | **`js_rc`** (`:1492`) |
| 2 | `0xeede3` | `0xeed10..0xeeff1` (737 B) | +`0xd3` (211) | 6, `:2361`–`:2366` | **`js_alloc_string_rt`** (`:2355`) |
| 3 | `0x1ebde` | `0x1ebb0..0x1eda4` (500 B) | +`0x2e` (46) | 4, `:3433`/`:3434` | **`__JS_NewAtomInit`** (`:3426`) |
| 4 | `0x55f5` | `0x5320..0x570b` (1003 B) | +`0x2d5` (725) | 5, `:3174`–`:3178` | **`JS_InitAtoms`** (`:3169`) |
| 5 | `0x43bc` | `0x3e40..0x4f6b` (4395 B) | +`0x57c` (1404) | 31, `:2076` … `:2118` | **`JS_NewRuntime2`** (`:2067`) |
| 6 | `0x31b9c8` | `0x31ad90..0x31cbeb` (7771 B) | +`0xc38` (3128) | 0 | **`c2_diag_sequence`** (`quickjs_wrapper.c:497`) |
| 7 | `0x31cc05` | `0x31cbf0..0x31cd30` (320 B) | +`0x15` (21) | 0 | **`C2DiagQuickJS`** (`quickjs_wrapper.c:580`) |
| 8 | `0x44e399` | `0x44e350..0x44e3cc` (124 B) | +`0x49` (73) | 0 | **`C2DiagQJSInto`** (`src/dll/exports.zig:240`) |

The four edges that make it a chain are in the source at the cited lines:

    quickjs.c:2096   if (JS_InitAtoms(rt))                      JS_NewRuntime2  → JS_InitAtoms
    quickjs.c:3191   if (__JS_NewAtomInit(rt, p, len, atom_type) == JS_ATOM_NULL)
                                                                JS_InitAtoms    → __JS_NewAtomInit
    quickjs.c:3430   p = js_alloc_string_rt(rt, len, 0);        __JS_NewAtomInit → js_alloc_string_rt
    quickjs.c:2361   js_rc(str)->ref_count = 1;                 js_alloc_string_rt → js_rc

Frame 2 is disassembled, not inferred: the call to `js_rc` is the 5-byte `call 0x18000bd70` at
`0xeeddf`, returning to `0xeede4` (printed `0xeede3`), and the next check site is the `:2361`
record at `0xeee07`. A read-only `E8` scan of `.text` finds **104** direct call sites to `0xbd70`;
the one at `0xeeddf` is the first this execution reached.

### 47.2 Three judgment rows, none matching; the check that fired is a third check site

Verbatim from the Task 2 listing (reproduced here with
`python3 scripts/pe_disrva.py zig-out/bin/stellaris_quickjs.dll 0xbd70 0xbdf3` — 40 insns,
131 bytes, byte-identical):

    0000bd86  xor     eax, eax
    0000bd88  test    al, 1
    0000bd8a  jne     0x18000bd9c
    0000bd8c  lea     rcx, [rip + 0x59f69d]  #0x5ab430
    0000bd93  xor     eax, eax
    0000bd95  mov     edx, eax
    0000bd97  call    0x180498170            # type_mismatch_v1
    0000bd9c  mov     r8, qword ptr [rbp - 0x10]
    0000bda0  test    r8, r8
    0000bda3  setne   al
    0000bda8  mov     rcx, r8
    0000bdab  add     rcx, -8
    0000bdbb  setne   r9b
    ...
    0000bddd  lea     rcx, [rip + 0x59f66c]  #0x5ab450
    0000bde4  call    0x180499cc0            # pointer_overflow

- **`0xbd86..0xbd97` — the check that aborted, on the compile-time constant 0.** `xor eax,eax` at
  `0xbd86`; `test al,1` at `0xbd88`; `jne 0xbd9c` at `0xbd8a`. The panic frame names `0xbd9b`, which
  resolves to the function entry `0xbd70`; at that entry `al` has just been zeroed and nothing writes
  it before the test, so the jump can never be taken; whether a caller also branches into the function
  elsewhere was not scanned for, so the claim is about this entry only.
  `lea rcx,[0x5ab430]`, then `xor eax,eax` / `mov edx,eax` put **0** in the handler's pointer
  slot and `call 0x498170` at `0xbd97`. The record decodes to `quickjs.c:1494:12`, kind
  `member_access`, type `JSMallocBlockHeader`, `log_align = 3` (8-byte alignment), `kind = 3`.
  The handler's entry reads `log_align` at `[rcx+0x18]`, `kind` at `[rcx+0x19]` and the type
  descriptor at `[rcx+0x10]`, and branches on `test rdx,rdx; jne …`: with `rdx = 0` it takes the
  null branch and formats `member access within null pointer of type 'JSMallocBlockHeader'` — the
  panic text at `c2_selfabort_4_4_4.log:36` and the return code 3 at `:34` are the two
  observations. The panic frame `0xbd9b` is `ip − 1` of the **return from `0xbd97`** (`0xbd9c`),
  not of the second call (`0xbde4` returns to `0xbde9`, printed `0xbde8`), so the text belongs to
  this call.
- **`0xbda0..0xbdd3` — the runtime pointer's zero test, and the subtraction.**
  `test r8,r8` at `0xbda0` reads the original `str`; `0xbdab` is `add rcx,-8` (the "sub 8",
  encoded `48 83 c1 f8`); `setne r9b` at `0xbdbb` tests the subtraction result's nullness;
  `0xbdd1 test al,1` / `0xbdd3 jne 0xbde9` either skips the second handler or falls into it.
- **`0xbde4` — the pointer-overflow report on `str − 8`.** `lea rcx,[0x5ab450]` at `0xbddd`,
  `call 0x499cc0` at `0xbde4`, with `rdx = str` and `r8 = str − 8`. The record at `0x5ab450` is a
  16-byte `PointerOverflowData`: only a source location — filename pointer, line 1494, column 12
  (read directly; the maintained tool decodes only `TypeMismatchData`). The handler's entry tests
  both `rdx` and `r8` and takes three arguments, matching `__ubsan_handle_pointer_overflow`
  (Task 2's attribution, re-checked at the entry). This is the only handler call that receives
  `str` as an argument — and the failing run never reaches it, because `0xbd97` aborts. The
  `test r8,r8` at `0xbda0` also reads `str`, but it feeds this call's guard, not the aborting
  call's operand.

So both a pre-subtraction zero test (on `str`) and a post-subtraction zero test (on `str − 8`)
exist; the plan's single-check premise does not describe this code. The check that fired is a
**third** check site — not either of the two sites the table contrasts — on neither quantity.

### 47.3 Judgment table: (i), (ii) and (iii) are inapplicable; the fourth row lands

| row | premise | what the 131 bytes show | verdict |
|---|---|---|---|
| **(i)** | zero test after `sub 8`, on the subtraction result ⇒ the header is checked ⇒ `str == 8` | the aborting report is `0xbd97`, **before** `add rcx,-8` at `0xbdab`; its operand is `edx = 0`, not `rcx` | **does not hold** |
| **(ii)** | zero test before `sub 8`, on `str` ⇒ `str == NULL` at `:2361` ⇒ `:2359` contradicted ⇒ attribution unreliable, Task 1 redo | a pre-subtraction `test r8,r8` does exist at `0xbda0`, but it feeds the `0xbde4` pointer-overflow report, not the aborting call; the aborting operand is 0 whatever `str` is | **does not hold** |
| **(iii)** | the test and the subtraction are in different blocks, or the trapping function is a thunk ⇒ handler hook | the straight-line path actually taken runs from `0xbd86` through the aborting call at `0xbd97` (conditional branches exist at `0xbd8a` and `0xbdd3`, but neither is taken on that path), and the zero test at `0xbda0` with the `add rcx,-8` at `0xbdab` are in the same basic block; the 131-byte function is `js_rc`'s own body (record at `:1494:12`), not a thunk | **does not hold** |
| **4** | none of the above | fallback `offsetof`'s compile-time null member access; constant-0 report; Zig abort; exit 3 | **lands** |

Row (ii)'s consequence deserves its own sentence, because it is the one that would have thrown
away Task 1: the attribution is **not** ambiguous here. The 131-byte function references exactly
two UBSan records and both carry the same `:1494:12` location — one `TypeMismatchData`
(`0x5ab430`) and one `PointerOverflowData` (`0x5ab450`). There is no competing line, so `js_rc` is
the function and `:1494` is the expression.

**Landing row: the plan's fourth row — with a mechanism, not with "offline disassembly cannot
judge".** This is the termination row: Task 4's allocator repair is not qualified by this
evidence.

### 47.4 The mechanism: the fallback `offsetof` is a syntactic null member access

    cutils.h:43    #ifndef offsetof
    cutils.h:44    #define offsetof(type, field) ((size_t) &((type *)0)->field)
    cutils.h:49    #ifndef container_of
    cutils.h:51    #define container_of(ptr, type, member) ((type *)((uint8_t *)(ptr) - offsetof(type, member)))
    quickjs.c:1492 static inline JSMallocBlockHeader *js_rc(void *ptr)
    quickjs.c:1494     return container_of(ptr, JSMallocBlockHeader, user_data);

The fallback is the definition that actually takes effect in this translation unit — measured,
not assumed. Preprocessing the same file with the build's default target (windows x86_64, Zig's
default ABI `.gnu`) and C flags

    $ zig cc -target x86_64-windows-gnu -DCONFIG_VERSION='"2025-09-13"' \
        -Wno-gnu-zero-variadic-macro-arguments -E libs/quickjs/quickjs.c > /tmp/qjs_s47.i   # rc=0

expands the body to

    return ((JSMallocBlockHeader *)((uint8_t *)(ptr)
            - ((size_t) &((JSMallocBlockHeader *)0)->user_data)));

The parenthesised expression is a member access through a null pointer written in the source. Its
value is the compile-time constant 8 (`user_data` at offset 8; the layout probe in
`c2_panicchain_4_4_4.log` (5) printed `sizeof(JSMallocBlockHeader)=8 u@0 block_size_idx@2 ref_count@4 user_data@8`), but clang's
`-fsanitize=null` instruments the **access**, not the folded value: the handler call for the
`TypeMismatchData` `0x5ab430` (file, line 1494, column 12, type descriptor `JSMallocBlockHeader`,
`log_align = 3`, `kind = 3 = member_access`) receives the null constant as its pointer argument.
There is no runtime branch that can suppress it: `xor eax,eax; test al,1; jne` on an `al` nothing
writes is a constant-false guard, so `0xbd97` runs on every call.

Zig's UBSan runtime takes that record and pointer: `kind = member_access` with pointer 0 prints
`member access within null pointer of type 'JSMallocBlockHeader'`, then panics; Zig's panic
handler aborts, and §45.1 measured the abort status as **3**. That is the whole chain: fallback
`offsetof` → statically-null member access → unconditional UBSan report with constant 0 → Zig
abort → exit 3.

**Why this is Windows-only, at the source level.** The same `zig cc -E` on the native target
expands the body to `__builtin_offsetof(JSMallocBlockHeader, user_data)`:

    $ zig cc -DCONFIG_VERSION='"2025-09-13"' -Wno-gnu-zero-variadic-macro-arguments \
        -E libs/quickjs/quickjs.c > /tmp/qjs_native.i                                     # rc=0
    static inline JSMallocBlockHeader *js_rc(void *ptr)
    { return ((JSMallocBlockHeader *)((uint8_t *)(ptr) - __builtin_offsetof(JSMallocBlockHeader, user_data))); }

The preprocessor trace explains it: on the native target `__linux__` selects the `<malloc.h>` branch
at `quickjs.c:38`, and that header includes `<stddef.h>` **fully** (no `__need_*`), so `offsetof` is
already the builtin when the `#ifndef` is reached. `<stdlib.h>` (`quickjs.c:25`) is not the source
of the pull: glibc's copy asks `<stddef.h>` for `size_t`/`wchar_t`/`NULL` only (`__need_size_t`,
`__need_wchar_t`, `__need_NULL`) and defines no `offsetof` — measured, the stdin probe
`zig cc -E -dM -x c -include stdlib.h - </dev/null` prints no `offsetof`, while the same command
with `-include malloc.h` prints `#define offsetof(t,d) __builtin_offsetof(t, d)` (verbatim output
in `c2_panicchain_4_4_4.log` (12)). On the MinGW headers this build uses, the `__linux__`/`__GLIBC__`
branch is not taken, `<stdlib.h>` defines no `offsetof`, and `<inttypes.h>` (`quickjs.c:28`)
reaches `<stddef.h>` only with `__need_wchar_t` — so `offsetof` is still undefined at `cutils.h:43`,
the fallback is defined, and the later full `<stddef.h>` inclusion (via `libregexp.h:27`) cannot
override it because `__stddef_offsetof.h` guards its definition with `#if !defined(offsetof)`. That
is a preprocessor-level difference sufficient to explain why the native control completes; whether
the native test binary also carries `-fsanitize=null` was not measured, so this is the source-level
reason the check exists on one target and not the other, not a claim about that binary's flags.

**What this does to the death window.** `js_rc` cannot return in this build, so the first call to
it is the death. The chain says that call is at `0xeeddf` — `js_alloc_string_rt`'s `:2361`, inside
the first `__JS_NewAtomInit` of `JS_InitAtoms`, after the 40-byte arena (`0xff0`) was handed over
and before any further `mf` call. §43/§45/§46 spent three sections narrowing to that window; §47
says the window is where the first `js_rc` happens, not where an arena computation goes wrong. No
allocator event needs to explain the stop.

### 47.5 What the report does **not** say

- **`str`'s runtime value and source are unobserved.** The report carries a type and the literal
  0; the only instruction in the function that **tests** `str` for null is `0xbda0`, and the check
  it feeds never runs. §46's boundary — "nothing in this section observes the value that `js_rc` was
  handed" — stands unchanged. §45's inference `str == 8` is **withdrawn**: it was derived from
  treating the `ptr − 8 == 0` check as the one that fired, and the check that fired does not test
  `ptr − 8`.
- **The pointer-overflow check's outcome for the real pointer is unobserved.** It would fire if
  `str == 8` (result null) or `str == 0` (base null, result non-null); neither value was seen. The
  old "8" story is exactly that check's condition, moved one call too late.
- **Whether a second defect hides behind this one is unobserved.** With the first check aborting,
  the rest of `js_rc` and the arena path are never executed in this build. A repair will reveal
  whatever is next; this section does not predict it.
- **The native test binary's sanitizer configuration was not measured** (47.4). The header
  difference is verified; its role as the sole difference between the two builds is not.

### 47.6 What this does to §46's 13 `Mx` rows

The rows remain valid observations of **our callbacks**: the sizes (`0x5a0`, `0x808`, `0xff0`), the
pointers, the 8-alignment and `≡8 mod 16` shape, the per-render `st` counts and the
`+0x408 = offsetof(JSMallocContext, malloc_state)` identity are all untouched. What changes is
their **discriminating power**: they were read as evidence about the header that `js_rc`
supposedly received null, and there is no null header in the report. The trip is independent of
runtime pointer values, so no allocator property — alignment, zero-size behaviour, state
arithmetic — can be selected or excluded by it. §46's row 4 ("candidate table incomplete") is
superseded: the table was not missing a fourth allocator candidate; the candidates were answers to
a question the binary never asked. **An allocator fix would have been the wrong target.**

### 47.7 Repair options, not implemented

Handed to the human; this plan implements none of them and changes no byte.

1. **Make `offsetof` well-defined for the vendored QuickJS.** In `cutils.h`, define it as
   `__builtin_offsetof(type, field)` (or include `<stddef.h>` before the `#ifndef`; on this
   MinGW target that header defines the builtin — verified in Zig's bundled
   `__stddef_offsetof.h`). The value stays 8 and the instrumented null member access disappears.
   Narrowest fix; vendored source only.
2. **Exclude `libs/quickjs` from null checks in the build** (e.g. `-fno-sanitize=null` on the
   QuickJS C files). Removes this trip and also every genuine null check in the vendored engine;
   treats the symptom.
3. **Make the Zig type-mismatch handler non-aborting for this record kind.** This is the plan's
   row-(iii) read point and needs the link-order/handler experiment (`ubsan_rt.zig` already
   exports the symbol; whether a C-side definition collides is untested) that the plan reserved
   as a **separate authorization**. It would still emit a report per `js_rc` call unless
   filtered, so it is not a first choice.

### 47.8 The Task 1 tool contract, and the §45 accounting Task 1 handed here

`dll_ubsan_site.py func` takes a **vma carrying the image base**; a bare RVA is a caller error and
exits 2, with the correct vma echoed. Measured on this artifact:

    $ python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x18000bd9b
    [ubsan_site] function holding 0x18000bd9b: rva 0xbd70..0xbdf3 (131 bytes)
      .../libs/quickjs/quickjs.c:1494:12 member_access type='JSMallocBlockHeader' ...   # rc=0

    $ python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0xbd9b
    [ubsan_site] func takes a vma carrying the image base (0x180000000); 0xbd9b is below it,
      so it looks like a bare rva — pass 0x18000bd9b for rva 0xbd9b                      # rc=2

That is the guard the §47-preparation batch installed — `docs/offline-tooling.md` calls it
"本批(§47 前置)加的口径护栏", i.e. the batch preceding §47, not §47 itself. Task 1's log (8)
records the guard; the log's forward reference at `c2_panicchain_4_4_4.log:616` is not to it — it
is the §45 `.pdata` accounting taken up in the next paragraph.

Task 1's log also promised (`c2_panicchain_4_4_4.log:616`) that §47 would carry the accounting
for §45's "the frame at `0xeede3` has no `.pdata` entry" sentence. It is false on §45's **own**
artifact: the same `func` there prints `rva 0xeed10..0xeeff1` (737 B) with the same six records
(chain log (4a)). §45's text is untouched; the correction is booked here.

### 47.9 Counts for §47

0 dispatch, 0 game process, 0 injection, 0 `CreateRemoteThread`, 0 new capability, 0 edit to
`src/`, `build.zig` or `libs/`, 0 DLL bytes changed (digest re-checked); 2 prior evidence files
read, 1 40-instruction listing reproduced (`pe_disrva`, 131 bytes), 2 UBSan records decoded
(`TypeMismatchData 0x5ab430`, `PointerOverflowData 0x5ab450`), 1 handler entry read (`0x498170`:
log_align/kind/type-descriptor offsets), 1 second handler entry read (`0x499cc0`: Base/Result
arguments), 1 `E8` scan (104 direct calls to `0xbd70`), 2 preprocessor runs (windows-gnu fallback
vs native builtin), 3 judgment rows rejected, 1 row landed (the fourth, with a named mechanism),
1 inference withdrawn (§45's `str == 8`), 1 candidate table retired (§46 row 4's "incomplete"
reading), 0 repair implemented.

## 48. Repair option (a) implemented: `offsetof` is the builtin now, and the artifact completes `C2DiagQJSInto` (2026-10-22, authorized, no game, no injection, no dispatch)

Transcript: `evidence/logs/c2_offsetof_fix_4_4_4.log`. Artifact of record:
`zig-out/bin/stellaris_quickjs.dll`, sha256
`79c8dc240ef87d3bc979efb78e3549b937b909d57939eb552832be0d1c5c230c`, deployed as
`C:\temp\sqjs_s48b.dll` and hash-checked on the host. Baseline control:
`77c0c35ec5b74abc8ccb849515621aaf53abd3fdc0a5e6ab8b9466acc0c11ad0`, read as a file copy.
The Windows host ran scp, `Get-FileHash` and `python` only — zero game, zero injection, zero
dispatch, zero `CreateRemoteThread`.

§47 left three repair options unimplemented and the choice to the human. The human chose **(a)**:
make the vendored fallback `offsetof` well-defined. This section records the one-line change, the
rebuilt bytes, and the zero-game verification that the abort is gone.

### 48.1 The change

    libs/quickjs/cutils.h:31
    +#include <stddef.h> /* MinGW defines no offsetof; the fallback below is a null member access */

The `#ifndef offsetof` fallback itself is untouched. Preprocessing the same file with the same flags
as §47.4 now expands `js_rc` to

    return ((JSMallocBlockHeader *)((uint8_t *)(ptr) - __builtin_offsetof(JSMallocBlockHeader, user_data)));

instead of the `((size_t) &((JSMallocBlockHeader *)0)->user_data)` form §47 measured. The value is
still 8; the syntactic null member access that `-fsanitize=null` instruments is gone. The change is
in vendored source, so it is one line plus a comment marking why it must survive a vendored update.

### 48.2 The build-cache trap (an operational finding)

A header-only edit did **not** invalidate the C compile in the existing Zig cache:
`zig build --summary all` reported `compile lib stellaris_quickjs Debug x86_64-windows cached` and
the DLL stayed at the baseline sha. A fresh `--cache-dir` forced the recompile. Consequence for the
offline fix loop: after a header-only edit, verify the compile step actually ran and the sha changed
before scp'ing; otherwise the host would receive the old bytes and the repro would show the old
abort, which reads as a failed fix. Recorded in `docs/offline-tooling.md`.

**A second consequence, in the tests.** `scripts/test_pe_disrva.py` had pinned the §47 trap's
`.pdata` span (`rva 0xbd70..0xbdf3`). After the rebuild that range is no longer code, and more than a
moved RVA: the `TypeMismatchData` record the listing was *about* is gone by construction, so an
updated constant would only re-arm the same trap for the next rebuild. The tests now derive the span
from the artifact — the `quickjs.c:1494:12` `SourceLocation` (now a `PointerOverflowData` record,
which `dll_ubsan_site` does not decode and the test scans directly) → the `lea` that loads it → the
enclosing `.pdata` range (`trap_span()`). The annotation witness checks that same record instead of
intersecting with the `TypeMismatchData` set. 5/5 pass on the new artifact; the §47-era numbers
(141 sites, 131 bytes) remain reproducible only against the baseline bytes.

### 48.3 Offline confirmation on the new bytes

`dll_ubsan_site.py site JSMallocBlockHeader`: **141 → 133** check sites; the `quickjs.c:1494:12`
record is **present once in the baseline, absent in the fixed artifact**. The 8 removed records are
exactly the 8 `container_of` expressions built from the fallback:

| line | function | expression |
|---:|---|---|
| 1494 | `js_rc` | `container_of(ptr, JSMallocBlockHeader, user_data)` |
| 1601 | `__js_free` | same, block header |
| 1607 | `__js_free` | `JSMallocLargeBlockHeader` (`header.user_data`) |
| 1645 | `__js_realloc` | block header |
| 1651 | `__js_realloc` | large-block variant |
| 1684 | `__js_realloc` | `container_of(new_ptr, …)` |
| 1704 | `__js_malloc_usable_size` | block header |
| 1711 | `__js_malloc_usable_size` | large-block variant |

Only `js_rc` was on the exercised path; the other seven were latent copies of the same
unconditional abort on the first free/realloc/usable-size call. This is why the include is the
right granularity: special-casing `js_rc` would have moved the abort, not removed it.

### 48.4 The zero-game run

`python C:\temp\c2_selfabort_repro.py C:\temp\sqjs_s48b.dll` (run 1; run 2 repeats it):

    RECORDER ok
    SANITY 42
    WITNESS 'enter heap_ok alloc_ok free_ok new_rt MmMmMmMmMmMmMmMmrt=00000000017B18D8 opaque_ok limits_ok ne'
    SURVIVED rc=0
    LOG 'enter heap_ok alloc_ok free_ok new_rt MmMmMmMmMmMmMmMmrt=00000000017B18D8 opaque_ok limits_ok new_raw RFraw_ok new_diag RFFFRFRFdiag_rc=0 ctx=00000000018BD5F8'
    child returncode = 0 (0x0)
    VERDICT: the child did not die with status 3; this artifact does not self-terminate on this path

Run 2 differs only in the ASLR-dependent numbers (`rt=0000000001833A88`, different `ctx`) and
reproduces `SURVIVED rc=0` and the same verdict. The tool's own exit status is 1 in both runs —
exit 0 means "abort signature reproduced", so 1 is the success side of this verification.

What the run shows: the same entry order as the live shot (`SANITY 42`, then the sequence), the
artifact loads, `JS_NewRuntime2` completes (`rt=` non-null), the stage markers past the old death
point run (`opaque_ok limits_ok new_raw RFraw_ok new_diag RFFFRFRF`), and `C2DiagQJSInto` returns
`rc=0`. The §42 witness's stop at `new_rt MmMmMm` is after three mallocs; the new witness has eight
`M`s before `rt=`, i.e. the allocation events after the old abort site now complete. §47.5's
"whether a second defect hides behind this one is unobserved" is now observed **on this path**: it
does not.

### 48.5 Boundaries

- This is a child-process result. In-game behavior — the host's loader, injection, `C2Init` in the
  engine, dispatch — is **not** tested here and needs a live shot under its own authorization.
- One artifact, two runs; the run is deterministic in its outcome across the two ASLR bases.
- The fix is a vendored-source edit; a future vendored update can drop the include (the comment marks
  it). No other vendored file was audited for the same fallback.
- The seven non-`js_rc` sites are inferred to be latent aborts from the record identity (same
  expression, same instrumentation) and the source shape; none of them was exercised in this run.
- The native test binary's sanitizer configuration remains unmeasured (§47.4); the native
  `zig build test` result is unchanged at `24/27 steps succeeded (1 failed); 314/314 tests passed`,
  the failure being the known `exports.zig` kernel32-undefined-symbol environment fact.

### 48.6 Counts for §48

1 authorized repair implemented (one include + one comment in `libs/quickjs/cutils.h`), 0 edits to
`src/` or `build.zig`; 1 artifact rebuilt in a fresh cache, sha checked locally and remotely;
1 UBSan site diff (141→133, 8 `container_of` expressions removed, `:1494:12` 1→0); 2 zero-game runs;
1 test file re-anchored to the artifact (`trap_span()`; the pinned §47 span no longer exists);
0 game processes, 0 injections, 0 dispatch, 0 hooks; 1 new evidence log.

## 49. Live shot after the fix: `C2Init rc=0`, `1+1` through `JS_Eval`, host survives (2026-10-22, authorized, one game launch)

Transcript: `evidence/logs/c2_live_s48_4_4_4.log`. Authorization: the user's "授权实际调试".
Artifact of record: the same bytes as §48, sha256
`79c8dc240ef87d3bc979efb78e3549b937b909d57939eb552832be0d1c5c230c`, uploaded under three unused
names (`sqjs_s48live.dll`, `sqjs_s48e2e.dll`, `sqjs_s48e2e_noinit.dll`; remote `Get-FileHash`
matched all three). One game launch via `scripts/windows/launch_stellaris.py` (Steam, pid 9932, main
menu), one session. The Windows host ran the launcher, scp/`Get-FileHash`/`Get-Process`/`Get-Content`
and the two maintained probes; no debugger attach, no hook, no byte edit.

### 49.1 Task 5: init works in the game

`python C:\temp\c2_task5_init.py C:\temp\sqjs_s48live.dll`, verbatim key lines:

    [task5] C2Sanity == 42, game alive → init dispatch authorized
    [task5] poll: witness g_diag_log: readable at 83.4ms, text 'enter heap_ok alloc_ok free_ok new_rt MmMmMmMmMmMmMmMmrt=00000001EE8C59D8 opaque'
    [task5] poll: stop: text complete, 158 bytes in view at 84.1ms
    [task5] poll: exit code = 0 (thread had returned); process exit code = 0x103, thread returned while process alive = True
    [task5] C2DiagQJSInto rc = 0
    [task5] C2Init rc = 0
    [task5] C2Init rc == 0, game alive
    [task5] g_test_rt  = 0x00000001ee8c7118
    [task5] g_test_ctx = 0x00000001f0f7a758

The witness text continues past the §42 stop (`new_rt MmMmMm`) through eight closed `M`s,
`rt=` non-NULL, `opaque_ok limits_ok new_raw RFraw_ok new_diag RFFFRFRFdiag_rc=0 ctx=…` — in 83 ms,
not a multi-second freeze. `process exit code = 0x103` is `STILL_ACTIVE`; the thread returned while
the process was alive. Both pointers are real 64-bit values read through `C2QuickJSPointersInto`.

**The disk log exists now.** `C:/temp/c2_diag_9932.log` (absent before the dispatch) holds three
`rc=0` lines after the session — Task 5's `C2DiagQJSInto`, Task 5's `C2Init`, and Task 6's `C2Init` —
each identical in text to the buffer and witness channels. §38's "live shots never create it" is
resolved on this path.

### 49.2 Task 6: the acceptance gate passes

    $ python C:\temp\c2_task6_e2e.py C:\temp\sqjs_s48e2e.dll
    [task6] C2Init rc == 0, game alive
    Task 6: `1+1` evaluated inside the game process and returned int32 2 (rc=11 = 2*4+3)

`rc=11` is the fixed encoding `n*4+3` for `n=2` (ruling P20), read through the remote thread's exit
code from the DLL's own `JS_Eval`. The guard case, in a second module copy of the same bytes:

    $ python C:\temp\c2_task6_e2e.py --noinit C:\temp\sqjs_s48e2e_noinit.dll
    Task 6 (Step 6): C2EvalProbeOnePlusOne returned 0 with no C2Init in this module copy → the !g_test_ctx guard holds and did not crash

`Get-Process stellaris` after every dispatch: pid 9932, `Responding=True`. No death, no teardown
window, no `SuspendThread gle=5` signature.

### 49.3 What this settles and what it does not

- (§42/§47 mechanism, closed) The live death was our own artifact's fallback `offsetof`; with the
  builtin in place the same entry order reaches `rt=`, completes the diag sequence, and returns
  `rc=0` in the game, not only in the zero-game child.
- (Task 5, closed) `C2Init` returns 0 with non-NULL `g_test_rt`/`g_test_ctx` in the injected module.
- (Task 6, closed) `1+1` is evaluated by QuickJS inside the game process and read back as int32 2;
  the no-init guard returns 0 without crashing.
- (§38 open item, closed on this path) The on-disk diag file is produced.
- **(Not closed)** This is the main menu: no scene load, no mod script evaluation, no
  `CEffect::Execute`. The keyword→JS routing layer (C3) and a visible new effect (C4) are untouched.
  The session leaks one QuickJS runtime per extra module copy (the known `C2TestQuickJS` reset
  without free); it did not affect the observations. No detour was installed, so the
  `ExecHookVerify != 0` unloading rule was not in play; the game was left running.

### 49.4 Counts for §49

1 game launch (Steam + launcher), 1 session, 1 injected game process (pid 9932); 3 module copies of
the same bytes (Task 5, Task 6, Task 6-noinit); 5 dispatches (`C2DiagQJSInto` ×1, `C2Init` ×2,
`C2EvalProbeOnePlusOne` ×2 — the Task 6 pair includes the noinit call); 3 `rc=0` lines in the disk
log; 0 debugger attaches, 0 hooks, 0 byte edits, 0 game-file changes; 1 new evidence log.
