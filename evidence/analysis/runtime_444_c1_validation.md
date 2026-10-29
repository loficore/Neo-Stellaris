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

---

## §50 — the seven unexercised `container_of` sites, exercised live

### 50.1 What §48 left untested, and the probe built for it

§48 removed UBSan instrumentation from eight fallback `container_of` expressions. Only
`js_rc` (quickjs.c:1494) was on the §49 path; the free/realloc/usable-size sites
(1601/1607, 1645/1651/1684, 1704/1711) never ran under any live probe. §50 adds one
fixed stress script and one export rather than a general evaluation API (P21/C3 stays
deferred):

    src/dll/quickjs/quickjs_wrapper.c   c2_stress_script[]; C2EvalStress() = C2EvalProbe(script)
    src/dll/exports.zig                 C2EvalStressOne() -> same n*4+3 encoding
    src/dll/quickjs/c2_diag_test.zig    native test calling C2EvalStress directly
    scripts/test_c2_harness.py          "C2EvalStressOne" added to the known-export tuple

The script (8 rounds of 2000 string concatenations, 4000 object pushes and one
`JSON.stringify`) drives string-builder/array growth through `js_realloc2` →
`js_realloc_rt` → `__js_realloc` + `__js_malloc_usable_size`, and per-round refcount
drops through `__js_free`. Its value uses only lengths, integer digits and insertion
order, so 15904 was computed independently with Node; the native test pins rc 63619.

### 50.2 Offline gate before the shot

    artifact sha256  938b6e15e0759d4fd8f5d47ae921550adeb3e5b762a17a2d6497a97a8fcd7777
    zig build test   24/27 steps succeeded (1 failed); 315/315 tests passed
                     (the 1 failure is the known exports.zig kernel32 Linux link fact)
    Python fences    163 passed
    PE export        C2EvalStressOne rva=0x44d800; C2Init rva=0x44dbc0

The artifact was deployed as `C:\temp\sqjs_s50.dll`; the remote `Get-FileHash` matched
the local sha. Same game session as §49 (pid 9932, main menu, never restarted).

### 50.3 The live shot, twice

Run 1, verbatim key lines (em dash shown as the console renders it):

    [stress] pid=9932  dll=C:\temp\sqjs_s50.dll
    [stress] sqjs_s50.dll base (64-bit): 0x7ffc12da0000
    [stress] MZ header at base OK
    [stress] C2Sanity == 42, game alive — dispatch authorized
    [stress] C2Init rc == 0, game alive
    [stress] C2EvalStressOne rc = 63619 (expected 63619)
    [stress] decoded n = 15904; host alive after the churn

Run 2 (same artifact bytes, fresh module copy, probe renamed out of the `c2_*` family
to satisfy R-depth): identical line for line, `rc = 63619`, host alive. `Get-Process
stellaris` after both: pid 9932, `Responding=True`.

### 50.4 What this settles and what it does not

- (§48 fix, extended) The in-game result equals the independently computed expectation
  on an allocator-heavy churn, on the exact seven sites the fix removed instrumentation
  from. If any of them still aborted, the remote thread would have died with status 3
  and the host would be gone — the §45/§49 signature.
- (Determinism) Two module copies, one artifact, identical result — no dependence on
  allocator layout or ASLR base.
- **(Not claimed)** Per-call-site coverage. The script implies the realloc/usable-size/
  free paths from the vendored source; the run is not instrumented per site, so it
  cannot say each of the seven executed individually.
- **(Not claimed)** Anything beyond the main menu: no scene load, no mod script
  evaluation, no `CEffect::Execute`. C3 (keyword→JS routing) and C4 (visible effect)
  remain untouched, and caller-supplied JS text stays deferred (P21).

### 50.5 Counts for §50

1 game session (pid 9932, reused, never restarted); 2 injected module copies (one per
run); 6 dispatches (2 × [`C2Sanity`, `C2Init`, `C2EvalStressOne`]); 2 identical
deterministic results (`rc=63619`); 0 debugger attaches, 0 hooks, 0 byte edits, 0
game-file changes; 1 new evidence log (`evidence/logs/c2_live_stress_4_4_4.log`).

---

## §52 — the C4 execution path: predicate patch → DLL vtable → QuickJS, live

> 注意：§51 从未写出。commit `329f99e` 的消息把当时的工作记作 §51，但三卷分析里没有这一节；本节编号取 §52，不补写 §51。

### 52.1 Design basis (all [VERIFIED 4.4.4 STATIC])

C4 lets a C1-registered effect token leave the engine's own dispatch and execute
through a vtable the DLL owns. The plan was written from eight disassembly facts;
they are restated here so this volume no longer depends on the plan file (which
moved to the private plan archive).

1. **effect instantiate `0x3B01A0`.** The prologue reads `[ctx+0x38]`; `0xb`
   means the lexer path, which the probe must skip. The normal path `0x3B0322`
   looks the token up in the effect BST, `0x3B039D` calls `class_info.create`,
   and a non-NULL return jumps straight to `0x3B0984` — bypassing the
   `[ctx+0x278]==3` check, which only guards the create==NULL fallback at
   `0x3B08E2`. `0x3B0984` writes `[child+0x20]=token` and `[child+0x28]=name`,
   calls the predicate `[child_vptr+0x98](child, r9)`, and on true appends the
   child to the container at `[arg1+8]` and calls `[child_vptr+0x08](child, ctx,
   r9)`. The legal probe shape is therefore `0x3B01A0(parent, ctx, token, 0)`:
   `r9=0` makes the predicate return true at its first branch without
   dereferencing the parent.
   **Live correction:** the real event scope is not a valid parse context.
   `[ctx+0x30]` is read by the name builder `0x1D0C9F0`, and a live scope leads
   into its `[B+0x70] != 0` branch, which threw `std::length_error` (52.4 b).
   The probe passes a synthetic context and keeps the real self/ctx only as an
   environment gate.
2. **donor effect vtable `0x2606FE0`.** slot[0] `+0x00` = `0x1B4B30` (scalar
   deleting destructor); slot[1] `+0x08` = `0x3AFD30` (donor Execute override);
   slot[2] `+0x10` = `0x3B01A0` (instantiate helper, not Execute); slot[15]
   `+0x78` = `0x1596B0` (read again by the predicate); slot[19] `+0x98` =
   `0x3B1420` (predicate). Slots through `+0xC0` are valid function pointers,
   so copying **25 slots** (200 bytes) is a safe lower bound. 25 slots is not
   "through `+0x98`"; `0x98/8 + 1 = 20`.
3. **effect predicate `0x3B1420(child, parent)`.** `if (parent == 0) return true;
   x = child->[vptr+0x78](); if (x == 0) return true; return parent != x;` — it
   dereferences the parent only when it is non-zero. After the detour repoints
   `[child]`, that same call's `[+0x78]` goes through slot[15] of our copy, so
   the copy must include slot[15].
4. **predicate prologue.** 21 bytes:
   `48 89 5C 24 08 / 57 / 48 83 EC 20 / 48 8B FA / 48 8B D9 / 48 85 D2 / 74 25`
   (mov [rsp+8],rbx; push rdi; sub rsp,0x20; mov rdi,rdx; mov rbx,rcx;
   test rdx,rdx; je +0x25). The detour's 14-byte JMP takes the first 16 bytes
   (5+1+4+3+3), so the trampoline copies only position-independent instructions
   and the `je` at offset 19 stays in place; the fingerprint still pins all 21
   bytes and rejects any other build.
5. **recursive parse `0x3B0DB2`** calls `[child_vptr+0x08]` with `(child, ctx,
   [rbp+0x548])` — independent evidence that slot[1] is the virtual Execute
   entry. Base Execute `0x1D08520` is merely the default body for classes that do
   not override slot[1]; its internal `call [rax+0x10]` is a different slot.
6. **donor Execute `0x3AFD30(self, ctx, a3)` loops the ctx lexer.** Chaining it
   in the middle of an effect list would re-parse the outer list, so the live
   chain stays OFF; the chain path is proven only natively with a fake donor.
7. **trigger path differs.** `0x349AE0` reaches `[vptr+0x28]`, not `+0x08`. C4
   does not touch triggers.
8. **base Execute runs ~5,300 times/s** in a running campaign (§10). The probe
   polls a bounded window; `fired=0` there is an environment verdict (NO_FIRE),
   not a bridge failure.

### 52.2 Implementation

    src/dll/quickjs/quickjs_wrapper.c   C2ExecArmToken/C2ExecCall/C2ExecStats/
                                        C2ExecDisarmState — the C bridge. Fixed
                                        script `(function(v,p){return
                                        (v===<token>)?1504:-1;})`; the
                                        `typeof p === 'number'` guard was dropped
                                        (ruling P5: the typeof peephole's
                                        `OP_strict_eq << 24` trips UBSan in this
                                        Debug build). C2ExecCall reads
                                        `[self+0x20]`, compares it with the armed
                                        token, takes a non-blocking try-lock, calls
                                        JS, and records stats; budget 64.
    src/dll/c2/vtable.zig              25-slot copy of donor 0x2606FE0 into DLL
                                        `.data`; slot[1] = effectExecute, which
                                        forwards `C2ExecCall(token, ctx)` and
                                        chains to 0x3AFD30 only on rc==1 with
                                        chain explicitly enabled (default OFF).
    src/dll/c2/predicate_hook.zig      detour on 0x3B1420; 21-byte fingerprint;
                                        when `[child+0x20]` equals the armed
                                        token it repoints `[child]` at the DLL
                                        copy before calling the original
                                        predicate. Every other object keeps its
                                        donor vtable.
    src/dll/c2/live_probe.zig          detour on base Execute 0x1D08520 (through
                                        exec_hook): run the engine's own call
                                        first, then one synthetic
                                        0x3B01A0(parent, ctx, token, 0) via
                                        cmpxchg; afterwards inert. Synthetic ctx
                                        (0x300 bytes; +0x30 -> A, A+8 -> B with B
                                        zeroed, +0x38=0) and a fake parent whose
                                        container at parent+8 is pre-sized
                                        (begin -> 16 qwords, capacity 16, size 0)
                                        so 0x22C4A0 stays on its fast path
                                        0x22C58B.
    src/dll/exports.zig                the eight C2Exec* exports; install order
                                        vtable -> predicate -> probe -> arm;
                                        cleanup ProbeUninstall -> ProbeVerify ->
                                        settle -> Disarm. Never FreeLibrary.
    scripts/c2_exec_probe.py           one-shot driver: module gate (C2Sanity==42),
                                        C1Run/C1EffectId, C2Init, install, bounded
                                        poll, cleanup, verdict on the live
                                        pre-disarm snapshot.

The C1 registration is the same one §24–§30 establish: trigger 68636 and effect
68637 are freshly minted tokens (`C1Run`), not official keywords.

### 52.3 The live shot

Artifact `stellaris_quickjs.dll` sha256 `da1e6bd5da38c25983015c2c5ecec0b3f52c60a4c42f0b6115dbf4ee260f290d`
(7,163,904 bytes), deployed as `C:\temp\sqjs_c4.dll`; the remote hash matched.
Game pid 15928, campaign loaded and unpaused, one module copy, one shot:

    [c4] C1 trigger_id=68636 effect_id=68637, game alive
    [c4] C2Init rc == 0, game alive
    [c4] C2ExecInstall(effect_id=68637) rc=0
    [c4] C2ExecProbeInstall rc=0
    [c4] C2ExecProbeUninstall rc=0
    [c4] C2ExecProbeVerify rc=0 (0 = base Execute bytes intact)
    [c4] C2ExecDisarm rc=0
    [c4] probe stats (live): armed=1 token=68637 calls=17 fired=1 ctx_skip=0
         invalid=0 instantiate_rc=0 patch_size=16 installed=1 verified=-1
         vtable=1 chain=0 pred_installed=1 pred_calls=1 pred_patched=1
    [c4] c bridge stats (live): armed=1 token=68637 budget_left=63 calls=1
         skip=0 busy=0 js_calls=1 js_ok=1 js_err=0 mismatch=0 last_rc=1
         last_token=68637 last_value=1504
    VERDICT: ok
    EXIT=0

(The lines are wrapped here; the verbatim transcript, byte for byte apart from
the cp936 em dash, is in `evidence/logs/c2_exec_probe_4_4_4.log`.) The host was
alive after the run: `Get-Process stellaris` -> Id 15928, `Responding=True`,
started 2026-10-23 08:51:57.

What ran, in order: the engine's own instantiate of some live effect called our
base-Execute detour; our probe let the engine finish, then synthesized one
instantiate of 68637; `0x3B01A0` hit the effect BST, donor `create` returned the
hidden_effect child, the predicate detour saw `[child+0x20]==68637`, repointed
`[child]` at the DLL's 25-slot copy, and the original predicate returned true;
`0x3B0984` appended the child and called slot[1]; `effectExecute` read the token,
the C bridge matched it and called the armed JS function; JS returned 1504 on the
first and only call. `budget_left=63` shows the single call consumed one of 64.
`C2ExecProbeVerify rc=0` shows the base-Execute bytes were restored;
`C2ExecDisarm rc=0` shows both hooks came down, and its zeroing of the bridge
token is why the post-cleanup read shows `armed=0 token=0`.

### 52.4 Failed attempts and crash analysis

(a) **Environment, twice** (pids 12764 and 9484). The probe installed cleanly but
`calls=0`: base Execute never ran because the session sat in the main menu or
was paused. The driver reported `no_fire` and the shot was retried in a fresh
game process per the one-shot rule. This is the fact behind design basis 8.

(b) **A real event scope is not a parse context** (pid 15576, 2026-10-23
07:10:52). The first version passed the live `ctx` straight to `0x3B01A0`. The
host died with `std::length_error`: the dump's `ThrowInfo` resolves to
`.?AVlength_error@std@@`, and its frames pin `0x3B0995` (inside `0x3B01A0`,
after the name lookup returned) and `0x1D0CCF3` (inside `0x1D0C9F0`'s
`[B+0x70] != 0` branch, after the call to `0x15F420`). The subsequent
`CreateRemoteThread` failures (`gle=5`) are the §44/§45 dead-thread signature,
not a second fault. Full-function review of `0x3B01A0..0x3B0DC7` shows the hit
path reads only `[ctx+0x38]` (prologue) and `[ctx+0x30]` (name builder); the
other ctx reads (`[ctx+0x278]`, `[ctx+0x48]`) belong to the create==NULL
fallback and the predicate-false error path. Fix: the synthetic context, with a
zeroed B so the builder takes its safe branch. Cost of the ruling: evidence is
"official dispatch path under a synthetic parse ctx", not "the game's real parse
ctx"; an unaudited ctx read on the hit path would have cost one more process,
which the full disassembly review ruled out and the shot confirmed.

(c) **The container is not a bare vector** (crash at 2026-10-23 07:47:32,
`stellaris_20261023_074732` minidump, 63,461,304 bytes). With the synthetic
ctx in place the host faulted at `stellaris.exe+0x22C55F`, the instruction
`call qword ptr [rax+0x18]` in `0x22C4A0`'s grow branch, with `rax=0`. The fake
parent's container (`parent+8`) had size == capacity == 0, so the append took the
grow branch and called a zero vptr. `0x22C4A0`'s layout is `+0x00 vptr`,
`+0x08 begin`, `+0x10 capacity (u32)`, `+0x14 size (u32)`; when
`size != capacity` it takes the fast path `0x22C58B`, which reads only those
fields. Fix: pre-size the container (begin -> a 16-qword buffer, capacity 16,
size 0). A native test pins size==0, capacity > size, capacity >= 2, and that
the first write lands at begin. No engine memory is touched; the container is
probe-private and the engine never owns it.

(d) **The chain worked, the driver judged the wrong snapshot** (pid 11648). The
first complete chain returned `js_ok=1`/`last_value=1504`/`pred_patched=1`, but
the driver's `finally` re-read the bridge stats after `_cleanup()` and
`C2ExecDisarm` zeroes the bridge `token`, so the assertion
`c bridge token 0 != effect_id 68637` aborted a successful shot. A second race:
the probe flips `fired` before `instantiate()` returns, so a poll read can stop
with `js_calls==0`. Fixes (`72a855d`): `contract_errors` judges the live
pre-disarm snapshot, and `poll_done` waits for `fired==1 && js_calls>=1`. Both
fixes were written test-first (RED -> GREEN, 14 host tests).

### 52.5 What this settles and what it does not

Settled live:

- A token minted by our C1 registration travels the engine's own `0x3B01A0`
  instantiate path — BST lookup, donor `create`, token/name write — not a
  hand-rolled call into `create`.
- The predicate detour patches exactly the armed object (`pred_patched=1`) and
  the original predicate still returns the engine's answer.
- Execution lands on the DLL's 25-slot donor copy, slot[1] reaches the C bridge,
  and QuickJS returns the sentinel (`js_ok=1`, `js_err=0`, `mismatch=0`).
- The base-Execute bytes are restored (`C2ExecProbeVerify rc=0`), both hooks come
  down (`C2ExecDisarm rc=0`), and the host survives.

Not claimed:

- **No visible gameplay effect.** The JS function returns 1504; nothing in the
  game state changes.
- **The donor chain did not run live.** `chain=0` by design (design basis 6);
  the forwarding behavior is covered only by the native fake-donor test.
- **One object, one call.** `pred_calls=1`, `calls=1`; this is a one-shot
  existence proof, not a throughput or idempotence claim.
- **Patched objects are permanent.** `[obj+0]` points into the DLL's `.data`
  for the rest of the process, so the module must never be unloaded; no evidence
  here says anything about reloading the DLL.
- **Disarm is a byte restore, not a quiescence window.** `C2ExecDisarm` restores
  the 21-byte prologue and `detour.removeHook` frees the trampoline; a thread
  already inside the detour just before the restore can return into freed
  trampoline memory. `SETTLE_S=2` narrows that window but does not close it.
  The driver's one-shot contract is what makes this acceptable: the next shot
  starts from a fresh game process. Do not treat arm/disarm as reusable in a
  live campaign without suspending the effect threads first.

### 52.6 Remaining boundary

仍待做 = 把 chokepoint 分数接进 wrapper. The data source is ready
(`evidence/xrefs/chokepoint_scores_4_4_4.tsv`); what remains is the wiring that
reads a score in JS and turns it into a per-system effect (for example an
`add_modifier`-shaped change) instead of the sentinel. C4's stated goal — a
visible effect — stops exactly at that boundary: the execution path is proven,
the payload is not written.

### 52.7 Counts for §52

6 game processes (two `no_fire`, two host deaths, one driver abort, one `ok`).
The artifact of record above is the hash-pinned DLL of the successful shot
(remote `Get-FileHash` before and after); the driver-abort run (pid 11648) used
the same DLL bytes with the pre-`72a855d` driver, and the two crash attempts
predate the fixes inside the artifact, so they did not run these bytes. 1
successful shot; the successful run made 9 named dispatches (`C2Sanity`,
`C1Run`, `C1EffectId`, `C2Init`, `C2ExecInstall`, `C2ExecProbeInstall`,
`C2ExecProbeUninstall`, `C2ExecProbeVerify`, `C2ExecDisarm`) plus the stats
read-backs; 0 debugger attaches, 0 game-file edits, 0 changes to game data;
2 host deaths, both triggered by the probe's own inputs: (i) a real event
scope used as the parse ctx raised `std::length_error` inside `0x3B01A0`;
(ii) a fake parent container with size==capacity sent artifact code down
`0x22C4A0`'s grow branch, which called a null vptr at `0x22C55F` — a fault in
DLL-owned probe code on synthetic input, removed by the pre-size fix. Both were
diagnosed from Windows `exception.txt`/minidump data, not the project's
zero-game repro tooling. 1 new evidence log
(`evidence/logs/c2_exec_probe_4_4_4.log`).

---

## §53 — C4 取证:base Execute 的 arg2 与 effect 应用入口(2026-10-23)

### §53.1 base-Execute 直接调用点普查(离线)

重生成命令(未使用 `NS_STELLARIS_EXE` 覆盖,走脚本默认游戏路径):

```bash
python3 scripts/fastcalls.py 0x1d08520 --top 40
# 62 direct code sites to 0x1d08520 in .text
# in 28 functions
# wrote evidence/xrefs/callers_0x1d08520_buckets.tsv
```

该 TSV 为 header + 28 行,`sites` 列合计 62 个直接调用点。逐站点结果落在
`evidence/xrefs/exec_frame_callers_4_4_4.tsv`(header + 62 行):列
`func_start / func_end / caller_count / src_files / site / rdx_origin / evidence`,
`rdx_origin` 的取值域为 `stack|incoming_arg|global|other|unresolved|not_examined`。

| `func_start..func_end` | sites |
|---|---|
| `0x24ab30..0x24d4c5` | 16 |
| `0x720350..0x723674` | 8 |
| `0x69e100..0x69e70c` | 4 |
| `0xdcdca0..0xdce3a0` | 3 |
| `0xdef440..0xdf06a8` | 3 |
| `0x6c32e0..0x6c38e7` | 2 |
| `0x7ebe60..0x7ec22a` | 2 |
| `0x7f67f0..0x7f6c0f` | 2 |
| `0x7ff6c0..0x7ffb09` | 2 |
| `0xb34360..0xb345c0` | 2 |
| `0x31cb70..0x31d738` | 1 |
| `0x665810..0x665b8b` | 1 |
| `0x6965c0..0x696ddc` | 1 |
| `0x6be150..0x6be23c` | 1 |
| `0x7d57c0..0x7d649f` | 1 |
| `0x7f3200..0x7f3305` | 1 |
| `0x813ea0..0x814f68` | 1 |
| `0x87e9c0..0x87ebbd` | 1 |
| `0x92f6e0..0x92fb0c` | 1 |
| `0x9473f0..0x94827c` | 1 |
| `0x9aad50..0x9aae1d` | 1 |
| `0xbdb880..0xbdd151` | 1 |
| `0xcc8bd0..0xcca75f` | 1 |
| `0xd05820..0xd068bd` | 1 |
| `0xe84100..0xe845ff` | 1 |
| `0xe8a800..0xe8a8ef` | 1 |
| `0xe8aa90..0xe8ace5` | 1 |
| `0x1bcd120..0x1bcd227` | 1 |
| **total** | **62** |

本次共打开 13 个窗口(10 个 ≥2 站点桶的首站点 + `0x1bcd120` / `0x813ea0` / `0x9473f0`),
实际判读 **17 个站点**:`incoming_arg` 12、`other` 5、`stack` 0、`global` 0、`unresolved` 0;
其余 45 个站点保持 `not_examined`。判读口径:取调用前最后一次写 `rdx` 的指令;源寄存器若在
函数入口由 `rdx` 赋值后、到该站点之前没有再次被写,记 `incoming_arg`;否则记 `other`
(5 例都是「`rdi` / `r13` / `r14` 在函数内被复用过」,不是没看到写点)。

逐字窗口摘录(均来自 `scripts/disrva.py <site-0x40> 0x100`;第二个参数必须 >0xFF 才是字节长度):

```asm
; 0x69e1dd..0x69e1e9 — rbx 自入口 rdx 赋值后未再改写
  0069e1dd  mov     rdx, rbx
  0069e1e0  lea     rcx, [rbp - 0x20]
  0069e1e4  cmp     r8, r14
  0069e1e7  jne     0x14069e1f0
  0069e1e9  call    0x141d08520  ; -> 0x1d08520

; 0xdcde9f..0xdcdea7 — 同形转发
  00dcde9f  mov     rdx, rbx
  00dcdea2  lea     rcx, [rsp + 0x20]
  00dcdea7  call    0x141d08520  ; -> 0x1d08520

; 0x1bcd17a..0x1bcd18d — 经 r8 与 0x1d08520 比较后的直接/间接双路派发
  01bcd17a  mov     rdx, rbx
  01bcd17d  mov     r8, qword ptr [rax + 8]
  01bcd181  lea     rax, [rip + 0x13b398]  ; -> 0x1d08520
  01bcd188  cmp     r8, rax
  01bcd18b  jne     0x141bcd194
  01bcd18d  call    0x141d08520  ; -> 0x1d08520
  01bcd192  jmp     0x141bcd197  ; -> 0x1bcd197
```

本次没有在窗口里看到 `lea rdx,[rbp±X]` / `lea rdx,[rsp+X]` / `mov rdx,rsp` 形态的帧构造;
能定的只有「17 个已判读站点里 12 个把**自己的入口 arg2** 原样交给 base Execute,5 个是函数内
重载(`other`),没有一个站点构造新帧」。本普查**不**说明 arg2 的类型与字段语义;那要 §53.3 的实机链。

### §53.2 effect 应用入口候选

先复核 `0x3B01A0` 命中路径(逐指令窗口 `0x3b0960` / `0x3b0c2d` / `0x3b0db2` / `0x3b0300`):

```asm
; 0x3b0984..0x3b09da — 写 token/name，然后调谓词 slot[19]
  003b0984  mov     dword ptr [rsi + 0x20], r12d
  003b09ad  lea     rcx, [rsi + 0x28]
  003b09b4  call    0x14015f770  ; -> 0x15f770
  003b09d1  mov     rax, qword ptr [rsi]
  003b09d4  mov     rdx, r14
  003b09d7  mov     rcx, rsi
  003b09da  call    qword ptr [rax + 0x98]

; 0x3b0c2d..0x3b0c5d — 谓词为真：把 child 追加到 [arg1+8] 指向的容器，再走 slot[1]
  003b0c3f  mov     rcx, qword ptr [rbp + 0x530]
  003b0c46  add     rcx, 8
  003b0c4a  lea     rdx, [rbp + 0x538]
  003b0c51  call    0x14022c4a0  ; -> 0x22c4a0
  003b0c56  mov     rsi, qword ptr [rbp + 0x538]
  003b0c5d  jmp     0x1403b0db2  ; -> 0x3b0db2

; 0x3b0db2..0x3b0dc2 — ctx 自入口 r13 原样传给 child 的 slot[1]
  003b0db2  mov     rax, qword ptr [rsi]
  003b0db5  mov     r8, qword ptr [rbp + 0x548]
  003b0dbc  mov     rdx, r13
  003b0dbf  mov     rcx, rsi
  003b0dc2  call    qword ptr [rax + 8]
```

`0x3b0300` 窗口另证 effect BST 查找(`[[0x33746e8]+0x18]`)命中后 `call [rax+8]` @`0x3b039d`
是 **class_info.create** 的 slot[1],不是本节的 Execute 入口;非空返回跳到 `0x3b0984`。

`0x3B01A0` 的 10 个直接调用点(全部由 `pdata.py` 从函数起点开窗核过)形状一致:
入口先把 `rcx` 存 `rdi`、`rdx`(或 `rax`/`r10`)存下,用 `r8d` 做 token 比较,未命中时
fall-through 到 `call 0x3b01a0` — 即 `rcx = parent 对象`、`rdx = 调用方入口 ctx`、`r8d = token`。
例如 `0x17fed70` 的 `mov rax,rdx; mov rdi,rcx; cmp r8d,0x3f9e; je …; call 0x3b01a0`。
这 10 个函数本身是脚本 effect 的逐 token thunk(`0x17fed70` / `0x17ffa30` 的直接调用点普查为
**0** —— 只能经 vtable/函数指针到达),所以往上一层拿不到「frame 是怎么造的」。

四个候选的判定(判据 ① 能把 token 施加到某个 scope/frame;② 不重跑脚本文本;③ 参数可从
JS 侧数据(system id / scope 指针)得到;④ 从 DLL 里以普通函数指针可调,或其 vtable 派发可复现):

- **A(`0x3b01a0`,instantiate+append)** — ① 满足:token + 调用方 parent/ctx 即可让引擎自己
  instantiate、追加并调 child slot[1];② 满足:该函数不解析脚本文本;④ 满足:普通函数指针;
  ③ **缺**:parent 容器与 ctx 目前只能由调用方给,JS 侧还没有「system id → scope 指针」的映射。
  判 `unresolved`(缺 ③)。
- **B(`0x1d08520` slot[1] 直接 Execute)** — ④ 满足,但 ①/③ 缺:需要一个真实 frame,而 Task 1
  没有定位任何 frame 构造点(17 个已判读站点里 12 个转发入口 `rdx`、5 个是函数内重载)。判 `unresolved`。
- **C(帧构造点)** — 执行 shot 前判 `unresolved: frame factory not located`:13 个窗口、17 个已判读站点里
  12 个把调用方入口 `rdx` 原样转发、5 个是函数内重载(`other`);两个代表性 thunk 的 `fastcalls`
  都是 0 个直接站点。**§53.3 第二次 shot 后更正为 `located`**:实测帧 vptr `0x26e4fa8` 让离线扫描在 33 个
  函数里找到内联构造,其中 `0x1C750D0` / `0x1C3CED0` / `0x9EC290` 构造 0x20 字节帧后紧接着
  `call [self_vtable+8]`;构造是内联的,没有独立 factory(见 §53.4 Q5)。
- **D(`0x9f5750` family,event command path)** — 三个 handler 各只开一个 0x100 窗口;首窗口内
  都没有 `call 0x3b01a0`(最近的调用是 `0x1ca3320` / `0x1ca35d0` / `0xa804b0`)。判 `unresolved`:
  首窗口无 effect 执行痕迹,按计划不扩窗。

本节的 `selected` 只是**首选入口**;本次一个都没有 `selected`。§53.4 已用 §53.3 第二次 shot 的实测输入
复核:计划预设的 `X→S→id` 链被证伪(`X` 是 .rdata 的 vtable、`S` 是代码),候选 A/B/D 维持
`unresolved`,C 因实测 vptr 找到内联构造点、改记 `located(构造形状已知,可用性未证)`。

### §53.3 实机采样(2026-10-23,两次点名,两次 shot)

**授权。** 本会话有两次点名,各对应一次安装:第一次 shot 由「点名 Task 6,准备执行实机一枪」授权;
第一次 shot `no_calls`(环境)后,用户选「重开一枪」并写明「我已经退出了,执行当前任务」,第二次 shot 在
**新游戏进程** pid 2460 上执行。两次安装都发生在前一次已经 `Uninstall` 之后,没有在同一进程里
重复 install(第二次 install 会返回 -2,本计划也禁止)。

**产物(两次 shot 同一份字节)。** `zig-out/bin/stellaris_quickjs.dll` → `C:/temp/sqjs_scope.dll`,sha256
`cb95b0f2dd07cc4d10acf0b2f24664350e376f76aaef578dfe962c4b5387b4ba`;`scripts/c2_scope_probe.py` →
`C:/temp/c2_scope_probe.py`,sha256 `7cb62a25675a9877091ef05e1be4c5fdc34468e23e845adf67c4b57c5fbdb726`;
`scripts/c2_harness.py` → `C:/temp/c2_harness.py`,sha256 `0c8bca42a70ab9a2cf28bba6036de1d039ff30ec01dba93550a9af5ded485713`。
游戏 4.4.4;第一次 shot pid 6852(载入 `autosave_2229.01.01.sav` 的战役),第二次 shot pid 2460。

#### 第一次 shot(pid 6852):no_calls

**shot 的启动方式。** 与 §52 同因(OpenSSH 通道会杀掉子进程树):驱动由交互会话的一次性计划任务
`c4-scope-run`(动作 `C:\temp\c4_scope_run.cmd`,上次运行 **11:15:18**)执行,输出重定向到
`C:/temp/c4_scope_run.txt`(最后写入 **11:17:21**):

```bat
cd /d C:\temp
python C:\temp\c2_scope_probe.py C:\temp\sqjs_scope.dll --census C:\temp\exec_frame_callers_4_4_4.tsv --id-names C:\temp\descriptor_oracle_4_4_4.tsv > C:\temp\c4_scope_run.txt 2>&1
```

**逐字 transcript**(`evidence/logs/scope_probe_4_4_4.log`,1590 B,CRLF,sha256 `8e5b22a3…`;第 4 行
`game alive <A1 AA> dispatch authorized` 的两字节是 cp936 的 `—`(与 §52 日志同型)。下文按 LF 重排、
把这处原始字节写作 `\xA1\xAA`;字节级以日志文件为准):

```
[scope] pid=6852  dll=C:\temp\sqjs_scope.dll
[scope] sqjs_scope.dll base (64-bit): 0x7ff9f31f0000
[scope] MZ header at base OK
[scope] C2Sanity == 42, game alive \xA1\xAA dispatch authorized
[scope] LAYOUT entry=104 stats=56 ring=256 mask=511 version=1
[scope] C2ScopeProbeInstall rc=0
[scope] waiting: calls=0 samples=0 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=0 samples=0 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=0 samples=0 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=0 samples=0 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=0 samples=0 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=0 samples=0 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=0 samples=0 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=0 samples=0 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=0 samples=0 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=0 samples=0 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=0 samples=0 invalid_self=0 invalid_ctx=0
STATS: calls=0 samples=0 invalid_self=0 invalid_ctx=0 lexer=0 x_nonzero=0 patch_size=16 installed=1 verified=-1
CALLERS:
CHAIN:
[scope] entries=0 valid=0 lexer=0 chain_ok=0 distinct_vtables=0 ids=[]
[scope] wrote 0 rows to C:/temp/c4_scope_probe.tsv
VERDICT: no_calls
the detour saw no base-Execute call within the poll window. That is an ENVIRONMENT result, not a code verdict: load a running campaign and unpause the game, then rerun with a fresh game process.
[scope] C2ScopeProbeUninstall rc=0
[scope] C2ScopeProbeVerify rc=0 (engine bytes intact)
[scope] host alive
EXIT:1
```

**读回。** `C2ScopeProbeInstall rc=0`(布局五字 `104/56/256/511/1` 与驱动校验一致);轮询 11 次
全为 `calls=0 samples=0`;`CALLERS:` / `CHAIN:` 均空,`entries=0`;`wrote 0 rows`;
`VERDICT: no_calls`。`C2ScopeProbeUninstall rc=0`;**`C2ScopeProbeVerify rc=0`(engine bytes
intact)**;`host alive`(shot 后约 17 分钟复查:pid 6852 仍活,CPU 2787.6 s,WS 240 MB,重度分页)。
cmd 退出码 1 —— 驱动对非 `captured` 判 1。`C:/temp/c4_scope_probe.tsv` 只有表头,按字节拉回
`evidence/logs/scope_probe_4_4_4.tsv`(25 B,CRLF,sha256 `0a6b5977…`)。

**环境。** 采样窗口内游戏没有执行 effect。shot 前 ~11:02:19 用一次 Space 解除暂停(前后帧里
`暂停` 横幅消失,`pc_b.jpg` 11:02:21),但 shot 后 ~11:32:29 的原生分辨率(`ImageGrab`)截图显示
右上角时间面板处于**暂停**(⏸ + `暂停`,日期 **2229.02.09**),右下有首次接触事件窗
(`通讯已建立`,正文含「敌对行为已经暂时停止」);载入存档是 `autosave_2229.01.01.sav` ⇒
战役只推进了 1 个月 8 天就停表 —— 也就是说采样窗口开始前游戏已经停表(推断,不是采样证据)。
`calls=0` 与暂停一致,驱动据此判为环境结论。

**结论。** 没有样本 ⇒ 没有 `ctx_words` 分布、没有调用点 join、没有链 id。不重试同一进程;
重开要求**新游戏进程 + 新点名** —— 该项已在第二次 shot 执行。

#### 第二次 shot(pid 2460,新游戏进程):captured

**shot 的启动方式(无控制台)。** SSH 会话会杀掉子进程树,`cmd` 包装又会抢焦点,所以探针由一个无控制台
启动器拉起:一次性计划任务 `c4-shot2` 的动作是 `pythonw.exe C:\temp\c4_shot_launcher.py`,启动器
用 `subprocess.CREATE_NO_WINDOW`(0x08000000)运行

```
python -u C:\temp\c2_scope_probe.py C:\temp\sqjs_scope.dll --census C:\temp\exec_frame_callers_4_4_4.tsv --id-names C:\temp\descriptor_oracle_4_4_4.tsv
```

并把 stdout/stderr 重定向到 `C:/temp/c4_scope_run.txt`。任务上次运行 **11:54:54**,退出码 0。
shot 前和窗口内各发过一次 Space(计划任务 `c4-unpause`,11:54:32 与 11:55:21,pid 2460,两次 rc=0)。
轮询窗口 120 s,每 10 s 打印一行进度;本地拉回 `/tmp/c4_scope_run.txt` 的时间是 11:57:22。

**逐字 transcript**(`evidence/logs/scope_probe_4_4_4_run2.log`,3507 B,CRLF,sha256 `01697d66…`;
第 4 行 `game alive \xA1\xAA dispatch authorized` 的两字节是 cp936 的 `—`。下文按 LF 重排、
把这处原始字节写作 `\xA1\xAA`;字节级以日志文件为准):

```
[scope] pid=2460  dll=C:\temp\sqjs_scope.dll
[scope] sqjs_scope.dll base (64-bit): 0x7ffa14eb0000
[scope] MZ header at base OK
[scope] C2Sanity == 42, game alive \xA1\xAA dispatch authorized
[scope] LAYOUT entry=104 stats=56 ring=256 mask=511 version=1
[scope] C2ScopeProbeInstall rc=0
[scope] waiting: calls=0 samples=0 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=596 samples=1 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=1108 samples=2 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=1108 samples=2 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=1108 samples=2 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=1108 samples=2 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=333873 samples=652 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=334925 samples=654 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=335953 samples=656 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=337001 samples=658 invalid_self=0 invalid_ctx=0
[scope] waiting: calls=338032 samples=660 invalid_self=0 invalid_ctx=0
STATS: calls=339118 samples=662 invalid_self=0 invalid_ctx=0 lexer=0 x_nonzero=13 patch_size=16 installed=1 verified=-1
CALLERS:
  site=0xde0539 count=40 func=- origin=-
  site=0x298a43 count=39 func=- origin=-
  site=0x33ca60 count=21 func=- origin=-
  site=0x33d4c7 count=16 func=- origin=-
  site=0xddcf24 count=14 func=- origin=-
  site=0xe9b5ed count=8 func=- origin=-
  site=0x1d08575 count=8 func=- origin=-
  site=0xde41ae count=7 func=- origin=-
  site=0xe58db1 count=6 func=- origin=-
  site=0x1c43699 count=6 func=- origin=-
  site=0x29a913 count=5 func=- origin=-
  site=0xcc9634 count=5 func=- origin=-
  site=0xcc9cae count=5 func=- origin=-
  site=0xde41ea count=5 func=- origin=-
  site=0xe845a7 count=5 func=0xe84100 origin=not_examined
  site=0xe9b5b7 count=5 func=- origin=-
  site=0xe9b5d2 count=5 func=- origin=-
  site=0x1bcd18d count=5 func=0x1bcd120 origin=incoming_arg
  site=0x30c033 count=4 func=- origin=-
  site=0xcc9d61 count=4 func=- origin=-
  site=0xe9b608 count=4 func=- origin=-
  site=0x84e85c count=3 func=- origin=-
  site=0xcc8c5a count=3 func=- origin=-
  site=0xcca278 count=3 func=- origin=-
  site=0xde418d count=3 func=- origin=-
  site=0xde41cf count=3 func=- origin=-
  site=0xe84146 count=3 func=- origin=-
  site=0xe96ebb count=3 func=- origin=-
  site=0xe9b71f count=3 func=- origin=-
  site=0xe9b7b1 count=2 func=- origin=-
  site=0x28b46f count=1 func=- origin=-
  site=0x28c8cf count=1 func=- origin=-
  site=0x29100f count=1 func=- origin=-
  site=0x29b34f count=1 func=- origin=-
  site=0x29fabf count=1 func=- origin=-
  site=0x396574 count=1 func=- origin=-
  site=0x3965e4 count=1 func=- origin=-
  site=0x92f999 count=1 func=- origin=-
  site=0x959057 count=1 func=- origin=-
  site=0x96e64b count=1 func=- origin=-
  site=0xcc9400 count=1 func=- origin=-
  site=0xcca08f count=1 func=- origin=-
  site=0xdd6286 count=1 func=- origin=-
CHAIN:
  ctx=0x7fe768 ok=1 x=0x7fe760 s=0x7ff7d7c35872 vptr=0x18408b4818488d48 id=683967304 name=- object=0xea14e80860ff4828
  ctx=0x7fed78 ok=1 x=0x7ff7d82dc6d7 s=0x8890ffcb8b48038b vptr=0x0 id=0 name=- object=0x0
[scope] entries=256 valid=256 lexer=0 chain_ok=2 distinct_vtables=38 ids=[(0, '-', 1), (683967304, '-', 1)]
[scope] wrote 47 rows to C:/temp/c4_scope_probe.tsv
VERDICT: captured
[scope] C2ScopeProbeUninstall rc=0
[scope] C2ScopeProbeVerify rc=0 (engine bytes intact)
[scope] host alive
EXIT:0
```

**读回。** 布局五字 `104/56/256/511/1`;`C2ScopeProbeInstall rc=0`;`STATS` 为
`calls=339118 samples=662 invalid_self=0 invalid_ctx=0 lexer=0 x_nonzero=13 patch_size=16 installed=1 verified=-1`
—— 662 = ⌊339118/512⌋,与 1/512 采样门一致;`verified=-1` 是安装期间的正常值(指纹必然不匹配)。
`entries=256 valid=256`、`distinct_vtables=38`、`chain_ok=2`、`wrote 47 rows`(=43 caller + 2 id + 2 chain)。
`C2ScopeProbeUninstall rc=0`;**`C2ScopeProbeVerify rc=0`(engine bytes intact)**;`host alive`;`EXIT:0`。
复查 pid 2460 仍活(WS ~332 MB)。TSV 按字节拉回 `evidence/logs/scope_probe_4_4_4_run2.tsv`
(1817 B,CRLF,sha256 `419edaf7…`,11:57:27 写)。

**环境。** `calls>0` 且 339,118 次基执行本身就证明窗口内游戏在跑 effect,不需要截图证据。窗口内
`calls` 有一次平台期(连续四次轮询停在 1108),之后恢复;第二次 Space 恰好落在平台期附近,但窗口内
没有截图,故不把平台期写成「暂停」的证据 —— 它不影响 `captured` 的有效性。

**只读补抽。** 驱动的 transcript 只有 `CHAIN` 聚合,没有 `ctx_words`。为了不再装一次 detour,在同一
进程上用只读导出补抽:`C2ScopeProbeStatsInto` + `C2ScopeProbeDrainInto`(drain 不清 ring),再用
`ReadProcessMemory` 跟随指针。两个一次性探针在 `scripts/scratch/2026-10_c4_live/`
(`c4_ring_dump.py` / `c4_ctx_probe.py`,不进 git;本卷按 basename 记录出处),产物按字节拉回:
`evidence/logs/scope_probe_4_4_4_run2_ring.txt`(1656 B,sha256 `db8a3459…`,12:00:12 写)与
`evidence/logs/scope_probe_4_4_4_run2_ctx.txt`(1350 B,sha256 `78c1aeea…`,12:01:49 写)。
这一步没有 install、没有 reset、没有新增 detour 次数。

**8 个 qword 的分布(256 条 ring,全部 valid)。**

| `ctx+` | 零 / 非零 | 取值 |
|---|---|---|
| `+0x00` | 0 / 256 | 全部 `0x7ff7d9f84fa8`,即 RVA `0x26e4fa8` |
| `+0x08` | 5 / 251 | 高 32 位以 `0x7ffa0000` 为主;低 32 位 `3`:55、`5`:52、`1`:52、`4`:34 |
| `+0x10` | 0 / 256 | 长命 ctx `0x1c4d3c410`:245;两个瞬态 `0x7fe960`:7、`0x7fef70`:4 |
| `+0x18` | 245 / 11 | `0x199b50001`:7、`0x1ed110001`:4 |
| `+0x20` | 245 / 11 | `0x100000385`:4、`0x3293`:2、`0x328f`:2 |
| `+0x28` | 0 / 256 | `0x4d`:245;`0x1`:7;`0x1ed119de0`:4 |
| `+0x30` | 245 / 11 | 全部 `0x7ff7d9d1b098`(RVA `0x247b098`) |
| `+0x38` | 0 / 256 | `0x7ff7d9a23ea5`:245;另 3 个各 1 |

`distinct_ctx=3`:0xee7fd00 ×245、0x7fe768 ×7、0x7fed78 ×4。每个 ctx 首条样本的 8 个字:

```
0xee7fd00 x=0 words=0x7ff7d9f84fa8 0x7ffa00000003 0x1c4d3c410 0x0 0x0 0x4d 0x0 0x7ff7d9a23ea5
0x7fe768  x=1 words=0x7ff7d9f84fa8 0x0 0x7fe960 0x199b50001 0x3293 0x1 0x7ff7d9d1b098 0xd37b41b0
0x7fed78  x=1 words=0x7ff7d9f84fa8 0x100000001 0x7fef70 0x1ed110001 0x100000385 0x1ed119de0 0x7ff7d9d1b098 0x19547ab0
```

`SELF_TOKEN_ID`(self+8 的 u32)前四:0×104、0xd9da97f8×39、1×11、0xd9d53690×10;`self_vtable` 38 个
不同,前四 0x250e4b0×40、0x25097c0×39、0x24b3690×31、0x24b3050×31。

**链证伪(两重证据)。** 驱动把 `X=[ctx+0x30]` 当对象指针、`S=[X+8]` 当对象、`[S+8]` 当 id、`[S+0x20]`
当 object。第二次 shot 证明这条链不成立:

1. **内容**:X = 0x7ff7d9d1b098,即 RVA `0x247b098`(.rdata)。离线读该处 8 个 qword:
   `0x140170690 / 0x1401706f0 / 0x140156540 / 0x140156570 / 0x1401601e0 / 0x141d08520 / 0x14032db40 / 0x140535070`。
   `X+0x00` 是一个类的内联构造/删除函数(它把 `[rcx]` 写成 `0x247b098`,删除时 `operator delete(rcx, 0x18)`),
   `X+0x08` 是普通函数 `0x1706f0`(首字节正是 `push rsi; sub rsp,0x20; mov eax,[rcx+0x14]`),
   `X+0x28` 是 base Execute 自己、`X+0x38` 是 §28.5 那个属性 getter `0x5350D0` ⇒ **X 是 vtable,不是对象**。
   于是 S=0x1706f0 是**代码地址**:`S[0]=0x418b20ec83485640`、`S+8=0x7410413bf18b4814`、
   `S+0x20=0x20c4834810468908` 全是指令字节;驱动报的「id=683967304(0x28c48348)」是 `add rsp,0x28`,
   「object=0x20c4834810468908」是 `mov [rsi+0x10],ecx; add rsp,0x20`。`descriptor_oracle` 对这两个 id
   都返回 `-`,因为它们本来就不是 id。
2. **范围**:arg2 的类大小是 **0x20 字节**(删除析构器 `0x1D10EA0` 以 `(rcx, 0x20)` 调 sized delete,
   同时把 `[rcx]` 写回 `0x26e4fa8`)。字段止于 `+0x19`;`+0x20..+0x38` 是**对象之外**的相邻内存。
   所以 `X=[ctx+0x30]` 按构造就不可能是 arg2 的字段 —— 两个瞬态 ctx 的 `+0x30` 恰好落在栈上另一个
   0x18 字节对象的 vptr 上(见下节),长命 ctx 的 `+0x30` 落在相邻堆内存 0。**这条链在模型层就死了,
   不是「值不好看」。**

**transcript 里的 CHAIN 行是过期读数。** 驱动的 `follow_chain` 在 120 s 轮询**之后**才重读
`[ctx+0x30]`(而不是用 ring 快照),此时两个瞬态栈帧已被回收:transcript 记的是 `x=0x7fe760` 与
`x=0x7ff7d82dc6d7`(后者还没对齐),而 ring 快照两个 ctx 都是 `0x7ff7d9d1b098`。补抽以 ring 快照为准;
这条驱动缺陷记进 ledger,本计划是纯取证,不改驱动。

**调用点 join。** 43 个不同站点。`site = return_rva - 5` 的口径对 5 字节 `call rel32` 恰好是调用起点,
对 3 字节 `call [rax+8]` 会落在**调用起点前 2 字节**。前四:0xde0539(40)、0x298a43(39)、0x33ca60(21)、
0x33d4c7(16);四个都已核过是 `mov rax,[self]; ...; call [rax+8]` 的 slot1 派发。只有两个站点 join 上
§53.1 的 62 站点普查:`0xe845a7`(func 0xe84100,`not_examined`)与 `0x1bcd18d`(func 0x1bcd120,
`incoming_arg`,§53.1 已读过的 devirtualization guard)。另有 8 条样本的站点是 `0x1d08575` = base Execute
内部 `call [rax+0x10]`(`0x1d08577`,3 字节)前 2 字节 ⇒ **递归派发本身被采到了**。其余 41 个站点不在
直接调用普查里 ⇒ 这一场景的基执行绝大多数经 vtable slot1 间接到达,§53.1 的 62 个直接站点只是少数路径。

join 带出的唯一未判读函数 `0xe84100` 也补读完了:`lea rcx,[rsp+0x20]; mov rdx,rdi; call 0x1d08520`,
循环体 `add rbx,0x110`,循环后 `dec dword [rdi+8]` —— 调用方和 base Execute 动的是同一个 `+8` 深度字段,
而且 rcx 是一个**栈上对象**。这正是下节帧构造点的一类。

**离线跟进:帧类与构造点。** 从 vptr `0x26E4FA8` 出发扫 `.pdata` 函数(离线,只用 `riprefs.py` /
`pdata.py` / `disrva.py`):

- 该 vtable 只有 1 槽(slot0 = `0x1D10EA0` 删除析构器,对象大小 0x20),槽后紧接着 .rdata 的字符串。
- 33 个函数含 `lea`→该 vtable 的引用;30 个把 vptr 写进栈上的局部对象;至少 8 个在构造后用
  `rdx=&frame` 调 `call [self_vtable+8]`(7 个落在 60 条指令窗口内,`0x1C3CED0` 更远、手工读通)。
  构造是**内联**的,没有独立工厂函数。
- 三个完整读通的样板:
  - `0x1C750D0`:helper 就地构造在 `rsp+0x50`,帧在 `rsp+0x30`(`[+8]=0`、`[+0x10]=helper`、
    `[+0x18]=sete`、`[+0x19]=0`),`lea rdx,[rsp+0x30]; mov rcx,rbx; call [rax+8]` 在 `0x1C75138`。
  - `0x1C3CED0`:helper 先 `new(0xa0)` 再用 `0x1CA5880` 构造;帧在 `rsp+0x38`(`[+0x19]=1`),
    slot1 调用在 `0x1C3D5B5`。同一函数的 `rsp+0x90` 还就地构造了一个 **0x18 字节、vptr 0x247b098**
    的对象作为 helper 构造参数 —— 这正是 ring 里 `X` 的来源形态。
  - `0x9EC290`:vtable 引用是 0x18 字节辅助对象的构造;0xa0 helper 被改写 vptr 为 `0x25243A8`,
    帧的 `[+8]` 先写 0 再改写为 **`0xffffffff`**,然后对 `[0x3260BB0]` 的全局实例调 slot1。
    base Execute 的 `test eax,eax; js` 正好跳过负深度的 trace 前奏 —— `+8` 是**trace 深度**得到交叉印证。
- 三个构造器都只写 `[+8]` 的低 32 位;`+0x0c`、`+0x18` 的高 7 字节、`+0x1a..+0x1f` 都是未初始化残留。
  这解释了 ring 里的怪 qword:`+8` 的 qword = int32 深度 + 未初始化高 32 位(`0x7ffa0000` 在 193/251 条
  里重复出现,是栈/堆残留);`+0x18` 的 qword 里只有低两字节是构造器写的标志
  (`[+0x18] = helper+0x14 == 0`、`[+0x19] = 拥有标志`),其余是残留。
- 1 槽 vtable 意味着 arg2 **不是** CEffect 家族对象(没有虚 Execute);base Execute 只读写 `+8`,并把帧
  交给 `0x16FDC0` / `0x1D116A0` 两个 trace helper,它们只读 `[+0x18]` 与 `[+8]`(窗口内未见写
  `+0x0c`/`+0x10`)。这与「arg2 = 执行深度帧」一致,与「arg2 = CEventScope」不一致。

### §53.4 判定

**Task 6 已执行完毕**:两次 shot,第二次 shot `captured`(§53.3)。以下六条按计划要求逐条回答;标注「实测」的是
第二次 shot 直接观测,「实测→离线」是由实测值带出的离线新判读。

1. **arg2 是栈帧、堆对象还是引擎全局?** **实测→离线:调用方构造的执行帧,不是引擎全局。**
   256/256 条样本的 `[arg2+0]` 都是 `0x26e4fa8`;该 vtable 单槽(slot0 = `0x1D10EA0` 删除析构器),
   析构器以 `(rcx, 0x20)` 调 sized delete ⇒ 类大小 0x20。样本里 3 个实例:0xee7fd00 ×245
   (`+0x10` 指向 `0x1c4d3c410`,像堆对象)、0x7fe768 ×7 与 0x7fed78 ×4(都在栈上,`+0x10` 指向邻近的
   栈 helper)。离线在 `0x1C750D0` / `0x1C3CED0` / `0x9EC290` 读到内联构造:栈上放 0x20 字节帧、写 vptr、
   写 `+8` 深度、`+0x10`=helper、`+0x18/+0x19`=标志,然后 `rdx=&frame` 调 `call [self+8]`。⇒「栈帧」在
   C++ 局部对象意义上成立,但同一个类也有长命实例;它**不是** `CEventScope`,也不是全局单例。
2. **`[+8]` / `[+0x18]` / `[+0x30]` 各观测到了什么?`X` 在样本间是否恒定?** **实测。**
   `+8` = 执行(trace)深度:base Execute 对它 `inc`/`dec`;样本低 32 位以 1..5 为主,5/256 为 0
   (顶层调用);高 32 位未初始化,`0x7ffa0000` 残留占多数。`+0x18` = 两个标志字节
   (`[+0x18]=helper+0x14==0`、`[+0x19]=拥有标志`)+ 未初始化残留;256 条里 245 条为 0(长命 ctx),
   11 条为 `0x199b50001`/`0x1ed110001`(低两字节 `01 00`)。`+0x30` **不属于 arg2**(类大小 0x20,
   `+0x20..+0x38` 是相邻内存);`X` **不恒定** —— 245 条为 0,11 条为 `0x7ff7d9d1b098`(栈上相邻的另一个
   0x18 字节对象的 vptr);全窗口 `x_nonzero=13/662`。
3. **`X→S→id` 的 id 在 `descriptor_oracle` 里 join 到了什么名字?是不是 keyword 空间 id?**
   **实测:没有 id,链已证伪。** X=0x247b098 是 .rdata 的 vtable,S=0x1706f0 是代码;所谓 id/object
   都是指令字节(`0x28c48348` = `add rsp,0x28`;`0x20c4834810468908` = `mov [rsi+0x10],ecx; add rsp,0x20`);
   `descriptor_oracle` 两次都回 `-`。`self+8` 的 u32(0×104 / 0xd9da97f8×39 / 1×11 / 0xd9d53690×10)
   也不像 token id,更像指针低 32 位,未 join。⇒ 第二次 shot 没有给出任何 keyword id。
4. **`S+0x20` 处的 qword 是什么?若像指针,再读一次它的首 qword;vptr 落在哪个已知 vtable 区间?**
   **实测:不是指针,问题作废。** `S+0x20=0x20c4834810468908` 是 `0x1706f0` 这段代码里的指令字节;
   S 没有 vptr,无法与 `ceffect_vtable_map` 比对。真正的 vptr 观测是 `[arg2+0]=0x26e4fa8`;
   `self_vtable` 的 38 个不同值才是 CEffect 实例那边的数据。
5. **应用入口:复核 Task 2 的 `selected`。** **候选 C 从 `unresolved` 变为「构造点已定位」;A/B/D 不变,
   仍无 `selected`。** `0x1C750D0` / `0x1C3CED0` / `0x9EC290` 证明帧由调用方内联构造并紧接着
   `call [self_vtable+8]`,给出了「引擎自己的正确用法」样板;但它**不是 C4 可直接调用的入口**:构造是
   内联的,helper(0xa0 对象)和 self 实例都来自引擎内部,JS 侧仍没有 scope/system 指针。因此 A
   (`0x3B01A0`)、B(slot1 直调)、D(`0x9F5750` family)维持 `unresolved`;C 改记为
   `located(构造形状已知,可用性未证)`。
6. **C4 接线计划可以假设什么、必须自己再测什么?** **可以假设(实测+离线)**:arg2 是 0x20 字节帧,
   vptr `0x26e4fa8`,`+8` 是深度(base Execute 只动它),`+0x10` 是 helper 指针,`+0x18/+0x19` 是标志;
   帧的构造序列如 `0x1C750D0`。**必须自己再测**:① 从 JS 侧拿 scope/system 指针(§53.2 候选 A 缺的
   判据 ③,未变);② effect 施加后的提交时机(append 之后谁在何时调 child slot1,未变);
   ③ **新增**:一个 `+0x10=NULL`、`+0x19=0` 的人工帧能否被真实 `ExecuteActual` 接受 —— base Execute
   只读写 `+8`,但 override 可能读 `+0x10`;不许把「知道形状」当成「可以合成帧」的授权。

### §53.5 边界

本计划仍不证明任何「按 system 施加」的行为。第二次 shot 抓到的是**帧的形状与构造点**,不是应用入口,也不是
scope 指针。`X→S→id/obj` 这条链已证伪,不要再把它当前提;`descriptor_oracle` 与实机 id 的 join 仍然为零。
C4 接线的下一次 shot 必须自带新点名,并且要先把「人工帧能否被接受」和「scope 指针怎么来」两件事分开验证。

---

## §54 C4 试点一接线:分数 → JS → 按 system 下 effect(2026-10-23)

### §54.1 授权与环境

2026-10-23 点名原话:「那你开始吧,现在Windows机器在线且可使用」。执行的是
`docs/superpowers/plans/2026-10-23-c4-chokepoint-wiring.md` 的 Task 7 —— 本计划唯一的实机动作。
计划允许诚实失败:`capture` 找不到唯一 `0..786` 列就是有效结论,roadmap 保持 `blocked`,不伪造 `ok`。

- 产物 `stellaris_quickjs.dll` sha `22a37aaa6e80146b3495b267b71ccbd5f3ff8cd3b068523c9394aa0c6c08a65b`,
  部署为 `C:/temp/sqjs_c4.dll`(远端 hash 核对一致);同批部署的驱动 sha
  `c4_wiring_probe.py` = `a43a46a9…`、注入器 `c2_harness.py` = `0c8bca42…`。
- 存档:驱动门比对 `C:/temp/stellaris_2226.sav`,sha
  `6f271294bcfe3620a5e7da367a7f3fb0891c77315baffa28601ca48ec5d8d94e`(与 Task 1 的 `--save-sha` 一致)。
  **运行中的进程加载的不是这个文件**,而是同 campaign(`_1474567734`)的 `autosave_2243.07.01.sav`;
  执行 shot 前先做拓扑校验(离线,`scripts/save_hypergraph.py`):787 system、id 恰为 `0..786`、逐 system 的
  度数与 `evidence/xrefs/chokepoint_scores_4_4_4.tsv` 完全相等(0 多、0 缺、0 不符)⇒ id→score 映射不变。
  这是 Task 7 的 ledger 裁定:它不是「文件相同」,是「映射相同」的替代证据。
- supervisor 是带 `console_open` 跟踪的版本(commit `416be63`)。本次 shot 的第一次尝试
  (`capture_not_delivered`)就是该缺陷:4.4.4 的控制台键是**开关**,命令提交后控制台保持打开,下一条命令的
  「开面板」那一下把它关掉,命令被丢在窗口外。修复后按一次 shot 一个进程重开,下面所有观测来自**新进程 pid 9552**;
  `game_supervisor status` 执行 shot 时读作 `paused`(`paused_no_window`,无窗口、人未介入),console 命令照常
  同步执行。

### §54.2 产物与布局

DLL 导出 8 个 wire 入口(`C4WireInstall` / `SetMode` / `SetSpec` / `StatsInto` / `DrainInto` / `Layout` /
`Disarm` / `C4ScoredStatsInto`)加只读的 `C4PredStatsInto`。`C4WireLayout` 读回
`[1, 0, 3368, 2048, 944, 256, 8, 256]`(版本、当时 mode、record 大小、ring 上限、ctx 944 B、a3 256 B、
8 个指针槽、窗口 256 B),与 `wire.zig` 常量逐项一致。`C4WireInstall(effect_id)` rc=0;C1 注册与 §52 相同:
trigger `68636`、effect `68637` 是 `C1Run` 现铸的 token,不是官方 keyword。armed token = `68637`。

### §54.3 预检

命令原文(经 supervisor 剪贴板通道;`console_sent` 20:31:53):

    effect every_system = { log = "C4_PREFLIGHT_9552_[This.GetName]" }

开始于 20:31:49,783 条 `Log effect, file:` marker 在 30 s 门限内出现。计划字面写「787 行」,Task 7 的
ledger 裁定把门限改成 **783**:787 个 system 里有若干名字重名,引擎日志 sink 又会丢弃会话内重复的同一段
文本,所以 787 次执行只渲染出 **783** 个不同名字。观测值 783 与该门限相等 ⇒ `campaign_gate: ok`,
console 投递本身也被这一步独立证明。

### §54.4 捕获

命令原文(`console_sent` 20:31:59;game.log 里 783 条 marker 的时间戳都是 20:31:59):

    effect every_system = { log = "C4_CAPSTART_9552_[This.GetName]" neo_action = { log = "NEO_CHOKE_EFFECT_[This.GetName]" set_name = "NEO_CHOKE" } }

- 投递门:`C4_CAPSTART_9552_` 哨兵 **783**,`classify_delivery` = ok。
- wire stats(`C4WireSetMode(0)` 之后读):`calls=1`、`records=1`、`dropped=0`、`armed_token=68637`。
  驱动为 `calls >= 787` 轮询了 30 s,没到,停在 1。
- 列判读:ring 里只有 1 条记录,`find_scope_column` 直接给 `count_mismatch`、`column=None`、`columns=[]`;
  这条记录本身没有进入结果 JSON(驱动只保留 find 结果),所以不存在「候选列 / 顺序假设」可写。
- 谓词 delta:`pred_calls` 206,692 → 413,387(Δ **206,695**),`pred_patched` 0 → **1**,
  `last_token=10344`(`auto_move_to_planet`,环境里其他 effect 的末次读数,与本次命令无关)。
- game.log 交叉检查:783 条 `C4_CAPSTART_9552_`、783 条 `NEO_CHOKE_EFFECT_`,**783 对全部相邻、
  0 个孤儿、两个名字集合对称差 0**;即每个跑到外层 `log` 的 system 都跑到了 `neo_action` 的 body。

判读:787 次 per-system 执行确实发生了(外层 `log` 与内层 `log` 都渲染了),但 `neo_action` 对象只在
**实例化时**经过一次谓词与一次 slot[1](predicate 匹配 1 次;wire 的 `calls` 在 token 过滤之前自增,所以
`calls=1` 就是全部入口数),per-system 的 783 次 body 执行**没有**进入 slot[1]。CAPSTART/NEO 全部成对
且集合相同 ⇒ 那次 slot[1] 入口不是「某一次 per-system 执行被抑制」,而是实例化路径多出来的一次
(与 §52 fact 1 的 `[child+0x20]` 写入 → 谓词 → `[child_vptr+0x08]` 顺序一致)。谓词 206,695 次里只有
1 次 armed-token 匹配 ⇒ 块没有在每次迭代经 `0x3B01A0` 重新实例化(那条路径先写 `[child+0x20]` 再调谓词,
若逐系统走,匹配数应为 787)。

### §54.5 应用

没有执行。`classify_capture` 在捕获阶段就给出 `count_mismatch`,`apply` 的 before/after/delta/scored/
`log_hits`/sentinel 全为 `null`;没有 `C4WireSetSpec`、没有 mode=apply、没有链 donor 的机会,`chain=0`。
截图 sha 为 `null`(supervisor 没有刷新截图文件)。QuickJS 侧(分数表、`C2ExecCallScored`、tier 直方图)
与本次 shot 的失败位置无关 —— 它根本没被调用。

### §54.6 结论

`VERDICT: count_mismatch`。失败位置 = 捕获阶段 slot[1] 的入口计数(1 vs 787)。

排除了:

1. **控制台投递**:783 哨兵(§54.3)与 783 条 CAPSTART(§54.4),两条命令落地。
2. **campaign 形状**:预检 783 = 门限,id 映射另有拓扑校验。
3. **token 身份 / 谓词**:armed token 恰好匹配 1 次,对象经引擎自己的 `0x3B01A0` 实例化。
4. **逐系统重新实例化**:若每次迭代都走 `0x3B01A0`,谓词会在 787 次里各匹配一次;实际 1 次。
5. **token 过滤吞掉入口**:`wire.captureWith` 先 `calls += 1` 再比 token,1 就是全部入口数。
6. **某次 per-system 执行被我们抑制**:CAPSTART/NEO 783 对全相邻、集合相同,0 孤儿。

未证 / 下一 datum:per-system 执行到底走哪个入口。两个候选 ——
(a) 同一个对象经 base Execute `0x1D08520`(非虚入口)派发到 slot[2];
(b) 每次迭代得到 donor vptr 的副本/克隆,谓词与我们的 vtable 都不经过。
判别方法:在 DLL vtable 副本的 **slot[2]**(或 base Execute)上装只读计数器,同一 `every_system` 命令下
看它是否得到 787:(a) ⇒ 787,(b) ⇒ 0。这是最小判别,不改控制流,也不需要新的写行为。

对 §52 的意义:§52 证的「谓词 → DLL vtable → slot[1] → QuickJS」是**实例化路径**上的存在性证明(它的
`calls=17` 来自 17 次合成 `0x3B01A0`);它从未证明 per-system 执行经 slot[1]。§52.5 的「one object,
one call」与本次 shot 不矛盾;本次 shot 否证的是把它外推成 per-system 入口。§53.4 第 6 条留下的
「append 之后谁在何时调 child slot[1]」在这个形状下有了答案:**不在 per-system 循环里**。

### §54.7 清理

`C4WireDisarm` rc=0,`host_alive=true`,没有 `FreeLibrary`(patch 过的对象仍指向 DLL `.data`);
pid 9552 在 shot 后继续存活,状态 `paused`。证据日志 `evidence/logs/c4_wiring_live_4_4_4.log` 含两次尝试:
第一次 `capture_not_delivered`(supervisor 控制台开关缺陷,修复前)、第二次 `count_mismatch`(本节)。

### §54.8 slot[2] 执行 shot 前的离线判据(2026-10-23,离线:无游戏、无注入、无点名)

上一份计划 Task 8 的实机尝试记了一条 Ruling:「DLL 的 slot[2] 包装器把四个寄存器参数原样转发给 donor,
所以它与未包装的 vtable 拷贝逐字等价」。本节把这句话换成证据 —— 量派发点递了什么、`0x3B01A0` 消费了什么,
以及对照之下等价性覆盖到哪、不覆盖到哪。命令(全部离线读 `NS_STELLARIS_EXE` 指向的 exe 拷贝):

```
python3 scripts/vtable.py 2606FE0 --slots 25
python3 scripts/pdata.py 1d08520
python3 scripts/disrva.py 1d08520 1d08650
python3 scripts/pdata.py 3b01a0
python3 scripts/disrva.py 3b01a0 3b0220
```

#### §54.8.1 槽位重钉

`0x2606FE0` 的 25 槽里 `+0x08 -> 3afd30`(§52 的 donor Execute 覆写)、`+0x10 -> 3b01a0`、
`+0x98 -> 3b1420`(谓词)三行都在输出里 —— 与 §52、AGENTS 的 RVA 表一致,判别 shot 的靶子仍在原位。

#### §54.8.2 派发点:base Execute 只递两个寄存器

`.pdata`:`0x1d08520` 是函数 `0x1d08520..0x1d085b0`(0x90 B),unwind `0x271dd44`;派发指令在 `0x1d08577`。
序言到该调用为止,逐字:

```
01d08520  mov     qword ptr [rsp + 8], rbx
01d08525  push    rdi
01d08526  sub     rsp, 0x20
01d0852a  mov     eax, dword ptr [rdx + 8]     ; arg2+8 = 深度
01d0852d  mov     rbx, rdx                     ; arg2 = 执行帧
01d08530  mov     rdi, rcx                     ; arg1 = effect 对象
01d08533  test    eax, eax
01d08535  js      0x141d08569                  ; 深度为负 ⇒ 直接到调用点
01d08537  mov     edx, 0x10
01d0853c  mov     rcx, rbx
01d0853f  call    0x14016fdc0                  ; trace 钩子
01d08544  mov     rcx, rbx
01d08547  call    0x141d116a0
01d0854c  mov     edx, 3
01d08551  mov     rcx, rbx
01d08554  call    0x14016fdc0
01d08559  mov     edx, 0x10
01d0855e  mov     rcx, rbx
01d08561  call    0x14016fdc0
01d08566  mov     eax, dword ptr [rbx + 8]
01d08569  inc     eax                          ; §26 的深度 +1
01d0856b  mov     rdx, rbx
01d0856e  mov     dword ptr [rbx + 8], eax
01d08571  mov     rcx, rdi
01d08574  mov     rax, qword ptr [rdi]         ; vptr
01d08577  call    qword ptr [rax + 0x10]       ; slot[2]
01d0857a  dec     dword ptr [rbx + 8]          ; §26 的深度 -1
01d0857d  mov     rcx, rbx
01d08580  call    0x141d116a0
```

三条定论:

1. 从序言到 `ret`(`0x1d085af`)这个函数**不写 `r8`/`r9`,也不碰任何 `xmm`**。⇒ 派发点递给 slot[2] 的
   有意义实参只有两个:`rcx` = effect 对象、`rdx` = 执行帧(`+8` 已 `inc`);`r8`/`r9` 是**上一次调用留下的
   scratch**(`0x1d08561` 那次 `0x16fdc0` 就在紧邻前面),不是 Execute 语义下的参数。
2. `rax` 在调用之后**没人读**:下一条就是 `dec [rbx+8]`,随后是 trace 钩子与 `ret`。⇒ 这一站不要求包装器
   保真返回值(保了无害)。
3. 深度走**内存**(`[rdx+8]` 的 `inc`/`dec`),不经寄存器 ⇒ 没有隐式寄存器入参被漏掉。

#### §54.8.3 donor `0x3B01A0` 消费的槽

`.pdata`:`0x3b01a0..0x3b0f7e`(0xdde B),unwind `0x27545b4`。序言窗口(`0x3b01a0..0x3b0220`)逐字:

```
003b01a0  mov     qword ptr [rsp + 0x18], rbx
003b01a5  mov     qword ptr [rsp + 0x20], r9      ; arg4 溢出
003b01aa  mov     qword ptr [rsp + 8], rcx        ; arg1 溢出
003b01af  push    rbp
003b01b0  push    rsi
003b01b1  push    rdi
003b01b2  push    r12
003b01b4  push    r13
003b01b6  push    r14
003b01b8  push    r15
003b01ba  lea     rbp, [rsp - 0x4f0]
003b01c2  sub     rsp, 0x5f0
003b01c9  mov     r12d, r8d                       ; arg3 的 32 位副本
003b01cc  mov     r13, rdx                        ; arg2
003b01cf  mov     r14, rcx                        ; arg1
003b01d2  mov     dword ptr [rbp + 0x538], 0
003b01dc  cmp     dword ptr [rdx + 0x38], 0xb     ; 入口门:arg2+0x38 必须 = 11
003b01e0  jne     0x1403b0322                     ; 否则走第二条路
003b01e6  lea     rdx, [rcx + 0x58]
003b01ea  xor     r8d, r8d
003b01ed  mov     rcx, r13
003b01f0  call    0x141d0ba00
003b01f5  mov     rdi, qword ptr [rip + 0x2fc44ec]  ; -> 0x33746e8 (ScriptedEffectDB)
003b0222  lea     rbx, [r14 + 0x68]
003b0236  call    0x1403af060                     ; db 查找
```

「后续在哪消费」出自同一脚本的整函数窗口(`disrva.py 3b01a0 3b0f7e`),按槽判读:

| 槽 | 读成什么宽度 | 消费点 |
|---|---|---|
| `rcx` | 指针 | `mov r14, rcx`;`[rcx+0x58]`(`0x3b01e6`)、`[r14+0x68]`(`0x3b0222`) |
| `rdx` | 指针 | `mov r13, rdx`;入口门 `[rdx+0x38]`(`0x3b01dc`);之后 `[r13+0x278]`(`0x3b03c5`)、`[r13+0x38]`(`0x3b03d3`/`0x3b07d7`)、`[r13+0x48]`(`0x3b08f4`/`0x3b0bbc`)、`[r13+0x30]`(`0x3b0ce5`/`0x3b0d12`) |
| `r8` | **32 位**(`r8d`) | `mov r12d, r8d`;与节点 token 比(`0x3b0366`/`0x3b038b`)、写回 `[rsi+0x20]`(`0x3b0984`)、两个特判常量 `0x474b`/`0x28df`(`0x3b0c2d`/`0x3b0c36`) |
| `r9` | 指针 | 溢出到 `[rsp+0x20]`(`0x3b01a5`);`jne` 那条路上 `mov r14, r9`(`0x3b0322`)、`[rsp+0x70]`(`0x3b0325`) |

`xmm` 在整个函数里只以 `xorps xmm0, xmm0` + `movdqu [rsp+0x48], xmm0` 出现(`0x3b08fd`/`0x3b09f5`),
是**清零本地内存**,不是传参。⇒ 四个 GPR 槽全被消费,`r8` 按 32 位取用(与 §53.2 的 `r8d = token` 一致),
`r9` 在门的另一条路上当指针用。

#### §54.8.4 对照结论:等价覆盖什么、不覆盖什么

**覆盖到的**:派发点只设 `rcx`/`rdx`、不读 `rax`;`0x3B01A0` 消费 `rcx/rdx/r8/r9` 四个槽。
DLL 侧 `effectInstantiate(a1, a2, a3, a4)`(`src/dll/c2/vtable.zig:90`,先 `slot2_calls += 1` 再按 `.c`
约定转发四参并返回 donor `rax`)在这一形状下与未包装的拷贝**逐字等价** —— 包括「`r8`/`r9` 是未定义 scratch」
这一项:两条路递给 slot[2] 的是同一份未定义值,包装器既不把它变得更像参数,也不变得更糟。计数副作用
(`lock xadd` 到 DLL `.data` 的一个 u64)不触碰任何引擎寄存器或内存。

**不覆盖到的两条,判读时必须记住**:

1. **`r8`/`r9` 不是 Execute 的参数**。`0x3B01A0` 把 `r8d` 当 token、把 `r9` 当指针用,而 Execute 从不设置它们
   ⇒ 经 Execute 派发进来的调用,这两个槽取的是上一个调用者的 scratch。所以 `slot2_counted` 只证明
   「有人经我们副本的 slot[2] 进来了」,**不证明**它是一次良构调用。要分开这两件事,得把 `a3`/`a4` 也记进
   只读统计(现在 `slot2` blob 只有 `calls` 与 `target`,`src/dll/c2/vtable.zig:119`)。
2. **入口门 `[rdx+0x38]` 与 §53 的「arg2 类大小 0x20」直接冲突**(`0x38 > 0x20`)。离线判不掉:要么 §53 量到的
   那个 0x20 对象不是 Execute 转发给 slot[2] 的 `rdx`,要么这一读落在帧之外的栈内存上、门几乎必然走 `jne`。
   **本节不改写 §53 的正文**,这是一条新增的未证张力。它对判据表的影响:`slot2_zero` 的读法不变(仍指向
   §54.6 的 (b) —— donor vptr 副本/克隆);`slot2_counted` 多一层读法 —— 计数命中 + 参数形状未经 Execute 建立,
   下一次 shot 若要区分「引擎真的经 base Execute 派发」与「别的调用者借道我们的副本」,需要的不是更多计数,
   而是第 1 条里那两个槽的取值。

### §54.9 控制台 desync 的根因(2026-10-23,只读取证:无注入、无按键、不执行 shot,只读 Windows 上的 supervisor 日志)

**为什么要这一节。** §54.4 的捕获命令只跑到 1 次 slot[1],投递门却判 `ok`(783 条哨兵都在);
下一次 slot2 shot 要靠同一条 console 通道连发三条命令。而 §54 之后补投的三次全部 **0 行**——
不先弄清这条通道什么时候会静默失灵,slot2 那次 shot 的 `count_mismatch` 就永远分不清「引擎没派发」和
「命令根本没进去」。Task 7 的 ledger 把这条列为 Blocker 2,当时的候选有 dedupe、Enter 空按、人工点击、
引擎自己关面板。**这一节的取证把 dedupe 从根因里剔除,并把缺陷钉在 supervisor 自己身上。**

**取证方式(可复现)。** `C:\temp\ns_game_log.jsonl`(12,113 B,LastWriteTime 21:54:14)只用
`ConvertFrom-Json` 读,不碰游戏窗口。远端控制台是 cp936、嵌套引号会被 cmd→PowerShell 层拆坏,且
**ssh stdout 超过约 1 KB 会被重置**(1,000 B 过、1,200 B 重置;`scp` 下载同样被重置),所以过滤在
服务端做、payload 本地编码:

    python3 -c "import base64; open('/tmp/enc3.txt','w').write(base64.b64encode(PS.encode('utf-16-le')).decode())"
    ssh -o ConnectTimeout=15 Windows_Jiaolong "powershell -NoProfile -EncodedCommand $(cat /tmp/enc3.txt)" \
      | tr -d '\000' | grep -v '^#<\|^<Objs'

`PS` 逐行 `ConvertFrom-Json`,按 `$o.t` 落在窗口内才输出 `HH:MM:SS event 详情`(详情截 46 字符)。
同类命令的三次输出:

- 全天事件计数:`2 close_posted, 96 command, 1 console_refused, 10 console_sent, 1 console_sync,
  10 serve_start, 7 serve_stop`。
- §54 那次 shot 与之后的时间线:`20:29:36 serve_start → 20:31:53 console_sent opened=True →
  20:31:59 opened=False`(两条都出哨兵),之后 `21:40:00 console_sent opened=True`(出 783 行)→
  `21:42:20 opened=False` → `21:42:50 opened=False` → `21:48:54 opened=False` →
  `21:51:42 opened=False`,**21:40–21:51 之间没有 `serve_start`**(daemon 没重启过,「重启把标记清成
  False」这条假说当场死)。
- 两次失败窗口的邻域(21:39:30–21:44:59 全事件,不过滤类型):

      21:39:56 command console effect every_system = { log = "NS_PREP
      21:40:00 console_sent chars=62 opened=True
      21:42:16 command console effect every_system = { log = "NS_PREP
      21:42:20 console_sent opened=False
      21:42:46 command console effect every_system = { log = "NS_PREP
      21:42:50 console_sent opened=False
      21:44:33 command shot

  另一段(21:48:00–21:52:59):`21:48:37 command click 1090 934` → `21:48:42 shot` →
  `21:48:51 console …` → `21:48:54 console_sent` → `21:50:16 shot` → `21:51:38 console …` →
  `21:51:42 console_sent`。

**判读。** `opened` 是 `not state["console_open"]` 的返回值,所以四条 `opened=False` 意思是:
**发命令那一刻,daemon 认为面板开着**,于是不按开关键、直接清行+粘贴+回车。§54.1 已实机证明
「提交后面板保持打开」,所以 21:40:00 之后那一刻的信念本应是对的;它错了,只有两种可能——
面板被别的东西关了,或者面板从来没开。日志里 21:40:00→21:42:16 **一个事件都没有**,这正是关键证据:
`game_supervisor.py` 的自动路径**不写日志**。serve 循环每个 tick(0.8 s)会按 `plan_step` 自己发输入:
`press_space`(自动暂停/恢复)、`click_row`(点选项)、`click_close`(关弹窗)——三者都只把结果写进
`note`,而 `note` 落在 `ns_game_status.json`,那个文件每 tick **原子覆盖**,历史不可回读。
`_handle_command` 里的 `speed` / `click` / `dismiss` 会写 `command` 事件(所以 21:48:37 那次点击看得见),
自动路径看不见。于是:

- **21:48:54 的失败有直接相邻证据**:前一条事件是 21:48:37 在游戏区的一次鼠标点击(与 `click_close`
  同类的 `_click_at`),它足以让面板失焦/关闭,而 `console_open` 仍然是 `True`。
- **21:42:20 / 21:42:50 的失败是同一机制的推断**:唯一能在日志里完全不留痕迹地改变面板状态的东西,
  就是那三条不写日志的自动输入。其中空格还有第二重自锁:面板开着时空格进的是**输入行**,游戏
  **不会暂停**,像素判读于是一直报 `playing`,`want=paused` 的循环就**每个 tick 再按一次空格**——
  既解释面板为什么不关,也解释游戏为什么停不下来。
- **dedupe 不需要参与解释**:21:51:42 那条用的是全新唯一前缀 `NS_FLUSH55_<epoch>_`,0 行;
  三次失败全部 `opened=False`,不需要「重复文本被 sink 丢掉」就已经解释得完。dedupe 只在
  §54.3/§54.4 解释 **787 执行 vs 783 渲染名** 时仍然是正确判据,那一处不改写。

**根因一句话:`console_open` 记的是「我以为」,从来不是「我看到」;而这个标记有两个消费者,
只有 console 动词在维护它——pause/speed/click/dismiss 全都往游戏发输入,没有一个字碰它。**

**改了什么(离线,TDD)。** `scripts/windows/game_supervisor.py` 把标记变成**三值信念**
`True|False|None`,并落三条不变量,每条一个先失败后通过的 host 测试
(`scripts/windows/tests/test_game_supervisor.py`,217 passed = 212 旧 + 5 新;`just fence` 27):

1. `console_send_plan(state)`:信念为 `None` 时**拒绝**——不猜奇偶、不按键、不碰剪贴板,写
   `console_refused reason=console_state_unknown`。只有 `console_sync` 或换游戏进程能抬回已知值。
2. 任何**发给游戏的输入**之后立刻作废:`speed`、`click`、`dismiss`,以及 serve 循环的
   `click_row` / `click_close`。自动路径没有测试接缝,由一条源码围栏钉住
   (`test_serve_loop_invalidates_the_belief_after_every_auto_click`)。`shot` 只截像素,不作废。
3. `send_pause_key(state, hwnd)`:信念为 `True` 时返回 `blocked_console` 且**不按键**,
   状态 note 变 `pause_blocked_console` / `resume_blocked_console`,打断上面那个空格自锁。
   代价是面板开着时自动暂停会卡住并写明理由;退出办法是新动词 `console_close`
   (仅当信念为 `True` 时按一下开关键、写回 `False`;`None` 时同样拒绝)。

**仍未证的事(不要当结论带走)。** 我们**始终没有观测过面板本身**:21:42 那两次归给不写日志的自动输入,
是「代码里只有这条路能静默改输入状态」+「21:48 那次有可见点击紧邻」的联合推断,不是直接观测。
能把它坐实的一次 shot-free 校准(需要人在机器前,本次没做):开面板 → `just game shot` → 关面板 → `shot`,
把两张截图的判读几何固化成一个面板检测器;在那之前,supervisor 的诚实行为就是
**未知即拒绝**,而不是继续猜。部署也未做:改动只在本仓库,`C:/temp/game_supervisor.py` 仍是
`416be63` 那一份(改完要 `just deploy` + `stop` + `start`,进程不热加载)。

**§54.9 部署记录(2026-10-23 23:22–23:25,同一台机,仍然零游戏)。** 上面那句「部署也未做」到此为止,
不改写正文,按约定追加:

- `just deploy`(scp 上传两条脚本)后**远端哈希与本地逐项相等**:`game_supervisor.py`
  `ea8c93c3eee5400375b594184397ce5b7d788d09658305e2454e7727fa591663`、
  `launch_stellaris.py` `3bba05666e59e29ec78c552d4a333dd264c539c869b21ca985cbd6948a9af522`,
  远端 `LastWriteTime 23:22:36`。判取哈希用 `Get-FileHash`,只读。
- 旧 daemon **pid 11616(20:29:36 起,就是跑过 21:40–21:51 那三条命令的那一份)经命令通道 `quit`
  正常退出**,状态读到 `STATUS=stopped note=quit`,不是 kill,也没碰 `schtasks` 之外的任何东西。
- 新 daemon **pid 18472,CreationDate 23:23:41**(晚于上传时刻,加载的必然是新文件),
  `status` 报 `no_game`(靶进程早就不在了),`handled=0`、`want=playing` —— 全新信念,`console_open`
  按新代码在**换进程**这条路上复位为「关」。
- 部署后的**行为验伪**(不接触 daemon、不写命令通道、不按键):在 `C:\temp` 里
  `python -c "import game_supervisor as g; print(g.parse_command('console_close'), …)"` 返回
  `{'verb': 'console_close'} True True True`,即新动词解析得到、`console_send_plan` /
  `send_pause_key` / `console_tap_plan` 三个新入口都在。
- **仍然没做的**:面板观测本身(上面那条校准)、以及任何一次 shot。下一次 shot 之前 `console_open` 的初值
  来自「新进程 = 面板关」这个约定,不是观测 —— 这一点不因部署而改变。

### §54.10 面板观测通道的建立与实机校准(2026-10-23→24,只做像素 + 两次开关键:无注入、无 console 命令、不执行 shot)

**为什么要这一节。** §54.9 结尾那句「仍未证」是这件事的全部动机:从头到尾**没有人观测过面板本身**,
`console_open` 的初值来自约定,而那个约定错了就直接决定「按不按开关键」。这一节把它换成观测。
用户批准的边界:`just game launch` 之后**只做**按一次开关键 → 读像素 → 再按一次 → 读像素。

**跨界问题与桥。** 直接 ssh 跑的是非交互登录会话,`EnumWindows` / 屏幕 DC 看不见 `stellaris.exe`
(`find_game()` → `no_game`),而 daemon 看得见(pid 21372 / hwnd 461430)。沿用仓库已有的跨界办法
(`launch_stellaris.py` 的 BRIDGE:`schtasks /ru <machine>\<user> /rl highest` + `/run /I`),剥成
「在交互会话里跑一条 python,stdout 写文件,只回短行」:
`scripts/scratch/2026-10_panelcalib/run_ps.py`(桥)+ `panel_pixel_map.py`(探针,复用 `gs` 的
`find_game` / `window_rect` / `grab_box` / `read_pause` / `console_tap_plan` / `_send_input_event`,
不另写一套像素层)。两个都是一次性,留在 scratch。**注意:`stats` / `footprint` / `bbox` 只读已存帧,
不需要桌面会话,直接 ssh 就能复算;只有 `tap` / `diag` / `png` 需要桥。**

**先否掉帧差(数字全部可复算)。** 校准存下 10 张全分辨率亮度帧 `C:\temp\ns_panel_<tag>.png`
(关:a, f, a2, i, k, m;开:b, g, j, l;窗口 2160×1440,阈值 30):

- 两帧**同态** `bbox a f` ⇒ **N=54273/3110400**,变化框 x124–2130 y66–1397 —— 主菜单背景动画自己就在动;
- 两帧同**开** `bbox b g` ⇒ N=1341、`bbox g j` ⇒ N=1508(`max=75`,是光标级微动,不是文字);
- **跨态** `bbox a b` ⇒ **N=329259**、`bbox f g` ⇒ **N=336667**,变化框铺满整窗。

同态 5.4 万 vs 跨态 33 万只有 6 倍,而同态差已经遍布全窗 ⇒ **差分的定位能力为零**。更早还有一条被淘汰的
指标:32×18 平均亮度网格,一次按键带来的权重变化 **21** 小于两帧同态的抖动 **74**,即指标本身选错了。

**换成单帧数「密集亮点」。** `footprint b vs i,k,m` ⇒ 72 格落在 `RECT x40-880 y80-880`(面板那一列),
取最重的八格定出框 **A = (120,640)-(400,880)**,阈值 **180**。`stats` 逐帧实测(A 框 thr=140/180/220 三档):

| 帧 | 状态 | A@140 | A@180 | A@220 |
|---|---|---|---|---|
| a | 关 | 0 | **0** | 0 |
| f | 关 | 0 | **0** | 0 |
| a2 / i / k / m | 关 | 2 / 2 / 2 / 2 | **0 / 0 / 0 / 0** | 0 |
| b / g / j / l | 开 | 2409 | **2315** | 270 |

四个开帧**逐字相同**(2315),六个关帧在 thr=180 全为 0 —— 同态之间零抖动,和帧差正相反。
对照组说明为什么选 A 而不是别的框:B 框 开=5865 / 关=1007–1012(把别的 UI 文字也算进来了,裕度一个量级),
C 框 开=592 / 关=2–18,而 W(整窗)开=20215 / 关=9950–14853 已经**区间重叠**,不能用。

**实现(TDD,提交 `987b6f8`)。** `scripts/windows/game_supervisor.py` 加
`CONSOLE_BOX_FRACTIONS`(按窗口比例存,换分辨率不吃亏)/ `CONSOLE_BRIGHT_MIN=180` /
`CONSOLE_CLOSED_MAX=120` / `CONSOLE_OPEN_MIN=600` / `classify_console` / `_console_box` /
`read_console` / `apply_console_observation`;serve 每 tick **在 `plan_step` 之前**观测,于是本轮动作
用的就是刚读到的状态;status 增加 `console_px`、`console_forced`。120–600 之间的模糊带判 `None`,
daemon 照 §54.9 的规矩**拒绝而不是猜**。`console_sync open|closed` 把信念钉住(观测让位于人),
`console_sync auto` 松开。6 个新 host 测试先失败后通过:`just host-tests` **223 passed**(217+6),
`just fence` 27 passed。

**实机验证(2026-10-24 00:04–00:12,同一台机、同一个 pid 21372)。** `just deploy` → 旧 daemon 经命令
通道 `quit` 正常退出(`STATUS=stopped note=quit`)→ `python C:/temp/game_supervisor.py start`
起新 daemon(pythonw pid 23208,00:04:34)。每一步**探针独立读 + daemon 自己读**对表:

| 动作 | 探针 diag(独立读) | daemon status |
|---|---|---|
| 起始 | — | `console_open=False console_px=0 forced=False` |
| 按一次开关键 | `BOXA bright=2312` | `console_open=True console_px=2309` |
| 再按一次 | `BOXA bright=0` | `console_open=False console_px=0` |
| `console_sync open` | 面板没动 | `console_open=True console_px=0 forced=True` ← 钉住生效 |
| `console_sync auto` | 面板没动 | 下一 tick `False / 0 / forced=False` ← 观测重新接管 |

daemon 日志(`C:\temp\ns_game_log.jsonl`,只读拉取)记到的转换:
`00:05:37 false/0 → 00:06:34 true/64118 → 00:06:46 false/0 → 00:06:52 true/1298 → 00:06:53 false/0`,
`00:08:17 console_sync forced → 00:08:28 auto → 00:08:29 false/0`。

**判读与代价(如实记下,不当结论带走)。** `64118` 和 `1298` 是面板**动画途中**的帧:动画里 A 区先整片
亮起来(远超稳态 2315),而 `00:06:46` 那次读到 **0** 说明**开启动画中存在一帧 A 区全暗**。
⇒ 「刚按完键的那一瞬间」不是稳态判据。现有多处消费点靠的是 tick 之间已经落定的画面;任何「按键后立刻
自证」的新逻辑都不能只读一帧,要么读够时间,要么落到 `None` 走拒绝。反方向不出事:落在模糊带是拒绝,
不是往开着的面板里打空格。

**仍未证的两件事。** (1) A 框只在**主菜单**(上表 10 帧)和**一次载入局**(live 2312)上校过,没有覆盖
全部界面;若某界面自己点亮 A 区,会被读成「开」→ daemon 拒绝动 console/space,这是可恢复的保守,不是
错误输入。(2) 校准结束时游戏是 `state=paused`(开合控制台自身的副作用),`want=playing` 由 daemon 接回,
本节没有为它做任何额外输入。

**复现命令行**(Linux 侧,原样):

    cd scripts/scratch/2026-10_panelcalib
    scp panel_pixel_map.py Windows_Jiaolong:C:/temp/                        # 探针上传
    python3 run_ps.py --wait 25 "chain diag;sleep,800;diag"          # 看窗口是谁、A 框现值(需桥)
    python3 run_ps.py --wait 30 "chain tap;sleep,1500;diag"          # 批准范围内的一次开关键 + 读像素
    ssh Windows_Jiaolong "python C:/temp/panel_pixel_map.py stats b" # 逐帧复算,不需要桥
    ssh Windows_Jiaolong "python C:/temp/panel_pixel_map.py footprint b i k m"
    ssh Windows_Jiaolong "python C:/temp/panel_pixel_map.py bbox a f"
    just game status   # console_open / console_px / console_forced

## §55 C4 slot[2] 判别 shot:base Execute 经不经我们的 vtable 副本(2026-10-24)

§54.6 把「per-system 执行到底走哪个入口」缩成一次二选一,§54.8 在执行 shot 前离线钉死了它的读法与
两条「不覆盖」。本节是那**一次 shot**的结果:一个游戏进程、一次注入、一条判别命令。

### §55.1 授权与环境

点名原话:**「执行 Task 6」**(2026-10-24,用户)。这正是 Task 6 Step 1 自己要的那句话
(「只有用户明确说『打这一枪 / 执行 Task 6』才继续」),不是我从别处推出来的许可。

**这次 shot 之前先烧掉的不是资源,是半天。** `just launch` 连续两次以退出码 22
(`EXIT_LAUNCHER_NO_FOCUS`)失败:`SetForegroundWindow` 返回 FALSE 且 `gle=0`。根因不在 launcher ——
Console 会话 1 自 12:02:11 起由 `LogonUI.exe` 停在锁屏上,锁屏桌面不接受注入的输入。
我当时评估过「远程解锁」这条路并**否掉**(架构上不可达:锁屏期间的输入被拒、`ImageGrab` 走的是屏幕 DC
而 ssh 起的进程看不到桌面;host 是 Win11 Home,没有入站 RDP 服务端 —— 补一句:
**给 Home 打 `termsrv.dll` 补丁是绕过许可,不是配置,这条我没做也不会做**)。
最后是**由人**在现场解锁,第三次 `just launch` 成功:`foreground_ok`,点击 handoff 在第 2 次尝试命中,
pid 13364。两次 22 都停在 `bring_to_foreground`,launcher 不做注入,所以没有消耗 pid 13364 的一次注入额度。

**产物:六项 sha256 本地 ↔ host 逐条相等**,且其中两项与结果 json 里的字段逐字相同。

| 本地 | host | sha256 |
|---|---|---|
| `zig-out/bin/stellaris_quickjs.dll` | `C:/temp/sqjs_c4.dll` | `1b568cd4154da1e9afcb25c451c5f9000ea5ce5cf6afdc995fd9760e06412ba9`(= json `dll_sha`) |
| `scripts/c4_wiring_probe.py` | `C:/temp/c4_wiring_probe.py` | `8a066109629ce79dc153036f97597dfcdf02b27c16082742e733036ba18ea09f` |
| `scripts/windows/game_supervisor.py` | `C:/temp/game_supervisor.py` | `1ad3f6f7931a15292bf4fd0e1284c358f6fbf8c7f647ce716ef32e78a09e7ec3` |
| `scripts/windows/launch_stellaris.py` | `C:/temp/launch_stellaris.py` | `3bba05666e59e29ec78c552d4a333dd264c539c869b21ca985cbd6948a9af522` |
| (gated,不在仓库) | `C:/temp/stellaris_2226.sav` | `6f271294bcfe3620a5e7da367a7f3fb0891c77315baffa28601ca48ec5d8d94e`(= json `save_sha`) |
| `scripts/c2_harness.py` | `C:/temp/c2_harness.py` | `0c8bca42a70ab9a2cf28bba6036de1d039ff30ec01dba93550a9af5ded485713`(注入通道的驱动侧,shot 没重新上传它) |

出处:`sha256sum …`(Linux 侧)+ `ssh Windows_Jiaolong "powershell -NoProfile -Command \"Get-FileHash -Algorithm SHA256 C:/temp/sqjs_c4.dll,C:/temp/c4_wiring_probe.py,C:/temp/c2_harness.py,C:/temp/game_supervisor.py,C:/temp/launch_stellaris.py,C:/temp/stellaris_2226.sav | Format-Table Path,Hash -AutoSize\""`,逐条原样在 `evidence/logs/c4_slot2_live_4_4_4.log` 第 8 节。

**观测前提(daemon 自己报的,不是我以为的)**,`just win "python C:/temp/game_supervisor.py status"`
在 13:03:09 那条记录里:`console_open=false`、`console_px=0`、`console_forced=false`。
⇒ 信念来自像素,且没被 `console_sync` 钉住。**没有为了凑这个前提去按 `console_sync`** ——
计划写死了这条禁令,§54.9 就是违反它的代价。同一份记录还有 `note=dialog_unknown`(策略想处理对话框,但 `auto_dismiss` 没开 —— `game_supervisor.py:1037-1046`)。
这里要说清两件事**不同源**,别把它们读成同一个框:`window.bbox=[1006,584,1939,840]` 是**事件带里检出的亮面板**,屏幕坐标(`_panel_bbox`,`:660-703`);而 A 框是**按游戏窗口宽高取比例**算出来的(`CONSOLE_BOX_FRACTIONS`,`:63`;`_console_box`,`:603-609`)。「那个面板会不会自己点亮 A 框」本次 shot**没证**,也不需要证:门二读到的就是 `false / px=0`,即那一瞬间 A 框是暗的;而投递真没被挡住 —— 预检随后拿到 783 行。

**进程地址两条,别混。** 结果 json 的 `base = 140721292902400 = 0x7ffc3aad0000` 是**我们 DLL 的装载地址**
(`_flow` 取 `harness.resolve_base_address(pid, os.path.basename(args.dll)`,`scripts/c4_wiring_probe.py:852-854、865`),
不是 exe 基址。`stellaris.exe` 主模块基址另取(`ssh Windows_Jiaolong "powershell … (Get-Process -Id 13364).MainModule.BaseAddress"`
= `140697292701696 = 0x7ff6a4270000`)。这对 §55.4 的仪器自证是关键,数字在那一节算。

**执行 shot 前的离线门(Task 1–3 的判据)**,`python3 -m pytest scripts/test_c4_wiring_probe.py -q` → **56 passed**;
`just fence` → **27 passed**;`just host-tests` → **223 passed**;`zig build test` → **445/445 tests passed**
(其中 `-Mroot=src/dll/exports.zig` 那一条链接步按 `docs/offline-tooling.md`「Host caveat」与裁定 P15 记为绿,
本批 `src/dll/` 一行未动)。`C4Slot2StatsInto` 在产物里的 rva 为 **`0x44b420`**(零游戏,离线枚举 PE 导出:
`python3 -c "import sys;sys.path.insert(0,'scripts');import c2_harness as h;e=h.list_exports('zig-out/bin/stellaris_quickjs.dll');print('C4Slot2StatsInto' in e, hex(e['C4Slot2StatsInto']))"`,`scripts/c2_harness.py:236`)。

### §55.2 三道前置门的实际判定

门顺序:`_wait_ready`(`:689`)先 `supervisor_ready` 再 `console_gate`,然后才是 save 哈希门、
导出 diff、`resolve_pid`、`_campaign_preflight`(`:799`,**注入之前**)。

1. **门一 · 导出集按模式**(`required_exports("slot2")`,`:91-99`):
   `REQUIRED_EXPORTS + ("C4Slot2StatsInto",)`,与产物导出做差集 ⇒ **空,放行**。
   含义:那次 shot 不可能走到 `_slot2_phase` 才发现导出不在(§54 那批 DLL 有 capture 的导出、没有 slot2 的)。
2. **门二 · 信念必须是观测**(`console_gate(rec)`,`:479-491`):
   输入 = §55.1 那条记录 ⇒ `console_open` 非 `None`、`console_forced` falsy ⇒ **`"ok"`,放行**。
   这里要点名是哪一轴(Task 3 复核留下的那条 minor):驱动侧的 verdict 名 `console_state_unknown`
   与 daemon 侧的拒收 `reason` 名**恰好同名,是两个东西**。本次 shot**两个都没触发** ——
   驱动没判 `console_state_unknown`(像素决定性),daemon 没写 `console_refused`(见门三)。
   `console_belief_pinned` 那一支也没触发(`forced=false`)。
3. **门三 · 拒收理由 2 s 内中止**(`classify_console_receipt`,`:443-460`;窗口常量
   `CONSOLE_RECEIPT_TIMEOUT_S = 2.0`,`:56`):
   每条 console 命令**写命令文件之前**先记 JSONL 的长度作偏移,2 s 内只分类该偏移之后的尾巴。
   本次 shot 两条都是 **`no_receipt` ⇒ best-effort 静默放行**,这是健康形状:daemon 的 `console_sent`
   要按完整键计划(≈3.5 s,第二条起 ≈3.3 s)才落盘,严格长于 2 s 窗口 —— 所以**读静默返回时不要去找
   「缺失的成功回执」**(`docs/offline-tooling.md` 前置门三已写明)。事后从 JSONL 尾巴读到的确认为:
   `{"event": "console_sent", "chars": 67, "opened": true, "t": "…13:04:32"}` 与
   `{"event": "console_sent", "chars": 148, "opened": false, "t": "…13:04:38"}`
   (`ssh Windows_Jiaolong "powershell -NoProfile -Command (Get-Content C:/temp/ns_game_log.jsonl -Tail 12)"`)。
   **无 `console_refused`,无 `console_clipboard_failed`** ⇒ 门三没有东西可中止。
   slot2 模式一共两条 console 命令(预检 + 判别),与计划一致(capture 模式是三条)。

**预检(注入前)**:`_campaign_preflight` 拿到 **783 行**哨兵 = 门限
(json `preflight_marker_count: 783`,`python3 -c "import json;print(json.load(open('/tmp/c4_wiring_result_slot2.json'))['preflight_marker_count'])"`),
等待 **4.18 s**(json `preflight_wait_s: 4.18`)。⇒ campaign 形状对、面板投递通、日志读回不瞎。

**我自己制造的一次噪声(如实记,与判读无关)**:`just win "python C:/temp/game_supervisor.py send shot"`
—— `send` 不是子命令(daemon 的 CLI 只认 `serve|start|stop|status|cmd`,其余首词按字面量走命令通道,
`game_supervisor.py:1191-1196`),于是命令文件收到字符串 `send shot`,daemon 回了
`{"event": "unknown_command", "raw": "send shot"}`。它落在 shot**之前**,不影响任何门的输入。

### §55.3 一次 shot

    $ just win "python C:/temp/c4_wiring_probe.py --mode slot2 --dll C:/temp/sqjs_c4.dll --save C:/temp/stellaris_2226.sav --json C:/temp/c4_wiring_result.json"
    VERDICT: slot2_zero
    error: recipe `win` failed on line 46 with exit code 1

退出码 1 不是崩溃:`main()` 只在 `verdict == "ok"` 返回 0(`scripts/c4_wiring_probe.py:1133-1136`),
而 `_slot2_phase` 的 docstring 早就写明 `slot2_zero` **is a datum, not a failure**。

`VERDICT: slot2_zero` 由 `classify_slot2(sentinel=783, body_hits=783, delta=0)` 得出
(`:198-210`);`detail` 逐字 `"slot2 delta=0 body=783 sentinel=783 target=0x7ff6a46201a0"`。

| 量 | 值 | 出处 |
|---|---|---|
| armed 哨兵 `C4_SLOT2START_13364` | **783 行** | json `slot2.sentinel` |
| `NEO_CHOKE_EFFECT` body | **783 行** | json `slot2.body_hits` |
| slot[2] 计数 before | `slot2_calls=0` | json `slot2.before` |
| slot[2] 计数 after | `slot2_calls=0` | json `slot2.after` |
| **delta** | **0** | json `slot2.delta` |
| 转发的 donor 地址 `slot2_target` | before = after = `140697296568736` = **`0x7ff6a46201a0`** | json `slot2.before/after` |
| 接线安装 | `install_rc=0`(**注入发生了,pid 13364 的一次额度已用掉**) | json `install_rc` |
| armed token | `effect_id=68637 = 0x10c1d` | json `effect_id` |
| wire 布局 | `[0x1, 0x0, 0xd28, 0x800, 0x3b0, 0x100, 0x8, 0x100]` = 与 `expected_layout` 逐槽相等 | json `layout`;比对在 `:888-891` |
| campaign 门 | `"ok"` | json `campaign_gate` |

### §55.4 判读

**`delta = 0` 判给 §54.6 的 (b)。** donor vptr 是一次**副本/克隆**:per-system body 执行既不经我们
vtable 副本的 slot[1](§54 已证 1/787),**也不经 slot[2]**(本次 shot)。⇒ 试点一要找的入口不在我们
那份 25 槽副本上,**换 chokepoint,不是修 slot[2] 包装器**。

**为什么这个 0 不是仪器故障 —— 三条独立自证:**

1. **计数器装在对的槽上。** `slot2_target - exe_base = 0x7ff6a46201a0 - 0x7ff6a4270000 = 0x3b01a0`,
   零余数,正好是 donor instantiate 的 RVA(§54.8.1 钉的 `+0x10 -> 3b01a0`)。
   包装器转发的靶子是真的引擎 `0x3B01A0`,不是别处的值。
2. **blob 两次都读到了,且自洽。** before/after 同值(`0 / 0x7ff6a46201a0`)⇒ 不是「读回失败当成 0」;
   `C4Slot2StatsInto` 写满 16 B 才返回 true(`src/dll/c2/vtable.zig:119-124`),
   短读会抛 `ValueError` 走中止路径,不会静默给 0。
3. **投递与执行都在。** 哨兵 783 + body 783 两次独立等齐(`_wait_marker` 定义在 `:667`,两次调用在 `_slot2_phase` 内 `:771、:775`)⇒
   「命令没进去」这条 §54.9 的老失败被排除;`install_rc=0` + 布局逐槽相等 ⇒ 接线本身成立。

**没排除的事,四条,读这节时必须带着:**

1. **入口 ≠ 良构调用(§54.8.4 第 1 条原样有效)。** 派发点 `0x1D08520` 只设 `rcx`/`rdx`,而 `0x3B01A0`
   消费 `rcx/rdx/r8/r9` 四槽,`r8`/`r9` **不是 Execute 的参数**、取的是上一调用者的 scratch。
   所以这一判据的形状是「计数只证明有人进来」;本次 shot 连「有人进来」都没证明,结论比它更强(0),
   但也**不能反过来**用它推断参数形状。
2. **0 只否证「经我们副本的 slot[2]」这一条路,没有指名真正的入口。** per-system 执行走的是
   donor vtable 原件、还是引擎自己复制的另一份表、还是压根不经虚派发 —— 本次 shot 三者不分。
   换 chokepoint 是结论,**下一个靶子不是**。
3. **非零那一支从未被正向验证过。** `classify_slot2` 把 `delta == SCORE_COUNT`(`SCORE_COUNT = 787`,`:39`)
   判成 `slot2_counted`,而我们的哨兵/body 是 **783**。783 是**渲染出的唯一 system 名数**,
   787 是 §54 那次记的 **per-system 执行次数** —— 两个数本来就不同源(§54.4 记过 787/783 的差)。
   如果 per-system 执行真经 slot[2],落在 `slot2_counted` 上的概率并不自动成立,可能落 `slot2_other`。
   本次 shot 判读走的是 0 那一支,**不依赖 787 这个数字**;但「787 ⇒ counted」这条判据从未被实机命中过这一点,
   要写在这里,不能让下一批人拿它当已验证的刻度。
4. **§54.8.4 第 2 条那道张力仍在。** 入口门 `[rdx+0x38]` 与 §53 的「arg2 类大小 `0x20`」直接冲突
   (`0x38 > 0x20`),离线判不掉。本次 shot 对它**中性** —— 既没支持也没否证「Execute 转发给 slot[2] 的
   `rdx` 就是 §53 量到的那个 0x20 对象」。

**这一节不改写 §54.6 或 §54.8 的正文**,只把它们的 fork 判到 (b)。

### §55.5 清理

`C4WireDisarm` **`disarm_rc = 0`**、**`host_alive = true`**(json `cleanup`),
`finally` 里走的是 `_cleanup`(`:1023`)。**没有 `FreeLibrary`** —— 被 patch 过的对象 `[obj+0]` 仍指向
DLL `.data` 的副本,卸载会让下一次 Execute 跳进空页(约束 5)。

pid 13364 在 shot 后仍存活。事后状态(`ssh Windows_Jiaolong "powershell -NoProfile -Command (Get-Content C:/temp/ns_game_status.json -Raw)"`,13:13:36):
`state="paused_no_window"`、`console_open=true`、`console_px=2315`、`console_forced=false`。
`2315` 就是 §54.10 校准的「开」值 ⇒ 控制台是 shot 留下的现场,**我没有为了收尾再去按键关闭它**:
那要再发一次输入,不属于这次 shot 的判据,也无助于任何结论。

**这次 shot 的现场是单向的**:pid 13364 注入过、额度用尽(约束:`stale_module` 不得放宽,一进程一次注入)。
它的处置(留着暂停、还是 `just game quit`)由人定,我不自行关游戏。

### §55.6 复现命令行

原始输出、误用、传输层的坑全在 `evidence/logs/c4_slot2_live_4_4_4.log`(逐条原样)。索引:

    just launch                                   # 第 1 节(两次 22 + 一次成功)
    just win "python C:/temp/game_supervisor.py status"     # 第 2 节(观测前提)
    ssh Windows_Jiaolong "powershell -NoProfile -Command (Get-Process stellaris).Id"
    ssh Windows_Jiaolong "powershell -NoProfile -Command (Get-Content C:/temp/ns_game_log.jsonl -Tail 12)"  # 第 4 节(门三输入)
    just win "python C:/temp/c4_wiring_probe.py --mode slot2 --dll C:/temp/sqjs_c4.dll --save C:/temp/stellaris_2226.sav --json C:/temp/c4_wiring_result.json"   # 第 5 节(本次 shot)
    ssh Windows_Jiaolong "powershell -NoProfile -Command \"(Get-Content C:/temp/c4_wiring_result.json -Raw)\""   # 第 6 节(json 原文)
    ssh Windows_Jiaolong "powershell -NoProfile -Command \"Get-FileHash -Algorithm SHA256 …\""   # 第 8 节(六项哈希)

**再打同一次 shot 的前置**(不是本节结论,是给下一批人的提醒):换一个游戏进程(注入额度已用)、
重跑 `just fence` / probe 56 / host-tests 223、并重新满足 §55.1 的观测前提。



---

## §56 scope 载体取型 shot:四根跟读 + 已知 vtable 集合命中(2026-10-24)

### §56.0 授权

人对这次 shot 的原话:**「退掉 13364 + launch 新进程 + 开枪」**;载入战役的方式选
**「我盲驱动,自己截图自己点」**。即:授权退掉 §55 的现场进程、起新进程、打这一发只读采样 shot,
并接受由我拉屏幕缩略图自己找按钮、自己点。

### §56.1 执行 shot 前必须先修的一件事:daemon 自己的控制台窗占住了前台

16:35 的第一次战役预检回报 `MARKERS 0 EXPECTED 783`,这一度被读成「这个进程没有战役」。
真因不在战役,在 `ns_game_log.jsonl`:

```
{"event": "console_refused", "hwnd": 198618, "reason": "focus", "t": "2026-10-24T16:35:29"}
STATUS=paused note=resume_failed: focus refused before Space
```

根因(离线可核,`Get-CimInstance Win32_Process`):

```
ProcessId 9608  pythonw.exe   "C:\temp\game_supervisor.py" serve      ParentProcessId 3348
ProcessId 3348  cmd.exe       /c ""C:\temp\ns_game_supervisor_task.cmd"  StartTime 16:31:09
```

`16:31:09` 与 `serve_start` 同一秒 ⇒ 那个 cmd 窗是 daemon 自己的父壳。任务用
`/ru <machine>\<user> /rl highest` + `/run /I` 起,cmd 于是在交互桌面上开了一个**可见**控制台窗。
这一轮 daemon 是在游戏(16:30:23)**之后**起的,所以窗口压在画面上并持有前台;`focus()` 的判据是
3 s 内 `GetForegroundWindow()==hwnd`,而 SetForegroundWindow 被 Windows 的前台锁拒掉 ⇒
一切要先 focus 的动作(console 投递、click、Space)全拒。处置是 `taskkill /F /PID 3348` 只杀父壳,
pythonw 9608 存活(`status age=0.2s`);窗口一消失 focus 立刻通。

**判读陷阱(新)**:「`MARKERS 0` ⇒ 没战役」是错的读法;`game.log` 只有 177 B 也不是判据 ——
Stellaris 的 `game.log` 只收 `log=` 与少量消息,启动叙述在 `debug.log`/`setup.log`,
day-1 存档留 177 B 完全正常(本卷 §55 的 783 条刻度也是从这一个文件数的)。
真判据是同目录的 `ns_game_log.jsonl` 里那条 `console_refused`。

**判读陷阱(新)**:daemon 的控制台窗会改变它自己要读的那张画面。§54.10 的像素门和
`classify_window` 都读同一张截图,窗口一挡分类就漂 —— 实测同一画面在挡与不挡之间从
`note=paused_no_window` 变成 `note=dialog_unknown`(挡的时候那个真事件窗根本不在采样区里)。

### §56.2 现场、字节、执行 shot 前提

- 游戏:pid **12796**(StartTime 16:30:23),hwnd 198618,`Responding=True`。
- 注入体:`C:/temp/sqjs_c4_scope_v2.dll` sha256 `373ab26ba87310f0acaffe941b9007bf0807b2a83872a5d27e2740c5d3e30471`,
  与本地 `zig-out/bin/stellaris_quickjs.dll`(15:45 构建)**逐字节同值**;装载基址 `0x7ffc3aad0000`。
- 判据集合:`C:/temp/ceffect_vtable_map_4_4_4.txt` sha256 `3e21961af61c6c6b…` = 本地同名文件,解析出 **1,805** 条 vtable。
- `keep_awake.py status` → `STATE=serving DESKTOP=unlocked`。
- 战役预检:`MARKERS 783 EXPECTED 783` —— 与 §55 同一份战役、同一条 783 刻度。
- 解除暂停前必须先清两个开局事件窗(「通讯已建立」的确认按钮、
  「信号传输接入 · 第一次接触」四选项里的**第一条**),都用 `just game click` 点掉;
  点完日期从 2249.01.01 走到 2249.01.04、底部「暂停」消失,再跑预检才拿到 783。

### §56.3 传输层:这次 shot 的 stdout 没活着回来

ssh 长连接在驱动跑完之前被重置,驱动自己那几十行(Install rc、STATS、OBJECTS、`VERDICT:`、
Uninstall/Verify/host alive)全部丢失。落盘的只有 TSV:10,580 B / 143 行,mtime 17:23:50。
**本节所有统计与判词都是从这份 TSV 加一次独立事后读回复算的,不是驱动的原始输出**,下文按此口径。

事后读回用 `scripts/scratch/2026-10_scope_shot/ns_scope_aftermath.py`(复用驱动自己的 helper,
读同一次 `C2ScopeProbeStatsInto`,间隔 2 s 读两遍):

```
READ 1: calls=414450 samples=809 invalid_self=1 invalid_ctx=0 lexer=0 x_nonzero=24 patch_size=16 installed=0 verified=0
READ 2: 同上,一字未动
```

`installed` 是 DLL 的实时 bool、`verified` 是 `verify()` 的实时返回值(`exec_hook.verifyState()`,
0 = 引擎字节完好),两者都**不是闩锁** ⇒ 这一对读数独立证明 Uninstall 真跑过、热路径已还原,
不需要驱动那行 `C2ScopeProbeVerify rc=0`。`calls` 两秒不涨是第三条佐证。

### §56.4 判词与它的字面答案

`classify()` 的固定阶梯按复算输入走:`calls=414450>0`、`samples=809>0`、
`valid>0`(256 条留存记录里 31 个不同 self 根、99 个 pointer-shaped 候选,直接可看出)、
`lexer=0` ⇒ 落到最后一档看 `known_vtable_hits`,它是 **14** ⇒ **`VERDICT: scope_candidate`**(exit 0)。

14 条命中的形状**全部 `source=self`**,即被采到的 base Execute 的 `this` 自己:

| 命中数 | self 内偏移 | 命中的 vtable RVA | 该类 slot[2] ExecuteActual |
|---|---|---|---|
| 5 | `+0x38` | `0x24b3050` | `0x33d410` |
| 5 | `+0x8`、`+0x30` | `0x2545e40` | `0xcc8bd0` |
| 2 | `+0x20` | `0x24c69e8` | `0x33c940` |
| 2 | `+0x10` | `0x254fa18` | `0xde40c0` |

四根各自的产出:

- `self`:31 个不同地址被跟读,99 个候选,14 个落在已知集合里。
- `helper`(= `[ctx+0x10]`):只有 **1** 个不同地址 `0x1900ede0`(栈地址),2 个候选,`known=0`;
  它 `+0x0` 那个 qword 解出 `0x7ff6a694c2d0` → **代码** RVA `0x9ec250`,不是 vtable。
  这正是 §53.4.1 记的「短命帧的邻位栈助手」,不是一个对象。
- `arg3` / `arg4`(r8/r9):**0 个地址过 `plausible_user_ptr` 门**,TSV 里一条 `source=arg*` 行都没有。

调用点直方图:256 条留存记录分布在 **41** 个不同站点上,头部是
`0x298a43`(40)、`0xde0539`(39)、`0x33ca60`(22)、`0x33d4c7`(19)、`0xddcf24`(12)、`0x1d08575`(8)。
其中只有 **2** 个能和 §53.1 那张 62 站点普查表对上
(`0x1bcd18d`→`incoming_arg`、`0xe845a7`→`not_examined`),其余 39 个 `func=- origin=-` ——
**包括全部六个头部站点**。

chain 两行 `ok=0 x=0x0`,与 §53.5 的证伪一致,判词中性,本节不取用它。

### §56.5 这次 shot 没有答的那个问题(负结论,且是有内容的负结论)

`scope_candidate` 这一档自己的判词就写着「CEventScope 的身份仍未由本判词确立」;数据把它说得更死:

1. **14 条全挂在 `self` 上**。一个对象的成员指向另一些 CEffect 家族对象,是复合 effect(子向量)的
   预期形状;这次 shot 重复确认的是「base Execute 的 `this` 是 CEffect 家族、且带 CEffect 家族成员」,
   不是「哪个对象是 scope 载体」。
2. **非 self 的三根一条命中都没有**。唯一带信息的 `helper` 解出的是代码,`arg3/arg4` 连门都过不去。
3. 集合是**下限**(§17 的过滤器要求 `slot[1]==base Execute`,任何覆写 Execute 的类都不在里面)
   ⇒ `known=0` 只能说「已知集合没匹配上」,不能说「不是对象」。
4. `arg3/arg4` 按 §54.8.4 不是参数(派发点只设 rcx/rdx),它们的值即使可读也不能按调用约定去读。
5. 那 39 个未对上的站点意味着:「这次 shot 采到的派发点是不是 §53 那批调用方」这个问题**没答上**;
   普查表覆盖的是另一批站点(它按 `0x1D08520` 的直接调用点建,这次 shot 的头部站点落在别处)。

⇒ 路线图段4 的问题(「真正的 `CEventScope` 是哪个对象」)**仍未收口**。而按「四根 + 一层解引用 +
已知集合」这个形状**再打一次,预期得到同一件事**,所以它不是「再开一次 shot」能推进的。往下需要的 datum
至少满足其一:

- **换判据集合**(零成本,应先做):1,805 是按 `slot[1]` 过滤的下限。拿一个不过滤的集合
  (全 `.rdata` vtable 候选)去重跑**已经躺在 `evidence/logs/scope_probe_v2_4_4_4.tsv` 里的 99 个候选**,
  离线就能做,不需要 shot、不需要进程。
- **换跟读形状**(需要 shot):self 之外必须有根 —— 例如从 `helper` 的栈邻位往调用帧方向扫,
  拿返回地址落回上面那 39 个未判读站点;或对已命中的对象做**第二跳**,看它们的成员里
  有没有非 CEffect 形状的对象。

### §56.6 现场与清理

- 一进程一次安装:pid 12796 的采样器额度**已用尽**(曾 `installed=1`,现 `installed=0`)。
- 不 FreeLibrary(约束 5):DLL 仍映射在 `0x7ffc3aad0000`,基址由事后读回确认。
- 引擎字节完好(`verified=0`,实时读两次)、host 存活(`Responding=True`)。
- 游戏停在**已载入并运行的 day-1 战役**里。事件窗选项(第一次接触选了四条里的第一条,善意回应)
  是**我替人做的**,它可能改变后续外交态势与系统数;783 这条刻度是在点那两个窗**之前**测的,
  本卷不据此推断战役后续状态。
- daemon 的父壳 cmd(3348)被我杀掉,daemon 本体存活;下次 `just game start` 之前不会再有那个窗。
- pid 13364(§55 现场)已按授权 `taskkill /F` 退掉。

### §56.7 复现命令行

```
# 前提:新游戏进程 + 战役已载入 + 已解除暂停
just launch
ssh Windows_Jiaolong "powershell -NoProfile -Command (Get-Process stellaris).Id"
ssh Windows_Jiaolong "cd C:\temp; python ns_scope_pre.py"          # 期望 MARKERS 783 EXPECTED 783
# 投递被拒时先看这条,不要先看 game.log:
ssh Windows_Jiaolong "cd C:\temp; Get-Content ns_game_log.jsonl -Tail 12"

# 本次 shot(一次安装额度,跑完不可重打)
ssh Windows_Jiaolong "python C:/temp/c2_scope_probe.py C:/temp/sqjs_c4_scope_v2.dll --poll-s 120 --settle-s 2 --out C:/temp/c4_scope_probe_v2.tsv --vtables C:/temp/ceffect_vtable_map_4_4_4.txt --census C:/temp/exec_frame_callers_4_4_4.tsv --id-names C:/temp/descriptor_oracle_4_4_4.tsv"

# stdout 丢了之后的恢复读回(证明 detour 已摘、引擎字节完好)
ssh Windows_Jiaolong "cd C:\temp; python ns_scope_aftermath.py C:/temp/sqjs_c4_scope_v2.dll"

# 拉回 artifact(scp 下载会重置连接,见 docs/offline-tooling.md 陷阱 8)
scripts/scratch/2026-10_scope_shot/pull_slice.sh c4_scope_probe_v2.tsv evidence/logs/scope_probe_v2_4_4_4.tsv
```

`--vtables` 在 host 上**必须显式给**:驱动里的默认值是相对路径 `evidence/xrefs/…`,
host 的 `C:\temp` 下没有这个目录,不给就会在注入**之前** `SystemExit`(这是设计好的不对称,不是缺陷)。

### §56.8 更正:§56.4 里三句话不成立,以及这次 shot 真正的 datum(2026-10-24)

终评审对着仪器重读了 §56.4,发现三个判读越界。原因是两个仪器缺陷加上一个缺 artifact 的乘积,
不是采样本身出错。修正提交:`e2567e3`。本节只追加,§56.4/§56.5 原文不改写。

**撤回 1 —— 「`arg3`/`arg4`:0 个地址过 `plausible_user_ptr` 门」。** 这三根**一次都没被读**。
旧的 `_entry_roots` 把 `arg3`/`arg4` 和 `helper` 一起放在 `valid == 1` 之后,而 `follow_roots` 的
`MAX_FOLLOW = 32` 是**四根共用**的预算:

```
for entry in entries:                      # 旧代码
    for source, addr in _entry_roots(entry):
        ...
        if len(objects) >= max_follow:
            return objects, implausible, True   # 整轮立刻结束,不是跳过这一根
```

artifact 里正好 **31 个 `self` 根 + 1 个 `helper` 根 = 32** —— 预算在 `helper` 上刚好耗尽,
同一批 valid 条目的 `arg3`/`arg4` 连门都没到过。所以「TSV 里一条 `source=arg*` 行都没有」
是**没读**,不是**过不了门**。`capture()` 是在任何 self/ctx 门**之前**写 arg3/arg4 的,
这两个槽的数据一直躺在环形记录里等着被读。

**撤回 2 —— 「`helper` 只有 1 个不同地址」。** 「1」是上面那条预算的算术结果,不是观测量。
而且它带的括号「(栈地址)」是本次 shot 没有做过的判读:区域归属只有 live 的 `QUERY_VIRTUAL_MEMORY` 能定,
这次 shot 只读了一个 qword。§53.4.1 那条「短命帧的邻位栈助手」讲的是**另一种**帧形状,拿它给
`0x1900ede0` 定性是套用,不是观测。**同时也不接受反向的套用**:有意见提出该地址落在确认在用的对象带里
(带 = `0x1_7ec02c80`…`0x2_147a5130`,即那 31 个 `self` 根的 min/max,复算自同一份 TSV),因而读起来像
稳定堆 —— 这条同样不成立:`0x1900ede0` 在带**之下**,只有 7 位十六进制,带的最小值是 9 位;按十六进制
**字符串**比大小会把它读成「在带内」,那是这次复核自己踩到的一次误读,记在这里是为了下次先按数值比。
两个方向都撤回之后,这一根剩下**唯一**站得住的 datum 是它的 word[0]:见下面撤回 3。

**撤回 3 —— 「它 `+0x0` 那个 qword 解出 `0x9ec250` → 代码,不是 vtable」。** 方向反了:
vtable 的每一个槽本来都是代码,「`[x]` 是代码」是 vtable 形状的**支持**证据而不是反驳。
这次 shot 真正的 helper datum 是把上界补上之后才露出来的:

```
root=0x1900ede0  off=0x0  ptr=0x7ff6a694c2d0  → 在 exe 镜像内,RVA 0x26dc2d0
```

`0x26dc2d0` 落在 `.rdata` 的 vtable 带里(§53 那个执行帧 vtable `0x26e4fa8` 同带),
不在 1,805 的下限集合内(下限只含 `slot[1]` 仍是 base Execute 的类),而它的第一个 qword 是代码
⇒ **一个 vtable 形状**。它不是「一个对象」,但也绝不是「一个被覆盖的栈残值」。
off=0x10 那一格是 `0x101000000`,镜像外,`vptr_rva=-`。

**因此:「四根 + 一层解引用 + 已知集合」这个形状没有退役。** §56.5 结尾那句「再打一次预期得到
同一件事」只在 `self` 那一根上成立 —— 四根里有三根从未被跟读,退役结论建立在一个只跑了
四分之一的形状上。§56.5 负结论的第 2 条(「非 self 的三根一条命中都没有」)**没有证据支撑**,
应当读作「非 self 的根没有被读过」。

`VERDICT: scope_candidate` 本身不变:14 条 `known` 命中不依赖上面任何一句话,复算仍是 14。
变的是这张判词**没有说**的东西。

**新的未决形状(复核时顺带看到,本次 shot 没有判。)** 帧指针本身是低地址,而帧里的字段是高地址:
两个 `ctx`(`0x7fe768`、`0x7fed78`)和 `helper` 根(`0x1900ede0`)都在 32 位量级,而 Windows x64 的
栈与模块装载都在 `0x7ff…` 这一量级 —— 这与「栈地址」的标注不符(撤回 2 的另一半理由)。
同一个 `helper` 根读出的 word[0] 却是 `0x7ff6a694c2d0`,一个正常的 48 位镜像内地址。
所以要么这些 `ctx`/`helper` 值是**arena 化/相对**的而不是绝对指针(AGENTS.md 对 db 全局记过同一种
疑症:主菜单读到的值「像 arena/相对指针或未初始化」),要么引擎真的在低 4 GB 里放这些东西。
两条都没法用这次 shot 的 artifact 分开 —— 它需要的是一次 `QUERY_VIRTUAL_MEMORY` + 同一个帧的
绝对/相对两种读法,而不是重跑同一个形状。**这条要进 §56.5 的那张「往下需要的 datum」清单。**

**新增的离线复算(零成本,不需要 shot、不需要进程)。** 脚本
`scripts/scratch/2026-10_scope_shot/ns_scope_recount.py` 只读两份已入库 artifact
(`evidence/logs/scope_probe_v2_4_4_4.tsv` + `evidence/xrefs/ceffect_vtable_map_4_4_4.txt`),
镜像界取 `exe_base = 0x7ff6a4270000`、`SizeOfImage = 0x3927000`(离线从 PE 头读,不是 DLL 基址 —— 陷阱 4):

- 候选总数 **99** = `self` 97 + `helper` 2;**在镜像内 64 条,镜像外 35 条**。
- 第二层查表(候选 qword **本身**是不是一个已知 vtable 地址,即多重继承子对象头的形状):
  **44 条,全部 `source=self`,13 个不同 RVA** ——
  `0x024b3690`×16、`0x024c69e8`×5、`0x024b3050`×5、`0x02517180`×4,
  ×2 的 `0x02545e40`/`0x0254a190`/`0x0254fa58`/`0x025531b0`/`0x025531e8`,
  ×1 的 `0x024b1c88`/`0x02551620`/`0x02553140`/`0x02553178`。
  其中 `0x024b3050`、`0x024c69e8` 同时出现在 §56.4 第一层的命中表里,即同一批地址既作为
  「成员的 vptr」出现,也作为「成员槽的值」出现。这是关于 **root 自己的类**的陈述,和第一层
  「成员指向某个已知类的对象」不是同一件事 ⇒ 修正后的仪器把 `member_vtable` **单独计数,
  并且故意不喂给 `classify()`** —— 喂进去会把「root 有子对象头」当成 scope 命中。
- **2 条 `vptr_rva` 是伪造的**:`0x7360ec6ccc426873`、`0x4e5ed44eaa1a4c50`。旧 `to_rva` 只有下界
  没有上界,一个明显是垃圾的 qword 被减出「像 RVA」的数。已补 DLL 自己的规则
  `[exe_base, exe_base+SizeOfImage)`;另有 16 条 `vptr_rva=-`。
- **2 条候选 ptr 是 ASCII 文本**:值 `0x54454e414c50` = `"PLANET"`,出现在两处 `off=0x18`
  (root `0x17ec8f580`、`0x17ec02c80`)。`plausible_user_ptr` 只看范围与 8 对齐,一段 6 字符
  文本正好满足 ⇒ 「pointer-shaped」不等于 pointer,这一格读的是个名字标签不是链接。

**判读陷阱(新)**:一条「某个 source 有 0 行」只有在预算没耗尽时才是负结论。共用预算 +
先到先得的迭代顺序 = 排在后面的根**必然**是 0,而这个 0 和「引擎在那个槽里没有指针」在
artifact 里长得一模一样。本次 shot 就是因为 TSV 里没有 meta 行、stdout 又被 ssh 重置吃掉(陷阱 11),
事后无从区分「没读到」与「读到但没有」。修正后:预算按根类型各自给(每源 8,总量仍是 32),
驱动打 `followed/implausible/capped/withheld` 四个 per-source 计数,并把它们连同 exe_base、
image_end、layout、stats 一起写进 TSV 的 `meta` 行 —— 判据现在住在带判词的 artifact 里。

**仪器侧另外两处**:装 `C2ScopeProbeStatsInto` 之前先过 `install_decision`(布局五字漂移就
拒绝安装,而不是带着位移过的偏移打完整一次 shot);`ns_scope_aftermath.py` 现在经 `gate_module`
拿 `base`/`exports`,即恢复读回也要 `C2Sanity == 42` 才派发 —— 它仍然先读一次
`resolve_base_address` 并在 `base == 0` 时早退,否则 `gate_module` 自己会把没映射的模块装进来,
`NOT_LOADED` 就永远打不出来。

## §56.9 用不过滤的形状集重问同一批候选(2026-10-24,零 shot)

一句话:**§56.8 那句「形状没有退役」现在有数了,但数不在驱动问过的那一层上。**

**判据集合与工具。** `scripts/scope_reclassify.py` —— 离线、只读三份已入库 artifact、不读 exe、
不起进程、不需要 shot:`evidence/logs/scope_probe_v2_4_4_4.tsv` 的 99 条 `object` 行 × 下限图 1,805 条
(经 `c2_scope_probe.load_vtable_map` **import 复用**,不重写解析)× Task 3 的
`evidence/xrefs/vtable_candidates_all_4_4_4.txt`(**172,296** 条,`run>=3`,不按 `slot[1]` 过滤)。

四桶(互斥且和为 `total`,由 `scripts/test_scope_reclassify.py` 钉住):

| 桶 | 条数 | 读成什么 | 读不出什么 |
|---|---|---|---|
| `total` | 99 | 与 §56.8 复算的候选总数一致 | —— |
| `floor_hits` | **14** | 与 §56.4 那 14 条命中对上 ⇒ 解析器口径没有漂 | 这 14 条仍是「成员指向一个已知类的对象」,不是「root 自己是 scope」 |
| `new_only_hits` | **0** | 在 `vptr_rva` 这一层,下限集**一条都没藏** | 绝不能读成「没有类覆写 Execute」 |
| `still_no` | 69 | 见下面分节普查 | 「不是对象」不成立:64 条的取值是代码 |
| `undecidable_no_rva` | 16 | 没有 datum | 不能读成「不是对象」 |

**那个 0 是结构性的,不是运气。** 对 83 条能解出 RVA 的行做分节普查(`rttibatch.Image` 只读 exe
拷贝的节表,零进程):`.text` **64**、`.rdata` **14**、`.data` **3**、镜像外 **2** —— 而那 14 条
`.rdata` 恰好就是 14 条下限命中。原因在取值的那一格:`vptr_rva` 是 `[[root+off]]`,即**驱动多读的
一层**;凡是候选 qword 自己就指向 `.rdata` 里的 vtable(§56.8 的第二层,44 条),多读一格拿到的是
那个类的**第一个虚函数**,而代码 RVA 不可能出现在任何 vtable 集合里(两个集合都只扫 `.rdata`)。
⇒ 「下限集藏了 Execute 覆写类」这件事在 `vptr_rva` 这一层**根本不可见**,不是因为没藏,而是因为
这一层的取值域不含 vtable。

**盲点显形的那一层。** 问候选 qword **自己**是不是 vtable(还是 §56.8 的第二层)。这一层 artifact
只能用绝对地址表达,而旧 TSV 没有 meta 行(§56.8 陷阱),于是必须借 §56.8 记下的
`exe_base = 0x7ff6a4270000`、`SizeOfImage = 0x3927000`(离线从 PE 头读,不是 DLL 基址 —— 陷阱 4)。
借来之后有两处独立对账把这个界钉住:镜像内 **64** / 镜像外 **35** 对上 §56.8 记的 64/35;
第二层落在下限集的行数 **44** 对上 §56.8 记的 44。复算脚本
`scripts/scratch/2026-10_scope_shot/ns_scope_ptr_shape.py`(一次性探针,**不是维护接口**)。

- 64 条候选指针**全部落在 `.rdata`**;**44** 条是下限集的 vtable,**20** 条不是。
- 这 20 条只有 **11 个不同 RVA**;对每个 RVA 向上数「同一串代码指针有多长」,
  **只有 3 个是块首**(`0x0247a530`、`0x02545b20`、`0x026dc2d0`),其余 8 个都在一条更长的连续
  代码指针串的**中途** —— 例如 `0x024b3030` 不是块首,而它 `+0x20` 处的 `0x024b3050` 正是 §56.4
  命中表里的表。Task 3 的集合按形状产出**每一个** run 起点(下限集必须是它的子集,这是它构造上的
  要求),所以「形状过而不在下限集」有两种同样可能的解释:**一个下限集漏掉的类**,或者
  **一张已知表的内部偏移**。本节只把块首当候选。
- 三个块首:

| ptr_rva | run | slot0 | slot1 | slot2 | root | source | off |
|---|---|---|---|---|---|---|---|
| `0x026dc2d0` | 8 | `0x9ec250` | `0x1ca5ae0` | `0x1ca5c90` | `0x1900ede0` | helper | `+0x0` |
| `0x0247a530` | 4 | `0x14f0a0` | `0x1564d0` | `0x156540` | `0x1d28c7d08`、`0x1d2a03ac8` | self | `+0x18` |
| `0x02545b20` | 8 | `0xd02480` | `0xd02480` | `0xd02460` | `0x1d286bfe8`、`0x1d2a73f28`、`0x1f7772248` | self | `+0x38` |

第一行就是 §56.8 撤回 3 那根 `helper`:`0x26dc2d0` 是一**块首形状**的 vtable 块,且不在 1,805 里
⇒ §56.8 那句「helper 不是对象没有证据」从现在起有了正面对象形状的证据。仍然读不出它是**哪个类**
(CEffect 家族无 RTTI,§14),也读不出这块内存属于哪类区域(私有提交?视图?保留?)。
后两行在 `self` 根上,各由 2–3 个不同 root 在同一内偏移命中同一个 RVA —— 记下来,本次 shot 不判。

**判读陷阱(新)**:`still_no` 那 69 条**几乎全是代码**。把「不在两个集合里」读成「不是 vtable /
不是对象」之前,先问这一层取的是哪一格 —— 多读一层之后的取值域是 `.text`,那个「一个都没有」是恒真的。

**判读陷阱(新)**:Task 3 的集合只叫「不按 `slot[1]` 过滤」,**不叫「不过滤」**:它扫 `.rdata`。
本次 shot 有 3 行 `vptr_rva` 落在 `.data`(同一个值 `0x2a0f450`,来自同一候选指针 `0xa7c060`,而它本身
在镜像基址**之下**,正是 §56.8 末尾那条「低地址形状」),它们在两个集合里都不可能命中 ⇒
这是**构造上的无法判定**,不是负证据。

**这一节改写了什么、没改写什么。** 改写了:§56.8 的「形状没退役」从一句读感变成可复查的判据 ——
在候选自己那一层,下限集漏掉 20 行 / 11 个 RVA,其中 3 个是块首,而 `helper` 根正是其中之一。
没改写的四件事:
① `vptr_rva` 那一层新集一条都没加(0),所以**只换集合不换层**是死路,下一次 shot 要问的是候选自己那一格;
② 本节这组数字依赖一个**从 artifact 外面借来**的 `exe_base`,旧那次 shot 没打 meta 行 —— 修正后的驱动已经会打
(§56.8 仪器侧),所以**下一次 shot**的同一问法是自足的,不必再借;
③ 绝对 `vptr` 没进 artifact(16 行 `vptr_rva=-` 同因),于是这 16 行加上 3 条 `.data` 行 = **19 行**
在本节的两个集合上**只能落在「无法判定」**,这不是判据缺失而是 datum 缺失;
④ **块首 ≠ 类**。要把 `0x26dc2d0` 这样的块首认成某个具体类,还缺「谁引用这张表」这一个静态 datum ——
它在镜像里问得出(`rttibatch.py` 已能扫 rip 相对引用与 vtable 附近的引用点),不需要 shot、不需要进程。


## §57 C4 下一个 chokepoint:离线判别(2026-10-24,零 shot)

一句话:**§55.4「没排除的第 2 条」那三种形状,静态没有把它们分开 —— 但它把缺的那一个读点、
以及下一次 shot 该点谁的函数,都定名了:采样面要换到 `0x3AFD30`,因为 `0x1D08520` 上根本采不到这一族。**

零 shot、零进程、零 Windows 机时:只读 `stellaris.exe` 拷贝的字节 + 已入库的 Task 3 候选集。
工具 `scripts/rttibatch.py --who-tables <rva[,rva]> [--candidates PATH]` / `--who-lea <rva>`,
接口一律以 **RVA** 表达(与 `AGENTS.md` 索引、下限图、候选集同口径)。

### §57.1 输入

| 输入 | 值 |
|---|---|
| 候选集 | `evidence/xrefs/vtable_candidates_all_4_4_4.txt`,**172,296** 行,`run>=3`,不按 `slot[1]` 过滤 |
| 交叉核对 | 下限图 1,805 条(独立复算:静态 qword 取值 == base Execute `0x1D08520` 的个数正好是 **1,805**) |
| 目标 RVA | `0x3B01A0`(donor 表 slot[2])、`0x3AFD30`(donor 表 slot[1] = Execute 覆写)、`0x2606FE0`(donor vtable 本身) |
| exe | sha 与出处见 `docs/offline-tooling.md` 前置条件,`NS_STELLARIS_EXE` 覆盖 |

### §57.2 观测(六个数,全部可离线复查)

| # | 观测 | 值 |
|---|---|---|
| 1 | `--who-tables 0x3b01a0,0x3afd30`:命中行数 / 不同表首 | 7,867 / 7,832 |
| 2 | 这些命中背后的**物理槽地址**(`vtable_rva + 8*slot_index` 去重) | **992** |
| 3 | 静态 qword 取值 == `0x3AFD30` / `0x3B01A0` / `0x2606FE0` | **538 / 454 / 0** |
| 4 | 前四槽与 donor 表逐槽相等(`0x1B4B30, 0x3AFD30, 0x3B01A0, 0x159730`)的候选表首 | **5 张**:`0x24B1D98`、`0x24EAAC0`、`0x25F4440`、`0x2606F00`、`0x2606FE0` |
| 5 | `--who-lea` 站点数(逐表) | `0x2606FE0`:1 站 `0x1893160`;`0x2606F00`:1 站 `0x18931B0`;`0x25F4440`:1 站 `0x18A05C0`;`0x24EAAC0`:**2** 站 `0x3AFB67`、`0x3AFC2D`;`0x24B1D98`:**75** 站;`0x3B01A0`:**0** 站 |
| 6 | 观测 4 那五张里 `slot[1] == base Execute 0x1D08520` 的张数 | **0** |

**站点 → 函数(`scripts/pdata.py` + `scripts/disrva.py` 逐条读到的,不是推的)。** 三个 create 逐字节同形,
`0x4e` 字节、共用同一份 unwind 记录 `0x274E810`,内部序列完全一致 —— `new(0xc0)` → `0x2188170(obj,0,0xc0)`
→ `call 0x3AFB40(obj)` → `[obj+0] = <各表>` → `[obj+8] = 0x24B1D78`,**只有那一张主表不同**:

| create | 装的 `[obj+0]` |
|---|---|
| `0x1893130..0x189317e` | `0x2606FE0`(= AGENTS 记的 donor create) |
| `0x1893180..0x18931ce` | `0x2606F00` |
| `0x18A0590..0x18A05DE` | `0x25F4440` |

而 `0x24EAAC0` 的两个站点在 `0x3AFB40..0x3AFC15` 与 `0x3AFC20..0x3AFD2C` 里 —— 前一个正是上面三个 create
共用的那个基类 ctor:`0x3AFB40` 先写 `[obj+0]=0x24EAAC0`、`[obj+8]=0x24B1D78`,派生 create 再把 `[obj+0]`
**覆写**成各自的表。⇒ 观测 4 那五张不是五个不相干的形状,而是**一个家族的 1 张基类表 + 4 张派生表**
(基类 `0x24EAAC0` 的 slot[1] 就已经是 `0x3AFD30`,即这一族从基类起就覆写了虚 Execute)。
`0x24B1D98`(75 站)不在这条 create 链上,它的 `[obj+8]` 邻居 `0x24B1D78` 才是那个共享子对象头。

### §57.3 简报那条规则在这里失效,要写明

计划写的是:「`0x3B01A0` 与 `0x3AFD30` 如果出现在**不止一张**静态表里,那『引擎自己复制的另一份表』
就有静态实体」。按字面执行 ⇒ 7,832 张 ⇒ 判给 (b)。**这个判定不成立**,三条独立原因,每一条都足以否掉它:

1. **两个靶子不是 donor 专属身份,是共用实现**(观测 3:`0x3AFD30` 在镜像里以静态 qword 出现 538 次)。
   一个共用实现出现在多少个派生类的表里,就等于「命中多少张表」,与复制无关。
2. **候选集按形状产出每一个 run 起点**(Task 3 为了让下限集成为子集必须这样构造),同一段指针数组被重复
   计入多个表首:7,867 行只对应 992 个物理槽(观测 1 vs 2)。
3. 收紧到「前四槽逐槽相等」把 7,832 压到 **5**,这一压缩是有用的枚举(§57.2 末尾把它认成了一个家族),
   但**前四槽逐字节相等是「从同一基类派生且这四槽都没覆写」的必然结果**。「复制」与「继承」在静态字节上
   是同一串,所以这一步仍然分不出 (a) 与 (b)。

⇒ 本节**不**按简报那条规则判给 (b)。按字面抄下来的数字留在观测 1 里,是为了让「这条判据长什么样」可复查,
不是为了给出结论。

### §57.4 判给哪一支 + 下一次 shot(判据与靶子点名级)

**三岔本身没被单独一次 shot 判掉,(a)/(b)/(c) 三支都还在。** 但「三者不分」现在的含义变了:静态把 (a) 从一个
猜测变成一个**有具体机制的候选** —— 这一族 objects 的虚 Execute 落点是它们 slot[1] 共用的 `0x3AFD30`,
而 `0x1D08520` 只是**没覆写 slot[1] 的那些类**的默认体(§52.5 原话)。于是:

**§54/§55/§56 三个 shot 工具的采样门全部挂在 `0x1D08520` 上,而按观测 6,这一族一张都不从那里进。**
这是本节对 C4 最直接的产出:前面三次 shot 的 `calls`/`delta`/`valid` 这些数,对 donor-shaped 这一族**没有覆盖**
—— 它们既不能证明这一族被执行,也不能证明没被执行。

**下一次 shot 的靶子(换成函数,不是换成槽):**

- **`0x3AFD30` 入口挂只读采样**,不是 `0x1D08520`,也不是我们那份 25 槽副本。记 `[self+0]` 的 RVA、
  `rdx`、`r8`。此处 `r8` **是** 第三个参数(`0x3AFD30(self, ctx, a3)`,§52.6),与 §55.4 未排除第 1 条
  「派发点上 `r8`/`r9` 取的是上一调用者的 scratch」**不同源**,两处的读数不能互相引用。
- 函数体一律转发原函数、不改寄存器不改控制流、永不 `FreeLibrary`(约束 5)。热路径纪律照 §10 的口径先测
  调用频率再定采样分母,不要照搬 base Execute 的 1/512。
- 前置:pid 13364 注入额度已用尽(§55.5)⇒ **新进程**;实机工具 ⇒ **本次会话内点名**。

**判据三档(互斥且完备,`[self+0]` 是那个缺的 datum):**

| 观测 | 判给 |
|---|---|
| calls>0 且 `[self+0] ∈ {0x24B1D98, 0x24EAAC0, 0x25F4440, 0x2606F00, 0x2606FE0}` | 经虚派发成立,且**指名哪一张**。若指名的不是 donor 那两张,§55.4 第 2 条的「引擎用的是另一份表」第一次拿到运行时实体 |
| calls>0 但 `[self+0]` 五张都不在 | 「另一份表」成立且**形态是运行时生成的表** —— 本节静态看不见它,下一节按实测 RVA 再问一次「谁引用这张表」(`--who-lea` 已能问) |
| 哨兵 body 等齐(执行确实发生)而 calls==0 | per-system 执行**不经这一族共用的 Execute 覆写** ⇒ 对 donor-shaped 而言 (c) 成立,再换 chokepoint |

### §57.5 没排除的事,五条(读这节时必须带着)

1. **运行时堆上生成/复制的表,静态看不见。** 观测 4 那五张是**静态候选**,不是「所有存在的表」。
2. **`slot_hits` 与「前四槽相等」都是形状判据,不是身份判据**(§57.3 第 3 条)。CEffect 家族无 RTTI(§14),
   所以也没有「按名字认表」这条退路。
3. **`--who-lea` 只认一种编码**(`48/4C 8D|8B` + `mod=00 rm=101` + disp32),既不认绝对立即数寻址,也不看
   `.rdata` 里的静态持有者。后者本节另扫了一遍:五张表的静态持有者都是 **0** —— 这个 0 是那次扫描给的,
   **不是** `--who-lea` 给的,别把它记成后者的能力。
4. **`0x3B01A0` 的 lea 站点 = 0**(观测 5)。instantiate helper 从不被代码 `lea`,它只以静态槽值存在。
   「0 站点」在这里的含义是「这个问题问不出答案」,不是「没人用它」—— 不要用前者推后者。
5. **候选集只扫 `.rdata`**(§56.9 那条陷阱原样适用),落在 `.data` 的表形成本节看不见,所以「命中 0 张」
   在任何一次 `--who-tables` 运行里都**不能**读成「没有另一份表」。

**这一节改写了什么、没改写什么。** 改写了:roadmap 段3 C4 行的「第一前置」从「下一个靶子未定」变成
「靶子 = `0x3AFD30` 只读采样,判据三档在 §57.4」;并新增一条覆盖范围的事实:**§54–§56 三次 shot 的采样面不含
覆写 slot[1] 的这一族**。没改写:① §55.4 第 2 条那个三岔仍未被判掉,只是从「三者不分」变成「缺的是哪一次
读取」;② 本节零 shot,对「per-system 执行到底发生了什么」没有任何直接断言,它只选出下一个读点;
③ §54.6 那个已判给 (b) 的 fork 与这里的 (a)/(b)/(c) **不同义** —— 前者的 (b) 说的是**我们那份副本**是克隆,
后者说的是**引擎侧有没有另一张表**,两个 (b) 不要串;④ donor create `0x1893130` 的身份、AGENTS 那张
RVA 表、以及约束 5 的别名策略,一行都不改。

### §57.6 复现命令行

```bash
python3 scripts/rttibatch.py --who-tables 0x3b01a0,0x3afd30 | grep 'rows'      # 观测 1+2:7867 / 7832 / 992
python3 scripts/rttibatch.py --who-lea 0x2606fe0                                # 观测 5:1 站 0x1893160
python3 scripts/rttibatch.py --who-lea 0x24eaac0                                # 观测 5:2 站(基类 ctor 那一侧)
python3 scripts/pdata.py  0x1893160 0x18931b0 0x18a05c0                          # §57.2 那三个 0x4e create 的边界
python3 scripts/disrva.py 0x1893130 0x4e                                          # create 体:两张表怎么写进对象
python3 scripts/disrva.py 0x3afb40 0xd5                                           # 基类 ctor:`[obj+0]=0x24EAAC0`
```

观测 3 与「静态持有者 = 0」那两条是段内全扫(`Image.secs` + `struct`),目前**没有 CLI flag**,
一次性脚本没入库 —— 要复核它们就照 §57.5 第 3 条的口径自己扫,别拿 `--who-lea` 的输出去对。

## §58 修正仪器重打:第一次 shot 是环境空值,成因有名(2026-10-25,点名)

**授权级别**:点名授权下的实机段。人对本段的原话是「**授权:我退进程 + 新 launch + 按修正流程重打**」;
现场弹窗另给一句「**你可以用现成的命令来关闭,如果还是不行,那就截图加自己点**」。本段没有新的 C1 注册、
没有引擎写入、没有 `FreeLibrary`。计划 = `2026-10-24-scope-reinterpret-and-desktop-gate` 的 Task 7,
PR #13(merge `534116d`)之后。

### §58.1 执行 shot 前的四条(D 组),以及第四条错在哪

| # | 前置 | 实测 |
|---|---|---|
| 1 | 注入体字节不变 | 远端 `C:/temp/sqjs_c4_scope_v2.dll` 与本地 `zig-out/bin/stellaris_quickjs.dll` 同为 `373ab26b…30471`,与 §56 记下的逐字一致;部署的 7 个 host 文件与 repo HEAD 全部 hash 相同 |
| 2 | 预检刻度 | `ns_scope_pre.py` → `MARKERS 783 EXPECTED 783` |
| 3 | 新进程 | pid **13132**(§56.6 那台 12796 的额度早已用尽) |
| 4 | 战役已载入**且已解除暂停** | 载入 ✓;「暂停」这一半**在预检之后没有重读** ⇒ 见 §58.3 |

第四条是这次 shot 唯一的实质损失,而且它不是「忘了看」:预检这个动作本身就会把状态打回暂停(§58.3)。
所以这条前置的正确读法是**紧邻执行 shot 读**,不是流程更早时的某一次读数 —— 已写进
`docs/offline-tooling.md` 判读陷阱 9。

### §58.2 读数:装上了,一次都没穿过

artifact = `evidence/logs/scope_probe_v3_4_4_4.tsv`(25 行,全量拉回)。

- `meta exe_base 0x7ff6abbf0000`(新 ASLR 基址)、`layout … version=2`、`per_source_follow 8` —— 仪器侧全部就位;
- `calls=0 samples=0 valid=0`;四根 `followed/implausible/capped/withheld` **全为 0**,
  即 Task 5 那笔账(§56.8 的「三个源恒 0」)在这次 shot**没有得到任何检验**;
- `regions_queried=0`、`region_verdicts` 空 ⇒ §56.8 末段那条低地址未决项**仍未测**;
- `known_vtable_hits / member_vtable_hits / unknown_ptr_hits / unreadable_roots` 全 0;
- `verdict no_calls`。

`scope_reclassify.py` 重问同一份 artifact:`object rows 0`,四桶全 0。⇒ **计划 Task 7 Step 4 那条
`undecidable_no_rva == 0` 的验收在零行 artifact 上恒真**,它这一刻不证明任何事;要有意义必须先有行。

### §58.3 成因:控制台开着 ⇒ 引擎暂停 ⇒ 热路径没有调用

执行 shot 前后的监督器记录读的是 `{'state': 'paused', 'note': 'dialog_unknown', 'red': 167→132, 'green': 0,
'console_open': True}`。`ns_scope_pre.py` 的通道就是调试控制台(剪贴板粘贴 + 回车),而 **Stellaris 在控制台
打开期间暂停**。链条因此是:`MARKERS 783` 成功 ⇒ 控制台仍开 ⇒ 游戏暂停 ⇒ `0x1D08520` 一次不被调用 ⇒
采样器 `install=1` 但计数为零。

这条 `no_calls` 是**环境结论,不是代码结论**,与 §56.2 那条「看到 `no_calls` 先核是否真在跑」同型,
只是这次的原因具体到控件。它也不推翻 Task 5 的仪器改动 —— 四个源各自预算的改动只在有 entry 时才起作用。

### §58.4 ssh 重置、清理、以及那行 `installed=1 verified=-1` 该怎么读

ssh 长连接在驱动跑完之前被重置(§56.3 的重复,判读陷阱 11)。**没有重新执行 shot**;走事后读回。

- artifact 里 `stats … installed=1 verified=-1` **不是遗留安装**:驱动在 `finally` 之前写 TSV
  (`scripts/c2_scope_probe.py:1210` 写,`:1222` 才 `_cleanup`),所以那一行是**写 artifact 时刻**的快照。
- 事后实时读回:手工那一遍跑之前就是 `installed=0 verified=0` ⇒ 驱动自己的 Uninstall/Verify 已跑完;
  `scripts/scratch/2026-10_scope_shot/ns_scope_finish_cleanup.py` 再幂等复核一次:
  `C2ScopeProbeUninstall rc=0`、`C2ScopeProbeVerify rc=0`(引擎字节完好)、host 存活、`RESTORE_OK`。
- 不 `FreeLibrary`(约束 5),DLL 仍映射。
- 预防措施:`scripts/scratch/2026-10_scope_shot/c4_scope_run_v4.cmd` —— 把驱动装在 host 上 detached 跑,
  stdout 与 `EXIT:%ERRORLEVEL%` 落 `C:\temp\c4_scope_run_v4.txt`,这样一次 ssh 重置不可能再把安装 orphan 在
  Uninstall 之前。**这是预防,不是 §58.4 上面那条的替代解释。**

### §58.5 重打被什么挡住

pid 13132 的「一进程一次安装」额度已用尽 ⇒ 按授权 `taskkill /F /PID 13132`,新 `just launch` 起 pid **22220**
(`hwnd=330684`,进战役)。第二遍预检再次 `MARKERS 783 EXPECTED 783`;但随后现场卡在
`state=paused, note=dialog_unknown, console_open=True, console_px 2313→2307` —— `console_close` 两次没落地,
`dismiss` 的读数被 ssh 争用打断(`JSONDecodeError`)。截图路线(人已授权)拉回 `ns_shot_small.jpg` 时
**主机整体不可达**:2026-10-25 `10.66.0.7` 走 `wg0`,ping 100% 丢包,ssh 三次 `Connection timed out`。
⇒ **修正流程的那次 shot(v4)没有打**,`evidence/logs/scope_probe_v4_4_4_4.tsv` 不存在。§56.5 那个问题
(真正的 `CEventScope` 是哪个对象)在本段之后**仍未收口**,状态与 §56.8 相同。

本地一侧不受影响。merge 后的树上:`just check` 在 `build` 之后停在 `test`(exit 1),那一条是基线形状
(`26/29 steps; 445/445 tests passed` + 16 个 kernel32 `undefined symbol`,依 ruling P15 记为绿);
因此 `fence`/`host-tests`/`chokepoints-check` 三个门单独跑,分别 27 passed、262 passed、exit 0;
计划 Task 9 Step 2 点名的五个 Python 文件 160 passed、0 failed。

### §58.6 附带实机观测:桌面门上线后的第一次 `just launch --verbose`

计划 Task 8 Step 1。两次 `just launch --verbose` 都退 **0**,时间线里各有 `step=trace` 行,attempt 1 为
`owns_foreground=True cursor_at=(1064,339) launcher_alive=True`,但交接要到 attempt 2 才成 —— 这正是被记为
deferred minor M3 的「点击落了但被吞掉」在实机上的一次重现,读数本身入档,修复不在本段范围。

**两条计划期望与实现的差,当场判掉(是判读,不是改代码):**

1. Task 8 Step 1 的 Expected 要求时间线里出现 `DESKTOP_GATE` 行。实现
   (`scripts/windows/launch_stellaris.py:1679-1692`)在 `verdict == "ok"` 时**先 return 再 log**,即桌面门
   **只在拒绝时留痕**。所以 exit 0 的那两轮根本没有 `DESKTOP_GATE` 行可看,这条 Expected 恒不满足。
   桌面门在实机上的正面 datum 只能来自退出码 **25**,而那需要 Task 8 Step 2(人当场按 `Win+L`)—— 未取。
2. Expected 里的 `step=diagnosis` 只在点击失败路径上打印(`:895-896`),成功交接的轮次**不可能**有这一行。
   同一次运行的 `cursor_at=(1064,339)` 但交接失败,已经证明「三档诊断」这条路径值得拿到实机读数 —— 它要的是
   失败轮,不是成功轮。

`desktop=locked` 那一格仍然只有离线测试钉着(§8 判读陷阱 6 的原话未过期)。

## §59 v4 按修正流程打的 shot:四根全跟到、区域仪器有读数,仍无 scope 候选(2026-10-25,点名)

产物 = `evidence/logs/scope_probe_v4_4_4_4.tsv`(4,845 B,pid 22220)。这是 §58 撤回空值之后按修正流程
重打的那次 shot,**装上了、验了字节、计数不为零**。本节逐条对 §56.8 的欠账还账,并更正 §58.3 的因果句。

### §59.1 更正 §58.3:控制台不是暂停者,弹窗才是

§58.3 把 v3 的 `no_calls` 归因于「预检打开调试控制台 ⇒ 引擎暂停」。这条因果句**错了**,本次 shot 执行前的
读数直接证伪它:

- 预检后现场读数 = `console_open=true`,而分类器 `red=0 / green=200` ⇒ `state=playing`。
  控制台开着**并没有**暂停引擎。
- 真正暂停游戏的是预检期间弹出来的**事件窗**(`dialog_unknown`)。事件窗自己会暂停游戏,
  这是监督器早就记下的判读陷阱 4;§58 那次 shot 撞上的是它,不是控制台。

⇒ 前置读数只有一条是必需的:**紧邻执行 shot 读 `state=playing`**。`console_open=false` 不是判据,
把它写进流程只会让人去关一个无关的窗(§58 里 `console_close` 两次没落地,本来就不该落地)。
`docs/offline-tooling.md` 判读陷阱 9 已按这条改写。
**这不是新错**:§54.9 早就把控制台的问题限定成「daemon 的 `console_open` 标记与面板实际状态脱钩」
(通道可靠性),从来没有「开着 ⇒ 暂停」这条;§58.3 是把两件事并成了一件。同类判读下次先查 §54.9 的措辞。

清窗走的是人已授权的点击路线,顺带暴露监督器的一处缺陷(见 §59.2),窗清掉后读数立刻回 `playing`。

### §59.2 打成功的流程,以及 `click_close` 的固定偏移

1. 按授权 `taskkill /F /PID 13132`(§58 把该进程的一次安装额度烧掉了)→ 新 `just launch` → pid **22220**、
   `hwnd=330684`、进战役。
2. 预检 `MARKERS 783 EXPECTED 783`(与 §58 同一读数)。
3. 事件窗挡路 → 需要点掉。监督器的 `click_close`
   (`scripts/windows/game_supervisor.py:737-746`)算出的点是 `(bbox[2]-96, bbox[1]+51)` = **(1843, 517)**,
   量出来的真 X 在 **(1343, 480)** —— 差 500 px。原因是 `click_close` 假定关闭按钮离 bbox 右缘 96 px,
   这个事件窗不满足。第一次点 (1343, 470) 差 10 px 没命中,第二次 (1343, 480) 命中,窗关,`state=playing`。
   **坐标是屏幕绝对的**(`window_metrics` 的 bbox 已加过 `x0/y0`,`_click_at` 用 `SetCursorPos`),
   这一点在拉截图量 X 之前值得先确认。缺陷入档,修 `click_close` 不在本段范围。
   回 `playing` 那一步**不能读成我们解除了暂停**:监督器判读陷阱 4 写的是「事件窗口自己会暂停游戏,
   关窗口又可能自己恢复」,这次 shot 没发过 `unpause`,是窗口消失后引擎自己走的 ⇒ 清窗之后必须重取一次读数,
   清窗前的 tick 不能当执行 shot 前置。
4. 紧邻执行 shot 读 `state=playing` → 执行 shot。

**两次后台启动都失败**:launcher 是普通子进程,sshd 会连子进程树一起收掉;而脱离作业对象的两种写法
(`start /min ""` 静默 no-op;`Start-Process` 经 ssh 的嵌套引号被 PowerShell 拆坏)都没把 shot 投递出去
(`scripts/scratch/2026-10_scope_shot/c4_scope_run_v4.cmd` 留在原地,别再试第三种写法)。最终**前台跑 +
ssh keepalive**,驱动完整走完并自己做完清理。判读:陷阱 11(ssh stdout 中途丢失)防的是「装了没卸」,
这条靠 `--out` 落盘的 TSV 与事后 `ns_scope_finish_cleanup.py` 的读回双重兜住,本次 shot 两者都验过。

### §59.3 §56.8 的账:四根确实全跟到了,负结论这次有内容

| 键 | 读数 |
|---|---|
| `stats` | `calls=3061 samples=5 valid=5 invalid_self=0 invalid_ctx=0 lexer=0 x_nonzero=5 patch_size=16 installed=1 verified=-1` |
| `followed_by_source` | `self=4/helper=2/arg3=1/arg4=1`(合计 8 = `per_source_follow`) |
| `capped_by_source` / `withheld_by_source` | 四源全 0 |
| `implausible_by_source` | `self=0/helper=0/arg3=2/arg4=0` |
| 四桶 | `known_vtable_hits=0 member_vtable_hits=0 unknown_ptr_hits=16 unreadable_roots=0` |
| 区域 | `regions_queried=10`;`arg3/image=1/arg4/image=1/ctx/private_committed=2/helper/private_committed=2/self/private_committed=4` |
| verdict | `no_scope_candidate` |

按源分预算这条修对了:没有任何一根被 `capped` 或 `withheld`,四根各至少读到一次,`unreadable_roots=0`。
所以 §56.8 撤回复判的依据(「`arg3`/`arg4` 一根没读、`helper` 撞预算」)在本次 shot**不成立**,
`no_scope_candidate` 这次是「仪器真的问完了」的负结论。

离线复算(`scripts/scope_reclassify.py --tsv 本产物`):`floor set 1805 / shape set 172,296 /
object rows 16 / floor_hits 0 / new_only_hits 1 / still_no 0 / undecidable 15`。
**`still_no=0`** —— §56.8 说的「99 行里那些没判读的站点」这次 shot 没有再出现,16 个 qword 全部要么在图像内、
要么被明确判成图像外/零。

### §59.4 §56.8 末段的未决项有了答案:低地址是绝对地址

10 次区域查询里 **7 次落在同一个区域**:`base=0x7fe000 size=0x2000 state=0x1000 protect=0x4 type=0x20000
alloc_base=0x400000`。五个 32 位量级的根(`0x7fe4f0`/`0x7fe960`/`0x7fe768`/`0x7feb00`/`0x7fed78`,
来源含 self、helper、ctx)全在这个区里,另外三根(self)落在两个正常的私有堆区
(`base=0x1fdf4a000 size=0x2000 alloc_base=0x1fd0d0000`;`base=0x10384d000 size=0x73000 alloc_base=0x103780000`)。

⇒ **它们是绝对地址,不是相对指针,也不是 arena 内偏移**:`type=0x20000` 是 `MEM_PRIVATE`(不是
`MEM_IMAGE`),`protect=0x4` 是 `PAGE_READWRITE`,状态 `0x1000` = `MEM_COMMIT`,而整个区被一次
起始于 `0x400000` 的分配持有。§56.8 提的两种猜想都被这一条否掉。
**这次 shot 没判、也不该判的**:这个 8 KB 私有区是谁给的(哪个分配器、干什么用的)。
它低地址、私有、可读可写,和「一堆执行深度帧 + 它们的暂存」相容,但相容不是证据。

### §59.5 §56.5 第 4 问有正面答案:`arg3`/`arg4` 承载的是代码,不是对象

| 根 | 区域判读 | 换算 |
|---|---|---|
| `arg3` | `image base=0x7ff6ad8f8000 protect=0x20 type=0x1000000 alloc_base=0x7ff6abbf0000` | 目标地址 `0x7ff6ad8f8520` = exe_base + **`0x1D08520`** = base Execute 自己 |
| `arg4` | `image … target 0x7ff6add77b28` | = exe_base + **`0x2187b28`** |

`arg3` 指回被 detour 的函数本身,`arg4` 那三点离线一拆就是复制 thunk:

```
02187b28  movzx ecx, word ptr [rdx]
02187b2b  mov   word ptr [rax], cx
02187b2e  ret
```

两个都在 `MEM_IMAGE` 且 `protect=0x20`(`PAGE_EXECUTE_READ`)。⇒ **这两根不是对象载体,是代码地址**;
`implausible_by_source arg3=2` 是仪器对它们的正确反应(判成不可信)。§56.5 第 4 问就此关掉:
四根里承载 scope 的候选只剩 `self` 与 `helper`,而 §59.6 把它们各自唯一能判的线索也降掉了。

### §59.6 唯一可判的 vptr,和它为什么不算 scope 证据

16 个 qword 里只有 **1** 个的 vptr 落在图像内(`vptr_rva=-` 的 15 个里:7 个非零但在图像外、5 个为 0、3 个读不到):

```
object 0x7fe960 source=helper off=0x10 ptr=0x2ddc2c90 vptr=0x7ff6ae06a358 vptr_rva=0x247a358
```

它**不在** 1,805 的 floor map(所以 `known_vtable_hits=0`),但在不过滤的形状集里 ⇒ 就是
`new_only_hits=1` 那一条。离线拆它的 Execute 槽:

```
00156cc0  push rbx / sub rsp,0x20 / mov eax,[rcx+0x14] / mov rbx,rcx /
00156ccc  cmp eax,[rcx+0x10] / je …  / test eax,eax / jne …
```

开头比较 `[rcx+0x10]` 与 `[rcx+0x14]` 两个计数 —— 访问器/容量检查的形状,**不是 CEffect 家族的
Execute 覆写**。⇒ 这条线索降级:`0x247a358` 是「形状像 vtable、槽内容不像 effect 派发」的表,
拿它当 scope 证据是读过头。

顺带记一个跨根的连线,它没被本次 shot 判读但下次值得看:`self` 根 `0x7feb00+0x28` 读到 `0x7febd0`,其首 qword
是 `0x2ddc2c90`;而 `helper` 根 `0x7fe960+0x10` 直接读到 `0x2ddc2c90`。两根碰到**同一个**格子,
说明它们至少在这一层是同源数据,不是四个独立对象巧合。

### §59.7 §56.5 第 5 问:caller 对普查表,一对一不中

```
caller 0x1bcd18d 3 func=0x1bcd120 origin=incoming_arg
caller 0x1c43699 2 func=- origin=-
```

`0x1bcd18d` 在 §53 的调用点普查里(`evidence/xrefs/exec_frame_callers_4_4_4.tsv:63`,
`mov rdx,rbx @0x1bcd17a; rbx <- rdx @0x1bcd131 (single write)`),`origin=incoming_arg` 意味着
`0x1bcd120` 只是把它**收到的**那个 0x20 B 帧转手递给 base Execute —— 真正的构造点在更上层,本次 shot 没到。
`0x1c43699` **不在**普查表里:普查是 §53 按当时的判据切的,不覆盖它 ⇒ 这是一条待办,不是矛盾。

### §59.8 Task 7 Step 4 那条验收写反了

计划里 `undecidable_no_rva == 0` 当验收。本次 shot **`undecidable=15`**,而那 15 个正是「vptr 不在图像内所以
没有 RVA」—— 这**就是** bounds 修复之后应该显示的样子(修之前它们会被误算成合法 RVA)。
⇒ 这条验收 mis-specified:零行 artifact 上它恒真(判读陷阱 9),有行 artifact 上它把正确行为判成失败。
它不该当验收,该当读数。

### §59.9 仍未收口的部分

`verdict=no_scope_candidate` 的有界含义照旧(判读陷阱 1):**四个根下没有任何 qword 的 vptr 落进那 1,805 个
已知 vtable**。本次 shot 把它从「仪器没问完」升级成了「仪器问完了,答案是零」,但**没有**确立真正的 `CEventScope`
是哪个对象 —— §26.2 那句仍然有效,§56 那一条在 roadmap 里仍不开口。

下一次 shot 的前置,本次 shot 读出来两条具体的:
1. 唯一还在的候选是 `self`/`helper` 两根,而它们的样本全在 §59.4 那个 8 KB 私有区里 ⇒ 要的是**更深的
   跟读形状**(同一根上第二层解引用,或按 §59.6 那条同源连线追),不是同形状再打一次。
2. `origin=incoming_arg` 说帧来自更上层 ⇒ 从 §53 普查表的调用方**往上**定帧构造点,是一条零 shot 路线,
   应当先于任何下一次 shot。

### §59.10 清理与本机状态

驱动的 `verified=-1` 是**清理前的快照**(`c2_scope_probe.py:1210` 先写 TSV,`:1222` 才 `_cleanup`)。
事后单独跑 `scripts/scratch/2026-10_scope_shot/ns_scope_finish_cleanup.py 22220 <dll>` 复核,顺序按授权要求:

```
[scope] C2ScopeProbeUninstall rc=0
        C2ScopeProbeVerify rc=0 (engine bytes intact)
        host alive
AFTER calls=3061 samples=5 … installed=0 verified=0
RESTORE_OK
```

进程 `Responding=True`,**没有** `FreeLibrary`(约束 5)。pid 22220 的「一进程一次安装」额度已用尽 ——
再来一次 shot 需要新进程,前置同 §59.2 第 1–3 步(尤其:清掉事件窗,再紧邻执行 shot 读 `state=playing`)。

### §59.11 复现

驱动那一行 argv 钉在 `scripts/scratch/2026-10_scope_shot/c4_scope_run_v4.cmd` 里(它同时是把脚本
scp 到 `C:\temp\` 后的落地形态):

```
python C:\temp\c2_scope_probe.py C:\temp\sqjs_c4_scope_v2.dll --poll-s 120 --settle-s 2 \
  --out C:\temp\c4_scope_probe_v4.tsv --vtables C:\temp\ceffect_vtable_map_4_4_4.txt \
  --census C:\temp\exec_frame_callers_4_4_4.tsv --id-names C:\temp\descriptor_oracle_4_4_4.tsv
```

本次 shot 是**前台经 ssh 跑这一行 + keepalive**(§59.2:两种脱离作业对象的写法都没把 shot 投递出去,不要再试第三种)。
清理复核单独跑 `python3 scripts/scratch/2026-10_scope_shot/ns_scope_finish_cleanup.py 22220 <dll>`
(位置参数**先 pid 后 dll**)。产物拉回走 slice 通道(判读陷阱 8):

```
scripts/scratch/2026-10_scope_shot/pull_slice.sh c4_scope_probe_v4.tsv evidence/logs/scope_probe_v4_4_4_4.tsv
python3 scripts/scope_reclassify.py --tsv evidence/logs/scope_probe_v4_4_4_4.tsv
python3 scripts/disrva.py 0x2187b28 6 && python3 scripts/disrva.py 0x156cc0 8
```

DLL sha `373ab26b…30471` 与 §58 同一份,merge `534116d` 没有改动它。

## §60 零 shot:承载函数 0x1c42fe0 自己构造执行帧;两条已知线索判死为「写者」(2026-10-25,离线)

授权级 = 离线 **零 shot**:无 launch/inject/install/Frida/process,只静态读默认本地 exe 拷贝(sha `9242c40a…b1a56`,
`docs/offline-tooling.md` 前置条件)。不走 IDA license 门:本节所有引用判读来自 `scripts/find_refs.py` 与
`scripts/riprefs.py`(离线完整解码),未用任何 IDA MCP xref。生产者脚本逐个标注在每个读数旁。
本节回答的是 §59.9 第 2 条的零 shot 路线(「从普查表往上定帧构造点」),问的是**谁写 `[rsp+0x38]`**,
不是 §59 的 scope 问题 —— **§59 的 `no_scope_candidate` 原样不动**,两问不同。

### §60.1 承载函数边界与入口契约(`pdata.py` / `disrva.py`)

`python3 scripts/pdata.py 1c4369b` → **0x1c42fe0..0x1c43884**,与 `evidence/xrefs/exec_frame_sites_4_4_4.tsv`
第 2 行的 func 列一致。函数体 = `python3 scripts/disrva.py 0x1c42fe0 --end=0x1c43884`(476 条)。

入口(`disrva.py` 同上,0x1c42fe0 起):`test rdx,rdx; je 0x1c43844` ⇒ arg2==0 直接 `ret`;
`mov [rsp+8],rcx; mov [rsp+0x10],rdx` 把两个寄存器参数落进影子槽 —— 7 个 push + `sub rsp,0x3e0` 之后
`[rsp+0x428]` 正是 arg2 的落槽,尾声 0x1c43628 `mov rdi,[rsp+0x428]` 取回的就是它。于是:

- **arg1(rcx→r13,0x1c43010)= 队列对象**:`[[arg1+0x88]+0x6c]` 是计数(0x1c43013/0x1c4301a,`disrva.py`),
  `[arg1+0x120]` 忙位由 `lock xadd` 取旧值(0x1c43037),旧值写进 arg2+0x18(0x1c4303f)。
- **arg2(rdx→rdi,0x1c4300d)= 被执行的 item**:`[item+0x12] ← min(0x7fff, 队列计数)`(0x1c43028),
  item 的虚表槽 +0x50 返回 token id(0x1c430b0,见 §60.3)。
- 同表 +0x30 槽 `0x1c42ee0`(`pdata.py` 0x1c42ee0..0x1c42fdc;`disrva.py 0x1c42ee0 60`)是成对的排空循环:
  锁 `[rip+0x74f601]→0x23925c0`、环 `[rbx+0x100]/[rbx+0x118]`、`call [rax+0x60]`、拷 `[rdi+0x18]→[rax+0x18]`、
  `call [rax]` edx=1 析构、`inc [[rbx+0x88]+0x6c]` —— 字段用法与本函数一致 ⇒ **0x26d4dd0 这类是异步
  effect 执行队列**(datum:类内两方法字段互证),承载函数是它的虚槽 +0x28「执行一条」。

### §60.2 `[rsp+0x38]` 写点逐条表(生产者:`disrva.py 0x1c42fe0 --end=0x1c43884`)

grep 全函数,涉 `[rsp+0x38]` 的指令**恰好 6 条**,帧内部字段写另有 4 条:

| RVA | 指令 | 帧字段(基 = rsp+0x38) | 说明 |
|---|---|---|---|
| 0x1c43081 | `mov [rsp+0x38], r14` | +0x00 vptr | r14 = `lea [rip+0xaa1f27]→0x26e4fa8` @0x1c4307a |
| 0x1c43086 | `mov dword [rsp+0x40], r15d` | +0x08 depth = 0 | r15d 于 0x1c4304e `xor` 清零 |
| 0x1c4308b | `mov byte [rsp+0x51], r15b` | +0x19 所有权 = 0 | |
| 0x1c43098 | `sete byte [rsp+0x50]` | +0x18 = (helper+0x14==0) | 前置 `cmp dword [rsp+0x244], r15d` @0x1c43090 |
| 0x1c430a5 | `mov [rsp+0x48], rax` | +0x10 helper 指针 | rax = `lea [rsp+0x230]` @0x1c4309d |
| 0x1c430b5 | `mov dword [rsp+0x58], eax` | **帧外**(帧 = 0x38..0x57) | token id spill,来自 §60.3 的 `[rax+0x50]` |
| 0x1c43669 | `lea rcx, [rsp+0x38]` | 帧地址第一次离开本函数 | → 0x1c4366e `call 0x1d129a0` |
| 0x1c43677 | `lea rcx, [rsp+0x38]` | | → 0x1c4367c `call 0x16fdc0`(edx=esi=id) |
| 0x1c43686 | `lea rcx, [rsp+0x38]` | 任务点名的 **edx=1 线索** | → 0x1c4368b `call 0x16fdc0` |
| 0x1c43693 | `lea rdx, [rsp+0x38]` | 帧作为 arg2 | → 0x1c4369b `call [rax+8]`(§60.6) |
| 0x1c4369f | `mov [rsp+0x38], r14` | +0x00 vptr 复写 | r14 = `lea [rip+0xaa196d]→0x26e4fa8` @0x1c43634 |

字面写 `[rsp+0x38]` = **2 条**(0x1c43081 初置、0x1c4369f 派发后复写),帧内其它字段写 = **4 条**
(0x1c43086/0x1c4308b/0x1c43098 `sete`/0x1c430a5)。骨架前文:规格对象 `0x247b098`(`lea [rip+0x83804f]`
@0x1c43042)落 `[rsp+0x68]` @0x1c43049,helper 就地构造 `call 0x1ca5880`(rcx=&[rsp+0x230], rdx=&[rsp+0x68],
r8=0, r9=1;0x1c43060..0x1c43074)。逐字段与 §53.3/§53.4 的帧表**字节一致**(vptr 0x26e4fa8 单槽表、
+0x8 depth、+0x10 helper、+0x18 flag、+0x19 ownership,字段止于 +0x19)。
vptr 来源 `python3 scripts/riprefs.py 0x26e4fa8` → 44 refs(`--verify` 后 43),列出的 25 个函数桶含
`2 func 1c42fe0..1c43884`(即本函数 0x1c4307a/0x1c43634 两处)。本轮 44 与 §53.4 记录的 33 不一致,
按 append-only 各记现值,不追溯改旧读数。

### §60.3 `[rax+0x50]` 不可能别名到帧(静态可证)

`call qword ptr [rax+0x50]` @0x1c430b0(rcx=item,返回 `mov esi,eax; mov [rsp+0x58],eax` = token id)。
§60.2 的 grep 计数说明:在 0x1c430b0 之前,`[rsp+0x38]` 只以**存储目标**出现过(0x1c43081),帧地址从未
进入任何寄存器实参或可读内存 ⇒ 该被调方拿不到帧地址。随后 `mov r12d,[rsp+0x40]; test; jle 0x1c43642`
@0x1c430c4/0x1c430c9:depth 刚被写成 0 ⇒ 遍历体(0x1c430d2..0x1c43628,含 `call 0x1d12c60`、
`call [rax+0x30]`×若干)整段跳过,直达 token-DB 尾段(§60.6)。

### §60.4 两条已知线索:字节级验证 = 「帧传递者」存活,「写者」判死

调用点在承载函数内(§60.2 表);函数体边界来自 `python3 scripts/pdata.py 16fdc0 1d129a0 1d11860`:
0x16fdc0..0x16feda、0x1d129a0..0x1d12a88、0x1d11860..0x1d11b83。

- 两个函数体内部的 `[rsp+0x38]` 写各只有 1 条,且都是 `mov qword ptr [rsp+0x38], 0x100`
  (0x16fe1a / 0x1d129c6,`disrva.py 0x16fdc0 120` / `disrva.py 0x1d129a0 80`)。它们各自 prologue 刚做完
  `sub rsp,0x140`(0x16fdda/0x1d129b4),同一偏移 0x28..0x3f 刚被 `movups xmmword ptr [rsp+0x28], xmm0`
  (0x16fe15/0x1d129c1)灌入 ⇒ 那是**自己栈帧里 std::string 暂存对象的 capacity 字**,与承载帧的 rsp 无关。
  ⇒ **两条线索作为「写 [rsp+0x38] 者」同判死**。
- 它们对帧做的事只剩把帧指针递下去:`0x16fe8c` 与 `0x1d12a3f` 各 `call 0x1d11860`(rcx=帧,
  rdx=&{id|string 暂存})。`disrva.py 0x1d11860 --end=0x1d11b83` 的 grep 判读:入口 `cmp byte [rcx+0x18],0`
  @0x1d1186f 是**读**,`mov rsi,rcx` @0x1d11878 起帧指针归 rsi;全函数**没有一条经 rcx/rsi/rdi 的存储**,
  也没有 `mov rcx,rsi` ⇒ 帧指针从不出现在任何 call 的 rcx 实参位;名字是经由 helper
  (`mov rcx,[rsi+0x10]` @0x1d118fa → `call [rax+0x30]`/`call [rax+0x48]`)挂到 helper 侧的。
  ⇒ **线索链(0x16fdc0 / 0x1d129a0 / 0x1d11860)整体不改写 0x20 B 帧字节,写全部停在 helper 一侧**。
  保留一处未判:0x1d11860 内 `cmovne r9,rcx` @0x1d118e8 —— 函数内可读路径上该 rcx 已在 0x1d1188d
  重载为 `[rdx+0x10]` 串指针,但 `0x1ca3980` 的写域没逐槽拆(§60.7 第 4 条)。

### §60.5 谁调用承载函数:0 直接调用 + 0 指令引用,唯一静态持有者 = vtable 槽 +0x28

- `python3 scripts/fastcalls.py 0x1c42fe0` → **caller_count=0**;产物
  `evidence/xrefs/callers_0x1c42fe0_buckets.tsv` 只有表头行。
- `python3 scripts/find_refs.py 0x1c42fe0 0x1bcd120`(.text 0x2390800 字节全解码)→ **两条都 0 references**。
  这是窗口陈述不是调用者陈述(offline-tooling 判读陷阱 11)。
- 静态持有者扫描(one-shot inline python;PE 布局镜像 `find_refs.py`:nsec@nh+6、SizeOfOptionalHeader@nh+20、
  节表 vsize@o+8、va/rawsz/praw `<III`@o+12、chars@o+36;过滤 `chars & 0x40` = CNT_INITIALIZED_DATA;
  键 = `0x140000000+RVA` 的 LE-qword,要求命中偏移 %8==0):`0x1c42fe0` → **恰好 1 个对齐命中**
  `.rdata:0x26d4df8`。邻域按 qword 读(one-shot):0x26d4cc8..0x26d5100 是连续代码指针区(136 槽),
  vtable 起点 **0x26d4dd0**,承载函数是槽 **+0x28**:
  `+0x00 0x1c42de0 | +0x08 0x15db30(`disrva.py 0x15db30 8` = `ret 0` 空桩)| +0x10 0x1c37ec0 |
  +0x18 0x1c37f20 | +0x20 0x1c38940 | +0x28 0x1c42fe0 | +0x30 0x1c42ee0 | +0x38 0x15db30 |
  +0x40 0x1b4c00 | +0x48 0x1c43890(`pdata.py 1c43890` → 不在任何函数,未决项 §60.7-2)`。
- 谁引用表 0x26d4dd0:`python3 scripts/riprefs.py 0x26d4dd0` → 恰好 2 处 —— **0x1c42d30..0x1c42ddc**
  (构造器:`lea rax→0x26d4dd0` @0x1c42d4d、`mov [rdi],rax` @0x1c42d54、`xchg [rdi+0x120],1` @0x1c42da6、
  `call 0x1c44390` @0x1c42dc3,edx=[0x2a01b24]、r8=&[rsp+0x40] 存 self ⇒ 把 self 注册进全局数组
  [0x2a01b18]/计数 [0x2a01b24])与 **0x1c42de0**(槽+0x00 析构:`lea rax→0x26d4dd0` @0x1c42def、
  `mov [rcx],rax` @0x1c42df9 复挂 vptr,随后遍历 [0x2a01b18] 比对摘除自注册)。对整区 137 个槽地址批量
  `riprefs.py`(输出留 /tmp)确认 0x26d4dd0 仅这两处,而邻接 0x26d4cc8/0x26d50e8/0x26d5108 各有自己的引用者
  ⇒ MSVC 背靠背 vtable,形状判读按 §57 那族陷阱,不放大成「同一大表」。
- 谁调构造器:`python3 scripts/fastcalls.py 0x1c42d30 --top 25` → 2 桶
  (`evidence/xrefs/callers_0x1c42d30_buckets.tsv`):站点 0x1ba708e @0x1ba6d20..0x1ba7126 与
  0x1ba7685 @0x1ba72a0..0x1ba77f4,后者 ref_strings `0x26ce430:Default Game | 0x26ce438:Game`
  ⇒ 两个静态构造点,按 PDS 文件头属 'Default Game'/'Game' 两条初始化。两站点字节同形
  (`disrva.py 0x1ba7070 8` / `disrva.py 0x1ba7660 16`):`mov ecx,0x128; call 0x2185218` → ctor
  `0x1c42d30`;第二处还把 self 存进 `[rbx+0x60]`(0x1ba768b)。对象大小 0x128 与 ctor/承载函数用到的
  字段上限 +0x120 相容。
- ⇒ **结论(本路线可答的部分)**:承载函数没有直接调用者,只被 `call [obj_vtbl+0x28]` 形态的动态派发调用;
  该形态的站点集合离线不可按类分(寄存器间接、目标类取决于运行时对象)。「谁调用承载函数」在这条路线上
  答到**类身份**为止(异步队列 0x26d4dd0,静态构造 ×2、运行时 self-注册进 [0x2a01b18] 数组),
  派发方集合进未决项。

### §60.6 与 §59 四根和普查表第 1 行的接线(`disrva.py` / one-shot 扫描)

- 几何:帧 = `[rsp+0x38]`,helper = `[rsp+0x230]` ⇒ Δ = **0x1f8**,与 §53.3 采样两对
  0x7fe768→0x7fe960、0x7fed78→0x7fef70 的间距逐位相符(0x7fe960 即 §59.4 的 helper 根)。
  相容不是证据(§59.4 原话保留):本函数运行在 §59.4 那个 8 KB 私有区上**没有**被本节判读。
- 尾段派发链:`call 0x1d12c60` @0x1c43642(token DB 单例)→ 容量检查 `[db+0x7c] vs [db+0x80]` →
  必要时 `call 0x1d12cd0` @0x1c43655 → holder = `[db+0x70] + id*0x30`(`movsxd rcx,esi; lea rdx,[rcx+rcx*2];
  shl rdx,4; add rdx,[rbx+0x70]` @0x1c4365a..0x1c43665 —— §53 的 stride 算术逐字节在此复现)→
  `call 0x1d129a0` / `call 0x16fdc0`(§60.4)。随后 0x1c43690 `mov rax,[rdi]`、0x1c43693 `lea rdx,[rsp+0x38]`、
  0x1c43698 `mov rcx,rdi`、0x1c4369b **`call [rax+8]`** —— 返回点 0x1c4369e 就是
  `exec_frame_sites_4_4_4.tsv` 第 2 行(form=mem,site_in_census=0 是待办不是矛盾,该工具判读卡原话)。
  帧作为 arg2 进 slot[1](Execute 槽)的形态与 §53.3 定义一致;接收类取决于 item 自己的 vtable,
  离线不能钉死为 `0x1D08520`(datum 止于形态)。
- r8/r9:函数体内写 r8/r9 的只有 0x1c43060/0x1c43064(给 helper ctor)与遍历体(0x1c4317d/0x1c43213/
  0x1c4322a/0x1c432b6…,depth=0 路径整段跳过);尾段 0x1c43628..0x1c4369b 无任何 r8/r9 写(grep)⇒
  派发点 arg3/arg4 = 上一调用者残留,判读陷阱 2 生效,与 §59.5「arg3 指回 0x1D08520 本身」读法相容。
- 普查表第 1 行(0x1bcd192 / func 0x1bcd120 / origin=incoming_arg):`find_refs.py 0x1bcd120` = 0 指令引用;
  one-shot 对齐 qword 扫描(同上布局)→ **365 个 .rdata 槽**,band 0x24b0400..0x2701d40 ⇒ 0x1bcd120 是被
  365 张表槽共享的虚实现(对照 §57 的 0x3AFD30×538 / 0x3B01A0×454),它的帧来自 incoming_arg,构造点在这条
  动态派发链更上游 —— **该行在普查路线上仍未决**,不在 §60 判决覆盖内(§60 只判承载函数路线)。

### §60.7 未决项

1. `[0x26d4dd0+0x28]` 形态的派发方集合:离线不可分(0 直接调用 + 0 指令引用 + 寄存器间接),要更深类型
   分析或实机采样。
2. `pdata.py 1c43890` 无命中(槽 +0x48 的值不在任何 RUNTIME_FUNCTION)——数据还是分析缺口,未判。
3. §59.4 的 8 KB 私有区是否就是承载函数运行所在的(纤程?)栈:几何相容,未取证(§59.4 措辞保留)。
4. `0x1ca3980`(被 0x1d11860 于 0x1d118f5 调用,rcx=[rbp-0x20] 局部、edx=0x20、r8=0x26e4f98)的写域未拆;
   `cmovne r9,rcx` @0x1d118e8 在函数内可读路径上 rcx 已非帧指针,但没证到所有进入路径。
5. 普查表第 1 行 0x1bcd120 的构造点(§60.6 末条)在这条路线之外,仍待上游判定。
6. vptr 0x26e4fa8 的引用总数本轮 44(`--verify` 43)vs §53.4 记录 33:append-only,两处各按当时口径读。
7. §53/§54 的长寿命堆 ctx(0xee7fd00)是否由 ctor 0x1c42d30 构造:本路线只证到构造器存在与 self-注册进
   [0x2a01b18],运行时返回值落点离线不可读。

### §60.8 判决梯与判决(继承 §59.9 的阶梯第 2 条)

对**承载函数路线**(0x1c42fe0..0x1c43884)三档:

- `frame_ctor_found` —— 帧的全部字面与字段写点在函数内定位且有字节证据;vptr 来源具名;帧指针下游的
  已知线索要么证实不写帧、要么被具名到「写停在 helper 一侧」。
- `frame_ctor_partial` —— 写点定位,但仍有帧写穿过未读透的被调方,无法排除。
- `no_frame_ctor_this_route` —— 承载函数根本不写 `[rsp+0x38]`(纯转发,构造点在上游)。

**判决 = `frame_ctor_found`**。依据:§60.2 的 6+4 条写点全表(逐条 RVA + `disrva.py`)、vptr 0x26e4fa8 由
`riprefs.py` 具名且本函数内仅 2 处引用、§60.4 把 `0x16fdc0`(edx=1)与 `0x1d129a0` 两条线索判死为写者并
证到共享 sink `0x1d11860` 零帧存储、§60.3 排除 `[rax+0x50]` 别名帧。§59 的 `no_scope_candidate` **不变**
——§60 问「谁构造帧」,§59 问「谁是 scope」;本轮也没有新执行 shot,§59.9 第 2 条(零 shot 先行)兑现。

### §60.9 复现

```
python3 scripts/pdata.py 1c4369b
python3 scripts/disrva.py 0x1c42fe0 --end=0x1c43884
python3 scripts/pdata.py 16fdc0 1d129a0 1d11860 1c42d30 1c42ee0 1c42de0
python3 scripts/disrva.py 0x16fdc0 120 && python3 scripts/disrva.py 0x1d129a0 80
python3 scripts/disrva.py 0x1d11860 --end=0x1d11b83
python3 scripts/disrva.py 0x15db30 8
python3 scripts/fastcalls.py 0x1c42fe0            # 0 桶 -> callers_0x1c42fe0_buckets.tsv(表头行)
python3 scripts/fastcalls.py 0x1c42d30 --top 25   # 2 桶 -> callers_0x1c42d30_buckets.tsv
python3 scripts/find_refs.py 0x1c42fe0 0x1bcd120  # 双 0 引用(.text 全解码)
python3 scripts/riprefs.py 0x26e4fa8              # 44 refs;桶含 2 func 1c42fe0..1c43884
python3 scripts/riprefs.py 0x26d4dd0              # 恰好 2 refs: 1c42d30 / 1c42de0
```

两个 one-shot inline-python 读数(§60.5 持有者扫描 + §60.6 的 0x1bcd120 计数)不是常驻工具,命令要素已
在原文写死:PE 节表按 `find_refs.py` 的字段偏移(nsec@nh+6、SizeOfOptionalHeader@nh+20、节表
vsize@o+8 / va,rawsz,praw@o+12.. / chars@o+36,过滤 `chars & 0x40`),键 = `0x140000000+RVA` 的
LE-qword、要求 8 对齐。第一次尝试把 SizeOfOptionalHeader 读在 nh+16(那是 NumberOfSymbols)导致
节名全花、0 命中 —— 修正后 1 命中 / 365 命中如上;vtable 槽 dump 用同一张节表做 VA→raw 映射。
承载函数帧写点的 grep 判据:`grep -n "rsp + 0x38" <disrva 输出>` 应得 6 行;0x1d11860 的无存储判据:
`grep "mov     qword ptr \[rsi\|\[rcx\|\[rdi" <disrva 输出>` 为空(表左值)。

## §61 零 shot:普查表第 1 行的帧来源 = base Execute 的 arg2 透传,不是独立构造点(2026-10-25,离线)

**问题**:`exec_frame_sites_4_4_4.tsv` 第 1 行(site `0x1bcd18d` / func `0x1bcd120` /
`census_origin=incoming_arg`)在 §60.7 挂作第 5 条,判词是「构造点在这条路线之外,仍待上游判定」。
本节把「上游」问到底:该行的 rdx 到底是谁造的。零 shot、零 Windows 机时。

### §61.1 那 365 个共享槽全在 slot[2],而游程启发式不可用

§60.6 只数了「`0x1bcd120` 出现在 365 个 `.rdata` 槽」,没答槽位。普查路线要的是**调用形态**:
`call [reg + off]` 的 `off` 必须是那个槽,否则找到的调用点与这条链无关。

- 第一版做法(游程):从命中处向前后扩,只要 8 对齐 LE-qword 落进 `.text` 就继续,起点当 vtable 基址。
  结果 **365 命中但游程长度分布出现 1401/1435/1564** ⇒ `.rdata` 里 vtable 是**紧挨着排的**,中间没有
  非指针分隔,整片并成一条游程,偏移全是垃圾。**这条启发式在本 build 的 `.rdata` 上不可用**,
  后面谁再拿「指针游程起点」当 vtable 基址,先读这段。
- 改用仓里现成的基址集:`evidence/xrefs/ceffect_vtable_map_4_4_4.txt` 的 1,805 个 vtable RVA
  (floor:只含 `+0x08` 仍是 base Execute 的那批),对每个基址按槽解引用比对目标 VA。
- **读数**:`slot_index 分布 = {2: 365}`,`orphan = 0`。⇒ 365 张表里 `0x1bcd120` **一律落在 slot[2] = +0x10**,
  也就是 §10 那条 `call [rax+0x10]` 派发槽;与 map 自己的列名 `ExecuteActual(slot2)` 同一件事。

### §61.2 `0x1bcd120` 对帧是纯透传,它造的是 this 拷贝

`disrva.py 0x1bcd120 100` 的关键 12 条(其余为对象头字段搬运):

```
01bcd131  mov rbx, rdx            ; 帧留底
01bcd139  mov rdi, rcx            ; this 留底
01bcd12a  lea rax,[rip+0xb03397]  ; -> 0x26d04c8
01bcd134  mov [rsp+0x20], rax     ; 栈上新对象的 vptr
01bcd13c..01bcd167  [rcx+8]/[rcx+0x12]/[rcx+0x14]/[rcx+0x16]/[rcx+0x18] -> [rsp+0x28..0x30]
01bcd175  lea rcx,[rsp+0x20]      ; arg1 = 新造的拷贝
01bcd17a  mov rdx, rbx            ; arg2 = 原帧,逐字不变
01bcd17d  mov r8, [rax+8]         ; = [0x26d04c8+0x08]
01bcd181  lea rax,[rip+0x13b398]  ; -> 0x1d08520
01bcd188  cmp r8, rax
01bcd18b  jne 0x141bcd194         ; 不是 base Execute 就走 slot 真值
01bcd18d  call 0x1d08520
```

- 在 `0x1bcd131 → 0x1bcd18d` 这段里 `rbx` **只作源不作目的**(`grep` 全文得 `mov rbx, rdx` /
  `mov rcx, rbx` / `mov rdx, rbx` 三条),即帧指针从入口到这条 call 没有任何改写。
- 全函数对帧的**内容**写只有 `[rbx+8]` 两处(`mov [rbx+8], eax` @0x1bcd1e2、`dec [rbx+8]` @0x1bcd1f1),
  都在那次派发**返回之后**,与 §53「+8 是调用深度计数、净为零」同一形态;`[rsp+0x20]` 那块是**新的 this**,
  与帧无关。⇒ **`0x1bcd120` 不构造帧、不换位帧、只把帧传下去。**
- `0x1bcd181..0x1bcd18b` 是 §53.1 那条 devirtualization guard 的同一个形状:先比 slot 真值与 base Execute,
  相等才直调,不等就 `call r8`。

### §61.3 被 devirt 的那张表与 base Execute 自己

- wrapper vtable `0x26d04c8`(在 floor map 内)槽位:`slot0 0x158950` / `slot1 0x1d08520`(base Execute ✓,
  guard 恒成立的来源)/ `slot2 0x1bccf30` / `slot3 0x535070`。⇒ 这次调用把 this 换成基类身份后再进 base Execute,
  base Execute 的 `call [rax+0x10]` 于是落到 **`0x1bccf30`**(`0x1bcd120` 的兄弟实现),不是回到自身 —— 无递归。
- base Execute 本体对帧同样是透传:`mov eax,[rdx+8]` @0x1d0852a 读深度 → `mov rbx,rdx` @0x1d0852d 留底 →
  `mov rdx,rbx; mov rcx,rdi; mov rax,[rdi]; call [rax+0x10]` @0x1d0856b..0x1d08577。中间只有
  `[rbx+8]` 的 `inc`/`dec` 与 `0x16fdc0`(edx=0x10/3/4)、`0x1d116a0` 的 rcx=帧 调用;
  `0x16fdc0` 在 §60.4 已被判死为「写者」(其 `[rsp+0x38]` 是各自栈里的 string capacity 暂存),本节不推翻,
  只补一句:**它在 base Execute 里以「拿帧当 rcx」的形态反复出现,是读/标记,不是重新赋值 rdx。**

### §61.4 判定与边界

**判定**:`exec_frame_sites_4_4_4.tsv` 第 1 行的 `incoming_arg` **没有独立的构造点**。它的 rdx 就是
base Execute 收到的 arg2,而 base Execute 收到的 arg2 就是 §60 判决里承载函数
`0x1c42fe0..0x1c43884` 在 `[rsp+0x38]` 内联构造的那个 0x20 B 执行深度帧。⇒ **§60.7 第 5 条折叠进第 1 条**:
剩下的不是「第 1 行的帧从哪来」,而是「谁以帧为 arg2 调用 base Execute 的 slot[1]」(派发方集合),两行同源。

**边界(不可越过的部分)**:
1. 本节只判了第 1 行这一条链。§53.1 记的 17 个站点里 `incoming_arg` 有 12 个,每个都要**逐函数**读它自己
   的 rdx 路径才能确认同源 —— 没读的不算已判。
2. 「谁调 base Execute」仍离线不可分(§60.5:承载函数 0 直接调用 + 0 指令引用、寄存器间接派发),
   本节没有新增杠杆。
3. §60 的判决 `frame_ctor_found` **限于承载函数路线**,本节的结论是「第 1 行与该路线同源」,
   不等于「全部帧都来自承载函数」;普查路线上仍有 §60.7-1 那条未决。
4. 无递归那句是从 slot 表读出来的静态推论(`slot2` 已换实现),没有实机执行序列佐证。

### §61.5 复现

```
python3 scripts/disrva.py 0x1bcd120 100      # 透传三处 + guard 12 条
python3 scripts/disrva.py 0x1d08520 40       # base Execute 对帧:rbx 留底、rdx 原样、[rbx+8] 净零
python3 scripts/scratch/2026-10_exec_frame_census/slot_offsets.py    # 游程版(展示为何不可用)
python3 scripts/scratch/2026-10_exec_frame_census/slot_offsets2.py   # floor map 版:{2: 365} / orphan 0
```

两个探针都是一次性读数,不是维护接口:节表字段偏移照 `find_refs.py`,键 = `0x140000000+RVA` 的 8 对齐
LE-qword;`slot_offsets2.py` 比的是**槽内容 == anchor VA**(第一版误比命中位置,得 365 全 orphan —— 记在这里,
免得下一次再把 orphan 当结论读)。

## §62 零 shot:普查表 12 个 `incoming_arg` 站点逐函数读完 —— 全部是 slot[2] ExecuteActual 覆写的帧透传(2026-10-25,离线)

**问题**:§61.4 边界第 1 条挂着「§53.1 记的 17 个站点里 `incoming_arg` 有 12 个,每个都要**逐函数**读它自己
的 rdx 路径才能确认同源 —— 没读的不算已判」。本节把那 12 行(9 个函数)全部读完,并把每行的**槽位身份**
定死。零 shot、零 Windows 机时、零 IDA license。

**口径**:数据源是 `evidence/xrefs/exec_frame_callers_4_4_4.tsv` 的 `rdx_origin=incoming_arg` 行
(`exec_frame_sites_4_4_4.tsv` 第 1 行是它的 join 结果)。探针
`scripts/scratch/2026-10_exec_frame_census/forwarding_wrappers.py` 每函数回答四件事:站点 `call` 的目标、
承载寄存器(把帧交回 rdx 的那个)在函数体内的全部写点、有没有 `mov [rdx+..]` / `mov [承载+..]` 这类
**对帧的写**、rdx 有没有从 `lea rdx,[rsp/rbp+..]` 取得(那就是 §60.7-1 要的栈上构造点)。
**自校验**:第 1 行函数 `0x1bcd120` 必须复现 §61.2 的 `mov rbx, rdx @0x1bcd131` —— 复现了。

### §62.1 逐函数读数:12/12 直调 base Execute,0 构造点

`留底` = 承载寄存器从入参 rdx 抄一次的那条;`站点前额外写` = 在「留底 → 站点」之间承载寄存器又被写的次数。

| 函数 | 站点 | 目标 | 承载 | 留底 | 站点前额外写 | `[<frame>+8]` 写(承载基) | 其他帧偏移写(承载基) | `lea rdx,[rsp..]` |
|---|---|---|---|---|---|---|---|---|
| `0x69e100..0x69e70c` | `0x69e1e9`, `0x69e289` | `0x1d08520` | rbx | `0x69e124` | 0 | 4 | 0 | 无 |
| `0x6c32e0..0x6c38e7` | `0x6c3837`, `0x6c38c3` | `0x1d08520` | rbx | `0x6c32f8` | 0 | 1 | 0 | 无 |
| `0x7ebe60..0x7ec22a` | `0x7ec137`, `0x7ec1d7` | `0x1d08520` | rbx | `0x7ebe78` | 0 | 2 | 0 | 无 |
| `0x7f67f0..0x7f6c0f` | `0x7f68d7` | `0x1d08520` | rbx | `0x7f6808` | 0 | 3 | 0 | 无 |
| `0x7ff6c0..0x7ffb09` | `0x7ff827` | `0x1d08520` | rbx | `0x7ff6d8` | 0 | 3 | 0 | 无 |
| `0xb34360..0xb345c0` | `0xb343cb` | `0x1d08520` | rbx | `0xb3437c` | 0 | 2 | 0 | 无 |
| `0xdcdca0..0xdce3a0` | `0xdcdea7` | `0x1d08520` | rbx | `0xdcdcb8` | 0 | 3 | 0 | 无 |
| `0xdef440..0xdf06a8` | `0xdef633` | `0x1d08520` | r14 | `0xdef46f` | 0 | 7 | 0 | 无 |
| `0x1bcd120..0x1bcd227` | `0x1bcd18d` | `0x1d08520` | rbx | `0x1bcd131` | 0 | 2 | 0 | 无 |

- **12 个站点全是 `call rel32` 直接打到 base Execute `0x1d08520`**,不是 `call [reg+off]` 间接派发。
- 承载寄存器每函数**在站点之前只有一次写**(函数头的 `mov <c>, rdx` 留底);之后的写都是**出口复位**,
  形态不一:7 个函数是 `mov <c>, [rsp+0x50..0x70]`,`0x69e100` 是 `mov rbx, [r11+0x38]`@`0x69e6d4`
  (仍在两个站点之后),`0xdef440` 是 `pop r14`@`0xdf05ac`。
  `0xdef440` 的 r14 在函数中段还有两次写(`0xdefa5f lea r14,[rip-0xbd5eb6]`、`0xdefc53 mov r14,[rbp+0x10c8]`),
  也都**在站点 `0xdef633` 之后**,所以该站点交回的仍是原帧 —— 这就是「站点前额外写」这一列存在的理由。
- `rdx` 自身在这些函数里被大量复用(`mov edx, 0x4184` 之类是日志/错误码入参),**这不影响透传结论**:
  留底的意义正是为了在每次调用前 `mov rdx, <c>` 把原帧交回去。
- **这 9 个函数动帧,但只动 `+8`**:承载寄存器基址的 `[<c>+8]` 写合计 **27 处**(探针末行
  `SUM carrier 基 [<frame>+8] 写 = 27 (inc/dec 21, 赋值 6)`),`+0x00/+0x10/+0x18` **一处都没有**。第 1 行的两处在
  `0x1bcd1e2 mov dword [rbx+8], eax` 与 `0x1bcd1f1 dec dword [rbx+8]`,中间夹着 `call [rax+0xa0]`@`0x1bcd1eb`
  —— 与 §61.2「帧内容只有 `[rbx+8]` 净零」同一件事,现在逐函数复现了。
  `0xdef440` 的 `0xdef527 inc dword [r14+8]` 在站点**之前**,即该覆写自己也在进 base Execute 前把深度加一格。
- **`+8` 这一列不是同一种写**:27 处里 **21 处是 `inc`/`dec`**(§53 的净零形状),**6 处是
  `mov dword [<c>+8], eax|ecx` 的赋值**(`0x69e539`、`0xb34445`、`0xb34538`、`0xdefdb0`、`0xdf00b8`、
  `0x1bcd1e2`)。赋值那 6 处**是否净零本节没有判** —— 要判得先追被赋的 `eax` 从哪来,而 `0x1bcd1e2`
  那条正是 §61.2 读过的「mov 完就去 `call [rax+0xa0]`、回来 `dec`」形状。§61.2 的「净零」措辞
  覆盖的是 inc/dec 那一半,不要把 27 这个数读成 27 个净零对。
- **假阳性已排除**:`0xdef440` 另有 `mov qword [rdx], rax`@`0xdefba8/0xdefbdc/0xdefc16` 与
  `mov qword [rdx+8], rax`@`0xdefbb6/0xdefbea/0xdefc24`,形状上是「rdx 基写」,但那里 rdx 是**交换循环的游标**
  (`mov rdx, rsi`@`0xdefb9b` → `mov [rdx], rax`@`0xdefba8` → `mov [r9], rcx`),且整段在 r14 被
  `0xdefa5f` 改写之后,帧已不在 rdx/r14 里 ⇒ **不算帧写**。这条是 §62.4 坑清单的第一条。

### §62.2 槽位身份:三方一致,9 个函数全是 floor map 的 slot[2]

`forwarding_wrappers.py` 只答「这一行是不是透传」。§61.4 边界第 1 条还要求说清**这些行与第 1 行是不是同一条链**,
所以补了槽位读数,三条独立口径对上:

1. **裸扫 `.rdata`**:每个函数名的 8 对齐 LE-qword 命中数 = `2, 2, 1, 2, 2, 1, 2, 2, 365`(共 379 槽)。
2. **前一个槽的内容**:每个命中的 `slot[-1]` 值**恰好是 `0x1d08520`**(379/379,无一例外)。
3. **floor map 对齐**:把命中地址回退 0x10 当 vtable 基址,该基址**全都在** `ceffect_vtable_map_4_4_4.txt`
   的 1,805 个基址里(379/379);并且 map 自己的 `ExecuteActual(slot2)` 列等于该函数的行数,与口径 1 的
   命中数**逐个相等**(`agree=True` × 9)。

⇒ 这 9 个函数(含 §61 判过的 `0x1bcd120`)**一律是 floor map 那批 vtable 的 slot[2] = ExecuteActual 覆写**,
而 slot[1] = base Execute。形态与 §61.2/§61.3 完全同一条:`base Execute` 进 → `[vptr+0x10]` 派发到这层覆写 →
覆写造一个 this 拷贝、把**原帧**交回 `base Execute`。

### §62.3 判定与边界

**判定**:§61.4 边界第 1 条**关闭**。普查路线上 `origin=incoming_arg` 的 12 行**全部同源**:帧不是在这 9 个函数
里造的(0 处 `lea rdx,[rsp..]`、0 处非 `+8` 帧字段写),它们是 ExecuteActual 覆写把 base Execute 的 arg2
原样透传回来,途中只按 §53 的规则动 `+8` 深度计数。⇒ §60.7 第 5 条的折叠不是只对第 1 行
成立,而是对整个 `incoming_arg` 集合成立。

**边界(不可越过的部分)**:
1. 本节判的是「这些行没有构造点」。**没有**新增「谁造帧」的杠杆:这 9 个函数自己也是**被** slot[1] 派发进来的
   (`base Execute` 调 `[vptr+0x10]`),帧的来源仍在上游 —— §60.7-1(派发方集合)原样未决。
2. `not_examined` 的那些站点(普查表里占多数)**不在本节范围内**,本节没读它们,不能拿本节的结论覆盖它们。
3. 口径 2/3 的「回退 0x10 即 vtable 基址」依赖 floor map 自己的列定义(slot[1]=base Execute、slot[2]=ExecuteActual),
   它仍是**下限**样本(§17 NOTE:覆写 Execute 的类不进这张表)。
4. 「`0xdef440` 站点的 r14 未被中途改写」是**区间判断**,不是数据流分析:函数体内 `0xdef46f..0xdef633` 之间无 r14 写点。
5. 直调 `0x1d08520` 是静态读数,**没有实机执行序列佐证**(与本卷其它零 shot 结论同一级别)。

### §62.4 复现

```
python3 scripts/scratch/2026-10_exec_frame_census/forwarding_wrappers.py      # §62.1 表 + 自校验
```

**坑(记在这里,免得下一次把假阴性读成结论)**:
1. 第一版探针用 capstone 的 `insn.regs_write` 判寄存器读写,本环境的 capstone 对 x86 **该属性恒空**,
   于是 `frame_writes` 与 `承载写点` 全读成 0 —— 那正是 §61.2 已经手工读出的 `mov rbx, rdx` 应当出现的地方。
   **0 个写点这种「太干净」的读数,先怀疑检测器,再怀疑二进制。**
2. 第二版只把 `mov` 当写,漏掉 `inc`/`dec`/`add [c+8]`,于是 §62.1 的「对帧的写」一度读成 0/0/0…,
   与 §61.2 自己记下的 `dec dword [rbx+8]` 直接矛盾。现版把 `MEM_WRITE` 整族纳入,并把 `+8` 单列。
3. 承载寄存器基址的 `+8` 写是**深度计数**,不是构造;但 `rdx` 基的写**必须回上下文核**(§62.1 的
   `0xdef440` 三处 `mov [rdx], rax` 就是交换循环游标)。

现版口径是「操作符字符串 + x86 别名表」(见脚本 docstring),并以第 1 行的已知读数做自校验。

## §63 零 shot:§60.7-1 队列派发方集合 —— 三条口径互证(2026-10-26,离线)

授权级 = 离线 **零 shot**:无 launch/inject/install/Frida/process,只静态读默认本地 exe 拷贝(sha 同 §60 前置,
`docs/offline-tooling.md`)。生产者 = `scripts/scratch/2026-10_exec_frame_census/queue_dispatchers.py`
(一条命令跑全三口径,A/B 自校验 + C 校准全绿才写 `evidence/xrefs/queue_dispatchers_4_4_4.tsv`;任一不过 ⇒
退出码 1、不写 artifact、不出负结论)。探针内部:口径 A = §60.5 one-shot 的同一条判据(节表字段偏移照
`find_refs.py`,键 = `BASE+RVA` 的 LE-qword、8 对齐、`chars & 0x40` 段);口径 B 的 rip 引用直接 import
`riprefs.refs_for`(§60.5 `riprefs.py --verify` 的同一实现);口径 C = 「候选字节形态 + 从 `.pdata` 函数首
对齐解码复核」,与 riprefs 同一族做法,只是操作数从 rip 换成 `[reg+disp]`。本节答 **§60.7-1(谁经 `+0x28`
槽派发)**;**§59 的 `no_scope_candidate` 原样不动**,本轮没有新执行 shot。

### §63.1 口径 A —— 对齐 qword 扫描,自校验恰好 1

`python3 scripts/scratch/2026-10_exec_frame_census/queue_dispatchers.py --only A` → 逐字读数:

```
channel A: aligned_hits=1 self_check=ok @ 0x26d4df8
```

`0x26d4df8 = 0x26d4dd0 + 0x28`(§60.5 的 vtable 槽)。判据是「恰好 1」:读到 0 或 ≥2 ⇒ 探针自己停
(exit 1)。⇒ 全镜像的初始化数据段里,承载函数 `0x1c42fe0` 的**静态持有者只有一个**,就是队列表 `+0x28` 槽。

### §63.2 口径 B —— 引用者集合(riprefs 同实现 + E8 直调扫描)

`python3 ... queue_dispatchers.py --only B` → 逐字读数:

```
channel B vtable-ref  0x1c42d4d  func 1c42d30..1c42ddc
channel B vtable-ref  0x1c42def  func 1c42de0..1c42ede
channel B ctor-call   0x1ba708e
channel B ctor-call   0x1ba7685
channel B build-site  0x1ba7076  mov ecx,0x128; call new 0x2185218
channel B build-site  0x1ba766e  mov ecx,0x128; call new 0x2185218
channel B: self_check=ok vtable_refs=2 ctor_callers=2 build_sites=['0x1ba7076', '0x1ba766e'] size=0x128
```

- vtable `0x26d4dd0` 的 RIP 引用**恰好 2 处**,桶 = ctor `0x1c42d30..0x1c42ddc` 与析构 `0x1c42de0..` ——
  与 §60.5 `riprefs.py 0x26d4dd0` 的两处逐位相符(0x1c42d4d/0x1c42def)。
- ctor 的调用点是 `E8 rel32` 直调,**riprefs 的形态覆盖不到它**(它只管 rip 操作数)—— §60.5 那两个站点
  (0x1ba708e/0x1ba7685)本来是 `fastcalls.py` 拿的;本探针用同口径「候选算术 + 函数首对齐复核」自扫
  `E8` 复现,两桶与 §60.5 完全一致。
- 构造站点字节抽查(`python3 scripts/disrva.py 0x1ba7048 16`):`0x1ba7076 mov ecx, 0x128` →
  `0x1ba707b call 0x2185218` → `0x1ba7080 mov [rsp+0x88], rax` → `0x1ba708e call 0x1c42d30`;
  第二处同形(`disrva.py 0x1ba7658 8`:`0x1ba766e mov ecx, 0x128` → `0x1ba7673 call 0x2185218`)。
  **一处修正**:§60.5 写的 0x1ba7070/0x1ba7660 是那次 `disrva.py` 命令的**窗口参数**,不是这对字节的首地址;
  按 §60.5 自己的命令重跑,`mov ecx,0x128` 首地址落在 **0x1ba7076/0x1ba766e**,datum 以字节为准。
- ⇒ B 把「谁能造出这个队列对象」钉死为**恰好两个静态构造点**(对象大小 0x128,§60.5 的 'Default Game'/'Game'
  两桶),与「谁引用这张 vtable」钉死为 ctor+析构 恰好两处。

### §63.3 口径 C —— `call [reg+0x28]` 站点集合;检测器先行

**校准**(§62.4 坑 1/2 同族:先证明机器能读出已知读数,再让它报未知):同一台机器、同一套形态扫描,位移
换成 `0x60` —— §60.5 记量排空循环 `0x1c42ee0..0x1c42fdc` 里有一条 `call [rax+0x60]`
(`disrva.py 0x1c42ee0 60` 实测 `01c42f74 call qword ptr [rax + 0x60]`)。探针必须找到它才允许出 `+0x28`
的数;首轮它 FAIL,抓到的是**扫描器自己的键空间 bug**(候选按 blob 内偏移、复核按 RVA 比对,两边没对消)
—— 修正后校准恰好命中 0x1c42f74。这一条本身就是「负结论先怀疑检测器」的活样本。

`python3 ... queue_dispatchers.py --only C` → 逐字读数:

```
channel C: calib call[reg+0x60] @0x1c42ee0..0x1c42fdc -> ['0x1c42f74'] self_check=ok; call[reg+0x28] sites=1214 with_ab_object_ref=0 []
```

全量跑 `python3 ... queue_dispatchers.py` 写 artifact(`#verdict dispatchers_partial …`;1214 条 C 行 +
A/B 行,列 `channel, site_rva, func_rva, func_begin, form, slot, object_ref, note`)。形态覆盖:
`call qword ptr [reg+disp8/disp32]`(含 SIB),`.text` 全量候选 + `.pdata` 函数首对齐复核;disp8 上限 0x7f,
0x28 两种编码都可表 ⇒ 该形态**无形态漏**。

补充 one-shot(inline python,`riprefs.refs_for` 同一实现问 `0x2a01b18`/`0x2a01b24`,再与 1214 站点所在
函数取交):`0x2a01b18: referrer_fns=5 with_0x28_site=[]`、`0x2a01b24: referrer_fns=4 with_0x28_site=[]`
—— 连「引用 self-注册数组的函数」里也没有一条 `call [reg+0x28]`。

### §63.4 判决与边界

**判决 = `dispatchers_partial`**(三档 `dispatchers_found | dispatchers_partial | no_dispatcher_static`)。
为什么是中间档:口径 C 的站点集合**非空**(1214 条,拒绝 `no_dispatcher_static`),但没有一条所在函数引用
A/B 集合里的对象(vtable `0x26d4dd0` / ctor `0x1c42d30` / 直调 ctor;连注册数组都是负的),派发方**无法具名**
(拒绝 `dispatchers_found`)。这不是「没人派发」—— §60.5 已证承载函数 0 直接调用、只被 `call [obj_vtbl+0x28]`
形态动态调用 —— 而是**静态归因在 `+0x28` 这个位移上到不了运行时对象**:1214 条站点的目标类取决于寄存器里
运行时装的是谁,离线不可按类分(判读陷阱 11 的窗口陈述反面:这次集合是读全了的)。

边界(不越过的部分):
1. 本节判的是「`call [reg+0x28]` **直接形态**的静态持有者与站点集合」;`mov reg,[obj+0x28]; call reg` 这类
   两段形态不在口径 C 内,本节**不宣称**它不存在,只把它留给后续。
2. 本节**没有**回答「谁是 scope」—— §59 的 `no_scope_candidate` 原样保持。
3. §60.7 其余未决项(−2…−7)不在本节覆盖内;−1 由本节**在口径 C 的形态边界内**作答。
4. 零 shot:无 launch/inject/install/Frida/process;C1 授权位未动。

`python3 scripts/scratch/2026-10_exec_frame_census/queue_dispatchers.py` 一条命令复现全部三口径与判决
(`--only A|B|C` 单跑;任一自校验/校准不过 ⇒ 退出码 1、artifact 不落盘)。

## §64 零 shot:孤儿 handler 的案卷 —— 前提「命名消费者 = C3」已被离线证伪,裁定仍归人(2026-10-26,离线)

授权级 = 离线零 shot(不 launch/inject/install/进程),且**本节只出材料,不做裁定**。对象 =
`src/dll/effects/handler.zig` + `src/dll/triggers/handler.zig`(§29 判「kept as orphans」留待 C3 的那两个)。
§29 原文(:707-711 逐字):「**kept as orphans.** … these two are the intended JS-routing layer for C3, so
they are a *placeholder with a named consumer* … If C3 ends up routing through QuickJS differently, they
are deleted then, not now.」本节把「等的那个消费者」在 2026-10-26 仓库里的真实状态读全。

### §64.1 三条离线事实(git grep 实跑,输出原样;超长行截到 120 字符并标注)

**事实 1 —— 零 importer。** 三条命令的第一条:

```
git grep -n "effects/handler\|triggers/handler" -- '*.zig' '*.py' '*.md' \
  | grep -v '^src/dll/effects/handler.zig:\|^src/dll/triggers/handler.zig:'
```

命中只剩**文档与旧读数**:`docs/offline-tooling.md:66-67`(29 条缺口构成 19+5+5)、`docs/roadmap.md:98`、
`docs/scope-read-points.md:57`(超长行,截断;含「effects/handler.zig 5 + triggers/handler.zig 5 … 零 importer」)、
`evidence/analysis/runtime_444_c1_validation.md:460/:707`(§29 自己)、`evidence/analysis/zig_test_coverage.md:26/27/64/65`
—— `src/**.zig` 与 `build.zig` 对该路径串**零命中**。**两处 brief 未料到的形状**:brief 的 Expected 说这条会露出
`build.zig:186-190` 与 `README.md:30/:32` —— 实跑不命中,因为那两处写的是「Effects handler」/「handler.zig」
而不是路径串;补跑 `grep -n "handler" build.zig` → :186/:187/:190 =
「`// Effects handler tests — SKIPPED: std.Thread.Mutex unavailable for x86_64-windows target.`」等原文,
`grep -n handler README.md` → :7/:8/:30/:32/:145/:146/:245(:30/:32 = 「`handler.zig — JS callback routing
(orphan: its hook was removed, see §26.3)`」)。再按符号问一遍全仓库:
`git grep -n "effects/handler\|triggers/handler\|effects_handler\|triggers_handler" -- 'src/**.zig' 'build.zig'`
(排除文件自身)→ **No matches found** —— import/build 面确实为零。

**事实 2 —— 孤儿函数的名字在仓库里不出现在别处。** 第二条命令:

```
git grep -n "handleCustomEffect\|handleCustomTrigger\|getHandlerCount" -- '*.zig' '*.py' '*.md'
```

`handleCustomEffect` 只在 `effects/handler.zig`(:190 定义 + 测试内引用),`handleCustomTrigger` 只在
`triggers/handler.zig`(:190)。**一处必须具名的出入**:`getHandlerCount` 有三个文件各自**定义** —— 孤儿两份
之外还有 `src/dll/c2/handler.zig:131`;那是 C2 现役 handler 的**同名函数**,不是对孤儿的引用(三处定义互不相干,
git grep 的命中全是定义/测试行,没有跨文件调用)⇒ 「名字不出现在别处」对 `handleCustom*` 严格成立,对
`getHandlerCount` 要按「族」读。

**事实 3 —— 现役 C4/C2 路线不经过它们。** 链路 = `0x1D08520` → slot[2] →
`src/dll/c2/vtable.zig:40` 的 `extern fn C2ExecCall(token: u32, ctx_word: u64) c_int;` →
`src/dll/quickjs/quickjs_wrapper.c:1097` 起的 `C2ExecCall`(**brief 写的 :1097 是 `C2ExecCall` 定义行,
`JS_Call` 实际调用在 :1121/:1265**,文件也在 `src/dll/quickjs/` 不是 `src/dll/c2/`)。
`src/dll/c2/handler.zig` 的 `dispatchEffect`/`dispatchTrigger`/`setContext` 按符号问外部引用
(`git grep -n … -- 'src/**.zig'` 排除 c2/handler.zig 自身)→ **零命中**;被 exports 引用的只有
`registerHandler`:`exports.zig:675/:712`,签名 `registerHandler(name, js_func: c.JSValue, kind)`
(c2/handler.zig:73),**与孤儿的 `registerHandler(effect_name, js_function_name)` 不是同一个函数**。
且 `C2RegisterEffect` 的返回值由 `main.js_runtime` 门控(有 runtime 成功返回 1/失败返回 0;runtime 从未建立
⇒ 走空分支返回 0)—— runtime 永不建立的出处 = `docs/offline-tooling.md:66-71`(`main.initializeQuickJS`
无调用点,「29 条零执行 = 可达性不是链接」)。§49.3(:3186 逐字)「The keyword→JS routing layer (C3) and
a visible new effect (C4) are untouched.」与 §50(:3261)「remain untouched, and caller-supplied JS text
stays deferred (P21)」记的是**当时**两次 shot 都没碰 C3 —— 与现役路线不经过孤儿一致。

### §64.2 正面结论:前提没了

`docs/roadmap.md:116` 段 5 逐字:「**C3 不再是待办,降为设计依据**:注册只需要两个前置 —— 目标 db 已拉起,
且我们的插入早于任何*求值*引用该 keyword;」。§29 决定「留」的唯一理由是「placeholder with a *named consumer*
(C3)」;C3 已不是待办 ⇒ **这个命名消费者不存在了**——§29 那句的条件句「If C3 ends up routing through
QuickJS differently, they are deleted then, not now」里等的触发条件**永远不会再被经过**。这是本节读全的
离线事实,不是删除建议。

### §64.3 边界声明(Review Focus 5)

**本节不判「该不该删」。** §29 的「留」是用户裁定,不是分析结论;离线只证到「等的那个消费者不存在了」。
案卷到此为止,删除需要新的裁定(见 §64.4 落点表)。本节同样不动 C1 授权位、不执行 shot、不改 `src/`。

### §64.4 移交清单(只写不执行)

若裁定为「删」,确切落点:
1. 删文件:`src/dll/effects/handler.zig`、`src/dll/triggers/handler.zig`。
2. `build.zig:186-190`:两段 SKIPPED 注释一并删。
3. `README.md`:行 7/8(特性清单里 Custom Effects/Triggers 两行)、30/32(目录树 handler 两行)、
   145/146(`registerEffect`/`registerTrigger` 表两行)、245(ID>4081 路由段)。
4. `docs/offline-tooling.md:66-71`:「29 条」构成 `19 + 5 + 5` → **19 条**(两个 handler 的 10 条随文件消失;
   但 `api/bridge.zig` 的 19 条仍在,`main.initializeQuickJS` 无调用点没被本删除修复)。
5. `docs/roadmap.md:98`:整条孤儿候选移除(该文件行数上限 140,删行允许)。
6. `docs/scope-read-points.md:57` 与 `evidence/analysis/*`(§29 :460/:707、zig_test_coverage 26/27/64/65)
   里的旧读数是**历史数,不改写**(append-only);删除后的新基线句(`599/599` 是否变、29→19)另记新节。
7. 预期门禁效应:两个文件**没有被任何构建根 import**(事实 1),其 10 条 test 本就在零执行缺口里 ⇒
   Zig 门禁计数与 DLL 字节**不应有任何变化**;真变了就是删坏了,回滚重查。

## §65 零 shot:Zig `extern fn` 绑 QuickJS 的布局契约双侧钉死(2026-10-26,离线)

授权级 = **无**(全部是离线构建 + 反汇编自己的产物;探针 DLL 从不执行)。本节只收
「布局 + 调用桩」这一半:**§36 那次 rc=3 的机制已由 §47/§48 重分类成 UBSan 报
`offsetof` 编译期常量 0,与 extern ABI 无关**,本节不复盘它。

**关键前提(先钉住再谈契约)**:`quickjs_wrapper.c` **不 include** `quickjs.h` ——
它在 :43-53 手抄 `JSValueUnion`/`JSValue`;`bindings.zig:97-176` 是第三份定义。
所以「双侧契约」不是一句注释,而是**各份定义自己的编译期断言**。

### §65.0 出货基线(改 build.zig 之前记录)

```
f397a6ba25193ff659142f032d70ef1f93a11d7134f05778938684ba70fa7b6b  zig-out/bin/stellaris_quickjs.dll
构建目录: /var/lofibass_ssd/code/zig/Neo-Stellaris/.zig-cache
```
构建目录路径会烧进 `.rdata` —— 段 sha 只在**同一个 build 目录内**可比(commit `2dbe245`)。
Step 6 复核:`just build && sha256sum -c` ⇒ `stellaris_quickjs.dll: 成功`,**出货字节不变**;
`abi-probe` 不在默认 `install` 依赖图里(判据即此 sha)。

### §65.1 布局断言读数(`src/dll/quickjs/abi_probe.c`)

`#include "quickjs.h"`(带 `-DCONFIG_VERSION="2025-09-13"`,同 `quickjs_c_flags`),
真实定义与**手抄孪生**(`ProbeJSValueUnion`/`ProbeJSValue`,按 `bindings.zig:82-89`+`:97-99` 同形)各断言一遍:

| 断言 | 真实定义 | 手抄孪生 | 读数 |
|---|---|---|---|
| `sizeof(JSValue)` | 16 | 16 | 通过 |
| `offsetof(JSValue, u)` | 0 | 0 | 通过 |
| `offsetof(JSValue, tag)` | 8 | 8 | 通过 |
| `sizeof(JSValueUnion)` | **8** | **8** | 通过 |
| `_Alignof(JSValue)` | 8 | 8 | 通过 |

**union 是 8 不是 16** —— 全部成员 ≤8 B(`uint64/float64/ptr/short_big_int`),
`JSValue` 的 16 = `u(8) + tag(8)`。这条是负向验证抓出来的:初稿把 union 也断成 16,
编译即红。Zig 侧同形断言在 `abi_probe.zig` 的 `comptime`(`@sizeOf==16`、
`@offsetOf("u")==0`、`@offsetOf("tag")==8`),两侧都过 ⇒ 三份定义(quickjs.h /
wrapper 手抄 / bindings.zig)在尺寸与偏移上**互相一致**。

### §65.2 负向验证(本任务的失败测试步)

把 `_Static_assert(sizeof(JSValue) == 16, …)` 临时改成 `== 17`,
`zig build abi-probe` ⇒ **编译失败**(摘原文):

```
src/dll/quickjs/abi_probe.c:21:16: error: static assertion failed due to requirement 'sizeof(struct JSValue) == 17': real JSValue size
src/dll/quickjs/abi_probe.c:24:16: error: static assertion failed due to requirement 'sizeof(union JSValueUnion) == 16': real JSValueUnion size
src/dll/quickjs/abi_probe.c:42:16: error: static assertion failed due to requirement 'sizeof(union ProbeJSValueUnion) == 16': twin JSValueUnion size
error: 3 compilation errors
```
改回(`JSValue==16`,两个 union 断言按实测改成 `==8`)⇒ 通过,两个探针 DLL 产出。
断言确实在跑,且抓到两处真实读数错误 —— 顺序未颠倒(先红后绿)。

### §65.3 强制引用与桩发射(`abi_probe.zig` + `abi_probe.c`)

Zig 只对**可达**函数体发射(死支路里的引用不进符号表),取函数地址不生成 call 桩 ⇒
每个点名符号各写一个 `export fn probe_<符号>`,体内**实际调用一次**并把结果 sink 进
全局。三条执行口径(都记在 SDD 台账):
- zig 0.16 已删 `volatile T`(实测 `error: expected type expression`),sink 用
  `export var`(外部可见 ⇒ 存储不被消除,机制等价);
- 强制集合 = brief 点名 7 条(JS_NewRuntime、JS_NewRuntime2、JS_UpdateStackTop、
  JS_Eval、JS_ToInt32、JS_Call、`__JS_FreeValue`);变参 `JS_Throw*Error` 族两侧都排除;
- `__JS_FreeValue` 在 `bindings.zig:623` 是**文件私有** extern,探针里按同签名重 declare
  (桩字节口径与 bindings 自己发射的无异);
- 两个探针 module 固定 **ReleaseFast**(Debug 码型把 JSValue ctor outline 成函数、
  外加 panic wrapper,把「一个桩恰好一次调用」的自校验淹掉;优化形也才是诚实的参数装配),
  C module 加 `-fno-stack-protector`(否则 clang 在 `JS_MKVAL` 的 16 B 局部上插
  `__stack_chk_fail`,多出的那条 call 会撞检测器)。

### §65.4 调用桩对照表(`scripts/scratch/2026-10_abi_probe/compare_stubs.py`)

对每个 `probe_*` 导出:pefile 读导出表拿 RVA → 该 DLL **自己的 `.pdata`** 取函数区间
(`scripts/pdata.py` 在 import 时就打开 stellaris.exe,读不了探针,故自解析)→
`scripts/pe_disrva.py <dll> <begin> <end>` 反汇编 → 自校验「函数区间内恰好一条对外 call/jmp」
(双侧 7/7 全过)→ 打 call 点前的参数装配窗口。完整窗口在
`.superpowers/sdd/…/abi_compare.txt`(一次性产物,不进 git);下表是逐条判读:

| 符号 | Zig 装配序列(机制) | C 装配序列(机制) | 同形? |
|---|---|---|---|
| **JS_Eval**(返 16 B) | `lea rcx,[rbp-0x10]` 返 slot、`rdx`=ctx、`r8`=input、`r9d`=len、`+0x20`=filename、`+0x28`=flags,`call` | 同一套,另把入口 rcx(sret)直接转发给了被调方(rcx 不再 `lea`) | **同形** |
| **JS_ToInt32**(按值收 val) | 栈槽写 `{1,0}` 后 `lea r8,[rbp-0x10]`,`rcx`/`rdx` 直传 | 栈槽由 `movups` 从 `.rdata` 灌入后 `lea r8,[rbp-0x10]` | **同形**(差异只在常量物化方式,不是 ABI) |
| **JS_Call**(收两个 16 B + 返 16 B) | 两个栈槽 `{0,3}`;`rcx`=返 slot、`rdx`=ctx、`lea r8/lea r9`、`+0x20`=argc=1、`+0x28`=argv | 同一套(返 slot 复用入口 rcx;栈槽 `movups` 灌) | **同形** |
| `__JS_FreeValue`(按值收,无返回) | 栈槽 `{0,-1}`、`rcx`=ctx 直传、`lea rdx,[rbp-0x10]` | 同一套 | **同形** |
| JS_NewRuntime(纯指针,对照) | `call` | 尾 `jmp` | 差异是**码型**(返回转发),无参数装配可言 |
| JS_NewRuntime2(纯指针,对照) | `xor ecx,edx` 后 `call` | 同 `xor` 后尾 `jmp` | 同上 |
| JS_UpdateStackTop(纯指针,对照) | 尾 `jmp` | 尾 `jmp` | 逐条相同 |

Win64 口径复核:16 B 结构体**按值**传参 = 调用方物化副本 + 一个 GPR 收指针
(只有 1/2/4/8 B 结构体进寄存器),16 B 返回 = `rcx` 隐藏返回槽 —— **Zig 发射的桩字节
与 C 编译器发射的走同一套约定,寄存器角色逐位对应**。

### §65.5 判决与边界

**判决词 = `abi_closed_static`。** 两份(实为三份)定义的尺寸/偏移断言一致,且三条
by-value `JSValue` 签名(`JS_Eval` 返 16 B、`JS_ToInt32` 按值收、`JS_Call` 两收一返)
的 Zig/C 调用桩装配**同形**;纯指针签名只作对照不作结论。⇒「Zig `extern fn` 会崩」的
ABI 假设**在「布局 + 调用桩」这一半被静态排除**。

边界(三条,不许越):
1. 本节判的是**调用方装配**;被调方是同一份 quickjs.c,不存在另一半差异来源,但**实机
   仍未执行 shot**,`extern fn` 路线的可用性最终仍要一次 shot 才算数(本场不开)。
2. **不因此放宽 `exports.zig:351-353`「不要新增 Zig `extern fn` 绑 QuickJS」的禁令** ——
   C 桥仍是现役实现,禁令变更要人点头(计划「明确不做」表)。
3. §36 的 rc=3 归因走的是 §47/§48 的 UBSan 线,与本节无涉;roadmap 段5 决策行的
   「根因未查」措辞按本节判决就地改写,不改写本节之前的取证原文。

坐标漂移(历史读数不改写,另记):§64.4 的删除落点 `build.zig:186-190` 因本节在 build.zig
插入 abi-probe 块而**后移**,现读数为 `:228`/:`232` 两段 SKIPPED 注释;执行删除时以
`grep -n SKIPPED build.zig` 现值为准。

门禁口径:`abi_probe.zig` **只被 `abi-probe` step 引用,不被任何 test 根 import**
⇒ 它不进 `599` 的账;本任务新增的 Zig 测试条数 = **0**,`just check` 计数不变。

## §66 零 shot:§63 边界外的两段形态派发方 —— 字节候选 + 函数首对齐复核(2026-10-26,离线)

授权级 = 离线 **零 shot**:无 launch/inject/install/Frida/process,只静态读默认本地 exe 拷贝
(sha 同 §60 前置,`docs/offline-tooling.md`);零运行时断言。生产者 =
`scripts/scratch/2026-10_exec_frame_census/queue_dispatchers_two_stage.py`(一条命令跑全三口径,
A′/B′ 硬门 + C′ 钉死判据全绿才写 `evidence/xrefs/queue_dispatchers_two_stage_4_4_4.tsv`;
任一不过 ⇒ 退出码 1、不写 artifact、不出负结论)。本节补的是 §63 边界 1 明文留下的口子:
`mov reg,[obj+0x28]; call reg` **两段形态**不在 §63 的 `call [reg+0x28]` 直接形态口径内。
解码口径直接 import 同族 `queue_dispatchers`(read_image/_blob/_md/_object_ref_functions/BASE),
复核与 §63 `_call_mem_disp_sites` 同一纪律:**候选=字节形态,复核=只对候选所在函数从 `.pdata`
函数首对齐解码**,绝不拿一次性整段 `.text` disasm 的结果当集合(见 §66.4 判读陷阱)。

### §66.1 口径 A′ —— `mov r64,[r64+0x28]` 候选 + 校准对硬门

`python3 scripts/scratch/2026-10_exec_frame_census/queue_dispatchers_two_stage.py --only A` → 逐字读数:

```
channel A': mov_candidates=8330 self_check=ok calibration_pair=(0x24d7e4,0x24d800)
channel A' sample: seed=444 n=400 verified_true=398 off_function=2 not_verified=0 []
```

候选字节形态 `[\x48-\x4f]\x8b[\x48-\x7f]\x28`(REX + `8b /r` mod=01 disp8、rm≠SIB 意图),
硬门 = 恰好 **8,330**(实测相符)+ 校准对必须找到。校准对 = load `0x24d7e4` / call `0x24d800`,
同在函数 `0x24d4d0`(`.pdata` 判 `0x24d4d0..0x24fc16`);逐条反汇编
(`python3 scripts/disrva.py 0x24d7e4 8`,2026-10-26 在案):

```
  0024d7e4  mov     r10, qword ptr [rax + 0x28]
  0024d7e8  mov     rax, qword ptr [rdi + 0x30]
  0024d7ec  mov     rcx, qword ptr [rax + 8]
  0024d7f0  lea     rdx, [rcx + 0x20]
  0024d7f4  mov     r9d, dword ptr [rcx + 8]
  0024d7f8  mov     r8d, ebx
  0024d7fb  lea     rcx, [rsp + 0x20]
  0024d800  call    r10
```

load 之后**第 7 条指令**就是 `call r10`,其间无任何写 `r10` 的 mov(写的是 rax/rcx/rdx/r9d/r8d)
⇒ 落在 C′ 的 ≤24 窗口里,已复现进 TSV 第 6 行(`C' 0x24d7e4 0x24d800 …,gap=7`)。
抽样复核 = 固定种子 444 抽 400 条、函数首对齐解码:398 条真、2 条落在 `.pdata` 函数边界外
(对齐解码不可达,即 padding/缝隙字节),0 条被解码判假 —— 与计划 brief 的「399 为真」是同一
现象(字节形态轻微过匹配 + 函数外伪命中),切分随抽样方法而移,不构成仪器分歧。
全量 8,330 条候选里 off-function 共 34 条(0.41%,与抽样 2/400 同率)。

### §66.2 口径 B′ —— `call <reg>` 候选下限门

`python3 ... queue_dispatchers_two_stage.py --only B` → 逐字读数:

```
channel B': call_candidates=14998 self_check=ok side_floor=ok(mov=8330,call=14998)
```

候选字节形态 `[\x40-\x4f]?\xff[\xd0-\xd7]`(可选 REX + `ff /2` mod=11)。硬门 = 恰好 **14,998**
(实测相符);续跑门 = `mov`/`call` 两侧候选各 ≥ 1,000(否则「配对 0」不可信,禁入 C′)。
全量 14,998 条里 off-function 共 7 条。

### §66.3 口径 C′ —— 同函数体内 load→call 配对(窗口 ≤ 24 条指令)

配对语义(钉死):同一函数体内(扫描限定「函数内同时含两种候选」,实测 1,420 个),
已核复 load 之后 ≤ 24 条指令内出现已核复 `call <dst>`,其间 `<dst>` 未被任何写目的地的
`mov` 重定义(GPR 家族归一后比较,`mov r10d,…` 算重定义 `r10`)。

`python3 ... queue_dispatchers_two_stage.py --only C` → 逐字读数:

```
channel C': pairs=105 both_form_funcs=1420 window<=24 object_fn_pairs=0 named=0 self_check=ok (undecodable-in-both=41, off-fn mov/call=34/7)
```

全量跑 `python3 ... queue_dispatchers_two_stage.py`(A′/B′/C′ 一条链)→ 逐字读数:

```
channel A': mov_candidates=8330 self_check=ok calibration_pair=(0x24d7e4,0x24d800)
channel A' sample: seed=444 n=400 verified_true=398 off_function=2 not_verified=0 []
channel B': call_candidates=14998 self_check=ok side_floor=ok(mov=8330,call=14998)
channel C': pairs=105 both_form_funcs=1420 window<=24 object_fn_pairs=0 named=0 self_check=ok (undecodable-in-both=41, off-fn mov/call=34/7)
verdict=two_stage_dispatchers_partial pairs=105 -> evidence/xrefs/queue_dispatchers_two_stage_4_4_4.tsv
trap-note: 一次性 disasm 整段 .text 的 call-reg 计数 = 17(desync 假数,§62.4 坑 1 同族)
```

配对集合非空:**105 对**,承载函数 86 个(多函数可贡献多对);
承载寄存器分布 `r10`×61、`rbx`×31、`r9`×9、`rdx`×2、`rsi`×1、`rdi`×1;base 寄存器
`rax`×90、`rcx`×7、`r10`×7、`rdx`×1;gap 全在 1..20。首三行样例(load/call/承载函数 begin..end):

```
C'  0x221430  0x22144b  0x221260..0x221726  mov r10, qword ptr [rax + 0x28]  rax->r10  gap=7
C'  0x2407d2  0x2407ec  0x240700..0x24086d  mov r10, qword ptr [rax + 0x28]  rax->r10  gap=7
C'  0x24d7e4  0x24d800  0x24d4d0..0x24fc16  mov r10, qword ptr [rax + 0x28]  rax->r10  gap=7  (校准对)
```

钉死判据第二条:§63 的四个对象引用函数 `{0x1c42d30, 0x1c42de0, 0x1ba6d20, 0x1ba72a0}`
(直接 import `queue_dispatchers._object_ref_functions` 重算,集合与这四个**相等**才继续)
内**配对数 = 0** —— 已复现;全部 105 对的 `object_ref` 列都是 `-`。
`undecodable-in-both=41` 是两侧字节候选中「对齐解码在函数内但落点不是该形态」的伪命中
(本场一次性用 `skipdata=True` 重解码不改变配对数 —— 该复核无提交态开关、非 CLI 可切模式
⇒ 不是解码停滞丢点,与 §63 的处置一致)。

### §66.4 读数漂移与判读陷阱(仪器状态自证)

**判读陷阱(记在本节,§62.4 坑 1 同族)**:一次性 `md.disasm(整段 .text)` 会撞不可解码字节
**静默停止**,本场实测它整段只报出 **17** 个 `call reg`(与 §62.4 当年的假数同值)——
17 对着候选口径的 **14,998**,就是「bulk 一次跑不能当集合」的反证本身。复核一律从 `.pdata`
函数首对齐解码(§66.1–§66.3 全程如此)。

**与计划 brief 的 C′ 读数漂移(报告而非迁就)**:brief 的表写「样本 132 条」。本探针按钉死语义
全量扫得 **105**,132 在任何钉死语义组合下构造不出。变体网格(同一 exe、同一候选集,均含
「函数内同时含两种候选」限定;**下表各变体读数是本场对同一检测器逻辑的一次性变体运行,不是提交态
CLI 的可切模式 —— 那个 CLI 只有 `--only A|B|C`,一条命令只复现钉死读数(A′ 8,330 + 校准对、
B′ 14,998、C′ 105 对 / 86 承载函数 / `object_fn_pairs=0`);网格是「计划 132 构造不出」的引证,
不是可复跑的测量**):

| 变体 | 配对数 |
|---|---|
| 钉死语义(load=候选位核复、call=候选位核复、mov 重定义剔除、窗口≤24) | **105** |
| 同上但 load 从解码流取(含 A′ 字节形态看不见的 dst=rax、disp32 变体) | 116 |
| 钉死语义去掉重定义剔除(窗口≤24 的无重定义上界) | 118 |
| 流式 load + 无重定义剔除 | 135 |
| 窗口扫描(钉死语义):16→96,20→105,24/28/32→105,40→109,50→112,64→113,不限→122 | — |
| `skipdata=True` / `size==4` 松紧 / 家族归一松紧 / disp 复核松紧 | 均不变(105 或流式 116) |

⇒ 实测变体中 132 不可构造:单条钉死条款放宽的上界是 118(去重定义剔除)与 116(load 越出候选),
最接近的 135 已经同时违反两处(load 越出候选 + 弃重定义剔除);窗口单独放宽(≤28/≤32 仍 105,
完全不设限也只到 122)。
A′/B′ 硬门(8330、14998、校准对第 7 条、两侧 ≥1,000)与 C′ 两条钉死判据(非空、四对象函数=0)
全部复现,检测器健康,按「brief 读数本身可疑时报改不静默改判据」处置:**本节与 artifact 记
全量实际读数 105**,判决档位不受影响(非空即中间档)。

### §66.5 判决与边界

**判决词 = `two_stage_dispatchers_partial`**(三档逐字
`two_stage_dispatchers_named | two_stage_dispatchers_partial | no_two_stage_pair_static`)。
为什么是中间档:配对集合**非空**(105 对,拒绝 `no_two_stage_pair_static` —— 该档也只在
A′/B′ 全绿时才有资格写,本场全绿),但没有一条配对的承载函数引用 §63 的 A/B 对象
(vtable `0x26d4dd0` / ctor `0x1c42d30` 那四个函数,拒绝 `two_stage_dispatchers_named`;
named 档若出现,必须附该承载函数的逐字节反汇编复核才允许断言,本场未触发)。
与 §63 同形:**静态能读全「两段形态的站点集合」,读不出「运行时谁把 [obj+0x28] 装进寄存器」**。

边界(三条,不许越):
1. 本节判的是「`mov reg,[obj+0x28]; call reg` **两段形态**」的静态配对集合;本节**没有**回答
   「谁是 scope」—— §59 的 `no_scope_candidate` 原样保持。
2. §63 的 `dispatchers_partial` 与本节的 `two_stage_dispatchers_partial` **不同义、不合并**:
   前者是 `call [reg+0x28]` 直接形态(1214 站点无一配对象),后者是两段形态(105 对无一配对象),
   两个集合、两个口径、两个判决词。
3. 零 shot、零运行时断言:C1 授权位未动,本节没有任何「实机如此」的宣称。

artifact `evidence/xrefs/queue_dispatchers_two_stage_4_4_4.tsv` 列 =
`channel, load_rva, call_rva, func_begin, func_end, load_form, base_reg, call_reg, object_ref, note`,
`#verdict` 行带 `mov_cands=8330` / `call_cands=14998` 两个仪器状态数(与三档判决词并列,
下一个人可先核仪器再核结论);一行 `A'` = 校准对(含逐条在案的第 7 条),105 行 `C'` = 全部配对。
一条命令复现全部三口径与判决(`--only A|B|C` 单跑;任一硬门/钉死判据不过 ⇒ 退出码 1、
artifact 不落盘)。

## §67 donor 第一次 shot:`0x3AFD30` 只读采样,窗口静默(2026-10-26,点名)

**授权级别**:本次会话内点名(roadmap 段2 第二行)。人对本段的原话是「**授权,立刻打**」,同一次问答里
对第二次 shot 的排序裁定是「donor 后我先写 Task 3,再打第二枪」—— 本段只含 donor 这一发。

**这一发问的是什么**:§57.4 那张三档表的前两档 —— donor 这一族到底进不进它们 slot[1] 共用的虚
Execute(`0x3AFD30`),进的是五张静态候选表(`0x24B1D98`/`0x24EAAC0`/`0x25F4440`/`0x2606F00`/
`0x2606FE0`)里的哪一张。读的是 `[self+0]`,即 effect 对象自己的 vptr;它与 scope 那次 shot 的
`self_vtable_rva`(base Execute 收到的 `self`)不同源,两处读数不得互相引用(§57.4 那段「不同源」的
原话 + §55.4 未排除第 1 条)。

**进程与字节**:pid=3416,hwnd=198502,`just launch` 第二次尝试才 handed off(第一次 30 s 内没等到
launcher 窗口,`inner_exit code=21`)。上线字节 `C:\temp\sqjs_c4.dll`,sha256
`7d3e45c4b25974324e48b0e952b44a8895c643779e3bc24ce97e41981f6ac0d3`(= 本场 `zig-out/bin/stellaris_quickjs.dll`,
导出面 `MISSING: []`)。**整文件 sha 只当出处,不做相等断言**(每次重链都换)。

**执行 shot 前踩到的两个环境坑(都是 instrument 侧,不是引擎侧)**:
① 远端 `sqjs_c4.dll` 原来是上一个会话留下的旧文件(sha `1b568cd4154da1e9afcb25c451c5f9000ea5ce5cf6afdc995fd9760e06412ba9`),
`ren` 因目标已存在而**静默失败**,长度照样非 0 ⇒ 「远端有文件且有长度」证明不了上线的是本场字节。
改用 `Copy-Item -Force` + `Get-FileHash` 对上 sha 才执行 shot。② ssh argv 里 DLL 写成相对名
`sqjs_c4.dll` ⇒ 目标进程 `LoadLibraryA` 按**游戏自己的 cwd** 解析,返回 NULL,驱动在任何注入之前
拒掉(`nothing was injected ⇒ no cleanup to run`,install 额度未耗)。argv 必须用绝对路径
`C:\temp\sqjs_c4.dll`(`donor_shot.cmd` 钉的就是绝对形态)。

**前置读数(§59.1)**:紧邻执行 shot 的 `just game status` = `STATUS=playing note=ok pid=3416 hwnd=198502
age=1.2s want=playing cmd=unpause`。要显式发一条 `just game unpause` 才到 `playing`:监督器的
`plan_step` 把「裸暂停」判成人工暂停、只上报不代推(`report_paused_no_window`)。没做 `console_open`
检查(它不是判据,§59.1)。

**读数(逐字取自 artifact 首行 `#meta`,665 B)**:

```
calls=0 samples=0 entries=0
tiers=h0=0/h1=0/h2=0/h3=0/h4=0/unmatched=0/invalid_self=0
unmatched_rows=0 rva_zero=0 in_image=0 at_or_above_image=0
verdict=no_calls_inconclusive named_table=-
layout=entry=48 stats=56 ring=256 mask=0 version=1   install_rc=0
```

频率:`calls/poll_s = 0/120.0 s = 0.0 calls/s`。layout 五个数与 `docs/offline-tooling.md` donor 一节
的口径一致(无 `LAYOUT_DRIFT`)。清理段序照纪律走完:`C4DonorProbeUninstall rc=0` → `verify=0` →
settle 2 s → `host alive`;全程不 `FreeLibrary`,DLL 映射原样留着(#meta 里 `installed=1` 是清理**前**
那次 stats 读数,不是残留状态)。

**verdict 的有界含义**。本次拿到的是五档里的 `no_calls_inconclusive`。它**不是** §57.4 的第三档:
第三档要「哨兵 body 等齐(执行确实发生)而 `calls==0`」,前半句是独立证据,而这把仪器既没有哨兵也
证明不了「执行确实发生」⇒ **本次读数不含第三档资格**(`VERDICTS` 值域里没有它,判读陷阱 1)。
安静窗口的唯一诚实读法是「没观测到」:主菜单的这 120 s 里,这一族有没有被调用,这台仪器没问出来。
前两档若将来命中,tier 1(`[self+0]` ∈ 五表)= 经虚派发成立且**指名哪一张表**;tier 2(五表之外)=
「看到一张静态候选之外的表」,**交给静态查表的接力**(`--who-lea` 问「谁引用这张表」),它不等于
「运行时生成的表成立」—— 计数侧 `unmatched` 同时吸收图像内 code-address、`toRva`→0、以及
`SizeOfImage` 之外尾巴的读数,能拆的只有环记录的 image span 三分区(本次四个数全是 0,因为没有记录)。

**下一次点名带不带 mask:仍带 `--mask 0`,但前置换。** §57.4 明写「先测调用频率再定采样分母,不要
照搬 1/512」,而频率只能从恒计的 `calls` 里读;带 mask 会让 ring 采样变稀,却不会让 `calls` 变准。
这一发缺的不是 mask,是**这一族真的在执行**:所以下一次点名的前置是「载入进行中的存档、确认
per-system 执行在发生」,而不是「第二次点名把 mask 调大」。

**§57.5 五条未排除事项的当前状态**(逐条,以本次 shot 的读数为准):
1. 运行时堆上生成/复制的表,静态看不见 —— **仍未排除,且这一发没碰它**。`calls=0` 对「有没有这样
   一张表」不提供任何信息;这一档的实体证据只能来自 tier 2 + 静态接力。
2. `slot_hits` 与「前四槽相等」是形状判据不是身份判据 —— **未变**;本次无记录,形状判据一次都没被行使。
3. `--who-lea` 只认一种编码(`48/4C 8D|8B` + `mod=00 rm=101` + disp32)—— **未变**,接力那一手仍受此限。
4. `0x3B01A0` 的 lea 站点 = 0,含义是「这个问题问不出答案」不是「没人用它」—— **未变**。
5. 候选集只扫 `.rdata`,落在 `.data` 的表形成看不见 ⇒ 「命中 0 张」不能读成「没有另一份表」——
   **未变**;本次 `h0..h4` 全 0 同样不携带任何「五表不被用」的信息。

**复现命令行**:

```bash
ssh -o ServerAliveInterval=15 Windows_Jiaolong "cd C:\\temp; python c2_donor_probe.py C:\\temp\\sqjs_c4.dll --mask 0 --poll-s 120 --settle-s 2 --out C:/temp/c4_donor_probe.tsv"
scripts/scratch/2026-10_scope_shot/pull_slice.sh c4_donor_probe.tsv evidence/logs/donor_probe_4_4_4.tsv
```

## §68 scope 深跟读第二次 shot:修正仪器后的第一发 `scope_candidate`(§59 是 0 命中、§56 在误配仪器下已有 14 条),而 `lineage_edge_found` 的两条边都不是血缘(2026-10-26,点名)

**授权级别**:点名。人对这一发的原话是「**donor 后我先写 Task 3,再打第二枪**」—— 那是一条顺序裁定,
同时也是本发的授权:Task 3 落地之后打这一发。前置读数、argv、清理复核逐字记在本节末。

**这一发问的是 §59.9 的前置 1** ——「要的是 `self`/`helper` 上**更深的跟读形状**」。形状由 Task 3 做进
`scripts/c2_scope_probe.py`(`plan_depth2` / `follow_depth2` / `find_shared_cells` / `classify_depth2`,
提交 `fcaff71`),**DLL 一个字节没动**:本发的 `#meta` 里 `dll=sqjs_c4.dll`、
`dll_sha256=7d3e45c4b25974324e48b0e952b44a8895c643779e3bc24ce97e41981f6ac0d3`,与 §67 那发同值 ——
「两发之间没重编 DLL」这句话的证据就是这一行,不是我的记忆。

**环境与前置**:新进程 pid **20220**(hwnd 329928)。`just launch` 头两次都以 `code=23 /
diagnosis=handoff_never_fired` 收场(三次点击都拿到焦点、光标都落在算得的点上,启动器原地不动),
第三次在 attempt 3 命中 handoff ⇒ 进程起来。**这一次游戏自动进了战役**(存档 2270.10.10),
停在一个事件窗「克伯利安恒星国同盟的末日」上;监督器 `policy=first` 的 `handle_choice` 对同一签名
连点 >3 次后自锁,状态报 `note=choice_stuck`,`just game choose 1` 与 `just game unpause` 都不动它。
按 §59.2 的手工路线先 `just game shot` 取回裁片人眼量出「确认」按钮的屏幕坐标,再
`just game click 1077 890` —— 事件关掉后游戏自己恢复,状态行回到
`STATUS=playing note=ok pid=20220 hwnd=329928 age=2.3s want=playing cmd=click 1077 890`。
**紧邻执行 shot 的前置读数就是这一行**(§59.1:判据是 `state=playing`,`console_open` 不是)。
本发没有换来新的环境条件 —— §59、§67、本发三发都是进战役后按 `state=playing` 前置打的;
换来的是**深度**:修正仪器之后第一次带着 depth-2 形状问 base Execute。

### §68.1 与 §59.3 基线的逐键差分(同一仪器、同一 DLL 字节、不同深度)

| 键 | §59.3(depth-1 基线) | 本发(depth-1 + depth-2) |
|---|---|---|
| `calls` | 3061 | **1046773**(120 s 窗口 ≈ 8723 calls/s,与 §10 的 ~5300/s 同量级) |
| `samples` | 5 | 2044 |
| `valid` | — | 256(环满,最老在前) |
| `followed_by_source` | self=4/helper=2/arg3=1/arg4=1 | self=8/helper=2/arg3=0/arg4=1 |
| `implausible_by_source` | — | self=0/helper=0/**arg3=256**/arg4=255 |
| `capped_by_source` | — | **self=245**/helper=0/arg3=0/arg4=0 |
| 四桶 known/member/unknown/unreadable | 0/0/16/0 | **2**/13/37/**0** |
| `regions_queried` | 0(那一发没问出来) | 26 |
| `verdict` | `no_scope_candidate` | **`scope_candidate`** |
| `verdict_d2` | 该档当时不存在 | **`lineage_edge_found`** |
| `shared_cells` | — | `n=2`(两条,见 §68.3) |

`arg3` 全 256 条 `implausible`、`arg4` 255 条:派发点上这两个寄存器是上一调用者的 scratch
(判读陷阱 2),这次连形状都不像指针,所以 depth-2 在 `arg3`/`arg4` 两支**必然是 0 计划**
(`d2_planned_by_source arg3=0/arg4=0`)—— 这是「没问出东西」,不是「问出没有」。

**预算没问完的那一支要按预算读**:`d2_capped_by_source self=19`(helper=0,这一键在 `#meta` 里),另有
`deduped_by_source` self=5/helper=1 —— **去重那两个数只在那一发 stdout 的逐源行里**,`d2_meta_rows`
的六个 `#meta` 键不含它们,所以它们不能从 TSV 读回,只能作为 stdout 记录引用。
所以 `self` 这一支的深跟读**只问了 8 个地址就撞到每源预算**,
剩下 19 个不同的候选值一个都没被 derefence。这一行不许读成「那 19 个槽里没有 scope」,
它读作「预算在这里截断」(与 §56.4 那次同一个形状,只是这次有键记着)。

### §68.2 `known=2`:修正仪器后的第一次非零,两条 floor 命中指名到根 + 偏移 + slot2(同两个 RVA 在 §56.4 已有)

```
object  root=0x1f6d6ecd8  source=self  off=0x30  ptr=0x1f6d6e510  vptr_rva=0x2545e40  slot2_rva=0xcc8bd0
object  root=0x1f6db2dc8  source=self  off=0x10  ptr=0x1f6db2d10  vptr_rva=0x254fa18  slot2_rva=0xde40c0
```

按修正流程打的两发里,`known` 这一档从 §59 的 0 变成本发的 2,两条都在 `self` 根上。**「这台仪器第
一次拿到 `known` 命中」这句话不成立,本节的初稿那样写过并已更正**:§56.4 在误配仪器那一发就报
`known_vtable_hits=14` ⇒ `VERDICT: scope_candidate`,§56.8 只撤回了那一发的**负结论**、明写
「`VERDICT: scope_candidate` 本身不变:14 条 `known` 命中不依赖上面任何一句话」;而 §56.4 那张命中表
里已经有 `+0x30`→`0x2545e40`/slot2 `0xcc8bd0` 与 `+0x10`→`0x254fa18`/slot2 `0xde40c0` 两行,
**与上面这两条同值** ⇒ 本发的 `known` 是**同两个 RVA 在修正仪器与更深层下重新交出**,不是新认出的类。
`member_vtable` 那 13 个
(artifact 里 14 行)**仍不进判词**(判读陷阱 7:它说的是 root 自己的类)。
离线复算(`scripts/scope_reclassify.py`)对同一份 TSV:`floor set 1805 / shape set 172296 /
object rows 106 / floor_hits 2 / new_only_hits 3 / still_no 33 / undecidable 68`。
三条 `new` 全挂在 `root=0x7fef70 source=helper` 的 `+0x10/+0x20/+0x38`,`vptr_rva` 是
`0x247a488`(两次)与 `0x25e54c8` —— **读数是读数,不是验收**(§59.8 把那条 mis-specified 的
验收降成了读数);`undecidable 68` 里含 depth-2 那些界外 `vptr`。
`caller` 44 行里 42 行 `func=-`:census join 走的是 `ret-5` 估值,虚调用 `call qword ptr [rax+8]`
只有 3 B,估值不挨着真站点 ⇒ 这读作「估值不是它的站点」,不读作「没人调用」(§59.7 口径)。
`chain` 一行 `ok=0 x=0x0`、`ids=[]`:那条 X→S 链早已 §53.3 证伪,本发不重提。

### §68.3 `lineage_edge_found` 的两条边,一条是标量、一条是静态表

`shared_cells` 全文:

```
n=2  0x100000000(rva=-)[helper@0x18fb29e20+0x10,self@0x1f6d85660+0x20,self@0x1f6d6e510+0x20]
     0x7ff6a095a488(rva=0x247a488)[self@0x1f6db2dc8+0x30,helper@0x170790bc0+0x0,helper@0x170790bc0+0x18,helper@0x170790bc0+0x30,helper@0x170790b40+0x38]
```

- 第一条 `0x100000000`:三个槽同值,但 `1<<32` 是**标量形状**,不是指针(界外 ⇒ `rva=-`,
  bounds 纪律在这里正好显出它的用处)。`find_shared_cells` 按候选值分组且**不筛
  `plausible_user_ptr`**,所以标量也能连成边 —— 这一条**不是**血缘证据,它是「同一份计数在
  多处出现」。
- 第二条 `0x7ff6a095a488`(`rva=0x247a488`,界内):`self` 的 `+0x30` 与两个 `helper` 根的
  四个槽共用这一个值。而**同一个 RVA 在 §68.2 的 `new` 行里是以 vptr 的身份出现的** ——
  ⇒ 它是一个**模块内静态 vtable 形状的格子**被多处引用,不是两个活对象共享一个堆成员。
- **§59.6 那条 `0x2ddc2c90` 在本发没有重现**(全文 `grep -c 2ddc2c90` = 0)。它仍是一条
  未复现的单点读数,本发既不证实也不证伪它。

**深跟读这一层的根有一半不在堆上**:`self.d2` 的 8 个根按 region 判为
`image=6 / private_committed=1 / reserved=1`,`helper.d2` 的 6 个根判为
`image=1 / private_committed=3 / free=2`。落在镜像里的那些「对象」是数据段的结构,
它们的「成员指针」是静态初始化值 —— 这一层的 `known`/`member_vtable` 读数在解释时要先过这一条。
另有 3 行 `root_unreadable`(`helper.d2` 两条 `0x45f00000000`/`0xe2100000000`、`self.d2` 一条
`0x29c55c0`),而 meta 的 `unreadable_roots=0`:**那个计数只算 depth-1**(它在 `summarize` 里定,
深跟读之后才并入 `summary["objects"]`),两个口径不同义。

### §68.4 `VERDICT_D2` 的有界含义 + §59.9 前置 1 的当前判定

`lineage_edge_found` 是五档梯子(`no_depth2_planned → depth2_unreadable → depth2_known_vtable_hit
→ lineage_edge_found → no_depth2_lead`)里的**两档证据之一**,它的有界含义只到
「**再下一层交出的候选值里,有一个值同时出现在两个不同基源的槽里**」。它不说:那个值是对象、
两个源共享同一个 scope、或者血缘方向。本发更进一步 —— 两条边一条是标量、一条是静态表
(§68.3),所以这一档**成立但没有把 scope 载体往前推一格**。

前置 1 的判定因此是**分支的,不是一句「问完了」**:
`helper` 支问完(`planned=6 / followed=6 / capped=0`),`self` 支**没问完**
(`planned=8 / followed=8 / capped=19`)。按 §57.4 那三档的读法,这里既不是「拿到新候选」
(`depth2_known_vtable_hit` 没有命中:depth-2 的 8+6 个根里没有一个候选的 `[ptr]` 落进 1,805),
也不是「这一层问完了、答案仍空」。**下一前置不是「再深一层」**,而是两件仪器侧的事:
① `find_shared_cells` 要先把候选值按 `plausible_user_ptr` 与界内/界外分档,再谈连线;
② `self` 支的 depth-2 预算要么抬高、要么把 `capped` 的 19 个地址点名留给下一发。
`verdict` 那侧的下一前置仍是 §67 那句:让这一族真的在执行时重打,与 depth-2 无关。

### §68.5 清理复核(一次 shot 一个进程、永不 `FreeLibrary`)

驱动自己的收尾打了 `C2ScopeProbeUninstall rc=0` / `C2ScopeProbeVerify rc=0 (engine bytes intact)`
/ `host alive`。artifact 的 `stats` 行停在 `installed=1 verified=-1` —— 那是轮询结束时的快照
(§59.10 那个坑的形状),不是残留状态,所以按流程补跑一次复核:

```
BEFORE calls=1046777 samples=2044 invalid_self=2 invalid_ctx=0 lexer=0 x_nonzero=21 patch_size=16 installed=0 verified=0
[scope] C2ScopeProbeUninstall rc=0
[scope] C2ScopeProbeVerify rc=0 (engine bytes intact)
[scope] host alive
AFTER  calls=1046777 samples=2044 invalid_self=2 invalid_ctx=0 lexer=0 x_nonzero=21 patch_size=16 installed=0 verified=0
RESTORE_OK
```

`calls` 在 BEFORE/AFTER 之间不再增长(1046773 → 1046777 后停住)⇒ 采样器确实已摘。
全程没有 `FreeLibrary`,pid 20220 保持存活。

### §68.6 措辞门与出处边界

本节**不引用 §67 的任何 `[self+0]` 读数当证据**:那一发读的是 `0x3AFD30` 入口的 `[self+0]`,
本发根本没读那个槽(本发是 `0x1D08520` 的 base Execute 采样 + 驱动侧 dereference)。两节各引各的
argv,见下面两组命令行。同样地,本发的 `calls=1046773` 只说明 base Execute 在跑,**不**说明
donor-shaped 那一族在跑(§57.4 末段那条覆盖范围结论原样适用)。

### §68.7 复现命令行

```bash
# 前置读数(紧邻执行 shot)
just game click 1077 890 && just game shot      # -> STATUS=playing note=ok age=2.3s
# 执行 shot(前台经 ssh,§59.2;argv 逐字照 scripts/scratch/2026-10_live_window_donor_scope/scope_shot.cmd)
ssh -o ServerAliveInterval=15 Windows_Jiaolong "cd C:\temp; python C:\temp\c2_scope_probe.py C:\temp\sqjs_c4.dll --poll-s 120 --settle-s 2 --out C:\temp\c4_scope_d2.tsv --vtables C:\temp\ceffect_vtable_map_4_4_4.txt --census C:\temp\exec_frame_callers_4_4_4.tsv --id-names C:\temp\descriptor_oracle_4_4_4.tsv"
# 拉回 + 离线复算
scripts/scratch/2026-10_scope_shot/pull_slice.sh c4_scope_d2.tsv evidence/logs/scope_probe_d2_4_4_4.tsv
python3 scripts/scope_reclassify.py --tsv evidence/logs/scope_probe_d2_4_4_4.tsv
# 清理复核
ssh Windows_Jiaolong "cd C:\temp; python C:\temp\ns_scope_finish_cleanup.py 20220 C:\temp\sqjs_c4.dll"
```

产物:`evidence/logs/scope_probe_d2_4_4_4.tsv`(211 行,`#meta` 带 depth-2 的六个键)。

### §68.8 移交表（本计划窗口收口，三条各带前置与授权级）

| # | 下一发窗口要问的 | 前置 | 所需授权级 | 归属 |
|---|---|---|---|---|
| ① | §57.4 **第三档** —— 「哨兵 body 等齐（执行确实发生）而 `calls==0`」 | 要一个**不带 predicate 的证人**来钉「执行确实发生」：哨兵与 donor/predicate 互斥性同源（§57.4 那段 + §54–§56 三次 shot 的门在 `0x1D08520`），所以它需要自己的取证节，不能挂在 donor 这把仪器上 | 点名（新仪器 = 新 argv） | **归下一个计划**（本计划「明确不在本计划内」表第 1 行的理由） |
| ② | scope 载体一问：若 `verdict_d2` 落在**非证据档**（`no_depth2_planned`/`depth2_unreadable`/`no_depth2_lead`） | 只剩 §59.9 **前置 2** 之外的一条**新路线** —— 两条零 shot 路线已判完（往上定帧构造点 = §61–§63，两段形态派发方 = §66），两者判决词不同义、不合并；**要新形状，不要重打同一形状** | 新路线若仍是零 shot 静态 ⇒ **无**；若要运行时证据 ⇒ 点名 | 下一个计划 |
| ③ | C5 试点二（种族占比 → 资源产出 / 外交与战争态度，叠加要道 → 全局图度量） | `docs/c5-pilot2-spec.md` §3 的 **5 项裁定**（归人），加**一次 galaxy map 拷贝** | galaxy map 拷贝 = **不是 shot**（离线静态输入）；实机部分授权级同 C4 | 等裁定，不成计划 |

本发（§68）落在 ② 的**证据档**：`lineage_edge_found` 成立但两条边一条是标量、一条是模块内静态表
（§68.3），没把载体往前推一格，所以 ② 现在是**条件式移交**，未触发。

**2026-10-28 改判（§73）**：下一发 `verdict_d2 = no_depth2_lead`（非证据档）⇒ ② 的触发条件成立，
**本仪器这一层问完了，只剩一条新路线**。改判的读数与作用域见 §73.4–§73.7（本发样本 5 个、
`capped` 全 0，与 §68 那 19 不是同一集合）。

## §69 同族 slot[2] 证人两窗（20 s + 120 s）：`0x3B01A0` 全程静默 —— 而「载入进行中存档」这一步是 launcher 的 `--continuelastsave` 代做的，点击路径本窗口未执行(2026-10-27,点名 ×2)

**授权级别**：同一个窗口里两段点名，彼此分开。第一段人给的是「**授权武装：launch + 载入点击**」，
选项原文明写「到 Step 5 读数后即停，再单独问 shot」；第二段在武装读数达成后另问一次，选项原文
「**两发都授权（频率窗→正式窗）**」。本段含这两发证人 shot，不含 donor 重打（那是 §70 的事）。

**进程与字节**：pid=15500，hwnd=133164。`just launch` 一次成功（`GAME_OBSERVE step=ok alive_s=30`、
`code=0`），没有 §67 那次 `inner_exit code=21` 的重试。上线字节 `C:\temp\sqjs_c4.dll`，sha256
`6613e3240fdad4ea594aedd0eae4673ab7eec818100fb035f35ed1ad937eafd9`（= 本场 `zig-out/bin/stellaris_quickjs.dll`；
导出门 17 名 `MISSING=[]`；走 `Copy-Item -Force` + `Get-FileHash`，不 `ren`，§67 坑 ①）。
**整文件 sha 只当出处，不做相等断言。**

本窗口另外钉了一条出处事实：主机侧 `C:\temp\c2_witness_probe.py` = `9254c5121d361f501ebf04fa5fb1bbac47158f9e75c1917d4ea4d16050304feb`、
`C:\temp\c2_donor_probe.py` = `0a529c537c87ba9044a7263e7b017e6b9cf1af0d865856af8ad458c3e09c0034`，
两个都逐字节等于 git HEAD 那一份 ⇒ 本窗两发放出去的仪器与仓库里那份同源可查。（对照：上一窗口的
donor 驱动在主机上与 git 全部四个版本都不符，那批字节已不可取回 —— 这条规矩就是从那件事来的。）

### §69.1 载入这一步实际发生了什么（不粉）

计划里的点击梯（Task 5 的决策核 + Step 4 的「逐步读图确认才点」）**一条都没有用上**。起进程后的第一张
截图 `ns_game_shot.png`（2160×1440，本地判读副本 basename `load_step1.png`）显示游戏**已经在战役内**
（日期 2273.01.01、暂停态）。进程命令行原文含 `--continuelastsave`（在 `--pdx-launcher-session-token`
之后、`-gdpr-compliant` 之前）⇒ 进战役的机制是 **launcher 自动续最近存档**，不是我们点 load 界面选存档。

因此本窗口对「载入进行中存档」这一前置的贡献是**达成状态**，不是**达成路径**：

- 存档确实在跑（下面 §69.2 的日期推进与 `playing` 读数是它的证据），但「我们能把存档载进去」这件事
  **没有被本窗口验证过**。
- `scripts/scratch/2026-10_c4_sentinel_window/load_path.py` 的 `STEPS` 保持空列表，
  `test_load_path.py` 复跑 **7 passed**；那条 `test_module_sequence_starts_empty`（写着「这条就是会被
  Task 7 改掉的那条」）**没有被改掉** —— 点击梯的实机验证仍是未做项，不在本段的读数里。
- 本窗口唯一一次由读图决定的点击是 §69.2 的清障点击，它属于「把状态弄回 playing」，不属于载入路径。

### §69.2 事件窗、清障点击与前置读数

武装完成后紧邻的第一次 `just game status` **不是** playing：

```
STATUS=paused note=choice_stuck pid=15500 hwnd=133164 age=1.3s want=playing policy=first handled=5 cmd=unpause speed=None
```

截图（主机原帧 `ns_game_shot.png`，本地全帧 basename `load_step6_choice.png`，1,659,703 B；
快速判读用同帧缩略 `ns_game_shot_small.jpg` → `load_step6_small.jpg`；量坐标用主机侧原生分辨率裁剪
`ns_dialog.png` → `dialog.png`（裁剪原点 760,500，尺寸 640×440）与 `ns_confirm_band.png` →
`confirm_band.png`（原点 900,850，尺寸 370×90））读回：这是一扇**事件窗**「克伯利安会议的末日」，
正文两句（「被称为克伯利安会议的帝国在敌人的进攻之下已经灭亡。这会怎样影响星系的政治环境还有待观察。」），
底部一条通宽的「确认」按钮，**没有任何可选项**。⇒ `choice_stuck` 的成因是**分类器把单按钮事件窗
当成了选择窗**：`policy=first` 去点「第一行」，在那扇窗上指不到「确认」，同签名连击 >3 次后按纪律停手。
这是仪器侧的分类缺口，不是引擎异常。

按原图量取按钮条（在 640×440 裁剪内 x≈40–530、y≈372–400 ⇒ 原生中心 ≈(1045, 885)，按钮条横向跨度
556 px，容差远大于量取误差）⇒ 一发 `just game click 1045 885` 点掉，状态回到 playing：

```
STATUS=playing note=ok pid=15500 hwnd=133164 age=0.1s want=playing policy=first handled=5 cmd=click 1045 885 speed=None
```

**发正式窗前最后一次紧邻读数**（Step 5 口径，§59.1：前置判据只有这一条，没做 `console_open` 检查）：

```
STATUS=playing note=ok pid=15500 hwnd=133164 age=1.4s want=playing policy=first handled=5 cmd=click 1045 885 speed=None
```

**发完正式窗后**同态且 `handled` 未涨（`age=0.5s ... handled=5 cmd=click 1045 885`）⇒ 120 s 里没有任何
新弹窗打断；日期从 2273.01.01 走到 2282.06.26 是「这段时间真在跑模拟」的同一条侧面读数。

**环境坑（与 §67 那两条不同的一条，判读陷阱 #10 在本窗口复现）**：第一次 `just game unpause` 得到
`note=resume_failed: focus refused before Space`。成因 = 我们自己的两扇任务父壳 cmd 持有前台并把游戏
挤下去（`tasklist`：cmd 9064 = `ns_awake_task.cmd`、17164 = `ns_game_supervisor_task.cmd`）。按文档处置
`taskkill /F` **只杀父壳**：pythonw 5624 / 17264 存活（`tasklist` 复核），`just awake check` 仍
`STATE=serving DESKTOP=unlocked detail=Default pid=5624` rc=0 ⇒ 防锁屏没被这次处置打断；顺带消掉压在
画面上的黑底控制台窗（§54.10 / 批次 2 记的像素污染面）。判据仍在那两个字符串上，不在 `game.log` 上。

### §69.3 频率窗（20 s，先测频率再定分母，§57.4）

argv：`python c2_witness_probe.py C:\temp\sqjs_c4.dll --mask 0 --poll-s 20 --settle-s 2 --out C:\temp\c4_witness_freq.tsv`
（artifact 拉回 `evidence/logs/witness_freq_4_4_4.tsv`，664 B）。读数 `calls=0 samples=0` ⇒
**`calls/poll_s = 0/20.0 s = 0.0 calls/s`**，`install_rc=0`，清理段走完。

决策：**这一档不是恒计**，所以「用 mask 定分母」这个问题在这一发里没有出现 —— 分母讨论要等到真的看到
非零计数才有对象。正式窗因此照 §57.4 的口径继续 `--mask 0`（全计），不调 mask。

### §69.4 正式窗（120 s，本窗判决读数）

argv 逐字取自 `scripts/scratch/2026-10_c4_sentinel_window/witness_shot.cmd`；artifact
`evidence/logs/witness_probe_4_4_4.tsv`（665 B），`#meta` 首行逐字：

```
#meta exe_base=0x7ff7a6030000 image_size=0x3927000 image_end=0x7ff7a9957000 dll=sqjs_c4.dll dll_sha256=6613e3240fdad4ea594aedd0eae4673ab7eec818100fb035f35ed1ad937eafd9 target_rva=0x3b01a0 mask=0x0 poll_s=120.0 layout=entry=48 stats=56 ring=256 mask=0 version=1 calls=0 samples=0 entries=0 tiers=h0=0/h1=0/h2=0/h3=0/h4=0/unmatched=0/invalid_self=0 verdict=no_calls_inconclusive named_table=- install_rc=0 stats=calls=0 samples=0 invalid_self=0 unmatched=0 h0=0 h1=0 h2=0 h3=0 h4=0 patch_size=15 installed=1 mask=0 unmatched_rows=0 rva_zero=0 in_image=0 at_or_above_image=0
```

频率：`calls/poll_s = 0/120.0 s = 0.0 calls/s`。`LAYOUT entry=48 stats=56 ring=256 mask=0 version=1`
与 donor 口径一致（无 `LAYOUT_DRIFT`）；`target_rva=0x3b01a0` = 证人靶（slot[2] instantiate helper，
静态 qword 出现 454 次，与 donor 的 538 不是同一个数，不得混引）。`named_table=-`、四个 code-span
分区计数全 0（没有记录可分）。

**清理段（逐字）**：`C4WitnessProbeUninstall rc=0` → `verify=0` → settle 2 s → `host alive`。两窗各自
走完这条序；`#meta` 里的 `installed=1` 是清理**前**那次 stats 读数，不是残留状态。全程不 `FreeLibrary`，
DLL 映射原样留着。

### §69.5 verdict 的有界含义（三行诚实条款，原样落文，不可事后放宽）

两窗都落在五档里的 `no_calls_inconclusive`（驱动结尾把它打成 ENVIRONMENT result）：

1. 证人 `calls==0` ⇒ **第三档资格不成立**。
2. instantiate helper 可能只在 parse / 全树枚举时被调用（§57.2 观测 4：枚举器对每个节点 `create`），
   「证人安静」有两种本仪器分不开的读法 —— **族不在执行** / **族在执行但不走 runtime-instantiate** ——
   两种读法都列名进未排除项，读数只判「本仪器没问出执行在发生」。
3. 只有证人 `calls>0`（尤其 tier-1 join）配上 donor 读数才进入判决表；tier-1 是「这一族在执行」的
   **最强同源陈述**。

⇒ 本窗口对 §57.4 的净贡献是**零**：既没建立第三档，也没否证它。它钉住的是两件工具事实 —— 这把仪器
能问这个问题（install/verify/清理三段全绿、布局无漂移、靶与 donor 不同源），以及**在一份正在跑的存档里
20 s + 120 s 两窗它都没听到 slot[2] 被调用**。第二件不是引擎的陈述：正在跑的存档里 per-system 执行
几乎必然在发生（日期在走），而证人没响 ⇒ 这把仪器证不了「执行经过 instantiate helper」，这条与前一条
合起来就是 §57.5 式的未排除项，不是新判决。

**下一次点名带不带 mask**：仍 `--mask 0`。这一发缺的不是采样密度，是**一次真的经过 helper 的执行**；
要么换触发形状（载入瞬间的 parse/枚举最可能命中 helper），要么承认这把仪器的靶选错了并回静态侧重新
选点 —— 后者是新的取证节，不是重打。

**§68.8 移交表 ① 的当前状态**：证人已存在、已装过、已扫过一份运行中的存档两窗，①的前置里
「不带 predicate 的证人」这一条**已满足**，「哨兵 body 等齐（执行确实发生）」这一条**没有**（本窗只有
日期推进这种侧面读数，不是哨兵）。① 仍是未触发。

**复现命令行**：

```bash
# 频率窗（20 s）
ssh -o ServerAliveInterval=15 Windows_Jiaolong "cd C:\\temp; python c2_witness_probe.py C:\\temp\\sqjs_c4.dll --mask 0 --poll-s 20 --settle-s 2 --out C:\\temp\\c4_witness_freq.tsv"
# 正式窗（120 s）
ssh -o ServerAliveInterval=15 Windows_Jiaolong "cd C:\\temp; python c2_witness_probe.py C:\\temp\\sqjs_c4.dll --mask 0 --poll-s 120 --settle-s 2 --out C:/temp/c4_witness_probe.tsv"
scripts/scratch/2026-10_scope_shot/pull_slice.sh c4_witness_probe.tsv evidence/logs/witness_probe_4_4_4.tsv
scripts/scratch/2026-10_scope_shot/pull_slice.sh c4_witness_freq.tsv evidence/logs/witness_freq_4_4_4.tsv
```

产物：`evidence/logs/witness_probe_4_4_4.tsv`（正式窗，665 B）、`evidence/logs/witness_freq_4_4_4.tsv`
（频率窗，664 B）。频率窗那份不在本计划 Task 7 的 Files 清单里，是本窗口自己加的 —— 它的 `#meta` 是
「不是恒计」这条决策的唯一凭据，留在主机 `C:\temp` 会被下一次上线覆盖（§67 坑 ①、Task 6 finding 同一族）。

## §70 donor 重打：§67 那条前置补齐之后仍然静默 —— 落 spec §4 判决表第 4 行「本仪器无第三档资格」(2026-10-27,点名)

**授权级别**：本窗口第三次点名，问题里写的是「donor 正式窗（Task 8 Step 2，本窗口唯一剩下的一发
shot）授权吗」，选项原文「**授权，同进程一发（120 s）**」。§69 那两发证人 shot 是前一次问答给的，
不含这一发。

### §70.1 进程出处：为什么合法地沿用 §69 那个进程

沿用 **pid=15500 / hwnd=133164**，没走 spec §3 的换进程 fallback。判据逐条：

- 证人两窗的清理段都是 `C4WitnessProbeUninstall rc=0` → `verify=0` → `host alive`（§69.3/§69.4 原文）。
  Task 8 Step 1 的同进程门要的就是这两个 0；任一非 0 或 `-7` 才 fallback。
- 两把 guard 是**各自私有的变量**，`-2`（已装）这条成因对本进程不成立 —— 证人已拆，donor 从未在本进程
  装过；`predicate armed` 那条也不成立（本窗口没人碰 `0x1D08520` 的哨兵）。所以 donor 装进这个进程
  不需要新进程，省一次 launch（这是 Task 2 就把 guard 变量分开的直接收益）。
- 前置读数（§59.1，紧邻本发之前）：`STATUS=playing note=ok pid=15500 hwnd=133164 age=1.7s want=playing
  policy=first handled=5 cmd=click 1045 885 speed=None`。发完同态（`age=1.8s`、`handled` 未涨）。
- 「存档真在跑」这条 §67 前置是怎么来的：本进程由 launcher `--continuelastsave` 自动续档进战役（§69.1），
  画面日期在武装段那段 playing 期间从 **2273.01.01 走到 2282.06.26**（两张截图对读：`load_step1.png`
  与 `load_step6_small.jpg`，都是主机原帧 `ns_game_shot.png` 的判读副本）。**donor 这一发的 120 s 内部
  没有再取帧**（一次全帧拉回 ≈23 min，代价与这条读数的边际价值不成比），所以本段能说的是「窗口前后
  `STATUS=playing`，且同一进程此前确实在推进日期」，不是「这 120 s 里日期又走了多少」。

### §70.2 读数（donor `#meta` 逐字，665 B）

argv 逐字取自 `scripts/scratch/2026-10_c4_sentinel_window/donor_shot.cmd`，即 §67 :6216 那条复现行：

```
#meta exe_base=0x7ff7a6030000 image_size=0x3927000 image_end=0x7ff7a9957000 dll=sqjs_c4.dll dll_sha256=6613e3240fdad4ea594aedd0eae4673ab7eec818100fb035f35ed1ad937eafd9 target_rva=0x3afd30 mask=0x0 poll_s=120.0 layout=entry=48 stats=56 ring=256 mask=0 version=1 calls=0 samples=0 entries=0 tiers=h0=0/h1=0/h2=0/h3=0/h4=0/unmatched=0/invalid_self=0 verdict=no_calls_inconclusive named_table=- install_rc=0 stats=calls=0 samples=0 invalid_self=0 unmatched=0 h0=0 h1=0 h2=0 h3=0 h4=0 patch_size=15 installed=1 mask=0 unmatched_rows=0 rva_zero=0 in_image=0 at_or_above_image=0
```

`LAYOUT entry=48 stats=56 ring=256 mask=0 version=1` 与 §67 逐字相同（无 `LAYOUT_DRIFT`）；
`target_rva=0x3afd30` = donor slot[1] Execute 覆写。频率：`calls/poll_s = 0/120.0 s = 0.0 calls/s`。
**清理段（逐字）**：`C4DonorProbeUninstall rc=0` → `verify=0` → settle 2 s → `host alive`；不 `FreeLibrary`。

artifact 落法：本发追加进 `evidence/logs/donor_probe_4_4_4.tsv` 作**第 3–4 行**，§67 第一次读数留在
第 1–2 行原样未动（`evidence/` 按 basename 追加不改写）。两段的 `exe_base` 不同（`0x7ff69e4e0000` vs
`0x7ff7a6030000`）正是两个进程、ASLR 各掷一次的样子。

### §70.3 spec §4 判决表的落点：第 4 行

| 本窗口拿到的 | 值 |
|---|---|
| witness（§69.4，`0x3B01A0`） | `calls==0`，`named_table=-`，`tiers` 五档计数全 0 |
| donor（本节，`0x3AFD30`） | `calls==0`，`named_table=-`，`tiers` 五档计数全 0 |

⇒ 落 **spec §4 第 4 行**：`witness calls==0 / donor 任意` ⇒ **本仪器无第三档资格**，donor 读数按 §67
同款有界措辞 —— 「没观测到」≠「没有」。第 1–3 行的前半句全是 `witness calls>0`，本窗口一次都没满足过，
所以 (c) 成立、前两档命中、弱第三档三种落点**都没有被判决**：既不是成立，也不是不成立，是这一档资格
从未出现。

**两条 `named_table`/`tiers` 各归各表，不互引**：证人的 `[self+0]` 读的是它命中对象自己的 vptr，donor 的
读的是另一处（§57.4 那段「不同源」对 donor/scope 成立，对 donor/证人同样成立）。本窗口两者都是 `-` 与
全 0，所以没有任何跨仪器的等式可以写；把「两个都 0」读成「同一个对象两次都没被调用」会超出读数。

### §70.4 频率结论（回填 §67「下一次带不带 mask」）

§67 结尾说「这一发缺的不是 mask，是这一族真的在执行」，并把下一次点名的前置写成「载入进行中的存档、
确认 per-system 执行在发生」。本窗口把那条前置走完并且**换了条件重打同一形状**：战役在跑、`playing`、
日期确实推进过，donor 仍 `0.0 calls/s`，证人两窗也 `0.0 calls/s`。

⇒ 回填口径：`--mask 0` 继续带，而且现在有了第二条理由 —— 不只是「计数没起来所以不能谈采样分母」，
而是**在一份真在推进的存档里两把仪器的 `calls` 都不涨**，恒计与非恒计这个问题在这两个靶上都不出现。
「重打同一形状」到此为止：§67 + §70 两次 donor、§69 两次证人，四种时间窗（主菜单 120 s、战役 20 s、
战役 120 s、战役 donor 120 s）都是同一个答案，再打第五发同一形状不改变落点。

**这把仪器问不出来的东西（§57.5 式未排除项，本窗口新增两条）**：
1. 「族在执行但不走 slot[2] instantiate helper」与「族不在执行」—— §69.5 第 2 行，本仪器分不开。
2. 「族在执行但不经 slot[1] 这个 Execute 覆写」—— donor 侧的对称读法，同样分不开：`0x3AFD30` 只是 donor
   那一族对象的 slot[1] 覆写地址，per-system 执行若走别的类自己的槽，这把仪器看不见。
3. 运行时堆上生成/复制的表（§57.5 第 1 条）—— **仍未排除，这两发同样没碰它**；`calls=0` 对它有零信息。

### §70.5 §68.8 移交表改判（本窗口收口）

| # | 原判 | 本窗口之后的状态 |
|---|---|---|
| ① | §57.4 第三档，要一个不带 predicate 的证人 | **问完这一轮，未触发**。证人已建成、装过、在运行中的存档上扫过 20 s + 120 s（§69），donor 同进程重打 120 s（§70），落 spec §4 第 4 行 = 无资格。①的前置从「缺一把证人」变成「缺一次真的经过这两个靶之一的执行」—— 这是**换靶/换形状**的问题，不是再点名一次同一形状的问题。 |
| ② | scope 载体：条件式移交，未触发 | **未被本窗口触及**，原样保留（§68.8 那句「要新形状，不要重打同一形状」同样适用于本表 ①）。 |
| ③ | C5 试点二等 5 项裁定 | **未被本窗口触及**，原样保留（归人）。 |

**复现命令行**：

```bash
ssh -o ServerAliveInterval=15 Windows_Jiaolong "cd C:\\temp; python c2_donor_probe.py C:\\temp\\sqjs_c4.dll --mask 0 --poll-s 120 --settle-s 2 --out C:/temp/c4_donor_probe.tsv"
scripts/scratch/2026-10_scope_shot/pull_slice.sh c4_donor_probe.tsv /tmp/donor_run2.tsv   # 再追加进 evidence/logs/donor_probe_4_4_4.tsv 第 3–4 行
```

### §70.6 donor 驱动出处：为什么本发能与 §67 并排读，而 §67/§68 那两发不能与更早的读数并排

本节把 §67 与 §70 两发 donor 读数放在同一张判决表里读，这个动作的合法性取决于**驱动字节**，不只取决于
argv。出处逐字：

- 本窗口上线**前**核对：主机 `C:\temp\c2_donor_probe.py` = `0a529c537c87ba9044a7263e7b017e6b9cf1af0d865856af8ad458c3e09c0034`，
  与 git HEAD 那一份逐字节相等（§69 那段同时钉了 witness 驱动 `9254c512…` = HEAD）。⇒ §70 这发的判读纯函数
  （`decode_stats` / `verdict_for` / 写序）就是仓库里被 14 条围栏钉住的那一份。
- **§67 与 §68 那两发不是**：2026-10-27 备枪舱上线前实测，主机当时那份 donor 驱动 sha256 =
  `d48378d711f6c3ae0abcec730825018cc85e45be8a717584c92c2133b1ae58f3`，git 里 donor 驱动的四个历史版本
  （`0a529c53` / `ea2a555d` / `27bf9dba` / `756edba9`）**没有一个对得上** —— 那是一份从没回写进 git 的现场改动，
  被本次上传覆盖，覆盖前未留副本，字节已不可取回。
- 影响的口径要写准：`d48378d7` 与 HEAD 的差异**内容未知**，所以既不能说 §67/§68 的读数错了，也不能说它与本发
  逐位可比。能说的是：§67 那句 `calls=0` / `no_calls_inconclusive` 是在「判读纯函数版本未经证明」的前提下取到的，
  而 §70 是在「= HEAD」的前提下取到的 ⇒ 两发**在 verdict 语义上可比**（五档判词的语义由围栏文档与 §57.4 共同固定，
  不靠哈希），**在字节层面不可比**。本节把第 4 行落成「资格从未出现」而不是「§67 被复核并确认」，就是这个差别。
- 立下的规矩（本窗口起生效，已在备枪舱流程里执行）：**任何上线前先对主机侧 `.py` 与 git 的 sha256；不一致就先
  把主机那份拉回留副本，再覆盖。** 违反的代价已经付过一次了（上面第二条）。

## §71 零 shot:族外靶离线定形 —— §13 那七把各 2,090 次的 shim 全在家族五张 vtable 之外,主靶 `0xCC4220` 的指纹与派发位钉死(2026-10-27,离线)

**授权级别**：离线。零 shot、无实机动作、无注入;本节只读 exe 拷贝(`NS_STELLARIS_EXE` → `/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe`,
sha256 `9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56`)与三份既有 artifact。
本节是窗口计划 `2026-10-27-live-window-out-of-family-witness.md` 的 Task 1,产物是 Task 2/4 的常量来源。

### §71.1 定形出来的四个值

| 项 | 值 | 来源 |
|---|---|---|
| 主靶 RVA | `0xCC4220` | structures §13 :412(七把 2,090 里表序第一把) |
| 主靶绑的 vtable | `0x25460F0` | §13 同表;map 行 `vtable 0x025460f0  slot0 0x0015ccc0  ExecuteActual(slot2) 0x00cc4220` |
| 24 B 前序 | `48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 48 83 ec 20 0f b6 79 08` | §71.5(命令与逐指令边界) |
| 族外七张 vtable | `0x25460F0 / 0x250E188 / 0x254FA18 / 0x25531E8 / 0x2551620 / 0x2553178 / 0x2553140` | §71.3 |
| 兜底靶 | `0x6BE150`(`.pdata` 函数 `0x6be150..0x6be23c`) | §71.4,启用条件见 §71.6 |

**§13 那张表在这份 exe 拷贝上逐字复核过**(九行同计数段),不只是转述:

```
  shim   0xe99c10  vtable  0x254a190  x2165      ← 2,165
  shim   0xe586d0  vtable  0x24c52b0  x2096      ← 2,096
  shim   0xcc4220  vtable  0x25460f0  x2090   ┐
  shim   0x974840  vtable  0x250e188  x2090   │
  shim   0xde40c0  vtable  0x254fa18  x2090   ├ 七把 plateau
  shim   0xe98720  vtable  0x25531e8  x2090   │
  shim   0xe58d80  vtable  0x2551620  x2090   │
  shim   0xe9b580  vtable  0x2553178  x2090   │
  shim   0xe96e90  vtable  0x2553140  x2090   ┘
```

2,090 是 2026-09-29 那份读数的**静态对应物**。本窗口之前**不假定**它在 4.4.4 当前场景、当前存档上仍然成立 ——
§13 自己的原话就是 `Next capture should correlate this number against the live system count … before claiming it`
(structures :425)。§74(Task 10)才是那次复采。

### §71.2 段①:普查表 28 个 `func_start` × map 的 `ExecuteActual(slot2)` 列

脚本:`scripts/scratch/2026-10_live_window_shim_witness/join_family_boundary.py`(本窗口新写,一次性探针,保留原 basename)。
原始输出逐字:

```
# map_vtables=1805 map_distinct_slot2=543 census_shim_rows=25
# callers_tsv_rows=62 distinct_func_start=28
## ① 普查表 func_start 与 map 的 ExecuteActual(slot2) 列
of 28 distinct func_start, 27 appear as some vtable's slot2; 1 do not —— 缺席 = 不在**这份静态集合**里,不是「族外」的证明
present=27 absent=1
  absent 0x6be150
```

判读:28 个里有 27 个就在 floor map 的 543 个 `slot2` 值里 —— 与 §62.2 的口径 1(裸扫 `.rdata` 命中数逐函数 1–365)
同一批函数自证。唯一缺席的是 `0x6BE150`(§66 那条 `origin=not_examined` 的候选,`token_id_use_sites_4_4_4.tsv:94000`
给它挂的静态名字是 `animation`)。

**边界**:map 是**下限**(只收 slot[1] 仍是 base Execute 的那批,AGENTS 段3 第 3 行)。所以「缺席」只等于
「不在这份静态集合里」,不等于「不参与 vtable 派发」,更不等于「族外」。§71.4 用三口径把它问到底。

### §71.3 段②:七把 shim 的 vtable × 家族五张 = 空集(这条是「族外」的直接读数)

家族五张 = `0x24B1D98 / 0x24EAAC0 / 0x25F4440 / 0x2606F00 / 0x2606FE0`(§57.2 观测 4 / §60.6)。
原始输出逐字:

```
## ② §13 七把 shim 的 vtable × 家族五张
family_five=0x24b1d98 0x24eaac0 0x25f4440 0x2606f00 0x2606fe0
census_rows_with_count_2090=7 (其余 18 行计数不同,单列)
  shim 0xcc4220 vtable 0x25460f0 x2090 family=no
  shim 0x974840 vtable 0x250e188 x2090 family=no
  shim 0xde40c0 vtable 0x254fa18 x2090 family=no
  shim 0xe98720 vtable 0x25531e8 x2090 family=no
  shim 0xe58d80 vtable 0x2551620 x2090 family=no
  shim 0xe9b580 vtable 0x2553178 x2090 family=no
  shim 0xe96e90 vtable 0x2553140 x2090 family=no
intersection={} EXPECT_EMPTY=True
```

（七行 = census 里计数恰为 2,090 的那批;同一文件另有 18 行计数不同 —— 2,096 / 2,165 / 2,442 … 54,003 ——
本脚本把它们单列、不并进七把。这条口径防的是「把完全不同的执行体凑成七张表」。)

**补一条同源读数(不在计划文本里,定靶需要它)**:把这七把 shim **自己**当对象再过一遍 §62.2 三口径,七把**全部**是
「命中 1 处 / 命中前一槽 = `0x1d08520` / 命中 −0x10 落进 map 基址」= 3/3:

```
target 0xcc4220 hits=1 prev_is_base_execute=1/1 hit_minus_0x10_in_map=1/1
  hit@rdata+0x1b4100 prev=0x1d08520
target 0x974840 hits=1 prev_is_base_execute=1/1 hit_minus_0x10_in_map=1/1
target 0xde40c0 hits=1 prev_is_base_execute=1/1 hit_minus_0x10_in_map=1/1
target 0xe98720 hits=1 prev_is_base_execute=1/1 hit_minus_0x10_in_map=1/1
target 0xe58d80 hits=1 prev_is_base_execute=1/1 hit_minus_0x10_in_map=1/1
target 0xe9b580 hits=1 prev_is_base_execute=1/1 hit_minus_0x10_in_map=1/1
target 0xe96e90 hits=1 prev_is_base_execute=1/1 hit_minus_0x10_in_map=1/1
```

⇒ 「族外」的**准确含义**是:「**派发位与证人相同,表不同**」—— 每把 shim 都是自己那张 vtable 的 **slot[2]**
(`ExecuteActual`,`[vptr+0x10]`),而 slot[1] 就是 base Execute `0x1D08520`。
**槽位要分开写**(2026-10-27 终审更正,本节读数未受影响):证人靶 `0x3B01A0` 也在 slot[2],与这七把 shim
是**同一个派发位**;而 donor 靶 `0x3AFD30` 在 **slot[1]**(`[vptr+0x08]`,Execute 的覆写,donor_exec_probe.zig
头注释自述)—— 它比 shim 早一槽,**不是**同一个派发位。所以「族外」差的不是派发位而是**表**:七张 vtable
既不在家族五张里,也不是 base Execute 的 slot[2]。

**这一条同时给出两个方向的界**:
- 正面:`calls>0` 能证明「一个 vtable 派发的 `ExecuteActual` 真的执行了」,形状与家族内证人**可比** —— 这正是 §57.4
  第三档缺的那类「执行确实发生」的独立证据形态。
- 反面:「不在家族五张」**只等于**「不在这五张里」。家族五张是 §57.2 那张**有界集合**,不是 CEffect 全体
  (1,805 是下限,AGENTS 段3 第 3 行)。所以任何写法都不能升格成「它不是 CEffect」或「族外没有另一份表」
  (Review Focus 3)。

### §71.4 段③:缺席候选 `0x6BE150` 的三口径 = 三零,以及它作为兜底靶的性质

```
target 0x6be150 hits=0 prev_is_base_execute=0/0 hit_minus_0x10_in_map=0/0
```

三口径**全 0**:`.rdata` 里没有任何 8 对齐 qword 指向它 ⇒ 它既不是 floor map 里任何一张 vtable 的槽,也没有别的
vtable 引它 ⇒ **它不是 vtable 派发的执行体**,是被直接 `call` 进去的普通函数(`.pdata` 给它的边界是
`0x6be150..0x6be23c`,0xec 字节;猜它是 `animation` 的那条名字来自 `token_id_use_sites` 的静态挂靠,不是本节读数)。

这也决定了它的**用途边界**:它**不能**当「同形证人」(它不经过 `[vptr+0x10]`),只能当主靶装不上时的**备用活体**,
而且它的 `calls>0` 连「一个 `ExecuteActual` 跑了」都证不出来。

### §71.5 24 B 前序:命令、逐指令边界、以及 36 vs 24 的取舍

```
$ python3 scripts/scratch/2026-10_c4_sentinel_window/pin_prologue.py cc4220 24
# exe=/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe
# rva=0xcc4220 bytes=36/36 section=.text
48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 48 83 ec 20 0f b6 79 08 48 8b da 48 8b f1 40 80 e7 01 74 26
```

`pin_prologue.py` 的第二个参数按**十六进制**解析,所以 `24` = 36 字节(退出码 0、落在 `.text`)。36 B 里
**前 24 字节恰好是 6 条完整指令**(指纹长度就取这 24;理由同 donor/证人:指纹要吃满的必须是定长指令序列,
而不是某条指令的中间):

| 字节 | 指令 |
|---|---|
| `48 89 5c 24 08` | `mov [rsp+8], rbx` |
| `48 89 6c 24 10` | `mov [rsp+0x10], rbp` |
| `48 89 74 24 18` | `mov [rsp+0x18], rsi` |
| `57` | `push rdi` |
| `48 83 ec 20` | `sub rsp, 0x20` |
| `0f b6 79 08` | `movzx edi, byte [rcx+8]` |

后 12 B(`48 8b da` `mov rbx,rdx` / `48 8b f1` `mov rsi,rcx` / `40 80 e7 01` `and dil,1` / `74 26` `je +0x26`)
属于同一个函数头、不在指纹里;`install()` 的指纹门只比对**前 24**。

**函数头确认**:`scripts/disrva.py 0xcc4220 --len=40` 从 `0xcc4220` 起就是这 6 条,无前导;
`scripts/pdata.py 0xcc4220` 给出 `func 0xcc4220..0xcc48ab (0x68b bytes) unwind 0x271f460`
⇒ `0xCC4220` 是**函数起点**,不是中段。函数体第一件事是把 `rcx` 当对象读 `[rcx+8]` 的一个 bool
(`movzx edi, byte [rcx+8]` → `and dil,1`)再 `je` 分两路 —— 与「`+8` 是 `CEffect` 家族的启用位」这一读法同形,
但本节只用它做指纹,不做类归属推断。

### §71.6 靶的取舍与有界含义(落进 Task 2/4 的三行诚实条款)

- **主靶 = `0xCC4220`**;`-5 UnexpectedPrologue` ⇒ **停手留证,不换靶硬绕**(Global Constraints);兜底靶 `0x6BE150`
  只在主靶装不上、且人明确点了名的那一窗口里启用 —— 它是「备用活体」,不是同形证人(§71.4)。
- `calls == 0` **不是** §57.4 第三档的正面证据,只是「本窗口没观测到」。
- `calls > 0` 只证明**这个执行体在跑**,**不**证明它按 system 走(§13 :425 的 `correlate before claiming it` 未做)。
- 七张表的命中是**形状**判据不是身份判据(§57.5 第 2 条);「不在七张里」≠「族外没有另一份表」。

### §71.7 移交

Task 2 抄 §71.1 的 24 B 串 + 七张 vtable,Task 4 抄同一串做围栏常量(不运行时读盘)。Task 8 的两发实机窗是本节
唯一的实机后续;若 `verdict` 落非证据档,分档措辞归 §72,本节不改写。

## §72 族外证人第一次正读:`0xCC4220` 120 s 内 `calls=2016`、`h0=2016`(表首 `0x25460F0`)、`unmatched=0` ⇒ `shim_hit_named` —— 一个**族外派发位**的执行体确实在跑(2026-10-27,点名 ×2)

**授权级别**：同一窗口两段点名。第一段「**开始吧**」= 起进程 + 载入;第二段「**继续正式窗,接受『引擎在跑』由
supervisor 读数作证**」= 频率窗 + 正式窗两发。本段含这两发 `0xCC4220` 只读 shot,**不含**族内重打、scope、census。

### §72.1 进程、字节与上线门

- pid **30260**,hwnd 461052,`exe_base=0x7ff7a6030000`、`image_size=0x3927000`(与 §70 同一份 exe)。
- 上线字节 `C:\temp\sqjs_c4.dll`,sha256 `17c2b8251d7e7faeec92481d27d963b7f73ed5cde51203426279c720aff1e840`
  (= 本场 `zig-out/bin/stellaris_quickjs.dll`;81 个导出,`C4ShimProbe*` 八名齐)。**整文件 sha 只当出处。**
- 主机侧驱动对账(§70.6 的规矩,覆盖前做):`c2_witness_probe.py` = `9254c512…` = git HEAD;
  `c2_scope_probe.py` = `9cca999f…` = `fcadef2`(§68 那一窗);`execspy.js` = `7f1a9405…` = `b47da01^` ——
  **三份都对得上已记录的 git 版本**,不是未记录的现场改动 ⇒ 覆盖不丢东西,无需先拉回副本。本窗口新上传
  `c2_shim_probe.py` = `791f3a8e…`、`execspy.py` = `1b535ad5…`;四份文件的 `Get-FileHash` 与本地逐字相同。
- 覆盖前的旧 DLL 是 `6613e324…`(§69/§70 那两发的字节)。**两份字节的读数不可逐位比对**,只能并排讨论。

### §72.2 环境读数、launcher 样本,以及一条仪器缺陷(控制台吃键)

- `just awake check` → `STATE=serving DESKTOP=unlocked detail=Default age=2.5s pid=5624 session=1/1`。
- `just game status` → `STATUS=no_game`(无遗留进程)。
- **计划 Task 7 Step 5 的 `just launch --continuelastsave` 是笔误**:`launch_stellaris.py` 没有这个旗标(它走
  `steam://rungameid/281990`),会直接 `unrecognized arguments`。改发裸 `just launch`,而**游戏自己的命令行**确实带
  `--continuelastsave`(由 Paradox launcher 加),所以 §69.1 的机制复现:一次就落在战役内(日期 2300.07.25)。
- launcher 三档样本(§92 那条线用):`inner_exit code=0` ⇒ **本轮无 23 样本**;但点击轨迹值得记 —— attempt 1/2 用的是
  `rect=(-32000,-32000,-31763,-31961)` 的**屏外矩形**(`owns_foreground=None` 然后 `False`),attempt 3 才拿到
  `rect=(-11,0,2153,1020)`、`owns_foreground=True` 并 handoff 成功。即「窗口矩形还没准备好就去点」是本轮的真实形态。
- **新缺陷(判读陷阱 9 的补充)**:任何 UI 交互(`just game shot`、点击)都会因失焦让 Stellaris **自己暂停**;而
  **游戏内控制台开着会吃掉空格键** —— `ns_game_log.jsonl` 17:04:14 有 `console_observed open=true px=1300`,那段时间
  `just game unpause` 静默无效、`status` 一直读 `paused note=paused_no_window`。可用的纪律:
  **`just game console_close`(或先查控制台)→ `status` 读到 `playing` → 立刻装,中间不碰 UI**。本节两发的入场
  读数就是这样拿到的(见下),不是「pause 了却以为在跑」。这不推翻 §59.1 证伪的「控制台 ⇒ 暂停」,那是**另一条**
  因果句。

### §72.3 频率窗(`--poll-s 20`)

```
[shim] LAYOUT entry=48 stats=64 ring=256 mask=0 version=1
[shim] C4ShimProbeInstall rc=0
STATS: calls=0 samples=0 invalid_self=0 unmatched=0 h0=0 h1=0 h2=0 h3=0 h4=0 h5=0 h6=0 patch_size=15 installed=1 mask=0
VERDICT: no_calls_inconclusive
[shim] C4ShimProbeUninstall rc=0 / verify=0 / host alive
```

20 s 静默。**这一发不是判据**,它的用途是「这靶子在当前场景到底跑不跑」——同一进程里紧接着的正式窗给出了相反的
读数(§72.4),所以两发并排读才是本窗口最有信息量的一对:**靶子不是死的,静默是窗口内的分布问题**。

### §72.4 正式窗(120 s,本段判决来源)—— 原始读数

```
STATS: calls=2016 samples=2016 invalid_self=0 unmatched=0 h0=2016 h1=0 h2=0 h3=0 h4=0 h5=0 h6=0 patch_size=15 installed=1 mask=0
VERDICT: shim_hit_named 表首=0x25460f0
[shim] unmatched 分区(证人侧,计数侧不可分):unmatched_rows=0 rva_zero=0 in_image=0 at_or_above_image=0
[shim] the ring wrapped at 256 records: …
[shim] C4ShimProbeUninstall rc=0
[shim] verify=0
[shim] host alive
```

`#meta` 首行逐字(产物 = `evidence/logs/shim_probe_4_4_4.tsv`):

```
#meta exe_base=0x7ff7a6030000 image_size=0x3927000 image_end=0x7ff7a9957000 dll=sqjs_c4.dll dll_sha256=17c2b8251d7e7faeec92481d27d963b7f73ed5cde51203426279c720aff1e840 target_rva=0xcc4220 mask=0x0 poll_s=120.0 layout=entry=48 stats=64 ring=256 mask=0 version=1 calls=2016 samples=2016 entries=256 tiers=h0=2016/h1=0/h2=0/h3=0/h4=0/h5=0/h6=0/unmatched=0/invalid_self=0 verdict=shim_hit_named named_table=0x25460f0 install_rc=0 stats=calls=2016 samples=2016 invalid_self=0 unmatched=0 h0=2016 h1=0 h2=0 h3=0 h4=0 h5=0 h6=0 patch_size=15 installed=1 mask=0 unmatched_rows=0 rva_zero=0 in_image=0 at_or_above_image=0
```

环里 256 条(全部 `matched=1`、`table_index=0`、`table_rva=0x25460f0`):

| 字段 | distinct | 读数 | 含义 |
|---|---|---|---|
| `self_vtable_rva` | **1** | `0x25460f0` | 七张表里只用了族外表序第一张,与 `h0=2016`/其余 `h*=0` 一致 |
| `caller_rva` | **1** | `0x1d0857a` | = **base Execute `0x1D08520` + 0x5A** ⇒ 调用点是 base Execute 体内那一发 `call [rax+0x10]`(§10 的口径),不是外来直调 |
| `self_ptr` | **256** | 256 个互不相同 | 抽样到的 256 条各是不同对象(环只有 256 槽,`2016` 次里这段被覆盖) |
| `ctx_ptr` | **1** | `0xee7fd00` | 全程一个 ctx |
| `a3` | **1** | `0x1` | 恒定 |
| `a4` | **1** | `0x7ff7a81b7bd4` | = `exe_base + 0x1817bd4`,模块内代码地址(与 §53.5 对证人靶 `arg4` 的读法同形) |

时间形状:进度行每 10 s 一条,**前 6 条全 0,第 7 条起 2016 并保持到窗末** ⇒ 一次突发落在窗口第 60–70 s 之间,
之后 50 s 平在 2016,没有第二次。

### §72.5 这份读数的有界含义(三条诚实条款,写死)

1. **它证到的是**:一个**族外 vtable**(`0x25460F0`)的 slot[2] `ExecuteActual` 在这 120 s 里**真的执行了 2,016 次**,
   派发点是 base Execute 体内 `+0x5A` 那一发。这是 §57.4 第三档一直缺的「**执行确实发生**」形态的**正面证人**,
   而且它的 `unmatched=0`/`invalid_self=0` 让「这条 trace 是我们自己的读数」这一层也站得住(不是 ring 空转)。
2. **它没说**:
   - **不是 per-system**:`2,016` 与 §13 那份 2026-09-29 的 `2,090` 数量级相近,但**场景不同**(那次是另一个存档/时段),
     相关性(`§13 :425` 的 `correlate … before claiming it`)是 §74 的事。本节不写「同一集合走了一遍」以外的任何循环语义。
   - **不是对家族的表态**:本节读的是 `0x25460F0`,与 `0x3AFD30`/`0x3B01A0` 那五张表无关;家族那边是否执行,本发**一个字都没说**。
   - **不是身份判据**:七张表命中 = 形状判据(§57.5 第 2 条);「命中表 0」不等于「这个类是 X」。
3. **新增未排除项**:一次突发 + 其余 110 s 静默这一形态,至少三种读法分不开 ——
   (a) 某个一次性遍历(载入后/事件结算)确实只走一遍;(b) 该遍历发生在别的 tick 节奏上、本窗只碰上一轮;
   (c) 该执行体只在特定状态下被走到,而本窗 100 s 的静止期里状态没到。本仪器不区分这三者。
   另:§72.3 的 20 s 静默与 §72.4 的突发**同进程**且相邻 40 s 内,说明「安静」在本靶上是**窗口内分布**的现象,
   不是存在性现象 —— 以后任何「本仪器安静」的说法都必须带上窗口长度与突发时刻。

### §72.6 复现命令行

```bash
# 前置:just game console_close → just game status 读到 STATUS=playing(中间不碰 UI)
ssh -o ServerAliveInterval=15 Windows_Jiaolong "python C:\\temp\\c2_shim_probe.py C:\\temp\\sqjs_c4.dll --mask 0 --poll-s 20  --settle-s 2 --out C:/temp/c4_shim_freq.tsv"    # 频率窗
ssh -o ServerAliveInterval=15 Windows_Jiaolong "python C:\\temp\\c2_shim_probe.py C:\\temp\\sqjs_c4.dll --mask 0 --poll-s 120 --settle-s 2 --out C:/temp/c4_shim_probe.tsv"  # 正式窗
scripts/scratch/2026-10_scope_shot/pull_slice.sh c4_shim_probe.tsv evidence/logs/shim_probe_4_4_4.tsv
```

### §72.7 移交

- 条件性第三发(同进程族内 slot[2] 重打,`witness_shot.cmd`)的**触发条件已经满足**(本发 `calls>0`),但它是新的一次
  install ⇒ 要另一次点名。它的价值是把「族外确实在跑」(本节)与「族内是否在跑」摆进同一个进程的两窗。
- **§74 的 B2 复采**(`census_run.cmd`,压最后)仍未打;本窗口的 `2016` 与它要复采的七把 shim 计数是两条不同的
  读数口径,不要混。
- scope(Task 9)未打;§68.8 表第 ② 行原样保留。

## §72.8 `h1..h6 = 0` 的口径:它由仪器结构决定,对另外六把 shim 零信息(2026-10-28,零 shot)

**授权级别**:零 shot。本节**不碰游戏、不注入、不装任何 detour**,只读 §71/§72 的既有读数与
`src/dll/c2/shim_witness_probe.zig` 的 install 语义;产物是一条给下一发实机窗口用的判读边界。

**要防的误读**:把 §72.4 那行 `h0=2016 h1=0 … h6=0` 读成「另外六把 shim 在那 120 s 里没跑」。
这个读法**错**,而且错在两头都误导人:①它不是观测事实,是**仪器口径的结构结果**;②即便它是真的,也
**回答不了**「另外六把跑没跑」这个问题 —— 那由 census 逐把计数回答(§74)。

### §72.8.1 五步论证

1. **本 guard 只 patch 一个函数。** `install()` 对 `moduleFunction(RVA_SHIM_WITNESS)`(= `0xCC4220`,
   `src/dll/shared/offsets.zig:241`)做 24 B 指纹门 + JMP patch(`src/dll/c2/shim_witness_probe.zig:323-350`;
   §72.4 的 `patch_size=15` 就是那 15 字节)。所以 `calls` = **`0xCC4220` 这个函数被调了多少次**,
   **不是** base Execute `0x1D08520` 的派发次数。
2. **计数是逐次的,不是采样后的。** `table_hits[idx]` 每次分类命中就原子自增
   (`shim_witness_probe.zig:184`),发生在采样门**之前**;采样门只决定哪些记录进那 256 槽的环
   (模块头注释:counters per-call、samples behind the gate、only the ring write passes the shouldSample gate)。
   ⇒ `hN` 是全量计数,环才是抽样。
3. **七张表里只有 `0x25460F0` 的 slot[2] 是 `0xCC4220`。** §71.1 把主靶钉成「该表的 slot[2]」;
   §71.3 段② 的表把七把 shim 与七张 vtable 一一配对,七把互不相同;那段里的「补一条同源读数」又给出
   七把各自 `hits=1 / prev_is_base_execute=1/1 / hit_minus_0x10_in_map=1/1` —— 即每把都是**自己那张表**的
   slot[2](slot[1] 仍是 base Execute)。⇒ 被采样对象的 vtable 只可能是 `0x25460F0` ⇒ `h1..h6 = 0` 是
   **结构必然**。
4. **前提,与它的闭合(两条分支分开写)。** ③ 的必然性有一个前提:「**没有第二张表也把 `0xCC4220`
   放在 slot[2]**」,它分两条:
   - **七张之内**:由 §71.3 的**逐把 hits=1** 闭合(每把 shim 的地址在 `.rdata` 里只出现一次 ⇒ 七把两两不同);
   - **七张之外**:`.rdata` 读不到运行时复制出来的表,这一支由 §72.4 的 **`unmatched=0`** 在**窗内**闭合
     (第二张表若在七张之外,它的对象必落 `unmatched`;而 `unmatched` 是**全量**计数,不是抽样)。
   `unmatched=0` 不是「佐证」,是**必要前提**:没有它,落在七张之外的调用既不进 `h0` 也不进 `h1..h6`。
   所以最强可写句是:
   **`h1..h6 = 0` 由仪器口径结构决定(前提如上,两条分支各由各自的事实闭合)、窗内被全量 `unmatched=0`
   闭合 ⇒ 对另外六把 shim 跑没跑零信息。**
5. **`unmatched=0` 的确切含义**:`unmatched` 是**逐次、采样门之前**的计数
   (`shim_witness_probe.zig:186`,门在 `:189`)⇒ 它覆盖**全部 2,016 次调用**,不只是环里那 256 条:
   每次调用的对象 vtable **全在七张之内** —— 不是「世界里只有这七张表」。同理 `h1..h6=0` 是**全量**事实,
   不是抽样事实。
6. **最强可写句(记账恒等式)。** 三个计数互斥且穷尽:`capture()` 先读 `[self+0]`,读不到 → `invalid_self`
   (`:177-179`);读到且落在七张之一 → 对应 `hN`(`:182-184`);读到但不在七张 → `unmatched`(`:186`);
   `calls` 由 detour 每次进入自增(`:313`)⇒ 恒有 **`calls = invalid_self + Σ(h0..h6) + unmatched`**。
   本窗 `2016 = 0 + 2016 + 0` ⇒ **每一次调用都落在 `0x25460F0` 那张表**。所以 `h1..h6=0` 是**推论**,
   不是一条独立观测 —— 写成「结构决定」必须同时带这条恒等式,否则下一发窗里会有人把它当成
   「另外六把没跑」的观测。

### §72.8.2 两条配套的限定

- **`calls=2016` 只对 `0x25460F0` 这一把有效**,不是族外执行总数(§72.5 第 2 条那半句「不是 per-system」
  的同源限定)。
- **`caller_rva = 0x1d0857a`**(§72.4)只证明**环里那 256 条**(= 2,016 次里的**最后** 256 次;环按
  `seq % 256` 覆盖,`shim_witness_probe.zig:47`、`:192`,§72.4「the ring wrapped at 256 records」)
  经 base Execute 体内那一发 `call [rax+0x10]` 进来 —— 那是**派发位**读数,不是**身份**读数;
  **前 1,760 次的 `caller_rva` 未被记录**,不能写成「这 2,016 次都从 base Execute 进来」。
  (取证卷 append-only:§72.5 第 1 条「派发点是 base Execute 体内 `+0x5A` 那一发」同样只对环里那 256 条
  成立,**以本条为准**。)

### §72.8.3 「另外六把跑没跑」归谁

§13 的「七把各 2,090」**本身就是逐把计数**;`docs/offline-tooling.md` 的 execspy 一节是 §13 census 的
复采通道 ⇒ **那正是 §74 的事**(复采口径单在该节)。guard 的 `h1..h6` 只回答**身份**问题:「本次**全部
2,016 次调用**的对象 vtable 是不是 `0x25460F0`」。两个口径的数**不可并排比、不可互相除**(那边已有同款
纪律:§72.7 第二条)。

### §72.8.4 移交

- `docs/offline-tooling.md` 的 `c2_shim_probe.py` 一节把这条写成**陷阱 4**;`AGENTS.md` 的 `0xCC4220`
  RVA 行带一句同款提示。
- 本节**不占 §73/§74 的号** —— 那两号留给 witness 计划 T9(scope 新形状)与 T10(B2 复采)。

## §72.9 零 shot:`0xCC4220` 的三条静态路线读数 —— 补 §72.8 第 4 步的「七张之内」那一支(2026-10-28,零 shot)

**授权级别**:零 shot。**不碰游戏、不注入、不装任何 detour**;只跑本仓库已有的离线脚本,读 exe 拷贝与
镜像。本节只做一件事:把 §72.8.1 第 4 步那条前提「**没有第二张表也把 `0xCC4220` 放在 slot[2]**」的
闭合证据从「§71.3 的 `.rdata` hits=1」再往前推一格,并把**没有闭合的那一格**写清楚。

### §72.9.1 三条命令与逐字输出

```bash
$ python3 scripts/join_family_boundary.py 0xcc4220
# exe=/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe
# base=0x140000000 base_execute=0x1d08520 (map 只收 slot[1] 仍是它的那批 = floor)
# map_vtables=1805 map_distinct_slot2=543 census_shim_rows=25
# mode=explicit_rvas 0xcc4220

## ③ §62.2 三口径(8 对齐 qword 命中 / 命中前一槽 == base Execute / 命中-0x10 落进 map)
target 0xcc4220 hits=1 prev_is_base_execute=1/1 hit_minus_0x10_in_map=1/1
  hit@rdata+0x1b4100 prev=0x1d08520

$ python3 scripts/fastcalls.py 0xcc4220
0 direct code sites to 0xcc4220 in .text
in 0 functions
wrote evidence/xrefs/callers_0xcc4220_buckets.tsv

$ python3 scripts/find_refs.py 0xcc4220
stellaris.exe  targets: 0xcc4220
scanning .text (0x2390800 bytes) ...
== 0xcc4220: 0 references ==
```

`evidence/xrefs/callers_0xcc4220_buckets.tsv` 是 `fastcalls.py` 的产物,**只有表头、零站点**
(与同目录其它 `callers_0x<rva>_buckets.tsv` 同一形状)。

### §72.9.2 三条各闭哪一格

1. **`hits=1` + `prev=0x1d08520`**:`0xCC4220` 在整个 `.rdata` 里只出现**一次**,而且那一处的前一槽就是
   base Execute ⇒ 它是**恰好一张** vtable 的 slot[2](`.rdata` 口径)。这闭的是 §72.8.1 第 4 步的
   **「七张之内」**那一支(七把两两不同 ⇒ `0xCC4220` 不在另外六把的表里)。
2. **`0 direct code sites`**:`.text` 里**没有**任何直接 `call` / `jmp` 指向 `0xCC4220` ⇒ 没有「绕过虚派发
   直接调它」的静态路线。
3. **`0 references`**:`.text` 里**没有**任何 rip 相对引用指向它 ⇒ 没有「拿它的地址当数据或立即数用」的
   静态路线。

⇒ 三条合起来:通往 `0xCC4220` 的**静态**路线只有那一张表的 slot[2](与 §72.8.1 第 1–3 步的读法一致:
它是 slot[2],派发位是 base Execute)。

### §72.9.3 没有闭合的那一格(不粉饰)

- 上面三条都是**静态**读数,它们**看不到运行时复制出来的 vtable**;那一格只能靠 §72.4 的
  **`unmatched=0`**(全量计数)在窗内闭合 —— 即 §72.8.1 第 4 步的**「七张之外」**那一支。
- 三个脚本都按**8 字节对齐**读指针 / 地址:一个把 `0xCC4220` 以 `imm32` 形式嵌在 `.text` 里的立即数,
  `fastcalls.py`(只找 call/jmp 目标)、`find_refs.py`(只找 rip 相对引用)与 `.rdata` 的 qword 扫描
  **三个都抓不到**。这一格**没有**被这三条命令闭合,也不假装闭合。

## §73 scope 新形状一发(预算 27):self 支 18/18 问完、`capped` 归零,`verdict_d2` 落 `no_depth2_lead` ⇒ §68.8 ② 的条件式移交**触发**(2026-10-28,点名 ×1)

**授权级别**:点名。人对这一窗的原话是「**实际操作吧,现在机器就在线**」;窗口内容在发前提里逐条列明为
「1 次 launch + 两发 install/uninstall(§73、§74)」,人回「**开跑**」。本节的这一发是两发里的第一发
(scope),census(§74)是第二发且压在其后。

**这一发问的是什么**:§59.9 前置 ①(连线前先按 `plausible_user_ptr` + 界内/界外分档)与前置 ②
(`self` 支预算抬高到 27)都已由计划 Task 5 做进驱动(`partition_cells` / `DEPTH2_PER_SOURCE = 27`,
DLL 侧一行未动);本发是**同形状之外的第一次**:深度与预算同时到位,而 DLL 字节是 §69/§70/§72
那一份。判据表照 §57.4/§68.8 原样,不在这里重述。

**环境与前置读数**:新进程 pid **3604**,hwnd 1116360。`just launch` 一次成功(`GAME_OBSERVE step=ok
alive_s=30`、`inner_exit code=0`),落地即战役内(launcher 自带
`--continuelastsave`,§69.1 的机制复现;本窗没有记存档名,这一格在 §74.4 里算账)。**紧邻执行 shot 的前置读数**:

```
STATUS=playing note=ok pid=3604 hwnd=1116360 age=0.1s want=playing policy=first handled=0 cmd=unpause
```

这一行不是 `just game status` 直接读到的 —— 见下面「仪器通道」,它是经 session 1 读出来的状态机读数
`STATE=IN_GAME_PAUSED_CLEAN … NEXT=unpause` 执行 `unpause` 之后的同一份监督器心跳。

**上线字节与对账**:`C:\temp\sqjs_c4.dll` sha256
`17c2b8251d7e7faeec92481d27d963b7f73ed5cde51203426279c720aff1e840`(= 本场 `zig-out/bin/stellaris_quickjs.dll`,
= §69/§70/§72 那一份字节;与 §68 的 `7d3e45c4…` **不同值**,所以本发与 §68 之间仪器换过,两发只能当
「同一台仪器族、不同字节」并排)。三份静态输入在主机上逐文件哈希对账一致:
`ceffect_vtable_map_4_4_4.txt` `3e21961a…`、`exec_frame_callers_4_4_4.tsv` `02b104c6…`、
`descriptor_oracle_4_4_4.tsv` `44b1768c…`。**驱动侧**`c2_scope_probe.py` 上传前=HEAD `31968f1f…`
(主机原有一份 `9cca999f…` = `fcadef2`,即 §68 那一发的记录版本,按 §70.6 先对账再覆盖)。

### §73.1 仪器通道:这一发第一次必须经 `session_bridge`

`c2_scope_probe.gate_module` 在 `inject_dll` **之前**调 `world_probe.gate_install('scope')`(spec §1:
证明不了前提就不许注入)。而 SSH 落在 **session 0**,`EnumWindows` 在那一层只看得到一个控制台窗口
(实测 `windows=1`),监督器与状态机在那里都只会读到 `NO_GAME` / `STATUS=stopped`。所以本发是从
`session_bridge.py`(schtasks `/run /I`)投进 **session 1** 跑的;直接 `ssh … python c2_scope_probe.py`
会在门口被拒(这是这条门第一次真的挡下东西,记录在此)。

同一晚在 bridge 上修了两处缺陷(都先看到红再补):

1. **读回路径缺 `mode`** —— `_open_file(OUT_PATH, encoding=...)` 少了 `"r"`,`TypeError` 在实机上炸在
   `print` 之前;总线上只有 shim 文本那条被围栏覆盖,读回半句没有。现在
   `scripts/windows/tests/test_session_bridge.py::test_run_interactive_reads_the_sentinel_back` 用
   RED→GREEN 钉住(4 passed → 7 passed)。
2. **默认超时 120 s 短于本发的 120 s 采样窗** —— 加了 `--timeout-s`,本发用 420 s;两个纯函数测试
   (`peel_timeout`)覆盖缺省与显式两条路。

### §73.2 depth-1 读数(与 §59.3 / §68.1 并排,不做增量断言)

| 键 | §59.3(depth-1) | §68.1(depth-1+2) | 本发(预算 27) |
|---|---|---|---|
| 字节 | `373ab26b…`(`sqjs_c4_scope_v2.dll`) | `7d3e45c4…` | `17c2b825…` |
| `calls` | 3061(≈25.5/s) | 1046773(≈8723/s) | **2970**(≈24.75/s) |
| `samples` | 5 | 2044 | **5** |
| `valid` / `lexer` | 5 / 0 | 256 / 0 | 5 / 0 |
| `followed_by_source` | self=4/helper=2/arg3=1/arg4=1 | self=8/helper=2/arg3=0/arg4=1 | self=5/helper=2/arg3=1/arg4=1 |
| `implausible_by_source` | arg3=2/arg4=0 | self=0/helper=0/**arg3=256**/arg4=255 | self=0/helper=0/**arg3=4**/arg4=0 |
| `capped_by_source` | 0 | self=245 | **self=0** |
| known / member / unknown / unreadable | 0/0/16/0 | 2/13/37/0 | **3**/2/20/0 |
| `verdict` | `no_scope_candidate` | `scope_candidate` | **`scope_candidate`** |
| `verdict_d2` | 该档当时不存在 | `lineage_edge_found` | **`no_depth2_lead`** |
| `shared_cells` | — | `n=2` | **`n=0`** |

本发的 calls/s 与 §59 几乎相同(24.75 vs 25.5),与 §68 差**两个数量级** —— §68 那个窗口是一扇事件窗在跑
(§68 首段:停在「克伯利安恒星国同盟的末日」上),不是一条基线。所以本发**只与 §59 同量级可比**;
`valid=5` 就是这一层的全部样本,判词的作用域是这 5 个样本,不是这条路径的全部行为。

`layout entry=120 stats=56 ring=256 mask=511 version=2`,采样率 1/512,`patch_size=16`、
`x_nonzero=5`、`C2Sanity == 42`、`C2ScopeProbeInstall rc=0`、`installed=1 verified=-1`(装着的窗口里
verify 报 -1 是期望值)。

### §73.3 `known=3`:三条 floor 命中指名到「根 + 偏移 + slot2」,其中一条的 slot2 是 `ret 0` 空桩

```
object root=0x7fe960    source=helper off=0x10 vptr_rva=0x24e9068 slot2_rva=0x396460
object root=0x2122c7a40 source=self   off=0x00 vptr_rva=0x24d02b0 slot2_rva=0x240640
object root=0x2122c7a40 source=self   off=0x38 vptr_rva=0x24ec880 slot2_rva=0x15db30
```

措辞门(照 §68.2 的口径):`known` 的定义是「某个根 + 偏移上的 qword 解引用一次后,其 vptr 落在
`ceffect_vtable_map_4_4_4.txt` 那 1,805 行 floor map 里」。所以这三行说的是**那三个槽里存着指向已知
CEffect 类对象的指针**,不是「找到了 `CEventScope`」。三条 RVA 与 §56.4/§68.2 那对
(`0x2545e40` / `0x254fa18`)**不同值** ⇒ 本发交出的是另外三行,既不是那两行的复现,也不是「新认出的类」
(known 的集合是 map,不是我的判断)。

第三条的 `slot2=0x15db30` 是 `ret 0` 空桩(`disrva.py 0x15db30 8`;§60.5 已把它记成承载函数 vtable
`0x26d4dd0` 的 `+0x08` 位)—— 换句话说那个类**有一个什么都不做的 `ExecuteActual`**。这是形状读数,
不是判据读数:它不许被读成「scope 找到了但是空的」,也不许读成「这一族不走 Execute」。

`member_vtable_hits=2`(`self@0x2122c7a40+0x30` → `member_slot2=0xe581e0`;`self@0x141deb020+0x00` →
`member_slot2=0x33d410`)按判读陷阱 7 **不进判词**:它说的是根自己的类(多继承副表),不是成员指向谁。

### §73.4 depth-2:两个有计划的源全部问完,`capped` 全 0

| 源 | `d2_planned` | `d2_followed` | `d2_capped` | 有候选的根 / 候选行 | 其余 |
|---|---|---|---|---|---|
| `self` | **18** | **18** | **0** | 10 根 / 47 行 | 2 根不可读(`0x4c4b40`、`0x7f0000000008`),6 根读了但 8 个 qword 里无一像指针 |
| `helper` | **5** | **5** | **0** | 3 根 / 8 行 | 2 根无候选 |
| `arg3` | 0 | 0 | 0 | — | §68.1 那一支的 256 条 implausible 在本发是 4 条,同样不产出 lead |
| `arg4` | 0 | 0 | 0 | — | 同上,0 条 |

`d2_implausible=12`(第三桶:从来不是 lead 的 cell,多为不可读;不读作「丢掉的标量」)、
`deduped self=0/helper=0`(stdout 逐源行,`#meta` 七个键不含它)、`shared_cells n=0`、
`verdict_d2 = no_depth2_lead`。

**「没有候选」与「预算截断」在这一发被分开了**:两类都写进上表,而 `capped` 这一键是 0 —— 18 个 lead
一个不剩地被 deref 过。这是本发与 §68.1(`self` 8 followed / **19 capped**)唯一的结构差别。

### §73.5 「§68 那 19 个问完了吗」—— 不能这么说,只能说本发的 lead 集问完了

§68.1 的 19 是**那一发样本**在每源预算 8 下没来得及 deref 的**余量**(8 followed + 19 capped + 5 deduped,
样本 2044)。本发**不是接着那 19 个地址往下问**:`plan_depth2` 每一发都从**本次** depth-1 候选重新规划,
并且把每一行自己的 root 排除(`already`),所以本发的 18 是**本发样本**的 lead 集,与 §68 那 19 个
不是同一个集合(样本 5 vs 2044,命中的根也不同)。

- 可以说:**本发这一支 `planned=18 / followed=18 / capped=0` ⇒ 本发的 lead 集问完了**。
- 不可以说:**「§68 那 19 个问完了」**。要给那 19 个地址一个身份,得把它们点名留给下一次同进程读数
  (或按 §73.6 判的新路线去问),本发读数里没有这一格。
- 也不可以说:本发「比 §68 问得更深」。两发的样本集不同,深度键只在本发内部闭合。

### §73.6 region 仪器:34 个查询,两条值得记

`regions_queried=34`,判决分布:

```
self/private_committed=5      helper/private_committed=2   arg3/image=1   arg4/image=1
ctx/private_committed=2       self.d2/private_committed=11 self.d2/image=4
self.d2/mapped_view=1         self.d2/reserved=1           self.d2/free=1
```

- `self.d2 0x7f0000000008` 落 **`free`** —— 与它同根那条 `root_unreadable` 是同一件事的两种写法
  (读一个不属于任何提交页的地址,读回失败不是「读到了 0」)。
- `0x100000000` 落 **`private_committed`**(`base=0x100000000 size=0xff0000 protect=0x404`)。
  §68.3 把它记成「一条标量边」,本发在区域层补一句:它是内存里一个**已提交的 16 MB 私有区**的基址。
  本发它**只在一个根下出现**,`shared_cells n=0` ⇒ 不构成边;`§68.3` 那条「标量」判定不被本发推翻,
  但「它不像指针」这个读法在本发站不住(它过了 `plausible_user_ptr`,并且有区域)。

### §73.7 判决与移交:§68.8 ② 的条件式移交**触发**

`verdict_d2 = no_depth2_lead` ∈ 非证据档(`EVIDENCE_D2_VERDICTS` 只有
`depth2_known_vtable_hit` / `lineage_edge_found` 两档)。按 §68.8 ② 的触发条件:

- **本仪器这一层问完了**:四根各自问过(depth-1 9 个根 / depth-2 两个有计划的源 capped 全 0)、
  `shared_cells=0`、`d2_implausible` 与「无候选」分开记账、`arg3`/`arg4` 两个源结构性地不产出 lead。
- **只剩一条新路线**:往上定帧构造点(§61–§63 已判完,`dispatchers_partial`)与两段形态派发方
  (§66 已判完,`two_stage_dispatchers_partial`)两条零 shot 路线都判完了,且判决词不同义、不合并;
  要再往前走,得是**新形状**(不是同一形状的第五发)。
- 不许写的两句:`scope 是这里的 X`(本发只是三条 floor 命中);`这一族不走 Execute`(静默与计数都不在
  本节的判据里 —— 那是 §57.4 第三档的口径,归 §72/§74)。

### §73.8 复现命令行与清理复核

```bash
# 前置读数(经 session 1 的状态机;SSH 在 session 0 看不到窗口)
just win "python C:/temp/session_bridge.py C:/temp/ns_world.py status"      # -> IN_GAME_PAUSED_CLEAN
just game console_close && just game unpause                               # -> STATUS=playing
# 执行 shot(必须经 bridge,否则 gate_install 在 session 0 拒装)
just win "python C:/temp/session_bridge.py --timeout-s 420 C:/temp/c2_scope_probe.py C:/temp/sqjs_c4.dll \
  --poll-s 120 --settle-s 2 --out C:/temp/c4_scope_d2_27.tsv \
  --vtables C:/temp/ceffect_vtable_map_4_4_4.txt --census C:/temp/exec_frame_callers_4_4_4.tsv \
  --id-names C:/temp/descriptor_oracle_4_4_4.tsv"
# 拉回
scp Windows_Jiaolong:C:/temp/c4_scope_d2_27.tsv evidence/logs/c4_scope_d2_27_2026_10_28.tsv
```

产物:`evidence/logs/c4_scope_d2_27_2026_10_28.tsv`(150 行,31 条 `#meta`,含 depth-2 七个键)、
`evidence/logs/c4_scope_live_2026_10_28.log`(158 行,含 `CALLERS` / `CHAIN` / 逐源 stdout)。
清理:`C2ScopeProbeUninstall rc=0`、`C2ScopeProbeVerify rc=0`(engine bytes intact)、`host alive`。
**一进程一次 install 额度已用尽** —— pid 3604 之后不许再装 scope probe,重打要新进程(点名)。

## §74 B2 复采:七把 shim 从 **2,090** 变 **2,494**,七把之间仍严格相等 —— 「仍是 2,090」这条判据按原文不成立,而「一个彼此相等、却随窗口变的量」比常数更有信息(2026-10-28,点名 ×1)

**授权级别**:点名。同一句「**开跑**」覆盖本窗两发;这一发是计划 Task 10 明写的**最后一发**(它武装
`0x1D08520` 的 detour,装上之后任何 `[self+0]` join 读数都不再干净 ⇒ §73 排在它之前,并已拆净)。

**判据出处**:roadmap 段4 的 B2 条原文 —— 「判据 = 换一个场景仍是 2,090 ⇒ per-system 循环」;
口径单(产物名 / `hist_overflow==0` 硬门 / 与 §13 并排两列 / 同场景 vs 换场景的措辞模板)在
`docs/offline-tooling.md` 的 execspy 一节。**口径边界照旧**:族外证人 guard 的 `calls` **不是** census
计数(§72.8) —— 本节只用 census 这条通道。

**通道与一处工具缺陷**:`execspy.py` 走 `ssh` 直连(它只 attach 进程,不需要桌面;与 §73 不同)。
10-27 备好的 `census_run.cmd` **第一次执行就坏了**:它的 `rem` 行是 UTF-8 中文,cp936 的 `cmd.exe`
把那些字节当命令执行(`'…顺序纪律…docs' 不是内部或外部命令` / `'_overflow' 不是内部或外部命令`)——
这正是 `session_bridge.shim_text()` 用 `text.encode("ascii")` 挡住的那种失败,只是那份 `.cmd` 没走那个函数。
本发改用 `census_run_ascii.cmd`(纯 ASCII,随本轮提交)。

**时序**:game 先 `pause`(静默窗)→ execspy 装 detour → 人/驱动 `unpause` → 60 s 观测 → `pause` →
`ExecHookUninstall`。本发在这一串里踩到一条**通道事实**:`just game pause` 之后 30 s 内发的
`just game unpause` 被静默吃掉一次(`cmd=unpause` 已记进事件日志,而 `STATUS` 仍是 `paused
want=paused`),再发一次才生效 —— 命令是**单行文件通道**,两个方向紧邻时后写的那行可能落在守护进程
两次 tick 之间。所以观测窗的起点不是「装好那一刻」,是**计数器真的动了那一刻**(execspy 自己就是这么
判的:`live: calls 0 -> 84, observing 60s`)。

### §74.1 门与清理(硬门逐条)

```
ExecHookInstall -> 0                       (patch_size 16,verify -1 = 我们的 JMP 在位)
60 s 观测窗 stats: calls=339504 samples=663 invalid=474 hist_overflow=0
Waiting for base Execute to go silent ... idle at calls=341998
ExecHookUninstall -> 0
ExecHookVerify -> 0                        (engine bytes intact at the target)
post-uninstall probe: 0 calls at base Execute in 1.5s (engine silent — resume to confirm)
EXIT:0
```

`hist_overflow = 0` **成立** ⇒ 直方图是完整普查(§13 定下的硬门:>0 就只能当环境样本)。
`invalid 474 / 339,504 = 0.14 %`,与 §13 的 473/316,468 = 0.15 % 同量级;环(`samples=663`,
drain 64 条)不参与判据。

### §74.2 与 §13 并排两列(同一条通道,不同进程)

| 键 | §13(2026-09-29) | 本发(2026-10-28) |
|---|---|---|
| 观测窗 | ~60 s | 60 s(`--poll` 语义同) |
| `calls` | 316,468(≈5,300/s) | **339,504**(≈5,658/s) |
| distinct shims | 291 | **282** |
| `invalid` | 473(0.15 %) | 474(0.14 %) |
| `hist_overflow` | 0 | **0** |
| 七把 shim | **2,090 each** | **2,494 each** |
| 表首 shim | `0x33D410` ×54,003 | `0x33D410` ×**58,027** |

### §74.3 七把逐把:一个都不少、彼此仍然严格相等、值变了

```
0x0974840 -> 2,494     0x0cc4220 -> 2,494     0x0de40c0 -> 2,494
0x0e58d80 -> 2,494     0x0e96e90 -> 2,494     0x0e98720 -> 2,494     0x0e9b580 -> 2,494
```

七把的 vtable(`0x250E188`/`0x25460F0`/`0x254FA18`/`0x2551620`/`0x2553140`/`0x2553178`/`0x25531E8`)
在直方图里逐张都在,阈值判据(§71 的「七张之内」)照旧成立。

**比值值得记**:七把 2,090→2,494 是 **×1.193**,而表首 shim 54,003→58,027 是 **×1.074**。两组量不在
同一个节奏上 ⇒ 支持 §13 结论 2 的读法(七把绑在「一次集合遍历」上,表首那批绑在「每帧评估」上),
而**削弱**「2,090 是帧数/速度的产物」这一读法 —— 若是同一个帧节奏,两组比值应当一致。

### §74.4 判据达成与否,按原文说

- **判据原文要求「仍是 2,090」⇒ 本发不达成**:七把是 2,494,不是 2,090。
- **但读数不是空的**:七把**彼此**仍严格相等(2,494 ×7),而它们的绝对值随窗口变 ⇒ 「一个恰好相等、
  又随世界变的量」正是「同一集合被完整走了一遍」的形状;**「2,090 是代码常量」这一读法被本发排除**。
- **不能说的是**:「per-system 成立」。要落这条还得一次**已知星系数**的对照 —— 要么在同一个窗口里读到
  当前 galaxy 的 system 数,要么换 galaxy size 再采一发(两条都还在「下一次点名」的口子里)。
- **场景这一格必须诚实**:本发**没有记录存档名**,进战役靠 launcher 自带 `--continuelastsave`;所以
  「换了一个场景」**没有被验证**,能确定的只有:不是同一个进程(pid 3604 vs §13 那次)、相隔 3.5 周。
  两种可能都写清:
  - 若**换了存档/星系规模**:2,090→2,494 与「集合大小随世界变」一致,方向指向 per-system,仍不是证明;
  - 若**仍是同一存档**:星系数没变而计数变了 ⇒ 这个量**不是星系数**,而是被遍历对象数(随事件/日期变),
    per-system 的读法反而**被削弱**。
  本发分不开这两支 —— 这是下一次复采要带上的第一格(存档名 + 星系数),不是本发能补的。

### §74.5 复现命令

```bash
just game pause                                   # 静默窗(先把 detour 装上)
just win "C:/temp/census_run_ascii.cmd"           # NS_LIVE_DLL=C:\temp\sqjs_c4.dll; execspy.py 60
just game unpause                                 # 计数器动了才起观测窗
# 60 s 后:
just game pause                                   # 让 uninstall 等到静默
scp Windows_Jiaolong:C:/temp/c4_census_run.txt evidence/logs/exec_shim_census_2026_10_28.txt
```

产物:`evidence/logs/exec_shim_census_2026_10_28.txt`(329 行,直方图 282 行 + 64 条 drain 记录)。
**顺序纪律已执行**:本发之后本窗不再有任何 `[self+0]` join 读数;装拆均 `rc=0`、`Verify=0`、host 存活。

## §75 零 shot:触发评价路径的形状 —— 谓词槽 `+0x80` 收 `(self, X)`、求值槽 `+0x28` 收 `(self, ctx, a3)`,基体被 1,091 处引用(2026-10-28,离线)

**授权级别**:离线。只读本地 exe 拷贝,不启动游戏、不注入、不占用任何 shot 额度。

**这一节问的是什么**:C5 v1 的数据面要先回答「我们的求值体能不能拿到被度量的那个对象」。
`docs/roadmap.md` 段4 那条「真正的 `CEventScope` 是哪个对象」问的是热路径(effect 路线的 `arg2`),
而 C5 的裁定③走的是 **trigger** 路线 —— 两条路线的入参是不是同一族,决定 C5 要不要重走那四轮 scope 猎取。

**复现**(全部读数由同一条命令产出,自校验不过即退出码 1):

```bash
python3 scripts/scratch/2026-10_c5_data_plane/trigger_path_readings.py
```

### §75.1 donor trigger 的对象形状:class_info → create → vtable

```
class_info 0x269CAA8 = 0x14034C090, 0x141B30450, 0x14034C090, 0x141B304B0
create 0x1B30450 的 lea 目标 = 0x268ED08, 0x26725C8, 0x26726C0
`mov [rbx], rax` @ 0x1B304A4            → 0x268ED08 被写进对象 [0]
vtable 0x268ED08: slot[5](+0x28) = 0x1B183B0   slot[16](+0x80) = 0x349230
```

与 §23.2 的 consumer 读法对齐:trigger 侧 create 之后写 `[obj+0x38]`=id、`[obj+0x40]`=name,
然后调 `[vptr+0x80]`。0x349230 就是那个槽的 donor 实现。

### §75.2 0x349230 是 72 B 的谓词,收 `(self, X)`

```
0034923a  mov  rdi, rdx          ; X = 第 2 实参
0034923d  mov  rbx, rcx          ; self
00349240  test rdx, rdx / je  -> return true
00349245  mov  rax, [rcx] / call qword ptr [rax + 0x70]   ; self 的 +0x70 取值器
0034924b  test rax, rax / je  -> return true
00349250  mov  rax, [rbx] / call qword ptr [rax + 0x70]
00349259  test rdi, rax / setne al                        ; return X != 那个值
```

形状与 effect 谓词 §52 fact 3 的同构:`(child, parent)` → `if (!parent) true; x = child->[+0x78](); return x != parent`。
两边都是「拿到一个对象指针,和一个 self 自己的取值器比一比」。

### §75.3 两个实参分别从哪来(`0x349AE0` 逐条)

```
00349b06  mov     r12, r9                       ; r12 = 第 5 实参
00349cb1  mov     rdx, r12                      ; 谓词第 2 实参
00349cb4  mov     rcx, rdi                      ; 谓词第 1 实参 = 新对象
00349cb7  call    qword ptr [rax + 0x80]        ; slot[16] 谓词
0034a007  mov     qword ptr [rdx + 0x180], rdi  ; 往上下文里写
0034a011  mov     r8, qword ptr [rbp + 0x7f]
0034a015  mov     rdx, r13
0034a018  mov     rcx, rdi
0034a01b  call    qword ptr [rax + 0x28]        ; slot[5] 求值
```

⇒ **谓词槽** `+0x80` 收 `(对象, r9)`;**求值槽** `+0x28` 收 `(对象, r13, [rbp+0x7f])`。两个槽都在
同一条实例化路径上被调到,这与 §52 fact 7「trigger path differs, `0x349AE0` reaches `[vptr+0x28]`」一致。

### §75.4 基体是共用的,但 21 字节指纹分不开它和 effect 谓词

```
initialized qwords == 0x140349230: 1091   align={0: 1091}
0x349230: 48 89 5c 24 08 57 48 83 ec 20 48 8b fa 48 8b d9 48 85 d2 74 25 48 8b 01 ff 50 70 48 85 c0 74 1a
0x3b1420: 48 89 5c 24 08 57 48 83 ec 20 48 8b fa 48 8b d9 48 85 d2 74 25 48 8b 01 ff 50 78 48 85 c0 74 1a
first 21 bytes equal: True; offset 26 = 0x70 vs 0x78
```

两条读数各有用处:

1. **1,091 处引用**(全部 8 对齐)说明 `0x349230` 是一个**共用基体**,不是一个类的私有实现。
   注意口径:`1,091` 是「等于这个地址的 qword 个数」,**不是**「1,091 张表的 slot[16]」——
   槽号只由 donor 表的 `+0x80` 推出来,没有穷举验证。要给槽号一个全量证人,得另外做一次按表基址归位的扫描。
2. **前 21 字节与 effect 谓词 `0x3B1420` 逐字节相同**,差别只在偏移 24..26 的调用槽
   (`FF 50 70` vs `FF 50 78`)⇒ 任何少于 27 字节的前序指纹都**不能**证明 detour 装在触发谓词上。
   新 guard 钉 32 字节(`src/dll/c2/trigger_pred_probe.zig` 的 `EXPECTED_CODE`)。

### §75.5 donor 求值槽把第 2 实参当解析上下文用

```
01b183c2  mov     rbx, rdx                 ; X
01b183c5  mov     rdi, rcx                 ; self
01b183d0  mov     rcx, rbx
01b183d3  call    0x1D0C9F0               ; 名字构造器(§52.1:[ctx+0x30] 的读者)
01b183db  mov     rdx, qword ptr [rbx + 0x288]
```

**这一条是本节最重要的一条否定**:X 被直接喂给名字构造器 `0x1D0C9F0`,并被按 `[X+0x288]` 取字段 ⇒
X 的形态是**解析上下文**,与 effect 侧 `0x3B01A0` 拿到的是同一族(§52.1 那句
「the real event scope is not a valid parse context」说的是同一件事)。

### §75.6 判读边界

- **能说的**:触发谓词槽是 `+0x80`、收 `(self, X)`;触发求值槽是 `+0x28`、收 `(self, ctx, a3)`;
  两者都从 `0x349AE0` 被调到;`0x349230` 是共用基体;21 字节指纹不够。
- **不能说的**:「X 就是被求值的星系对象」。§75.5 的读数把这条**削弱**了 —— X 是解析上下文。
  「scope 被直接交到我们手上、所以 C5 可以绕开热路径那四轮」这个假设**不成立为结论**,
  它现在只是一个待观测的分支。
- **不能说的**:「§5.2 因此收口」。本节只把「下一发往哪儿打」从「热路径四根」换成
  「`+0x80` 的计数与 X 的身份」;是否每个系统一个 X,是点名 shot 的读数,不是本节的推论。
- **§68.8 ② 的移交不受影响**:那一行说的是 scope 载体一问剩一条新路线,本节不是那条路线的判决,
  只是把它具体化成「谓词/求值两个槽的实参形态」。

### §75.7 落点

- 新 guard 的靶与指纹:`0x349230` + 32 B(`EXPECTED_CODE`),见 `src/dll/c2/trigger_pred_probe.zig`。
- 下一发的问题:谓词被调几次、X 的 vtable/区域长什么样 —— 判据与 verdict 值域见
  `docs/offline-tooling.md` 的 `c2_trigger_pred_probe.py` 一节。

## §76 触发谓词第一发:装拆干净、`calls` ≈ 9,800/s,但 `+0x80` 在 787 次求值里只被调 **11** 次且 X 恒为 **0x80** ⇒ 谓词是实例化期检查,不是每次求值(2026-10-28,点名 ×1)

**授权级别**:点名(2026-10-28 本会话内授权「打这一发」)。一进程一次 install 额度 —— pid 3604,本发之后
该进程的 trigpred guard 已拆净(`Uninstall rc=0`、`Verify rc=0`),但**同一进程不再重打**(纪律见 §57.5)。

**这一发问的是什么**:§75 留下的那个数 —— 一个 trigger 放进 `every_system` 的 `limit` 之后,谓词槽
`+0x80`(`0x349230`)被调几次、每次的第 2 实参 X 长什么样。判据与 verdict 值域见
`docs/offline-tooling.md` 的 `c2_trigger_pred_probe.py` 一节。

**产物**:`evidence/logs/c5_trig_pred_4_4_4.tsv`(20 行 `#meta` + 表头 + **11 行**)。

### §76.1 门与清理(硬门逐条)

```
layout   version=1 entry_size=40 ring_len=256 stats_size=40 target_rva=0x349230 prologue_len=32
inject   sqjs_c5.dll sha256 = 59A97C02…B819461C(与本地 zig-out/bin 逐字对上)
gate     IN_GAME_RUNNING(pause=playing console=closed window=none)
install  rc=0   premise: 32 B 指纹,前 21 B 与 0x3B1420 相同、偏移 26 = 0x70
C1Run    trigger_token=68636(进程里早已注册,与 C:/temp/c1_result.log 一致)
uninstall rc=0  verify rc=0  host alive = 1
```

### §76.2 三个数,按读数说

| 键 | 值 | 出处 |
|---|---|---|
| `calls`(谓词基体的调用总数) | 1,467,771(≈ **9,800/s**,窗口约 150 s) | `stats_final` |
| `token_matched`(= `[self+0x38] == 18203`) | **11** | `stats_final` |
| 脚本实际求值的系统数 | 787(`every_system`),其中 **78** 个 `is_rim_system` 为真并写了 `TS_RIM_<名>` | `game.log`: `MARKER_TS_RIM=78` |

artifact 的 11 行**逐行同形**:

```
token	self_ptr	self_vtable_rva	x_ptr	x_vtable_rva
18203	0x1ea57b430	0x26938f8	0x80	0x0
18203	0x1c6731e20	0x26938f8	0x80	0x0
…(共 11 行,self_ptr 有 7 个不同值,self_vtable_rva 全 = 0x26938F8,x_ptr 全 = 0x80)
```

`0x26938F8` 是 `is_rim_system` 的 vtable(`vtable.py 0x26938f8` 读出 slot[9] 引用
`IS_RIM_SYSTEM_TRIGGER`,slot[16] 也是 `0x349230`)—— 所以 detour 确实抓的是 trigger,不是别的东西。

### §76.3 判决:**谓词不是每次求值**

787 次 `limit` 求值,谓词只被调 **11** 次;11 次里 X 全等于 `0x80`(小常量,不是指针,`x_vtable_rva=0`)。

- **形状与 §54 的 effect 侧同源**:§54 那次 206,695 次谓词调用里,armed token 只匹配 **1** 次。
- 所以 `+0x80` 是**实例化期**的 scope 检查:`if (!X) true; y = self->[+0x70](); return X != y` —— X 是
  一个 scope/类型掩码,不是被求值的对象。
- **verdict 按读数 = `predicate_instantiate_once`**(不是 `predicate_per_system`)。驱动自己在 artifact 里
  写的是 `script_refused`,理由是「marker 30 s 内没出现」;那两格是**驱动口径**的问题,见 §76.4。
  本节以读数为准,并把这个分歧原样留在案:**同一份 artifact 上,`overall_verdict` 与
  `stats_final/last_token` 打架**,下一发之前必须先修驱动的口径(§76.4 第 2 条)。

### §76.4 三条通道/驱动缺陷(都实测到了,都还没修)

1. **`game.log` 是缓冲写的,30 s 等不到 marker。** 驱动 `SCRIPT_WAIT_S = 30`;实测 RIM 的 78 条 marker
   在**约 2 分钟后**才落盘(`GAME_LOG size=1606 → 10101`)。⇒ 两段的 `sent_*` 全 0,但它们**不是**
   `script_refused` 的证据,只是「30 s 内没看见」。
2. **verdict 只看两个窗口,丢掉了 poll 窗。** 11 次匹配全部落在 `--poll-s 120` 那一段
   (`stats_b_raw` 时 `token_matched=0`,`stats_final` 才 11)。驱动把 poll 窗只记进 `stats_final`、
   不参与 `verdict()` ⇒ 一次「脚本晚到」被读成了「脚本没跑」。
3. **NEO 段的命令从未被守护进程消费。** supervisor 的 `ns_game_log.jsonl` 里**只有一条 `command` 事件**
   (RIM,`21:39:50`),没有 NEO 的;`game.log` 里 `TS_NEO=0`。而驱动在 `_send_console` 返回 False 之后
   仍然写下一条命令,**把还没被消费的 NEO 命令覆盖掉了**(`ns_game_cmd.txt` 里最后只剩 RIM)。
   NEO 是否**本身**会失败(scope 类型)仍未验证 —— 它没被送到。

诊断用的只读探针:`scripts/scratch/2026-10_c5_data_plane/probe_logs.py`(game.log 尾部 + supervisor
事件 + 命令文件/`.seen` 的状态,一次打印);它的输出留在 `evidence/logs/c5_trig_pred_after_4_4_4.txt`。

### §76.5 对 §75 的修正(append-only,不改写 §75)

§75.5 写的是「X 的形态是解析上下文」,依据是 donor 的 **slot[5]**(求值槽 `0x1B183B0`)把第 2 实参
喂给名字构造器 `0x1D0C9F0`。本节实测的 X 来自 **slot[16]**(谓词槽),它是 `0x80` —— 一个常量。

⇒ **§75.5 那条结论只适用于求值槽的第 2 实参,不能推广到谓词槽。** 两个槽的实参不是同一个东西:
- 谓词槽 `+0x80`:第 2 实参是**小常量**(本节实测 `0x80`);
- 求值槽 `+0x28`:第 2 实参是 `ctx`,donor 把它当解析上下文用(§75.5 的读数)。

§75.6 的「不能说的」因此要加一条:**不能说「谓词拿到的 X 是 scope 或解析上下文」** —— 它是掩码量。

### §76.6 下一靶(零 shot,已定形)

`is_rim_system` 的 vtable `0x26938F8` 的 **slot[5] (+0x28) = `0x1A91A80`**,而 `.rdata` 里等于它的
qword 有 **352** 个 ⇒ 它也是一个**共用基体**,且是**每次求值**走的那一个(§75 读数 3:
`0x34A01B call [rax+0x28]`,实参 `rcx=self, rdx=r13, r8=[rbp+0x7f]`)。它的头部:

```
01a91a8f  mov  rdi, rcx        ; self
01a91a92  mov  rsi, r8         ; a3
01a91a95  add  rcx, 0x78       ; &self[0x78]
01a91a99  mov  rbx, rdx        ; ctx
01a91a9c  call 0x1A918E0
01a91aa1  mov  rax, [rdi]
01a91aa4  lea  rdx, [rbx + 0x278]   ; ctx + 0x278
```

⇒ 下一发把 detour 从 `0x349230` 换到 **`0x1A91A80`**,记 `(self, ctx, a3)`;要问的是
「ctx 或 `ctx+0x278` 上有没有星系的身份」。这是**新仪器**(新靶、新指纹、新 Entry 字段),
不在本计划内 —— 归下一份计划,判据与授权级由它自己写。

### §76.7 复现命令

```bash
just game cmd status        # 清掉上一次的 quit,否则新 daemon 起来就退出
just game start
just game unpause
just win "python C:/temp/session_bridge.py C:/temp/ns_world.py status"     # -> IN_GAME_RUNNING
just win "python C:/temp/session_bridge.py --timeout-s 420 C:/temp/c2_trigger_pred_probe.py \
  C:/temp/sqjs_c5.dll --systems 787 --script-file C:/temp/ts_scripts.txt --poll-s 120 \
  --out C:/temp/c4_trig_pred.tsv"
scp Windows_Jiaolong:C:/temp/c4_trig_pred.tsv evidence/logs/c5_trig_pred_4_4_4.tsv
```

`sqjs_c5.dll` 是本发的模块名(**不是** `sqjs_c4.dll`):pid 3604 里 `sqjs_c4.dll` 已被早前会话装载,
`scp` 覆盖被占用文件实测失败(dest open: Failure),所以本发换名装载同一份字节(sha 逐字相同)。
**这也意味着该进程里两个模块副本同时在**,后续任何 `[self+0]` join 读数都要先确认不是 `sqjs_c4` 那份
(本 guard 不读 `[self+0]` 做判据,只读 `[self+0x38]` 的 token,所以本节不受影响)。

### §76.8 修复状态与判决的可辩依据(2026-10-28 终审后追加,append-only)

**§76.4 那三条「都还没修」在同一个提交里就已经修了** —— 本节的标题读作「记录」而不是「待办」。
逐条对账(全部在 `62fb984` 与 `f792be1` 之后的终审提交里收口):

| §76.4 | 修在哪 | 怎么钉 |
|---|---|---|
| ① marker 30 s 等不到 | `SCRIPT_WAIT_S` 30 → **180** + `--script-wait-s` | `docs/offline-tooling.md` 的用法行 |
| ② verdict 丢掉 poll 窗 | 新增 poll 窗 + 纯函数 `overall_verdict()` | `test_overall_verdict_lets_the_poll_window_win` |
| ③ 未确认仍写下一段(覆盖未消费命令) | 未确认即停;并且**把 3 s 的 `.seen` 确认换成窗口预算** | 见下一条 |

**③ 的根因终审补上了(此前只写了现象)**:supervisor 在持有世界租约时**整段跳过 `read_command`**
(`game_supervisor.py` 的 `yield_to_lease` 分支先 `continue`)。本次产物自己就有这条证人 ——
`evidence/logs/c5_trig_pred_after_4_4_4.txt` 里 21:39:42–21:39:49 连续 8 条 `YIELD_TO_LEASE`,
21:39:50 才出现唯一的 `command` 事件,21:39:54 `console_sent`。所以 NEO 的命令不是「被拒」,是**被延后**,
然后被下一段覆盖。`_send_console` 的 3 s 确认窗口短于一次租约持有 ⇒ 现在的实现把「等租约」等满
`--script-wait-s` 再判,而不是 3 s 就放弃。

**artifact 是修前驱动写的**(meta 里是 `sent_a`/`sent_b`,没有 `delivered_*`/`marker_*`/`verdict_poll`)。
本节的读数按 artifact 原样保留;要让 JSON 级的 meta 与当前驱动一致,只有重打一发(未打)。

**判决的可辩依据要换一条(此前用的是比值,而比值分母的来源被夸大过)**:

1. **787 不是本窗口的求值次数。** 它来自**存档拷贝**(10:56 UTC 的 `save_hypergraph.py`,见
   `evidence/logs/c5_save_graph_4_4_4.log`),不是 shot 里的计数。§76.2 把它写成「脚本实际求值的系统数」
   是错的;能说的只有「按存档,这场战役有 787 个系统」。工具文档自己也写着「拿它当分母会把
   `token_matched=1` 判成 `predicate_instantiate_once` —— 结论对、理由错」。
2. **那 11 次匹配属于官方 `is_rim_system`(token 18203),不是 C1 的 `neo_effect`(68636)。**
   artifact 的 11 行全是 `token=18203`;NEO 段的命令从未送达(§76.4 ③)⇒ **C5 自己的 keyword 在这一发里
   一次也没被求值过**。所以本节的结论是关于「一个 system-scoped 官方 trigger」的,不是关于 C5 keyword 的。
3. **结论该站在哪两条上**:①artifact 里 **11 次调用落在 7 个不同的 `self_ptr` 上**(7 个对象,不是 787 个);
   ②基体自己的代码形状 `if (!X) true; x = self->[+0x70](); return X != x` —— 是「拿一个掩码和自身掩码
   比一比」,不是「把对象交给调用方」。两条合起来才支撑「实例化期检查」;`11 vs 787` 只是**一致**,
   不是依据。

## §77 触发求值槽 `0x1A91A80` 的静态形状:尾调 slot[4]、第二实参是 `&ctx[0x278]`、`ctx` 带 `+0x158` 类型门(2026-10-29,离线,零 shot)

本节是 C5 前置 #2 的**静态**部分:§76.6 已经把下一靶定形为「求值槽 `+0x28` 的共用基体
`0x1A91A80`,收 `(self, ctx, a3)`,要问的是『ctx 或 `ctx+0x278` 上有没有星系的身份』」。本节只把
**代码形状**读出来,不动游戏、不注入、不 dispatch —— 一发实机读数是下一份计划的事。

### §77.1 三件静态事实

**① 32 B 指纹与被调函数。** 目标前 32 B 逐字节为:

```
48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 49 8B F0 48 83 C1 78 48 8B DA E8 3F FE FF
```

窗口内的 `E8 rel32` 位于 `+0x1C`(指令地址 `0x1A91A9C`),目标 = `0x1A918E0`。**32 B 的末字节落在
这条 call 的 rel32 中间**(rel32 的第 5 字节在 `+0x20`),指纹长度仍然够:`0x349230` 与本目标的**前 10
字节就分开了**(`48 89 74 24 10` vs `48 89 5C 24 08`),与 §75.4 那条「21 字节不够、要钉 32」的教训同向。

**② 它是个转发器,不是叶子。** 全文:

```
01a91a8f  mov  rdi, rcx              ; self
01a91a92  mov  rsi, r8               ; a3
01a91a95  add  rcx, 0x78             ; &self[0x78]
01a91a99  mov  rbx, rdx              ; ctx
01a91a9c  call 0x1A918E0             ; 带 ctx 进去
01a91aa1  mov  rax, qword ptr [rdi]  ; self 的 vtable
01a91aa4  lea  rdx, [rbx + 0x278]    ; 第二实参 = &ctx[0x278]
01a91aab  mov  r8, rsi
01a91aae  mov  rcx, rdi              ; self
01a91ac0  jmp  qword ptr [rax + 0x20]  ; 尾调 self 的 slot[4]
```

⇒ **`ctx+0x278` 是被当对象传出去的**(`lea` 的是**地址**),所以 `[ctx+0x278]` 很可能是那个子对象的
**首 qword(vtable)**;若它落在镜像内,一格读数就能拿到一个**类型**,而不用再猜偏移链(§59 那条线正是
输在猜偏移上:`no_scope_candidate`,§73 的 depth-2 也已问完)。**尾部是 `jmp [rax+0x20]`,即 slot[4]** ——
本目标本身不做判定,它把活交给下一张表。

**③ `ctx` 带一个类型门。** 被调函数 `0x1A918E0` 的头 6 条:

```
01a918ed  mov  rdi, rdx
01a918f0  mov  r9d, dword ptr [rdx + 0x158]   ; ← ctx 的类型标签
01a918f7  mov  r8d, r9d
01a918fa  sub  r8d, 1
01a918fe  je   0x1a91a08
01a91904  cmp  r8d, 0x426
01a9190b  je   0x1a91a08
```

即 `ctx+0x158` 必须是 **1** 或 **0x426**(1062),否则走另一条拼字符串的路径(0x15efd0 / 0x5e2ef0 /
0x1565a0,形态像断言/错误消息)。⇒ `ctx` 是个**带标签的大对象**,不是裸 scope;`+0x158` 是一个**廉价且已
被代码证实**的判别量。

### §77.2 口径边界:`352` 是**绝对地址**的 qword 数

`.rdata` 里的 vtable 槽存的是 `ImageBase + RVA`,不是 RVA。本仓镜像基址 `0x140000000`,于是:

| 口径 | 计数 |
|---|---|
| `.rdata` 中等于 `ImageBase + 0x1A91A80`(`0x141A91A80`)的 qword | **352** |
| `.rdata` 中等于**裸 RVA** `0x1A91A80` 的 qword | **0** |
| 全镜像(按 8 字节对齐扫) | 352(全部在 `.rdata`) |

⇒ 与 §76.6 的「352 个 qword」一致,且**它是 qword 个数,不是「352 张表」** —— 与 §75.4 那条
「1,091 是 qword 个数,不是 1,091 张表的 slot[16]」同一种口径警告。

### §77.3 复现命令

```bash
python3 scripts/scratch/2026-10_eval_slot/shape_1a91a80.py
```

产物:32 B 十六进制、`+0x1C` 的 call 目标、`0x1A918E0` 的前 8 条指令、两种口径的 qword 计数。exe 路径走
`disrva.resolve_exe()` 的候选链(`NS_STELLARIS_EXE` 优先),不内联受保护路径。

### §77.4 这一节**不能**说的

1. **静态形状不说明 `ctx` 是什么对象。** 「`ctx+0x278` 是个 vtable」是**候选**;它要等一发实机读数
   (`[ctx+0x278]` 落在镜像内还是外、`distinct ctx` 有多少个)才成立或不成立。
2. **`+0x158 ∈ {1, 0x426}` 是代码里的常量,不是读数。** 它证明「ctx 带标签」,不证明「本窗口的 ctx 标签是
   哪一个」。
3. **本节没有分母。** 星系数仍须从**当前存档**重建(`save_hypergraph.py`),787 属于另一场存档(§76.8 ①)。

## §78 孤儿 handler 已按用户裁定删除:门禁计数与**出货字节**逐字未变(2026-10-29,离线,零 shot)

§64 是**案卷**(§64.3 逐字:「本节不判『该不该删』……删除需要新的裁定」)。裁定在 2026-10-29 由人给出:
**删**。本节落账执行结果与新基线。

### §78.1 删了什么(照 §64.4 的落点清单逐条执行)

| 落点 | 动作 |
|---|---|
| `src/dll/effects/handler.zig`、`src/dll/triggers/handler.zig` | **删文件**(两个目录随之消失) |
| `build.zig:228-232` | 两段 SKIPPED 注释(`std.Thread.Mutex` 那两条)一并删 |
| `README.md` | 特性清单「Custom Effects / Custom Triggers」两行、目录树 `effects/` `triggers/` 两段、API 表 `registerEffect` / `registerTrigger` 两行、「Scripted Effect Threshold」一节 |
| `docs/offline-tooling.md:70` | 「至今零执行 **29 条**」(`bridge.zig` 19 + 两个 handler 各 5)→「至今零执行 **19 条**」(`bridge.zig` 19),并注明两个孤儿已于本日删除 |
| `docs/roadmap.md:98` | 整条孤儿候选移除(行数 139 → **138**,删行在 140 上限内) |

**没动的**:`evidence/` 里 §29 :460/:707、`zig_test_coverage.md` 26/27/64/65、`docs/scope-read-points.md:57`
的旧读数 —— 那是**历史数**,按 append-only 不改写;新基线记在本节。

### §78.2 新基线:**逐字未变**

删除前后的两次实测(同一棵树,只差那两个文件):

| 读数 | 删除前 | 删除后 |
|---|---|---|
| `zig build test --summary all` | `31/31 steps; 743/743 tests` | `31/31 steps; 743/743 tests` |
| `zig-out/bin/stellaris_quickjs.dll` sha256 | `ec3716a2655df117d8aafe1f2fd7ab59b4bbf3ae6bbdd11fe03cbd22e85c4614` | **同前,逐字相同** |
| 同上文件大小 | 7,282,176 B | **同前** |
| `scripts/test_scripts_layout.py` | 38 passed | 38 passed |

⇒ 那两个文件**从未进入任何构建根**(§64.1 事实 1 的正面复核):删掉它们,出货字节一个 bit 都不变。

### §78.3 这一节**不能**说的

1. **这不证明「C3 那层不需要 JS 路由」。** 它只证明这两个**具体文件**是死的。JS 路由本身仍存在,只是走
   现役路线(`C2ExecCall` → `quickjs_wrapper.c`,§64.1 事实 3)—— 那是设计问题,不在本节的裁定范围。
2. **README 删掉的那几行描述的是孤儿的「设计」,不是能力。** `ID > 4081` 这个阈值在整个 `src/` 树里
   **只出现在那两个文件**(删前实测),`registerEffect` / `registerTrigger` 也不在别处(唯一同名的
   `src/dll/ui/button.zig:183` 是**按钮**效果注册,另一回事)。而「我们注册的新 keyword 的 effect 执行走
   JS」这个**能力**不受影响(C4 路线)—— README 目前没有一句描述它。**补那一句是另一件事**,不在 §64.4 的
   落点清单里,留给下一次有意的文档改动,不在本节顺手做。

### §78.4 复现命令

```bash
git show --stat <删除提交>
zig build test --summary all 2>&1 | grep "Build Summary"
sha256sum zig-out/bin/stellaris_quickjs.dll      # 与 §78.2 的两列逐字相同
```

**下一发(§77 那台仪器)的实机读数改记 §79** —— 本节占了 §78 这个号。

## §79 求值槽第一发:`calls=1`(不是 787)⇒ 求值槽**不是**每系统一次;`ctx+0x278` 是标量 0x3fba 不是 vtable;`self_vtable_rva` 与 §76.6 对得上(2026-10-29,点名 ×1)

靶 = §77 钉死的触发求值槽共用基体 `0x1A91A80`(`[vptr+0x28]`,352 张表共用)。仪器 = §77 的静态形状 +
`C4TrigEval*` 九导出 + `scripts/c2_trigger_eval_probe.py`(48 B Entry、1,024 槽 ctx 去重表、三档证据)。
实测在 **pid 10680**、战役 `_1474567734` 的 `autosave_2234.01.01.sav`(sha `a80c469a…`,N = **787** 系统 /
1,217 边,`save_hypergraph.py` 重建)上完成;装拆均 `rc=0` / `verify_rc=0` / `host_alive=1`。

### §79.1 这一发之前的三个通道/仪器缺陷(都实测到,两个当场修了)

1. **`world_probe.py` 缺 `import sys`**(本仓**也是**,不是主机陈旧):`gate_install` 的拒绝分支
   `print(..., file=sys.stderr)` 抛 `NameError`,把**拒绝理由**吞掉,驱动只留下一段 traceback。
   已修 + 围栏 `scripts/windows/tests/test_sys_imports.py`(扫整个 `windows/` 族:`sys.` 必须配 `import sys`)。
2. **主机侧 `session_bridge.py` 陈旧**(缺 §76 那次加的 `_printable`):驱动跑完、回显输出时
   `UnicodeEncodeError` 崩在 `print(output)`,把整段 stdout 吃掉。已 `just deploy` 对齐。
3. **事件窗检测盲区(未修,交下一份计划)**:游戏里弹了一个**第一次接触**窗(维林集体意识,三个选项),
   而**两个检测器都看不见它** —— `world_probe` 的 bbox = `None`(暗面板不匹配亮度剖面)⇒ 世界状态判
   `IN_GAME_PAUSED_CLEAN` ⇒ **门拒绝开火**(fail-closed,行为正确);daemon 的 `classify_window` = `none` ⇒
   `acquire_or_refuse(state,"click_option")` 不发租约 ⇒ `just game click` 被**静默丢弃**
   (`_handle_command` 的 `lease is None` 分支是 `pass`,不写日志)。**只有人手工点**能过(§72.2 先例)。
   附带实测:daemon 的「金色行」检测在**银河地图**上把右侧大纲栏当成事件选项(`handled` 涨到 14),
   它点的是 outliner 的行,不是选项。

### §79.2 上线两道门(§70.6)

```
DLL    C:/temp/sqjs_c6.dll          sha256 cbaa63c6e85ee4669c2a7aee408db290b0646886b9065100fdcdf05f58ba2961
驱动   C:/temp/c2_trigger_eval_probe.py  sha256 7f0aa61b1697f7cd03d228e213f1ae70b543f938b4abf01dbc32d3cb276ce516
```
两份都与本机 `zig build` / git HEAD 的产物**逐字相同**(主机侧 `Get-FileHash` 原样对上)。launcher 一次
成功(`inner_exit code=0`,`stellaris_pid=10680`;点击轨迹 attempt 1/2 就在**屏内** `rect=(-11,-11,2171,1379)`、
`owns_foreground=True` —— 与 §72.2 的屏外矩形样本相反,三档诊断本轮无 23 样本)。

### §79.3 读数(artifact `evidence/logs/c5_trig_eval_4_4_4.tsv`)

| 窗 | token | delivered / marker | calls | token_matched | distinct_ctx | verdict |
|---|---|---|---|---|---|---|
| A `neo_effect` | 68636 | 1 / **0** | 0 | 0 | 0 | `script_refused` |
| B `is_rim_system` | 18203 | 1 / **1** | **1** | 1 | **1** | `ctx_single` |
| poll(120 s) | 18203 | — | 0 增量 | 0 | 1(绝对) | `no_calls` |

唯一一行(`#meta` 之后):

```
token  ctx_tag  sub_vtable_rva  self_vtable_rva  occurrences  ctx_ptr    a3    sub_obj
18203  0x1      0x0             0x26938f8        1            0x7fed50   0x80  0x3fba
```

### §79.4 判读

1. **求值槽不是「每次求值」都走。** 脚本确实按系统求值了(窗 B 的 `marker=1`,§76 同一形状的
   `TS_RIM_` 标记在 `game.log` 里出现),但目标函数在整个窗口只被调 **1** 次 ⇒ §76.6 把 `+0x28` 写成
   「每次求值走的那一个」**不成立**;它至少是**每次实例化/每脚本一次**这一档。
2. **`ctx` 是低地址区里的小对象**:`ctx_ptr = 0x7fed50`,落在 §56.8 记过的那个 `MEM_PRIVATE` RW 8 KB 区
   (base `0x7fe000`)。两格读都成功(所以那两页**确已提交**),不是「读不到」。
3. **`ctx+0x158 = 1`** —— §77.1 ③ 的两个合法值之一 ✓(类型门成立)。
4. **`ctx+0x278 = 0x3fba` 是标量,不是 vtable**:`0x3fba` 远低于镜像基址(本次 `0x7ff96be20000`)⇒
   `sub_vtable_rva = 0` 读成「那里不是一个对象」,**不是**「我们认不出来」。§77.1 ② 的「被当对象传出去」
   只说明**引擎**把 `&ctx[0x278]` 传下去,不说明那一格是 vtable。
5. **`self_vtable_rva = 0x26938F8`** = §76.6 记的 `is_rim_system` 的 vtable ⇒ self-vtable 的 join 是正确的
   (这条同时证明 I-6 的诚实条款没有被触发:没有 predicate 残留)。
6. **`a3 = 0x80`** —— 与 §76 记的谓词第 2 实参 `X = 0x80` **同值**;两个槽的「掩码量」疑似同一个常量。

### §79.5 这一发**不能**说的

1. **`calls=1` 不等于「这条路上没有 per-system 路径」。** 它只说**这个槽**不是每系统一次;每系统的
   东西一定在别的槽/别的函数里(§76 的谓词槽是 11 次,也不是 787)。
2. **窗口只有 120 s。** 脚本的 787 次求值发生在窗 B 的 marker 之前;poll 窗 120 s 内 0 增量。更长窗口
   是否会再调,本发未测。
3. **`ctx` 的语义仍未定**:它是「解析上下文」这一档,**不是**「某个星系」。所以 C5 §2 那格
   「星系对象句柄从哪来」**仍然未观测** —— 这一发给出的是**负结论**:求值槽不是入口。
4. **`0x3fba` 未定性**(16,314):可能是枚举/位域/计数,本发只记值,不做猜测。

### §79.6 复现命令

```bash
just awake start                                   # 机器重启过,守护进程没起来 ⇒ 先拉起
just launch                                        # 裸命令;Paradox launcher 自己加 --continuelastsave
just game start && just game unpause
just win "python C:/temp/session_bridge.py C:/temp/ns_world.py status"    # → IN_GAME_RUNNING
just win "python C:/temp/session_bridge.py --timeout-s 900 C:/temp/c2_trigger_eval_probe.py \\
  C:/temp/sqjs_c6.dll --systems 787 --script-file C:/temp/ts_scripts.txt \\
  --poll-s 120 --out C:/temp/c4_trig_eval.tsv"
scp Windows_Jiaolong:C:/temp/c4_trig_eval.tsv evidence/logs/c5_trig_eval_4_4_4.tsv
```

`ts_scripts.txt` 的两行 = `scripts/scratch/2026-10_c5_data_plane/ts_scripts.txt` 逐字(与 §76 同一份;
supervisor 日志里那条 `console effect every_system = { limit = { is_rim_system = yes } log = "TS_RIM_[This.GetName]" }`
是它的原文)。

### §79.7 交下一份计划的四件事

1. **事件窗检测盲区**(§79.1 ③):`world_probe._panel_bbox` 与 `classify_window` 都认不出「第一次接触」类暗面板;
   后果是 `install` 与 `click_option` **同时**失效,而失败是**静默**的(`pass`)。修法两条都要:检测器认这一类窗,
   且 `lease is None` 分支必须**说话**(写日志 + 非零退出)。
2. **每系统路径在哪**:求值槽与谓词槽都是「实例化档」(1 次 / 11 次),而 787 次逐系统求值确实发生了。
   下一靶应在**求值循环**里找(§75.3 的 `0x34A01B` 调用点所在的函数,往上找循环体)。
3. **`ctx` 那个低地址区**(`0x7fe000`/8 KB,§56.8 也见过)到底是什么:同一区域两次独立读数都指到它,
   值得单独一发只读普查(它可能是引擎的「求值暂存区」)。
4. **`a3 = 0x80` 与 §76 的 `X = 0x80` 同值**:两个槽的第 2/第 3 实参是否是同一个掩码常量,值得静态确认。

## §80 逐系统循环定位:A1 注册点 / A2 循环体 / A3 三条证伪判据(2026-10-29,离线,零 shot)

§79 的负结论把「787 次逐系统求值发生在哪」从求值槽(`+0x28`,1 次)和谓词槽(`+0x80`,11 次)上摘掉了
—— 两个槽都是**实例化档**。本节改从 `every_system` 这个迭代器**自己的注册点**入手:先定名字是哪个
函数拼的、注册函数在哪、它建的对象的 create 是谁(§80.1),再读 create 出来的对象的「按系统」循环
(§80.2),最后用三条**可证伪**的判据钉候选承载寄存器(§80.3)。三小节都只读 exe 拷贝。

### §80.1 `every_system` 的名字由 `0x192AFE0` 拼(`"every_" + "system"`),注册函数是 `0x19682F0`

**三件事。**

**① 拼接器 = `0x192AFE0..0x192B0C5`。** 它把 `0x2668DD8` 处的 6 B 字面量 `"every_"` 与入参名字
拼接(`0x15F420` 是 `std::string` 的 `operator+`);同一模板的兄弟:`0x192B350` 拼 `"random_"`(前缀在
`0x2668DD0`,7 B),`0x192B690` 拼 `"ordered_"`(`movabs rax, 0x5F6465726564726F`)。前缀是**代码里的
立即数/字面量**,不是从别处读的变量。`every_system` 那次调用在 `0x196860C`:

```
  01968600  lea     rdx, [rip + 0xb11ea1]  ; -> 0x247a4a8  "system"
  01968607  lea     rcx, [rsp + 0x50]
  0196860c  call    0x14192afe0  ; -> 0x192afe0  "every_" + 入参
  01968612  mov     rcx, rax
  01968615  call    0x141d13270  ; -> 0x1d13270  GetOrAddToken
```

⇒ 运行时拼出的名字 = `"every_" + "system"` = `every_system`。这与计划背景里那条实测一致:
`b"every_system\0"` 在 exe 里不存在,`b"every_"` 只在名字池。

**② 注册函数 = `0x19682F0..0x1968BE6`(0x8F6 B)。** 它的**唯一**直接调用者是
`0x1165D0..0x1165E9` —— 一个静态初始化 thunk(`call 0x19682F0` 之后 `jmp 0x218556C`),**不在** §19 的
101 个注册函数区间里。计划里「对命中的 concat_fn 找它的调用者(应当是 101 个注册函数之一)」这一句
按字面不成立:**字面量所在的那个函数自己就是注册函数**,再往上只有 static init。`0x19682F0` 同时落在
§19 的两个区间内(`0x1930E70..0x196D3E6` 与 `0x195A580..0x19A7268` 在 `0x195A580..0x196D3E6` 重叠),
所以「落在 §19 区间内」这一条判据成立,但「它是被 §19 注册函数调用的拼接器」不成立。

**③ 它建的对象(原样窗口,`mint @0x1968615` 起的对象构造段):**

```
  0x196867f  mov     rbx, qword ptr [rip + 0x1a0c062]   ; -> 0x33746e8 (ScriptedEffectDB)
  0x1968686  test    rbx, rbx
  0x1968689  jne     0x19686ac
  0x196868b  lea     ecx, [rbx + 0x70]                  ; rbx==0 ⇒ size 0x70
  0x196868e  call    0x2185218                          ; operator new(0x70)
  0x196869d  call    0x3aeba0                           ; db ctor(§21 的 effects 拉起)
  0x19686a5  mov     qword ptr [rip + 0x1a0c03c], rax   ; -> 0x33746e8
  0x19686ac  mov     ecx, 0x10
  0x19686b1  call    0x2185218                          ; operator new(0x10)
  0x19686bd  mov     qword ptr [rax + 8], rsi           ; +8 = 拼好的名字("every_system")
  0x19686c1  lea     rcx, [rip + 0xcfdfa8]              ; -> 0x2666670
  0x19686c8  mov     qword ptr [rax], rcx               ; +0 = class_info
  0x19686ce  mov     edx, r14d                          ; token id(0x1968615 的 eax)
  0x19686d4  call    0x3aef60                           ; BST insert(db, id, value)
  class_info qwords: 0x14034c090, 0x141a74eb0, 0x14034c090, 0x141a75010
```

⇒ value = `new(0x10){ class_info = 0x2666670, name = "every_system" }`;`0x2666670` 的 qword[1] =
`0x141A74EB0` ⇒ **create = `0x1A74EB0`**(§80.2 的入口,按 §75.1/§23.2 的 class_info 读法)。
docstring 是 `0x2669D98` = `"Iterate through all systems"`。

**附带发现(对 §80.2 有用):一个注册函数注册同族的四个 keyword。** 同一个 `0x19682F0` 里还有三个
mint 点,前缀分别来自不同拼接器:

| mint | 前缀 | 运行时名字 | class_info | create | 目标 db |
|---|---|---|---|---|---|
| `0x1968364` | `random_`(`0x192B350`) | `random_system` | `0x26665D0` | `0x1A74E10` | effect `0x33746E8`(`0x3AEF60`) |
| `0x19684C9` | `ordered_`(`0x192B690`) | `ordered_system` | `0x26665C0` | `0x1A74E60` | effect `0x33746E8`(`0x3AEF60`) |
| `0x1968615` | `every_`(`0x192AFE0`) | **`every_system`** | `0x2666670` | **`0x1A74EB0`** | effect `0x33746E8`(`0x3AEF60`) |
| `0x1968890` / `0x1968ADD` | trigger 侧(`count_` 等) | `any_system` 族 | `0x2666690` | `0x1A74F50` | trigger `0x32611C8`(`0x348150`) |

前两行与第三行的 class_info qword 都是逐条读出来的;**第四行只读了插入调用与 class_info 地址,
未逐条核对 create**(A2 不用 trigger 侧)。

**这一节不能说的。** ① `every_system` 是「静态两段拼起来」的名字:拼接器读 6 B 前缀 + 入参
`"system"` 有代码支持,但没有实机把 token 名字读回来;② `0x1165D0` 只说明注册发生在静态初始化期,
**不说明**它早于任何求值(时序仍按 §19:插入早于第一次引用该 keyword 的求值);③ `0x1A74EB0` 是
「create」是按 `class_info` qword[1] 的 §75.1 读法,**不是** call-site 证人。

**复现:**

```bash
python3 scripts/scratch/2026-10_per_system_loop/find_iterator.py
```

探针输出里的原始行:`# functions in 0x195a580..0x19a7268 with a 'system' lea: 13 (deduped;
.pdata chained records merged)`、`# of which the literal is exactly 'system': 1`、
`## registrar=0x19682f0 ...`、`mint @0x1968615 ... join=0x192afe0 prefix='every_' class_info=0x2666670`。

### §80.2 `every_system` 的逐系统循环:边界 `0x1A762A0..0x1A76335`,容器是 4 B id 向量,候选承载 = scope 结构里的 id/对象格

§80.1 的 create `0x1A74EB0` 写出的 vtable 是 `0x26562D0`。槽 `+0x70` = **`0x1A76130`**,而这个槽正是
`CEffect` 家族「把子效果带到某个 scope 里去走一遍」的那个虚位:基类实现 `0x3B1330` 在槽 `+0x70`
里递归每个子效果(`[self+0x10]` 向量、`[self+0x1c]` 计数,stride 8);`every_system` 把它覆写成
**先枚举、再逐个 scope 下发**。

**① 枚举来源(两次虚调,不在循环里)。**

```
  01a76205  mov     rax, qword ptr [r14]
  01a7620d  mov     rcx, r14
  01a76210  call    qword ptr [rax + 0xe8]      ; 计数
  01a76216  mov     edi, eax
  ...
  01a7626a  mov     rax, qword ptr [r14]
  01a7626d  mov     r9, qword ptr [rbx + 8]      ; 目标向量(dword 数组)
  01a76271  lea     r8, [rbp + 0xc0]             ; ← 过滤后的实际条数写这里
  01a7627d  mov     rcx, r14
  01a76280  call    qword ptr [rax + 0xf0]      ; 填 id
```

`+0xE8` = `0x1A798C0`:`[[0x3260BB0]+0x59C]`(一个 dword 计数);`+0xF0` = `0x1A8CC50` →
`0x19307D0`,后者是真正的枚举器:

```
  019307da  mov     rax, qword ptr [rip + 0x19303cf]  ; -> 0x3260bb0
  019307e7  mov     rdx, qword ptr [rax + 0x590]      ; 容器基址
  019307ee  movsxd  rax, dword ptr [rax + 0x59c]      ; 原始条数
  019307f5  lea     rdi, [rdx + rax*4]                ; end = base + n*4
  ...
  01930842  cmp     byte ptr [rax + 0x137c], 0        ; 逐对象的过滤位
  01930849  je      0x141930857
  0193084b  mov     ecx, dword ptr [rax + 8]          ; 只收 [obj+8](4 B)
  01930851  mov     dword ptr [rbx], ecx
  01930853  add     rbx, 4
  01930857  add     rdx, 4                            ; stride = 4 B
  0193085b  cmp     rdx, rdi
  0193085e  jne     0x141930810
```

⇒ 容器 = `[[0x3260BB0]+0x590]` 的 **dword 向量**(原始条数 `[[0x3260BB0]+0x59C]`),元素尺寸 4 B;
过滤条件是 `[obj+0x137C] != 0`,写进输出数组的是 `[obj+8]`(4 B)。`+0xF0` 把**过滤后的条数**写回
`[rbp+0xC0]`,循环用的是这个数,不是原始条数。

**② 循环本体(`0x1A762A0..0x1A76335`,原样):**

```
  01a76289  cmp     dword ptr [rbp + 0xc0], r12d      ; r12d = 0
  01a76290  jle     0x141a7633b                       ; 0 条 ⇒ 直接收尾
  01a76296  mov     rdi, r12                          ; i = 0(字节偏移)
  01a762a0  mov     rax, qword ptr [rbx + 8]          ; ← 列表头读取
  01a762a4  mov     r8d, dword ptr [rdi + rax]        ; ← 第 i 个 id(4 B)
  01a762a8  mov     rax, qword ptr [r14 + 0x180]     ; 本对象的掩码(=0x80,ctor 写死)
  01a762af  mov     qword ptr [rsp + 0x28], rax      ; scope+0x08 = 0x80
  01a762b4  mov     dword ptr [rsp + 0x30], r8d      ; scope+0x10 = id
  01a762b9  cmp     rax, 0x10
  01a762bd  jne     0x141a7630c                       ; 掩码 != 0x10 ⇒ 对象格 = NULL
  ...                                               ; 掩码 == 0x10 才去 0x3260FF8 里按 id 解对象
  01a7630c  mov     rax, r12
  01a7630f  mov     qword ptr [rsp + 0x34], rax      ; scope+0x14 = 对象指针(本掩码下 = 0)
  01a76319  mov     r8, r15
  01a7631c  lea     rdx, [rsp + 0x20]                ; ← 本轮的 scope 结构
  01a76321  mov     rcx, r14
  01a76324  call    0x1403b1330                       ; ← 每轮的下发:子效果 × 本 scope
  01a76329  inc     esi
  01a7632b  add     rdi, 4                            ; ← 迭代推进(stride 4)
  01a7632f  cmp     esi, dword ptr [rbp + 0xc0]
  01a76335  jl      0x141a762a0
```

三条要求的指令:

| 角色 | 指令 |
|---|---|
| 列表头读取 | `0x1A762A0  mov rax,[rbx+8]`(容器基址;`rbx` 是 `0x1A8F080` 造的那个数组头) |
| 迭代推进 | `0x1A76329 inc esi` + `0x1A762B` 处的 `0x1A7632B add rdi,4`,上界 `[rbp+0xC0]`,`0x1A76335 jl` |
| 每轮的调用/写入 | `0x1A76324 call 0x3B1330`(`self, &scope, r15`);scope 三格在 `0x1A762AF/0x1A762B4/0x1A7630F` 写入 |

⇒ **循环边界 = `0x1A762A0..0x1A76335`**(函数 `0x1A76130..0x1A7643D`,slot `+0x70`)。

**③ 候选承载 `S`。** 本轮内变化、且被后续调用带进参数的只有两样:元素 **id**(`r8d`,来自
`[rdi+[rbx+8]]`)和它写进的 **scope 结构**(栈上 `[rsp+0x20]`,三格 `+0x08` mask、`+0x10` id、
`+0x14` 对象)。唯一被带进 `0x3B1330` 的是 **scope 结构的地址**(`rdx`),所以候选 `S` 取
**scope 结构里的对象格 `[scope+0x14]`**,其次才是 id 格 `[scope+0x10]`。

- 它从哪来:先由 `0x19307D0` 从 `[[0x3260BB0]+0x590]` 的 dword 向量里过滤出 id(条件是
  `[obj+0x137C] != 0`,写的是 `[obj+8]`);循环里再用掩码决定是否拿 id 去 `0x3260FF8` 里解对象。
- **本掩码(0x80)下对象格恒为 0**:`cmp rax,0x10 / jne` 分支把 `rax` 置成 `r12`(=0)。也就是说
  `every_system` 轮内下发的 scope 是 `{mask=0x80, id, obj=NULL}` —— 对象要到下一层再解。
- 旁证:`0x80` 与 §76 的谓词第 2 实参 `X`、§79 的 `a3` **同值**;本节给出它的静态出处:
  `every_system` 的 create 里 `mov edx,0x80`(`0x1A74EC8`),ctor 存进 `[obj+0x180]`。

**这一节不写的结论。** ① **不说** `S` 就是星系对象 —— 本掩码下它是 NULL,id 才是身份;
② **不说**这个槽是「运行期执行」而不是「装载期按 scope 解析」:§24.4.2 把这个虚位记成
`parse`(按静态形状),本节只证明「它按 id 列表逐轮把子效果带进 scope 结构」,**parse 还是
execute 是 §80.3 判据 1 要问的第一件事**;③ 过滤器 `[obj+0x137C]` 的语义未定(可能是
「已生成/有效」),`787` 是本节的预期分母,不是读数。
