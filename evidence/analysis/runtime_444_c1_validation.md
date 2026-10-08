# 4.4.4 C1 validation and corrections — offline evidence (§24–§30)

> **Volume 3 of 3.** This evidence log is split across three files; the `§` numbers are unique across them.
> §1–§15 — `runtime_444_structures.md` (live hot path, detours, CEffect class map, the falsified registration chain).
> §16–§23 — `runtime_444_keyword_pipeline.md` (the static registration pipeline: driver, descriptors, thunk arrays, token allocator, class_info, consumers).
> §24–§30 — `runtime_444_c1_validation.md` (the alias/donor decision, A5 cross-validation, ABI corrections,
> backlog, the fallback settled as an error-view builder, and the token DB's `id → name` table).

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
   the refcounted tags and ends in `default: abort()` (quickjs.c:6571-6572), so
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
`1+1` (the pending exception is moved out by `c2_clear_pending_exception`,
quickjs.c:7406-7413, so the gate is dispatchable more than once per instance);
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
#    expect: 3ad4433ea75fe893d5771e1f63e3ffed75a417f58f6190966077ff17b15a3cac

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
