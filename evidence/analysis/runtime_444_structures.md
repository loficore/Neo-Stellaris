# 4.4.4 Runtime Structure Verification & Architecture Correction (§1–§15)

Verified against live `stellaris.exe` 4.4.4 (pid 5172, base `0x7ff74a630000`).

> **Volume 1 of 3.** This evidence log is split across three files; the `§` numbers are unique across them.
> §1–§15 — `runtime_444_structures.md` (live hot path, detours, CEffect class map, the falsified registration chain).
> §16–§23 — `runtime_444_keyword_pipeline.md` (the static registration pipeline: driver, descriptors, thunk arrays, token allocator, class_info, consumers).
> §24–§29 — `runtime_444_c1_validation.md` (the alias/donor decision, A5 cross-validation, ABI corrections, backlog).

## 1. DB globals are live even at main menu (CONFIRMED)

Both scripted databases are fully populated at the main menu — no need to load a save to inspect them.

| DB | Global RVA | Resolves to (absolute arena ptr) | Entries |
|----|-----------|----------------------------------|---------|
| ScriptedEffectDB | `0x33746E8` | `0x9741f0` (game arena @ low addr) | **1056** (`obj+0x20` = `_Mysize`) |
| ScriptedTriggerDB | `0x32611C8` | `0x31a4f10` | (size field elsewhere; layout differs) |

**Pointer model**: the stored global qword is a *direct absolute pointer into a game-owned
arena mapped at low addresses (~0x97xxxx / ~0x31a_xxxx / nodes at ~0x2f4_xxxx–0x324_xxxx)*.
It is NOT image-relative, and NOT in the CRT heap. The game reserves its own arena region.
A detour that dereferences the global must NOT add the module base — read `[global]` and use
the value directly, guarding the low-arena address range.

## 2. BST (std::map) node layout (CONFIRMED)

Lookup walk in `GetScriptedEffect` (`0x89F960`) matches standard MSVC `std::map`:
```
DB_obj: [obj+0x18] = map head sentinel ptr  (effect);  [obj+0x88] for trigger
head:   +0x00 _Left(begin)  +0x08 _Parent(=root)  +0x10 _Right(end)  +0x19 _Isnil
node:   +0x00 _Left  +0x08 _Parent  +0x10 _Right  +0x18 _Color  +0x19 _Isnil
        +0x20 = key (uint32)          <- ascending, confirmed: 146,227,10000,10001,...
        +0x28 = value ptr             <- points to per-entry descriptor (own vtable)
```
Keys 10000+ = scripted/custom id space (matches "value range higher for scripted").
value+0x00 = descriptor vtable (imgrel ~0x2611xxx / 0x24eaab0 for effects). Name std::string
is present in the value but its exact member offset still needs pinning (saw fragments
`step_horizontal_increase`, `_left_first` near value+0x10).

## 3. ARCHITECTURE CORRECTION — no monolithic effect dispatch switch (4.4.4)

The AGENTS.md 3.x premise `effect dispatch switch-case @ 0x14180B050 (579 cases)` does **not
hold in 4.4.4**. The `effect_impl.cpp` string has 361 refs across 231 functions; the top ones
(`0x180A950`, `0x1803890`, `0x18237C0`, ...) are ~1.4–7.5KB each = **individual polymorphic
`CEffect::Execute(CEventScope*)` implementations** (they read their own member fields,
e.g. `[rdi+0x112c]`, `[rax+0x98]`, and log via `__FILE__`). Dispatch is a **virtual call**
(`call qword ptr [r8+8]` on the effect vtable), not a table switch.

Consequences for this project:
- `offsets.zig` `c_effect.OFFSET_EFFECT_ID=4080`, `OFFSET_VTABLE=1704`, and
  `id_mapper.zig`'s "IDs derived from the switch-case at 0x14180B050" are **3.x fiction** —
  there is no central id→case table to hook, and the numeric `known_effect_ids` map is not
  real. Treat all of it as unverified placeholders.
- The correct 4.4.4 extension point is the **scripted lookup functions** + their BSTs:
  - `GetScriptedEffect` @ `0x89F960`, DB global `0x33746E8`
  - `GetScriptedTrigger` @ `0x8A0450`, DB global `0x32611C8`
  Hooking the lookup (return our own template on miss) or inserting a node into the live BST
  is the viable route to new scripted effects/triggers — this is achievable without inventing
  new hardcoded keywords, sidestepping the "no new effect keyword" constraint for the
  SCRIPTED layer (mod-visible `scripted_effect { ... }` blocks, not raw DSL keywords).

## 4. Recommended next actions
1. Retarget `hooking/` + `effects/` from "dispatch switch" to "scripted lookup detour".
   Rewrite `offsets.zig` with the CONFIRMED layout above (arena, map head, node key/value).
2. Pin the name std::string member offset by walking value ptr (read a few known effect names).
3. Detour `GetScriptedEffect`/`GetScriptedTrigger`: on not-found, consult the QuickJS registry.
   OR insert nodes into the live BST at init (id key >= 10000 space).
   *(Superseded: §27.2 shows there is no "not-found" to branch on at these two — the detour
   cannot supply a template there. The BST-insert half of this advice is what Phase C1 is now
   built on, and the consumer that actually branches is `0x3B01A0`/`0x349AE0`, §23.)*

## 5. Calling convention of the scripted lookups (confirmed 2026-09-28, Frida live)

Both `GetScriptedEffect` (RVA `0x89F960`) and `GetScriptedTrigger` (RVA `0x8A0450`)
share an **identical prologue** and return a large ref struct via the MSVC x64
hidden-pointer (sret) convention:

```
;   rcx = out   — sret pointer, caller-allocated ref object
;   edx = id    — int32 requested id (-1 for name-only lookups, e.g. sentinel init)
;   r8  = name  — ptr to a wrapper object; the std::wstring key sits at wrapper+0x10
;                 (cap check: cmp qword [wrapper+0x28], 0x10 → SSO threshold)
;   miss overwrites out+0x00 / out+0x40 with null-template vtables (imgrel
;     0x24b46e0 / 0x24b9e80 paths) — hit/miss is judged from `out`, not a flag
;   prologue (both): 48 89 5c 24 10 / 48 89 4c 24 08 / 55 56 57 41 56 41 57 / 48 83 ec 60
```

**Corrected in place by §27 (2026-09-30, offline)** — the prologue and the
`wrapper+0x10` string offset hold up; three other things in this block do not.
The key is a **`std::string`, one byte per char**, not a wstring (§27.1: a byte-wise
strlen loop, and the empty `.data` holder carries cap 15 rather than wstring's 7).
`out+0x40` is an **embedded CEffect's vptr** (0x2518128, slot[1] = base Execute), not a
second name string (§27.2). And "hit/miss is judged from `out`" is **false**: both
functions write the same four words on every call and return `out` unconditionally; the
walk's only effect is the `"is overwriting an existing effect/trigger, rename it"`
warning (§27.3). The Frida note below this block — zero calls at main-menu idle — is
consistent with that: these are load-time ref builders, not per-frame getters.

Implications implemented in `src/dll/scripted/lookup_hook.zig`:
- No RIP-relative instruction within the first 14 bytes → `detour.installHook`'s
  copy-based trampoline is safe as-is for these two targets (verified by disasm).
- A Zig `callconv(.c)` fn receives rcx/rdx/r8 as its first three integer args →
  the detour needs **no asm stub**; it records `(id, name)`, forwards through the
  trampoline, then records the filled `out.vtable/id/name`.
- Stage 1 = forward-and-log only, installed via exported `LookupHookInstall`
  (explicit injector command; never DllMain); records drained via `LookupHookDrain`
  as fixed 248-byte `Entry` structs.
- Frida `Interceptor` spy armed at both functions during main-menu idle saw zero
  calls → lookups fire only when script code resolves scripted names in-game;
  runtime log capture requires actual gameplay.

## 6. Zig 0.16 Windows-target fixes discovered while wiring the detour
- `std.Thread.Mutex` no longer exists (0.16 moved Mutex to `std.Io.Mutex`, whose
  `lock` needs an `Io` context). `detour.zig` now uses a small `@atomicRmw`
  spinlock (`lockHooks`/`unlockHooks`) valid for both targets; this also unblocks
  compiling `hooking/` for x86_64-windows at all (previously it had never been
  analyzed in the DLL build).
- `std.math.min` → `@min` in `windows.allocNear`.

## 7. Runtime hot-path analysis (2026-09-28, Frida live session, in-game)

**Base correction**: live session image base = `0x7ff74a630000`. All runtime
addresses in this section re-expressed as RVAs:

| Runtime addr | RVA | Role |
|---|---|---|
| `0x7ff74c338520` | `0x1D08520` | vtable 0x24B1990 slot[3] — hot (2.24M calls / 5 min active play) |
| `0x7ff74ab65070` | `0x535070` | slot[5] — 49k / 5 min; wrapper: reads `[arg2+0x30]→+8→dword`, calls `0x7ff74C3385B0` (RVA `0x2D085B0`), calls slot[6], then **tail-jmp slot[5] = the switch below** |
| `0x7ff74ab650d0` | `0x5350D0` | **~~The effect/trigger dispatch switch~~ → a virtual named-member getter, §26.1/§28** — keyed on a stored numeric type code (`r8d`), binary-search chain (0x3b9a, 0x3656, 0x2e42, 0x2c65, 0x2a68, 0x2cd, 0x1b …). Case 0x2cd: loads string key from template+0x288, looks it up in global DB at RVA `0x325EBA0`, calls `[td+0x38]`, error-logs with source string RVA `0x24F8F70` + line 0x16a. ~~→ the `trigger:` keyword evaluator~~ (refuted: 0 direct call sites, 1 `.rdata` ref, default branch tails to the generic `0x1D092C0`) |
| `0x7ff74ae3d500` | `0x80D500` | slot[6] — tiny getter: type 0xb5 → view of `this+0x38`, 0x1b → view of `this+8`, else tail `0x7ff74C3392C0` (RVA `0x2D092C0`) — per-type field accessor, **not** Execute |
| `0x7ff74b215750` | `0xBE5750` | callee inside slot2-inner: build 0x20-byte ref + `call BE5750(self, scope, key, out, scope+0x6c8 / +0x740)` |

slot3 body (`0x1D08520`): guard-frame calls (`0x7ff74A79FDC0`, RVA `0x16FFDC0`,
edx=0x10/3 enter-leave) + recursion counter inc/dec at `[arg2+8]`, then
`mov rax,[rdi]; call [rax+0x10]` = **calls this->slot[2]** (0x22FB40 → thin
wrapper into the big function at RVA `0x7E5280`, the per-effect execute shim).

### Key conclusions
1. **GetScriptedEffect/GetScriptedTrigger (0x89F960/0x8A0450) = load-time only.**
   Confirmed true-negative: zero calls during 5 min of *active* gameplay
   (6 months game time). Scripted names are expanded at script load; runtime
   executes stored template instances.
2. The **real runtime extension surface** is the vtable-`0x24B1990` family:
   slot[3] `0x1D08520` (execute entry, hot), slot[5] `0x535070` → switch
   `0x5350D0` (keyword dispatch on stored type code).
   *(Void — corrected in place by §26.1 and closed by §28.5: the "switch" is one class's virtual
   named-member getter with a generic fallback, it has zero direct call sites, and the executor is
   §23/§24's `create()` + per-class virtuals. The slot indices in this line are also unreliable, §28.4.)*
3. **RTTI probe status**: spy armed at slot3/slot5/switch during a *paused*
   window saw zero events → simulation must be running for these to fire;
   the 4.4.4 runtime is fully quiescent when paused (no idle effect ticks).
4. `0x2D09A00`-family (`0x7ff74c339a00`) seen as tail callee of slot[2] wrapper
   `0x80D540` region → generic iterator/accessor, deprioritized.

### Stage-2 options (pending user decision)
- (a) Detour the **execute entry slot[3]** or the **switch 0x5350D0**: intercept
  execution of *existing* keywords per type code; new custom keywords still need
  template instances to dispatch to.
- (b) **Load-time BST injection**: add entries to ScriptedEffectDB /
  ScriptedTriggerDB globals (RVAs `0x33746E8` / `0x32611C8`) around script load
  (new game / `reload data`) so `my_type = { ... }` scripted definitions resolve
  from our registry — this preserves the original "new keyword" goal without
  touching per-type dispatch.

## 8. Keyword registration pipeline (2026-09-28) — **FALSIFIED; read §15–§17 for the real thing**

> Condensed 2026-09-29 to keep this file inside its line budget. Kept as the historical record of what
> was claimed from the Frida call-site reads, so later corrections stay checkable. RVAs, base of that
> session `0x7ff74a630000`.

**Claimed** load-time chain: script load (the `0x89F960` region calls `0xA78C70`, itself called from
`0x724F00` / `0x78DEEC` / `0xDDDACA` / `0x1142DA3`) → `0xA78C70` → `0x256730` → `0x265DD0` (init driver,
"one-shot guard byte" `0x337A844`) → `0xCCCEB0` ("MASTER keyword registration, ~13,000 entries") →
`0xD150A0` ("register fn") → tail callee `0xE88500`. Around it: name pool `0x2490000`–`0x2491000`, keyword table
global `0x33799C0`, "token descriptor `[array + idx*0x18]`, `.type = [d+0x20]`, `.packed = [d+0x24]`
(low 24 = index, high 8 = generation)", observed registration ids `0x33E2..0x33F7+`.

**Still holds** (each re-confirmed independently later):
- The register **signature** `rcx = descriptor slot, edx = token id, r8 = name ptr` — exactly right; §16
  re-confirmed it on the real registrar `0x1D15270`, so §8 only *mis-addressed* it.
- The chain `0x265DD0 → 0xCCCEB0 → 0xD150A0 → 0xE88500`, with `0xCCCEB0` reached from **exactly one**
  site — §15.
- The name pool range is real data, but it is a point *inside* §16's block `0x247F480..0x2494070`, not a
  separate pool; and the low-24/high-8 token packing is real — for **runtime lexer handles**, 3 sightings
  in §15.
- Runtime side, unaffected by the falsification and the reason §10 exists: base Execute `0x1D08520`
  observed 1.5M calls/40 s across 40+ effect vtables (`0x26D04C8`, `0x2532758`, `0x2522C40`, `0x2521170`,
  `0x250A4E0`, `0x25435D8`, `0x24B2530` …) and dispatches `call [this+0x10]` → slot[2] via the thin thunk
  `0x22FB40` (`sub rcx,0x40; jmp 0x1B52C0` = the real body); `0x535070`/`0x5350D0` (both in vtable
  `0x24F9900`, at +0x38/+0x40) are the scope-gated Execute variant — its 3rd arg is an 8-byte code observed
  as literal ASCII `0x6d61676573756170` = "pausage" — and the binary-search type-code switch, whose case
  `0x2cd` reads a wstring key at `[obj+0x288]` (wstr ctor `0x16BF770`), looks it up with
  `0xB6B3E0(rcx = [0x325EBA0]+8, rdx = key)` in the global DB `0x325EBA0`, and calls `[result+0x38]`;
  and on a miss logs `invalid template "%s"` (RVA `0x24F8FB8`) from `galaxy_configuration.cpp:0x16a`
  (`0x24F8F70`); these fire **only while the sim runs**. No MSVC RTTI/COL on any of it — naming must come
  from strings, not RTTI (quantified in §14).
- The name pool examples recorded then: `ringworld`, `army_maintenance`, `pop_faction_support_increase_mul`,
  `has_triggered_message`, `pre_communications_name_format`, `on_built`, `on_queued`.

**Falsified**: `0xCCCEB0` = master registrar (§15: entered once, with an already-resolved object as `a1`);
the ~13k entries = keywords (§15); `0xD150A0`/`0xE88500` as the registration writer (§15: they emit
`BIOSHIP_NO_GROWTH_UPGRADE` / operate on `BIOSHIP_GROWTH_PROGRESS`, item ids 543–544); "call site `0xD15308`
sits inside the 13k-entry block" (`0xD150A0` ends at `0xD1528F`); `0x337A844` as a registration guard (§16:
a trace-enable flag); the `[array+idx*0x18]` descriptor table and `0x33799C0` as the keyword table (§16
finds the real array: driver `0x172E50`, base `0x337B400`, stride `0x120`, 9,863 entries); and `gen<<24|index`
as anything to do with registration ids (§17: those are compile-time immediates like `mov edx, 0x2778`).
The stage-2 plan derived from it ("hook `0xD150A0` at process start, replicate its descriptor write") is
void; the live recipe is §17 + §18 + §19.

## 9. Keyword descriptor layout, the alleged extension contract (2026-09-28) — **contract void, slot shape kept**

> Same condensation note as §8. One claim here is load-bearing and independently confirmed twice
> (§10 disasm, §11 live capture): per-keyword implementation objects share a vtable shape —

```
[0] +0x00 per-keyword ctor/clone          (0x158950 / 0x6FD180 / 0x645490)
[1] +0x08 0x1D08520  shared base Execute  (the 1.5M/40 s hot function)
[2] +0x10 per-keyword Execute shim        (0x1BCD120 / 0x1BCCF30 / …)
[3] +0x18 0x535070   scope-gated Execute variant
[4] +0x20 per-keyword helper (0x1BCD020 / 0x1BCD230)   [5] +0x28, [6] +0x30 = 0x15DB30 (ret 0)
```

`0x1D08520` reads `this->vtable[2]` and calls it with the same (rcx, rdx): **base Execute dispatches into
the keyword's own slot[2]**, so a keyword is defined by that one slot and everything above it (scope guard
`0x16FDC0`, recursion counter, ctx marshalling) is provided by the engine.

**Void parts.** The instance field map (`+0x08` token id, `+0x0c` 2nd token, `+0x12/14/16` flags, `+0x18`
arg token) and the `shim_execute` ctx-marshalling contract were both read out of the single shim
`0x1BCD120`; §11 and §13 show those offsets carry flags, `0x7fff` sentinels and pointer low-halves
depending on the class, so "the keyword id lives at `self+0x08`" is **not** a general rule and the route-A
cheap path keyed on it is invalid as written. The "registration contract from `0xD150A0`/`0xE88500`"
(keyword map at `reg_obj+0x450`, entries stride `0x110`, packed handle `+0x990`, explicit index `+0x97c`,
generic keyword vtable `0x33720E8`, searched token `0x220`) rides on §8's falsified chain — §15 records
that the three field anchors *do* appear verbatim in `0xCCCEB0`'s body but flags that as **circular** (§9
was derived from that same chain), §16 corrects the stride to **`0x120`**, and §10 shows `0x33720E8` sits in
uninitialized `.data` and is runtime-written data, not a vtable.

Practical consequences as stated then: cheap path = register a scripted effect and detour `0x1D08520`
comparing `self+0x08` against our id (invalid, above); full path = allocate a descriptor + our own vtable
and call `0xD150A0` after `0xCCCEB0`, "needs the 0x110-byte entry layout mapped first" (both addresses and
the stride wrong). Superseded by §17–§19.

## 10. base Execute hook surface, verified for the log-only detour (2026-09-28)

Target `0x1D08520` fully disassembled (capstone over the shipped exe, 48 bytes):

```
+00  mov  [rsp+8], rbx        ; 48 89 5C 24 08   arg1 rcx = keyword instance, arg2 rdx = ctx
+05  push rdi                 ; 57
+06  sub  rsp, 0x20           ; 48 83 EC 20
+0a  mov  eax, [rdx+8]        ; 8B 42 08         ctx+0x08 = signed recursion counter
+0d  mov  rbx, rdx            ; 48 8B DA
+10  mov  rdi, rcx            ; 48 8B F9
+13  test eax, eax / js +0x32 ; 85 C0 78 32
+19  mov  edx, 0x10           ; BA 10 00 00 00   guard frame enter
+1e  mov  rcx, rbx / call 0x16FDC0
...  inc [rbx+8]; mov rdx,rbx; mov rcx,rdi; mov rax,[rdi]; call [rax+0x10]  (+57)
     dec [rbx+8]; ... guard leave ... mov rbx,[rsp+0x30]; add rsp,0x20; pop rdi; ret (+8f)
```

Key facts for hooking:
1. **Exactly two integer args.** No r8/r9 use, no `[rsp+0x28]` stack parameter, no
   meaningful return value (rax at `ret` is an internal leftover) → a Zig
   `callconv(.c) fn(u64,u64,u64,u64) u64` detour forwards transparently.
2. **Trampoline-safe**: the first 16 bytes (`5+1+4+3+3`) contain no RIP-relative
   instruction, so detour.installHook's copy-based trampoline is correct here. The 32-byte
   prefix through the `call` opcode is displacement-free → a stable, ASLR-invariant
   build fingerprint (implemented in `src/dll/scripted/exec_hook.zig`).
3. `call [rax+0x10]` at +0x57 confirms §9: base Execute dispatches the instance's
   **vtable slot[2] shim** with the same (rcx, rdx). The counter at `ctx+0x08` is
   inc'd before and dec'd after that call, so it is a live depth indicator a detour can
   read without touching it.

### CORRECTION to §9: `0x33720E8` is NOT the generic keyword vtable
Live read (pid 16768, base `0x7ff74a630000`) of 8 qwords at `0x33720E8` returned
`0x0, 0x7a1200, 0x1e8480, 0x3d0900, 0x989680, 0xdbba0, 0xf4240, 0x3b9aca00` — small
integers / relative offsets, not code pointers. Statically the same RVA sits in the
**uninitialized span of `.data`** (va_end 0x37356d4, raw size only 0xd9200), so it is
runtime-written data, not a vtable. Drop the "descriptor[1] = generic vtable at
0x33720E8" idea; use the code fingerprint for provenance instead.

### PE section table (measured, for pointer classification)
`.text 0x1000+0x2390710`, `.rdata 0x2392000+0x5c16ea`, `.data 0x2954000+0xde16d4`
(raw only 0xd9200 — the tail is BSS), `.pdata 0x3736000+0x17ea94`, `_RDATA 0x38b5000`,
`.rsrc 0x38b6000`, `.reloc 0x38c9000+0x5d7cc` → module span ends at **RVA 0x39267cc**.

### Implemented
`src/dll/scripted/exec_hook.zig` (log-only, installed by command only): counters, a
96-slot histogram of the shim each instance dispatches to, a 1024-entry 1-in-512 sampled
ring (instance vtable RVA, shim RVA, token id `self+0x08`, 2nd token, flags, arg token,
ctx counter, ctx `+0x10/+0x18/+0x30`). Exports: `ExecHookInstall/Uninstall/Stats/Drain/
Histogram/Reset/Layout` (Layout packs the record sizes so `scripts/execspy.js` cannot
parse a stale layout). Driver flow: pause game (runtime is quiescent → no thread is
inside the 16-byte patch window) → install → resume 30-60 s → pause → Stats/Histogram/
Drain → uninstall → verify. `ExecHookVerify` (0 = engine bytes intact) is what makes the
uninstall claim checkable; the run before it existed proved it was necessary — see §12.

## 11. First live capture through the hook (2026-09-28, 30 s of active simulation)

Driver: `scripts/execspy.py` (pause-gated install, activity-gated observation).

| Metric | Value |
|---|---|
| pre-install Frida probe | 0 calls / 1.5 s → simulation paused, patch window safe |
| `ExecHookInstall` | 0, `patch_size` 16 (the predicted decode) |
| calls while installed | 2,914 in ~30 s (≈97/s in this scene; earlier sessions saw ~37k/s in a large one) |
| ring records | 5 (1-in-512 gate), `invalid` 0, `hist_overflow` 0 |
| distinct shims | 2 |

Shims observed (counts were **sample hits**, not call frequencies — fixed since):

| shim RVA | instance vtable RVA | sample hits | predicted in §9? |
|---|---|---|---|
| `0x1BCCF30` | `0x26D04C8` | 4 | yes |
| `0x1BCD120` | `0x2521170` | 1 | yes |

Both confirm §9's core claim: base Execute hands control to the **instance's own vtable
slot[2]**, so a keyword is defined by that one slot.

### The §9 instance field map does NOT generalize
Records from these two classes:

```
token_id (+0x08)   = 1                 # not a token id — a flag/count for these classes
second_token(+0x0c)= 32767 (0x7fff)    # sentinel
flag_12    (+0x12) = 32767 (0x7fff)    # same sentinel
arg_token  (+0x18) = 7231 / 1288785832 # the latter is a pointer's low half, not a token
ctx_counter(+0x08) = 0 / 1             # recursion depth, behaves as documented
ctx_30             = 0x7ff74ab1c458-ish (module pointer) # behaves as documented
```
So `+0x08 … +0x18` are **class-specific**. §9's map was read out of the `0x1BCD120` shim's
own field copies and cannot be reused as a generic "keyword id lives at self+0x08" rule.
Route B must derive the layout per registered class (from its shim's disassembly), and the
route-A cheap path (identify our keyword by `self+0x08` token id) is **not valid as written**.

Reliable, class-independent identifiers per invocation: `self` vtable RVA + slot[2] shim
RVA. That pair is what the histogram keys on, and it is enough to route a detour.

## 12. Leftover-patch incident (2026-09-29) — why uninstall now verifies

After the §11 capture, `ExecHookUninstall` returned 0 (success) while the engine's hottest
function stayed **patched**: a later install refused with -4, and `peek` showed

```
base+0x1D08520:  FF 25 00 00 00 00 90 0A 1C 84 FC 7F 00 00 90 90   (14-byte JMP + 2 NOPs)
                 -> absolute target 0x7ffc841c0a90, inside our DLL's mapping
```
`exec_hook.uninstall()` was `detour.removeHook(&h) catch {}` — every restore error swallowed,
and the return code said 0 regardless. The game kept running paused; the moment it was
resumed with the DLL FreeLibrary'd, that JMP would have jumped into unmapped memory (crash).

Recovery + hardening:
1. `scripts/restoreexec.py` — probes quiescence with an independent Interceptor, then writes
   the 16 position-independent prologue bytes back through Frida `Memory.patchCode`; re-peeks
   and compares with `EXPECTED_CODE`. Outcome: `RESTORED`, 32-byte fingerprint matches again.
   `scripts/peekexec.py` is the read-only diagnostic (works with no DLL loaded).
2. `install()` snapshots the target's first 32 bytes into `saved_code` before patching, and
   `uninstall()` restores from that snapshot itself instead of trusting `removeHook`, then
   requires `fingerprintMatches()` — otherwise `ExecHookUninstall` returns **-6**.
3. `detour.installHookArmed(target, detour, prearm)` publishes the trampoline **before** the
   patch goes live, closing a window where the patch was active but `orig` was still null and
   the detour would have dropped the call (returning 0 without executing the engine).
   `installHook` remains as a 2-arg wrapper. `orig` is cleared only after the restore.
4. Driver prints `verify` + `stats` immediately after install (verify must be -1 = our JMP is
   in place, `patch_size` must be 16) and `ExecHookVerify` after uninstall.

**Standing rule for this project**: never FreeLibrary the DLL without `ExecHookVerify -> 0`;
`scripts/nsunload.py` is only safe after that check.

## 13. Complete shim census (2026-09-29, ~60 s of active simulation)

Two runs. The first (315,302 calls) filled the 128-slot histogram table and reported
`hist_overflow: 107967` — its "128 distinct shims" was a truncation artifact, not a
measurement. `HIST_LEN` went to 1024 (16 KB of `.bss`, still no allocation in the detour)
and the second run is the first census with **no overflow**, so its counts are complete:

| Metric | Value |
|---|---|
| `ExecHookInstall` | 0, `patch_size` 16 |
| calls while installed | 316,468 over ~60 s (≈5,300/s in this scene) |
| distinct shims | **291** (`hist_overflow` 0) |
| ring records | 618 (1-in-512), `invalid` 473 = **0.15 %** |
| uninstall | waited for silence (`idle at calls=319048`) → `ExecHookUninstall` 0 → `ExecHookVerify` **0** |

The pause-gated uninstall behaved for the first time here: reading Stats/Histogram/Drain is
safe while the sim runs, so only the byte-restore is gated now.

Top of the census (25 of 291 shims carry 278,209 of the calls = **88 %**; the other 266
share 38,259):

| shim RVA | instance vtable RVA | calls |
|---|---|---|
| `0x33D410` | `0x24B3050` | 54,003 |
| `0x33C940` | `0x24C69E8` | 36,581 |
| `0x34DAD0` | `0x24B3690` | 32,438 |
| `0x230990` | `0x24B1C88` | 28,676 |
| `0xBD4120` | `0x2541268` | 23,342 |
| `0xDE0050` | `0x250E4B0` | 21,396 |
| `0xA67200` | `0x24EC7C8` | 11,405 |
| `0x6EC640` | `0x25097C0` | 10,068 |
| `0x7FBE60` | `0x24B8468` | 8,762 |
| `0xE6C230` | `0x2552788` | 8,334 |
| `0x3CAEF0` | `0x24EC788` | 7,530 |
| `0x6C04B0` | `0x2508678` | 4,052 |
| `0xDE0430` | `0x254F720` | 3,968 |
| `0xD05820` | `0x2546C98` | 3,875 |
| `0xB62130` | `0x2517180` | 2,446 |
| `0x8D3150` | `0x24B5480` | 2,442 |
| `0xE99C10` | `0x254A190` | 2,165 |
| `0xE586D0` | `0x24C52B0` | 2,096 |
| `0xCC4220`/`0x974840`/`0xDE40C0`/`0xE98720`/`0xE58D80`/`0xE9B580`/`0xE96E90` | `0x25460F0`/`0x250E188`/`0x254FA18`/`0x25531E8`/`0x2551620`/`0x2553178`/`0x2553140` | **2,090 each** |

### What this changes about the plan
1. **The §9 `0x1BCCF30`/`0x1BCD120` scripted-effect family is not in the hot set at all.**
   What dominates base Execute is a set of generic engine classes (`0x24B3050`,
   `0x24C69E8`, `0x24B3690`, `0x24B1C88`, vtables clustered in `0x24B…0x255`), i.e. the
   always-on per-frame condition/flag evaluation, not scripted effect blocks. A QuickJS-side
   rule engine has to attach to *those* classes (or to base Execute itself keyed by shim RVA),
   not only to the scripted-effect templates §9 described.
2. **Exact repeated counts are a data-driven iteration signature.** Seven distinct shims
   executed *exactly* 2,090 times in one window — the same collection walked once per pass.
   A 4.4.4 galaxy is ~2,000-2,500 systems, so this is the prime candidate for "the engine's
   per-system loop", which is exactly where a trade-node / chokepoint scoring rule belongs.
   Next capture should correlate this number against the live system count (change scene,
   change galaxy size) before claiming it.
3. 291 (vtable, shim) pairs is small enough to enumerate and name offline: IDA can resolve
   each shim's disassembly into a keyword/class label once, giving a routing table for the
   detour instead of per-install reverse engineering.

### `self+0x08 … +0x18` re-confirmed as class-specific (more evidence for the §11 correction)
From the 618 records of this run, the same offsets mean different things per shim, and one
shim's meaning shifts with the call path:

```
0x33D410  token_id 0  flag_* 0        arg_token = 73 / 97 / 18774 / 3487937216 / 1919640399
                                      # small ints and pointer low-halves in the SAME field
0x34DAD0  token_id 10465035 / 11970240   flag_12 65518 / 65517   flag_14/16 = 255  arg_token 0
0xE6C230  token_id 4294967295 (-1)       second_token 2402   flag_12 19630  flag_14 247
0x33C940  token_id 0  second_token 0|1   arg_token 1162696014 / 1162690894 / 1163018576
ctx_counter (+0x08 of ctx) 2..9, and 3/5/6/8/9 occur for the *same* shim -> per-path depth
ctx_ptr    constant 0x0FFCFD00            # a stack address, not a heap scope
ctx_10     constant 8813261104 in this run (8813260752 in the previous one)
ctx_30     0x0 in every record here, a module pointer in the §11 run
```
So neither `self`'s field layout nor `ctx`'s is uniform: `ctx` contents depend on the
caller path, and `self+0x08…+0x18` depend on the concrete class. Any route that reads a
"keyword id" out of `self` must first decode that class's shim. The only field that behaved
as documented across both runs is the recursion counter at `ctx+0x08`.

`invalid` is stable at 0.15 % across two independent captures (the 2,914-call run and
473/316,468) — the plausibility guard rejects a constant tiny tail, and those records are
zero-filled but still counted, so `calls` remains exact.

## 14. The full CEffect class map, enumerated offline (2026-09-29)

The census dump answered a question that needed no game time. `scripts/peekexec.py`-style
raw reads of the census' vtables (`scripts/rttibatch.py --dump 0x24B3050`) show the table
shape directly:

```
vtable 0x24B3050:  slot0 0x1401B3EA0   slot1 0x141D08520 (= base Execute)   slot2 0x14033D410
```

`slot[1]` **is** the hooked function and `slot[2]` is the address the live recorder reported
as that class's shim. So the vtable is the classical `CEffect` pair — inherited
`Execute` in slot 1, the class's own `ExecuteActual` in slot 2 — which is exactly what
`call [rax+0x10]` inside base Execute consumes. Confirmed against external research
("`CEffect::ExecuteActual(CEventScope*)` — virtual, every effect enters here").

That makes the whole population enumerable from the file with no attach and no patching:
`scripts/rttibatch.py --effects` scans `.rdata` for 8-aligned qwords equal to
`image_base + 0x1D08520` whose neighbours are both in `.text`.

| Result | Value |
|---|---|
| vtables with base Execute at slot[1] | **1,805** |
| distinct `ExecuteActual` bodies among them | 543 (classes share templated implementations) |
| live census rows explained | **25 / 25** — every top-25 vtable is in the map and its slot[2] equals the observed shim RVA |
| artifact | `evidence/xrefs/ceffect_vtable_map_4_4_4.txt` (vtable, slot0, ExecuteActual per line) |

### What this settles
1. **The hook is on the right door.** 1,805 effect classes, one dispatch point, and a static
   table that predicts the live target. Adding our own class means building a vtable with the
   same shape (slot1 = base Execute, slot2 = our `ExecuteActual`) and registering instances of
   it — the map is the template, and the recorder can now tell us whether our instance is
   reached, by shim RVA, with no new instrumentation.
2. **Route B's registry key is now bounded**: 1,805 known classes vs 291 observed hot ones.
   Anything outside the map is either a non-CEffect class reaching base Execute (none seen) or
   a class we added.
3. **RTTI is not available the way `scripts/rtti_check.py` assumed.** Across all 1,805 vtables
   (`scripts/rttibatch.py --col`): 1,621 have a **.text** pointer at `vtable[-8]` (another
   vtable slot), 183 land outside any section, 1 points into `.rdata`. A CompleteObjectLocator
   is never there, so `vtable[-8] -> COL -> TypeDescriptor` cannot name this family — the build
   has RTTI off for it. (The same check "succeeds" with a plausible-looking string for 18 of
   them; those are garbage reads, not names.) That kills `scripts/rtti_check.py`,
   `rtti_check2.py` and `rtti_offline.py`; naming has to come from string references inside each
   `ExecuteActual` body or from the keyword registration table (§8), not from RTTI.
   First pass at `--strings` over the hottest bodies yields almost nothing to work with
   (`0x33D410` cites `"Unreadable String"`, `0x34DAD0` cites `"%lld"`, the rest have no
   rip-relative string in their first 0x400 bytes), which says these are small generic
   implementations — the keyword name lives in the *instance*, not the code.


### Next, from this map (all offline unless noted)
- Name the hot bodies by scanning each `ExecuteActual` for `lea r, [rip+d]` string refs and
  matching them against the `effect_impl.cpp` / keyword string clusters (§8's `0x173C30`
  region registers keyword strings; a body that cites a keyword name is that keyword's class).
- Correlate the seven 2,090-call shims from §13 against the same cluster: if they belong to one
  pass, their bodies will sit near each other in `.text` (0xDE40C0, 0xE98720, 0xE58D80,
  0xE9B580, 0xE96E90, 0xCC4220, 0x974840 are already clustered in 0xE5…0xE9).
- Live (needs one more paused install): driver now prints all 291 rows, so the next capture
  gives the full census to join against the 1,805-entry map.

## 15. Local IDA headless is usable; §8/§9's registration chain is FALSIFIED (2026-09-29)

IDA MCP now opens this exe headless on Linux with no license gate — the "本机 IDA 不可用"
blocker in PLAN §3 is gone. Session `f3ea6101`, imagebase `0x140000000`, 103,000 functions,
`hexrays_ready: true`, string cache 196,503 entries.

**IDB quality caveat (cost me several detours):** this is a *fresh* IDB built from the exe, not
the Windows `.i64`. Function *bounds* are right, but Hex-Rays frequently returns a 5-byte
`JUMPOUT` stub. `mark_cfunc_dirty(ea, True)` fixes some (base Execute at `0x141D08520`), and the
rest need `del_func` + `add_func` + `plan_and_wait` before decompiling (`0xCCCEB0`,
`0xD150A0`, `0xE88500` all needed it). At least one pre-existing `func_t` was corrupt:
`0x140E88500` reported size 5,301,002,666 bytes before rebuild, 716 after. Do not read a
`JUMPOUT` as "no function here".

### What held up
`0xCCCEB0` is confirmed as a driver walking ~13k entries, and **all three §9 field anchors
appear verbatim in its body**: container ref at `obj+0x450` (1104), explicit index at `obj+0x97c`
(2428), packed token at `obj+0x990` (2448). The map it walks matches §9 exactly: array at
`[c+0x20]`, count at `[c+0x2c]`, **entry stride 272 = 0x110**. Token→object resolution goes
through globals `qword_14325EF00` / `qword_143260FD0`: 16-byte buckets, array at `[g+0x18]`,
count at `[g+0x20]`, index = low 24 bits of the packed id (`& 0xFFFFFF`), then a full-word
equality check. That is independent confirmation of A3's `gen<<24 | index` packing from the
decompiler side, not from cap.py.

### What did NOT hold up
`0xD150A0` and its tail callee `0xE88500` are **not the keyword-registration writer**. Decompiled
(`evidence/disasm/a2_register_fn_0xD150A0.c`): `0xD150A0` is a bounded-container push helper that
emits the localization key `BIOSHIP_NO_GROWTH_UPGRADE` when the container can't grow — and that
string's only xref (`0x140d15181`) is genuinely inside the function (size `0x1ef`), so it is not
a boundary artifact. `0xE88500` is game logic operating on `BIOSHIP_GROWTH_PROGRESS` / item ids
543–544. Neither writes a 0x110 descriptor field. So §8's "register fn: rcx = buffer obj,
edx = token id, r8 = name ptr" and §9's "Registration contract (from 0xD150A0 / 0xE88500)" are
both wrong; they were inferred from dynamic call sites without a decompiler view. §9's *offsets*
survive, its *call chain* does not.

### Consequence for Phase A
The 0x110 entry field table (A2) cannot be built by following `0xD150A0`. Also, the name pool
range from §8 is real (`pop_faction_support_increase_mul` sits at `0x142490410`, inside
`0x2490000`–`0x2491000`) but **has zero code xrefs, at the string and at the base address** — the
pool is reached only through computed addresses, so "who registers keyword X" is not answerable
by xref walking. Next discriminator should come from the consumer side: `0xCCCEB0`'s own id array
at `[a1+0x320]` / count at `[a1+0x32c]`, i.e. find who *fills* that array, instead of chasing a
registration writer that may not exist as a distinct function.

### Call-graph correction via offline scan (`scripts/find_refs.py`, 2026-09-29)

IDA recorded **zero** xrefs to `0xCCCEB0` and to the name pool — because `auto_analysis_ready:
false`: global flow analysis never ran on this fresh IDB, so cross-references simply are not
populated. Pumping `auto_make_step` over `.text` drains at ~42k items/s yet had not emptied the
queue after 2.75M steps, and a range-scoped `plan_and_wait` on a large function wedged the IDA
main thread (785 s and counting). Do not use `plan_and_wait` on whole functions in this IDB.

Hence a standalone PE scanner: `scripts/find_refs.py <rva>...` linear-sweeps executable sections
for `call/jmp rel32` and `lea reg,[rip+d]`, decoding hits with capstone. Full `.text` sweep is
~13 s and needs no IDA at all. Results:

| Target | Call sites found |
|--------|------------------|
| `0xCCCEB0` | **exactly one** — `0x266D3D` (inside §8's `0x265DD0` init driver) |
| `0xD150A0` | `0xCCD09E` (inside `0xCCCEB0`), `0xD1B0CB`, and `0xD15308` |
| `0xE88500` | `0xD15269` (inside `0xD150A0`) |

Two consequences. First, §8's "call site `0xD15308` sits inside the 13k-entry block" is wrong:
`0xD150A0` spans `0xD150A0`–`0xD1528F` (size `0x1EF`), so `0xD15308` is past its end, in the
following function. Second, the real chain is `0x265DD0 → 0xCCCEB0 → 0xD150A0 → 0xE88500`, a
single-caller path whose leaf emits `BIOSHIP_GROWTH_PROGRESS`. A single call site is still
consistent with a master registration routine, but the leaf's game-logic strings are not — so the
"~13,000 entries = keywords" reading is now the open question, not an established fact. The §9
offset anchors that the decompiler confirmed may themselves have been *derived from this same
chain*, which would make the agreement in §15 circular; treat `+0x450`/`+0x97c`/`+0x990` as
unverified until seen from an independent path.

Note: `find_refs.py` initially scanned only 0x5D800 bytes because the section tuple was unpacked
into `vs` while the body used `rawsz`, leaking the previous loop's last value (`.reloc`'s size).
Fixed; the 13 s full-section runtime is the tell that it is actually sweeping.

### The sole call site refutes "0xCCCEB0 = master keyword registration" (2026-09-29)

`sub_140265DD0` will not decompile in this IDB (`Decompilation failed at 0x14026639c`), so the
call site was disassembled offline with capstone instead. The 9 instructions before
`call 0xCCCEB0` perform a **complete token→object resolution**:

```
266ce2: mov  eax, [rbx+0x430]          ; packed token
266ce8: cmp  qword [rip+0x2ffa2e8], 0  ; -> RVA 0x3261FD8 (db global)
266cf2: mov  edx, eax
266cf4: and  edx, 0xFFFFFF             ; low 24 bits = index   (A3 packing, 3rd independent sighting)
266cfa: mov  rcx, [rip+0x2ffa2d7]      ; -> RVA 0x3260FD8
266d01: cmp  edx, [rcx+0x20]           ; count at +0x20
266d0b: mov  rdx, [rcx+0x18]           ; bucket array at +0x18
266d0f: mov  rcx, [rdx+rdi*8+8]        ; 16-byte buckets, payload at +8
266d19: cmp  [rcx+0x20], eax           ; full-word packed-id verification
266d1e: mov  rcx, [rip+0x2ff866b]      ; fallback -> RVA 0x325F390 == qword_14325F390
266d3d: call 0xCCCEB0                  ; rcx = the RESOLVED OBJECT
```

The fallback global `0x325F390` is the same `qword_14325F390` that appears in `0xD150A0`'s
decompiled body, so the two sites are confirmed to share one token database.

Conclusion: `0xCCCEB0` is entered **with an already-resolved object as `a1`**, from a single site,
in a context that reads `[rbx+0x430]` as a token. That is runtime object handling, not a startup
loop registering ~13,000 keywords. §8's headline ("MASTER keyword registration (~13,000 entries)")
should be treated as **unconfirmed / probably wrong**, and with it the Phase A premise that the
registration pipeline can be read out of `0xCCCEB0`/`0xD150A0`. The `[a1+0x320]` / `[a1+0x32c]`
array and the `+0x450`/`+0x97c`/`+0x990` fields are still real observations about this object, but
they now describe *some* engine object with a token-keyed 272-byte-entry map — not a proven keyword table.

`0xCCCEB0` and the name-pool base also have zero IDA xrefs purely because global flow analysis
never ran (`auto_analysis_ready: false`); `plan_and_wait` blocks on the **whole** auto queue, not
the requested range, which is what wedged the IDA main thread for 785 s. Avoid it on this IDB.
