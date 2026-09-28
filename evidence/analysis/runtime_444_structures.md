# 4.4.4 Runtime Structure Verification & Architecture Correction

Verified against live `stellaris.exe` 4.4.4 (pid 5172, base `0x7ff74a630000`).

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
| `0x7ff74ab650d0` | `0x5350D0` | **The effect/trigger dispatch switch** — keyed on a stored numeric type code (`r8d`), binary-search chain (0x3b9a, 0x3656, 0x2e42, 0x2c65, 0x2a68, 0x2cd, 0x1b …). Case 0x2cd: loads string key from template+0x288, looks it up in global DB at RVA `0x325EBA0`, calls `[td+0x38]`, error-logs with source string RVA `0x24F8F70` + line 0x16a → the `trigger:` keyword evaluator |
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

## 8. Keyword registration pipeline (2026-09-28, confirmed — the extension point)

Chains below are **RVA** (image base this session: `0x7ff74a630000`).

### Load-time registration
```
script load (0x89F960 region calls 0xA78C70)
  → 0xA78C70            (called from 0x724F00 / 0x78DEEC / 0xDDDACA / 0x1142DA3 …)
  → 0x256730
  → 0x265DD0            init driver, one-shot guard byte at RVA 0x337A844
  → 0xCCCEB0            MASTER keyword registration (~13,000 entries)
  → 0xD150A0            register fn:  rcx = buffer obj, edx = token id, r8 = name ptr
                          (call site 0xD15308 sits inside the 13k-entry block;
                           observed token ids 0x33E2..0x33F7+)
Keyword name pool:      RVA 0x2490000-0x2491000 ("ringworld", "army_maintenance",
                        "pop_faction_support_increase_mul", "has_triggered_message",
                        "pre_communications_name_format", "on_built", "on_queued" …)
Keyword table global:   RVA 0x33799C0 →  [g] = heap array, [g+8] = count
Token descriptor:       [array + idx*0x18]; .type = [d+0x20], .packed = [d+0x24]
                        (low 24 bits = index into [g+0x10] array, high 8 = generation)
```

### Runtime execution (active simulation only; zero calls when paused)
```
0x1D08520  = generic virtual Execute(this=effect obj, arg2=&scope ctx on stack)
             observed 1.5M calls / 40 s across 40+ distinct effect vtables
             (2532758, 26D04C8, 2522C40, 2521170, 250A4E0, 25435D8, 24B2530 …)
  └→ calls [this+0x10] → 0x22FB40 (thunk: sub rcx,0x40; jmp 0x1B52C0 real body)
0x535070   = sibling Execute variant; tail-jmp [vt+0x28]; 3rd arg = scope type
             8-byte code, observed literal ASCII: 0x6d61676573756170 = "pausage"
0x5350D0   = dispatcher switch, keyed on stored numeric type code
             case 0x2cd: wstring key at [obj+0x288] → wstr ctor 0x16BF770
                         → lookup 0xB6B3E0(rcx=[0x325EBA0]+8, rdx=key)
                         → call [result+0x38]; miss logs
                         "invalid template "%s"" (RVA 0x24F8FB8) from
                         galaxy_configuration.cpp:0x16a (RVA 0x24F8F70)
NOTE: 0x24F9900 is the vtable containing both 0x535070 (+0x38) and 0x5350D0 (+0x40).
RTTI: this binary has NO MSVC RTTI/COL headers on these vtables (verified statically)
      — class identification must use behavior + string pools, not RTTI.
```

### Stage-2 conclusion
New *hardcoded* keywords are reachable by registering into the same table the engine
uses at load: call `0xD150A0` (or replicate its descriptor write) after `0xCCCEB0`
runs, with a free token id + a name from/added to the string pool, and a descriptor
whose type slots route execution into our own handler. Next step: hook `0xD150A0` at
process start (before init) to dump `rcx` buffer layout + per-field writes.

## 9. Keyword descriptor layout — the actual extension contract (2026-09-28)

Per-keyword implementation object vtable (observed rels `0x26D04C8`, `0x2532758`,
`0x2522C40`, … all share this shape):

```
[0] +0x00  per-keyword ctor/clone              (e.g. 0x158950, 0x6FD180, 0x645490)
[1] +0x08  0x1D08520  = shared base Execute    ← the 1.5M/40s hot function
[2] +0x10  per-keyword Execute shim           (0x1BCD120 / 0x1BCCF30 / …)
[3] +0x18  0x535070   = scope-gated Execute variant
[4] +0x20  per-keyword helper                 (0x1BCD020 / 0x1BCD230)
[5] +0x28  0x15DB30   (ret 0 stub)
[6] +0x30  0x15DB30
```

Instance field map (from shim `0x1BCD120`) — **SUPERSEDED, see §11: live records from other
keyword classes do not fit this map**, so treat these offsets as per-class hypotheses:
```
+0x08 dword  script token id / keyword id   (0x1f3 = 499 in observed sample)
+0x0c word   second token id                (0xc7 in 0x1BCCF30 sample)
+0x12 word, +0x14 byte, +0x16 byte         flags
+0x18 dword  argument / parameter token
```

Shim contract (verified by disasm of `0x1BCD120`):
```c
void shim_execute(EffectObj* self /*rcx*/, ExecCtx* ctx /*rdx*/) {
    ctx->vtbl   = &descriptor_vtable;        // [rsp+0x20]
    ctx->field8 = self->+0x08;               // token id
    ctx->fieldC = self->+0x0c; ctx->field12/14/16/18 = ...
    ctx->self   = self;
    ctx->slot1  = &0x1D08520;                // vtable[1]
    base_execute(ctx /*as this*/, self);     // = 0x1D08520, which does:
                                             //   call [ctx->vtbl + 0x10] → THIS shim (recurse)
    // or, if slot1 != 0x1D08520: call [vtbl] slot directly
}
```
`0x1D08520` reads `this->vtable[2]` and calls it with the same two args — i.e. **the
base Execute dispatches into the keyword's own vtable[2] shim**. Therefore a new
keyword only needs a descriptor whose vtable[2] (and optionally [0]/[4]) are ours;
everything above it (scope guard `0x16FDC0`, recursion counter, ctx marshalling)
is provided by the engine.

Registration contract (from `0xD150A0` / `0xE88500`):
```
reg_obj->+0x450  = keyword map container   (entries 0x110 bytes, array at [c+0x20],
                                            count at [c+0x2c])
reg_obj->+0x990  = packed (gen<<24 | index) token handle
reg_obj->+0x97c  = optional explicit entry index
0xE88500(rdx=out descriptor*, r8=map, r9=name_obj, ...):
    *out = vtable at RVA 0x33720E8          // engine's generic keyword vtable
    token 0x220 (544) is the name/`type` token id it searches for
```

### Practical consequence for QuickJS integration
1. **Cheap path (recommended first)**: register `my_qjs_effect` as a *scripted*
   effect via the normal `common/scripted_effect` pipeline (tokens exist:
   `on_built`, `has_triggered_message`, `trigger:` …) and detour `0x1D08520`
   (read `ctx+0x10` → `self->+0x08` token id, compare with our id) to hand
   execution to QuickJS. Zero binary patching, one hook point.
2. **Full path**: allocate a descriptor + our own vtable with a Zig `callconv(.c)`
   `slot2` shim and call `0xD150A0`/`0xE88500` after `0xCCCEB0` has run
   (one-shot guard byte at RVA `0x337A844`), producing genuinely new hardcoded
   keywords. Needs the 0x110-byte entry layout fully mapped first.

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
