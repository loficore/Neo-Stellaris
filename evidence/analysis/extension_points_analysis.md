# DLL Hook Extension Points Analysis

**Binary**: `stellaris.exe` (Clausewitz "augustus")
**Task**: T7 — Identify DLL hook extension points from T4/T5/T6 evidence, compared against stellarstellaris-win patterns.
**Sources**: `effect_dispatch_switch_cases.md`, `registration_functions_analysis.md`, `string_to_id_registration_analysis.md`, AGENTS.md, stellarstellaris-win README + `hooking_common.cpp`.

---

## 0. stellarstellaris-win Hook Pattern (baseline for comparison)

From the project README and `src/dll/hooking_common.cpp`:

- **Targets**: virtual dispatcher/execution methods called at runtime — `CEffect::ExecuteActual`, `CTrigger::Evaluate`/`ExecuteActual`, `CRandomInListEffect::ExecuteActual`, `CEveryInListEffect::ExecuteActual`, `COnActionDatabase::PerformEvent`, `CToken` internals (investigation), `CEvent::ExecuteActual`.
- **Technique**:
  - 5-byte `E9 rel32` relative jump installed at target entry via `memcpy` (khalladay hooking-by-example / minhook-style **trampoline detour**).
  - `VirtualProtect(func, 1024, PAGE_EXECUTE_READWRITE)` before write.
  - Original first 14 bytes copied to a nearby executable page (`AllocatePageNearAddress`) as the trampoline.
  - A pre-payload block saves argument registers, pushes the real jump target to a TLS stack (`PushAddress`), restores regs, then absolute-jumps to the payload `WriteAbsoluteJump64`.
  - Payload calls the original through the trampoline, preserving ABI.
- **Versioning**: VA tables maintained per game version for 3.4.5–3.7.4 (`address_helper.cpp`), plus `assembly_patches.cpp` for surgical in-place patches.
- **Key lesson for this task**: *All* successful stellarstellaris-win hooks are on **runtime per-call virtual dispatch** (ExecuteActual/Evaluate/PerformEvent). The project **never** registers new hardcoded effect/trigger keywords; it only intercepts the existing execution path.

---

## 1. Feasibility Summary Matrix

| # | Function | Address | Role | Classification | Preferred Hook Type | Risk |
|---|----------|---------|------|----------------|---------------------|------|
| 1 | `sub_14180B050` | `0x14180B050` | Effect dispatch switch (create/modify species) | **Hookable** (secondary) | Trampoline detour on entry OR vtable slot patch | **Medium** |
| 2 | `sub_1408A6EB0` | `0x1408A6EB0` | Scripted effect template registration | **Not hookable (useless)** | — | n/a |
| 3 | `sub_1408A79A0` | `0x1408A79A0` | Scripted trigger template registration | **Not hookable (useless)** | — | n/a |
| 4 | `sub_140173C30` | `0x140173C30` | Static string-to-ID token table init (247 KB) | **Patchable only** (not runtime-hookable) | Static-binary patch / ctor append | **High** |
| 5 | `sub_141D36B40` | `0x141D36B40` | Token constructor (ID + name) | **Patchable / emulatable** | Append ctor calls into a new 0x120 slot | **High** |
| 6 | `sub_1401B6CA0` | `0x1401B6CA0` | Database registration (init-time) | **Not hookable (useless)** | — | n/a |

---

## 2. Per-Function Assessment

### 2.1 `sub_14180B050` — Effect dispatch (create/modify species) → **Hookable / Medium**

Evidence (`effect_dispatch_switch_cases.md`):
- 2166 bytes, 141 basic blocks, cyclomatic complexity 113; 3 dense jump tables (254+159+166 cases) plus a sparse equality ladder.
- Dispatch key = DWORD at object `a3 + 0x68` (offset 104) — but this is a **per-effect-class special-case dispatcher over the create_species/modify_species family**, routed to shared handler LABEL_97 (`sub_140358B20`), NOT a full effect-keyword dispatch.
- Called twice from `sub_14181B740` / `sub_141851260` (code xrefs `0x14181c47c`, `0x1418513b0`) and is a vtable entry at `0x143824504`.

Hookability:
- **Trampoline detour is technically feasible**: entry has a normal prologue (`sub rsp` region at `0x14180b08e`); a 5-byte `E9` at `0x14180B050` would not clobber meaningful state for the first instruction. The vtable entry at `0x143824504` also allows a **vtable-slot rewrite** (swap the method pointer) — lower risk than code detour and version-fragile.
- **But value is limited**: this function only dispatches *one effect family* (species creation). Hooking it intercepts species-effect behavior only — a narrow slice of the full effect system. stellarstellaris-win hooks the generic `CEffect::ExecuteActual`/`CTrigger::Evaluate`, not a single special-case dispatcher.
- **Risk Medium**: 141 blocks, 113 complexity — a detour here is safe (entry-only), but any in-place jump-table patch (to add a case) is fragile across versions and ASLR.

**Recommendation**: Hookable as a vtable-slot patch or entry detour for observing/redirecting species-effect execution, but it is **not** the primary effect-extension point. Lower value than the generic dispatch roots (`CEffect::ExecuteActual`, `sub_14181B740`, `sub_141851260` which are the real per-effect entry points).

---

### 2.2 `sub_1408A6EB0` / 2.3 `sub_1408A79A0` — Scripted effect / trigger registration → **Not hookable (no extension value)**

Evidence (`registration_functions_analysis.md`):
- These are the **runtime registration entry points** for script-defined effects/triggers from `common/scripted_effects` / `common/scripted_triggers`.
- They intern the script keyword to a numeric ID via the global string→ID hash (`qword_14375D000`, built from the static table), then BST-insert into `qword_14339AEA8` (effect) / `qword_143287968` (trigger).
- Duplicate-ID detection is a **soft warning** (`sub_141CB3210`, "overwriting an existing effect/trigger, rename it") — nothing is refused.

Why NOT hookable for *new effect keywords*:
- These functions do **not** create new hardcoded keyword IDs. They map *existing* script names to *existing* interned numeric IDs (default `12` when unmapped). The keyword→ID mapping for hardcoded effects lives in the **static init table** (`sub_140173C30`), which already ran before load.
- Hooking registration lets you observe/modify *which scripted template object* gets stored in the BST for a given ID — i.e., you could **redirect an existing scripted effect's template body** — but that is already achievable via normal modding (a mod `common/scripted_effects` file overwrites the entry and the engine fails soft).
- It grants **zero** ability to introduce a brand-new effect keyword, because the numeric ID space and keyword→ID hash are established statically at `sub_140173C30` time, far earlier.

**Classification**: Not hookable *as an extension point for new effects* (technically a detour would install fine, but it provides no new registration capability that mod files already provide). Risk of hoofing: low value, version-fragile.

---

### 2.4 `sub_140173C30` — String-to-ID static token table init (247 KB) → **Patchable only / High risk**

Evidence (`string_to_id_registration_analysis.md`):
- A one-time magic-static initializer (~247 KB, 49,481 instructions, 9,876 keyword strings) that registers graphics/config tokens into `unk_1433A1B70`-onward, using the `lea r8,str / mov edx,id / lea rcx,tok / call sub_141D36B40` idiom per keyword.
- Runs at static-init time under `_Init_thread_header` guard — **before any DLL hook point that a runtime-injected loader can reach reliably**.
- Token structs are contiguous at 0x120 stride in `.bss`.

Why **not** runtime-hookable:
- It executes once during process/image initialization. A DLL injected via `stellar-loader` attaches *after* static init (the loader runs against an already-running game). By the time the DLL hooks, `sub_140173C30` has already returned; hooking it yields nothing on an already-loaded process.
- The strings registered here are the **graphics/GUI token family** (fonts, sprites, meshes, textures, screen modes), NOT effect/trigger keywords. This is the *graphics config* token table — distinct from effect dispatch.

When patchable:
- To add new tokens you would need to **patch the binary image** (append ctor calls at the tail of the registration block before `loc_1401B0290`), extend the `.bss` token array, and guarantee the new ID does not collide. This is a **static binary patch**, not a runtime DLL hook — high risk, version-locked, and touches only graphics tokens regardless.

**Classification**: Patchable-only (static), High risk; and even if patched it does not affect effect/trigger keyword extension.

---

### 2.5 `sub_141D36B40` — Token constructor (ID + name) → **Patchable / emulatable / High risk**

Evidence (`string_to_id_registration_analysis.md` §4–5):
- 92-byte constructor: clears flags, sets vtable `off_14249E1D8`, inline buffer at +32, `strlen`, then `sub_141D37170` stores numeric ID at +0 and memmoves keyword bytes.
- Called only from `sub_140173C30`. `sub_141D37170` is reusable and called from token reload paths (`sub_140355930` etc.).

Why **not** a clean runtime hook:
- Same timing problem as 2.4: the constructor runs during static init. A post-load DLL cannot catch the calls.
- However, it is **emulatable**: a DLL could replicate the ctor (`sub_141D37170`-equivalent: write ID at +0, grow buffer, memmove string) into a fresh 0x120 slot in the `.bss` token region *itself* — but that requires the token table to have reserved/appendable space and a consumer that discovers the new token by traversing the array by stride (fragile). The mapper `sub_141D34E40` that builds `qword_14375D000` iterates a *fixed count* (`2848896/288 = 9892` records), so appended tokens would **not** be picked up by the prebuilt hash map unless that count and iteration are also patched.

**Classification**: Patchable (static) / emulatable at High risk; low practical value for effect extension because the numeric-ID hash map is built once with a fixed record count.

---

### 2.6 `sub_1401B6CA0` — Database registration init (18 KB) → **Not hookable (useless)**

Evidence (AGENTS.md list; no dedicated disasm file — covered only as "registers CScriptedEffectTemplateDatabase, etc." at init):
- An **init-time** registration routine (~18 KB) that wires up the database singletons (ScriptedEffectDB, ScriptedTriggerDB, EventDB, etc.).
- Runs during static/early init, before a runtime-injected DLL attaches.

Hookability:
- A runtime detour would miss the init entirely on an already-loaded process (stellarstellaris-win loader attaches post-launch). No per-call runtime traffic to intercept thereafter (databases are ready). Any new DB registration must happen at init — i.e., **static patch**, which is disproportionately risky for no new-effect capability (adding a whole new database type requires supplying matching parser/consumer code in the binary).

**Classification**: Not hookable as a DLL extension point. Highest risk-to-reward ratio of the six; relegated to "static patch if ever needed."

---

## 3. Feasibility Matrix (deliverable)

| Address | Function | Hook Type | Risk | Required Permissions | Runtime traffic? | Extension payoff |
|---------|----------|-----------|------|----------------------|------------------|------------------|
| `0x14180B050` | Effect dispatch (species family) | Vtable-slot rewrite or trampoline detour | Medium | VirtualProtect RWX on .text, near-page RWX alloc | Yes (per species-effect) | Low–Medium (narrow family) |
| `0x1408A6EB0` | Scripted effect registration | (detour installs, no value) | — | — | Yes (script load) | **None** beyond mod files |
| `0x1408A79A0` | Scripted trigger registration | (detour installs, no value) | — | — | Yes (script load) | **None** beyond mod files |
| `0x140173C30` | Static string-to-ID token init | Static binary patch | High | Image-file patch (not runtime) | Once, at init (missed by DLL) | None for effects (graphics tokens) |
| `0x141D36B40` | Token constructor | Static patch / emulation | High | Image patch or .bss append + fixed-count map patch | Once, at init (missed by DLL) | None for effects (hash map fixed-count) |
| `0x1401B6CA0` | Database registration init | Static patch | Very High | Image-file patch | Once, at init (missed by DLL) | None (needs paired parser/consumer) |

---

## 4. Conclusion & Recommendation

1. **No single function in T4/T5/T6 is a runtime DLL hook point that can register a NEW hardcoded effect/trigger keyword.** This matches AGENTS.md's critical constraint and stellarstellaris-win's track record: no public project has added a new hardcoded effect keyword; the viable surface is *intercepting/modifying existing* execution, not expanding the keyword set.

2. The reason is architectural and confirmed by evidence:
   - The **keyword→numeric-ID mapping is static-init** (`sub_140173C30`/`sub_141D36B40`, fixed 9892-record table, built before DLL attach).
   - Runtime registration (`sub_1408A6EB0`) only maps **script names → pre-existing IDs** and easily fails soft.
   - Therefore new-hardcoded-effect support would require a **static binary patch** to the init table (function 2.4/2.5) plus a matching bump to the hash-map count (`sub_141D34E40`) — High risk, version-locked, and not a "hook."

3. **The best-feasibility DLL extension point in the analyzed set is `sub_14180B050`** (§2.1), but only for *species-effect* interception/redirection. For broad effect/trigger interception the real generic roots are the ones stellarstellaris-win already targets (`CEffect::ExecuteActual`, `CTrigger::Evaluate`, `CEvent::PerformImmediate`, `COnActionDatabase::PerformEvent`) — identified in AGENTS.md, outside the T4/T5/T6 function set.

4. Recommended follow-up: locate the **generic `CEffect::ExecuteActual` / `CTrigger::Evaluate`** entry addresses (the virtual dispatch roots that route by effect-class vtable) and add them to the extension matrix — those are the highest-value, lowest-risk trampoline-detour targets, consistent with production-proven stellarstellaris-win usage.

---

## 5. Status
- [x] Read all three T4/T5/T6 evidence files
- [x] Compared with stellarstellaris-win hook patterns (README + hooking_common.cpp)
- [x] Classified all 6 functions (hookable / patchable / not hookable)
- [x] Feasibility matrix with address, hook type, risk level, permissions
