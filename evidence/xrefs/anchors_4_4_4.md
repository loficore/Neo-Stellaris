# Stellaris 4.4.4 Re-Anchored Addresses

AGENTS.md key addresses are valid only for **3.4.5–3.7.4**. The game is now **4.4.4**
(codename still `augustus`). This table re-locates the anchors against the live binary
using a Frida memory scan (no IDA for 4.4.4 yet).

**Method**: locate each source-path C-string (`C:\mnt\gsg\stellaris\augustus\augustus\source\...`)
in the image, then find RIP-relative `lea` sites (modrm `mod=00 rm=101`) inside executable
ranges whose disp32 exactly resolves to the string VA. Resolve each site to its enclosing
function via int3-padding (`CC CC`) boundary walk-back.

**Scan runtime**: `pid 5172`, module base `0x7ff74a630000`, image size `0x392D000` (ASLR → only RVAs are stable).
Section layout: `.text` = rel `0x1000..0x2392000` (r-x); `.rdata`/strings = rel `0x2392000..0x2954000` (r--).

All addresses below are **module-relative offsets (RVA)** — add to runtime base.

## String anchors (imgrel)

| File / symbol | String-start RVA | Notes |
|---------------|------------------|-------|
| effect_impl.cpp | `0x26162c0` | 361 code refs across 231 fns (per-effect `__FILE__` logging) |
| scriptedeffect.cpp | `0x25181d0` | 1 code ref |
| scriptedtrigger.cpp | `0x25182c0` | 1 code ref |
| eventcommands.cpp | `0x2524780` | 6 refs / 3 fns |
| eventmanager.cpp | `0x24ee4e0` | 24 refs / 9 fns |
| game_singleobjectdatabase.h | `0x24b46e0` | 166 refs / 165 fns (per-DB template init) |
| CScriptedEffectTemplateDatabase (RTTI name) | `0x24b6190` | 1 ref |
| CScriptedTriggerTemplateDatabase (RTTI name) | `0x24b6130` | 1 ref |

## Function / data anchors (imgrel) — the deliverables

| Purpose | 3.x VA (RVA) | **4.4.4 RVA** | Confidence |
|---------|--------------|---------------|------------|
| ScriptedEffect **ref builder** (`GetScriptedEffect`) | `0x1408A6EB0` (0x8A6EB0) | **`0x89F960`** | High — but **not a getter** (§27, 2026-09-30): it builds a 0x118-byte ref with constant vtables and the BST walk only emits `"scripted effect %s is overwriting an existing effect, rename it"` (scriptedeffect.cpp:33). Hit/miss is not observable from `out`. |
| ScriptedTrigger **ref builder** (`GetScriptedTrigger`) | `0x1408A79A0` (0x8A79A0) | **`0x8A0450`** | High (exact twin; message `"scripted trigger %s is overwriting an existing trigger, rename it"` at scriptedtrigger.cpp:18) |
| ScriptedEffectDB global (BST head ptr) | `qword_14339AEA8` | **`0x33746E8`** | High (loaded by `mov rbp,[rip+..]` in the lookup, tested null, walked at `+0x18`) |
| ScriptedTriggerDB global (BST head ptr) | `qword_143287968` | **`0x32611C8`** | High (same; walked at `+0x88`) |
| CScriptedEffectTemplate vtable | — | **`0x24B1990`** | High (referenced by all template subclasses at 0x3a4xxx/0x3a8xxx) |
| CScriptedEffectTemplateDatabase ctor | — | **`0x1B5B10`** | Med (zeroes object, sets `+0xC0=0x62`) |
| Effect dispatch (huge switch) region | `0x14180B050` (0x180B050) | **`~0x180A9xx`** (top `effect_impl.cpp` caller cluster `0x180a950`) | Med — same RVA band as 3.x; needs jump-table confirmation |
| Event command handler | `0x1409FCE90` (0x9FCE90) | **`0x9F5750` / `0x9F6420` / `0x9F65E0`** | Med (3 fns in same band reference eventcommands.cpp) |
| Event manager (PerformEvent region) | `qword_14339AFE8` DB | look at `0x402C50` (9 refs) / `0x400920` (7 refs) | Low — TBD |

## Lookup function anatomy (`0x89F960`)

```
89fa5a: mov rbp, [rip+0x2ad4c87]        ; rbp = ScriptedEffectDB global @ 0x33746e8
89fa61: test rbp, rbp ; je notfound     ; skip if DB null
89fa7c: <hash the name string>          ; call 0x7ff74a78f770 / 0x7ff74c342c60
89fa9a: walk std::map at [rbp+0x18]     ; compare node key dword [node+0x20] vs hash
89fad7: lea rax,[rip+..]  -> 0x25181d0  ; on miss: __FILE__="...scriptedeffect.cpp", line=0x21
89fb0c: call 0x7ff74c2c1c30             ; CW_LOG/trace "no scripted effect <name>"
```
Trigger twin at `0x8A0450` walks `[rbp+0x88]`, DB global `0x32611c8`.

## Open items / caveats

- **DB global contents**: at pid 5172 (main-menu) both globals held small non-absolute
  values (`effDB@0x33746e8 → 0x9741f0`, `trigDB@0x32611c8 → 0x31a4f10`). Clausewitz uses
  base-relative/arena pointers; and/or the BST is only populated after a savegame loads.
  **Must re-read these globals in a live in-game session** before hooking them.
- `offsets.zig` `c_effect` placeholders (OFFSET_EFFECT_ID=4080, OFFSET_VTABLE=1704) are
  inherited from 3.x and are **unverified / suspect** for 4.4.4 — reconfirm against the
  dispatch switch at `0x180A9xx` once located precisely.
- ASLR: never hardcode the runtime base; resolve via `GetModuleHandle("stellaris.exe")` + these RVAs.

## Reproduction scripts

- `scripts/anchor444.js` — Frida RPC scanner (findStr/cstrStart/ripRefs/absRefs/funcStart).
  NOTE: prior scans returned false negatives because `Number(NativePointer.toString(16))`
  yields NaN in Frida's QuickJS; fixed by computing `Number(target)-Number(base)`.
- `scripts/scan444.py` — driver: dumps `C:\ns\anchor444.json` (raw + per-anchor func histogram).
