# AGENTS.md — Stellaris Reverse Engineering

## Project Context

Reverse engineering `stellaris.exe` (Clausewitz engine, codename "augustus") to map the mod system's registration pipeline and identify extension points for new effects/triggers.

**Game version**: **4.4.4** (as of 2026-09). Address tables below marked 3.x are legacy; use the 4.4.4 RVA table.
**Binary**: `/mnt/drive_d/SteamLibrary/steamapps/common/Stellaris/stellaris.exe`
**IDA session**: Use `ida-pro_idb_open` with `mode=force_headless`. The `.i64` database exists alongside the exe.
**Game data**: `/mnt/drive_d/SteamLibrary/steamapps/common/Stellaris/common/` — scripted_effects, scripted_triggers, on_actions, events, defines, etc.

## Evidence Collection

All analysis artifacts go to `evidence/` at project root:
- `evidence/disasm/` — disassembly snippets, decompiled pseudocode
- `evidence/strings/` — relevant string references with addresses
- `evidence/xrefs/` — cross-reference maps for key functions
- `evidence/external/` — findings from external sources (stellarstellaris-win, forums, docs)
- `evidence/errors/` — error logs from failed operations
- `evidence/analysis/` — synthesis reports, extension point analysis

**Naming convention**: `<component>_<finding>.md` (e.g., `effect_dispatch_switch_cases.md`)

## IDA Pro MCP Workflow

```
# Open binary (use force_headless, never prefer_gui in this project)
ida-pro_idb_open(input_path="...stellaris.exe", mode="force_headless")

# Session ID is required for ALL subsequent calls — pass database="<session_id>"

# Survey first
ida-pro_survey_binary(database=session_id, detail_level="standard")

# Find strings
ida-pro_find_regex(database=session_id, pattern="...", limit=50)

# Trace xrefs
ida-pro_xrefs_to(addrs=["0x..."], database=session_id, limit=30)

# Decompile
ida-pro_decompile(addr="0x...", database=session_id)

# Analyze function (includes callees, strings, xrefs)
ida-pro_analyze_function(addr="0x...", database=session_id)
```

**Gotcha**: If `ida-pro_idb_open` fails, check if another IDA GUI instance has the file locked. Close it first.

## Key Addresses (Confirmed)

### Stellaris 4.4.4 (CURRENT) — RVA table (add to runtime module base, ASLR on)

Re-anchored via Frida scan. Full detail in `evidence/xrefs/anchors_4_4_4.md`.

| RVA | Function / Data | Source anchor | Notes |
|-----|-----------------|---------------|-------|
| `0x89F960` | GetScriptedEffect(name) lookup | `scriptedeffect.cpp:33` | Walks BST at global below; unique string xref |
| `0x8A0450` | GetScriptedTrigger(name) lookup | `scriptedtrigger.cpp:18` | Twin of the effect lookup |
| `0x33746E8` | ScriptedEffectDB global | (loaded by lookup) | BST root at `[global+0x18]` |
| `0x32611C8` | ScriptedTriggerDB global | (loaded by lookup) | BST root at `[global+0x88]` |
| `0x24B1990` | CScriptedEffectTemplate vtable | xrefs (no RTTI, see note below) | Referenced by all template subclasses |
| `0x1D08520` | `CEffect::Execute` (base) — THE hot path | live Frida detour + 32-byte code fingerprint | ~5,300 calls/s; dispatches `call [rax+0x10]` = the instance's slot[2] `ExecuteActual` |
| `0x1B5B10` | CScriptedEffectTemplateDatabase ctor | class-name string | Med confidence |
| ~~effect dispatch switch~~ | **does not exist in 4.4.x** | §3/§14 of `runtime_444_structures.md` | 3.x RVA 0x180B050 is void; per-class vtable dispatch instead |
| `0x9F5750`/`0x9F6420`/`0x9F65E0` | Event command handlers | `eventcommands.cpp` | Pick via deeper trace |

**No RTTI on the CEffect family**: `vtable[-8]` is another code slot, never a
CompleteObjectLocator (measured across all 1,805 of them). Class names cannot come from RTTI —
use string refs inside `ExecuteActual` or the §8 keyword registration table.
**Full static class map**: `evidence/xrefs/ceffect_vtable_map_4_4_4.txt` (1,805 vtables whose
slot[1] is base Execute → 543 distinct `ExecuteActual` bodies), produced by
`scripts/rttibatch.py --effects`.

**Caveat**: DB globals must be re-read in a live in-game session (main-menu values looked like arena/relative pointers or uninitialized).

### Stellaris 3.4.5–3.7.4 (LEGACY — do not use for 4.4.4)

### Effect System
| Address | Function | Source File | Notes |
|---------|----------|-------------|-------|
| `0x14180B050` | Effect dispatch switch-case | `effect_impl.cpp` | 254+159+166 cases, reads effect ID from object+104 |
| `0x1408A6EB0` | Scripted effect template registration | `scriptedeffect.cpp` | Registers to BST at `qword_14339AEA8` |
| `0x1408A79A0` | Scripted trigger template registration | `scriptedtrigger.cpp` | Registers to BST at `qword_143287968` |
| `0x140173C30` | String-to-ID registration (247KB) | static init | Calls `sub_141D36B40(target, id, string)` per keyword |
| `0x1401B6CA0` | Database registration (18KB) | init | Registers CScriptedEffectTemplateDatabase, etc. |
| `0x1409FCE90` | Event command handler | `eventcommands.cpp` | Processes player event option selections |

### Key Global Data
| Address | Name | Purpose |
|---------|------|---------|
| `qword_14339AEA8` | ScriptedEffectDB | BST of scripted effect templates |
| `qword_143287968` | ScriptedTriggerDB | BST of scripted trigger templates |
| `qword_14339AFE8` | EventDB | Event database |
| `qword_143287360` | GameState | Main game state object |
| `qword_143287788` | CountryDB | Country database |

### Source File String References
| String | Address | Points To |
|--------|---------|-----------|
| `effect_impl.cpp` | `0x14260ee30` | Effect implementation core |
| `scriptedeffect.cpp` | `0x14253bb70` | Scripted effect template code |
| `scriptedtrigger.cpp` | `0x14253bc60` | Scripted trigger template code |
| `eventcommands.cpp` | `0x142548290` | Event command processing |
| `eventmanager.cpp` | `0x142511938` | Event manager |
| `game_singleobjectdatabase.h` | `0x1424d7c30` | Database template base |

## Engine Architecture (from external research)

**C++ class names** (from Linux symbols, confirmed by stellarstellaris-win):
- `CEffect::ExecuteActual(CEventScope*)` — virtual, every effect enters here
- `CTrigger::Evaluate(const CEventScope&)` — virtual trigger evaluation
- `CEvent::PerformImmediate` — event execution pipeline
- `COnActionDatabase::PerformEvent` — on_action dispatch
- `CToken::Init` / `CTextLexer::GetTok` — script tokenizer/parser
- `CEventScope` — scope object: `escopetype` at +8, `objectid` at +12

**Jomini layer**: Shared library between game and engine. Implements scope types, event targets, variables, scripted effects/triggers. Registration categories: Types, Promotes, Functions, Callbacks.

**Critical constraint**: No public project has added a new hardcoded effect keyword. DLL hook (see stellarstellaris-win) can intercept/modify existing effects but not register new ones without deep binary patches.

## External References

- **stellarstellaris-win**: https://github.com/MattMills/stellarstellaris-win — DLL injection + hook framework, versioned VA tables for 3.4.5–3.7.4
- **rakaly/jomini**: https://github.com/rakaly/jomini — Rust parser for Clausewitz text+binary saves
- **CWTools**: https://github.com/cwtools/cwtools — F# validator with per-game effect/trigger databases
- **class101 Ghidra guide**: Steam community "Enabling Achievements in Stellaris With Mods [SRE]"

## Game Data Structure

The engine auto-registers script definitions by scanning `common/` subdirectories:
- `common/scripted_effects/` — 42 files, macro effects with `$PARAM$` substitution
- `common/scripted_triggers/` — 37 files, conditional logic
- `common/on_actions/` — 4 files, event hooks (on_game_start, on_monthly_pulse, etc.)
- `common/scripted_actions/` — 6 files, fleet/megastructure commands
- `events/` — 170 event files

Script DSL features: scope chains (This/Root/Prev/From), parameterized macros, inline math `@[expr]`, `optimize_memory` tag, conditional blocks `[[PARAM] ... ]`.
