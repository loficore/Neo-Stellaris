# Version Compatibility

> **本文件大部分内容是 3.x 时代的归档，不要拿它当 4.4.4 的事实来源。**
>
> 当前目标是 **Stellaris 4.4.4**（exe 路径、sha256、`NS_STELLARIS_EXE` 覆盖见
> `docs/offline-tooling.md` 的「前置条件」）。4.4.4 的权威地址索引在 `AGENTS.md` 的「Stellaris 4.4.4
> RVA 索引」与 `evidence/xrefs/anchors_4_4_4.md`；逐条证伪结论在 `AGENTS.md` 的「已证伪」表。
>
> 下面 `Verified Offsets` 一节里的 CEffect / CEventScope / CTrigger 字段偏移，以及 `0x14…` 那批绝对地址，
> **都已被 4.4.4 的取证否掉**（§26 证伪 3.x `CEventScope` 布局；§3/§14 判死「主分发 switch 在 4.4.x 不存在」；
> §53.3 判死 `+0x30` 一族的取值路线）。保留它们是为了解读 `evidence/` 里的旧引用，**不是可复用的偏移表**。
>
> 仍在生效的只有这几节：`DLL Compatibility` 的 Build Requirements / Injection Method / Memory Model，
> `Common Changes Between Versions` 的缓解列，以及 `Future Compatibility`。
>
> **对 agent 的显式警告**：把本文件的偏移表当作 4.4.4 事实喂给任何分析工具（IDA MCP / Ghidra / REA），
> 会产出「看起来有据、实际是 3.x 假偏移」的结论。要问 4.4.4，只从 `AGENTS.md` 的 RVA 索引出发。

## Supported Versions

| Stellaris Version | Status | Notes |
|-------------------|--------|-------|
| 3.x (3.0–3.14) | 归档 | 本节全部偏移的出处；对 4.4.4 无效 |
| 4.4.4 | **当前目标** | 权威表见 `AGENTS.md` RVA 索引 + `evidence/xrefs/anchors_4_4_4.md` |
| 4.0–4.4.3 | Not tested | 需要按 4.4.4 的口径重做偏移复核 |

**Current target:** Stellaris **4.4.4** (codename "augustus")

> 旧文本曾在此写「Current target: Stellaris 3.x」与「4.0+ Not tested」，与 `AGENTS.md` 的版本约束矛盾，
> 已于 2026-10-27 更正；上面那张表就是更正后的口径。

## Engine Version

The Clausewitz engine version is identified by:
- **Binary:** `stellaris.exe`
- **Codename:** "augustus"
- **Architecture:** x86_64 (Windows PE)
- **Runtime:** Custom allocator, no libc dependency

## Verified Offsets

**下列三张布局表都是 3.x 读数，对 4.4.4 已被证伪，保留只为解读旧引用。**
4.4.4 上 `src/dll/api/scope.zig` 仍在读那两个假偏移，逐条处置见 `docs/scope-read-points.md`；
`offsets.zig` 里当前生效的 4.4.4 常量另见 `AGENTS.md` 的 RVA 索引。

All offsets are derived from IDA reverse engineering of the 3.x binary. They are stored in `src/dll/shared/offsets.zig`.

### CEffect Object Layout（3.x，已证伪）

| Offset | Field | Type | Description |
|--------|-------|------|-------------|
| +0x038 (56) | Effect name | SSO string | Small String Optimization (≤22 bytes inline) |
| +0xFF0 (4080) | Effect ID | i32 | Used for dispatch in main effect switch |
| +0x6A8 (1704) | Vtable pointer | ptr | Virtual function table |

> `+0xFF0` 那句「Used for dispatch in main effect switch」依赖的主分发 switch **在 4.4.x 不存在**（§3/§14：
> 4.4.4 改为 per-class vtable 派发，base Execute = RVA `0x1D08520` 经 `call [rax+0x10]` 走 slot[2]）。
> 4.4.4 上 effect 的 `{id @ +0x20, name @ +0x28}` 是**消费者 `call create` 之后往对象里写**的结果（§23），
> 不是这张表。

### CEventScope Layout（3.x，已被 §26 证伪）

| Offset | Field | Type | Description |
|--------|-------|------|-------------|
| +8 | Scope type | i64 | Bit flag (power of 2) |
| +16 | Object ID | i64 | Game object identifier |

> **哪个对象是 scope 在 4.4.4 仍未定**（§56 没能确立；§59 按修正仪器问完四根，负结论是「问完了」的；
> §68 两条边非血缘）。这两个偏移不要再当事实引用。

### CTrigger Object Layout（3.x，已证伪）

| Offset | Field | Type | Description |
|--------|-------|------|-------------|
| +0x038 (56) | Trigger name | SSO string | Small String Optimization |
| +0xFF0 (4080) | Trigger ID | i32 | Trigger identifier |
| +0x6A8 (1704) | Vtable pointer | ptr | Virtual function table |

> 4.4.4 上 trigger 侧对应的是 `{id @ +0x38, name @ +0x40}` 再 `call [vptr+0x80]`（§23）。

### Hook Addresses（3.x 绝对 VA，勿用于 4.4.4）

| Function | Address | Purpose |
|----------|---------|---------|
| `CEffect::ExecuteActual` | `0x14181B740` | Effect execution hook target |
| `CTrigger::Evaluate` | `0x1408A6F20` | Trigger evaluation hook target |

> 4.4.4 的对应物是 **base Execute RVA `0x1D08520`**（热路径，~5,300 calls/s）与其 slot[2] 覆写集合，
> 且**禁止热路径 detour `0x5350D0`**（§28.5，detour 价值 = 0）。上面这两个绝对地址来自已删除的
> 3.x `ceffect.zig`/`ctrigger.zig`，见本文件 `Common Changes Between Versions` 那一行。

### Global Data Addresses（3.x 绝对 VA，勿用于 4.4.4）

| Address | Name | Purpose |
|---------|------|---------|
| `0x143287360` | GameState | Main game state object |
| `0x143287788` | CountryDB | Country database |
| `0x14339AEA8` | ScriptedEffectDB | Scripted effect templates |
| `0x143287968` | ScriptedTriggerDB | Scripted trigger templates |
| `0x14339AFE8` | EventDB | Event database |

> 4.4.4 的两个 db 全局是 RVA `0x33746E8`(ScriptedEffectDB，BST 根 `[db+0x18]`) 与
> `0x32611C8`(ScriptedTriggerDB，BST 根 `[db+0x88]`)，见 §1/§21。**db 全局需在实机会话里重读**
> （主菜单值曾看起来像 arena/相对指针或未初始化）。

### Stellaris 3.4.5–3.7.4 地址表(存档 — 勿用于 4.4.4)

移自 `AGENTS.md`(2026-09-30 拆分)。4.4.4 的 RVA 表见 `AGENTS.md` 与
`evidence/xrefs/anchors_4_4_4.md`;下表里的 `0x14180B050` 主分发 switch 在 4.4.x **不存在**
(见 `evidence/analysis/runtime_444_structures.md` §3/§14)。

#### Effect System
| Address | Function | Source File | Notes |
|---------|----------|-------------|-------|
| `0x14180B050` | Effect dispatch switch-case | `effect_impl.cpp` | 254+159+166 cases, reads effect ID from object+104 |
| `0x1408A6EB0` | Scripted effect template registration | `scriptedeffect.cpp` | Registers to BST at `qword_14339AEA8` |
| `0x1408A79A0` | Scripted trigger template registration | `scriptedtrigger.cpp` | Registers to BST at `qword_143287968` |
| `0x140173C30` | String-to-ID registration (247KB) | static init | Calls `sub_141D36B40(target, id, string)` per keyword |
| `0x1401B6CA0` | Database registration (18KB) | init | Registers CScriptedEffectTemplateDatabase, etc. |
| `0x1409FCE90` | Event command handler | `eventcommands.cpp` | Processes player event option selections |

#### Key Global Data
| Address | Name | Purpose |
|---------|------|---------|
| `qword_14339AEA8` | ScriptedEffectDB | BST of scripted effect templates |
| `qword_143287968` | ScriptedTriggerDB | BST of scripted trigger templates |
| `qword_14339AFE8` | EventDB | Event database |
| `qword_143287360` | GameState | Main game state object |
| `qword_143287788` | CountryDB | Country database |

#### Source File String References
| String | Address | Points To |
|--------|---------|-----------|
| `effect_impl.cpp` | `0x14260ee30` | Effect implementation core |
| `scriptedeffect.cpp` | `0x14253bb70` | Scripted effect template code |
| `scriptedtrigger.cpp` | `0x14253bc60` | Scripted trigger template code |
| `eventcommands.cpp` | `0x142548290` | Event command processing |
| `eventmanager.cpp` | `0x142511938` | Event manager |
| `game_singleobjectdatabase.h` | `0x1424d7c30` | Database template base |

## Scripted Effect/Trigger Threshold

| Threshold | Value | Description |
|-----------|-------|-------------|
| `SCRIPTED_EFFECT_BASE` | 4081 | First custom/scripted effect ID |
| Vanilla effects | ≤ 4081 | Pass through to engine |
| Custom effects | > 4081 | Routed to JavaScript handlers |

## DLL Compatibility

### Build Requirements

| Requirement | Version |
|-------------|---------|
| Zig compiler | ≥ 0.16.0 |
| Target | x86_64-windows |
| Output | `stellaris_quickjs.dll` (dynamic library) |

### Injection Method

The DLL exports two functions:

1. **`DllMain`** — Standard Windows DLL entry point
2. **`PushCApplicationPtr(ptr)`** — Called by the C++ loader after injection to pass the engine pointer

The DLL must be injected using a DLL injector that supports calling exported functions after load.

### Memory Model

- The DLL uses page-aligned memory allocation for trampolines
- Memory protection changes use `VirtualProtect` (RX↔RWX)
- Instruction cache is flushed after code patching
- Trampoline memory is allocated near the target function (within ±2GB for rel32 compatibility)

## Version Update Process

**下面 7 步是 3.x 时代的流程归档。** 它假设「在 IDA 里核对 CEventScope 布局」这件事有意义，而那个前提
已被 §26 打掉；4.4.4 上也没有可核对的主分发 switch（§3/§14）。当前口径按下面「4.4.4 实际用的流程」执行。

1. **Dump the new binary** — Open `stellaris.exe` in IDA Pro
2. **Verify offsets** — Check that CEffect/CEventScope/CTrigger layouts haven't changed
3. **Verify hook addresses** — Confirm `CEffect::ExecuteActual` and `CTrigger::Evaluate` addresses
4. **Verify global addresses** — Check GameState, CountryDB, and other global pointers
5. **Update offsets.zig** — Modify the offset constants
6. **Run tests** — Ensure all unit tests pass
7. **Test in-game** — Verify effects/triggers fire correctly

### 4.4.4 实际用的流程（当前口径）

1. **取新 exe 并钉身份** — 记 sha256 与来源；`NS_STELLARIS_EXE` 指向它，所有离线脚本只读这份拷贝
   （判据「只读 exe 拷贝 = 工具，需要进程 = 探针」见 `AGENTS.md` 的 scripts/ 约定）。
2. **静态侧先重跑离线工具**，不要先在 IDA 里找：`scripts/find_refs.py`（完整交叉引用，不走 IDA xrefs）、
   `scripts/vtable.py` / `scripts/rttibatch.py`（vtable 与家族普查）、`scripts/thunkarrays.py`（keyword→behaviour
   转储）、`scripts/chokepoints_emit.py`（要道普查表的漂移围栏）。
3. **Frida 重锚定** — `scripts/anchor444.js` 那条通道产出 `evidence/xrefs/anchors_4_4_4.md` 形状的全表；
   版本变了就重打并另存该版本的文件名。
4. **热路径判别用实机只记录 detour**，且只在点名时（授权门见 `docs/roadmap.md` 第 2 节）；
   `0x5350D0` 不要再当 detour 靶（§28.5）。
5. **新 keyword 一律走引擎自己的 mint 路径** — `0x1D13270` 之前必须先过 `scripts/c1_preflight.py`
   且退出码 0（约束 4：大小写不敏感会接管官方 keyword）。不要手挑 id。
6. **`zig build test` + `just check`** — 后者一次跑构建、两套测试、布局围栏与普查表漂移围栏。
7. **实机验** — `just launch` / `just game` 那条通道；看到「host 死了」先按约束 8 排除我们自己的产物 trip
   （`scripts/c2_selfabort_repro.py` 零游戏判别器）。

### Common Changes Between Versions

| Change Type | Impact | Mitigation |
|-------------|--------|------------|
| Object layout shift | Breaks field reads | Update offsets in `offsets.zig` |
| Hook address change | Breaks detour installation | Update addresses in `scripted/exec_hook.zig`/`scripted/lookup_hook.zig` (the 3.x `ceffect.zig`/`ctrigger.zig` they used to live in were deleted — their absolute addresses and field offsets are falsified for 4.4.4, see `evidence/analysis/runtime_444_c1_validation.md` §26) |
| Global address change | Breaks game state reads | Update addresses in `gamestate.zig` |
| New effect IDs | May collide with an official keyword | Do **not** hand-pick ids: mint them via the engine's own `0x1D13270` (id = `[db+0x64]+[db+0x84]+1`) and run `scripts/c1_preflight.py --name X` for the case-fold collision check (§25.5). `SCRIPTED_EFFECT_BASE` is an observation, not an allocation base (§29) |
| Vtable changes | Breaks virtual calls | Re-analyze vtable layout in IDA |

## Cross-Platform Notes

| Platform | Status | Notes |
|----------|--------|-------|
| Windows x86_64 | Supported | Primary target |
| Linux x86_64 | Not supported | Requires Wine/Proton; DLL injection differs |
| macOS | Not supported | No native Clausewitz builds |

The build system defaults to x86_64-windows. Cross-compilation to other targets is possible but not officially supported.

## Testing Compatibility

```bash
# Run all tests to verify offset consistency
zig build test

# Tests verify:
# - Offset values match expected constants
# - Scope types are power-of-2 bit flags
# - Effect IDs are within valid ranges
# - SSO string layout matches engine
# - x86_64 instruction decoding is correct
```

> **读法修正**：上面这份清单是 3.x 时代的措辞。「matches engine」这句在 4.4.4 上不成立 ——
> `api/scope` 那两个假偏移现在由 `LAYOUT_CONFIRMED = false` 的测试**钉住为待处置**，不是确认；
> 逐条读点处置与「绿」的定义见 `docs/scope-read-points.md`。全绿时的基线读数与门的读法
> （退出码 0 + `29/29 steps succeeded`，单看 tests passed 会误读）在同一份文件的前置条件一节。

## Future Compatibility

Planned work to improve version compatibility:

- [ ] Dynamic offset detection (scan for patterns instead of hardcoding)
- [ ] Version-specific offset profiles
- [ ] Runtime offset validation
- [ ] Automatic offset discovery via signature scanning
