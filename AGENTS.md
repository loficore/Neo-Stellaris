# AGENTS.md — Stellaris Reverse Engineering

## Project Context

Reverse engineering `stellaris.exe` (Clausewitz engine, codename "augustus") to map the mod system's
registration pipeline and identify extension points for new effects/triggers.

**Game version**: **4.4.4** (as of 2026-09). 3.4.5–3.7.4 的地址表已移入
`docs/version-compatibility.md`,**不要用于 4.4.4**。
**Binary / game data**: 路径、sha256、`NS_STELLARIS_EXE` 覆盖方式见 `docs/offline-tooling.md` 的"前置条件"。
`evidence/` 下所有产物的生产者也在该文件里说明。

**文档地图 — 本文件只放约束与索引,论证在别处:**

| 内容 | 位置 |
|---|---|
| 取证过程 §1–§15(热路径、detour、CEffect 类图、被证伪的注册链) | `evidence/analysis/runtime_444_structures.md` |
| 取证过程 §16–§23(注册管线:driver、descriptor、thunk 数组、token 分配器、class_info、消费者) | `evidence/analysis/runtime_444_keyword_pipeline.md` |
| 取证过程 §24–§30(donor 别名决策、A5 交叉验证、ABI 修正、`0x5350D0` 复评、backlog、兜底路径定性) | `evidence/analysis/runtime_444_c1_validation.md` |
| 离线脚本用法与判读陷阱 | `docs/offline-tooling.md` |
| 4.4.4 锚点全表(Frida 重锚定) | `evidence/xrefs/anchors_4_4_4.md` |
| keyword→behaviour 机器可读转储(3,900 条) | `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`(`scripts/thunkarrays.py`) |
| CEffect 类图(1,805 个 vtable,**是下限不是类数**,§14/§17) | `evidence/xrefs/ceffect_vtable_map_4_4_4.txt` |
| descriptor 回放 oracle | `evidence/xrefs/descriptor_oracle_4_4_4.tsv` |
| 阶段计划与授权状态 | `PLAN.md` |

## 硬性约束(每次动手前核对)

1. **不许绕过 IDA license 门**:**do not patch `libidalib.so`'s guard branch and do not write the
   `EULA 90` registry key** — that is bypassing the license gate, not accepting it. 静态 RE 一律走
   本仓库的离线脚本(不需要 license、不需要进程、不需要暂停游戏)。
2. **不得对 session `f3ea6101` 调用 `ida_auto.plan_and_wait`** — 它把 IDA 主线程卡死 785 s。
   交叉引用用 `scripts/find_refs.py`(离线、完整)而不是 IDA xrefs。IDB 是**从 exe 建的**,没有
   Windows 侧的命名/类型历史。
3. **C1(真机注册一个新 keyword)未授权**:`src/dll/scripted/keyword_registry.zig:208` 的
   `authorize.c1_registration = false`,所以 `pub fn register`(`:419`)直接返回
   `RegisterError.NotAuthorized`,真正的执行器 `registerSequence`(`:432`)是 file-private。
   翻转那一个常量就是 C1 的授权步骤。
4. **任何新 keyword 名在进 `0x1D13270` 之前必须先过 `scripts/c1_preflight.py` 且退出码 0**
   (§25.5):token 查找**大小写不敏感**,`Add_Modifier` 会拿回 `add_modifier` 的 `10104`,
   我们的插入会**接管一个官方 keyword**,而 `eax` 分不清 mint 与命中。运行时同一条规则由
   `keyword_registry.NameCheck` 执行(空串 / §20 首字符 / 全小写)。
5. **class_info 只能 ALIAS 官方的,不要伪造对象**(§24)。docstring 用 donor 自带的 `.rdata` 字符串
   (§24.6),使**我们的 DLL 没有任何指针留在 db 里** — 引擎持有它的生命周期超过我们 DLL 的卸载。
6. **ABI**:`0x2185218` 保留并转发完整 `rcx`,thunk 写的是 `ecx`,所以从 Zig 传 **u64** 而不是 u32;
   `0x1D13270`/`0x89F960` 的名字持有者其 std::string 在 **`holder+0x10`**,一个 char 一字节(§20/§27)。
7. **禁止热路径 detour `0x5350D0`** — 它是某个类的虚属性 getter,**detour 价值 = 0**(§28.5:
   `fastcalls` 找不到任何直接调用点,`.rdata` 只有 1 处引用)。

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
ida-pro_idb_open(input_path="...stellaris.exe", mode="force_headless")   # 永不使用 prefer_gui
# 之后的每个调用都必须带 database="<session_id>"
ida-pro_survey_binary(database=session_id, detail_level="standard")
ida-pro_find_regex(database=session_id, pattern="...", limit=50)
ida-pro_xrefs_to(addrs=["0x..."], database=session_id, limit=30)
ida-pro_decompile(addr="0x...", database=session_id)
ida-pro_analyze_function(addr="0x...", database=session_id)
```

If `ida-pro_idb_open` fails, check if another IDA GUI instance has the file locked. Close it first.
Cross-reference work prefers the offline scripts (约束 2)。

## Stellaris 4.4.4 RVA 索引(add to runtime module base, ASLR on)

只列**是什么**与**在哪论证**;任何行内论证的完整版在对应 §。

### keyword 注册管线(可写的扩展面)

| RVA | 含义 | 证据 |
|-----|------|------|
| `0x1D13270` | **`eax = GetOrAddToken(rcx = *name holder)` — 运行时 token 分配器**;`rdx` 死;名以 `-` 或数字开头则 `eax=0` | §18 §20 |
| `0x1D12C60` / `0x37347A0` | token DB singleton 访问器 / 对象(vtable `0x26E5180`, ctor `0x1D13570`, guard `0x3734790`) | §18 |
| **`0x1D12CD0`** | **`id → name` 反查表构建器**(无参,自取 singleton):`[db+0x70] + id*0x30` 的 holder 数组,`std::string` 在 `holder+0x10`;两半灌入 —— 9,863 条静态描述符 + `[db+0x58]`/`[db+0x64]` 的动态 map | **§30.2** |
| `0x1D15270` / `0x1D152D0` | descriptor 写手:静态路径 / 动态路径 | §20 |
| `0x1D158A0` | **两条路径共用的 slot writer** ⇒ 运行时 descriptor 与静态字节一致 | §18 §20 |
| `0x337B400` | descriptor 数组,**stride `0x120` × 9,863**,只含 `{token id, SSO name}`,无 behaviour 槽 | §17 §20 |
| `0x247F480..0x2494070` | keyword 名字池(上面 SSO 串的载体) | §17 |
| `0x172E50..0x1AF1E7` | token-name driver(247 KB,每 entry 一个 `lea rcx,[0x337B400+0x120*n]`) | §17 |
| `0x23AC600` ×754 / `0x23AF628` ×482 / `0x23B0540` ×405 | effect / trigger **注册 thunk 数组**(约 106 B/thunk) | §17 |
| `0x33746E8` / `0x32611C8` | ScriptedEffectDB / ScriptedTriggerDB 全局;BST 根在 `[db+0x18]` / `[db+0x88]` | §1 §21 |
| `0x3AEBA0` / `0x347BD0` | db 拉起:effect placement ctor(要 caller 先 `new(0x70)`) / trigger 无参 ensure 自发布 | §21 |
| `0x3AEF60` / `0x348150` | BST insert,effect 走 `db+0x18`、trigger 走 `db+0x88`,**参数形状相同但不可互换** | §21 |
| `0x3B01A0` / `0x349AE0` | **消费者**:按 token id 查树并 `call create`,键无范围检查 | §23 |
| `0x3AF130` / `0x348450` | 全树枚举,对每个节点 `create` ⇒ **注册不是惰性的** | §23.3 |
| `0x260ABD8` | `add_modifier` 的 class_info = `{deleter 0x34C090, create 0x18A3340}`;字段 0 是**共享** deleting destructor | §17 §22.2 |
| `0x269CAA8` / `0x2611070` | **C1 donor class_info**:trigger `has_crisis_perk`(create `0x1B30450`, `new(0x80)`)/ effect `hidden_effect`(create `0x1893130`, `new(0xc0)`) | §24 §24.6 |
| `0x26C1BA0` / `0x2616260` | donor 自带 `.rdata` docstring(C1 用这两个,不用我们的串) | §24.6 |
| `0x2185218` | `operator new(size)` | §17 §21 |
| `0x1930E70..0x196D3E6` | 101 个 scope-iterator 注册函数 — **官方自带的加 keyword 模板,可直接照抄** | §19 |
| `0x195A580..0x19A7268` | 104 个 iterator **名字拼接器**(头 keyword 可以完全没有静态 descriptor) | §25.4 |
| `0x388130`…`0x389224` / `0x3797C0..0x37B056` / `0x114CE0` | 9 个 Meyers 惰性 token 访问器 / `mod_%s` 生成器 / 仅被 `.rdata` 指针数组引用的 25 B shim | §19 |

### 热路径与执行

| RVA | 含义 | 证据 |
|-----|------|------|
| `0x1D08520` | **`CEffect::Execute` (base) — 热路径**,~5,300 calls/s,派发到 `call [rax+0x10]` = slot[2] `ExecuteActual` | §10 §14 |
| `0x1D08520` arg2 | 执行帧:**`+8` 是调用深度计数**(`inc`/`dec` 包着那次虚调用),不是 3.x 声称的 scope type | §26 |
| `0x3B1330` | effect `[vptr+0x70]` base impl = 递归 parse(先调 `[vptr+0x68]`,再走 `[obj+0x10]`/`[obj+0x1c]*8` 子向量);723/723 携带 | §24.4.2 |
| `0x3B1420` | effect `[vptr+0x98]` base impl = **bool 谓词**,不是 parse | §23.1 §24.4.2 |
| `0x89F960` / `0x8A0450` | `GetScriptedEffect` / `GetScriptedTrigger` — **不是 getter**:填进去的 vtable 是常量,命中与否无法从 `out` 观察;唯一副作用是重复定义告警 ⇒ 该告警是 §25.5 劫持的运行时检测器 | §27 |
| `0x1C91C30` | 上述重复告警走的 logger | §27 |
| `0x24B1990` | `CScriptedEffectTemplate` vtable(CEffect 家族**没有 RTTI**,`vtable[-8]` 永远是别的 code slot) | §14 |
| `0x1B5B10` | `CScriptedEffectTemplateDatabase` ctor(中可信度) | `anchors_4_4_4` |
| `0x5BBF80` | token-id 二分查找派发树 — **不是 keyword 注册表**,别在此找 keyword 绑定 | §17 |
| `0x9F5750` / `0x9F6420` / `0x9F65E0` | Event command handlers(`eventcommands.cpp`,需更深 trace 选点) | `anchors_4_4_4` |

### 已证伪 — 不要再当锚点用

| 曾经的断言 | 实况 | 证据 |
|---|---|---|
| `0xCCCEB0` = master keyword registrar | **false**;唯一调用方 `0x266D3D` 是把 token 解析成对象的通用运行时处理 | §15 |
| `0x337A844` = 一次性注册守卫 | 是 trace-enable bool(PLAN §6 C3 旧触发条件作废) | §16 |
| effect dispatch switch(`3.x 0x180B050`) | 4.4.x **不存在**;改为 per-class vtable 派发 | §3 §14 |
| lexer/parser 会从脚本文本 mint token | **false**;567 个调用点分 139 桶无一处在解析器里,且 `0x1D13270` **零 qword 引用**。mod 脚本里的新词**不会**有 id,DLL 必须自己调 | §19 |
| `0x5350D0` = keyword 执行器 / 真实扩展面 | 是按 token-id 的属性 getter,22 个派发消息里混着 `graphicsSettings`/`sendgame`;**0 个直接调用点** | §26.1 §28 |
| `0x1D092C0` 可作 JS 作用域变量桥的候选锚点 | **已否**(§30):它是 parse-error 表追加器 —— `new(0x80)` 节点写进 `[obj+0x10]/+0x18/count +0x20` 链表、置 `[obj+0x28]=1`,尾调 tokenizer 推进 `0x1D09130`;`0x1D09330` 的 **22** 个调用方全部传**错误文案**(`'Unexpected token'`/`'Unreadable String'`/`'Unhandled Entry'`/`'Expected list start'`)。真正的按名变量查找**仍未定位**,不要再从这里找 | §28.3 → **§30** |
| `0x337ACBC` 像"脚本错误计数" | 是**递归深度** global:全镜像只有 2 处引用,都在 `0x1D09130` 内(入口 `inc`、提前返回路径 `dec`),净为零 | §30 |
| 3.x `CEventScope` 布局(`+8` scope type / `+16` object id) | 被 §26 证伪;但 `src/dll/api/scope.zig` **仍在读 `+8`/`+16` 且已链进 DLL** | §26 |

## 新硬编码 keyword 配方(Phase A 结论 — 全程离线,不 patch 静态表)

```
1. edx = 0x1D13270(rcx = *name holder)      ; GetOrAddToken。约束 4:先跑 c1_preflight,退出码 0
2. value = new(0x10){ &class_info, &docstring }
3. 先拉起 db,再插入(两者参数形状相同,函数不同 — §21):
       effects:   if ![0x33746E8] { p = new(0x70); [0x33746E8] = 0x3AEBA0(p) }   0x3AEF60(db, edx, value)   ; db+0x18
       triggers:  if ![0x32611C8] { 0x347BD0() }                                0x348150(db, edx, value)   ; db+0x88
   ; 两个 insert 都用 `dword [node+0x20]` 与裸 id 比较,无范围检查 ⇒ 动态 id 是合法键
4. class_info = ALIAS 官方的(约束 5)。C1 第一个目标 = trigger db(§24.6):
       triggers: 0x269CAA8  has_crisis_perk   create 0x1B30450  new(0x80)   docstring 0x26C1BA0
       effects:  0x2611070  hidden_effect     create 0x1893130  new(0xc0)   docstring 0x2616260
```

**插入后引擎会怎么写、怎么调**(§23,C1 stub 必须满足):命中后 `0x3B01A0`/`0x349AE0` 先
`call create`,然后**往对象里写** — effect 得到 `{id @ +0x20, name std::string @ +0x28}` 再
`call [vptr+0x98]`;trigger 得到 `{id @ +0x38, name @ +0x40}` 再 `call [vptr+0x80]`,`al` 的 bool 决定
`trigger.cpp` 是否打印 `'An error occurred when reading trigger.h %s'`。加上全树枚举器会对每个节点
`create`,所以 **C1 用的必须是真·良构对象,vtable 至少到 `+0x98`**,不是一槽垫片。

**时机**(§19):步骤 1 是**强制**的(解析器永不 mint token)。不需要全局同步点;真正的前置只有
两个 —— 目标 db 已拉起,以及我们的插入早于任何 *求值* 引用该 keyword。id 空间在整个启动期间持续增长
(iterator 初始化数组、惰性访问器),所以"等 id 不再变化"是错的判据。

**插入后的读回验伪,以及时序错了会长什么样**(§30):`0x1D12CD0` 会把 `[db+0x70] + id*0x30` 的反查表
从静态描述符**和**动态 map 重灌一遍,所以我们 mint 的名字应能按 `[[0x37347A0+0x70] + id*0x30 + 0x10]`
读回 —— 这条不依赖任何脚本走到 BST,是判据 ② 之外的独立只读观测(候选:守卫 `[db+0x7c] != [db+0x80]
是否被我们的 mint 触发,仍需实机)。反过来,若脚本在我们插入**之前**就引用了新 keyword,落点是
`0x5350D0` 默认分支 → `0x1D092C0` → `0x1D09330`,产出的是 **`'Unexpected token'` 错误表项 + `[obj+0x28]=1`**,
即「报错」而非「静默没命中」——杂散的 `Unexpected token` 就是时序问题的信号。
`0x1D092C0` 本身**不是**作用域变量桥(§30 判定为 error-view 构建器)。

**Zig 侧**:`src/dll/scripted/keyword_registry.zig` — 字节层(`buildDescriptor`/`ValueRecord`/`NameCheck`,
对 56 条 golden 向量做测试)+ 带门执行器(按 §19 顺序 `getToken` → `ensureDb` → `new(0x10)` → insert)。
`ClassInfo` 由调用方提供,`ClassInfo.triggerDonor`/`effectDonor` 构造 §24 决定的那对官方地址。
`scripted/lookup_hook.zig` 按 §27 建模 `NameHolder`/`ScriptedRef`,把 `out+0x00` 分类为
`Shape.{ref, null_template, unknown}`,常量在 `offsets.scripted_lookup`。
**Caveat**:db 全局需在实机会话里重读(主菜单值曾看起来像 arena/相对指针或未初始化)。

## Engine Architecture(外部研究结论)

**C++ 类名**(Linux 符号,经 stellarstellaris-win 证实):`CEffect::ExecuteActual(CEventScope*)`
(每个 effect 的入口,虚函数)、`CTrigger::Evaluate(const CEventScope&)`、`CEvent::PerformImmediate`、
`COnActionDatabase::PerformEvent`、`CToken::Init` / `CTextLexer::GetTok`。注意 `CEventScope` 的 3.x
偏移已被 §26 证伪(见上表)。

**Jomini layer**: game 与 engine 共享的库,实现 scope types / event targets / variables /
scripted effects & triggers。注册类别:Types, Promotes, Functions, Callbacks。

**关键约束的现状**:「没有公开项目成功新增过 hardcoded effect keyword」— 这条**已被正面满足**
(2026-09-29,Phase A + C0):上面的配方通过引擎自己的 `0x1D13270` + BST 插入注册**真正全新**的
keyword,不 patch 静态表,Zig 侧已写好并对引擎自己的写手做了字节校验。门是
`authorize.c1_registration = false`。

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

Script DSL features: scope chains (This/Root/Prev/From), parameterized macros, inline math `@[expr]`,
`optimize_memory` tag, conditional blocks `[[PARAM] ... ]`.
