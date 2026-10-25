# AGENTS.md — Stellaris Reverse Engineering

## Project Context

Reverse engineering `stellaris.exe` (Clausewitz engine, codename "augustus") to map the mod system's
registration pipeline and identify extension points for new effects/triggers.

**Game version**: **4.4.4**. 3.4.5–3.7.4 的地址表在 `docs/version-compatibility.md`,**不要用于 4.4.4**。
**Binary / game data 的路径、sha256、`NS_STELLARIS_EXE` 覆盖方式,以及 `evidence/` 产物的生产者**:
`docs/offline-tooling.md` 的「前置条件」。

**文档地图 —— 本文件只放约束与索引。论证、逐枪读数、判读陷阱都不在这里:**

| 内容 | 位置 |
|---|---|
| 取证 §1–§15(热路径、detour、CEffect 类图、被证伪的注册链) | `evidence/analysis/runtime_444_structures.md` |
| 取证 §16–§23(注册管线:driver、descriptor、thunk 数组、token 分配器、class_info、消费者) | `evidence/analysis/runtime_444_keyword_pipeline.md` |
| 取证 §24–§62(donor 别名与 ABI 修正、C2 QuickJS bootstrap 与自杀链 §38–§50、C4 执行路径 §52–§57、scope 载体重打两枪 §58–§59、零枪帧构造点回溯 §60、普查表第 1 行帧来源=透传 §61、普查表 12 行 `incoming_arg` 逐函数读完=全是 slot[2] 透传 §62) | `evidence/analysis/runtime_444_c1_validation.md` |
| 上面那卷的逐节索引(每节标题自带日期、授权级别、结论) | `grep '^## ' 该卷` |
| 离线脚本用法 + **全部判读陷阱**(编号在此,不在别处) | `docs/offline-tooling.md` |
| 阶段状态、前置、授权级别 | `docs/roadmap.md` |
| `api/scope` 假偏移的逐条读点处置(16 行 `src/` + 1 行 `build.zig`)与 P15 绿定义 | `docs/scope-read-points.md` |
| 脚本速查表(哪个读什么、产出哪个 artifact) | `scripts/README.md`、`scripts/test_scripts_layout.py`(约定的执行者) |
| 4.4.4 锚点全表(Frida 重锚定) | `evidence/xrefs/anchors_4_4_4.md` |
| keyword→behaviour 机器可读转储(3,900 条) | `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`(`scripts/thunkarrays.py`) |
| CEffect 类图(1,805 个 vtable,**是下限不是类数**,§14/§17) | `evidence/xrefs/ceffect_vtable_map_4_4_4.txt` |
| descriptor 回放 oracle | `evidence/xrefs/descriptor_oracle_4_4_4.tsv` |

**细计划在 `docs/superpowers/plans/`,该目录不进 git**;要状态与前置看 `docs/roadmap.md`,要步骤得在本地私有目录里找名字。

## 硬性约束(每次动手前核对)

1. **不许绕过 IDA license 门**:**do not patch `libidalib.so`'s guard branch and do not write the
   `EULA 90` registry key** — that is bypassing the license gate, not accepting it. 静态 RE 一律走
   本仓库的离线脚本(不需要 license、不需要进程、不需要暂停游戏)。
2. **不得对 session `f3ea6101` 调用 `ida_auto.plan_and_wait`** — 它把 IDA 主线程卡死 785 s。
   交叉引用用 `scripts/find_refs.py`(离线、完整)而不是 IDA xrefs。IDB 是**从 exe 建的**,没有
   Windows 侧的命名/类型历史。
3. **C1(真机注册一个新 keyword)的门现在是开的**:`src/dll/scripted/keyword_registry.zig:211` 的
   `authorize.c1_registration = true`(`:725` 的测试断言它为 true),`pub fn register`(`:419`)会走到
   执行器 `registerSequence`(`:432`)。**翻回 `false` 即撤回** —— 翻转那一个常量就是 C1 的授权步骤。
4. **任何新 keyword 名在进 `0x1D13270` 之前必须先过 `scripts/c1_preflight.py` 且退出码 0**(§25.5):
   token 查找**大小写不敏感**,`Add_Modifier` 会拿回 `add_modifier` 的 `10104`,我们的插入会**接管一个
   官方 keyword**,而 `eax` 分不清 mint 与命中。运行时同一条规则由 `keyword_registry.NameCheck` 执行。
5. **class_info 只能 ALIAS 官方的,不要伪造对象**(§24)。docstring 用 donor 自带的 `.rdata` 字符串
   (§24.6),使**我们的 DLL 没有任何指针留在 db 里** —— 引擎持有它的生命周期超过我们 DLL 的卸载。
   C4 之后 `[obj+0]` 还会指向 DLL `.data` 的 vtable 副本,已 patch 的对象会让卸载后的下一次 Execute
   跳进空页 —— 同样**永不 `FreeLibrary`**。
6. **ABI**:`0x2185218` 保留并转发完整 `rcx`,thunk 写的是 `ecx`,所以从 Zig 传 **u64** 而不是 u32;
   `0x1D13270`/`0x89F960` 的名字持有者其 std::string 在 **`holder+0x10`**,一个 char 一字节(§20/§27)。
7. **禁止热路径 detour `0x5350D0`** — 它是某个类的虚属性 getter,**detour 价值 = 0**(§28.5)。
8. **实机看到「host 死了」,先按「我们自己的产物 trip」排除**(§45)。出货的 DLL 是 **Debug** 构建
   (`build.zig` 的 `standardOptimizeOption(.{})` 默认),safety check 就编译在跑进 host 的代码里,
   一次 trip → `abort()` → 退出码 **3** → host 被杀。零游戏判别器(不要枪、不要点名):
   `scripts/c2_selfabort_repro.py`(把出货字节装进自己的子进程,读回 §46 的环形记录器 `MFREC`)与
   `scripts/dll_ubsan_site.py`(用 `.pdata` + UBSan 记录把 panic 钉到源文件行号)。
   **该机制与运行时指针值无关**(§47:报告里的指针操作数是 fallback `offsetof` 的编译期常量 0),
   所以 allocator 形状 / 记录器数据都不能当判别器。§48 的修复已实施,并有实机证据(§49 一枪、§50 压测)。
   `header-only` 改动可能命中 Zig 缓存(`compile … cached`、sha 不变),重建后先核 compile 状态与 sha。

## Evidence Collection

All analysis artifacts go to `evidence/` at project root:
`disasm/`(反汇编/伪码)、`strings/`(带地址的串引用)、`xrefs/`(交叉引用地图)、
`external/`(外部研究)、`errors/`(失败操作日志)、`analysis/`(综合报告、扩展点)、`logs/`(实机产出)。

**Naming convention**: `<component>_<finding>.md`。取证卷与 `evidence/logs/` **按 basename 记录出处,
追加不改写**;改名等于让取证记录指向不存在的文件。

## scripts/ 命名与目录约定

规则的机械部分由 `python3 -m pytest scripts/test_scripts_layout.py -q` 执行(十条规则各是一个纯函数);
下面这段是这些规则文本的权威位置。

- **顶层只放维护中的接口**:离线 PE 工具、`c1_*`/`c2_*` 实机注入通道、`windows/` launcher。一次性探针进
  `scripts/scratch/<年-月>_<主题>/`。判据两条:**只读 exe 拷贝 = 工具,需要进程 = 探针**;以及
  **有没有在用的东西依赖它**(文档、`src/` 注释、测试 import、产出的 artifact)。
- **命名:`<通道或对象>_<动作或问题>.py`**,读名字就该知道它读什么、对谁动手。禁止 `2`/`final`/`new`/`misc`
  这类版本后缀(版本属于 git,不属于文件名)。不要用 stdlib 模块名当 basename。
- **移入 scratch 的一次性脚本保留原 basename**(见上节)。
- **改维护中工具的名字是一个文档动作**,不是 `git mv` 就完:`evidence/` 里已有的引用不改写,新旧名映射记进
  `docs/offline-tooling.md`,并在被改文件自己的 docstring 里留一句旧名。
- **每个维护中的工具在 `docs/offline-tooling.md` 有一节**(用法 + 判读陷阱);新工具第一次被文档引用时就要补。
  **写死绝对路径的脚本不算维护中** —— 要么改成 `NS_STELLARIS_EXE`,要么进 `scratch/`。
- **`.py` 驱动与同名 `.js` 是一对**(驱动 + 注进去的脚本),移动必须成对。
- **`c1_*`/`c2_*` 的文件名还是 scp 到 `C:/temp/<name>.py` 的线上契约**(裁定 P5),且
  `scripts/test_c2_harness.py` 用裸名 import 它们、按「上两级」定位 `zig-out/` 的 DLL —— 这一族既不能改名,
  也不能下沉一级目录。
- **根目录 `justfile` 只做薄索引**(`just --list`);`just check` 一次跑构建 + 两套测试 + 布局围栏,它不实现逻辑。

**围栏的口径边界**(读报错前先核这几条,否则会把合规读成缺陷):`R-env` 只管**从磁盘读 `stellaris.exe`**
的脚本(带 `CreateRemoteThread` 的实机脚本被排除),候选链旁的 `D:\SteamLibrary\…` fallback 合规;
`R-pair` 与 `R-rva`(即 P10)同一口径**只扫顶层**,`scratch/` 与 `windows/` 不在范围;`R-suffix` 放行 `444`
(那是游戏版本号);`R-depth` 管 `c1_*`/`c2_*`/`test_c2_harness.py`;`R-refs` 只扫 living docs
(`AGENTS.md`、`docs/**`,剔掉私有 `docs/superpowers/`),`evidence/` 永不扫;`R-wire` 管 `justfile` 里的
`C:/temp/<name>.py` 必须对得上某个非 scratch 源文件的 basename;`R-roadmap` + `R-header` 管
`docs/roadmap.md` 的行数(≤140)、禁写私有计划路径、状态表按状态必填出处、以及表头五个列名必须齐;
`R-stray` 管 `scripts/` 子树里**文件名本身是 Windows 路径**的残留(host 测试没重定向模块全局时会落下)。
**加豁免 = 把文件名写进那条规则函数的 docstring,不是 `xfail`。**

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

只列**是什么**与**在哪论证**;行内论证的完整版在对应 §。

### keyword 注册管线(可写的扩展面)

| RVA | 含义 | 证据 |
|-----|------|------|
| `0x1D13270` | **`eax = GetOrAddToken(rcx = *name holder)` — 运行时 token 分配器**;`rdx` 死;名以 `-` 或数字开头则 `eax=0` | §18 §20 |
| `0x1D12C60` / `0x37347A0` | token DB singleton 访问器 / 对象 | §18 |
| **`0x1D12CD0`** | **`id → name` 反查表构建器**(无参):holder 数组在 `[db+0x70] + id*0x30`,静态 + 动态两半灌入 | **§30.2** |
| `0x1D15270` / `0x1D152D0` | descriptor 写手:静态路径 / 动态路径 | §20 |
| `0x1D158A0` | 两条路径共用的 slot writer ⇒ 运行时 descriptor 与静态字节一致 | §18 §20 |
| `0x337B400` | descriptor 数组,**stride `0x120` × 9,863**,只含 `{token id, SSO name}`,无 behaviour 槽 | §17 §20 |
| `0x247F480..0x2494070` | keyword 名字池(上面 SSO 串的载体) | §17 |
| `0x172E50..0x1AF1E7` | token-name driver(每 entry 一个 `lea rcx,[0x337B400+0x120*n]`) | §17 |
| `0x23AC600` ×754 / `0x23AF628` ×482 / `0x23B0540` ×405 | effect / trigger **注册 thunk 数组** | §17 |
| `0x33746E8` / `0x32611C8` | ScriptedEffectDB / ScriptedTriggerDB 全局;BST 根在 `[db+0x18]` / `[db+0x88]` | §1 §21 |
| `0x3AEBA0` / `0x347BD0` | db 拉起:effect placement ctor(要 caller 先 `new(0x70)`) / trigger 无参 ensure | §21 |
| `0x3AEF60` / `0x348150` | BST insert,**参数形状相同但不可互换** | §21 |
| `0x3B01A0` / `0x349AE0` | **消费者**:按 token id 查树并 `call create`,键无范围检查 | §23 |
| `0x3AF130` / `0x348450` | 全树枚举,对每个节点 `create` ⇒ **注册不是惰性的** | §23.3 |
| `0x260ABD8` | `add_modifier` 的 class_info(deleter `0x34C090` 是**共享** deleting destructor) | §17 §22.2 |
| `0x269CAA8` / `0x2611070` | **C1 donor class_info**:trigger `has_crisis_perk` / effect `hidden_effect` | §24 §24.6 |
| `0x26C1BA0` / `0x2616260` | donor 自带 `.rdata` docstring(C1 用这两个,不用我们的串) | §24.6 |
| `0x2185218` | `operator new(size)` | §17 §21 |
| `0x1930E70..0x196D3E6` | 101 个 scope-iterator 注册函数 — **官方自带的加 keyword 模板,可直接照抄** | §19 |
| `0x195A580..0x19A7268` | 104 个 iterator **名字拼接器**(头 keyword 可以完全没有静态 descriptor) | §25.4 |
| `0x388130`…`0x389224` / `0x3797C0..0x37B056` / `0x114CE0` | 惰性 token 访问器 / `mod_%s` 生成器 / 仅被 `.rdata` 引用的 25 B shim | §19 |

### 热路径与执行

| RVA | 含义 | 证据 |
|-----|------|------|
| `0x1D08520` | **`CEffect::Execute` (base) — 热路径**,~5,300 calls/s,派发到 `call [rax+0x10]` = slot[2] | §10 §14 |
| `0x1D08520` arg2 | **调用方内联构造的 0x20 B 执行深度帧**:`+8` 是调用深度计数,`+0x10` 是 helper;**不是** scope 对象 | §26 §53 |
| `0x3B1330` | effect `[vptr+0x70]` base impl = 递归 parse(子向量在 `[obj+0x10]`/`[obj+0x1c]*8`) | §24.4.2 |
| `0x3B1420` | effect `[vptr+0x98]` base impl = **bool 谓词**,不是 parse(§52 的 detour 点) | §23.1 §52 |
| `0x3AFD30` | donor `hidden_effect` 的 `[vptr+0x08]` Execute 覆写;实机保持 OFF | §52 |
| `0x2606FE0` | donor effect vtable,25 槽可复制(slot[1]=Execute、slot[2]=instantiate、slot[19]=谓词) | §52 |
| `0x89F960` / `0x8A0450` | `GetScriptedEffect` / `GetScriptedTrigger` — **不是 getter**;唯一副作用是重复定义告警 | §27 |
| `0x1C91C30` | 上述重复告警走的 logger | §27 |
| `0x24B1990` | `CScriptedEffectTemplate` vtable(CEffect 家族**没有 RTTI**) | §14 |
| `0x1B5B10` | `CScriptedEffectTemplateDatabase` ctor(中可信度) | `anchors_4_4_4` |
| `0x5BBF80` | token-id 二分查找派发树 — **不是 keyword 注册表** | §17 |
| `0x9F5750` / `0x9F6420` / `0x9F65E0` | Event command handlers(需更深 trace 选点) | `anchors_4_4_4` |

### 已证伪 — 不要再当锚点用

| 曾经的断言 | 实况 | 证据 |
|---|---|---|
| `0xCCCEB0` = master keyword registrar | **false**;唯一调用方是通用的 token→对象运行时处理 | §15 |
| `0x337A844` = 一次性注册守卫 | 是 trace-enable bool(C3 旧触发条件作废) | §16 |
| effect dispatch switch(3.x `0x180B050`) | 4.4.x **不存在**;改为 per-class vtable 派发 | §3 §14 |
| lexer/parser 会从脚本文本 mint token | **false**;mod 里的新词**不会**有 id,DLL 必须自己调 `0x1D13270` | §19 |
| `0x5350D0` = keyword 执行器 / 真实扩展面 | 是按 token-id 的属性 getter,**0 个直接调用点** | §26.1 §28 |
| `0x1D092C0` 可作 JS 作用域变量桥 | **已否**:它是 parse-error 表追加器。真正的按名变量查找**仍未定位**,不要再从这里找 | §28.3 → §30 |
| `0x337ACBC` 像「脚本错误计数」 | 是**递归深度** global(净为零) | §30 |
| 3.x `CEventScope` 布局(`+8`/`+16`) | 被 §26 证伪;`src/dll/api/scope.zig` **仍在读那两个偏移且已链进 DLL**,由 `LAYOUT_CONFIRMED = false` 的测试钉住,逐条处置见 `docs/scope-read-points.md`。**哪个对象是 scope 仍未定**(§56 没能确立;§59 按修正仪器问完四根,负结论这次是「问完了」的,且 §60 未重新起诉它)。**执行帧的构造点在承载函数路线上已定位**(§60 判决 `frame_ctor_found`,限于该路线):承载函数 `0x1c42fe0..0x1c43884` 自己写帧,`0x16fdc0`/`0x1d129a0` 判死为写者;**谁经队列派发**(`[0x26d4dd0+0x28]` 形态的派发方集合)仍是 §60.7 未决项;普查表第 1 行 `origin=incoming_arg` 的帧来源**已由 §61 判完(仅限该行)** —— `0x1bcd120` 对帧是纯透传,365 个共享槽全在 slot[2] = `call [rax+0x10]` 派发槽,该行与第 2 行同源,§60.7-5 折叠进 §60.7-1;**其余 11 行已由 §62 逐函数读完 —— 12 行(9 个函数)全是 floor map 的 slot[2] `ExecuteActual` 覆写,承载寄存器只在函数头从入参 rdx 抄一次、站点全是 `call 0x1d08520` 直调、除 `+8` 深度计数(27 处)外**零帧字段写**、零栈上 `lea` 构造 ⇒ 整个 `incoming_arg` 集合同源,§60.7-1(谁经队列派发)仍开放** | §26 §53 §56 §59 §60 §61 §62 |
| `X=[arg2+0x30]→S→id/obj` 可拿 effect token/object | **false**:arg2 类大小 0x20,`+0x30` 在对象外;X 是 `.rdata` vtable、S 是代码 | §53.3 |

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

- **插入后引擎怎么写、怎么调**(§23):命中后消费者先 `call create` 再**往对象里写** —— effect 得
  `{id @ +0x20, name @ +0x28}` 再 `call [vptr+0x98]`;trigger 得 `{id @ +0x38, name @ +0x40}` 再
  `call [vptr+0x80]`。全树枚举器会对每个节点 `create`,所以 **C1 用的必须是真·良构对象,vtable 至少到 `+0x98`**。
- **时机**(§19):步骤 1 是**强制**的。前置只有两个:目标 db 已拉起,且插入早于任何*求值*引用该 keyword。
  id 空间在整个启动期间持续增长 ⇒ "等 id 不再变化"是错的判据。
- **读回验伪 / 时序错了长什么样**(§30):mint 的名字应能按 `[[0x37347A0+0x70] + id*0x30 + 0x10]` 读回;
  若脚本在插入前就引用新词,落点是 `0x5350D0` 默认分支 → `0x1D092C0`,产出**`'Unexpected token'` 错误表项**,
  即「报错」而非「静默没命中」—— 杂散的 `Unexpected token` 就是时序问题的信号。
- **Zig 侧**:`src/dll/scripted/keyword_registry.zig`(字节层 + 带门执行器)、`scripted/lookup_hook.zig`
  (按 §27 建模 `NameHolder`/`ScriptedRef`)、常量在 `offsets.scripted_lookup`。
- **Caveat**:db 全局需在实机会话里重读(主菜单值曾看起来像 arena/相对指针或未初始化)。

## Engine Architecture(外部研究结论)

**C++ 类名**(Linux 符号,经 stellarstellaris-win 证实):`CEffect::ExecuteActual(CEventScope*)`、
`CTrigger::Evaluate(const CEventScope&)`、`CEvent::PerformImmediate`、`COnActionDatabase::PerformEvent`、
`CToken::Init` / `CTextLexer::GetTok`。注意 `CEventScope` 的 3.x 偏移已被证伪(见上表)。

**Jomini layer**:game 与 engine 共享的库,实现 scope types / event targets / variables / scripted
effects & triggers。注册类别:Types, Promotes, Functions, Callbacks。

**关键约束的现状**:「没有公开项目成功新增过 hardcoded effect keyword」— 这条**已被正面满足**(Phase A + C0):
上面的配方注册的是**真正全新**的 keyword,不 patch 静态表,Zig 侧已对引擎自己的写手做了字节校验。

## External References

- **stellarstellaris-win**: https://github.com/MattMills/stellarstellaris-win — DLL injection + hook framework, versioned VA tables for 3.4.5–3.7.4
- **rakaly/jomini**: https://github.com/rakaly/jomini — Rust parser for Clausewitz text+binary saves
- **CWTools**: https://github.com/cwtools/cwtools — F# validator with per-game effect/trigger databases
- **class101 Ghidra guide**: Steam community "Enabling Achievements in Stellaris With Mods [SRE]"

## Game Data Structure

The engine auto-registers script definitions by scanning `common/` subdirectories:
`scripted_effects/`(42 files, `$PARAM$` 宏)、`scripted_triggers/`(37)、`on_actions/`(4)、
`scripted_actions/`(6),外加 `events/`(170 files)。

Script DSL features: scope chains (This/Root/Prev/From), parameterized macros, inline math `@[expr]`,
`optimize_memory` tag, conditional blocks `[[PARAM] ... ]`.
