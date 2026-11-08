# 版本漂移:地址 vs 结构(4.4.4 离线读数)

**这份文件回答一个问题:「版本适配 = 改地址偏移 + 简单逻辑修改」这句话,在什么范围内成立?**

只做三件事:把 3.x 的旧表与 4.4.4 的锚点表按**名字**(不是值)取交集;给每个交集锚点判
`address` / `structure`;给一组可复算的统计数。结论只有一句,在 §5。

**口径声明。** 本文件不新增任何 RE 事实 —— 每个 4.4.4 值都来自已经入库的出处(`AGENTS.md` 的
RVA 索引、`evidence/xrefs/anchors_4_4_4.md`、`docs/version-compatibility.md`、取证卷 §3/§14/§26/§27/§53.3/
§75/§77)。本文的**新东西是分类与计数**,不是地址。地址变了要重打的是那几份出处,不是这里。

**证据等级(本文自用,不替代别处的 `High/Med/Low`):**

| 等级 | 含义 |
|---|---|
| **A** | 双侧独立证人(逐字节 / 调用点 / 实机读数),且语义由「调用它的地方 + 参数形状」验证过 |
| **B** | 单侧静态证人(一处引用 / 一张表),语义**未**由调用点验证 |
| **C** | 候选:只有形状或同族类比,没定性 —— 任何判据都不该只靠 C 级锚点 |

---

## §0 分类判据(先写判据,再列表)

| 类 | 定义 | 补丁后重锚的代价 |
|---|---|---|
| `address` | 一个函数或全局的**入口**:语义可由「谁调用它 + 参数形状 + 它引用哪个字符串」重新验证 | 便宜:重跑 `scripts/find_refs.py` / `fastcalls.py` / `strrefs.py`,地址换掉即可 |
| `structure` | 依赖**对象布局**、**vtable 槽号**、**字段偏移**、**容器步长** | 贵:入口找回来也不够,必须重新证明「这个偏移上是什么」;旧的验证手段(读 DWORD、按 sizeof 算槽)全部失效 |

`structure` 不是「更难的 address」,它是**另一个问题**:address 的失败是「跳错地方」(立刻可见、
崩在有栈的地方);structure 的失败是「读对地方、读错格子」(不崩,读出看起来合理的垃圾 —— 取证卷
§26、§53.3 两次都是这个形状)。

---

## §1 两边的候选集(定义,让计数可复算)

**3.x 侧(候选集 = 16 个具名锚点 + 6 个文件字符串 = 22 条)。** 取 `docs/version-compatibility.md`
里 `## Verified Offsets` 起、到 `## Scripted Effect/Trigger Threshold` 前的全部具名行:

```bash
sed -n '/^## Verified Offsets/,/^## Scripted Effect/p' docs/version-compatibility.md
```

数出来是:3 张布局表(CEffect / CEventScope / CTrigger)、Hook Addresses 2 行
(`CEffect::ExecuteActual`、`CTrigger::Evaluate`)、Global Data Addresses 5 行
(GameState / CountryDB / ScriptedEffectDB / ScriptedTriggerDB / EventDB)、3.4.5–3.7.4 地址表的
6 个函数行(dispatch switch、两个 template registration、String-to-ID、Database registration、
Event command handler)—— 该表另有 5 个全局行,与上面那 5 个**重名**,按一条计 ——
再加 6 个 source-file 字符串。**16 = 3 + 2 + 5 + 6**。

**4.4.4 侧(候选集 = `AGENTS.md` RVA 索引签字的那批)。** 权威表是
`evidence/xrefs/anchors_4_4_4.md`,它的每一行**自己**带 3.x 旧值(「3.x VA (RVA)」列)——
所以「它是同一个锚点」这件事不是我配的,是那张表配的。

**取交集的方式:** 3.x 行与 4.4.4 行**名字/角色相同**才计一条。名字不同但角色被 4.4.4 表显式
断言相同的(例:`Scripted effect template registration` ↔ `GetScriptedEffect`),按 4.4.4 表的断言计。
名字与角色都对不上的(GameState / CountryDB / String-to-ID / Database registration /
`SCRIPTED_EFFECT_BASE`)**不计**,列在 §2.4 的「未交集」里。

**交集 18 = 12 个具名(9 个函数/全局 + 3 张布局表)+ 6 个字符串。** 22 − 18 = 4 条具名未交集
(加 1 条阈值,见 §2.4)。

---

## §2 交集表(18 行)

「4.4.4 值」列是**当前**的落点;「判」列 = 我给的类;**「变了吗」列才是关键** ——
`address` 类里也可能藏着语义/形态变化。

### §2.1 函数 / 全局锚点(9)

| # | 锚点 | 3.x | 4.4.4 | 判 | 变了吗 | 证据 |
|---|---|---|---|---|---|---|
| 1 | ScriptedEffect ref builder | `0x8A6EB0` | **`0x89F960`** | address | 地址移位 **+ 语义换了**:3.x 当它是「注册/取回」,4.4.4 上它**不是 getter** —— 唯一副作用是重复定义告警 | anchors_4_4_4 High;取证卷 §27 |
| 2 | ScriptedTrigger ref builder | `0x8A79A0` | **`0x8A0450`** | address | 地址移位;语义同 #1(孪生) | anchors_4_4_4 High;§27 |
| 3 | ScriptedEffectDB 全局 | `qword_14339AEA8` | **`0x33746E8`**(BST 根 `+0x18`) | address | 纯移位 | anchors_4_4_4 High;§1/§21 |
| 4 | ScriptedTriggerDB 全局 | `qword_143287968` | **`0x32611C8`**(BST 根 `+0x88`) | address | 纯移位 | anchors_4_4_4 High;§21 |
| 5 | Effect dispatch(主 switch 那一带) | `0x180B050` | `~0x180A9xx`(同 RVA 带) | address | **形态换了**:4.4.4 没有主 switch,改为 per-class vtable 派发(base Execute `0x1D08520` → `call [rax+0x10]`) | anchors_4_4_4 Med;§3/§14 |
| 6 | Event command handler | `0x9FCE90` | `0x9F5750` / `0x9F6420` / `0x9F65E0`(三个) | address | 一拆三;靠 `eventcommands.cpp` 串定位 | anchors_4_4_4 Med |
| 7 | Event manager / EventDB | `qword_14339AFE8` | `0x402C50` / `0x400920`(候选,`Low — TBD`) | address | **未收口**:3.x 是全局,4.4.4 只有两个代码候选 | anchors_4_4_4 Low |
| 8 | `CEffect::ExecuteActual` | `0x14181B740` | base Execute **`0x1D08520`** + slot[2] 覆写集合(543 个不同实体) | address | **结构变了**:3.x 一个函数 = 全部实例的 ExecuteActual;4.4.4 是一层基体 + 每类覆写 | §10/§14 + §17 |
| 9 | `CTrigger::Evaluate` | `0x1408A6F20` | 谓词槽 `0x349230`(`[vptr+0x80]`)+ 求值槽 `0x1A91A80`(`[vptr+0x28]`) | address | 一拆二,且两槽都不是「每系统一次」 | §75/§76/§77/§79 |

### §2.2 文件字符串锚点(6)

| # | 锚点 | 3.x | 4.4.4 | 判 | 变了吗 | 证据 |
|---|---|---|---|---|---|---|
| 10 | `effect_impl.cpp` | `0x14260ee30` | `0x26162c0` | address | 纯移位(361 个代码引用,231 个函数) | anchors_4_4_4 |
| 11 | `scriptedeffect.cpp` | `0x14253bb70` | `0x25181d0` | address | 纯移位(1 个引用) | 同上 |
| 12 | `scriptedtrigger.cpp` | `0x14253bc60` | `0x25182c0` | address | 纯移位(1 个引用) | 同上 |
| 13 | `eventcommands.cpp` | `0x142548290` | `0x2524780` | address | 纯移位(6 引用 / 3 函数) | 同上 |
| 14 | `eventmanager.cpp` | `0x142511938` | `0x24ee4e0` | address | 纯移位(24 引用 / 9 函数) | 同上 |
| 15 | `game_singleobjectdatabase.h` | `0x1424d7c30` | `0x24b46e0` | address | 纯移位(166 引用 / 165 函数) | 同上 |

文件字符串是**最便宜**的一类:它们不是「地址」而是「内容 + 位置」,内容由 `__FILE__` 字面量决定,
所以重锚的方式是内容匹配而不是偏移推算。它们在这张表里的作用是**指纹**,不是调用目标
—— 见 §6 的 loader 校验。

### §2.3 三张布局表(3)

| # | 锚点 | 3.x | 4.4.4 | 判 | 变了吗 | 证据 |
|---|---|---|---|---|---|---|
| 16 | CEffect 对象布局 | 名 `+0x038`、id `+0xFF0`、vtable `+0x6A8` | **已证伪**;4.4.4 上 `{id @ +0x20, name @ +0x28}` 是消费者 `call create` **之后**写进去的 | structure | **断裂**:槽号体系不同(基体 slot[1]=`0x3AFD30`、slot[2]=ExecuteActual、slot[19]=谓词、`+0x70`=parse) | §14/§23 + 本文 §4.1 |
| 17 | CTrigger 对象布局 | 名 `+0x038`、id `+0xFF0`、vtable `+0x6A8` | **已证伪**;`{id @ +0x38, name @ +0x40}` 再 `call [vptr+0x80]` | structure | 断裂,同 #16 | §23 |
| 18 | CEventScope 布局 | 类型 `+0x08`(i64 bit flag)、id `+0x10`(i64) | **已被 §26 证伪**(`[arg2+0x8]` 那里是**调用深度计数器**);**真 scope 对象到 4.4.4 仍未定**(§56/§59/§68 三发,负结论「问完了」) | structure | **断裂且未收口** | §26/§53.3/§56/§59/§68 |

### §2.4 计数

| 统计 | 数 | 复算方式 |
|---|---|---|
| **交集锚点数** | **18** | §2.1 九行 + §2.2 六行 + §2.3 三行 |
| **`address` 数** | **15** | 9 + 6 |
| **`structure` 数** | **3** | 三张布局表 |

未交集(3.x 有、4.4.4 落不了地):**5 条** —— `GameState`、`CountryDB`、`String-to-ID registration`
(`0x140173C30`)、`Database registration`(`0x1401B6CA0`)、`SCRIPTED_EFFECT_BASE = 4081`。
其中 `SCRIPTED_EFFECT_BASE` 的现口径是「一次观测,不是分配基数」(§29),所以它连「漂移」都谈不上。

---

## §3 三个数读出来的不是结论,是三个问题

**结构类只占 3/18 = 17%。** 如果就这样把「只改偏移成立 83%」写进 roadmap,那是骗人的 ——
原因有两条,都不是计数问题:

**(a) 三个 `structure` 恰好是运行时每 tick 都要用的那三个。** scope 是谁、effect 对象的 id/名字在
哪一格、槽号怎么排 —— 这三个不成立时,**其余 15 个 `address` 锚点一个也用不上**:它们只负责
「把描述符插进 BST」,而插进去之后引擎怎么执行,全在 `structure` 那三格里(§23 的
`call create` → 写 `+0x20`/`+0x28` → `call [vptr+0x98]`)。

**(b) `address` 类里已经混进两条「语义/形态变了」的**,而且都在关键路径上:

- #5「Effect dispatch switch」:RVA 带没怎么动(3.x `0x180B050` → 4.4.4 `~0x180A9xx`),
  但**主 switch 在 4.4.x 不存在**。一个 `address` 锚点被保住了,用法却整个换掉。
- #1「ScriptedEffect 注册/取回」:地址换了一格,但它在 4.4.4 **不是 getter**(§27)——
  拿它当 lookup 会得到「永远命中/永远不命中都不可观测」的结果。

所以真正的判据不是「多少条是 structure」,而是**「你依赖的那条语义,有没有被调用点验证过」**。
`address` 类的定义里已经写了这件事(§0 判据),上面两条是它没兑现时的样子。

---

## §4 三条「结构断裂」的实例(为什么它不崩、只读错)

### §4.1 槽号体系断裂(CEffect)

3.x 的表说 vtable 在 `+0x6A8`、id 在 `+0xFF0`。4.4.4 上:

- 对象 `[obj+0]` 是 vtable,**id 在 `+0x20`、名字在 `+0x28`**,而且都是消费者 `call create`
  之后写进去的(§23)—— 即「对象一创建就有的字段」这句话本身不成立;
- 基体 `0x1D08520` 的派发是 `call [rax+0x10]`(slot[2]),predicate 在 slot[19] `+0x98`,
  parse 在 `+0x70`,body 在 `+0x48`(§91.6)。

偏移与槽号全换,而且是**两套**坐标(id 用字段偏移、执行用槽号)。拿 3.x 的 `+0xFF0` 去读 4.4.4 的
对象,读出的是分配器残留或邻居对象的内容 —— 不崩。

### §4.2 分发形态断裂(主 switch → per-class vtable)

3.x 的 `effect_impl.cpp` 有一个 254+159+166 分支的主 switch,按 `object+104` 的 effect id 分派。
4.4.4 上**不存在**这个 switch(§3/§14):每个类自己的 vtable 里 slot[2] 就是它的 ExecuteActual
(1,805 张 vtable 里 543 个不同的实体)。这条变化把「我只要找到 switch 在哪」从一个
`address` 问题变成了「我得知道每个类的槽表」。

### §4.3 `+0x30` 那一族(帧/scope 的取值路线被证伪)

`CEventScope` 的 3.x 布局(`+8` 类型 / `+16` id)在 4.4.4 上被两件事同时否掉:

1. **§26**:`CEffect::Execute` 的第二实参 `[arg2+0x8]` 在 `call [vptr+0x10]` 前 `+1`、后 `-1`
   —— 那是调用深度计数器,不是 scope 类型;
2. **§53.3**:`X = [arg2+0x30] → S → id/obj` 这条取值路线也死了 —— arg2 那个类大小 0x20,
   `+0x30` 在对象外;X 是 `.rdata` 的 vtable、S 是代码。

⇒ 今天真正能用的 scope 形状是从**逐系统派发**那一侧量的(§80.2/§91.7:`+0x08` mask、
`+0x10` id,系统 mask = `0x80`),不是从 `Execute` 的第二实参反推的。这条区别是 §5 判决的地基:
**「改偏移」的前提是偏移所在的坐标系还在;3.x 的 scope 坐标系已经没了。**

---

## §5 判决:**「只改偏移」在什么范围内成立**

> **成立的范围 = 一个锚点的语义由「调用它的地方 + 参数形状」验证过,且它不携带对象布局的时候。**
> 具体到 4.4.4:18 个交集锚点里 **13 条**落在这一档(9 个 `address` 去掉 #1/#5 两条语义已变的
> = 7,加 6 个文件字符串),**5 条不成立**(3 张布局表 + #1 + #5)。
>
> **这 13 条恰好只覆盖「注册/写入」那一半;「执行」那一半一条都不在。** 也就是说:
> `版本适配 = 改地址偏移 + 简单逻辑修改` 能让你**把 keyword 注册进去并让它出现在日志里**,
> 但**不能**让你安全地读 scope、读 effect 对象、或猜派发槽。

推论(写给下一次大版本):

1. **每个大版本必须重做的:** scope 对象形状、effect/trigger 对象的字段与槽号、派发形态。
   这三件事不是「偏移表更新」,是「重新取证」—— 4.4.4 花掉的是 §26/§53/§56/§59/§60–§68 十几发。
2. **可以只改偏移的:** 两个 db 全局、两个 ref builder、event command handler、6 个文件字符串。
   条件是**每条都要重新回答一次「它的语义还是我以为的那个吗」**(#1/#5 就是反例)。
3. **不要用「结构类占比」当判据。** 3/18 会被读成便宜,5/18 也不是重点 —— 重点是**那 3 条正好是
   每 tick 都用的那 3 条**。判据应该是「执行路径上有没有一条未验证的 `structure` 锚点」;
   有一条,这一版就只能读不能写。

---

## §6 loader 应当做的校验(指纹 / 字段抽查 / 失败话术)

这一节是 §5 的**可执行形式**:把「语义验证」压成三条机械检查。三条都已在仓库里有先例。

| 检查 | 做什么 | 先例 |
|---|---|---|
| **① 版本指纹** | `stellaris.exe` 的 sha256 必须在 `SUPPORTED` 表里;**不在就一行 `NEO_PLAY fail reason=version_unsupported`,不写任何引擎状态** | `scripts/windows/neo_install.py`(本计划 Task 1) |
| **② 代码指纹** | 每个要 hook / 要直调的 RVA,装之前比一段**字节指纹**(不是只比 RVA);不一致就拒绝 | `src/dll/c2/neo_dispatch.zig` 的 `EXPECTED_CODE`(19 B)+ `fingerprintMatches()`;各 `c2_*_probe` 的 32 B 指纹 |
| **③ 字段抽查** | 拿到 scope 后先核 `+0x08` mask 与 `+0x10` id 的**已知关系**(例:当下发 id ∈ 容器集、mask 是期望值);不成立就 fail-closed,不写 | `neo_vtable.runBody` 的 `isSystemScope` 门 + `writeSystemVariable` 的 `wrong_scope` 分支 |

失败话术固定两段:**一行回执 + 一句「不支持这个版本」**,不打印 traceback(除非 `--debug`),
不写坏存档(§Global Constraints 的 fail-closed)。`NEO_PLAY fail reason=<tag>` 的 tag 表见
`docs/runtime-js-sdk.md`。

---

## §7 这一节不能说的(三条)

1. **这 18 条不是 4.4.4 的全部锚点。** 交集只覆盖「两边都点过名」的那些;`AGENTS.md` RVA 索引里
   真正在用的(`0x1D13270`/`0x3AEF60`/`0x348150`/`0x1D15270`/`0x3B0F80`/`0x3B1330` …)3.x 侧根本
   没有同名行,它们**不在**统计里。
2. **#7 是 C 级,不是 B 级。** `Event manager / EventDB` 的 4.4.4 落点仍是 `Low — TBD`;把它算进
   `address` 是因为「3.x 的 EventDB 是个全局、4.4.4 侧有两个候选」这件事本身还是地址问题,
   不是因为那两个候选被验证了。
3. **「13 条可只改偏移」是一句**上限**。** 它说的是「这 13 条的**入口**能靠偏移+语义复核找回」,
   不是说「4.4.4 的运行时可以只靠这 13 条工作」。执行那一半仍在 §5 的「必须重做」里。
