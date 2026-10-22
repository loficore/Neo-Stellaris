# docs/roadmap.md — 阶段计划与授权状态

本文件是那份 449 行叙述性计划的归位结果:**只放状态、门、指针**。论证一律在 `evidence/analysis/runtime_444_*.md`
三卷里(§1–§15 `structures`、§16–§23 `pipeline`、§24–§37 `c1_validation`),这里一个都不重复。
细计划不进 git,所以本表只写它们的**文件名**:要状态与前置看这里,要步骤得在私有 plans 目录里按名字找。
防再膨胀的机械判据是 `scripts/test_scripts_layout.py` 的 `violates_roadmap_shape`(≤140 行、状态词表、按状态必填出处)。

## 1. 目标与判据

> 创建出一个**新的 mod 系统**，而非只能复现一遍现在的官方 mod 系统。比如判定哪个星系是交通要道，
> 通过 QuickJS 根据这个来给各个星系加上新的 effect；或者种族占比会影响资源产出、以及对其母国的
> 外交和战争态度之类的。

判据：新能力必须**表达不出**于现有 DSL（scripted_effects 只是宏展开），同时不改动官方 mod 系统语义。

## 2. 授权门

| 门 | 状态 | 翻它要改哪一行 | 上次授权动作 |
|---|---|---|---|
| `authorize.c1_registration` | **开** | `src/dll/scripted/keyword_registry.zig:211` 现为 `true`;翻回 `false` 即撤回 | 2026-10 的 C1:注册 trigger `neo_effect` + effect `neo_action` |
| 实机只记录 detour `0x1D08520` | **只在点名时** | 无常量可翻;装与拆都要明确指令 + 等热路径静默窗口 | 铁律:`ExecHookVerify != 0` 时绝不 `FreeLibrary` |
| 实机枪预算 | 见在飞计划 | 预算归各计划自己的 Global Constraints,本表不重复数 | — |

`AGENTS.md` 约束 1–7 的文本不在这里复制 —— 段2 只记**状态与改动点**,约束文本继续住在它唯一的权威位置。

## 3. 阶段状态表

已经钉死、不必重做的四条(文字照旧计划的句子,证人 § 在最后一列):

| 事实 | 出处 |
|---|---|
| base Execute = RVA `0x1D08520`，两个整数参数，`call [rax+0x10]` 派发到实例的 **vtable slot[2]**（即 `ExecuteActual`）| structures §10/§14 |
| 一次**完整**普查（hist_overflow=0）：316,468 次调用 / 291 个不同 shim / invalid 0.15% | structures §13 |
| CEffect 家族静态全图：**1,805 个 vtable → 543 个不同 ExecuteActual 实体**；**口径修正**：该计数只统计 slot[1] 仍为 base Execute `0x1D08520` 的 vtable，**覆写了 Execute 的类不在内**，所以 1,805 是下界而非类总数 | structures §14 + pipeline §17 |
| 该 build **没有 RTTI/COL**（对全部 1,805 个测过）→ 类别身份只能来自字符串池与行为 | structures §14 |

第五条旧事实「静态输入已在本地」不在这里重复:exe 路径、完整 sha256、`NS_STELLARIS_EXE` 覆盖方式见
`docs/offline-tooling.md` 的「前置条件」一节。

**实机枪可用的前提是 Windows 机时与 SSH 隧道在 —— 这是环境约束,不是门。**

| 阶段 | 状态 | 证据 | 计划 | 第一前置 |
|---|---|---|---|---|
| A | done | pipeline §17/§18/§19,c1_validation §25 | — | — |
| B3 | planned | — | `2026-10-22-b3-fridadis-bringup.md` | 把 `scripts/dis.js` 送到 `C:\ns\dis.js` |
| api/scope 假偏移 | planned | c1_validation §26 | `2026-10-22-scope-false-offset-consolidation.md` | 无(纯离线,今天就能开工) |
| C0 | done | pipeline §20/§21 | — | — |
| C1 | done | c1_validation §24/§24.6 | — | — |
| C2 | blocked | c1_validation §36/§37 | `2026-10-22-c2-live-death-localization.md` | 那个计划的 Task 3 实机一枪(需 Windows 机时 + SSH 隧道) |

为什么顺序是 C0→C1→C2:C0 在**离线**把「我们造的描述符到底像不像真的」证实到字节;C1 在**实机**把「别名式注册
能不能活过 create + write + predicate 链」证实;C2 才轮到「让 keyword 执行 JS」—— QuickJS 不在注入环境里活下来,后面没有一步能开工。

## 4. 候选条线

每条四要素:判据 / 前置 / 所需授权级 / **为什么现在还不能写成计划**(缺的多半是「步骤能从现有事实写出来」)。
授权级记号:**无** = 纯离线;**点名** = 明确指令下的实机只记录动作;**一枪** = 一次远程 dispatch(计入该机时的枪数)。

- **B2 七把 shim 各 2,090 次的复采**：判据 = 换一个场景仍是 2,090 ⇒ per-system 循环，正是「星系交通要道」类效果要的抓手。
  前置 = 热路径静默窗口；授权级 = 点名；不能成计划 = 选哪个场景要先有新观测（§13）。
- **B4 九个 Meyers 惰性访问器绑定的关键字名字**（`0x388130`…`0x389224`，buffer 在镜像里是零）：判据 = 首次使用时铸出的 id 与名字。
  前置 = 游戏在跑；授权级 = 点名(只读)；不能成计划 = 它不影响 Phase C 任何判据，默认不做（§19）。
- **C4 试点一 `chokepoint_score`**：判据 = 按图连通度给星系打上我们自己的新 effect，日志与行为都可见。
  前置 = C2 活到能跑 JS；授权级 = 一枪 + 实机可见行为（注册门已开,不需新常量）；不能成计划 = 「连通度数据从哪来」还没有答案,写步骤就是编造。
- **C5 试点二 种族占比 → 资源产出 / 对母国的外交与战争态度**：判据 = 段1 那句的第二个例子真的改变了游戏行为。
  前置 = 与 C4 同一面（跨 scope 聚合），授权级同 C4；不能成计划 = 没有 spec，且要读的字段还没按 4.4.4 钉过。
- **C6 验收**：判据 = 日志 + 可复现行为，且官方 scripted_effects 路径不受影响。
  前置 = C4/C5 至少一条落地；授权级 = 实机观测,不新增门；不能成计划 = 验收对象的形状还没定。
- **launcher `LAUNCHER_CLICK` exit-23**(`EXIT_LAUNCHER_NO_ADVANCE`：三轮点击 + settle 后窗口不推进)：判据 = 缺陷定位到具体那一步。
  前置 = Windows 机时 + SSH 隧道（环境约束,非门）；授权级 = 一枪(定位缺陷要远程实跑 launcher 观测,每次跑都占该机时枪数)；不能成计划 = 连「点击没送达」还是「窗口判断错」都还不知道(`scripts/windows/launch_stellaris.py`)。
- **真正的 `CEventScope` 是哪个对象**：判据 = 拿到一个真的 `arg2` 并逐字段读通。
  前置 = 段3 那条只记录 detour 交出现场；授权级 = 点名；不能成计划 = 离线拿不到，§26.2 明写仍未定。
- **`0x24F9910` 的槽号归属**：判据 = 那个数组的偏移各对应哪个虚槽。
  前置/授权级 = 更深静态(**无**)或实机(点名)；不能成计划 = §28.4 已判定它不可当前提,没有可执行的判据依赖它。
- **孤儿 `effects/handler.zig` + `triggers/handler.zig`**：判据 = C3 的 JS 路由层真的经过这两个文件。
  前置 = C2 通过；授权级 = **无**(纯 src 改动)；不能成计划 = §29 已决「留」(与 `id_mapper` 的不对称是刻意)，等的就是 C3 —— 若 C3 最终不经过这层路由那时再删。
- **Zig `extern fn` 绑定 QuickJS C 函数的根治**：判据 = 对比 Zig 调用桩与 C wrapper 的 `call` 序列后给出机制。
  前置 = 段5 的 C 包装绕行使它能长期延后；授权级 = 复现崩溃要一枪；不能成计划 = ABI 不匹配与 TLS 初始化两个假设还没分开(§36)。

## 5. 仍生效的决策

- **走全路**(真·新 keyword),**便宜路**(注册成 scripted effect + detour `0x1D08520`)作为对照实现保留。依据是段1 的判据:
  跨 scope 聚合便宜路表达不出;而两条路共用同一个 `0x120` 描述符与同一条铸 id→插 BST 链,所以先做 C0 不影响选路。
- **未定义字节保持显式清零**(`0x1D158A0` 从不写 `+0x05..07` 与名字 terminator 之后的尾部)⇒ oracle 才能逐字节判定;
  实机若在这两处读到非零,那是分配器残留,不是语义。
- **覆盖率 = 56 golden + 全量 tsv**:Zig 测试内嵌 56 个引擎产物向量,9,863 条全量比对留在
  `evidence/xrefs/descriptor_oracle_4_4_4.tsv`,不把 1 MB 十六进制塞进二进制。
- **`.i64` 不拷本机** —— 现状那句在 `docs/offline-tooling.md:15`(文件留在 Windows,不在本机);理由是 Phase A 全程靠
  capstone + `.pdata` + relocated-qword 三件套离线完成,IDA 的历史分析并没有提供额外杠杆,要大规模类型化反编译再另说。
- **C1 的两个参数**(2026-09-30 已决,2026-10 已执行):① `value+8` 的 docstring 用 donor 自带 `.rdata` 串(trigger `0x26C1BA0` /
  effect `0x2616260`),不放我们 DLL 里的串 —— 引擎在 db 生命周期内一直持有这个指针;② 先打 trigger db `0x32611C8`(donor `0x269CAA8`),
  effect 侧留作孪生复现。**执行结果**:`neo_effect` 与 `neo_action` 均注册成功,四判据全通过(§24.6)。
- **C3 不再是待办,降为设计依据**:注册只需要两个前置 —— 目标 db 已拉起,且我们的插入早于任何*求值*引用该 keyword;
  不需要全局同步点(解析器从不铸 token),`0x337A844` 是 trace-enable bool 而不是注册守卫(§16)。
- **Zig `extern fn` 绑 QuickJS C 函数会崩 ⇒ 所有 QuickJS 调用走 `src/dll/quickjs/quickjs_wrapper.c` 的 C 包装,根因未查**
  (ABI 不匹配?TLS 初始化?)。这是旧计划 §3 阻塞表里唯一还活着的实现约束,`src/` 注释的出处就指这一条。

## 6. 新旧 § 映射

本表左列的「旧 §N」指**根目录那份 449 行叙述性计划**的段号,不是 evidence 的 §(旧名→新名的对照记在
`docs/offline-tooling.md`,删除动作单独一个提交)。

| 旧 | 去处 |
|---|---|
| §0 | 段1 |
| §1 | 段2(与 `AGENTS.md` 约束 1–7 重叠的文本不复制) |
| §2 | 段3 上方小表 4 行;第 5 条改指 `docs/offline-tooling.md` 的「前置条件」 |
| §3 | 活着的四条:死宿主 → 段3 的 C2 行、`extern fn` 绕过 → 段5、机时/SSH → 段3 头注、`.i64` → 决策留段5 而其现状已在 `docs/offline-tooling.md:15`,故此处丢弃;其余 8 行是已划掉的历史,论证在 evidence |
| §4 | 段3 一行 `A = done`;A1–A5 长叙述丢弃,顺带清掉死指针 `evidence/analysis/keyword_entry_layout.md`(**从未存在过**,全仓库只有旧计划引用它) |
| §5 | B3 → 段3 的 `planned` 行 + 新计划;B2/B4 → 段4;B1 已作废 |
| §6 | C0/C1/C2 → 段3 三行;C3 → 段5;C4/C5/C6 → 段4;「为什么是这个顺序」压成段3 表下 2 行 |
| §7 | 未闭合四项 → 段4;已结历史整段丢(`0x5350D0` 重估、`0x1D092C0` = 错误视图、`id_mapper` 退役、`ceffect`/`ctrigger` 删除、`diag.py` 清理) |
| §8 | 段5 七条;已决且已执行的部分由段3 的状态行代表 |

旧名的**活引用**除 `evidence/` 外全部迁到本文件;`evidence/analysis/runtime_444_keyword_pipeline.md` 里的 4 处按不可变约定
保留,靠这张表解读。
