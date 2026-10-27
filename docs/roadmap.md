# docs/roadmap.md — 阶段计划与授权状态

本文件是那份 449 行叙述性计划的归位结果:**只放状态、门、指针**。论证一律在 `evidence/analysis/runtime_444_*.md`
三卷里(§1–§15 `structures`、§16–§23 `pipeline`、§24–§60 `c1_validation`),这里一个都不重复。
细计划不进 git,所以本表只写它们的**文件名**:要状态与前置看这里,要步骤得在私有 plans 目录里按名字找。
防再膨胀的机械判据是 `scripts/test_scripts_layout.py` 的 `violates_roadmap_shape`(≤140 行、状态词表、按状态必填出处)
与它的同伴 `violates_missing_roadmap_header`(钉住那张状态表的表头确实带齐五个列名 —— 否则前者找不到表,按行检查会静默失效)。

## 1. 目标与判据

> 创建出一个**新的 mod 系统**，而非只能复现一遍现在的官方 mod 系统。比如判定哪个星系是交通要道，
> 通过 QuickJS 根据这个来给各个星系加上新的 effect；或者种族占比会影响资源产出、以及对其母国的
> 外交和战争态度之类的。

判据：新能力必须**表达不出**于现有 DSL（scripted_effects 只是宏展开），同时不改动官方 mod 系统语义。

## 2. 授权门

| 门 | 状态 | 翻它要改哪一行 | 上次授权动作 |
|---|---|---|---|
| `authorize.c1_registration` | **开** | `src/dll/scripted/keyword_registry.zig:211` 现为 `true`;翻回 `false` 即撤回 | 2026-10 的 C1:注册 trigger `neo_effect` + effect `neo_action` |
| 实机只记录 detour `0x1D08520` | **只在点名时** | 无常量可翻;装与拆都要明确指令 + 等热路径静默窗口 | 2026-10-27 证人两窗(pid 15500,§69:20 s 频率窗 + 120 s 正式窗,靶 `0x3B01A0` 同进程串行,装拆均 `rc=0`、`verify=0`、host 存活);前一日 2026-10-26 两次点名(§67 donor pid 3416、§68 scope pid 20220,同一份 DLL 字节)。铁律不变:`ExecHookVerify != 0` 时绝不 `FreeLibrary` |
| 实机 shot 预算 | 见在飞计划 | 预算归各计划自己的 Global Constraints,本表不重复数 | — |

`AGENTS.md` 约束 1–8 的文本不在这里复制 —— 段2 只记**状态与改动点**,约束文本继续住在它唯一的权威位置。

## 3. 阶段状态表

已经钉死、不必重做的四条(文字照旧计划的句子,证人 § 在最后一列):

| 事实 | 出处 |
|---|---|
| base Execute = RVA `0x1D08520`，两个整数参数，`call [rax+0x10]` 派发到实例的 **vtable slot[2]**（即 `ExecuteActual`）| structures §10/§14 |
| 一次**完整**普查（hist_overflow=0）：316,468 次调用 / 291 个不同 shim / invalid 0.15% | structures §13 |
| CEffect 家族静态全图：**1,805 个 vtable → 543 个不同 ExecuteActual 实体**；**口径修正**：该计数只统计 slot[1] 仍为 base Execute `0x1D08520` 的 vtable，**覆写了 Execute 的类不在内**，所以 1,805 是下界而非类总数 | structures §14 + pipeline §17 |
| 该 build **没有 RTTI/COL**（对全部 1,805 个测过）→ 类别身份只能来自字符串池与行为 | structures §14 |

第五条旧事实「静态输入已在本地」不在这里重复:exe 路径、sha256、`NS_STELLARIS_EXE` 覆盖见 `docs/offline-tooling.md`「前置条件」。

**实机 shot 可用的前提是 Windows 机时与 SSH 隧道在 —— 这是环境约束,不是门。** 无人值守弹窗处置这条线**能力已上线、放行名单为空 ⇒ 当前全部停手留证**:2026-10-25 第一批实机留证的 23 个 distinct `popup_id` 全部判「只留证」(21 条是调试控制台文本面板被切成的亮块、2 条是主 UI 切片),证人 `evidence/xrefs/popup_fingerprints_4_4_4.tsv`。同日第二批(`evidence/logs/unattended_popup_batch2_4_4_4.log`)取到三条:① 人工 `Win+L` 期间 `just awake check` 实机 **rc=0**、探针读到 `Default`(`LogonUI.exe 2188/2216 Console 1` 是当时的锁屏证人,权限与会话两种归因已排除)⇒ **桌面可达性这道门对真锁无感**,`desktop_locked` 从未被任何真锁产生;② OCR 成本三组样本 12/14/12 行 = 27,134.9/36,810.8/42,885.4 ms ⇒ 固定+线性模型只当量级,**「一次真识别必然打穿 24 s 会话预算」是三次一致的读数**;③ 一扇真事件窗被读成 `text:2188ca0b`(`source=text`、12 行、`attempts=0`),但它的裁片是**对话框 + 星图舰队列表的并集切片**,`close_point` 换算到裁片本地 (964, 51) 落在舰队条目上 ⇒ 名单条目没写,`dismiss_attempt`/`dismiss`(`no_effect`) 三元组仍 **not_observed**,前置从「量一次关闭点」改成「先证明 bbox 是一扇窗而不是切片」。同批次人在场授权后走**手工 `click`**(不是 daemon 的 `dismiss`)把窗关掉,顺带第一次量到 ✖ 真实中心 (1345, 483) 对算得的 (1843, 606) 差 (498, 123),且 ✖ 的 y 比 bbox 上边界还高 72 px ⇒ 「裁片里没有 ✖」是结构性的。

| 阶段 | 状态 | 证据 | 计划 | 第一前置 |
|---|---|---|---|---|
| A | done | pipeline §17/§18/§19,c1_validation §25 | — | — |
| B3 | done | c1_validation §26 + `evidence/disasm/fridadis_live_0x1D08520.c` | `2026-10-22-b3-fridadis-bringup.md` | — |
| api/scope 假偏移 | done | c1_validation §26/§26.3 | `2026-10-22-scope-false-offset-consolidation.md` | 无(§26.2 的真实布局仍未定 → 段4 那条线) |
| C0 | done | pipeline §20/§21 | — | — |
| C1 | done | c1_validation §24/§24.6 | — | — |
| C2 | done | c1_validation §36–§50 | `2026-10-22-c2-live-death-localization.md`+`2026-10-22-c2-jsnewruntime2-boundary.md`(均已执行) | **§47 找到机制**:`libs/quickjs/cutils.h:43-44` 的 fallback `offsetof`(`&((type *)0)->field`)让 `container_of`(quickjs.c:1494)里带进一次**编译期空成员访问**,UBSan 对那个**字面 0** 在 `0xbd97` 无条件报告(`:1494:12`,记录 `0x5ab430`)→ Zig 的 type-mismatch 打 `member access within null pointer of type 'JSMallocBlockHeader'` 后 abort → 退出码 3;第一次 `js_rc` 调用就是 `JS_InitAtoms` 首个 `__JS_NewAtomInit` 的字符串分配(`js_alloc_string_rt:2361`)。**这次 trip 与运行时指针值无关**,所以 §46 的 13 条 `Mx`(size `5a0`/`808`/`ff0`、ptr 全 8 对齐且 `≡8 mod 16`、每次完整渲染恰 2 个 `st` 且第二个 = 运行时块 `+0x408` = `offsetof(malloc_ctx.malloc_state)`)仍是有效观测但不再判别候选、§45.5 的 (a)/(b)/(c) 都不是机制;§45 的「user pointer was 8」**撤回**,`str` 的值/来源仍未被观测,与 §46 的边界一致。**§48 已按授权实施修复 (a)**:`libs/quickjs/cutils.h` 引入 `<stddef.h>`,`offsetof` 改用 builtin;新产物(sha `79c8dc24…`)零游戏 `SURVIVED rc=0`、witness 出现 `rt=` 并跑到 `diag_rc=0`;UBSan 记录 141→133,8 条 fallback `container_of` 全移除(`:1494:12` + free/realloc/usable-size 的 7 条同源隐患)。**§49 实机一次 shot 已通过**(2026-10-22,同一份字节):`C2Init rc=0`、`g_test_rt`/`g_test_ctx` 非空、`1+1` 经 DLL 自己的 `JS_Eval` 返回 int32 2(rc=11)、`--noinit` 守卫返回 0 不崩、host 全程存活,`C:/temp/c2_diag_9932.log` 首次在实机写出。**§50 实机压测**:固定脚本经 `C2EvalStressOne` 跑 8 轮字符串/数组增长 + `JSON.stringify`,打满 §48 移除仪表的另 7 条 `container_of`(free/realloc/usable-size)路径,`rc=63619`(n=15904)、两次模块副本一致、host 存活。修复循环仍是离线的(edit → `zig build` → scp 新文件名 → `c2_selfabort_repro.py`)。§44 那次 shot(单发射,**已耗尽**)证明被杀后 2.1 s 的窗口是 teardown 不是执行:80 ms 起 `SuspendThread` 全 gle=5、`pr_user_us` 22 采样一动 0 µs、内存单调下降,两条对照分别判掉「仪器坏」与「线程已退出」 |
| C4 执行路径 + 试点一接线 | in-progress | c1_validation §52;§53;§54(`count_mismatch`:不经 slot[1]);§55(`slot2_zero`:也不经 slot[2]);§67(donor 第一次 shot 读数) | `2026-10-23-c4-chokepoint-wiring.md` | **第一发已按 §57.4 前两档打完 = c1_validation §67**,读数 `no_calls_inconclusive`(pid 3416,`Install rc=0`,`calls=0`/120 s = 0.0 calls/s,清理段 `Uninstall rc=0`/`verify=0`/host alive);该档**不含第三档资格**(仪器无哨兵,「安静」只读作「没观测到」,不是引擎的陈述)。剩余前置 = **让这一族真的在执行**:载入进行中的存档并确认 per-system 执行在发生,再取紧邻 `state=playing` 重打;**不是**换 mask —— §57.4 要的调用频率只能从恒计 `calls` 读,下一次点名仍带 `--mask 0`。靶子与判据未变(只读采样 `0x3AFD30` 记 `[self+0]` join 那五张,三档在 §57.4);§57.4 **第三档**不在本计划内、归下一个计划(要一个不带 predicate 的证人来钉「执行确实发生」,与 donor/predicate 互斥性同源 —— 取证卷 §68.8 表第 ① 行);§54–§56 三次 shot 的门挂在 `0x1D08520`,按 §57 观测 6 那一族一张都不从那里进 |

为什么顺序是 C0→C1→C2:C0 在**离线**把「我们造的描述符到底像不像真的」证实到字节;C1 在**实机**把「别名式注册
能不能活过 create + write + predicate 链」证实;C2 才轮到「让 keyword 执行 JS」—— QuickJS 不在注入环境里活下来,后面没有一步能开工。

C2 实机状态(§38–§45,两计划落账):`C2Init rc = 3` **不是已确认的步骤码**(§38 撤回那种把 rc 当步骤码的读法;
§45 进一步给出机制:`rc=3` 是 UCRT `abort()` 的进程退出状态,`rc=3 → bucket=intrinsic name=Date` 那整套解码作废);
每一次 shot 序列里最后可见的标记都是 `new_rt ` —— 即 `JS_NewRuntime2` **之前**那一个(§39);分配风暴已排除,host 变得
不可读之前先把自己约 8 GiB commit 释放干净(§39);注入 + `C2Sanity` + 20 s 观测可存活(§39 无 dispatch 控制 shot);
而 §40 那条只执行 `kernel32!Sleep(8000)` 的长远程线程让 host 活了下来 ⇒ 「一条长远程线程本身足以杀死游戏」这个
读法死了,靶精确落到 `JS_NewRuntime2`。**尚未结论**:引擎为何退出、`C:\temp\c2_diag_<pid>.log` 为何从不生成,两条都
还不知道 —— §40 只指明先攻哪条轴,不是根因(§39 的排除项别误读成根因)。

§41/§42 推进了上面那句「最后可见标记是 `new_rt `」:给 `heap_malloc` 打标记后,尾标到了 `new_rt MMM`(§41 只记入口)再到 `new_rt MmMmMm`(§42 加闭合 `m`/`!`)。**三次 `heap_malloc` 全部进入且全部返回,无悬空 `M`** ⇒ 死不在我们的 allocator/`HeapAlloc`,而在引擎第 3 次分配返回之后、第 4 次进入之前的 ~6.9s 零分配段。§39 的 no-alloc-storm 独立复现;`rc=3→Date` 仍非步骤码(§38.5)。**§43(离线读源码 + 忠实复刻 `heap_mf` 重放)把这段窗口钉到 `JS_InitAtoms` 首个 `__JS_NewAtomInit` 迭代**(`:3430` 名字串分配 → `:3330` `atom_array` 增长)之间的一段**直线平凡代码**,并**否掉两条 QuickJS-内部假说**:跨线程 stack guard(`JS_UpdateStackTop` 在 `:2116`,晚于死点)与坏 hash/自由链(该处 `atom_hash` 刚清零)—— ⇒ 6.9s 不可能耗在 QuickJS 控制流上,**「整段在 QuickJS 代码内、故要 hook QuickJS」这个 §42 收尾判读被 §43 取代**;只读 DLOG 打标确实到顶,但下一步是**对远程线程 `Rip`+CPU-time 的只读新型采样**(超 `ReadProcessMemory` 级,需 点名),它先于、并可能取消那次「hook QuickJS」升级。**C2 仍 blocked。**

§44/§45 收了 §43 点的那笔账,并把方向整个换掉:§43 说「下一次 shot 是对远程线程 `Rip`+CPU-time 的只读新型采样」,
那次 shot 打了(§44,单发射,**已耗尽**),返回的是 22 次 `SuspendThread gle=5` + 进程 user CPU 一动 0 µs + 内存单调
下降 ⇒ 我们盯的 2.2 s **不是 QuickJS 在算,是 host 已经在收尾**;§42 那段「6.9 s 零分配段在 QuickJS 自己代码内」
连同它请求的「hook QuickJS = 升级授权」一起作废 —— 那个窗口不存在。**§45 零 shot 定位**:同一份字节在零游戏的
子进程里以 `0x3` 死掉(witness 与实机逐字相同,两个 ASLR base 下帧集合一致 ⇒ 确定性),`.pdata` + UBSan 记录把
trap 钉到 quickjs.c:1494 `js_rc`,持有它的 131 字节函数与第三帧 `__JS_NewAtomInit`(quickjs.c:3433/3434)各自
独立对上 §43 离线缩窄的同一个函数。**§47 撤回这段机制读法**:trap 报告的指针操作数是 fallback `offsetof` 的
**编译期常量 0**,与运行时 header 值无关 —— 第一次 `js_rc` 调用就无条件 abort(另 7 条同源 `container_of`
藏在 free/realloc/usable-size 路径里)。**§48 按授权实施修复 (a)**,新产物在零游戏复现器里
`SURVIVED rc=0`、`rt=` 出现、跑到 `diag_rc=0`。**§49 实机一次 shot 通过**:Task 5 `C2Init rc=0` +
非空 `g_test_rt`/`g_test_ctx`、Task 6 `1+1` 经 `JS_Eval` 返回 int32 2、`--noinit` 守卫不崩、
host 存活;**§50 压测**让另 7 条 `container_of` 路径在实机跑满(`C2EvalStressOne rc=63619`,两次一致)—— C2 收口。下一面是 C4 的**实机可见行为**:执行路径的独立一次 shot 已通过(c1_validation §52),剩下的是分数 → JS → 按 system 下 effect 的接线与可见行为授权。

## 4. 候选条线

每条四要素:判据 / 前置 / 所需授权级 / **为什么现在还不能写成计划**(缺的多半是「步骤能从现有事实写出来」)。
授权级记号:**无** = 纯离线;**点名** = 明确指令下的实机只记录动作;**一次 shot** = 一次远程 dispatch(计入该机时的 shot 数)。
术语(与取证卷、PR 正文共用;取证卷与 commit 里的旧中文比喻按此对译):**shot**(旧词对译:开枪/一枪/重打 → 执行 shot / 一次 shot / 重打;零枪 → 零 shot;首枪、第 N 枪 → 第一次、第 N 次 shot;判别枪、取型枪、采样枪 → 判别、取型、采样 shot;枪机 → shot 宿主机)= 在实机进程上 install → sample → uninstall 的一次往返,引擎限制每进程只许 install 一次;**root**(旧作「根」)= 跟读起点,scope_probe 用 `self`/`helper`/`arg3`/`arg4` 四个 root,跟读指从 root 解引用一层内存内容并对照已知 vtable 集合;**已知 vtable 集合** = `evidence/xrefs/ceffect_vtable_map_4_4_4.txt` 的静态转储(是下限,不是全量)。

- **B2 七把 shim 各 2,090 次的复采**：判据 = 换一个场景仍是 2,090 ⇒ per-system 循环，正是「星系交通要道」类效果要的抓手。
  前置 = 热路径静默窗口；授权级 = 点名；不能成计划 = 选哪个场景要先有新观测（§13）。
- **B4 九个 Meyers 惰性访问器绑定的关键字名字**（`0x388130`…`0x389224`，buffer 在镜像里是零）：判据 = 首次使用时铸出的 id 与名字。
  前置 = 游戏在跑；授权级 = 点名(只读)；不能成计划 = 它不影响 Phase C 任何判据，默认不做（§19）。
- **C5 试点二 种族占比 → 资源产出 / 对母国的外交与战争态度,叠加要道 → 全局图度量**：判据 = `docs/c5-pilot2-spec.md` §0 修正后的差异口径（全局图度量 / 自定义权重 / 跨 scope 聚合 / 运行时可写）真的改变了游戏行为；「识别要道」本身已被官方 `is_bottleneck_system` 覆盖（spec §0）。
  前置 = 段3 C4 那一面 + 5 项裁定 + **一次 galaxy map 拷贝**（离线静态输入,**不是 shot**）；授权级 = 拷贝 **无**,实机部分同 C4；不能成计划 = spec 在 `docs/c5-pilot2-spec.md`、待 §3 五项裁定（裁定归人,见取证卷 §68.8 表第 ③ 行）；要读的字段按 spec §2 三档标签标注（星系句柄来源与星连边运行时形态未观测）。
- **C6 验收**：判据 = 日志 + 可复现行为，且官方 scripted_effects 路径不受影响。
  前置 = C4/C5 至少一条落地；授权级 = 点名(实机只读观测,不新增门)；不能成计划 = 验收对象的形状还没定。
- **launcher `LAUNCHER_CLICK` exit-23**(`EXIT_LAUNCHER_NO_ADVANCE`：三轮点击 + settle 后窗口不推进)：判据 = 缺陷定位到具体那一步。
  前置 = Windows 机时 + SSH 隧道（环境约束,非门）；授权级 = 一次 shot(定位缺陷要远程实跑 launcher 观测,每次跑都占该机时 shot 数)；不能成计划 = 2026-10-25 实机批次里 `just launch` **RC=0**,本场未复现 exit 23 ⇒ 三档诊断「点击没送达 / 窗口判断错 / 别的」一个样本都没有(不是已排除某一档)(`scripts/windows/launch_stellaris.py`)。
- **真正的 `CEventScope` 是哪个对象**：判据 = 拿到一个真的 `arg2` 并逐字段读通。§63 判队列派发方 = `dispatchers_partial`(限于 `call [reg+0x28]` 直接形态口径,取证卷 §63)。
  前置 = §56 那次 shot 的负结论被 §56.8 撤回,仪器**已修正**(按源分预算、判据进 TSV meta 行、加 `VirtualQueryEx` 区域判读,PR #13 / merge `534116d`),并按修正流程重打成功 = **§59**(pid 22220,`calls=3061 samples=5`;四根全跟到 `self=4/helper=2/arg3=1/arg4=1`、`capped`/`withheld`/`unreadable_roots` 全 0 ⇒ `no_scope_candidate` 这次是问完了的负结论)。§56.8 末段的低地址未决项**已答** = 绝对地址,7 个根同在一个 `MEM_PRIVATE` RW 8 KB 区(`base=0x7fe000`,分配起于 `0x400000`);§56.5 第 4 问**已答** = `arg3`/`arg4` 载的是代码(`arg3` 指回 `0x1D08520` 本身、`arg4` 是三点复制 thunk),候选只剩 `self`/`helper`;唯一可判的 vptr `0x247a358` 已降级(其 Execute 槽是计数访问器)。**仍未收口**:哪个对象是 scope。§58 的因果句(控制台⇒暂停)由 §59.1 证伪,执行 shot 前置改为单条「紧邻执行 shot 读 `state=playing`」(判读陷阱 9)。授权级 = 离线 **无**、重打 = 点名(pid 22220 额度已用尽,清理已验 `installed=0 verified=0`);不能成计划 = §26.2 明写仍未定,且同形状再打没有信息增量 —— 要的是 self/helper 上**更深的跟读形状**:**该前置已按 §59.9 打完 = §68**(pid 20220、同一份 DLL 字节;`verdict=scope_candidate` 是**修正仪器后的第一发**(§56 在误配仪器下已报 `known_vtable_hits=14` ⇒ `scope_candidate`,§56.8 未撤回该判词;§59 修正后是 0 命中)、`verdict_d2=lineage_edge_found`,但两条边一条是标量 `0x100000000` 一条是模块内静态表 `rva=0x247a488`,§59.6 的 `0x2ddc2c90` 未重现;`self` 支 depth-2 `capped=19` ⇒ 那一支没问完),下一前置 = ① 连线前先按 `plausible_user_ptr` + 界内/界外分档、② `self` 支预算抬高或把那 19 个地址点名留给下一发;或先从 §53 普查表 `origin=incoming_arg` 那条往上定帧构造点(零 shot,应先做;§61–§62 已做完,负结论 = 该集合内无构造点)。**§60 已判承载函数路线(判决 `frame_ctor_found`,仅限该路线;`incoming_arg` 那条零 shot 普查路线已由 §61–§62 读完(集合内无构造点))**:执行帧就在承载函数 `0x1c42fe0..0x1c43884` 内构造(2 处 vptr 写 + 4 处字段写,逐条字节在案),`0x16fdc0`/`0x1d129a0` 两条线索判死为写者(其 `[rsp+0x38]` 是各自栈里的 string capacity 暂存),共享 sink `0x1d11860` 零帧存储、写全停在 helper 一侧;承载函数无直接调用者,唯一静态持有者是 vtable `0x26d4dd0` 槽 +0x28(异步 effect 队列类,ctor `0x1c42d30` 由 'Default Game'/'Game' 两处静态构造);**普查路线的 `incoming_arg` 第 1 行已由 §61 判完(仅限该行)** —— `0x1bcd120` 对帧纯透传(`mov rbx,rdx`@`0x1bcd131`→`mov rdx,rbx`@`0x1bcd17a`→`call 0x1d08520`@`0x1bcd18d`,rbx 在该段只作源),365 个共享槽全在 slot[2] = `call [rax+0x10]` 派发槽,该行与承载函数那条**同源**,§60.7-5 折叠进 §60.7-1;其余 11 个 `incoming_arg` 站点**已由 §62 逐函数读完**:12 行(9 个函数)全是 floor map 的 slot[2] `ExecuteActual` 覆写(三条口径互证:裸扫 `.rdata` 命中数 = map 的 slot2 行数 = 每命中前一槽为 `0x1d08520`,379/379),承载寄存器只在函数头抄一次入参 rdx、站点全是 `call 0x1d08520` 直调、对帧只动 `+8` 深度字段(27 处)、其余帧偏移零写、零栈上 `lea` ⇒ 整个 `incoming_arg` 集合与承载函数那条同源;谁经队列派发(`[0x26d4dd0+0x28]` 形态的派发方集合)已由 §63 在 `call [reg+0x28]` 直接形态口径内判完 = `dispatchers_partial`(`mov reg,[obj+0x28]; call reg` 两段形态不在口径内 → §66 判两段形态 = `two_stage_dispatchers_partial`,105 对无一配四对象函数,取证卷 §66),与 `AGENTS.md` 现文一致 —— scope 一问仍未收口,但 §59 的 `no_scope_candidate` **已被 §68 换成修正仪器后的第一发 `scope_candidate`**(`known=2`,两条都在 `self` 根:`+0x30`→vptr_rva `0x2545e40`、`+0x10`→vptr_rva `0x254fa18`;这两个 RVA 与 §56.4 命中表里那两行同值,**不是新认出的类**)。移交口径见取证卷 **§68.8** 那张表的第 ② 行:若下一发 `verdict_d2` 落在**非证据档**,本仪器这一层就问完了,只剩 §59.9 前置 2 之外的一条**新路线**(两条零 shot 路线 §61–§63 / §66 已判完且判决词不合并)⇒ **要新形状,不要重打同一形状**。
- **`0x24F9910` 的槽号归属**：判据 = 那个数组的偏移各对应哪个虚槽。
  前置/授权级 = 更深静态(**无**)或实机(点名)；不能成计划 = §28.4 已判定它不可当前提,没有可执行的判据依赖它。
- **孤儿 `effects/handler.zig` + `triggers/handler.zig`**：§64 证前提消失(命名消费者 C3 已降为设计依据,:116),判据永不再触发;删否等用户裁定,删除落点见取证卷 §64.4。
  前置 = C2 通过；授权级 = **无**(纯 src 改动)；不能成计划 = §29 已决「留」(与 `id_mapper` 的不对称是刻意)，§64 已证伪该前提(等的 C3 已降为设计依据,:116)—— 删除要新裁定,落点见取证卷 §64.4。
- **Zig `extern fn` 绑定 QuickJS C 函数的根治**：判据已由 §65 给出 = `abi_closed_static`(布局+调用桩双侧钉死,取证卷 §65);余下只剩实机确认。
  前置 = 段5 的 C 包装绕行使它能长期延后；授权级 = 实机确认要一次 shot(本场零 shot)；ABI 假设 §65 已静态排除,TLS 初始化不归本节管(§36)。

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
- **Zig `extern fn` 绑 QuickJS C 函数会崩 ⇒ 绕行使它长期延后(全部 QuickJS 调用走 `src/dll/quickjs/quickjs_wrapper.c` 的 C 包装),机制已静态排除(§65 `abi_closed_static`)**
  (ABI 不匹配假设由 §65 排除;TLS 初始化不在该节口径内)。这是旧计划 §3 阻塞表里唯一还活着的实现约束,`src/` 注释的出处就指这一条,禁令(`exports.zig:351-353`)未放宽。

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
