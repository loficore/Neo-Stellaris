# PLAN.md — Neo-Stellaris 路线图（2026-09-29）

证据一律指向三卷取证日志 `evidence/analysis/runtime_444_*.md` 的 § 号（§1–§15 在 `runtime_444_structures.md`、§16–§23 在 `runtime_444_keyword_pipeline.md`、§24–§30 在 `runtime_444_c1_validation.md`），不在这里重复论证。

## 0. 目标（不变，用来判断每一步值不值得做）

> 创建出一个**新的 mod 系统**，而非只能复现一遍现在的官方 mod 系统。比如判定哪个星系是交通要道，
> 通过 QuickJS 根据这个来给各个星系加上新的 effect；或者种族占比会影响资源产出、以及对其母国的
> 外交和战争态度之类的。

判据：新能力必须**表达不出**于现有 DSL（scripted_effects 只是宏展开），同时不改动官方 mod 系统语义。

## 1. 授权边界（硬约束）

- 动态注入只允许**只记录、不改行为**的 base Execute detour；装/拆都只在明确指令下，且必须等热路径静默窗口。
- 铁律：`ExecHookVerify` 不为 0 时**绝不** FreeLibrary。
- 不绕过任何许可门：不 patch `libidalib.so` 的 EULA 分支、不手写 `EULA 90` 注册表键。
- **边界提醒（2026-09-29）**：上面第一条**不覆盖 §6 的 C1**。向 `0x33746E8`/`0x32611C8` 插入新 keyword
  是在改引擎状态，不再是「只记录」。C1 需要一次单独的明确授权，C0（纯离线）不受此限。

## 2. 已经钉死、不必重做的事

- base Execute = RVA `0x1D08520`，两个整数参数，`call [rax+0x10]` 派发到实例的 **vtable slot[2]**；detour 面已在 §10 全量反汇编并实现（`src/dll/scripted/exec_hook.zig`，HIST_LEN=1024）。
- 一次**完整**普查（hist_overflow=0）：316,468 次调用 / 291 个不同 shim / invalid 0.15%，见 §13。
- CEffect 家族静态全图：**1,805 个 vtable → 543 个不同 ExecuteActual 实体**（§14）。今天在本机对拷贝来的 exe 重跑，逐行与 Windows 产物一致。
  **口径修正（§17）**：该计数只统计 slot[1] 仍为 base Execute `0x1D08520` 的 vtable，**覆写了 Execute 的类不在内**，
  所以 1,805 是下界而非类总数。
- 该 build **没有 RTTI/COL**（对全部 1,805 个测过）→ 类别身份只能来自字符串池与行为。
- 静态输入已在本地：`/var/lofibass_ssd/data/stellaris/4.4.4/{stellaris.exe,common/,events/}`，
  exe sha256 `9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56` 与 `D:\` 原件核对一致。
  工具自动定位该路径，`NS_STELLARIS_EXE` 可覆盖。

## 3. 当前阻塞

| 阻塞 | 影响 | 处置 |
|------|------|------|
| Windows 机时开时关、SSH 隧道要人工恢复 | 一切动态验证 | Phase A 完全不碰它 |
| ~~本机 IDA 不可用~~ **已解除** 2026-09-29：headless 能开，无许可门 | 反编译可用，但是**从 exe 新建的 IDB**，没有 Windows 侧 `.i64` 的历史分析 | 用前先 `del_func`+`add_func`+`mark_cfunc_dirty`，否则 Hex-Rays 常给 5 字节 `JUMPOUT` 假象（详见 §15） |
| `stellaris.exe.i64`（705 MB）留在 Windows | 拿不到历史分析成果 | 只在 IDA 有合法可用路径后再取，纯静态不需要 |
| **C1 的实机注册超出 §1 的「只记录」边界** | 第一次真正改引擎状态 | **仍是唯一真阻塞**。C0 已把执行体写完并加硬门（§6 C0 进度、§8 第一条），翻 `authorize.c1_registration` 需要点名授权 |
| ~~`0x1D13270` 的调用约定还差一步钉死~~ **已解除**（§20） | Zig 侧传参会猜 | `eax = f(rcx = *holder)`，rdx 死参数；执行体照此实现并有假指针测试 |
| ~~§17 第 4 步 `class_info.factory` 的调用约定未定~~ **已解除**（§22） | 我们造不出 class-info 记录 | 1,605 条 keyword 记录全部普查：field0 是**共享 deleting destructor `0x34C090`**（不是 ctor），field1 是**无参 `create`**，对象在 `rax`。未知项向前挪了一格，见下一行 |
| ~~**§22.4：引擎在哪里 walk BST 并调 `create`**~~ **已解除**（§23，纯静态） | 插进去的 keyword 会不会被实例化 | 消费方是 `0x3B01A0`(effect) / `0x349AE0`(trigger)：读 db 全局、按裸 token id walk `_Tree`、命中就 `call [value[0]+8]`。**无范围校验**，所以运行期新 mint 的 id 与静态 id 完全等价。工具 `scripts/createsites.py`（按 shape 找）× `scripts/riprefs.py`（按字节找 data global 引用，~5 s vs find_refs 的 ~15 min） |
| **C1 真正的门槛变了**：不再是「地址未知」，而是「对象必须well-formed」 | 造出来的 `create` 返回值要经得起引擎写它 | §23：引擎在调任何虚函数**之前**就往对象里写 `{id, name std::string}`（effect `+0x20/+0x28`，trigger `+0x38/+0x40`），随后 `call [vptr+0x98]`/`[vptr+0x80]`；且 `0x3AF130`/`0x348450` 会**遍历整棵树逐个 create**。vtable 只到 slot[2] 的桩不是保守选择，是往空槽里跳 |
| ~~「那么我们自己造的这个对象长什么样？」~~ **已解除**（§24，决定 = 别名式 C1） | 不造对象，借官方 `class_info` | **别名是引擎自带的形态**：1,615 条 keyword 记录压在 1,605 个 class_info 上，其中 9 个服务 2-3 个 token id（`if`/`else_if`/`else` 共用 `0x269DC98`），而 1,605 个 `create` 体**互不相同** → 共享只发生在 class_info 层。每个 keyword 仍各自 `new(0x10)`，所以共享 deleter `0x34C090` 永远不会拿到同一块 → **没有 double-free 面**（这原本是别名唯一可能不成立的地方）。捐赠者选定：trigger `0x269CAA8`(new 0x80，本身已是 2-id 别名) / effect `0x2611070`(new 0xc0)。别名验的是管线，不是自定义行为——keyword 会按捐赠类的语义动作，这点写进 §24.5 |

## 4. Phase A — 纯静态：把注册管线啃穿（本机就能做完）

> **2026-09-29 前提受挫。** A1 已做完，结论是 §8 的「`0xCCCEB0` = 主 keyword 注册器」很可能是误读：
> 唯一调用点 `0x266D3D` 先把一个 packed token 解析成对象、再以该对象为 `a1` 进入 `0xCCCEB0`，
> 这是通用的运行期对象处理，不是启动期注册 13,000 个 keyword。`0xD150A0`/`0xE88500` 也已证伪为注册器
> （它们是 BIOSHIP 相关玩法逻辑）。§9 的偏移因此带**循环论证**风险。
> 详见 `runtime_444_structures.md` §15。**A2/A3 需要换一个不经过这条链的入口再开工**，
> 在此之前不要按原判据继续投入。仍然成立的只有：链路结构本身，和 `gen<<24|index` 的 token 打包。
>
> **2026-09-29 更新：换入口后 A4 已结（§17）、A3 已结（§18），Phase A 完成。** keyword→行为的绑定
> 根本不在 `0xCCCEB0` 那条链上，而是 `.rdata` 里三张**静态注册 thunk 数组**
> （effects `0x23AC600`×754、triggers `0x23AF628`×482 + `0x23B0540`×405），每个 thunk 直接
> `jmp 0x3AEF60` 写进 BST 全局。`0x337B400` 的 `0x120` 描述符数组只是 `{token id, SSO 名字}`，不带行为。
> 而新 keyword 需要的 token id 由运行期分配器 `0x1D13270` 现场生成，**与静态数组逐字节同构**，
> 因此不需要 patch 任何静态表。详见 §17、§18 与 `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`。
>
> **2026-09-29 追加（§19）：动态 id 的铸造时机已查清，且配方从「够用」升级为「必需」。**
> `0x1D13270` 的全部 567 个直接调用点分在 139 个函数里，**没有一个属于词法/语法解析器**，
> 而且它在镜像里**没有任何 qword（函数指针/虚表）引用** → 全是静态直调。
> 其中 505 个（89%）落在 101 个定长 `0x8f6` 的 **scope-iterator 注册函数**（`0x1930e70..0x196d3e6`，
> 每个自带 docstring + keyword 名），由 `.rdata` 指针数组驱动（样本 `0x23AF208` → 薄壳 `0x114CE0`），
> 即**启动期静态初始化**。另有 9 个 `0x34` 字节的 **Meyers 惰性访问器**（`0x388130`…`0x389224`，
> id 缓存块 `0x3261740..0x3261824`）把 id 留到**首次使用**才铸。
> **推论：mod 脚本里的新词不会因为「被解析」而获得 token id —— 必须由 DLL 侧主动调 `0x1D13270`。**

产出物：`evidence/analysis/keyword_entry_layout.md`。

- **A1** 反汇编 `0xCCCEB0`（约 13,000 条目的主注册函数），确定 reg_obj 来自哪个全局、以及它的 `+0x450` 容器怎么初始化。
  **2026-09-29 部分完成**：三个字段锚点全部在反编译体中实证 —— `obj+0x450` 容器、`obj+0x97c` 显式索引、`obj+0x990` packed token；
  容器为 `[c+0x20]` 数组 / `[c+0x2c]` 计数 / **条目 stride 272 = 0x110**，与 §9 完全吻合。驱动数组在 `[a1+0x320]`、计数 `[a1+0x32c]`。
  token→对象解析走 `qword_14325EF00`/`qword_143260FD0`（16 字节桶，索引 = packed 低 24 位，整字校验），**从反编译侧独立印证了 A3 的 `gen<<24|index`**。
  伪代码：`evidence/disasm/a1_master_reg_0xCCCEB0.c`。
- **A2** ~~跟 `0xD150A0` 的写入顺序~~ **前提已被 §15 推翻**：`0xD150A0` 是「有界容器 push，满则报 `BIOSHIP_NO_GROWTH_UPGRADE`」的 helper，
  尾调用的 `0xE88500` 是 `BIOSHIP_GROWTH_PROGRESS` / id 543–544 的玩法逻辑，两者都不写 0x110 条目字段。
  §9 的**偏移**成立、**调用链**不成立。改判据：从消费端反查 —— 找**填充 `[a1+0x320]` 那个 id 数组**的代码，而不是找一个可能不存在的独立注册器。
  **2026-09-29 已结（§17）**：新判据跑通，但结论是「那张 `0x120` 数组根本没有行为字段」。`descscan.py` 数出
  指向它的引用共 **19,727 = 9,863（驱动初始化）+ 9,863（`0x21CBFF0` 字符串析构 thunk）**，全部落在 `+0x000`，
  没有任何静态指针持有槽地址 → 语义钉死为 `{token id, SSO 名字}`，行为绑定另在 A4 的 thunk 数组里。
- **A3** token id 分配路径：packed = `gen<<24 | index`，找出申请新 index 的入口与命名池 `0x2490000` 能否增长。
  **2026-09-29 已结（§17 + §18）**：
  * 注册期 id 是**编译期立即数**（`mov edx, 0x2778` 这类），没有分配器、没有 generation 字段；
    `gen<<24|index` 只描述**运行期 lexer handle**，与注册无关。
  * 运行期**有**分配器，而且命名池**能增长**：`0x1D13270`（`clausewitz/pdx_parser/lexer.cpp`，
    `.rdata` 里 `Creation of dynamic token "` 的唯一引用点）查不到名字就
    `new(0x120)` 一个描述符、id 取 `[db+0x64] + [db+0x84] + 1`、写回 `[db+0x80]`，
    再经 token db 单例 `0x37347A0`（vtable `0x26E5180`）的 slot[2] 查找 / slot[6] 插入。
  * **静态与动态共用同一个写入器 `0x1D158A0`**（`mov [slot], edx` = id + SSO 名字），
    所以运行期描述符与静态数组**逐字节同构**，不需要 patch 任何静态表。
  * 限制：名字不能以 `-` 或数字开头（同一条 lexer.cpp 报错）。
  * **时机（§19 追加）**：567 个调用点 139 个函数，**解析器一个都没有**；89% 是启动期的 scope-iterator
    注册族，另有 9 个 Meyers 惰性访问器把铸造推迟到首次使用。所以「id 空间何时冻结」是个错问题 ——
    正确不变量只有两条，且都由分配器自己保证：`0x1D13270` 发的号 `[db+0x64]+[db+0x84]+1` 对静态与动态**全局唯一**；
    `0x3AEF60` 拿裸 32 位 id 当 key、无范围校验。工具 `scripts/fastcalls.py`（字节级匹配 `E8`/`FF 15`/`FF 25`，
    2.6 s 出结果；全量 capstone 线性扫描 10 分钟都跑不完）。
- **A4** ~~描述符各槽语义~~ **2026-09-29 已结（§17），且问题本身被重新表述**：描述符没有行为槽；真正的
  keyword→行为注册是 `.rdata` 里 ~106 字节的一次性 thunk，形态为
  `lazy-ctor db(0x3AEBA0)` → `new(0x10){&class_info, &docstring}` → `edx = 编译期 token id` → `jmp 0x3AEF60`(BST 插入)。
  完整闭环样例：`"add_modifier"` → thunk `0x1045B0` → db `0x33746E8` → class_info `0x260ABD8{deleter 0x34C090, create 0x18A3340}`
  → `new(0x528); memset; 0x3AFB40; 发布两个 vptr` → vtable `0x2641B38`，slot[1] `0x18AA2F0`(Execute 覆写)、slot[2] `0x18E60C0`(ExecuteActual)。
  字段语义由 §22 的 1,605 条全量普查确定，原先写的 `{ctor, factory}` 是错的。
- **A5** 用本地 `common/`、`events/` 的真实脚本名反查 token，做一轮纯离线交叉验证。**已完成（§25，2026-09-30）**：
  工具 `scripts/tokencorpus.py` → `evidence/xrefs/token_corpus_crosscheck_4_4_4.tsv`（25,656 行）。
  ① 两套互不依赖的仪器（unicorn 重放 oracle 与 `.rdata` thunk 普查）在 keyword id 上 **1,609/1,609 一致、0 冲突**；
  ② **token 查表是大小写不敏感的**（脚本写 `NOT/OR/AND/NOR/IF/ICON`，表里只有小写；35 个 head word 只能折叠后命中；
  9,863 个名字里**不存在只差大小写的成对项**）—— 这条直接新增一条 C1 预检：名字必须在折叠意义下唯一，
  否则 `0x1D13270` 会返回**已存在的 id**，而 `eax` 分不出是铸的还是撞的；
  ③ `count_*`/`any_*` 这类迭代器 keyword 的名字**在镜像里不存在整串**，是 104 个 name builder 在运行时
  把 `count_`（`0x266A818`）拼到 scope 名（`owned_pop_amount` @`0x266A620`）上生成的 —— 这从脚本侧独立证实了
  §19 的「head keyword 可以完全没有静态描述符」，也就是我们注册序列的形状。

**完成判据**：能在不看游戏进程的情况下，写出「新增一个 hardcoded keyword 需要填的每个字段和每个调用」。
**2026-09-29：判据达成。** §17 给出 keyword→行为的静态注册形态，§18 补上最后一环（运行期取 token id），
§19 钉死铸造时机（解析器不参与，必须主动铸）。
四步全部落在真实地址上，且**不需要改动任何静态表**。Phase A 结束。

## 5. Phase B — 动态确认（需要 Windows + 暂停授权，只在点名时做）

- ~~**B1** hook `0xD150A0`（只记录）dump `rcx` 与逐字段写入~~ **作废**：`0xD150A0` 已被 §15 证伪为注册器，
  且 A2/A4 已纯静态闭合，没有需要观测的推断残留。
- **B2** 验证 §13 的**七把 shim 各恰好 2,090 次**假设：换一个场景再采一次，若仍是 2,090 就是 per-system 循环——这正是「星系交通要道」类效果要的抓手。
- **B3** `scripts/fridadis.py` 首次用之前，`dis.js` 还没上传（上次 scp 失败），先补。
- **B4** ~~只有一种情况需要动态~~ **已由 §19 纯静态穷尽**：567 个调用点全部归桶，解析器零命中，
  铸造时机与顺序不再是未知。**唯一残留**是那 9 个 Meyers 访问器绑定的**关键字名字** —— 它们的
  `std::string` buffer 在镜像里是零，只有运行期才有内容（对象在 `0x297E780`/`0x297F9A0`/`0x297F9D8`…，
  id 缓存块 `0x3261740..0x3261824`）。这条**不影响 Phase C 的任何判据**，故默认不做；
  若要做，必须是在明确授权下的**只记录**读取。

## 6. Phase C — Zig 侧落地：把新 mod 系统做出来

> **2026-09-29 状态**：Phase A 已结束，本节是当前主线。原先的 C1–C6 是按「先查清再动手」排的，
> 现在前置条件齐了，重排成**可执行序列**：先做纯离线就能验收的 C0，把风险全部压到实机那一步之前；
> C1 才是第一次真正改引擎状态的动作，它**超出 §1 现有的「只记录」授权**，需要单独点头。

### 执行顺序

**C0 — 离线把注册链的代码写完并验掉（不需要游戏，不需要 Windows，现在就能做完）**

> **2026-09-29 进度：C0 四项全部完成**（详见 `runtime_444_keyword_pipeline.md` §20、§21）。
> * **第 4 项已结（§20）**：`eax = 0x1D13270(rcx = *TokenNameHolder)`，`rdx` 是死参数（只有
>   callee-save spill，体内从不读）；holder 只有 `+0x10` 的 MSVC `std::string`（chars `+0x10`、
>   size `+0x20`、cap `+0x28`）被读，`+0x00..+0x0F` 完全忽略。§18 的「name at rdi+0x10」是字段偏移，
>   不是寄存器；与 §19 的观测一致。
> * **第 3 项的判据被推翻重写（§20 + §21）**：`0x337B400` 整段落在 `.data` 的 raw data 之外，镜像里
>   **没有字节可对**（数组是启动期由驱动写的）。替代 oracle = `scripts/emu_desc.py`：用 unicorn
>   执行引擎自己的 `0x1D15270`（静态注册器）与 `0x1D152D0`（动态构造器），
>   **全 9,863 条真实条目，两条路径逐字节一致（0 处分歧），名字长度 1..66、
>   `cap=0x100`/buf `=slot+0x20`/vtable `=base+0x247B078`/`size=len+1` 四个内联字段 9,863/9,863 命中，
>   没有任何一条走 `0x1704B0` 的堆路径**。
>   Zig 侧 `keyword_registry.zig` 的构造结果对其中 56 个 golden 向量做 sha256 逐字节比对。
>   这把 §18「逐字节同构」从推断变成实测，但**真值来自反汇编的指令语义，不是运行中的游戏** ——
>   残留缺口仍是 §18 划的那条：实机读取。
> * **第 1 项已结**：`offsets.zig` 新增 `keyword_reg` 块（代码锚点 + `0x120` 描述符全字段 +
>   holder/value-record/class-info 布局），带 section 与 stride 自检。
>   过程中 §17 的一处口径被证伪（§21）：**effects 与 triggers 不是同一对函数** ——
>   effect thunk `0x1045B0` 自己 `new(0x70)` + `0x3AEBA0` placement ctor 并写回全局，
>   trigger thunk `0x100260` 只调无参的 `0x347BD0`（内含 `new(0x98)` 且自写全局 `0x32611C8`）；
>   插入函数也分两套 `0x3AEF60`(walks `db+0x18`) / `0x348150`(walks `db+0x88`)，
>   这反过来独立印证了 `scripted_db` 的两个 head 偏移。
> * **第 2 项已结**：`keyword_registry.zig` = 纯字节层 + 执行体（`getToken → ensureDb → new(0x10) → insert`，
>   顺序照 §19 的官方样板）。执行体按决策**写但加硬门**：`authorize.c1_registration = false`，
>   且 `registerSequence` **不是 pub** —— 门外的世界只有一个会返回 `error.NotAuthorized` 的包装函数。
>   门做成运行时分支而非 `@compileError`，正是为了让这 8 条执行体测试能用假函数指针离线跑：
>   断言调用顺序、`new(0x70)`/`new(0x10)` 两个尺寸、走的是哪个 insert 孪生，
>   以及四条失败路径（名字被拒、分配失败、ensure 没写回全局、空名）都停在插入之前。
>   `zig build test`：keyword_registry 18/18（§24.6 donor 配对 + §25.5 `NameCheck` 与混合大小写在
>   `0x1D13270` 之前停住）、全库 270/270（仅剩两个**先前就存在**的
>   QuickJS 测试二进制因本机 `GLIBC_2.35` 缺失无法启动，与本次改动无关）。
> * ~~**仍未定**：§17 第 4 步 `class_info.factory` 的调用约定~~ **已结（§22，2026-09-29 纯静态）**：
>   工具 `scripts/cinfo.py` → `evidence/xrefs/class_info_census_4_4_4.tsv`（1,605 行，只取两个 keyword db）。
>   field0 = 共享 scalar deleting destructor `0x34C090`，它 `mov edx,0x10` 释放的正是 value record 本身；
>   field1 = **无参** `create`（def/use 证明：1,605/1,605 在入口 rsp 坐标下 `slot >= 0x20` 的读为 0），
>   对象在 `rax`；官方函数体是 `new(size) → memset → 共享基类 ctor → 发布 vptr → ret`
>   （「发布 `[obj+0]` 与 `[obj+8]` 两个」是 §22.3 从一个样例推出来的，§24.4 实测已改掉：`+0x8` 只是
>   effect 侧的习惯，trigger 侧那一手是从全局复制指针到 `[obj+0x78]`，且有 544/1,605 个工厂自己一个都不发布）。
>   `offsets.zig` 常量随之改名 `CLASS_INFO_DELETER`/`CLASS_INFO_CREATE` 并新增 `RVA_CLASS_INFO_DELETER`。
> * ~~**C1 前唯一剩下的未知项挪到了 §22.4**：引擎在哪段代码里 walk BST、 deref value record 并调 `create`~~
>   **已结（§23，同日，仍纯静态）**：消费方 = `0x3B01A0`(effect) / `0x349AE0`(trigger)。它们**直接读 db 全局**
>   （`0x349B12` 读 `0x32611C8`、`0x3B032A` 读 `0x33746E8`，都带 thunk 同款 inline lazy-ctor），用内联的
>   MSVC `_Tree::_Lbound` 按裸 u32 key 走树，命中即 `call [value[0]+8]`。§22.4 里「引擎不从 .text 读这个全局」
>   那句是错的，已在原处标注。找到它靠换钥匙：`class_info` 的地址搜不到（永远以 `[reg+8]` 形式出现），
>   但**形状**可搜 —— `scripts/createsites.py`（`.pdata` 对齐解码，要求 `mov [reg+0x28]` 近距离接
>   `call [reg+8]` 且函数碰过 `[reg+0x20]`）× `scripts/riprefs.py`（字节级 rip 引用，5 s 顶掉 15 min 的
>   `find_refs.py`）。221 个形状命中里，同时读 `0x33746E8` 的只有 1 个函数。
> * **C1 的性质因此变了**：不再是「缺一个地址」，而是「造出来的对象必须经得起引擎写它」。
>   create 返回之后引擎先写 `[obj+0x20]=id` / `[obj+0x28]=name`（trigger 是 `+0x38`/`+0x40`），
>   再 `call [vptr+0x98]`（trigger `[vptr+0x80]`，al 为 bool，失败即 trigger.cpp 那句报错）。
>   且 `0x3AF130`/`0x348450`（由 `0x1BFD30` 调用）会**遍历整棵树逐个 create** —— 注册不是无害操作。
> * **C1 形态已决策（2026-09-29，选项 = 别名式）并写完静态依据（§24）**：不自己造对象，
>   value record 的 `class_info` 直接指向一个**现有官方** class_info。这不是绕路，是引擎自带的形态：
>   1,615 条 keyword 记录压在 1,605 个 class_info 上，**9 个已经服务 2-3 个 token id**
>   （`if`/`else_if`/`else` 共用 `0x269DC98`），而 1,605 个 `create` 体两两不同 → 共享只发生在 class_info 层。
>   `riprefs` 侧证据：每个 keyword 在自己的 thunk 里恰好一个 rip 引用点，且各自 `new(0x10)` ——
>   **别名不共享 value record，所以共享 deleter `0x34C090` 拿不到同一块，没有 double-free 面**。
>   捐赠者：trigger `0x269CAA8`(`create 0x1B30450`, `new(0x80)`，全文件最小且本身已是 2-id 别名)、
>   effect `0x2611070`(`create 0x1893130`, `new(0xc0)`)；两者的 `+0x78/+0x80/+0x98` 已按裸 qword 读过。
>   顺带这次测量改掉两处旧结论（§24.4）：`lea rax,[rip+X]` 发布地址 vs `mov rax,[rip+X]` 复制全局值被
>   §22.3 混为一谈，实测次指针 effect 在 `+0x8`、trigger 在 `+0x78`，且 **1,605 个工厂里 544 个只发布
>   0 或 1 个静态地址**（其余由基类 ctor 补）；§23.1 把 `+0x98` 认成 `0x3B1330` 也是错的，实测是
>   `0x3B1420`（bool 谓词），递归解析在**隔壁** `+0x70`（723/723 稳定）。新工具 `scripts/vptrslots.py`
>   + 产物 `evidence/xrefs/vptr_publish_slots_4_4_4.txt`。
>   **别名验的是管线（mint → 插入 → 命中 → create），不是自定义行为**：keyword 会按捐赠类的语义动作，
>   所以 C1 通过不等于 C2（我们自己的类）就近了。仍是 C1 级动作，**仍未授权**。
> * **工具链依赖已入仓（决策）**：`scripts/requirements.txt`（capstone 5.0.7 / pefile 2024.8.26 /
>   unicorn 2.1.4）。unicorn 只有 `emu_desc.py` 需要，它的产物
>   `evidence/xrefs/descriptor_oracle_4_4_4.tsv` 与 `keyword_registry_golden.zig` 已签入，
>   所以重跑 `zig build test` 不需要装 unicorn。
> * **§27（2026-09-30，纯离线）把 C1 判据② 的前提拆了，也顺手改了岗 `lookup_hook.zig`**：
>   读完 `0x89F960`/`0x8A0450` 全体（`scripts/disrva.py`，命令记在 `evidence/logs/lookup_probe_4_4_4.log`）后
>   实测：这两个函数**不是 getter** —— 它们只按 §20 那个「holder +0x10 才是 std::string」的形状读名字
>   （且**单字节字符**：字节级 strlen 循环 + `.data` 里那个空 holder 的 cap 是 15 不是 7），往 0x118 字节的
>   out 里写**四个常量**（`out+0 = 0x25180A8`、`out+0x40 = 0x2518128`，后者的 slot[1] 就是 base
>   `CEffect::Execute 0x1D08520` ⇒ `+0x40` 是内嵌 CEffect 的 vptr，**不是**第二个名字串），
>   然后走 BST，命中只做一件事：经 `0x1C91C30` 打
>   `"scripted effect %s is overwriting an existing effect, rename it"`（`0x2518190`，scriptedeffect.cpp:33）。
>   所以「lookup 返回非空」这条判据**不可观测**（命中与未命中写出的字节一模一样），② 必须改成 §23 的消费方命中；
>   同时白捡一个 §25.5 折叠撞名的**运行时探测器**：游戏日志里出现这句 overwriting 告警，就等于我们的 keyword
>   静默接管了官方 id ⇒ 「零 overwriting 告警」是硬判据。另：名字没有 token 时兜底搜索 key 是 **12**，
>   而 12 在 9,863 个描述符与两个 keyword db 里都是空洞 ⇒ 未铸造的名字不可能误报。
>   `lookup_hook.zig` 照此改岗并修掉三个真 bug：名字读偏移差 `0x10`、把 `+0x40` 的 vptr 当 wstring 读、
>   `LookupHookDrain` 扫 `0..total` 后把 `seq` 归零（环回绕后每条重发一遍，且与在途 recorder 抢槽位）。
>   现在 `Shape.classify` 用 install 时抓到的 image base 把 `out+0x00` 归成 `ref/null_template/unknown`，
>   drain 用私有 cursor + 消费标记 + `LookupHookDropped`/`LookupHookTotal`。常量入 `offsets.scripted_lookup`。
>   `zig build test`：**293/293**（24/27 steps，两个 QuickJS 链接步仍是本机 glibc 起不来；
>   §29 退役 `id_mapper` 后为 **272/272**）。

1. `src/dll/shared/offsets.zig` 补齐缺的锚点：`0x1D13270`(GetOrAddToken)、`0x1D12C60`(token db 单例)、
   db 对象 `0x37347A0`、`0x1D158A0`(slot writer)、`0x3AEBA0`(db lazy-ctor)、`0x3AEF60`(BST insert)、
   `0x1D08520`(base Execute)。现有的 `scripted_db` 块里 `RVA_EFFECT_DB_GLOBAL`/`RVA_TRIGGER_DB_GLOBAL`/
   `NODE_KEY = 0x20` 已经和 §18 对上了，不用动。
2. 新建 `src/dll/scripted/keyword_registry.zig`：按 §17/§18 的配方实现「铸 id → 造 value 记录 → 插 BST」
   三步，descriptor 用 `0x120` stride、字段布局照 §18 的 `0x1D158A0`（`+0x00` u32 id、`+0x04` 一字节 0、
   `+0x08` SSO 名字、buffer 在 `+0x20`、容量 `0x100`）。
3. **离线验收判据（这是 C0 的全部意义）**：拿本地 `stellaris.exe` 拷贝，把我们自己构造的 `0x120` 字节块，
   与 `evidence/xrefs/keyword_registration_table_4_4_4.tsv` 里真实条目的字节做逐字节 diff，
   差异只允许出现在 id 与名字两处。**对不上就不许进 C1** —— §18 说「逐字节同构」是推断，
   这一步把它变成实测。对照实现可以复用 `scripts/pestr.py` / `scripts/fastcalls.py` 的 PE 读取骨架。
4. 顺手结掉 §19 唯一残留的前半：确认 `0x1D13270` 的调用约定。现有证据只到「调用点一律
   `lea rcx, [&object]`，对象之间间隔 `0x38`，对象在 `.data` 且文件里全零」，
   而 §18 记的是 `name at rdi+0x10`。这两种说法需要在静态上钉死一个，否则 Zig 侧传参会猜。

**C1 — 实机别名注册（第一次改引擎状态，需新的明确授权）**

- 内容（2026-09-29 决策：别名式，不造对象）：铸一个新 token id，把它的 value record 指向一个
  **现有官方** `class_info`（trigger `0x269CAA8` / effect `0x2611070`，见 §24.3）。没有「我们的
  `ExecuteActual` 写一行日志」这种事了 —— §23 要求对象 well-formed，而别名把这条要求整个继承掉。
- **两个参数已定（2026-09-30，§24.6）**：① **先打 trigger db `0x32611C8`** —— 它的 bring-up 是一句无参
  `0x347BD0`（自己 `new(0x98)` + 构造 + 回写全局），而 effect 侧要我们分配 `0x70`、placement-construct、
  再发布全局，多两个引擎地址和一条失败模式；参考 thunk 样板 `0x127e60`。
  ② `value+8` 的 docstring **复用 donor 自己的 `.rdata` 串**（`0x26C1BA0`；effect 侧 `0x2616260`），
  不用我们 DLL 里的串 —— 引擎在 db 生命周期内一直持有这个指针，我们的模块随时可能被卸。
  代价说清楚：共享 `0x269CAA8` 的两个官方 keyword 各自带**不同**的 docstring（Crisis `0x26C1BA0` vs
  Menace `0x26C1B40`），所以「一 keyword 一条文案」才是 shipped 形态，复用是**明知故犯的、纯外观的**偏离，
  换掉的是 use-after-free 那一类风险。Zig 侧 `ClassInfo.triggerDonor(base)` 一次给齐两个字段。
- 照 §19 的官方样板：**铸 token、lazy-ctor db、插 BST 放在同一次调用序列里**（`0x1930e70` 体内就是这个顺序），
  不分两阶段。
- **C1 预检（§25.5 新增，硬条件）**：候选名字必须在**大小写折叠意义下**与 9,863 个描述符名和 1,610 个
  keyword 名都不相同。查表是大小写不敏感的（脚本里的 `NOT/OR/ICON` 在表里只有小写形式），所以一个只差
  大小写的名字不会铸出新 id，而是**返回官方那个 id** —— 新 keyword 会静默接管官方 keyword，而 `eax`
  看不出区别。§20 的「不能以 `-` 或数字开头」不足以保证这一点。离线一条命令即可判定：
  `python3 scripts/c1_preflight.py --name X --db triggers`（读 oracle + keyword 普查两张表，大小写折叠
  比对，退出码 0 = 干净）。执行体内已织入同一规则：`keyword_registry.NameCheck` 会在 `0x1D13270` **之前**
  拒掉空名 / §20 首字符 / 非全小写。
- **可观测的 id 预测**：首次铸造应为 `max static 18817 + 1 = 18818`。更大的 id 正常（§19：启动期惰性
  访问器继续铸），**更小**的 id 就意味着这张脚本刚查过的那种折叠撞名 —— 判据②要同时看命中和这个数。
- 判据（必须是不看日志也能证的观测；按①的 decided 顺序，先只写 trigger 侧，effect 侧是它的孪生）：
  ① 载入不报错，官方 keyword 路径不受影响（§0 第二条判据）—— **§30 给了这一条的具体看法**：若脚本在我们
  插入**之前**就引用了新 keyword，`0x5350D0` 的默认分支会落到 `0x1D092C0`，产出的是 `Unexpected token`
  错误表项 + `[obj+0x28] = 1`，即「报错」而不是「静默没命中」，所以日志里冒出杂散 `Unexpected token` 就是时序问题；
  ② 消费方**命中**：`0x349AE0` 的 `_Lbound` 走到我们那个节点并 `create` 出对象（effect 侧对应 `0x3B01A0`）。
  ~~「或 trigger lookup `0x8A0450` 按新名字返回非空」~~ **§27 已删掉这半条**：那两个 `GetScripted*` 无论命中
  与否都往 out 写同一组常量 vtable，「返回非空」在两个分支上都成立，拿来当判据等于没有判据；
  ③ 遍历路径不炸：`0x348450`（effect 侧 `0x3AF130`）会逐个 create 整棵树，我们插入的节点必经此一路径 ——
  这一步等价于「别名对象在 dump 里活着」；
  ④ **零 `is overwriting an existing` 告警**（§27.3 新增）：这句 scriptedeffect.cpp:33 / scriptedtrigger.cpp:18
  的告警只在名字的 token id **已经在 db 里**时打出来，所以它正是 §25.5 折叠撞名的运行时探测器 ——
  出现一行就说明我们静默接管了官方 keyword，而不是铸造了新 id。配合「可观测的 id 预测」（首发应为 18818）一起看。
  四者齐了才算注册链可信。
- **失败回退**：db 全局 `0x33746E8`/`0x32611C8` 是我们唯一写入点，插入前先快照原树根，出错即整块还原。
  绝不在 `ExecHookVerify != 0` 时 FreeLibrary（§1 铁律）。

**C2 — QuickJS 运行时单例 + 最小 API 面**（沿用原计划：先只定「读 scope / 写 scope / 遍历星系」三类原语，不做多余抽象。
现有 `src/dll/quickjs/{runtime.zig,bindings.zig}` 是骨架，等 C1 证明注册链可信再接。）

**C3 — 注册时机的结论**（不再是待办，降为设计依据）：~~「`0xCCCEB0` 跑完之后 + guard byte `0x337A844`~~ 已作废，
`0x337A844` 是 trace-enable 开关（§16）。~~「等脚本载入完成」~~ 也不需要 —— §19：解析器从不铸 token，
id 唯一性由 `0x1D13270` 自身保证，`0x3AEF60` 对 key 无范围校验，晚插入合法。
只剩两个前提：(a) 目标 db 已被 `0x3AEBA0` 构造（我们自己在调用序列里先调），(b) 在**求值**引用该 keyword 之前完成。

**C4 — 试点一**：`chokepoint_score`，按图连通度给星系打新 effect。
**C5 — 试点二**：种族占比 → 资源产出 / 对母国外交与战争态度。
**C6 — 验收**：日志 + 可复现行为；官方 scripted_effects 路径不受影响。

### 为什么是这个顺序

C0 把「我们造的描述符到底像不像真的」这个唯一的硬风险在**离线**环境下证伪或证实，
不消耗 Windows 机时、不碰游戏进程、不改任何引擎状态。C0 不过，C1 就不该开工。

## 7. Backlog（不阻塞主线）

~~触发器路径（`0x5350D0` 家族，§26 已把它从「分发开关」改判为按 token id 取值的 getter，这条 backlog 的价值
需要按新定性重估）~~ **已重估并关闭（§28，2026-09-30，纯离线）**：`0x5350D0` 在 37 MB `.text` 里
**零直接调用点**，`.rdata` 里**只有一个引用**（`0x24F9940`）⇒ 它是某个类的**虚成员槽**，不是全局分发器；
每个 case 读的是 `rdx` 对象的**硬编码字段**（`+0x120/+0x28/+0x288/+0x278`），邻槽 `0x5345E0` 直接以常量
`mov edx, 0x2cd` 要 id 717 —— 这是「按名取成员」，与 §26 从 id 集合推出的定性对上了。
**默认分支不是失败路径**：它 tail 进 `0x1D092C0`（429 站点 / 394 函数，调用者全是脚本读取侧），
所以新 mint 的 id 走到这里也不会被丢掉 —— 注册新 keyword 不需要这里配合，这里也没有可教给引擎的东西。
结论：**它作为 detour 目标的价值 = 0**，§7 旧结论 2 正式作废；执行面仍是 §23/§24 的 `create()` + 每类自己的虚函数。
留下的两点**未定且被明写为不可当前提使用**：~~`0x1D092C0` 兜底到底是「按名取变量」还是「造错误视图」~~
**已由 §30 离线判定 = 造错误视图**（`0x1D09330` 的 22 个调用方全部传错误文案，节点是
`{文案, token id, offending 文本}` 追加进 `obj+0x10` 链表并置 `obj+0x28 = 1`，随后尾调 tokenizer 推进），
所以它**不是** JS 作用域变量桥的锚点；同一次追查在 §30.2 找到了真正要用的东西 —— token DB 的
**`id → name` 反查表**（`[0x37347A0+0x70] + id*0x30`，holder 的 `std::string` 在 `+0x10`，由 `0x1D12CD0`
从 9,863 条静态描述符**和**动态 name→id map 两半一起灌），这是 C1 首发 id 的**读回验伪**候选，也是
QuickJS 侧「这个 id 是哪个 keyword」的第一条实锚。剩下未定的只有 `0x24F9910` 这个数组的**槽号归属**
（`0x535070` 末尾 `jmp [rax+0x28]` 字面上是跳回自己，且
`riprefs` 显示 `.text` 里**没有任何站点发布 `0x24F9910`** ⇒ 它多半不是被发布的 vtable 起点，§22.5 的合并段）。~~`src/dll/scripted/lookup_hook.zig` 退役或改岗~~ **已改岗（§27，2026-09-30，纯离线）**：
它的两个目标不是 getter 而是「按名构造 ref + 撞名告警」，所以钩子继续留得住，但**模型换掉了** ——
名字是 `r8+0x10` 的**单字节** `std::string`（不是 UTF-16，不是 r8 本身），`out+0x40` 是内嵌 CEffect 的 vptr
（不是第二个名字串），并且新增 `Shape.classify` + 修好 drain 的 cursor/重复/丢记录问题。
「退役」这个选项之所以不再需要：判据② 换了落点（§23 的消费方 + ④ 零告警），钩子交出的
`out_vtable`/`ceffect_vtable`/`req_name` 现在都是可解释的字段，而不是垃圾。
~~`src/dll/effects/id_mapper.zig` —— 它自己的头注释已承认那份内置 id 表「只是示意、不是活的引擎表」，
C0 之后若确实用不上就退役~~ **已退役（§29，2026-09-30，你点头的「删除」）**：判据是三条实测而不是口味 ——
① `src/` + `build.zig` 零 import（唯一引用是它专属的测试步，所以它那 21 条测试是全文件唯一在跑的东西，
而它们测的是手搓 `AutoHashMap`，不是引擎）；② 它自己承认内置表「ILLUSTRATIVE ONLY … NOT read from the
engine」，来源是 4.4.4 并不存在的 3.x `0x14180B050` 开关；③ **重锚定方案已评估并否掉**：真实 name↔id 对
离线就有（`keyword_behaviour_registration_4_4_4.tsv` 的 741 条 effect 行），但**没有消费者** —— id 归谁由
引擎的 `0x1D13270` 决定（§18/§19），C1 不手挑 id，§25.5 的撞名问题已由 `c1_preflight.py`（离线）+
`keyword_registry.NameCheck`（运行期）回答。为零消费者嵌 741 行就是本项目一直在删的投机。
`offsets.known_effect_ids.SCRIPTED_EFFECT_BASE = 10000` 作为**观测记录**保留（活树 key 不是连续段：
146、227、10000+），已改标 `[OBSERVED, no consumer]`。计数：`zig build test` → **22/25 步、272/272**
（293 − 21，减去两步），`zig build` 照常产出 DLL。
~~`diag.py` 里已死的 3.x `0x180B050` 引用~~ **已清（2026-09-30）**：那条不只是死引用 —— 它以
`ptr("0x14180B050")` **绝对地址**直接 `Interceptor.attach`，既没加 module base（ASLR 下必然错位），
钩的又是 4.4.4 并不存在的那个 switch（§3/§14），真跑起来是去 patch 某个不相干的函数。现在钩
`module.base + 0x1D08520`（已确认的 base `CEffect::Execute`），并按 §1 保持只记录：~5,300 calls/s 下
不逐条存记录，改成计数 + slot[2](`ExecuteActual`) 目标直方图，且补了 `collect()` —— 之前那个数组
push 进去后**从来没有被读回**，命令只会打印 "Monitoring completed"。同一命令里的 `monitor-triggers`
整段没有 attach 任何东西（只 enumerate 了内存范围）却回报 `success: true`，已删除：4.4.4 没有确认的
`CTrigger::Evaluate` 锚点，留着就是假成功（trigger 侧我们只钉到 §23 的解析期 `0x349AE0`/`0x348450`）。
3.x `c_effect`/`c_event_scope` 偏移核对（`offsets.zig` 里这几条仍标 `[UNVERIFIED 3.x]`）
**已做完离线一半（§26，2026-09-30）**：`[arg2+8]` 在 `0x1D08520` 里是 `inc`→`call [vptr+0x10]`→`dec`
的**调用深度计数器**，所以 3.x 那条「`CEventScope` 的 `+8` 是 scope type」对 Execute 收到的对象是**错的**；
4.4.4 真正走到 keyword id 的链是 `[[frame+0x30]+8]+8`（§26.1），而 `0x5350D0` 据此从「effect/trigger
分发开关」改判为**按 token id 取值的 getter**（它 22 个分派 id 里混着 `graphicsSettings`/
`defaultAnimationTime`/`maxHeight`/`sendgame` —— 触发器求值器不会 dispatch 这些），所以 §7 结论 2 不能再
拿来当作「detour 那个开关」的理由。另一半是活的代码风险：`api/scope.zig` 被 `main.zig → bridge.zig`
链进 DLL，读的就是这两条 `+8`/`+16`，已把它的「verified from IDA」声明和 `ceffect.zig`/`ctrigger.zig`
的同类声明改成实测状态（`+0xFF0` 那条最硬：1,605 个 keyword 类里**只有 3 个**分配得到 `+0xFF0`，其余
1,602 个是越界读）。仍未定的：真正的 `CEventScope` 是哪个对象 —— 那要等 §5 的只记录 detour 交出
一个真的 `arg2`，离线拿不到。**`ceffect.zig`/`ctrigger.zig` 已删除（2026-09-30，你点头的）**：它们既没被
import 也没进 build.zig，铁证是它自己的测试断言 `SCRIPTED_EFFECT_BASE == 4081`，而表里早就是 `10000`，
这断言真在跑就会红 —— 死代码 + 错结论 + 静默不测。不选「按 §23 重锚定保留骨架」的原因是它的**钩子模型**
本身被 4.4.4 否掉了：单点绝对 `ExecuteActual`/`Evaluate` 不存在，分派是每实例 `call [vptr+0x10]`（§26），
留下骨架只会留下错的形状。删后 `zig build`（DLL 照常链接）与 `zig build test`（`270/270`）不变，这就是
「没人依赖它」的确认。**遗留**：`effects/handler.zig` 与 `triggers/handler.zig` 只被这两个文件 import，
现在也成孤儿了；~~暂时留着当 C3 的 JS 路由层~~ **2026-09-30 已决：留（你的「2. 留」，理由见 §29）** ——
与 `id_mapper` 的不对称是刻意的：这两个是**有具名消费者（C3）的占位**，`id_mapper` 是**没有消费者且前提为假
的表**。若 C3 最终不经过这层路由，那时再删。
QuickJS eval 在 Windows 的实机测试。

## 8. 待定决策

- ~~「写而不装」算不算越界~~ **2026-09-29 已决：写，但加硬门。** C0 第 2 项的执行体已经落在
  `keyword_registry.zig` 里，`authorize.c1_registration = false` + `registerSequence` 非 `pub`，
  外部唯一入口只会返回 `error.NotAuthorized`；门本身是运行时分支，因此能被这批离线假指针测试覆盖
  （执行体 9 条：四条成功路径与顺序、`0x1D13270` 之前的名字预检、引擎自身拒绝、分配失败、ensure 未回写）。
  **C1 的授权动作由此退化成一次一行的源码改动 + 一句明确指令**：翻常量之前，任何东西都调不到它，
  DLL 里也没有装它的地方。
- 未定义字节 **保持显式清零**（`0x1D158A0` 从不写 `+0x05..07` 与名字 terminator 之后的尾部）。
  oracle 因此可以逐字节判定；实机若在这两处出现非零，那是分配器残留，不是语义。
- 覆盖率 **56 golden + 全量 tsv**：Zig 测试内嵌 56 个引擎产物向量，9,863 条全量比对留在
  `evidence/xrefs/descriptor_oracle_4_4_4.tsv` 里，不把 1 MB 十六进制塞进二进制。
- QuickJS 接入走**便宜路**（注册成 scripted effect + detour `0x1D08520`）还是**全路**（真·新 keyword）——
  **2026-09-29 更新：A3/A4 双双闭合（§17 + §18），全路已无未知项**，四步配方全部落在真实地址且不需要 patch 静态表。
  决策依据回到 §0 判据：若便宜路表达不出「星系连通度」「种族占比→外交态度」这类跨 scope 聚合，就走全路。
  **建议走全路**，成本已从「未知深水区」降为「按配方实现」；便宜路可作为对照实现保留。
  **2026-09-29：这条决策不再是主线阻塞 —— 两条路都需要同一个 `0x120` 描述符与同一条铸 id→插 BST 链，
  所以先做 C0 不影响选路**，等 C0 的逐字节对照结果出来再定也来得及。
- `.i64` 要不要拷到本机 —— **不需要了**：Phase A 全程用 `scripts/*` 的 capstone + `.pdata` +  relocated-qword
  三件套离线完成，`0x1D13270` 这种关键函数就是靠 `.rdata` 报错字符串 + `find_refs.py` 单点引用直接定位的，
  IDA 的历史分析并没有提供额外杠杆。若 Phase C 需要大规模类型化反编译再另说。
- **C1 的两个参数（2026-09-30 已决，细节在证据文件 §24.6）**：
  ① `value+8` 的 docstring **走保守路** —— 复用 donor 官方 `.rdata` 串（trigger `0x26C1BA0` /
  effect `0x2616260`），不放我们 DLL 里的串。理由不是外观，是引擎在 db 生命周期内一直持有这个指针，
  而我们自己的串一旦模块卸载就悬空（与 §1「`ExecHookVerify != 0` 时绝不 FreeLibrary」是同一类风险）。
  已知偏离：共享 `0x269CAA8` 的两个官方 keyword 带**不同**文案，per-keyword docstring 才是 shipped 形态。
  ② **先打 trigger db `0x32611C8`**（donor `0x269CAA8`），effect 侧留作孪生复现。
  这两条是**参数选择，不是授权** —— C1 仍需一次单独的明确指令。
