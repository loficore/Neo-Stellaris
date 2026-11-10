# docs/c6-acceptance.md — C6 验收标准

> **形状已定（2026-11-06），读数未产生。** 本文件定的是「什么样算通过」，不是「已经通过」。
> 六个门 id `C6-1` … `C6-6` 由 `scripts/test_c6_acceptance_doc.py` 的围栏钉住：每个门一行、
> 六个列齐全、`auto` 门必须点名一个**真的能产出那个证据词**的脚本、`manual` 门必须给两份对照组。
> 数字一律不抄到这里：读数只引用既有取证卷的 §，理由见 §0 末段。

## 0. 范围

C6 判的是「这套运行期 keyword 能力可以交给 mod 作者用」，不是「每个新效果都对」。
一个新 keyword 的行为对不对，是那个 keyword 自己的验收；C6 只判四条**共性**总判据：

1. **日志对得上** —— 脚本回执、`game.log`、存档三处的计数能互相闭合。
2. **行为可复现** —— 同一存档、同一窗口长度、同一个开关（DLL 装没装），两次读数同形。
3. **官方 scripted_effects 路径不受影响** —— 我们的注册与 detour 不给官方脚本添错误。
4. **收尾能验证** —— 拆掉之后钩子计数归零，且**从不** `FreeLibrary`（`AGENTS.md` 约束 5）。

**为什么门里不写数字。** 上一场战役的系统数与边数是**那一场存档**的读数（M4 那一发是
788/1219，而 §95 的分母是 787），换存档就变。写死的数字会在下一场变成一条读起来像判负、
其实只是换了存档的红。分母一律写「这一场的容器原始条数」并给出取法。

## 1. 六道门

| gate | 判据 | 观测 | 证据词 | 阈值 | 方式 |
|---|---|---|---|---|---|
| C6-1 | 新 keyword 在脚本解析前就拿到 token id | `scripts/c2_boot_inject.py` 的 `BOOT` 回执一行 | install_rc=0 | effect_id>0 且 set_id>0，且 `gate=world_state` | auto |
| C6-2 | 引擎按星系调用我们的代码 | `scripts/c2_exec_caller_probe.py` 的 artifact | dispatch_named | distinct_ids 与**这一场**容器原始条数逐项相等 | auto |
| C6-3 | 状态写进真实存档、逐系统可对 | `scripts/c5_variable_probe.py --name neo_mark` 的逐系统行 + 同一进程的 `--stats` 写入计数 | systems= | 系统集合与容器逐项相等、值 = 系统 id（判词 `neo_state_written`） | auto |
| C6-4 | 官方 DSL 读得回我们写的状态并据此分支 | `scripts/c2_graph_reconcile.py` 的引擎回执 vs 主机侧重算 | tiers_named | 有 `--name-map` 时逐名相等；没有时只能 `tiers_counts`（判词 `score_drives_official_state`） | auto |
| C6-5 | 官方 scripted_effects 语义不变 | 同一存档同一场景的两份 `game.log`（`base.log` / `with_dll.log`）与两份 `error.log` | official_effects_unchanged | `error.log` 零新增脚本错误、官方 marker 集合逐项相等 | manual |
| C6-6 | 收尾可验证、不留下必须卸载的钩子 | `scripts/c2_boot_inject.py --uninstall` 的回执一行 | UNINSTALL | rc=0 且 verify=0，host 存活，且**从不** FreeLibrary | auto |

## 2. 每道门：通过 / 失败 / 不能说

### C6-1 注册早于解析

**通过**：`BOOT` 回执行里 `install_rc=0`、`effect_id>0`、`set_id>0`，`alive=1`；
同一场的 `error.log` **零** `Unexpected token`（§30：晚注册的签名就是这条错误表项，
而不是「静默没命中」）。

**失败**：`effect_id==0`（名字被 `scripts/c1_preflight.py` 的规则挡下，或 mint 失败）、
`install_rc!=0`、或 `error.log` 出现 `Unexpected token` ⇒ 这一场的脚本压根没解析我们的词，
后面五道门全部作废。

**不能说**：这一门只证「词有了 id 且解析期没报错」。它**不**证明 id 落在期望的号段、
不证明 `class_info` 被引擎认成「新类」、也不证明 keyword 被执行 —— 那是 C6-2 的事。

### C6-2 逐系统调用

**通过**：artifact 判词 `dispatch_named` —— 调用者 RVA 唯一且落在镜像里、
去重后的系统 id 集合与**这一场**容器原始条数逐项相等（`--systems` 无默认值，必须现场取：
先在同一进程读容器原始条数，再打这一发）。

**失败**：`ids_not_in_container` / `ids_out_of_range`（id 集合与容器对不上，说明我们拿到的
不是逐系统 scope）、或 `no_calls`（装上了但引擎没派发到）。

**不能说**：这一门只证「引擎按星系调到了我们的代码」。它**不**证明每个系统的分数是对的
（那是 C6-4 与离线重算的活），也**不**证明调用次数等于系统数乘月数 —— 月数不在这一门里。

### C6-3 写状态

**通过**：存档里目标变量的系统集合与容器逐项相等（`systems=` 那一行的计数等于容器原始条数，
且 `min`/`max` 覆盖 `0..N-1`），逐项值与该系统的 id 相等；同一进程的写入计数等于命中计数。
这一组读数在取证卷里的判词名是 `neo_state_written`。

**失败**：存档里缺系统（`systems=` 小于容器原始条数）或值不相等；写入计数与命中计数不等
（`skipped` 非 0 ⇒ 有系统被跳过，不是「都写了」）。

**不能说**：这一门只证「值落进了存档能读到的 `variables={}`」。它**不**证明值编码在别的号段
（>786 或负数）成立 —— §94 已记这条边界 —— 也不证明这个变量名不会被别的 mod 覆写。

### C6-4 官方 DSL 读回

**通过**：`c2_graph_reconcile` 的 tier 对账判 `tiers_named`（给了 `id<TAB>name` 映射时逐名相等）；
引擎回执侧用官方 `check_variable` / `has_star_flag` 分档并落 flag，flag 集合与离线 tier 集合
逐项相等。这一组读数在取证卷里的判词名是 `score_drives_official_state`（§95）。

**失败**：`tiers_disagree`（引擎分档与独立重算不一致，且缺口在引擎一侧）；
或合法回执里出现离线重算不可能产生的 tier。

**不能说**：这一门只证「官方 DSL 能按我们写的值分支」。它**不**证明分数表对**别的存档**成立
（表是存档局部的，§95 已记）、不证明 `check_variable` 的比较语义之外的东西、也不证明
flag 不会被持久化带进下一局 —— 它**就是**会持久化。

### C6-5 官方语义不受影响

**通过**：对照组 = **同一存档、同一场景、同一窗口长度，只差 DLL 装没装**。
两份 `game.log` 里官方 marker 集合逐项相等；两份 `error.log` 零新增脚本错误
（行数差为 0，不是「差不多」）。

**失败**：任一份 `error.log` 出现新增脚本错误、官方 marker 少一条或多一条、
或窗口长度不一致（那就不是对照组，读数作废而不是判负）。

**不能说**：这一门只证「官方脚本的**行为与错误面**没变」。它**不**证明性能不变
（detour 在热路径上，开销是另一类读数），也**不**证明所有官方 keyword 都被覆盖 ——
只覆盖这一场脚本实际跑到的那一部分。

### C6-6 收尾

**通过**：`--uninstall` 回执里 rc=0 且 verify=0（`C2NeoUninstall` 拆完 detour 后
`C2NeoVerify==0`），host 存活；全程没有一次 `FreeLibrary`。

**失败**：rc 非 0、verify 非 0（还有钩子没拆）、或拆完 host 死了
（先按 `AGENTS.md` 约束 8 跑两个零游戏判别器，再谈是不是我们的产物）。

**不能说**：「不留下必须卸载的钩子」指的是 `C2NeoUninstall` 之后 `C2NeoVerify==0`，
**不是**「DLL 可以 `FreeLibrary`」—— 后者永远不行（约束 5：引擎持有 class_info 与
vtable 副本的生命周期，超过我们 DLL 的卸载点）。

跑法见 `docs/offline-tooling.md` 的 `c6_acceptance.py` 一节（`--systems` 必填；缺产物降 `cannot_say`，不是 `fail`）。
