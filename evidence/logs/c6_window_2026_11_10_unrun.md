# 实机窗口 2026-11-10/11 —— R2 / R3 / R5 / R8 未打的原因，与已落的读数

> 授权记录（逐字）：2026-11-10，用户指令：「Windows已经上线了，继续派发实机任务。实际任务都要使用code-reverse模型」
>
> 本轮范围（任务书）：R0、R1、R2、R3、R4、R5、R8。不做 R6 / R7（依赖未合并分支）。

## 已落

| 发次 | 判决词 | 产物 |
|---|---|---|
| R0（环境前置） | `just awake check` → `rc=0`（`STATE=serving DESKTOP=unlocked`）；`ns_world status` → `STATE=NO_GAME`（无进程）；主机 `c2_boot_inject.py` sha256 与仓库 `32ec722c…` 逐字一致；`Game Version: Pegasus v4.4.4`；无残留 `stellaris.exe` | 本节 |
| R1（独立复打一发） | C6-1 `pass`（`install_rc=0 effect_id=19343 set_id=19344`）、C6-3 `pass`（`writes=2364==matched`、`skipped=0`；存档 `systems=788 min=0 max=787`）、C6-6 `pass`（`UNINSTALL rc=0 verify=0`） | 本文件目录外的 `c6_r1_*`（**另一发已先提交，见下**） |
| R4（issue #46） | **`graph_collision_named`**：指纹 `3991881723736717560` 与哈希 `cec23a9e2b0a890d` 加/删同一对边后都回到原值，边数 `1219 -> 1219` | `c5_graph_collide_4_4_4.tsv`、`c5_graph_collide_4_4_4.log` |
| 工具缺陷 | `c2_graph_read.read_live_pair` 的 `struct.unpack("<QQ", buf, 0)`（`unpack` 没有 offset）⇒ 整条 `--mutate-collide` 在主机上 `TypeError`。已修 + 补回归测试（该函数此前无测试） | `scripts/c2_graph_read.py`、`scripts/test_c2_graph_read.py` |

**R1 的归属说明（诚实条款）**：我这一发（pid 7888，`sqjs_lw1.dll` sha `01deb02f…`，`writes=2364`）
是在**另一个 worker 已经提交了它自己那一发之后**跑的（`dc2a311`，pid 与 `writes=18124`）。
我一度覆盖了那两个已入库的证据文件，发现后已 `git checkout --` 还原；本发读数记在这里，
不重写已入库的那两份（`evidence/` 只追加、不改写）。

## 未打：R2 / R3 / R5 / R8（全部同一个环境原因）

**这一场窗口的桌面被第二个操作者/另一个 worker 同时占用**，实测证据：
`win-desktop` MCP 在 23:59 返回 `USER_CONTROL`（`state=user`，等待 10 s），
即**人在操作这台机器的桌面**；同一时段游戏的 pid 在我没有下达任何命令时自行更换
（17980 → 6656 → 17884 → 18736 → 17044），`C:\temp\ns_game_cmd.txt` 里出现不是我写的
`dismiss` 与两次 `quit`。协调者（`term_e9614e61…`）在 21:5x 的 message 里已确认存在「第二操作者」
并要求停手等 go。

在这个前提下每一发的门都是 `exit 2`，逐条：

| 发次 | 当时的回执 | 为什么不能绕 |
|---|---|---|
| R2（`--guard execcaller`） | `STATE=WINDOW_UNSTABLE EXIT=2` | 洁净星图上密集的舰队/星系铭牌落在判据带里（`gold_px` 上万、`row_count` 20+），状态机读成 `dialog`；`--allow-window` 是**操作者声明前提**，需要人当场确认屏幕，而屏幕正被另一个人操作 |
| R3（C6-4 对账） | 未起进程 | 需要「加一条边并保留」的第二窗口 + 两次边快照 + `id<TAB>name` 映射；仓库里**没有** name-map 生产者，按任务书只能落 `tiers_counts` ⇒ C6-4 记 `cannot_say` |
| R5（C6-5 对照组） | 未起进程 | 需要**两趟**同存档同窗口长度的运行；桌面争用下第二趟无法保证与前一趟同起点。另：`scripts/c6_acceptance.py` 不在本 worktree 的 HEAD 里（另一条 lane 在写），我没有用它出判词 |
| R8（census） | 未起进程 | `execspy.py` 要求「暂停 → 装 → 解除暂停 → 60 s → 暂停 → 拆」的人机同步；MCP 已被 `USER_CONTROL` 挡下，无法保证静默窗 |

## 环境事实（与读数一起记，不是判负）

1. **Windows→Linux 回传在 ~4–8 KB 处被重置**：`cat` 18 KB 的文件只到 6098 B 就
   `Connection reset by peer`；6.6 KB 的 base64 到达 0 B；`scp` 下载 4 KB 也断；上传 7.8 MB 正常。
   本轮用 `scripts/scratch/2026-11_live_window/` 的一次性工具绕开：主机侧 `gzip` + 500 B/块 base64
   （`lw_pull.py` / `lw_remote.py`，~330 B/s）。**3.4 MB 的存档因此没有拉回 Linux**：
   C6-3 的存档侧读数改成在主机上跑同一个 `c5_variable_probe.py`（见 `c6_r1_save_variables_4_4_4.txt`）。
2. **状态机的 `window=dialog` 有两种来源，必须分开读**：一种是**真的**事件窗（本轮撞到两次：
   「卡威萨姆展示灵能潜能」与一个 12 行选项窗），点掉即恢复 `IN_GAME_RUNNING`；另一种是洁净星图上
   密集的舰队条/星系铭牌落进判据带（`gold_px` 4,594–20,691、`row_count` 12–24），
   这一档才是 §31 的假阳性。**只按 `pause=` 与截图一起判，不要只读 `window=`。**
3. **主机上还有第二个操作者**：见上。任何「pid 换了」都要先问是不是别人重启的，
   不要把别人的重启读成我们自己的 `host_died`。

## 要协调者裁定的两件事

1. 这个窗口的**桌面/游戏归谁**：在我与另一个 worker 之间先划清楚，否则每一发的门都可能被
   另一个人的点击/暂停打断（本轮的 R1 已经出现过两发并存）。
2. R1/R4 之后的 R2/R3/R5/R8 是否继续由我打、还是交给另一个 worker（它已经落了 R1/R6/R7）。

## 收尾状态（逐字读回）

- 我为 R2 起的那个进程：`stellaris.exe` pid 17044，**没有注入我们的 DLL**（R2 的驱动在装之前就被门挡住了），
  所以**桌面上没有我们任何 detour 的残留**（`C2NeoInstall` 的额度也没被消耗）。
  这个进程**留在桌面上了**：23:59 时 `win-desktop` 返回 `USER_CONTROL`（人在操作这台机器），
  强杀会打断别人的那一趟 ⇒ 没有 `taskkill`，交给人/协调者处置。
- 我们自己 boot 注入过的那两个进程（7888、18736）都已 `taskkill /F`，收尾时逐字读回 `PROCS count=0`。
