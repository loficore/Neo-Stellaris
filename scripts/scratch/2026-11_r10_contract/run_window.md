# R10 runbook — 收到 START 之后的单页操作手册

> **什么时候读这份**：协调者发来 START（带授权原话逐字 + 「主机已在线」的复核命令输出）之后。
> **读法**：从上往下跑；每步有 **expected** 与 **fail 判词**；标着 ⛔ 的失败**必须停**，不许绕过。
> **占位符**：`<SYSTEMS>` / `<SAVE_NAME>` / `<DLL_SHA>` / `<SAVE_SHA>` —— 不要凭印象填，填已测得的值。

## 0. 已测得（离线，可直接填）

| 占位符 | 值 | 出处 |
|---|---|---|
| `<DLL_SHA>` | `2e1ba6d94bb392b477404652a1be520f7f1be54a3344313e4d1f30e7ffee8068` | 本地 `sha256sum` 与远端 `Get-FileHash` 逐字相等 |
| `<SAVE_NAME>` | `r10_base` | `evidence/logs/c6_r10_save_4_4_4.log` |
| `<SAVE_SHA>` | `f6bfae78c7991f1ec25d148b44227659adbc36e27719c4aeb44090f4a02ddfa1` | 同上（远端 + 本地两份相等） |
| `<SYSTEMS>` | `788` | 同上：存档 `galactic_object` **条目数**（id 连续 `0..787`） |

`<SYSTEMS>` 是**存档**的分母；artifact 的 `container_raw_count` 必须等于它，不等 ⇒ 环境档（见 Step 2）。

**bundle 形状的离线复核**（不是 SDK 的 `neo check`，见 §7 第 8 条）：

```bash
node scripts/scratch/2026-11_r10_contract/bundle_smoke.mjs .
```

expected：`SMOKE ok`（manifest 严格 7 字段、5 条 forbidden 模式、`R10_NBR`/`R10_FLAG` 逐字相等、
`r10throw` 抛 `R10_INTENTIONAL`）。改了任何 bundle 之后重跑一次。

## 1. 前置（不占进程）

| # | 命令 | expected | fail 判词 / 动作 |
|---|---|---|---|
| 1.1 | `ping 10.66.0.7` + `ssh Windows_Jiaolong "echo ALIVE"` | 有回包 | ⛔ 不通 ⇒ 停，回协调者（不启动任何进程） |
| 1.2 | `win-desktop Screenshot`（MCP） | 截图**非黑**、能看到桌面 | ⛔ 黑屏 ⇒ 停，查 `Get-Process LogonUI`（计数 >0 = 锁屏 ⇒ 停） |
| 1.3 | `just win "powershell -NoProfile -Command \"(Get-Process LogonUI -ErrorAction SilentlyContinue \| Measure-Object).Count\""` | `0` | ⛔ 非 0 ⇒ 停（锁屏） |
| 1.4 | `just awake check` | `STATE=serving DESKTOP=unlocked`，rc=0 | 非 0 ⇒ `just awake start` 再 check |
| 1.5 | `just win "powershell -NoProfile -Command \"(Get-Process stellaris -ErrorAction SilentlyContinue \| Measure-Object).Count\""` | `0` | ⛔ 非 0 ⇒ `just win "taskkill /F /IM stellaris.exe"` 后复读；仍非 0 ⇒ 停 |
| 1.6 | `just deploy` | rc=0 | 失败 ⇒ 停（脚本没到位，后面的命令全是旧版） |
| 1.7 | `ssh Windows_Jiaolong 'powershell -NoProfile -Command "(Get-FileHash C:\temp\sqjs_r10.dll -Algorithm SHA256).Hash.ToLower()"'` | == `<DLL_SHA>` | ⛔ 不等 ⇒ 停（`dll_locked`/传输问题，不许继续） |
| 1.8 | `just win 'powershell -NoProfile -Command "Remove-Item C:/temp/neo_js.log -Force -ErrorAction SilentlyContinue"'` | 文件不存在 | —（不做 ⇒ 旧行会混进行数） |
| 1.9 | `just win 'powershell -NoProfile -Command "Remove-Item -Recurse -Force C:\temp\neo_mods -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Path C:\temp\neo_mods \| Out-Null"'` | 目录空 | ⛔ 失败 ⇒ 停（残留 mod 会掺进读数，Review Focus 3） |
| 1.10 | `scp <repo>/scripts/scratch/2026-11_r10_contract/bad/r10timeout/{mod.json,main.js} Windows_Jiaolong:C:/temp/neo_mods/r10timeout/neo/`（同 r10throw） | 两个目录各有 2 个文件 | ⛔ 失败 ⇒ 停 |
| 1.11 | `scp -r <repo>/scripts/scratch/2026-11_r10_contract Windows_Jiaolong:C:/temp/r10_contract/` | 目录在 | — |
| 1.12 | `just win "python C:/temp/neo_install.py --dll C:/temp/sqjs_r10.dll --mod C:/temp/r10_contract --no-launch --dry-run --debug"` | 计划 7 步（dll/neo/official×4/descriptor/dlc_load） | `NEO_PLAY fail reason=<tag>` ⇒ 停（tag 见 `FAILURE_TAGS`） |
| 1.13 | `just win "python C:/temp/neo_install.py --dll C:/temp/sqjs_r10.dll --mod C:/temp/r10_contract --no-launch"` | `NEO_PLAY ok dll=<16> mod=r10good pid=0` | ⛔ `fail` ⇒ 停 |
| 1.14 | `scp <repo>/scripts/scratch/2026-11_live_window/lw_set_mods.py Windows_Jiaolong:C:/temp/` | 文件在 | — |
| 1.15 | `just win "python C:/temp/lw_set_mods.py r10good.mod"` | `MODS=mod/r10good.mod` | ⛔ 失败 ⇒ 停。**为什么必须只剩它**：`neo_ps_probe` 也在 `every_system` 里调 `neo_action`，留着会让每系统每月多派发一次，`R10_NBR` 行数翻倍 |

## 2. 进程 A（合同覆盖 + C6-1 + C6-6）—— 预算 1/2

| # | 命令 | expected | fail 判词 / 动作 |
|---|---|---|---|
| 2.1 | `just win "python C:/temp/session_bridge.py --timeout-s 300 C:/temp/ns_world.py assert-ready --action install --guard c6r10"` | `STATE=NO_GAME … EXIT=2`（此刻没有游戏窗口） | **把整行抄进日志**（放行的前提是门确实因为 NO_GAME 拒绝，不是 `blocked`/`wedged`/别的）。若读数**不是** NO_GAME ⇒ ⛔ 停，把读数报给协调者 |
| 2.2 | `just win "python C:/temp/session_bridge.py --timeout-s 900 C:/temp/c2_boot_inject.py C:/temp/sqjs_r10.dll --act write --allow-window --launch 'D:/SteamLibrary/steamapps/common/Stellaris/stellaris.exe' --launch-args=--continuelastsave --timeout-s 600"` | `BOOT dll=sqjs_r10.dll sha=<16> effect_id=<>0 set_id=<()>0 install_rc=0 alive=1` | ⛔ `effect_id=0` 或 `set_id=0` ⇒ **C6-1 判负**，停（后面的门全部作废）。⛔ `install_rc != 0` ⇒ 停（`install_rc=-2` = 复用了进程 ⇒ 读数作废）。`BOOT FAIL <step>` ⇒ 停。**注意**：`session_bridge` 的第一个位置参数就是脚本路径，**不要**再写前导 `python`；`--stats` 与 `--launch` 互斥（stats 只读已在跑的进程），本步不要带 `--stats` |
| 2.3 | `just game status` | `pause=playing` | 不是 playing ⇒ `just game unpause`；仍不动 ⇒ `win-desktop Shortcut("space")`（键盘能解暂停，鼠标点不能，见 `docs/offline-tooling.md`） |
| 2.4 | `just game speed up`；`sleep 120`；`just game status` | 日期推进 **≥ 3 个月** | 只推进 1–2 个月 ⇒ 再 `sleep 120` + `just game status`；仍不足 ⇒ 停（判据是 3 个月的行数） |
| 2.5 | `just win "python C:/temp/session_bridge.py --timeout-s 300 C:/temp/c2_boot_inject.py C:/temp/sqjs_r10.dll --stats"` | 一行含 `installed=1 verify=0`（C6-6 的**前置**，不是 C6-6 本身） | `installed=0` ⇒ 停 |
| 2.6 | `scp "Windows_Jiaolong:C:/temp/neo_js.log" evidence/logs/c6_r10_neo_js_4_4_4.log` | 文件在 | ⛔ 没有 ⇒ 停（读数源没了） |
| 2.7 | `just win "python C:/temp/session_bridge.py --timeout-s 300 C:/temp/c2_boot_inject.py C:/temp/sqjs_r10.dll --uninstall"` | `UNINSTALL rc=0 verify=0 alive=1` | ⛔ `rc!=0` 或 `verify!=0` ⇒ C6-6 判负，停。**回执文件的正文里不要再出现 `rc=` / `verify=` 这类空白分隔记号**：`c6_acceptance.py` 的 `parse_uninstall` 会把整份文件按空白切 `k=v`，后出现的同名键覆盖真回执 ⇒ 门读成 `missing_input` |
| 2.8 | `just win "taskkill /F /IM stellaris.exe"` | 进程数回 0 | 失败 ⇒ ⛔ 停（下一发必须是干净进程） |

### 2.9 三条路径的判据（逐条落盘，任何一条判负都要记原文）

| 判据 | expected | 判负时写什么 |
|---|---|---|
| `neighbors` | `R10_NBR` 行数 == 3 × `<SYSTEMS>`（±1 个月边界），**且每一行** `n == deg` | 任何一行 `n != deg` ⇒ 记 `neighbors_disagree id= deg= n=`，再按 §4 的排查顺序走 |
| `timeout` | `NEO_JS_TIMEOUT` **恰好 1 行**且 `mod=r10timeout` | 0 行 ⇒ `timeout_not_observed`（仪器/装载问题，**不是**「没超时」）；>1 行 ⇒ 逐行抄下来 |
| `error` | `NEO_JS_ERROR` **恰好 1 行**且 `mod=r10throw`，含 `R10_INTENTIONAL` | 0 行 ⇒ 同上；文本不含 `R10_INTENTIONAL` ⇒ 抄原文 |
| `hasStarFlag` | 第一个月的 `before=false` → `after=true`；之后的月份 `before=true` | 始终 false ⇒ 抄 `NEO_JS_FLAG_REJECT … reason=<tag>` 原文（`reason=` 是关键） |
| 好 mod 存活 | 坏 mod 被禁用**之后** `R10_NBR` 仍在涨 | 不再涨 ⇒ 记「坏 mod 拖死了好 mod」 |

**判读提示**：`NEO_JS_CALL` 在 session 循环**之前**打 —— 它是派发次数，不是「mod 干了多少活」。
判「好 mod 没被拖死」要看**好 mod 自己的行**（`R10_NBR`）在坏 mod 被禁用之后还在涨。

## 3. 进程 B（C6-2）—— 预算 2/2

| # | 命令 | expected | fail 判词 / 动作 |
|---|---|---|---|
| 3.1 | 进程数复读（1.5 同一条命令） | `0` | ⛔ 非 0 ⇒ 停 |
| 3.2 | `just win "python C:/temp/lw_set_mods.py neo_ps_probe.mod"` | `MODS=mod/neo_ps_probe.mod` | ⛔ 失败 ⇒ 停 |
| 3.3 | 进程 B 的门：**走它自己的 `gate_install`**（`c2_exec_caller_probe` 内部那道），**不许拿进程 A 的放行当通用豁免** | 读数抄进日志 | 若门判负 ⇒ 停下并报协调者（授权边界） |
| 3.3b | **启动期注入（runbook 初版漏了这一步）**：`neo_ps_probe` 的官方半边在 `every_system` 里调 `neo_action`，我们的 keyword 只在 DLL 载入时进 token DB ⇒ 存档载入前必须有 DLL，否则该事件解析失败、`log` 也不会逐系统下发。用**同字节的第二份文件名**：`ssh … "Copy-Item C:/temp/sqjs_r10.dll C:/temp/sqjs_r10b.dll -Force"`，然后 `just win "python C:/temp/session_bridge.py --timeout-s 900 C:/temp/c2_boot_inject.py C:/temp/sqjs_r10b.dll --act log --allow-window --launch 'D:/SteamLibrary/steamapps/common/Stellaris/stellaris.exe' --launch-args=--continuelastsave --timeout-s 600"` | `BOOT dll=sqjs_r10b.dll … effect_id>0 set_id>0 install_rc=0 alive=1`，随后 `just game start` + `just game unpause`（scancode Space；`win-desktop` 的 Shortcut 对游戏无效） | ⛔ 失败 ⇒ 停。**为什么换名**：`refuse_if_resident` 按模块名拒绝同名的第二份注入 |
| 3.4 | `just win "python C:/temp/session_bridge.py --timeout-s 700 C:/temp/c2_exec_caller_probe.py C:/temp/sqjs_r10.dll --systems <SYSTEMS> --save-name <SAVE_NAME> --out C:/temp/c6_r10_exec_caller.tsv --poll-s 240 --rule 0:0"` | `overall_verdict=dispatch_named`、`coverage_distinct == container_raw_count == <SYSTEMS>`、`recorded_callers=1`、`install_rc=0`、`uninstall_rc=0`、`verify_rc=0`、`host_alive=1`；`#meta gate=world_state`（真门，不是 `operator_override`） | ⛔ `ids_out_of_range`/`ids_not_in_container`/`ids_coverage_incomplete` ⇒ **判负**，**不许改 `--systems` 重打**，artifact 整份抄回来、判词写清、停。`dispatch_denominator_mismatch` ⇒ **环境档**（分母不是这一场的），重开进程再打，不许改判据 |
| 3.5 | `scp "Windows_Jiaolong:C:/temp/c6_r10_exec_caller.tsv" evidence/logs/c6_r10_exec_caller_4_4_4.tsv` | `#meta` 里有 `container_raw_count` / `dll_sha256` | `dll_sha256` != `<DLL_SHA>` ⇒ ⛔ 停（不是这一发装的那份字节） |

### 3.6 `--rule 0:0` 不是可选项

`c2_exec_caller_probe.py` 的默认 `--rule 100:0` 会把通过的 `dispatch_named` **改写**成
`poc_rule_hits` / `poc_no_hits`（`fold_overall_verdict`，`c2_exec_caller_probe.py:301-313`），
而 C6-2 只认 `dispatch_named`（`scripts/c6_acceptance.py` 的 `EVIDENCE_VERDICTS`）。
`--rule 0:0` = 规则关闭 ⇒ 判词不被改写。

## 4. `neighbors` 判负时的排查顺序（每条都要写进日志）

1. `n == 0` 但 `deg > 0` ⇒ 先看 `__neo_system_neighbors` 的返回长度编码（数组的 `len` 在前还是后）；
2. `n > 0` 但元素越界 ⇒ 看元素偏移（边容器元素 **`+8`** 才是 id，见 `runtime_444_graph_runtime.md` §1.3）；
3. `n != deg` 但两者都合理 ⇒ 用 Task 3 拷回来的存档跑 `save_hypergraph.py`，拿离线边表与日志里
   同一批 id 对账（同 id 的邻居集合）。

⛔ **不许**在此时改 `src/` 后直接用第三个进程验证 —— 改完要另开授权。

## 5. 台账与文档（只在有真实读数之后）

```bash
python3 scripts/c6_acceptance.py \
  --boot evidence/logs/c6_r10_boot_4_4_4.log \
  --uninstall evidence/logs/c6_r10_uninstall_4_4_4.log \
  --exec-caller evidence/logs/c6_r10_exec_caller_4_4_4.tsv \
  --systems <SYSTEMS> \
  --out evidence/logs/c6_acceptance_r10_4_4_4.tsv
```

expected：`C6-1 pass` / `C6-2 pass` / `C6-6 pass`，其余三门 `cannot_say`（本发没打 C6-3/4/5 的输入）。

然后才改 `site/guide/known-limits.md`（`neighbors` 的实机形态、flag 「一次读数」→「两次」）与
`docs/roadmap.md` 的 C6 行；**没有读数就不许写这两处**。

```bash
python3 -m pytest scripts/test_docs_site.py scripts/test_c6_acceptance_doc.py scripts/test_scripts_layout.py -q
```

## 6. 清理

```bash
just win "powershell -NoProfile -Command \"Remove-Item -Recurse -Force C:\temp\neo_mods\r10timeout,C:\temp\neo_mods\r10throw -ErrorAction SilentlyContinue\""
just win "python C:/temp/neo_install.py --dry-run --debug"
```

`r10_base.sav` 留着（下一发要用同一份存档）。

## 7. 与计划的偏差（离线发现；每条都写进了 `evidence/logs/c6_r10_4_4_4.log`）

1. **manifest 不能写 `name` / `version`。** loader 的字段集是**严格 7 个**
   （`src/dll/c2/neo_js_loader.zig:168-194`），第 8 个键 = `UnknownField` = `NEO_JS_BAD_MANIFEST`
   ⇒ 整个 mod 不载入。计划草图里的 `{"name":…,"version":…}` 会让好 mod 缺席。
2. **权限必须带 `flag.read`。** `hasStarFlag` 走 `canReadFlag`
   （`src/dll/c2/neo_js_host.zig:1188`）；缺这一位不只是「读回 false」，它会
   `disableCurrent()` **把 session 整个禁用** ⇒ `R10_FLAG` 只出现一次、`after=true` 永不出现。
3. **分母的正则**：`galactic_object` 的 `{` 在**下一行**（`(?m)^\t(\d+)=\n\t\{`），计划草图的
   `^\s*\d+=\s*\{` 恒 0 命中；且必须取**顶级** `^galactic_object=$` 那一块。
4. **C6-2 必须 `--rule 0:0`**（见 §3.6）—— 计划草图的命令没带，会把 `dispatch_named` 改写掉。
5. **门在启动期结构上不可能满足**：`assert_ready` 要求 `IN_GAME_RUNNING`，而注入必须早于存档载入
   （解析在载入时）⇒ 启动期那一次读数必然是 `NO_GAME`。2026-11-15 的授权原话就是为此发的；
   **进程 B 仍走它自己的门**。
6. **JS 的写路径不看 `--act`**：`act_mode` 只管**引擎 effect 自己**的 `neo_mark`/`neo_score`
   （`src/dll/c2/neo_vtable.zig:389`），JS 的 `setVariable`/`setStarFlag` 不经过它
   （`src/dll/c2/neo_js_host.zig` 的 `writeSystemVariable`/`setSystemFlag`）。
   本发仍用 `--act write`（顺带产出 `neo_mark`/`neo_score`），但**不要**把 `--act log` 下的
   `NEO_JS_WRITE_REJECT` 当成 JS 写被拒的证据。
7. **SDK 的 `neo check` 对这三个 bundle 不适用**（不是失败，是工具形状不同）：`neo check` 要一个
   authoring project（`tsconfig.json` + `src/main.ts`，`sdk/src/build.ts:17`），且 `sdk/node_modules`
   未安装；我们的三份是手写 `neo/main.js`。替代复核 = `bundle_smoke.mjs`（无依赖，32 项全过，
   含 `neo check` 第 2 层的同五条 forbidden 模式）。
8. **`.ps1` 必须纯 ASCII**：这台机器把无 BOM 的 `.ps1` 按 cp936 读，一行中文注释会把**下一行**
   吞掉（实测：`LastWriteTime` 赋值静默不生效）。路径里有空格 ⇒ 主机上的脚本用 `-File` 跑，
   别用内联 `-Command`（`just win` → ssh → 远端 shell 三层引号会吃掉单引号）。
