# `scripts/scratch/2026-11_flag_verify/` — flag keyspace 的实机实证(一次性)

**属于哪次取证**:2026-11-08 的 flag keyspace 修复(`site/reference/sdk.md` 的
「Flag ids」一节、`evidence/analysis/flag_store_4_4_4.md`),证明动作由
`docs/superpowers/plans/2026-11-10-flag-keyspace-live-verification.md` 的 Task 5 发起。
**不是维护中的工具**,不进顶层 `scripts/`(AGENTS.md 的 scratch 约定);
它**需要游戏进程**(装成 mod 才有意义),所以是探针不是工具。

## 这一发问什么

两条链是否落在**同一张 flag 名字表**上:

| # | 判据 | 生产者 | 消费者 |
|---|---|---|---|
| 1 | 官方写的 flag,我们的 native 读得见 | 官方脚本 `set_star_flag = neo_probe` | JS `__neo_system_has_flag(id, "neo_probe")` → `C:/temp/neo_js.log` |
| 2 | 我们写的 flag,官方读得见 | JS `__neo_system_set_flag(82, "neo_probe2")` | 官方 `has_star_flag = neo_probe2` → `game.log` |
| 3 | 两个名字互不串味(同一张表、不同 id) | 上面两行日志按 **token 完整值** 比对 | `scripts/c5_flag_verify.py` |
| 4 | 两个 flag 都进存档 | 引擎序列化 | 最新 `.sav` 的 `flags={}` 按键名查 |

判词工具:`scripts/c5_flag_verify.py`(维护中,`docs/offline-tooling.md` 有用法与
判读陷阱)。它吃三份产物、吐一行 `FLAG_VERIFY <tag> …`、退出码 0 当且仅当
`flags_end_to_end`。

## 两半

- **官方半边** `mod/neo_flag_probe/`:`on_monthly_pulse` → `neo_flag.100`,事件体四步
  (写 `neo_probe` → 官方自己读回 → `neo_action = { }` 把系统 scope 交给 runtime →
  官方读 `neo_probe2`)。顺序就是判据;两个 `every_system` 必须包在
  `random_system` 里(无 scope 事件里裸 `every_system` 只跑一次,§89.2)。
- **runtime 半边** `mod/neo_flag_probe/neo/`:`mod.json` + 手写 `main.js`
  (**不经 SDK 构建**,零 npm)。回调里若 `neo_probe` 为真就记一行(只记真,否则
  788 行/月);`id === 82` 时写 `neo_probe2` 再读回并记录。

## 产物(判词的三份输入)

| 产物 | 位置 | 谁写的 |
|---|---|---|
| `game.log` | 游戏安装目录 `logs/game.log` | 官方半边(两个固定词 `NEO_FLAG_OFFICIAL name=<n>`) |
| `neo_js.log` | `C:/temp/neo_js.log` | runtime 半边(`NEO_FLAG_READ name=<n> present=<t/f> id=<n>`) |
| 最新 `autosave_*.sav` | `save games/` | 引擎(`flags={ <名字>=<时间戳> }`) |

**`--offset` 要用**:flag 持久化、事件每月重跑,计数会累加;窗口开始前记下
`game.log` 的字节偏移,判词只读偏移之后那一段。

## 上线前的手工门

- `python3 scripts/c1_preflight.py neo_probe` 与 `… neo_probe2` 都必须退出 `0`
  (两个 flag 名不是官方 keyword;`c1_preflight` 查的是 keyword 名,名字碰撞门在
  `neo build`,本探针不经构建,所以这两个名字**上线前手工 grep 一次**
  `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`)。
- `grep -n "effect\s*=" mod/neo_flag_probe/common/on_actions/*.txt` 必须无输出
  (4.4.4 的 on_action 只收 `events` / `random_events`)。

## 用完要删

窗口结束:两侧探针都删(`C:/temp/neo_flag_probe/` 与 `dlc_load.json` 的条目先备份
再还原),`taskkill /F` 关游戏(零 `FreeLibrary`,与既有所有 shot 同口径)。留在仓库
里的只有 `evidence/logs/flag_store_verify_4_4_4.log` — **产物是证据,探针不是**。
