# `examples/chokepoint` 的 mod 外壳

这是把 `examples/chokepoint`(TS → QuickJS bundle)挂进引擎的**外层壳**,按 2026-11-13
C6-4 那一发的形状收进仓库:同一个事件 id、`random_system → every_system`、每系统先
`neo_action = { }` 再用官方 DSL 分支。两处**只影响界面/触发方式**的标准字段是新加的
(`hide_window = yes`、`is_triggered_only = yes`;那一发是显式点掉弹窗走过去的),flag 名是**占位**。

证据与判读陷阱在 `evidence/logs/c6_r8_score_join_4_4_4.log`(存档逐 id 对账)与
`evidence/logs/c5_chokepoint_mod_join_4_4_4.log`(示例原样跑在引擎里)。

## 三部分

| 文件 | 作用 |
|---|---|
| `descriptor.mod` | 描述符。`path="mod/neo_chokepoint"` 必须与目录名一致 —— 这是唯一被围栏钉住的字段 |
| `common/on_actions/neo_chokepoint_on_actions.txt` | `on_monthly_pulse` → 触发 `neo_chokepoint.1` |
| `events/neo_chokepoint_events.txt` | `random_system → every_system` 里先跑 `neo_action = { }`(我们的 effect),再在同一 scope 用官方 `check_variable` 分支、落两个 star flag |

## 安装

1. 把本目录**整个**拷成游戏的 `<user data>/mod/neo_chokepoint/`(descriptor 与
   `common/`、`events/` 同级)。
2. 启动器读的是外置描述符,所以同一份内容再放一份到 `<user data>/mod/neo_chokepoint.mod`。
   2026-11-13 那一发就是这两个文件并存的结构。
3. **`neo/` 不在这个仓库里,也不在 mod 目录里。** runtime 部分(`mod.json` + `main.js`,
   由 `examples/chokepoint` 构建)由 DLL 从 **`C:/temp/neo_mods/<id>/`** 读;`mod.json`
   的 `id` 就是那个 `<id>`(示例用 `chokepoint`)。mod 目录只提供触发时机,不提供 JS。
4. DLL 侧还要按判据选装法:`--act write`(不写就是只记)与 `--score-source 1`(活体重算;
   默认 `0` = 烘焙表)。两个开关的含义见 `docs/offline-tooling.md`。

## flag 名是一次性的

`neo_hub_t1` / `neo_hub_t2` 是**占位**。flag 会随存档持久化,所以「存档里出现了这个 flag」
只有在**这个战役从来没出现过该名字**时才等价于「这一发写的」。

换名规则:每一发开始前挑两个本战役从未用过的名字(查窗口前的几份存档,或干脆换前缀,
如 `neo_c64_t1/t2`、`neo_r9_t1/t2`),同时改本文件里的两处 `set_star_flag` 与读数命令的
`--tier1-flag/--tier2-flag`。用旧名字读到的集合是上一轮的残留 —— 2026-11-13 第一次用
`neo_tier1/2` 判,读到的 15/55 全是更早窗口留下的。

## 顺序依赖(别把 `betweenness` 当便宜的本地查询)

- `neo_action = { }` 先跑:我们的 effect 用官方 body 写 `neo_score`;同一 `immediate` 里
  随后的 `check_variable` 读到的就是它。**反过来不成立**。
- JS 的 `graph.betweenness(s)` 读的是**图**,不是 `neo_score` 变量。`--score-source 1` 下它是
  **每次求值的活体重算**,不是查表;`--score-source 0` 下它是 2226 战役那张烘焙表。
  同一个 id 在两种装法下会读到不同的数(例如 236 vs 234),见
  `evidence/logs/js_graph_source_4_4_4.log`。
- 所以「每系统每月一次」的量级预算要按**重算**算,不是按查表算。

## 围栏

`scripts/test_examples_chokepoint.py` 只钉两件事:描述符的 `path=` 与目录同名、事件文件
引用 `neo_action` 且落两个 flag。它**不**钉注释、不钉 flag 的具体名字 —— 那些每发都要换。
