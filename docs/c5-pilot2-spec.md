# docs/c5-pilot2-spec.md — C5 试点二 spec(全局图度量,待 5 项裁定)

本文是 C5 的 spec:**零 shot**产物(无 launch/inject/install/Frida/process,只读 TSV 与本地解包游戏数据)。
它的任务是把 5 项待裁定决策写成**可裁定**的形态,并修正 roadmap 段1 例子句在判据上的失实之处(§0)。
它**不是**实现计划:算法本体与字段读取都不在本文(见 §4)。

数据来源:`evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`(生产者 `scripts/thunkarrays.py`,
列 `keyword` = 第 6 列、`token_id` 第 5、`db_global_rva` 第 4、`field0_rva` 第 7 即 class_info、
`doc_first_line` 第 10);本地解包数据 `/var/lofibass_ssd/data/stellaris/4.4.4/{common,events}`;
取证三卷与 `docs/offline-tooling.md`。§0/§1 的每条读数都是本文撰写会话(2026-10-26)实跑并**原样粘贴**的,
数字不改述。状态标签三档:`pinned(§N)` / `静态推断(未验证)` / `未观测`;`未观测` 的行不得出现确认措辞。

## §0 判据修订:段1 的「交通要道」例子失去差异化判据资格

roadmap 段1 的例子句(原文不动,它是用户的原始意图):「比如判定哪个星系是交通要道,通过 QuickJS 根据这个来
给各个星系加上新的 effect」。作为「现有 DSL 表达不出」的判据,这个例子**不成立** —— 游戏自带该判定。
两条事实,本会话实跑:

**事实一:官方自带「要道」判定。**

```
$ awk -F'\t' 'NR>1 && $6 ~ /bottleneck|closest_system|is_neighbor_of|can_access_system/ {print $6" | token="$5" | db="$4" | class_info="$7" | "$10}' \
  evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv
closest_system | token=10288 | db=0x33746e8 | class_info=0x260e9f0 | Executes enclosed effects on a system -within a specific number of jumps span- that meets the limit criteria. This completely ignores bypasses (wormholes and gateways)
is_neighbor_of | token=18292 | db=0x32611c8 | class_info=0x269efe8 | Checks if the scoped object is neighbors with target country
can_access_system | token=18214 | db=0x32611c8 | class_info=0x269e778 | Checks if the scoped fleet is able to enter the system. Note: Avoid overusing this, it is a performance-intensive trigger!
is_bottleneck_system | token=18202 | db=0x32611c8 | class_info=0x269e828 | Checks if the system is bottleneck within the range NDefines::NGameplay::SYSTEM_BOTTLENECK_RADIUS
closest_system | token=10288 | db=0x32611c8 | class_info=0x269e428 | Finds the closest system within the given hyperlane steps and limit = { <triggers> }. If this system does not exist, it returns false. If it does exist, it is checked against the triggers outside of t

$ grep -n "SYSTEM_BOTTLENECK_RADIUS" /var/lofibass_ssd/data/stellaris/4.4.4/common/defines/00_defines.txt
730:		SYSTEM_BOTTLENECK_RADIUS = 2				# System will be considered bottleneck if within N systems there are no intersections between all of the directions
```

读数:`is_bottleneck_system` 是**官方 trigger** —— token `18202`,class_info `0x269E828`,注册在 trigger db
`0x32611C8`。doc 原文把「要道」定义为**半径内**判定,半径 = `NDefines::NGameplay::SYSTEM_BOTTLENECK_RADIUS` =
**2**(`common/defines/00_defines.txt:730`),define 注释自己给出算法:「within N systems there are no
intersections between all of the directions」。原版脚本已在用它:本地 `common/` 下 12 个文件共 49 处引用
(本会话 `grep -rl` / `grep -rn` 计数),被点名的三处 `common/megastructures/19_deep_space_citadel.txt:112`、
`common/decisions/14_infernal_decisions.txt:236`、`common/scripted_effects/00_scripted_effects.txt:4324` 都在其中。

同族读法三条(都不给全局量):`closest_system`(token 10288,effect/trigger 双注册)只在 **N 个 hyperlane
跳数限**内搜索,effect 侧 doc 明写「completely ignores bypasses (wormholes and gateways)」;
`is_neighbor_of`(18292)的邻接是**国家 scope** 的,不是星系的;`can_access_system`(18214)的 doc 自己警告
性能敏感。

⇒ **修正后的差异口径**(C5 的「新」只能落在这里,不能再写「识别要道」):
① **全局图度量** —— 半径 2 之外的整体结构(割点集、betweenness、跨区流量);官方的 bottleneck 是
半径内局部拓扑测试,`closest_system` 类搜索止步于 ≤N 跳;
② **自定义权重** —— 官方判定没有可写的边权/节点权;
③ **跨 scope 聚合** —— 见 §1 表:现有全局量只有简单计数;
④ **运行时可写** —— 判定结果作为脚本层可查询、可随战局更新的状态。
roadmap 段1 原文不改;修正说法住本节,`AGENTS.md` 文档地图带一条注明。

限定一条,C5 自己的工具不算反例:离线存档分析链(`scripts/save_hypergraph.py` →
`scripts/chokepoint_scores.py` → `scripts/chokepoints_emit.py` → `src/dll/c2/chokepoint_table.zig`)
已经**在 DLL 之外**算过 degree / Brandes betweenness / 割点 / 桥 —— 那是构建期烘焙的静态分数表
(存档局部 id,`docs/offline-tooling.md` 离线存档分析判读陷阱 10),不是引擎内、不是 DSL 可表达、
也不是运行时可更新的能力。它证明图度量**可算**,不证明现有 DSL **可表达**。

## §1 现有 DSL 表达力清单(邻接/路径/距离/邻国/星系类,41 条)

覆盖面命令与逐字输出(本会话;行数即 41,全表唯一关键词 1,634,同场实测):

```
$ awk -F'\t' 'NR>1 && tolower($6) ~ /adjacent|bypass|path|distance|neighbor|system/ {print $6}' \
  evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv | sort -u
add_seen_bypass
add_seen_bypass_type
bypass_event
can_access_system
closest_system
compare_distance
controlled_systems
cosmic_storm_system_influence
count_end_cycle_systems
count_ship_size_in_system
count_systems_with_aura
create_bypass
distance
distance_to_capital
distance_to_core_percent
distance_to_empire
every_system_in_cluster
governors_skill_in_system
has_seen_any_bypass
has_seen_specific_bypass
is_bottleneck_system
is_bypass_type
is_capital_system
is_neighbor_of
is_rim_system
is_system_connected_to_relay_network
is_system_locked
lock_bypass
move_system
num_claims_on_system
num_galaxy_systems
num_neighbor_systems
num_planets_in_system
owns_any_bypass
renew_bypass_lock
set_spawn_system_batch
set_system_locked
spawn_system
starting_system
system_event
total_system_workforce_with_job_tag

$ awk -F'\t' 'NR>1 && tolower($6) ~ /adjacent|bypass|path|distance|neighbor|system/ {print $6}' evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv | sort -u | wc -l
41
$ awk -F'\t' 'NR>1 {print $6}' evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv | sort -u | wc -l
1634
```

逐条清单(`db` 列 `0x33746e8` = ScriptedEffectDB、`0x32611c8` = ScriptedTriggerDB,§21;`closest_system`
双 db,两行都列,关键词计数仍 41)。「局部/全局」列是每行的标注 —— 这张表是「新能力必须表达不出于现有 DSL」
的唯一离线证人:

| keyword | token | db | doc_first_line | 局部/全局 |
|---|---|---|---|---|
| add_seen_bypass | 10452 | 0x33746e8 | Makes the scoped country remember that it has encountered the bypass | 状态记忆(单个遭遇),非量 |
| add_seen_bypass_type | 10451 | 0x33746e8 | Makes the scoped country remember that it has encountered the bypass type | 状态记忆(单个类型),非量 |
| bypass_event | 16876 | 0x33746e8 | Fires a bypass event for the scoped bypass, with optional DAYS and RANDOM delay | 动作(触发事件),非查询 |
| can_access_system | 18214 | 0x32611c8 | Checks if the scoped fleet is able to enter the system. Note: Avoid overusing this, it is a performance-intensive trigger! | 局部关系(单 fleet × 单 system) |
| closest_system | 10288 | 0x32611c8 | Finds the closest system within the given hyperlane steps and limit = { <triggers> }. If this system does not exist, it returns false. If it does exist, it is checked against the triggers outside of t | 局部关系(半径 N 跳内最近) |
| closest_system | 10288 | 0x33746e8 | Executes enclosed effects on a system -within a specific number of jumps span- that meets the limit criteria. This completely ignores bypasses (wormholes and gateways) | 局部关系(半径跳数内) |
| compare_distance | 18264 | 0x32611c8 | Checks whether the current scope is closer to a specified object than it is to a second specified object within the same solar system. | 局部关系(两距离比较) |
| controlled_systems | 18536 | 0x32611c8 | Checks the country's or sector's number of owned systems | 全局量(计数:归属聚合,非图) |
| cosmic_storm_system_influence | 18705 | 0x32611c8 | Checks the systems total cosmic storm influence | 局部量(单 system 求和) |
| count_end_cycle_systems | 18787 | 0x32611c8 | Checks the amount of needed systems with the End Cycle psionic aura | 全局量(计数) |
| count_ship_size_in_system | 18796 | 0x32611c8 | Checks the sum of the ship_size's size_multiplier of every ship present in the scoped system. | 局部量(系内聚合) |
| count_systems_with_aura | 18788 | 0x32611c8 | Checks the amount of systems covered by the country's aura | 全局量(计数) |
| create_bypass | 10429 | 0x33746e8 | Creates a bypass in the parent SpatialObject (stored in FromFrom), of the type passed in "type". | 动作(构造),非查询 |
| distance | 11793 | 0x32611c8 | Checks the scoped object's galaxy map distance to target in absolute units | 局部关系(galaxy map 距离,两点) |
| distance_to_capital | 18402 | 0x32611c8 | Checks the distance of a controlled system to its owner's capital | 局部关系(单 system → 首都) |
| distance_to_core_percent | 18401 | 0x32611c8 | Checks the ship/fleet/planet/leader/pop/system's distance to the galactic core in percent, where center = 0 and galactic rim = 100 | 局部关系(相对银心的坐标量) |
| distance_to_empire | 18320 | 0x32611c8 | Checks the ship/fleet/planet/system's galaxy map distance to target empire | 局部关系(到目标帝国的距离) |
| every_system_in_cluster | 12796 | 0x33746e8 | Executes enclosed effects on every system in the cluster that meet the limit criteria | scope 遍历(cluster 是生成期分组,不是星连边) |
| governors_skill_in_system | 18755 | 0x32611c8 | Checks if valid colony governors in the scoped has a specific base experience level | 局部关系(系内) |
| has_seen_any_bypass | 18498 | 0x32611c8 | Checks the scoped country has ever encountered a bypass of a given type before | 状态查询(遭遇集合) |
| has_seen_specific_bypass | 18499 | 0x32611c8 | Checks the scoped country has encountered a specific bypass before | 状态查询(单个) |
| is_bottleneck_system | 18202 | 0x32611c8 | Checks if the system is bottleneck within the range NDefines::NGameplay::SYSTEM_BOTTLENECK_RADIUS | 局部关系(半径 2 内拓扑测试,§0) |
| is_bypass_type | 18696 | 0x32611c8 | Returns true if the scope bypass is of type <type> | 局部关系(单对象类型) |
| is_capital_system | 18058 | 0x32611c8 | Checks if the solar system has its owner's capital | 局部关系(单 system 归属) |
| is_neighbor_of | 18292 | 0x32611c8 | Checks if the scoped object is neighbors with target country | 局部关系(**国家**邻接,非星系) |
| is_rim_system | 18203 | 0x32611c8 | Checks if the system is on the galactic rim | 局部关系(边缘位置) |
| is_system_connected_to_relay_network | 18527 | 0x32611c8 | Checks if target system is connected to own capitals through hyper relay network | 全局关系(连通布尔,仅 relay 网络) |
| is_system_locked | 18797 | 0x32611c8 | Checks if the scoped fleet/carrier is locked in its current system. | 状态查询(锁定态) |
| lock_bypass | 10629 | 0x33746e8 | Lock a Bypass for exclusive access for a given country. | 动作,非查询 |
| move_system | 15112 | 0x33746e8 | Moves scoped system to a position relative to the given system/planet/ship. | 动作(位移),非查询 |
| num_claims_on_system | 18814 | 0x32611c8 | Counts the number of claims the scoped empire has on the target system | 局部量(目标 system 上的计数) |
| num_galaxy_systems | 18635 | 0x32611c8 | Checks number of star systems in the galaxy | 全局量(银河总数,计数) |
| num_neighbor_systems | 18756 | 0x32611c8 | Checks the number of neighbor systems within a specific distance | 局部关系(特定距离内邻居计数) |
| num_planets_in_system | 18634 | 0x32611c8 | Checks the solar system's total number of planets | 局部量(系内计数) |
| owns_any_bypass | 18500 | 0x32611c8 | Checks if the scoped country controls any system containing a bypass of a specific type | 归属查询(any,非量) |
| renew_bypass_lock | 10628 | 0x33746e8 | Renew a Bypass Lock's duration as if it was just built. | 动作,非查询 |
| set_spawn_system_batch | 10157 | 0x33746e8 | Optimizes the calls for spawn_system effect. Spawn system should be located in a block between Begin and End. | 动作(构造批控),非查询 |
| set_system_locked | 10765 | 0x33746e8 | Sets the system lock status for the scoped colony or carrier and cancels any current encampment or packup process | 动作,非查询 |
| spawn_system | 10158 | 0x33746e8 | Spawns a new system at a position relative to the scoped object. | 动作(构造),非查询 |
| starting_system | 12426 | 0x32611c8 | Checks if the system is the starting system for any country | 局部关系(开局归属) |
| system_event | 16052 | 0x33746e8 | Fires a system event for the scoped system | 动作(触发事件),非查询 |
| total_system_workforce_with_job_tag | 18772 | 0x32611c8 | Checks how much workforce that has jobs with all given tags in a system. An optional limit (colony scope) filters which colonies contribute. | 局部量(系内聚合) |

**表内分布**(只统计上表的标注列,41 个唯一关键词):动作/构造 9,状态记忆/查询 5,归属查询 1,scope 遍历 1,
局部关系/局部量 20,**全局量(计数)仅 4**(`controlled_systems`、`count_end_cycle_systems`、
`count_systems_with_aura`、`num_galaxy_systems`),**全局关系(连通布尔)仅 1**
(`is_system_connected_to_relay_network`,且只经 hyper relay 网络)。**没有任何一条是图度量**:
没有割点集、没有 betweenness/流量、没有可写边权;唯一按跳数走的搜索 `closest_system` 止步 ≤N 跳。
这张表支撑的论断口径是:§0 修正后的四项(全局图度量 / 自定义权重 / 跨 scope 聚合 / 运行时可写)
表达不出于现有 DSL;**「识别要道」不在其中**。

## §2 需要的引擎数据与字段(每条带状态标签)

三档标签:`pinned(§N)` = 取证卷已钉;`静态推断(未验证)` = 静态材料给出的候选机制,没有运行时读数;
`未观测` = 从未被任何读数触及。出处 § 指取证卷(`runtime_444_structures.md` §1–§15、
`runtime_444_keyword_pipeline.md` §16–§23、`runtime_444_c1_validation.md` §24–§66)。

| 需要的数据/字段 | C5 里干什么 | 当前状态 |
|---|---|---|
| effect 对象 `[obj+0x20]` = token id、`[obj+0x28]` = name | 消费者 `create` 后引擎写入的良构字段(effect 侧) | `pinned(§23)` |
| trigger 对象 `[obj+0x38]` = token id、`[obj+0x40]` = name | 同上(trigger 侧) | `pinned(§23)` |
| 注册管线:mint `0x1D13270` → value `new(0x10)` → BST insert(`0x3AEF60` / `0x348150`)→ class_info ALIAS | 新 keyword 进入引擎的四步(`AGENTS.md` 配方) | `pinned(§18 §20 §21 §24)` |
| donor effect vtable `0x2606FE0` 25 槽可复制(slot[1]=Execute、slot[2]=instantiate、slot[19]=谓词) | 实现侧对象形状与谓词槽 | `pinned(§52)` |
| donor-shaped 对象的执行是否落进 slot[1] 共用覆写 `0x3AFD30` | 决定实例化/执行路线走哪一族;读数归 §5 的探针 | `静态推断(未验证)` —— §57.4 把 (a) 支变成有具体机制的候选,三岔未判掉 |
| 星系对象句柄从哪来(我们的求值体内如何拿到被度量的对象) | 图度量的对象来源,一切读取的前提 | `未观测` —— scope 一问未收口:§59 四根跟完 = `no_scope_candidate`,候选只剩 self/helper |
| hyperlane 星连边集(运行时形态的星系图) | 任何图度量的输入 | `未观测` —— 静态 galaxy map 文件不在本地(§5);存档侧离线抽取过等价边表,但那是构建期数据且 id 为存档局部 |
| 帝国可见性/归属的运行时字段 | 若裁定②选「帝国可见」口径 | `未观测` |
| `SYSTEM_BOTTLENECK_RADIUS` 在引擎内的读取形态(全局缓存还是逐调用读) | 对齐官方半径口径,避免双标 | `静态推断(未验证)` —— trigger docstring 引 NDefines 符号(§0 的 doc 原文);引擎内部读点没碰过 |
| 运行时星连图的版本/变更信号(缓存失效用) | 裁定④的缓存键;没有它就只能在每次求值时全量重算 | `未观测` —— 裁定④带出来的新条目 |
| 求值体中「当前 scope 是哪个星系」→ 图上节点的映射 | 一切查表的前提 | `未观测` —— 收口计划打的就是这一问 |

### §2.1 不要再试(已证伪清单,只列与 C5 数据面直接相关的)

| 曾经的思路 | 实况 | 出处 |
|---|---|---|
| `X=[arg2+0x30]→S→id/obj` 拿 effect token/object | 已证伪:arg2 类大小 0x20,`+0x30` 在对象外;X 是 `.rdata` vtable、S 是代码。§53.5 原话「不要再把它当前提」 | §53.3 §53.5 |
| 3.x `CEventScope` 偏移 `+8`/`+16` | 被 §26 证伪;`src/dll/api/scope.zig` 仍读它们但被 `LAYOUT_CONFIRMED = false` 钉住,逐条读点处置见 `docs/scope-read-points.md` | §26 §53 |
| detour `0x5350D0` 当执行器 | 按 token id 的虚属性 getter,0 个直接调用点,detour 价值 = 0(`AGENTS.md` 约束 7) | §26.1 §28.5 |
| `0x89F960`/`0x8A0450` 当 getter 取已注册对象 | 不是 getter;唯一副作用是重复定义告警(走 `0x1C91C30` logger) | §27 |
| 等 lexer/parser 给 mod 新词铸 token | false;新词不会有 id,必须自己调 `0x1D13270`(且先过 `scripts/c1_preflight.py`,约束 4) | §19 |

## §3 已裁定决策(5 项,2026-10-28)

每项:选项、默认、以及「选了它后面哪一步变」。**裁定归人;本文只记录裁定,不代裁。** 五项结论在表末(2026-10-28)。

**① 度量定义。** 选项:(a) betweenness(Brandes,无向无权);(b) 割点/桥(Tarjan);
(c) 出入度差;(d) 自定义权重组合。默认:(a)。
选了它后面哪一步变:默认 (a) 时,离线侧口径直接沿用 C4 已建的七列分数表(`scripts/chokepoint_scores.py`
的输出契约),实现步只需把同一算法的形状搬进运行时;(b) 则分数表退化为布尔列;(c)/(d) 要新增边权来源,
裁定②必须同时选带归属的口径,权重字段还得新观测。

**② 作用范围。** 选项:(a) 全银河;(b) 帝国可见子图;(c) 半径 N 邻域。默认:(a)。
选了它后面哪一步变:(a) 不需要可见性字段,§2 表里那条 `未观测` 不阻塞;(b) 实现计划多一条运行时读点
(§2 帝国可见性字段),且第一前置加一次点名;(c) 与官方半径 2 同族,直接放弃 §0 差异口径的「全局」项,
C5 判据要重议 —— 等于把本 spec 作废。

**③ 输出形态。** 选项:(a) 新 trigger 供原版条件位使用;(b) 新 effect 写 modifier;(c) 一对(trigger 查询 + effect 写入)。
默认:(a)。
选了它后面哪一步变:(a) 落 trigger db `0x32611C8`,消费方先 `create` 再 `call [vptr+0x80]`(§23),
对象形状按 §2 已钉字段走,验收不依赖任何 UI;选 (b) 或 (c) 必须先回答「计算结果谁持有、写到哪」——
§2 没有任何运行时可写位置的观测,这一步在 (a) 之后才谈得上。

**④ 触发时机。** 选项:(a) 每 tick 重算;(b) 开局一次;(c) 手动(scripted 路径显式调用时算)。默认:(c)。
选了它后面哪一步变:(a) 把计算压进热路径,实施前必须先按 §10 的口径测调用频率再定采样/预算
(不照搬 base Execute 的 1/512);(b) 需要一个已确立的开局钩子,当前没有任何钩子被钉过;
(c) 计算由脚本显式驱动,时机问题转化为「附带一个刷新用的 effect」,与裁定③的 (a) 可以解耦。

**⑤ 验收观测点。** 选项:(a) 日志(我方记录器/引擎日志);(b) 银河地图可见(modifier/标记);
(c) 原版 tooltip 变化。默认:(a),之后升级 (b)。
选了它后面哪一步变:(a) 只吃 C2 已趟活的诊断写出路径,零 UI 依赖;选 (b) 要求存在可显示的写入对象,
被裁定③里「写」的那一支阻塞;选 (c) 要求谓词槽与 docstring 走通原版渲染(§52 的 slot[19]、§24.6 的
docstring 策略),同样被裁定③的 trigger 口径牵动。

### §3.1 裁定结论(2026-10-28)

| # | 裁定 | 连带后果 |
|---|---|---|
| ① | **两列**:Brandes betweenness(无向无权,归一化)+ Tarjan 割点/桥 | 出货表从 1 列 u16 扩到多列;C4 的 `TIER1_MIN`/`TIER2_MIN` 阈值语义随之重定义。排除 (c) 出入度差 —— `num_neighbor_systems` 已在 DSL 内(§1),撞「必须表达不出于现有 DSL」;(d) 自定义权重 v1 不做,边权来源无观测(`未观测`)。 |
| ② | **全银河** | (a) 不需要可见性字段,§2 那条 `未观测` 不阻塞;(b) 帝国可见子图要「帝国可见性/归属运行时字段」= `未观测`;(c) 半径 N 排除 —— spec §0 的「全局」项会失去,等于作废本 spec。帝国尺度的聚合交给「跨 scope 聚合」那层,不靠缩小度量域。 |
| ③ | **新 trigger**,落 trigger db `0x32611C8` | 消费方 `0x349AE0` → `create` → `call [vptr+0x80]`;class_info ALIAS 官方 trigger(约束 5),docstring 用 donor 自带 `.rdata` 串;不改官方 `is_bottleneck_system`。 |
| ④ | **脚本显式调用时算 + 按图版本缓存** | 禁止每 tick 重算。**连带新增一条未观测项**:「运行时星连图的版本/变更信号」(见 §2 表末)。 |
| ⑤ | **日志** | (a) 只吃 C2 已趟活的诊断写出路径,零 UI 依赖;(b) 需要可显示的可写对象,被 ③ 的 (b)/(c) 支阻塞;(c) 原版 tooltip 不作语义验收 —— 约束 5 规定 docstring 用 donor 的串,UI 上显示的是 donor 文案。 |

## §4 明确不做

- **不改官方 `is_bottleneck_system` 及其同族关键词的语义。** C5 加新词,官方判定原样;class_info 只 ALIAS、
  不伪造(`AGENTS.md` 约束 5)。
- **不 patch 静态表。** 不动 `0x337B400` 描述符数组与名字池;走运行时 mint + BST insert 全链(`AGENTS.md`
  配方,Phase A 结论)。
- **不在本 spec 里承诺实机成本。** shot 预算与点名归各在飞计划的 Global Constraints(roadmap 段2 的口径);
  本文档零 shot。
- **不含算法本体与实现步骤。** 5 项裁定未定、星系句柄来源未观测、星连边运行时形态未观测、galaxy map
  文件未拷 —— 实施计划等这四件事收齐再写。
- **不新增 QuickJS `extern fn` 绑定。** 段5 决策未变,`src/dll/exports.zig:351-353` 的禁令未放宽(§65
  判 `abi_closed_static` 也只排除了一半,放宽要人点头)。
- **v1 只做图度量那一半。** 「种族占比 → 资源产出 / 对母国的外交与战争态度」不在 v1 内:它需要
  帝国 × 种族 × 系统的字段与读点,而本 spec 全文没有这些行(§0–§5 全是图度量)。roadmap 段4 的 C5 行已同步标注。

## §5 前置与依赖

1. **donor 探针先给出「执行到底进不进这一族」。** `scripts/c2_donor_probe.py`(DLL 侧
   `C4DonorProbe{Install,SetMask,Uninstall,Verify,Layout,StatsInto,DrainInto,Reset}`)已建好、已过门,
   **从未运行**(本任务零 shot)。它的 verdict 值域是**五档**,不是四档:
   `donor_family_hit_named`、`donor_family_hit_unknown_table`(只有这两档 EVIDENCE_VERDICTS 回答关于引擎代码
   的问题)、`no_calls_inconclusive`、`instrument_broken`、`counter_desync`(后三档是环境/仪器读数)。
   禁令照旧:它给出的任何读数都**不许读成「不经这一族」** —— §57.4 第三档要「哨兵 body 等齐(执行确实发生)
   而 `calls==0`」,其前半句是独立证据,运行中的战役永远供不上。用法与门序:
   `docs/offline-tooling.md` C4 donor 一节;离线围栏 `scripts/test_c2_donor_probe.py`(14 条)。
   C5 从它拿的是 §2「执行落点」那行 `静态推断(未验证)` 的第一手读数。
2. **scope 一问仍未收口,但下一靶已定形(2026-10-28)。** §59 `no_scope_candidate` 原样保持;
   §63 `dispatchers_partial` 与 §66 `two_stage_dispatchers_partial` 两个判决词不同义、不合并。
   **新增(§76,点名 ×1)**:trigger 的谓词槽 `+0x80`(`0x349230`)在 `every_system` 的 787 次 limit 求值里
   只被调 **11** 次、第 2 实参恒为 `0x80` ⇒ 它是**实例化期**的掩码检查,不是每次求值,也不交对象。
   下一靶 = 求值槽 `+0x28` 的共用基体 **`0x1A91A80`**(352 张表共用,收 `(self, ctx, a3)`,算 `ctx+0x278`);
   §2 里那三条 `未观测` 都挂在这条线上,而这一发的读数把它们**从「谓词」挪到了「求值槽」**。
3. **galaxy map 拷贝 —— 已落地(2026-10-28,文件拷贝,不是 shot)。** 走存档侧
   (`scripts/save_hypergraph.py` → `scripts/chokepoint_scores.py`):当前战役
   `_1474567734/autosave_2231.07.01.sav`(sha `32413c3e…`)重建出的边表
   **N = 787 系统 / 1,217 条无向边 / 连通**;分数表与烘焙进 `chokepoint_table.zig` 的那一份**逐字节相同**
   (除 CRLF)⇒ 这张图在本战役里稳定。产物:`evidence/xrefs/c5_campaign_edges_4_4_4.tsv` +
   `evidence/logs/c5_save_graph_4_4_4.log`。**仍未解决**:存档 id 是**存档局部**的,运行时 join 未观测。
4. **本 spec §3 的 5 项裁定 —— 已下(2026-10-28)。** 结论见 §3.1(两列度量 / 全银河 / 新 trigger /
   手动 + 按图版本缓存 / 日志验收)。
5. **新 keyword 命名门禁。** 任何候选词名在进 `0x1D13270` 之前先过 `scripts/c1_preflight.py` 且退出码 0
   (约束 4:token 查找大小写不敏感,撞名即接管官方词)。
6. 指针:roadmap 段3 C4 行、段4 C5 条与 scope 条;本计划(Task 1–7)的 hand-off 表在
   `.superpowers/sdd/2026-10-28-c5-data-plane-scope-and-graph/progress.md`(私有目录,不进 git)。

**§5 的当前账(2026-10-31 更新):四道门里 1(donor 读数)、3(galaxy map)、4(裁定)已落或已引用,
只剩 2(星系句柄来源)未收口。** 那一格现在的证据指针是 **`runtime_444_c1_validation.md` §80(逐系统循环体
`0x1A762A0..0x1A76335`)、§81.1(靶位闸)、§82.1/§82.2(靶的层 = `execute`,有条件)、§82.2.2(一次完整
读档 `0x3B1330 calls=0`)** —— 靶仍是 `0x3B1330`(`every_system` 的 `+0x70`,按 `[self]==0x26562D0`
过滤),判据 = 容器原始条数 788 且每轮下发次数 = 去重 id 数、id ⊆ 容器集 ⊆ `[1,788]`;卡住的不再是
「靶在哪」,而是**驱动**:要让 `every_system` 作为父 effect 的子效果被分发(测试 mod 的
`on_monthly_pulse`,或 issue #32 修好后的控制台投递)。原句「靶位 `0x1A91A80`」已由 §79 判负(求值槽
不是每系统一次),不再指向它。
