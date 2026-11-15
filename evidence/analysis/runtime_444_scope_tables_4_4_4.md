# runtime_444_scope_tables_4_4_4 — pop / fleet / planet 三张表 + 五个 scope getter 的离线定形

**授权:零 shot。** 只读 exe 副本 + 仓内取证卷 + 存档文本;不注入、不起游戏、不碰 Windows 机、不用 IDA。
置信档沿用既有卷:`pinned(§N)` / `静态推断(未验证)` / `未定形`。

```text
exe  = /var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe
sha256(实测) = 9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56
size = 46,253,688 B
date = 2026-11-15
```

**本卷回答什么**:`runtime_444_transitability_4_4_4.md` §8.2 那张表里点到的 8 个候选——5 个
`scope cell → 对象` 的 getter(`0x394190` / `0x2b6470` / `0x393ec0` / `0x394870` / `0x393970`)
与 3 张表(`0x3260ff0` / `0x3261030` / `0x3261068`)——**各自是什么形状**:
getter 收 scope cell 的哪个字段、经哪张表、返回什么;表 = `全局槽 / 界 / 表指针 / 记录步长 /
对象指针偏移 / 对象内 id 偏移`,外加**读者数**。

**本卷不回答什么**:

1. **它们是哪个 scope 的语义名。** 「这张表是 pop 表」这句话本卷不写 —— 名字不是从符号来的
   (`§1.4`,§5「不能说的」第 1 条),本卷只有「哪条指令读哪个全局槽」。
2. **能不能当 API。** §8.2 作者卷的 §6.3 已经立过这条规矩:字段未 pinned 前不许写成契约。
   本卷把形状钉死,但**没有一次运行时读数**,所以连「形状在活体里成立」都还没证。
3. **`getPlanet(id)` / `getPop(id)` 能不能实现。** §4.3 给出还缺哪几格;缺的格本卷不填。

**输入**(全部只读):

| 输入 | 用途 |
|---|---|
| `stellaris.exe` 4.4.4(上面那份 sha256) | 唯一的指令来源 |
| `evidence/analysis/runtime_444_transitability_4_4_4.md` §8.2 | 候选清单的**唯一起点**,逐字引用不改写 |
| `runtime_444_graph_runtime.md` §1.2/§1.11 | 系统索引的形状先例与「步长 16 B」勘误 |
| `src/dll/shared/offsets.zig` 的 `country_table` / `graph` | 国家表与系统索引的形状先例(只读,不改) |
| 4.4.4 存档(`scripts/save_hypergraph.py`) | 只证伪(§4.1) |

**工具**(口径见 `docs/offline-tooling.md`,本卷不新增脚本):

```text
scripts/disrva.py       逐条指令(rip 相对操作数解析成 RVA);本卷全部读数的来源
scripts/global_xrefs.py 快通道:单全局反查 + 形态分类(读者数的来源)
scripts/find_refs.py    慢通道:call/jmp/rip 全域扫描(与快通道互为独立读者)
scripts/rttibatch.py    镜像 / .pdata / RTTI(本卷用它否掉「表对象有 RTTI 名」这一条路,§2.1)
```

**产物出处**(按 basename 记录,追加不改写):

```text
evidence/xrefs/scope_tables_4_4_4.tsv   8 条候选 + getter 自带的表:一行一个读数
evidence/analysis/runtime_444_scope_tables_4_4_4.md   本卷
```

**两套编号,全卷不许混**(计划 Review Focus 第 1 条):

- **A 套 = `offsets.zig` 的 `scope_types`**(`PLANET=2` / `COUNTRY=4` / `SHIP=8` / `POP=16` /
  `FLEET=32` / `GALACTIC_OBJECT=64` / `LEADER=128` / …)。该结构体的 docstring 自己写着
  `[UNVERIFIED 3.x] from stellarstellaris-win; not reconfirmed on 4.4.4`(`offsets.zig:601-603`)。
- **B 套 = §8.2 的 mask 位**:`is_owned_by` 从 `[scope+8]` 读到的那个值(`1` / `0x10` / `0x20` /
  `0x40` / `0x80` / … / `0x80000000`)。它是**4.4.4 的静态读数**,但每一 bit 的**语义名**未观测。
- 两套**数值上有重合**(`POP=16=0x10`、`FLEET=32=0x20`)、**也有一处明确冲突**(A 套 `0x80=LEADER`,
  而 B 套的 `0x80` 是系统 scope —— `country_scope_4_4_4.md` §6 的 A 级读数、`graph` 卷 §1.2 的
  解析器 `0x3939f0` 都以 `0x80` 为系统)。⇒ 本卷一律写「B 套 mask `0xNN`」,不写「pop 表」。

---

## §1 工单:8 条候选(2026-11-15,零 shot,结论:全部收到读数,详见 §2/§3)

来源:`runtime_444_transitability_4_4_4.md` §8.2 —— **逐字引用**(下表右列即该卷原文的「已知线索」列,
一个字没改)。数值取自 §8.2,本卷没有一处改过候选地址。

| 候选 | 类型 | 已知线索(§8.2 原文) |
|---|---|---|
| `0x394190` | getter | mask `0x10`:`[obj+0x18]` → 表 `0x3260ff0`(项 id `+0x10`)→ `[entry+0x3a8]` → 表 `0x3261068`(项 id `+0x10`)→ `[entry+0xf78]` → `0xd3b4d0` → vtable `+0x58` |
| `0x2b6470` | getter | mask `0x20`:`[obj+0x3a8]` → 表 `0x3261068` → `[entry+0xf78]` → `0xd3b4d0` → vtable `+0x58` |
| `0x393ec0` | getter | mask `0x40`:`[obj+0x434]` |
| `0x394870` | getter | mask `1`:`[obj+0x1b8]` |
| `0x393970` | getter | mask `0x80`(系统):接 `0x8bc870` |
| `0x3260ff0` | table | 项 id 在 `+0x10`(§8.2) |
| `0x3261030` | table | 项 id 在 `+0x8`(mask `0x2000000` 行) |
| `0x3261068` | table | 项 id 在 `+0x10`(mask `0x10`/`0x20` 两行都用到) |

### §1.1 工单口径

- **`候选`** 是 §8.2 里出现的**地址**:getter 是**函数入口**,table 是**全局槽**(`.data` 里存表对象
  绝对地址的那一格,BSS 未初始化 ⇒ 静态读不出值,只能读**谁读它、读出来怎么用**)。
- **`类型`** 只有两种:getter / table。§8.2 里其余地址(`0x8bc870` / `0x648b80` / `0xd3b4d0` …)是
  中继体,不在本工单内,但它们出现在链上时按「链上站点」记进 §2/§3,不单独立项。
- **档**:getter 用 `getter_named` / `getter_unresolved`;table 用 `table_named` / `single_reader` /
  `not_a_table` / `unresolved`(计划 Task 3 Step 2 的封闭词表)。

### §1.2 读数怎么落(TSV ↔ 卷)

`evidence/xrefs/scope_tables_4_4_4.tsv` 一行一个候选:`candidate / kind / reading / source`。
`reading` 是**一行摘要**(形状五元组 + 判词),`source` 是**能逐条复读的站点 RVA**(`disrva.py` 的入参)。
卷里每一节都给出**逐字输出块**;TSV 只放可 grep 的结论,不放指令。

### §1.3 复现(一条命令一条候选)

```bash
for r in 0x394190 0x2b6470 0x393ec0 0x394870 0x393970; do
  echo "===== $r"; python3 scripts/disrva.py "$r" --len=0x80
done
for g in 0x3260ff0 0x3261030 0x3261068; do
  echo "===== $g"; python3 scripts/global_xrefs.py "$g"
done
```

### §1.4 §1 不能说的

1. **「候选」不等于「锚点」。** §8.2 的读数本身是**静态推断**(那卷 §8.5 第 1 条:20 个第一跳函数的
   返回类型一个都没命名)。本卷只把**形状**从「一个地址」推进到「全局槽 + 界 + 步长 + id 偏移」,
   没有把任何一条升成 `pinned`。
2. **`§8.2` 的表列里有一处需要分叉读**(§2.1):mask `0x10` 那一行的 getter `0x394190` **自己**读的是
   全局槽 `0x3260ff8`,不是 `0x3260ff0`;`0x3260ff0` 是它**下一跳**才用的表。两格都在 `.data`
   相邻 8 字节处,漏读一格就会把两张表认成一张。
3. **本卷没有一次运行时读数**(零 shot 的代价):所有「全局槽里有值」都只是「`mov rax,[rip+…]`
   这条指令存在」,不是「那一格非空」。
