# 全局 `onMonthly` 的入口在哪:从 `on_monthly_pulse` 顺到执行侧(4.4.4,离线,零 shot)

**这一卷回答什么。** 我们的 JS 现在**借**脚本才被每月叫一次
(`examples/chokepoint/mod/common/on_actions/neo_chokepoint_on_actions.txt` 的
`on_monthly_pulse = { events = { neo_chokepoint.1 } }`)。计划问的是:**不用这层脚本 stub,
引擎自己有没有一个「每月」的边界,能在那儿拿到一次调用?** 本卷只答这一格:先从字符串
`on_monthly_pulse` 顺到引擎读它的地方,再从引擎自己的**月度边界**(`0x265DD0`)往下读到
on_action 执行侧(`0x406F90` → `0x402C50`),最后把计划台账里的五个候选逐个读体否掉。
§4 给判决,§5 写这一卷不能说的。

**生产者。** `scripts/scratch/2026-11_onmonthly/onaction_field_readers.py`(只读 exe 拷贝,
`NS_STELLARIS_EXE` 优先)。它一次打完本卷四条可机械复核的读数:名字串的引用点、14 行
名字→字段映射、DB 固定字段的读者表、五个候选的间接调用槽/直调锚点。逐字节反汇编另用
`scripts/disrva.py --len=`(长度一律由 `.pdata` 算,不跨函数)、调用者桶用
`scripts/fastcalls.py`(产物落在 `evidence/xrefs/callers_0x*_buckets.tsv`)。

---

## §1 台账:五个候选 + 两条已知负结论(2026-11-15,离线,零 shot)

### §1.1 候选(数值逐字取自来源,不改写)

| 候选 | 来源 | 已知 |
|---|---|---|
| `0x9F5750` | `AGENTS.md` RVA 表 | Event command handler,需更深 trace |
| `0x9F6420` | 同上 | 同上 |
| `0x9F65E0` | 同上 | 同上 |
| `0x18B7B70` | `c1_validation` §83 | effect vtable `+0x70` 派发候选,拿对象不派活 |
| `0x18B7E30` | 同上 | 同上 |

两条**既有负结论**(本卷不推翻,只对齐):

- **§83 = `dispatcher_partial`**:两个 `+0x70` 候选追到的是「谁造这个对象」(类自己的 create +
  class_info vtable),没有往外接到列表驱动 / on_action / event 那种入口。
- **§89 = `+0x70` 那一族不在执行路径**:实机窗内 16 个月度脉冲、`12,544 = 16 × 784` 次逐系统
  下发,而 `0x3B1330`(`+0x70` 的 base impl)`calls=0`;§90.1 把它加强成「它只有三个直接
  调用者,三个全部沉默」。

### §1.2 本卷新增的台账行(来源 = §2)

| 候选 | 来源 | 已知 |
|---|---|---|
| `0x407330` | §2.2 | **唯一**读 `on_monthly_pulse` / `on_yearly_pulse` 真串的函数:名字 → DB 固定字段 |
| `0x265DD0` | §2.3 | **唯一**读 DB`+0x28` 的函数;唯一调用者按「月变」触发 |
| `0x406F90` | §2.5 | `Perform OnAction`(`onaction.cpp`):`events` / `random_events` → `0x402C50` |

### §1.3 复现

```
python3 scripts/scratch/2026-11_onmonthly/onaction_field_readers.py
```

四段读数(名字引用点 / 14 行映射 / 字段读者表 / 五候选调用槽)与 §2、§3 的每个数一一对应;
`pytest` 不在本卷范围(该脚本是 `scratch/`,冻结留档,不进 lint 也不进围栏)。

---

