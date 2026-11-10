# 示例

预览包里带两个完整的 mod。两个都是普通的 Stellaris mod——`descriptor.mod`、`common/on_actions/`、
`events/`、`localisation/`——只有一个外来名字:`neo_action` 效果,由注入的宿主注册。没有注入时,
脚本解析器会把 `neo_action` 报成未知效果,这行日志是预期行为。

## `neo_events`——JS 决策,官方脚本点火

对运行时 mod 来说可行的形状是:**JavaScript 写一个官方状态值,官方脚本读回来并触发真事件。**

```ts
import { graph, log, onSystem } from "@neo/runtime";

const DRIVER_SYSTEM = 82;
const driver = { id: DRIVER_SYSTEM } as unknown as Parameters<typeof graph.betweenness>[0];

onSystem((s) => {
  const betweenness = graph.betweenness(driver);
  const pick = betweenness >= 200 ? 2 : 1;
  s.setVariable("neo_event_pick", pick);
  if (s.id === DRIVER_SYSTEM) {
    log(`NEO_EVENT_PICK source=js system=${s.id} pick=${pick} betweenness=${betweenness}`);
  }
});
```

官方那一半随后在玩家国家上触发对应事件:

```text
on_monthly_pulse                       (common/on_actions/neo_events_on_actions.txt)
  └─ neo_events.100 (hidden, events/neo_events.txt)
       ├─ random_system { every_system { neo_action = { } } }
       │    └─ 注入的宿主对每个星系调一次 onSystem
       │       └─ JS 在系统 82 上写 neo_event_pick = 0 | 1 | 2
       └─ every_country { limit = { is_ai = no … }
            any_system { check_variable = { which = neo_event_pick value = 1 } }
            └─ country_event = { id = neo_events.2 } }
```

有两个地方是承重的,而且都容易搞错:

- 事件没有 system 作用域时,`every_system` **必须**包在 `random_system` 里;在无作用域的事件体里
  它只迭代一次,不是 788 次。
- 事件必须落在**玩家控制的国家**上。向 AI 国家触发的事件永远不会画出窗口,所以示例用
  `is_ai = no` 触发,并用 `any_system` 触发器读系统变量,而不是在 `owner` 上触发。

**你应该看到什么:** 一个带单一可点击选项的事件窗口,每月脉冲一次。选项把 `NEO_EVENT_PICK <n>` 写进
`game.log`、把 `neo_event_last = <n>` 写给国家;另一半是 `C:/temp/neo_js.log` 里的
`NEO_EVENT_PICK source=js system=82 pick=<n>`。两个数字必须一致——不一致是真缺陷,不是演示的小毛病。

构建并检查它:

```bash
cd sdk && npm ci
node dist/cli.js build --dir ../examples/neo_events   # 写出 neo/main.js
node dist/cli.js check --dir ../examples/neo_events   # NEO_CHECK ok … handler=1
```

完整源码与 README:
[examples/neo_events](https://github.com/loficore/Neo-Stellaris/tree/main/examples/neo_events)。

## `neo_opinion`——只读的国家契约

形状相同,但读取发生在运行时而不是脚本文本里:每月一次,宿主把每个非 AI 国家交给 bundle,它读引擎
好感矩阵的一格。

```ts
import { log, onCountry } from "@neo/runtime";

onCountry((c) => {
  const self = c.opinionOf(c.id);
  log(`NEO_OPINION_SELF id=${c.id} value=${self === null ? "null" : self}`);
});
```

| SDK | 引擎 keyword | 格子 |
|---|---|---|
| `c.opinionOf(targetId)` | `opinion` | `base[(target * n) + self]` |
| `c.theirOpinionOf(targetId)` | `their_opinion` | `base[(self * n) + target]` |

两个是**同一个**矩阵里互为转置的两格。哪一个才是「我们对他们的看法」尚未确立,所以示例读对角线
(`c.opinionOf(c.id)`)——它在两种读法下都良定义:单国存档没有不对称的一对可以区分。

`null` 是唯一的失败值,而且它不是 `0`。它表示:这一格从未被计算(引擎哨兵 `0x7fffffff`)、某个 id
越界、矩阵还不存在(主菜单,或没有载入战役)、会话缺少 `opinion.read` 权限,或 id 与当次派发的国家
不一致。每次拒绝同时会记一行 `NEO_JS_OPINION_REJECT … reason=<tag>`。

**没有写入口。** 这个矩阵是惰性填充的引擎缓存;填一格意味着调引擎自己的计算器,那是写操作。这不在
契约里,`Country` 也没有 setter。

构建并检查它:

```bash
node dist/cli.js build --dir ../examples/neo_opinion
node dist/cli.js check --dir ../examples/neo_opinion   # NEO_CHECK ok … handler=1
```

完整源码与 README:
[examples/neo_opinion](https://github.com/loficore/Neo-Stellaris/tree/main/examples/neo_opinion)。

## 仓库里还有

仓库还带第三个更小的示例——
[examples/chokepoint](https://github.com/loficore/Neo-Stellaris/tree/main/examples/chokepoint)——
它给星连图打分,把分数写成一个系统变量。这是最简单的形状:一个 `onSystem` 处理函数、一次变量写、
一行日志,完全没有事件那一半。

`neo new` 的模板
([`sdk/templates/neo-mod`](https://github.com/loficore/Neo-Stellaris/tree/main/sdk/templates/neo-mod))
是第四个起点:一个注册的处理函数,读邻居列表,并演示标记的读/写一对。
