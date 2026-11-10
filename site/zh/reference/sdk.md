# SDK 参考

运行时 JS SDK 是**运行时 JS mod**的作者界面:TypeScript 由 `neo build` 编译成一个 bundle,注入的
QuickJS 宿主在游戏主线程上求值它——每个星系一次、每个国家一次。

冻结的契约是
[`sdk/api.def`](https://github.com/loficore/Neo-Stellaris/blob/main/sdk/api.def)
(`version: 1`)。这里的 TypeScript 界面、`neo check` 用的 mock 宿主、以及出货 DLL 里的 Zig 宿主必须
与它一致;本页描述的是那个契约,不是一份设计提案。

契约是增量且带版本的:`API_VERSION` 一直是 `1`,成员只会往后追加。`s.name` 与 `s.variable()` 是
**刻意缺席**的——见[刻意缺席](#刻意缺席)。

## 前置条件

- 编写需要 Node.js **24**(`sdk/package.json` 声明 `engines.node >= 24`)。
- SDK 源码:仓库克隆,或开发者预览包里的 `sdk/` 目录。v1 里两者都不发布到 registry。
- 真要跑起来:Windows x86_64 上的 Stellaris 4.4.4,外加注入的 DLL——见[安装](/zh/guide/install)。

## 项目结构

```
my-mod/
├── tsconfig.json        # 把 @neo/runtime 映射到 SDK 源码
├── src/main.ts          # 你的 mod
├── neo/mod.json         # 清单(加载器读它)
├── neo/main.js          # 构建产物,不提交
├── descriptor.mod       # 启动器元数据
├── common/on_actions/   # 每月驱动(on_monthly_pulse -> 事件)
└── events/              # 隐藏事件:every_system { neo_action = { } }
```

`neo new` 写出的正是
[`sdk/templates/neo-mod/`](https://github.com/loficore/Neo-Stellaris/tree/main/sdk/templates/neo-mod)
里的模板;验收承诺是:生成的目录不经手工修改就能过 `neo build` 与 `neo check`。

`tsconfig.json` 必须把 `@neo/runtime` 指向 SDK 的 `src/runtime.ts`;SDK 本身没有 registry 安装步骤。
`neo new` 会相对生成目录解析这个路径:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true,
    "baseUrl": ".",
    "paths": { "@neo/runtime": ["../../sdk/src/runtime.ts"] }
  },
  "include": ["src/**/*.ts"]
}
```

示例
([`examples/chokepoint`](https://github.com/loficore/Neo-Stellaris/tree/main/examples/chokepoint))
是一个完整、可构建的项目:

```ts
import { onSystem, graph, log } from "@neo/runtime";

onSystem((s) => {
  const b = graph.betweenness(s);
  if (b >= 200) {
    s.setVariable("neo_score", b);
    if (!s.hasStarFlag("neo_hub")) {
      s.setStarFlag("neo_hub");
    }
    log(`NEO_HUB ${s.id} ${b}`);
  }
});
```

## API

| 导出 | 签名 | 说明 |
|---|---|---|
| `onSystem` | `(handler: (s: System) => void) => void` | 注册按星系的处理函数。只调用一次——宿主每个会话只保留一个处理函数。 |
| `System.id` | `number` | 本次调用的引擎星系 id。SDK 唯一留存的句柄。 |
| `System.degree` | `number` | 星连度,每次访问都重新读(不缓存)。 |
| `System.neighbors` | `readonly number[]` | 邻居星系 id,每次访问都重新读;宿主返回一个新数组,上限 64,超出会有截断日志。需要 `graph.read`。 |
| `System.setVariable` | `(name: string, value: number) => void` | 经官方 `set_variable` 函数体为当前星系写值。 |
| `System.setStarFlag` | `(name: string) => void` | 经 `set_star_flag` 函数体设置官方标记 `name`。需要 `flag.write`。名字由引擎的标记名表解析为 `u16` id;表里没见过的名字会在首次使用时插入(脚本写同一个字面量时引擎就是这么做的)。名字必须是 **1–15 个小写字节的字符串字面量**,且不得与官方 keyword 撞名。拿不到 id 时报 `no_flag_token`。 |
| `System.hasStarFlag` | `(name: string) => boolean` | 从标记容器里读官方标记 `name`。需要 `flag.read`。**只读:**名字用不插入的查找解析——表里没有 id 的名字读出 `false` 并记 `reason=no_flag_token`。有 id 但容器里没有(或容器读不了)同样读出 `false`(fail-closed)。字面量规则与写入相同。 |
| `onCountry` | `(handler: (c: Country) => void) => void` | 注册按国家的处理函数。需要清单的 `scope` 里有 `"country"`;只声明 system 的 bundle 调用它会记 `NEO_JS_REGISTER_REJECT … scope=country` 并保持惰性(会话**不会**被禁用)。 |
| `Country.id` | `number` | 本次调用的引擎国家 id(被派发作用域的 `+0x10`)。SDK 唯一留存的句柄。 |
| `Country.opinionOf` | `(targetId: number) => number \| null` | 引擎 `opinion` keyword:矩阵里的一个 `int32` 格,键是 `target * n + self`(两个 id 都掩到低 24 位——引擎的键空间;直接传 `Country.id`)。**`null` = fail-closed**,绝不是 `0`:未计算(引擎哨兵 `0x7fffffff`)、任一 id 越界、矩阵没建(主菜单/没有战役)、会话没有 `opinion.read`,或 id 与被派发的国家不符。每次拒绝还会记 `NEO_JS_OPINION_REJECT … reason=<tag>`。**只读:**这一格是惰性填充的引擎缓存,宿主从不调它的计算器。 |
| `Country.theirOpinionOf` | `(targetId: number) => number \| null` | 引擎 `their_opinion` keyword——`opinionOf` 的**转置**(`self * n + target`)。同样的 fail-closed 规则。哪一个才表示「我们对他们的看法」**尚未确立**;见[已知限制](/zh/guide/known-limits)。 |
| `graph.betweenness` | `(s: System) => number` | 该星系的图分数(与交通要道打分同源)。 |
| `graph.isChokepoint` | `(s: System) => boolean` | `betweenness(s) >= 200`——一个固定阈值,不是 v1 里的可调参数。 |
| `log` | `(message: string) => void` | 往 `C:/temp/neo_js.log` 追加 `NEO_JS_LOG <text>`。 |
| `apiVersion` | `() => number` | 返回宿主的契约版本;v1.x 是 `1`。 |

## native 契约

SDK 是宿主装的十三个全局对象之上的薄封装。`sdk/api.def` 是唯一权威;TypeScript 界面、mock 宿主
与 Zig 宿主都必须与它一致。v1 的七个名字在前,原样不变;v1.1 的追加项按宿主自己的顺序排在后面。

| native | 参数 | 返回 |
|---|---|---|
| `__neo_register_system` | `function` | `void` |
| `__neo_system_degree` | `u32` | `u32` |
| `__neo_system_set_var` | `u32`、`string`、`f64` | `void` |
| `__neo_graph_betweenness` | `u32` | `u32` |
| `__neo_graph_is_chokepoint` | `u32` | `bool` |
| `__neo_log` | `string` | `void` |
| `__neo_api_version` | — | `u32` |
| `__neo_system_neighbors` | `u32` | `array<u32>` |
| `__neo_system_set_flag` | `u32`、`string` | `void` |
| `__neo_system_has_flag` | `u32`、`string` | `bool` |
| `__neo_register_country` | `function` | `void` |
| `__neo_country_opinion` | `u32`、`u32` | `i32 \| null`(`undefined` = 被拒绝) |
| `__neo_country_their_opinion` | `u32`、`u32` | `i32 \| null`(`undefined` = 被拒绝) |

system 那些 native 的 `u32` 就是**星系 id**;国家那一对取 `(self, target)`。「被拒绝」是宿主的
fail-closed 答案,刻意与「算出来的 `0`」区分开。

## 清单

`neo/mod.json`——加载器读固定位置 `C:/temp/neo_mods/<id>/neo/{mod.json,main.js}`:

```json
{
  "id": "chokepoint",
  "entry": "main.js",
  "scope": ["system"],
  "permissions": ["graph.read", "flag.read", "flag.write", "variable.write", "log"],
  "engine": "4.4.4",
  "runtime": ">=0.1",
  "flags": ["neo_hub"]
}
```

- `id`——目录名与日志标签。必填。
- `entry`——加载器求值的 bundle 文件名。必填。
- `scope`——`"system"`、`"country"`,或 `["system","country"]`(字符串形式与 1–2 元素数组形式都接受,
  每个名字最多一次)。bundle 只会收到它声明的作用域。必填。
- `permissions`——`graph.read`、`variable.write`、`variable.read`、`flag.read`、`flag.write`、`log`、
  `opinion.read` 任选。缺权限的 native 会被宿主拒绝,未知权限则在加载时禁用该 mod。`degree`、
  `neighbors`、`betweenness`、`isChokepoint` 属于 `graph.read`;`setStarFlag` 属于 `flag.write`;
  `hasStarFlag` 属于 `flag.read`;`opinionOf` / `theirOpinionOf` 属于 `opinion.read`。
- `engine` / `runtime`——兼容性字符串;不匹配会记一行日志并禁用该 mod。
- `flags`——**可选**(没有它的旧清单照样能加载)。它是**构建期撞名门**,不是运行期权威:`neo build`
  把 bundle 里 `setStarFlag("…")` 的字面量记在这里,`neo check` 拒绝不再匹配的列表,这样作者就不会
  在没察觉的情况下把一次写打到官方 keyword 上。**宿主不再读这个字段**——运行时名字由引擎的标记名表
  在首次使用时解析。最多 **32** 个名字;每个 1–15 字节、全小写、不以 `-` 或数字开头。缺 `flags`
  等价于 `[]`。

宿主从 `C:/temp/neo_mods/<id>/` 最多加载 **8** 个 mod,每个一个 QuickJS 上下文/会话:抛异常、
死循环或越界的 mod 只禁用它自己的会话,其它会话照常收到 `onSystem`。一个 mod 都没有会记
`NEO_JS_NO_MOD`。

## `neo new`

`neo new <dir> --id <id> [--name <name>]` 拷贝 `sdk/templates/neo-mod/`(替换 id、显示名与相对的
`@neo/runtime` 路径),并打印 `NEO_NEW ok dir=<abs> id=<id> files=<n>`。

它拒绝非空目标、`[a-z0-9][a-z0-9_]{0,63}` 之外的 id(id 同时是清单 id、加载器目录名和 Clausewitz
事件命名空间),以及含引号或控制字符的显示名。生成的目录就是模板:`src/main.ts`、`neo/mod.json`、
`tsconfig.json`、`descriptor.mod`、`common/on_actions/<id>_on_actions.txt`、
`events/<id>_events.txt`、`README.md`。生成的清单声明
`["graph.read", "flag.read", "flag.write", "log"]`,它的 `onSystem` 示例演示标记的读/写一对。

## `neo build` 与 `neo check`

`neo build --dir <project> [--outfile <file>]`

1. `tsc --noEmit -p <project>`——类型错误(包括缺 `@neo/runtime` 的导出)会让构建失败。
2. esbuild 以 `--bundle --format=iife --platform=neutral --target=es2020` 打包 `src/main.ts`。产物里
   没有 `import`、没有 `require`,也不依赖模块加载器。
3. 写出 `<project>/neo/<清单里的 entry>`(默认 `neo/main.js`)。
4. 把 bundle 里 `setStarFlag("…")` 的字面量记进 `<project>/neo/mod.json` 的 `flags`(去重并排序,
   清单其它字段原样保留)。没有清单的项目不会被自动补一个——构建会在 stderr 打印
   `NEO_BUILD warn: no neo/mod.json, flags not recorded`,而标记调用在运行时会 fail closed。
   `neo build` **不**查 keyword 表(那是 `neo check` 的门),它只记录名字。

`neo check --dir <project>` 在内存里做同样的类型检查与打包,然后:

1. 静态拒绝 `require(`、`process.`、`window.`、`document.` 与动态 `import(`(宿主上下文里都没有这些);
2. 对 bundle 跑**标记名门**(见下);
3. 拒绝 `flags` 列表与 bundle 字面量不再一致的清单:
   `flags: manifest flags are stale; run "neo build" (bundle has ["neo_hub"], manifest has [])`。
   缺 `flags` 字段算作 `[]`;
4. 在**真实 QuickJS 运行时**(`quickjs-emscripten`,与宿主内嵌的同一族引擎)里装上 mock 宿主并求值
   bundle;
5. 断言恰好注册了一个 `onSystem` 处理函数、它在假星系 id `7` 上不抛异常,以及 `__neo_api_version()`
   与 `api.def` 一致。

一次通过的检查只打印一行并以 `0` 退出:

```
NEO_CHECK ok dir=/abs/path/examples/chokepoint handler=1 calls=6
```

失败打印 `NEO_CHECK fail: <reason>` 并以 `2` 退出。

mock 宿主(`sdk/src/mock-host.ts`)记录每一次 native 调用;`calls=` 是假星系上的调用数,`handler=` 是
注册的处理函数数。两者都是形状检查——`calls` 换成别的数字没关系,`handler=1` 有关系。

### 标记名门(构建期)

`s.setStarFlag(name)` 会在 bundle 运行前被检查,因为与官方 keyword 撞名的标记会打到引擎行为而不是
标记(与当年 `Add_Modifier` 撞名同型,只是深了一层)。两条规则:

- **只能是字符串字面量**——v1 对计算出来的名字没有构建期答案,所以 `s.setStarFlag(someVariable)`
  会失败,并说明必须是字面量;
- **不得与官方 keyword 撞名**——每个字面量都与
  [`evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`](https://github.com/loficore/Neo-Stellaris/blob/main/evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv)
  的 `keywords` 列做大小写不敏感比较;命中就让检查失败。

这个门读的是作者写的 `setStarFlag("…")` 调用点,而不是 native `__neo_system_set_flag(id, name)`:
SDK 封装总是转发自己的参数,所以 native 调用在每个 bundle 里都是动态的。`hasStarFlag("…")` 的字面量
**不**参与 keyword 门:读不写任何东西,所以计算出来的或古怪的读名字只会 fail closed
(`no_flag_token`、`false`)。

因为需要 keyword 表,`neo check` 需要仓库的 `evidence/` 目录(预览包正是为此才带上那一个 TSV);表
缺失时检查会失败并打印它找过的路径。

### 标记 id(首次使用时解析)

标记名由引擎自己的**标记名表**在游戏主线程上、于该名字第一次 `setStarFlag` / `hasStarFlag` 时
解析成引擎的 **`u16` 标记 id**:

| 步骤 | 写(`setStarFlag`) | 读(`hasStarFlag`) |
|---|---|---|
| 对名字做哈希 | 是 | 是 |
| 探测标记名表的桶数组 | 是 | 是 |
| 未命中 | 插入并分配表里的下一个 id | **停下并返回 `false`** |

所以写入可能注册一个新名字(脚本写同一个字面量时引擎就是这么做的),而读取永远不注册任何东西——
一次读不会污染标记表。

为什么不用词法 token 表:`set_star_flag` 把键存在一个 `u16` 格子里,但官方脚本路径是通过**标记名表**
解析名字的。词法 token 表是另一个对象,编号宽得多也密得多,所以 token id 永远不可能等于引擎
`has_star_flag` 算出来的 id。变的是键空间,容器与写函数体都没变。

16 位 id 是**标记表自己的编号**(稠密,由它自己的 size 字段分配),不是词法池,所以不再有安装期铸 id:
宿主在安装时不碰标记,任何构建里都不再存在 `NEO_JS_PREMINT*` 那些日志行。

失败码:

| 行 | 含义 |
|---|---|
| `NEO_JS_WRITE_REJECT … reason=no_flag_token kind=flag` | 标记表没给出 id(模块基址没解析出来、名字非法、计数器为 `0`,或 `0xFFFF` 哨兵)。标记**没有**被写入。 |
| `NEO_JS_FLAG_REJECT … reason=no_flag_token` | 读的名字在标记表里没有 id;调用返回 `false` |
| `NEO_JS_FLAG_REJECT … reason=no_permission` | 会话缺少 `flag.read`;该会话被禁用 |

边界:

- `0xFFFF`(以及 `0`,模块同样视为不可用)是**硬失败**,永远不是一次成功写入:官方写者在
  `id == 0xFFFF` 时直接返回;
- 名字 1–15 字节(引擎字符串对象的内联容量);更长的名字在碰表之前就被拒绝;
- 宿主里有一个正的名字→id 缓存,避免每个星系/每月重复哈希同一个名字;*未命中*不会被缓存(官方脚本
  之后可能会注册这个名字)。

**这条解析路径还没有实机读数。** 静态推导在
[`evidence/analysis/flag_store_4_4_4.md`](https://github.com/loficore/Neo-Stellaris/blob/main/evidence/analysis/flag_store_4_4_4.md)
§6;按[已知限制](/zh/guide/known-limits)里的说法,把这两个标记调用当成未证明。

## `neo pack`

`neo pack --dir <project> [--out <zip>]`

1. 先跑 `neo build`(这样 `neo/<entry>` 才存在)与 `neo check`;check 失败会以
   `NEO_PACK fail: pack: neo check failed: …` 中止打包,并且不写归档。
2. 按**白名单**暂存 `<project>/dist/<id>/`:`descriptor.mod`、`common/**`、`events/**`、
   `neo/mod.json`、`neo/<entry>`,以及一份 `README.md`(作者自己的 README,如果有,再加上已知限制段)。
3. 写一个 store-only zip(固定 1980-01-01 时间戳、条目排序)——同样的输入产出同样的字节——写到
   `--out` 或 `<project>/dist/<id>.zip`。
4. 把归档读回来,逐条与暂存内容比对,然后才报告 `NEO_PACK ok dir=<abs> out=<zip> entries=<n>`。

`node_modules/`、`dist/` 与 `.git/` 是按构造排除的(它们从来不在白名单里),而不是靠一个可能悄悄漏掉
某个的过滤器。打包出的 README 总是带上「这不是 Workshop mod / 没有注入宿主就是惰性的」这条限制。

## 刻意缺席

- **没有 `s.name`,没有 `s.variable()`。** 它们要等到各自的官方函数体/读路径被解析出来才谈得上;
  延后的名字就是缺席,绝不猜。
- **没有舰队、星球、人口作用域。** 带着任何其它作用域来的派发只会被记下来然后丢弃:
  `NEO_SCOPE_OTHER mask=0x<mm> id=<n>`(只读)。
- **没有 `onMonthly`,也没有全局 tick 钩子。** 每月驱动是生成的 `on_action` + 隐藏 `event` 一对——
  官方脚本路径。
- **不解析 `dlc_load.json`,也没有 mod 之间的 JS 调用。** 宿主加载最多 8 个隔离会话,不是模块图。
- **`log` 写 `C:/temp/neo_js.log`**,不是官方 `game.log`。
- **SDK 以 TypeScript 源码分发**,不是 registry 包。

## 宿主强制的限制

| 限制 | 值 |
|---|---|
| 上下文内存 | 16 MiB |
| 栈 | 1 MiB |
| 每次处理函数调用的中断预算 | 10 ms → `NEO_JS_TIMEOUT`,会话被禁用 |
| JavaScript 异常 | `NEO_JS_ERROR`,会话被禁用 |

会话被禁用时游戏继续跑;DLL 永不被卸载(`FreeLibrary` 是被禁止的——打过补丁的引擎对象会跳进死页)。
完整清单,包括 Debug 构建带来的后果,在[已知限制](/zh/guide/known-limits)。

## 分发

实验性质,只发源码。v1 里 `@neo/runtime` 不发布到 npm:克隆仓库(或解开开发者预览包),按上面那样
用 `paths` 映射这个包。

预览包由 `scripts/pack_preview.py` 按显式清单组装(DLL、注入器、SDK、示例、许可证),并附一份
`SHA256SUMS`,覆盖两个二进制与 zip 自身。
