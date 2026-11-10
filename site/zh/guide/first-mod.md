# 第一个 mod

这一页把一个全新的运行时 JS mod 从空目录走到一个可以安装的 zip。前提是已经解开开发者预览包(或
克隆了仓库),并且在装了 **Node.js 24** 的机器上编写。

两种情况下 SDK 都在 `sdk/` 里;下面所有命令都在包根目录执行,除非另行说明。

## 1. 装 SDK 自己的依赖

```bash
cd sdk
npm ci        # 按 sdk/package-lock.json 的精确版本安装
```

SDK 不发布到任何 registry,所以这是唯一的安装步骤。它拉的是 TypeScript 编译器与 `neo check` 用来
跑你 bundle 的 QuickJS 构建。

想要短命令的话,在 `sdk/` 里 `npm link` 会把 `neo` 装到全局;不做的话,把下面所有 `neo` 换成
`node dist/cli.js`。

## 2. 脚手架

```bash
neo new ../my-mod --id my_mod --name "My Mod"
# NEO_NEW ok dir=/abs/path/my-mod id=my_mod files=7
```

`neo new` 会拒绝非空的目标目录、`[a-z0-9][a-z0-9_]{0,63}` 之外的 id(id 同时是清单 id、加载器目录名
和 Clausewitz 事件命名空间),以及含引号或控制字符的显示名。

生成的目录就是 `sdk/templates/neo-mod/` 里的模板:

```
my-mod/
├── src/main.ts          # 你的 mod——通常你只改这个文件
├── neo/mod.json         # 清单(加载器读它)
├── neo/main.js          # 构建产物,不提交
├── tsconfig.json        # 把 @neo/runtime 映射到 SDK 源码
├── descriptor.mod       # 启动器元数据
├── common/on_actions/   # 每月驱动
├── events/              # 隐藏事件:random_system { every_system { neo_action = { } } }
└── README.md
```

验收承诺是:这棵树不经任何手工修改就能过 `neo build` 与 `neo check`。

## 3. 写处理函数

`src/main.ts` 会被打进游戏,所以只能用 `@neo/runtime` 和普通 JavaScript 内建对象(不能用
`process`、`window`、`document`、`require` 或动态 `import`;`neo check` 会静态拒绝这些)。

```ts
import { log, onSystem } from "@neo/runtime";

// 每个星系、每月脉冲跑一次。保持便宜。
onSystem((s) => {
  if (s.degree >= 4) {
    s.setVariable("neo_hub", s.degree);
    log(`NEO_HUB ${s.id} degree=${s.degree}`);
  }
});
```

几条踩到就会疼的规矩:

- **`onSystem` 只调用一次。** 宿主每个会话只保留一个处理函数;第二次 `onSystem(...)` 不会替换任何
  东西,那是你 mod 的 bug。
- **`s.id` 是唯一能留的句柄。** 对象是按次调用的;跨调用缓存一个 `System` 不受支持。
- **标记名是字符串字面量**,1–15 个小写字节,且不得与官方 keyword 大小写不敏感地撞名。两条都由
  `neo check` 执行。
- **写操作走官方引擎函数。** `s.setVariable` 就是 `set_variable`,`s.setStarFlag` 就是
  `set_star_flag`。你的脚本用官方触发器把它们读回来——这就是全部的集成模型。

完整成员表在 [SDK 参考](/zh/reference/sdk)。

## 4. 构建与检查

```bash
neo build --dir ../my-mod
# NEO_BUILD ok dir=/abs/path/my-mod out=/abs/path/my-mod/neo/main.js

neo check --dir ../my-mod
# NEO_CHECK ok dir=/abs/path/my-mod handler=1 calls=6
```

`build` 用 `tsc` 做类型检查,用 esbuild 打成一个 IIFE(宿主里没有模块加载器),写出 `neo/<entry>`,
并把 bundle 里 `setStarFlag("…")` 的字面量记进清单的 `flags` 字段。

`check` 在内存里做同样的类型检查与打包,然后在**真实 QuickJS 运行时**里对着 mock 宿主跑 bundle,
断言:恰好注册了一个 `onSystem` 处理函数、它在假星系 id `7` 上不抛异常、`__neo_api_version()` 与
`sdk/api.def` 一致。失败会打印 `NEO_CHECK fail: <reason>` 并以 `2` 退出。

`calls=` 是 mock 宿主看到的 native 调用数。它是形状检查,不是预算:`calls=6` 表示你的处理函数在假
星系上碰了六个 native,换成别的数字也不代表错。

**`neo check` 不能证明引擎行为。** 它证明的是:bundle 类型正确、没有宿主里不存在的全局对象、注册了
一个处理函数、过了标记名门、并且说的是冻结的 native 契约。游戏到底会不会调它,是实机问题,答案在
下面的日志行里。

## 5. 打包与安装

```bash
neo pack --dir ../my-mod --out ../my_mod.zip
# NEO_PACK ok dir=/abs/path/my-mod out=/abs/path/my_mod.zip entries=9
```

`pack` 先跑 `build` 与 `check`,再按白名单挑文件(`descriptor.mod`、`common/**`、`events/**`、
`neo/mod.json`、`neo/<entry>`、`README.md`),写一个确定性 zip:固定时间戳、条目排序,同样的输入
产出同样的字节。check 失败会中止打包,并且不写任何归档。

安装用 `neo.bat` / `neo_install.py`,或者手工——见[安装](/zh/guide/install)。

## 6. 「成了」长什么样

驱动是一对自动生成的脚本文件,在怪 JavaScript 之前值得先读一遍:

```text
# common/on_actions/my_mod_on_actions.txt
on_monthly_pulse = {
	events = { my_mod.1 }
}
```

```text
# events/my_mod_events.txt
namespace = my_mod

event = {
	id = my_mod.1
	hide_window = yes
	is_triggered_only = yes

	immediate = {
		random_system = {
			every_system = {
				neo_action = { }
			}
		}
	}
}
```

两个细节是承重的:

- **`every_system` 必须从 system 作用域进入。** 在无作用域的事件体里它只迭代一次;包在
  `random_system` 里才会遍历每个星系(默认银河是 788 个)。
- **`neo_action` 收一个空块。** `neo_action = yes` 是解析错误:注册的效果解析的是一个赋值块。

宿主注入之后,一次每月脉冲会在 `C:/temp/neo_js.log` 里留下:

```
NEO_JS_CALL ...
NEO_JS_LOG NEO_HUB 82 degree=5
NEO_JS_WRITE ... kind=variable name=neo_hub
```

没有注入时,同一次脉冲会在 `error.log` 里把 `neo_action` 记成未知效果——脚本那一半是好的,缺的是宿主。

零就是「没发生」,不是「修好了」:`NEO_JS_ERROR = 0` 只表示没有处理函数抛异常,不表示错误路径可用。

## 7. 迭代

改 `src/main.ts`,重跑 `neo build`(或 `pack`),再装一次 `neo/` 那一半。`neo/main.js` 是生成的:
`neo check` **不会**把它和源码比对,所以过期的 bundle 能过所有门,并且表现得像你忘掉的那次编辑。

没有热重载。mod 文件在游戏启动时读,运行时那一半在宿主加载时读。改了 bundle 就要重启。

## 排查

| 症状 | 看哪里 |
|---|---|
| `NEO_CHECK fail: …` | 消息会指名规则:被禁的全局对象、过期 `flags` 列表、计算出来的标记名,或缺少某个 `@neo/runtime` 导出 |
| `error.log` 里 `neo_action` 是未知效果 | DLL 没注入——没有宿主的运行时 mod 就是这个样子 |
| 宿主加载了,但一条 `NEO_JS_CALL` 都没有 | `on_actions` → 事件 → `every_system` 这条链没触发;查播放集条目与事件 id 是否与命名空间一致 |
| `NEO_JS_FLAG_REJECT … reason=no_flag_token` | 这个名字在引擎的标记表里没有 id;见[已知限制](/zh/guide/known-limits)——标记读取尚无实机读数 |
| 整个游戏进程消失 | DLL 是 Debug 构建,某次安全检查 abort 了它;重跑之前先读[已知限制](/zh/guide/known-limits) |
