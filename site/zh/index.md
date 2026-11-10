---
layout: home

hero:
  name: Neo-Stellaris
  text: 为 Stellaris 写运行时 JavaScript mod
  tagline: 用 TypeScript 写 mod 逻辑。注入的 QuickJS 宿主在游戏主线程上运行它——每个星系一次、每个国家一次。
  actions:
    - theme: brand
      text: 下载预览包
      link: https://github.com/loficore/Neo-Stellaris/releases/latest
    - theme: alt
      text: 读 SDK 参考
      link: /zh/reference/sdk

features:
  - title: 写 TypeScript,不写脚本文本
    details: 图算法、跨作用域聚合、按对象存状态,这些在 Clausewitz DSL 里都很别扭。用普通 TypeScript 写,面向一层很小且冻结的 native 接口。
  - title: 官方脚本仍是官方脚本
    details: 宿主只写引擎状态;你自己的事件、on_actions、触发器照常干活。没有自定义文件格式,也没有替换掉事件引擎。
  - title: 出货前先过门
    details: "`neo check` 会把代码打包、在真实 QuickJS 里对着 mock 宿主跑一遍,并拒绝与官方 keyword 撞名的标记名。"
---

## 60 秒上手路径

1. **下载**最新 Release 里的 `neo-stellaris-preview-<version>.zip`,解压到任意目录。包里有注入宿主 DLL、
   注入器、TypeScript SDK 和两个完整示例——下载本身不需要 npm registry。
2. **安装**:DLL 放到 `stellaris.exe` 旁边,mod 的 `neo/` 目录放到 `C:/temp/neo_mods/<id>/`。一键安装器
   (`neo.bat`)会把两半都装好;手工路线与失败标签见[安装](/zh/guide/install)。
3. **写**一个处理函数。下面就是一个完整的运行时 mod 正文:

```ts
import { log, onSystem } from "@neo/runtime";

onSystem((s) => {
  log(`system ${s.id} has degree ${s.degree}`);
});
```

然后 `neo build` → `neo check` → `neo pack`,再安装产物。完整流程(包括自动生成、每月驱动一次
处理函数的 `on_actions`/`events` 一对文件)在[第一个 mod](/zh/guide/first-mod)。

::: warning 开玩之前先读限制
出货的 DLL 是 **Debug** 构建:一次内部安全检查失败会把游戏进程整个 abort 掉,而不是只停掉 mod。
标记(flag)读写在实机上还没有读数,国家作用域是只读的。这些都写在[已知限制](/zh/guide/known-limits)
里——读一遍只要一分钟,它决定你拿到的是演示还是坏存档。
:::

## 这不是什么

不是 Workshop mod。没有注入宿主时,运行时 JS mod 是惰性的:脚本解析器会把 `neo_action` 当成未知
效果,而 `neo/main.js` 之所以会跑,只是因为宿主从 `C:/temp/neo_mods/<id>/neo/` 里求值了它。没有任何
订阅能把这些装好,也没有热重载。

本站其余部分是面向作者的那一半:[安装](/zh/guide/install)、[第一个 mod](/zh/guide/first-mod)、
[示例](/zh/guide/examples)、[已知限制](/zh/guide/known-limits)与 [SDK 参考](/zh/reference/sdk)。
