# 安装

运行时 JS mod 有**两半**,缺一不可。**官方那一半**(`descriptor.mod`、`common/`、`events/`、
`localisation/`)就是一个普通的 Stellaris mod;**运行时那一半**是一个 `neo/` 目录,注入的 QuickJS
宿主从固定路径读它。只装前一半,你会得到一个「能加载、但什么都不做」的 mod——本页存在的意义就是
消灭这个失败形状。

一键安装器会把两半都装好,先讲它;然后讲手工路线,给排查问题时用。

## 你需要什么

- **Windows x86_64** 与 **Stellaris 4.4.4**。宿主的版本门是 `stellaris.exe` 的 sha256,所以别的
  补丁版本会被直接拒绝,而不是半支持。
- **开发者预览包**——从[最新 Release](https://github.com/loficore/Neo-Stellaris/releases/latest)
  下载 `neo-stellaris-preview-<version>.zip`。包里是 `stellaris_quickjs.dll`、`inject.exe`、
  TypeScript SDK(`sdk/`)、两个完整示例(`examples/`)、`INSTALL.md`(本页的离线版)、`LICENSE`、
  `THIRD-PARTY-NOTICES.md` 与 QuickJS 许可证。
- **Node.js 24**——只在**写 mod** 的那台机器上需要,而且只给 `neo new/build/check/pack` 用。
  玩一个已经构建好的 mod 不需要 Node。

## 校验下载

每个 Release 都带一个 `SHA256SUMS`,三行:DLL、`inject.exe` 和 zip 自身。

```bash
sha256sum -c SHA256SUMS
# stellaris_quickjs.dll: OK
# neo-stellaris-preview-<version>.zip: OK
```

zip 自己的哈希没法从 zip 内部核对——拿那一行去和 Release 页面比对。任何一行不匹配就别装:DLL 会被
注入游戏进程,而出货字节必须是被门验过的那份字节。

## 用一键安装器安装

`neo_install.py` 加它的 `neo.bat` 包装是玩家入口。把两个文件放到游戏旁边(或 `C:/temp/`),双击
`neo.bat`:它装好两半、注入运行时、启动游戏。输出恒为一行:

```
NEO_PLAY ok dll=8c774e60b36c2969 mod=neo_events pid=4242
NEO_PLAY fail reason=version_unsupported
```

`pid=0` 表示**这一趟没有启动游戏**(dry-run,或 `--no-launch` 且本来没有进程在跑),不是错误。

在命令行里,同一个文件接受参数:

```bash
python C:/temp/neo_install.py --dry-run --debug            # 只打计划,不写任何东西
python C:/temp/neo_install.py --mod C:/temp/mods/my_mod    # 装这个项目并启动
python C:/temp/neo_install.py --no-launch                  # 只装不启动
```

### 它把什么放到哪里

| 哪一半 | 目的地 |
|---|---|
| 官方 mod(`descriptor.mod`、`common/`、`events/`、`localisation/`) | `<Documents>/Paradox Interactive/Stellaris/mod/<id>/`,外加一个指回它的 `<id>.mod` 描述符与一条 `dlc_load.json` 条目 |
| 运行时(`<project>/neo/`) | `C:/temp/neo_mods/<id>/neo/`——注入加载器读的固定路径 |
| 宿主 | `stellaris_quickjs.dll` → `C:/temp/`,由 `inject.exe` 加载 |

`dlc_load.json` 那条就是**播放集(playset)**那一半:少了它,文件再对引擎也永远不会加载这个 mod。
手工安装时这一步要你自己做(见[手工安装](#手工安装))。

### 失败标签

每个标签只有一个词,因为玩家只拿到一行:

| 标签 | 含义 |
|---|---|
| `game_not_found` | `--exe`、`NS_STELLARIS_EXE`、`--game-root` 与 Steam 默认路径都没有 `stellaris.exe` |
| `version_unsupported` | exe 的 sha256 不是受支持的 4.4.4 摘要——**一个字节都不写** |
| `dll_missing` | 脚本旁边、`NEO_DLL` 里、`zig-out/bin` 里都没有 `stellaris_quickjs.dll` |
| `dll_locked` | 拷贝时遇到共享/权限错误——通常是正在运行的游戏占着旧 DLL |
| `mod_missing` | 没有项目目录(缺 `descriptor.mod`) |
| `manifest_invalid` | `neo/mod.json` 读不了,或 `id` 不在 `[a-z0-9][a-z0-9_]{0,63}` 里 |
| `bundle_missing` | `neo/<entry>` 不存在——先跑 `neo build` |
| `python_missing` | `neo.bat` 自己打的:既没有 `python` 也没有 `py -3` |
| `bridge_failed` | 启动/注入通道返回非零 |
| `internal` | 其它情况;`--debug` 会打出 traceback |

**安装器做不到的一件事:** mod 文件在游戏启动时读一次,所以安装时游戏已经在跑,这一局就看不到它们。
没有进程时安装器会自己拉起游戏;用了 `--no-launch`,就要自己重启再等事件。

## 手工安装

当你在改宿主本身,或者上面某个标签指向安装器会处理、但你想亲眼看它发生的环节时,走这条路线。

1. **解压。** 保持 zip 的目录结构;`sdk/` 与 `examples/` 的相对位置是有意义的。
2. **先构建 bundle。** 安装前 `neo/main.js` 必须存在:

   ```bash
   cd sdk && npm ci
   node dist/cli.js build --dir ../examples/neo_events
   node dist/cli.js check --dir ../examples/neo_events
   ```

3. **拷运行时那一半。** 项目的 `neo/` 目录放到 `C:/temp/neo_mods/<id>/neo/`,使 `neo/mod.json` 与
   `neo/main.js` 直接位于其中。`<id>` 就是清单里的 `id` 字段,它同时是加载器的目录名,二者必须一致。
4. **拷官方那一半。** 项目的 `descriptor.mod`、`common/`、`events/`、`localisation/` 放进
   `<Documents>/Paradox Interactive/Stellaris/mod/<id>/`,并在该目录旁写一个 `<id>.mod` 文件,
   用 `path=` 指回它。
5. **在播放集里启用。** 把 `mod/<id>.mod` 加进 `dlc_load.json` 的 `enabled_mods`(启动器会按自己的
   注册库重写这个文件,所以从启动器 UI 里勾选通常更省事,而且一定生效)。
6. **在脚本解析器运行前注入。** 经 Steam 启动游戏,然后对进程运行 `inject.exe` 加载
   `stellaris_quickjs.dll`。宿主每个进程只加载一次,且永不被卸载。

## 怎么判断装好了

`C:/temp/neo_js.log` 里应该出现宿主自己的行:

```
NEO_JS_LOAD id=neo_events entry=main.js
NEO_JS_CALL ...            # 每个星系、每月脉冲各一次
NEO_JS_LOG NEO_EVENT_PICK source=js system=82 pick=2 ...
```

**没有**注入的局里,`neo_action` 会被记成未知效果。这对运行时 JS mod 是预期行为,也是区分
「DLL 没进去」与「JS 坏了」最快的方法。

宿主加载了、但你的处理函数一次都没跑,要查的链条是
`on_actions` → 隐藏事件 → `every_system`/`every_country` → `neo_action`:派发是**官方脚本**驱动的,
不是宿主内部的定时器。[第一个 mod](/zh/guide/first-mod) 会把这条链走一遍,
[已知限制](/zh/guide/known-limits)列出预览包刻意不做的部分。
