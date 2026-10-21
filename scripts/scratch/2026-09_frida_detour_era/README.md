# 2026-09 detour 时代善后探针

给 §10–§13 那条「往 base `CEffect::Execute 0x1D08520` 挂只记录 detour」的路线收尾用的四个脚本。
那条路线本身已被评掉（`AGENTS.md` 约束 7：`0x5350D0` detour 价值 = 0；`0x1D08520` 是 ~5,300 calls/s
的热路径，只允许只记录观测，不允许成为长期依赖）。**文件名不改**：`evidence/` 按 basename 引用。

| 文件 | 干什么 |
|---|---|
| `restoreexec.py` | 把被 detour patch 掉的 base Execute prologue 还原回引擎自己的字节 |
| `nsunload.py` | 在 `stellaris.exe` 里 `FreeLibrary` 我们的 mod DLL，好让文件能被覆盖（P12 换名重注入的前身） |
| `peekexec.py` | dump 某 RVA（默认 base Execute）的 live 字节并与磁盘拷贝比对，判「有没有残留 patch」 |
| `read_remote_mem.py` | 裸 `OpenProcess`+`ReadProcessMemory` 读一段字节 —— 已被 `../../c2_harness.py` 的 `read_memory` / `read_u64` 取代 |

三个（`restoreexec.py`、`nsunload.py`、`peekexec.py`）通过 **`../../execspy.js`** 的 RPC 干活，那个 driver
留在顶层没动 —— `src/dll/scripted/exec_hook.zig:167` 的注释把它当记录格式的契约方引用。
和 A 目录一样：需要 frida-server 在跑、游戏在跑、`C:\ns\` 下那套 js 还在。
