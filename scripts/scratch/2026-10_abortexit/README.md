# 2026-10_abortexit — §45 的自杀判别器与离线符号化

一次性:回答两件事 ——「这份 DLL 会不会自己杀死承载它的进程」,以及「在没有符号表、没有 debug
段的产物里,UBSan panic 落在哪一行」。

| 文件 | 当时在回答哪个问题 |
|---|---|
| `dll_abort_repro.py` | 把**出货的那份字节**用 `ctypes.WinDLL` 装进本脚本自己拥有的子进程,按实机那次 shot 的门序跑 `C2Sanity` → `C2DiagQJSInto`,同时用一个 0.2 ms 的 daemon 线程盯 `g_diag_log`。零游戏、零注入、零 dispatch:子进程若在没人碰它的情况下以退出码 3 死掉、且 witness 文本与实机逐字相同,那么「host 死了」这件事就与 `stellaris.exe` 无关。 |
| `ubsan_site.py` | 离线符号化。产物里没有 `.debug_*`、没有符号表,Zig 的 panic 打印只能说 `???`。镜像里还有两样东西能回答「在哪」:`.rdata` 里每个 UBSan 检查点的 `TypeMismatchData` 记录(带**源文件名、行、列**和类型描述器名字),以及 `.pdata`(x64 异常目录)给出的每个函数的精确 `{begin, end}` 区间。`site <类型名>` 列出该类型的所有检查点,`func <vma>` 给出持有该地址的函数区间与它引用的记录。 |

**怎么跑**:

```
scp 后在 Windows 侧: python C:/temp/dll_abort_repro.py C:/temp/sqjs_s43.dll
本机: python3 scripts/scratch/2026-10_abortexit/ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x18000bd9b
```

`dll_abort_repro.py` 只用 `ctypes` + 子进程,不调 `CreateRemoteThread`;`ubsan_site.py` 只读文件。

**结论落在** `evidence/analysis/runtime_444_c1_validation.md` §45,逐字记录在
`evidence/logs/c2_selfabort_4_4_4.log`。

**不作为接口维护**:可以失效,但别重犯它已经踩过的口径错误 —— panic 栈打印的是 `ip−1`,直接把它当
调用点会比错一个字节;`.pdata` 解析在这份产物里只吐出 3,042 条区间(对 0x4c8b86 字节的 `.text`),
所以「某地址不在任何区间内」证明不了任何事。
