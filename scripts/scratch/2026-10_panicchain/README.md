# 2026-10_panicchain — §47 前置:把磁盘上那 8 帧钉成调用链

一次性:回答一件事 ——「§45 与 §46 已经落在磁盘上的那 8 个 panic 帧 RVA,在**当前这份产物**的字节上
分别是谁」。全部输入都是 log 文件里已有的数,全部工具都是纯读文件:**零 shot、零游戏、零 dispatch、
零 Windows 通道** —— `stellaris.exe` 没有被启动、没有被接触、连文件都没有被打开过;§44 的单发授权
早已在 §44 用掉,这一批既没有使用它,也没有 rehearsal。

这一批**只有笔记,没有新脚本**:符号化用的就是 Task 2 已升为维护工具的 `scripts/dll_ubsan_site.py`
(纯离线读 PE 的 `.pdata` 区间 + `.data`/`.rdata` 里的 `TypeMismatchData` 记录)。仓库外只有一个
临时的 C 布局探针(在 `/tmp`),它的作用与它的逐字输出都记在
`evidence/logs/c2_panicchain_4_4_4.log` 的 (5),**故意不进 git** —— 里面没有任何一次实测,只有把
`quickjs.c:270-280`/`:289-302`/`:583-599` 三个 struct 重打成一次 `zig cc` 编译,好让
`sizeof(JSString)` = 20(Windows 目标)/ 12(主机)这句话不是抄来的。

## 当时在回答的问题

| 问题 | 落在哪 |
|---|---|
| 帧的**顺序**从哪来? | `evidence/logs/c2_selfabort_4_4_4.log:36-45` 的 stderr 转储才是顺序;`:48` 与 §46 `:107`/`:127`/`:173` 那几行是**排序后的集合**,不是栈序。见 log (2)。 |
| 该读哪一份字节? | 读 `zig-out/bin/stellaris_quickjs.dll`,它当下就是 §46 的 `77c0c35e…c11ad0`,所以主表用 §46 的 `0x44e399`;§45 的 `0x44d339` 也有本地字节(`.zig-cache/o/ecf27c97deb9b81534b0b477808ab19f/stellaris_quickjs.dll`,`863917f2…86617`),两套八帧都在 log (1)/(3)/(4a) 解了 —— 帧 1–7 的区间逐字相同,只有帧 8 移动 `+0x60`。 |
| 八帧各自是谁? | log (3) 是八段逐字工具输出,log (4) 是链表:函数名、`.pdata` 区间、区间内偏移、引用了 `quickjs.c` 的哪几行。五个 QuickJS 名字逐个回到 `libs/quickjs/quickjs.c` 读外层定义钉住,四条调用边各有一条真实源码头。 |
| 外三帧(6–8)呢? | 工具打出区间后回答「this function's code references no UBSan record」(exit 1)。**这是结论,不是故障**:它表示该函数代码不引用任何 UBSan 记录 —— 是插桩的事实,不是帧的语言;C 函数没有检查点也是同一输出。三帧按导出表 + `E8` 调用点扫描 + 源码归因(log (4)):`c2_diag_sequence`(C)→ `C2DiagQuickJS`(C)→ `C2DiagQJSInto`(Zig 导出),不是链接期符号名。 |
| §46 那条环记录能对上吗? | 能,而且只对上到一个类:`0xff0` = `40 + 101*40` = **40 字节 block class** 的 new-arena 请求,在 31 个类里唯一。log (5) 另附主机布局的对照分支(同一表达式给 `0xfe8`,正是 §46 原生正对照 render 的那个数)。 |
| 工具的 2 号退出码够窄吗? | 不够。`func` 拿到裸 RVA(低于镜像基址)过去会落到与真结论**同形同码**的 exit 1,本批把它改成 exit 2 并把该传的数回显;护栏的 before/after 逐字输出在 log (7) 与 (8)。 |

## 怎么跑

```
R=/var/lofibass_ssd/code/zig/Neo-Stellaris
cd "$R" && sha256sum zig-out/bin/stellaris_quickjs.dll   # 必须是 77c0c35e…c11ad0,否则下面读的不是这批证据的字节
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x18000bd9b     # 帧 1(最内)
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x1800eede3     # 帧 2
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x18001ebde     # 帧 3
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x1800055f5     # 帧 4
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x1800043bc     # 帧 5
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x18031b9c8     # 帧 6
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x18031cc05     # 帧 7
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x18044e399     # 帧 8(最外)
```

`0x180000000` 是这份产物的镜像基址(从 optional header 读,不是写死的),上面每个数都是
`image_base + rva` 现算的:`python3 -c "print(hex(0x180000000+0x1ebde))"`。**别用字符串拼接**
(`"0x18000" + "1ebde"` = `0x180001ebde`,是另一个地址),这一批真的踩过,记在 log (7) 的陷阱 1。

围栏(三条,全绿才算完):

```
python3 -m pytest scripts/test_scripts_layout.py -q          # 23 passed
python3 -m pytest scripts/test_c2_harness.py -q              # 134 passed(133 + 本批新增 1 条)
PYTHONPATH=scripts/windows python3 -m pytest scripts/windows/tests -q   # 169 passed
```

## 不作为接口维护

可以失效,但别在新结论上重犯这一批已经踩到并写下来的口径错误:

1. **`func` 要带镜像基址的 vma。** 低于基址的数现在是 exit 2(调用错了,对产物什么都没结论),
   不再是那条与真结论同形的 exit 1。两种 exit 1 也**不许并成一句**:「不在任何 `.pdata` 区间」与
   「命中函数但该函数不引用任何记录」是两件事。
2. **记录行不带 `[ubsan_site]` 前缀**(两空格开头)。`grep -F '[ubsan_site]'` 实测把
   `func 0x1800055f5` 的 7 行砍成 2 行,证据全丢;更坏的是不加转义的 `grep '[ubsan_site]'` —— 那是
   **字符类**,7 行一行不丢,看着像过滤器其实是直通。要记录行就 `grep '^  '` 或 `grep 'quickjs\.c:'`。
3. **帧打印的是 `ip − 1`**,既不是出错指令也不是调用点;直接交给 `func` 没问题,别当指令地址解读。
4. **`.pdata` 这条解析是不完整的**:当前产物(`.text` 0x4c9be6)量到 4,824 条区间,缓存的 §45 字节
   (0x4c8b86)量到 4,818 条;3,042 是 §45.4 当时的历史计数,不是当前工具在同一份字节上的结果。两个
   当前数都盖不住镜像里的函数,所以"没命中"证明不了任何事。
5. **`rc=3` 是子进程被 UBSan 杀死的状态码,不是工具的步骤码**;它只说明"我们自己的字节能复现这次死亡"。
6. **布局数会随编译器变。** `sizeof(JSString)` = 20 与 12 的差是 MS x86_64 位域各自成分配单位,本批
   用双向 `_Static_assert`(两个方向都会失败)钉住;换了目标或换了 `DUMP_LEAKS` 就要重测,别沿用。

**结论落在** `evidence/analysis/runtime_444_c1_validation.md` §47,逐字记录在
`evidence/logs/c2_panicchain_4_4_4.log`。
