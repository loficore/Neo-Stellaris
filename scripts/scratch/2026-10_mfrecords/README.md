# 2026-10_mfrecords — §46 的读回与判别

一次性:把 Task 1 装在 `heap_mf` 三个回调里的环形记录器在 Windows 上读回来,并按计划的判定表
判 §45.5 的三条候选 ——「(a) 我们 returned 的指针不满足 `JSMallocBlockHeader` 的对齐要求」、
「(b) 我们的 `size == 0 → NULL` 规则被 QuickJS 的零尺寸请求踩到」、「(c) `JSMallocState` 被分成
两份,回调看到的 `st` 与 `JS_NewRuntime2` 那次不是同一份」。

这一批**只有笔记,没有脚本**。两件工具在 Task 2 已经升为受维护的顶层工具,读回与符号化都用它们:
`scripts/c2_selfabort_repro.py`(Windows 侧 `C:/temp/c2_selfabort_repro.py`,零 shot、零游戏、零 dispatch:
它只用 `ctypes` 把**我们自己的 DLL**装进脚本自己拥有的子进程)与 `scripts/dll_ubsan_site.py`(纯离线读文件)。

| 文件 | 当时在回答哪个问题 |
|---|---|
| `判别说明` | 三件事的完整过程记录:(1) 首发 14 次只回空环时的**取样节奏诊断**(2 ms 记录器轮询 vs 亚毫秒死亡窗口,以及为什么"扩 CPU 超订"是唯一不新增能力的补救);(2) 逐条 render 的判别算术(13 条事件行的 `ptr % 8` / `ptr % 16` / `size` / 每 render 的 distinct `st` 数与 `st − ptr₁ = +0x408` 恒等式);(3) 第 5 条 render 为什么是**陈旧读**、以及把它与完整 render 汇池会凭空造出候选 (c)。末尾是重跑命令的逐字转录。 |

**怎么跑**(逐字转录在 `判别说明` 的最后一节;Windows 侧远程 shell 是 PowerShell,所以用 `;` 串联,`&&` 在那里不是分隔符):

```
R=/var/lofibass_ssd/code/zig/Neo-Stellaris
cd "$R" && zig build && sha256sum zig-out/bin/stellaris_quickjs.dll
scp zig-out/bin/stellaris_quickjs.dll Windows_Jiaolong:C:/temp/sqjs_s46.dll      # 别覆盖 sqjs_s43.dll
scp scripts/c2_selfabort_repro.py     Windows_Jiaolong:C:/temp/c2_selfabort_repro.py
ssh Windows_Jiaolong "python C:\temp\c2_selfabort_repro.py C:\temp\sqjs_s46.dll"
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x18000bd9b
```

单次跑基本只会读到空环 —— 需要把主机 CPU 超订(16–24 个子进程并发)才能让读线程在死亡窗口里拿到
一个时间片。84 次真实子进程跑只有 5 次带数据,这个数字本身就是结论的一部分,写在
`evidence/logs/c2_mfrecords_4_4_4.log` 的 (7)。

**结论落在** `evidence/analysis/runtime_444_c1_validation.md` §46,逐字记录在
`evidence/logs/c2_mfrecords_4_4_4.log`。判定表落到**第四行**:三条候选都被数据判掉,候选表不完整,
C2 阻塞,下一步归人,不归 Task 4。

**零 shot、零游戏、零 dispatch**:`stellaris.exe` 未被启动、未被接触;§44 的单发授权未被使用,也未 rehearsal。

**不作为接口维护**:可以失效,但别在新结论上重犯这一批已经踩到并避开的口径错误 ——
(1) 环形记录器的 `st` **任何两条不同**在健康运行时也成立(`quickjs.c:2070` 是栈上的 `JSMallocState`,
`:2082` 才拷进堆),所以行 3 只能按"模式"读,distinct 数要打印出来;
(2) 我们 return 的指针**结构上恒为 `≡ 8 (mod 16)`**,原生序列也一样,所以 `ptr & 0xf != 0` 单独不构成
候选 (a) 的证据,判据只能是 `ptr % 8 != 0`;
(3) `ptr=----------------` 是"进了没出"或"读不稳",`__ size=0 ptr=----------------` 是**从没写过的槽**,
两者都不是零尺寸请求,不能进表;
(4) `C2DiagMfRecordsInto` 只读一次游标再走槽位(设计如此),因此存在陈旧读,**跨 render 汇池会造假**。
