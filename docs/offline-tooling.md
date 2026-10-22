# 离线 RE 工具目录与判读陷阱

本文件收录 `scripts/` 下**长期有效**的离线探测工具的完整判读说明:每条命令的输出、
它编码的 capstone/PE 陷阱、以及曾经导致错误结论的度量口径。`AGENTS.md` 只保留一行一条的索引,
用到哪个脚本时再来读这里。

结论本身(§17–§30)在三卷取证日志 `evidence/analysis/runtime_444_*.md`——§16–§23 在
`runtime_444_keyword_pipeline.md`,§24–§30 在 `runtime_444_c1_validation.md`;本文件只讲**怎么量**。

## 前置条件

**Binary**:`D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe` on the Windows host `Windows_Jiaolong`, copied to
`/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe` on Linux — 46,253,688 bytes, 4.4.4, sha256 `9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56`(2026-10-22 实测于本地拷贝;旧缩写串 `9242c40a…b1a56` 是同一条,与 `D:\` 原件一致)。
`scripts/rttibatch.py` / `scripts/cap.py` find it automatically (`NS_STELLARIS_EXE` overrides).
The `.i64` (705 MB) stays on Windows.

旧名 `PLAN.md` → 新落点 `docs/roadmap.md`(六段:目标与判据 / 授权门 / 阶段状态表 / 候选条线 / 仍生效的决策 / 新旧 § 映射);
`evidence/` 里指向 `PLAN.md` 的旧引用按不可变约定**不改写**,靠那份映射解读。

**Game data**: `/var/lofibass_ssd/data/stellaris/4.4.4/{common,events}` (2,186 files, copied 2026-09-29 from
`D:\SteamLibrary\steamapps\common\Stellaris\`) — scripted_effects, scripted_triggers, on_actions, events, defines, etc.

**Offline toolchain dependencies are pinned** in `scripts/requirements.txt` (capstone 5.0.7, pefile 2024.8.26,
unicorn 2.1.4). Only `emu_desc.py` needs unicorn, and its artifacts are checked in, so regenerating the oracle
is the step that requires it — `zig build test` does not.

**Host caveat**: 当前基线(2026-10-22 复测 `zig build test --summary all`)=
`Build Summary: 24/27 steps succeeded (1 failed); 314/314 tests passed`,裁定 **P15 把这一步记为绿**。
更早的 `24/27 …; 307/307` 与 `22/25 steps …; 296/296 tests passed` 都是历史数(逐条计数与增量出处在
`docs/scope-read-points.md` 的「计数」一节)。
那 1 个 failed 是 `exports.zig` 为 root 的 QuickJS 链接步,理由是 8 条 kernel32 undefined-symbol
(`CreateFileA`/`WriteFile`/`CloseHandle`/`GetModuleHandleA`)—— Windows API 在 Linux 上本来就没有,
**不是代码故障**;其余 2 步是它的传递失败(没跑到)。
旧的 GLIBC 措辞已**被实测作废**,不要再当现时约束引用:那一版说「两个链接 QuickJS 的步在这里根本启动不了
(`/lib64/libm.so.6: version GLIBC_2.35 not found`)」,而 2026-10-22 这次运行**没有** GLIBC 那条,QuickJS
的 C 是能编的、失败发生在链接符号解析。别把两个理由混成一个;GLIBC 的旧叙述留在
`evidence/analysis/build_pipeline_status.md` 与 `zig_test_coverage.md`(不可变,不改写)。
历史计数:`293/293`,until `effects/id_mapper.zig` and its 21 tests were retired,
then `272/272` at that time — see §29 of `runtime_444_c1_validation.md`;不要拿这两个旧数当现在的门限。

## 基础:PE + capstone,不需要 IDA

**Static RE runs offline here, no IDA**: `scripts/cap.py` (PE + capstone, rip operands) and `scripts/rttibatch.py`
(PE census) reproduced the full CEffect map locally — 1,805/1,805 rows byte-identical to `evidence/xrefs/ceffect_vtable_map_4_4_4.txt`.
Neither needs a license, a running process, or a paused game.

### `scripts/cap.py` / `scripts/rttibatch.py`

PE 解析 + capstone 反汇编(rip 操作数已解析)与 RTTI/vtable 普查。
`rttibatch.py --effects` 产出 `evidence/xrefs/ceffect_vtable_map_4_4_4.txt`。

### `scripts/disrva.py <start_rva> [end_rva|count]`

**Any RVA range, disassembled offline** — annotates every
rip-relative operand with the RVA it resolves to; this is what pinned the descriptor ctors' store order (§20).

**第二个参数的口径（§30 现场踩过）**:它**不是**结束 RVA —— `a > 0xFF` 时脚本算的是 `end = start + a`,
所以 `disrva.py 0x1D092C0 0x1D09330` 会去反汇编 `0x1D092C0..0x3A125F0`(约 30 MB `.text`)。
要按函数边界读,先 `pdata.py <rva>` 取区间,再传**指令条数**(`a <= 0xFF`)或传**长度** `end-start`。
本函数边界一律以 `.pdata` 为准,不要靠 `int3` 填充猜结尾。

### `scripts/emu_desc.py` — the oracle

**The oracle, offline**: runs the engine's **own** descriptor writers
(`0x1D15270` static, `0x1D152D0` dynamic) under unicorn — image mapped at its preferred base, only memcpy
(`0x2187AC0`) and the reserve (`0x1704B0`) emulated host-side — over all 9,863 table entries
(`python3 scripts/emu_desc.py oracle`). Output: `evidence/xrefs/descriptor_oracle_4_4_4.tsv` plus
`src/dll/scripted/keyword_registry_golden.zig` (56 vectors the Zig builder is tested against).
This is how §18's "byte-for-byte identical" claim became a measurement: **9,863/9,863 agree, 0 divergences**.

## 调用关系与引用扫描

### `scripts/fastcalls.py <rva> [--top N]`

**Who-calls-what, offline**: buckets every direct call/jmp to an RVA by its
`.pdata` function and labels each bucket with the message strings and `__FILE__` tail that function references
(`evidence/xrefs/callers_<rva>_buckets.tsv`). It matches the `E8 rel32` / `FF 15` / `FF 25` **encodings over raw
bytes** instead of decoding 37 MB, so it finishes in ~3 s where a full capstone linear scan hadn't finished in
10+ minutes. Two capstone/PE gotchas it encodes: rip-relative lives in `op.mem.base == X86_REG_RIP` (**not**
`op.reg`, which is `X86_REG_INVALID` for memory operands and silently matches nothing), and this binary's
`__FILE__` strings are full backslash build paths, so filename regexes must match the tail.

### `scripts/riprefs.py <rva>... [--verify]`

**Two more offline searches, for the things `fastcalls` structurally cannot find** (§23):
who reads/writes a **data global**. A rip operand is fully
determined by its encoding (`mod=00, rm=101` + `disp32`), so a byte scan plus arithmetic answers it in
~5 s; `find_refs.py` decodes 37 MB for the same list and needs ~15 min. `--verify` re-decodes each hit
aligned to its `.pdata` start, because a byte match can land mid-instruction.

### `scripts/createsites.py [--gap N]`

who calls a function pointer that **never appears as an immediate**
(e.g. `class_info.create`). Shape-based: `mov r?,[r?+0x28]` within N insns of `call qword ptr [r?+8]`, in
a function that also touches `[r?+0x20]`. Decode must be aligned per `.pdata` function — a linear window
starting mid-instruction resynchronises by luck and had earlier "found" 190 sites in one function.

### `scripts/vtable.py <data_rva> [--slots N --first --callers]`

vtable slots with `.pdata` bounds and the
strings each references. It does **not** prove extent (MSVC merges vtables back to back; §22.5), and §24.4
caught the failure going *both* ways: against `0x2641B38` it stops listing at `+0x78` because `0x18879C0`
is not a `.pdata` start, while `+0x80`..`+0xa8` all hold `.text` addresses. Extents truncate as well as
overrun; only a call site proves a slot is reached.

### `scripts/vptrslots.py [census.tsv]`

across all 1,605 keyword `create`s, where the factory stores the
addresses it materialises, split by instruction: `lea rax,[rip+X]` publishes **X** (a vtable), while
`mov rax,[rip+X]` copies the **value** at global X (not a vtable). Confusing the two is how §22.3 came to
claim a universal `[obj+0]`/`[obj+8]` two-vptr shape; full per-class dump in
`evidence/xrefs/vptr_publish_slots_4_4_4.txt`.

### `scripts/thunkarrays.py`

产出 `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`(3,900 条记录)——keyword→behaviour
静态绑定的机器可读转储(§17)。

## 语料交叉验证

### `scripts/tokencorpus.py [corpus_root]`

A5: joins the replayed descriptor oracle against the
`.rdata` registration census (id agreement) and against the real shipped scripts in `common/`+`events/`
(coverage), and classifies every non-token head word by the mechanism that resolves it
(`evidence/xrefs/token_corpus_crosscheck_4_4_4.tsv`). Two method traps it encodes: `(\w+)\s*=` is not a
head token but *every* LHS including operand values (it "found" 9,858/9,863 descriptors in use — an
artifact of measuring the wrong relation), and a block-only `WORD = {` regex understates the other way,
because scalar triggers (`has_crisis_perk = <x>`) are not blocks. So `HEAD` classifies and `ANYEQ` counts
usage. Findings: 1,609/1,609 keyword ids agree (§25.1), token lookup is **case-insensitive** (§25.5),
and the `count_*`/`any_*` iterator keywords exist in the image only as **two separate strings** that a
name builder concatenates at runtime (§25.4).

## C1 硬门

### `scripts/c1_preflight.py --name NAME [--name ...] [--db effects|triggers]`

**the hard gate before C1**, offline and read-only. `0x1D13270` is GetOrAddToken and §25.5 measured that
its lookup case-folds, so `eax` cannot tell a mint from a collision: a name like `Add_Modifier` would
return `add_modifier`'s `10104` and our insert would **take over an official keyword**. The script FAILs on
an exact or case-folded hit over all 9,863 descriptor names plus the 1,610 registered keyword names,
checks §20's leading-char rule, warns on mixed case, and prints the predicted first id
(`max static 18817 + 1 = 18818`) with its reading rule — larger is normal (§19 lazy accessors keep minting
during start-up), smaller means the collision this check exists for. Exit code 0 = clear.

## live 侧:需要运行中的进程

以下工具**不满足离线前提**——它们 attach 到正在运行的 `stellaris.exe`,读的是活内存。按
`scripts/README.md` 的两条判据(只读 exe 拷贝 = 工具,需要进程 = 探针)它们是**探针**;
但因为它们是维护中的接口,仍留在 `scripts/` 顶层。

### `scripts/fridadis.py` + `scripts/dis.js` — 线性反汇编 live 镜像

对**正在运行的**游戏做一次只读线性反汇编,让 live 列表与离线取证在同一条指令上相遇。

**用法**(两个分支,同一个 attach):
```
python C:/ns/fridadis.py <rva> <instructions>        # 线性:从 rva 反 N 条
python C:/ns/fridadis.py --chain <rva> off,off,…     # 指针链:沿偏移读活指针再反汇编
```
在 Windows 本机跑(`frida.get_local_device()`),两个文件必须先成对上传到 `C:\ns\`。

**它是探针,不是离线工具**:需要运行中的 `stellaris.exe`;缺进程时 `fridadis.py` 在
`next(...)` 那行抛 `StopIteration`——那是"游戏没在跑"的签名,不是工具坏了,回去补环境前置,
不要去改那一行。名字必须全等 `stellaris.exe`(靠 `.lower()` 忽略大小写,别的 launcher 名不算)。

**read-only 自证**:两个文件的头注各自写着"Read-only (no Interceptor, no Memory.patchCode),
so it is safe against an unpaused game"。评审要复核这句话仍成立——`Interceptor`/`patchCode`/
`writeByteArray`/`writePointer`/`Memory.protect` 这些符号只应出现在注释行,一条代码行都不能有。
`dis.js` 渲染 hex 列用的是 `readByteArray`(**读**解码后的字节 span,不是写),没有新增能力。

**硬编码路径 = 上传契约**:`fridadis.py` 里 `JS = r'C:\ns\dis.js'` 钉死,所以上传目标目录**只能**
是 `C:\ns\`;传到别处会得到 `FileNotFoundError`,那不是工具的错。`fridadis.py` 与 `dis.js` 刻意
异名(见本节末尾的配对说明),`.py`↔`.js` 必须同目录成对上传、成对核 sha。

**判读陷阱**:
1. **渲染差异 + 条数口径都不是分歧**。`fridadis.py` 把第二个参数按 **10 进制**读(`40` = 40 条),
   而 `scripts/disrva.py` 按 **16 进制**读(`40` 会被读成 0x40=64 条)。要和 live 那 40 条比,离线必须写
   `0x28`。两侧行形也不同:live 第一列是**距起始 rva 的字节偏移**(`+0x00XX`,不是 RVA),mnemonic 不补宽;
   离线第一列是**绝对 RVA**,mnemonic 补宽到 7。所以判据是空白宽容的 `grep -E`,**不是**逐字 diff。
2. **`--chain` 读的是活指针,不是镜像字节**——那是运行期状态,会随存档变。别把 `--chain` 的输出混进
   线性 disasm 产物,会污染判读。
3. `StopIteration` 见上,是缺进程不是缺功能。

**交叉验证的正确姿势**:与 `scripts/disrva.py` **同 RVA** 比,用 `grep -E` 数命中,**不比 diff**;
"先核版本再核指令"——live 与离线对不上时第一假设是"跑的不是这一份 build"(exe 身份见本文件"前置条件"),
不是"capstone 错了"。第一次实机跑通记录见 `evidence/logs/fridadis_b3_4_4_4.log`,产物见
`evidence/disasm/fridadis_live_0x1D08520.c`。同样的活从**文件**读(不需要进程/游戏)用 `scripts/cap.py`。

## live 侧:§44 的只读线程状态通道

`scripts/c2_init_threadstate.py` + `scripts/c2_harness.py:capture_thread_state` 是**一套**,
两个零成本对照 `scripts/c2_control_cpuwatch.py` / `scripts/c2_control_suspendcap.py` 是它的
判读前置。三个都不写内存、不 hook、不 `FreeLibrary`;`SuspendThread`→`GetThreadContext`→
`ResumeThread` 的顺序由 `finally` 保证不悬空挂起。

**用法**:三个都要在 Windows 侧跑,且都是 scp `c2_harness.py` + 该脚本到 `C:\temp\`(裸名 import,P5)后
`python C:/temp/<name>.py`;`c2_init_threadstate.py` 额外要先有 §42 那份 DLL(它会核 sha256,不是那份字节就拒绝),
两个对照不需要 DLL,只要一个正在跑的**未触碰**游戏(`c2_control_cpuwatch.py [watch_ms] [every_ms]`,默认 20 s)。

**判读陷阱**:
1. **`SuspendThread gle=5` 有两种意思,单看它无法区分**。句柄缺权限和「线程已经退出」报的是同一个
   错误码 —— 把它们分开的是 `scripts/scratch/2026-10_threadhandle_matrix/`(4/4 格:活线程两种句柄都读得到,
   退出线程两种句柄都 gle=5)。所以读到 gle=5 先怀疑后者,别去改 `OpenThread` 的权限位。
2. **`pr_user_us` 一动不动,可能是仪器坏了**。用 `c2_control_cpuwatch.py` 打未触碰的游戏对照:它 20 s 前进
   约 12.8 s user ⇒ 计数器是活的,那句「冻结」才是真的停。
3. **线程状态通道给的是 teardown 的形状,不是执行的形状**。内存单调下降 + 80 ms 起就 suspend 不掉,
   这个组合的意思是进程已经开始终止 —— §42 把同一种序列读成「6.9 s 零分配段在 QuickJS 代码内」,那条读法已撤回。
4. 名字里的 `threadstate` 不是能力声明:它**只读 context 与 times**,拿不到栈,也设不了线程。

## §45 修复循环的两个维护工具(从 `scratch/2026-10_abortexit/` 提升)

**新旧名映射(本仓库的改名约定,同上面 `PLAN.md` 那条)**:
`scripts/scratch/2026-10_abortexit/dll_abort_repro.py` → **`scripts/c2_selfabort_repro.py`**;
`scripts/scratch/2026-10_abortexit/ubsan_site.py` → **`scripts/dll_ubsan_site.py`**。
两个 scratch 原件**字节不动**(`evidence/logs/c2_selfabort_4_4_4.log` 按 basename 记了出处,§45 的
log 还逐字引了它们的输出),提升是**复制**不是移动。两处都留了旧名一句。

### `scripts/dll_ubsan_site.py [dll] (site <类型名子串> | func <vma>)`

无符号、无 debug 段的产物里,把 UBSan panic 钉到源文件行号:只读 DLL 文件,用 `.rdata`/`.data`
里的 `TypeMismatchData` 记录(文件名、行、列、类型描述器名字)+ `.pdata`(x64 异常目录)的
`{begin, end}` 函数区间。第一个参数**不是 `site`/`func` 就是 DLL 路径**(按小写比较模式名;
所以 `C:\temp\S43_new.DLL` 这种大写扩展名、以及没有扩展名的 scp 文件名都是路径 —— 旧规则
「以 `.dll` 结尾才算路径」会把它们当成模式,于是**分析仓库默认的产物却打印出你给的那个参数**,
一个没有报错的错答案)。没有路径参数时才落到仓库自己构建的
`zig-out/bin/stellaris_quickjs.dll`,按**本文件位置**解析,不是按 cwd);`image_base` 从镜像自己的
optional header 读,没有任何地址是写死的 —— 换一份产物就把 RVA 重算一遍。

**退出码有三种意思,调用方必须能分开**:0 = 读到了且有匹配;1 = 读到了但**没有**匹配 —— 这是
一个结论,不是故障。**1 有两种不同的意思,别把它们并成一句话**:「该类型名零个检查点 / `func`
的地址不在任何 `.pdata` 函数区间里」和「命中了函数、但**该函数代码不引用任何 `TypeMismatchData` 记录**」
是两件事(工具分别打 `rva 0x… is not inside any .pdata function entry` 和
`this function's code references no TypeMismatchData record (other UBSan record
kinds are not decoded)`),后者的含义是"这一帧没有
可归因的捕获",不是"这里没有 UBSan";**2 = 调用本身是错的,所以对产物什么都没下结论** ——
工具没能读到产物(路径不存在、不可读、截断、非 PE32+),**或 `func` 拿到的数低于镜像基址**
(那是 panic 栈打的裸 RVA,不是 vma;本批(§47 前置)加的口径护栏,打一行 stderr 并把该传的
`image_base + rva` 原样回显)。修复循环会拿 `c2_selfabort_repro.py` 送来的任意文件名调它,
把 2 误读成 1 就是「这份产物没有检查点」的假结论 —— 两条 exit-1 消息与 2 的措辞故意不同形,
护栏就是为了不让"调用写错了"长得像"结论"。**本批围栏实测**:`scripts/test_c2_harness.py`
**134 passed**(133 + 新增 1 条),`scripts/test_scripts_layout.py` **23 passed**。

```
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll site JSMallocBlockHeader
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x18000bd9b
```

`site JSMallocBlockHeader`(2026-10-22 实测于当前产物 `77c0c35e…c11ad0`)=
**141** 个检查点,其中 `quickjs.c:1494:12` 恰好 1 条;`func 0x18000bd9b` = 持有该地址的函数
`rva 0xbd70..0xbdf3`(**131 bytes**),引用记录 `quickjs.c:1494:12 member_access
type='JSMallocBlockHeader'`,`record_rva=0x5ab430 loaded_at=0x18000bd8c` —— 与 §45.3 记的同一条。
同一函数还 `call 0x499cc0`(`__ubsan_handle_pointer_overflow`),带的是 `0x5ab450` 处的 16 字节
`PointerOverflowData`(同为 `:1494:12`);它**不在**上面这条记录的输出里 —— 见判读陷阱 7。

**判读陷阱**:
1. **`func` 打印的是 `.pdata` 区间和该区间加载了哪些记录,不是链接期函数名。** 帧归属靠的是
   区间 + 记录引用;要说"这是 `__JS_NewAtomInit`",得去读那几行 C 本身(§45.3 就是这么做的)。
2. **"地址不在任何区间内"证明不了任何事 —— 这份解析是不完整的。** §45.4 记的 **3,042** 条区间是
   **当时那版解析器**在同一份字节(`.text` 0x4c8b86,§42/§45 产物)上的输出,不是那份产物的属性;
   现在的 `runtime_functions` 在同一份字节上出 **4,818** 条,同一份工具跑当前产物(`.text` 0x4c9be6)
   出 **4,824** 条(现场可复测)—— 差 6 条的是字节,差 1,776 条的是解析器版本。两个数都覆盖不了
   镜像里的函数,所以"没命中"既可能是地址在数据/填充里,也可能只是 `.pdata` 这条解析没读全 —— 分不清。
3. **panic 栈每帧打印的是 `ip − 1`**,即调用指令**前一字节**,所以那个数值本身既不是出错指令也不是
   调用点。直接把它传给 `func` 没问题(`.pdata` 查找是闭区间 `begin <= rva < end`),但别把打印值
   当成指令地址来解读。
4. **和冻结原件比计数要先去重。** 原件的 `.rdata`/`.data` 扫描没有按段定界(从段起始一路扫到 EOF),
   而这份产物的记录**全部**落在 `.data` 里,于是每个记录被 `.rdata` 那趟再过一遍:原件
   `site JSMallocBlockHeader` 打 **282** 行,其实是 **141** 个不同记录(成对共享同一个
   `record_rva`)。提升版把每趟扫描定到该段自己的 raw 字节 ⇒ 141 行,与 §45.3 记的数一致。
   **记录的集合本身没变**,只变了重复。
5. **同一段扫描的上界要按「读多少」算,不是按「步长」算。** 记录之间隔 32 字节,但被读的字段
   只有 26 字节(`struct.calcsize("<QIIQBB")`),原件的上界 `end - 32` 因此**够不着**落在某段最后
   32 字节里那条完全可读的记录。提升版改成 `end - 26 + 1`。当前产物上两个界给出**逐条相同的
   13,693 条记录**(`site JSMallocBlockHeader` 仍是 141,`quickjs.c:1494:12` 仍恰好 1 条),所以这条
   不改变任何已记录的计数 —— 它是给下一次链接准备的,届时布局器未必不把记录放进那段尾部。
6. **记录行不带 `[ubsan_site]` 前缀,所以按前缀过滤会把证据丢掉。** `site`(`:256`)与 `func`
   (`:285`)的 header 行带前缀,而每条记录行是**两个空格**开头(分别在 `:259`/`:299` 打印)—— `grep -F '[ubsan_site]'`
   (或转义 `\[ubsan_site\]`)只留下 header。本批(§47 前置)对一次真实输出(`func 0x1800055f5`)实测 = 7 行
   (2 行 header + 5 行记录),过滤后**只剩 2 行**,5 条记录全丢。更糟的是另一种写法:
   不加转义的 `grep '[ubsan_site]'` 是**字符类**(任一字符 u/b/s/a/n/_/i/t/e),同一份
   7 行输出**一行都不会被滤掉** —— 看起来"过滤生效了、什么都没丢",其实过滤根本没起作用。
   两种写法都别拿来取证据:要记录行就 `grep '^  '` 或 `grep 'quickjs\.c:'`(同一份输出各实测
   5 行)。
7. **`#0x…` 标注只能和 `TypeMismatchData` 记录的 `record_rva=` 比。** `func`/`site` 只解码
   `TypeMismatchData` 的 kind 3–11(`scripts/dll_ubsan_site.py:93`,`:196` 还要求 `log_align <= 7`),
   其它 UBSan 记录种类**不解码** —— 例如 `PointerOverflowData` 是 16 字节、只有 `SourceLocation`,
   没有类型描述器与 kind 字节,所以它没有 `record_rva=` 行,"no record" ≠ "no handler"。实例:
   `js_rc` 的 131 字节函数有两次 handler 调用(`0x498170`/`0x5ab430` 的
   `member_access type='JSMallocBlockHeader'` 与 `0x499cc0`/`0x5ab450` 的
   `PointerOverflowData`),`func` 只打出前一条;`evidence/disasm/js_rc_trap_77c0c35e.md` 两次都列。
   所以一个函数"恰好一条记录"只意味着**恰好一条可解码的 `TypeMismatchData`**,不是只有一次
   UBSan handler 调用。
8. **报告里的 `pointer == 0` 可能是编译期常量,不是被检查的那个运行时指针。** §47 的实例:fallback
   `offsetof`(`cutils.h:43-45` 的 `&((type *)0)->field`)把一次**空成员访问**编译进 `container_of`
   (`quickjs.c:1494`),于是 `type_mismatch` 的指针操作数是字面 0;handler 文本里的 "null pointer"
   因此**不是**「运行时指针为 0」的观测,allocator 形状或记录器数据都不能拿来判它。

### `scripts/c2_selfabort_repro.py <dll_path>`(Windows 侧;§45 的自检器)

把出货字节装进**本脚本自己拥有的**子 python,按实机那枪的门序跑 `C2Sanity` → `C2DiagQJSInto`,
零游戏、零注入、零 dispatch:子进程若在没人碰它的情况下以退出码 3 死掉、且 witness 文本与实机逐字
相同,"host 死了"这件事就与 `stellaris.exe` 无关。修复循环的形状(§45.4):**每改一次 QuickJS/
allocator 就重跑这一条命令**,不需要第二支枪。

```
scp scripts/c2_selfabort_repro.py Windows_Jiaolong:C:/temp/     # 单文件,无裸名 import 依赖
python C:/temp/c2_selfabort_repro.py C:/temp/<新文件名>.dll      # 退出码 0=复现到 abort 签名,1=没有,2=路径没给/不存在
```

关键行(子进程的逐字 echo,父进程的带 `[repro] ` 前缀,`VERDICT` 永远是最后一行):
`BASE`、`LOGADDR`、`RECORDER ok|absent`、`SANITY`、`WITNESS '<g_diag_log>'`、
`MFREC <seq> <watch|post> '<渲染>'`、`SURVIVED rc=<n>`、`LOG '<调用方 buffer>'`、`[repro] VERDICT: …`。

**为什么 `MFREC` 是一条读取线程,而不是 `C2DiagQJSInto` 之后的一次 dump**(这条设计**不要**被
"简化"掉,§45 就是理由):子进程的主线程是在 `C2DiagQJSInto` **内部**abort 的 —— witness 停在
`new_rt MmMmMm`,`SURVIVED rc=` 从来不打印。所以调用之后再读永远轮不到,Task 3 将没有记录器数据可判。
读取线程每 ~2 ms 调一次 `C2DiagMfRecordsInto`,只在渲染**变了**时才发一行,自己封顶 400 次,并且
在门序跑起来**之前**启动。调用后那一次**保留**(`post` 标签、无条件打印):Task 4 修好之后调用会返回,
那一行是 Task 4 验收要读的。代价写明:在一个正死的进程里多一个线程是扰动 —— 于是"子进程活了"
在缺陷仍在时是 Task 3 的**停下来报告**条件,不是通过。

**判读陷阱**:
1. **`VERDICT` 的两半都吃重**:`returncode == 3` **且** stdout 里没有 `SURVIVED`。只有 3 不算 ——
   harness 早就警告过被进程终止杀掉的线程会把进程状态当自己的退出码报回来(§44);`0xC0000409`
   (`os.abort()` 的 fastfail)也不是 `abort()` 的 3(§45.1 量的就是这一对)。
2. **`MFREC` 行里 `filled` 是 `_` 的那一行是竞态伪影或"没走到出口",不是分配器行为。** 渲染层对
   「槽在快照中途被重写」的行就是画成未填充形(`<kind>_`,kind 保持 `M`/`F`/`R`/`_`),并把指针换成
   16 个短横(`ptr=----------------`),所以**哨兵 `0x1` 与假零永远不会以指针的形式出现在文本里**;
   看到 `_` 不要读成"分配返回了 NULL"——真的返回 NULL 是 `filled=x` 且 `ptr=0`,那是另一种形状。
3. **`Fx size=` 是被释放那块内存**自己记下的 size(在 entry 时从块头读的),不是请求大小。**只有
   `M`/`R`(malloc/realloc 两个请求)的 `size` 才是请求**;Task 3 的判定表读 `size == 0` 时**只看
   `M`/`R`**。把 `F` 混进去的错法很具体:`free(NULL)` 合法地记 `size=0 ptr=0`(没有任何块被释放),
   它会被读成"发生过一次零大小的分配请求"——那是另一个事实,而计划的判据要的正是后者。
   (`quickjs_wrapper.c` 的 `mf_rec_free_size` 就是为这条区分写的。)
4. **渲染按字面 token 解析,不要按列。** 每行是
   `"<kind><filled> size=<十六进制,不补零> ptr=<十六进制,不补零> st=<正好 12 位十六进制>\n"`,
   8 行、oldest→newest;两个十六进制列**不定宽**,所以只能用 `" size="`/`" ptr="`/`" st="` 切。
5. **`RECORDER absent`**:被测产物里没有 `C2DiagMfRecordsInto` 这个导出(比 §45 更早的字节)。
   这**不是**工具坏了 —— 那条通道确实不存在,`MFREC` 一行也不会有,`WITNESS`/`VERDICT` 照常可用。
   导出地址按名字从注入那份的导出表解析(P10),所以工具不需要任何 RVA。
6. `SANITY` 必须是 42;不是 42 时后面看到的一切都不属于那条门序(和实机同样的一句话)。
7. **退出码 1 有两种意思,工具自己会说是哪一种**:真的没自杀(有 `BASE`、没死在 3),**或**子进程
   压根没把 DLL 装进来(平台不对 / 路径不对 / 装载失败 —— 于是没有 `BASE` 行)。后者打的是
   `VERDICT: inconclusive`,它对"这份产物会不会自杀"**什么都没证明**,不要当成阴性结果读
   (判据是纯函数 `child_loaded_the_dll`,120 s 超时也走同一条 `inconclusive` 形状)。

## 我们自己产物的反汇编(`scripts/pe_disrva.py`)

`scripts/disrva.py` 与 `scripts/cap.py` 反汇编的是**游戏**:它们只收 RVA,自己去找 `stellaris.exe`
(`NS_STELLARIS_EXE` / 固定候选)。`scripts/pe_disrva.py` 反汇编的是**你给的那份 PE**,路径是必填的
第一个位置参数 —— 本仓库用它读自己构建的 `zig-out/bin/stellaris_quickjs.dll`(§45/§47 的 `js_rc` trap),
不读游戏,所以没有默认路径、也不受 `NS_STELLARIS_EXE` 影响。

```
python3 scripts/pe_disrva.py <pe_path> <rva_start_hex> [<rva_end_hex>|<count>]
python3 scripts/pe_disrva.py zig-out/bin/stellaris_quickjs.dll 0xbd70 0xbdf3   # end 不含
python3 scripts/pe_disrva.py zig-out/bin/stellaris_quickjs.dll 0xbd70 40       # 40 条(默认 64,上限 4096)
```

- 第三个参数:`0x` 开头 = **结束 RVA,不含**;纯十进制数字 = **指令条数**。所以小的十六进制结束 RVA
  必须带 `0x`(裸 `100` 是 100 条,不是 rva 0x100)。
- 每条绝对 `call`/`jmp` 目标与每个 `rip+disp` 操作数标 `  #0x<rva>`;`#0x` 后是**相对 image base**
  的 RVA(image base 从该 PE 的 optional header 读),所以能和 `dll_ubsan_site.py` 的
  `record_rva=` 比 —— 但那条只对**它解码的 `TypeMismatchData` 记录**成立(见上一节判读陷阱 7)。
- **只解码带 `IMAGE_SCN_MEM_EXECUTE`(`0x20000000`)的段**。RVA 0 落在 PE 头里,capstone 会把 `MZ...`
  当指令解出来,所以工具在喂给它之前按 section 位拒绝。可执行段外的起点、文件映射之外的起点、或解出
  **0 条指令**,一律退出 1 —— 那是「这段不是代码」的结论。
- 退出码三义与 `dll_ubsan_site.py` 一致:**0** = 至少解出 1 条;**1** = 不是可执行代码 / 0 条;
  **2** = 调用错了(缺参、非 hex、文件读不到、非 PE32+、end < start、count <= 0),一行 stderr、无
  traceback。
- 上限 4096 条,超出打 `; truncated at 4096 insns`;头行给 `N insns, M bytes`。**未截断时** end 模式下
  `M` 等于 `end - start`;可一旦超过 4096 条(或 end 越过段尾被裁剪),头行的 end 是**有效(裁剪后)
  的 end**,`M` 小于请求的 `end - start`,同时带上截断提示(实测 `0xbd70 0x800000` 头行打
  `0x4cac00` 并附 `; truncated at 4096 insns`;未截断的 `0xbd70..0xbdf3` = 131 字节 = 40 条)。

**判读陷阱:**
1. **反汇编证明的是「被检查的是哪个表达式」,永远不是运行时值。** 它读得出 `0xbd70` 的 `test r8,r8`
   在 `add rcx,-8` 之前、测的是原始指针;它证明不了那一枪里 `r8` 是不是 NULL。
2. **`#0x...` 是 image-base-relative 的 RVA,不是 VA**;rip 目标按 `address + size + disp` 算,不是从
   指令起点算。
3. **clang 的「减 8」可能是 `add reg,-8`**:本产物里 `container_of` 的 header 偏移是 `48 83 c1 f8`
   (`add rcx,-8`)。按 mnemonic 找 `sub` 会漏 —— 读语义,不读拼写。
4. **0 条的退出 1 是结论不是失败**,但别把它读成「这里没有 sub」:先看 stderr 是「不在可执行段」还是
   「段内 0 条」,两者都与「成功但没有该指令」分开。
5. 想验证「0 条 → 1」可以拿 RVA 0,但它走的是 section 门,不是 capstone 解失败;两条路都退出 1,
   理由不同,不要混成一条判据。

## IDA headless 现状(环境状态,非规则)

**IDA MCP**: registered in `~/.qoder/settings.json` (`/home/lofibass/.local/bin/idalib-mcp --stdio --unsafe`).
**Status updated 2026-09-29**: headless open now works — session `f3ea6101` is live on the local
`stellaris.exe` copy (there is also a `stellaris.exe.i64`, 585 MB, produced by that headless open, which
contradicts the earlier "the `.i64` stays on Windows" note; neither file was hand-edited).
The earlier `License not yet accepted, cannot run in batch mode` failure is **no longer reproducible**.

两条**规则**不随状态改变,留在 `AGENTS.md`:不许绕过 license 守卫分支,以及本 IDB 上不得调用
`ida_auto.plan_and_wait`。

## 一次性探测脚本

历次取证的一次性探针已经不在 `scripts/` 顶层,按取证批次归进 `scripts/scratch/<年-月>_<主题>/`,
每个目录自带 README(逐行列出「这个文件当时在回答哪个问题」):

| 目录 | 内容 | 判据 |
|---|---|---|
| `scripts/scratch/2026-09_frida_hot_site_spies/` | `fs*.py`、`body*.py`/`body.js`、`spy*.{py,js}`、`strs*.py`、`kv*.py`、`vt.py`/`vtlive.{py,js}`、`walkdb.*`、`prologue.*`、`caller*.py`、`regfn.py`、`missstr.py`、`strdump.py` | 需要运行中的游戏 + Frida |
| `scripts/scratch/2026-09_offline_hardcoded_oneshots/` | `callscan*.py`、`prol_exec*.py`、`rtti_check*.py`、`rtti_offline.py`、`refscan.py`、`sec.py`、`pedump.py`、`verify_base.py`、`dumpvt.py`、`vtcheck.py`、`kwmeta.py`、`cap2.py` | 只读 exe 拷贝,但**路径写死成 `D:\SteamLibrary\…`** |
| `scripts/scratch/2026-09_frida_detour_era/` | `restoreexec.py`、`nsunload.py`、`peekexec.py`、`read_remote_mem.py` | detour 路线的善后 |
| `scripts/scratch/2026-10_newrt_allocmap/` | `allocmap.c` | 同一份 vendored `quickjs.c` 在 Linux 上离线跑 `JS_NewRuntime2`,零游戏(§43) |
| `scripts/scratch/2026-10_threadhandle_matrix/` | `threadhandle_matrix.py` | 需要进程,但目标是自己 spawn 的子 python —— 不碰游戏、不注入我们的 DLL(§44.3) |
| `scripts/scratch/2026-10_abortexit/` | `dll_abort_repro.py`、`ubsan_site.py` | 前者把出货 DLL 装进自己的子进程看它会不会自杀(零游戏);后者只读 DLL 文件,用 `.pdata` + UBSan 记录做无符号符号化(§45)。**两个脚本已提升为维护工具(`scripts/c2_selfabort_repro.py`、`scripts/dll_ubsan_site.py`,见上一节),原批次冻结留档、字节不动** |

它们**不作为接口维护**——可以失效,但不要在新结论上重犯它们已踩过的口径错误(见各节"陷阱"段)。
结论已进 `evidence/` 与 `runtime_444_*.md` 三卷对应 §。

**`evidence/` 里按 `scripts/<name>` 记的出处指的就是这些文件,现在同一个 basename 在
`scripts/scratch/<批次>/<basename>`。** 取证记录不改写,对应关系靠 basename 一一对上;
这批脚本移进来时**一个字都没改**,所以路径之外的任何"修复"都不构成重跑它们的理由。

**`.py`↔`.js` 配对按「同目录内被引用」判定**(`scripts/test_scripts_layout.py` 的 `violates_pairing`,只扫顶层,
所以上面这些 scratch 目录里的孤儿 `.js` 不算违规),`fridadis.py`↔`dis.js` 与 `scan444.py`↔`anchor444.js`
是**刻意异名**(`C:\ns\` 是线上路径),不是待修的历史遗留。

A 目录那批还依赖仓库外的现场文件:`C:\ns\deep.js`、`C:\ns\deep2.js`(以及 `cap2.py` 要 `C:\ns\cap.py`、
`rtti_offline.py` 要 `C:\ns\spy4_table.txt`)——**这些 `.js` 不在仓库里**,只在当时那台机器上,
所以现在直接跑会失败,这是预期而不是回归。
