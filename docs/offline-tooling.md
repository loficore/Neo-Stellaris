# 离线 RE 工具目录与判读陷阱

本文件收录 `scripts/` 下**长期有效**的离线探测工具的完整判读说明:每条命令的输出、
它编码的 capstone/PE 陷阱、以及曾经导致错误结论的度量口径。`AGENTS.md` 只保留一行一条的索引,
用到哪个脚本时再来读这里。

结论本身(§17–§60)在三卷取证日志 `evidence/analysis/runtime_444_*.md`——§16–§23 在
`runtime_444_keyword_pipeline.md`,§24–§60 在 `runtime_444_c1_validation.md`;本文件只讲**怎么量**。

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

**`--all-vtables` —— 不过滤的那一张(`evidence/xrefs/vtable_candidates_all_4_4_4.txt`)**:
`python3 scripts/rttibatch.py --all-vtables [--min-run 3]`。判据**只看形状** —— `.rdata` 里每个 8-对齐位置,
只要从它起连续 ≥ `min_run` 个 qword 落在 `.text`,就产一行,**绝不读 `RVA_BASE_EXECUTE`**;而且**一个 run 里的
每个起点都单独成行**(§17 那张下限表的表首正是这种中途起点,只报极大 run 的开头就会把它们全丢掉)。
每行带 `run=` 与前三个槽的 RVA 原值。4.4.4 上 `min-run=3` 是 **172,296 行**(≈14 MB 明文,gzip 后 1.2 MB)。

**判读陷阱(这条是 §17 那句「覆写了 Execute 的类一个都不在」的直接解药,也是最容易读过头的地方):
「形状过」不等于「是 vtable」,更不等于「是 CEffect 家族」。** 函数指针数组、`switch` 跳表、虚表片段、
以及任何「连续几个代码地址」的静态数据都会过这道形状判据 —— 172,296 与 1,805 之间那 16 万多的差**不是**
「发现了 16 万个新类」。往下筛只有两个字段可用:**`run=` 长度**与 **`slot1` 原值**(slot1 == base Execute
`0x1D08520` 正好把 §14 那张 1,805 的下限集取回来,这也是 `test_the_floor_map_is_a_subset_of_the_unfiltered_candidate_set`
钉住的关系);除此之外没有别的静态滤网,所以任何「这张表是谁」的结论都得另找证据(名字池、行为、实机)。

**`--who-tables <rva[,rva]> [--candidates PATH]` / `--who-lea <rva>` —— 两张集合的离线 join(§57)**:
`slot_hits()` 按候选的 `vtable_rva` **回到镜像里重读前 8 槽**逐个比对(不是只看产物带出的 `slot0..slot2`),
`lea_sites_to()` 把 `rip_refs()` 那条 modrm 判定推广到**整个 `.text`**,返回指令起始 RVA。接口一律 **RVA**
(与 `AGENTS.md` 索引、下限图、候选集同口径),命令行里不出现带 image base 的数。`--candidates` 默认读
`vtable_candidates_all_4_4_4.txt`,所以不必在枪机上重跑 `all_vtables`。

**判读陷阱:`--who-tables` 那张「命中 N 张表」的表,不能拿来证明「引擎复制了表」。** 两个独立原因,
每一个都足以让这条推断作废(§57 就是在核这一条):
① **候选集对同一段指针数组产出多个重叠起点**(`rttibatch.py --all-vtables` 的候选枚举为了让下限集成为子集必须这样构造),所以行数永远
大于物理槽地址数 —— 4.4.4 上实测 **7,867 行 / 7,832 个表首 / 992 个物理槽**;
② **靶子若是共用实现,命中数就正比于「继承它的兄弟类个数」,与复制无关** —— `0x3AFD30`(donor 表 slot[1]
的 Execute 覆写)在镜像里以静态 qword 出现 **538** 次,`0x3B01A0` **454** 次。
收紧到「前四槽与目标表逐槽相等」把 7,832 压到 5,这一步是有用的枚举,但**仍分不出「另一份表」与
「同基类未覆写前四槽的兄弟类」** —— 两者在字节上就是同一串。要判身份,得问运行时 `[self+0]`(§57 的下一枪)。
`--who-lea` 另有两条边界:它只认 `48/4C 8D|8B mod=00 rm=101` 这一种编码(不认绝对立即数寻址,也不认
`.rdata` 里的静态持有),而**站点数 0 不等于没人用** —— `0x3B01A0` 就是 0 站点,因为它只以静态槽值存在。

### `scripts/disrva.py <start_rva> [<count>|<length>|--end=<rva>|--len=<n>]`

**Any RVA range, disassembled offline** — annotates every
rip-relative operand with the RVA it resolves to; this is what pinned the descriptor ctors' store order (§20).

**第二个参数的口径（§30 现场踩过）**:裸数字**不是**结束 RVA —— `a > 0xFF` 时脚本算的是 `end = start + a`,
所以 `disrva.py 0x1D092C0 0x1D09330` 会去反汇编 `0x1D092C0..0x3A125F0`(约 30 MB `.text`)。
要按函数边界读,先 `pdata.py <rva>` 取区间,再传**指令条数**(`a <= 0xFF`)或传**长度** `end-start`。
本函数边界一律以 `.pdata` 为准,不要靠 `int3` 填充猜结尾。

**`--end=<rva>` / `--len=<n>` 是自 §59.9 起才有的显式形式**(§59.9 那条「往上定帧构造点」的零枪路线要按真边界取区间),
**取证卷里旧命令一律按旧语义复现** —— 上面那个 `>0xFF` 启发式没有被改写,只是搬进了可测的纯函数 `parse_range`;
裸数字口径、头一行 `; <exe>  <sec> RVA 0x…  (N insns)` 的条数、rip 注解写法全部不变
(`scripts/test_disrva.py` 钉语义;影子副本基准用**已冻结的改动前修订** `git show 02eb551:scripts/disrva.py`(= 本分支第一次动 `disrva.py` 之前的那个提交,`git log --oneline -1 488b1fc^` 与它相同)逐字节钉输出 —— 意图是「重跑旧实现,输出与改动前逐字节相同」;**基准不写 `HEAD`**,合并之后 `git show HEAD:scripts/disrva.py` 就是新实现自己,自比自恒等,这条钉会静默失效)。
`--end=` 的第二段就是结束 RVA(不含),`--len=` 是字节长度;两者与裸数字一样**不猜**:结束 RVA 低于起始、
非十六进制、负数、`--flag` 缺少数值、未知 flag —— **任何不可判 = 拒绝**,一行 `[disrva] …` 进 stderr 并退出 2。

**`import disrva` 没有副作用**:旧版本在导入时就读 46 MB 镜像、候选链全不存在就 `sys.exit`,现在读镜像是懒加载,
`resolve_exe()` 返回 `str | None` 而不是退出 —— 所以别的离线工具可以直接 import
`parse_range`/`resolve_exe` 而不必先有 game data。只有 CLI 在候选链全落空时才报
`[disrva] 没有可读的 stellaris.exe 拷贝(设 NS_STELLARIS_EXE);候选链 <列表>` 并退出 2。

### `scripts/emu_desc.py` — the oracle

**The oracle, offline**: runs the engine's **own** descriptor writers
(`0x1D15270` static, `0x1D152D0` dynamic) under unicorn — image mapped at its preferred base, only memcpy
(`0x2187AC0`) and the reserve (`0x1704B0`) emulated host-side — over all 9,863 table entries
(`python3 scripts/emu_desc.py oracle`). Output: `evidence/xrefs/descriptor_oracle_4_4_4.tsv` plus
`src/dll/scripted/keyword_registry_golden.zig` (56 vectors the Zig builder is tested against).
This is how §18's "byte-for-byte identical" claim became a measurement: **9,863/9,863 agree, 0 divergences**.

## 离线重问实机 artifact(读已入库产物,不读 exe、不起进程、不要枪)

### `scripts/scope_reclassify.py [--tsv PATH] [--floor PATH] [--all PATH] [--json PATH]`

**把同一批 scope 候选问两张 vtable 集**:§56 那发只读采样枪留下的
`evidence/logs/scope_probe_v2_4_4_4.tsv` 的 99 条 `object` 行,同时对着 1,805 条下限集
(`ceffect_vtable_map_4_4_4.txt`,**import `c2_scope_probe.load_vtable_map` 复用**,不重写解析)和
172,296 条形状集(`vtable_candidates_all_4_4_4.txt`,`rttibatch.py --all-vtables`)分四桶:
`floor_hits` / `new_only_hits`(只有新集看得见)/ `still_no` / `undecidable_no_rva`。
四桶互斥且和为 `total`,由 `scripts/test_scope_reclassify.py` 钉住。产物:stdout 七行计数
(含 **`floor set` / `shape set` 两个输入集大小**)+ `--json` 全量(含 `new_rows` 每行的 `slot1` 与
run-length,以及 `input_sets`)。**形状集解析出 0 行就抛错**(`load_candidate_map` 拒绝返回空集):
`new_only_hits=0` 与「这份文件我读不懂」在计数里长得一模一样,而 §56.9 那一版差点把前者当结论 ——
行语法(`slot0 0x…`,两列)一旦错一格,172,296 行会被全部静默跳过。两个集的大小打在读数旁边,
就是为了让「0」永远带着它的分母。

**它不读 exe**,所以不受 `R-env` 约束、不需要 `NS_STELLARIS_EXE`;需要分节普查(判一个 RVA 落在
`.text`/`.rdata`/`.data`)时那是另一件事 —— 本次用的是
`scripts/scratch/2026-10_scope_shot/ns_scope_ptr_shape.py`(一次性探针,不是维护接口)。

**判读陷阱 1(本节实测)**:`still_no` 多**不等于**候选不是对象。99 条里 83 条能解出 RVA,而它们的
`vptr_rva` 分节普查是 `.text` 64 / `.rdata` 14 / `.data` 3 / 镜像外 2 —— 代码 RVA 永远不可能在任何
vtable 集合里(两张集都只扫 `.rdata`),所以「新集一条都没加」在这个层是**恒真**,不是结论。
往下筛之前先问:取的是哪一格?`vptr_rva` 是 `[[root+off]]`(多读一层),候选自己那一格是 `ptr`。

**判读陷阱 2**:「不过滤」只指**不按 `slot[1]` 过滤**,新集仍然只扫 `.rdata`,而且它按形状产出
**每一个** run 起点(下限集必须是它的子集,这是构造要求),所以一张已知表的**内部偏移**也会命中。
`.data` 里的 vtable、以及中途偏移,都是「无法判定」而不是「新集看到的类」。

## 站点离线反解(`scripts/exec_frame_sites.py`,读 artifact **也**读 exe 拷贝)

### `scripts/exec_frame_sites.py --probe <tsv> [--census <tsv>] [--out <tsv>]`

**重读 exe 字节、按字节反解 shot 记录的真实 call site —— 不是 `-5` 估值。** 背景在 §59.7 与下面
`c2_scope_probe` 一节的 CALLERS 口径:枪记的是**返回 RVA**,`E8 rel32` 是 5 B,而每一次 vtable 槽
派发(`call qword ptr [rax+8]`)只有 3 B;把 `ret-5` 当站点会把 mem 形状的点画进前一条指令中间,
census join 落空,`func=-` 于是被误读成「没人调用」。`c2_scope_probe.py` 的 caller 行键已降回返回 RVA,本工具是「精确
反解」的另一半。**exe 候选链 import `disrva.resolve_exe`**(同一份 `NS_STELLARIS_EXE` 口径,不复制
第二份路径表,也不需要镜像基址 —— 全部地址运算在 RVA 空间对消)。

**用法**:`python3 scripts/exec_frame_sites.py --probe evidence/logs/scope_probe_v4_4_4_4.tsv`
(`--census` 默认 `evidence/xrefs/exec_frame_callers_4_4_4.tsv`,`--out` 默认
`evidence/xrefs/exec_frame_sites_4_4_4.tsv`)。caller 行两代形状都认:新版 `c2_scope_probe.py` 起 detail 带 `ret=`
直接用;v4 及更早键是估值,`ret = key + 5` 且计入汇总的 `assumed` 计数 —— **assumed 行读出的
site/func/census 一律以反解结果为准,估值只是对账**。

**候选边界怎么枚举**(这是判读的全部依据,不是「取最短/取最长」):回看窗 `[ret-16, ret)` 内对
**每一个字节偏移**起解码 capstone 第一条指令,只保留「结束地址恰好落在返回点」且
`mnemonic ∈ {call, jmp}` 的边界。候选 >1 ⇒ `form=ambiguous`、`site=None` —— 歧义是真实的字节重叠
(例:REX 前缀让 `48 FF 50 08` 与 `FF 50 08` 都恰好结束于同一点),不替他选;候选 0 ⇒ `form=none`;
唯一候选判 `form`:`E8`→`rel32`(若目标首字节是 `EB`/`E9` 跳板 →`thunk`),`FF /2`→`mem`(寄存器
间接 `FF D0` 同档,`insn` 列给真实反汇编文本),唯一一条 `jmp` 边界 →`thunk`。

**join**:`func_start`/`func_end` 来自 `.pdata`(延迟 import `pdata.func_of`;import/查找失败是**诊断
退出**,不是静默 `func=-`),键是**反解出的真站点**;站点不可判(ambiguous/none)时退回用返回 RVA
查函数边界 —— 返回地址与调用点同属一个 RUNTIME_FUNCTION,函数归属仍是 datum。
`census_origin`/`site_in_census` **只认真站点**:没 join 上就写 0,不解释原因(解释留给取证卷)。

**拒绝语义**:没有可读的 exe 拷贝 → 一行 `[exec_frame_sites] …` stderr + 退出码 2(无 traceback);
回看窗缺任何一个字节 → `SiteDecodeError` → 同样诊断退出 —— **读不出来 ≠ 窗口里没有**,绝不把它
写成 `form=none`。

**判读陷阱(本节)**:
- `site_in_census=0` **不是矛盾,是待办**:普查表是 §53 按当时判据切的,没覆盖的站点本就不在表里
  (v4 的 `0x1c4369e → site 0x1c4369b`(`form=mem`)正是这种;§59.7 末句)。
- `form=none` 的全局判读在文末 `c2_scope_probe` 一节的**判读陷阱 11**:它只说明返回 RVA 前 16 字节
  内没有 call/jmp 边界,**不等于没人调用**。
- 本工具读的是**磁盘拷贝**;游戏版本换了、而产物里的返回 RVA 来自别的版本字节,解出来的 form/site
  不代表当时跑的进程 —— 换版本先对 `anchors_4_4_4.md` 重锚。

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

## 离线存档分析(C4)

`scripts/save_hypergraph.py` 与 `scripts/chokepoint_scores.py` 读的是**玩家的 `.sav` 存档**,不是
`stellaris.exe` —— 所以它们不受 `NS_STELLARIS_EXE` 影响,也不需要进程、注入或 dispatch。存档本身是
用户数据,**不进 git**;`evidence/` 只记路径、大小、sha256 与派生统计,表与存档 sha 必须成对出现。

### `scripts/save_hypergraph.py <save.sav> --edges <out.tsv> [--stats]`

`.sav` 是 **ZIP**,本次两条 entry:`gamestate`(27,281,802 字节,**文本** Clausewitz,首行
`version="Pegasus v4.4.4"`)与 `meta`(365 字节)。工具解 ZIP、读 `gamestate`、用 UTF-8 +
`errors="replace"` 解码,取顶层 `galactic_object` 下每个系统块的 `hyperlane={ { to=… length=… } … }`,
输出无向边表(列序 `a\tb\tlength`,去重成 `a<b`,按 `(a,b)` 升序)。`--stats` 把计数按 `key=value`
逐行打 stdout;本存档实测:`systems=787`、`undirected_edges=1217`、`components=1`、`isolates=0`、
`self_loops=0`、`duplicate_entries=8`、`asymmetric_edges=0`、`conflicting_edges=0`、
`replacement_chars=0`(完整输出在 `evidence/logs/c4_chokepoint_offline_4_4_4.log`)。

**判读陷阱:**
1. **文本存档限定。** 同一账号下别的 `.sav` 可能是二进制 Clausewitz;`read_gamestate` 以「不是 ZIP /
   ZIP 里没有 `gamestate`」或「解码后前 4096 字符出现 NUL」为硬错误退出 2,不把二进制喂给解析器。
2. **解码不是无损的。** `errors="replace"` 让一个坏字节不至于杀掉整张图,但 `replacement_chars > 0`
   意味着名字里有被替换的字符。图仍可能正确(边只依赖数字),不要把它读成「存档坏了」,也不要
   静默当 0。
3. **重复键与匿名块必须保留。** `planet=…` 会重复,`hyperlane` 内层是无键的 `{ to=… }`;普通 dict
   会丢前者、把后者当非法输入。解析器的 `Block.entries` 是 `(key, value)` 列表,`key=None` 即匿名块;
   值列表里的裸 token(`required_dlcs = { "Horizon Signal" }`)同样以 `key=None` 的标量保留。
4. **不对称边与长度冲突是硬错误,不是统计项。** 每个系统自己列出出边,`a→b` 与 `b→a` 应成对且长度
   相同;缺一半、或两个方向给的长度不同,一律退出 2 并打印样本。自环与**同长**的重复声明只计数
   (`self_loops`、`duplicate_entries`)并从图里去掉 —— 本轮实测到 8 条重复声明,这是计数后继续的
   口径,不是「静默去重」。
5. **`galactic_object` 必须唯一。** 顶层出现 0 个或 2 个以上同名块,退出 2:选第一个等于悄悄改图。
6. **0 条边是硬错误。** 空块、或只有孤立系统的图在去掉自环后没有任何无向边时,退出 2 ——
   「0 个星系」不是正常结论,不写空表、不返回 0。
7. **`to=` 的全文件正则计数会高估。** 计划探针按行首 `to=<数字>` 数出 4,397 条,那是文件里所有
   `to=` 键;工具只数 `galactic_object` 系统块内、`hyperlane` 匿名块里的 `to`,本轮 2,442 条
   (= 1,217 对 + 8 条重复)。两个数字回答的不是同一个问题。
8. **孤立系统只计数,不进边表。** `isolates` 是 stats 里的计数,CLI 会往 stderr 打一行警告;
   边表只含 `a<b` 的边,所以下游分数表的 `n` 只覆盖有边的系统,孤立系统**没有行**,分母也
   不把它们算进去。本存档 `isolates=0`,这条只影响别的存档。
9. **整份 `gamestate` 都会建树。** 解析器先把整个文本建成 `Block` 树再取 `galactic_object`;
   本存档 27,281,802 字节实测跑通,更大的后期存档耗时与峰值内存**未测** —— 这是边界,不是承诺。
10. **id 是存档局部的。** 这里的 `system_id` 只对这份存档(与它的 sha256)有意义;换一局、换一版,
    同一个数字指向另一个星系。表不能当跨战役常量用。

### `scripts/chokepoint_scores.py <edges.tsv> --out <scores.tsv> [--top N]`

只读边表(无表头;第一行全是数字就当数据),算 `degree`、无向无权 Brandes `betweenness`、Tarjan
割点/桥,输出固定七列:
`system_id\tdegree\tbetweenness\tbetweenness_norm\tscore\tis_articulation\tis_bridge_endpoint`。
数据行按 `system_id` 升序,浮点 `.6f`,`--top N` 按 `(score, betweenness, -system_id)` 降序打前 N 行。
`betweenness_norm = b / ((n-1)(n-2)/2)`(n>2),`score = round(1000 * betweenness_norm)`。

**判读陷阱:**
1. **无向图只计一次。** Brandes 标准实现最后 `b[v] /= 2`,所以一条最短路只算一对端点;把无向图
   当有向图跑会得到两倍分数。
2. **`score` 是全局归一化的相对排序,不是绝对阈值。** 分母用全图 `n`,而 betweenness 在分量内
   计算;断开的图里小分量的高分点会被压低。本存档实测 `components=1`,这里两者一致 ——
   换图先看 stats 再读分。
3. **`betweenness` 与 `betweenness_norm` 不同分母。** 前者按无序对计数后的原始值,后者的分母是
   `(n-1)(n-2)/2`;`score` 只由后者算。比较两轮分数时比 `betweenness_norm`,不要比原始值。
4. **割点/桥是布尔,不是权重。** `is_bridge_endpoint=1` 只说明这个点挨着至少一条桥;`degree=2` 的
   点也可能是割点。
5. **空输入退出 2。** 空边表 / 坏行 / 自环 / 重复边 / 参数错误都是退出 2 —— 「0 个星系」不是正常结论。
6. **输出的确定性是契约。** 同一输入两次 `--out` 应逐字节相等(测试钉住);行序与邻接遍历都已
   排序,输入行序不影响分数 —— 若有差异,先查输入内容(重复边是硬错误),不要先怀疑排序。

**把产物拿回 Linux 的传输陷阱:** 本轮 `scp` 下载 1.9 MB 存档会被主机重置,14 KB 的边表与 27 KB 的
分数表也一样。最后用的是主机侧 `gzip` + base64、按 1,024 字符块走 SSH、本地逐块 `base64 -d >>` 并
去掉 PowerShell 带回的 `\r`,再用 `sha256sum` 与主机 `Get-FileHash` 对账。存档留在主机,只回传小产物;
小文件能直接 `scp` 时不用这套。

### `scripts/chokepoints_emit.py --tsv PATH --save-sha SHA [--out PATH] [--check]`

把 `chokepoint_scores.py` 的七列表编译成 DLL 侧常量 `src/dll/c2/chokepoint_table.zig`:
`SCORE_COUNT`、`TIER1_MIN=100`、`TIER2_MIN=200`、`SAVE_SHA256` 与 787 项 `[u16]` 分数表。
`system_id` 是**存档局部**的(见上一节陷阱 10),所以生成的表与 save sha 必须成对出现;换一局、
换版本都要重新生成并把 `--save-sha` 换成新存档的 sha256。`--check` 不写文件,现有产物与 TSV
渲染结果不同(或文件缺失)时退出 **2**;根目录 `just chokepoints-check` 与 `just check` 都跑它。
生成器自己复现 `zig fmt` 的多行列对齐,所以 `zig fmt --check src/dll/c2/chokepoint_table.zig`
必须为 0 —— 若不为 0,先修生成器的排版,不要在产物上手改(下次 `--out` 会覆盖)。

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
**§47 终评修复轮**(2026-10-22)`parse` 补上 section 越界检查后,截断输入真的走 2 了(此前
`func` 会拿空 `.pdata` 答 1);新增 1 条截断测试,`test_c2_harness.py` 变为 **135 passed**,
`test_pe_disrva.py` 变为 **5 passed**。

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

**§48 修复后的当前产物**:`cutils.h` 引入 `<stddef.h>` 让 `offsetof` 用 builtin,`:1494:12` 的
`TypeMismatchData` 记录消失(`site JSMallocBlockHeader` 141→133、该行 0 条),因此
`func 0x18000bd9b` 在新产物上不再有记录可打;`js_rc` 本体仍在,只剩 `:1494:12` 的
`PointerOverflowData`(工具不解码),区间也随重链移动到 `rva 0xbba0..0xbc01`(97 字节)。
`scripts/test_pe_disrva.py` 的 `trap_span()` 就是从这条 SourceLocation 反查当前区间,不钉常量。
上面 141/131 字节那组数字属于 §47 产物 `77c0c35e…`,要复现请读基线字节(缓存副本)。

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
6. **记录行不带 `[ubsan_site]` 前缀,所以按前缀过滤会把证据丢掉。** `site`(`:261`)与 `func`
   (`:290`)的 header 行带前缀,而每条记录行是**两个空格**开头(分别在 `:264`/`:304` 打印)—— `grep -F '[ubsan_site]'`
   (或转义 `\[ubsan_site\]`)只留下 header。本批(§47 前置)对一次真实输出(`func 0x1800055f5`)实测 = 7 行
   (2 行 header + 5 行记录),过滤后**只剩 2 行**,5 条记录全丢。更糟的是另一种写法:
   不加转义的 `grep '[ubsan_site]'` 是**字符类**(任一字符 u/b/s/a/n/_/i/t/e),同一份
   7 行输出**一行都不会被滤掉** —— 看起来"过滤生效了、什么都没丢",其实过滤根本没起作用。
   两种写法都别拿来取证据:要记录行就 `grep '^  '` 或 `grep 'quickjs\.c:'`(同一份输出各实测
   5 行)。
7. **`#0x…` 标注只能和 `TypeMismatchData` 记录的 `record_rva=` 比。** `func`/`site` 只解码
   `TypeMismatchData` 的 kind 3–11(`scripts/dll_ubsan_site.py:93`,`:201` 还要求 `log_align <= 7`),
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

**重建陷阱(§48 实测)**:只改头文件(`libs/quickjs/*.h`)时,已有 Zig 缓存的 `zig build` 可能把 C
编译报成 `cached` 并留下旧字节 —— 此时 scp 出去的是**旧 DLL**,复现器仍显示 abort,会被误读成
「修复无效」。改完头文件先核 `zig build --summary all` 里 `compile lib stellaris_quickjs` 的状态
行与 `sha256sum zig-out/bin/stellaris_quickjs.dll` 是否真的变了;没变就换一个 `--cache-dir` 重建。

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

### `scripts/c2_exec_probe.py [dll]` — C4 执行路径实机一枪

把 C1 注册的 effect token 走完 C4 执行链:谓词 detour 把实例的 `[obj+0]` 换成 DLL vtable,
base-Execute 探针合成**一次** instantiate,slot[1] 经 `C2ExecCall` 进固定 JS 脚本,脚本返回哨兵
`1504`。读的是两组统计:`C2ExecStatsInto`(C 桥:`armed/token/js_calls/js_ok/js_err/mismatch/
last_rc/last_value`)与 `C2ExecProbeStatsInto`(探针与谓词:`calls/fired/ctx_skip/invalid/
pred_patched/chain/verified`)。两个 buffer 都是**有界轮询**(1 s 间隔、120 s 上限),判读取 `C2ExecDisarm` **之前**的 live 快照
(`Disarm` 会把 C 桥的 `token` 清零,清理后的快照不可判),轮询中间值仍不看。

**一枪一进程**:`C1Run`/`C2Init`/`C2ExecInstall`/`C2ExecProbeInstall` 每个都只派发一次,重跑必须
重开游戏。清理段(`finally`)顺序固定:先 `C2ExecProbeUninstall` 让探针 inert,再
`C2ExecProbeVerify`(0 = base-Execute 字节已还原),`SETTLE_S` 之后 `C2ExecDisarm`(`-1` = C 桥锁忙,
最多重试 5 次)。任何一步报 `-6`/非 0 都**绝不 `FreeLibrary`**。

**verdict 判读表**(`classify`,缺失键按 0):

| verdict | 条件 | 意思 |
|---|---|---|
| `no_fire` | `fired == 0` | 120 s 内没抓到可用调用 —— **环境结论,不是代码结论**:加载一个跑着的战役并取消暂停,重开进程再跑 |
| `ctx_skip_only` | `fired >= 1`、`js_calls == 0`、`ctx_skip > 0`、`invalid == 0` | 每次调用都带 lexer 哨兵 `[ctx+0x38]==0xb`,instantiate 被拒 |
| `fired_no_js` | `fired >= 1`、`js_calls == 0`、其余 | instantiate 发了但没走到 JS:实例没经过 patch 后的谓词/vtable 链,或 C 桥已 disarm |
| `ok` | `fired >= 1`、`js_ok >= 1`、`pred_patched >= 1`、无 `js_err`/`mismatch` | 链路成立;还会断言 `token == C1EffectId()`、`last_value == 1504`、`chain == 0` |
| `error` | 其余 | 链跑了但 JS 没给哨兵:看 `js_err`(脚本/异常)与 `mismatch`(到达 JS 的 token 不对) |

`no_fire` 报出来时先查环境(战役是否在跑、是否暂停),不要去改探针。**宿主死了先跑 §45 的两个
离线工具**(`scripts/c2_selfabort_repro.py` + `scripts/dll_ubsan_site.py`)排除我们自己的产物再谈别的。

### `scripts/c2_scope_probe.py [dll]` — C4 执行帧只读取样

`src/dll/c2/scope_probe.zig` 在 base Execute `0x1D08520` 上挂**只读** detour:每 512 次调用采样一次
(`calls & 511 == 0`),记录真实 `arg2`(执行帧)的 8 个 qword、`[self+0]` 的 vtable RVA、`[self+8]` 的
token id、`@returnAddress()` 的**返回 RVA**(记的是调用指令的下一条,不是调用点本身 —— 读法见下面 CALLERS
一段的口径),以及派发点上的 `r8`/`r9` 两个 scratch
槽(布局 v2 起,`Entry` = 120 字节)。**函数体一律转发原函数**,不改寄存器、不改内存、不改控制流。
`r8`/`r9` 记的是**值**,不是它们指向的内存 —— 一切解引用都发生在驱动侧的 `ReadProcessMemory`,采样器本身
不解引用任何二级指针。

驱动随后对**四个根**做进程外解引用:`self`、`[ctx+0x10]` 的 helper、`r8`、`r9`;每个根读 8 个 qword,
每个像指针的 qword 再读它指向处的首 qword,减 `exe_base` 得 RVA,拿去 `--vtables`
(默认 `evidence/xrefs/ceffect_vtable_map_4_4_4.txt`,1,805 个)做命中判定。**跟读预算按根类型各自给**
(每源 8 个不同地址,四源合计仍是 32)—— 共用一个预算会让排在后面的源必然是 0 行,见下面陷阱 5。
每个候选做**两次独立查表**:`known` 查 `[ptr]` 的 vptr(成员指向已知类的对象),`member_vtable` 查
`ptr` 本身是不是一个已知 vtable 地址(root+off 直接放着一张 vtable = 多重继承子对象头,说的是 root
自己的类);两者是两件事,后者**故意不喂给 `classify()`**。RVA 一律界在 `[exe_base, exe_base+SizeOfImage)`
(`SizeOfImage` 从活进程 PE 头读:`e_lfanew` 在 `+0x3C`,`SizeOfImage` 在 NT 头 `+0x50`),界外不产生 RVA。
**这条取代了旧判据**:
`X=[ctx+0x30] → S=[X+8] → id=[S+8] / obj=[S+0x20]` 那条链已由 c1_validation **§53.3 第二枪证伪**
(`+0x30` 不属于 0x20 字节的帧,读到的「id/object」是 `add rsp,0x28` 一类指令字节),链仍然照旧跟、照旧写进
TSV,但**不再进任何 verdict**。

读的是 7 个导出 + `C2Sanity`:`C2ScopeProbeLayout`(5 个 u32:entry `120` / stats `56` / ring `256` /
mask `511` / version `2`)、`C2ScopeProbeReset`(装之前先清统计)、`C2ScopeProbeInstall`、
`C2ScopeProbeStatsInto`、`C2ScopeProbeDrainInto`(环形记录,最老在前)、`C2ScopeProbeUninstall`、
`C2ScopeProbeVerify`。**layout 任一字段漂了就打 `LAYOUT_DRIFT` 且不装** —— 驱动与 DLL 的解码契约断了,
后面的字节都不能读。**拿 104 字节的旧 DLL 配 v2 驱动(或反过来)一定会漂**,这不是巧合,是这条判据在生效:
按 104 解 120 会让每条记录串进下一条,读出一堆「看着像指针的垃圾」。

```
python3 scripts/c2_scope_probe.py [dll] [--poll-s 120] [--settle-s 2] \
        [--out C:/temp/c4_scope_probe.tsv] [--census ...] [--id-names ...] [--vtables ...]
```

`--vtables` 指向的那份表**必须在开枪机上存在**(Windows 侧要上传,见「前置条件」),表缺失或解析出 0 条时
脚本在**注入之前**就退出:判据挂在一个空集合上,那一枪无论怎么打都只会得到 `no_scope_candidate`。

轮询一直采样到 `--poll-s` 截止(不是拿到第一个样本就停),环形记录保留最后 256 条;
`--poll-s` 太短只会让样本变稀,不会让判读变快。

**一枪一进程**:`C2ScopeProbeInstall` 每个进程只派发一次,`exec_hook` 已被占用时返回 `-2`(单 detour
约束),**不重试** —— 看到 `-2` 换一个新游戏进程,不要在同进程里绕。其余安装码:`-3` 模块未找到、
`-4` 该地址已被别的 detour 占据、`-5` 序言不匹配、`-6` patch 太宽、`-1` 其他安装失败。清理段(`finally`)顺序固定:
`C2ScopeProbeUninstall` → `C2ScopeProbeVerify`(0 = 引擎字节已还原)→ 等 `--settle-s` → 断言 host 存活。
`Verify` 非 0 时打 `RESTORE_INCOMPLETE DO_NOT_FREELIBRARY`,**放弃该进程**,绝不 `FreeLibrary`
(只有本次 install 真的返回过 0 才这样判;本次根本没装上时,verify 读到 `-1`/`-3` 属正常,
驱动打 `verify=<n> (not installed this run)`)。
卸载走的是仓库共用的 detour 原语(`detour.zig` 的 `removeHook`):`VirtualProtect` 把 16 字节 patch
逐字节写回,**不暂停线程、也不检查有没有线程正处在那段字节里**。这是 §52 那一枪同样继承的残余竞态,
驱动侧造不出「静默窗口」(跑着的战役每秒数千次调用);host 恰在清理瞬间死掉时,先归因于 detour
卸载而不是采样器,并按 §45 排除我们自己的产物。

**点名门**:这是实机工具,按 `docs/roadmap.md` 的授权表,派发前必须有**本次会话内的点名**;
通用历史授权(「仅限于游戏调试相关」)不算。没有点名时只跑纯函数测试。

**verdict 判读表**(`classify`,固定顺序):

| verdict | 条件 | 意思 |
|---|---|---|
| `no_calls` | `calls == 0` | 轮询窗口内没有 base-Execute 调用 —— **环境结论,不是代码结论**:加载一个跑着的战役并取消暂停,重开进程再跑 |
| `no_samples` | `samples == 0` | 有调用但 1/512 门没触发;唯一手段是更长的 `--poll-s`,本次什么都没采到 |
| `all_invalid` | `valid == 0` | 每个样本的 `self`/`ctx` 都不可信,一帧没记;环境/调用形状结论,换新进程再试 |
| `lexer_only` | `lexer > 0` 且 `lexer == valid` | 全部有效样本都带 lexer 哨兵 `[ctx+0x38]==0xb`(§52 那条路径),**不能**回答「真实执行帧是哪个对象」 |
| `no_scope_candidate` | `known_vtable_hits == 0` | 四个根下没有任何 qword 指向「vptr 在那 1,805 个已知 vtable 内」的对象。这是**有界的代码结论**,见下面判读陷阱 1 |
| `scope_candidate` | 其余 | 至少一个 qword 命中已知 vtable 集合;TSV 的 `object` 行指名是哪个根、哪个偏移、匹配到哪个 slot2 实体。这**仍不证明**它是 `CEventScope` |

`scope_candidate` 之外一律退出码 1。`no_calls`/`no_samples`/`all_invalid`/`lexer_only` 四条一律先按**环境**读
(战役是否在跑、有没有取消暂停、进程是不是新进程),不要读成代码结论。链里的 `id` 是 **keyword token id**,
永远不是 system id;名字只在 `--id-names`(默认 `evidence/xrefs/descriptor_oracle_4_4_4.tsv`)里查得到时填,
查不到就留 `-`,不猜。`CALLERS` 的 `func`/`origin` 来自 Task 1 的调用点普查(`--census`,默认
`evidence/xrefs/exec_frame_callers_4_4_4.tsv`);Windows 侧没有这两份表时两列退化为 `-`,离线再 join。
**CALLERS 行的口径:返回 RVA ≠ 站点**(§59 读圈子的根源,这次修的是产物的声称):行键与 `ret=` 就是
返回 RVA 本身,`est_site=` 是按「这条 call 是 `E8 rel32`(5 B)」给出的**估值** `caller_rva - 5`
(`caller_site_estimate`)。虚调用 `call qword ptr [rax+8]` 只有 3 B,`-5` 会把站点画进前一条指令中间,
census 于是 join 不上而报 `func=-` —— 那读法是「估值不是它的站点」,**不是**「没人调用」。join 仍走估值
(这是估值的唯一用途);返回 RVA 不足 5 字节时不估值,写 `est_site=-`,绝不因一个被记录的值让 shot 死掉。
**精确站点归 `scripts/exec_frame_sites.py` 的离线反解**(见上文「站点离线反解」一节):重读 exe 字节反解出真正的 call site(§59.7),本工具的产物不再声称它是站点。
完整结果写到 `--out`(长表 `kind/key/value/detail`,**meta** / caller / id / chain / object /
root_unreadable / **region** 七类行)。
`meta` 行在最前面,带 `exe_base`、`image_end`、`image_size`、`dll_sha256`、`vtable_map_count`、`layout`、
`stats`、`per_source_follow`,四根的 `followed_by_source`/`implausible_by_source`/`capped_by_source`/
`withheld_by_source`、三个命中计数,以及区域仪器的 `regions_queried`/`region_verdicts`。**这不是装饰**:§56 那一枪的 stdout 被一次 ssh 重置整段吃掉,而旧 TSV
里没有这些数,事后无从区分「某个根读到但没有命中」与「那个根根本没被读」,于是把一次预算耗尽读成了一条
负结论(陷阱 5)。判据现在住在带判词的 artifact 里。

**内存区域仪器(`VirtualQueryEx`,§56.8 那条「绝对值还是相对值」缺的 datum)**:`follow_roots` 之后、
清理之前,驱动对**每个被跟过的根地址 + 每条 chain 的 `ctx`** 各问一次 `VirtualQueryEx`,答案写成 `region` 行
(`region\t0x<addr>\t<verdict>\tsource=.. base=0x.. size=0x.. state=0x.. protect=0x.. type=0x.. alloc_base=0x..`)
并汇总进 meta 的 `regions_queried`/`region_verdicts`(后者是 `source/verdict=count` 的排序串)。
**判据是判序,不是标志位的名字**:`None` → `unreadable`;否则**只看地址** ——
`exe_base <= BaseAddress < image_end` → `image`,这一段刻意不查 `Type`(否则一个落在镜像里的
`MEM_PRIVATE` 会被读成「不是镜像」);否则 `State` 是 `MEM_FREE`(`0x10000`)→ `free`、
`MEM_RESERVE`(`0x2000`)→ `reserved`;否则 `MEM_COMMIT`(`0x1000`)时按 `Type` 分派 ——
`MEM_MAPPED`(`0x40000`)→ `mapped_view`、`MEM_PRIVATE`(`0x20000`)→ `private_committed`、
`MEM_IMAGE`(`0x1000000`)→ `image`;其余 → `unknown`。查不到句柄、内核拒绝描述、返回字节数不够,一律
`unreadable`(与 `reader()` 同口径:一个描述不出来的地址是 datum,不是故障)。
**这条仪器不参与 `classify()` 的六档阶梯**,也不参与退出码 —— 区域判定只进 artifact,供离线复算。
结构体那条坑记在这里:`MEMORY_BASIC_INFORMATION` 只声明 SDK 的 7 个命名字段,x64 上 ctypes 的自然对齐
就补出了 `__alignment1`(offsets 0/8/16/24/32/36/40,`sizeof`=48);**把那个 padding 字段也写出来会多插
4 字节,`State` 读到的其实是 `Protect` 的槽**。

**十一条判读陷阱(§53.4 / §54.8.4 / §56.8 / §58 / §59 实机与离线复算取到的,读 verdict 之前先看):**

1. **`no_scope_candidate` 的口径是「不在已知集合内」,不是「不是对象」。** 那 1,805 个 vtable 只包含 slot[1]
   仍是 base Execute 的类,**覆写了 Execute 的类一个都不在**(structures §14 + pipeline §17)。所以这一判读
   不排除候选是对象,只排除「它属于那个集合」。反过来 `scope_candidate` 也只到「命中已知集合」为止。
2. **`r8`/`r9` 在派发点不是参数**(§54.8.4 第 1 条:`0x1D08520` 只设 `rcx`/`rdx`,而 `0x3B01A0` 消费四槽,
   `r8`/`r9` 取的是上一调用者的 scratch)。它们的命中**不能**用来推断调用约定,也不能读成「引擎把 scope 传在了
   第四个槽」。
3. **`unreadable` 与「读到但没命中」是两件事。** 短命帧的 `+0x10` 指向邻近栈 helper(§53.4.1),而读取发生在
   轮询结束之后 —— 那时栈早被覆盖。这类根进 `root_unreadable` 行与 `unreadable_roots` 计数,不该被当成
   「那个位置是空」。模块外(堆)的地址保留**绝对值**在 `ptr`,只有 `vptr_rva` 才是基址相对的;把堆指针压成
   `rva=0` 会和真正的 0 混成一类。
4. **实机结果里的 `base` 有两种,判 vtable 命中只用其中一个。** 驱动打印与 `c4_wiring_result.json` 的
   `base` 是**我们 DLL 的装载地址**(`resolve_base_address(pid, module)` 按模块取),不是 exe 主模块基址;
   vtable map 的键是 exe 相对 RVA,拿错基址就永远命不中,而失败长得很像「没有候选」。完整对照与取法见 §55.1。
5. **某个 `source` 在 TSV 里是 0 行,先读 `capped_by_source` 与 `withheld_by_source`,再谈它是负结论。**
   旧版四根**共用**一个 32 的跟读预算,而迭代顺序是每条记录先交 `self`:排在后面的源必然是 0 行,
   这个 0 与「引擎在那个槽里没有指针」在 artifact 里长得一模一样。§56 就这么把「`arg3`/`arg4` 一行都没有」
   读成「过不了 `plausible_user_ptr` 门」,把「`helper` 只有 1 个地址」读成观测量 —— 实际是
   `31 self + 1 helper = 32` 预算刚好耗尽(§56.8)。`withheld` 是另一半:entry 无效时 `ctx` 没被记,
   `helper` 根不是「读了没命中」而是「无从读起」。**没有 meta 行的旧 artifact 不能事后重开这个判断**,
   只能按未定处理。
6. **两个「像指针」的假象:`vptr_rva` 可以根本不在镜像里,`ptr` 可以根本不是指针。**
   旧 `to_rva` 只有下界没有上界,§56 的 artifact 里就有 2 条 `vptr_rva` 是
   `0x7360ec6ccc426873` / `0x4e5ed44eaa1a4c50` 这种垃圾 qword 减出来的数 —— 它过了「是个 RVA」的形状检查,
   却没过「这个模块有这个偏移」。现在界在 `[exe_base, exe_base+SizeOfImage)`,界外留 `-`。另一半:
   `plausible_user_ptr` 只看范围与 8 对齐,而 §56 的候选里有 **2 条的值是 ASCII `"PLANET"`**
   (`0x54454e414c50`,两处 `off=0x18`)—— 它合法地过了门。所以「pointer-shaped」不等于 pointer,
   命中表里出现一个可疑成员时先按值读一遍,再按指针解引用。同一类还有**量级**:§56 的 `ctx` 帧
   (`0x7fe768`/`0x7fed78`)与 `helper` 根(`0x1900ede0`)都在 32 位量级,而 x64 的栈与模块装载在
   `0x7ff…` 量级 —— 低地址不等于栈,把它们读成绝对指针之前要先按数值比量级(§56.8 末段)。
7. **`known` 与 `member_vtable` 是两个不同的陈述,不能相加。** 前者说「这个成员指向一个已知类的对象」,
   后者说「这个槽里直接放着一张已知 vtable」(多重继承子对象头,说的是 root 自己的类)。§56 的 99 个候选里
   第一层 14 条、第二层 **44 条**(全在 `self` 上,13 个不同 RVA),后者若喂进 `classify()` 会把
   「root 带子对象头」当成 scope 命中 —— 所以现在单独计数、单独写 TSV,且**不进判词阶梯**。
8. **`unreadable`、`free` 与「这个数不是地址」是三件事。** 区域仪器只能说「此刻没有一段已提交的内存覆盖这个
   范围」:`unreadable` 是**问不出来**(句柄、权限或内核不给描述,包含「根来自一条无效 entry」这种没被记下的
   值),`free` 是**问得出且那里是空洞**。而一个 32 位量级的数落在空洞里,既可以是一个还没被提交的相对偏移,
   也可以是一个从未被提交过的绝对地址 —— 这一条不能替二者做决定。`reserved` 更弱:地址有效但内容还没提交,
   拿它解释低地址会把「相对值」这条假说杀掉得不够干净。只有 `private_committed`/`mapped_view`/`image`
   才正面回答「这是一个有人拥有的地址」。
9. **`no_calls` 先读「有没有弹窗」,再读代码。** 预检 `ns_scope_pre.py` 走调试控制台,而**预检本身不暂停
   游戏**(实测:控制台开着时 `red=0 / green=200` ⇒ `state=playing`,§59.1 更正了 §58.3 的因果句)。
   真正暂停游戏的是预检期间弹出来的**事件窗**——它自己会暂停(监督器判读陷阱 4),而 `dialog_unknown`
   这种没归过类的窗口不会被 `dismiss` 收掉。§58 那一枪就是这样:预检通过后没回头确认窗口已关、状态回
   `playing`,烧掉 pid 13132 的「一进程一次安装」额度换来一个 `calls=0`。所以**「已载入且已解除暂停」这条
   前置的读数必须紧邻开枪取**(`state=playing` 是判据,`console_open` 不是),预检与开枪之间隔多久这条就作废多久。
   同理:`regions_queried=0` 与四桶全 0 在这种枪里是**同一件事的四个写法**,不能读成「区域仪器判了 0 个」
   或「形状集没命中」;而 `scope_reclassify.py` 的 `undecidable_no_rva == 0` 这条验收在零行 artifact 上
   **恒真**,零行时它不证明任何事 —— **有行的时候它也不该被当成验收**:v4 的 16 条 object 行里 15 条
   `vptr` 根本不在镜像内(那是 `0x0`/`0x102`/`0x4000000040` 这种值),界外留 `-` 正是 bounds 修复要显示的
   事,不是要消灭的事(§59.8)。
10. **`dismiss` 的关闭点仍是写死偏移 —— 工具缺陷已修(可覆盖 + 每次尝试留痕),偏移本身对任何窗的正确性待实机复核。**
    历史(§59.2 唯一反样本):`click_close` 走 `bbox[2]-96, bbox[1]+51`(2160x1440 上量来的),而 `bbox` 来自金色像素的 panel 检测:
    §59 那个事件窗的 `bbox` 右界 1939 落在**右侧栏**上,算出的点 1843 不在 X glyph 上(真 X 在 1343,480)。
    当时 `dismiss` 返回成功、日志无痕、窗口原地不动 —— 「点击没送达」与「框判错」无法区分。
    现在:偏移提出为 `CLOSE_INSET`,由纯函数 `close_point(bbox, inset)` 算点;`dismiss <dx> <dy>` 可逐命令覆盖
    (屏幕绝对点仍走 `just game click`)。每次尝试**先**写 `dismiss_attempt`(本来会点的坐标、
    `method ∈ {fixed_inset, refused}`、inset、bbox),真点击后重读窗写 `dismiss`(`no_effect` 即「点后窗还在」);
    判 `refused` 则不点击、raise,状态 note 为 `dismiss_refused`。「dismiss 成功但窗还在」由此变成**可检出的事件**。
    「检出」的边界要写明:`no_effect` 是 **panel 检测器的陈述,不是 glyph 的陈述**,两个方向都可能误报 ——
    重读若锁上*另一块*亮面板,窗真没了也报 `no_effect: true`;漏点后检测器若丢掉金色锁定,窗还在也只报
    `no_effect: false`(`bbox_after` 出自同一个当初把右界量到侧栏的检测器,§59.2 的原失效模式并未被这条事件根除)。
    留痕把问题从「无痕」降级为「待复核」,判定仍靠下面的手动量测(`shot` + `just game click`)。
    **但 §59.2 只有一个反样本,不足以推量测式 —— 第一版刻意不发明几何规则**;复核要等下一次有窗的实机机会。
    复核之前的临时取代:先 `shot` + 裁 `titlebar` 量 glyph 中心,再 `just game click <x> <y>`(坐标是**屏幕绝对**的,
    `window_metrics` 的 bbox 已经加过窗口原点)。
11. **`form=none` 是窗口陈述,不是调用者陈述。** `exec_frame_sites.py` 报 `none` 只说明**返回 RVA 前
    16 字节内没有任何恰好结束于返回点的 call/jmp 边界**,**不等于没人调用**:调用可能经过 thunk
    (返回点不挨着任何紧邻边界),或样本记录的返回 RVA 本身就读错了(旧产物把估值当键的世代)。
    `none` 是要带进取证卷的 datum,不是负结论;`ambiguous` 同理 —— 它是字节里真实存在的重叠,
    照原样进卷,不替他选一个候选。

**宿主死了先跑 §45 的两个离线工具**(`scripts/c2_selfabort_repro.py` + `scripts/dll_ubsan_site.py`)
排除我们自己的产物,再谈引擎。

### `scripts/c4_wiring_probe.py [--mode capture|slot2] [--dll PATH] [--save PATH] [--json PATH] [--supervisor-log PATH] [--allow-drift]`

C4 接线驱动,一枪一进程。`--mode capture`(默认):跑 `capture` 找 `ctx`/`a3` 里承载 system id 的列,
`apply` 把该列喂给 QuickJS 的 787 分数表(tier 阈值 100/200),tier ≥ 1 的 70 个系统 chain donor
Execute 应用 `log`/`set_name`。**capture 只读**(RPM 采样 + 环形记录),整条 apply 路径里唯一的引擎
写入是引擎自己的 donor Execute。`--mode slot2`(§54.6 判别枪):**预检 → install → 一次 armed 的
`every_system` pass**,读 slot[2] 只读计数器(`C4Slot2StatsInto`,`<QQ>` 16 B:计数 + 转发目标),
verdict ∈ {`slot2_counted`(787 ⇒ base Execute 经我们的副本 slot[2] 派发)、`slot2_zero`(0 ⇒ donor
vptr 副本/克隆,不经我们的 vtable)、`slot2_body_not_executed`(body 没跑满 783,计数没有意义)、
`slot2_sentinel_mismatch`(哨兵不等于 783)、`slot2_other`}。判据先钉哨兵 783 行与 body marker 783
行(投递与执行都发生),再读计数增量 —— 否则 `0` 无法区分「不经 slot[2]」与「没跑」。包装器的
等价性有离线出处(`runtime_444_c1_validation.md` §54.8):派发点 `0x1D08520` 只设 `rcx`/`rdx`、不读
`rax`,而 `0x3B01A0` 四个 GPR 槽全消费 —— 但同一节也记了 `r8`/`r9` 在派发点**不是参数**、
`slot2_counted` 只证明入口不证明良构调用。路径默认
`C:\temp\sqjs_c4.dll` / `C:\temp\stellaris_2226.sav` / `C:\temp\c4_wiring_result.json`,`--game-log` /
`--supervisor-status` / `--supervisor-cmd` / `--shot` 也走参数,脚本不读环境变量。

**前置**:supervisor 必须已在 Windows 机上跑着(见下一节)。驱动先写 `want paused` 并等到状态
`paused`(状态文件超过 5 s 未更新按「没在跑」判),然后才注入。**console 命令都经 supervisor
的 `console` 动词**(剪贴板 + 按键),条数按模式定:`--mode capture` **三条**(预检 + capture +
apply),`--mode slot2` **两条**(预检 + 判别枪)—— 两种模式都含那条预检;不直接对游戏发键。
控制台键是**开关**,而命令执行完面板不关(2026-10-23 实机),所以 supervisor 自己记
`console_open`:首条命令按一下打开,其余每条只清行、粘贴、回车;换进程时这个标记复位。

```
effect every_system = { log = "C4_PREFLIGHT_<pid>_[This.GetName]" }             # 预检，应得 783 行
effect every_system = { log = "C4_CAPSTART_<pid>_[This.GetName]" neo_action = { … } }   # capture 哨兵
effect every_system = { log = "C4_APPSTART_<pid>_[This.GetName]" neo_action = { … } }   # apply 哨兵
effect every_system = { log = "C4_SLOT2START_<pid>_[This.GetName]" neo_action = { … } } # slot2 判别枪哨兵
```

> 哨兵与预检共用 `[This.GetName]` 的 783 行去重形状，但带 pid 与相位：capture/apply 的哨兵在
> 同一会话里互不冒充。3 s 内没有被 supervisor 消费 → `console_send_failed`；0 行 → `*_not_delivered`；
> 非 783 行 → `*_sentinel_mismatch`。宽限取 3 s,是因为 supervisor 的 serve 循环是 0.8 s、读命令前
> 还要做像素截图 —— 投递失败现在会中止整枪,1 s 会把健康通道误判成坏通道。

**谓词计数器**：`C4PredStatsInto` 是 `<QQII>` 24 B（calls, patched, last_token, installed）；驱动取
capture 前后的**增量**，不是绝对值 —— `pred_patched` 是进程累计值，预检的 effect 也会进 detour。

**命令形状**:keyword 要写在 `effect` 与 `=` 之间(`effect every_system = { … }`)。写成
`effect = { every_system = { … } }` 时引擎往 error.log 打 `Invalid scripted effect: =`,盒子根本不跑 ——
这个形状曾经让预检只数到 1 行。

**marker 必须逐系统不同**:引擎的 log sink 会**丢弃本会话里已经打过的同样消息**(game.log、
error.log 一致),所以固定文本的 marker 在 787 次执行后只剩 1 行,第二条同样的命令连一行都不加。
marker 带 `[This.GetName]`(`log` 里会插值,`GetID` 渲染为空),每个系统渲染自己的名字。实测:787 个
系统只渲染出 **783 个不同名字**(3 对低分系统重名,均不在 tier ≥1),apply 的 70 个 tier ≥1 系统名字
全不同 ⇒ `PREFLIGHT_MARKERS = 783`、apply 仍按 70 行判。

预检 marker 带 pid,但从**本次偏移**读到 EOF 再数,所以同一会话里重跑的旧行不会串进来;命令原文
的回显那行不含 `Log effect, file:`,所以 `count_marker_lines` 只数带这个片段的行,回显不会被当成输出。
预检 0 行 = `console_unavailable`(焦点/键盘路径坏了),非 783 行 = `campaign_mismatch`(不是测试战役)。
行数是**轮询到 ≥783 或 30 s 超时后的最大值** —— 日志分块 flush,中途停在某个非零值不算终值;
apply 的 70 行 marker 同理(3 s 静默后再等 15 s,取最大值)。

**预检现在跑在 DLL 装载之前**(`_campaign_preflight`,在 `resolve_pid` 之后、`resolve_base_address`/
`inject_dll` 之前),并且 `--mode capture` 与 `--mode slot2` **都跑**。因此
`console_unavailable` / `campaign_mismatch` / `log_unreadable` 三种结论**不消耗游戏进程** —— 进程没被注入,
修好通道后同一个 pid 可以复用;`install_failed` 之后的结论才要换进程。预检同时记
`result["preflight_wait_s"]`(发命令到读到 783 行的墙钟秒数,保留 2 位小数;读不到日志时不写这个字段)
—— 它量的是引擎日志 flush 到 783 行要多久,对着 30 s 门限读:接近 30 s 的值说明门限余量不够,别把
`campaign_mismatch` 当成战役不对。

**save sha 门**:`stellaris_2226.sav` 的 sha256 必须等于钉住的 `6f271294…`。读不到文件 →
`campaign_unverified`,`--allow-drift` 只把「读到了但不匹配」降级成 `drift_allowed`(诊断用),
读不到仍然 `campaign_unverified`。预检的 783 行是战役形状的第二道门。

**drain 缓冲契约**:`C4WireDrainInto` 的调用方必须提供 `RING_CAP * RECORD_SIZE`
= 2048 × 3368 = 6,897,664 B 的远程缓冲(驱动只分配一次);DLL 写 `n * RECORD_SIZE` 字节并清空
环形计数,驱动只读回这 `n` 条。`layout` 导出先钉 `[1, mode, 3368, 2048, 944, 256, 8, 256]`,
任一字段漂了都是 `layout_drift`,后面的字节一个都不读。

**前置门一 — 导出集按模式取**(`required_exports(mode)`,2026-10-24):capture 要 `REQUIRED_EXPORTS`
的 13 个名字,slot2 在此之上多一个 `C4Slot2StatsInto`。`_flow` 在 `resolve_pid`/`inject_dll` **之前**
就拿按模式的集合与 DLL 导出做差,缺了当场 `dll_exports_missing`(detail 是缺名排序表)—— 没有计数器
导出的 DLL 不许拖进游戏里才在回读 `C4Slot2StatsInto` 时失败。capture 的目标集没有扩大,旧 capture
批次仍是合法目标。

**前置门二 — 控制台信念必须来自观测**(`console_gate`,与 `supervisor_ready` 并列,见 §54.10):
`_wait_ready` 在发出第一条 console 命令之前同时要求 supervisor 状态 `paused` + 新鲜(>5 s 按没在跑判)
**和** console 门通过。`console_gate` 只接受**判决性**观测:`console_open` 为 `True` 或 `False` 都放行
—— 首条命令之后面板常开,要求 `False` 会拒掉每一个多命令枪;键**缺失或 `None`** 拒成
`console_state_unknown`(键缺失 = daemon 早于像素通道,那是猜测不是观测);`console_forced` 为真值拒成
`console_belief_pinned`(钉住的信念不算观测)。两条拒绝的 detail 带 `console_open=` / `console_px=` /
`console_forced=` 三个实际值(`_wait_gate_detail`;整条状态记录都读不到时三者都是 `-`),读一眼就知道
是哪个门拒的。两条都发生在注入之前,不烧进程。

**前置门三 — daemon 回执,2 s 内具名**(`_send_console_or_abort`):每条 console 命令写出后,驱动从
**写命令之前**捕获的字节偏移起,读 daemon 自己的事件日志尾(默认
`SUPERVISOR_LOG = r"C:\temp\ns_game_log.jsonl"`,`--supervisor-log` 可覆盖)至多
`CONSOLE_RECEIPT_TIMEOUT_S = 2.0` 秒。偏移取在写之前,否则上一条命令的旧 `console_refused` 会中止
一发本来健康的枪;日志**stat 不到**(共享争用 / AV 扫描)时偏移记 `None`,直接跳过回执轮询 ——
读不到就退回 0 等于「从头分类整个文件」,会把上一条命令甚至上一轮运行的拒收算到这条健康命令头上,
而 `_slot2_phase` 那一枪发生在注入之后,烧掉的是游戏进程。`console_refused` /
`console_clipboard_failed` 当场中止,把 daemon 记的 `reason` 放进 result 的 `detail`(daemon 没记
reason 时落命令原文,`reason or text`);窗口内真出现 `console_sent` 才由它返回。**但健康的命令通常
不是靠 `console_sent` 返回的** —— daemon 的成功行要按完 `console_key_plan` 的全部键才写:
`BACKSPACE_CLEAR = 64` 个退格(每个 down/up 两个事件 × 20 ms = 2.56 s)、开面板的一下 tap(2 × 80 ms)、
粘贴/回车(6 × 80 ms)、末尾 0.3 s sleep,合计约 3.5 s(第二条起不按 tap,仍 3.3 s),**严格长于 2 s
窗口**;即时落盘的只有拒绝(`console_send_plan` 判 `None` 或 `focus` 失败时一个键都不按)。所以
**读不到回执不算失败,它是健康投递的默认形状,不是回执丢了** —— 静默到点即返回,日志轮转/读不出同样
按 `no_receipt` 吞掉,投递的终判仍是 783 行哨兵;§55 读一个 2 s 的静默返回时不要去找「缺失的成功回执」。
这一条把 §54.9 那种「命令被静默拒绝、30 s 后才以零输出暴露」变成 2 s 内的具名失败:窗口只会缩短一个
已知失败,永远不会推迟一发健康的枪(预批次的代码在 `.seen` 之后就立即返回)。

**verdict 表**(驱动按顺序判,先命中的胜出):**装载前**的结论(`supervisor_*`、
`console_state_unknown`/`console_belief_pinned`、`campaign_*`、`dll_exports_missing`、`game_not_running`、
预检三条)**不烧进程**,修好通道可以在同一个 pid 上再打;
`install_failed` 之后的结论才需要换进程。

| verdict | 条件 | 意思 |
|---|---|---|
| `supervisor_not_running` | 15 s 内状态文件缺失/过期/`no_game`/`stopped` | supervisor 没跑 —— 环境结论 |
| `supervisor_not_paused` | 状态新鲜但 15 s 内没到 `paused` | 战役没暂停成功,不要注入 |
| `console_state_unknown` / `console_belief_pinned` | `_wait_ready` 里 `console_gate` 拒:`console_open` 键缺失或为 `None` / `console_forced` 为真值 | 控制台信念不是判决性像素观测(§54.10),一条 console 命令都没发(`want paused` 已经写了)—— daemon/环境结论,不烧进程 |
| `campaign_unverified` | 存档 sha256 读不到 | 路径/权限问题 |
| `campaign_mismatch` | sha256 不匹配(且未 `--allow-drift`),或预检(装载前)行数 ≠ 783 | 不是那场 787 系统的测试战役 |
| `dll_exports_missing` | 缺 9 个 `C4Wire*`/`C4ScoredStatsInto`/`C4PredStatsInto` 或 `C2Sanity`/`C2Init`/`C1Run`/`C1EffectId`(`--mode slot2` 另需 `C4Slot2StatsInto`,按模式判,见前置门一) | 产物不对,注入之前就判 |
| `game_not_running` | `resolve_pid("stellaris")` 失败 | 环境结论 |
| `stale_module` | 注入前 base 已能解析(含 `ambiguous base`),或非 `is not loaded` 的解析失败 | 进程里已有 DLL 副本,**换新进程**,不重装 |
| `inject_failed` | `inject_dll` 或注入后的 base 解析失败 | 注入通道问题 |
| `sanity_failed` / `quickjs_init_failed` / `c1_failed` | `C2Sanity≠42` / `C2Init≠0` / `C1Run==0` 或 `C1EffectId==0` | C1/C2 前置门 |
| `layout_drift` | layout 导出 ≠ 8 个字或字段不匹配 | 驱动与 DLL 解码契约断了 |
| `install_failed` | `C4WireInstall != 0` | 谓词 detour/arm 失败,**不重试**,换进程 |
| `console_send_failed` | 命令写入 3 s 内 supervisor 未消费（seen-key 不变） | 键盘/supervisor 通道坏了，游戏没收到命令 |
| `console_refused` / `console_clipboard_failed` | 命令写出后 2 s 内 daemon 事件日志尾(`C:\temp\ns_game_log.jsonl`)出现该具名回执 | daemon 明确拒收,它的 `reason` 进 detail(daemon 没记时落命令原文)—— 预检(装载前)那次不烧进程,装载后的各相位烧;§54.9 的静默拒绝在这里变成具名失败 |
| `console_unavailable` / `log_unreadable` | 预检(装载前)marker 0 行 / 日志读不了 —— `log_unreadable` 在装载后的 capture、slot2 窗口也会出 | 键盘路径 / 路径问题;只在预检那次不烧进程 |
| `capture_not_delivered` / `capture_sentinel_mismatch` | capture 哨兵 0 行 / ≠ 783 行 | 命令没进游戏 / 战役形状不对 |
| `apply_not_delivered` / `apply_sentinel_mismatch` | apply 哨兵 0 行 / ≠ 783 行 | 第二次命令没生效 / 战役形状不对 |
| `no_calls` | capture `calls == 0` 且未提供谓词计数（纯函数默认） | 没有 `neo_action` 执行 —— 环境结论 |
| `predicate_not_reached` | capture `calls=0` 且谓词 detour 增量 `calls=0` | detour 没被调用：脚本没实例化 effect，或 detour 不在路径上 |
| `predicate_not_matched` | capture `calls=0`、detour 有调用、`patched=0` | detour 在跑，但没有任何对象带 armed token |
| `execute_not_reached` | capture `calls=0`、`patched>0` | vtable 已换，但 slot[1] Execute 没被调用 |
| `no_readable_ctx` | capture 记录 0 条 | ctx 读不出来 |
| `count_mismatch` | capture calls/records ≠ 787、有 dropped、或 drain 条数不符 | 调用数/记录数不对 |
| `no_scope_column` | 没有一列严格等于 `0..786` | 这次 capture 里没有可用的 scope 列 |
| `scope_order_unverified` | 只有排序后相等的列 | 列是 `0..786` 的乱序,driver 不猜 |
| `ambiguous_column` | 多于一条严格匹配列 | 需要人工看 capture 记录 |
| `apply_no_calls` | apply 窗口内 calls 没有增量 | 第二次 console 没生效 |
| `scored_js_error` | scored `js_err`/`invalid` 非 0 | QuickJS 分数脚本出错 |
| `apply_count_mismatch` | `resolved≠787` 或 `unresolved≠0` | 解析没覆盖全部系统 |
| `tier_mismatch` | tier 直方图 ≠ `(717,55,15)` | 分数表或阈值漂了 |
| `chain_mismatch` | `chain≠70` | tier≥1 没全部 chain |
| `log_mismatch` | `NEO_CHOKE_EFFECT` 行数 ≠ 70 | effect 没真正应用 |
| `record_drift` / `scan_drift` | 记录长度不对,或 DLL 记录的指针目标不在 blob 的扫描序列里 | 驱动与 DLL 的扫描规则漂了;DLL 只记 ≤8 个且跳过窗口读失败的指针,所以「扫描多出目标」本身合法 |
| `stats_drift` / `scored_stats_unreadable` / `mode_failed` / `apply_setup_failed` | 读回长度/解码/set-mode/set-spec 失败 | 驱动自检 |
| `host_dead` | `assert_game_alive` 失败 | **先跑 §45 的两个离线工具** |
| `restore_incomplete` | `C4WireDisarm` 返回 `-6` | 引擎字节没还原,打印 `RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY`,放弃该进程 |
| `cleanup_incomplete` | 流程本可 `ok`,但 `C4WireDisarm` 抛异常(读不到 rc) | 清理状态未知,不算成功;不要在该进程上重试 |

清理段固定:`SetMode(0)` → `C4WireDisarm`(`-1` 锁忙最多重试 6 次 × 0.5 s;6 次仍 `-1` 记为
benign,`0`/`-1` 都算清理成功)→ `assert_game_alive`。**绝不 `FreeLibrary`** — patch 过的 effect
对象持有 DLL 内的 vtable 副本。只有 verdict `ok` 且清理成功(host 存活、disarm 是 `0`/`-1`)退出码
才是 0;disarm 抛异常时 verdict 降为 `cleanup_incomplete`。**装载前中止的枪没有清理段可跑**
(进程里既没有 DLL,也没有 detour),退出码同样是 1,但进程保持可用 —— 别把这种 1 读成「烧了一枪」。

判读纯函数(`decode_records` / `_wire_stats` / `_scored_stats`、`pack_spec`/`unpack_spec`、
`column_sequences`/`find_scope_column`、`classify_capture`/`classify_apply` 等)由
`python3 -m pytest scripts/test_c4_wiring_probe.py -q` 覆盖,无游戏、无 Windows API。

## 实机调试:游戏监督器(`scripts/windows/game_supervisor.py`)

一个长驻在 Windows 机上的小循环:每 tick 读右上角暂停图标、读事件窗口带、消费一次命令文件,然后把
「想要的状态」推到游戏上。给 agent 用 —— 它把「事件弹出导致暂停、要人点选项」这种原本必须人盯的环节
变成一次文件写入。

宿主侧经根目录 `justfile` 调用(`NS_WIN_HOST` 可覆盖主机名):

```
just deploy                  # scp game_supervisor.py + launch_stellaris.py 到 C:/temp/
just launch                  # 经 Steam 拉起游戏(launcher 点击 + 30 s 观察窗,启动后仍是暂停)
just game start              # schtasks 拉起守护进程,见到状态心跳才返回
just game status             # 一行摘要:state/note/pid/hwnd/age/want/policy/handled/cmd/speed
just game pause | unpause | toggle
just game want playing       # 持久目标,不是一次性动作
just game policy first       # first | last | random | <1-based n>
just game choose 2           # 对当前事件一次性选第 2 项
just game speed up | down
just game click 1400 861     # 屏幕绝对坐标(窗口在 (0,0) 时等于窗口坐标)
just game console effect every_system = { log = "X" }   # 原样写进控制台(剪贴板粘贴)
                                             # 注意 keyword 在 effect 后、= 前;带括号的命令经
                                             # just/ssh 转手会被远端 shell 改写,驱动直接写命令文件
just game console_sync open | closed | auto   # 人工声明面板当前是否开着(auto 交还给像素观测)
just game console_close                      # 只在标记为「开」时按一下开关键,把状态收回「关」
just game dismiss            # 只在 paused 且有窗口 bbox 时生效(需 serve --auto-dismiss)
just game close              # WM_CLOSE 优雅关窗口(游戏会话内 PostMessage;不是 kill)
just game shot               # 存 C:\temp\ns_game_shot.png
just game stop | quit
```

`want=playing` 时,监督器发现「被事件或人暂停 + 有选项窗口」会先点一行再恢复运行;没有窗口的裸暂停
按「可能是人按的」处理,只报 `paused_no_window`、不发 Space —— 要恢复就发一次 `unpause`(或 `want playing`),
它带一个只生效一次的 `resume` 覆盖。`want=paused` 时反过来:只保留它自己发起的暂停。默认策略 `first`。

产物:`C:\temp\ns_game_status.json`(状态心跳,含 `epoch`)、`ns_game_log.jsonl`、`ns_game_shot.png`、
`ns_game_supervisor.out`(pythonw 的 stdout/stderr)。`state` 取值 `playing|paused|unknown|no_game|stopped`。

**判读陷阱:**
1. **SSH 会杀子进程树**,守护进程不能直接挂在 ssh 会话下。`start` 写一个只含 ASCII 的 `.cmd` shim,
   用 `schtasks /ru <user> /rl highest` 跑 `pythonw ... serve`;返回条件是**状态文件心跳**,不是
   schtasks 的退出码。改了 `game_supervisor.py` 要重新 `deploy` 再 `stop` + `start`(进程不会热加载)。
2. **命令文件只消费一次**,键是 `mtime_ns:size`;写入相同字节也算新命令。空行与不认识的动词只进日志,
   不动作。缩写入口(`just game pause`)等价于 `cmd pause`,固定等 0.8 s 后打状态 —— 这次状态可能是**动作
   之前**的心跳(`unpause` 后第一次读仍常显示 `paused`),要确认结果就再读一次 `just game status`。
3. **暂停图标按窗口相对几何采样**:右上角 `w-243..w-198, y5..50`(2160x1440 量得),红 956..965 / 绿 0
   为 paused,绿 200..207 / 红 0 为 playing。同一个 4.4.4 会话里暂停图标还会以橙红色出现(掩码 209 像素),
   所以 paused 的下限是 80 而不是峰值;顶栏棕色背景(`r<140`)落在掩码外。换分辨率、UI scale 或窗口模式
   要重新量;`unknown` 是真实第三态,监督器对 unknown **不动作**。
4. **事件窗口自己会暂停游戏,关窗口又可能自己恢复**。所以每次动作后都重新读图标,不复用上一 tick 的
   判读;`_restore` 发现链式窗口(刚关掉一个又弹一个)时推迟 Space,留给下一 tick 处理。
5. **choice 的判据是金色行,不是 bbox**:行需 `x0>=1150 && x1>=1450`、至少 2 行、gold>=8000。
   新闻窗口右边界约 1420,因此不会被当成选项。`dialog`(有面板、无金色行)只配 `dismiss`;
   `serve --auto-dismiss` 默认关,因为点 ✖ 的几何只在实测过的窗口类型上可信。
6. **数字键不选选项**(实测),必须点行中心。同一组行签名连点 3 次后记 `choice_stuck` 并停手,
   防止在无响应窗口上打转。
7. **`console <text>` 走剪贴板,不是逐字符打字**:`parse_command` 保留 `<text>` 的大小写、内部空白
   与引号,`_set_clipboard_text` 以 UTF-16LE + 双 NUL 写进剪贴板,再发:反引号(仅在
   `console_open` 为假时)→ 64 个退格 → Ctrl+V → Enter,**不发收尾反引号**。两条实机事实
   (2026-10-23):控制台键是**开关**,开着的面板被再按一下会**关掉**;命令执行完面板**不关**。
   不做状态记录时,同一会话的第二条命令的「开面板」那一下会把面板关掉,退格/粘贴/回车全打进游戏,
   命令一行都不执行(实测 783 条哨兵 0 行 —— 这正是 C4 首枪 `capture_not_delivered` 的机制)。
   所以 supervisor 用 `console_open` 记状态:首条命令按一下打开,之后只清行、粘贴、回车;换游戏
   进程时复位,人工看屏后可 `console_sync open|closed` 校正。64 个退格清输入行残留,退格 20 ms/个、
   其余 80 ms/个。`focus(hwnd)` 3 s 内拿不到前台就写 `console_refused`(不按键);剪贴板失败写
   `console_clipboard_failed`;成功写 `console_sent`(带 `opened` 标记)。`_send_key_events` 是
   **成对** down/up,修饰键必须跨 V 的 down/up 按住,所以 Ctrl 只能用 `_send_input_event` 逐事件发。
   数效果 marker 用驱动里的 `count_marker_lines`(只数同时含 `Log effect, file:` 与 marker 的行,
   控制台回显匹配不上)。

   **`console_open` 是三值信念,不是布尔**(`True` 开 / `False` 关 / `None` 未知)。第二枪暴露的
   不是「键序不对」,是**按键之前无人观测面板真的开着**:21:40:00 那条 `opened=true` 出 783 行,
   之后三条 `opened=false` 全 0 行,而这段时间 supervisor 日志里**一个事件都没有**(见 §54.9)——
   被按下的一次是 serve 循环自动补的 pause 空格,它把空格**打进开着的面板**,游戏因此永不暂停、
   像素判读一直报 `playing`,于是每个 tick 再按一次,而这条路**只写状态 note、不写日志**。
   现在的三条不变量:
   - **未知就拒绝**:`console_send_plan` 遇到 `None` 不猜奇偶,写 `console_refused` +
     `reason=console_state_unknown`,一个键都不按、剪贴板都不碰;只有 `console_sync` 或新进程能
     把 `None` 抬成已知值。宁可在日志里响一声,也不要一发静默的 0 行枪。
   - **碰过游戏就作废**:任何发给游戏的输入 —— `speed`、`click`、`dismiss`、自动点选项
     (`click_row`)、自动关窗 (`click_close`) —— 之后立刻 `console_open = None`。点在游戏区可能
     关掉或夺走面板焦点,而 daemon 看不见。`shot` 只截图像素,不作废。
   - **面板开着时不发空格**:`send_pause_key(state, hwnd)` 在信念为 `True` 时返回
     `blocked_console` 并按下不按键,状态 note 变 `pause_blocked_console` / `resume_blocked_console`;
     信念为 `False`/`None` 才真按(按下不改变面板状态,所以不作废)。
   代价:面板被我们打开后,自动暂停会**卡住并写明理由**。退出办法是新动词
   **`just game console_close`**(2026-10-23 加):仅在信念为 `True` 时按一下开关键并把信念写 `False`,
   信念为 `None` 时同样拒绝(奇偶未知,按一下可能反而打开)。解析在 `parse_command` 的无参动词表里。

   **`console_open` 现在是观测,不再是纯信念**(2026-10-24 实机校准,§54.10)。serve 每个 tick 在
   `plan_step` **之前**读一次面板文本框 —— 窗口比例的 `(120,640)-(400,880)` @2160×1440,数亮度 >180 的
   像素:实测**关 = 0**(6 帧全 0)、**开 = 2315**(4 帧逐字相同),所以阈值定在
   `CONSOLE_CLOSED_MAX=120` / `CONSOLE_OPEN_MIN=600`,**中间带判 `None` ⇒ 拒绝**(上面第一条不变量)。
   判据是**单帧密集亮字数**,不是帧差:两帧同态都能差 5.4 万像素、变化框铺满全窗(主菜单背景在动),
   差分没有定位能力。状态文件多两个字段:`console_px`(当帧像素数)与 `console_forced`(是否被人工钉住)。
   `console_sync open|closed` 会**钉住**信念、盖过观测,`console_sync auto` 松开让观测接管 —— 钉住存在的
   理由是这个框只在主菜单与一次载入局上校过,别的界面若自己点亮该区域会被读成「开」(后果是拒绝动手,
   不是错误按键)。**读帧的时机有坑**:日志记到开启动画途中的帧是 `64118` 和 `1298`,中间还有一帧读回
   `0`,即「刚按完键那一瞬」不是稳态判据;要自证就读够时间,否则落到 `None` 走拒绝。
7. **`speed up/down` 实机已验证**:`up` 让标签从「常速」变「快速」,`down` 回落。命令会把 `speed_sha`
   的前后值写进状态,但绿色标签背景会脉冲,哈希自己也会变 —— 判结果要读截图里的两个字,不要只看哈希。
8. **scp 上传可用,批量下载会把 SSH 连接重置**:取产物用分块 base64,单次输出 **≤700 字节**稳定
   (900 字节起连接被重置),不要 `scp -r`。远端控制台是 cp936,shim 与命令行都刻意保持 ASCII。
9. 纯逻辑(暂停判读、窗口分类、策略、命令词表、几何归一化)在 Linux 上跑:`just host-tests`
   (= `cd scripts/windows && python3 -m pytest tests -q`)。Windows 专有路径只在实机被调用。
10. **daemon 的父壳 `cmd.exe` 是一个真实的桌面窗口,会占住前台并把游戏从前台挤下去**。
    `start` 的 shim 是 `.cmd`,任务用 `/ru <machine>\<user> /rl highest` + `/run /I` 跑,所以 cmd 在交互
    桌面上开了一个可见控制台窗(pythonw 自己无窗)。**daemon 晚于游戏启动时**,这个窗压在画面上并持有
    前台,`focus()` 的 3 s `GetForegroundWindow()==hwnd` 判据就永远不成立 ⇒ 一切要先 focus 的动词
    (`console`、`click`、Space)全拒,日志写 `console_refused reason=focus`、状态写
    `resume_failed: focus refused before Space`。**判据在这两个字符串上,不在 `game.log` 上** ——
    `game.log` 只收 `log=` 与少量消息(day-1 存档 177 B 完全正常),把它当「有没有战役」的证据会得出
    错结论(2026-10-24 实机,§56.1)。处置是 `taskkill /F /PID <cmd>` 只杀父壳:pythonw 不是被 job
    管的树,存活且窗一消失 focus 立刻通。顺带第二条:那个窗会**污染像素判读** —— §54.10 的面板计数和
    `classify_window` 都读同一张截图,挡与不挡之间 `note` 能从 `paused_no_window` 漂到 `dialog_unknown`。
11. **ssh 长连接会在长跑的实机驱动跑完之前被重置,那之后 stdout 全丢**。枪的 artifact 若只在结尾
    打印(判词、Verify rc、host alive),就取不回来了。所以实机驱动的关键状态要能被**事后独立读回**:
    `scope_probe` 的 `installed` 是实时 bool、`verified` 是 `verify()` 的实时返回值(不是闩锁),
    配一次 `C2ScopeProbeStatsInto` 双读(`calls` 两秒不涨 = 热路径已还原)就把「Uninstall 跑过、引擎
    字节完好」证完,不需要驱动那行输出(§56.3)。

### `scripts/windows/keep_awake.py` —— 桌面可达性守护

常驻在交互会话里,用 `SetThreadExecutionState` 顶住空闲,并**观测**当前输入桌面名以判定桌面可达性。
它掐掉的是 2026-10-24 只读测得的那条自动链:插电 60 分钟关屏(`VIDEOIDLE ac = 0xe10 = 3600 s`)、
电池 3 分钟即睡(`STANDBYIDLE dc = 0xb4`),唤醒要求登录 ⇒ 桌面变成 `Winlogon`,而 LogonUI 占住 Console
会话就是那两次 `just launch` 停在 `SetForegroundWindow` FALSE、`inner_exit code=22` 的现场。断言是
**进程级**的(`ES_CONTINUOUS|ES_DISPLAY_REQUIRED|ES_SYSTEM_REQUIRED`),所以不写注册表、不改电源计划、
不改屏保与登录策略:进程一退,Windows 立刻恢复原行为。

命令行(经根目录 `justfile`,`just deploy` 之后 `C:/temp/keep_awake.py` 与本地逐字节相同):

```
just awake start            # 只在「没有东西在跳」时拉起任务;成功判据是**比它看到的那条更新**的心跳
just awake status           # 一行摘要,读不到也返回 0(它只报现状,不判决)
just awake check            # 判决:0 unlocked / 1 锁或读不到或过期 / 2 状态文件 absent
just awake stop             # 写 quit + 登记去重键 + 删任务;daemon 自己写 state="stopped"
just awake serve --interval 5.0 --assert-every 25.0 --stop-after-s 0
```

`serve` 是 daemon 本体:`--interval` 是 tick 秒数,`--assert-every`(`DEFAULT_ASSERT_EVERY_S = 25.0`)
是重申断言的间隔,`--stop-after-s` 非 0 = 有界会话(也是循环的测试接缝)。状态文件
`C:\temp\ns_awake_status.json` 每 tick 写一次,`desktop` 七态
`unlocked|locked|screensaver|wrong_session|unreadable_denied|unreadable_error|unknown_name`,
`state` 取 `serving|stopped`,`STATUS_MAX_AGE_S = 15.0` 是消费端认可的快照年龄(三个漏拍)。
另有 `ns_awake_cmd.txt`(+ `.seen` 去重键)、`ns_awake_log.jsonl`(只在桌面状态**变化**时写一行
`desktop_change`)、`ns_awake_task.cmd`、`ns_awake.out`。

**判读陷阱:**

1. **它只掐空闲链**。人工 `Win+L`、别人远程操作、以后新增的组策略锁都不在能力范围内;`check` 报
   `locked` 时**先想人,不要想守护坏了**。守护也绝不在 secure desktop 合成输入、不尝试解锁、不猜口令。
2. **`unreadable_denied` ≠ 锁**。它是 `OpenInputDesktop` 被 DACL 拒(`err=5`,detail 形如
   `err=5 sessions=1/1`);判决按保守方向走「不可开枪」,但根因可能是进程不够权限而非桌面被锁 ——
   两个名字分开就是为了不让人去查一个不存在的锁。同一族里还有 `err=1`:那是**会话不对**,
   `OpenInputDesktop` 只看得到调用方自己会话的输入桌面,而 ssh 起的进程在 session 0,那里没有
   控制台输入桌面可开(实机 2026-10-24:`h=None gle=1`);`desktop_detail` 里出现 `sessions=-1/1`
   则是更早的一格 —— 自己的会话号都没读到(`ProcessIdToSessionId` 的第一参是**进程号**,
   递句柄进去一律 `gle=87`)。两种都不是锁,也都修不好,只能把守护放回控制台会话里跑。
3. **断言随进程消失**。`stop`、被杀、机器重启 ⇒ 顶不住空闲,这是刻意的安全性质(不改电源计划);
   唯一的发现途径是 `check` 的非 0 退出码,而「屏幕还亮着」不能当证据 —— 顶住它的进程可能已经走了,
   状态文件里 `state` 仍是 `serving` 的僵尸心跳靠 `STATUS_MAX_AGE_S` 兜住。同一条也管 `start`:
   心跳新鲜只让它**不重复拉起**第二个守护,不当成「已经在使用」的成功 —— 成功必须是一条**严格更新**的
   心跳。写完最后一条就死的守护会让 `start` 报 `STATUS=timeout` 返回 1,而不是静默地把没顶住的机器
   交回给你。`powercfg /requests` 是它的证人:断言期间该命令里必须有本进程的 `DISPLAY`/`SYSTEM`
   请求条目,`stop` 之后必须消失(两条都已在 `evidence/logs/keep_awake_live_4_4_4.log` 实机取到;
   同一份输出里游戏自己与音频驱动也各有一条,所以**别人的请求不是我们的证据**)。
   状态文件里的 `assert_rc` 是上一次调用的**前一状态**,不是「现在顶没顶住」:`0x80000000` 读作
   「这条断言刚起」,`0x80000003` 读作「起之前还挂着」。
4. **无人值守请插电**:电池下 3 分钟就睡,而断电是任何软件都救不了的。
5. **`assert_rc` 是日志字段,不是判据**。`SetThreadExecutionState` 返回 `0`(断言压根没挂上)时 `check`
   与 `keep_awake_gate` 照旧放行 —— 两处的判决只看 `state`/`epoch`/`desktop`。断言真的挂没挂,证人只有
   `powercfg /requests`(第 3 条)。
6. **`locked` 那一格实机未取**。2026-10-24 的验收全程无人按 `Win+L`,所以锁屏分支只有离线测试钉着;
   日志 §8 留了补它的命令与 Expected(`DESKTOP=locked`、`RC=1`、`desktop_detail` 含 `Winlogon`)。

**与开枪的关系:**`c4_wiring_probe._flow` 的**第一道门**读 `ns_awake_status.json`,
`keep_awake_gate` 的六个 verdict —— `keep_awake_absent|keep_awake_stopped|keep_awake_stale|
desktop_locked|desktop_unreachable|desktop_unobserved` —— 一律中止,且中止发生在为游戏写
`want paused` **之前**(连 launcher 的 22 都不用花)。两端唯一的耦合是两个字符串:状态文件的
`desktop == "unlocked"` 与 `state == "serving"`,没有 import 关系。这是 §54.9
「`console_open` 是信念不是观测」在桌面可达性这条新轴上的重申。

**launcher 侧也接了这道门**(`launch_stellaris.py` 的 `desktop_gate_or_none`,新退出码 **25**):位置在
`_run_launch_chain_phases` 里 dry-run 返回之后、`launcher_click` 之前 —— 晚一步就等于没接,锁屏下的点击失败
仍会被记成 22/23,而那正是 exit 23 至今判不下去的原因。`--keep-awake-status` 的默认值是
`keep_awake.STATUS_PATH`,不是第二份 `C:\temp\...` 字面量。

两处判决函数(`keep_awake.desktop_gate` 与 `c4_wiring_probe.keep_awake_gate`)**各留一份是刻意的**:开枪通道
是 `C:/temp/<name>.py` 线上契约的一部分,不能因为 launcher 侧要读同一个文件就获得一个 import 关系。代价有两条,
都记在这里:(1) 状态窗口 `STATUS_MAX_AGE_S` 在 `keep_awake.py:50` 与 `c4_wiring_probe.py:499` 各有一份字面量
`15.0`,**本计划不合并** —— 合并意味着给线上契约加一条跨模块依赖;(2) launcher 侧把 `screensaver`/
`wrong_session`/`unknown_name` 归进 `desktop_unreachable`,而开枪通道把它们留在 `desktop_unobserved`。
两者都拒绝,区别只在诊断:桌面被**读到**但不是 `unlocked` 的三种状态,在 launcher 这一侧是「可达性已知为否」,
`desktop_unobserved` 因此只留给 `DESKTOP_STATES` 以后新增、这个名字还不认识的状态。

**exit 23 现在自带三档观测,但仍不是结论。**`launcher_click` 每轮在 `step=click` 之后补一条
`step=trace`(`owns_foreground` / `cursor_at` / `launcher_alive`,rect 已在 `step=click` 里记过,不重复),
耗尽三轮后在返回 23 之前记一条 `step=diagnosis`,值是 `click_not_delivered|wrong_window|
handoff_never_fired|inconclusive`。**退出码不因它改变**,读回失败(`GetForegroundWindow`/`GetCursorPos`
任一条抛或返回 FALSE)只把对应字段写成 `None`,而任何一轮带 `None` 就把整条结论压成 `inconclusive` ——
仪器没测到不等于测到了反面。判读陷阱:`handoff_never_fired` 只说「三轮都拿到焦点、光标都落在那一点、
launcher 仍没推进」,**不**说「Continue 按钮在别处」;这一档要成为结论得等实机那一次(离线无从知道
CEF 把按钮画在哪)。

## 我们自己产物的反汇编(`scripts/pe_disrva.py`)

`scripts/disrva.py` 与 `scripts/cap.py` 反汇编的是**游戏**:它们只收 RVA,自己去找 `stellaris.exe`
(`NS_STELLARIS_EXE` / 固定候选)。`scripts/pe_disrva.py` 反汇编的是**你给的那份 PE**,路径是必填的
第一个位置参数 —— 本仓库用它读自己构建的 `zig-out/bin/stellaris_quickjs.dll`(§45/§47 的 `js_rc` trap),
不读游戏,所以没有默认路径、也不受 `NS_STELLARIS_EXE` 影响。

```
python3 scripts/pe_disrva.py <pe_path> <rva_start_hex> [<rva_end_hex>|<count>]
python3 scripts/pe_disrva.py zig-out/bin/stellaris_quickjs.dll 0xbba0 0xbc01   # end 不含(§48 产物的 js_rc)
python3 scripts/pe_disrva.py zig-out/bin/stellaris_quickjs.dll 0xbba0 40       # 40 条(默认 64,上限 4096)
```

**RVA 每次重链都会变**:上面的 `0xbba0..0xbc01` 是 §48 产物(`79c8dc24…`)的 `js_rc`;
`scripts/test_pe_disrva.py` 的 `trap_span()` 从 `quickjs.c:1494:12` 的 SourceLocation 反查
`record → LEA → .pdata` 得到当前区间,所以测试不会因重链失效。§47 的 `0xbd70..0xbdf3` 属于基线
产物 `77c0c35e…`。

- 第三个参数:`0x` 开头 = **结束 RVA,不含**;纯十进制数字 = **指令条数**。所以小的十六进制结束 RVA
  必须带 `0x`(裸 `100` 是 100 条,不是 rva 0x100)。
- 每条绝对 `call`/`jmp` 目标与每个 `rip+disp` 操作数标 `  #0x<rva>`;`#0x` 后是**相对 image base**
  的 RVA(image base 从该 PE 的 optional header 读),所以能和 `dll_ubsan_site.py` 的
  `record_rva=` 比 —— 但那条只对**它解码的 `TypeMismatchData` 记录**成立(见上一节判读陷阱 7)。
- **只解码带 `IMAGE_SCN_MEM_EXECUTE`(`0x20000000`)的段**。RVA 0 落在 PE 头里,capstone 会把 `MZ...`
  当指令解出来,所以工具在喂给它之前按 section 位拒绝。可执行段外的起点、文件映射之外的起点、或解出
  **0 条指令**,一律退出 1 —— 那是「这段不是代码」的结论。
- 退出码三义与 `dll_ubsan_site.py` 一致:**0** = 至少解出 1 条;**1** = 不是可执行代码 / 0 条;
  **2** = 调用错了(缺参、非 hex、文件读不到、非 PE32+、**截断的镜像**(section 表声明的 raw 字节
  越过 EOF)、end < start、count <= 0),一行 stderr、无 traceback。
- **起点不落在任何段里、或落在非可执行段里,是 1 而不是 2**(控制器的裁定):那是「这个文件里这段
  确定不是代码」的结论;2 只留给**读不了 / 非 PE / 截断的输入**和写错的调用参数。
- 上限 4096 条,超出打 `; truncated at 4096 insns`;头行给 `N insns, M bytes`。**未截断时** end 模式下
  `M` 等于 `end - start`;可一旦超过 4096 条(或 end 越过段尾被裁剪),头行的 end 是**有效(裁剪后)
  的 end**,`M` 小于请求的 `end - start`,同时带上截断提示(实测 `0xbba0 0x800000` 头行裁到
  段尾并附 `; truncated at 4096 insns`;未截断的 `0xbba0..0xbc01` = §48 产物的 `js_rc` = 97 字节 = 29 条)。

**判读陷阱:**
1. **反汇编证明的是「被检查的是哪个表达式」,永远不是运行时值。** 它读得出 `js_rc` 的
   `test rdx,rdx` 在 `add rcx,-8` 之前、测的是原始指针;它证明不了那一枪里 `rdx` 是不是 NULL。
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
