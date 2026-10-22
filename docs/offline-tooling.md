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

**Host caveat**: 当前基线(2026-10-22 实测 `zig build test --summary all`)=
`Build Summary: 22/25 steps succeeded (1 failed); 296/296 tests passed`,裁定 **P15 把这一步记为绿**。
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

## IDA headless 现状(环境状态,非规则)

**IDA MCP**: registered in `~/.qoder/settings.json` (`/home/lofibass/.local/bin/idalib-mcp --stdio --unsafe`).
**Status updated 2026-09-29**: headless open now works — session `f3ea6101` is live on the local
`stellaris.exe` copy (there is also a `stellaris.exe.i64`, 585 MB, produced by that headless open, which
contradicts the earlier "the `.i64` stays on Windows" note; neither file was hand-edited).
The earlier `License not yet accepted, cannot run in batch mode` failure is **no longer reproducible**.

两条**规则**不随状态改变,留在 `AGENTS.md`:不许绕过 license 守卫分支,以及本 IDB 上不得调用
`ida_auto.plan_and_wait`。

## 一次性探测脚本

历次取证的一次性探针已经不在 `scripts/` 顶层,按取证批次归进三个目录,每个目录自带 README
(逐行列出「这个文件当时在回答哪个问题」):

| 目录 | 内容 | 判据 |
|---|---|---|
| `scripts/scratch/2026-09_frida_hot_site_spies/` | `fs*.py`、`body*.py`/`body.js`、`spy*.{py,js}`、`strs*.py`、`kv*.py`、`vt.py`/`vtlive.{py,js}`、`walkdb.*`、`prologue.*`、`caller*.py`、`regfn.py`、`missstr.py`、`strdump.py` | 需要运行中的游戏 + Frida |
| `scripts/scratch/2026-09_offline_hardcoded_oneshots/` | `callscan*.py`、`prol_exec*.py`、`rtti_check*.py`、`rtti_offline.py`、`refscan.py`、`sec.py`、`pedump.py`、`verify_base.py`、`dumpvt.py`、`vtcheck.py`、`kwmeta.py`、`cap2.py` | 只读 exe 拷贝,但**路径写死成 `D:\SteamLibrary\…`** |
| `scripts/scratch/2026-09_frida_detour_era/` | `restoreexec.py`、`nsunload.py`、`peekexec.py`、`read_remote_mem.py` | detour 路线的善后 |

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
