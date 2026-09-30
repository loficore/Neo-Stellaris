# 离线 RE 工具目录与判读陷阱

本文件收录 `scripts/` 下**长期有效**的离线探测工具的完整判读说明:每条命令的输出、
它编码的 capstone/PE 陷阱、以及曾经导致错误结论的度量口径。`AGENTS.md` 只保留一行一条的索引,
用到哪个脚本时再来读这里。

结论本身(§17–§30)在三卷取证日志 `evidence/analysis/runtime_444_*.md`——§16–§23 在
`runtime_444_keyword_pipeline.md`,§24–§30 在 `runtime_444_c1_validation.md`;本文件只讲**怎么量**。

## 前置条件

**Binary**:`D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe` on the Windows host `Windows_Jiaolong`, copied to
`/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe` on Linux — sha256 `9242c40a…b1a56` identical on both, 46,253,688 bytes, 4.4.4.
`scripts/rttibatch.py` / `scripts/cap.py` find it automatically (`NS_STELLARIS_EXE` overrides).
The `.i64` (705 MB) stays on Windows.

**Game data**: `/var/lofibass_ssd/data/stellaris/4.4.4/{common,events}` (2,186 files, copied 2026-09-29 from
`D:\SteamLibrary\steamapps\common\Stellaris\`) — scripted_effects, scripted_triggers, on_actions, events, defines, etc.

**Offline toolchain dependencies are pinned** in `scripts/requirements.txt` (capstone 5.0.7, pefile 2024.8.26,
unicorn 2.1.4). Only `emu_desc.py` needs unicorn, and its artifacts are checked in, so regenerating the oracle
is the step that requires it — `zig build test` does not.

**Host caveat**: two `zig build test` steps that link QuickJS cannot start here
(`/lib64/libm.so.6: version GLIBC_2.35 not found`). Pre-existing toolchain mismatch, not a code failure;
every compiling test passes (272/272; 293/293 until `effects/id_mapper.zig` and its 21 tests were retired
— see §29 of `runtime_444_c1_validation.md`).

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

## IDA headless 现状(环境状态,非规则)

**IDA MCP**: registered in `~/.qoder/settings.json` (`/home/lofibass/.local/bin/idalib-mcp --stdio --unsafe`).
**Status updated 2026-09-29**: headless open now works — session `f3ea6101` is live on the local
`stellaris.exe` copy (there is also a `stellaris.exe.i64`, 585 MB, produced by that headless open, which
contradicts the earlier "the `.i64` stays on Windows" note; neither file was hand-edited).
The earlier `License not yet accepted, cannot run in batch mode` failure is **no longer reproducible**.

两条**规则**不随状态改变,留在 `AGENTS.md`:不许绕过 license 守卫分支,以及本 IDB 上不得调用
`ida_auto.plan_and_wait`。

## 一次性探测脚本

`scripts/` 下 `body*.py`、`spy*.py`/`spy*.js`、`fs*.py`、`strs*.py`、`callscan*.py`、`vt*.py`、
`prol_*`、`peekexec.py`、`verify_base.py` 等是历次取证的一次性探针,结论已进 `evidence/` 与
`runtime_444_*.md` 三卷对应 §,**不作为接口维护**——可以失效,但不要在新结论上重犯它们已踩过的口径错误
(见各节"陷阱"段)。
