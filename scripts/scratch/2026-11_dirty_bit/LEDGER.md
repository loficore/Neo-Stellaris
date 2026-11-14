# SDD ledger — plan: issue #46 方案 2(脏位 `0x296cc68` 可用性)

零 shot、零 Windows、零 `src/` 改动。exe:`/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe`
(46,253,688 B,sha256 `9242c40a…2b1a56`)。围栏基线 `scripts/test_scripts_layout.py` = 38 passed。

## Pre-flight

- Task 1 → Task 2/3 共享接口:`xrefs_296cc68.tsv`(列 `insn_rva fn_start fn_end form mnemonic op_str`)。一致。
- Task 2 → Task 3/4 共享接口:`container_writers.tsv`(列 `offset insn_rva fn_start dir sets_bit0`)。一致。

## 任务记录

- Task 0: complete(exe 身份 + 38 passed 基线)。
- Task 1: complete。新增 `global_xrefs.py`;实读 `refs=24 set_bit=17 overwrite_imm=4 overwrite_reg=1
  read_mask=1 read_bit=1 other=0`,与慢通道 `find_refs.py`(24 refs)地址集合逐条相等。
- Task 2: complete。`container_writers.tsv` 37 行(30 yes / 7 unknown)。
- Task 3: complete。§10.1–§10.3;判词 `dirty_bit_cleared_by_consumer`。
- Task 4: complete。§10.4–§10.5;`+0x5a0` = `stamp_candidate`,`+0x137d` = `boolean_flag`。
- Task 5: complete。§10.6–§10.8;围栏 38 passed。

## Rulings

- **Ruling: 快通道用 `target = insn_end + disp32` 位移反查而非线性解码** — `find_refs.py` 单次 5–10 min
  且截断 25 条,本计划只跑它一次;快通道 19 s,完整。代价:若一条候选的指令跨 `.pdata` 边界漏识,
  由慢通道兜底(本次两通道逐条相等)。
- **Ruling: `.pdata` 连续块合并为逻辑函数再 join** — 删例程 7 段(`0x8bbc20..0x8bbd8a`),计数减在
  `0x8bbd11` 段、置位在 `0x8bbd2d` 段;不合并则同一条例程被判 `unknown`。合并正确性由 `0x8bbd90` 验证
  (`0x8bbda7 jle 0x8bbe2f` 跳到自己的尾段 ⇒ 三段是一个函数)。代价:若两个不同函数恰好紧邻无 padding
  会被误并(本次未观察到)。
- **Ruling: `container_writers.tsv` 从 514 条原始写点收窄到 37 条** — `field_xrefs.py` 计数是上界,同一位移
  遍及无关结构。保留:(a) `+0x137d`/`+0x59c` 全部;(b) 系统对象算子(写 `+0x137d` 或属 `0x296cc68` 族);
  (c) 同时写 `+0x59c` 计数的函数(整体重建必须搬计数)。代价:`+0x588/+0x590/+0x598` 上若有既非族内、
  又不搬计数的重建写者,会被漏掉;该风险在 §10.6「incomplete 未证」里显式保留。
- **Ruling: 计划 Task 4 Step 1 的前提「删例程不改 `+0x5a0`」为假** — 删例程尾段 `0x8bbd74`
  `mov [rdi+0x5a0],rax` 确实写它。故 `+0x5a0` 不是 `pointer_to_last_element`,判 `stamp_candidate`。
- **Ruling: `0x1d90e00` 排除为边容器写者** — 它把 `+0x590` 写 dword、`+0x594` 写哨兵 `0x7fffffff`、
  `+0x5a0` 写 byte,布局与边容器冲突。
- **Ruling: `0x249500` 保留 `unknown`** — 类析构(vtable `0x24bfe00`)把 `+0x588/+0x590/+0x59c` 一组
  vector 归零,形状同边容器,但静态上无法钉到系统对象。不影响判词(见 §10.6)。

## 复现

```sh
python3 scripts/scratch/2026-11_dirty_bit/global_xrefs.py 0x296CC68
python3 scripts/find_refs.py 0x296cc68                 # 慢通道,只跑一次
python3 scripts/scratch/2026-11_transitability/field_xrefs.py 0x588 0x590 0x598 0x59c 0x5a0 0x137d --writes-only
python3 scripts/scratch/2026-11_dirty_bit/container_writers.py
python3 -m pytest scripts/test_scripts_layout.py -q    # 38 passed
```
