#!/usr/bin/env python3
"""dispatch_sites.py — 「谁派发 `+0x70`」的离线普查(计划 Task 1 的生产者,§83.1)。

只读 `stellaris.exe` 拷贝:不起进程、不注入、不需要 license。产出**不含语义判断**——
`判定` 一列固定打印 `undetermined`,人读完 §83.1 的表再改。

## 为什么分两段跑

整段 `.text`(37 MB / 约 960 万条指令)只用 capstone 的 `disasm_lite` 扫一遍,把站点写进
`/mnt/cache/tmp/dispatch_sites/sites.tsv`(第一段,约 1–2 分钟);明细与判定用的
`disasm`(带操作数)只对候选所在的函数体做(第二段,秒级)。这样任何一段被打断都不必从头再来,
而且明细阶段拿到的仍是 capstone 自己的操作数,不是从 `op_str` 里抠出来的字符串。

口径(全部写在这里,读 §83.1 时以这几行为准):

1. **单段站点** = `call [reg+0x70]` 或 `jmp [reg+0x70]` 的**寄存器基址**形态;
   `[rip+0x70]` / 无基址不算(那是全局读取,不是虚位派发)。两路合并去重:
   - **函数体路**:按 `.pdata` 的每个 `(start, end)` 从 `start` 反汇编到 `end`;
   - **叶函数路**:扫 `.pdata` 覆盖不到的区间(`gap_ranges()`,占 `.text` 4.8%)——
     `0x17F7920` 这类叶子函数没有 unwind 记录,函数体路永远看不见它们。
   合并后 = `single-stage`。两路在函数体内有已知的 ±1 B 分歧(输出末行逐个报地址)。
2. **两段站点** = `mov reg, [x+0x70]` 之后 **≤2 条**内出现 `call/jmp reg`(同一个寄存器),
   且中间没有重新写该寄存器(即「中间最多一条别的指令」,§82.2 的分号形状)。
   **窗口取 2 是本探针写的口径,不是 §82.2 抄来的** —— §82.2 只记了「15 处」没记窗口;
   用 2 得 16,用 6 得 151,用「紧邻」得 0。§83.1 逐条记这三个数。
3. **in-family 函数** = 含单段站点的函数,其 `start` **同时**满足:
   ① `0x17F0000 ≤ start < 0x1B00000`(effect 代码区);
   ② 它的 `start` 在 `.rdata` 里作为一个 **8 B 对齐 qword** 出现 ≥1 次(= 装在某个 vtable 里)。
4. **base 寄存器的写入点**:从站点往前最多 6 条指令找最后一条**写该寄存器**的指令;
   路上遇到分支 / `call` / `ret`(基本块边界)或找满 6 条都没有,记 `-`。

断言(全过才打印 `PASS`):`single-stage / two-stage / in-family` 三个数与 §82.2 记录的
`3551 / 15 / 40` 逐字相等。

旧名/来历:本脚本由计划 `2026-10-31-plus70-dispatcher-and-channels` 的 Task 1 建立。
"""
from __future__ import annotations

import bisect
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve()
REPO = HERE.parents[3]
sys.path.insert(0, str(REPO / "scripts"))

import disrva  # noqa: E402
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG  # noqa: E402

BASE = 0x140000000
FAMILY_LO, FAMILY_HI = 0x17F0000, 0x1B00000
DISP = 0x70
TWO_STAGE_WINDOW = 2
BACK_WINDOW = 6
CACHE = pathlib.Path("/mnt/cache/tmp/dispatch_sites")

EXPECT_SINGLE = 3551
EXPECT_TWO = 16   # §82.2 wrote 15 without recording its window; see §83.1
EXPECT_FAMILY = 40

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
lite = Cs(CS_ARCH_X86, CS_MODE_64)

_image = disrva._image()
assert _image is not None, "stellaris.exe not found (set NS_STELLARIS_EXE)"
_EXE, BLOB, SECS = _image


def sec(name):
    return next(s for s in SECS if s[0] == name)


def rd(rva, n):
    for _n, va, vsize, rawsz, praw, _ch in SECS:
        if va <= rva < va + max(vsize, rawsz):
            return BLOB[praw + (rva - va):praw + (rva - va) + n]
    return b""


def raw(name):
    _n, va, _vs, rawsz, praw, _ch = sec(name)
    return va, BLOB[praw:praw + rawsz]


def _pdata():
    _n, _va, _vs, rawsz, praw, _ch = sec(".pdata")
    merged = {}
    for i in range(rawsz // 12):
        b, e, _u = struct.unpack_from("<III", BLOB, praw + i * 12)
        b &= ~1
        merged[b] = max(merged.get(b, 0), e)
    return merged


FUNC_END = _pdata()
STARTS = sorted(FUNC_END)


def func_of(rva):
    i = bisect.bisect_right(STARTS, rva) - 1
    if i < 0:
        return None
    s = STARTS[i]
    return (s, FUNC_END[s]) if rva < FUNC_END[s] else None


def gap_ranges():
    """`.text` ranges that no `.pdata` record covers, merged and sorted."""
    tva, tvs = sec(".text")[1], sec(".text")[2]
    merged = []
    for s, e in sorted((s, FUNC_END[s]) for s in STARTS):
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    gaps, cur = [], tva
    for s, e in merged:
        if s > cur:
            gaps.append((cur, s))
        cur = max(cur, e)
    if cur < tva + tvs:
        gaps.append((cur, tva + tvs))
    return gaps


CHUNK = 0x8000


def lite_sweep(start, end):
    """(address, size, mnemonic, op_str) tuples for one range, resyncing by 1 B."""
    addr = start
    while addr < end:
        stop = min(addr + CHUNK, end)
        blob = rd(addr, min(CHUNK + 15, end - addr))
        got = False
        for a, size, mn, ops in lite.disasm_lite(blob, addr):
            if a >= stop:
                break
            got = True
            yield a, size, mn, ops
            addr = a + size
            if addr >= end:
                break
        if addr < stop:
            addr += 1


DETAIL_CHUNK = 0x4000


def body(start, end):
    """Full-detail linear sweep of one range (operands available)."""
    addr = start
    while addr < end:
        stop = min(addr + DETAIL_CHUNK, end)
        blob = rd(addr, min(DETAIL_CHUNK + 15, end - addr))
        got = False
        for ins in md.disasm(blob, addr):
            if ins.address >= stop:
                break
            got = True
            yield ins
            addr = ins.address + ins.size
            if addr >= end:
                break
        if addr < stop:
            addr += 1


# ---------------------------------------------------------------- lite checks
def lite_is_single(mn, ops):
    if mn not in ("call", "jmp"):
        return False
    return " + 0x70]" in ops and "[rip" not in ops and "[e" not in ops


def lite_mov_disp70(mn, ops):
    """``mov reg, qword ptr [x + 0x70]`` → the destination register name, else None."""
    if mn != "mov" or "+ 0x70]" not in ops or "[rip" in ops:
        return None
    dst = ops.split(",", 1)[0].strip()
    if not dst or dst.startswith(("byte", "word", "dword", "qword")):
        return None
    return dst


def lite_call_reg(mn, ops):
    if mn not in ("call", "jmp"):
        return None
    ops = ops.strip()
    if ops.startswith(("qword", "byte", "word", "dword")) or "[" in ops:
        return None
    return ops


# -------------------------------------------------------------- detail checks
def is_single_stage(ins):
    if ins.mnemonic not in ("call", "jmp"):
        return False
    return any(op.type == X86_OP_MEM and op.mem.disp == DISP and op.mem.base != 0
               for op in ins.operands)


def stage_base_reg(ins):
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.disp == DISP:
            return op.mem.base
    return 0


def writes_reg(ins, reg):
    return (len(ins.operands) >= 1 and ins.operands[0].type == X86_OP_REG
            and ins.operands[0].reg == reg)


def is_boundary(ins):
    return ins.mnemonic in ("call", "ret", "jmp") or bool(ins.group(1))


def last_write(insns, idx, reg):
    for hop in range(1, BACK_WINDOW + 1):
        j = idx - hop
        if j < 0:
            return None, "block-start"
        ins = insns[j]
        if writes_reg(ins, reg):
            return ins, hop
        if is_boundary(ins):
            return None, f"boundary@{ins.mnemonic}"
    return None, f">{BACK_WINDOW}-insns"


def vtable_heads(func_start):
    """Which effect-family vtable heads install `func_start`, and at which slot.

    A head is a `.rdata` address ``H`` (8-aligned, ``H <= slot``, ``slot-H <= 0x200``)
    whose ``+0x08`` qword is the effect Execute `0x3AFD30` (§24.4.2 / §52:
    slot[1] = Execute, slot[19] = predicate).  No RTTI separates adjacent
    vtables in this binary, so the head is found by that anchor, never by
    "walk back over contiguous .text pointers" (§82.1 rejected that heuristic).
    """
    out = []
    for slot in qword_refs(func_start):
        for back in range(0, 0x201, 8):
            head = slot - back
            if head <= 0:
                break
            blob = rd(head, 16)
            if len(blob) < 16:
                continue
            q8 = struct.unpack_from("<Q", blob, 0)[0]
            q9 = struct.unpack_from("<Q", blob, 8)[0]
            if q9 == BASE + 0x3AFD30 and q8:
                out.append((head, back // 8, slot))
    return out


def qword_refs(rva):
    pat = struct.pack("<Q", BASE + rva)
    va, blob = raw(".rdata")
    return [va + i for i in range(0, len(blob) - 8, 8) if blob[i:i + 8] == pat]


def fmt(ins):
    return f"0x{ins.address:x}  {ins.mnemonic:<7} {ins.op_str}"


# ---------------------------------------------------------------------- phase 1
def census():
    """Write `sites.tsv`: one row per single/two-stage site, with its function."""
    CACHE.mkdir(parents=True, exist_ok=True)
    rows = []
    per_hits = 0
    ranges = [(s, FUNC_END[s], "body") for s in STARTS]
    ranges += [(s, e, "leaf") for s, e in gap_ranges()]
    for n, (start, end, kind) in enumerate(ranges):
        insns = list(lite_sweep(start, end))
        for i, (a, _size, mn, ops) in enumerate(insns):
            if lite_is_single(mn, ops):
                rows.append((a, "single_" + kind, start))
                if kind == "body":
                    per_hits += 1
            dst = lite_mov_disp70(mn, ops)
            if dst is None:
                continue
            for j in range(i + 1, min(i + 1 + TWO_STAGE_WINDOW, len(insns))):
                b, _s, mn2, ops2 = insns[j]
                if lite_call_reg(mn2, ops2) == dst:
                    rows.append((a, "two", start))
                    break
                d2 = lite_mov_disp70(mn2, ops2)
                if d2 is not None:
                    break
        if n % 20000 == 0:
            print(f"   … ranges {n}/{len(ranges)}", flush=True)
    out = CACHE / "sites.tsv"
    with out.open("w") as fh:
        for a, kind, start in rows:
            fh.write(f"0x{a:x}\t{kind}\t0x{start:x}\n")
    single = sorted({a for a, k, _s in rows if k.startswith("single")})
    single_set = set(single)
    two = sorted({a for a, k, _s in rows if k == "two"})
    print(f"## single-stage = {len(single)}  two-stage = {len(two)}  → {out}")
    print("## single-stage by path: "
          + ", ".join(f"{kind}={sum(1 for a, k, _ in rows if k == 'single_' + kind and a in single_set)}"
                      for kind in ("body", "leaf")), flush=True)
    return single, two


# ---------------------------------------------------------------------- phase 2
def table(single, two):
    by_func = {}
    for a in single:
        span = func_of(a)
        key = span[0] if span else 0
        by_func.setdefault(key, []).append(a)
    family = []
    for start in sorted(by_func):
        if not (FAMILY_LO <= start < FAMILY_HI) or start == 0:
            continue
        refs = qword_refs(start)
        if refs:
            family.append((start, FUNC_END[start], by_func[start], refs))

    print(f"## in-family 函数 = {len(family)}"
          f"(0x{FAMILY_LO:x}..0x{FAMILY_HI:x} 内、自身在 .rdata 里有 qword 槽、且含单段站点)")
    print()
    hdr = ("func_rva", "extent", "site", "base", "write_insn", "obj", "obj_write", "判定")
    print("  ".join(f"{h:<12s}" for h in hdr))
    for start, end, hits, refs in family:
        insns = list(body(start, end))
        idx_of = {ins.address: i for i, ins in enumerate(insns)}
        for a in sorted(hits):
            idx = idx_of.get(a)
            if idx is None:                      # decoded only by the lite sweep
                ins = next(md.disasm(rd(a, 16), a))
                reg, wtxt, obj, objw = stage_base_reg(ins), "-", "-", "-"
            else:
                ins = insns[idx]
                reg = stage_base_reg(ins)
                w, _hop = last_write(insns, idx, reg)
                wtxt = "-" if w is None else w.mnemonic + " " + w.op_str
                obj = objw = "-"
                if w is not None and w.mnemonic == "mov" and len(w.operands) >= 2 \
                        and w.operands[1].type == X86_OP_MEM and w.operands[1].mem.base:
                    ob = w.operands[1].mem.base
                    obj = w.reg_name(ob)
                    ow, _h = last_write(insns, idx_of[w.address], ob)
                    objw = "-" if ow is None else ow.mnemonic + " " + ow.op_str
                    if obj == "rcx" and idx_of[w.address] < 12:
                        objw += " (== entry this?)"
            print(f"  0x{start:08x}  0x{end:08x}  0x{a:08x}  {ins.reg_name(reg):<5s}"
                  f"  {wtxt:<30s}  {obj:<4s}  {objw:<30s}  undetermined")
            if idx is not None:
                back = insns[max(0, idx - 3):idx]
                print("        slice: " + " | ".join(f"{i.mnemonic} {i.op_str}" for i in back)
                      + " | " + f"{ins.mnemonic} {ins.op_str}")
        print("      head: " + " ; ".join(fmt(i) for i in insns[:5]))
        heads = vtable_heads(start)
        print(f"      .rdata qword slots for function start: {len(refs)}"
              f" (first 0x{refs[0]:x})")
        if heads:
            print("      effect-family vtable: " + ", ".join(
                f"head 0x{h:x} slot+0x{off * 8:02x}" for h, off, _s in heads))
        else:
            print("      effect-family vtable: none (no head with +0x08 == 0x3AFD30 "
                  "within 0x200 before the slot)")
    return family


def main():
    sites_file = CACHE / "sites.tsv"
    if "--census" in sys.argv or not sites_file.exists():
        single, two = census()
    else:
        single, two = [], []
        for line in sites_file.read_text().splitlines():
            a, kind, _start = line.split("\t")
            (single if kind.startswith("single") else two).append(int(a, 16))
        single, two = sorted(set(single)), sorted(set(two))
        print(f"## cached: single-stage = {len(single)}  two-stage = {len(two)}")
    family = table(single, two)

    print()
    print(f"single-stage={len(single)} two-stage={len(two)} in-family={len(family)}")
    assert len(single) == EXPECT_SINGLE, (len(single), EXPECT_SINGLE)
    assert len(two) == EXPECT_TWO, (len(two), EXPECT_TWO)
    assert len(family) == EXPECT_FAMILY, (len(family), EXPECT_FAMILY)
    print("PASS")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
