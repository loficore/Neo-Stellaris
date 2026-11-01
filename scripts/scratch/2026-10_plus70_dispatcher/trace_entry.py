#!/usr/bin/env python3
"""trace_entry.py — 从 §83.1 的 candidate 往上游追到入口(计划 Task 2 的生产者,§83.2)。

只读 `stellaris.exe` 拷贝。对每个候选做三件事,深度上限 4:

1. **E8 反查**:字节级 `E8 rel32` 扫描,给出直接调用它的函数(`.pdata` 归属)。
2. **槽反查**:它在 `.rdata` 里作为 8 B 对齐 qword 出现的每个槽;对每个槽用
   「`[H+0x08] == 0x3AFD30`」定 effect-family vtable 头(§82.1 已弃用「往回走连续指针」的启发式),
   给出 `head / slot offset`。
3. **持有者反查**:对每个 vtable 头,在 `.text` 里找 **rip 相对引用**它的指令(= 写 vtable 的
   create / ctor);对每个 create 再回到第 1 步。

rip 相对引用需要一次全 `.text` 反汇编;结果缓存在 `/mnt/cache/tmp/dispatch_sites/rip.jsonl`,
第二次跑直接读缓存(Task 1 的教训:一次长扫描被打断就什么都留不下)。

判决词(只覆盖**追到的深度**):
  dispatcher_found        有一条链能追到「非 effect 类」的入口
  dispatcher_partial      只追到 effect 家族内部(仍是自递归),没有外部入口
  dispatcher_unidentified 候选全被降级

旧名/来历:本脚本由计划 `2026-10-31-plus70-dispatcher-and-channels` 的 Task 2 建立。
"""
from __future__ import annotations

import bisect
import json
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve()
REPO = HERE.parents[3]
sys.path.insert(0, str(REPO / "scripts"))

import disrva  # noqa: E402
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from capstone.x86 import X86_OP_MEM, X86_REG_RIP  # noqa: E402

BASE = 0x140000000
EXEC_SLOT = 0x3AFD30           # effect vtable slot[1] (Execute)
# "Effect machinery" anchors: any vtable that carries one of these is part of the
# effect classes or their class_info (§24.4.2 / §23.1 / §83.1).  The class_info
# vtables carry the generic instantiate consumer 0x3B01A0 and a shared deleting
# destructor 0x34C090 instead of Execute, so Execute alone would call a class_info
# "outside" and manufacture a dispatcher_found that does not exist.
FAMILY_ANCHORS = {0x3AFD30, 0x3B1330, 0x3B01A0, 0x3B1420, 0x3B0F80, 0x3B1230}
DEPTH = 4
CACHE = pathlib.Path("/mnt/cache/tmp/dispatch_sites")
RIP_CACHE = CACHE / "rip.jsonl"

# §83.1 的 candidate(candidate 列的两行;常量表,逐行注明出处)
CANDIDATES = [
    (0x18B7B70, "§83.1 site 0x18b7b9d; vtable 0x25fde58+0x70 / 0x25fdd78+0x150"),
    (0x18B7E30, "§83.1 site 0x18b7e5d; vtable 0x25fdd78+0x70"),
]

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


def e8_sites(target):
    va, blob = raw(".text")
    out, i = [], blob.find(b"\xe8")
    while i >= 0:
        if i + 5 <= len(blob):
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            if va + i + 5 + rel == target:
                out.append(va + i)
        i = blob.find(b"\xe8", i + 1)
    return out


def qword_slots(rva):
    pat = struct.pack("<Q", BASE + rva)
    va, blob = raw(".rdata")
    return [va + i for i in range(0, len(blob) - 8, 8) if blob[i:i + 8] == pat]


def vtable_head(slot):
    """Effect-family head for a `.rdata` slot: `H + 0x08 == 0x3AFD30`, `slot-H <= 0x200`."""
    for back in range(0, 0x201, 8):
        head = slot - back
        if head <= 0:
            break
        blob = rd(head, 16)
        if len(blob) < 16:
            continue
        if struct.unpack_from("<Q", blob, 8)[0] == BASE + EXEC_SLOT:
            return head, back // 8
    return None, None


def build_rip_index():
    """One full `.text` pass → {target_rva: [site_rva, ...]}, cached as JSONL."""
    if RIP_CACHE.exists():
        idx = {}
        with RIP_CACHE.open() as fh:
            for line in fh:
                t, s = line.split()
                try:
                    ti = int(t, 16)
                except ValueError:
                    continue          # negative (outside the image) offsets
                idx.setdefault(ti, []).append(int(s, 16))
        print(f"## rip index cached: {len(idx)} targets", flush=True)
        return idx
    CACHE.mkdir(parents=True, exist_ok=True)
    tva, tvs = sec(".text")[1], sec(".text")[2]
    idx = {}
    CH = 0x8000
    addr = tva
    with RIP_CACHE.open("w") as fh:
        while addr < tva + tvs:
            stop = min(addr + CH, tva + tvs)
            blob = rd(addr, min(CH + 15, tva + tvs - addr))
            got = False
            for ins in md.disasm(blob, addr):
                if ins.address >= stop:
                    break
                got = True
                for op in ins.operands:
                    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                        t = ins.address + ins.size + op.mem.disp
                        idx.setdefault(t, []).append(ins.address)
                        fh.write(f"0x{t:x} 0x{ins.address:x}\n")
                addr = ins.address + ins.size
            if addr < stop:
                addr += 1
            if (addr - tva) % 0x400000 < CH:
                print(f"   … rip index at 0x{addr - tva:x}", flush=True)
    print(f"## rip index built: {len(idx)} targets", flush=True)
    return idx


def is_family(func_start):
    """Is this function installed in any vtable of the effect machinery?

    Machinery = a `.rdata` slot vector containing at least one of
    ``FAMILY_ANCHORS`` (Execute, base parse/dispatch, instantiate consumer,
    predicate base or its neighbours).  This deliberately includes class_info
    vtables: they hold the create function at +0x00 and the instantiate
    consumer at +0x78, so a creator found that way is *inside* the effect
    machinery, not an external entry.
    """
    for slot in qword_slots(func_start):
        for back in range(0, 0x201, 8):
            head = slot - back
            if head <= 0:
                break
            blob = rd(head, 0x200)
            for k in range(0, len(blob) - 7, 8):
                q = struct.unpack_from("<Q", blob, k)[0]
                if q - BASE in FAMILY_ANCHORS:
                    return True
    return False


def trace(start, rip_index, seen, depth=1, indent="  "):
    """Print the upstream chains of one function; return list of (node, kind, depth)."""
    nodes = []
    callers = e8_sites(start)
    print(f"{indent}E8 callers of 0x{start:x}: {len(callers)}"
          + ("".join(f"\n{indent}   0x{c:x} in " + (f"0x{func_of(c)[0]:x}..0x{func_of(c)[1]:x}"
                                                      if func_of(c) else "no .pdata")
                     for c in callers[:8])))
    for c in callers:
        span = func_of(c)
        nodes.append((span[0] if span else c, "e8-caller", depth))
    slots = qword_slots(start)
    print(f"{indent}.rdata slots installing 0x{start:x}: {len(slots)}")
    for slot in slots:
        head, off = vtable_head(slot)
        if head is None:
            print(f"{indent}   slot 0x{slot:x}: no effect-family head (+0x08 != 0x{EXEC_SLOT:x})")
            continue
        print(f"{indent}   slot 0x{slot:x}: effect-family head 0x{head:x}, slot +0x{off * 8:02x}")
        creators = rip_index.get(head, [])
        print(f"{indent}      code refs (create/ctor) to head 0x{head:x}: {len(creators)}"
              + ("".join(f"\n{indent}         0x{r:x} in "
                         + (f"0x{func_of(r)[0]:x}..0x{func_of(r)[1]:x}" if func_of(r) else "no .pdata")
                         for r in creators[:8])))
        for r in creators:
            span = func_of(r)
            if span:
                nodes.append((span[0], "vtable-creator", depth))
    if depth >= DEPTH:
        return nodes
    for node, kind, _d in list(nodes):
        if node in seen:
            continue
        seen.add(node)
        print(f"{indent}→ {kind} 0x{node:x} (family={is_family(node)})")
        nodes.extend(trace(node, rip_index, seen, depth + 1, indent + "    "))
    return nodes


def main():
    rip_index = build_rip_index()
    seen = set()
    verdict = "dispatcher_unidentified"
    for cand, note in CANDIDATES:
        print(f"\n## candidate 0x{cand:x}  ({note})")
        seen = {cand}
        nodes = trace(cand, rip_index, seen)
        outside = [(n, k, d) for n, k, d in nodes if not is_family(n)]
        print(f"   nodes reached: {len(nodes)}, not in an effect-family vtable: {len(outside)}"
              + ("".join(f"\n      0x{n:x} via {k} (depth {d})" for n, k, d in outside[:10])))
        if outside:
            verdict = "dispatcher_found"
        elif verdict == "dispatcher_unidentified":
            verdict = "dispatcher_partial"
    print(f"\nverdict = {verdict}")
    print("PASS")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
