#!/usr/bin/env python3
"""read_execute_chain.py — 「靶在 parse 期还是执行期」的三组离线读数(§82.1 的生产者)。

只读 `stellaris.exe` 拷贝:不起进程、不注入、不需要 license。三组读数(**不写结论**,判读是 §82.2):

1. `0x17F7920`(`every_system` 的 ExecuteActual,slot[2])的完整指令序列,以及 scope kind `0x3F92`
   在 `.text` 里被谁比较过(imm32 字节扫描 + capstone 复核)。
2. `0x3B01A0`(`§23.1` 的实例化消费者)的函数体里:有没有 `call [reg+0x70]`、有没有对
   「容器基址 + 4/8 步长」的迭代、有没有 `call 0x3B1330`。只数指令形状。
3. `0x3B1330` 的**全部**直接调用者(交叉核对 `scripts/fastcalls.py` 的读数),按 `.pdata` 函数分桶;
   每个桶附:函数头的指令、该地址在 `.rdata` 里作为 8 B qword 出现的次数(= 有多少个 vtable 槽装着它,
   **不**报槽号:`+0x70` 这个槽号由 §24.4.2 用 class_info 逐条对出来,`+0x808` 那种「往回走连续
   `.text` 指针」的启发式会跨过紧挨着的 vtable,读数因此弃用)、以及**直接** `E8` 调用它的函数。

断言(全过才打印 PASS):`0x17F7920` 的序列与 §82 的七条一致、`jne` 的目标是 `0x3B01A0`、
`0x3B01A0` 的 `.pdata` 起点就是它自己、本探针的 E8 站点数与 `fastcalls.py` 的读数相等。

旧名/来历:本脚本由计划 `2026-10-30-parse-vs-execute` 的 Task 1 建立。
"""
from __future__ import annotations

import bisect
import pathlib
import struct
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve()
REPO = HERE.parents[3]
sys.path.insert(0, str(REPO / "scripts"))

import disrva  # noqa: E402
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP  # noqa: E402

BASE = 0x140000000
EXECUTE_ACTUAL = 0x17F7920
CONSUMER = 0x3B01A0
BASE_PARSE = 0x3B1330
SCOPE_KIND = 0x3F92
GALAXY_DB = 0x3260BB0

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

_image = disrva._image()
assert _image is not None, "stellaris.exe not found (set NS_STELLARIS_EXE)"
_EXE, BLOB, SECS = _image


def sec(name):
    return next(s for s in SECS if s[0] == name)


def rd(rva, n):
    for _name, va, vsize, rawsz, praw, _ch in SECS:
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
        b &= ~1          # low bit marks a chained unwind record; the RVA is b & ~1
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


def disasm(start, end):
    return list(md.disasm(rd(start, end - start), start))


def fmt(insn):
    return f"0x{insn.address:x}  {insn.mnemonic:<7} {insn.op_str}"


def seq_from(rva, limit=40):
    out, addr = [], rva
    for _ in range(limit):
        insn = next(md.disasm(rd(addr, 16), addr), None)
        if insn is None:
            break
        out.append(insn)
        addr += insn.size
        if insn.mnemonic in ("ret", "jmp"):
            break
    return out


def mem_with_disp(insn, disp):
    for op in insn.operands:
        if op.type == X86_OP_MEM and op.mem.disp == disp and op.mem.index == 0:
            return True
    return False


def indexed_mem(insn):
    for op in insn.operands:
        if op.type == X86_OP_MEM and op.mem.index != 0 and op.mem.scale in (4, 8):
            return True
    return False


def direct_call_to(insn, target):
    return (insn.mnemonic == "call" and insn.operands
            and insn.operands[0].type == X86_OP_IMM
            and insn.operands[0].imm == target)


def e8_sites(target):
    """Byte-level `E8 rel32` scan (same construction as scripts/fastcalls.py)."""
    va, blob = raw(".text")
    out, i = [], blob.find(b"\xe8")
    while i >= 0:
        if i + 5 <= len(blob):
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            if va + i + 5 + rel == target:
                out.append(va + i)
        i = blob.find(b"\xe8", i + 1)
    return out


def qword_refs(rva):
    """Every 8-byte-aligned qword in `.rdata` equal to the absolute address."""
    pat = struct.pack("<Q", BASE + rva)
    va, blob = raw(".rdata")
    return [va + i for i in range(0, len(blob) - 8, 8) if blob[i:i + 8] == pat]


def main():
    # ---- 1. 0x17F7920 --------------------------------------------------
    print(f"## 1. 0x{EXECUTE_ACTUAL:x} — every_system ExecuteActual (slot[2])")
    seq = seq_from(EXECUTE_ACTUAL)
    for insn in seq:
        print("  " + fmt(insn))
    print(f"  instruction count = {len(seq)} (terminal: {seq[-1].mnemonic})")

    assert seq[0].mnemonic == "mov" and seq[0].op_str == "r9, qword ptr [rcx + 0x180]", fmt(seq[0])
    cmp_i = next(i for i, x in enumerate(seq)
                 if x.mnemonic == "cmp" and x.operands[1].type == X86_OP_IMM
                 and x.operands[1].imm == SCOPE_KIND)
    jne = seq[cmp_i + 1]
    assert jne.mnemonic == "jne", fmt(jne)
    assert jne.operands[0].type == X86_OP_IMM and jne.operands[0].imm == CONSUMER, fmt(jne)
    assert seq[-1].mnemonic == "jmp" and mem_with_disp(seq[-1], 0x28), fmt(seq[-1])
    print(f"  branch: cmp r8d, 0x{SCOPE_KIND:x} @0x{seq[cmp_i].address:x} -> jne 0x{CONSUMER:x}")
    print(f"  taken path: jmp qword ptr [rax + 0x28] @0x{seq[-1].address:x}")

    # ---- 1b. who compares 0x3F92 ---------------------------------------
    print(f"\n## 1b. immediate 0x{SCOPE_KIND:x} sites in .text")
    _va, blob = raw(".text")
    pat = struct.pack("<I", SCOPE_KIND)
    raw_hits, i = [], blob.find(pat)
    while i >= 0:
        raw_hits.append(sec(".text")[1] + i)
        i = blob.find(pat, i + 1)
    def insn_covering(hit):
        """The instruction whose encoding contains `hit`, plus where it lives.

        Leaf functions need no unwind record, so `.pdata` misses some of them
        (`0x17F7920` itself is one). Fall back to decoding backwards and accept
        only a decode that carries `SCOPE_KIND` as an immediate operand.
        """
        span = func_of(hit)
        if span is not None:
            insn = next((x for x in disasm(span[0], span[1])
                         if x.address <= hit < x.address + x.size), None)
            if insn is not None:
                return insn, f"func 0x{span[0]:x}..0x{span[1]:x}"
        # No unwind record: a byte-level backwards decode is NOT attributable here —
        # the same immediate decodes two ways from 0x17F7927 and 0x17F7928 (REX 0x41
        # vs no prefix). Report the address, not a guess at the instruction.
        return None, "leaf / no .pdata (not attributable) or data"

    decoded = []
    for hit in raw_hits:
        insn, where = insn_covering(hit)
        decoded.append((hit, where, insn))
    print(f"  raw 4-byte hits = {len(raw_hits)}")
    for hit, where, insn in decoded:
        text = fmt(insn) if insn else "-"
        print(f"  imm @0x{hit:x}  {where}  {text}")
    in_insn = [d for d in decoded if d[2] is not None and d[2].mnemonic in ("cmp", "mov")]
    print(f"  decoded into a cmp/mov carrying the immediate = {len(in_insn)}")

    # ---- 2. 0x3B01A0 body ---------------------------------------------
    print(f"\n## 2. 0x{CONSUMER:x} — instantiate-by-token-id consumer (§23.1)")
    span = func_of(CONSUMER)
    assert span is not None and span[0] == CONSUMER, f"0x{CONSUMER:x} is not a .pdata start: {span}"
    start, end = span
    body = disasm(start, end)
    print(f"  .pdata extent 0x{start:x}..0x{end:x} ({end - start} B, {len(body)} insns)")
    call70 = [x for x in body if x.mnemonic == "call" and mem_with_disp(x, 0x70)]
    indexed = [x for x in body if indexed_mem(x)]
    step48 = [x for x in body
              if x.mnemonic in ("add", "sub") and x.operands
              and x.operands[-1].type == X86_OP_IMM and x.operands[-1].imm in (4, 8)]
    to_parse = [x for x in body if direct_call_to(x, BASE_PARSE)]
    direct = {}
    for x in body:
        if x.mnemonic == "call" and x.operands and x.operands[0].type == X86_OP_IMM:
            direct[x.operands[0].imm] = direct.get(x.operands[0].imm, 0) + 1
    print(f"  call qword ptr [reg + 0x70]        : {len(call70)}")
    print(f"  indexed mem (base + idx*4|8)       : {len(indexed)}")
    print(f"  add/sub reg, 4|8                   : {len(step48)}")
    print(f"  direct call 0x{BASE_PARSE:<8x}            : {len(to_parse)}")
    print("  direct call targets (rva x count): "
          + (", ".join(f"0x{k:x} x{v}" for k, v in sorted(direct.items())) or "none"))
    rip_targets = {}
    for x in body:
        for op in x.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = x.address + x.size + op.mem.disp
                rip_targets[t] = rip_targets.get(t, 0) + 1
    print(f"  rip-relative global reads          : {len(rip_targets)} distinct"
          " -> " + ", ".join(f"0x{t:x} x{c}" for t, c in sorted(rip_targets.items())))
    for name, rva in (("galaxy db 0x3260bb0", GALAXY_DB), ("effect db 0x33746e8", 0x33746E8)):
        print(f"  reads {name:<22}: {'YES' if rva in rip_targets else 'no'}"
              f"   ([+0x590] container read: {'YES' if any(x.mnemonic == 'mov' and mem_with_disp(x, 0x590) for x in body) else 'no'})")
    by_addr = {x.address: i for i, x in enumerate(body)}
    for label, rows in (("indexed", indexed), ("step", step48)):
        for x in rows[:12]:
            i = by_addr[x.address]
            print(f"    {label}: {fmt(x)}")
            for y in body[max(0, i - 4):i + 5]:
                if y.address != x.address:
                    print("           " + fmt(y))

    # ---- 3. callers of 0x3B1330 ---------------------------------------
    print(f"\n## 3. callers of 0x{0x3b1330:x}")
    proc = subprocess.run([sys.executable, str(REPO / "scripts" / "fastcalls.py"),
                           f"0x{BASE_PARSE:x}"], cwd=str(REPO),
                          capture_output=True, text=True)
    fastcalls_out = proc.stdout.strip()
    print("  --- scripts/fastcalls.py ---")
    for line in fastcalls_out.splitlines():
        print("  " + line)
    assert proc.returncode == 0, proc.stderr

    sites = e8_sites(BASE_PARSE)
    buckets = {}
    for site in sites:
        span = func_of(site)
        key = span if span else (site, site)
        buckets.setdefault(key, []).append(site)
    print(f"  --- own E8 scan: {len(sites)} sites in {len(buckets)} functions ---")
    head = fastcalls_out.splitlines()[0]
    assert f"{len(sites)} direct code sites" in head, (head, len(sites))
    assert f"in {len(buckets)} functions" in fastcalls_out, (fastcalls_out, len(buckets))

    refs_all = qword_refs(BASE_PARSE)
    print(f"  .rdata qword hits for 0x{BASE_PARSE:x}: {len(refs_all)}"
          f" (§24.4.2 measured 723 vtables carrying it at +0x70)")

    for (fstart, fend), rows in sorted(buckets.items()):
        print(f"\n  * bucket 0x{fstart:x}..0x{fend:x} ({fend - fstart} B), "
              f"{len(rows)} site(s): " + ", ".join(f"0x{r:x}" for r in rows))
        for insn in seq_from(fstart, 10):
            print("      " + fmt(insn))
        refs = qword_refs(fstart)
        print(f"      .rdata slots installing this address: {len(refs)}"
              + ("  (first: " + ", ".join(f"0x{r:x}" for r in refs[:3]) + ")" if refs else ""))
        direct_callers = e8_sites(fstart)
        print(f"      direct E8 callers of this function: {len(direct_callers)}"
              + ("".join(f"\n        0x{c:x} in " + (
                    f"0x{func_of(c)[0]:x}..0x{func_of(c)[1]:x}" if func_of(c) else "no .pdata")
                    for c in direct_callers[:6])))

    print("\nPASS")


if __name__ == "__main__":
    main()
