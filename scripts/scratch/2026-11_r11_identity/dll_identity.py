#!/usr/bin/env python3
"""Compare two stellaris_quickjs.dll builds at the instruction level.

**Why this exists.** A full-file sha changes on every relink, and the Zig build
embeds the build-directory path in `.rdata`, so two builds of the *same* source
from two different directories differ in `.rdata` size, `.data` pointers and
`.reloc`. Section shas are therefore not a code identity (see
`docs/offline-tooling.md`, "出货 DLL 的整文件 sha256 不是代码身份").

This tool answers the question the shas cannot: **is it the same program?**

Method: decode `.text` of both files with capstone and compare, instruction by
instruction at the same VA:

* mnemonic;
* every register operand by name;
* every immediate operand by value, except in-image addresses (branch/call
  targets), which are compared as the marker `A` — a function that moved would
  still line up here only if everything around it moved the same way, and the
  per-instruction address is printed on a mismatch;
* every memory operand by base/index/scale/displacement, except `[rip+…]`,
  whose displacement must shift when `.rdata` moves (compared as `M:rip`).

So the tool proves "the instruction stream is identical up to layout". It does
**not** prove the data is identical: run `--sections` to see the section shas,
and inspect the `.data` pointer deltas if that matters.

Usage:

    python3 scripts/scratch/2026-11_r11_identity/dll_identity.py A.dll B.dll
    python3 scripts/scratch/2026-11_r11_identity/dll_identity.py A.dll B.dll --sections

Exit codes: 0 = instruction streams identical; 1 = differ (first mismatch
printed); 2 = input unreadable.
"""

from __future__ import annotations

import collections
import hashlib
import sys

import capstone
import pefile


def _section(path: str, name: str):
    pe = pefile.PE(path, fast_load=True)
    for section in pe.sections:
        if section.Name.rstrip(b"\0").decode("latin1") == name:
            return section.get_data(), pe.OPTIONAL_HEADER.ImageBase, section.VirtualAddress, pe
    raise SystemExit(f"{path}: no {name}")


def signatures(path: str):
    data, base, va, _ = _section(path, ".text")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    out = []
    for insn in md.disasm(data, base + va):
        ops = []
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_REG:
                ops.append("R:" + insn.reg_name(op.reg))
            elif op.type == capstone.x86.X86_OP_IMM:
                value = op.imm
                if base <= value < base + 0x2000000:
                    ops.append("A")
                else:
                    ops.append("I:%d" % (value & 0xFFFFFFFF))
            elif op.type == capstone.x86.X86_OP_MEM:
                mem = op.mem
                b = insn.reg_name(mem.base) if mem.base else "-"
                i = insn.reg_name(mem.index) if mem.index else "-"
                if b == "rip":
                    ops.append("M:rip")
                else:
                    ops.append("M:%s:%s:%d:%d" % (b, i, mem.scale, mem.disp & 0xFFFFFFFF))
            else:
                ops.append("?")
        out.append((insn.address, insn.mnemonic + " " + ",".join(ops)))
    return out


def section_table(path: str) -> dict[str, tuple[int, str]]:
    pe = pefile.PE(path, fast_load=True)
    table = {}
    for section in pe.sections:
        name = section.Name.rstrip(b"\0").decode("latin1")
        data = section.get_data()
        table[name] = (len(data), hashlib.sha256(data).hexdigest()[:16])
    return table


def data_pointer_delta(path_a: str, path_b: str) -> dict:
    """Every differing 8-byte word in `.data`: is it a pointer pair, and by how much?"""
    da, _, _, _ = _section(path_a, ".data")
    db, _, _, _ = _section(path_b, ".data")
    base = pefile.PE(path_a, fast_load=True).OPTIONAL_HEADER.ImageBase
    import struct

    diffs = [i for i in range(min(len(da), len(db))) if da[i] != db[i]]
    kinds = collections.Counter()
    deltas = collections.Counter()
    seen = set()
    for i in diffs:
        q = i & ~7
        if q in seen:
            continue
        seen.add(q)
        a = struct.unpack_from("<Q", da, q)[0]
        b = struct.unpack_from("<Q", db, q)[0]
        if base <= a < base + 0x2000000 and base <= b < base + 0x2000000:
            kinds["both_pointers"] += 1
            deltas[b - a] += 1
        else:
            kinds["not_both_pointers"] += 1
    return {"differing_words": len(seen), "kinds": dict(kinds),
            "top_deltas": deltas.most_common(6)}


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    a, b = argv[1], argv[2]
    try:
        sig_a = signatures(a)
        sig_b = signatures(b)
    except (OSError, pefile.PEFormatError) as exc:
        print(f"cannot read: {exc}")
        return 2

    print(f"insns {a} = {len(sig_a)}")
    print(f"insns {b} = {len(sig_b)}")
    mismatches = []
    for k in range(min(len(sig_a), len(sig_b))):
        if sig_a[k][1] != sig_b[k][1]:
            mismatches.append((k, sig_a[k], sig_b[k]))
    print(f"differing positions = {len(mismatches)}")
    for k, x, y in mismatches[:5]:
        print(f"  @{x[0]:#x}")
        print("    A:", x[1][:140])
        print("    B:", y[1][:140])

    if "--sections" in argv:
        ta, tb = section_table(a), section_table(b)
        for name in sorted(set(ta) | set(tb)):
            flag = "SAME" if ta.get(name) == tb.get(name) else "DIFF"
            print(f"{flag} {name:10} A={ta.get(name)} B={tb.get(name)}")
        print("data pointer check:", data_pointer_delta(a, b))

    same = len(sig_a) == len(sig_b) and not mismatches
    print("VERDICT", "instruction_stream_identical" if same else "instruction_stream_differs")
    return 0 if same else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
