#!/usr/bin/env python3
"""One-off probe (#46): who reads/writes the struct field `[reg + <disp>]`?

Why this exists: the maintained `scripts/find_refs.py` answers "who references this
*address*". The #46 question is the other axis -- "who reads/writes this *struct
field offset*" -- and no maintained tool answers that offline.

usage: field_xrefs.py 0x1370 [0x434 ...] [--writes-only] [--limit N]

Reads only a local exe copy (NS_STELLARIS_EXE or the 4.4.4 default). No process,
no IDA, no Frida.

Method (and why it is not a linear sweep):
  A plain `Cs.disasm` over 37 MB of .text stops at the first undecodable byte, so a
  sweep silently truncates. Instead:
    1. byte-prefilter .text for the little-endian disp32 (a positive disp > 0x7f is
       always encoded as 4 bytes, so the pattern is exact),
    2. for each hit, find the containing .pdata RUNTIME_FUNCTION and disassemble that
       function from its real entry,
    3. keep only instructions whose address equals the hit and whose memory operand
       carries exactly that disp.
Reading traps baked in:
  * `mov [reg+disp], ...` is a write; `mov reg, [reg+disp]` is a read -- same disp,
    opposite direction; both are reported, flagged.
  * rip-relative operands are skipped (their disp is an address delta).
  * the same value can be a non-field constant (vtable slot, array index). Counts are
    an *upper bound*, never a list of owners.
"""
import sys
import struct
import os
import bisect
import argparse

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_REG_EIP

EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
BASE = 0x140000000

WRITE_MNEMONICS = {
    'mov', 'movzx', 'movsx', 'movsxd', 'movaps', 'movups', 'movdqu', 'movdqa',
    'movss', 'movsd', 'add', 'sub', 'and', 'or', 'xor', 'inc', 'dec', 'shl',
    'shr', 'sar', 'neg', 'not', 'xchg', 'movbe', 'cmovne', 'cmove', 'cmova',
}
READONLY = {'test', 'cmp', 'bt', 'btc', 'btr', 'bts', 'lea', 'push'}


def load():
    with open(EXE, 'rb') as fh:
        f = fh.read()
    mz = struct.unpack_from('<I', f, 0x3c)[0]
    nsec = struct.unpack_from('<H', f, mz + 6)[0]
    no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
    secs = {}
    for i in range(nsec):
        nm = f[no + i * 40:no + i * 40 + 8].rstrip(b'\0').decode('latin1')
        vs, va, rsz, rp = struct.unpack_from('<IIII', f, no + i * 40 + 8)
        secs[nm] = (va, vs, rsz, rp)
    return f, secs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('offsets', nargs='+', help='field offsets, hex like 0x1370')
    ap.add_argument('--writes-only', action='store_true')
    ap.add_argument('--limit', type=int, default=10)
    ap.add_argument('--width', choices=['dword', 'qword', 'byte', 'any'],
                    default='any', help='access width filter (owner ids are dword)')
    a = ap.parse_args()

    f, secs = load()
    tva, tvs, trsz, trp = secs['.text']
    text = f[trp:trp + min(tvs, trsz)]

    # .pdata -> RUNTIME_FUNCTION list (begin/end RVAs)
    pva, pvs, prsz, prp = secs['.pdata']
    praw = f[prp:prp + min(pvs, prsz)]
    funcs = sorted(struct.unpack_from('<II', praw, i)
                   for i in range(0, len(praw) - 11, 12))
    starts = [b for b, _ in funcs]

    def func_of(rva):
        i = bisect.bisect_right(starts, rva) - 1
        if i >= 0 and funcs[i][0] <= rva < funcs[i][1]:
            return funcs[i]
        return None

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    decoded = {}

    def disasm_func(begin, end):
        if begin in decoded:
            return decoded[begin]
        off = begin - tva
        blob = text[off:off + (end - begin)]
        decoded[begin] = list(md.disasm(blob, BASE + begin))
        return decoded[begin]

    print(f'# module {EXE}')
    print(f'# .text bytes={len(text)} pdata funcs={len(funcs)}')
    for spec in a.offsets:
        disp = int(spec, 16)
        pat = struct.pack('<i', disp)
        hits = []
        pos = text.find(pat)
        while pos != -1:
            rva = tva + pos
            fn = func_of(rva)
            if fn:
                for ins in disasm_func(*fn):
                    # the pattern hit is the *disp bytes*, not the instruction start:
                    # accept the instruction whose byte range contains the hit.
                    istart = ins.address - BASE
                    if not (istart <= rva < istart + ins.size):
                        continue
                    for i, op in enumerate(ins.operands):
                        if op.type != X86_OP_MEM:
                            continue
                        if op.mem.base in (X86_REG_RIP, X86_REG_EIP):
                            continue
                        if op.mem.disp != disp:
                            continue
                        w = (i == 0 and ins.mnemonic in WRITE_MNEMONICS
                             and ins.mnemonic not in READONLY)
                        sz = op.size
                        hits.append((rva, fn[0], ins.mnemonic,
                                     'W' if w else 'r', sz, ins.op_str))
            pos = text.find(pat, pos + 1)
        if a.writes_only:
            hits = [h for h in hits if h[3] == 'W']
        if a.width != 'any':
            want = {'dword': 4, 'qword': 8, 'byte': 1}[a.width]
            hits = [h for h in hits if h[4] == want]
        w = sum(1 for h in hits if h[3] == 'W')
        print(f'\n## [reg+0x{disp:x}]  width={a.width} hits={len(hits)} writes={w}')
        for rva, fstart, mn, d, sz, ops in hits[:a.limit]:
            print(f'  0x{rva:x}  {d}  {mn} {ops}   (in func 0x{fstart:x})')


if __name__ == '__main__':
    sys.exit(main())
