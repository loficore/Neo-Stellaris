#!/usr/bin/env python3
"""对比两个 parse 体是不是同一函数的两个副本(一次性探针)。

`evidence/analysis/flag_store_4_4_4.md` §3.3 的读数由它产出:
`set_star_flag` 的 parse(`0x180F590`)与 `has_star_flag` 的 parse(`0x1AA5D10`)
各 176 条指令,规范化后**只差 5 条**,且全是对象自身字段偏移
(`+0xC0/+0xC8/+0xF8` vs `+0x220/+0x228/+0x258`)。

判读口径(与取证卷一致):抹掉的是**地址**(call/lea 目标)、**栈偏移**
(`[rsp + X]`)与**注释**;保留的是 mnemonic、寄存器、以及结构体字段偏移
(后者正是要看的差异来源)。**不要**把结构体偏移也抹掉 —— 那样两个副本
会"完全相等",反而丢掉唯一的信息。

usage:
    python3 scripts/scratch/2026-11_flag_store/diff_parse_bodies.py \
        --a 0x180F590 --b 0x1AA5D10
"""
import argparse
import difflib
import os
import re
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE_CANDIDATES = [
    os.environ.get('NS_STELLARIS_EXE'),
    '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe',
    r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe',
]

ADDR = re.compile(r'0x1?4?0?[0-9a-f]{5,}')
RSP = re.compile(r'\[rsp \+ 0x[0-9a-f]+\]')


def resolve_exe():
    for c in EXE_CANDIDATES:
        if c and os.path.exists(c):
            return c
    sys.exit('diff_parse_bodies.py: no stellaris.exe found (set NS_STELLARIS_EXE)')


def load(path):
    f = open(path, 'rb').read()
    mz = struct.unpack_from('<I', f, 0x3c)[0]
    no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
    secs = []
    for i in range(struct.unpack_from('<H', f, mz + 6)[0]):
        nm = f[no+i*40:no+i*40+8].rstrip(b'\0').decode('latin1')
        vs, va, rsz, rp = struct.unpack_from('<IIII', f, no+i*40+8)
        secs.append((nm, va, vs, rsz, rp))
    return f, secs


def pdata(f, secs):
    pd = [s for s in secs if s[0] == '.pdata'][0]
    raw = f[pd[4]:pd[4] + pd[3]]
    out = []
    for o in range(0, len(raw), 12):
        b = raw[o:o+12]
        if len(b) < 12:
            break
        st, en, _un = struct.unpack('<III', b)
        if st == 0 and en == 0:
            break
        out.append((st, en))
    return sorted(set(out))


def norm_body(f, secs, funcs, rva):
    span = None
    for st, en in funcs:
        if st == rva:
            span = (st, en)
            break
    if span is None:
        sys.exit(f'{hex(rva)} is not a .pdata function start')
    text = [s for s in secs if s[0] == '.text'][0]
    _, tva, tvs, trsz, trp = text
    code = f[trp + span[0] - tva: trp + span[0] - tva + (span[1] - span[0])]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    out = []
    for insn in md.disasm(code, span[0]):
        ops = ADDR.sub('TGT', insn.op_str)
        ops = RSP.sub('[rsp+X]', ops)
        out.append(f'{insn.mnemonic} {ops}')
    return span, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--a', required=True)
    ap.add_argument('--b', required=True)
    args = ap.parse_args()
    f, secs = load(resolve_exe())
    funcs = pdata(f, secs)
    sa, a = norm_body(f, secs, funcs, int(args.a, 16))
    sb, b = norm_body(f, secs, funcs, int(args.b, 16))
    print(f"A {hex(sa[0])}..{hex(sa[1])}  instrs={len(a)}")
    print(f"B {hex(sb[0])}..{hex(sb[1])}  instrs={len(b)}")
    n = 0
    for line in difflib.unified_diff(a, b, 'A', 'B', lineterm='', n=0):
        if line.startswith(('---', '+++', '@@')):
            continue
        print(line)
        n += 1
    print(f"diff lines: {n}")


if __name__ == '__main__':
    main()
