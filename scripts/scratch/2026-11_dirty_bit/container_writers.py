#!/usr/bin/env python3
"""One-off probe (#46 plan 2, Task 2): who writes the system object's edge-container
fields, and does each writer set bit0 of 0x296cc68?

Reuses the `[reg+disp]` axis of `scripts/scratch/2026-11_transitability/field_xrefs.py`
(that probe's counts are an *upper bound*: the same displacement is a field in many
unrelated structs). This probe narrows to the rows that matter for the "does every
container writer set the dirty bit" question:

  * the writer's logical function is a system-object operator -- it writes +0x137d,
    or references the resolver global 0x3260b98, or is in the 0x296cc68 family;
  * or the function writes >= 2 of {+0x588,+0x590,+0x598,+0x59c} in one function --
    the shape of a wholesale container rebuild (the second-storage-path suspect);
  * or the offset is +0x59c / +0x137d (count + per-system byte) -- small sets that
    are examined in full.

.pdata splits one logical function across contiguous chunks (the remove routine is
7 chunks 0x8bbc20..0x8bbd8a). Chunks that abut exactly (end == next begin) are
merged into one logical function before the family join, otherwise the count-decrement
chunk 0x8bbd11 would miss its own routine's set-bit site at 0x8bbd65.

usage: container_writers.py [--json]
Output TSV: offset \t insn_rva \t fn_start \t dir \t sets_bit0
Reads only a local exe copy (NS_STELLARIS_EXE or the 4.4.4 default).
"""
import sys
import os
import json
import struct
import bisect
import argparse

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_REG_EIP

BASE = 0x140000000
OFFSETS = [0x588, 0x590, 0x598, 0x59c, 0x5a0, 0x137d]
WINDOW = {0x588, 0x590, 0x598, 0x59c}
CANDIDATES = [os.environ.get('NS_STELLARIS_EXE'),
              '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe']
WRITE_MNEMONICS = {
    'mov', 'movzx', 'movsx', 'movsxd', 'movaps', 'movups', 'movdqu', 'movdqa',
    'movss', 'movsd', 'add', 'sub', 'and', 'or', 'xor', 'inc', 'dec', 'shl',
    'shr', 'sar', 'neg', 'not', 'xchg', 'movbe', 'cmovne', 'cmove', 'cmova',
}
READONLY = {'test', 'cmp', 'bt', 'btc', 'btr', 'bts', 'lea', 'push'}
DIRTY_GLOBAL = 0x296cc68
RESOLVER_GLOBAL = 0x3260b98


def resolve_exe():
    for c in CANDIDATES:
        if c and os.path.exists(c):
            return c
    return None


class Image:
    def __init__(self, path):
        with open(path, 'rb') as fh:
            f = fh.read()
        self.f = f
        mz = struct.unpack_from('<I', f, 0x3c)[0]
        nsec = struct.unpack_from('<H', f, mz + 6)[0]
        no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
        secs = {}
        for i in range(nsec):
            o = no + i * 40
            nm = f[o:o + 8].rstrip(b'\0').decode('latin1')
            vs, va, rsz, rp = struct.unpack_from('<IIII', f, o + 8)
            secs[nm] = (va, vs, rsz, rp)
        tva, tvs, trsz, trp = secs['.text']
        self.tva = tva
        self.text = f[trp:trp + min(tvs, trsz)]
        _pva, pvs, prsz, prp = secs['.pdata']
        praw = f[prp:prp + min(pvs, prsz)]
        self.raw_funcs = sorted(struct.unpack_from('<II', praw, i)
                                for i in range(0, len(praw) - 11, 12))
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self._decoded = {}
        self._build_logical()

    def _build_logical(self):
        """Merge abutting .pdata chunks so a split routine reads as one function."""
        self.logical = []                 # list of (start, end)
        for b, e in self.raw_funcs:
            if self.logical and self.logical[-1][1] == b:
                self.logical[-1] = (self.logical[-1][0], e)
            else:
                self.logical.append((b, e))
        self.lstarts = [b for b, _ in self.logical]

    def logical_of(self, rva):
        i = bisect.bisect_right(self.lstarts, rva) - 1
        if i >= 0 and self.logical[i][0] <= rva < self.logical[i][1]:
            return self.logical[i]
        return None

    def raw_of(self, rva):
        starts = [b for b, _ in self.raw_funcs]
        i = bisect.bisect_right(starts, rva) - 1
        if i >= 0 and self.raw_funcs[i][0] <= rva < self.raw_funcs[i][1]:
            return self.raw_funcs[i]
        return None

    def decode(self, begin, end):
        key = begin
        if key in self._decoded:
            return self._decoded[key]
        off = begin - self.tva
        blob = self.text[off:off + (end - begin)]
        self._decoded[key] = list(self.md.disasm(blob, BASE + begin))
        return self._decoded[key]


def scan_field(img, disp):
    """Every (insn_start, logical_fn, dir, base_reg, mnemonic, op_str) that touches [reg+disp]."""
    pat = struct.pack('<i', disp)
    hits = []
    pos = img.text.find(pat)
    while pos != -1:
        rva = img.tva + pos
        fn = img.logical_of(rva)
        if fn is None:
            fn = img.raw_of(rva)
        if fn:
            for ins in img.decode(fn[0], fn[1]):
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
                    if not w:
                        continue
                    base = ins.reg_name(op.mem.base) if op.mem.base else '?'
                    hits.append((istart, fn[0], fn[1], base, ins.mnemonic, ins.op_str))
        pos = img.text.find(pat, pos + 1)
    # de-dup (a disp can be matched from two pattern positions in one insn)
    return sorted(set(hits))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--dump-family', action='store_true')
    a = ap.parse_args()

    exe = resolve_exe()
    if exe is None:
        sys.exit('stellaris.exe not found - set NS_STELLARIS_EXE')
    img = Image(exe)

    # family = logical functions that write +0x137d (the per-system edge byte) or
    # reference the resolver global -- demonstrated system-object operators.
    family = set()
    for off in (0x137d,):
        for h in scan_field(img, off):
            family.add(h[1])

    all_hits = {}
    for off in OFFSETS:
        all_hits[off] = scan_field(img, off)

    # rebuild suspects: functions that also write the count +0x59c. A wholesale
    # rewrite of the edge container has to move the count too -- a vector data
    # pointer / capacity write alone is generic vector machinery, not a rebuild.
    per_fn_fields = {}
    for off in WINDOW:
        for h in all_hits[off]:
            per_fn_fields.setdefault(h[1], set()).add(off)
    rebuild = {fn for fn, fs in per_fn_fields.items() if 0x59c in fs}

    # dirty-bit family: logical fns that set bit0 (read the xref table built by Task 1)
    set_bit_fns = set()
    tsvin = os.path.join(os.path.dirname(__file__), 'xrefs_296cc68.tsv')
    if os.path.exists(tsvin):
        with open(tsvin, encoding='utf-8') as fh:
            lines = fh.readlines()
        for line in lines:
            if line.startswith('#') or '\t' not in line:
                continue
            cols = line.rstrip('\n').split('\t')
            if len(cols) >= 4 and cols[3] == 'set_bit':
                fn = int(cols[1], 16)
                lf = img.logical_of(fn) or (fn, fn)
                set_bit_fns.add(lf[0])

    # callers of 0xab5e30 (the graph recompute) to label the clearing sites' subsystem
    rows = []
    for off in OFFSETS:
        for istart, fstart, fend, base, mn, ops in all_hits[off]:
            if base in ('rsp', 'esp'):
                continue                       # stack, never the system object
            keep = (off in (0x59c, 0x137d) or fstart in family
                    or fstart in set_bit_fns or fstart in rebuild)
            if not keep:
                continue
            if fstart in set_bit_fns:
                verdict = 'yes'
            elif fstart in family or fstart in rebuild:
                verdict = 'unknown'
            else:
                verdict = 'unknown'
            rows.append({'offset': f'0x{off:x}', 'insn_rva': f'0x{istart:x}',
                         'fn_start': f'0x{fstart:x}', 'dir': 'W',
                         'sets_bit0': verdict, 'base': base,
                         'instr': f'{mn} {ops}'})

    rows.sort(key=lambda r: (r['offset'], int(r['insn_rva'], 16)))
    if a.json:
        print(json.dumps({'module': exe, 'family': [f'0x{f:x}' for f in sorted(family)],
                          'set_bit_fns': [f'0x{f:x}' for f in sorted(set_bit_fns)],
                          'rebuild_fns': [f'0x{f:x}' for f in sorted(rebuild)],
                          'rows': rows}, ensure_ascii=False))
        return
    print(f'# module {exe}')
    print(f'# family(+0x137d writers)={len(family)} set_bit_fns={len(set_bit_fns)} '
          f'rebuild(also writes +0x59c count)={len(rebuild)}')
    for r in rows:
        print(f"{r['offset']}\t{r['insn_rva']}\t{r['fn_start']}\t{r['dir']}\t{r['sets_bit0']}")


if __name__ == '__main__':
    main()
