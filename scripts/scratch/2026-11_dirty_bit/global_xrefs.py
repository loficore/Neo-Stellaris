#!/usr/bin/env python3
"""One-off probe (#46 plan 2): classify every rip-relative reference to a global.

Why this exists: `scripts/find_refs.py` is a full linear capstone sweep of .text
(5-10 min) and truncates its listing at 25 hits. This probe answers the *shape*
question -- set-bit / overwrite / read-mask / read-bit -- for each reference, and
finishes in well under a minute, so the volume and the form of the reference set
can be read without paying for the whole sweep. `find_refs.py` stays the
independent (slow) cross-check; the two disagreeing is a finding, not a merge.

usage: global_xrefs.py <rva_hex> [--json]
    TSV rows: insn_rva \t fn_start \t fn_end \t form \t mnemonic \t op_str
    last line: refs=N set_bit=.. overwrite_imm=.. overwrite_reg=.. read_mask=.. read_bit=.. other=..

Method (why not a linear sweeep):
  A rip-relative operand resolves as `target = insn_end + disp32`. For a global at
  RVA T, a disp32 stored at RVA p is a candidate iff the instruction ends at
  e = T - v (v = signed dword at p) and `p + 4 <= e <= p + 8` (a disp32 may be
  followed by 0..4 immediate bytes, so the instruction ends 4..8 bytes after p).
  The whole .text is walked once computing e per byte position; each surviving
  candidate is then confirmed by disassembling its containing .pdata function
  from the real entry (leaf fragments without .pdata fall back to a decode from
  p-2). Candidates are rare, so this is seconds -- not the minutes a full
  instruction-by-instruction sweep costs.

Reading traps baked in:
  * `mov [rip+..], imm` is a write with bit0 likely cleared; `mov reg,[rip+..]`
    is a read. Only the destination/source position distinguishes them.
  * the read *shape* is a property of what consumes the loaded register, not of
    the load: `and`/whole-value `test` -> read_mask, `shr`/`sar`/`shl`/`bt`/
    single-bit `test` -> read_bit. Copy chains (`mov ecx,eax`) are followed so a
    shift of a copied register still classifies.
  * a value that is neither a field nor a flag can still sit in a rip-relative
    operand; `other` is a real answer, never folded into a neighbour.

Reads only a local exe copy (NS_STELLARIS_EXE or the 4.4.4 default). No process,
no IDA, no Frida.
"""
import sys
import os
import json
import struct
import bisect
import argparse

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_OP_REG, X86_REG_RIP, X86_REG_EIP

BASE = 0x140000000
CANDIDATES = [os.environ.get('NS_STELLARIS_EXE'),
              '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe']


def resolve_exe():
    for c in CANDIDATES:
        if c and os.path.exists(c):
            return c
    return None


def _sections(f):
    mz = struct.unpack_from('<I', f, 0x3c)[0]
    nsec = struct.unpack_from('<H', f, mz + 6)[0]
    no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
    secs = {}
    for i in range(nsec):
        o = no + i * 40
        nm = f[o:o + 8].rstrip(b'\0').decode('latin1')
        vs, va, rsz, rp = struct.unpack_from('<IIII', f, o + 8)
        secs[nm] = (va, vs, rsz, rp)
    return secs


def candidates_for_global(text, tva, target):
    """Every (p, v, e) with text[p:p+4] = disp32 resolving to `target`."""
    out = []
    up = struct.unpack_from
    n = len(text)
    for p in range(n - 8):
        v = up('<i', text, p)[0]
        e = target - v
        rva = tva + p
        if rva + 4 <= e <= rva + 8:
            out.append((rva, v, e))
    return out


class Image:
    def __init__(self, path):
        with open(path, 'rb') as fh:
            self.f = fh.read()
        self.secs = _sections(self.f)
        self.tva, self.tvs, trsz, trp = self.secs['.text']
        self.text = self.f[trp:trp + min(self.tvs, trsz)]
        _pva, pvs, prsz, prp = self.secs['.pdata']
        praw = self.f[prp:prp + min(pvs, prsz)]
        self.funcs = sorted(struct.unpack_from('<II', praw, i)
                            for i in range(0, len(praw) - 11, 12))
        self.starts = [b for b, _ in self.funcs]
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def func_of(self, rva):
        i = bisect.bisect_right(self.starts, rva) - 1
        if i >= 0 and self.funcs[i][0] <= rva < self.funcs[i][1]:
            return self.funcs[i]
        return None

    def decode(self, begin, end):
        off = begin - self.tva
        blob = self.text[off:off + (end - begin)]
        return list(self.md.disasm(blob, BASE + begin))


READ_FIRST = {'and': 'read_mask', 'shr': 'read_bit', 'sar': 'read_bit',
              'shl': 'read_bit', 'bt': 'read_bit', 'bts': 'read_bit',
              'btr': 'read_bit', 'btc': 'read_bit'}


def _is_tracked(op, track):
    return op.type == X86_OP_REG and op.reg in track


def classify(ins_list, idx):
    ins = ins_list[idx]
    ridx = None
    for i, op in enumerate(ins.operands):
        if op.type == X86_OP_MEM and op.mem.base in (X86_REG_RIP, X86_REG_EIP):
            ridx = i
            break
    if ridx is None:
        return 'other'

    if ridx == 0:                       # memory operand is the destination -> write
        oth = ins.operands[1] if len(ins.operands) > 1 else None
        if ins.mnemonic == 'or' and oth is not None and oth.type == X86_OP_IMM \
                and (oth.imm & 1):
            return 'set_bit'
        if ins.mnemonic in ('mov', 'movzx', 'movsx') and oth is not None:
            if oth.type == X86_OP_IMM:
                return 'overwrite_imm'
            if oth.type == X86_OP_REG:
                return 'overwrite_reg'
        return 'other'

    # memory operand is a source -> read; the shape is what consumes the value
    track = set()
    dst = ins.operands[0]
    if dst.type == X86_OP_REG:
        track.add(dst.reg)
    for j in range(idx + 1, min(idx + 13, len(ins_list))):
        it = ins_list[j]
        # follow `mov reg, tracked`
        if it.mnemonic == 'mov' and len(it.operands) == 2 \
                and it.operands[0].type == X86_OP_REG \
                and _is_tracked(it.operands[1], track):
            track.add(it.operands[0].reg)
            continue
        if it.mnemonic in READ_FIRST and any(_is_tracked(op, track)
                                             for op in it.operands):
            return READ_FIRST[it.mnemonic]
        if it.mnemonic == 'test' and any(_is_tracked(op, track)
                                         for op in it.operands):
            imm = next((op.imm for op in it.operands if op.type == X86_OP_IMM), None)
            if imm is not None and imm and (imm & (imm - 1)) == 0:
                return 'read_bit'
            return 'read_mask'
    return 'other'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('rva', help='global RVA, hex like 0x296cc68')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    exe = resolve_exe()
    if exe is None:
        sys.exit('stellaris.exe not found - set NS_STELLARIS_EXE')
    target = int(a.rva, 16)
    img = Image(exe)
    rows = []
    for p, v, e in candidates_for_global(img.text, img.tva, target):
        fn = img.func_of(e - 1) or img.func_of(p)
        ins_list = None
        if fn:
            ins_list = img.decode(fn[0], fn[1])
        if ins_list is None or not any(
                (ins.address - BASE) <= p < (ins.address - BASE) + ins.size
                and (ins.address - BASE) + ins.size == e for ins in ins_list):
            # leaf fragment without .pdata (or decode stopped early): decode locally
            ins_list = img.decode(p - 2, p - 2 + 0x80)
            fn = (p - 2, p - 2 + 1)      # extent unknown without unwind info
        idx = None
        for i, ins in enumerate(ins_list):
            istart = ins.address - BASE
            if istart <= p < istart + ins.size and istart + ins.size == e:
                idx = i
                break
        if idx is None:
            rows.append({'insn_rva': p - 2, 'fn_start': fn[0], 'fn_end': fn[1],
                         'form': 'other', 'mnemonic': '?', 'op_str': '<no decode>'})
            continue
        ins = ins_list[idx]
        # confirm the operand really resolves to the target
        ok = any(op.type == X86_OP_MEM and op.mem.base in (X86_REG_RIP, X86_REG_EIP)
                 and ins.address + ins.size + op.mem.disp - BASE == target
                 for op in ins.operands)
        form = classify(ins_list, idx) if ok else 'other'
        rows.append({'insn_rva': ins.address - BASE, 'fn_start': fn[0],
                     'fn_end': fn[1], 'form': form, 'mnemonic': ins.mnemonic,
                     'op_str': ins.op_str})

    rows.sort(key=lambda r: r['insn_rva'])
    counts = {k: sum(1 for r in rows if r['form'] == k)
              for k in ('set_bit', 'overwrite_imm', 'overwrite_reg',
                        'read_mask', 'read_bit', 'other')}

    if a.json:
        print(json.dumps({'module': exe, 'target': f'0x{target:x}',
                          'refs': len(rows), 'counts': counts, 'rows': rows},
                         ensure_ascii=False))
        return

    print(f'# module {exe}')
    print(f'# global 0x{target:x}  .text bytes={len(img.text)}  pdata funcs={len(img.funcs)}')
    for r in rows:
        print(f"{r['insn_rva']:08x}\t{r['fn_start']:08x}\t{r['fn_end']:08x}\t"
              f"{r['form']}\t{r['mnemonic']}\t{r['op_str']}")
    print('refs=%d set_bit=%d overwrite_imm=%d overwrite_reg=%d '
          'read_mask=%d read_bit=%d other=%d'
          % (len(rows), counts['set_bit'], counts['overwrite_imm'],
             counts['overwrite_reg'], counts['read_mask'], counts['read_bit'],
             counts['other']))


if __name__ == '__main__':
    main()
