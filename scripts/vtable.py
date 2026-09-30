#!/usr/bin/env python3
"""Dump a vtable: its slots, each slot's .pdata function bounds, and the strings
that function references. Answers "what are this object's virtual methods" without
IDA and without guessing the extent.

The extent is the problem this exists to solve. Walking a code-pointer run until a
non-code qword appears over-reads constantly, because this linker packs vtables back
to back (measured in §22.5: 711 of the 1,805 CEffect vtables measure >= 256 slots that
way). So the default here is a bounded window, and each slot is checked against .pdata:
a slot is real only if its target is the *start* of a RUNTIME_FUNCTION entry. That also
detects the end, since a neighbouring vtable's slots still look like function starts --
which is why `--first` is what trims them, not the code check.

usage: vtable.py <data_rva_hex> [--slots N] [--callers] [--first]
"""
import sys, os, struct, bisect, re, argparse
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz + 6)[0]
no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
BASE = 0x140000000
secs = []
for i in range(nsec):
    nm = f[no + i * 40:no + i * 40 + 8].rstrip(b'\0').decode()
    vs, va, rsz, rp = struct.unpack_from('<IIII', f, no + i * 40 + 8)
    secs.append((nm, va, vs, rsz, rp))

def rd(rva, n):
    for nm, va, vs, rsz, rp in secs:
        if va <= rva < va + vs:
            return f[rp + rva - va: rp + rva - va + n]
    return b''

# .pdata -> set of function starts, plus bounds lookup.
pdata = next(s for s in secs if s[0] == '.pdata')
raw = rd(pdata[1], pdata[2])
funcs = []
for i in range(0, len(raw) - 11, 12):
    begin, end = struct.unpack_from('<II', raw, i)
    funcs.append((begin, end))
funcs.sort()
starts = {b for b, _ in funcs}
bounds = [(b, e) for b, e in funcs]

def func_of(rva):
    i = bisect.bisect_right(bounds, (rva, 0x7fffffffffffffff)) - 1
    if i >= 0 and bounds[i][0] <= rva < bounds[i][1]:
        return bounds[i]
    return None

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def strings_in(rva, size, limit=400):
    """rip-relative string/data targets a function touches, readable ones first."""
    out = []
    code = rd(rva, min(size, limit * 16))
    for ins in md.disasm(code, BASE + rva):
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = ins.address + ins.size + op.mem.disp - BASE
                s = rd(t, 64).split(b'\0')[0]
                if len(s) >= 3 and all(32 <= c < 127 for c in s):
                    out.append((t, s.decode()))
        if len(out) > 12:
            break
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('rva')
    ap.add_argument('--slots', type=int, default=16)
    ap.add_argument('--callers', action='store_true',
                    help='also count direct call/jmp sites per slot (byte scan, slower)')
    ap.add_argument('--first', action='store_true',
                    help='stop at the first slot whose target is not a function start')
    a = ap.parse_args()
    root = int(a.rva, 16)
    blob = rd(root, a.slots * 8)
    # The file's .rdata holds pre-relocation absolute VAs (image base baked in), so a
    # slot is `0x140000000 + rva`; tolerate either form rather than assume one.
    relocated = []
    for i in range(0, len(blob) - 7, 8):
        v = struct.unpack_from('<Q', blob, i)[0]
        relocated.append(v)
    n = 0
    for idx, v in enumerate(relocated):
        rva = v - BASE if v > BASE else v
        fb = func_of(rva) if rva else None
        is_start = rva in starts
        if a.first and not is_start:
            print(f'  [{idx}] stop: {v:#x} is not a function start')
            break
        marks = []
        if fb and is_start:
            marks.append('bounds %x..%x' % fb)
        elif fb:
            marks.append('mid-function of %x..%x' % fb)
        else:
            marks.append('NOT CODE')
        if a.callers and is_start:
            marks.append('callers %d' % len(call_sites(rva)))
        strs = strings_in(rva, (fb[1] - fb[0]) if fb and is_start else 0x40) \
            if fb and is_start and fb[1] - fb[0] < 0x40000 else []
        print(f'  [{idx:#03x}] +{idx*8:#04x} -> {rva:x}  ' + '  '.join(marks))
        for t, s in strs[:4]:
            print(f'          str {t:x} "{s[:70]}"')
        n += 1
    print(f'({n} slots shown; extent is NOT proven by this listing — see docstring)')

def call_sites(target_rva):
    """E8 rel32 call sites for target (cheap, exact for direct calls)."""
    text = next(s for s in secs if s[0] == '.text')
    code = rd(text[1], text[2])
    hits = []
    for m in re.finditer(b'\xe8', code):
        off = m.start()
        disp = struct.unpack_from('<i', code, off + 1)[0]
        if BASE + text[1] + off + 5 + disp == BASE + target_rva:
            hits.append(text[1] + off)
    return hits

if __name__ == '__main__':
    main()
