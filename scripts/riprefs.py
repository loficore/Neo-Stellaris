#!/usr/bin/env python3
"""Who reads or writes a data global -- in seconds, without decoding 37 MB.

`find_refs.py` answers this too, but it linearly disassembles every executable section,
which is a 15-minute job. A rip-relative operand is fully determined by its *encoding*, so
no disassembly is needed to find one: the ModRM byte with mod=00 and rm=101 *is* the
`[rip + disp32]` form, the opcode tells us the operation, and the target is
`next_insn_address + disp32`. So a byte regex collects every candidate and the disp32 is
checked arithmetically. Same answer, ~3 s.

Caveats this encodes deliberately:
  * A byte match can land on the middle of an instruction. Those produce a target that
    happens to equal the query by accident, so `--verify` re-decodes each hit aligned from
    its own .pdata function start and drops the ones that are not a real rip operand.
  * disp32-only forms are covered; a global at a disp8 offset from a rip base cannot be
    encoded, so there is nothing to miss there.
  * `FF 15` (call/jmp through [rip]) has rm=101 too and is included.

usage: riprefs.py <rva_hex> [more...] [--verify] [--section .text]
"""
import sys, os, struct, re, bisect, argparse
from collections import defaultdict
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

def rd(rva, n, sec):
    for nm, va, vs, rsz, rp in secs:
        if nm == sec and va <= rva < va + vs:
            return f[rp + rva - va: rp + rva - va + n]
    return b''

PDATA = next(s for s in secs if s[0] == '.pdata')
raw = rd(PDATA[1], PDATA[2], '.pdata')
funcs = []
for i in range(0, len(raw) - 11, 12):
    funcs.append(struct.unpack_from('<II', raw, i)[:2])
funcs.sort()

def func_of(rva):
    i = bisect.bisect_right(funcs, (rva, 0x7fffffffffffffff)) - 1
    return funcs[i] if i >= 0 and funcs[i][0] <= rva < funcs[i][1] else None

# opcode | / opcode | lea | cmp | sbb/adc | FF /x (call/jmp/thunk through [rip])
OPC = rb'\x8b\x89\x8d\x3b\x39\x3d\x2b\x13\x03\x0b\x21\x29\x31\xff'
RM101 = frozenset(b'\x05\x0d\x15\x1d\x25\x2d\x35\x3d\x45\x4d\x55\x5d\x65\x6d\x75\x7d')
# Scan the opcode byte alone. A 3-byte regex pattern cannot overlap, so a match starting
# one byte into another candidate's displacement would be silently lost; per-byte
# occurrence scanning costs a little speed and loses nothing.
OPC_PAT = re.compile(rb'[' + OPC + b']')

def candidates(blob):
    """Yield (opcode_index, disp32_index, insn_len_without_disp) per plausible rip operand.

    Byte order is [REX] opcode modrm disp32, so given an opcode byte at i the ModRM is at
    i+1 whether or not a REX prefix precedes it. ModRM encodes rip when mod==00 and rm==101.
    """
    n = len(blob)
    for m in OPC_PAT.finditer(blob):
        i = m.start()
        if i + 5 >= n:
            continue
        modrm = blob[i + 1]
        if (modrm >> 6) or (modrm & 7) != 5:
            continue
        prev = blob[i - 1] if i else 0
        has_rex = 0x40 <= prev <= 0x4f
        # length = (rex?) + opcode + modrm + disp32, measured from the first byte of the insn
        head_len = (3 if has_rex else 2)
        yield i - (1 if has_rex else 0), i + 2, head_len

def refs_for(targets, sec, verify):
    va = next(s[1] for s in secs if s[0] == sec)
    vs = next(s[2] for s in secs if s[0] == sec)
    blob = rd(va, vs, sec)
    hits = defaultdict(list)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for insn_at, disp_at, head_len in candidates(blob):
        disp = struct.unpack_from('<i', blob, disp_at)[0]
        site = va + insn_at
        target = site + head_len + 4 + disp
        if target not in targets:
            continue
        if verify:
            fb = func_of(site)
            if fb is None:
                continue
            ins = next((i for i in md.disasm(rd(fb[0], site - fb[0] + 16, sec), BASE + fb[0])
                        if i.address - BASE == site), None)
            if ins is None or not ins.operands:
                continue
            op = next((o for o in ins.operands if o.type == X86_OP_MEM), None)
            if not (op is not None and op.mem.base == X86_REG_RIP):
                continue
            if site + ins.size + op.mem.disp != target:
                continue
        hits[target].append((site, blob[insn_at:disp_at + 4]))
    return hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('rvas', nargs='+')
    ap.add_argument('--section', default='.text')
    ap.add_argument('--verify', action='store_true',
                    help='re-decode each hit aligned to its function start, dropping '
                         'mid-instruction false positives (slower, still seconds)')
    ap.add_argument('--limit', type=int, default=25)
    a = ap.parse_args()
    targets = {int(r, 16) for r in a.rvas}
    hits = refs_for(targets, a.section, a.verify)
    for t in sorted(targets):
        h = hits.get(t, [])
        print(f'\n== {len(h)} refs to {t:x} ({a.section}){" [verified]" if a.verify else ""} ==')
        by_fn = defaultdict(list)
        for site, enc in h:
            by_fn[func_of(site)].append((site, enc))
        for fb, sites in sorted(by_fn.items(), key=lambda kv: -len(kv[1]))[:a.limit]:
            tag = f'{fb[0]:x}..{fb[1]:x}' if fb else 'not-in-pdata'
            print(f'  {len(sites):5d}  func {tag}')
        if len(by_fn) > a.limit:
            print(f'  ... {len(by_fn)-a.limit} more functions')

if __name__ == '__main__':
    main()
