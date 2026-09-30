#!/usr/bin/env python3
"""Where does each keyword `create` publish its vpointers?

§22.3 established that a keyword factory is `new(size) -> memset -> base ctor -> publish vptrs`, and
it recorded the two stores as `[obj+0]` and `[obj+8]`. That was read off ONE worked example
(`add_modifier`, an effect), and `0x1b30450` (`has_crisis_perk`) is what sent the question back to the
data — it stores at `[obj+0x78]`. This tool measures all 1,605 of them and splits the two instructions
that look alike: `lea rax,[rip+X]; mov [obj+d],rax` **publishes X** (X is a vtable), while
`mov rax,[rip+X]; mov [obj+d],rax` **copies the value at global X** (not a vtable). §22.3 had counted
them together, which is where the universal `+0`/`+8` shape came from.

Method: decode each factory ALIGNED from its `.pdata` start (a mid-function window resynchronises by
luck and invents stores), remember the rva of the most recent rip-relative `lea`/`mov` into a register,
and record `mov [reg + disp], r` as a publication of that rva at `disp`, tagged with which instruction
it came from.

Output is also written as evidence: `python scripts/vptrslots.py > evidence/xrefs/
vptr_publish_slots_4_4_4.txt` (see §24.4.1 for the numbers it produced).

Usage: python scripts/vptrslots.py [census.tsv]
"""
import sys, os, struct, re, collections, csv
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *

_cands = [os.environ.get('NS_STELLARIS_EXE'),
          '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe',
          r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe']
EXE = next((c for c in _cands if c and os.path.exists(c)), None)
if EXE is None:
    sys.exit('stellaris.exe not found - set NS_STELLARIS_EXE')
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz + 6)[0]
nopt = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
BASE = 0x140000000
secs = []
for i in range(nsec):
    o = nopt + i * 40
    name = f[o:o + 8].rstrip(b'\0').decode()
    vsize, va, rawsize, raw = struct.unpack_from('<IIII', f, o + 8)
    secs.append((name, va, vsize, raw, rawsize))

def off(rva):
    for name, va, vsize, raw, rawsize in secs:
        if va <= rva < va + max(vsize, rawsize):
            return raw + (rva - va)
    return None

pdata = next(s for s in secs if s[0] == '.pdata')
praw = f[pdata[3]:pdata[3] + pdata[4]]
funcs = []
for i in range(0, len(praw) - 11, 12):
    begin, end = struct.unpack_from('<II', praw, i)
    if begin and end > begin:
        funcs.append((BASE + begin, BASE + end))
funcs.sort()

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
census = sys.argv[1] if len(sys.argv) > 1 else 'evidence/xrefs/class_info_census_4_4_4.tsv'
rows = list(csv.DictReader(open(census), delimiter='\t'))
by_begin = {b: e for b, e in funcs}

out = collections.Counter()
detail = {}
for r in rows:
    fa = int(r['factory_rva'], 16) + BASE
    end = by_begin.get(fa)
    if end is None:
        # not a .pdata start; take the function containing it
        cand = [(b, e) for b, e in funcs if b <= fa < e]
        if not cand:
            detail[r['class_info_rva']] = 'no .pdata entry'
            continue
        fa, end = cand[0]
    blob = f[off(fa - BASE):off(end - BASE)]
    pubs = []
    last_rip = None          # (reg, resolved_rva, kind) kind: 'lea' or 'load'
    for ins in md.disasm(blob, fa):
        ops = ins.operands
        if len(ops) != 2:
            continue
        # `lea r?, [rip+X]` publishes the ADDRESS X (a vtable lives there);
        # `mov r?, [rip+X]` copies the VALUE stored at global X (not a vtable).
        if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM \
                and ops[1].mem.base == X86_REG_RIP and ins.mnemonic in ('lea', 'mov'):
            kind = 'lea' if ins.mnemonic == 'lea' else 'load'
            last_rip = (ops[0].reg, ins.address + ins.size + ops[1].mem.disp, kind)
        elif ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG and ins.mnemonic == 'mov':
            mem, src = ops[0].mem, ops[1]
            if last_rip and src.reg == last_rip[0] and mem.index == X86_REG_INVALID:
                pubs.append((mem.disp, last_rip[1] - BASE, last_rip[2]))
                last_rip = None
    detail[r['class_info_rva']] = pubs
    for d, _, kind in pubs:
        out[(kind, d)] += 1

for kind in ('lea', 'load'):
    print(f"== {kind}-sourced stores into the fresh block, disp -> factory count ==")
    for (k, d), c in sorted(((k, v) for k, v in out.items() if k[0] == kind), key=lambda x: x[0][1]):
        print(f"  +{d:#x} ({d}): {c}")
    print()
print("per class_info, full dump (tsv):")
print("class_info_rva\tcreate_rva\tlea_stores\tload_stores")
for r in rows:
    pubs = detail.get(r['class_info_rva'])
    if not isinstance(pubs, list):
        continue
    lea_s = ' '.join(f"+{d:#x}={v:#x}" for d, v, k in pubs if k == 'lea')
    ld_s = ' '.join(f"+{d:#x}={v:#x}" for d, v, k in pubs if k == 'load')
    print(f"{r['class_info_rva']}\t{r['factory_rva']}\t{lea_s}\t{ld_s}")
