#!/usr/bin/env python3
"""Map every rip-relative reference and call/jmp target in executable code that
lands inside a given RVA range (default: the hardcoded script keyword name block),
then histogram by 4 KB code page so a registration driver shows up as a dense run.

One full linear capstone decode of .text, ~4.5 min. usage: kwscan.py [lo hi]
"""
import sys, os, struct, re
from collections import Counter, defaultdict
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz + 6)[0]
no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
BASE = 0x140000000
secs = []
for i in range(nsec):
    o = no + i * 40
    nm = f[o:o + 8].split(b'\0')[0].decode('latin1')
    vs, va, rsz, rp = struct.unpack_from('<IIII', f, o + 8)
    ch = struct.unpack_from('<I', f, o + 36)[0]
    secs.append((nm, va, vs, rsz, rp, ch))

RIP = re.compile(rb'\[(?:rip|eip)\s*([+-])\s*(0x[0-9a-f]+)\]', re.I)
lo = int(sys.argv[1], 16) if len(sys.argv) > 2 else 0x247f480
hi = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x2494070
print(f'{os.path.basename(EXE)}  target range [{lo:#x}, {hi:#x})', flush=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
pages = Counter()
per_addr = defaultdict(list)

for nm, va, vs, rsz, rp, ch in secs:
    if not (ch & 0x20000000):
        continue
    blob = f[rp:rp + rsz]
    n = len(blob)
    off = 0
    print(f'scanning {nm} ({n:#x} bytes) ...', flush=True)
    while off < n:
        nxt = off
        for ins in md.disasm(blob[off:off + 0x400000], BASE + va + off):
            irva = ins.address - BASE
            for op in ins.operands:
                t = None
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp - BASE
                elif op.type == X86_OP_IMM and ins.mnemonic in ('call', 'jmp') \
                        and op.imm > BASE:
                    t = op.imm - BASE
                if t is not None and lo <= t < hi:
                    pages[(nm, irva & ~0xFFF)] += 1
                    per_addr[irva].append((ins.mnemonic, t))
            nxt = ins.address + ins.size - (BASE + va)
        off = nxt if nxt > off else off + 1

print(f'\ntotal refs: {sum(len(v) for v in per_addr.values())} '
      f'at {len(per_addr)} sites across {len(pages)} code pages\n')
print('== code pages by reference density (top 40) ==')
for (sn, pg), c in pages.most_common(40):
    print(f'  {sn:<8} 0x{pg:07x}  {c}')
print('\n== distinct target RVAs hit ==')
tg = sorted({t for v in per_addr.values() for _, t in v})
print(f'  {len(tg)} of the keywords, first 20: '
      + ', '.join(f'{t:x}' for t in tg[:20]))

# Full site dump: every referencing instruction, grouped by page, so a second
# 4.5-minute pass is never needed.
by_page = defaultdict(list)
for rva, lst in per_addr.items():
    by_page[rva & ~0xFFF].append((rva, lst))
with open('evidence/xrefs/keyword_block_ref_sites_4_4_4.txt', 'w') as w:
    w.write(f'# stellaris.exe 4.4.4 — every code reference into keyword name block '
            f'[0x{lo:x}, 0x{hi:x})\n')
    w.write(f'# {sum(len(v) for v in per_addr.values())} refs at {len(per_addr)} sites'
            f' / {len(tg)} distinct names\n')
    for pg in sorted(by_page, key=lambda p: -sum(len(l) for _, l in by_page[p])):
        sites = sorted(by_page[pg])
        w.write(f'\n--- page 0x{pg:07x}  ({len(sites)} sites, '
                f'{sum(len(l) for _, l in sites)} refs) ---\n')
        for rva, lst in sites:
            for mn, t in lst:
                w.write(f'  0x{rva:07x}  {mn} -> 0x{t:x}\n')
print('\nfull dump -> evidence/xrefs/keyword_block_ref_sites_4_4_4.txt')
