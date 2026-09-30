"""Scan .text for every rip-relative reference landing inside the keyword
descriptor array 0x337B400 + 0x120*n. Buckets by field offset within the
0x120 entry, and separates the known registration driver from everyone else.

usage: descscan.py [d0_rva] [count]
"""
import sys, os, struct
from collections import Counter, defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_REG_RIP
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
BASE = 0x140000000
secs = []
for i in range(struct.unpack_from('<H', f, mz + 6)[0]):
    o = no + i * 40
    nm = f[o:o + 8].split(b'\0')[0].decode('latin1')
    vs, va, rsz, rp = struct.unpack_from('<IIII', f, o + 8)
    ch = struct.unpack_from('<I', f, o + 36)[0]
    secs.append((nm, va, vs, rsz, rp, ch))

D0 = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x337B400
N = int(sys.argv[2]) if len(sys.argv) > 2 else 9863
STRIDE = 0x120
D1 = D0 + STRIDE * N
DRIVER = (0x172E50, 0x1AF1E7)
print(f'array [0x{D0:x}, 0x{D1:x})  driver 0x{DRIVER[0]:x}..0x{DRIVER[1]:x}',
      flush=True)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
pages = Counter()
fields = Counter()
outside = defaultdict(list)
total = 0

for nm, va, vs, rsz, rp, ch in secs:
    if not (ch & 0x20000000):
        continue
    blob = f[rp:rp + rsz]
    off = 0
    while off < len(blob):
        ran = 0
        for ins in md.disasm(blob[off:off + 0x400000], BASE + va + off):
            irva = ins.address - BASE
            for op in ins.operands:
                t = None
                if op.type == 3 and op.mem.base == X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp - BASE
                elif op.type == 4 and ins.mnemonic in ('call', 'jmp') \
                        and op.imm > BASE:
                    t = op.imm - BASE
                if t is not None and D0 <= t < D1:
                    total += 1
                    k = (t - D0) % STRIDE
                    fields[k] += 1
                    pages[(nm, irva & ~0xFFF)] += 1
                    if not (DRIVER[0] <= irva < DRIVER[1]):
                        outside[k].append((irva, ins.mnemonic,
                                           ins.reg_name(ins.operands[0].reg)
                                           if ins.operands[0].type == 3
                                           or ins.operands[0].type == 1 else '?',
                                           t - D0))
            ran = ins.address + ins.size - (BASE + va)
        off = ran if ran > off else off + 1
    print(f'  done {nm}', flush=True)

print(f'\n{total} refs into the array')
print('field-offset histogram within the 0x120 entry:')
for k, c in sorted(fields.items()):
    print(f'  +0x{k:03x}  {c}')
print('\nrefs OUTSIDE the driver:')
if not outside:
    print('  NONE')
for k, lst in sorted(outside.items()):
    print(f'  field +0x{k:03x}: {len(lst)} sites')
    for site, mn, r0, delta in lst[:25]:
        print(f'    0x{site:x}  {mn:<8} {r0:<5} -> 0x{D0 + delta:x} '
              f'(entry {delta // STRIDE})')
