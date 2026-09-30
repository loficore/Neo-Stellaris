"""Token ids are compile-time immediates in the registration driver, so any
static table keyed by a token id is findable offline. Two probes per id:
  1. dword occurrences of the id in .rdata/.data followed by a plausible pointer
     (a {id, factory} or {id, vtable} registry record)
  2. code sites with the id as an immediate operand (cmp/mov) outside the driver
usage: idscan.py <id_hex> [<id_hex> ...]
"""
import sys, os, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM
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
SEC = {nm: (va, rsz, rp) for nm, va, vs, rsz, rp, ch in secs}


def rva_of(nm, off):
    va, rsz, rp = SEC[nm]
    return va + off - rp


DRIVER = (0x172E50, 0x1AF1E7)
ids = [int(a, 16) for a in sys.argv[1:]]

# --- probe 1: data records  <dword id><...><pointer into .text/.rdata>
print('=== data records containing the id as a dword ===')
for nm, va, vs, rsz, rp, ch in secs:
    if nm not in ('.rdata', '.data'):
        continue
    blob = f[rp:rp + rsz]
    for i in ids:
        pat = struct.pack('<I', i)
        s = 0
        n = 0
        while True:
            k = blob.find(pat, s)
            if k < 0:
                break
            s = k + 1
            for gap in (4, 0):
                q = struct.unpack_from('<Q', blob, k + 4 + gap)[0] \
                    if k + 12 + gap <= len(blob) else 0
                if q < BASE:
                    continue
                t = q - BASE
                tn, tv, trp = None, None, None
                for nm2, va2, vs2, rsz2, rp2, ch2 in secs:
                    if va2 <= t < va2 + rsz2:
                        tn, tv, trp = nm2, va2, rp2
                        break
                if tn in ('.text', '.rdata', '.data'):
                    print(f'  id {i:#x} @ {nm} rva 0x{rva_of(nm, k):x} '
                          f'gap {gap} -> {tn} 0x{t:x}')
                    n += 1
                    break
            if n > 6:
                break

# --- probe 2: code immediates
print('\n=== code sites using the id as an immediate ===')
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
want = set(ids)
hits = {i: [] for i in ids}
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
                if op.type == X86_OP_IMM and op.imm in want:
                    hits[op.imm].append((irva, nm, ins.mnemonic, ins.op_str,
                                         DRIVER[0] <= irva < DRIVER[1]))
            ran = ins.address + ins.size - (BASE + va)
        off = ran if ran > off else off + 1

for i in ids:
    lst = hits[i]
    ndrv = sum(1 for h in lst if h[4])
    print(f'\nid {i:#x}: {len(lst)} sites ({ndrv} inside driver, '
          f'{len(lst) - ndrv} elsewhere)')
    for irva, nm, mn, ops, d in lst:
        if not d:
            print(f'  0x{irva:x} [{nm}] {mn} {ops}')
