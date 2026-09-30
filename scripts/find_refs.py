"""Find image-relative references to given RVAs in stellaris.exe, without IDA.

Linear capstone decode of every executable section, resyncing one byte at a time
when a decode fails, so all operand forms count: `call`/`jmp` with a resolved
target, plus any rip-relative operand (`lea`, `mov`, `cmp`, `test`, stores...).
RIP targets on data globals are therefore found, not just `lea`.

Usage: python scripts/find_refs.py <rva_hex> [more_rvas...]
"""
import sys, os, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

_cands = [os.environ.get('NS_STELLARIS_EXE'),
          '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe',
          r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe']
EXE = next((c for c in _cands if c and os.path.exists(c)), None)
if EXE is None:
    sys.exit('stellaris.exe not found - set NS_STELLARIS_EXE')

f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz + 6)[0]
nsec_off = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
BASE = 0x140000000
secs = []
for i in range(nsec):
    o = nsec_off + i * 40
    nm = f[o:o + 8].rstrip(b'\0').decode()
    va, rawsz, praw = struct.unpack_from('<III', f, o + 12)
    ch = struct.unpack_from('<I', f, o + 36)[0]
    secs.append((nm, va, rawsz, praw, ch))

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

targets = [int(a, 16) for a in sys.argv[1:]]
if not targets:
    sys.exit(__doc__)
tset = set(targets)
hits = {t: [] for t in targets}
print(f'{os.path.basename(EXE)}  targets: ' + ', '.join(f'0x{t:x}' for t in targets))

for nm, va, rawsz, praw, ch in secs:
    if not (ch & 0x20000000):
        continue
    blob = f[praw:praw + rawsz]
    print(f'scanning {nm} ({len(blob):#x} bytes) ...', flush=True)
    n = len(blob)
    off = 0
    while off < n:
        # Decode in big chunks: iterating one generator is far cheaper than
        # re-entering capstone per instruction. Resync by 1 byte where it stops.
        nxt = off
        for ins in md.disasm(blob[off:off + 0x400000], BASE + va + off):
            for op in ins.operands:
                t = None
                if op.type == X86_OP_IMM:
                    if ins.mnemonic in ('call', 'jmp') and op.imm > BASE:
                        t = op.imm - BASE
                elif op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp - BASE
                if t is not None and t in tset:
                    hits[t].append((ins.address - BASE, ins.mnemonic, ins.op_str, nm))
            nxt = ins.address + ins.size - (BASE + va)
        off = nxt if nxt > off else off + 1

for t in targets:
    hs = hits[t]
    print(f'\n== 0x{t:x}: {len(hs)} references ==')
    for rva, mn, ops, sn in hs[:25]:
        print(f'  {sn} {rva:#x}: {mn} {ops}')
    if len(hs) > 25:
        print(f'  ... {len(hs) - 25} more')
