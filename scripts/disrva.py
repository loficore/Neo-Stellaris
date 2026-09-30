#!/usr/bin/env python3
"""Disassemble an RVA range of stellaris.exe offline, annotating every
rip-relative operand with the RVA it resolves to and every call target.

Usage: python scripts/disrva.py <start_rva_hex> [end_rva_hex|count]
"""
import sys, os, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

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
    nm = f[o:o + 8].split(b'\0')[0].decode('latin1')
    vs, va, rawsz, praw = struct.unpack_from('<IIII', f, o + 8)
    ch = struct.unpack_from('<I', f, o + 36)[0]
    secs.append((nm, va, vs, rawsz, praw, ch))


def rd(rva, n):
    for nm, va, vs, rawsz, praw, ch in secs:
        if va <= rva < va + max(vs, rawsz):
            off = praw + rva - va
            return f[off:off + n], nm
    return b'', '?'


RIP = re.compile(r'\[(?:rip|eip)\s*([+-])\s*(0x[0-9a-f]+)\]', re.I)

start = int(sys.argv[1], 16)
if len(sys.argv) > 2:
    a = int(sys.argv[2], 16)
    # heuristic: small second arg = instruction count, large = end rva
    end, cnt = (start + a, None) if a > 0xFF else (None, a)
else:
    end, cnt = None, 80

code, sec = rd(start, (end - start) if end else cnt * 16)
print(f'; {os.path.basename(EXE)}  {sec} RVA 0x{start:x}'
      + (f'-0x{end:x}' if end else f'  ({cnt} insns)'))
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
n = 0
for ins in md.disasm(code, BASE + start):
    if end and ins.address >= BASE + end:
        break
    note = ''
    m = RIP.search(ins.op_str)
    if m:
        d = int(m.group(2), 16)
        t = ins.address + ins.size + (d if m.group(1) == '+' else -d)
        note = f'  ; -> 0x{t - BASE:x}'
    elif ins.mnemonic in ('call', 'jmp') and ins.op_str.startswith('0x'):
        note = f'  ; -> 0x{int(ins.op_str, 16) - BASE:x}'
    print(f'  {ins.address - BASE:08x}  {ins.mnemonic:<7} {ins.op_str}{note}')
    n += 1
    if cnt and n >= cnt:
        break
