"""Find every copy of a keyword string in the image, then every code site that
rip-refers one of those copies. Answers "who else registers this name?" without
IDA: the token table owns one copy, effect/factory registration uses another.

usage: strrefs.py <name> [<name> ...]
"""
import sys, os, struct
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_REG_RIP, X86_OP_MEM, X86_OP_IMM, X86_OP_REG
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


def rva_of_off(off):
    for nm, va, vs, rsz, rp, ch in secs:
        if rp <= off < rp + rsz:
            return nm, va + off - rp
    return '?', None


def off_of_rva(rva):
    for nm, va, vs, rsz, rp, ch in secs:
        if va <= rva < va + max(vs, rsz):
            return rp + rva - va
    return None


names = sys.argv[1:]
targets = {}
for n in names:
    pat = n.encode() + b'\0'
    hits = []
    s = 0
    while True:
        i = f.find(pat, s)
        if i < 0:
            break
        if i == 0 or f[i - 1] == 0 or f[i - 1] >= 0x80:
            hits.append(i)
        s = i + 1
    for i in hits:
        sec, rva = rva_of_off(i)
        targets.setdefault(rva, []).append((n, sec))
    print(f'{n}: {len(hits)} copies -> ' +
          ', '.join(f'{s} 0x{rva_of_off(i)[1]:x}' for i in hits))

want = set(targets)
if not want:
    sys.exit(0)

found = defaultdict(list)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
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
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp - BASE
                elif op.type == X86_OP_IMM and ins.mnemonic in ('call', 'jmp') \
                        and op.imm > BASE:
                    t = op.imm - BASE
                if t in want:
                    for n, s in targets[t]:
                        found[n].append((irva, nm, ins.mnemonic,
                                         ins.op_str, t))
            ran = ins.address + ins.size - (BASE + va)
        off = ran if ran > off else off + 1

print(f'\n{sum(len(v) for v in found.values())} reference sites')
for n in names:
    print(f'\n### {n}')
    for irva, sn, mn, ops, t in found.get(n, []):
        fx = None
        print(f'  0x{irva:x} [{sn}] {mn} {ops}  -> 0x{t:x}')
