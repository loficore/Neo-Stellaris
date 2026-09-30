"""Enumerate every code site that uses a keyword-table token id as an
immediate outside the registration driver. Those are the real extension
points: per-keyword metadata/behaviour registries keyed by compile-time ids.

usage: idregistry.py            # reads evidence TSV produced by regscan.py
"""
import sys, os, struct
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
TSV = 'evidence/xrefs/keyword_registration_table_4_4_4.tsv'
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

by_id = defaultdict(list)
rows = 0
for ln in open(TSV):
    if ln.startswith('#'):
        continue
    p = ln.rstrip('\n').split('\t')
    if len(p) < 5 or p[0] == '-':
        continue
    by_id[int(p[0])].append(p[2])
    rows += 1
want = set(by_id)
print(f'{rows} ids, {len(want)} distinct', flush=True)

# .pdata -> function bounds. Tuple is (nm, va, vs, rsz, rp, ch): the table
# lives at rp (index 4) and its byte length is rsz (index 3), NOT SizeOfVirtualSize.
pd = next(s for s in secs if s[0] == '.pdata')
funcs = sorted(struct.unpack_from('<III', f, pd[4] + i * 12)
               for i in range(pd[3] // 12))
FSTART = [x[0] for x in funcs]
import bisect


def func_of(rva):
    i = bisect.bisect_right(FSTART, rva) - 1
    if i < 0:
        return None
    b, e, u = funcs[i]
    return (b, e, u) if rva < e else None


DRIVER = (0x172E50, 0x1AF1E7)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
sites = []
for nm, va, vs, rsz, rp, ch in secs:
    if not (ch & 0x20000000):
        continue
    blob = f[rp:rp + rsz]
    off = 0
    while off < len(blob):
        ran = 0
        for ins in md.disasm(blob[off:off + 0x400000], BASE + va + off):
            irva = ins.address - BASE
            if not (DRIVER[0] <= irva < DRIVER[1]):
                for op in ins.operands:
                    if op.type == X86_OP_IMM and op.imm in want:
                        sites.append((irva, nm, ins.mnemonic, ins.op_str,
                                      op.imm, func_of(irva)))
            ran = ins.address + ins.size - (BASE + va)
        off = ran if ran > off else off + 1
    print(f'  done {nm}: {len(sites)} sites', flush=True)

per_fn = defaultdict(list)
for s in sites:
    per_fn[s[5][0] if s[5] else 0].append(s)

out = open('evidence/xrefs/token_id_use_sites_4_4_4.tsv', 'w')
out.write('# func_start\tfunc_end\tsite_rva\tsection\tmnemonic\toperands'
          '\ttoken_id\tkeyword\n')
for fs in sorted(per_fn):
    e = next((x[1] for x in funcs if x[0] == fs), 0)
    for irva, nm, mn, ops, imm, fx in sorted(per_fn[fs], key=lambda s: s[0]):
        out.write(f'0x{fs:x}\t0x{e:x}\t0x{irva:x}\t{nm}\t{mn}\t{ops}\t'
                  f'{imm}\t{",".join(by_id[imm])}\n')
out.close()

print(f'\n{len(sites)} sites in {len(per_fn)} functions')
rank = sorted(per_fn.items(), key=lambda kv: len(kv[1]), reverse=True)
for fs, lst in rank[:20]:
    e = next((x[1] for x in funcs if x[0] == fs), 0)
    print(f'  0x{fs:x}..0x{e:x} ({e - fs:#x})  {len(lst)} id uses')
