"""Parse the master registration driver (one giant generated function) into a
table of (token id, keyword name, static descriptor address, call site).

Shape of every entry, as emitted by the compiler:
    lea r8, [rip+name]        ; keyword name string
    mov edx, <id>             ; sequential token id
    lea rcx, [rip+descriptor] ; static descriptor object
    call <registrar>

usage: regscan.py [func_start_rva registrar_rva]
"""
import sys, os, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
import pdata

REG = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x1D15270
if sys.argv[1:2] == ['all']:
    _t = next(s for s in pdata.secs if s[0] == '.text')
    lo, hi = _t[1], _t[1] + _t[2]
else:
    START = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x172E50
    fx = pdata.func_of(START)
    assert fx, f'0x{START:x} not in .pdata'
    lo, hi, _u = fx
BASE = 0x140000000
# read function bytes
def rd(rva, n):
    for nm, va, rsz, rp in pdata.secs:
        if va <= rva < va + rsz:
            return pdata.f[rp + rva - va: rp + rva - va + n]
    return b''

code = rd(lo, hi - lo)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def rip_target(ins, op):
    return ins.address + ins.size + op.mem.disp - BASE


rows = []
pending = {}


def consider(ins):
    """Advance the (r8 name, edx id, rcx descriptor) state machine and emit a
    row when a call to the registrar lands."""
    global pending
    ops = ins.operands
    if ins.mnemonic == 'lea' and len(ops) == 2 \
            and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM \
            and ops[1].mem.base == X86_REG_RIP:
        dst = ins.reg_name(ops[0].reg)
        src = ins.address + ins.size + ops[1].mem.disp - BASE
        if dst == 'r8':
            pending['name'] = src
        elif dst == 'rcx':
            pending['desc'] = src
    elif ins.mnemonic == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_REG \
            and ins.reg_name(ops[0].reg) == 'edx' and ops[1].type == X86_OP_IMM:
        pending['id'] = ops[1].imm
    elif ins.mnemonic == 'call' and ops and ops[0].type == X86_OP_IMM \
            and ops[0].imm - BASE == REG:
        rows.append((pending.get('id'), pending.get('name'),
                     pending.get('desc'), ins.address - BASE))
        pending = {}


# Chunked linear decode with 1-byte resync: one md.disasm() over a 37 MB blob
# stops at the first undecodable byte, so whole-section scans need this.
CHUNK = 0x400000
scan_from, off = lo, lo
while off < hi:
    blob = rd(off, min(CHUNK, hi - off))
    if not blob:
        break
    nxt = off
    for ins in md.disasm(blob, BASE + off):
        consider(ins)
        nxt = ins.address + ins.size - BASE
    off = nxt if nxt > off else off + 1

print(f'function 0x{lo:x}..0x{hi:x} ({hi - lo:#x} bytes), registrar 0x{REG:x}')
print(f'{len(rows)} registration calls')
ids = [r[0] for r in rows if r[0] is not None]
print(f'id range: {min(ids):#x}..{max(ids):#x}  distinct={len(set(ids))}  '
      f'contiguous={max(ids)-min(ids)+1 == len(set(ids))}')
d = [r[2] for r in rows if r[2]]
print(f'descriptors: distinct={len(set(d))} span 0x{min(d):x}..0x{max(d):x}')
ds = sorted(set(d))
runs = {}
for i in range(len(ds) - 1):
    runs.setdefault(ds[i + 1] - ds[i], 0)
    runs[ds[i + 1] - ds[i]] += 1
print('descriptor deltas across the sorted set: '
      + ', '.join(f'{g:#x}:{c}' for g, c in
                  sorted(runs.items(), key=lambda kv: -kv[1])[:6]))

from collections import Counter
fc = Counter(pdata.func_of(site)[0] if pdata.func_of(site) else -1
             for _, _, _, site in rows)
print('\ncalls per enclosing function (top 12):')
for st, c in fc.most_common(12):
    fx = pdata.func_of(st + 1) if st < 0 else None
    print(f'  func {st and hex(st) or "??"}  {c} calls')

out = open('evidence/xrefs/keyword_registration_table_4_4_4.tsv', 'w')
out.write('# id\tname_rva\tname\tdescriptor_rva\tcall_site_rva\t'
          'registrar_rva=0x1d15270\n')


def cstr(rva, cap=128):
    b = rd(rva, cap)
    return b.split(b'\0')[0].decode('utf-8', 'replace')


for i, (tid, name, desc, site) in enumerate(rows):
    out.write(f'{tid if tid is not None else "-"}\t'
              f'{name and hex(name)}\t{cstr(name) if name else "?"}\t'
              f'{desc and hex(desc)}\t{site:#x}\n')
out.close()
print('\nfirst 12 rows:')
for r in rows[:12]:
    print(f'  id={r[0] and hex(r[0])}  name={cstr(r[1])!r:<34} '
          f'desc={r[2] and hex(r[2])}  site=0x{r[3]:x}')
