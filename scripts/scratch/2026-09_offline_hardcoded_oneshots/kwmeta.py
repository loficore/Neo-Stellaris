"""Extract the per-keyword metadata registry.

Each hardcoded keyword has a small thunk that does:
    rbx = [g_db]                       (g_db = 0x33746E8 in this build)
    r8  = operator new(0x10)
    [r8 + 0] = <field A ptr>           (relocated -> class table / ctor fn)
    [r8 + 8] = <field B ptr>           (documentation string)
    edx = <token id, compile-time constant>
    rcx = rbx
    jmp <BST insert>                   (0x3AEF60 in this build)

This walks every .pdata function, matches that shape by the `mov edx, <id>` +
`jmp <insert>` pair, and dumps id -> keyword -> {A, B}. No IDA needed.

usage: kwmeta.py [db_rva] [insert_rva]
"""
import sys, os, struct, bisect
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import (X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP)
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
BASE = 0x140000000
DB = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x33746E8
INS = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x3AEF60

f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
secs = []
for i in range(struct.unpack_from('<H', f, mz + 6)[0]):
    o = no + i * 40
    nm = f[o:o + 8].split(b'\0')[0].decode('latin1')
    vs, va, rsz, rp = struct.unpack_from('<IIII', f, o + 8)
    ch = struct.unpack_from('<I', f, o + 36)[0]
    secs.append((nm, va, vs, rsz, rp, ch))


def rd(rva, n):
    for nm, va, vs, rsz, rp, ch in secs:
        if va <= rva < va + max(vs, rsz):
            off = rp + rva - va
            return f[off:off + n]
    return b''


def cstr(rva, cap=400):
    return rd(rva, cap).split(b'\0')[0].decode('utf-8', 'replace')


name_by_id = {}
for ln in open('evidence/xrefs/keyword_registration_table_4_4_4.tsv'):
    if ln.startswith('#'):
        continue
    p = ln.rstrip('\n').split('\t')
    if len(p) >= 5 and p[0] != '-':
        name_by_id[int(p[0])] = p[2]

pd = next(s for s in secs if s[0] == '.pdata')
funcs = sorted(struct.unpack_from('<III', f, pd[3] + i * 12)
               for i in range(pd[2] // 12))
FSTART = [x[0] for x in funcs]

TEXTRVA = next((va, rsz, rp) for nm, va, vs, rsz, rp, ch in secs
               if nm == '.text')
tva, trsz, trp = TEXTRVA
blob = f[trp:trp + trsz]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

recs = []
CHUNK = 0x400000
off = 0
cur = None


def flush(ins_list):
    """Try to match the registration shape over one function's instructions."""
    if not ins_list:
        return
    last = ins_list[-1]
    tail = None
    for ins in reversed(ins_list):
        if ins.mnemonic in ('jmp', 'call') and ins.operands and \
                ins.operands[0].type == X86_OP_IMM and \
                ins.operands[0].imm - BASE == INS:
            tail = ins
            break
        if ins.mnemonic == 'ret':
            break
    if tail is None:
        return
    ids = [ins.operands[1].imm for ins in ins_list
           if ins.mnemonic == 'mov' and len(ins.operands) == 2
           and ins.operands[0].type == X86_OP_REG
           and ins.reg_name(ins.operands[0].reg) == 'edx'
           and ins.operands[1].type == X86_OP_IMM
           and ins.operands[1].imm in name_by_id]
    if len(ids) != 1:
        return
    fields = {}
    pend = {}
    for ins in ins_list:
        o = ins.operands
        if ins.mnemonic == 'lea' and len(o) == 2 and o[0].type == X86_OP_REG \
                and o[1].type == X86_OP_MEM and o[1].mem.base == X86_REG_RIP:
            pend[ins.reg_name(o[0].reg)] = \
                ins.address + ins.size + o[1].mem.disp - BASE
        elif ins.mnemonic == 'mov' and len(o) == 2 and o[0].type == X86_OP_MEM \
                and o[1].type == X86_OP_REG:
            reg = ins.reg_name(o[1].reg)
            if reg in pend and o[0].mem.disp in (0, 8):
                fields[o[0].mem.disp] = pend[reg]
    if len(fields) != 2:
        return
    recs.append((ids[0], fields.get(0), fields.get(8),
                 ins_list[0].address - BASE))


print(f'db 0x{DB:x}  insert 0x{INS:x}  scanning .text '
      f'({trsz:#x} bytes)', flush=True)
cur = None
nseen = 0


def boundary(irva):
    """Return func record containing irva, or None."""
    i = bisect.bisect_right(FSTART, irva) - 1
    if i < 0:
        return None
    b, e, u = funcs[i]
    return (b, e) if b <= irva < e else None


off = 0
while off < trsz:
    ran = off
    for ins in md.disasm(blob[off:off + CHUNK], BASE + tva + off):
        ran = ins.address + ins.size - (BASE + tva)
        nseen += 1
        irva = ins.address - BASE
        fx = boundary(irva)
        if fx is None:
            if cur is not None:
                flush(cur[1])
                cur = None
            continue
        if cur is not None and cur[0] != fx[0]:
            flush(cur[1])
            cur = None
        if cur is None:
            cur = (fx[0], [])
        cur[1].append(ins)
        if irva + 1 >= fx[1]:
            flush(cur[1])
            cur = None
    off = ran if ran > off else off + 1
    print(f'  0x{off:x}/{trsz:x}  {nseen} insns  {len(recs)} recs', flush=True)

if cur is not None:
    flush(cur[1])

print(f'\n{len(recs)} keyword metadata records')
out = open('evidence/xrefs/keyword_meta_registry_4_4_4.tsv', 'w')
out.write('# token_id\tkeyword\tfield0_rva\tfield0_meaning'
          '\tfield8_doc_rva\tdoc_first_line\tthunk_rva\n')
for tid, a, bptr, thunk in sorted(recs):
    fa = '?'
    if a is not None:
        q = rd(a, 8)
        if len(q) == 8:
            v = struct.unpack('<Q', q)[0]
            fa = f'ptr->0x{v - BASE:x}' if v > BASE else repr(v)
    doc = cstr(bptr, 200).split('\n')[0] if bptr else ''
    out.write(f'{tid}\t{name_by_id[tid]}\t{a and hex(a)}\t{fa}\t'
              f'{bptr and hex(bptr)}\t{doc}\t0x{thunk:x}\n')
out.close()
print(f'distinct ids: {len({r[0] for r in recs})} of {len(name_by_id)} keywords')
for r in sorted(recs)[:10]:
    print(f'  id={r[0]:<6} {name_by_id[r[0]]:<20} f0={r[1] and hex(r[1])} '
          f'f8={r[2] and hex(r[2])} thunk=0x{r[3]:x}')
