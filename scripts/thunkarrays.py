"""Parse the static arrays of per-keyword registration thunks in .rdata.

Each array element points at a small (~106 byte) function shaped like:
    rbx = [g_db]                                  ; BST global, lazy-ctor'd
    if (!rbx) rbx = ctor(call 0x3aeba0)
    p = operator new(0x10)
    [p + 0] = &class_table_or_ctor
    [p + 8] = &doc_string
    edx = <token id>                              ; compile-time constant
    r8  = p ; rcx = rbx
    jmp <BST insert>                              ; e.g. 0x3aef60

This is the keyword -> behaviour binding. Run it over every run of function
pointers found in .rdata/.data, so effects, triggers and anything else that
uses the same idiom fall out together.

usage: thunkarrays.py [min_array_len]
"""
import sys, os, struct, bisect
from collections import Counter, defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
BASE = 0x140000000
MINLEN = int(sys.argv[1]) if len(sys.argv) > 1 else 40

f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
secs = []
for i in range(struct.unpack_from('<H', f, mz + 6)[0]):
    o = no + i * 40
    nm = f[o:o + 8].split(b'\0')[0].decode('latin1')
    vs, va, rsz, rp = struct.unpack_from('<IIII', f, o + 8)
    secs.append((nm, va, rsz, rp))


def rd(rva, n):
    for nm, va, rsz, rp in secs:
        if va <= rva < va + rsz:
            return f[rp + rva - va: rp + rva - va + n]
    return b''


def cstr(rva, cap=300):
    return rd(rva, cap).split(b'\0')[0].decode('utf-8', 'replace')


# .pdata bounds
pd = next(s for s in secs if s[0] == '.pdata')
funcs = sorted(struct.unpack_from('<III', f, pd[3] + i * 12)
               for i in range(pd[2] // 12))
FUNC_BY_START = {x[0]: (x[0], x[1]) for x in funcs}
FSTART = [x[0] for x in funcs]


def func_at(rva):
    i = bisect.bisect_right(FSTART, rva) - 1
    if i < 0:
        return None
    b, e, u = funcs[i]
    return (b, e) if b <= rva < e else None


# --- find runs of function-start pointers in .rdata/.data -------------------
arrays = []
run = None
for nm, va, rsz, rp in secs:
    if nm not in ('.rdata', '.data'):
        continue
    for i in range(rsz // 8):
        q = struct.unpack_from('<Q', f, rp + i * 8)[0]
        r = q - BASE
        hit = 0 < r < 0x2400000 and r in FUNC_BY_START
        if hit:
            if run is None:
                run = [va + i * 8, 0]
            run[1] += 1
        else:
            if run and run[1] >= MINLEN:
                arrays.append((nm, run[0], run[1]))
            run = None
    if run and run[1] >= MINLEN:
        arrays.append((nm, run[0], run[1]))
    run = None
print(f'{len(arrays)} pointer arrays >= {MINLEN}', flush=True)

name_by_id = defaultdict(list)
for ln in open('evidence/xrefs/keyword_registration_table_4_4_4.tsv'):
    if ln.startswith('#'):
        continue
    p = ln.rstrip('\n').split('\t')
    if len(p) >= 5 and p[0] != '-':
        name_by_id[int(p[0])].append(p[2])

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def parse_thunk(t):
    insns = list(md.disasm(rd(t, FUNC_BY_START[t][1] - t), BASE + t))
    db = tid = None
    fields = {}
    pend = {}
    insert = None
    for ins in insns:
        o = ins.operands
        if ins.mnemonic in ('mov',) and len(o) == 2 and o[0].type == X86_OP_REG \
                and o[1].type == X86_OP_MEM and o[1].mem.base == X86_REG_RIP:
            if ins.reg_name(o[0].reg) in ('rbx', 'r14', 'rdi', 'rsi'):
                db = ins.address + ins.size + o[1].mem.disp - BASE
        elif ins.mnemonic == 'lea' and len(o) == 2 and o[0].type == X86_OP_REG \
                and o[1].type == X86_OP_MEM and o[1].mem.base == X86_REG_RIP:
            pend[ins.reg_name(o[0].reg)] = \
                ins.address + ins.size + o[1].mem.disp - BASE
        elif ins.mnemonic == 'mov' and len(o) == 2 and o[0].type == X86_OP_REG \
                and ins.reg_name(o[0].reg) == 'edx' and o[1].type == X86_OP_IMM:
            tid = o[1].imm
        elif ins.mnemonic == 'mov' and len(o) == 2 and o[0].type == X86_OP_MEM \
                and o[0].mem.base in (X86_REG_RIP,) and o[1].type == X86_OP_REG:
            pass
        elif ins.mnemonic == 'mov' and len(o) == 2 and o[0].type == X86_OP_MEM \
                and o[1].type == X86_OP_REG:
            reg = ins.reg_name(o[1].reg)
            if reg in pend and o[0].mem.disp in (0, 8) and \
                    ins.reg_name(o[0].mem.base) in ('rax', 'rcx', 'r8'):
                fields[o[0].mem.disp] = pend[reg]
        elif ins.mnemonic in ('jmp', 'call') and o and o[0].type == X86_OP_IMM \
                and o[0].imm > BASE:
            insert = o[0].imm - BASE
    return db, tid, fields.get(0), fields.get(8), insert


rows = []
summ = []
for nm, addr, n in arrays:
    dbs = Counter()
    recs = []
    for i in range(n):
        q = struct.unpack_from('<Q', rd(addr + i * 8, 8))[0]
        t = q - BASE
        if t not in FUNC_BY_START:
            continue
        db, tid, a, b, ins = parse_thunk(t)
        if db is not None:
            dbs[db] += 1
        if tid is not None:
            recs.append((i, t, db, tid, a, b, ins))
    summ.append((nm, addr, n, dbs.most_common(3), len(recs)))
    for i, t, db, tid, a, b, ins in recs:
        rows.append((addr, i, t, db, tid, a, b, ins))

print(f'\n{"arr":<22} {"len":>5} {"ids":>5}  db globals')
for nm, addr, n, dbs, nrec in summ:
    print(f'{nm+" 0x"+format(addr,"x"):<22} {n:>5} {nrec:>5}  ' +
          ', '.join(f'0x{d:x}x{c}' for d, c in dbs))

out = open('evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv', 'w')
out.write('# array_rva\tindex\tthunk_rva\tdb_global_rva\ttoken_id\tkeywords'
          '\tfield0_rva\tfield0_target\tfield8_doc_rva\tdoc_first_line'
          '\tinsert_fn_rva\n')
for addr, i, t, db, tid, a, b, ins in sorted(rows):
    tgt = '?'
    if a is not None:
        q = rd(a, 8)
        if len(q) == 8:
            v = struct.unpack('<Q', q)[0]
            tgt = f'0x{v - BASE:x}' if v > BASE else repr(v)
    doc = cstr(b, 200).split('\n')[0] if b else ''
    out.write(f'0x{addr:x}\t{i}\t0x{t:x}\t{db and hex(db)}\t'
              f'{tid}\t{",".join(name_by_id.get(tid, ["?"]))}\t'
              f'{a and hex(a)}\t{tgt}\t{b and hex(b)}\t{doc}\t'
              f'{ins and hex(ins)}\n')
out.close()
known = sum(1 for r in rows if r[4] in name_by_id)
print(f'\n{len(rows)} records, {known} with a token id present in the '
      f'keyword table')
