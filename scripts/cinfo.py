"""Census every class_info pair the official registration thunks insert, and pin the calling
convention of its factory.

A registration thunk stores `new(0x10){ class_info, docstring }` in the keyword db, and
`class_info` is the 16-byte pair `{field0, field1}`. field0 is the same function for almost every
entry; field1 is per-keyword. Neither is ever referenced by an immediate anywhere in `.text`
(`fastcalls.py 0x18a3340` and `0x34c090` both return zero direct sites, and `find_refs.py` finds
each class_info exactly once — in its own thunk), so both are reached only through the value
record. Their convention therefore has to come from the bodies themselves.

Per factory this reports, over its exact `.pdata` extent:
  arg_reads      — did it READ rcx/rdx/r8/r9 (or a stack argument) before ever writing them?
                   False means the function is a nullary `T()`, whatever the caller passes.
  new_sizes      — the immediates it hands to operator new
  callees        — call targets, in order
  published      — rip-relative objects it touches (the vpointers it stores)

usage: cinfo.py [out_tsv]
"""
import csv
import os
import struct
import sys
from collections import Counter

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_READ, CS_AC_WRITE
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM, X86_REG_RIP, X86_REG_RSP

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
REG_TSV = 'evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv'
OUT_DEFAULT = 'evidence/xrefs/class_info_census_4_4_4.tsv'
BASE = 0x140000000
OPERATOR_NEW = 0x2185218

f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
secs = []
for i in range(struct.unpack_from('<H', f, mz + 6)[0]):
    nm = f[no + i * 40:no + i * 40 + 8].split(b'\0')[0].decode('latin1')
    vs, va, rsz, rp = struct.unpack_from('<IIII', f, no + i * 40 + 8)
    secs.append((nm, va, vs, rsz, rp))


def rd(rva, n):
    for nm, va, vs, rsz, rp in secs:
        if va <= rva < va + vs:
            return f[rp + rva - va:rp + rva - va + n]
    return b''


def qword(rva):
    b = rd(rva, 8)
    return struct.unpack('<Q', b)[0] if len(b) == 8 else None


# .pdata gives exact function bounds, so a factory is decoded over its real extent and cannot
# bleed into whichever function happens to follow it in the linker's layout.
pd = next(s for s in secs if s[0] == '.pdata')
funcs = []
for i in range(pd[3] // 12):
    begin, end, _unwind = struct.unpack_from('<III', f, pd[4] + i * 12)
    funcs.append((begin, end))
funcs.sort()


def func_bounds(rva):
    for begin, end in funcs:
        if begin <= rva < end:
            return begin, end
    return None, None


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

ALIASES = {'al': 'rax', 'ax': 'rax', 'eax': 'rax', 'ah': 'rax',
           'bl': 'rbx', 'bx': 'rbx', 'ebx': 'rbx',
           'cl': 'rcx', 'cx': 'rcx', 'ecx': 'rcx', 'ch': 'rcx',
           'dl': 'rdx', 'dx': 'rdx', 'edx': 'rdx', 'dh': 'rdx',
           'sil': 'rsi', 'si': 'rsi', 'esi': 'rsi',
           'dil': 'rdi', 'di': 'rdi', 'edi': 'rdi',
           'bpl': 'rbp', 'bp': 'rbp', 'ebp': 'rbp',
           'r8b': 'r8', 'r8w': 'r8', 'r8d': 'r8',
           'r9b': 'r9', 'r9w': 'r9', 'r9d': 'r9'}
ARGS = frozenset(('rcx', 'rdx', 'r8', 'r9'))


def norm(rid):
    nm = md.reg_name(rid)
    if nm is None:
        return None
    return ALIASES.get(nm, nm)


def operand_regs(op):
    if op.type == X86_OP_REG:
        return {norm(op.reg)}
    if op.type == X86_OP_MEM:
        out = set()
        for rid in (op.mem.base, op.mem.index):
            if rid and md.reg_name(rid) != 'rip':
                out.add(norm(rid))
        return out
    return set()


def classify(rva):
    """Decode one function over its exact .pdata extent.

    arg_reads is a def/use pass over the four register parameters and over `[rsp+N]` slots with
    N >= 0x20: either kind of read, before anything in this body wrote it, means the function
    consumes caller state. Reads that the same operand also writes (`xor edx, edx`, `sub rsp, 0x20`)
    are excluded — those are idiom writes, not uses. The slot rule is only sound because these
    frame-slot test is done in entry-rsp coordinates: every push and `sub rsp` is tracked, so a
    spill written before the frame was set up (`mov [rsp+8], rbx` then `push`/`sub`) is recognised
    as the same slot its epilogue reloads. Without that normalisation the common
    `mov rbx, [rsp+0x30]` reload reads like a stack argument.
    """
    begin, end = func_bounds(rva)
    if begin is None:
        return None
    code = rd(begin, end - begin)
    written = set()
    slots = set()
    frame = 0
    arg_reads = False
    read_regs = set()
    new_sizes = []
    callees = []
    published = []
    for ins in md.disasm(code, BASE + begin):
        ops = ins.operands
        # `xor edx, edx` / `sbb eax, eax` are MSVC zeroing idioms: capstone marks the destination
        # READ|WRITE, but nobody is reading a caller parameter there. `add rcx, rcx` is not in the
        # set, because it genuinely consumes the incoming value.
        self_zero = ins.mnemonic in ('xor', 'sub', 'sbb') \
            and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG \
            and ops[0].reg == ops[1].reg
        reads = set()
        writes = set()
        for op in ops:
            regs = operand_regs(op)
            if op.access & CS_AC_WRITE:
                writes |= regs
            if op.access & CS_AC_READ and not self_zero:
                reads |= regs
        if (reads & ARGS) - written:
            arg_reads = True
            read_regs |= (reads & ARGS) - written
        written |= writes
        if ins.mnemonic == 'call':
            callees.append(ops[0].imm - BASE if ops and ops[0].type == X86_OP_IMM else None)
        if len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM \
                and norm(ops[0].reg) == 'rcx':
            new_sizes.append(ops[1].imm)
        for i, op in enumerate(ops):
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RSP:
                slot = op.mem.disp - frame
                # Only a plain store defines the slot; `lea reg, [rsp+N]` hands the address out and
                # would let a callee write there.
                if op.access & CS_AC_WRITE and i == 0 and ins.mnemonic.startswith('mov'):
                    slots.add(slot)
                elif slot >= 0x20 and slot not in slots:
                    arg_reads = True
                    read_regs.add('[rsp+0x%x]' % slot)
        for op in ops:
            if op.type != X86_OP_MEM:
                continue
            if op.mem.base == X86_REG_RIP:
                published.append(op.mem.disp + ins.address + ins.size - BASE)
        if ins.mnemonic == 'push':
            frame += 8
        elif ins.mnemonic == 'pop':
            frame -= 8
        elif len(ops) == 2 and ops[0].type == X86_OP_REG and norm(ops[0].reg) == 'rsp':
            if ins.mnemonic == 'sub' and ops[1].type == X86_OP_IMM:
                frame += ops[1].imm
            elif ins.mnemonic == 'add' and ops[1].type == X86_OP_IMM:
                frame -= ops[1].imm
        if ins.mnemonic == 'ret':
            break
    return dict(arg_reads=arg_reads, read_regs=sorted(read_regs), new_sizes=new_sizes,
                callees=callees, published=published)


# Only the two keyword dbs. The same producer tsv also carries 2,160 rows from the type-registry
# init arrays (db_global None), and those records are a different shape — including them made
# 6 "factories" look like they consumed a parameter when they are in fact class vtables.
KEYWORD_DBS = ('0x33746e8', '0x32611c8')
rows = [r for r in csv.DictReader(open(REG_TSV), delimiter='\t')
        if r['field0_rva'] not in ('', 'None', None) and r['db_global_rva'] in KEYWORD_DBS]
addrs = sorted({int(r['field0_rva'], 16) for r in rows})
out_path = sys.argv[1] if len(sys.argv) > 1 else OUT_DEFAULT
out = open(out_path, 'w')
out.write('class_info_rva\tfield0_rva\tfactory_rva\tfactory_arg_reads\twhich_args\tnew_sizes\t'
          'callees\tpublished_rvas\n')

f0 = Counter()
arguse = Counter()
callee_sets = Counter()
newsize = Counter()
whichkind = Counter()
fail = 0
for a in addrs:
    d0, d1 = qword(a), qword(a + 8)
    if d0 is None or d1 is None or not (BASE <= d1 < BASE + 0x2392000):
        fail += 1
        continue
    info = classify(d1 - BASE)
    if info is None:
        fail += 1
        continue
    f0[hex(d0 - BASE)] += 1
    arguse[info['arg_reads']] += 1
    if info['arg_reads']:
        whichkind['param register' if any(not r.startswith('[rsp') for r in info['read_regs'])
                  else 'stack slot'] += 1
    for s in dict.fromkeys(info['new_sizes']):
        newsize[hex(s)] += 1
    callee_sets[tuple(dict.fromkeys('indirect' if c is None else ('operator_new' if c == OPERATOR_NEW
                                                                  else hex(c))
                                    for c in info['callees']))] += 1
    out.write('%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' % (
        hex(a), hex(d0 - BASE), hex(d1 - BASE), info['arg_reads'],
        ' '.join(info['read_regs']),
        ' '.join(hex(s) for s in dict.fromkeys(info['new_sizes'])),
        ' '.join('indirect' if c is None else ('operator_new' if c == OPERATOR_NEW else hex(c))
                 for c in info['callees']),
        ' '.join(hex(p) for p in dict.fromkeys(info['published']))))
out.close()

print('class_info pairs censused:', len(addrs) - fail, ' skipped:', fail)
print('field0 (the shared function):', f0.most_common(8))
print('factory reads an incoming argument register:', dict(arguse))
print('by kind:', whichkind.most_common())
print('sizes handed to operator new (top):', newsize.most_common(10))
print('\ncallee sets:')
for k, v in callee_sets.most_common(8):
    print('  %4d  %s' % (v, ' '.join(k)))
print('wrote', out_path)
