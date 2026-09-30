"""Byte-level locate of every direct call/jmp to an RVA, bucketed by .pdata
function, each bucket labelled with the source-file strings inside that
function. No full linear disassembly, so it runs in seconds: it matches the
`E8 rel32` / `EB.. jmp` encodings by construction instead of decoding 37 MB.

usage: fastcalls.py <target_rva_hex> [--section .text]
"""
import sys, struct, bisect, os, re
from collections import defaultdict
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
BASE = 0x140000000
SECS = []
for i in range(struct.unpack_from('<H', f, mz + 6)[0]):
    o = no + i * 40
    nm = f[o:o + 8].split(b'\0')[0].decode('latin1')
    vs, va, rsz, rp = struct.unpack_from('<IIII', f, o + 8)
    ch = struct.unpack_from('<I', f, o + 36)[0]
    SECS.append((nm, va, vs, rsz, rp, ch))
BY_NAME = {s[0]: s for s in SECS}


def sec_of(rva):
    for nm, va, vs, rsz, rp, ch in SECS:
        if va <= rva < va + max(vs, rsz):
            return nm, va, rp
    return None


def to_off(rva):
    s = sec_of(rva)
    return None if s is None else s[2] + (rva - s[1])


def cstr(rva, cap=160):
    o = to_off(rva)
    if o is None or o >= len(f):
        return None
    end = f.find(b'\0', o, o + cap)
    if end < 0:
        return None
    try:
        s = f[o:end].decode('utf-8')
    except UnicodeDecodeError:
        return None
    return s if len(s) >= 3 else None


pd = BY_NAME['.pdata']
funcs = sorted(struct.unpack_from('<III', f, pd[4] + i * 12)
               for i in range(pd[3] // 12))
STARTS = [x[0] for x in funcs]
END_OF = {x[0]: x[1] for x in funcs}


def func_of(rva):
    i = bisect.bisect_right(STARTS, rva) - 1
    if i < 0:
        return None
    b, e, u = funcs[i]
    return (b, e, u) if rva < e else None


args = [a for a in sys.argv[1:] if not a.startswith('--')]
sect = sys.argv[sys.argv.index('--section') + 1] if '--section' in sys.argv \
    else '.text'
TARGET = int(args[0], 16)
nm, va, vs, rsz, rp, ch = BY_NAME[sect]
blob = f[rp:rp + rsz]

# 1. E8 rel32 near call, EB rel8 short jmp, FF /2 rip-relative jmp [addr],
#    FF /3 rip-relative call [addr] (thunk form used by the compiler here).
sites = []
want = TARGET - BASE - va
pos = 0
while True:
    pos = blob.find(b'\xe8', pos)
    if pos < 0:
        break
    pos += 1
    if pos + 4 >= len(blob):
        continue
    rva_here = va + pos - 1
    rel = struct.unpack_from('<i', blob, pos)[0]
    if BASE + rva_here + 5 + rel == BASE + TARGET:
        sites.append(rva_here)
    pos += 4

for opc in (b'\xff\x25', b'\xff\x15'):
    pos = 0
    while True:
        s = blob.find(opc, pos)
        if s < 0:
            break
        pos = s + 1
        rva_here = va + s
        if s + 6 >= len(blob):
            continue
        disp = struct.unpack_from('<i', blob, s + 2)[0]
        ptr_rva = (BASE + rva_here + 6 + disp) - BASE
        po = to_off(ptr_rva)
        if po is None or po + 8 > len(f):
            continue
        if struct.unpack_from('<Q', f, po)[0] != BASE + TARGET:
            continue
        sites.append(rva_here)

sites = sorted(set(sites))
print(f'{len(sites)} direct code sites to 0x{TARGET:x} in {sect}')

per_fn = defaultdict(list)
unresolved = []
for s in sites:
    fx = func_of(s)
    if fx:
        per_fn[fx[0]].append(s)
    else:
        unresolved.append(s)

# __FILE__ here is a full build-machine path with backslashes
# (C:\mnt\gsg\stellaris\augustus\augustus\source\policy.cpp), so match the tail.
FILE_RE = re.compile(r'([^\\/]+\.(?:cpp|cc|c|h|hpp|inl))$')
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def ref_strings(fs, e, cap=56):
    """Every printable C-string a rip operand inside [fs,e) points at, plus the
    source-file names among them. Message text attributes a stripped function to
    a subsystem far more reliably than __FILE__ constants, which the compiler
    often only materialises in the error-reporting helper it tail-calls."""
    o = to_off(fs)
    out, files = [], set()
    if o is None:
        return out, files
    for ins in md.disasm(f[o:o + (e - fs)], fs):
        for op in ins.operands:
            # x86 rip-relative lives in op.mem.base, not op.reg
            if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                continue
            t = ins.address + ins.size + op.mem.disp
            s = sec_of(t)
            if s is None or s[0] not in ('.rdata', '.data'):
                continue
            txt = cstr(t)
            if not txt:
                continue
            m = FILE_RE.search(txt)
            if m:
                files.add(m.group(1))
                continue
            if 4 <= len(txt) <= cap and txt.isprintable():
                out.append((t, txt))
    return out, files


rows = []
for fs, lst in per_fn.items():
    e = END_OF.get(fs, fs + 1)
    strs, files = ref_strings(fs, e)
    rows.append((len(lst), fs, e, sorted(files), strs, lst))
rows.sort(key=lambda r: (-r[0], r[1]))

TOP = int(sys.argv[sys.argv.index('--top') + 1]) if '--top' in sys.argv else 25
print(f'in {len(rows)} functions'
      f'{"" if not unresolved else f"  ({len(unresolved)} outside .pdata)"}\n')
for cnt, fs, e, files, strs, lst in rows[:TOP]:
    print(f'{cnt:>3} sites  0x{fs:x}..0x{e:x} ({e - fs:#x})  '
          f'{" ".join(files) if files else "-"}')
    for t, txt in strs[:6]:
        print(f'         0x{t:x} {txt!r}')

path = f'evidence/xrefs/callers_0x{TARGET:x}_buckets.tsv'
with open(path, 'w') as out:
    out.write('# caller_count\tfunc_start\tfunc_end\tsrc_files\tsites'
              '\tref_strings\n')
    for cnt, fs, e, files, strs, lst in rows:
        out.write(f'{cnt}\t0x{fs:x}\t0x{e:x}\t{",".join(files)}\t'
                  f'{",".join(hex(x) for x in lst)}\t'
                  f'{" | ".join(f"0x{t:x}:{txt}" for t, txt in strs[:12])}\n')
print(f'\nwrote {path}')
