import sys, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
EXE = r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe'
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz+6)[0]
opt_off = mz + 24
nsec_off = opt_off + struct.unpack_from('<H', f, mz+20)[0]
secs = []
for i in range(nsec):
    nm = f[nsec_off+i*40:nsec_off+i*40+8].rstrip(b'\0').decode()
    va, vs, praw = struct.unpack_from('<III', f, nsec_off+i*40+12)
    secs.append((nm, va, vs, praw))
def rd(rva, n):
    for nm, va, vs, praw in secs:
        if va <= rva < va + vs: return f[praw + rva - va: praw + rva - va + n]
    return b''
BASE = 0x140000000
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
RVA = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x1D08520
N = int(sys.argv[2]) if len(sys.argv) > 2 else 90
code = rd(RVA, N*16)
out = []
for ins in md.disasm(code, BASE + RVA):
    out.append(ins)
    if len(out) >= N: break
for ins in out:
    mark = ''
    if '[rip' in ins.op_str:
        m = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-f]+)\]', ins.op_str)
        if m:
            d = int(m.group(2),16); t = ins.address+ins.size+(d if m.group(1)=='+' else -d)
            mark = f'   ; imgrel {t-BASE:x}'
    elif ins.mnemonic in ('call','jmp') and re.fullmatch(r'0x[0-9a-f]+', ins.op_str or ''):
        mark = f'   ; imgrel {int(ins.op_str,16)-BASE:x}'
    print(f'{ins.address-BASE:x}: {ins.mnemonic} {ins.op_str}{mark}')
print('\n--- arg-reference audit ---')
for i, ins in enumerate(out):
    if re.search(r'\[rsp \+ 0x[2-9a-f][0-9a-f]\]', ins.op_str) or 'r8' in ins.op_str or 'r9' in ins.op_str or 'dword ptr [rsp' in ins.op_str:
        print(f'  +{i:02d} {ins.address-BASE:x}: {ins.mnemonic} {ins.op_str}')
