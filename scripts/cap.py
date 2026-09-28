import sys, struct
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
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
BASE = 0x140000000
def dis(rva, n, label=None):
    if label: print(f'\n== {label} @{rva:x} ==')
    code = rd(rva, n*16)
    for ins in md.disasm(code, BASE + rva):
        extra = ''
        if ins.mnemonic in ('call','lea','jmp','jcc') and ins.operands and ins.operands[-1].type == 4:
            pass
        mark = ''
        if '[rip' in ins.op_str:
            import re as _re
            m = _re.search(r'\[(rip|eip)\s*([+-])\s*(0x[0-9a-f]+)\]', ins.op_str, _re.I)
            if m:
                d = int(m.group(3), 16)
                t = ins.address + ins.size + (d if m.group(2) == '+' else -d)
                mark = f'   -> imgrel {t-BASE:x}'
        elif ins.mnemonic == 'call':
            try:
                t = int(ins.op_str, 16)
                if t > BASE: mark = f'   -> imgrel {t-BASE:x}'
            except ValueError: pass
        print(f'{ins.address-BASE:x}: {ins.mnemonic} {ins.op_str}{mark}')
        n -= 1
        if n <= 0: break
dis(0xD150A0, 55, 'register_fn')
dis(0xD152C0, 30, 'caller context in master init')
dis(0xD15175, 90, 'register_fn body cont')
dis(0x1BCD120, 40, 'per-keyword Execute impl (vtable[2])')
dis(0x1BCCF30, 30, 'other keyword impl')
