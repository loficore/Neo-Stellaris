import sys, struct, binascii
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
for label, rva in [('base_execute', 0x1D08520), ('slot5', 0x535070), ('switch', 0x5350D0)]:
    code = rd(rva, 48)
    print(f'\n== {label} RVA {rva:x} ==')
    print('bytes:', binascii.hexlify(code[:32]).decode())
    acc = 0; riprel = False
    for ins in md.disasm(code, BASE + rva):
        mark = ''
        if '[rip' in ins.op_str:
            mark = '   <-- RIP-RELATIVE'; riprel = True
        print(f'  +{ins.address-(BASE+rva):02x} ({acc:2d}) {ins.mnemonic} {ins.op_str}{mark}')
        acc += ins.size
        if acc >= 20: break
    print(f'  first-14-byte window rip-relative? {riprel}')
