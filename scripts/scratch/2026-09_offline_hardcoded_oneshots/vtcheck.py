import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
EXE = r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe'
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz+6)[0]
nsec_off = mz + 24 + struct.unpack_from('<H', f, mz+20)[0]
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
for label, rva in [('generic_keyword_vtable', 0x33720E8), ('base_execute_slot_check', 0x1D08520)]:
    if label == 'base_execute_slot_check':
        print(label, struct.unpack('<16B', rd(rva,16)))
        continue
    print(f'== {label} RVA {rva:x} ==')
    for i in range(8):
        v = struct.unpack('<Q', rd(rva+i*8, 8))[0]
        rel = v - BASE if v > BASE else 0
        print(f'  slot[{i}] +0x{i*8:02x}: {v:016x}  imgrel={rel:x}')
