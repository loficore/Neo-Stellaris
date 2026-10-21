import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
EXE = r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe'
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz+6)[0]
nsec_off = mz + 24 + struct.unpack_from('<H', f, mz+20)[0]
print('sections:')
for i in range(nsec):
    nm = f[nsec_off+i*40:nsec_off+i*40+8].rstrip(b'\0').decode()
    vs, va, praw = struct.unpack_from('<III', f, nsec_off+i*40+8)
    print(f'  {nm:8s} va={va:08x} vsz={vs:08x} raw={praw:08x} va_end={va+vs:08x}')
BASE=0x140000000
def rd_raw(rva, n):
    for i in range(nsec):
        nm = f[nsec_off+i*40:nsec_off+i*40+8].rstrip(b'\0').decode()
        vs, vsize_dummy = None, None
        vsize, va, rawsize, praw = struct.unpack_from('<IIII', f, nsec_off+i*40+8)
        if va <= rva < va + max(vsize, rawsize):
            return nm, f[praw + rva - va: praw + rva - va + n]
    return None, b''
nm, data = rd_raw(0x33720E8, 64)
print('section for 0x33720E8:', nm)
for i in range(8):
    v = struct.unpack('<Q', data[i*8:i*8+8])[0]
    print(f'  slot[{i}] +0x{i*8:02x}: {v:016x}  imgrel={v-BASE:x}' if v > BASE else f'  slot[{i}] +0x{i*8:02x}: {v:016x}')
