import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
f = open(r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe', 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz+6)[0]
opt_off = mz + 24
nsec_off = opt_off + struct.unpack_from('<H', f, mz+20)[0]
secs = [struct.unpack_from('<III', f, nsec_off+i*40+12) for i in range(nsec)]
def r2off(rva):
    for va, vs, praw in secs:
        if va <= rva < va + vs: return praw + (rva - va)
    raise KeyError(hex(rva))
def rd(rva, n): return f[r2off(rva):r2off(rva)+n]
def name_of_vt(vtrva):
    col = struct.unpack('<Q', rd(vtrva-8, 8))[0] - 0x140000000
    td = struct.unpack('<I', rd(col+0x10, 4))[0]
    return rd(td+0x10, 96).split(b'\0')[0].decode('utf-8','replace')
for v in (0x24B1990, 0x24B46E0, 0x24B9E80):
    print(f'{v:x}: {name_of_vt(v)}')
