import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
f = open(r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe', 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz+6)[0]
opt_off = mz + 24
nsec_off = opt_off + struct.unpack_from('<H', f, mz+20)[0]
secs = []
for i in range(nsec):
    va, vs, praw = struct.unpack_from('<III', f, nsec_off+i*40+12)
    secs.append((va, vs, praw))
def rd(rva, n):
    for va, vs, praw in secs:
        if va <= rva < va + vs: return f[praw + rva - va: praw + rva - va + n]
    raise KeyError(hex(rva))
def dump(rva, label, cnt=12):
    print(f'== {label} @ {rva:x} ==')
    for i in range(cnt):
        v = struct.unpack('<Q', rd(rva + i*8, 8))[0]
        print(f'  [{i}] 0x{v:x}')
dump(0x24B1988, 'vtable family start (slot0=1B5360?)', 8)
dump(0x24F9900, 'region around switch xref 24F9940', 12)
dump(0x247AC00, 'region with 535070 cluster', 40)
