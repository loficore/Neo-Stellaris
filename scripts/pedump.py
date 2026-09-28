import sys, struct
EXE = r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe'
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz+6)[0]
opt_off = mz + 24
nsec_off = opt_off + struct.unpack_from('<H', f, mz+20)[0]
secs = []
for i in range(nsec):
    o = nsec_off + i*40
    nm = f[o:o+8].rstrip(b'\0').decode()
    va, vs, praw = struct.unpack_from('<III', f, o+12)
    secs.append((nm, va, vs, praw))
def r2off(rva):
    for nm, va, vs, praw in secs:
        if va <= rva < va + vs: return praw + (rva - va)
    raise KeyError(hex(rva))
print('sections:', [(n, hex(v), hex(s)) for n, v, s, p in secs])
dd_off = opt_off + 112
for i, nm in enumerate(['export','import','resource','exception','cert','basectrl','debug','arch','seceng','baserelo','dir','dir64','iacfg','delay','clr','rtti']):
    rva, sz = struct.unpack_from('<II', f, dd_off + i*8)
    if rva: print(f'DD[{i}] {nm}: rva={rva:x} size={sz:x}')
for target in (0x24B1990, 0x24B3050, 0x24B1C88):
    print(f'\n-- bytes at imgrel {target:x} +-32 --')
    o = r2off(target)
    for off in range(o-32, o+48, 8):
        print(f'  {off and struct.unpack("<Q", f[off:off+8])[0] or 0:016x}')
