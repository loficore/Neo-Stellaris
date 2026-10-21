import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
f = open(r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe', 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz+6)[0]
opt_off = mz + 24
nsec_off = opt_off + struct.unpack_from('<H', f, mz+20)[0]
secs = []
for i in range(nsec):
    nm = f[nsec_off+i*40:nsec_off+i*40+8].rstrip(b'\0').decode()
    va, vs, praw = struct.unpack_from('<III', f, nsec_off+i*40+12)
    secs.append((nm, va, vs, praw))
def off2sec(o):
    for nm, va, vs, praw in secs:
        if praw <= o < praw + vs: return f'{nm}+{va + (o - praw):x}'
    return '?'
# 1. verify layout at 0x24B1990
def r2off(rva):
    for nm, va, vs, praw in secs:
        if va <= rva < va + vs: return praw + (rva - va)
o = r2off(0x24B1990)
print('file off of 0x24B1990 =', hex(o), '->', f[o:o+8].hex(), '| at -8:', f[o-8:o].hex(), '| at -16:', f[o-16:o-8].hex())
print('sec@o:', off2sec(o), ' sec@o-8:', off2sec(o-8))
# 2. scan .rdata/.data for qword == 0x140535070 and 0x535070 (RVA-encoded)
targets = {0x140535070: 'abs 0x535070', 0x535070: 'rva 0x535070', 0x1405350D0: 'abs switch', 0x5350D0: 'rva switch'}
hits = {}
for nm, va, vs, praw in secs:
    if nm not in ('.rdata', '.data'): continue
    buf = f[praw:praw+vs]
    for i in range(0, len(buf)-8, 8):
        v = struct.unpack_from('<Q', buf, i)[0]
        if v in targets:
            hits.setdefault(targets[v], []).append(f'{nm}:{va+i:x}')
for k, v in hits.items():
    print(k, '->', v[:20])
