import sys, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
f = open(r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe', 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz+6)[0]
opt_off = mz + 24
nsec_off = opt_off + struct.unpack_from('<H', f, mz+20)[0]
va, vs, praw = struct.unpack_from('<III', f, nsec_off+12)  # .text
tb = f[praw:praw+vs]
TARGET = 0xD15270
hits = []
for m in re.finditer(b'\xe8', tb):
    i = m.start()
    if i + 5 > len(tb): break
    rel = struct.unpack_from('<i', tb, i+1)[0]
    if (va + i + 5 + rel) == TARGET:
        hits.append(hex(va + i))
print('callers of 0x%X:' % TARGET, len(hits))
print(' '.join(hits[:60]))
