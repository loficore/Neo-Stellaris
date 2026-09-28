import sys, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
f = open(r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe', 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
opt_off = mz + 24
nsec_off = opt_off + struct.unpack_from('<H', f, mz+20)[0]
va, vs, praw = struct.unpack_from('<III', f, nsec_off+12)
tb = f[praw:praw+vs]
TEXT_END = va + vs
for TARGET in (0xD15230, 0xD15270):
    hits = []
    for m in re.finditer(b'\xe8', tb):
        i = m.start()
        rel = struct.unpack_from('<i', tb, i+1)[0]
        insn = va + i
        if ((insn + 5 + rel) & 0xffffffffffffffff) == TARGET:
            hits.append(hex(insn))
    print(hex(TARGET), 'callers:', len(hits), hits[:15])
