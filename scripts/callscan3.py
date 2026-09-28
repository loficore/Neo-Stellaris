import sys, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
f = open(r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe', 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
opt_off = mz + 24
nsec_off = opt_off + struct.unpack_from('<H', f, mz+20)[0]
nsec_cnt = struct.unpack_from('<H', f, mz+6)[0]
secs = []
for i in range(nsec_cnt):
    nm = f[nsec_off+i*40:nsec_off+i*40+8].rstrip(b'\0').decode()
    va, vs, praw = struct.unpack_from('<III', f, nsec_off+i*40+12)
    secs.append((nm, va, vs, praw))
for target in (0xD15270, 0x34AC9E0, 0x34AB6C0):
    tot = []
    for nm, va, vs, praw in secs:
        buf = f[praw:praw+vs]
        for m in re.finditer(b'\xe8', buf):
            i = m.start()
            rel = struct.unpack_from('<i', buf, i+1)[0]
            insn = va + i
            if ((insn + 5 + rel) & 0xffffffffffffffff) == target:
                tot.append((nm, hex(insn)))
        # rip-rel lea (48 8d .. rel32)
        for m in re.finditer(rb'\x48\x8d[\x00-\xff]', buf):
            i = m.start()
            op = buf[i+1]
            if (op & 0xc7) == 0x05:
                rel = struct.unpack_from('<i', buf, i+2)[0]
                insn = va + i
                if ((insn + 6 + rel) & 0xffffffffffffffff) == target:
                    tot.append((nm, 'lea ' + hex(insn)))
    print(hex(target), '->', len(tot), tot[:20])
