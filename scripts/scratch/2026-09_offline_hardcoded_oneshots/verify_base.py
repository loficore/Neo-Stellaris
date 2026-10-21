import sys, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
f = open(r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe', 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
opt_off = mz + 24
pref = struct.unpack_from('<Q', f, opt_off+0x18)[0]
print('preferred base:', hex(pref))
nsec_off = opt_off + struct.unpack_from('<H', f, mz+20)[0]
va, vs, praw = struct.unpack_from('<III', f, nsec_off+12)
print('.text va=%x vs=%x praw=%x' % (va, vs, praw))
tb = f[praw:praw+vs]
# count rel32 calls whose absolute target lands in valid image range at preferred base
cnt = ok = 0
samples = []
for m in re.finditer(b'\xe8', tb):
    i = m.start(); cnt += 1
    rel = struct.unpack_from('<i', tb, i+1)[0]
    t = (va + i + 5 + rel)
    if 0 <= t < 0x3a00000:
        ok += 1
        if len(samples) < 8: samples.append((hex(va+i), hex(t)))
print('E8 occurrences:', cnt, 'plausible targets:', ok)
print(samples)
# locate the init bytes to find real runtime base from file offsets
needle = bytes.fromhex('4c8d05') # lea r8, rip
# instead: find the sequence 488d0d3af33103 (lea rcx, imgrel 34ac9e0 at D15200-ish)
pat = bytes.fromhex('488d0d3af33103')
j = tb.find(pat)
print('pattern lea rcx->34ac9e0 found at file idx:', hex(j) if j>=0 else None, '=> RVA', hex(va+j) if j>=0 else None)
