"""Locate exact C-strings in stellaris.exe by name. usage: strfind.py kw [kw...]"""
import sys, os, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
EXE = os.environ.get('NS_STELLARIS_EXE', '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
BASE = 0x140000000
secs = []
for i in range(struct.unpack_from('<H', f, mz + 6)[0]):
    o = no + i * 40
    nm = f[o:o+8].split(b'\0')[0].decode('latin1')
    vs, va, rsz, rp = struct.unpack_from('<IIII', f, o + 8)
    ch = struct.unpack_from('<I', f, o + 36)[0]
    secs.append((nm, va, vs, rsz, rp, ch))

for name in sys.argv[1:]:
    pat = name.encode() + b'\0'
    got = []
    for nm, va, vs, rsz, rp, ch in secs:
        blob = f[rp:rp + rsz]
        i = 0
        while True:
            j = blob.find(pat, i)
            if j < 0:
                break
            # require a real string start: previous byte is NUL or non-ascii-printable
            prev = blob[j-1] if j else 0
            if prev == 0 or prev >= 0x80:
                got.append((nm, va + j))
            i = j + 1
    print(f'{name!r}: ' + (', '.join(f'{s} 0x{r:x}' for s, r in got) or 'NOT FOUND'))
