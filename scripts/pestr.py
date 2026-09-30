"""Read bytes / C-strings at RVAs in stellaris.exe. usage: pestr.py rva [len]..."""
import sys, os, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
_cands = [os.environ.get('NS_STELLARIS_EXE'),
          '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe']
EXE = next((c for c in _cands if c and os.path.exists(c)), None)
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
nsec = struct.unpack_from('<H', f, mz + 6)[0]
secs = []
for i in range(nsec):
    o = no + i * 40
    nm = f[o:o+8].split(b'\0')[0].decode('latin1')
    vs, va, rsz, rp = struct.unpack_from('<IIII', f, o + 8)
    secs.append((nm, va, vs, rsz, rp))
def rd(rva, n):
    for nm, va, vs, rsz, rp in secs:
        if va <= rva < va + max(vs, rsz):
            off = rp + rva - va
            return f[off:off+n]
    return b''
def cstr(rva, cap=256):
    b = rd(rva, cap)
    return b.split(b'\0')[0].decode('utf-8', 'replace')
if __name__ == '__main__':
    for a in sys.argv[1:]:
        rva, _, n = a.partition('#')
        rva = int(rva, 16)
        print(f'0x{rva:x}: ' + (rd(rva, int(n, 0)).hex(' ') if n else repr(cstr(rva))))
