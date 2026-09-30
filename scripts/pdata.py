"""x64 .pdata (RUNTIME_FUNCTION) table -> exact function bounds, no analysis needed.
usage: pdata.py [query_rva ...]   # no args: print count + widest functions
"""
import sys, struct, bisect, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
BASE = 0x140000000
secs = []
for i in range(struct.unpack_from('<H', f, mz + 6)[0]):
    o = no + i * 40
    nm = f[o:o + 8].split(b'\0')[0].decode('latin1')
    vs, va, rsz, rp = struct.unpack_from('<IIII', f, o + 8)
    secs.append((nm, va, rsz, rp))
pd = next(s for s in secs if s[0] == '.pdata')
n = (pd[2]) // 12
funcs = []
for i in range(n):
    b, e, u = struct.unpack_from('<III', f, pd[3] + i * 12)
    funcs.append((b, e, u))
funcs.sort()
STARTS = [x[0] for x in funcs]


def func_of(rva):
    """Return (start, end, unwind) of the function containing rva, or None."""
    i = bisect.bisect_right(STARTS, rva) - 1
    if i < 0:
        return None
    b, e, u = funcs[i]
    return (b, e, u) if rva < e else None


if __name__ == '__main__':
    if len(sys.argv) > 1:
        for a in sys.argv[1:]:
            rva = int(a, 16)
            fx = func_of(rva)
            print(f'0x{rva:x} -> ' + (f'func 0x{fx[0]:x}..0x{fx[1]:x} '
                  f'({fx[1] - fx[0]:#x} bytes) unwind 0x{fx[2]:x}'
                  if fx else 'NOT IN ANY FUNCTION'))
    else:
        print(f'{len(funcs)} functions in .pdata')
        for b, e, u in sorted(funcs, key=lambda x: x[1] - x[0], reverse=True)[:15]:
            print(f'  0x{b:07x}..0x{e:07x}  {e - b:>9#x}  unwind 0x{u:x}')
