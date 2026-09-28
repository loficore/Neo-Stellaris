# Offline RTTI name resolution for vtables captured by spy4.
# Reads stellaris.exe directly; no game interaction.
import sys, struct, json
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
EXE = r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe'
PREF = 0x140000000  # will verify from optional header

f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
nsec = struct.unpack_from('<H', f, mz+6)[0]
opt_off = mz + 24
nsec_off = opt_off + struct.unpack_from('<H', f, mz+20)[0]
secs = []
for i in range(nsec):
    o = nsec_off + i*40
    va, vs, praw = struct.unpack_from('<III', f, o+12)
    secs.append((va, vs, praw))
def r2off(rva):
    for va, vs, praw in secs:
        if va <= rva < va + vs:
            return praw + (rva - va)
    raise KeyError(hex(rva))
def rd(rva, n): return f[r2off(rva):r2off(rva)+n]

RUNTIME_BASE = 0x7ff74a630000
vts = []
for line in open(r'C:\ns\spy4_table.txt', encoding='utf-8'):
    r = json.loads(line)
    vts.append((r['count'], int(r['vt'], 16) - RUNTIME_BASE))

out = {}
for cnt, rva in vts:
    try:
        col_ptr = struct.unpack('<Q', rd(rva - 8, 8))[0]  # absolute VA at preferred base
        col_rva = col_ptr - PREF if col_ptr >= PREF else col_ptr
        td_rva = struct.unpack('<I', rd(col_rva + 0x10, 4))[0]
        name = rd(td_rva + 0x10, 96).split(b'\0')[0].decode('utf-8', 'replace')
        out[f'{rva:x}'] = (cnt, name)
    except Exception as e:
        out[f'{rva:x}'] = (cnt, f'ERR {e}')
for k, (cnt, name) in sorted(out.items(), key=lambda kv: -kv[1][0]):
    print(f'{cnt:>9}  imgrel {k}  {name}')
