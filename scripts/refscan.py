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
def rd(rva, n):
    for nm, va, vs, praw in secs:
        if va <= rva < va + vs: return f[praw + rva - va: praw + rva - va + n]
    return None
def cstr(rva, n=96):
    d = rd(rva, n)
    if not d: return None
    return d.split(b'\0')[0].decode('latin1', 'replace')
# 1. static string reads
for name, rva in [('scope_exec_desc_26E4F70', 0x26E4F70), ('scope_exec_desc_26E4FA8', 0x26E4FA8),
                  ('scope_desc_body_26E4F80', 0x26E4F80), ('exec_impl_src_24F8F70', 0x24F8F70),
                  ('trigger_key_24F8FB8', 0x24F8FB8), ('switch_vt_24F9900', None)]:
    if rva is None: continue
    d = rd(rva, 48)
    hexs = d.hex() if d else 'OOB'
    print(f'{name} @ {rva:x}: {hexs} | ascii: {cstr(rva)}')
# 2. code xrefs (RIP-rel lea/cmp and E8 rel32) to key data RVAs
text = [s for s in secs if s[0] == '.text'][0]
tv, tvs, tp = text[1], text[2], text[3]
tb = f[tp:tp+tvs]
def find_refs(target_rva, label):
    hits = []
    for i in range(0, len(tb) - 7, 1):
        b = tb[i]
        if b == 0xE8:
            rel = struct.unpack_from('<i', tb, i+1)[0]
            insn_rva = tv + i
            if ((insn_rva + 5 + rel) & 0xffffffffffffffff) == target_rva:
                hits.append(('call', hex(insn_rva)))
        elif b == 0x0F and i+8 <= len(tb) and 0x80 <= tb[i+1] <= 0x8F:
            rel = struct.unpack_from('<i', tb, i+4)[0]
            insn_rva = tv + i
            if ((insn_rva + 6 + rel) & 0xffffffffffffffff) == target_rva:
                hits.append(('lea/cmp', hex(insn_rva)))
        if len(hits) >= 12: break
    print(f'{label} ({target_rva:x}): {len(hits)} refs: {hits[:12]}')
for t, l in [(0x26E4F70, 'exec_desc_A'), (0x26E4FA8, 'exec_desc_B'), (0x24F8F70, 'src_string'), (0x24F8FB8, 'trig_string')]:
    find_refs(t, l)
