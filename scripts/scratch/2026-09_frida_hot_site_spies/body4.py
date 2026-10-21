import sys, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
try:
    PID = int(sys.argv[1])
except (IndexError, ValueError):
    PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
d2 = s.create_script(open(r'C:\ns\deep2.js', encoding='utf-8').read()); d2.load()
ex = d2.exports_sync
for name, rva, n in [('db_lookup_b6b3e0', 'b6b3e0', 60), ('db_ctor_c338520?', None, 0)]:
    if rva is None: continue
    print(f'\n== {name} ==')
    out = ex.disasm(rva, n)
    print('\n'.join(out if isinstance(out, list) else [str(out)]))
s.detach()
