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
for lbl, rva in [('hash_site', '2533860'), ('generic_exec', 'b3719b0'), ('db_lookup_real', 'b6b3e0')]:
    try:
        r = ex.funcStart(rva)
        print(lbl, rva, '-> funcStart', r)
    except Exception as e:
        print(lbl, 'ERR', e)
s.detach()
