import sys, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
try:
    PID = int(sys.argv[1])
except (IndexError, ValueError):
    PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
d1 = s.create_script(open(r'C:\ns\deep.js', encoding='utf-8').read()); d1.load()
d2 = s.create_script(open(r'C:\ns\deep2.js', encoding='utf-8').read()); d2.load()
c1, c2 = d1.exports_sync, d2.exports_sync
for name, rva in [('GetScriptedEffect','89f960'), ('GetScriptedTrigger','8a0450')]:
    print(f'\n== callers of {name} ==')
    for site in c1.callers_of(rva):
        print(f'  call@{site} funcStart={c2.func_start(str(site))}')
s.detach()
