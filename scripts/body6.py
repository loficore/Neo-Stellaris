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
for name, rva, n in [('register_fn_d15270', 'd15270', 45)]:
    print(f'\n== {name} ==')
    out = ex.disasm(rva, n)
    print('\n'.join(out if isinstance(out, list) else [str(out)]))
print('\n== registry_global_33799C0 dump ==')
for off in range(0, 0x48, 8):
    try: print(f'+{off:#x}', ex.ptrAt('33799c0', off))
    except Exception as e: print(f'+{off:#x} ERR', e)
s.detach()
