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
for name, rva, n in [('generic_exec_7e69b0', '7e69b0', 70), ('hashfn_18d6b0', '18d6b0', 30), ('exec_thunk_b6b350', 'b6b350', 20)]:
    print(f'\n== {name} ==')
    out = ex.disasm(rva, n)
    print('\n'.join(out if isinstance(out, list) else [str(out)]))
s.detach()
