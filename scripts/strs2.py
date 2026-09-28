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
for rva in ['24e9068', '24b88e8', '26e4fa8', '26e4f70']:
    try:
        r = ex.strAt(rva, 64)
        print(rva, '->', repr(r))
    except Exception as e:
        print(rva, 'ERR', e)
print('\n== hashfn_2533860 ==')
out = ex.disasm('2533860', 25)
print('\n'.join(out if isinstance(out, list) else [str(out)]))
print('\n== generic_exec_target_b3719b0 head ==')
out = ex.disasm('b3719b0', 40)
print('\n'.join(out if isinstance(out, list) else [str(out)]))
s.detach()
