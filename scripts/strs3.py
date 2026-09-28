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
print('== registry_init_18d500 ==')
out = ex.disasm('18d500', 40)
print('\n'.join(out if isinstance(out, list) else [str(out)]))
for rva in ['24909c0', '24909e8', '24909f8', '2490a10', '2490a20', '2512660', '24d0448', '247a4f0']:
    print(rva, '->', repr(ex.strAt(rva, 48)))
# registry global at 33799c0: dump header + first entries via ptrAt
print('\n== registry_global_33799c0 ==')
for off in ['0', '8', '10', '18', '20', '28']:
    print('+' + off, '->', ex.ptrAt('33799c0', int('0x' + off, 16)))
s.detach()
