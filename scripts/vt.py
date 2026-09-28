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
base = 0x24B1990
for i in range(8):
    r = ex.ptr_at(hex(base + 8 * i))
    print(f'slot[{i}] @ {hex(base+8*i)} -> rva {r}')
    try:
        lines = ex.disasm(r, 8)
        print('   ', ' | '.join(lines[:6]))
    except Exception as e:
        print('    disasm err', e)
s.detach()
