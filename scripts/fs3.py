import sys, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
try:
    PID = int(sys.argv[1])
except (IndexError, ValueError):
    PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
d2 = s.create_script(open(r'C:\ns\deep2.js', encoding='utf-8').read()); d2.load()
d = s.create_script(open(r'C:\ns\deep.js', encoding='utf-8').read()); d.load()
ex2 = d.exports_sync
for r in ['d150a0', '14a80']:
    try: print('callersOf', r, '->', ex2.callersOf(r))
    except Exception as e: print(r, 'ERR', e)
out = ex2 if False else d2.exports_sync
print('\n== func 14a80 head ==')
print('\n'.join(out.disasm('14a80', 30)))
s.detach()
