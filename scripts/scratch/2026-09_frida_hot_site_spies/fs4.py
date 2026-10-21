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
out = d2.exports_sync
fs = out.funcStart('ccd09e')
print('init function start =', fs)
print('\n== head ==')
print('\n'.join(out.disasm(fs, 20)))
try: print('\ncallersOf', fs, '->', ex2.callersOf(fs))
except Exception as e: print('callers err', e)
s.detach()
