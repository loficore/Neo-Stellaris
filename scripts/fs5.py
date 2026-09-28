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
out = d2.exports_sync; ex2 = d.exports_sync
fs = out.funcStart('266d3d')
print('caller function start =', fs)
print('\n'.join(out.disasm(fs, 25)))
print('\ncallersOf', fs, '->', ex2.callersOf(fs))
print('\nstring 2545cd0 =', repr(out.strAt('2545cd0', 64)))
s.detach()
