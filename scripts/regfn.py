import sys, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
try:
    PID = int(sys.argv[1])
except (IndexError, ValueError):
    PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
d2 = s.create_script(open(r'C:\ns\deep2.js', encoding='utf-8').read()); d2.load()
out = d2.exports_sync
print('== register fn D150A0 (60 ins) ==')
print('\n'.join(out.disasm('d150a0', 60)))
print('\n== caller site D15308 context ==')
print('\n'.join(out.disasm('d152c0', 20)))
s.detach()
