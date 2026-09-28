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
for r in ['d15270', 'd15230', 'd15000']:
    print(r, '-> funcStart', ex.funcStart(r))
d = s.create_script(open(r'C:\ns\deep.js', encoding='utf-8').read()); d.load()
ex2 = d.exports_sync
try:
    print('callersOf d15270:', ex2.callersOf('d15270'))
except Exception as e:
    print('callersOf err', e)
s.detach()
