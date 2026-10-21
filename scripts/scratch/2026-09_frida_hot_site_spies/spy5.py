import sys, frida, time
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
try:
    PID = int(sys.argv[1])
except (IndexError, ValueError):
    PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
sc = s.create_script(open(r'C:\ns\spy5.js', encoding='utf-8').read()); sc.load()
ex = sc.exports_sync
print(ex.armDispatch())
print(ex.armSlot3())
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 120
t = 0
while t < DUR:
    time.sleep(10); t += 10
    d = ex.drain()
    if d: print(f'--- t={t}s ---'); print(d[:3000], flush=True)
print('=== HIST ===')
h = sorted([l.split(' ') for l in ex.hist().splitlines() if l], key=lambda r: -int(r[1]))
for k, c in h[:40]: print(c, k)
s.detach()
