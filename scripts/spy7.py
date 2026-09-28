import sys, frida, time
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
try:
    PID = int(sys.argv[1])
except (IndexError, ValueError):
    PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
sc = s.create_script(open(r'C:\ns\spy7.js', encoding='utf-8').read()); sc.load()
ex = sc.exports_sync
print(ex.run(), flush=True)
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 60
t = 0
while t < DUR:
    time.sleep(10); t += 10
    d = ex.drain()
    if d: print(f'--- t={t}s ---'); print(d[:6000], flush=True)
print('FINAL counts:', ex.counts())
s.detach()
