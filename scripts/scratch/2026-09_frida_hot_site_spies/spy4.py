import sys, frida, time, json
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
try:
    PID = int(sys.argv[1])
except (IndexError, ValueError):
    PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
sc = s.create_script(open(r'C:\ns\spy4.js', encoding='utf-8').read()); sc.load()
ex = sc.exports_sync
print(ex.arm('1d08520', 'slot3', 0))
print(ex.arm('535070', 'slot5', 0))
print(ex.arm('5350d0', 'dispatch', 1))  # rcx=rbx=out?, rdx=rdi=template obj? probe idx 1 too
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 60
t = 0
while t < DUR:
    time.sleep(30); t += 30
    print(f'--- t={t}s ---', flush=True)
    print(ex.drain()[:2000])
print('=== VTABLE TABLE ===')
tbl=[json.loads(l) for l in ex.table().splitlines() if l.strip()]
tbl.sort(key=lambda r:-r['count'])
for r in tbl: print(f"{r['count']:>9}  {r['vt']}  imgrel {int(r['vt'],16)-0x7ff74a630000:x}  {r['rtti']['name']} ({r['rtti']['enc']})")
s.detach()
