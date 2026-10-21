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
cur = '265dd0'
for depth in range(5):
    cs = ex2.callersOf(cur)
    print(f'callers of {cur}:', cs[:8])
    if not cs: break
    nxt = out.funcStart(cs[0])
    print('  -> funcStart', nxt)
    if nxt == cur: break
    cur = nxt if nxt else cs[0]
s.detach()
