import sys, time, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
PID = int(sys.argv[1])
SECS = int(sys.argv[2]) if len(sys.argv) > 2 else 300
js = open(r'C:\ns\spy2.js', encoding='utf-8').read()
sess = frida.get_local_device().attach(PID)
sc = sess.create_script(js); errs = []
sc.on('message', lambda m, d: errs.append(m))
sc.load()
print(sc.exports_sync.arm(hex(0x89F960), 'effect'), flush=True)
print(sc.exports_sync.arm(hex(0x8A0450), 'trigger'), flush=True)
t0 = time.time()
while time.time() - t0 < SECS:
    time.sleep(15)
    out = sc.exports_sync.drain()
    if out:
        print(f'--- t={int(time.time()-t0)}s ---', flush=True)
        print(out[:8000], flush=True)
print('FINAL stats:', sc.exports_sync.stats(), flush=True)
out = sc.exports_sync.drain()
if out: print(out[:8000], flush=True)
for e in errs[:5]: print('MSG', str(e)[:300], flush=True)
sess.detach()
