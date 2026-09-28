import sys, time, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
PID = int(sys.argv[1])
SECS = int(sys.argv[2]) if len(sys.argv)>2 else 20
TARGETS = [('effect', 0x89F960), ('trigger', 0x8A0450)]
js = open(r'C:\ns\spy.js', encoding='utf-8').read()
sess = frida.get_local_device().attach(PID)
sc = sess.create_script(js); errs=[]
sc.on('message', lambda m,d: errs.append(m))
sc.load()
for lbl, rva in TARGETS:
    print(sc.exports_sync.arm(hex(rva), lbl))
print(f'listening {SECS}s...')
t0=time.time()
while time.time()-t0 < SECS:
    time.sleep(5)
    out = sc.exports_sync.drain()
    if out: print(out[:6000])
print('stats:', sc.exports_sync.stats())
for e in errs[:10]: print('MSG', str(e)[:300])
sess.detach()
