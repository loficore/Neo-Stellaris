import sys, json, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
pid = next(p.pid for p in DEV.enumerate_processes() if p.name.lower() == 'stellaris.exe')
print('pid', pid)
s = DEV.attach(pid)
d = s.create_script(open(r'C:\ns\vtlive.js', encoding='utf-8').read()); d.load()
print(json.dumps(json.loads(d.exports_sync.probe()), indent=1))
s.detach()
