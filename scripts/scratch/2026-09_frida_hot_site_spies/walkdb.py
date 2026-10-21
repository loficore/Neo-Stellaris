import sys, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
try:
    PID = int(sys.argv[1])
except (IndexError, ValueError):
    PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
sc = s.create_script(open(r'C:\ns\walkdb.js', encoding='utf-8').read()); sc.load()
ex = sc.exports_sync
print(ex.dump('325eba0', 0x18, 0x20))
s.detach()
