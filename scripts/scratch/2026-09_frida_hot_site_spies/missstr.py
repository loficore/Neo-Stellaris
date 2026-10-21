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
for r in ['2a02d68','24b46a8','24b46e0','24b9e80','24b9e40','325f5c8','325f5d0','325f5c1']:
    print(r, 'str:', repr(ex.str_at(r))[:100])
print('ptr@325f5c8:', ex.ptr_at('325f5c8'), ' ptr@325f5d0:', ex.ptr_at('325f5d0'))
print('bytes@2a02d68:', ex.hex_at('2a02d68', 48))
print('bytes@32611c8:', ex.hex_at('32611c8', 8), ' bytes@33746e8:', ex.hex_at('33746e8', 8))
s.detach()
