"""Dump the live bytes at an RVA of stellaris.exe (default: base Execute) and compare them
with the fingerprint gate in src/dll/scripted/exec_hook.zig. No DLL needed.

usage: python peekexec.py [rva_hex] [nbytes]
"""
import json
import sys

import frida

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

JS = r'C:\ns\execspy.js'
RVA = int(sys.argv[1] if len(sys.argv) > 1 else '1D08520', 16)
N = int(sys.argv[2]) if len(sys.argv) > 2 else 48

# exec_hook.zig EXPECTED_CODE, first 32 bytes.
EXPECTED = [
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20,
    0x8B, 0x42, 0x08, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF9, 0x85,
    0xC0, 0x78, 0x32, 0xBA, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8B,
    0xCB, 0xE8,
]

dev = frida.get_local_device()
procs = [p for p in dev.enumerate_processes() if p.name.lower() == 'stellaris.exe']
if not procs:
    sys.exit('stellaris.exe is not running')
pid = procs[0].pid

sess = dev.attach(pid)
script = sess.create_script(open(JS, encoding='utf-8').read())
script.on('message', lambda m, d: print('MSG:', json.dumps(m)[:300]))
script.load()
api = script.exports_sync

live = json.loads(api.peek(RVA, N))
b = bytes(int(x, 16) for x in live['hex'].split())
print(f"pid={pid}  module base={live['addr']}  rva=0x{RVA:x}  {N} bytes")
print('live:  ' + ' '.join(f'{x:02X}' for x in b))
print('gate:  ' + ' '.join(f'{x:02X}' for x in EXPECTED))
mismatch = [i for i, (g, l) in enumerate(zip(EXPECTED, b)) if g != l]
print(f'first mismatch at +{mismatch[0]:#x}' if mismatch else 'fingerprint matches')
if b[:6] == bytes([0xFF, 0x25, 0, 0, 0, 0]):
    import struct
    tgt = struct.unpack_from('<Q', b, 6)[0]
    print(f'>>> JMP [rip+0] to absolute 0x{tgt:x} — a detour patch is STILL in place')
sess.detach()
