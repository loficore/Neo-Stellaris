"""Restores the engine's own prologue at base Execute when a detour patch was left behind.

usage: python restoreexec.py [rva_hex]

Refuses unless an independent Frida Interceptor proves the address is silent, so the 16-byte
write can never land while a game thread is mid-function. The bytes written are the first 16
of exec_hook.zig's EXPECTED_CODE — position-independent, so they are build-correct under ASLR.
"""
import json
import sys

import frida

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

JS = r'C:\ns\execspy.js'
RVA = int(sys.argv[1] if len(sys.argv) > 1 else '1D08520', 16)
ORIGINAL_HEAD = '48895C2408574883EC208B4208488BDA'  # 16 bytes, exec_hook.zig EXPECTED_CODE[0..16]

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

n = json.loads(api.spy(RVA, 1500))
print(f"pid={pid} probe at 0x{n['addr']}: {n['calls']} calls in 1.5s")
if n['calls'] != 0:
    sys.exit('address is LIVE — pause the game and re-run; refusing to rewrite hot code')

before = bytes(int(x, 16) for x in json.loads(api.peek(RVA, 32))['hex'].split())
print('before: ' + ' '.join(f'{b:02X}' for b in before))
if before[:6] != bytes([0xFF, 0x25, 0, 0, 0, 0]):
    sys.exit('no JMP [rip+0] patch here — nothing to restore, leaving memory alone')

print('unpatch:', api.unpatch(RVA, ORIGINAL_HEAD))
after = bytes(int(x, 16) for x in json.loads(api.peek(RVA, 32))['hex'].split())
print('after:  ' + ' '.join(f'{b:02X}' for b in after))
expected = bytes.fromhex(ORIGINAL_HEAD)
print('RESTORED' if after[:16] == expected else 'STILL WRONG — do not resume the game')
sess.detach()
