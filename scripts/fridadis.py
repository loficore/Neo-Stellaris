"""Linear disassembly of a live stellaris.exe through Frida's bundled Capstone.

usage: python fridadis.py <rva> [instructions]      e.g. python fridadis.py 0xCCCEB0 120
       python fridadis.py --chain <rva> off,off,..   e.g. python fridadis.py --chain 0x33799C0 0x450,0x20

Read-only (no Interceptor, no Memory.patchCode), so it is safe against an unpaused game.
Exists because the IDA MCP is not always connected; rip-relative operands are annotated with
their resolved RVA and, when they land on printable bytes, the string itself.
For the same job from the file alone — no process, no game — use scripts/cap.py.
This used to be scripts/dis.py; that name shadowed stdlib `dis` for anything run from this
directory and broke capstone's import.
"""
import json
import sys

import frida

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

JS = r'C:\ns\dis.js'
args = [a for a in sys.argv[1:]]
if not args:
    sys.exit(__doc__)

dev = frida.get_local_device()
pid = next(p.pid for p in dev.enumerate_processes() if p.name.lower() == 'stellaris.exe')
sess = dev.attach(pid)
script = sess.create_script(open(JS, encoding='utf-8').read())
script.on('message', lambda m, d: print('MSG:', json.dumps(m)[:300]))
script.load()
api = script.exports_sync

if args[0] == '--chain':
    print(api.readchain(int(args[1], 16), [int(o, 0) for o in args[2].split(',')]))
else:
    rva = int(args[0], 16)
    count = int(args[1]) if len(args) > 1 else 80
    out = json.loads(api.dis(rva, count))
    print(f'# disassembled {len(out["lines"])} instructions from RVA {out["from"]}, '
          f'{out["bad"]} decode failures')
    for line in out['lines']:
        print(line)
sess.detach()
