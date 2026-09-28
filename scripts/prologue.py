"""Dump + decode prologues of the 4.4.4 scripted-lookup functions.

usage: python prologue.py <pid> [js_path]
"""
import sys, json, frida

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PID = int(sys.argv[1])
JS_PATH = sys.argv[2] if len(sys.argv) > 2 else r'C:\ns\prologue.js'

RVAS = {
    'GetScriptedEffect':   0x89F960,
    'GetScriptedTrigger':  0x8A0450,
}

js = open(JS_PATH, encoding='utf-8').read()
dev = frida.get_local_device()
sess = dev.attach(PID)
script = sess.create_script(js)
errs = []
script.on('message', lambda m, d: errs.append(m))
script.load()
api = script.exports_sync

base = api.base()
print(f'base={base}')
for name, rva in RVAS.items():
    r = json.loads(api.prologue(hex(rva), 32))
    print(f'\n== {name} @ {r["addr"]} ==')
    print('bytes:', r['hex'])
    for line in r['insns']:
        print(' ', line)
    print('rip-relative within first 14 bytes:', r['hasRipRel'])
for e in errs:
    print('MSG:', json.dumps(e)[:500])
sess.detach()
