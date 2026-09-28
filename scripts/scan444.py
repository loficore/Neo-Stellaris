"""Re-anchor Stellaris 4.4.4 key functions via Frida.

For each source-path anchor string: locate the C-string start, scan for
RIP-relative LEA refs (within executable ranges) and absolute 8-byte pointer
refs, then resolve each ref site to its enclosing function start (int3-padding
boundary heuristic). Emits a per-anchor caller-function histogram.

usage: python scan444.py <pid> [js_path]
"""
import sys, json, frida

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PID = int(sys.argv[1])
JS_PATH = sys.argv[2] if len(sys.argv) > 2 else r'C:\ns\anchor444.js'

ANCHORS = [
    'effect_impl.cpp',
    'scriptedeffect.cpp',
    'scriptedtrigger.cpp',
    'eventcommands.cpp',
    'eventmanager.cpp',
    'game_singleobjectdatabase.h',
    'CScriptedEffectTemplateDatabase',
    'CScriptedTriggerTemplateDatabase',
]

js = open(JS_PATH, encoding='utf-8').read()
dev = frida.get_local_device()
sess = dev.attach(PID)
script = sess.create_script(js)
script.load()
ex = script.exports_sync

report = {'pid': PID, 'module': ex.base(), 'anchors': {}}

for name in ANCHORS:
    entry = {}
    tails = ex.find_str(name)
    starts = {}
    for t in tails:
        cs = ex.cstr_start(t)
        if cs and cs['str']:
            starts[cs['start']] = cs['str']
    entry['strings'] = [{'start': s, 'text': txt} for s, txt in sorted(starts.items())]
    for s in starts:
        rip = ex.rip_refs(s)
        absr = ex.abs_refs(s)
        funcs = {}
        for r in rip:
            fs = ex.func_start(r)
            funcs.setdefault(fs, []).append(r)
        # histogram: function-start -> #call-sites (a big dispatch fn has one
        # func-start key with many sites)
        hist = sorted(funcs.items(), key=lambda kv: -len(kv[1]))
        entry[s] = {
            'text': starts[s],
            'rip_count': len(rip),
            'abs_refs': absr,
            'top_funcs': [{'func': f, 'sites': len(v), 'first_site': v[0]} for f, v in hist[:8]],
            'num_funcs': len(funcs),
        }
    report['anchors'][name] = entry

# compact console summary
print('module', report['module'])
for name, entry in report['anchors'].items():
    print('\n===', name, '===')
    for s, item in entry.items():
        if s == 'strings':
            continue
        print(' str@', s, repr(item['text'][:60]))
        print('   rip_refs=%d abs_refs=%d distinct_funcs=%d' % (item['rip_count'], len(item['abs_refs']), item['num_funcs']))
        for tf in item['top_funcs']:
            print('     func=%-10s sites=%-4d first=%s' % (tf['func'], tf['sites'], tf['first_site']))

with open(r'C:\ns\anchor444.json', 'w') as f:
    json.dump(report, f, indent=1)
print('\nwrote C:\\ns\\anchor444.json')
sess.detach()
