// spy6.js — backtrace + keyword-string identity probes
var LOG = [];
var CNT = {};
var BTDONE = {};
function push(s) { LOG.push(s); if (LOG.length > 20000) LOG = LOG.slice(-15000); }
function imgBase() { return Process.findModuleByName('stellaris.exe').base; }
function cstr(o, off) { try { var p = o.add(off).readPointer ? null : null; var s = o.add(off).readCString(64); if (s && /^[ -~]{2,}$/.test(s)) return s; } catch (e) {} try { var q = o.add(off).readPointer(); var s2 = q.readCString(64); if (s2 && /^[ -~]{2,}$/.test(s2)) return s2; } catch (e) {} return null; }
function rel(a) { try { return a.sub(imgBase()).toString(16); } catch (e) { return '' + a; } }
function arm(label, rvaHex, opts) {
    var addr = imgBase().add(ptr('0x' + rvaHex));
    Interceptor.attach(addr, {
        onEnter: function (args) {
            CNT[label] = (CNT[label] || 0) + 1;
            if (CNT[label] > (opts.sampleMax || 9e15)) return;
            var doBt = !BTDONE[label] && (opts.bt || 0) > 0 && CNT[label] <= (opts.bt || 0);
            if (!doBt && !(opts.str)) return;
            if (doBt) BTDONE[label] = CNT[label];
            var rec = { f: label, n: CNT[label] };
            try {
                (opts.str || []).forEach(function (spec) {
                    try {
                        var o = args[spec.i];
                        if (!o.isNull()) {
                            var s = cstr(o, spec.off);
                            if (s) rec['s' + spec.i + '_' + spec.off.toString(16)] = s;
                            rec['vt' + spec.i] = rel(o.readPointer());
                            if (spec.typeOff !== undefined) rec['t' + spec.i] = args[spec.i].add(spec.typeOff).readU32 ? '' : '';
                        }
                    } catch (e) {}
                });
                if (opts.argRaw) opts.argRaw.forEach(function (i) { rec['a' + i] = args[i].toString(); });
            } catch (e) { rec.err = '' + e; }
            if (doBt) { try { rec.bt = Thread.backtrace(this.context, Backtracer.ACCURATE).map(rel).join(' '); } catch (e) { rec.bt = 'NA'; } }
            push(JSON.stringify(rec));
        }
    });
    return 'armed ' + label + ' @ ' + addr;
}
rpc.exports = {
    run: function () {
        var out = [];
        out.push(arm('switch_5350D0', '5350D0', { bt: 5, sampleMax: 40, str: [{ i: 1, off: 0x288 }], argRaw: [0, 1, 2] }));
        out.push(arm('wrap_535070', '535070', { bt: 5, sampleMax: 40, str: [{ i: 0, off: 0x288 }, { i: 1, off: 0x288 }], argRaw: [0, 1, 2] }));
        out.push(arm('slot3_1D08520', '1D08520', { bt: 3, sampleMax: 30, str: [{ i: 0, off: 0x288 }, { i: 1, off: 0x288 }], argRaw: [0, 1] }));
        out.push(arm('B0_1B5360', '1B5360', { bt: 3, sampleMax: 30, str: [{ i: 0, off: 0x288 }], argRaw: [0, 1] }));

        out.push(arm('B2_22FB40', '22FB40', { bt: 3, sampleMax: 30, str: [{ i: 0, off: 0x288 }, { i: 1, off: 0x288 }], argRaw: [0, 1] }));
        out.push(arm('inner_7E5280', '7E5280', { bt: 3, sampleMax: 20, str: [{ i: 1, off: 0x288 }], argRaw: [0, 1, 2] }));
        return out.join('\n');
    },
    drain: function () { var r = LOG.join('\n'); LOG = []; return r; },
    counts: function () { return JSON.stringify(CNT); }
};
