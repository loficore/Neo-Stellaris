// spy5.js — identity probes where RTTI is absent:
//  (A) dispatch 0x5350D0: this=args[1]; sample wstring/chars at this+0x288 etc.
//  (B) slot3 0x1D08520: args[0]=self?, args[1]=effect obj → vt histogram of args[1]
var LOG = [];
var SEEN = {};
function push(s) { LOG.push(s); if (LOG.length > 20000) LOG = LOG.slice(-15000); }
function imgBase() { return Process.findModuleByName('stellaris.exe').base; }
function wstrAt(o, off, max) {
    try {
        var p = o.add(off);
        var size = p.add(0x10).readU32 ? 0 : 0;
        var sz = Number(p.add(0x10).readU64());
        var cap = Number(p.add(0x18).readU64());
        var data = p.readPointer ? p.readPointer() : p;
        if (sz === 0 || sz > 512) return null;
        var bytes;
        if (cap >= 0x10) { try { bytes = p.readPointer(); } catch (e) { return null; } }
        else bytes = p;
        var out = [];
        for (var i = 0; i < sz; i++) { var c = bytes.add(i * 2).readU16(); if (c > 0 && c < 128) out.push(String.fromCharCode(c)); }
        var s = out.join('');
        return /^[ -~]{1,}$/.test(s) ? s : null;
    } catch (e) { return null; }
}
function cstrAt(o, off) {
    try {
        var p = o.add(off).readPointer ? null : null;
        var q = o.add(off);
        var first = q.readU8();
        if (first >= 0x20 && first <= 0x7e) return q.readCString(48);
        var ptrv = q.readPointer();
        return ptrv.readCString(48);
    } catch (e) { return null; }
}
rpc.exports = {
    armDispatch: function () {
        var addr = imgBase().add(0x5350D0);
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var o = args[1];
                var vt = o.readPointer ? o.readPointer() : ptr(0);
                var key = 'D|' + vt;
                var n = SEEN[key] || 0;
                SEEN[key] = n + 1;
                if (n < 3) {
                    var rec = { f: 'dispatch', obj: o.toString(), vt: vt.toString(), typecode: args[2].toString() };
                    var offs = [0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x288, 0x290, 0x298];
                    for (var i = 0; i < offs.length; i++) {
                        var w = wstrAt(o, offs[i]);
                        if (w) rec['w' + offs[i].toString(16)] = w;
                        var c = cstrAt(o, offs[i]);
                        if (c) rec['c' + offs[i].toString(16)] = c;
                    }
                    push(JSON.stringify(rec));
                }
            }
        });
        return 'armed dispatch @ ' + addr;
    },
    armSlot3: function () {
        var addr = imgBase().add(0x1D08520);
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var a0 = args[0], a1 = args[1];
                var v0 = a0.readPointer(), v1;
                try { v1 = a1.readPointer(); } catch (e) { v1 = ptr(0); }
                var key = 'S|' + v1;
                var n = SEEN[key] || 0;
                SEEN[key] = n + 1;
                if (n < 2) push(JSON.stringify({ f: 'slot3', a0: a0.toString(), a0vt: v0.toString(), a1: a1.toString(), a1vt: v1.toString() }));
            }
        });
        return 'armed slot3 @ ' + addr;
    },
    drain: function () { var r = LOG.join('\n'); LOG = []; return r; },
    hist: function () {
        var out = [];
        for (var k in SEEN) out.push(k + ' ' + SEEN[k]);
        return out.join('\n');
    }
};
