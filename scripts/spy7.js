// spy7.js — read scope type descriptors + effect object identity at hot sites
var LOG = [];
var SEEN = {};
var CNT = {};
function push(s) { LOG.push(s); if (LOG.length > 20000) LOG = LOG.slice(-15000); }
function imgBase() { return Process.findModuleByName('stellaris.exe').base; }
function rel(a) { try { return a.sub(imgBase()).toString(16); } catch (e) { return '' + a; } }
function asciiAt(p, len) { try { var s = p.readCString(len); if (s && /^[\x20-\x7e]{2,}$/.test(s)) return s; } catch (e) {} return null; }
function wstrAt(o, off) {
    try {
        var p = o.add(off);
        var sz = Number(p.add(0x10).readU64());
        var cap = Number(p.add(0x18).readU64());
        if (sz === 0 || sz > 64) return null;
        var data = cap >= 0x10 ? p.readPointer() : p;
        var out = [];
        for (var i = 0; i < sz; i++) out.push(String.fromCharCode(data.add(i * 2).readU16()));
        var s = out.join('');
        return /^[ -~]{1,}$/.test(s) ? s : null;
    } catch (e) { return null; }
}
function describeScope(o) {
    var vt = o.readPointer();
    var rec = { scope_vt_rel: rel(vt) };
    // try COL→TD name
    try {
        var col = vt.sub(8).readPointer();
        var tdRva = col.add(0x10).readU32();
        var nm = asciiAt(imgBase().add(tdRva).add(0x10), 96);
        if (nm) rec.scope_class = nm;
    } catch (e) {}
    // scan first 0x60 bytes for embedded names / type id
    for (var off = 0x8; off <= 0x58; off += 8) {
        var w = wstrAt(o, off); if (w) rec['w' + off.toString(16)] = w;
        var a = asciiAt(o.add(off), 24); if (a) rec['c' + off.toString(16)] = a;
        try { var pv = o.add(off).readPointer(); var pa = asciiAt(pv, 24); if (pa) rec['p' + off.toString(16)] = pa; } catch (e) {}
    }
    return rec;
}
function describeEffect(o) {
    var vt = o.readPointer();
    var rec = { eff_vt_rel: rel(vt) };
    try {
        var col = vt.sub(8).readPointer();
        var tdRva = col.add(0x10).readU32();
        var nm = asciiAt(imgBase().add(tdRva).add(0x10), 96);
        if (nm) rec.eff_class = nm;
    } catch (e) {}
    var offs = [0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x100, 0x120, 0x140, 0x160, 0x180, 0x200, 0x280, 0x288, 0x290];
    for (var i = 0; i < offs.length; i++) {
        var w = wstrAt(o, offs[i]); if (w) rec['w' + offs[i].toString(16)] = w;
        try { var pv = o.add(offs[i]).readPointer(); var a = asciiAt(pv, 32); if (a) rec['p' + offs[i].toString(16)] = a; } catch (e) {}
        var a2 = asciiAt(o.add(offs[i]), 24); if (a2) rec['c' + offs[i].toString(16)] = a2;
    }
    return rec;
}
function arm(name, rvaHex, thisIdx, scopeIdx) {
    CNT[name] = 0;
    Interceptor.attach(imgBase().add(ptr('0x' + rvaHex)), {
        onEnter: function (args) {
            CNT[name]++;
            try {
                var eff = args[thisIdx], scope = args[scopeIdx];
                var vt = eff.readPointer();
                var key = name + '|' + vt;
                var n = SEEN[key] || 0;
                SEEN[key] = n + 1;
                if (n < 2) {
                    var rec = { f: name, n: CNT[name], sflag: n };
                    try { rec.scope = describeScope(scope); } catch (e) { rec.scope_err = '' + e; }
                    try { rec.eff = describeEffect(eff); } catch (e) { rec.eff_err = '' + e; }
                    push(JSON.stringify(rec));
                }
            } catch (e) {}
        }
    });
    return 'armed ' + name;
}
rpc.exports = {
    run: function () {
        var o = [];
        o.push(arm('exec_1D08520', '1D08520', 0, 1));
        o.push(arm('wrap_535070', '535070', 0, 1));
        return o.join('\n');
    },
    drain: function () { var r = LOG.join('\n'); LOG = []; return r; },
    counts: function () { return JSON.stringify(CNT); }
};
