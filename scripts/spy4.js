// spy4.js — RTTI class-name histogram at hot vtable slots
var VT = {};
var LOG = [];
function imgBase() { return Process.findModuleByName('stellaris.exe').base; }
function looksLikeName(td) {
    try {
        var s = td.add(0x10).readCString(96);
        if (s && s.length > 2 && /^\??[A-Za-z_.]/.test(s)) return s;
    } catch (e) {}
    return null;
}
function tryRtti(vt) {
    var b = imgBase();
    try {
        var col = vt.sub(8).readPointer();
        // x64 MSVC: COL = {u32 vbOff, u32 offset, u32 cdOff, u32 tdRVA, u32 chdRVA}; TD = {u64, u64, name}
        var tdRva = col.add(0x10).readU32();
        var td = b.add(tdRva);
        var n = looksLikeName(td);
        if (n) return { name: n, enc: 'rva' };
        // fallback: absolute pointer form (VS2019+ can emit plain pointers)
        var tdp = col.add(0x10).readPointer();
        n = looksLikeName(tdp);
        if (n) return { name: n, enc: 'ptr' };
        n = looksLikeName(tdp.xor(b));
        if (n) return { name: n, enc: 'xor' };
    } catch (e) { return { name: 'ERR ' + e, enc: '?' }; }
    return { name: '?', enc: '?' };
}
rpc.exports = {
    arm: function (rvaHex, label, thisIdx) {
        var addr = imgBase().add(ptr('0x' + rvaHex));
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var rec = { f: label, a: rvaHex };
                try {
                    var th = args[thisIdx];
                    var vt = th.readPointer();
                    rec.this = th.toString(); rec.vt = vt.toString();
                    var key = vt.toString();
                    var v = VT[key];
                    if (!v) {
                        v = { count: 0, rtti: tryRtti(vt) };
                        VT[key] = v;
                        try { rec.stack = Thread.backtrace(this.context, Backtracer.ACCURATE).map(function (a) { return a.sub(imgBase()).toString(16); }).join(' '); } catch (e) { rec.stack = 'NA'; }
                        LOG.push('NEWVT ' + JSON.stringify(rec));
                    }
                    v.count++;
                } catch (e) { rec.err = '' + e; LOG.push(JSON.stringify(rec)); }
            }
        });
        return 'armed ' + label + ' @ ' + addr;
    },
    table: function () {
        var out = [];
        for (var k in VT) out.push(JSON.stringify({ vt: k, count: VT[k].count, rtti: VT[k].rtti }));
        return out.join('\n');
    },
    drain: function () { var r = LOG.join('\n'); LOG = []; return r; },
    reset: function () { VT = {}; LOG = []; return 'ok'; }
};
