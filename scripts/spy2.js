// spy2.js — long-horizon ABI-correct spy on the 4.4.4 scripted lookups.
// Decodes (rcx=out sret, edx=id, r8=name-wrapper[+0x10 wstring key]).
// Records one line per call; drain via rpc to avoid huge RPC returns.
var LOG = [];
var NAMES = {};
var CAP = 4000;

function rdWStr(addr) {
    // MSVC std::wstring at addr: buf/ptr at +0x00, size at +0x10, cap at +0x18
    try {
        const size = addr.add(0x10).readU64().toNumber();
        const cap = addr.add(0x18).readU64().toNumber();
        if (size < 0 || size > 256) return '<size' + size + '>';
        const dataPtr = (cap < 0x10) ? addr : addr.readPointer();
        if (dataPtr.isNull()) return '';
        return dataPtr.readUtf16String(size);
    } catch (e) { return '<err ' + e.message + '>'; }
}

rpc.exports = {
    arm: function (rvaHex, label) {
        const base = Process.findModuleByName('stellaris.exe').base;
        const addr = base.add(rvaHex);
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.out = args[0]; this.id = args[1]; this.wrap = args[2];
                // name key is the std::wstring at wrapper+0x10
                this.name = rdWStr(this.wrap.add(0x10));
            },
            onLeave: function (retval) {
                let ov = '<err>', oi = '<err>';
                try {
                    ov = this.out.readPointer().toString();
                    oi = this.out.add(8).readS32();
                } catch (e) {}
                const rec = { f: label, id: this.id.toNumber(), name: this.name,
                    out_vtbl: ov, out_id: oi };
                LOG.push(JSON.stringify(rec));
                if (LOG.length > CAP) LOG = LOG.slice(-CAP);
                NAMES[label] = (NAMES[label] || 0) + 1;
            }
        });
        return 'armed ' + label + ' @ ' + addr;
    },
    drain: function () { const r = LOG.join('\n'); LOG = []; return r; },
    stats: function () { return JSON.stringify(NAMES); },
    count: function () { return LOG.length; }
};
