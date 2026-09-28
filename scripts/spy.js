// spy.js — log args/retval of a function; drain via rpc
var LOG = [];
var NAMES = {};
rpc.exports = {
    arm: function (rvaHex, label) {
        const base = Process.findModuleByName('stellaris.exe').base;
        const addr = base.add(rvaHex);
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.a0 = args[0]; this.a1 = args[1]; this.a2 = args[2];
            },
            onLeave: function (retval) {
                try {
                    const r8 = this.a2;
                    let name = '<err>';
                    try {
                        const cap = r8.add(0x18).readU64();
                        const dataPtr = (cap < 0x10) ? r8 : r8.readPointer();
                        name = dataPtr.readUtf16String();
                    } catch (e) { name = '<unreadable>'; }
                    LOG.push(JSON.stringify({
                        f: label, a0: this.a0.toString(), a1: this.a1.toString(),
                        a2: r8.toString(), name: name,
                        ret_vtbl: this.a0.readPointer().toString(),
                        ret_id: this.a0.add(8).readS32()
                    }));
                    NAMES[label] = (NAMES[label] || 0) + 1;
                } catch (e) { LOG.push('ERR ' + e.message); }
            }
        });
        return 'armed ' + label + ' @ ' + addr;
    },
    drain: function () { const r = LOG.join('\n'); LOG = []; return r; },
    stats: function () { return JSON.stringify(NAMES); }
};
