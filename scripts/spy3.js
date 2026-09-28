// spy3.js — attach by RVA with per-site arg readers, long-horizon
var LOG = [];
var NAMES = {};
function pushRec(rec) {
    LOG.push(JSON.stringify(rec));
    if (LOG.length > 6000) LOG = LOG.slice(-5000);
}
rpc.exports = {
    arm: function (rvaHex, label) {
        const addr = Process.findModuleByName('stellaris.exe').base.add(rvaHex);
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.t0 = Date.now();
                const rec = { f: label, this: args[0].toString(), a1: args[1].toString() };
                try { rec.scope_type = args[1].readPointer().toString(); } catch (e) {}
                try { rec.f2 = args[1].add(8).readS64().toString(); } catch (e) {}
                try { rec.f3 = args[1].add(16).readS64().toString(); } catch (e) {}
                this.rec = rec;
            },
            onLeave: function (retval) {
                this.rec.ret = retval.toString();
                this.rec.ms = Date.now() - this.t0;
                pushRec(this.rec);
                NAMES[this.rec.f] = (NAMES[this.rec.f] || 0) + 1;
            }
        });
        return 'armed ' + label + ' @ ' + addr;
    },
    drain: function () { const r = LOG.join('\n'); LOG = []; return r; },
    stats: function () { return JSON.stringify(NAMES); }
};
