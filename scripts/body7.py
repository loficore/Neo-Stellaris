import sys, frida, json, time
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
try:
    PID = int(sys.argv[1])
except (IndexError, ValueError):
    PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
js = r'''
rpc.exports = {
    dis: function (rvaHex, n) {
        var addr = Process.findModuleByName('stellaris.exe').base.add(ptr('0x' + rvaHex));
        var out = [];
        var a = addr;
        for (var i = 0; i < n; i++) {
            try { out.push(a.sub(Process.findModuleByName('stellaris.exe').base).toString(16) + ': ' + Instruction.toString(a)); }
            catch (e) { out.push(a + ': ERR ' + e); break; }
            a = a.add(out[out.length - 1].indexOf('ERR') >= 0 ? 1 : Instruction.parse(a).size);
        }
        return out.join('\n');
    },
    readg: function (rvaHex) {
        var g = Process.findModuleByName('stellaris.exe').base.add(ptr('0x' + rvaHex));
        var out = [];
        for (var off = 0; off < 0x30; off += 8) {
            try { out.push('+' + off.toString(16) + ' = ' + g.add(off).readPointer()); } catch (e) { out.push('+' + off.toString(16) + ' ERR'); }
        }
        // also deref [g] if pointer, dump first 0x40
        try {
            var p = g.readPointer();
            for (var i = 0; i < 8; i++) out.push('  [' + i + ' @ ' + p + '+0x' + (i*8).toString(16) + '] = ' + p.add(i*8).readPointer());
        } catch (e) { out.push('deref ERR ' + e); }
        return out.join('\n');
    }
};
'''
sc = s.create_script(js); sc.load()
ex = sc.exports_sync
print('== d15270 =='); print(ex.dis('d15270', 40))
print('\n== global 33799c0 =='); print(ex.readg('33799c0'))
s.detach()
