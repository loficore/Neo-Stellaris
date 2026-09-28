import sys, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
try:
    PID = int(sys.argv[1])
except (IndexError, ValueError):
    PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
js = r'''
rpc.exports = {
    bytes: function (rvaHex, n) {
        var addr = Process.findModuleByName('stellaris.exe').base.add(ptr('0x' + rvaHex));
        var b = new Uint8Array(addr.readByteArray(n));
        return Array.from(b).map(function (x) { return ('0' + x.toString(16)).slice(-2); }).join(' ');
    },
    disat: function (absHex) {
        var a = ptr(absHex);
        var out = [];
        try { out.push('0x' + a.toString(16) + ': ' + Instruction.toString(a)); } catch (e) { out.push('ERR ' + e); }
        return out.join('\n');
    },
    readg: function (rvaHex) {
        var b = Process.findModuleByName('stellaris.exe').base;
        var g = b.add(ptr('0x' + rvaHex));
        var out = [];
        for (var off = 0; off < 0x30; off += 8) {
            try { out.push('+' + off.toString(16) + ' = ' + g.add(off).readPointer()); } catch (e) { out.push('+' + off.toString(16) + ' ERR'); }
        }
        return out.join('\n');
    }
};
'''
sc = s.create_script(js); sc.load()
ex = sc.exports_sync
print('bytes@0x7ff74b345270:', ex.bytes('d15270', 64))
print('disat base+d15270:', ex.disat('0x7ff74b345270'))
print('\nglobal 33799c0:'); print(ex.readg('33799c0'))
s.detach()
