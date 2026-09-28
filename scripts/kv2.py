import sys, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
js = r'''
function B() { return Process.findModuleByName('stellaris.exe').base; }
function R(h) { return ptr('0x' + h); }
function relstr(p) { try { var r = p.sub(B()); return p + ' (rel ' + r + ')'; } catch (e) { return '' + p; } }
function ascii(p, n) { try { var b = new Uint8Array(p.readByteArray(n || 40)); var o = ''; for (var i = 0; i < b.length; i++) o += (b[i] >= 32 && b[i] < 127) ? String.fromCharCode(b[i]) : (b[i] === 0 ? '|' : '.'); return o; } catch (e) { return 'ERR'; } }
rpc.exports = {
    raw: function (rva, n) {
        var p = B().add(R(rva));
        var out = ['raw @' + rva];
        for (var i = 0; i < n; i++) {
            try { var v = p.add(i*8).readPointer(); out.push('  +' + (i*8).toString(16) + ' = ' + v + '  rel=' + v.sub(B())); } catch (e) { out.push('  +' + (i*8).toString(16) + ' ERR'); }
        }
        return out.join('\n');
    },
    heap: function (absHex, n, label) {
        var p = ptr(absHex);
        var out = [label + ' @' + p];
        for (var i = 0; i < n; i++) {
            try {
                var v = p.add(i*8).readPointer();
                var a = ascii(v, 32);
                out.push('  +' + (i*8).toString(16) + ' = ' + v + '  rel=' + (v.compare(B()) >= 0 && v.sub(B()).toNumber() < 0x3a00000 ? v.sub(B()) : '-') + (a !== 'ERR' && a.indexOf('|') > 1 ? '  "' + a + '"' : ''));
            } catch (e) { out.push('  +' + (i*8).toString(16) + ' ERR'); }
        }
        return out.join('\n');
    },
    vt: function (rva, n) {
        var p = B().add(R(rva));
        var out = ['vtable rel ' + rva];
        for (var i = 0; i < n; i++) { try { out.push('  [' + i + '] = ' + p.add(i*8).readPointer().sub(B())); } catch (e) { out.push('  ERR'); } }
        return out.join('\n');
    },
    str: function (rva, n) { return ascii(B().add(R(rva)), n || 48); }
};
'''
sc = s.create_script(js); sc.load()
ex = sc.exports_sync
print(ex.raw('33799c0', 10))
arr = ex.raw('33799c0', 10).splitlines()[1].split('=')[1].split()[0]
print('\n== keyword array heap dump ==')
print(ex.heap(arr, 40, 'kwarr'))
for v in ['26d04c8', 'f152f0', '2532758', '2522c40']:
    print('\n' + ex.vt(v, 8))
s.detach()
