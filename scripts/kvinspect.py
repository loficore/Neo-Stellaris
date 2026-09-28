import sys, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
js = r'''
function B() { return Process.findModuleByName('stellaris.exe').base; }
function R(h) { return ptr('0x' + h); }
function ascii(p, n) { try { var b = new Uint8Array(p.readByteArray(n || 48)); var o = ''; for (var i = 0; i < b.length; i++) o += (b[i] >= 32 && b[i] < 127) ? String.fromCharCode(b[i]) : (b[i] === 0 ? '|' : '.'); return o; } catch (e) { return 'ERR'; } }
function qwords(p, n) { var o = []; for (var i = 0; i < n; i++) { try { o.push((i*8).toString(16) + ':' + p.add(i*8).readPointer()); } catch (e) { o.push('ERR'); } } return o; }
rpc.exports = {
    base: function () { return '' + B(); },
    globals: function () {
        var out = [];
        var list = [['kw_array', '33799c0'], ['kw_count', '33799c8'], ['token_desc_glob', '3260fd8'],
                    ['tmpl_db', '325eba0'], ['exec_vtbl_glob', '33720e8'], ['guard_flag', '337a844'],
                    ['guard_flag2', '325d750'], ['effect_db', '33746e8'], ['trigger_db', '32611c8']];
        list.forEach(function (g) {
            var a = B().add(R(g[1]));
            try { out.push(g[0] + ' @' + g[1] + ' = ' + a.readPointer() + '  rel ' + a.readPointer().sub(B())); } catch (e) { out.push(g[0] + ' ERR'); }
        });
        return out.join('\n');
    },
    kwtable: function (n) {
        var g = B().add(R('33799c0'));
        var arr = g.readPointer();
        var cnt = g.add(8).readPointer();
        var out = ['array=' + arr + ' rel=' + arr.sub(B()) + '  count=' + cnt];
        for (var i = 0; i < (n || 6); i++) {
            var e = arr.add(i * 0x18);
            out.push('entry[' + i + '] @' + e + ': ' + qwords(e, 3).join(' '));
            var p = e.readPointer();
            out.push('   deref0: ' + ascii(p, 48) + '  | ptrs ' + qwords(p, 4).join(' '));
        }
        return out.join('\n');
    },
    vtbl: function (rva, n) {
        var v = B().add(R(rva));
        var out = ['vtable ' + rva + ' = ' + v];
        out = out.concat(qwords(v, n || 10).map(function (x) { return '  ' + x; }));
        return out.join('\n');
    }
};
'''
sc = s.create_script(js); sc.load()
ex = sc.exports_sync
print('base =', ex.base())
print(ex.globals())
print('\n== keyword array head ==')
print(ex.kwtable(8))
print('\n== vtable at 33720E8 (value) ==')
print(ex.vtbl('33720e8', 12))
s.detach()
