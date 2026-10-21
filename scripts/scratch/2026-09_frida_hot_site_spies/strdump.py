import sys, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
DEV = frida.get_local_device()
try:
    PID = int(sys.argv[1])
except (IndexError, ValueError):
    PID = [pr.pid for pr in DEV.enumerate_processes() if pr.name.lower() == 'stellaris.exe'][0]
s = DEV.attach(PID)
js = r'''
function imgBase() { return Process.findModuleByName('stellaris.exe').base; }
function bytesAt(absPtr, n) {
    var b = new Uint8Array(absPtr.readByteArray(n));
    var ascii = '';
    for (var i = 0; i < b.length; i++) ascii += (b[i] >= 32 && b[i] < 127) ? String.fromCharCode(b[i]) : (b[i] === 0 ? '\0' : '.');
    return ascii;
}
rpc.exports = {
    at: function (absHex, n) { return bytesAt(ptr(absHex), n || 64); },
    rel: function (rvaHex, n) { return bytesAt(imgBase().add(ptr('0x' + rvaHex)), n || 64); },
    ptr: function (absHex, off) { return '' + ptr(absHex).add(off || 0).readPointer(); },
    derefrel: function (rvaHex, off, depth) {
        var p = imgBase().add(ptr('0x' + rvaHex)).add(off || 0).readPointer();
        return '' + p;
    }
};
'''
sc = s.create_script(js); sc.load()
ex = sc.exports_sync
# keyword table global: [g] = array ptr (heap 0x23e08a70)
g = ex.rel('33799c0', 16)
print('global area bytes:', repr(g))
arr = None
# find heap array pointer: first 8 bytes as hex little-endian via python-side parse
import struct
# use ex.ptr on absolute global address
BASE = 0x7ff74a630000
grva = 0x33799c0
abs_g = hex(BASE + grva)
p = ex.ptr(abs_g, 0)
print('[global] =', p)
print('entry[0]:', repr(ex.at(p, 256)))
print('entry[1]:', repr(ex.at(ptr_add := hex(int(p,16)+0x18), 64) if False else ex.at(hex(int(p,16)+0x18), 64)))
# token descriptors at [r8+0x10]
q = ex.at('0x7ff74b345230', 64)
print('\nbytes@D15230:', q)
# string pool sample around 2490000
for r in ['2490000', '2490400', '2490800', '2490890', '24908d8', '24908e0', '2490908', '2490928']:
    print(r, '->', repr(ex.rel(r, 48)))
s.detach()
