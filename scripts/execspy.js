// execspy.js — drives the log-only base-Execute detour inside stellaris.exe.
// All engine access goes through the DLL's own recorder; this script only calls exports.

var DLL_NAME = 'stellaris_quickjs.dll';
// ExecHookLayout writes five u32s; never hand it a smaller buffer than it fills.
var LAYOUT_BYTES = 32;

// Frida 17 dropped the static Module.findExportByName; resolve through the module.
function exp(name) {
    var m = Process.findModuleByName(DLL_NAME);
    if (m === null) throw new Error(DLL_NAME + ' is not loaded');
    var a = m.findExportByName(name);
    if (a === null) throw new Error('export not found: ' + name + ' (have: ' +
        m.enumerateExports().map(function (e) { return e.name; }).join(',') + ')');
    return a;
}

var fn = {};
function f(name, ret, args) {
    if (fn[name] === undefined) fn[name] = new NativeFunction(exp(name), ret, args);
    return fn[name];
}

function num(v) { return (v && v.toNumber) ? v.toNumber() : Number(v); }

function k32(name) {
    return Process.getModuleByName('kernel32.dll').findExportByName(name);
}

rpc.exports = {
    // The game keeps one copy of the DLL mapped, so a rebuilt DLL only takes effect
    // after unload + load. Safe because the detour is uninstalled and nothing else in
    // the process references our module.
    load: function (path) {
        var fn = new NativeFunction(k32('LoadLibraryW'), 'pointer', ['pointer']);
        var buf = Memory.allocUtf16String(path);
        var h = fn(buf);
        return h.isNull() ? 'null' : h.toString();
    },

    unload: function () {
        var m = Process.findModuleByName(DLL_NAME);
        if (m === null) return 'not loaded';
        var fn = new NativeFunction(k32('FreeLibrary'), 'int32', ['pointer']);
        return String(fn(m.base));
    },

    // Independent quiescence probe: attach a counting Interceptor for `ms`, then detach.
    // Tells us (a) the address really is the hot path and (b) whether the simulation is
    // paused right now — which our own counter cannot report before the first install.
    spy: function (rvaHex, ms) {
        var addr = Process.findModuleByName('stellaris.exe').base.add(rvaHex);
        var n = 0;
        var listener = Interceptor.attach(addr, { onEnter: function () { n++; } });
        return new Promise(function (resolve) {
            setTimeout(function () {
                listener.detach();
                resolve(JSON.stringify({ addr: addr.toString(), calls: n }));
            }, ms);
        });
    },

    // Raw engine bytes at an RVA — the only way to tell a leftover JMP patch from a
    // relocated build. Needs no DLL, so it works even when install refuses.
    peek: function (rvaHex, n) {
        var addr = Process.findModuleByName('stellaris.exe').base.add(rvaHex);
        // Frida 17 removed the static Memory.read* helpers; read through the pointer.
        var bytes = new Uint8Array(addr.readByteArray(n));
        var s = '';
        for (var i = 0; i < bytes.length; i++) {
            s += ('0' + bytes[i].toString(16)).slice(-2) + (i % 16 === 15 ? '\n' : ' ');
        }
        return JSON.stringify({ addr: addr.toString(), hex: s });
    },

    // Emergency restore: write the engine's own 16 prologue bytes back over a leftover JMP
    // patch. Only the position-independent prefix is ever written, and the caller must have
    // proven the address quiescent first.
    unpatch: function (rvaHex, hexBytes) {
        var addr = Process.findModuleByName('stellaris.exe').base.add(rvaHex);
        var raw = [];
        for (var i = 0; i < hexBytes.length; i += 2) raw.push(parseInt(hexBytes.substr(i, 2), 16));
        // patchCode is Frida's write-to-executable-memory path; it flips page protection.
        Memory.patchCode(addr, raw.length, function (code) {
            code.writeByteArray(Uint8Array.from(raw));
        });
        return JSON.stringify({ wrote: raw.length, at: addr.toString() });
    },

    loaded: function () {
        var m = Process.findModuleByName(DLL_NAME);
        return JSON.stringify({ loaded: m !== null, base: m ? m.base.toString() : null });
    },

    layout: function () {
        var buf = Memory.alloc(LAYOUT_BYTES);
        f('ExecHookLayout', 'uint32', ['pointer'])(buf);
        return JSON.stringify({
            entry: buf.readU32(),
            hist: buf.add(4).readU32(),
            stats: buf.add(8).readU32(),
            ring: buf.add(12).readU32(),
            hist_len: buf.add(16).readU32(),
        });
    },

    install: function () { return String(f('ExecHookInstall', 'int32', [])()); },
    uninstall: function () { return String(f('ExecHookUninstall', 'int32', [])()); },
    reset: function () { f('ExecHookReset', 'void', [])(); return 'ok'; },

    // Direct proof the engine's own bytes are back at the target (call after uninstall).
    verify: function () { return String(f('ExecHookVerify', 'int32', [])()); },

    stats: function () {
        var buf = Memory.alloc(48);
        f('ExecHookStats', 'int32', ['pointer'])(buf);
        var names = ['calls', 'samples', 'invalid', 'hist_overflow', 'img_base', 'patch_size'];
        var out = {};
        for (var i = 0; i < 6; i++) out[names[i]] = buf.add(i * 8).readU64().toString();
        return JSON.stringify(out);
    },

    drain: function (max) {
        var lay = Memory.alloc(LAYOUT_BYTES);
        f('ExecHookLayout', 'uint32', ['pointer'])(lay);
        var esz = lay.readU32();
        var buf = Memory.alloc(esz * max);
        var n = f('ExecHookDrain', 'uint32', ['pointer', 'uint32'])(buf, max);
        var recs = [];
        for (var i = 0; i < n; i++) {
            var p = buf.add(i * esz);
            recs.push({
                valid: p.readU8(),
                vtable_rva: '0x' + p.add(4).readU32().toString(16),
                shim_rva: '0x' + p.add(8).readU32().toString(16),
                token_id: p.add(12).readU32(),
                second_token: p.add(16).readU32(),
                flag_12: p.add(20).readU32(),
                flag_14: p.add(24).readU32(),
                flag_16: p.add(28).readU32(),
                arg_token: p.add(32).readU32(),
                ctx_counter: p.add(36).readS32(),
                self_ptr: p.add(48).readPointer().toString(),
                ctx_ptr: p.add(56).readPointer().toString(),
                ctx_10: p.add(64).readU64().toString(),
                ctx_18: p.add(72).readU64().toString(),
                ctx_30: p.add(80).readU64().toString(),
            });
        }
        return JSON.stringify({ n: n, entry_size: esz, records: recs });
    },

    hist: function (max) {
        var lay = Memory.alloc(LAYOUT_BYTES);
        f('ExecHookLayout', 'uint32', ['pointer'])(lay);
        var hsz = lay.add(4).readU32();
        // The DLL's table is fixed-size; asking for more slots than it has is a caller bug.
        var want = Math.min(max, lay.add(16).readU32());
        var buf = Memory.alloc(hsz * want);
        var n = f('ExecHookHistogram', 'uint32', ['pointer', 'uint32'])(buf, want);
        var rows = [];
        for (var i = 0; i < n; i++) {
            var p = buf.add(i * hsz);
            rows.push({
                shim_rva: '0x' + p.readU32().toString(16),
                vtable_rva: '0x' + p.add(4).readU32().toString(16),
                count: p.add(8).readU64().toString(),
            });
        }
        rows.sort(function (a, b) { return Number(b.count) - Number(a.count); });
        return JSON.stringify({ n: n, rows: rows });
    },
};
