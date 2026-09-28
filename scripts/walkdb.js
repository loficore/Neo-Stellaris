// walkdb.js — dump global at RVA 0x325EBA0 and BST-walk node strings
function imgBase() { return Process.findModuleByName('stellaris.exe').base; }
function cstr(p, n) { try { var s = p.readCString(n || 64); if (s && /^[\x20-\x7e]{2,}$/.test(s)) return s; } catch (e) {} return null; }
rpc.exports = {
    dump: function (rvaHex, wordOff, nodeOff) {
        var b = imgBase();
        var g = b.add(ptr('0x' + rvaHex));
        var out = ['global ' + rvaHex + ':'];
        for (var off = -0x20; off <= 0x60; off += 8) {
            var v = g.add(off).readPointer();
            var s = cstr(v, 48) || cstr(g.add(off), 48);
            out.push('  +' + off.toString(16) + ' = ' + v + (s ? '  "' + s + '"' : ''));
        }
        // BST walk: assume root at [g + wordOff], node: key string data at [node + nodeOff] (wstring SSO/heap)
        var root = g.add(wordOff).readPointer();
        var found = [];
        function wstrInfo(p) {
            try {
                var sz = Number(p.add(0x10).readU64());
                var cap = Number(p.add(0x18).readU64());
                if (sz > 64 || (cap === 0 && sz > 0)) return null;
                var data = cap >= 0x10 ? p.readPointer() : p;
                var bytes = [];
                for (var i = 0; i < sz; i++) bytes.push(String.fromCharCode(data.add(i * 2).readU16()));
                var s = bytes.join('');
                return { size: sz, cap: Number(cap), str: /^[ -~]{1,}$/.test(s) ? s : '(nonascii)' };
            } catch (e) { return null; }
        }
        function walk(node, depth) {
            if (!node || node.isNull() || depth > 14 || found.length >= 25) return;
            var left, right;
            try { left = node.readPointer(); right = node.add(8).readPointer(); } catch (e) { return; }
            var payload = node.add(wordOff);
            var w = wstrInfo(payload);
            var c = cstr(payload, 32);
            found.push({ depth: depth, key: w ? w.str + ' sz' + w.size + ' cap' + w.cap : (c || ('? ' + payload.readPointer())) });
            walk(left, depth + 1); walk(right, depth + 1);
        }
        out.push('root([' + rvaHex + '+' + wordOff.toString(16) + ']) = ' + root);
        walk(root, 0);
        out.push('nodes: ' + JSON.stringify(found));
        return out.join('\n');
    }
};
