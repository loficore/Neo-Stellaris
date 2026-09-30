/*
  Linear disassembly through Frida's bundled Capstone — the IDA-less path.

  Read-only: it never writes memory and never attaches an Interceptor, so it is safe against
  a live, unpaused game. The value is in what each line's rip-relative operand resolves to:
  every shipped MSVC x64 body addresses static data only through [rip+d], so a decoded
  `lea rcx, [rip+d]` inside 0xCCCEB0/0xD150A0 hands us the global it registers into, and a
  `mov rax, [rip+d]` hands us the pointer table. Those globals are what the 0x110-byte
  keyword entry layout has to be read out of.
*/
'use strict';

function mod() {
    const m = Process.findModuleByName('stellaris.exe');
    if (!m) throw new Error('stellaris.exe not mapped');
    return m;
}

function rvaOf(addr) {
    return '0x' + addr.sub(mod().base).toString(16);
}

function cstringAt(addr, max) {
    // Printable-ASCII probe; returns null on the first unprintable byte.
    try {
        const bytes = addr.readByteArray(max || 64);
        const u = new Uint8Array(bytes);
        let s = '';
        for (let i = 0; i < u.length; i++) {
            if (u[i] === 0) break;
            if (u[i] < 0x20 || u[i] > 0x7e) return null;
            s += String.fromCharCode(u[i]);
        }
        return s.length >= 3 ? s : null;
    } catch (e) {
        return null;
    }
}

function targetNote(insn) {
    // Only operands that look like an address are worth resolving; Capstone prints the
    // displacement already, so recompute the effective address from the next instruction.
    const ops = insn.opStr;
    const m = /\[rip\s*\+\s*(0x[0-9a-f]+)\]/i.exec(ops) || /\[rip\s*-\s*(0x[0-9a-f]+)\]/i.exec(ops);
    if (!m) return ops;
    const sign = ops.indexOf('rip -') >= 0 || /\[rip\s*-/.test(ops) ? -1 : 1;
    const ea = insn.address.add(insn.size).add(sign * parseInt(m[1], 16));
    let extra = '  ; ' + rvaOf(ea);
    const s = cstringAt(ea, 48);
    if (s) extra += ' "' + s + '"';
    else {
        try { extra += ' q=' + ea.readPointer(); } catch (e) { /* unreadable */ }
    }
    return ops.replace(/\[rip\s*[-+]\s*0x[0-9a-f]+\]/i, '[' + rvaOf(ea) + ']') + extra;
}

rpc.exports = {
    // dis(0xCCCEB0, 200) -> { lines: ["+0x00  push rbp  ...", ...], bad: n }
    dis: function (rva, count) {
        const start = mod().base.add(rva);
        let p = start;
        const lines = [];
        let bad = 0;
        for (let i = 0; i < count; i++) {
            let insn;
            try {
                insn = Instruction.parse(p);
            } catch (e) {
                lines.push('+' + '0x' + (p.sub(start)).toString(16).padStart(4, '0') +
                    '  db ' + p.readU8().toString(16).padStart(2, '0') + '  ; decode failed');
                p = p.add(1);
                bad++;
                continue;
            }
            const off = '+' + '0x' + p.sub(start).toString(16).padStart(4, '0');
            const hex = Array.from(insn.bytes)
                .map(b => b.toString(16).padStart(2, '0')).join(' ');
            lines.push(off.padEnd(9) + hex.padEnd(20) + insn.mnemonic + ' ' + targetNote(insn));
            p = p.add(insn.size);
            if (insn.mnemonic === 'ret' && i > count * 0.6) break;
        }
        return JSON.stringify({ from: '0x' + rva.toString(16), lines: lines, bad: bad });
    },

    // A live pointer chain read: walk a list of offsets from a base RVA holding a pointer.
    readchain: function (rva, offsets) {
        let p = mod().base.add(rva).readPointer();
        const trace = ['[0x' + rva.toString(16) + '] = ' + p];
        for (const o of offsets) {
            try {
                p = p.add(o).readPointer();
                trace.push('  +' + o + ' -> ' + p);
            } catch (e) {
                trace.push('  +' + o + ' -> UNREADABLE');
                break;
            }
        }
        return JSON.stringify({ ptr: p.toString(), trace: trace });
    }
};
