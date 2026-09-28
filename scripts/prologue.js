// prologue.js — dump + decode function prologues for detour feasibility check
rpc.exports = {
    base: function () {
        return Process.findModuleByName('stellaris.exe').base.toString();
    },
    prologue: function (rvaHex, count) {
        const base = Process.findModuleByName('stellaris.exe').base;
        const addr = base.add(rvaHex);
        const hex = Array.from(new Uint8Array(addr.readByteArray(count))).map(b => b.toString(16)).join(' ');
        const lines = [];
        let off = 0;
        let ripRel = false;
        while (off < count) {
            try {
                const ins = Instruction.parse(addr.add(off));
                const txt = ins.toString();
                // rip-relative instructions starting before byte 14 land inside the patch
                if (txt.indexOf('[rip') !== -1 && off < 14) ripRel = true;
                lines.push(txt);
                off += ins.size;
            } catch (e) {
                lines.push('<parse fail at ' + off + '>');
                break;
            }
        }
        return JSON.stringify({ addr: addr.toString(), hex: hex, insns: lines, hasRipRel: ripRel });
    }
};
