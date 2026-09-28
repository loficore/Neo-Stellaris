// body.js — disassemble a whole function range for calling-convention analysis
rpc.exports = {
    body: function (rvaHex, startOff, count) {
        const base = Process.findModuleByName('stellaris.exe').base;
        const addr = base.add(rvaHex).add(startOff);
        const lines = [];
        let off = startOff;
        const end = startOff + count;
        while (off < end) {
            try {
                const ins = Instruction.parse(base.add(rvaHex).add(off));
                lines.push('+' + off.toString(16) + ': ' + ins.toString());
                off += ins.size;
                if (ins.id === 0x5a /*ret*/ && off > startOff + 32) { /* keep going a bit */ }
            } catch (e) {
                lines.push('+' + off + ': <parse fail>');
                break;
            }
        }
        return JSON.stringify(lines);
    }
};
