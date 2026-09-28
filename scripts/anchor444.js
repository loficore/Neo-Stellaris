'use strict';
const m = Process.getModuleByName('stellaris.exe');

function imageRanges() {
  return Process.enumerateRanges('r--').filter(r =>
    r.base.compare(m.base) >= 0 && r.base.compare(m.base.add(m.size)) < 0);
}

let EXEC_CACHE = null;
function execRanges() {
  if (EXEC_CACHE) return EXEC_CACHE;
  EXEC_CACHE = Process.enumerateRanges('r-x').filter(r =>
    r.base.compare(m.base) >= 0 && r.base.compare(m.base.add(m.size)) < 0);
  return EXEC_CACHE;
}

function inExec(addr) {
  for (const r of execRanges()) {
    if (addr.compare(r.base) >= 0 && addr.compare(r.base.add(r.size)) < 0) return true;
  }
  return false;
}

function R(x) { return typeof x === 'number' ? x : parseInt(x, 16); }

rpc.exports = {
  base: function () {
    return { base: m.base.toString(16), size: m.size };
  },

  // locate all occurrences of an ASCII string inside the image, return rel offsets
  findStr: function (needle) {
    const pat = Array.from(needle).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
    const out = [];
    for (const rng of imageRanges()) {
      try {
        for (const h of Memory.scanSync(rng.base, rng.size, pat)) {
          out.push(h.address.sub(m.base).toString(16));
        }
      } catch (e) {}
    }
    return out;
  },

  readAt: function (rel, n) {
    try { return m.base.add(R(rel)).readCString(n); } catch (e) { return null; }
  },

  // given any offset inside a NUL-terminated C string, return the string start + content
  cstrStart: function (rel) {
    rel = R(rel);
    const back = 512;
    let u8;
    try { u8 = new Uint8Array(m.base.add(R(rel) - back).readByteArray(back)); }
    catch (e) { return null; }
    let nul = back;
    for (let i = back - 1; i >= 0; i--) { if (u8[i] === 0) { nul = i + 1; break; } }
    const startRel = rel - back + nul;
    return { start: startRel.toString(16), str: m.base.add(startRel).readCString(512) };
  },

  // RIP-relative LEA refs (opcode 8D, modrm mod=00 reg=101) to a rel offset in the image
  ripRefs: function (targetRel) {
    const target = m.base.add(R(targetRel));
    const out = [];
    const page = 0x10000;
    for (const rng of imageRanges()) {
      const off0 = Number(rng.base.sub(m.base));
      const len0 = Math.min(rng.size, m.size - off0);
      for (let off = off0; off < off0 + len0; off += page) {
        const len = Math.min(page, off0 + len0 - off);
        const base = m.base.add(off);
        let bytes;
        try { bytes = base.readByteArray(len); } catch (e) { continue; }
        const u8 = new Uint8Array(bytes);
        const relDiff = Number(target) - Number(base);
        if (relDiff < -0x7ffffff0 || relDiff > 0x7ffffff0) continue;
        for (let i = 1; i + 6 <= len; i++) {
          if (u8[i] !== 0x8d) continue;
          const modrm = u8[i + 1];
          if ((modrm & 0xC7) !== 0x05) continue;
          const disp = (u8[i+2] | (u8[i+3] << 8) | (u8[i+4] << 16) | (u8[i+5] << 24)) | 0;
          if (disp === relDiff - (i + 6)) {
            const site = base.add(i - 1);
            if (inExec(site)) out.push(site.sub(m.base).toString(16));
          }
        }
      }
    }
    return out;
  },

  // 8-byte absolute pointer refs to a rel offset, within image data
  absRefs: function (targetRel) {
    let t = BigInt('0x' + m.base.add(R(targetRel)).toString(16));
    const bytes = [];
    for (let i = 0; i < 8; i++) { bytes.push(Number(t & 0xffn).toString(16).padStart(2, '0')); t >>= 8n; }
    const needle = bytes.join(' ');
    const out = [];
    for (const rng of imageRanges()) {
      try {
        for (const h of Memory.scanSync(rng.base, rng.size, needle)) {
          out.push(h.address.sub(m.base).toString(16));
        }
      } catch (e) {}
    }
    return out;
  },

  // walk backwards from a code offset to find MSVC function start (after int3 padding)
  funcStart: function (rel) {
    rel = R(rel);
    const back = Math.min(rel, 0x40000);
    let u8;
    try { u8 = new Uint8Array(m.base.add(R(rel) - back).readByteArray(back)); }
    catch (e) { return null; }
    let start = null;
    let i = 0;
    while (i < back) {
      if (u8[i] !== 0xcc) { i++; continue; }
      let j = i;
      while (j < back && u8[j] === 0xcc) j++;
      if (j - i >= 2 && j < back) start = j;
      i = j;
    }
    if (start === null) return null;
    return (rel - back + start).toString(16);
  },

  disasmAround: function (rel, n) {
    const results = [];
    try {
      let p = m.base.add(R(rel));
      for (let k = 0; k < n; k++) {
        const ins = Instruction.parse(p);
        results.push(p.sub(m.base).toString(16) + ': ' + ins.toString());
        p = ins.next;
      }
    } catch (e) { results.push('err ' + e.message); }
    return results;
  }
};
