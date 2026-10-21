rpc.exports = {
  probe: function () {
    var b = Process.findModuleByName('stellaris.exe').base;
    var out = { base: b.toString(), abs: [], imgrel: [] };
    var vt = b.add(0x33720E8);
    for (var i = 0; i < 8; i++) {
      var v;
      try { v = vt.add(i * 8).readPointer(); } catch (e) { v = null; }
      out.abs.push(v === null ? 'AV' : v.toString());
      out.imgrel.push(v === null ? 'AV' : '0x' + v.sub(b).toString(16));
    }
    out.slot1_is_base_execute = (out.imgrel[1] === '0x1d08520');
    return JSON.stringify(out);
  }
};
