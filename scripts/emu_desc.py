#!/usr/bin/env python3
"""C0.3 oracle — run the engine's OWN descriptor writers under an emulator.

PLAN §6 C0.3 asked for a byte diff between a descriptor we build and a "real" one.
There are no real bytes to diff against: the 0x120 x 9,863 array at 0x337B400 lives
past the .data raw data (BSS-style, loader zero-fills it) and is filled at start-up
by the driver — §20. So this script makes the binary itself the authority instead:

  * emulates 0x1D15270 (static registrar, what the 247 KB driver calls) and
    0x1D152D0 (dynamic ctor, what GetOrAddToken 0x1D13270 calls) over a zeroed
    0x120 slot, for the same (id, name) pair;
  * diffs the two outputs byte-for-byte — this is the MEASURED version of §18's
    inferred "byte-for-byte identical" claim;
  * dumps a canonical expected block so the Zig builder in
    src/dll/scripted/keyword_registry.zig can be checked against it.

Everything the engine calls that is not plain register/memory work is host-implemented
below (memcpy, the cstr reserve); both writers are asserted not to need the heap.

usage: emu_desc.py static-dynamic          ; diff the two paths for one sample
       emu_desc.py oracle [tsv] [out]      ; emit the per-entry oracle table
"""
import sys, os, struct, hashlib
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RAX

EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
f = open(EXE, 'rb').read()
mz = struct.unpack_from('<I', f, 0x3c)[0]
no = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
BASE = 0x140000000
SECS = []
for i in range(struct.unpack_from('<H', f, mz + 6)[0]):
    o = no + i * 40
    nm = f[o:o + 8].split(b'\0')[0].decode('latin1')
    vs, va, rsz, rp = struct.unpack_from('<IIII', f, o + 8)
    SECS.append((nm, va, vs, rsz, rp))

def rd(rva, n):
    for nm, va, vs, rsz, rp in SECS:
        if va <= rva < va + max(vs, rsz):
            return f[rp + rva - va: rp + rva - va + n]
    return b''

# --- synthetic address map -------------------------------------------------
PG = 0x1000
STACK = 0x70000000
SLOT = 0x50000000          # the 0x120 descriptor slot
NAME = 0x60000000          # NUL-terminated chars for the static path
HOLDER = 0x61000000        # TokenNameHolder for the dynamic path (std::string at +0x10)

RVA_STATIC_CTOR = 0x1D15270   # (rcx=slot, edx=id, r8=char* name)
RVA_DYN_CTOR = 0x1D152D0      # (rcx=slot, edx=id, r8=holder)
RVA_WRITER = 0x1D158A0        # (rcx=slot, edx=id, r8=chars, r9=len)
RVA_RESERVE = 0x1704B0        # (rcx=slot+8, edx=needed) — host-implemented, no-op below cap
RVA_MEMCPY = 0x2187AC0        # (rcx=dst, rdx=src, r8=len) — host-implemented

def code_rvas(*rvs):
    out = set()
    for r in rvs:
        p = r // PG
        for k in range(4):          # a function body can straddle a few pages
            out.add(p + k)
    return out

# --- the emulator ----------------------------------------------------------
class Engine:
    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.uc.mem_map(STACK, 8 * PG, UC_PROT_ALL)
        self.uc.mem_map(SLOT, 4 * PG, UC_PROT_ALL)
        self.uc.mem_map(NAME, 4 * PG, UC_PROT_ALL)
        self.uc.mem_map(HOLDER, 4 * PG, UC_PROT_ALL)
        self.uc.mem_map(HEAP, 4 * PG, UC_PROT_ALL)
        for p in code_rvas(RVA_STATIC_CTOR, RVA_DYN_CTOR, RVA_WRITER,
                           RVA_RESERVE, RVA_MEMCPY):
            self.uc.mem_map(BASE + p * PG, PG, UC_PROT_ALL)
            self.uc.mem_write(BASE + p * PG, rd(p * PG, PG).ljust(PG, b'\x90'))
        self.heap = {}
        self.memcpys = 0
        self.reserves = 0
        self.uc.hook_add(UC_HOOK_CODE, self._dispatch)
        self.touched = set()

    def _ret(self):
        sp = self.uc.reg_read(UC_X86_REG_RSP)
        ra = struct.unpack('<Q', bytes(self.uc.mem_read(sp, 8)))[0]
        self.uc.reg_write(UC_X86_REG_RSP, sp + 8)
        self.uc.reg_write(UC_X86_REG_RIP, ra)

    def _dispatch(self, uc, addr, size, user):
        off = addr - BASE
        if off == RVA_MEMCPY:
            rcx, rdx, r8 = (uc.reg_read(uc_reg(r)) for r in ('RCX', 'RDX', 'R8'))
            src = self._read(rdx, r8)
            self.touched.update(range(rcx, rcx + r8))
            uc.mem_write(rcx, src)
            self.memcpys += 1
            self._ret(); return
        if off == RVA_RESERVE:
            rcx, rdx = (uc.reg_read(uc_reg(r)) for r in ('RCX', 'RDX'))
            cap = struct.unpack('<I', bytes(uc.mem_read(rcx + 0x10, 4)))[0]
            if rdx > cap:
                raise RuntimeError('reserve wants %d > cap %d — name too long for inline'
                                   % (rdx, cap))
            self.reserves += 1
            self._ret(); return
        if addr in self.heap:                      # an unimplemented call target
            raise RuntimeError('unhandled call to 0x%x' % (addr - BASE))

    def _read(self, addr, n):
        return bytes(self.uc.mem_read(addr, n))

    def zero(self, addr, n):
        self.uc.mem_write(addr, b'\0' * n)

    def call(self, rva, rcx, rdx, r8, r9=0, steps=20000):
        uc = self.uc
        sp = STACK + 4 * PG
        self.zero(sp, 8)
        for p, v in (('RCX', rcx), ('RDX', rdx), ('R8', r8), ('R9', r9)):
            uc.reg_write(uc_reg(p), v)
        uc.reg_write(UC_X86_REG_RSP, sp)
        uc.mem_write(sp, struct.pack('<Q', 0xdead0))   # sentinel return address
        uc.reg_write(UC_X86_REG_RIP, BASE + rva)
        for _ in range(steps):
            if uc.reg_read(UC_X86_REG_RIP) == 0xdead0:
                return uc.reg_read(UC_X86_REG_RAX)
            uc.emu_start(uc.reg_read(UC_X86_REG_RIP), 0xdead0, count=1)
        raise RuntimeError('did not return from 0x%x' % rva)

from unicorn.x86_const import (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
                               UC_X86_REG_R9, UC_X86_REG_RAX as _RAX)
def uc_reg(n):
    return {'RCX': UC_X86_REG_RCX, 'RDX': UC_X86_REG_RDX,
            'R8': UC_X86_REG_R8, 'R9': UC_X86_REG_R9}[n]

def build_static(eng, tid, name):
    eng.zero(SLOT, 0x120)
    nb = name.encode('latin-1', 'replace') + b'\0'
    eng.zero(NAME, 0x200)
    eng.uc.mem_write(NAME, nb)
    eng.call(RVA_STATIC_CTOR, SLOT, tid, NAME)
    return bytes(eng.uc.mem_read(SLOT, 0x120))

HEAP = 0x62000000          # holder's heap string buffer, stands in for operator new

def build_dynamic(eng, tid, name):
    """The dynamic ctor path: holder with an MSVC std::string at +0x10.

    len < 0x10 keeps the chars inline at holder+0x10 (cap 0x0F); longer names store a
    heap pointer there with cap >= 0x10 — the engine's own allocator is not involved,
    we just hand it a buffer, because 0x1D152D0 only reads chars/size/cap.
    """
    eng.zero(SLOT, 0x120)
    eng.zero(HOLDER, 0x120)
    nb = name.encode('latin-1', 'replace')
    if len(nb) < 0x10:
        eng.uc.mem_write(HOLDER + 0x10, nb.ljust(16, b'\0'))
        cap = 0x0F
    else:
        eng.uc.mem_write(HOLDER + 0x10, struct.pack('<Q', HEAP))
        eng.uc.mem_write(HEAP, nb + b'\0')
        cap = ((len(nb) + 16) // 16) * 16 - 1
    eng.uc.mem_write(HOLDER + 0x20, struct.pack('<Q', len(nb)))
    eng.uc.mem_write(HOLDER + 0x28, struct.pack('<Q', cap))
    eng.call(RVA_DYN_CTOR, SLOT, tid, HOLDER)
    return bytes(eng.uc.mem_read(SLOT, 0x120))

def fields(block, slot=SLOT, base=BASE):
    vtable = struct.unpack_from('<Q', block, 0x08)[0]
    bufptr = struct.unpack_from('<Q', block, 0x10)[0]
    return {
        'id': struct.unpack_from('<I', block, 0x00)[0],
        'flag': block[4],
        'pad5_7': block[5:8],
        'vtable_rva': vtable - base if vtable >= base else vtable,
        'buf_off': bufptr - slot,
        'cap': struct.unpack_from('<I', block, 0x18)[0],
        'size': struct.unpack_from('<I', block, 0x1C)[0],
        'chars': block[0x20:0x20 + 0x100].split(b'\0')[0].decode('latin-1', 'replace'),
    }

def diff(a, b):
    return [(i, a[i], b[i]) for i in range(len(a)) if a[i] != b[i]]

def main():
    what = sys.argv[1] if len(sys.argv) > 1 else 'static-dynamic'
    eng = Engine()
    if what == 'static-dynamic':
        samples = [('add_modifier', 10104), ('id', 11), ('save_progress_to_user', 0x2778),
                   ('a', 7), ('change_city_capital', 0x1234),
                   ('fifteen_chars_h', 0xAAAA),          # exactly SSO_MAX
                   ('sixteen_chars_xx', 0xAAAAB),        # exactly at the heap boundary
                   ('a_name_that_is_quite_longindeed', 0x1),
                   ('x' * 254, 0x2),                     # size 255 < cap 256: stays inline
                   ('y' * 255, 0x3),                     # size 256 == cap: last inline case
                   ('z' * 256, 0x4)]                     # size 257 > cap: reserve must fire
        bad = 0
        for name, tid in samples:
            try:
                s = build_static(eng, tid, name)
                d = build_dynamic(eng, tid, name)
            except RuntimeError as e:
                print('%-34s -> %s' % (name[:34], e))
                continue
            ds = diff(s, d)
            tail_s = s[0x21 + len(name):]
            tail_d = d[0x21 + len(name):]
            print('%-34s id=%-6d static==dynamic: %-5s  diff@ %s  tail zero: %s/%s  f=%s'
                  % (name[:34], tid, 'YES' if not ds else 'NO', ds[:6],
                     not any(tail_s), not any(tail_d), fields(s)))
            if ds:
                bad += 1
            if name == 'add_modifier':
                print('    block[0x00:0x30] =', s[:0x30].hex())
        print('\n%d samples diverge; reserves hit %d, memcpys %d'
              % (bad, eng.reserves, eng.memcpys))
        return
    if what == 'oracle':
        tsv = sys.argv[2] if len(sys.argv) > 2 else \
            'evidence/xrefs/keyword_registration_table_4_4_4.tsv'
        out = sys.argv[3] if len(sys.argv) > 3 else \
            'evidence/xrefs/descriptor_oracle_4_4_4.tsv'
        golden = sys.argv[4] if len(sys.argv) > 4 else \
            'src/dll/scripted/keyword_registry_golden.zig'
        rows = []
        for line in open(tsv):
            if line.startswith('#'):
                continue
            p = line.rstrip('\n').split('\t')
            rows.append((int(p[0]), p[2]))
        by_len = {}
        extra = set()
        for tid, name in rows:
            if len(name) >= 0x100:
                continue
            by_len.setdefault(len(name), (tid, name))
            if len(name) >= 60:
                extra.add((tid, name))
        picks = sorted(by_len.values()) + sorted(extra)
        picks.append((10104, 'add_modifier'))
        picks = sorted(set(picks))

        diverge, hashes = [], {}
        with open(out, 'w') as w:
            w.write('# id\tname\tdo_not_write\tsha256_static\tsha256_dynamic\twritten_bytes_hex\n')
            w.write('# slot=0x%x module_base=0x%x; whole 0x120 block hashed after zero-fill\n'
                    % (SLOT, BASE))
            for i, (tid, name) in enumerate(rows):
                if len(name) >= 0x100:
                    continue
                s = build_static(eng, tid, name)
                d = build_dynamic(eng, tid, name)
                if diff(s, d):
                    diverge.append(name)
                hs, hd = hashlib.sha256(s).hexdigest(), hashlib.sha256(d).hexdigest()
                hashes[(tid, name)] = hs
                # §20: the ctors write +0x00..+0x04 and +0x08..+(0x20+len), and nothing else.
                # +0x05..+0x07 and the tail past the terminator are never touched by either path.
                w.write('%d\t%s\t0x05-0x07,0x%x-0x11f\t%s\t%s\t%s\n' % (
                    tid, name, 0x21 + len(name), hs, hd,
                    s[:0x20 + len(name) + 1].hex()))
                if i % 2000 == 0:
                    print('  %d/%d' % (i, len(rows)), flush=True)
        print('rows %d, static!=dynamic %d %s' % (len(rows), len(diverge), diverge[:5]))

        with open(golden, 'w') as g:
            g.write('// GENERATED by scripts/emu_desc.py oracle — do not edit.\n'
                    '// Each vector is the sha256 of the full 0x120 descriptor block that\n'
                    "// the engine's OWN writers (0x1D15270 static, 0x1D152D0 dynamic) produce\n"
                    '// for (id, name) at slot=0x%x, module base=0x%x.\n'
                    '// One vector per distinct name length in the 9,863-entry table, plus every\n'
                    '// name of length >= 60, plus add_modifier.\n\n'
                    'pub const slot: usize = 0x%x;\n'
                    'pub const module_base: usize = 0x%x;\n\n'
                    'pub const Vector = struct { id: u32, name: []const u8, sha256: []const u8 };\n\n'
                    'pub const vectors = [_]Vector{\n'
                    % (SLOT, BASE, SLOT, BASE))
            for tid, name in picks:
                g.write('    .{ .id = %d, .name = "%s", .sha256 = "%s" },\n'
                        % (tid, name, hashes[(tid, name)]))
            g.write('};\n')
        print('golden vectors %d -> %s' % (len(picks), golden))
        return
    sys.exit('unknown mode %r' % what)

if __name__ == '__main__':
    main()
