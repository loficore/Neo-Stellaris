"""Names MSVC C++ classes for a list of vtable RVAs, straight off the on-disk PE.

usage: python rttibatch.py 0x24B3050 0x24C69E8 ...
       python rttibatch.py --stdin < vtable_rvas.txt

Read-only file parse (no process attach, no patching), so it is safe to run any time.
Used to label the (vtable, shim) census from execspy.py: MSVC x64 stores an absolute
CompleteObjectLocator pointer just below the vtable, and the COL holds a 4-byte RVA to the
TypeDescriptor whose name follows a 16-byte header.
"""
import os
import struct
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def find_exe():
    """Same PE on either machine: env override first, then the Linux copy, then Windows."""
    cands = [os.environ.get('NS_STELLARIS_EXE'),
             '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe',
             r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe']
    for c in cands:
        if c and os.path.exists(c):
            return c
    sys.exit('stellaris.exe not found — set NS_STELLARIS_EXE')


EXE = find_exe()


class Image:
    def __init__(self, blob):
        mz = struct.unpack_from('<I', blob, 0x3C)[0]
        self.image_base = struct.unpack_from('<Q', blob, mz + 24 + 0x18)[0]  # preferred base
        nsec = struct.unpack_from('<H', blob, mz + 6)[0]
        opt = mz + 24
        secs_off = opt + struct.unpack_from('<H', blob, mz + 20)[0]
        self.secs = [struct.unpack_from('<III', blob, secs_off + i * 40 + 12)
                     for i in range(nsec)]
        self.blob = blob

    def read(self, rva, n):
        for va, vs, praw in self.secs:
            if va <= rva < va + vs:
                return self.blob[praw + (rva - va): praw + (rva - va) + n]
        raise KeyError(hex(rva))

    def u32(self, rva):
        return struct.unpack('<I', self.read(rva, 4))[0]

    def u64(self, rva):
        return struct.unpack('<Q', self.read(rva, 8))[0]


def class_name(img, vtable_rva):
    """vtable[-8] -> COL, COL+0x10 -> TypeDescriptor RVA, TD+0x10 -> mangled name."""
    col_va = img.u64(vtable_rva - 8)
    col = col_va - img.image_base
    if not 0 <= col < 0x4000_0000:
        return None, f'COL pointer implausible: {col_va:#x}'
    td_rva = img.u32(col + 0x10)
    raw = img.read(td_rva + 0x10, 128).split(b'\0')[0]
    name = raw.decode('utf-8', 'replace')
    if name.startswith('.?AV'):
        name = name[4:]
    if name.endswith('@@'):
        name = name[:-2]
    return name, f'col={col:#x} td={td_rva:#x}'


def dump(img, vtable_rva):
    """What actually sits below the vtable — the COL-at-[-8] assumption needs checking
    against this build before any name can be trusted."""
    print(f'--- {vtable_rva:#x} ---')
    for off in range(-0x20, 0x28, 8):
        try:
            q = img.u64(vtable_rva + off)
        except (KeyError, struct.error) as e:
            print(f'  {off:+#x}  unreadable ({e})')
            continue
        as_rva = q - img.image_base
        where = ''
        try:
            img.read(as_rva if 0 < as_rva < 0x4000_0000 else q, 1)
            where = '  -> in-image' if 0 < as_rva < 0x4000_0000 else '  -> not an image VA'
        except KeyError:
            where = '  -> no such RVA'
        print(f'  {off:+#x}  {q:#018x}  col_candidate={as_rva:#x}{where}')


RVA_BASE_EXECUTE = 0x1D08520


def section_of(img, rva):
    for i, (va, vs, praw) in enumerate(img.secs):
        if va <= rva < va + vs:
            return i
    return None


def section_name(img, i):
    mz = struct.unpack_from('<I', img.blob, 0x3C)[0]
    secs_off = mz + 24 + struct.unpack_from('<H', img.blob, mz + 20)[0]
    return img.blob[secs_off + i * 40: secs_off + i * 40 + 8].split(b'\0')[0].decode()


def effects(img):
    """Enumerate every CEffect-derived class in the image.

    The census proved the vtable shape: slot[1] is base Execute (the function we hook) and
    slot[2] is that class's own ExecuteActual — base Execute dispatches `call [rax+0x10]`.
    So every 8-byte-aligned .rdata location holding base Execute's VA is one such vtable,
    and its slot[2] is the concrete implementation. This is a full static class map, from
    the file alone, no process and no patching.
    """
    target = img.image_base + RVA_BASE_EXECUTE
    text = [i for i in range(len(img.secs)) if section_name(img, i) == '.text']
    out = []
    for i, (va, vs, praw) in enumerate(img.secs):
        if section_name(img, i) != '.rdata':
            continue
        blob = img.blob[praw:praw + vs]
        for off in range(8, len(blob) - 16, 8):  # need a slot before and after
            if struct.unpack_from('<Q', blob, off)[0] != target:
                continue
            vt = va + off - 8
            slot0 = struct.unpack_from('<Q', blob, off - 8)[0] - img.image_base
            slot2 = struct.unpack_from('<Q', blob, off + 8)[0] - img.image_base
            if all(section_of(img, s) in text for s in (slot0, slot2)):
                out.append((vt, slot0, slot2))
    return out


def cstring(img, rva, limit=96):
    """Printable string at an RVA, or None."""
    try:
        raw = img.read(rva, limit)
    except KeyError:
        return None
    s = raw.split(b'\0')[0]
    if len(s) < 4 or any(c < 0x20 or c > 0x7E for c in s):
        return None
    return s.decode('ascii')


def rip_refs(img, func_rva, span=0x400):
    """RIP-relative lea/mov targets inside a function prologue region.

    `48/4C 8D|8B <modrm mod=00 rm=101> disp32` is the only way a shipped MSVC x64 body can
    name a static string, and with COL-less RTTI (§14) those strings are what remains to
    identify a class with. No full decoder — just the one addressing mode that matters.
    """
    code = img.read(func_rva, span)
    hits = []
    for i in range(len(code) - 7):
        if code[i] not in (0x48, 0x4C) or code[i + 1] not in (0x8D, 0x8B):
            continue
        if code[i + 2] & 0xC7 != 0x05:
            continue
        disp = struct.unpack_from('<i', code, i + 3)[0]
        target = func_rva + i + 7 + disp
        s = cstring(img, target)
        if s:
            hits.append((i, target, s))
    return hits


def col_census(img):
    """How many of the 1,805 CEffect vtables actually have a CompleteObjectLocator below
    them. A COL is a VA into .rdata; a second slot is a VA into .text. Decides offline
    whether class names are recoverable at all."""
    rows = effects(img)
    text = [i for i in range(len(img.secs)) if section_name(img, i) == '.text']
    rdata = [i for i in range(len(img.secs)) if section_name(img, i) in ('.rdata', '.data')]
    kinds = {}
    for vt, _, _ in rows:
        q = img.u64(vt - 8) - img.image_base
        sec = section_of(img, q)
        kind = 'col?' if sec in rdata else ('slot' if sec in text else f'sec{sec}')
        kinds[kind] = kinds.get(kind, 0) + 1
    print(f'# {len(rows)} CEffect vtables, what sits at vtable[-8]: {kinds}')
    named = 0
    for vt, _, _ in rows:
        try:
            name, _ = class_name(img, vt)
        except (KeyError, struct.error):
            continue
        if name:
            named += 1
    print(f'# class_name() produced a name for {named} of them')


def main():
    args = [a for a in sys.argv[1:] if a != '--stdin']
    if '--col' in args:
        img = Image(open(EXE, 'rb').read())
        col_census(img)
        return
    if '--strings' in args:
        img = Image(open(EXE, 'rb').read())
        for token in args[args.index('--strings') + 1:]:
            rva = int(token, 16)
            try:
                hits = rip_refs(img, rva)
            except KeyError:
                print(f'{rva:#x}: unreadable')
                continue
            print(f'--- ExecuteActual {rva:#x}')
            for off, target, s in hits:
                print(f'  +{off:#06x} -> {target:#010x}  "{s[:80]}"')
            if not hits:
                print('  (no rip-relative strings in the first 0x400 bytes)')
        return
    if '--effects' in args:
        img = Image(open(EXE, 'rb').read())
        rows = effects(img)
        print(f'# {len(rows)} vtables whose slot[1] is base Execute '
              f'({img.image_base + RVA_BASE_EXECUTE:#x})')
        print('# NOTE: this is a FLOOR, not the CEffect class count. The filter requires '
              'slot[1]==base Execute, so every class that OVERRIDES Execute is absent '
              '(e.g. add_modifier vtable 0x2641B38, slot[1]=0x18AA2F0). '
              'See runtime_444_keyword_pipeline.md §17.')
        for vt, slot0, slot2 in rows:
            print(f'vtable {vt:#010x}  slot0 {slot0:#010x}  ExecuteActual(slot2) {slot2:#010x}')
        return
    if '--dump' in args:
        img = Image(open(EXE, 'rb').read())
        for token in args[args.index('--dump') + 1:]:
            dump(img, int(token, 16))
        return
    if not args and '--stdin' in sys.argv[1:]:
        args = [t for line in sys.stdin for t in line.split()]
    if not args:
        sys.exit(__doc__)
    img = Image(open(EXE, 'rb').read())
    print(f'# image base {img.image_base:#x}, {len(img.secs)} sections')
    for token in args:
        rva = int(token, 16)
        try:
            name, note = class_name(img, rva)
        except (KeyError, struct.error) as e:
            print(f'{rva:#10x}  unreadable ({e})')
            continue
        print(f'{rva:#10x}  {name or "<no RTTI>":<44} {note}')


if __name__ == '__main__':
    main()
