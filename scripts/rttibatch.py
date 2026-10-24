"""Names MSVC C++ classes for a list of vtable RVAs, straight off the on-disk PE.

usage: python rttibatch.py 0x24B3050 0x24C69E8 ...
       python rttibatch.py --stdin < vtable_rvas.txt
       python rttibatch.py --all-vtables [--min-run 3]
       python rttibatch.py --who-tables 0x3b01a0,0x3afd30 [--candidates PATH]
       python rttibatch.py --who-lea 0x2606fe0

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

# Task 3's artifact, which --who-tables reads instead of re-running all_vtables.
DEFAULT_CANDIDATES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                  'evidence', 'xrefs', 'vtable_candidates_all_4_4_4.txt')


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


_MAX_RUN_REPORTED = 8


def all_vtables(img, min_run: int = 3):
    """Every 8-aligned .rdata position that starts a run of >= min_run pointers into .text.

    The floor map above filters on slot[1] == base Execute, so a class that *overrides*
    Execute — the thing C4 is looking for — has no static entity in it. This is the set
    without that filter, and it carries slot[1]'s raw value so "which of these override
    Execute" is answerable offline from the artifact alone.

    Shape only: this is NOT a class table. Function-pointer arrays, switch jump tables
    and vtable fragments all pass, which is why every row reports its run length and its
    first four slot RVAs verbatim. Those two fields are the only way downstream can filter
    further, so nothing here may pre-judge them.

    Every run start is emitted, not just the start of each maximal run: a vtable header can
    sit in the middle of a longer run, and the floor map's own entries are exactly such
    mid-run starts. run_length counts forward from the position and stops at
    _MAX_RUN_REPORTED, the window a slot reader looks at anyway.
    """
    text_bounds = [(va, va + vs) for i, (va, vs, _praw) in enumerate(img.secs)
                   if section_name(img, i) == '.text']
    out = []
    for i, (va, vs, praw) in enumerate(img.secs):
        if section_name(img, i) != '.rdata':
            continue
        blob = img.blob[praw:praw + vs]
        words = struct.unpack('<%dQ' % (len(blob) // 8), blob[:len(blob) // 8 * 8])
        flags = [any(lo <= q - img.image_base < hi for lo, hi in text_bounds)
                 for q in words]
        runs = [0] * (len(flags) + 1)
        for at in range(len(flags) - 1, -1, -1):
            runs[at] = min(runs[at + 1] + 1, _MAX_RUN_REPORTED) if flags[at] else 0
        for at, run in enumerate(runs[:-1]):
            if run >= min_run:
                out.append((va + at * 8, run,
                            [w - img.image_base for w in words[at:at + 4]]))
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


def format_candidate_row(vt, run, slots):
    """One --all-vtables row, in the only syntax parse_candidate_lines reads back.

    The formatter and the parser are one contract, so this prints every slot it is
    given: the artifact's three-column shape is a decision at the call site, not
    something this function can silently enforce on a round-trip.
    """
    cols = ''.join(f'  slot{k} {s:#010x}' for k, s in enumerate(slots))
    return f'vtable {vt:#010x}  run={run}{cols}'


def parse_candidate_lines(text):
    """Read --all-vtables output back into (vtable_rva, run, [slot RVAs]) tuples.

    Lines that do not start with `vtable ` are the artifact's own `#` header and are
    skipped. Everything else is parsed strictly: a `vtable` line that does not parse
    means this file is not the product of this tool (or not this exe's), and a quiet
    empty candidate set would make --who-tables look like "no copied table" when all
    it found was a file it could not read.
    """
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] != 'vtable':
            continue
        run = int(parts[2].split('=', 1)[1])
        rows.append((int(parts[1], 16), run, [int(v, 16) for v in parts[4::2]]))
    return rows


_SLOTS_READ = 8


def slot_hits(img, targets, candidates):
    """Which candidates have one of `targets` (RVAs) in their first 8 slots.

    The slots come from the image at `vtable_rva`, not from the tuple's carried
    columns, so a target deeper than the artifact's three printed slots still hits.
    `run` is deliberately NOT a filter here: a hit beyond the run is still a pointer
    with that value in that slot, and dropping it would make the 0-hit observation
    uninterpretable — which is the one reading §57 must not be allowed to draw.
    A vtable_rva outside every section raises out of Image.read: that candidate does
    not belong to this exe, and the run should stop rather than report a miss.
    """
    hits = []
    for vt, _run, _slots in candidates:
        raw = img.read(vt, _SLOTS_READ * 8)
        for index in range(len(raw) // 8):
            value = struct.unpack_from('<Q', raw, index * 8)[0] - img.image_base
            if value in targets:
                hits.append({'vtable_rva': vt, 'slot_index': index, 'target_rva': value})
    return hits


def physical_slots(hits):
    """The distinct qwords a hit set actually read, sorted.

    --who-tables counts *proposed table starts*, and the candidate set deliberately
    emits every run start, so that count is an upper bound on how many overlapping
    windows saw the value — not how many static slots hold it. §57 reads this number
    for the second, because the first one is inflated by construction.
    """
    return sorted({h['vtable_rva'] + 8 * h['slot_index'] for h in hits})


def lea_sites_to(img, target_rva):
    """Every .text instruction RVA that RIP-relative-loads `target_rva` into a register.

    Same encoding rip_refs() documents — `48/4C 8D|8B` with modrm `mod=00 rm=101` plus
    a disp32 — but over the whole section instead of one function's first `span`
    bytes. The displacement is relative to the byte after the instruction, so

        disp = target_va - (site_va + 7)

    and this inverts it: `site_rva + 7 + disp == target_rva` (image base cancels on
    both sides). Returns instruction starts in scan order; no mnemonic is decoded, so
    a mov-into-address (0x8B) is reported the same way as a lea.
    """
    sites = []
    for i, (va, vs, praw) in enumerate(img.secs):
        if section_name(img, i) != '.text':
            continue
        code = img.blob[praw:praw + vs]
        for off in range(len(code) - 6):
            if code[off] not in (0x48, 0x4C) or code[off + 1] not in (0x8D, 0x8B):
                continue
            if code[off + 2] & 0xC7 != 0x05:
                continue
            disp = struct.unpack_from('<i', code, off + 3)[0]
            if va + off + 7 + disp == target_rva:
                sites.append(va + off)
    return sites


def _slot1(img, vt):
    """slot[1] as an RVA, or '-' when the table ends too close to the section tail."""
    raw = img.read(vt + 8, 8)
    return f'{struct.unpack("<Q", raw)[0] - img.image_base:#010x}' if len(raw) == 8 else '-'


def _targets_from(tokens):
    targets = set()
    for token in tokens:
        for part in token.split(','):
            if part:
                targets.add(int(part, 16))
    return targets


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
    if '--all-vtables' in args:
        img = Image(open(EXE, 'rb').read())
        min_run = 3
        if '--min-run' in args:
            min_run = int(args[args.index('--min-run') + 1])
        rows = all_vtables(img, min_run)
        print(f'# {len(rows)} vtable-shaped runs in .rdata, run>={min_run}, '
              'NOT filtered by slot[1]')
        for vt, run, slots in rows:
            print(format_candidate_row(vt, run, slots[:3]))
        return
    if '--who-tables' in args:
        at = args.index('--who-tables') + 1
        targets = _targets_from(args[at:at + 1])
        path = DEFAULT_CANDIDATES
        if '--candidates' in args:
            path = args[args.index('--candidates') + 1]
        with open(path, encoding='utf-8') as f:
            candidates = parse_candidate_lines(f.read())
        img = Image(open(EXE, 'rb').read())
        hits = slot_hits(img, targets, candidates)
        slots_hit = physical_slots(hits)
        print(f'# {len(targets)} target RVAs {sorted(targets)}, '
              f'{len(candidates)} candidates from {os.path.basename(path)}')
        for h in hits:
            print(f"{h['vtable_rva']:#010x}  slot{h['slot_index']}  "
                  f"target {h['target_rva']:#010x}  slot1 {_slot1(img, h['vtable_rva'])}")
        print(f'# {len(hits)} rows, {len({h["vtable_rva"] for h in hits})} distinct table '
              f'starts, {len(slots_hit)} distinct physical slots')
        print('# 那两个数不等价:table starts 被 run 起点重复与「靶子是共用实现」两头抬高,'
              '不能用来判「引擎复制了表」。读法见 §57.3 与 docs/offline-tooling.md 的 --who-tables 陷阱。')
        for addr in slots_hit:
            print(f'slot {addr:#010x}')
        return
    if '--who-lea' in args:
        target = int(args[args.index('--who-lea') + 1], 16)
        img = Image(open(EXE, 'rb').read())
        sites = lea_sites_to(img, target)
        print(f'# {len(sites)} RIP-relative load sites of {target:#x} in .text')
        for site in sites:
            print(f'site {site:#010x}')
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
