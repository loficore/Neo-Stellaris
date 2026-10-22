"""Offline: turn a UBSan panic from this DLL into the C source lines it came from.

Formerly ``scripts/scratch/2026-10_abortexit/ubsan_site.py``; that frozen original
stays where it is because §45's evidence records provenance by basename. This copy is
the maintained one — the §45 fix loop (edit → ``zig build`` → re-run) calls it
repeatedly, so it lives at ``scripts/`` top level with the other offline PE tools.

Zig links `lib/ubsan_rt.zig` as the UBSan runtime, and its Debug build compiles the
vendored C (`build.zig:9-14`) with clang's undefined-behaviour checks. Every check
carries its own `TypeMismatchData` record in a data section (`.rdata`/`.data` — the
linker chooses, and in this artifact all 13,693 of them land in `.data`):

    struct { char *FileName; u32 Line; u32 Column; TypeDescriptor *td; u8 log_align; u8 kind; }

The DLL has no symbol table and no debug sections (`objdump -h`: .text .rdata .buildid
.data .pdata .tls .reloc), so a panic prints `???:?:?: 0x...` and Zig's own printer has
nothing to resolve. Two things in the image still answer "where":

  * the UBSan records above hold file, line, column and the type-descriptor name — which
    is exactly the `of type 'JSMallocBlockHeader' (aka 'struct JSMallocBlockHeader')` text
    in the panic, so the panic text says which records to read;
  * `.pdata` is the x64 exception directory: one `RUNTIME_FUNCTION` per function with
    `{ BeginAddress, EndAddress }` RVAs, i.e. exact function boundaries without symbols.

So a panic RVA resolves: `site` lists every check site for a type name, and `func <va>`
finds the function containing that address and lists the source lines of every UBSan
record its code references — which names the function, by reading the C at those lines.

    python3 scripts/dll_ubsan_site.py [dll] site JSMallocBlockHeader
    python3 scripts/dll_ubsan_site.py [dll] func 0x18000bd9b

The DLL path is the first argument when it ends in ``.dll``; with no argument it falls
back to the artifact this repository builds (``zig-out/bin/stellaris_quickjs.dll``,
resolved from this file's location, not from the cwd). Nothing here is hard-coded to one
link: RVAs are recomputed from whichever image you hand it, and `image_base` is read from
its own optional header.

Read-only: opens a file copy, no process, no game, no dispatch.

**Judgement traps (full write-up in ``docs/offline-tooling.md``):** `func` prints the
`.pdata` range plus the records that range loads — that is frame *attribution*, not a
link-time function name; this parse yields only a fraction of the image's real function
count (**3,042** entries for §42's 0x4c8b86-byte `.text`, **4,824** for the current
build's 0x4c9be6 one — measured with `runtime_functions` on each), so "the address is not
inside any range" proves nothing; and a panic stack prints each return address as
``ip − 1``, so a frame's printed value is one byte *before* the call instruction — pass it
to `func` as-is (the `.pdata` lookup is the inclusive ``begin <= rva < end``), but never
read the printed address itself as the faulting or calling instruction.
"""
from __future__ import annotations

import os
import struct
import sys

# The artifact this repository builds. Tests import this module and pass their own
# bytes; only the CLI needs a default, and it must not be a hard-coded absolute path.
DEFAULT_DLL = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "zig-out", "bin", "stellaris_quickjs.dll")

KIND_NAMES = [
    "load", "store", "reference_binding", "member_access", "member_call",
    "constructor_call", "downcast_pointer", "downcast_reference", "upcast",
    "upcast_to_virtual_base", "nonnull_assign", "dynamic_operation",
]
# The kinds clang routes through __ubsan_handle_type_mismatch_v1.
TYPE_MISMATCH_KINDS = {3, 4, 5, 6, 7, 8, 9, 10, 11}


def parse(data: bytes):
    """(image_base, [(name, rva, vsize, raw_size, raw_off), ...])."""
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    n_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    magic = struct.unpack_from("<H", data, pe_off + 24)[0]
    if magic != 0x20b:
        raise ValueError(f"PE32+ expected, got magic {magic:#x}")
    image_base = struct.unpack_from("<Q", data, pe_off + 24 + 0x18)[0]
    table = pe_off + 24 + opt_size
    secs = []
    for i in range(n_sections):
        at = table + i * 40
        name = data[at:at + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, rva, raw_size, raw_off = struct.unpack_from("<IIII", data, at + 8)
        secs.append((name, rva, vsize, raw_size, raw_off))
    return image_base, secs


def make_maps(secs):
    """rva <-> file offset, given the section table."""
    def off_of(rva):
        for _, s_rva, s_vsize, s_raw, s_off in secs:
            if s_rva <= rva < s_rva + max(s_vsize, s_raw):
                return s_off + (rva - s_rva)
        return None

    def rva_of(off):
        for _, s_rva, s_vsize, s_raw, s_off in secs:
            if s_off <= off < s_off + max(s_vsize, s_raw):
                return s_rva + (off - s_off)
        return None
    return off_of, rva_of


def cstring(data: bytes, off, limit=200) -> str:
    if off is None or off < 0 or off >= len(data):
        return ""
    end = data.find(b"\0", off, off + limit)
    if end < 0:
        end = min(off + limit, len(data))
    return data[off:end].decode("utf-8", "replace")


def iter_records(data: bytes, image_base: int, secs):
    """Yield (record_rva, file, line, col, kind, type_name) for each plausible
    TypeMismatchData in a data section.

    A validated byte scan, not an offset walk: the linker places these records wherever
    it likes and nothing indexes them. Stride 8 because a record starts with a pointer
    and is 32 bytes.

    **Each scan is bounded to its own section's raw bytes.** The frozen original scanned
    from each data section's file offset to EOF, so a record living in a section that
    comes later in the file was yielded once per earlier scan. In this artifact **all**
    the records are in `.data` and `.data` follows `.rdata` in the file, so
    `site JSMallocBlockHeader` printed 282 rows for **141** distinct records (the pairs
    share one `record_rva`) while §45.3 quotes the 141. The bound is the fix; the row
    content is unchanged, and so is the set of records found.
    """
    off_of, rva_of = make_maps(secs)
    for name, _, _, s_raw, s_off in secs:
        if not name.startswith((".rdata", ".data")):
            continue
        end = min(s_off + s_raw, len(data))
        for start in range(s_off, end - 32, 8):
            (name_va, line, col, td_va, log_align, kind) = struct.unpack_from(
                "<QIIQBB", data, start)
            if log_align > 7 or kind not in TYPE_MISMATCH_KINDS or line == 0:
                continue
            name_off, td_off = off_of(name_va - image_base), off_of(td_va - image_base)
            if name_off is None or td_off is None:
                continue
            file_name = cstring(data, name_off)
            if not file_name.endswith((".c", ".h", ".zig")):
                continue
            # Zig reads the name at td + @sizeOf(TypeDescriptor) = 4 (kind u16 + info
            # u16); this build's panic text confirms it. +8 is the newer clang ABI's
            # offset, tried so a toolchain bump shows up as "no sites" — the scan below
            # only accepts +4, so a bump must widen it deliberately.
            type_name = cstring(data, td_off + 4)
            if not type_name.isascii() or len(type_name) < 4:
                continue
            yield rva_of(start), file_name, line, col, KIND_NAMES[kind], type_name


def runtime_functions(data: bytes, secs):
    """.pdata -> sorted [(begin_rva, end_rva), ...]: the x64 function boundaries."""
    for name, _, s_vsize, s_raw, s_off in secs:
        if name != ".pdata":
            continue
        size = min(s_vsize or s_raw, len(data) - s_off)
        out = []
        for i in range(size // 12):
            begin, end = struct.unpack_from("<II", data, s_off + i * 12)
            if 0 < begin < end:
                out.append((begin, end))
        return sorted(out)
    return []


def lea_record_targets(data: bytes, secs, begin: int, end: int, want_vas):
    """RIP-relative `lea rcx/r8..,[rip+disp32]` inside [begin, end) hitting `want_vas`.

    That is exactly how clang passes a UBSan data record: `lea rcx,[rip+Data]` a few
    bytes before `call __ubsan_handle_*`, so the record's address is recoverable from
    the instruction bytes without a disassembler.
    """
    off_of, _ = make_maps(secs)
    lo, hi = off_of(begin), off_of(end - 1)
    if lo is None or hi is None:
        return {}
    body = data[lo:hi + 1]
    hits = {}
    for i in range(len(body) - 7):
        if body[i] != 0x48 or body[i + 1] != 0x8D:
            continue
        if (body[i + 2] & 0xC7) != 0x05:  # mod=00, r/m=101 => RIP-relative
            continue
        disp = struct.unpack_from("<i", body, i + 3)[0]
        target = begin + i + 7 + disp
        if target in want_vas:
            hits.setdefault(target, []).append(begin + i)
    return hits


def cmd_site(data, image_base, secs, want):
    rows = [r for r in iter_records(data, image_base, secs) if want in r[5]]
    print(f"[ubsan_site] {len(rows)} UBSan check sites for a type containing {want!r}")
    for rva, f, l, c, k, t in sorted(rows, key=lambda r: (r[1], r[2], r[3])):
        where = f"record_rva={rva:#x}" if rva is not None else "record_rva=?"
        print(f"  {f}:{l}:{c} {k} type={t} {where}")
    return 0 if rows else 1


def cmd_func(data, image_base, secs, va):
    rva = va - image_base
    span = next((f for f in runtime_functions(data, secs) if f[0] <= rva < f[1]), None)
    if span is None:
        print(f"[ubsan_site] rva {rva:#x} is not inside any .pdata function entry")
        return 1
    begin, end = span
    print(f"[ubsan_site] function holding {va:#x}: rva {begin:#x}..{end:#x} "
          f"({end - begin} bytes)")
    recs = {}
    for r, f, l, c, k, t in iter_records(data, image_base, secs):
        if r is not None:
            recs[r] = (f, l, c, k, t)
    hits = lea_record_targets(data, secs, begin, end, set(recs))
    if not hits:
        print("[ubsan_site] this function's code references no UBSan record")
        return 1
    for hit_rva in sorted(hits):
        f, l, c, k, t = recs[hit_rva]
        sites = ", ".join(f"{image_base + a:#x}" for a in hits[hit_rva])
        print(f"  {f}:{l}:{c} {k} type={t} record_rva={hit_rva:#x} loaded_at={sites}")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    path = DEFAULT_DLL
    if argv and argv[0].endswith(".dll"):
        path, argv = argv[0], argv[1:]
    with open(path, "rb") as f:
        data = f.read()
    image_base, secs = parse(data)
    mode = argv[0] if argv else "site"
    arg = argv[1] if len(argv) > 1 else "JSMallocBlockHeader"
    print(f"[ubsan_site] {path} image_base={image_base:#x} mode={mode}")
    if mode == "func":
        return cmd_func(data, image_base, secs, int(arg, 16))
    return cmd_site(data, image_base, secs, arg)


if __name__ == "__main__":
    sys.exit(main())
