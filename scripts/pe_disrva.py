#!/usr/bin/env python3
"""Disassemble an RVA range of **our own** PE artifact offline.

The other disassemblers in this repo read the game: ``scripts/disrva.py`` and
``scripts/cap.py`` take a bare RVA and find ``stellaris.exe`` through
``NS_STELLARIS_EXE`` / fixed candidates. This one takes the PE **path as a
required positional argument**, because the thing §45/§47 need to read is the DLL
this repository builds:

    python3 scripts/pe_disrva.py zig-out/bin/stellaris_quickjs.dll 0xbd70 0xbdf3

Usage:

    pe_disrva.py <pe_path> <rva_start_hex> [<rva_end_hex>|<count>]

* ``rva_start_hex`` is hex with or without ``0x`` (case-insensitive).
* A third token beginning with ``0x`` is an **end RVA, exclusive**.
* A third token that is all decimal digits is an **instruction count** (default
  64, hard cap 4096 — a longer request prints ``; truncated at 4096 insns``).
  This is why a small hex end RVA must keep its ``0x``: bare ``100`` is a count,
  not RVA 0x100.
* Every absolute ``call``/``jmp`` target and every ``rip + disp`` operand gets
  ``  #0x<rva>``, resolved against the image base read from the PE (never a
  hard-coded base). ``.pdata``-style RVAs from ``dll_ubsan_site.py`` therefore
  compare directly with these annotations.

Only bytes mapped inside a section carrying ``IMAGE_SCN_MEM_EXECUTE``
(``0x20000000``) are decoded. RVA 0 lives in the PE headers; capstone would
happily decode ``MZ...`` as instructions, so the section bit — not capstone's
goodwill — decides that "this is not code".

**Exit codes (same three-way split as ``scripts/dll_ubsan_site.py``):**
0 = at least one instruction decoded; 1 = the range is not executable code, is
outside the file mapping, or decoded 0 instructions — that is a *finding*, not a
success, and must not be read as "the listing had no subtract-8"; 2 = the
invocation is wrong (missing args, non-hex, unreadable file, non-PE32+, a
truncated image whose sections run past EOF, end RVA below start, non-positive
count), printed as one line on stderr, no traceback.

**Judgement traps:**
1. Disassembly proves *which expression* is checked, never a runtime value. In
   particular it can show that the zero test reads the original pointer rather
   than the post-``-8`` value, but it cannot prove what that pointer held.
2. "Subtract 8" is a semantic, not one opcode: clang/LLVM picks among
   ``sub reg,8``, ``add reg,-8`` and ``lea reg,[reg-8]``. Do not grep the
   artifact for the plan's word "sub"; read the encoding it actually uses.
3. The ``#0x...`` annotation is an RVA (image-base-relative), not a VA, and a
   ``rip + disp`` target is computed from ``address + size + disp`` — the
   instruction's end, not its start.
4. Instruction count, byte count and RVA span are three different numbers. With
   an exclusive end, a fully decoded range covers ``end - start`` bytes; compare
   that, not the number of lines, when matching a ``.pdata`` span.

Read-only: opens the path it is given, no process, no game, no dispatch.
"""
from __future__ import annotations

import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
from capstone.x86 import X86_REG_RIP

IMAGE_SCN_MEM_EXECUTE = 0x20000000
DEFAULT_COUNT = 64
MAX_INSNS = 4096
EXIT_CALLER_ERROR = 2


def parse(data: bytes):
    """(image_base, [(name, rva, vsize, raw_size, raw_off, characteristics), ...])."""
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    n_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    magic = struct.unpack_from("<H", data, pe_off + 24)[0]
    if magic != 0x20B:
        raise ValueError(f"PE32+ expected, got magic {magic:#x}")
    image_base = struct.unpack_from("<Q", data, pe_off + 24 + 0x18)[0]
    table = pe_off + 24 + opt_size
    secs = []
    for i in range(n_sections):
        at = table + i * 40
        name = data[at:at + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, rva, raw_size, raw_off = struct.unpack_from("<IIII", data, at + 8)
        characteristics = struct.unpack_from("<I", data, at + 36)[0]
        if raw_size and raw_off + raw_size > len(data):
            raise ValueError(
                f"section {name} claims {raw_size:#x} raw bytes at file offset "
                f"{raw_off:#x}, past the end of the file ({len(data):#x} bytes): "
                "truncated image")
        secs.append((name, rva, vsize, raw_size, raw_off, characteristics))
    return image_base, secs


def exec_bytes(data: bytes, secs, rva: int):
    """(section_name, file_offset, available_bytes) for ``rva``, or a reason.

    Returns ``(None, reason)`` when the RVA is not inside an executable section
    or has no file-backed bytes there. The caller turns either into exit 1: both
    mean "do not feed these bytes to capstone".
    """
    sec = next((s for s in secs
                if s[1] <= rva < s[1] + max(s[2], s[3])), None)
    if sec is None:
        return None, f"rva {rva:#x} is not inside any PE section"
    name, s_rva, _vsize, s_raw, s_off, characteristics = sec
    if not characteristics & IMAGE_SCN_MEM_EXECUTE:
        return None, (f"rva {rva:#x} is inside {name}, which lacks "
                      "IMAGE_SCN_MEM_EXECUTE")
    delta = rva - s_rva
    if delta >= s_raw:
        return None, f"rva {rva:#x} is in {name} but past its file-backed bytes"
    off = s_off + delta
    avail = min(s_raw - delta, len(data) - off)
    if avail <= 0:
        return None, f"rva {rva:#x} has no file-backed bytes at offset {off:#x}"
    return (name, off, avail), None


def _annotations(ins, image_base: int):
    """``  #0x<rva>`` notes for direct call/jmp targets and rip+disp operands."""
    notes = []
    if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
        try:
            notes.append(f"#0x{int(ins.op_str, 16) - image_base:x}")
        except ValueError:
            pass
    for op in ins.operands:
        if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
            target = ins.address + ins.size + op.mem.disp
            notes.append(f"#0x{target - image_base:x}")
    return notes


def disassemble(path: str, start: int, end=None, count=DEFAULT_COUNT) -> int:
    try:
        with open(path, "rb") as f:
            data = f.read()
        image_base, secs = parse(data)
    except OSError as e:
        print(f"[pe_disrva] cannot read {path}: {e}", file=sys.stderr)
        return EXIT_CALLER_ERROR
    except (ValueError, struct.error) as e:
        print(f"[pe_disrva] {path} is not a readable PE32+ image: {e}",
              file=sys.stderr)
        return EXIT_CALLER_ERROR

    located, reason = exec_bytes(data, secs, start)
    if located is None:
        print(f"[pe_disrva] {reason}; refusing to decode it as code",
              file=sys.stderr)
        return 1
    sec_name, off, avail = located
    if end is not None:
        avail = min(avail, end - start)
    code = data[off:off + avail]
    effective_end = start + len(code)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    limit = MAX_INSNS if end is not None else min(count, MAX_INSNS)
    rows = []
    n = 0
    total = 0
    for ins in md.disasm(code, image_base + start):
        if n >= limit:
            break
        suffix = "".join(f"  {note}" for note in _annotations(ins, image_base))
        rows.append(f"  {ins.address - image_base:08x}  "
                    f"{ins.mnemonic:<7} {ins.op_str}{suffix}")
        n += 1
        total += ins.size

    if n == 0:
        print(f"[pe_disrva] rva {start:#x}..{effective_end:#x}: 0 instructions "
              "decoded — this range is not code", file=sys.stderr)
        return 1

    span = (f"rva {start:#x}..{effective_end:#x} (end exclusive)" if end is not None
            else f"rva {start:#x}.. (up to {limit} insns)")
    print(f"; {os.path.basename(path)} {sec_name} {span} "
          f"image_base={image_base:#x}: {n} insns, {total} bytes")
    for row in rows:
        print(row)
    if n == MAX_INSNS and total < len(code):
        print(f"; truncated at {MAX_INSNS} insns")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    usage = ("[pe_disrva] usage: python3 scripts/pe_disrva.py <pe_path> "
             "<rva_start_hex> [<rva_end_hex>|<count>]")
    if not 2 <= len(argv) <= 3:
        print(usage, file=sys.stderr)
        return EXIT_CALLER_ERROR
    path, start_tok = argv[0], argv[1]
    try:
        start = int(start_tok, 16)
    except ValueError:
        print(f"[pe_disrva] bad rva_start {start_tok!r}: expected hex",
              file=sys.stderr)
        return EXIT_CALLER_ERROR
    if start < 0:
        print(f"[pe_disrva] rva_start {start_tok!r} is negative", file=sys.stderr)
        return EXIT_CALLER_ERROR

    end = None
    count = DEFAULT_COUNT
    if len(argv) == 3:
        tok = argv[2]
        try:
            if tok.lower().startswith("0x"):
                end = int(tok, 16)
            elif tok.isdigit():
                count = int(tok, 10)
            else:
                # Hex end RVA without 0x that cannot be a decimal count.
                end = int(tok, 16)
        except ValueError:
            print(f"[pe_disrva] bad end/count {tok!r}: expected 0x<end_rva> "
                  "or a decimal instruction count", file=sys.stderr)
            return EXIT_CALLER_ERROR
        if end is not None and end < start:
            print(f"[pe_disrva] end rva {end:#x} is below start rva {start:#x}",
                  file=sys.stderr)
            return EXIT_CALLER_ERROR
        if end is None and count <= 0:
            print(f"[pe_disrva] instruction count must be positive, got {count}",
                  file=sys.stderr)
            return EXIT_CALLER_ERROR
    return disassemble(path, start, end=end, count=count)


if __name__ == "__main__":
    sys.exit(main())
