"""Re-derive the corrected per-root numbers for the §56.8 append.

Reads only committed artifacts -- evidence/logs/scope_probe_v2_4_4_4.tsv (the
shot's own object rows) and evidence/xrefs/ceffect_vtable_map_4_4_4.txt (the
1,805-entry floor map).  No process, no gun.

Three things this answers that §56.4 could not:

1. how many candidate qwords are THEMSELVES known vtable addresses (the second
   lookup the fixed instrument now runs per candidate), and on which source;
2. which vptr_rva values in the artifact are fabrications -- an RVA computed
   from a pointer that does not live in the exe image at all;
3. what the `helper` root's first word actually resolves to once the image
   bound is applied.

EXE_BASE is the live exe base recorded in §56 (the DLL base 0x7ffc3aad0000 is
NOT it -- trap 4).
"""

import collections
import re
import sys

TSV = "evidence/logs/scope_probe_v2_4_4_4.tsv"
VTABLES = "evidence/xrefs/ceffect_vtable_map_4_4_4.txt"
EXE_BASE = 0x7FF6A4270000
SIZE_OF_IMAGE = 0x3927000
IMG_END = EXE_BASE + SIZE_OF_IMAGE

_FIELD = re.compile(r"(\w+)=(-|0x[0-9a-f]+|\S+)")


def load_floor():
    rvas = set()
    pat = re.compile(r"vtable (0x[0-9a-f]{8})")
    for line in open(VTABLES, encoding="utf-8", errors="replace"):
        m = pat.search(line)
        if m:
            rvas.add(int(m.group(1), 16))
    return rvas


def parse_detail(text):
    return {k: (None if v == "-" else v) for k, v in _FIELD.findall(text)}


def main():
    floor = load_floor()
    roots = collections.defaultdict(set)
    cands = collections.Counter()
    known_hits = 0
    member_rows = collections.Counter()
    member_rvas = collections.Counter()
    member_slot2 = {}
    ptr_out_image = 0
    ptr_in_image = 0
    fabricated_vptr_rva = []
    vptr_rva_absent = 0
    ascii_ptrs = []
    helper_rows = []

    for line in open(TSV, encoding="utf-8", errors="replace"):
        parts = line.rstrip("\n").split("\t")
        if parts[0] != "object":
            continue
        root = int(parts[1], 16)
        d = parse_detail(parts[3])
        source = d["source"]
        off = int(d["off"], 16)
        ptr = int(d["ptr"], 16)
        vptr_rva = None if d["vptr_rva"] is None else int(d["vptr_rva"], 16)
        roots[source].add(root)
        cands[source] += 1
        if parts[2] == "1":
            known_hits += 1

        in_image = EXE_BASE <= ptr < IMG_END
        ptr_in_image += in_image
        ptr_out_image += not in_image
        if in_image and (ptr - EXE_BASE) in floor:
            member_rows[source] += 1
            member_rvas[ptr - EXE_BASE] += 1
            member_slot2.setdefault(ptr - EXE_BASE, d.get("slot2_rva"))

        # ASCII-looking qwords that the pointer-shaped gate let through
        as_bytes = ptr.to_bytes(8, "little")
        if re.fullmatch(rb"[ -~]{4,}\x00+", as_bytes):
            ascii_ptrs.append(
                (source, root, off, as_bytes.rstrip(b"\x00"))
            )

        # §56.4 computed vptr_rva with no upper bound: anything above
        # SizeOfImage is a fabricated RVA, not a module offset.
        if vptr_rva is None:
            vptr_rva_absent += 1
        elif vptr_rva >= SIZE_OF_IMAGE:
            fabricated_vptr_rva.append((source, root, off, ptr, vptr_rva))

        if source == "helper":
            helper_rows.append((root, off, ptr, vptr_rva))

    print(f"FLOOR_MAP  {len(floor)} vtables")
    print(f"IMAGE      0x{EXE_BASE:x}..0x{IMG_END:x}  SizeOfImage 0x{SIZE_OF_IMAGE:x}")
    print("DISTINCT_ROOTS  " + "  ".join(
        f"{k}={len(v)}" for k, v in sorted(roots.items()))
        + f"  arg*=0  total={sum(len(v) for v in roots.values())}")
    print("CANDIDATES      " + "  ".join(
        f"{k}={v}" for k, v in sorted(cands.items())) + f"  total={sum(cands.values())}")
    print(f"KNOWN_VTABLE_HITS (first lookup, as §56.4)  {known_hits}")
    print("MEMBER_VTABLE_ROWS (second lookup)  " + "  ".join(
        f"{k}={v}" for k, v in sorted(member_rows.items()))
        + f"  total={sum(member_rows.values())}  distinct_rvas={len(member_rvas)}")
    for rva, n in member_rvas.most_common():
        print(f"    member vtable 0x{rva:08x}  seen x{n}")
    print(f"PTR_IN_IMAGE  {ptr_in_image}   PTR_OUT_OF_IMAGE  {ptr_out_image}")
    print(f"VPTR_RVA_ABSENT  {vptr_rva_absent}")
    print(f"VPTR_RVA_FABRICATED (>= SizeOfImage)  {len(fabricated_vptr_rva)}")
    for row in fabricated_vptr_rva:
        print(f"    source={row[0]} root=0x{row[1]:x} off=0x{row[2]:x} "
              f"vptr=0x{row[3]:x} -> fake rva 0x{row[4]:x}")
    print(f"ASCII_SHAPED_PTRS  {len(ascii_ptrs)}")
    for src, root, off, txt in ascii_ptrs:
        print(f"    source={src} root=0x{root:x} off=0x{off:x} {txt.decode()}")
    print("HELPER_ROOT_ROWS")
    for root, off, ptr, vptr_rva in helper_rows:
        where = "out-of-image" if not (EXE_BASE <= ptr < IMG_END) else \
            f"in-image RVA 0x{ptr - EXE_BASE:x}"
        print(f"    root=0x{root:x} off=0x{off:x} ptr=0x{ptr:x} "
              f"vptr_rva={'-' if vptr_rva is None else hex(vptr_rva)}  {where}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
