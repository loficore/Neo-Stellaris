"""Pure-function tests for rttibatch.py — synthetic PE, no game, no disk.

Fixtures build a two-section PE by hand instead of reading stellaris.exe, so the
shape criterion in all_vtables() can be pinned to addresses a reader verifies by
eye. The one real-file test names its artifact and reads it straight.
"""

import struct

from rttibatch import Image, all_vtables

HEADER_SIZE = 0x100
TEXT_RAW = 0x200


def pack(base, *rvas):
    """Section contents: each slot is the VA of one of these RVAs."""
    return b"".join(struct.pack("<Q", base + r) for r in rvas)


def fake_image(slots, text_va=0x1000, text_size=0x2000,
               rdata_va=0x4000, base=0x140000000):
    """One .text (0xcc filler, only there so section_of can name it) plus one
    .rdata holding `slots`.

    Image.__init__ reads e_lfanew at 0x3C, NumberOfSections at +6,
    SizeOfOptionalHeader at +20, ImageBase at optional+0x18, and per section
    entry the triple at +12 — which Image.read unpacks as
    (VirtualAddress, SizeOfRawData, PointerToRawData). VirtualSize is therefore
    written equal to SizeOfRawData: the fields are the same number here so the
    aliasing cannot matter.

    `slots` are RVAs; they become VAs through `pack`. Every value a test expects
    to read as "a pointer into .text" must land inside [text_va, text_va +
    text_size) and outside the .rdata range — the two sections may not overlap,
    because Image.read returns from whichever section it matches first.
    """
    rdata = pack(base, *slots)
    blob = bytearray(TEXT_RAW + text_size + len(rdata))
    struct.pack_into("<I", blob, 0x3C, HEADER_SIZE)          # e_lfanew
    blob[HEADER_SIZE:HEADER_SIZE + 4] = b"PE\0\0"
    struct.pack_into("<H", blob, HEADER_SIZE + 6, 2)         # NumberOfSections
    struct.pack_into("<H", blob, HEADER_SIZE + 20, 0x68)     # SizeOfOptionalHeader
    struct.pack_into("<H", blob, HEADER_SIZE + 24, 0x20B)    # PE32+
    struct.pack_into("<Q", blob, HEADER_SIZE + 24 + 0x18, base)
    secs = HEADER_SIZE + 24 + 0x68
    for i, (name, va, size, raw) in enumerate((
            (b".text", text_va, text_size, TEXT_RAW),
            (b".rdata", rdata_va, len(rdata), TEXT_RAW + text_size))):
        off = secs + i * 40
        blob[off:off + 8] = name
        struct.pack_into("<I", blob, off + 8, size)          # VirtualSize
        struct.pack_into("<I", blob, off + 12, va)           # VirtualAddress
        struct.pack_into("<I", blob, off + 16, size)         # SizeOfRawData
        struct.pack_into("<I", blob, off + 20, raw)          # PointerToRawData
    blob[TEXT_RAW:TEXT_RAW + text_size] = b"\xcc" * text_size
    blob[TEXT_RAW + text_size:] = rdata
    return Image(bytes(blob))


def test_all_vtables_takes_a_run_of_three_text_pointers_without_looking_at_slot1():
    # .rdata 的头 8 字节不是 .text 指针,随后三个是 ⇒ 表首 = rdata_va + 8
    img = fake_image([0xDEADBEEF, 0x1000, 0x1040, 0x1080])
    assert [(vt, run) for vt, run, _slots in all_vtables(img)] == [
        (0x4000 + 8, 3)]


def test_all_vtables_reports_every_run_start_not_only_the_first_one():
    # 四个连续 in-text 指针 ⇒ 起点 0 与起点 1 都产一条(这是 floor ⊆ 新集成立的前提)
    img = fake_image([0x1000, 0x1040, 0x1080, 0x10C0])
    starts = [vt for vt, _run, _s in all_vtables(img, min_run=3)]
    assert starts == [0x4000, 0x4000 + 8]
    assert [run for _vt, run, _s in all_vtables(img, min_run=3)] == [4, 3]


def test_all_vtables_refuses_a_run_of_two_and_still_never_asks_about_base_execute():
    img = fake_image([0x1000, 0x1040, 0xDEADBEEF])
    assert all_vtables(img, min_run=3) == []
    # slot1 原值必须带着,即便它不是 base Execute —— 这条就是 §17 那个下限的补集
    img = fake_image([0x1000, 0x2A5C, 0x1080, 0x10C0])
    hit = [s for _vt, _run, s in all_vtables(img) if 0x2A5C in s]
    assert hit and hit[0][1] == 0x2A5C


def load_rva_column(path):
    """Every `vtable 0x…` column in an artifact, as a set of RVAs.

    Both maps name their table-start column the same way, so the subset relation
    the test below checks is a set relation and not a line-count comparison that a
    duplicate row could satisfy.
    """
    found = set()
    with open(path, encoding='utf-8') as f:
        for line in f:
            if line.startswith('vtable '):
                found.add(int(line.split()[1], 16))
    return found


def test_the_floor_map_is_a_subset_of_the_unfiltered_candidate_set():
    floor = load_rva_column('evidence/xrefs/ceffect_vtable_map_4_4_4.txt')
    cand = load_rva_column('evidence/xrefs/vtable_candidates_all_4_4_4.txt')
    assert floor <= cand, f"floor entries missing from the new set: {sorted(floor - cand)[:5]}"
    assert len(cand) >= len(floor) == 1805
