"""Pure-function tests for rttibatch.py — synthetic PE, no game, no disk.

Fixtures build a two-section PE by hand instead of reading stellaris.exe, so the
shape criterion in all_vtables() can be pinned to addresses a reader verifies by
eye. The one real-file test names its artifact and reads it straight.
"""

import struct

from rttibatch import (slot_hits, lea_sites_to, parse_candidate_lines,
                       physical_slots, format_candidate_row, Image, all_vtables)

HEADER_SIZE = 0x100
TEXT_RAW = 0x200


def pack(base, *rvas):
    """Section contents: each slot is the VA of one of these RVAs."""
    return b"".join(struct.pack("<Q", base + r) for r in rvas)


def fake_image(slots, text_va=0x1000, text_size=0x2000,
               rdata_va=0x4000, base=0x140000000, text_bytes=None):
    """One .text (0xcc filler, only there so section_of can name it) plus one
    .rdata holding `slots`.

    `text_bytes` replaces the .text filler (padded up to the caller's `text_size`),
    which is what lets a .text scan test pin an instruction site without a real PE.

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
    if text_bytes is not None:
        text_size = max(text_size, len(text_bytes))
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
    filler = b"\xcc" * text_size
    if text_bytes is not None:
        filler = text_bytes.ljust(text_size, b"\xcc")
    blob[TEXT_RAW:TEXT_RAW + text_size] = filler
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


def test_slot_hits_reads_eight_slots_from_the_image_not_only_the_four_carried():
    # .rdata 起 0x4000 放八个 qword,index 6 是目标 —— 目标不在 tuple 带出的前 4 个里,
    # 命中只能来自「回到镜像里按 vtable_rva 重读 8 槽」这条实现路径。
    target = 0x3AFD30
    img = fake_image([0x1000, 0x2000, 0x3000, 0x1000, 0x2000, 0x3000, target, 0x1000])
    cands = [(0x4000, 8, [0x1000, 0x2000, 0x3000, 0x1000])]
    assert [(h["vtable_rva"], h["slot_index"], h["target_rva"]) for h in slot_hits(img, {target}, cands)] \
        == [(0x4000, 6, target)]


def test_slot_hits_counts_distinct_tables_so_two_shares_of_the_same_target_are_visible():
    target = 0x3B01A0
    img = fake_image([target, 0x1000, 0x2000, 0x3000,
                      target, 0x1000, 0x2000, 0x3000])
    cands = [(0x4000, 4, [target, 0x1000, 0x2000, 0x3000]),
             (0x4020, 4, [target, 0x1000, 0x2000, 0x3000])]
    hits = slot_hits(img, {target}, cands)
    assert sorted({h["vtable_rva"] for h in hits}) == [0x4000, 0x4020]


def test_lea_sites_to_scans_the_whole_text_section_and_returns_instruction_rvas():
    # .text 起 RVA 0x1000,内容里放两条 RIP-relative lea,各自把同一个 RVA 载进寄存器。
    target, text_start = 0x4000, 0x1000
    body = bytearray(b"\xcc" * 0x40)
    for i in (0, 7):
        # 48 8D 0D disp32:disp = target_va - (本条之后那条指令的 VA)
        body[i:i + 7] = b"\x48\x8d\x0d" + struct.pack("<i", target - (text_start + i + 7))
    img = fake_image([0x1000, 0x2000, 0x3000], text_bytes=bytes(body))
    assert lea_sites_to(img, target) == [0x1000, 0x1007]
    assert lea_sites_to(img, 0xDEADBEEF) == []


def test_physical_slots_collapse_the_same_qword_counted_by_overlapping_run_starts():
    # 候选集对同一段指针数组产出多个 run 起点(Task 3 为了让下限集成为子集必须这样构造),
    # 于是「命中 N 张表」里的 N 永远大于真正被写的槽数。§57 的判据用的是后者,所以那个
    # 折叠必须有一个被测的落点,不能只活在一次性脚本里。
    hits = [{'vtable_rva': 0x4000, 'slot_index': 6, 'target_rva': 0x3afd30},
            {'vtable_rva': 0x4028, 'slot_index': 1, 'target_rva': 0x3b01a0},
            {'vtable_rva': 0x4030, 'slot_index': 0, 'target_rva': 0x3b01a0}]
    assert physical_slots(hits) == [0x4030]


def test_parse_candidate_lines_reads_back_what_the_tool_wrote():
    # 往返:同一个 formatter 既是 CLI 产物行也是这里的输入,所以「解析读不回自己写的列」
    # 会直接红,而不是让 --who-tables 静默地拿到空候选集(那会被 §57 读成「没有复制表」)。
    rows = [(0x24b3050, 3, [0x1d08520, 0x1a00, 0x1b00]),
            (0x2606fe0, 8, [0x3afd30, 0x3b01a0, 0x1c00])]
    text = ('# 123 vtable-shaped runs in .rdata, run>=3, NOT filtered by slot[1]\n'
            + '\n'.join(format_candidate_row(*row) for row in rows) + '\n')
    assert parse_candidate_lines(text) == rows


def test_parse_candidate_lines_tolerates_a_truncated_slot_column():
    # §56 之前那版产物只有 slot0..slot2 三列;少一列不是错误,第三列只是用不上的那份
    assert parse_candidate_lines('vtable 0x00004000  run=4  slot0 0x00001000'
                                 '  slot1 0x00002000\n') == [(0x4000, 4, [0x1000, 0x2000])]


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
