"""Tests for global_xrefs.py — synthetic fixtures first, the real exe last.

The synthetic half runs everywhere (CI has no stellaris.exe): handwritten
instruction bytes pin both ends of the `p + 4 <= e <= p + 8` window, the form
classifier's write/read split, the copy-chain follow, and the `.pdata` chain
merge.  The last test reads the pinned 4.4.4 binary and is skipped when no copy
is reachable through `NS_STELLARIS_EXE` / the default chain — it is the one that
says the tool still reproduces
`evidence/analysis/runtime_444_graph_runtime.md` §10.2.
"""

import os
import struct
import subprocess
import sys

import pytest
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from global_xrefs import (BASE, Pdata, candidates_for_global, chain_parent, classify,
                          count_forms, merge_chain_extents, pdata_entries,
                          resolve_exe, scan, select_rows, summary_line)

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
TEXT_RVA = 0x1000
TARGET = 0x4000000          # a data global well outside .text
OFF = 0x100                 # where every fixture instruction sits in the blob


# --- fixture assembly -------------------------------------------------------
#
# Each entry is (instruction bytes with a zero disp32 placeholder, offset of that
# placeholder, instruction length).  The three forms differ in how many bytes
# follow the disp32, which is exactly what the candidate window has to cover:
# 0 (loads, `lea`), 1 (`or dword [rip+d], imm8`) and 4 (`mov dword [rip+d], imm32`).
OR_IMM8 = (b'\x83\x0d' + b'\0' * 4 + b'\x01', 2, 7)              # ends at p+5
MOV_IMM32 = (b'\xc7\x05' + b'\0' * 4 + b'\x02\x00\x00\x00', 2, 10)  # ends at p+8
MOV_EAX = (b'\x8b\x05' + b'\0' * 4, 2, 6)                        # ends at p+4
MOV_STORE_EAX = (b'\x89\x05' + b'\0' * 4, 2, 6)


def assemble(template, tail=b'', target=TARGET, off=OFF):
    """Patch the placeholder disp32 so the instruction resolves to `target`.

    `tail` lands immediately after the instruction (consumers must stay inside
    `classify`'s 12-instruction lookahead window); the nop padding follows it.
    """
    body, disp_at, insn_len = template
    buf = bytearray(b'\x90' * off + body + tail + b'\x90' * 0x40)
    struct.pack_into('<i', buf, off + disp_at, target - (TEXT_RVA + off + insn_len))
    return bytes(buf)


def disassemble(blob, off=OFF):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return list(md.disasm(blob[off:], BASE + TEXT_RVA + off))


class FakeImage:
    """The three members `scan` reads, backed by a synthetic `.text` blob.

    `func_of`/`block_of` return None, so `scan` takes its no-`.pdata` fallback:
    decode from p-2 -- which for these fixtures is the instruction's own entry.
    """

    def __init__(self, text, tva=TEXT_RVA):
        self.text, self.tva = text, tva
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def func_of(self, rva):
        return None

    def block_of(self, rva):
        return None

    def decode(self, begin, end):
        off = begin - self.tva
        return list(self.md.disasm(self.text[off:off + (end - begin)], BASE + begin))


def unwind(flags=0, codes=0, chained=None):
    """One UNWIND_INFO record, exact byte layout (codes padded to an even count)."""
    body = bytearray([1 | (flags << 3), 0, codes, 0])
    body += b'\0' * (codes * 2)
    if codes & 1:
        body += b'\0\0'
    if chained is not None:
        body += struct.pack('<III', *chained)
    return bytes(body)


# --- the candidate window ---------------------------------------------------

@pytest.mark.parametrize('template,ends_at_p_plus', [
    (MOV_EAX, 4),           # lower edge: nothing follows the disp32
    (OR_IMM8, 5),           # the actual set-bit sites (§10.3): imm8 after the disp32
    (MOV_IMM32, 8),         # upper edge: 4 immediate bytes after the disp32
])
def test_candidates_cover_every_disp32_immediate_width(template, ends_at_p_plus):
    hits = candidates_for_global(assemble(template), TEXT_RVA, TARGET)
    assert len(hits) == 1, hits
    p, _v, e = hits[0]
    assert p == TEXT_RVA + OFF + 2
    assert e - p == ends_at_p_plus


@pytest.mark.parametrize('template', [MOV_EAX, OR_IMM8, MOV_IMM32])
@pytest.mark.parametrize('delta', [-1, 1])
def test_a_neighbouring_global_never_confirms_as_a_reference(template, delta):
    # The byte window alone cannot always tell: shifting the target by one moves
    # the implied end by one, and for OR_IMM8/MOV_IMM32 that lands on p+4, still
    # inside the window. What rejects it is the confirmation step (decode and
    # compare the disp), so this is asserted at `scan`, not at the window.
    rows = scan(FakeImage(assemble(template, target=TARGET + delta)), TARGET)
    assert all(r['mnemonic'] == '?' for r in rows), rows
    assert not [r for r in rows if r['form'] != 'other']


def test_candidates_reject_an_end_beyond_the_window():
    # An encoding whose implied end is p+9 is not an instruction boundary of any
    # rip-relative form here; taking the window wider would admit it.
    text = bytearray(b'\x90' * 0x40)
    p = 0x20
    struct.pack_into('<i', text, p, TARGET - (TEXT_RVA + p + 9))
    assert candidates_for_global(bytes(text), TEXT_RVA, TARGET) == []


def test_candidates_reject_an_end_below_the_window():
    # delta=+1 on the load form implies e = p+3. Opening the window down to p+3
    # would make the candidate step admit it (confirmation would still drop it,
    # but every byte position in .text would then need a decode).
    text = assemble(MOV_EAX, target=TARGET + 1)
    p = TEXT_RVA + OFF + 2
    assert TARGET - struct.unpack_from('<i', text, OFF + 2)[0] == p + 3
    assert candidates_for_global(text, TEXT_RVA, TARGET) == []


# --- form classification ----------------------------------------------------

@pytest.mark.parametrize('template,expected', [
    (OR_IMM8, 'set_bit'),
    (MOV_IMM32, 'overwrite_imm'),
    (MOV_STORE_EAX, 'overwrite_reg'),
])
def test_classify_names_writes_by_destination_and_source(template, expected):
    assert classify(disassemble(assemble(template)), 0) == expected


def test_classify_does_not_call_an_or_without_bit0_a_set_bit():
    # `or dword [rip+d], 2` touches the word but does not set bit0 -> `other`.
    template = (b'\x83\x0d' + b'\0' * 4 + b'\x02', 2, 7)
    assert classify(disassemble(assemble(template)), 0) == 'other'


def test_classify_reads_the_shape_off_the_consumer_not_the_load():
    assert classify(disassemble(assemble(MOV_EAX, tail=b'\xc3')), 0) == 'other'
    assert classify(disassemble(assemble(MOV_EAX, tail=b'\x83\xe0\x01')), 0) == 'read_mask'
    assert classify(disassemble(assemble(MOV_EAX, tail=b'\xa9\x01\x00\x00\x00')), 0) == 'read_bit'
    assert classify(disassemble(assemble(MOV_EAX, tail=b'\xa9\x03\x00\x00\x00')), 0) == 'read_mask'


def test_classify_follows_a_copy_chain_to_the_shift():
    # §10.3's consumer body, verbatim: mov eax,[T]; mov ecx,eax; shr ecx,1; test cl,1
    tail = b'\x89\xc1' + b'\xd1\xe9' + b'\xf6\xc1\x01'
    assert classify(disassemble(assemble(MOV_EAX, tail=tail)), 0) == 'read_bit'


def test_classify_keeps_an_unrelated_consumer_out_of_the_neighbour_forms():
    # A load consumed only by `add` is neither a mask nor a bit: `other` is a
    # real answer, not something to fold into the nearest vocabulary word.
    assert classify(disassemble(assemble(MOV_EAX, tail=b'\x83\xc0\x01')), 0) == 'other'


# --- .pdata chain merge -----------------------------------------------------

def test_pdata_entries_reads_12_byte_runtime_function_triples():
    raw = struct.pack('<III', 0x1000, 0x1010, 0x8000) + \
        struct.pack('<III', 0x1100, 0x1120, 0x8010) + b'\0\0\0\0\0'   # trailing partial
    assert pdata_entries(raw) == [(0x1000, 0x1010, 0x8000), (0x1100, 0x1120, 0x8010)]


def test_chain_parent_is_none_without_the_chaininfo_flag():
    assert chain_parent(unwind(flags=2, codes=6)) is None


@pytest.mark.parametrize('codes', [0, 1, 2, 5])
def test_chain_parent_reads_the_record_past_the_padded_unwind_codes(codes):
    blob = unwind(flags=4, codes=codes, chained=(0x1100, 0x1120, 0x8010))
    assert chain_parent(blob) == (0x1100, 0x1120, 0x8010)


SEVEN_BLOCKS = [        # the shape of §1.5's delete routine: one function, 7 fragments
    (0x1000, 0x1040, 2),    # root, unchained
    (0x1100, 0x1120, 4),
    (0x1120, 0x1130, 4),
    (0x1200, 0x1210, 4),
    (0x1210, 0x1230, 4),
    (0x1300, 0x1310, 4),
    (0x1310, 0x1330, 4),
]


def _seven_block_pdata():
    entries, blobs = [], {}
    for i, (begin, end, flags) in enumerate(SEVEN_BLOCKS):
        u = 0x8000 + i * 0x40
        chained = SEVEN_BLOCKS[i - 1] if flags & 4 else None
        entries.append((begin, end, u))
        blobs[u] = unwind(flags=flags, codes=2, chained=chained)
    raw = b''.join(struct.pack('<III', *e) for e in entries)
    return Pdata(raw, lambda rva, n: blobs.get(rva, b'')[:n])


def test_pdata_merges_a_seven_block_chain_into_one_function():
    p = _seven_block_pdata()
    assert p.func_of(0x1305) == (0x1000, 0x1330)      # min begin .. max end
    assert p.func_of(0x1005) == (0x1000, 0x1330)
    assert p.func_of(0x1331) is None


def test_pdata_keeps_the_fragment_for_decoding_but_reports_the_merge():
    # Decoding has to start at the fragment's own entry: the bytes between two
    # fragments are not this function's code.
    p = _seven_block_pdata()
    assert p.block_of(0x1305) == (0x1300, 0x1310)
    assert p.func_of(0x1305) == (0x1000, 0x1330)


def test_merge_chain_extents_leaves_an_unchained_function_alone():
    entries = [(0x1000, 0x1010, 0x8000), (0x2000, 0x2040, 0x8040)]
    assert merge_chain_extents(entries, [None, None]) == [(0x1000, 0x1010),
                                                          (0x2000, 0x2040)]


# --- output shape -----------------------------------------------------------

ROWS = [{'insn_rva': 0x1000 + i, 'fn_start': 0x1000, 'fn_end': 0x1100,
         'form': 'set_bit' if i < 3 else 'other', 'mnemonic': 'or',
         'op_str': 'dword ptr [rip + 1], 1'} for i in range(5)]


def test_select_rows_prints_everything_by_default():
    assert select_rows(ROWS, 0) == (ROWS, 0)


def test_select_rows_truncates_only_when_asked_and_counts_what_it_dropped():
    shown, omitted = select_rows(ROWS, 2)
    assert shown == ROWS[:2] and omitted == 3
    assert select_rows(ROWS, 99) == (ROWS, 0)


def test_summary_line_matches_the_forensics_volumes_wording_and_only_grows_on_truncation():
    counts = count_forms(ROWS)
    assert summary_line(counts, len(ROWS)) == (
        'refs=5 set_bit=3 overwrite_imm=0 overwrite_reg=0 '
        'read_mask=0 read_bit=0 other=2')
    assert summary_line(counts, len(ROWS), 3).endswith('other=2 truncated=3')


def test_resolve_exe_prefers_the_first_readable_candidate(monkeypatch, tmp_path):
    fake = tmp_path / 'stellaris.exe'
    fake.write_bytes(b'MZ')
    monkeypatch.setattr('global_xrefs.CANDIDATES', [None, str(fake)])
    assert resolve_exe() == str(fake)
    monkeypatch.setattr('global_xrefs.CANDIDATES', [str(tmp_path / 'gone.exe')])
    assert resolve_exe() is None


# --- the real binary (skipped on CI) ---------------------------------------

def run_cli(argv):
    """Run the tool, returning (rows, summary dict)."""
    out = subprocess.run([sys.executable, os.path.join(SCRIPTS, 'global_xrefs.py'), *argv],
                         capture_output=True, text=True, check=True).stdout
    rows, summary = [], {}
    for line in out.splitlines():
        if line.startswith('#'):
            continue
        if line.startswith('refs='):
            summary = {k: int(v) for k, v in
                       (tok.split('=', 1) for tok in line.split())}
            continue
        parts = line.split('\t')
        rows.append({'insn_rva': int(parts[0], 16), 'fn_start': int(parts[1], 16),
                     'fn_end': int(parts[2], 16), 'form': parts[3]})
    return rows, summary


@pytest.mark.skipif(resolve_exe() is None, reason="stellaris.exe not available")
def test_296cc68_reference_set_matches_the_forensics_volume():
    rows, out = run_cli(['0x296CC68'])
    assert out['refs'] == 24
    assert out['set_bit'] == 17 and out['overwrite_imm'] == 4 and out['overwrite_reg'] == 1
    assert out['read_mask'] + out['read_bit'] == 2
    assert out['other'] == 0
    assert 'truncated' not in out           # 默认全打印,§10 就是差一点被 25 行上限漏站点
    # Chain merge against the real table: §10.2's raw block for this site is the
    # delete routine's tail (0x8bbd2d..0x8bbd8a, 7 fragments in §1.5); the merged
    # logical function is 0x8bbc20..0x8bbd8a, and §10.2's prose says exactly that
    # for 0x8bbd90, whose site 0x8bbe45 must come back as 0x8bbd90..0x8bbe63.
    by_site = {r['insn_rva']: r for r in rows}
    assert (by_site[0x8bbd65]['fn_start'], by_site[0x8bbd65]['fn_end']) == (0x8bbc20, 0x8bbd8a)
    assert (by_site[0x8bbe45]['fn_start'], by_site[0x8bbe45]['fn_end']) == (0x8bbd90, 0x8bbe63)
