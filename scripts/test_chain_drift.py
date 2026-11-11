"""Pure-function tests for chain_drift.py — synthetic PE, no game, no disk.

Fixtures build a PE by hand (same header field layout as test_rttibatch.fake_image)
so every locator kind is pinned to addresses a reader verifies by eye.  The
self-证 fence at the bottom reads the pinned 4.4.4 binary and is skipped when no
copy is reachable through NS_STELLARIS_EXE / the default chain.
"""

import struct

import pytest

from chain_drift import (Image, LocatorError, ManifestError, Node, parse_locator,
                         parse_manifest, pdata_index, pe_version)

HEADER = ("chain\tnode\tclass\tlocator\texpect\tdepends_on\twitness\tevidence\n")


def test_parse_manifest_reads_every_column_and_skips_comments():
    text = ("# chain drift manifest\n"
            "# 注释行不产生 Node\n" + HEADER +
            "register\tget_scripted_effect\taddress\tstrref:scriptedeffect.cpp\t0x89f960\t\ttoken_readback\tc1 §27\n")
    assert parse_manifest(text) == [
        Node(chain="register", node="get_scripted_effect", cls="address",
             locator="strref:scriptedeffect.cpp", expect="0x89f960",
             depends_on=(), witness="token_readback", evidence="c1 §27")]


def test_parse_manifest_splits_depends_on_on_commas():
    text = HEADER + ("register\ta\taddress\tbytes:90\t0x1\t\t\tx\n"
                     "register\tb\taddress\tbytes:90\t0x2\t\t\tx\n"
                     "register\tc\taddress\tbytes:90\t0x3\ta,b\t\tx\n")
    assert parse_manifest(text)[2].depends_on == ("a", "b")


def test_parse_manifest_rejects_duplicate_node_in_the_same_chain_with_line_number():
    text = HEADER + ("register\ta\taddress\tbytes:90\t0x1\t\t\tx\n"
                     "register\ta\taddress\tbytes:90\t0x2\t\t\tx\n")
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert exc.value.line_no == 3
    assert "duplicate node" in exc.value.message


def test_parse_manifest_allows_the_same_node_name_in_two_chains():
    text = HEADER + ("register\ta\taddress\tbytes:90\t0x1\t\t\tx\n"
                     "dispatch\ta\taddress\tbytes:90\t0x2\t\t\tx\n")
    assert len(parse_manifest(text)) == 2


def test_parse_manifest_rejects_unknown_class_and_wrong_column_count():
    for bad in ("register\ta\tbogus\tbytes:90\t0x1\t\t\tx\n",
                "register\ta\taddress\tbytes:90\n"):
        with pytest.raises(ManifestError) as exc:
            parse_manifest(HEADER + bad)
        assert exc.value.line_no == 2


def test_parse_locator_keeps_kind_argument_and_raw_parameters():
    loc = parse_locator("strref:effect_impl.cpp@calls=0x1d13270@reads=0x38")
    assert loc.kind == "strref"
    assert loc.arg == "effect_impl.cpp"
    assert loc.params == (("calls", "0x1d13270"), ("reads", "0x38"))


def test_parse_locator_splits_a_bytes_confirmation_chain():
    loc = parse_locator("strref:scriptedeffect.cpp&bytes:48 89 5c 24 ??")
    assert loc.kind == "strref"
    assert [c.kind for c in loc.confirms] == ["bytes"]
    assert loc.confirms[0].arg == "48 89 5c 24 ??"


def test_parse_locator_collects_node_references_from_the_whole_expression():
    loc = parse_locator("global:writes_by=@node:effect_db_init,reads_by=@node:bst_insert_effect")
    assert loc.kind == "global"
    assert loc.node_refs == ("effect_db_init", "bst_insert_effect")


def test_parse_locator_rejects_unknown_kind_and_empty_pattern():
    for bad in ("rva:0x1d13270", "bytes:", "bytes:   ", "vtable:"):
        with pytest.raises(LocatorError):
            parse_locator(bad)


def test_parse_locator_rejects_a_tab_inside_a_pattern():
    with pytest.raises(LocatorError):
        parse_locator("bytes:48\t89")


def test_parse_manifest_allows_backward_references_only():
    ok = HEADER + ("register\ta\taddress\tbytes:90\t0x1\t\t\tx\n"
                   "register\tb\taddress\tbytes:90\t0x2\ta\t\tx\n")
    assert parse_manifest(ok)[1].depends_on == ("a",)

    # depends_on 前向引用
    with pytest.raises(ManifestError) as exc:
        parse_manifest(HEADER + ("register\ta\taddress\tbytes:90\t0x1\tb\t\tx\n"
                                 "register\tb\taddress\tbytes:90\t0x2\t\t\tx\n"))
    assert exc.value.line_no == 2 and "forward" in exc.value.message

    # locator 里的 @node: 前向引用
    with pytest.raises(ManifestError) as exc:
        parse_manifest(HEADER + ("register\ta\taddress\tvtable:slot1==@node:b\t0x1\t\t\tx\n"
                                 "register\tb\taddress\tbytes:90\t0x2\t\t\tx\n"))
    assert exc.value.line_no == 2 and "forward" in exc.value.message


HEADER_SIZE = 0x100
RAW_START = 0x200


def fake_pe(sections, base=0x140000000):
    """Build a PE from [(name, rva, bytes)] with the header fields Image.__init__ reads.

    Same field layout as test_rttibatch.fake_image, generalised to any number of
    named sections: e_lfanew=0x100, SizeOfOptionalHeader=0x68, VirtualSize ==
    SizeOfRawData, raw bytes packed from 0x200 in declaration order.
    """
    blob = bytearray(RAW_START + sum(len(data) for _n, _va, data in sections))
    struct.pack_into("<I", blob, 0x3C, HEADER_SIZE)            # e_lfanew
    blob[HEADER_SIZE:HEADER_SIZE + 4] = b"PE\0\0"
    struct.pack_into("<H", blob, HEADER_SIZE + 6, len(sections))   # NumberOfSections
    struct.pack_into("<H", blob, HEADER_SIZE + 20, 0x68)          # SizeOfOptionalHeader
    struct.pack_into("<H", blob, HEADER_SIZE + 24, 0x20B)         # PE32+
    struct.pack_into("<Q", blob, HEADER_SIZE + 24 + 0x18, base)   # ImageBase
    secs = HEADER_SIZE + 24 + 0x68
    raw = RAW_START
    for i, (name, va, data) in enumerate(sections):
        off = secs + i * 40
        blob[off:off + 8] = name.encode()
        struct.pack_into("<I", blob, off + 8, len(data))       # VirtualSize
        struct.pack_into("<I", blob, off + 12, va)             # VirtualAddress
        struct.pack_into("<I", blob, off + 16, len(data))      # SizeOfRawData
        struct.pack_into("<I", blob, off + 20, raw)            # PointerToRawData
        blob[raw:raw + len(data)] = data
        raw += len(data)
    return Image(bytes(blob))


def test_pdata_index_resolves_the_enclosing_function():
    pdata = struct.pack("<III", 0x1000, 0x1100, 0x2000) + struct.pack("<III", 0x1100, 0x1200, 0x2010)
    img = fake_pe([(".text", 0x1000, b"\xcc" * 0x200), (".pdata", 0x3000, pdata)])
    idx = pdata_index(img)
    assert idx.func_of(0x10FF) == (0x1000, 0x1100)
    assert idx.func_of(0x1100) == (0x1100, 0x1200)
    assert idx.func_of(0x1200) is None
    assert idx.func_of(0x0FFF) is None


def test_pe_version_reads_fixed_file_info_and_falls_back_to_unknown():
    fixed = struct.pack("<IIII", 0xFEEF04BD, 0x00010000, 0x00040004, 0x00040005)
    assert pe_version(b"\x00" * 32 + fixed) == "4.4.4.5"
    assert pe_version(b"\x00" * 64) == "unknown"
