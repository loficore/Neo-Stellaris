"""Pure-function tests for chain_drift.py — synthetic PE, no game, no disk.

Fixtures build a PE by hand (same header field layout as test_rttibatch.fake_image)
so every locator kind is pinned to addresses a reader verifies by eye.  The
self-证 fence at the bottom reads the pinned 4.4.4 binary and is skipped when no
copy is reachable through NS_STELLARIS_EXE / the default chain.
"""

import os
import struct

import pytest

from chain_drift import (Image, Locator, LocatorError, ManifestError, Node, NodeResult, match_bytes, parse_bytes_pattern, parse_locator,
                         parse_manifest, pdata_index, pe_version, Resolver, substitute_node_refs,
                         decide, evaluate_chain, exit_code, format_report, locator_mix,
                         REPORT_COLUMNS, find_cstring, find_exe_or_none, load_image, main,
                         mask_rel32, report_path_for, memory_disp_set)

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
RAW_START = 0x400   # section table ends at 0x1A4 + 40*n; must stay below the raw data


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
        blob[off:off + 8] = name.encode().ljust(8, b"\0")
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


def _lea(site_va, target_va):
    """48 8D 0D <disp32> —— 指向 target 的 lea rcx。"""
    return b"\x48\x8d\x0d" + struct.pack("<i", target_va - (site_va + 7))


def test_find_cstring_returns_the_start_of_the_containing_string():
    # 后缀命中只说明"这串出现在这里"；代码 lea 指向整串第一个字节，所以返回值必须是
    # 包含该后缀的那个 C 串起点，而不是后缀本身。
    img = fake_pe([(".rdata", 0x4000, b"a.cpp\x00C:\\src\\b.cpp\x00")])
    assert find_cstring(img, "a.cpp") == [0x4000]
    assert find_cstring(img, "b.cpp") == [0x4000 + 6]


def test_strref_anchors_at_the_cstring_start_when_the_needle_is_only_a_suffix():
    # 真实镜像存的是 C:\mnt\gsg\...\source\scriptedeffect.cpp，代码 lea 指向整串起点
    # 0x25181d0（不是后缀 0x25181fe）。后缀命中回溯失败时这条会得 0 个候选。
    path = b"C:\\mnt\\gsg\\stellaris\\augustus\\augustus\\source\\scriptedeffect.cpp\x00"
    code = bytearray(b"\xcc" * 0x40)
    code[0x10:0x17] = _lea(0x1010, 0x4000)
    img = fake_pe([(".text", 0x1000, bytes(code)),
                   (".pdata", 0x3000, struct.pack("<III", 0x1000, 0x1040, 0)),
                   (".rdata", 0x4000, path)])
    assert Resolver(img, pdata_index(img)).resolve(
        Locator("strref", "scriptedeffect.cpp"), {}) == [0x1000]


def test_strref_resolves_to_the_enclosing_function():
    target = 0x4000 + 4                       # ".cpp" 串在 .rdata
    code = b"\xcc" * 0x10 + _lea(0x1010, target) + b"\xcc" * 0x20
    img = fake_pe([(".text", 0x1000, code),
                   (".pdata", 0x3000, struct.pack("<III", 0x1000, 0x1100, 0)),
                   (".rdata", 0x4000, b"abc\x00scriptedeffect.cpp\x00")])
    assert Resolver(img, pdata_index(img)).resolve(
        Locator("strref", "scriptedeffect.cpp"), {}) == [0x1000]


def test_strref_calls_refinement_rejects_a_function_that_does_not_call_the_rva():
    target = 0x4004                              # ".rdata" 里 "x.cc" 的起点
    code = bytearray(b"\xcc" * 0x40)
    code[0x10:0x17] = _lea(0x1010, target)
    secs = [(".text", 0x1000, bytes(code)),
            (".pdata", 0x3000, struct.pack("<III", 0x1000, 0x1040, 0)),
            (".rdata", 0x4000, b"abc\x00x.cc\x00")]
    img = fake_pe(secs)
    assert Resolver(img, pdata_index(img)).resolve(
        Locator("strref", "x.cc", (("calls", "0x1d13270"),)), {}) == []

    code2 = bytearray(code)
    code2[0x20:0x25] = b"\xe8" + struct.pack("<i", 0x1d13270 - (0x1020 + 5))
    img2 = fake_pe([(".text", 0x1000, bytes(code2)), secs[1], secs[2]])
    assert Resolver(img2, pdata_index(img2)).resolve(
        Locator("strref", "x.cc", (("calls", "0x1d13270"),)), {}) == [0x1000]


def test_callshape_matches_the_disp_on_any_base_register():
    # FF /2 disp8 is `call [reg+disp8]` whatever the register: the recipe names a
    # displacement, not rax, so an rcx-only site must still be returned.
    code = bytearray(b"\xcc" * 0x80)
    code[0x10:0x13] = b"\xff\x51\x48"         # call qword ptr [rcx+0x48]
    img = fake_pe([(".text", 0x1000, bytes(code)),
                   (".pdata", 0x3000, struct.pack("<III", 0x1000, 0x1080, 0))])
    assert Resolver(img, pdata_index(img)).resolve(
        Locator("callshape", "callptr+0x48"), {}) == [0x1000]


def test_callshape_callptr_disp_returns_every_enclosing_function():
    code = bytearray(b"\xcc" * 0x80)
    code[0x10:0x13] = b"\xff\x50\x08"         # call qword ptr [rax+8]
    img = fake_pe([(".text", 0x1000, bytes(code)),
                   (".pdata", 0x3000, struct.pack("<III", 0x1000, 0x1080, 0))])
    r = Resolver(img, pdata_index(img))
    assert r.resolve(Locator("callshape", "callptr+0x8"), {}) == [0x1000]
    assert r.resolve(Locator("callshape", "callptr+0x48"), {}) == []


def test_vtable_locator_filters_on_the_requested_slot():
    img = fake_pe([(".text", 0x1000, b"\xcc" * 0x40),
                   (".rdata", 0x4000, struct.pack("<4Q", 0x140000000 + 0x1000,
                                                  0x140000000 + 0x1020,
                                                  0x140000000 + 0x1030,
                                                  0x140000000 + 0x1040))])
    r = Resolver(img, pdata_index(img))
    assert r.resolve(Locator("vtable", "slot1", (("eq", "0x1020"),)), {}) == [0x4000]
    assert r.resolve(Locator("vtable", "slot2", (("eq", "0x1020"),)), {}) == []


def test_node_reference_is_substituted_before_resolution():
    results = {"base_execute": NodeResult(node="base_execute", verdict="moved",
                                          got=0x1D08600, candidates=(0x1D08600,))}
    assert substitute_node_refs(Locator("vtable", "slot1", (("eq", "@node:base_execute"),)),
                                results).params == (("eq", "0x1d08600"),)


def test_node_reference_to_a_zero_node_raises_lookup_error():
    results = {"base_execute": NodeResult(node="base_execute", verdict="zero",
                                          got=None, candidates=())}
    with pytest.raises(LookupError):
        substitute_node_refs(Locator("vtable", "slot1", (("eq", "@node:base_execute"),)), results)


def test_bytes_pattern_treats_question_marks_as_wildcards():
    value, mask = parse_bytes_pattern("48 89 ?? 24")
    assert value == b"\x48\x89\x00\x24"
    assert mask == b"\xff\xff\x00\xff"
    img = fake_pe([(".text", 0x1000, b"\xcc" * 8 + b"\x48\x89\x5c\x24" + b"\xcc" * 8)])
    assert match_bytes(img, (value, mask), 0x1000, 0x1014) == [0x1008]


def test_global_locator_intersects_rip_targets_of_both_functions():
    gva = 0x4000
    def _mov(site, target):
        return b"\x48\x8b\x05" + struct.pack("<i", target - (site + 7))
    code = bytearray(b"\xcc" * 0x80)
    code[0x10:0x17] = _mov(0x1010, gva)
    code[0x40:0x47] = _mov(0x1040, gva)
    img = fake_pe([(".text", 0x1000, bytes(code)),
                   (".pdata", 0x3000, struct.pack("<III", 0x1000, 0x1040, 0)
                                + struct.pack("<III", 0x1040, 0x1080, 0)),
                   (".rdata", 0x4000, b"\x00" * 8)])
    results = {"w": NodeResult("w", "found", 0x1000, (0x1000,)),
               "r": NodeResult("r", "found", 0x1040, (0x1040,))}
    loc = Locator("global", "-", (("writes_by", "@node:w"), ("reads_by", "@node:r")))
    assert Resolver(img, pdata_index(img)).resolve(loc, results) == [0x4000]


def test_decide_found_when_the_single_candidate_matches_expect():
    assert decide("address", "0x1d13270", [0x1D13270]) == NodeResult("", "found", 0x1D13270, ())


def test_decide_moved_keeps_the_delta_visible():
    r = decide("address", "0x1d13270", [0x1D133A0])
    assert (r.verdict, r.got) == ("moved", 0x1D133A0)


def test_decide_ambiguous_never_picks_expect_out_of_several_candidates():
    r = decide("address", "0x1d13270", [0x1D13270, 0x1D132A0])
    assert (r.verdict, r.got) == ("ambiguous", None)
    assert r.candidates == (0x1D13270, 0x1D132A0)


def test_decide_zero_and_structure_without_expect():
    assert decide("address", "0x1", []).verdict == "zero"
    assert decide("structure", "-", [0x2000]).verdict == "found"


def _nodes():
    return [Node("register", "a", "address", "bytes:90", "0x1000", (), "", "x"),
            Node("register", "b", "address", "bytes:90", "0x2000", ("a",), "", "x"),
            Node("register", "s", "structure", "", "-", (), "", "x")]


class _StubResolver:
    def __init__(self, table):
        self.table = table

    def resolve(self, loc, results):
        if loc.kind == "bytes":
            return self.table[loc.arg]
        return []


def test_evaluate_chain_is_green_when_every_reachable_node_is_found():
    r = _StubResolver({"90": [0x1000], "91": [0x2000]})
    a, _b, s = _nodes()
    nodes = [a, Node("register", "b", "address", "bytes:91", "0x2000", ("a",), "", "x"), s]
    color, results, unverified = evaluate_chain(nodes, r)
    assert color == "green"
    assert unverified == ["s"]
    assert [x.verdict for x in results] == ["found", "found", "skipped_structure"]


def test_evaluate_chain_is_yellow_when_only_moved():
    color, _, _ = evaluate_chain(_nodes()[:2], _StubResolver({"90": [0x1010], "91": [0x2000]}))
    assert color == "yellow"


def test_evaluate_chain_short_circuits_dependents_to_not_run():
    color, results, _ = evaluate_chain(_nodes()[:2], _StubResolver({"90": [], "91": [0x2000]}))
    assert color == "red"
    assert [x.verdict for x in results] == ["zero", "not_run"]


def test_format_report_emits_meta_lines_then_header_then_stable_rows():
    nodes = [Node("register", "a", "address", "bytes:90", "0x1000", (), "token_readback", "x")]
    results = [NodeResult("a", "moved", 0x1030, (0x1030,))]
    text = format_report({"target_version": "4.4.4", "exe_sha256": "ab" * 32},
                         nodes, results)
    lines = text.splitlines()
    assert lines[0] == "# manifest=evidence/xrefs/chain_manifest_4_4_4.tsv"
    assert any(line.startswith("# locators: ") for line in lines)
    header = next(i for i, line in enumerate(lines) if line.startswith("chain\t"))
    assert lines[header].split("\t") == list(REPORT_COLUMNS)
    assert lines[header + 1].split("\t")[:7] == [
        "register", "a", "address", "moved", "0x1000", "0x1030", "+0x30"]


def test_locator_mix_counts_every_kind_in_a_fixed_order():
    nodes = [Node("register", "a", "address", "strref:x.cc", "0x1", (), "", "x"),
             Node("register", "b", "address", "bytes:90", "0x2", (), "", "x"),
             Node("register", "c", "structure", "", "-", (), "", "x")]
    assert locator_mix(nodes) == "strref=1 callshape=0 vtable=0 global=0 bytes=1 structure=1"


def test_exit_code_maps_red_to_two_and_everything_else_to_zero():
    assert exit_code(["green", "yellow"]) == 0
    assert exit_code(["green", "red"]) == 2
    assert exit_code([]) == 2


def test_mask_rel32_wildcards_call_and_jump_displacements_only():
    assert mask_rel32(bytes.fromhex("48895c2408e800000000")) == "48 89 5c 24 08 e8 ?? ?? ?? ??"
    assert mask_rel32(bytes.fromhex("7f32488bcb")) == "7f 32 48 8b cb"


def test_report_path_is_versioned():
    assert report_path_for("/x/stellaris.exe", "4.4.4").endswith("chain_drift_4.4.4.tsv")


def test_main_rejects_unknown_chain_name(tmp_path, capsys):
    man = tmp_path / "m.tsv"
    man.write_text("chain\tnode\tclass\tlocator\texpect\tdepends_on\twitness\tevidence\n"
                   "register\ta\taddress\tbytes:90\t0x1\t\t\tx\n")
    assert main(["--exe", "/nonexistent.exe", "--manifest", str(man), "--chain", "nope"]) == 3


def test_main_rejects_writing_the_report_over_the_manifest(tmp_path):
    man = tmp_path / "m.tsv"
    man.write_text("chain\tnode\tclass\tlocator\texpect\tdepends_on\twitness\tevidence\n")
    assert main(["--exe", "/nonexistent.exe", "--manifest", str(man),
                 "--report", str(man)]) == 3


def test_main_reports_environment_error_when_exe_is_missing(tmp_path):
    man = tmp_path / "m.tsv"
    man.write_text("chain\tnode\tclass\tlocator\texpect\tdepends_on\twitness\tevidence\n")
    assert main(["--exe", str(tmp_path / "nope.exe"), "--manifest", str(man)]) == 3


MANIFEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence", "xrefs",
                        "chain_manifest_4_4_4.tsv")


def _chain_nodes(chain):
    with open(MANIFEST, encoding="utf-8") as fh:
        return [node for node in parse_manifest(fh.read()) if node.chain == chain]


@pytest.mark.skipif(find_exe_or_none() is None, reason="stellaris.exe not available")
def test_register_chain_is_green_on_the_pinned_4_4_4_binary():
    nodes = _chain_nodes("register")
    img = load_image(find_exe_or_none())
    color, results, unverified = evaluate_chain(nodes, Resolver(img, pdata_index(img)))
    assert color == "green", [r for r in results if r.verdict not in ("found", "skipped_structure")]
    assert unverified == ["token_db_object", "descriptor_array", "class_info_trigger",
                          "class_info_effect", "donor_docstring_trigger",
                          "donor_docstring_effect"]


@pytest.mark.skipif(find_exe_or_none() is None, reason="stellaris.exe not available")
def test_dispatch_chain_is_green_on_the_pinned_4_4_4_binary():
    nodes = _chain_nodes("dispatch")
    img = load_image(find_exe_or_none())
    color, results, unverified = evaluate_chain(nodes, Resolver(img, pdata_index(img)))
    assert color == "green", [r for r in results if r.verdict not in ("found", "skipped_structure")]
    assert unverified == ["donor_vtable"]


@pytest.mark.skipif(find_exe_or_none() is None, reason="stellaris.exe not available")
@pytest.mark.parametrize("chain,expected_unverified", [
    ("state_write", ["class_info_set_variable", "docstring_set_variable",
                     "field_name_string", "field_value_cell", "field_parse_state"]),
    ("graph", ["edge_table_global", "edge_container_offsets", "dirty_mask_global"]),
    ("scope", ["scope_mask_field", "scope_id_field", "country_scope_vtable",
               "dispatch_passes_scope_in_rdx"]),
])
def test_remaining_chains_are_green_with_their_structure_gaps(chain, expected_unverified):
    nodes = _chain_nodes(chain)
    img = load_image(find_exe_or_none())
    color, results, unverified = evaluate_chain(nodes, Resolver(img, pdata_index(img)))
    assert color == "green", [r for r in results if r.verdict not in ("found", "skipped_structure")]
    assert unverified == expected_unverified


def test_memory_disp_set_survives_a_data_island_instead_of_raising():
    # skipdata 是故意开的(解码缺口不能截断扫描),代价是缺口以 id==0 的伪指令出现,
    # 读它的 operands 会抛 CS_ERR_SKIPDATA。以前这一抛会让整条链崩掉 —— 拿不到判决,
    # 而「这个函数里有数据岛」恰恰是 reads= 谓词该看见的事实。
    code = b"\x48\x8b\x41\x38" + b"\x06\x06\x06" + b"\x48\x8b\x51\x40"
    img = fake_pe([(".text", 0x1000, code)])
    assert memory_disp_set(img, 0x1000, 0x1000 + len(code)) == {0x38, 0x40}


def test_parse_locator_rejects_a_pattern_with_no_fixed_byte():
    # An all-wildcard pattern matches every offset in the image, so a node carrying
    # one would report `found` on any build at all — the same defect as `bytes:`.
    with pytest.raises(LocatorError):
        parse_locator("bytes:?? ??")


def test_parse_manifest_rejects_an_address_node_without_a_hex_expectation():
    text = HEADER + ("register\ta\taddress\tbytes:90\tnot-an-rva\t\t\tx\n")
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert exc.value.line_no == 2
