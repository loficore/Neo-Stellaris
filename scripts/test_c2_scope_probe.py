"""Pure-function tests for c2_scope_probe.py — no game, no Windows API.

Fixtures mirror the DLL contract: Entry is 120 bytes with the layout pinned by
src/dll/c2/scope_probe.zig, and the layout words are [120, 56, 256, 511, 2].
"""

import inspect
import struct

import pytest

import c2_scope_probe as scope
from c2_scope_probe import (
    D2_VERDICTS, DEPTH2_PER_SOURCE, EVIDENCE_D2_VERDICTS,
    _entry_roots, _region_verdicts, caller_site_estimate, classify,
    classify_depth2, classify_region, collect_region_addrs, d2_meta_rows,
    decode_entry, decode_layout, decode_stats,
    exit_code_for, find_shared_cells, follow_chain, follow_depth2,
    follow_object, follow_roots,
    image_end_from_header, install_decision, load_call_census,
    load_vtable_map, plan_depth2, plausible_user_ptr, poll_done, region_rows,
    summarize,
    write_tsv,
)

BEGIN_REGION_ROW_LITERAL = "region" + "\t"


def _entry(**kw):
    base = {
        "valid": 1, "lexer": 0, "self_vtable_rva": 0xA, "shim_rva": 0x10,
        "token_id": 1, "caller_rva": 0x24BD25, "self_ptr": 0x100,
        "ctx_ptr": 0x1000, "ctx_words": [0] * 8, "arg3": 0, "arg4": 0,
    }
    base.update(kw)
    return base


def _reader_from(mapping):
    def read(addr, size):
        for base, blob in mapping.items():
            if base <= addr and addr + size <= base + len(blob):
                off = addr - base
                return blob[off:off + size]
        return None
    return read


def test_decode_layout_returns_pinned_values():
    assert decode_layout([120, 56, 256, 511, 2]) == {
        "entry": 120, "stats": 56, "ring": 256, "mask": 511, "version": 2,
    }


def test_decode_layout_rejects_unknown_version():
    with pytest.raises(ValueError):
        decode_layout([120, 56, 256, 511, 1])


def test_decode_layout_rejects_wrong_entry_size():
    with pytest.raises(ValueError):
        decode_layout([104, 56, 256, 511, 2])


def test_decode_entry_reads_all_fields():
    raw = struct.pack(
        "<BBHIIII4xQQ8Q2Q",
        1, 0, 0, 0x1234, 0x5678, 0x1F3, 0x24BD25,
        0x7FF700001000, 0x7FF700002000,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x1111222233334444, 0x5555666677778888,
    )
    assert len(raw) == 120
    e = decode_entry(raw)
    assert e["valid"] == 1
    assert e["lexer"] == 0
    assert e["self_vtable_rva"] == 0x1234
    assert e["shim_rva"] == 0x5678
    assert e["token_id"] == 0x1F3
    assert e["caller_rva"] == 0x24BD25
    assert e["self_ptr"] == 0x7FF700001000
    assert e["ctx_ptr"] == 0x7FF700002000
    assert e["ctx_words"][0] == 0x11
    assert e["ctx_words"][6] == 0x77
    assert e["ctx_words"][7] == 0x88
    assert e["arg3"] == 0x1111222233334444
    assert e["arg4"] == 0x5555666677778888


def test_decode_entry_rejects_short_buffer():
    with pytest.raises(ValueError):
        decode_entry(b"\x00" * 119)


def test_decode_stats_parses_every_key():
    text = ("  calls=7 samples=2 invalid_self=1 invalid_ctx=0 lexer=1 "
            "x_nonzero=1 patch_size=16 installed=1 verified=-1  \n")
    assert decode_stats(text) == {
        "calls": 7, "samples": 2, "invalid_self": 1, "invalid_ctx": 0,
        "lexer": 1, "x_nonzero": 1, "patch_size": 16, "installed": 1,
        "verified": -1,
    }


def test_caller_row_key_is_return_rva_and_estimate_is_detail(tmp_path):
    entries = [_entry(caller_rva=0x1C4369E), _entry(caller_rva=0x1C4369E)]
    path = str(tmp_path / "probe.tsv")
    write_tsv(path, summarize(entries, {}, {}, {}, {}), meta={})
    line = next(l for l in open(path, encoding="utf-8") if l.startswith("caller"))
    cols = line.rstrip("\n").split("\t")
    assert cols[1] == "0x1c4369e"                              # 键 = 返回 RVA
    assert "ret=0x1c4369e" in cols[3] and "est_site=0x1c43699" in cols[3]


def test_estimate_is_five_bytes_only_for_the_rel32_form():
    assert caller_site_estimate(0x1C4369E) == 0x1C43699
    assert caller_site_estimate(0x4) is None      # 不够长就不估值(原来是 raise ValueError)


def test_load_call_census_indexes_every_site(tmp_path):
    path = tmp_path / "census.tsv"
    path.write_text(
        "# func_start\tfunc_end\tcaller_count\tsrc_files\tsite\trdx_origin\tevidence\n"
        "0x24ab30\t0x24d4c5\t16\t-\t0x24bd20\tother\tmov rdx,rdi @0x24bd13\n"
        "0x69e1c0\t0x69e200\t1\t-\t0x69e1e2\tincoming_arg\tmov rdx,rbx\n",
        encoding="utf-8",
    )
    census = load_call_census(path)
    assert set(census) == {0x24BD20, 0x69E1E2}
    assert census[0x24BD20]["func"] == 0x24AB30
    assert census[0x69E1E2]["origin"] == "incoming_arg"


def test_follow_chain_reads_x_s_id_and_object():
    mapping = {
        0x1030: struct.pack("<Q", 0x2000),
        0x2008: struct.pack("<Q", 0x3000),
        0x3000: struct.pack("<Q", 0x2606FE0),
        0x3008: struct.pack("<I", 4242),
        0x3020: struct.pack("<Q", 0x4000),
    }
    chain = follow_chain(_reader_from(mapping), 0x1000)
    assert chain["x"] == 0x2000
    assert chain["s"] == 0x3000
    assert chain["s_vptr"] == 0x2606FE0
    assert chain["id"] == 4242
    assert chain["object"] == 0x4000
    assert chain["ok"] is True


def test_follow_chain_reports_unreadable_x():
    chain = follow_chain(lambda addr, size: None, 0x1000)
    assert chain["x"] is None
    assert not chain["ok"]


def test_follow_chain_reports_unreadable_s():
    mapping = {0x1030: struct.pack("<Q", 0x2000)}
    chain = follow_chain(_reader_from(mapping), 0x1000)
    assert chain["s"] is None
    assert not chain["ok"]


def test_summarize_counts_callers_and_identities():
    entries = [
        _entry(),
        _entry(ctx_ptr=0x2000),
        _entry(self_vtable_rva=0xB, caller_rva=0x1005),
    ]
    summary = summarize(entries, {"calls": 100, "samples": 3}, {}, {}, {})
    assert summary["by_caller"] == {0x24BD20: 2, 0x1000: 1}
    assert summary["distinct_vtables"] == 2
    assert summary["valid"] == 3
    assert summary["calls"] == 100


def test_summarize_joins_census_onto_the_caller_row():
    # The census join runs on the -5 estimate (est_site), keyed per return RVA;
    # §60's evidence work reads func/origin off that row, so pin the join.
    census = {0x24BD20: {"func": 0x24AB30, "origin": "incoming_arg"}}
    summary = summarize([_entry()], {"calls": 1, "samples": 1}, {}, census, {})
    row = summary["callers"][0]
    assert row["return_rva"] == 0x24BD25 and row["est_site"] == 0x24BD20
    assert row["func"] == 0x24AB30 and row["origin"] == "incoming_arg"


def test_summarize_joins_token_ids_to_names():
    chains = {
        0x1000: {
            "ok": True, "id": 4242, "x": 1, "s": 2,
            "s_vptr": 3, "object": 4,
        },
    }
    summary = summarize(
        [_entry()], {"calls": 100, "samples": 1}, chains, {}, {4242: "neo_action"},
    )
    assert summary["ids"] == [(4242, "neo_action", 1)]
    assert summary["chain_ok"] == 1


def test_classify_no_calls():
    assert classify(
        {"calls": 0, "samples": 0, "valid": 0, "lexer": 0, "chain_ok": 0}
    ) == "no_calls"


def test_classify_no_samples():
    assert classify(
        {"calls": 10, "samples": 0, "valid": 0, "lexer": 0, "chain_ok": 0}
    ) == "no_samples"


def test_classify_all_invalid():
    assert classify(
        {"calls": 10, "samples": 2, "valid": 0, "lexer": 0, "chain_ok": 0}
    ) == "all_invalid"


def test_classify_lexer_only():
    assert classify(
        {"calls": 10, "samples": 2, "valid": 2, "lexer": 2, "chain_ok": 0}
    ) == "lexer_only"


def test_classify_no_scope_candidate_when_only_unknowns():
    # The falsified X->S->id chain must not rescue this verdict: chain_ok > 0
    # with zero known-vtable hits is exactly what §53.3 second shot produced, and
    # it answered nothing.
    assert classify(
        {"calls": 53120, "samples": 104, "valid": 104, "lexer": 0,
         "chain_ok": 3, "known_vtable_hits": 0, "unknown_ptr_hits": 5}
    ) == "no_scope_candidate"


def test_classify_scope_candidate_ignores_the_falsified_chain():
    assert classify(
        {"calls": 53120, "samples": 104, "valid": 104, "lexer": 0,
         "chain_ok": 0, "known_vtable_hits": 1}
    ) == "scope_candidate"


def test_classify_environment_rungs_precede_the_scope_verdict():
    for summary, expected in (
        ({"calls": 0, "samples": 0, "valid": 0, "lexer": 0,
          "known_vtable_hits": 7}, "no_calls"),
        ({"calls": 10, "samples": 0, "valid": 0, "lexer": 0,
          "known_vtable_hits": 7}, "no_samples"),
        ({"calls": 10, "samples": 2, "valid": 0, "lexer": 0,
          "known_vtable_hits": 7}, "all_invalid"),
        ({"calls": 10, "samples": 2, "valid": 2, "lexer": 2,
          "known_vtable_hits": 7}, "lexer_only"),
    ):
        assert classify(summary) == expected


def test_load_vtable_map_skips_comments_and_uses_rvas():
    m = load_vtable_map("evidence/xrefs/ceffect_vtable_map_4_4_4.txt")
    assert 0x0247ADD0 in m                      # the file's keys are RVAs
    assert m[0x0247ADD0]["slot2"] == 0x0032DA50


def test_follow_object_classifies_known_vtable_by_rva():
    exe_base = 0x7FF600000000
    image_end = 0x7FF680000000
    vtables = {0x247ADD0: {"slot0": 0x15CCC0, "slot2": 0x32DA50}}
    obj = 0x1C4D3C410                 # the frame's +0x10 helper pointer
    heap = 0x2A12345000               # an object whose vptr is a known vtable

    def reader(addr, size):
        if addr == obj and size == 64:
            return struct.pack("<8Q", 0, heap, 0, 0, 0, 0, 0, 0)
        if addr == heap and size == 8:
            return struct.pack("<Q", exe_base + 0x247ADD0)
        return None

    out = follow_object(reader, exe_base, image_end, vtables, obj)
    assert out["root"] == obj and not out["unreadable"]
    cand = out["candidates"][0]
    assert cand["offset"] == 8 and cand["known"] is True
    assert cand["ptr"] == heap
    assert cand["vptr_rva"] == 0x247ADD0 and cand["slot2_rva"] == 0x32DA50


def test_follow_object_keeps_unknown_pointers_as_observation():
    # The 1,805-vtable map is a FLOOR: classes that override Execute are absent,
    # so a readable vptr that misses the map is still a candidate object.
    exe_base = 0x7FF600000000
    image_end = 0x7FF680000000
    obj = 0x1C4D3C410
    heap = 0x2A12345000

    def reader(addr, size):
        if addr == obj and size == 64:
            return struct.pack("<8Q", 0, 0, 0, heap, 0, 0, 0, 0)
        if addr == heap and size == 8:
            return struct.pack("<Q", exe_base + 0x1234)
        return None

    out = follow_object(reader, exe_base, image_end, {}, obj)
    assert out["candidates"][0]["offset"] == 0x18
    assert out["candidates"][0]["known"] is False
    assert out["candidates"][0]["ptr"] == heap
    assert out["candidates"][0]["vptr_rva"] == 0x1234
    assert out["candidates"][0]["slot2_rva"] is None


def test_follow_object_keeps_a_pointer_it_cannot_dereference():
    # The plan Review Focus 6: a heap pointer outside the exe image must not be
    # flattened to rva 0, and a failed deref is its own datum.
    exe_base = 0x7FF600000000
    image_end = 0x7FF680000000
    obj = 0x1C4D3C410
    heap = 0x2A12345000

    def reader(addr, size):
        if addr == obj and size == 64:
            return struct.pack("<8Q", heap, 0, 0, 0, 0, 0, 0, 0)
        return None

    out = follow_object(reader, exe_base, image_end, {}, obj)
    assert out["unreadable"] is False
    assert out["candidates"][0]["ptr"] == heap
    assert out["candidates"][0]["ptr_rva"] is None
    assert out["candidates"][0]["vptr"] is None
    assert out["candidates"][0]["known"] is False


def test_follow_object_reports_unreadable_root_not_zeros():
    # A stack helper that has already been overwritten reads as nothing. That is
    # NOT the same observation as "readable but no candidate".
    out = follow_object(
        lambda addr, size: None, 0x7FF600000000, 0x7FF680000000, {}, 0x7FE960)
    assert out["unreadable"] is True
    assert out["candidates"] == []


def test_follow_object_refuses_a_base_that_cannot_be_bounded():
    with pytest.raises(ValueError):
        follow_object(lambda addr, size: None, 0, 0, {}, 0x1C4D3C410)


def test_plausible_user_ptr_matches_the_dll_gate():
    assert plausible_user_ptr(0x7FF74A630000)
    assert plausible_user_ptr(0x1C4D3C410)      # off-module heap pointer
    assert not plausible_user_ptr(0)
    assert not plausible_user_ptr(0x1234)
    assert not plausible_user_ptr(0x7FF74A630003)   # not 8-aligned
    assert not plausible_user_ptr(0xFFFF800000000000)


def test_summarize_counts_known_and_unknown_scope_candidates():
    objects = [
        {"source": "helper", "root": 0x1C4D3C410, "unreadable": False,
         "candidates": [{"offset": 8, "ptr": 0x2000, "known": True,
                         "vptr_rva": 0x247ADD0, "slot2_rva": 0x32DA50}]},
        {"source": "arg3", "root": 0x7FE960, "unreadable": True,
         "candidates": []},
        {"source": "arg4", "root": 0x3000, "unreadable": False,
         "candidates": [{"offset": 0x18, "ptr": 0x4000, "known": False,
                         "vptr_rva": None, "slot2_rva": None}]},
    ]
    summary = summarize(
        [_entry()], {"calls": 10, "samples": 1}, {}, {}, {}, objects=objects,
    )
    assert summary["known_vtable_hits"] == 1
    assert summary["unknown_ptr_hits"] == 1
    assert summary["unreadable_roots"] == 1
    assert summary["objects"] == objects


def test_poll_runs_to_the_deadline_after_a_sample_arrives():
    # The 1/512 gate fires within ~1 s of install; stopping there would drain
    # ~10 entries instead of a distribution across the whole window (plan
    # Task 5 item 3: poll to --poll-s).
    assert not poll_done(now=2.0, deadline=120.0)
    assert poll_done(now=120.0, deadline=120.0)


# --- roots: which addresses the record can speak to (Review Focus 4) --------

def test_entry_roots_offers_scratch_slots_even_when_the_entry_is_invalid():
    # capture() writes arg3/arg4 BEFORE any self/ctx gate, so an invalid sample
    # still records what the dispatch point held in r8/r9. Gating them on
    # valid==1 threw that datum away and made "never read" look like "rejected".
    e = _entry(valid=0, arg3=0x9000, arg4=0xa000)
    roots = {src: (addr, why) for src, addr, why in _entry_roots(e)}
    assert roots["arg3"] == (0x9000, None)
    assert roots["arg4"] == (0xa000, None)
    assert roots["self"] == (0x100, None)


def test_entry_roots_marks_the_helper_root_as_not_captured():
    # ctx_words stay zeroed unless the frame passed plausible(ctx); a zero there
    # is "the DLL never read it", not "the engine stored null". helper is the
    # frame's +0x10, which is ctx_words[2].
    e = _entry(valid=0, ctx_words=[0] * 8, arg3=0x9000)
    roots = {src: (addr, why) for src, addr, why in _entry_roots(e)}
    assert roots["helper"][1] == "ctx_not_captured"

    e = _entry(valid=1, ctx_words=[0, 0, 0x1C4D3C410, 0, 0, 0, 0, 0])
    roots = {src: (addr, why) for src, addr, why in _entry_roots(e)}
    assert roots["helper"] == (0x1C4D3C410, None)


def test_follow_roots_budgets_each_source_separately():
    # One shared cap across all four roots got exhausted by the self roots, so
    # arg3/arg4 were never read at all — and the empty TSV read as a negative
    # result about those slots (§56.4's mistake).
    entries = [
        _entry(self_ptr=0x2000_0000 + 0x40 * i, ctx_ptr=0x3000_0000 + 0x40 * i,
               ctx_words=[0, 0, 0x4000_0000 + 0x40 * i, 0, 0, 0, 0, 0],
               arg3=0x5000_0000 + 0x40 * i, arg4=0x6000_0000 + 0x40 * i)
        for i in range(20)
    ]
    objects, root_stats = follow_roots(
        _reader_from({}), 0x7FF600000000, 0x7FF680000000, {}, entries,
        per_source=8,
    )
    followed = {}
    for obj in objects:
        followed[obj["source"]] = followed.get(obj["source"], 0) + 1
    assert followed == {"self": 8, "helper": 8, "arg3": 8, "arg4": 8}
    assert root_stats["capped_by_source"] == {
        "self": 12, "helper": 12, "arg3": 12, "arg4": 12}
    assert root_stats["withheld_by_source"] == {
        "self": 0, "helper": 0, "arg3": 0, "arg4": 0}
    assert root_stats["implausible_by_source"] == {
        "self": 0, "helper": 0, "arg3": 0, "arg4": 0}


def test_follow_roots_reports_implausible_per_source():
    # helper == 7 is not a rejected address, it is a ctx word that failed the
    # DLL's own gate; arg3 == 0 is the scratch slot genuinely holding null.
    e = _entry(self_ptr=0x2000_0000, ctx_ptr=0x3000_0000,
               ctx_words=[0, 0, 7, 0, 0, 0, 0, 0],
               arg3=0, arg4=0x6000_0000)
    objects, root_stats = follow_roots(
        _reader_from({}), 0x7FF600000000, 0x7FF680000000, {}, [e],
        per_source=8,
    )
    assert [o["source"] for o in objects] == ["self", "arg4"]
    assert root_stats["implausible_by_source"] == {
        "self": 0, "helper": 1, "arg3": 1, "arg4": 0}
    assert root_stats["withheld_by_source"] == {
        "self": 0, "helper": 0, "arg3": 0, "arg4": 0}


def test_follow_roots_counts_roots_withheld_by_an_invalid_entry():
    # An invalid frame never had its ctx read, so the helper root is withheld
    # rather than counted as an observation about that slot.
    e = _entry(valid=0, self_ptr=0x2000_0000, arg3=0x5000_0000,
               arg4=0x6000_0000)
    objects, root_stats = follow_roots(
        _reader_from({}), 0x7FF600000000, 0x7FF680000000, {}, [e],
        per_source=8,
    )
    assert [o["source"] for o in objects] == ["self", "arg3", "arg4"]
    assert root_stats["withheld_by_source"] == {
        "self": 0, "helper": 1, "arg3": 0, "arg4": 0}
    assert root_stats["implausible_by_source"] == {
        "self": 0, "helper": 0, "arg3": 0, "arg4": 0}


def test_follow_roots_refuses_an_unbounded_image():
    # Passing the whole address space as "the module" is how a stale qword turns
    # into a fabricated RVA hit.
    with pytest.raises(ValueError):
        follow_roots(_reader_from({}), 0x7FF600000000, 0x7FF600000000, {}, [])


def test_image_end_from_header_adds_sizeofimage():
    # e_lfanew is at +0x3C; SizeOfImage is at NT header +0x50 in PE32+. Getting
    # either offset wrong silently makes every in-image pointer "outside" it.
    exe_base = 0x7FF6A4270000
    dos = bytearray(64)
    struct.pack_into("<I", dos, 0x3C, 0x100)
    nt = bytearray(0x54)
    struct.pack_into("<I", nt, 0x50, 0x481_0000)
    mapping = {exe_base: bytes(dos), exe_base + 0x100: bytes(nt)}
    assert image_end_from_header(_reader_from(mapping), exe_base) == (
        exe_base + 0x481_0000)


def test_image_end_from_header_reports_a_short_read():
    assert image_end_from_header(lambda addr, size: None, 0x7FF6A4270000) is None


# --- candidate classification: image bound and member vtables --------------

def test_follow_object_refuses_an_rva_past_the_end_of_the_image():
    # The DLL's toRva returns 0 for anything outside [img_base, img_end). A
    # stale qword that happens to land above the image is not a module address,
    # and calling it an RVA manufactures a judgement out of garbage.
    exe_base = 0x7FF600000000
    image_end = exe_base + 0x4000000
    obj = 0x1C4D3C410
    member = 0x2A12345000
    stale = exe_base + 0x4000000

    def reader(addr, size):
        if addr == obj and size == 64:
            return struct.pack("<8Q", member, 0, 0, 0, 0, 0, 0, 0)
        if addr == member and size == 8:
            return struct.pack("<Q", stale)
        return None

    out = follow_object(reader, exe_base, image_end, {}, obj)
    cand = out["candidates"][0]
    assert cand["vptr"] == stale
    assert cand["vptr_rva"] is None
    assert cand["known"] is False


def test_follow_object_flags_a_member_that_is_itself_a_known_vtable():
    # A known CEffect vtable address stored AT root+off is a secondary vtable —
    # it says something about the root's own class, which is a different datum
    # from "this member points at an object whose vtable is known". It therefore
    # gets its own field and never folds into `known`.
    exe_base = 0x7FF600000000
    image_end = exe_base + 0x4000000
    vtables = {0x247ADD0: {"slot0": 0x15CCC0, "slot2": 0x32DA50}}
    obj = 0x1C4D3C410
    member = exe_base + 0x247ADD0

    def reader(addr, size):
        if addr == obj and size == 64:
            return struct.pack("<8Q", 0, member, 0, 0, 0, 0, 0, 0)
        return None

    out = follow_object(reader, exe_base, image_end, vtables, obj)
    cand = out["candidates"][0]
    assert cand["known"] is False
    assert cand["ptr_rva"] == 0x247ADD0
    assert cand["member_vtable"] is True
    assert cand["member_slot2_rva"] == 0x32DA50


def test_follow_object_leaves_ptr_rva_none_for_an_out_of_image_member():
    exe_base = 0x7FF600000000
    image_end = exe_base + 0x4000000
    obj = 0x1C4D3C410
    heap = 0x2A12345000

    def reader(addr, size):
        if addr == obj and size == 64:
            return struct.pack("<8Q", heap, 0, 0, 0, 0, 0, 0, 0)
        return None

    out = follow_object(reader, exe_base, image_end, {}, obj)
    cand = out["candidates"][0]
    assert cand["ptr"] == heap
    assert cand["ptr_rva"] is None
    assert cand["member_vtable"] is False


def test_summarize_counts_member_vtable_hits_separately_from_known_hits():
    objects = [
        {"source": "self", "root": 0x1000, "unreadable": False, "candidates": [
            {"offset": 0x38, "ptr": 0x7FF60247ADD0, "known": False,
             "vptr_rva": None, "slot2_rva": None,
             "ptr_rva": 0x247ADD0, "member_vtable": True,
             "member_slot2_rva": 0x32DA50},
            {"offset": 0x40, "ptr": 0x2000, "known": True,
             "vptr_rva": 0x247ADD0, "slot2_rva": 0x32DA50,
             "ptr_rva": None, "member_vtable": False,
             "member_slot2_rva": None},
        ]},
    ]
    summary = summarize(
        [_entry()], {"calls": 10, "samples": 1}, {}, {}, {}, objects=objects,
    )
    assert summary["known_vtable_hits"] == 1
    assert summary["member_vtable_hits"] == 1


# --- seams the driver reads back (live paths that must stay honest) --------

def test_install_decision_refuses_a_drifted_layout():
    layout, reason = install_decision([120, 56, 256, 511, 1])
    assert layout is None
    assert "version" in reason


def test_install_decision_authorizes_the_pinned_layout():
    layout, reason = install_decision([120, 56, 256, 511, 2])
    assert reason is None
    assert layout["entry"] == 120 and layout["version"] == 2


def test_exit_code_is_zero_only_for_scope_candidate():
    assert exit_code_for("scope_candidate") == 0
    for verdict in ("no_calls", "no_samples", "all_invalid", "lexer_only",
                    "no_scope_candidate", "detour_unavailable"):
        assert exit_code_for(verdict) == 1


def test_write_tsv_writes_meta_rows_before_the_evidence_rows(tmp_path):
    # The artifact has to support its own verdict offline: after the ssh channel
    # ate the driver's stdout, the TSV alone could not say which base the RVAs
    # were relative to, how many roots were followed, or that a cap was hit.
    path = str(tmp_path / "shot.tsv")
    summary = {"callers": [], "ids": [], "chains": [], "objects": []}
    rows = write_tsv(path, summary, meta={
        "exe_base": "0x7ff6a4270000",
        "per_source_follow": "8",
    })
    lines = open(path, encoding="utf-8").read().splitlines()
    assert lines[0].startswith("# kind")
    assert lines[1] == "meta\texe_base\t0x7ff6a4270000\t-"
    assert lines[2] == "meta\tper_source_follow\t8\t-"
    assert rows == 2


def test_classify_region_decides_image_by_address_range_before_type():
    # 同一个 type=0x20000(MEM_PRIVATE)的两个地址,一个落在镜像区间内,一个在外。
    # 落在内 ⇒ "image":这是刻意的前后顺序 —— 判 image 只看地址,不看 type。
    info = {"base": 0x1900000, "allocation_base": 0x1900000, "protect": 0x04,
            "state": 0x1000, "type": 0x20000, "size": 0x1000}
    assert classify_region(info, 0x1400000, 0x4000000) == "image"
    outside = {**info, "base": 0x5000000, "allocation_base": 0x5000000}
    assert classify_region(outside, 0x1400000, 0x4000000) == "private_committed"


def test_classify_region_names_private_committed_and_reserved_apart():
    # 字面量是钉子,不 import 模块常量:常量取错值时这条测试必须变红。
    # 真实 Win32:MEM_COMMIT=0x1000 MEM_RESERVE=0x2000 MEM_FREE=0x10000
    #            MEM_PRIVATE=0x20000 MEM_MAPPED=0x40000 MEM_IMAGE=0x1000000
    committed = {"base": 0x7fe000, "protect": 0x04, "state": 0x1000, "type": 0x20000,
                 "allocation_base": 0x7f0000, "size": 0x1000}
    assert classify_region(committed, 0x1000000, 0x4000000) == "private_committed"
    assert classify_region({**committed, "type": 0x40000}, 0x1000000, 0x4000000) == "mapped_view"  # MEM_MAPPED
    assert classify_region({**committed, "state": 0x2000}, 0x1000000, 0x4000000) == "reserved"    # MEM_RESERVE
    assert classify_region({**committed, "state": 0x10000, "type": 0},
                           0x1000000, 0x4000000) == "free"  # MEM_FREE:state 与 type 同时异常时 free 先于 unknown


def test_classify_region_reports_unreadable_for_none_and_unknown_for_unmapped_flags():
    assert classify_region(None, 0x1400000, 0x4000000) == "unreadable"
    # base 落在镜像区间外:判 image 只看地址(brief 的判序 (2)),所以一条 state/type
    # 都认不出的行必须先躲过那一档,才能走到 unknown。
    assert classify_region({"state": 0xdead, "type": 0xdead, "protect": 4,
                            "base": 0x5000, "size": 1, "allocation_base": 0x5000},
                           0x1000, 0x2000) == "unknown"


def test_region_rows_carries_the_source_and_the_verdict_for_every_queried_root():
    # 调用顺序钉在 Produces 块的 region_rows(classify, query, addrs) 上:两个参数都是
    # 可调用对象,顺序写反不会静默走偏,只会在这里炸 —— 这条测试就是那个钉子。
    bound = lambda info: classify_region(info, 0x1000, 0x2000)  # noqa: E731
    seen = []

    def query(addr):
        seen.append(addr)
        if addr == 0x99:
            return None
        return {"base": 0x1500, "allocation_base": 0x1500, "size": 0x1000,
                "state": 0x1000, "protect": 0x04, "type": 0x20000}

    rows = region_rows(bound, query, [(0x1900, "helper"), (0x99, "ctx")])
    assert seen == [0x1900, 0x99]
    assert [r["source"] for r in rows] == ["helper", "ctx"]
    assert [r["verdict"] for r in rows] == ["image", "unreadable"]
    assert rows[0]["base"] == 0x1500 and rows[0]["type"] == 0x20000
    assert all(rows[1][k] is None for k in
               ("base", "size", "state", "protect", "type", "allocation_base"))


def test_region_rows_do_not_change_the_verdict_ladder():
    # 回归钉:区域仪器是 datum,不参与六档阶梯。将来有人把判定接进去,这条变红。
    base_summary = {"calls": 10, "samples": 2, "valid": 2, "lexer": 0,
                    "chain_ok": 0, "known_vtable_hits": 1}
    with_regions = dict(base_summary,
                        regions=[{"addr": 0x1900, "source": "helper",
                                  "verdict": "unreadable"}])
    assert classify(base_summary) == classify(with_regions) == "scope_candidate"


def test_region_rows_are_written_and_are_not_object_rows(tmp_path):
    from scope_reclassify import parse_object_rows
    region = {"addr": 0x1900, "source": "helper", "verdict": "unreadable",
              "base": 0x1000, "size": 0x1000, "state": 0x1000,
              "protect": 0x4, "type": 0x20000, "allocation_base": 0x1000}
    summary = {"calls": 10, "samples": 2, "valid": 2, "lexer": 0,
               "chain_ok": 0, "known_vtable_hits": 0,
               "callers": [], "ids": [], "chains": [], "objects": [],
               "regions": [region]}
    path = tmp_path / "probe.tsv"
    write_tsv(path, summary, meta={"verdict": "no_scope_candidate"})
    text = path.read_text()
    assert text.count(BEGIN_REGION_ROW_LITERAL) >= 1
    assert len(parse_object_rows(text)) == 0


def test_region_row_detail_carries_every_query_field(tmp_path):
    # 判读一条 region 行不该回头读驱动源码:六个查询字段全在 detail 里,不可用的那
    # 些是 "-"。字段名 alloc_base= 是 artifact 的线上格式,不是随手起的。
    region = {"addr": 0x1d28c7d08, "source": "ctx", "verdict": "unknown",
              "base": None, "size": None, "state": None, "protect": None,
              "type": None, "allocation_base": None}
    summary = {"calls": 0, "samples": 0, "valid": 0, "lexer": 0,
               "callers": [], "ids": [], "chains": [], "objects": [],
               "regions": [region]}
    path = tmp_path / "probe.tsv"
    rows = write_tsv(path, summary, meta={})
    assert rows == 1
    assert path.read_text().splitlines()[1] == (
        "region\t0x1d28c7d08\tunknown\tsource=ctx base=- size=- state=- "
        "protect=- type=- alloc_base=-"
    )


def test_region_verdict_census_is_one_sorted_line_per_source_and_verdict():
    census = _region_verdicts([
        {"source": "helper", "verdict": "private_committed"},
        {"source": "ctx", "verdict": "unreadable"},
        {"source": "helper", "verdict": "private_committed"},
        {"source": "self", "verdict": "image"},
        {"source": "ctx", "verdict": "free"},
    ])
    assert census == (
        "ctx/free=1/ctx/unreadable=1/helper/private_committed=2/self/image=1"
    )
    assert _region_verdicts([]) == ""


# ---------------------------------------------------------------- depth-2 follow

def _cand(off, ptr, *, ptr_rva=None, known=False, member_vtable=False,
          vptr=0, vptr_rva=None):
    return {
        "offset": off, "ptr": ptr, "ptr_rva": ptr_rva, "vptr": vptr,
        "vptr_rva": vptr_rva, "known": known,
        "slot2_rva": 0x1D08520 if known else None,
        "member_vtable": member_vtable,
        "member_slot2_rva": 0x1D08520 if member_vtable else None,
    }


def _obj(source, root, candidates, unreadable=False):
    return {
        "source": source, "root": root, "unreadable": unreadable,
        "words": [0] * 8, "candidates": candidates,
    }


D2_EXE_BASE = 0x140000000
D2_IMAGE_END = D2_EXE_BASE + 0x3927000


def test_plan_depth2_skips_roots_already_read_at_depth1():
    """A candidate that points back at a root already read is not a lead.

    Re-planning it would spend the per-source budget on a read whose datum is
    already in the artifact, and the cap would then hide the slots never reached.
    """
    root = 0x2000_0000
    lead = 0x2000_1000
    objects = [_obj("self", root, [_cand(0x0, root), _cand(0x8, lead)])]
    assert plan_depth2(objects) == [(lead, "self")]
    assert plan_depth2(objects, already={root, lead}) == []


def test_plan_depth2_caps_per_source_not_shared():
    """The §56.4 fence: self filling its budget must not starve helper.

    One shared cap reads in the artifact exactly like helper's slots held
    nothing, which is the misreading §56.4 produced.
    """
    self_row = _obj(
        "self", 0x2000_0000,
        [_cand(i * 8, 0x3000_0000 + i * 8)
         for i in range(DEPTH2_PER_SOURCE + 8)])
    helper_row = _obj(
        "helper", 0x2000_4000,
        [_cand(i * 8, 0x4000_0000 + i * 8)
         for i in range(DEPTH2_PER_SOURCE)])
    plan = plan_depth2([self_row, helper_row])
    by_source = {}
    for addr, source in plan:
        by_source.setdefault(source, []).append(addr)
    assert len(by_source["self"]) == DEPTH2_PER_SOURCE
    assert len(by_source["helper"]) == DEPTH2_PER_SOURCE


def test_plan_depth2_skips_unreadable_rows():
    """An unreadable depth-1 root carries no candidates; planning must not raise."""
    objects = [
        _obj("arg3", 0x2000_0000, [], unreadable=True),
        _obj("arg4", 0x2000_2000, [_cand(0x10, 0x5000_0000)]),
    ]
    assert plan_depth2(objects) == [(0x5000_0000, "arg4")]


def test_follow_depth2_labels_source_with_d2_suffix():
    """Each depth-2 read carries its base source plus the d2 suffix."""
    seen_sources = []

    def spy(source):
        seen_sources.append(source)
        return _obj(source, 0x0, [], unreadable=True)

    import c2_scope_probe as mod
    original = mod.follow_object
    mod.follow_object = lambda r, b, e, v, addr, *, source="": spy(source)
    try:
        objects = [
            _obj("self", 0x2000_0000, [_cand(0x0, 0x3000_0000)]),
            _obj("helper", 0x2000_4000,
                 [_cand(0x0, 0x4000_0000), _cand(0x8, 0x4000_0008)]),
        ]
        d2_objects, d2_stats = follow_depth2(
            lambda addr, size: b"\x00" * size,
            D2_EXE_BASE, D2_IMAGE_END, {}, objects)
    finally:
        mod.follow_object = original
    assert [o["source"] for o in d2_objects] == ["self.d2", "helper.d2",
                                                  "helper.d2"]
    assert seen_sources == ["self.d2", "helper.d2", "helper.d2"]
    assert d2_stats["followed_by_source"] == {"self": 1, "helper": 2,
                                              "arg3": 0, "arg4": 0}
    assert d2_stats["planned_by_source"] == {"self": 1, "helper": 2,
                                             "arg3": 0, "arg4": 0}


def test_find_shared_cells_requires_two_distinct_sources():
    """A value two slots of the SAME root hold is not a cross-root lineage edge."""
    shared_value = 0x2ddc_2c90
    two_sources = [
        _obj("self", 0x7fe_b00, [_cand(0x28, shared_value)]),
        _obj("helper", 0x7fe_960, [_cand(0x10, shared_value)]),
    ]
    rows = find_shared_cells(two_sources)
    assert len(rows) == 1
    assert rows[0]["value"] == shared_value

    one_source = [
        _obj("self", 0x7fe_b00,
             [_cand(0x28, shared_value), _cand(0x30, shared_value)]),
    ]
    assert find_shared_cells(one_source) == []


def test_find_shared_cells_folds_d2_suffix_into_base_source():
    """self.d2 and helper sharing a value is a cross-source edge."""
    shared_value = 0x2ddc_2c90
    objects = [
        _obj("self.d2", 0x7fe_bd0, [_cand(0x0, shared_value)]),
        _obj("helper", 0x7fe_960, [_cand(0x10, shared_value)]),
    ]
    rows = find_shared_cells(objects)
    assert len(rows) == 1
    assert {site[0] for site in rows[0]["sites"]} == {"self", "helper"}


def test_classify_depth2_ladder_order():
    """Five rungs, each hit once; planned==0 outranks unreadable."""
    empty = _obj("self.d2", 0x1000, [], unreadable=True)
    assert classify_depth2([empty], [], 0) == "no_depth2_planned"
    assert classify_depth2([empty], [], 8) == "depth2_unreadable"

    hit = _obj("self.d2", 0x1000,
               [_cand(0x0, 0x2000, ptr_rva=0x1000, known=True)])
    shared_value = 0x2ddc_2c90
    shared = find_shared_cells([
        _obj("self.d2", 0x1000, [_cand(0x0, shared_value)]),
        _obj("helper", 0x2000, [_cand(0x10, shared_value)]),
    ])
    assert classify_depth2([hit], shared, 8) == "depth2_known_vtable_hit"
    assert classify_depth2(
        [_obj("self.d2", 0x1000, [_cand(0x0, shared_value)])], shared,
        8) == "lineage_edge_found"
    assert classify_depth2(
        [_obj("self.d2", 0x1000, [_cand(0x0, 0x9000)])], [],
        8) == "no_depth2_lead"


def test_verdict_d2_domain_has_no_negative_tier():
    """There is no deeper-layer-holds-nothing rung: silence is not a verdict."""
    assert set(D2_VERDICTS) == {
        "depth2_known_vtable_hit", "lineage_edge_found", "depth2_unreadable",
        "no_depth2_planned", "no_depth2_lead",
    }
    assert set(EVIDENCE_D2_VERDICTS) == {
        "depth2_known_vtable_hit", "lineage_edge_found",
    }


def test_d2_meta_rows_carries_seven_keys():
    """Seven keys, exactly: the budget rungs, the cap, the verdict, the edges, and
    the bucket that was never a lead (``d2_implausible`` — §68.4 前置 ①)."""
    stats = {
        "planned_by_source": {"self": 1, "helper": 0, "arg3": 0, "arg4": 0},
        "followed_by_source": {"self": 1, "helper": 0, "arg3": 0, "arg4": 0},
        "capped_by_source": {"self": 3, "helper": 0, "arg3": 0, "arg4": 0},
        "deduped_by_source": {"self": 0, "helper": 0, "arg3": 0, "arg4": 0},
    }
    rows = d2_meta_rows(stats, "no_depth2_lead", [], d2_implausible=4)
    assert set(rows) == {
        "depth2_per_source", "d2_implausible", "d2_planned_by_source",
        "d2_followed_by_source", "d2_capped_by_source", "verdict_d2",
        "shared_cells",
    }
    assert rows["d2_implausible"] == 4
    assert rows["depth2_per_source"] == DEPTH2_PER_SOURCE
    assert rows["verdict_d2"] == "no_depth2_lead"


def test_find_shared_cells_calibrates_on_the_59_6_pair():
    """The detector must read the one lineage edge already in evidence.

    §59.6 recorded self root 0x7feb00+0x28 -> 0x7febd0 whose first qword is
    0x2ddc2c90, and helper root 0x7fe960+0x10 -> 0x2ddc2c90. A finder that
    returns nothing here cannot be trusted to report a zero for the shot.
    """
    objects = [
        _obj("helper", 0x7fe_960, [_cand(0x10, 0x2ddc_2c90)]),
        _obj("self.d2", 0x7fe_bd0, [_cand(0x0, 0x2ddc_2c90)]),
    ]
    rows = find_shared_cells(objects)
    assert len(rows) == 1
    assert rows[0]["value"] == 0x2ddc_2c90
    assert {site[0] for site in rows[0]["sites"]} == {"helper", "self"}
    assert len(rows[0]["sites"]) == 2


def test_collect_region_addrs_carries_both_layers():
    """region_rows must see depth-2 roots too, each labelled with its own source."""
    objects = [_obj("self", 0x7fe_b00, [])]
    d2_objects = [_obj("self.d2", 0x7fe_bd0, [])]
    assert collect_region_addrs(objects, d2_objects) == [
        (0x7fe_b00, "self"), (0x7fe_bd0, "self.d2"),
    ]


# ---------------------------------------------------------------------------
# Task 5 (plan 2026-10-27-live-window-out-of-family-witness, §68.4 前置 ①②):
# depth-2 cells get bucketed before they are joined, and the per-source budget
# covers the 19 cells §68 capped on the `self` branch.
# ---------------------------------------------------------------------------

def test_partition_buckets_by_plausibility_and_image_bounds():
    """Three cells, three buckets: in-image user ptr / out-of-image user ptr / scalar.

    §68.4's two prerequisites in one function: ``plausible_user_ptr`` is the DLL's
    own gate (so a cell the guard could never read is not a "lead"), and the
    image bounds are the exe's, so a plausible pointer outside the module is told
    apart from a plausible in-module one.  A scalar like ``0x100000000`` is
    neither ⇒ ``implausible``, and it must never reach the lineage join.
    """
    exe_base, image_end = 0x7FF600000000, 0x7FF600000000 + 0x3927000
    cells = [
        {"source": "self.d2", "root": 0x7FE000,
         "candidates": [{"offset": 0x10, "ptr": exe_base + 0x247A488,
                         "ptr_rva": 0x247A488}]},
        {"source": "helper.d2", "root": 0x7FE960,
         "candidates": [{"offset": 0x28, "ptr": 0x2DDC2C90,
                         "ptr_rva": None}]},
        {"source": "self.d2", "root": 0x7FEB00,
         "candidates": [{"offset": 0x30, "ptr": 0x1000, "ptr_rva": None}]},
    ]
    buckets = scope.partition_cells(cells, exe_base, image_end)
    assert [c["root"] for c in buckets["user_ptr_in_image"]] == [0x7FE000]
    assert [c["root"] for c in buckets["user_ptr_out_of_image"]] == [0x7FE960]
    assert [c["root"] for c in buckets["implausible"]] == [0x7FEB00]
    assert sum(len(v) for v in buckets.values()) == 3
    # Without bounds the only available test is the cell's own ptr_rva.
    fallback = scope.partition_cells(cells)
    assert [c["root"] for c in fallback["user_ptr_in_image"]] == [0x7FE000]
    # §68's scalar edge is `0x100000000` — and it PASSES plausible_user_ptr (the
    # gate's ceiling is 0x7FFF_FFFF_0000), so it is a plausible pointer outside the
    # image, NOT an implausible cell.  Recorded here so the §73 shot does not read
    # that edge as bucket three.
    scalar = [{"source": "helper.d2", "root": 0x7FE960,
               "candidates": [{"offset": 0x10, "ptr": 0x1_0000_0000,
                               "ptr_rva": None}]}]
    got = scope.partition_cells(scalar, exe_base, image_end)
    assert got["implausible"] == []
    assert [c["root"] for c in got["user_ptr_out_of_image"]] == [0x7FE960]


def test_depth2_budget_covers_the_19_uncapped_cells():
    """27 = §68.4's ``followed=8`` + ``capped=19`` on the self branch.

    The budget is what makes "that branch was not finished being asked" go away;
    if this number drops back to 8, §73's shot re-asks the same 19 cells and gets
    the same cap.  The comment next to the constant must carry the arithmetic and
    its source (§68.4), because the number alone reads like a tuning knob.
    """
    assert scope.DEPTH2_PER_SOURCE == 27
    src = inspect.getsource(scope)
    at = src.index("DEPTH2_PER_SOURCE = 27")
    window = src[max(0, at - 700):at + 120]
    assert "68.4" in window, "预算 27 旁边必须写出处 §68.4"
    assert "19" in window and "8" in window, "预算 27 旁边必须写 8+19 的算术"
