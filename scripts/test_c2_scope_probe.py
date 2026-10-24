"""Pure-function tests for c2_scope_probe.py — no game, no Windows API.

Fixtures mirror the DLL contract: Entry is 120 bytes with the layout pinned by
src/dll/c2/scope_probe.zig, and the layout words are [120, 56, 256, 511, 2].
"""

import struct

import pytest

from c2_scope_probe import (
    caller_site, classify, decode_entry, decode_layout, decode_stats,
    follow_chain, follow_object, load_call_census, load_vtable_map,
    plausible_user_ptr, poll_done, summarize,
)


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


def test_caller_site_is_return_rva_minus_five():
    assert caller_site(0x24BD25) == 0x24BD20


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
    vtables = {0x247ADD0: {"slot0": 0x15CCC0, "slot2": 0x32DA50}}
    obj = 0x1C4D3C410                 # the frame's +0x10 helper pointer
    heap = 0x2A12345000               # an object whose vptr is a known vtable

    def reader(addr, size):
        if addr == obj and size == 64:
            return struct.pack("<8Q", 0, heap, 0, 0, 0, 0, 0, 0)
        if addr == heap and size == 8:
            return struct.pack("<Q", exe_base + 0x247ADD0)
        return None

    out = follow_object(reader, exe_base, vtables, obj)
    assert out["root"] == obj and not out["unreadable"]
    cand = out["candidates"][0]
    assert cand["offset"] == 8 and cand["known"] is True
    assert cand["ptr"] == heap
    assert cand["vptr_rva"] == 0x247ADD0 and cand["slot2_rva"] == 0x32DA50


def test_follow_object_keeps_unknown_pointers_as_observation():
    # The 1,805-vtable map is a FLOOR: classes that override Execute are absent,
    # so a readable vptr that misses the map is still a candidate object.
    exe_base = 0x7FF600000000
    obj = 0x1C4D3C410
    heap = 0x2A12345000

    def reader(addr, size):
        if addr == obj and size == 64:
            return struct.pack("<8Q", 0, 0, 0, heap, 0, 0, 0, 0)
        if addr == heap and size == 8:
            return struct.pack("<Q", exe_base + 0x1234)
        return None

    out = follow_object(reader, exe_base, {}, obj)
    assert out["candidates"][0]["offset"] == 0x18
    assert out["candidates"][0]["known"] is False
    assert out["candidates"][0]["ptr"] == heap
    assert out["candidates"][0]["vptr_rva"] == 0x1234
    assert out["candidates"][0]["slot2_rva"] is None


def test_follow_object_keeps_a_pointer_it_cannot_dereference():
    # The plan Review Focus 6: a heap pointer outside the exe image must not be
    # flattened to rva 0, and a failed deref is its own datum.
    exe_base = 0x7FF600000000
    obj = 0x1C4D3C410
    heap = 0x2A12345000

    def reader(addr, size):
        if addr == obj and size == 64:
            return struct.pack("<8Q", heap, 0, 0, 0, 0, 0, 0, 0)
        return None

    out = follow_object(reader, exe_base, {}, obj)
    assert out["unreadable"] is False
    assert out["candidates"][0]["ptr"] == heap
    assert out["candidates"][0]["vptr"] is None
    assert out["candidates"][0]["known"] is False


def test_follow_object_reports_unreadable_root_not_zeros():
    # A stack helper that has already been overwritten reads as nothing. That is
    # NOT the same observation as "readable but no candidate".
    out = follow_object(lambda addr, size: None, 0x7FF600000000, {}, 0x7FE960)
    assert out["unreadable"] is True
    assert out["candidates"] == []


def test_follow_object_survives_exe_base_zero():
    out = follow_object(
        lambda addr, size: struct.pack("<8Q", *([0x2A12345000] + [0] * 7))
        if addr == 0x1C4D3C410 and size == 64 else None,
        0, {}, 0x1C4D3C410,
    )
    assert out["candidates"][0]["vptr_rva"] is None
    assert out["candidates"][0]["known"] is False


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
