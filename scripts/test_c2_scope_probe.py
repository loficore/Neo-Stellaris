"""Pure-function tests for c2_scope_probe.py — no game, no Windows API.

Fixtures mirror the DLL contract: Entry is 104 bytes with the layout pinned by
src/dll/c2/scope_probe.zig, and the layout words are [104, 56, 256, 511, 1].
"""

import struct

import pytest

from c2_scope_probe import (
    caller_site, classify, decode_entry, decode_layout, decode_stats,
    follow_chain, load_call_census, summarize,
)


def _entry(**kw):
    base = {
        "valid": 1, "lexer": 0, "self_vtable_rva": 0xA, "shim_rva": 0x10,
        "token_id": 1, "caller_rva": 0x24BD25, "self_ptr": 0x100,
        "ctx_ptr": 0x1000, "ctx_words": [0] * 8,
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
    assert decode_layout([104, 56, 256, 511, 1]) == {
        "entry": 104, "stats": 56, "ring": 256, "mask": 511, "version": 1,
    }


def test_decode_layout_rejects_unknown_version():
    with pytest.raises(ValueError):
        decode_layout([104, 56, 256, 511, 2])


def test_decode_layout_rejects_wrong_entry_size():
    with pytest.raises(ValueError):
        decode_layout([120, 56, 256, 511, 1])


def test_decode_entry_reads_all_fields():
    raw = struct.pack(
        "<BBHIIII4xQQ8Q",
        1, 0, 0, 0x1234, 0x5678, 0x1F3, 0x24BD25,
        0x7FF700001000, 0x7FF700002000,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    )
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


def test_decode_entry_rejects_short_buffer():
    with pytest.raises(ValueError):
        decode_entry(b"\x00" * 103)


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


def test_classify_chain_unreadable():
    assert classify(
        {"calls": 10, "samples": 3, "valid": 3, "lexer": 1, "chain_ok": 0}
    ) == "chain_unreadable"


def test_classify_captured():
    assert classify(
        {"calls": 10, "samples": 3, "valid": 3, "lexer": 1, "chain_ok": 2}
    ) == "captured"
