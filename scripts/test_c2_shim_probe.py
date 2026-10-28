"""Offline fence for the OUT-OF-FAMILY shim witness — ``src/dll/c2/shim_witness_probe.zig``
and ``scripts/c2_shim_probe.py``.

Sibling of ``test_c2_witness_probe.py`` (same shape, different target and different join
table): this guard watches ``0xCC4220`` — the first of §13's seven exec shims that each ran
exactly 2,090 times — which §71 pinned as the ``slot[2]`` of vtable ``0x25460F0``, a table that
is NOT one of the five family tables.

Everything the Zig module hard-codes was copied out of tools by hand, so this file re-reads it
from its *authorities* and fails when a copy drifts:

* the 24-byte prologue is compared byte-for-byte against the on-disk ``stellaris.exe`` through
  ``disrva.rd`` (the only exe-path resolution allowed in a top-level script — the layout
  fence's R-env rule);
* the seven vtable RVAs are compared against ``evidence/xrefs/exec_shim_census_2026_09_29.txt``,
  the machine-readable census row that recorded them at 2,090 calls each.

Host-only, zero shots: file reads, one exe byte window, no process, no Windows API.
"""

import inspect
import pathlib
import re
import struct
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import disrva  # noqa: E402
import c2_shim_probe as shim  # noqa: E402
from c2_shim_probe import (  # noqa: E402
    EVIDENCE_VERDICTS,
    STATS_KEYS,
    VERDICTS,
    decode_entry,
    decode_layout,
    decode_stats,
    table_rvas,
    verdict_for,
)
from test_c2_witness_probe import zig_array_literal  # noqa: E402

SHIM_RVA = 0xCC4220
ZIG_MODULE = REPO / "src" / "dll" / "c2" / "shim_witness_probe.zig"
CENSUS = REPO / "evidence" / "xrefs" / "exec_shim_census_2026_09_29.txt"
EVIDENCE_VOLUME = REPO / "evidence" / "analysis" / "runtime_444_c1_validation.md"

# §71.5 的权威读数(pin_prologue.py cc4220 24 → 36 B 的前 24 B,6 条完整指令)。
# 这里当**独立第三方**写死:测试文件、Zig 模块、磁盘上的 exe 三方必须逐字一致。
TASK1_PROLOGUE = [
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10,
    0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20,
    0x0F, 0xB6, 0x79, 0x08,
]
# §71.3 的七张表(census 里计数恰为 2,090 的那七行,文件顺序)。
TASK1_OUT_OF_FAMILY_VTABLES = [
    0x25460F0, 0x250E188, 0x254FA18, 0x25531E8, 0x2551620, 0x2553178, 0x2553140,
]

# The 6-word layout contract as the Zig module writes it (layoutInto):
# [Entry size, Stats size, RING_LEN, mask low 32, mask high 32, version].
GOOD_LAYOUT = [48, 64, 256, 0, 0, 1]


def _stats(**over):
    """A complete 14-key stats dict (decode_stats' output shape) with zeros."""
    base = dict.fromkeys(STATS_KEYS, 0)
    base["installed"] = 1
    base.update(over)
    return base


def census_vtables():
    """The seven vtable RVAs the census recorded at exactly 2,090 calls, in file order."""
    out = []
    for line in CENSUS.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "shim" or parts[2] != "vtable":
            continue
        if parts[4].lstrip("x") == "2090":
            out.append(int(parts[3], 16))
    return out


def zig_stats_key_order():
    """The key order the Zig module's ``statsInto`` actually writes.

    Read out of the format string, not out of a comment: ``decode_stats`` refuses
    a missing/unknown key, so this order is the driver's whole contract.
    """
    src = ZIG_MODULE.read_text(encoding="utf-8")
    match = re.search(r'"((?:calls=\{[a-z]+\} )?.*?mask=\{[a-z]+\}\\n)"', src)
    assert match is not None, "Zig 模块里没有 statsInto 的格式串"
    return tuple(re.findall(r"([a-z_0-9]+)=\{[a-z]+\}", match.group(1)))


# ---------------------------------------------------------------------------
# The six fences the plan names
# ---------------------------------------------------------------------------

def test_verdict_domain_has_no_per_system_tier():
    """Review Focus 1: nothing in the domain may claim "per-system".

    §13's own words are ``correlate this number against the live system count …
    before claiming it`` — that correlation is §74's job, not this guard's.  So no
    verdict name may carry per-system / system-count wording, and the domain is
    exactly five strings.
    """
    assert len(VERDICTS) == 5
    for verdict in VERDICTS:
        lowered = verdict.lower()
        assert "per_system" not in lowered and "per-system" not in lowered
        assert "system_count" not in lowered
        assert "persystem" not in lowered
    assert set(VERDICTS) == {
        "no_calls_inconclusive",
        "shim_hit_named",
        "shim_hit_unknown_table",
        "instrument_broken",
        "counter_desync",
    }


def test_no_calls_inconclusive_not_in_evidence_verdicts():
    """A silent window is an environment result, never a code answer (exit 0 gate)."""
    assert "no_calls_inconclusive" not in EVIDENCE_VERDICTS
    assert set(EVIDENCE_VERDICTS) == {"shim_hit_named", "shim_hit_unknown_table"}
    assert set(EVIDENCE_VERDICTS) <= set(VERDICTS)


def test_unknown_table_verdict_says_not_in_the_seven():
    """Review Focus 3: tier 2 is a handoff to a static lookup, not a negative proof.

    The fence is on wording, because wording is what reaches the evidence volume:
    the driver must say "handoff to a static lookup" / 「不在这七张里」 and must
    never say anything of the form 「族外没有另一份表」 (the map is a FLOOR —
    AGENTS 段3 第 3 行).
    """
    doc = (shim.__doc__ or "") + (verdict_for.__doc__ or "")
    for banned in ("族外没有另一份表", "no other table exists",
                   "proves it is not a CEffect", "证明它不是 CEffect"):
        assert banned not in doc, f"措辞越界:{banned!r}"
    assert "静态查表" in verdict_for.__doc__, (
        "tier 2 必须写明它是交给静态查表的接力")
    assert "七张" in verdict_for.__doc__


def test_stats_keys_has_fourteen_entries_in_dll_order():
    """14 keys, same order as ``statsInto`` — a torn line must not become a verdict."""
    assert len(STATS_KEYS) == 14
    assert STATS_KEYS == (
        "calls", "samples", "invalid_self", "unmatched",
        "h0", "h1", "h2", "h3", "h4", "h5", "h6",
        "patch_size", "installed", "mask",
    )
    assert tuple(STATS_KEYS) == zig_stats_key_order()


def test_layout_words_are_entry48_stats64_ring256():
    """[48, 64, 256, mask_lo, mask_hi, 1] — Stats is 64 here, NOT the family's 56.

    That one word is how a shot's #meta line identifies which guard was armed, so
    a driver that accepted 56 would happily read the witness module's stats line
    and decode h5/h6 as patch_size/installed.
    """
    layout = decode_layout(GOOD_LAYOUT)
    assert layout["entry"] == 48
    assert layout["stats"] == 64
    assert layout["ring"] == 256
    assert layout["version"] == 1
    for stats_size in (56, 48, 72):
        words = list(GOOD_LAYOUT)
        words[1] = stats_size
        with pytest.raises(ValueError):
            decode_layout(words)
    for bad_version in (0, 2):
        words = list(GOOD_LAYOUT)
        words[5] = bad_version
        with pytest.raises(ValueError):
            decode_layout(words)
    with pytest.raises(ValueError):
        decode_layout(GOOD_LAYOUT[:5])
    # mask is split across two words; the driver recombines, never reads word 3 alone.
    assert decode_layout([48, 64, 256, 0x1FF, 0, 1])["mask"] == 0x1FF
    assert decode_layout([48, 64, 256, 0, 1, 1])["mask"] == 1 << 32


def test_expected_code_matches_disrva():
    """The Zig fingerprint must equal the bytes on disk at 0xCC4220.

    With the exe copy present this is the full three-way check (exe ↔ Zig ↔ this
    file's literal); without it, the literal and the Zig module are still compared
    so the fence never silently degrades to "skipped".
    """
    src = ZIG_MODULE.read_text(encoding="utf-8")
    want = zig_array_literal(src, "EXPECTED_CODE")
    assert len(want) == 24
    assert want == TASK1_PROLOGUE
    exe = disrva.resolve_exe()
    if exe is None:
        pytest.skip("no stellaris.exe copy on this host — literal ↔ Zig still checked")
    got = list(disrva.rd(SHIM_RVA, 24)[0])
    assert want == got, "Zig 指纹与磁盘上的 stellaris.exe 不一致"


# ---------------------------------------------------------------------------
# The same-target fences the witness file carries (kept, because drift here is
# just as silent)
# ---------------------------------------------------------------------------

def test_shim_vtables_match_zig_and_census():
    """The seven tables: Zig ↔ census ↔ this file's literal, order included.

    Order is load-bearing: ``matched`` is ``1 + index``, so a reordered list keeps
    the set and breaks every ``hN`` reading — that is the drift this fence exists
    for.  ``table_rvas()`` is the driver's copy, ``OUT_OF_FAMILY_VTABLES`` the
    module's, the census line the authority.
    """
    src = ZIG_MODULE.read_text(encoding="utf-8")
    assert zig_array_literal(src, "OUT_OF_FAMILY_VTABLES") == TASK1_OUT_OF_FAMILY_VTABLES
    assert census_vtables() == TASK1_OUT_OF_FAMILY_VTABLES
    assert list(table_rvas()) == TASK1_OUT_OF_FAMILY_VTABLES
    assert shim.TARGET_RVA == SHIM_RVA


def test_prologue_triangulation_pins_the_evidence_volume():
    """§71.5 must carry the same 24 bytes the module and the exe carry.

    A fingerprint that drifts together with the volume is still wrong, so the
    volume is read here as a third copy: the hex run in §71.1's 「24 B 前序」 row.
    """
    text = EVIDENCE_VOLUME.read_text(encoding="utf-8")
    section = text[text.index("## §71 "):]
    match = re.search(r"^\| 24 B 前序 \| `([0-9a-f ]+)`", section, re.M)
    assert match is not None, "§71.1 表里没有 24 B 前序行"
    covered = [int(tok, 16) for tok in match.group(1).split()]
    assert covered == TASK1_PROLOGUE


def test_decode_entry_reads_all_fields():
    """48-byte Entry; ``matched`` is 1 + index into the SEVEN tables, 0 = none."""
    # Seven tables ⇒ indices 0..6, so matched == 7 is the LAST real table.
    raw = struct.pack("<BBHII4xQQQQ", 1, 7, 0, 0x2553140, 0x1A2B3C,
                      0x10AB, 0x20CD, 0x30EF, 0x4001)
    assert len(raw) == shim.ENTRY_SIZE == 48
    entry = decode_entry(raw)
    assert entry["valid"] == 1
    assert entry["matched"] == 7
    assert entry["table_index"] == 6
    assert entry["table_rva"] == 0x2553140
    assert entry["self_vtable_rva"] == 0x2553140
    assert entry["caller_rva"] == 0x1A2B3C
    assert entry["self_ptr"] == 0x10AB
    assert entry["ctx_ptr"] == 0x20CD
    assert entry["a3"] == 0x30EF
    assert entry["a4"] == 0x4001

    unmatched = decode_entry(struct.pack("<BBHII4xQQQQ", 1, 0, 0, 0x2606FE0,
                                         0x10, 1, 2, 3, 4))
    assert unmatched["table_index"] is None
    assert unmatched["table_rva"] is None
    # matched=8 would be index 7 — one past the seven tables ⇒ layout drift, no name.
    drift = decode_entry(struct.pack("<BBHII4xQQQQ", 1, 8, 0, 0x1, 0x2, 1, 2, 3, 4))
    assert drift["table_index"] is None
    with pytest.raises(ValueError):
        decode_entry(raw[:47])


def test_decode_stats_parses_every_key():
    """14 keys, ``mask`` in hex and everything else decimal (per-key base)."""
    text = ("calls=17 samples=17 invalid_self=1 unmatched=5 h0=2 h1=0 h2=0 h3=0 "
            "h4=0 h5=3 h6=0 patch_size=16 installed=1 mask=1ff\n")
    stats = decode_stats(text)
    assert set(stats) == set(STATS_KEYS)
    assert [stats[f"h{i}"] for i in range(7)] == [2, 0, 0, 0, 0, 3, 0]
    assert stats["patch_size"] == 16
    assert stats["mask"] == 0x1FF
    with pytest.raises(ValueError):
        decode_stats(text.replace("h6=0 ", ""))
    with pytest.raises(ValueError):
        decode_stats(text + " h7=1")


def test_verdict_ladder_shapes():
    """Every counter shape answers with a domain member, and the ladder's order holds."""
    assert verdict_for(_stats()) == "no_calls_inconclusive"
    assert verdict_for(_stats(calls=7, samples=7, invalid_self=7)) == "instrument_broken"
    assert verdict_for(_stats(calls=17, samples=17, h5=3, unmatched=1)) == "shim_hit_named"
    assert verdict_for(_stats(calls=9, samples=9, unmatched=9)) == "shim_hit_unknown_table"
    assert verdict_for(_stats(calls=9, samples=9, unmatched=9, installed=0)) == "counter_desync"
    for calls, invalid, unmatched, hit in (
        (0, 0, 0, 0), (5, 5, 0, 0), (5, 2, 3, 0), (5, 0, 0, 1),
        (5, 0, 5, 0), (5, 3, 0, 0), (5, 0, 0, 0),
    ):
        stats = _stats(calls=calls, invalid_self=invalid, unmatched=unmatched,
                       patch_size=15)
        if hit:
            stats["h6"] = hit
        if invalid or unmatched or hit:
            stats["samples"] = calls
        assert verdict_for(stats) in VERDICTS


def test_named_table_resolves_through_the_seven():
    """A named hit must name a real RVA from the same seven the module joins."""
    stats = _stats(calls=17, samples=17, h5=4, h6=1)
    assert shim.named_table(stats) == 0x2553178   # index 5, the larger count
    assert shim.named_table(_stats(calls=1, samples=1, unmatched=1)) is None


def test_build_meta_keeps_every_key_and_the_target_rva():
    common = {
        "exe_base": 0x140000000,
        "image_end": 0x140000000 + 0x3927000,
        "dll_path": r"C:/temp/sqjs_c4.dll",
        "dll_sha": "deadbeef",
        "mask": 0,
        "poll_s": 120.0,
        "layout": {"entry": 48, "stats": 64, "ring": 256, "mask": 0,
                   "version": 1},
        "stats": _stats(calls=3, samples=3, unmatched=3),
        "stats_text": "calls=3 samples=3",
        "entries": [],
        "verdict": "shim_hit_unknown_table",
        "table": None,
        "install_rc": 0,
    }
    meta = shim.build_meta(**common)
    for key in ("exe_base", "image_size", "image_end", "dll", "dll_sha256",
                "target_rva", "mask", "poll_s", "layout", "calls", "samples",
                "entries", "tiers", "verdict", "named_table", "install_rc", "stats"):
        assert key in meta, f"build_meta dropped an original key {key!r}"
    assert meta["target_rva"] == f"0x{SHIM_RVA:x}"
    assert meta["tiers"].startswith("h0=0/h1=0/h2=0/h3=0/h4=0/h5=0/h6=0")


def test_cleanup_escalates_verify_without_install(monkeypatch, capsys):
    """A bad verify escalates even when this run never completed an install (witness Finding 3)."""
    exports = {"C4ShimProbeUninstall": 0x11, "C4ShimProbeVerify": 0x22}
    state = {"verify": -2}

    def fake_call_remote(pid, base, rva, *a, **k):
        return state["verify"] if rva == exports["C4ShimProbeVerify"] else 0

    monkeypatch.setattr(shim, "call_remote", fake_call_remote)
    monkeypatch.setattr(shim, "call_remote_with_arg", lambda *a, **k: 0)
    monkeypatch.setattr(shim, "assert_game_alive", lambda pid: None)

    assert shim._cleanup(1234, 0x140000000, exports, False, 0) is False
    assert "RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY" in capsys.readouterr().out
    state["verify"] = -3
    assert shim._cleanup(1234, 0x140000000, exports, False, 0) is True
    assert "RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY" not in capsys.readouterr().out


def test_run_writes_the_artifact_before_it_drains_the_ring():
    """Order protection (§56): the meta-only artifact lands before the ring is touched."""
    src = inspect.getsource(shim.run)
    readable = src.index("stats, stats_text = last_good")
    drained = src.index("entries = drain_entries(", readable)
    window = src[readable:drained]
    assert "write_tsv(out_path, [], meta)" in window
    assert "rows = write_tsv(out_path, entries, meta)" in src[drained:]
