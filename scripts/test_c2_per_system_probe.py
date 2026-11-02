#!/usr/bin/env python3
"""test_c2_per_system_probe.py — 第七把 guard 的离线围栏(零游戏、零 Windows API)。

围栏分三层:
  * 契约层:Entry/Stats 的尺寸与字段序、stats 行的键序、layout 六词 —— 直接读 Zig 源码,
    任何一边改了字面量都会红;
  * 判读层:`verdict` 的十二档、容器解码、meta/artifact;
  * 门序层:安装码表、路径与命令通道的拒绝。

Task 3 建了契约层的两条;Task 4 长全判读层。
"""
from __future__ import annotations

import pathlib
import struct

import pytest

import c2_per_system_probe as mod
from c2_per_system_probe import (
    EVIDENCE_VERDICTS,
    STATS_KEYS,
    TARGET_RVA,
    VERDICTS,
    artifact_rows,
    build_meta,
    decode_container,
    decode_entry,
    decode_layout,
    gate_label,
    install_decision,
    parse_stats,
    preflight_paths,
    refuse_if_resident,
    script_marker,
    sha_gate,
    verdict,
    verdict_watch,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIG = REPO_ROOT / "src/dll/c2/per_system_probe.zig"
EXPORTS_ZIG = REPO_ROOT / "src/dll/exports.zig"


def test_entry_size_matches_the_zig_module():
    src = ZIG.read_text()
    assert "@sizeOf(Entry) != 32" in src   # comptime 断言在源码里
    assert "@sizeOf(Stats) != 56" in src


def test_the_eight_exports_exist_in_the_zig_source():
    src = EXPORTS_ZIG.read_text()
    for name in ("C5PerSystemInstall", "C5PerSystemUninstall", "C5PerSystemVerify",
                 "C5PerSystemLayout", "C5PerSystemStatsInto", "C5PerSystemSetDrainCap",
                 "C5PerSystemDrainInto", "C5PerSystemReset"):
        assert f"export fn {name}" in src, f"missing export fn {name}"


# --- fixtures ---------------------------------------------------------------------


def _stats(**over):
    stats = dict.fromkeys(STATS_KEYS, 0)
    stats.update({"calls": 10_000, "matched": 787, "distinct_ids": 787,
                  "patch_size": 15, "installed": 1, "verify": 0})
    stats.update(over)
    return stats


def _rows(ids):
    return [{"id": i, "mask": 0x80, "self_vtable_rva": mod.VTABLE_RVA,
             "occurrences": 1, "obj": 0, "scope_ptr": 0x1000 + i} for i in ids]


def _container(ids):
    return {"raw_count": len(ids), "ids": list(ids)}


GALAXY = list(range(1, 788))   # 787 systems, ids 1..787


# --- contract ---------------------------------------------------------------------


def test_layout_words_decode_with_the_linux_module_contract():
    layout = decode_layout([1, 32, 2048, 56, TARGET_RVA, mod.VTABLE_RVA])
    assert layout["entry_size"] == 32
    assert layout["ring_len"] == 2048
    assert layout["target_rva"] == TARGET_RVA
    assert layout["vtable_rva"] == 0x26562D0


def test_stats_keys_match_the_dll_line():
    src = ZIG.read_text()
    line = [ln for ln in src.splitlines() if "calls={d} matched={d}" in ln]
    assert line, "statsInto format line not found"
    assert [key for key in STATS_KEYS if f"{key}={{d}}" in line[0]] == list(STATS_KEYS)


def test_parse_stats_rejects_a_missing_key():
    with pytest.raises(ValueError, match="missing"):
        parse_stats("calls=1 matched=2")


def test_decode_entry_matches_the_zig_field_order():
    blob = struct.pack("<IIIIQQ", 42, 0x80, 0x26562D0, 3, 0, 0x1000)
    entry = decode_entry(blob)
    assert entry == {"id": 42, "mask": 0x80, "self_vtable_rva": 0x26562D0,
                     "occurrences": 3, "obj": 0, "scope_ptr": 0x1000}


def test_artifact_rows_are_six_columns_in_order():
    rows = artifact_rows(_rows([42]))
    assert rows[0].split("\t") == ["42", "0x80", "0x26562d0", "1", "0x0", "0x102a"]


def test_build_meta_carries_save_name_and_systems():
    lines = build_meta(overall_verdict="per_system_loop", systems=787,
                       save_name="autosave_2231.07.01.sav", container_raw_count=787)
    assert "systems=787" in lines
    assert "save_name=autosave_2231.07.01.sav" in lines
    assert lines == sorted(lines)


# --- container --------------------------------------------------------------------


def test_decode_container_reads_exactly_count_ids():
    blob = struct.pack("<3I", 7, 8, 9)
    assert decode_container(blob, 3) == [7, 8, 9]
    with pytest.raises(ValueError, match="did not agree"):
        decode_container(blob + b"\x00", 3)


def test_decode_container_short_blob_raises():
    with pytest.raises(ValueError):
        decode_container(b"\x01\x00\x00\x00", 2)


# --- verdict ----------------------------------------------------------------------


def test_verdict_instrument_broken_wins():
    stats = _stats(verify=-1)
    assert verdict(stats, _rows(GALAXY), _container(GALAXY), expected=787,
                   script_sends=1, log_hits=787) == "instrument_broken"
    # A layout that points at another target is the same class of failure.
    layout = decode_layout([1, 32, 2048, 56, 0x1A91A80, mod.VTABLE_RVA])
    assert verdict(_stats(), _rows(GALAXY), _container(GALAXY), expected=787,
                   script_sends=1, log_hits=787, layout=layout) == "instrument_broken"


def test_verdict_no_calls_is_environment():
    assert verdict(_stats(calls=0), [], _container(GALAXY), expected=787,
                   script_sends=1, log_hits=787) == "no_calls"


def test_verdict_filter_missed_when_log_hits_exist():
    assert verdict(_stats(matched=0, distinct_ids=0), [], _container(GALAXY), expected=787,
                   script_sends=1, log_hits=787) == "filter_missed"


def test_verdict_script_refused_when_no_log_receipt():
    assert verdict(_stats(), _rows(GALAXY), _container(GALAXY), expected=787,
                   script_sends=1, log_hits=0) == "script_refused"


def test_verdict_per_system_loop_is_the_only_clean_branch():
    assert verdict(_stats(), _rows(GALAXY), _container(GALAXY), expected=787,
                   script_sends=1, log_hits=787) == "per_system_loop"


def test_verdict_per_system_loop_filtered():
    ids = GALAXY[:780]
    assert verdict(_stats(matched=780, distinct_ids=780), _rows(ids), _container(GALAXY),
                   expected=787, script_sends=1, log_hits=780) == "per_system_loop_filtered"


def test_verdict_loop_not_per_system():
    # 787 dispatches but only 780 distinct ids: some id went out twice.
    assert verdict(_stats(matched=787, distinct_ids=780), _rows(GALAXY[:780]),
                   _container(GALAXY), expected=787, script_sends=1,
                   log_hits=787) == "loop_not_per_system"


def test_verdict_denominator_mismatch():
    ids = list(range(1, 701))
    assert verdict(_stats(matched=700, distinct_ids=700), _rows(ids), _container(ids),
                   expected=787, script_sends=1, log_hits=700) == "dispatch_denominator_mismatch"


def test_verdict_ids_not_in_container():
    container = list(range(1, 787)) + [999]
    assert verdict(_stats(), _rows(GALAXY), _container(container), expected=787,
                   script_sends=1, log_hits=787) == "ids_not_in_container"


def test_verdict_id_out_of_range():
    bad = [0] + GALAXY[1:]
    assert verdict(_stats(), _rows(bad), _container(GALAXY), expected=787,
                   script_sends=1, log_hits=787) == "ids_out_of_range"


def test_verdict_container_unreadable():
    assert verdict(_stats(), _rows(GALAXY), {"raw_count": 787, "ids": []}, expected=787,
                   script_sends=1, log_hits=787) == "container_unreadable"


def test_verdict_multiple_script_sends_scale():
    rows = _rows(GALAXY)
    for row in rows:
        row["occurrences"] = 2
    assert verdict(_stats(matched=1574, distinct_ids=787), rows, _container(GALAXY),
                   expected=787, script_sends=2, log_hits=1574) == "per_system_loop"


def test_verdict_dedupe_full_is_never_evidence():
    assert verdict(_stats(dedupe_full=3), _rows(GALAXY), _container(GALAXY), expected=787,
                   script_sends=1, log_hits=787) == "dedupe_full"
    assert "dedupe_full" not in EVIDENCE_VERDICTS


def test_verdict_values_are_all_in_the_vocabulary():
    assert set(EVIDENCE_VERDICTS) < set(VERDICTS)
    assert VERDICTS[0] == "instrument_broken"


# --- gates ------------------------------------------------------------------------


def test_install_decision_rejects_stale_target():
    good = decode_layout([1, 32, 2048, 56, TARGET_RVA, mod.VTABLE_RVA])
    stale = decode_layout([1, 32, 2048, 56, 0x1A91A80, mod.VTABLE_RVA])
    assert install_decision(0, good) == "ok"
    assert install_decision(-2, good) == "refused"
    assert install_decision(0, stale) == "stale_target"


def test_script_marker_stops_at_bracket():
    assert script_marker('effect every_system = { log = "PS_HIT" }') == "PS_HIT"
    assert script_marker('effect every_system = { log = "PS_[This.GetName]" }') == "PS_"
    assert script_marker("effect every_system = { }") is None


def test_preflight_paths_rejects_missing_script():
    with pytest.raises(SystemExit) as exc:
        preflight_paths("/no/such/script.txt", "C:\\temp\\ns_game_cmd.txt")
    assert exc.value.code == 2


def test_preflight_paths_rejects_wrong_cmd_path():
    script = pathlib.Path(__file__)
    for cmd in ("C:\\temp\\ns_cmd.txt", "C:\\other\\ns_game_cmd.txt"):
        with pytest.raises(SystemExit) as exc:
            preflight_paths(str(script), cmd)
        assert exc.value.code == 2
    preflight_paths(str(script), "C:\\temp\\ns_game_cmd.txt")   # the one that passes


def test_sha_gate_refuses_a_missing_file_and_hashes_a_real_one():
    with pytest.raises(SystemExit) as exc:
        sha_gate("/no/such/dll")
    assert exc.value.code == 2
    digest = sha_gate(__file__)
    assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)


def test_resident_module_refuses():
    with pytest.raises(SystemExit) as exc:
        refuse_if_resident("sqjs_c7.dll", 0x7FF6_0000)
    assert exc.value.code == 2
    refuse_if_resident("sqjs_c7.dll", None)


# --- live-path helpers (pure parts only) ------------------------------------------


def test_script_sends_is_the_transport_count():
    log = "PS_HIT alpha\nPS_HIT beta\n"
    assert mod.count_marker(log, "PS_HIT") == 2
    assert mod.count_marker(log, None) == 0
    assert mod.count_marker("", "PS_HIT") == 0
    assert "script_sends=2" in build_meta(script_sends=2, log_hits=2)


# --- watch-only mode (no console script: let the game's own scripts dispatch) -----


def test_watch_per_system_loop_requires_full_runs_and_full_coverage():
    rows = _rows(GALAXY)
    stats = _stats(matched=787 * 2, distinct_ids=787)
    for row in rows:
        row["occurrences"] = 2
    assert verdict_watch(stats, rows, _container(GALAXY), expected=787) == "per_system_loop_watch"


def test_watch_loop_partial_when_matched_is_not_a_multiple():
    rows = _rows(GALAXY[:500])
    stats = _stats(matched=500, distinct_ids=500)
    assert verdict_watch(stats, rows, _container(GALAXY), expected=787) == "loop_partial_watch"


def test_watch_loop_not_invoked_is_environment():
    stats = _stats(calls=5, matched=0)
    assert verdict_watch(stats, [], _container(GALAXY), expected=787) == "loop_not_invoked"


def test_watch_no_calls_is_environment():
    assert verdict_watch(_stats(calls=0, matched=0), [], _container(GALAXY),
                         expected=787) == "no_calls"


def test_watch_instrument_broken_wins():
    stats = _stats(verify=-1)
    assert verdict_watch(stats, _rows(GALAXY), _container(GALAXY), expected=787) == "instrument_broken"


def test_gate_label_records_an_operator_override():
    assert gate_label(False) == "world_state"
    assert gate_label(True) == "operator_override"


# --- watch-only + --marker: the two meanings of `calls/matched == 0` --------------


def test_watch_calls_zero_with_marker_hits_is_a_target_negative():
    """The loop demonstrably ran (marker lines in game.log) yet the detour never fired.

    That is a fact about the *target*, not an environment reading: before `--marker`
    existed, the same artifact said `no_calls` and could not be told apart from
    "the game dispatched nothing at all" (2026-11-01, §89).
    """
    stats = _stats(calls=0, matched=0)
    reading = verdict_watch(stats, [], _container(GALAXY), expected=787, marker_hits=12_544)
    assert reading == "target_not_on_path"
    assert reading in EVIDENCE_VERDICTS


def test_watch_matched_zero_with_marker_hits_is_filter_missed():
    stats = _stats(calls=5, matched=0)          # hook alive, vtable filter never matched
    assert verdict_watch(stats, [], _container(GALAXY), expected=787,
                         marker_hits=784) == "filter_missed"


def test_watch_marker_hits_absent_keeps_the_two_environment_readings():
    """No `--marker` on the command line -> `None` -> the old readings, unchanged."""
    assert verdict_watch(_stats(calls=0, matched=0), [], _container(GALAXY),
                         expected=787) == "no_calls"
    assert verdict_watch(_stats(calls=5, matched=0), [], _container(GALAXY),
                         expected=787) == "loop_not_invoked"


def test_marker_zero_hits_is_not_a_target_negative():
    stats = _stats(calls=0, matched=0)
    assert verdict_watch(stats, [], _container(GALAXY), expected=787,
                         marker_hits=0) == "no_calls"


def test_target_not_on_path_is_in_the_vocabulary_and_is_evidence():
    assert "target_not_on_path" in VERDICTS
    assert "target_not_on_path" in EVIDENCE_VERDICTS


def test_marker_scope_error_refuses_marker_without_watch_only():
    assert mod.marker_scope_error(watch_only=True, marker="PS_HIT") is None
    assert mod.marker_scope_error(watch_only=False, marker=None) is None
    message = mod.marker_scope_error(watch_only=False, marker="PS_HIT")
    assert message and "--watch-only" in message


def test_marker_window_is_none_without_a_marker():
    """No `--marker` -> no window -> `None` (not 0: 0 would read as "the loop never ran")."""
    assert mod.marker_window("C:/temp/game.log", None) is None
    assert mod.marker_hits_since("C:/temp/game.log", None, "PS_HIT") is None


def test_resolve_game_log_falls_back_to_the_default_when_none_is_given():
    """`--game-log` absent must not mean "empty path" (2026-11-01 live run read nothing)."""
    assert mod.resolve_game_log(None, default="C:/temp/game.log") == "C:/temp/game.log"
    assert mod.resolve_game_log("", default="C:/temp/game.log") == "C:/temp/game.log"
    assert mod.resolve_game_log("C:/temp/mine.log", default="C:/temp/game.log") == "C:/temp/mine.log"
