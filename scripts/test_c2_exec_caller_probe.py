#!/usr/bin/env python3
"""test_c2_exec_caller_probe.py — 第八把 guard 的离线围栏(零游戏、零 Windows API)。

三层:
  * 契约层:Entry 32 B 字段序、Stats 48 B、stats 行八键、layout 六词、八个导出 —— 直接读 Zig 源码;
  * 判读层:`verdict` 的十一档、容器解码、artifact 六列;
  * 门序层:安装码表、sha 门、同名模块拒绝。
"""
from __future__ import annotations

import pathlib
import struct

import pytest

import c2_exec_caller_probe as mod
from c2_exec_caller_probe import (
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
    refuse_if_resident,
    sha_gate,
    verdict,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIG = REPO_ROOT / "src/dll/c2/exec_caller_probe.zig"
EXPORTS_ZIG = REPO_ROOT / "src/dll/exports.zig"


def test_entry_size_matches_the_zig_module():
    src = ZIG.read_text()
    assert "@sizeOf(Entry) != 32" in src
    assert "@sizeOf(Stats) != 48" in src


def test_the_eight_exports_exist_in_the_zig_source():
    src = EXPORTS_ZIG.read_text()
    for name in ("C6ExecCallerInstall", "C6ExecCallerUninstall", "C6ExecCallerVerify",
                 "C6ExecCallerLayout", "C6ExecCallerStatsInto", "C6ExecCallerSetDrainCap",
                 "C6ExecCallerDrainInto", "C6ExecCallerReset"):
        assert f"export fn {name}" in src, f"missing export fn {name}"


def test_stats_keys_match_the_dll_line():
    src = ZIG.read_text()
    line = [ln for ln in src.splitlines() if "calls={d} distinct_ids={d}" in ln]
    assert line, "statsInto format line not found"
    assert [key for key in STATS_KEYS if f"{key}={{d}}" in line[0]] == list(STATS_KEYS)


# --- fixtures ---------------------------------------------------------------------


def _stats(**over):
    stats = dict.fromkeys(STATS_KEYS, 0)
    stats.update({"calls": 12_544, "distinct_ids": 788, "patch_size": 15,
                  "installed": 1, "verify": 0})
    stats.update(over)
    return stats


def _rows(ids, caller=0x1D08520):
    return [{"caller_rva": caller, "id": i, "mask": 0x80, "occurrences": 1,
             "self_ptr": 0x2000 + i, "scope_ptr": 0x1000 + i} for i in ids]


def _container(ids):
    return {"raw_count": len(ids), "ids": list(ids)}


GALAXY = list(range(1, 789))   # 788 systems, ids 1..788


# --- contract ---------------------------------------------------------------------


def test_layout_words_decode_with_the_linux_module_contract():
    layout = decode_layout([1, 32, 2048, 48, TARGET_RVA, 0])
    assert layout["entry_size"] == 32
    assert layout["ring_len"] == 2048
    assert layout["target_rva"] == TARGET_RVA
    assert layout["vtable_rva"] == 0


def test_parse_stats_rejects_a_missing_key():
    with pytest.raises(ValueError, match="missing"):
        parse_stats("calls=1 distinct_ids=2")


def test_decode_entry_matches_the_zig_field_order():
    blob = struct.pack("<IIIIQQ", 0x1D08520, 42, 0x80, 3, 0x2000, 0x1000)
    entry = decode_entry(blob)
    assert entry == {"caller_rva": 0x1D08520, "id": 42, "mask": 0x80,
                     "occurrences": 3, "self_ptr": 0x2000, "scope_ptr": 0x1000}


def test_decode_container_needs_one_consistent_blob():
    assert decode_container(struct.pack("<2I", 7, 9), 2) == [7, 9]
    with pytest.raises(ValueError, match="did not agree"):
        decode_container(struct.pack("<1I", 7), 2)


def test_artifact_rows_are_six_columns_in_order():
    rows = artifact_rows(_rows([42]))
    assert rows[0].split("\t") == ["0x1d08520", "42", "0x80", "1", "0x202a", "0x102a"]


def test_build_meta_carries_the_target_and_the_save():
    lines = build_meta(overall_verdict="dispatch_named", systems=788,
                       save_name="autosave_2282.01.01", container_raw_count=788)
    assert all(line.startswith("#meta ") for line in lines)
    assert lines == sorted(lines)


# --- judgement --------------------------------------------------------------------


def test_verdict_named_dispatch_is_evidence():
    rows = _rows(GALAXY)
    reading = verdict(_stats(), rows, _container(GALAXY), expected=788)
    assert reading == "dispatch_named"
    assert reading in EVIDENCE_VERDICTS


def test_verdict_no_calls_is_environment():
    assert verdict(_stats(calls=0, distinct_ids=0), [], _container(GALAXY), expected=788) == "no_calls"


def test_verdict_caller_unnamed_is_environment():
    rows = _rows(GALAXY, caller=0)      # the hook could not resolve a caller RVA
    assert verdict(_stats(), rows, _container(GALAXY), expected=788) == "caller_unnamed"


def test_verdict_caller_mixed_is_environment():
    rows = _rows(GALAXY[:400]) + _rows(GALAXY[400:], caller=0x1D0BA00)
    assert verdict(_stats(), rows, _container(GALAXY), expected=788) == "caller_mixed"


def test_verdict_scope_constant_is_environment():
    rows = _rows([5])                   # one id for every call: not the per-system scope shape
    assert verdict(_stats(distinct_ids=1), rows, _container(GALAXY), expected=788) == "scope_constant"


def test_verdict_ids_out_of_range_is_a_negative():
    rows = _rows([1, 2, 999])
    assert verdict(_stats(), rows, _container(GALAXY), expected=788) == "ids_out_of_range"
    assert "ids_out_of_range" in EVIDENCE_VERDICTS


def test_verdict_ids_not_in_container_is_a_negative():
    rows = _rows([1, 2, 3])             # 3 is in range but not in the container
    container = _container([1, 2, 5, 6, 7, 8, 9, 10, 11, 12])
    assert verdict(_stats(distinct_ids=3), rows, container, expected=10) == "ids_not_in_container"


def test_verdict_denominator_mismatch():
    rows = _rows([1, 2])
    assert verdict(_stats(), rows, _container(GALAXY), expected=787) == \
        "dispatch_denominator_mismatch"


def test_verdict_container_unreadable():
    assert verdict(_stats(), _rows([1]), None, expected=788) == "container_unreadable"


def test_verdict_dedupe_full_is_never_evidence():
    reading = verdict(_stats(dedupe_full=3), _rows(GALAXY), _container(GALAXY), expected=788)
    assert reading == "dedupe_full"
    assert reading not in EVIDENCE_VERDICTS


def test_verdict_instrument_broken_wins():
    stats = _stats(verify=-1)
    assert verdict(stats, _rows(GALAXY), _container(GALAXY), expected=788) == "instrument_broken"


def test_verdict_values_are_all_in_the_vocabulary():
    assert set(EVIDENCE_VERDICTS) < set(VERDICTS)
    assert VERDICTS[0] == "instrument_broken"


# --- gates ------------------------------------------------------------------------


def test_install_decision_rejects_stale_target():
    layout = decode_layout([1, 32, 2048, 48, 0x3B1330, 0])
    assert install_decision(0, layout) == "stale_target"
    assert install_decision(0, decode_layout([1, 32, 2048, 48, TARGET_RVA, 0])) == "ok"
    assert install_decision(-2, decode_layout([1, 32, 2048, 48, TARGET_RVA, 0])) == "refused"


def test_gate_label_records_an_operator_override():
    assert gate_label(False) == "world_state"
    assert gate_label(True) == "operator_override"


def test_sha_gate_refuses_a_missing_file_and_hashes_a_real_one(tmp_path):
    with pytest.raises(SystemExit) as exc:
        sha_gate(str(tmp_path / "nope.dll"))
    assert exc.value.code == 2
    target = tmp_path / "x.dll"
    target.write_bytes(b"abc")
    assert sha_gate(str(target)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_resident_module_refuses():
    refuse_if_resident("sqjs_c10.dll", 0)          # not resident -> fine
    with pytest.raises(SystemExit) as exc:
        refuse_if_resident("sqjs_c10.dll", 0x7FF8EB220000)
    assert exc.value.code == 2


def test_the_detour_forwards_with_a_tail_call():
    """§91.1: the trampoline is a verbatim prologue copy, so `rsp` must not move by 8.

    A plain `call` shifts it, and this target's prologue saves rbx/rsi/rdi into
    `[rsp+0x10/0x18/0x20]` — shifted, the epilogue restores them from the wrong slots
    (three corrupted callee-saved registers per dispatch; the game died 3/3 shots).
    """
    src = ZIG.read_text()
    assert "@call(.always_tail, f," in src
    assert "return f(self, scope, a3);" not in src


def test_record_mode_default_is_the_full_path():
    """§91.2: 0/1 are bisect builds (count-only / reads-only); the shipped value is 2."""
    src = ZIG.read_text()
    assert "const RECORD_MODE: u8 = 2;" in src
