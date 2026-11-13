#!/usr/bin/env python3
"""test_c2_capability_probe.py — C3 自检驱动的离线围栏(零游戏、零 Windows API)。

三层:
  * 契约层:`CHECK_IDS` / `STATUSES` / `REASONS` / `STATS_SIZE` 与 `capability.zig` 的**字面量互校**
    (Review Focus 3:两边各有一份名字与顺序,漂了就红);三个导出在 `exports.zig` 里可 grep 到;
  * 判读层:`fold_verdict` 的五档、失败项按次序排列、`state_cleared` 与见证两个报告字段;
  * 门序层:`sha_gate` / `refuse_if_resident` / 装拆码表。
"""
from __future__ import annotations

import pathlib
import re
import struct

import pytest

import c2_capability_probe as mod
from c2_capability_probe import (
    CHECK_IDS,
    LAYOUT_VERSION,
    REASONS,
    STATS_SIZE,
    STATUSES,
    WITNESS,
    apply_environment,
    artifact_rows,
    build_meta,
    decode_layout,
    decode_stats,
    fold_verdict,
    gate_label,
    install_decision,
    ran_once,
    refuse_if_resident,
    sha_gate,
    verdict_line,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIG = REPO_ROOT / "src/dll/c2/capability.zig"
EXPORTS_ZIG = REPO_ROOT / "src/dll/exports.zig"


# --- contract layer: the two literal tables must agree ----------------------------


def _zig_check_names():
    src = ZIG.read_text(encoding="utf-8")
    block = re.search(r"pub const CHECK_NAMES = \[_\]\[\]const u8\{(.*?)\};", src, re.DOTALL)
    assert block, "CHECK_NAMES not found in capability.zig"
    return tuple(re.findall(r'"([a-z_]+)"', block.group(1)))


def _zig_enum(name):
    src = ZIG.read_text(encoding="utf-8")
    block = re.search(rf"pub const {name} = enum\(u8\) \{{(.*?)\}};", src, re.DOTALL)
    assert block, f"{name} enum not found in capability.zig"
    return {key: int(value) for key, value in re.findall(r"(\w+) = (\d+)", block.group(1))}


def test_check_ids_match_the_dll_order():
    assert CHECK_IDS == ("scope", "token", "descriptor", "graph", "state", "vtable", "fingerprint")
    assert _zig_check_names() == CHECK_IDS


def test_status_codes_match_the_dll_enum():
    assert _zig_enum("Status") == {name: code for code, name in STATUSES.items()}


def test_reasons_match_the_dll_enum():
    assert _zig_enum("Reason") == {name: code for code, name in REASONS.items()}


def test_stats_size_is_seven_pairs_in_both_places():
    src = ZIG.read_text(encoding="utf-8")
    assert "pub const STATS_SIZE: usize = CHECK_COUNT * 8;" in src
    assert STATS_SIZE == 7 * 8


def test_the_three_exports_exist_in_the_zig_source():
    src = EXPORTS_ZIG.read_text(encoding="utf-8")
    for name in ("C3CapabilityLayout", "C3CapabilityStatsInto", "C3CapabilityReset"):
        assert f"export fn {name}" in src, f"missing export fn {name}"


def test_layout_version_matches_the_dll():
    src = ZIG.read_text(encoding="utf-8")
    assert f"pub const LAYOUT_VERSION: u32 = {LAYOUT_VERSION};" in src


# --- wire decoding ----------------------------------------------------------------


def test_decode_layout_takes_two_words():
    assert decode_layout([1, 7]) == {"version": 1, "check_count": 7}
    with pytest.raises(ValueError):
        decode_layout([1])


def test_decode_stats_pairs_status_with_reason():
    blob = struct.pack("<II", 2, 4) + struct.pack("<II", 1, 0) * 6
    stats = decode_stats(blob)
    assert stats[0] == (2, 4)
    assert stats[1] == (1, 0)
    with pytest.raises(ValueError):
        decode_stats(b"\0" * 40)


# --- judgement --------------------------------------------------------------------


def test_fold_returns_capability_named_only_with_the_script_witness():
    stats = [(1, 0)] * 5 + [(3, 0)] + [(1, 0)]
    assert fold_verdict([1, 7], stats, ["NEO_CAP_VAR_OK"])[0] == "capability_named"
    assert fold_verdict([1, 7], stats, [])[0] == "capability_partial"
    assert fold_verdict([1, 7], stats, [])[1]["missing_witness"] is True


def test_fold_orders_failures_by_check_name():
    stats = [(1, 0), (2, 2), (1, 0), (2, 4), (1, 0), (1, 0), (1, 0)]
    verdict, detail = fold_verdict([1, 7], stats, ["NEO_CAP_VAR_OK"])
    assert verdict == "capability_failed"
    assert detail["failed"] == ["token:mismatch", "graph:out_of_range"]


def test_fold_reports_instrument_and_environment():
    assert fold_verdict([2, 7], [], [])[0] == "instrument_broken"
    assert fold_verdict([1, 7], [(0, 0)] * 7, [])[0] == "capability_partial"


def test_fold_flags_a_state_row_that_was_written_but_not_cleared():
    stats = [(1, 0), (1, 0), (1, 0), (1, 0), (1, 6), (1, 0), (1, 0)]
    verdict, detail = fold_verdict([1, 7], stats, ["NEO_CAP_VAR_OK"])
    assert verdict == "capability_named"          # 写成功了,只是没收回
    assert detail["state_cleared"] is False       # 但报告必须能看出残留


def test_fold_keeps_presence_out_of_the_failure_list():
    stats = [(1, 0), (1, 0), (1, 0), (1, 0), (1, 0), (3, 0), (1, 0)]
    verdict, detail = fold_verdict([1, 7], stats, ["NEO_CAP_VAR_OK"])
    assert verdict == "capability_named"
    assert detail["presence"] == ["vtable"]
    assert detail["failed"] == []


def test_environment_needs_no_dispatch_and_no_matrix():
    skips = [(0, 0)] * 7
    ok = [(1, 0)] * 7
    assert apply_environment("capability_partial", dispatched=False, stats=skips) == "environment"
    # 派发过、或者矩阵真跑过 ⇒ 不是环境档。
    assert apply_environment("capability_partial", dispatched=True, stats=skips) == "capability_partial"
    assert apply_environment("capability_named", dispatched=False, stats=ok) == "capability_named"
    assert apply_environment("instrument_broken", dispatched=False, stats=skips) == "instrument_broken"


def test_ran_once_reads_the_matrix():
    assert ran_once([(0, 0)] * 7) is False
    assert ran_once([(0, 0)] * 6 + [(1, 0)]) is True


def test_verdict_line_carries_the_two_report_fields():
    _verdict, detail = fold_verdict([1, 7], [(1, 0)] * 7, [])
    detail["stats"] = [(1, 0)] * 7
    line = verdict_line("capability_partial", detail)
    assert line.startswith("CAPABILITY capability_partial")
    assert "state_cleared=1" in line and "witness=0" in line


def test_artifact_rows_are_one_per_check_in_order():
    detail = {"stats": [(1, 0), (2, 2), (0, 3), (3, 0), (1, 6), (1, 0), (1, 0)]}
    rows = artifact_rows(detail)
    assert [row.split("\t")[0] for row in rows] == list(CHECK_IDS)
    assert rows[1] == "token\tfail\tmismatch"
    assert rows[2] == "descriptor\tskip\tno_scope"


def test_witness_is_the_script_side_marker():
    assert WITNESS == "NEO_CAP_VAR_OK"


# --- gate layer -------------------------------------------------------------------


def test_meta_block_is_sorted_and_prefixed():
    lines = build_meta(zeta=1, alpha=2)
    assert lines == ["#meta alpha=2", "#meta zeta=1"]


def test_sha_gate_refuses_a_missing_file(tmp_path):
    with pytest.raises(SystemExit) as exc:
        sha_gate(str(tmp_path / "nope.dll"))
    assert exc.value.code == mod.EXIT_REFUSED


def test_sha_gate_hashes_the_file(tmp_path):
    dll = tmp_path / "x.dll"
    dll.write_bytes(b"ab")
    assert sha_gate(str(dll)) == "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"


def test_a_resident_module_is_refused_without_the_override():
    with pytest.raises(SystemExit):
        refuse_if_resident("stellaris_quickjs.dll", 0x1000_0000)
    refuse_if_resident("stellaris_quickjs.dll", None)   # 没装过 ⇒ 不拦


def test_install_decision_reads_the_code_table():
    assert install_decision(0) == "ok"
    assert install_decision(-4) == "refused"


def test_gate_label_records_the_premise():
    assert gate_label(True) == "operator_override"
    assert gate_label(False) == "world_state"
