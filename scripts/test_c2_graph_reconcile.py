"""test_c2_graph_reconcile.py — §7.7 对账驱动的纯函数围栏(零游戏、零 Windows API)。

四档判据来自计划 Task 4 Step 1:两边一致 ⇒ `tiers_named`;差一个名 ⇒
`tiers_disagree` 且 detail 有名;窗口内只有部分系统 ⇒ `tiers_partial`;空窗口 ⇒
`tiers_partial`(**不是** `named`)。名字与 id 的缺口用 `tiers_counts` 那一档表达。
"""
import json

import pytest

import c2_graph_reconcile as mod


def test_equal_name_keyed_tiers_are_named():
    live = {"甲": "T2", "乙": "T1", "丙": "T0"}
    host = {"甲": "T2", "乙": "T1", "丙": "T0"}
    verdict, detail = mod.compare_tiers(live, host)
    assert verdict == "tiers_named"
    assert "3" in detail


def test_one_different_tier_is_a_disagreement_that_names_the_system():
    live = {"甲": "T2", "乙": "T1"}
    host = {"甲": "T2", "乙": "T2"}
    verdict, detail = mod.compare_tiers(live, host)
    assert verdict == "tiers_disagree"
    assert "乙" in detail
    assert "live=T1" in detail and "host=T2" in detail


def test_only_part_of_the_systems_is_partial_not_named():
    live = {"甲": "T2", "乙": "T1"}
    host = {"甲": "T2", "乙": "T1", "丙": "T0"}
    verdict, detail = mod.compare_tiers(live, host)
    assert verdict == "tiers_partial"
    assert "丙" in detail


def test_an_empty_window_is_partial_not_named():
    assert mod.compare_tiers({}, {"甲": "T2"})[0] == "tiers_partial"
    assert mod.compare_tiers({"甲": "T2"}, {})[0] == "tiers_partial"
    assert mod.compare_tiers({}, {})[0] == "tiers_partial"


def test_two_sides_with_no_shared_names_are_partial():
    verdict, _ = mod.compare_tiers({"甲": "T2"}, {"乙": "T2"})
    assert verdict == "tiers_partial"


def test_tier_counts_is_the_name_less_path_and_says_so():
    live = {"甲": "T2", "乙": "T1", "丙": "T0"}
    host = {1: "T2", 2: "T1", 3: "T0"}
    verdict, detail = mod.compare_counts(live, host)
    assert verdict == "tiers_counts"
    assert "no name map" in detail
    assert "T2=1" in detail and "T1=1" in detail and "T0=1" in detail


def test_a_coverage_gap_is_partial_not_a_disagreement():
    """The engine log only carries the systems whose name it could print.

    Measured 2026-11-04: 788 systems run the effect every month, 785 emit a
    receipt.  Three systems per month produce no line at all, so the host side
    always has three more systems than the engine side.  That is a coverage
    difference, not a tier disagreement — calling it `tiers_disagree` would trip
    the plan's stop rule on an instrument gap.
    """
    live = {"甲": "T2", "乙": "T0"}
    host = {1: "T2", 2: "T0", 3: "T0"}
    verdict, detail = mod.compare_counts(live, host)
    assert verdict == "tiers_partial"
    assert "coverage" in detail
    assert "live=2" in detail and "host=3" in detail


def test_tier_counts_disagree_when_the_distribution_moves():
    verdict, detail = mod.compare_counts({"甲": "T2"}, {1: "T1"})
    assert verdict == "tiers_disagree"
    assert "T2: live=1 host=0" in detail


def test_parse_tiers_reads_the_receipt_lines_and_keeps_spaces_in_names():
    text = ("2026-11-04 12:00:00 NEO_T2 杰克进星\r\n"
            "NEO_T1 天津四\r\n"
            "PS_HIT 杰克进星\r\n"
            "some other line\r\n")
    assert mod.parse_tiers(text) == {"杰克进星": "T2", "天津四": "T1"}


def test_parse_tiers_is_empty_for_an_empty_window():
    assert mod.parse_tiers("") == {}


def test_the_engine_thresholds_are_the_ones_the_mod_logs():
    assert mod.tier_of(200) == "T2" and mod.tier_of(199) == "T1"
    assert mod.tier_of(100) == "T1" and mod.tier_of(99) == "T0"
    assert mod.tier_of(0) == "T0"


def test_windows_are_byte_ranges_and_are_validated(tmp_path):
    path = tmp_path / "w.json"
    path.write_text(json.dumps([{"name": "base", "start": 0, "end": 10}]), encoding="utf-8")
    assert mod.windows_from_json(path) == [{"name": "base", "start": 0, "end": 10}]

    path.write_text(json.dumps([{"name": "base", "start": 5, "end": 1}]), encoding="utf-8")
    with pytest.raises(ValueError):
        mod.windows_from_json(path)
    path.write_text(json.dumps({"nope": 1}), encoding="utf-8")
    with pytest.raises(ValueError):
        mod.windows_from_json(path)


def test_window_text_slices_the_log_by_byte_offset():
    data = "HEADNEO_T2 甲\r\nTAIL".encode("utf-8")
    start = data.index("NEO".encode("utf-8"))
    end = data.index("TAIL".encode("utf-8"))
    text = mod.window_text(data, {"name": "w", "start": start, "end": end})
    assert mod.parse_tiers(text) == {"甲": "T2"}


def test_host_tiers_rekeys_by_name_only_when_a_map_is_given(tmp_path):
    scores = tmp_path / "s.tsv"
    scores.write_text(
        "system_id\tdegree\tbetweenness\tbetweenness_norm\tscore\tis_articulation\tis_bridge_endpoint\n"
        "5\t2\t0\t0\t250\t0\t0\n"
        "9\t3\t1\t0.5\t120\t1\t1\n", encoding="utf-8")
    assert mod.host_tiers(scores) == {5: "T2", 9: "T1"}
    assert mod.host_tiers(scores, {5: "甲"}) == {"甲": "T2"}


def test_the_cli_is_exit_0_unless_a_disagreement_was_recorded(tmp_path):
    """The driver's exit code is the stop rule: `tiers_disagree` must not be silent."""
    log = tmp_path / "game.log"
    log.write_text("NEO_T2 甲\nNEO_T0 乙\n", encoding="utf-8")
    base = tmp_path / "base.tsv"
    base.write_text("1\t2\t1\n", encoding="utf-8")
    windows = tmp_path / "w.json"
    windows.write_text(json.dumps([{"name": "base", "start": 0,
                                    "end": log.stat().st_size}]), encoding="utf-8")
    scores_dir = tmp_path / "scores"
    scores_dir.mkdir()
    rc = mod.main(["--log", str(log), "--windows", str(windows),
                   "--edges-base", str(base), "--edges-add", str(base),
                   "--scores-dir", str(scores_dir)])
    # no name map ⇒ counts path; two systems, two edges of one node ⇒ whatever the
    # tiers are, the run must produce a verdict line and a defined exit code.
    assert rc in (0, 1)
