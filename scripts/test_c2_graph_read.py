"""c2_graph_read 的纯函数围栏。

这些测试一行真内存都不碰:drivers 的 live 段在 Windows 上跑,判词与解析在
Linux 上测。口径来自计划 Task 2 的 verdict 表 —— 每一档都必须能单独被触发,
因为「读不到」「读到了但脏」「读到了但两次不一致」是三种不同的结论。
"""

import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import c2_graph_read as mod


GOOD_LAYOUT = [1, 0x3260B98, 0x18, 0x20, 16, 8, 0x59C, 0x20]

#: 小样本:不依赖 `evidence/xrefs/c5_campaign_edges_4_4_4.tsv`(那是实机对账用的)。
ROWS = [(0, 1), (1, 2), (2, 3)]


def stats(systems, edges, skipped=0, max_id=None):
    """A `#meta`-shaped stats dict. `max_id` defaults to the dense upper bound."""
    return {
        "systems": systems,
        "edges": edges,
        "skipped": skipped,
        "max_id": (systems - 1) if max_id is None else max_id,
    }


def env(rc=0, **kwargs):
    """The non-stat readings a verdict needs. Defaults = the happy path.

    The two expectations are part of the shot's premise (the driver always fires with
    them), so they live here rather than in a separate argument.
    """
    base = {"rc": rc, "gate": "world_state", "no_game": False, "exports_ok": True,
            "alive": True, "expect_systems": 787, "expect_edges": 1217}
    base.update(kwargs)
    return base


def good_layout():
    return list(GOOD_LAYOUT)


def test_layout_mismatch_is_instrument_broken():
    # 字 4 = 记录步长。8 是「按 8 字节步长读表」那个已勘误的口径(§1.11)⇒ 探针漂了。
    layout = [1, 0x3260B98, 0x18, 0x20, 8, 8, 0x59C, 0x20]
    verdict, detail = mod.classify(stats(787, 1217), ROWS, ROWS, layout, env())
    assert verdict == "instrument_broken"
    assert "layout" in detail


def test_read_matches_offline_edge_table():
    assert mod.classify(stats(787, 1217), ROWS, ROWS, good_layout(), env())[0] == \
        "graph_live_read_named"


def test_count_equal_but_skipped_is_partial():
    verdict, detail = mod.classify(stats(787, 1217, skipped=2), ROWS, ROWS, good_layout(), env())
    assert verdict == "graph_live_read_partial"
    assert "skipped" in detail


def test_two_reads_that_disagree_are_unstable():
    # rows_a != rows_b ⇒ 活容器撕裂读(Review Focus #3)。
    verdict, detail = mod.classify(stats(787, 1217), ROWS, ROWS, good_layout(), env(),
                                   again=ROWS[:-1])
    assert verdict == "graph_live_read_unstable"
    assert "read2" in detail


def test_disagree_names_the_first_difference():
    bad = ROWS[:-1]
    verdict, detail = mod.classify(stats(787, 1216), bad, ROWS, good_layout(), env())
    assert verdict == "graph_live_read_disagree"
    assert "1216" in detail


def test_index_unreadable_is_an_environment_reading():
    verdict, _ = mod.classify(stats(0, 0), [], None, good_layout(), env(rc=-2))
    assert verdict == "graph_index_unreadable"


def test_a_refused_gate_is_window_not_playing():
    verdict, _ = mod.classify(stats(0, 0), [], None, good_layout(), env(gate="refused"))
    assert verdict == "window_not_playing"


def test_unknown_read_code_is_instrument_broken():
    # -1 / -3 都不是证据档:一个说基址取不到,一个说边表超容量 —— 都是仪器的事。
    for rc in (-1, -3):
        verdict, _ = mod.classify(stats(0, 0), [], None, good_layout(), env(rc=rc))
        assert verdict == "instrument_broken", rc


def test_partial_names_a_non_dense_max_id():
    # 计数相等、skipped==0,但活槽有空洞(max_id != systems-1)⇒ 仍带欠账。
    verdict, detail = mod.classify(stats(787, 1217, max_id=900), ROWS, ROWS,
                                  good_layout(), env())
    assert verdict == "graph_live_read_partial"
    assert "max_id" in detail


def test_truncated_rows_are_disagree_not_named():
    # 驱动侧那一道:行数必须等于 stats 的 edges(判词函数本身不重数,由 rows_complete 传进来)。
    verdict, detail = mod.classify(stats(787, 1217), ROWS, ROWS, good_layout(), env(),
                                   rows_complete=False)
    assert verdict == "graph_live_read_disagree"
    assert "rows" in detail


def test_parse_artifact_round_trips_meta_and_rows():
    text = "#meta overall_verdict=graph_live_read_named\n#meta edges=2\n0\t1\n1\t2\n"
    meta, rows = mod.parse_artifact(text)
    assert meta == {"overall_verdict": "graph_live_read_named", "edges": "2"}
    assert rows == [(0, 1), (1, 2)]


def test_parse_artifact_refuses_a_short_row():
    meta, rows = mod.parse_artifact("#meta edges=1\n0\t1\t9\n")
    assert meta == {"edges": "1"}
    assert rows == []          # 三列不是一对 id:不猜


# --- Task 4: 改一条边再读两次 ------------------------------------------------


def test_mutation_delta_plus_one_then_back():
    seq = [stats(787, 1217), stats(787, 1218), stats(787, 1217)]
    verdict, detail = mod.classify_mutation(
        seq, x=5, y=9, base_rows=ROWS, added_rows=[*ROWS, (5, 9)])
    assert verdict == "graph_mutation_recompute_named"
    assert "(5, 9)" in detail


def test_mutation_that_leaves_the_graph_dirty_names_the_step():
    seq = [stats(787, 1217), stats(787, 1218), stats(787, 1219)]
    verdict, detail = mod.classify_mutation(
        seq, x=5, y=9, base_rows=ROWS, added_rows=[*ROWS, (5, 9)])
    assert verdict == "mutation_left_dirty"
    assert "remove" in detail


def test_mutation_whose_add_never_landed_is_dirty_at_add():
    # edges +1 但边集里没有那一对 ⇒ add 没落进容器(或落到了别的系统上)。
    seq = [stats(787, 1217), stats(787, 1218), stats(787, 1217)]
    verdict, detail = mod.classify_mutation(
        seq, x=5, y=9, base_rows=ROWS, added_rows=[*ROWS, (5, 10)])
    assert verdict == "mutation_left_dirty"
    assert "add" in detail


def test_mutation_that_came_back_with_a_different_set_is_dirty():
    # 计数回到基线,但边集不是同一套 ⇒ 删错了边或删多了。
    other = [(0, 1), (1, 2), (3, 4)]
    seq = [stats(787, 1217), stats(787, 1218), stats(787, 1217)]
    verdict, detail = mod.classify_mutation(
        seq, x=5, y=9, base_rows=ROWS, added_rows=[*ROWS, (5, 9)],
        removed_rows=other)
    assert verdict == "mutation_left_dirty"
    assert "remove" in detail


def test_mutation_with_a_nonzero_export_code_is_dirty():
    # 导出返回码非 0(解析失败/越界)⇒ 后面的步骤都不许再调,直接判脏。
    seq = [dict(stats(787, 1217)), dict(stats(787, 1218), rc=-2), stats(787, 1217)]
    verdict, detail = mod.classify_mutation(
        seq, x=5, y=9, base_rows=ROWS, added_rows=[*ROWS, (5, 9)])
    assert verdict == "mutation_left_dirty"
    assert "add" in detail


def test_a_mutation_shot_has_no_read2_keys():
    # 改边发是三个快照(base/add/remove),没有「第二次读」。把 base 复制成 read2_* 会让
    # artifact 声称一次没发生过的复读 —— 证据里最不该有的东西。
    assert mod.read2_meta(None, None) == {}
    fields = mod.read2_meta(stats(788, 1219), 0)
    assert fields == {"read2_edges": 1219, "read2_rc": 0, "read2_systems": 788,
                      "read2_skipped": 0}


# --- Part A Task 5: 同窗加删(加与删之间不夹读) --------------------------------


def test_collide_steps_put_no_read_between_add_and_remove():
    steps = mod.collide_steps(5, 9)
    assert steps == ["base", "add", "remove", "collide_read"]


def test_a_collision_where_the_hash_differs_is_flagged_suspicious():
    verdict = mod.classify_collision(
        base_fingerprint=2446, collide_fingerprint=2446,
        base_hash=0x46F76122D529552D, collide_hash=0x1234)
    assert verdict == "graph_collision_suspicious"


# --- A1: --attach(挂到已注入的那一份,不二次注入) -------------------------------


def test_attach_refuses_when_the_module_is_not_resident():
    assert mod.decide_injection(attach=True, resident=False) == "refuse"


def test_attach_never_selects_the_inject_path_when_resident():
    assert mod.decide_injection(attach=True, resident=True) == "attach"
    assert mod.decide_injection(attach=False, resident=True) == "refuse"
    assert mod.decide_injection(attach=False, resident=False) == "inject"


def test_the_attach_branch_does_not_call_inject_dll():
    src = (pathlib.Path(__file__).resolve().parent / "c2_graph_read.py").read_text(encoding="utf-8")
    branch = src.split("if attach:", 1)[1].split("else:", 1)[0]
    assert "inject_dll" not in branch
    assert "gate_install" not in branch


# --- A2: --rewire(保度 2-switch —— 指纹不变、边集变) ---------------------------


def test_a_degree_preserving_switch_exists_in_a_four_cycle():
    edges = [(1, 2), (2, 3), (3, 4), (4, 1)]
    switch = mod.choose_switch(edges)
    assert switch is not None
    a, b, c, d = switch
    assert len({a, b, c, d}) == 4
    assert (min(a, b), max(a, b)) in {tuple(sorted(e)) for e in edges}
    assert (min(c, d), max(c, d)) in {tuple(sorted(e)) for e in edges}
    assert (min(a, c), max(a, c)) not in {tuple(sorted(e)) for e in edges}
    assert (min(b, d), max(b, d)) not in {tuple(sorted(e)) for e in edges}


def test_a_triangle_has_no_degree_preserving_switch():
    assert mod.choose_switch([(1, 2), (2, 3), (3, 1)]) is None


def test_rewire_steps_put_no_read_between_the_four_mutations():
    assert mod.rewire_steps() == ["base", "remove_ab", "remove_cd", "add_ac", "add_bd",
                                  "rewire_read"]


def test_a_detected_rewire_needs_an_evaluation_and_a_recompute():
    assert mod.classify_rewire(
        base_fingerprint=9001, rewire_fingerprint=9001,
        base_hash=0x46F76122D529552D, rewire_hash=0x1234,
        evaluated_delta=788, recomputed_delta=1, restore_ok=True,
    ) == "graph_rewire_detected"


def test_the_missed_branch_is_the_one_issue_46_is_about():
    assert mod.classify_rewire(
        base_fingerprint=9001, rewire_fingerprint=9001,
        base_hash=0x46F76122D529552D, rewire_hash=0x1234,
        evaluated_delta=788, recomputed_delta=0, restore_ok=True,
    ) == "graph_rewire_missed"


def test_no_evaluation_is_an_instrument_reading_not_a_miss():
    assert mod.classify_rewire(
        base_fingerprint=9001, rewire_fingerprint=9001,
        base_hash=0x46F76122D529552D, rewire_hash=0x1234,
        evaluated_delta=0, recomputed_delta=0, restore_ok=True,
    ) == "no_pulse"


def test_an_unchanged_hash_means_the_switch_did_not_land():
    assert mod.classify_rewire(
        base_fingerprint=9001, rewire_fingerprint=9001,
        base_hash=0x46F76122D529552D, rewire_hash=0x46F76122D529552D,
        evaluated_delta=788, recomputed_delta=0, restore_ok=True,
    ) == "graph_rewire_invisible"


def test_a_failed_restore_is_dirty_even_if_the_rewire_was_detected():
    assert mod.classify_rewire(
        base_fingerprint=9001, rewire_fingerprint=9001,
        base_hash=0x46F76122D529552D, rewire_hash=0x1234,
        evaluated_delta=788, recomputed_delta=1, restore_ok=False,
    ) == "restore_dirty"


# --- A3: 读回 live/verify 计数,等一次核对 ---------------------------------------


def test_parse_live_reads_the_three_exports_in_order():
    stats = struct.pack("<8Q", 788, 3, 785, 0, 0, 0, 788, 9001)
    h = struct.pack("<QQ", 0x46F76122D529552D, 1219)
    v = struct.pack("<QQ", 7, 0)
    live = mod.parse_live(stats, h, v)
    assert live["evaluated"] == 788
    assert live["recomputed"] == 3
    assert live["fingerprint"] == 9001
    assert live["hash"] == 0x46F76122D529552D
    assert live["verified"] == 7


def test_pulse_progress_reports_three_deltas_and_never_wraps():
    before = {"evaluated": 100, "recomputed": 1, "verified": 2}
    after = {"evaluated": 888, "recomputed": 2, "verified": 5}
    assert mod.pulse_progress(before, after) == {
        "evaluated": 788, "recomputed": 1, "verified": 3}


# --- 一发之前的硬门:换错存档 / 二次注入 -----------------------------------------


def test_rewire_refuses_a_save_that_does_not_match_the_expectations():
    assert mod.expectations_match(
        systems=788, edges=1219, expect_systems=788, expect_edges=1219)
    assert not mod.expectations_match(
        systems=787, edges=1219, expect_systems=788, expect_edges=1219)
    assert not mod.expectations_match(
        systems=788, edges=1218, expect_systems=788, expect_edges=1219)


def test_rewire_without_attach_is_refused_before_any_shot():
    import pytest

    with pytest.raises(SystemExit):
        mod.main(["x.dll", "--expect-systems", "1", "--expect-edges", "1",
                  "--save-name", "s", "--rewire", "auto"])
