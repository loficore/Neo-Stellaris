"""`c6_score_join.py` 的离线围栏:四条判据的边界,不起进程、不读存档。

判据的输入都是已经读出来的数,所以这里全部用合成数据 —— 真存档的形状由
`evidence/logs/c6_r8_score_join_4_4_4.tsv` 与 `c5_chokepoint_mod_join_4_4_4.tsv` 承载。
"""
import pathlib

import c6_score_join as join

#: 三档 + 一个第二写者:0 与 1 是 T0,2 是 T1,3 是 T2。
SCORES = {0: 0, 1: 2, 2: 150, 3: 234}
VALUES = {0: 0, 1: 2, 2: 150, 3: 234}
MARKS = {0: 0, 1: 1, 2: 2, 3: 3}


def _join(**overrides):
    kwargs = {"scores": SCORES, "score_values": VALUES, "mark_values": MARKS,
              "tier2": [3], "tier1": [2], "flags_blocks": 4,
              "second_writer": set()}
    kwargs.update(overrides)
    return join.join(**kwargs)


def test_a_clean_join_passes_and_reports_every_number():
    verdict, numbers, detail = _join()
    assert verdict == join.PASS
    assert detail == ""
    assert numbers["systems"] == 4 and numbers["score_systems"] == 4
    assert numbers["tier2"] == 1 and numbers["offline_tier2"] == 1
    assert numbers["tier1"] == 1 and numbers["offline_tier1"] == 1
    assert numbers["score_diffs"] == 0 and numbers["bad_mark"] == 0


def test_a_missing_system_is_incomplete_not_a_disagreement():
    # 「官方没比到」与「官方比错了」是两件事:前者是读数不够,后者才是判负。
    verdict, numbers, detail = _join(score_values={0: 0, 1: 2, 2: 150})
    assert verdict == join.INCOMPLETE
    assert numbers["missing"] == 1
    assert "missing=1" in detail


def test_an_empty_offline_table_is_incomplete():
    assert _join(scores={}, tier2=[], tier1=[])[0] == join.INCOMPLETE


def test_flag_sets_that_do_not_match_the_offline_tiers_fail():
    # 残留/漏写都落这一档:集合不等就是不等,不看条数(15 对 15 也可能换了一个 id)。
    verdict, numbers, detail = _join(tier2=[1])
    assert verdict == join.TIER_DISAGREE
    assert numbers["tier2"] == 1 and numbers["offline_tier2"] == 1
    assert "tier2_diff" in detail


def test_a_score_diff_outside_the_second_writer_fails():
    verdict, _, detail = _join(score_values={0: 0, 1: 2, 2: 150, 3: 235})
    assert verdict == join.VALUE_DISAGREE
    assert "first_bad=3:235!=234" in detail


def test_a_score_diff_inside_the_second_writer_is_recorded_not_failed():
    # runtime JS 也会写同一个 neo_score;它写的那个 id 的差值只记账。
    verdict, numbers, _ = _join(score_values={0: 0, 1: 2, 2: 150, 3: 236},
                                second_writer={3})
    assert verdict == join.PASS
    assert numbers["score_diffs"] == 1
    assert numbers["diffs_outside_second_writer"] == 0
    assert numbers["max_abs_delta"] == 2


def test_a_mark_that_is_not_the_system_id_fails():
    verdict, numbers, detail = _join(mark_values={0: 0, 1: 1, 2: 2, 3: 0})
    assert verdict == join.VALUE_DISAGREE
    assert numbers["bad_mark"] == 1
    assert "bad_mark=[3]" in detail


def test_render_carries_the_verdict_line_the_gate_reads():
    text = join.render(join.PASS, {"systems": 4})
    assert text.startswith("SCORE_JOIN score_drives_official_state ")
    assert "verdict=score_drives_official_state\n" in text


def test_read_scores_skips_the_header_and_keeps_column_five(tmp_path):
    path = tmp_path / "scores.tsv"
    path.write_text("system_id\tdegree\tbetweenness\tbetweenness_norm\tscore\tx\n"
                    "0\t4\t618.95\t0.002\t2\t0\n"
                    "7\t1\t0.0\t0.0\t0\t0\n", encoding="utf-8")
    assert join.read_scores(path) == {0: 2, 7: 0}


def test_second_writer_ids_reads_the_hub_lines_only(tmp_path):
    path = tmp_path / "neo_js.log"
    path.write_text("NEO_JS_CALL id=3\nNEO_JS_LOG NEO_HUB 771 253\n"
                    "NEO_JS_WRITE id=3 name=neo_score\nNEO_HUB 82 236\n", encoding="utf-8")
    assert join.second_writer_ids(path) == {771, 82}


def test_second_writer_ids_without_a_log_is_empty():
    assert join.second_writer_ids(None) == set()


def test_artifact_has_the_meta_header_and_one_row_per_id(tmp_path):
    text = join.artifact(join.PASS, {"systems": 4}, scores=SCORES, score_values=VALUES,
                         tier2=[3], tier1=[2], second_writer={3}, sav_name="a.sav",
                         scores_name="s.tsv", js_log_name="neo_js.log sha256=deadbeef")
    lines = text.splitlines()
    assert lines[0] == "#meta verdict=score_drives_official_state"
    assert "#meta systems=4" in lines
    assert "#meta js_log=neo_js.log sha256=deadbeef" in lines
    header = next(i for i, line in enumerate(lines) if line.startswith("id\t"))
    assert len(lines) - header - 1 == 4
    assert lines[header + 1].split("\t") == ["0", "0", "0", "0", "0", "T0", "0"]
    assert lines[-1].split("\t")[:3] == ["3", "1", "0"]


def test_the_module_is_read_only_apart_from_out():
    source = pathlib.Path(join.__file__).read_text(encoding="utf-8")
    # 唯一允许写文件的地方是 --out;别的 open(..., "w") 都不许出现。
    assert source.count('open(args.out, "w"') == 1
    assert "write_text(" not in source
