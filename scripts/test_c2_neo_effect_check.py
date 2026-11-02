"""test_c2_neo_effect_check.py — §93 判据的纯函数围栏(零游戏、零 Windows API)。

判据来自 spec §1:`game.log` 每轮出现 N 行 `Neo: system <id>`,N = 命中数。
所以这一层只回答两件事 —— 增量行数、以及它和期望值的关系;`verdict` **只认精确相等**,
多一行也判 `extra`(日志膨胀/重复注册都会先在这里露头)。
"""
import c2_neo_effect_check as mod


def test_verdict_is_exact_match_only(tmp_path):
    log = tmp_path / "game.log"
    log.write_text("x\n", encoding="utf-8")
    off = log.stat().st_size
    with log.open("a", encoding="utf-8") as fh:
        fh.write("Neo: system 1\nNeo: system 2\n")
    assert mod.count_since(str(log), off, "Neo: system") == 2
    assert mod.verdict(2, 2) == "neo_lines_ok"
    assert mod.verdict(1, 2) == "neo_lines_short"
    assert mod.verdict(3, 2) == "neo_lines_extra"


def test_count_since_only_reads_after_the_offset(tmp_path):
    log = tmp_path / "game.log"
    log.write_text("Neo: system 9\n", encoding="utf-8")
    assert mod.count_since(str(log), 0, "Neo: system") == 1
    assert mod.count_since(str(log), log.stat().st_size, "Neo: system") == 0


def test_count_since_measures_nothing_when_the_offset_is_unknown(tmp_path):
    assert mod.count_since(str(tmp_path / "missing.log"), None, "Neo: system") is None
    log = tmp_path / "game.log"
    log.write_text("Neo: system 1\n", encoding="utf-8")
    assert mod.count_since(str(log), None, "Neo: system") is None


def test_cli_verdict_word_is_the_plan_vocabulary():
    # `neo_lines_unmeasured` is the 4th word added after the 2026-11-02 review
    # (M-6): an unmeasured window is not "too few lines".
    assert set(mod.VERDICTS) == {
        "neo_lines_ok", "neo_lines_short", "neo_lines_extra", "neo_lines_unmeasured"}


def test_histogram_counts_each_id_after_the_offset(tmp_path):
    log = tmp_path / "game.log"
    log.write_text("Neo: system 9\n", encoding="utf-8")
    off = log.stat().st_size
    with log.open("a", encoding="utf-8") as fh:
        fh.write("Neo: system 1\nNeo: system 2\nNeo: system 1\n")
    assert mod.histogram(str(log), off, "Neo: system") == {1: 2, 2: 1}
    assert mod.histogram(str(log), None, "Neo: system") is None


def test_an_unmeasured_window_is_its_own_word(tmp_path):
    """`None` is an environment failure, `short` is an evidence failure."""
    assert mod.verdict(None, 3) == "neo_lines_unmeasured"
    assert mod.verdict(0, 3) == "neo_lines_short"
