"""test_c5_flag_verify.py — flag 键空间四条判据的判词围栏(零游戏、零 Windows)。

判据来自 `evidence/analysis/flag_store_4_4_4.md` §6:官方写的 flag 我们能读、
我们写的 flag 官方能读、两者的 id 落在同一张表、两者都进存档。这里钉的是
**哪一条链断了要能说出名字**,而不是一个笼统的 fail —— 所以每个用例都从
某一个链接全通、只留一个缺口。
"""
import c5_flag_verify as mod


def test_official_hit_count_reads_the_probe_word():
    text = "NEO_FLAG_OFFICIAL name=neo_probe\nnoise\nNEO_FLAG_OFFICIAL name=neo_probe2\n"
    assert mod.official_hit_count(text, "neo_probe") == 1
    assert mod.official_hit_count(text, "neo_probe2") == 1
    assert mod.official_hit_count(text, "neo_probe3") == 0


def test_js_flag_lines_keep_only_present_true_for_that_name():
    text = ("NEO_JS_LOG NEO_FLAG_READ name=neo_probe present=true id=82\n"
            "NEO_JS_LOG NEO_FLAG_READ name=neo_probe present=false id=7\n"
            "NEO_JS_LOG NEO_FLAG_READ name=neo_probe2 present=true id=82\n")
    assert mod.js_flag_lines(text, "neo_probe") == [82]


def test_verdict_names_which_chain_failed():
    ok = mod.verdict(official_hits=1, js_reads=[82], official_readback=1,
                     save_official=[3], save_ours=[82],
                     official="neo_probe", ours="neo_probe2")
    assert ok[0] == "flags_end_to_end"
    only_official = mod.verdict(official_hits=1, js_reads=[], official_readback=0,
                                save_official=[3], save_ours=[],
                                official="neo_probe", ours="neo_probe2")
    assert only_official[0] == "our_read_missing"
    only_ours = mod.verdict(official_hits=0, js_reads=[], official_readback=1,
                            save_official=[], save_ours=[82],
                            official="neo_probe", ours="neo_probe2")
    assert only_ours[0] == "official_control_failed"


def test_verdict_reports_a_save_gap_even_when_the_logs_agree():
    tag, detail = mod.verdict(official_hits=1, js_reads=[82], official_readback=1,
                              save_official=[], save_ours=[82],
                              official="neo_probe", ours="neo_probe2")
    assert tag == "save_missing"
    assert "neo_probe" in detail


def test_every_tag_is_in_the_domain():
    assert set(mod.VERDICTS) >= {"flags_end_to_end", "our_read_missing",
                                 "official_control_failed", "save_missing"}


def test_save_missing_carries_the_flags_block_control():
    """`save_missing` 有两种来源:真的没写进存档,和「根本没找到 flags 块」。

    后者是解析形状(换版本、换存档布局),与引擎行为无关 —— 所以判词要把
    `flag_scan` 的第二个返回(带 `flags` 块的系统数)带出来,像 `c5_variable_probe`
    的 `flags_blocks=0` 一样把两者分开。
    """
    tag, detail = mod.verdict(official_hits=1, js_reads=[82], official_readback=1,
                              save_official=[], save_ours=[82], save_flags_blocks=0,
                              official="neo_probe", ours="neo_probe2")
    assert tag == "save_missing"
    assert "flags_blocks=0" in detail
    tag, detail = mod.verdict(official_hits=1, js_reads=[82], official_readback=1,
                              save_official=[], save_ours=[82], save_flags_blocks=586,
                              official="neo_probe", ours="neo_probe2")
    assert tag == "save_missing"
    assert "flags_blocks=586" in detail
