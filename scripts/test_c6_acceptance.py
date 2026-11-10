"""C6 验收台帐的离线围栏。

六道门的判据逐字来自 `docs/c6-acceptance.md`；这里只喂**既有驱动已经产出的回执形状**
（`BOOT` 行、`#meta` 台帐、`verdict=` 行、`UNINSTALL` 行、两份日志），不起进程、不联网。
"""
import c6_acceptance as c6


def test_c6_1_passes_on_the_boot_receipt():
    line = ("BOOT dll=sqjs_c20.dll sha=8c774e60b36c2969 effect_id=19344 "
            "set_id=19345 install_rc=0 alive=1")
    gate = c6.gate_registration(c6.parse_boot(line))
    assert (gate.gate, gate.status) == ("C6-1", c6.PASS)
    assert "effect_id=19344" in gate.detail and "set_id=19345" in gate.detail


def test_c6_1_fails_when_install_or_ids_are_zero():
    line = "BOOT dll=x sha=0 effect_id=0 set_id=0 install_rc=0 alive=1"
    assert c6.gate_registration(c6.parse_boot(line)).status == c6.FAIL


def test_c6_1_cannot_say_on_an_unparseable_receipt():
    assert c6.gate_registration(c6.parse_boot("garbage")).status == c6.CANNOT_SAY


def test_c6_6_passes_on_a_clean_uninstall():
    gate = c6.gate_teardown("UNINSTALL rc=0 verify=0 alive=1")
    assert (gate.gate, gate.status) == ("C6-6", c6.PASS)


def test_c6_6_fails_when_a_hook_survives():
    assert c6.gate_teardown("UNINSTALL rc=0 verify=1 alive=1").status == c6.FAIL
    assert c6.gate_teardown("UNINSTALL rc=2 verify=0 alive=1").status == c6.FAIL


def test_c6_6_cannot_say_without_a_receipt():
    assert c6.gate_teardown("").status == c6.CANNOT_SAY


ARTIFACT = """#meta act=record
#meta container_raw_count=788
#meta distinct_ids=788
#meta overall_verdict=dispatch_named
#meta save_name=autosave_2281.01.01.sav
0x3b101f\t0\t0x80\t4\t0x0\t0x0
"""


def test_c6_2_passes_when_the_id_count_equals_the_container():
    gate = c6.gate_per_system(c6.parse_meta(ARTIFACT), systems=788)
    assert (gate.gate, gate.status) == ("C6-2", c6.PASS)


def test_c6_2_fails_when_the_container_disagrees():
    gate = c6.gate_per_system(c6.parse_meta(ARTIFACT), systems=787)
    assert gate.status == c6.FAIL
    assert "container=788" in gate.detail and "systems=787" in gate.detail


def test_c6_2_fails_on_a_judged_negative_verdict():
    text = ARTIFACT.replace("dispatch_named", "ids_not_in_container")
    assert c6.gate_per_system(c6.parse_meta(text), systems=788).status == c6.FAIL


def test_c6_2_cannot_say_when_the_artifact_is_missing_or_environmental():
    assert c6.gate_per_system({}, systems=788).status == c6.CANNOT_SAY
    env = ARTIFACT.replace("dispatch_named", "window_not_playing")
    assert c6.gate_per_system(c6.parse_meta(env), systems=788).status == c6.CANNOT_SAY


def test_parse_meta_reads_only_the_meta_lines():
    meta = c6.parse_meta(ARTIFACT)
    assert meta["overall_verdict"] == "dispatch_named"
    assert "0x3b101f" not in meta


def _save(body):
    return "galactic_object={ " + " ".join(
        f'{i}={{ variables={{ neo_mark={v} }} }}' for i, v in body) + " }"


STATS_OK = ("calls=9444 matched=9444 log_calls=9444 last_id=786 rule_hits=0 installed=1 "
            "verify=0 dispatched=30518 null_scope=0 mask_odd=0 writes=9444 skipped=0 "
            "score_writes=0 score_skipped=0 set_calls=0 set_runs=0")


def test_c6_3_passes_when_every_system_holds_its_own_id():
    text = _save([(0, 0), (1, 1), (2, 2)])
    gate = c6.gate_state_written(text, "neo_mark", 3, c6.parse_stats(STATS_OK))
    assert (gate.gate, gate.status) == ("C6-3", c6.PASS)


def test_c6_3_fails_when_a_value_is_not_the_id():
    text = _save([(0, 0), (1, 7), (2, 2)])
    gate = c6.gate_state_written(text, "neo_mark", 3, c6.parse_stats(STATS_OK))
    assert gate.status == c6.FAIL
    assert "first_bad=1" in gate.detail


def test_c6_3_fails_when_a_system_is_missing():
    assert c6.gate_state_written(_save([(0, 0), (2, 2)]), "neo_mark", 3,
                                 c6.parse_stats(STATS_OK)).status == c6.FAIL


def test_c6_3_fails_when_skipped_is_not_zero_or_writes_differ():
    text = _save([(0, 0), (1, 1), (2, 2)])
    skipped = c6.parse_stats(STATS_OK.replace(" skipped=0 ", " skipped=3 "))
    assert c6.gate_state_written(text, "neo_mark", 3, skipped).status == c6.FAIL
    short = c6.parse_stats(STATS_OK.replace("writes=9444", "writes=9440"))
    assert c6.gate_state_written(text, "neo_mark", 3, short).status == c6.FAIL


def test_c6_3_cannot_say_without_a_save_or_stats():
    assert c6.gate_state_written("", "neo_mark", 3, c6.parse_stats(STATS_OK)).status == c6.CANNOT_SAY
    text = _save([(0, 0), (1, 1), (2, 2)])
    assert c6.gate_state_written(text, "neo_mark", 3, {}).status == c6.CANNOT_SAY


NAMED = "window=base live=15 host=15 verdict=tiers_named detail=equal\n"


def test_c6_4_passes_on_tiers_named():
    gate = c6.gate_official_readback(NAMED)
    assert (gate.gate, gate.status) == ("C6-4", c6.PASS)


def test_c6_4_fails_on_tiers_disagree():
    assert c6.gate_official_readback(NAMED.replace("tiers_named", "tiers_disagree")).status == c6.FAIL


def test_c6_4_cannot_say_on_counts_only_readings():
    text = NAMED.replace("tiers_named", "tiers_counts")
    assert c6.gate_official_readback(text).status == c6.CANNOT_SAY
    assert c6.gate_official_readback("").status == c6.CANNOT_SAY


BASE = "EVENT_PICK 1\nPS_HIT\nother line\nGAME_START\n"
WITH = "EVENT_PICK 1\nPS_HIT\nNEO_JS_CALL id=3\nGAME_START\n"


def test_c6_5_passes_when_official_markers_match_and_errors_do_not_grow():
    gate = c6.gate_official_unchanged(
        base_log=BASE, with_log=WITH, base_err="", with_err="")
    assert (gate.gate, gate.status) == ("C6-5", c6.PASS)


def test_c6_5_ignores_only_our_dll_prefixes():
    markers = c6.official_markers(WITH)
    assert "NEO_JS_CALL" not in markers
    assert "PS_HIT" in markers          # 我们的 mod 两趟都跑,不能被排除
    assert "EVENT_PICK" in markers


def test_c6_5_fails_when_an_official_marker_disappears():
    gate = c6.gate_official_unchanged(
        base_log=BASE, with_log="EVENT_PICK 1\nPS_HIT\n", base_err="", with_err="")
    assert gate.status == c6.FAIL
    assert "GAME_START" in gate.detail


def test_c6_5_fails_on_one_new_script_error():
    gate = c6.gate_official_unchanged(
        base_log=BASE, with_log=WITH, base_err="", with_err="Script Error: x\n")
    assert gate.status == c6.FAIL
    assert "error_delta=1" in gate.detail


def test_c6_5_cannot_say_when_a_pair_is_missing():
    gate = c6.gate_official_unchanged(
        base_log=None, with_log=WITH, base_err="", with_err="")
    assert gate.status == c6.CANNOT_SAY
