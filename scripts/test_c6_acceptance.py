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
