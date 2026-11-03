"""test_c2_boot_inject.py — T1 驱动的纯函数围栏(零游戏、零 Windows API)。

驱动本身只做「注入 → C1Run → C1EffectId → C2NeoInstall」并把读压成一行回执;
能在 Linux 上判的是回执的形状与 sha 前缀 —— 真跑留给实机窗口。
"""
import hashlib

import c2_boot_inject as mod


def test_receipt_is_one_line_with_the_required_fields():
    line = mod.receipt(dll="sqjs.dll", sha16="deadbeefdeadbeef", effect_id=18818,
                       set_id=18819, install_rc=0, alive=True)
    assert line.startswith("BOOT ")
    for token in ("dll=sqjs.dll", "sha=deadbeefdeadbeef", "effect_id=18818",
                  "install_rc=0", "alive=1"):
        assert token in line
    assert "\n" not in line


def test_receipt_reports_a_dead_host_as_alive_0():
    line = mod.receipt(dll="x.dll", sha16="0" * 16, effect_id=1, set_id=2, install_rc=-4,
                       alive=False)
    assert "install_rc=-4" in line
    assert "alive=0" in line


def test_receipt_carries_the_set_id():
    line = mod.receipt(dll="x.dll", sha16="0" * 16, effect_id=19331, set_id=19332,
                       install_rc=0, alive=True)
    assert "set_id=19332" in line


def test_the_set_exports_are_in_the_drivers_needed_tuple():
    assert "C1SetId" in mod.NEEDED
    assert "C2NeoArmSet" in mod.NEEDED


def test_sha16_is_the_first_16_hex_digits_of_the_file(tmp_path):
    path = tmp_path / "sqjs.dll"
    path.write_bytes(b"abc")
    assert mod.sha16(str(path)) == hashlib.sha256(b"abc").hexdigest()[:16]


def test_fail_line_names_the_step():
    assert mod.fail_line("inject") == "BOOT FAIL inject"
    assert "\n" not in mod.fail_line("c1")


def test_pack_rule_is_mod_high_rem_low():
    assert mod.pack_rule("100:0") == (100 << 32)
    assert mod.pack_rule("1:0") == (1 << 32)
    assert mod.pack_rule("0:0") == 0
    assert mod.pack_rule("8:3") == (8 << 32) | 3
    assert mod.pack_rule("8") == (8 << 32)


def test_missing_exports_names_exactly_what_a_stale_dll_lacks():
    assert mod.missing_exports(("A", "B", "C"), ["A", "C"]) == ["B"]
    assert mod.missing_exports(("A",), ["A"]) == []


def test_needed_covers_every_export_the_driver_calls():
    """Every `exports["X"]` the driver indexes must be in `NEEDED`.

    2026-11-02 review I-2: `C2NeoSetRule`/`C2NeoUninstall` were called but not
    listed, so a stale DLL produced a traceback (`KeyError`) instead of the
    designed `BOOT FAIL exports` — and in the uninstall case that leaves the
    detour live in the game.
    """
    import pathlib
    import re

    src = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
    called = set(re.findall(r'exports\["(\w+)"\]', src))
    assert called, "no export call sites found — the fence would pass vacuously"
    assert called <= set(mod.NEEDED), sorted(called - set(mod.NEEDED))


def test_pack_rule_rejects_malformed_input():
    import pytest

    with pytest.raises(ValueError):
        mod.pack_rule("x:y")
    with pytest.raises(ValueError):
        mod.pack_rule("-1:0")


def test_pack_act_maps_the_two_action_modes():
    assert mod.pack_act("log") == 0
    assert mod.pack_act("write") == 1


def test_pack_act_rejects_an_unknown_mode():
    import pytest

    with pytest.raises(ValueError):
        mod.pack_act("modify")


def test_a_bad_rule_is_a_usage_error_not_a_traceback():
    import pytest

    with pytest.raises(SystemExit) as exc:
        mod.main(["--rule", "x:y", "--stats"])
    assert exc.value.code == 2


def test_settle_default_waits_past_the_early_loader():
    """50 ms injection crashed the game once; 5 s landed and parsed much later.

    2026-11-03: the first launch died before ``setup.log``; the same DLL with
    ``--settle-s 5`` worked, and the script parser runs ~30 s after launch.
    """
    assert mod.DEFAULT_SETTLE_S >= 5.0
    assert mod.boot.__kwdefaults__["settle_s"] == mod.DEFAULT_SETTLE_S
