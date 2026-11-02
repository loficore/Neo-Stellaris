"""test_c2_boot_inject.py — T1 驱动的纯函数围栏(零游戏、零 Windows API)。

驱动本身只做「注入 → C1Run → C1EffectId → C2NeoInstall」并把读压成一行回执;
能在 Linux 上判的是回执的形状与 sha 前缀 —— 真跑留给实机窗口。
"""
import hashlib

import c2_boot_inject as mod


def test_receipt_is_one_line_with_the_required_fields():
    line = mod.receipt(dll="sqjs.dll", sha16="deadbeefdeadbeef", effect_id=18818,
                       install_rc=0, alive=True)
    assert line.startswith("BOOT ")
    for token in ("dll=sqjs.dll", "sha=deadbeefdeadbeef", "effect_id=18818",
                  "install_rc=0", "alive=1"):
        assert token in line
    assert "\n" not in line


def test_receipt_reports_a_dead_host_as_alive_0():
    line = mod.receipt(dll="x.dll", sha16="0" * 16, effect_id=1, install_rc=-4, alive=False)
    assert "install_rc=-4" in line
    assert "alive=0" in line


def test_sha16_is_the_first_16_hex_digits_of_the_file(tmp_path):
    path = tmp_path / "sqjs.dll"
    path.write_bytes(b"abc")
    assert mod.sha16(str(path)) == hashlib.sha256(b"abc").hexdigest()[:16]


def test_fail_line_names_the_step():
    assert mod.fail_line("inject") == "BOOT FAIL inject"
    assert "\n" not in mod.fail_line("c1")
