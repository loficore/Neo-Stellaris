"""test_c5_variable_probe.py — C5-WRITE 的存档侧读值围栏(零游戏、零 Windows)。

判据 2 要的是「存档里 `neo_mark` 的值逐项 = 该星系的运行时 id」。这条读值路径
不能靠肉眼:解析器要能从 `.sav` 的 `gamestate` 里挑出**系统变量**,而不是任意
同名键。窄解析,够判据 2 用;不冒充通用 Clausewitz 解析器。
"""
import pathlib
import zipfile

import pytest

import c5_variable_probe as mod


def test_find_variables_reads_system_variables():
    text = 'systems={ 3={ variables={ neo_mark=7 } } 5={ variables={ neo_mark=9 } } }'
    assert mod.find_variables(text, "neo_mark") == {3: 7, 5: 9}


def test_find_variables_ignores_other_variables():
    text = 'systems={ 3={ variables={ other=1 neo_mark=7 } } }'
    assert mod.find_variables(text, "neo_mark") == {3: 7}


def test_the_two_segments_must_use_the_same_rule():
    mod.assert_same_rule("1:0", "1:0")
    with pytest.raises(ValueError):
        mod.assert_same_rule("1:0", "100:0")


def test_find_variables_reads_the_real_container_name():
    """Real 4.4.4 saves put systems under `galactic_object`, not `systems`."""
    text = "galactic_object={ 787={ variables={ neo_mark=787 } } }"
    assert mod.find_variables(text, "neo_mark") == {787: 787}


def test_find_variables_reads_the_block_encoded_variable_form():
    """Some save versions serialize a variable as `{ name=… value=… }`."""
    text = (
        "galactic_object={ 12={ variables={ { name=neo_mark value=12 } } } }"
    )
    assert mod.find_variables(text, "neo_mark") == {12: 12}


def test_a_missing_variable_is_an_empty_map_not_an_error():
    assert mod.find_variables("galactic_object={ 1={ } }", "neo_mark") == {}


def test_a_missing_system_container_is_an_empty_map():
    assert mod.find_variables("date=2200.01.01", "neo_mark") == {}


def test_a_fixed_point_encoded_integer_reads_back_as_an_integer():
    """Shot 1 wrote raw ids; the save showed them as `0.00786` (value × 1e-5)."""
    text = "galactic_object={ 3={ variables={ neo_mark=3.00000 } } }"
    assert mod.find_variables(text, "neo_mark") == {3: 3}


def test_a_non_integral_value_stays_a_float():
    text = "galactic_object={ 3={ variables={ neo_mark=3.50000 } } }"
    assert mod.find_variables(text, "neo_mark") == {3: 3.5}


def test_read_gamestate_unzips_the_sav(tmp_path):
    sav = tmp_path / "x.sav"
    with zipfile.ZipFile(sav, "w") as archive:
        archive.writestr("gamestate", "galactic_object={ 1={ variables={ neo_mark=1 } } }")
    text = mod.read_gamestate(sav)
    assert mod.find_variables(text, "neo_mark") == {1: 1}


def test_cli_prints_count_min_max_and_a_sample(tmp_path, capsys):
    sav = tmp_path / "x.sav"
    text = "galactic_object={ 1={ variables={ neo_mark=1 } } 9={ variables={ neo_mark=9 } } }"
    with zipfile.ZipFile(sav, "w") as archive:
        archive.writestr("gamestate", text)
    assert mod.main(["--sav", str(sav), "--name", "neo_mark"]) == 0
    out = capsys.readouterr().out
    assert "systems=2" in out
    assert "min=1" in out
    assert "max=9" in out


def test_find_flags_reads_system_flags():
    text = "galactic_object={ 3={ flags={ neo_tier2=1 } } 5={ flags={ neo_tier1=1 } } }"
    assert mod.find_flags(text, "neo_tier2") == [3]


def test_find_flags_ignores_other_flags():
    text = "galactic_object={ 3={ flags={ empire_home_system=1 neo_tier2=1 } } }"
    assert mod.find_flags(text, "neo_tier2") == [3]


def test_a_missing_flag_is_an_empty_list():
    assert mod.find_flags("galactic_object={ 1={ } }", "neo_tier2") == []


def test_find_flags_dedupes_a_system_listed_twice():
    """`systems=N` is a pass/fail criterion, so a repeated container must not inflate it."""
    text = ("galactic_object={ 3={ flags={ neo_tier2=1 } } } "
            "galactic_object={ 3={ flags={ neo_tier2=1 } } }")
    assert mod.find_flags(text, "neo_tier2") == [3]


def test_flag_scan_counts_the_systems_that_have_a_flags_block():
    """`systems=0` alone cannot tell "no flag" from "we looked in the wrong place"."""
    text = "galactic_object={ 3={ flags={ other=1 } } 5={ flags={ neo_tier2=1 } } 7={ } }"
    assert mod.flag_scan(text, "neo_tier2") == ([5], 2)


def test_the_flag_report_carries_the_block_count():
    assert mod.format_flag_report("neo_tier2", [], 787) == "neo_tier2: systems=0 flags_blocks=787"


def test_cli_all_prints_every_matching_id(tmp_path, capsys):
    """Flags persist across windows, so the id set must be checkable against the tier log."""
    sav = tmp_path / "x.sav"
    body = " ".join(f"{i}={{ flags={{ neo_tier2=1 }} }}" for i in range(1, 8))
    with zipfile.ZipFile(sav, "w") as archive:
        archive.writestr("gamestate", f"galactic_object={{ {body} }}")
    assert mod.main(["--sav", str(sav), "--flag", "neo_tier2", "--all"]) == 0
    out = capsys.readouterr().out
    assert out.strip() == "neo_tier2: systems=7 flags_blocks=7 ids=1,2,3,4,5,6,7"


def test_cli_prints_the_flag_count(tmp_path, capsys):
    sav = tmp_path / "x.sav"
    with zipfile.ZipFile(sav, "w") as archive:
        archive.writestr("gamestate", "galactic_object={ 3={ flags={ neo_tier2=1 } } }")
    assert mod.main(["--sav", str(sav), "--flag", "neo_tier2"]) == 0
    out = capsys.readouterr().out
    assert out.strip() == "neo_tier2: systems=1 flags_blocks=1 sample=3"
