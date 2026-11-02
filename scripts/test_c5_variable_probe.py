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
