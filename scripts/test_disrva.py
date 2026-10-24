"""Contract tests for ``scripts/disrva.py`` — the offline disassembler readers use daily.

Two things are pinned here:

(1) ``parse_range`` is a pure *token -> interval* function.  The second positional
argument keeps its legacy heuristic (`<=0xFF` is an instruction count, `>0xFF` is a
byte **length**, never an end RVA — the misreading is recorded in 取证卷 §30), and the
explicit ``--end=<rva>`` / ``--len=<n>`` forms added per §59.9 are the only way to say
"end RVA".  Anything undecidable is a ``ValueError`` — a refusal, never a silent
fallback ("任何不可判 = 拒绝").

(2) Importing the module has no side effects: no 46 MB read, and no ``sys.exit`` when
no exe copy exists — ``resolve_exe()`` returns ``None`` and the caller decides.  This is
what lets a plan-level tool import ``parse_range``/``resolve_exe`` on a machine with no
game data.

Module is loaded the way ``scripts/test_pe_disrva.py:31-35`` does it: ``sys.path.insert``
then a plain import.
"""
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import disrva  # noqa: E402
from disrva import parse_range  # noqa: E402


def test_bare_second_arg_below_ff_is_instruction_count():
    begin, end, mode = parse_range("0x1D08520", "60")
    assert mode == "count" and begin == 0x1D08520


def test_bare_second_arg_above_ff_is_byte_length_not_end_rva():
    begin, end, mode = parse_range("0x1D092C0", "0x100")
    assert mode == "legacy_len" and end == 0x1D092C0 + 0x100


def test_explicit_end_flag_is_the_end_rva():
    begin, end, mode = parse_range("0x1D092C0", None)          # 无第二参
    assert mode == "count" and begin == 0x1D092C0
    begin, end, mode = parse_range("0x1D092C0", "--end=0x1D09330")
    assert mode == "end" and end == 0x1D09330


def test_end_below_start_is_refused():
    with pytest.raises(ValueError, match="below start"):
        parse_range("0x1D09330", "--end=0x1D092C0")


def test_resolve_exe_returns_none_when_no_copy_exists(monkeypatch):
    monkeypatch.setenv("NS_STELLARIS_EXE", "/nonexistent/stellaris.exe")
    monkeypatch.setattr(disrva, "CANDIDATES", ["/nonexistent/stellaris.exe"])
    assert disrva.resolve_exe() is None
