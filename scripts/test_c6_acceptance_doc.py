"""c6-acceptance 的文本围栏。

验收标准的价值在于「门 → 脚本 → 证据词」三者对得上。任何一条对不上，文档就会
变成愿望清单：读者照着跑，却拿不到文档承诺的判词。这里只做纯文本检查，不跑游戏。
"""
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
DOC = REPO / "docs/c6-acceptance.md"
GATES = ("C6-1", "C6-2", "C6-3", "C6-4", "C6-5", "C6-6")
COLUMNS = ("gate", "判据", "观测", "证据词", "阈值", "方式")


def _rows(text):
    rows = {}
    for line in text.splitlines():
        if not line.startswith("| C6-"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        rows[cells[0]] = cells
    return rows


def test_every_gate_has_one_row_and_all_columns():
    rows = _rows(DOC.read_text(encoding="utf-8"))
    assert tuple(rows) == GATES
    for gate, cells in rows.items():
        assert len(cells) == len(COLUMNS), f"{gate}: {cells}"
        assert all(cells), f"{gate} has an empty cell"


def test_auto_gates_name_a_real_script_and_a_verdict_it_can_emit():
    text = DOC.read_text(encoding="utf-8")
    for gate, cells in _rows(text).items():
        if cells[5] != "auto":
            continue
        script = re.search(r"scripts/[a-z0-9_]+\.py", cells[2])
        assert script, f"{gate}: 观测列没有点名脚本"
        src = (REPO / script.group(0)).read_text(encoding="utf-8")
        assert cells[3] in src, f"{gate}: 证据词 {cells[3]} 不在 {script.group(0)} 里"


def test_manual_gates_name_two_distinct_artifacts():
    text = DOC.read_text(encoding="utf-8")
    for gate, cells in _rows(text).items():
        if cells[5] != "manual":
            continue
        artifacts = set(re.findall(r"[A-Za-z0-9_./-]+\.(?:log|tsv|sav)", cells[2]))
        assert len(artifacts) >= 2, f"{gate}: manual 门要给两份对照组"


def test_each_gate_has_a_pass_and_a_claim_boundary_section():
    text = DOC.read_text(encoding="utf-8")
    for gate in GATES:
        section = text.split(f"### {gate}", 1)[1].split("### ", 1)[0]
        assert "**通过**" in section
        assert "**不能说**" in section
