"""Pure-function fence for the graph fixture emitter.

Written before ``graph_fixture_emit.py`` (TDD step 1): the four tests named in
the plan's Task 4 — parse_edges ordering/dedup/blank-skip, parse_scores CRLF +
header, deterministic render, and the ``--check`` drift gate — plus the contract
rejections and the shipped-file round trip.
"""

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import chokepoint_scores
import graph_fixture_emit as mod
from graph_fixture_emit import GraphFixtureDataError, main, parse_edges, parse_scores, render

EDGES_TSV = ROOT / "evidence/xrefs/c5_campaign_edges_4_4_4.tsv"
SCORES_TSV = ROOT / "evidence/xrefs/chokepoint_scores_4_4_4.tsv"
FIXTURE = ROOT / "src/dll/c2/graph_fixture.zig"

SCORE_HEADER = (
    "system_id\tdegree\tbetweenness\tbetweenness_norm\tscore"
    "\tis_articulation\tis_bridge_endpoint"
)


def _score_table(count: int) -> str:
    rows = [
        f"{i}\t1\t0.0\t0.0\t{i % 100}\t{'1' if i % 7 == 0 else '0'}\t{'1' if i % 11 == 0 else '0'}"
        for i in range(count)
    ]
    return "\n".join([SCORE_HEADER, *rows]) + "\n"


def _array_lines(src: str, name: str) -> list[str]:
    """The body lines of one emitted Zig array literal, header stripped."""
    start = src.index(f"pub const {name}:")
    open_brace = src.index(".{", start)
    close = src.index("};", open_brace)
    return [line for line in src[open_brace + 2 : close].splitlines() if line.strip()]


# --- parse_edges -----------------------------------------------------------


def test_parse_edges_ignores_blank_lines_and_orders_pairs():
    text = "0\t1\t2.5\n1\t0\t2.5\n\n2\t3\t1\n"
    assert mod.parse_edges(text) == [(0, 1, 2.5), (2, 3, 1.0)]


def test_parse_edges_strict_mode_rejects_duplicates():
    text = "0\t1\t2.5\n1\t0\t2.5\n"
    assert mod.parse_edges(text) == [(0, 1, 2.5)]
    with pytest.raises(GraphFixtureDataError):
        mod.parse_edges(text, strict=True)


@pytest.mark.parametrize("text", [
    "0\t0\t1\n",            # self-loop
    "0\t1\n",               # two columns
    "0\t1\t2\t3\n",         # four columns
    "x\t1\t2\n",            # non-numeric system id
    "0\t1\tnope\n",         # non-numeric length
    "0\t²\t1\n",        # unicode digit: isdigit() is true, int() rejects it
])
def test_parse_edges_rejects_broken_rows(text):
    with pytest.raises(GraphFixtureDataError):
        mod.parse_edges(text)


# --- parse_scores ---------------------------------------------------------


def test_parse_scores_reads_crlf_and_skips_header():
    text = (
        "system_id\tdegree\tbetweenness\tbetweenness_norm\tscore"
        "\tis_articulation\tis_bridge_endpoint\r\n"
        "0\t1\t0.0\t0.0\t7\t1\t0\r\n"
    )
    assert mod.parse_scores(text)[0] == (0, 7, 1, 0)


def test_parse_scores_reads_the_shipped_table():
    rows = parse_scores(SCORES_TSV.read_text(encoding="utf-8"))
    assert len(rows) == 787
    assert rows[0] == (0, 2, 0, 0)
    assert rows[5] == (5, 4, 1, 1)
    assert rows[7] == (7, 118, 0, 0)
    assert sum(row[2] for row in rows) == 105
    assert sum(row[3] for row in rows) == 159
    assert all(row[0] == i for i, row in enumerate(rows))


@pytest.mark.parametrize("text", [
    SCORE_HEADER.rsplit("\t", 1)[0] + "\n0\t1\t0\t0\t1\t0\n",     # six-column header
    SCORE_HEADER + "\n0\t1\t0\t0\t1\t0\t0\n2\t1\t0\t0\t1\t0\t0\n",  # gap in ids
    SCORE_HEADER + "\n0\t1\t0\t0\t65536\t0\t0\n",                   # score > u16
    SCORE_HEADER + "\n0\t1\t0\t0\t1\t0\n",                          # six fields
    SCORE_HEADER + "\n0\t1\t0\t0\t1\t2\t0\n",                       # non-boolean flag
    SCORE_HEADER + "\n0\t1\t0\t0\t²\t0\t0\n",                  # unicode digit score
    SCORE_HEADER + "\n²\t1\t0\t0\t1\t0\t0\n",                  # unicode digit system_id
])
def test_parse_scores_rejects_broken_tables(text):
    with pytest.raises(GraphFixtureDataError):
        parse_scores(text)


# --- render ---------------------------------------------------------------


def test_render_is_deterministic():
    """Same tables in, same bytes out -- and the layout is the documented one.

    40 systems wrap both the score array (16 per line) and the flag arrays
    (32 per line), so a silent change of either width shows up here.
    """
    rows = [(i, i % 100, i % 2, (i + 1) % 2) for i in range(40)]
    edges = [(i, i + 1, 1.0) for i in range(39)]
    src = mod.render(edges, rows)
    assert src == mod.render(edges, rows)

    # the six declarations, in the documented shape
    assert "pub const SYSTEM_COUNT: usize = 40;" in src
    assert "pub const EDGE_COUNT: usize = 39;" in src
    assert "pub const edges: [EDGE_COUNT][2]u16 = .{" in src
    assert "pub const expected_scores: [SYSTEM_COUNT]u16 = .{" in src
    assert "pub const expected_articulation: [SYSTEM_COUNT]u8 = .{" in src
    assert "pub const expected_bridge_endpoint: [SYSTEM_COUNT]u8 = .{" in src

    # 16 scores per line, 32 flags per line, last line short
    score_lines = _array_lines(src, "expected_scores")
    assert [len(line.split(",")) - 1 for line in score_lines] == [16, 16, 8]
    articulation_lines = _array_lines(src, "expected_articulation")
    assert [len(line.split(",")) - 1 for line in articulation_lines] == [32, 8]
    bridge_lines = _array_lines(src, "expected_bridge_endpoint")
    assert [len(line.split(",")) - 1 for line in bridge_lines] == [32, 8]


def test_render_declares_the_brief_constants():
    src = render([(0, 1, 2.5), (0, 2, 1.0)], [(0, 7, 1, 0), (1, 3, 0, 1), (2, 0, 0, 0)])
    assert "pub const SYSTEM_COUNT: usize = 3;" in src
    assert "pub const EDGE_COUNT: usize = 2;" in src
    assert "pub const edges: [EDGE_COUNT][2]u16" in src
    assert "pub const expected_scores: [SYSTEM_COUNT]u16" in src
    assert "pub const expected_articulation: [SYSTEM_COUNT]u8" in src
    assert "pub const expected_bridge_endpoint: [SYSTEM_COUNT]u8" in src


def test_render_rejects_out_of_range_endpoints_self_loops_and_duplicates():
    rows = [(0, 7, 1, 0), (1, 3, 0, 1)]
    with pytest.raises(GraphFixtureDataError):   # endpoint 2 >= SYSTEM_COUNT
        render([(0, 2, 1.0)], rows)
    with pytest.raises(GraphFixtureDataError):   # self-loop
        render([(1, 1, 1.0)], rows)
    with pytest.raises(GraphFixtureDataError):   # duplicate after normalisation
        render([(0, 1, 1.0), (1, 0, 1.0)], rows)
    with pytest.raises(GraphFixtureDataError):   # non-dense score ids
        render([(0, 1, 1.0)], [(1, 7, 1, 0), (0, 3, 0, 1)])
    with pytest.raises(GraphFixtureDataError):   # score outside u16
        render([(0, 1, 1.0)], [(0, 65536, 1, 0), (1, 3, 0, 1)])
    with pytest.raises(GraphFixtureDataError):   # empty edge table
        render([], rows)


# --- CLI + shipped fixture ------------------------------------------------


def test_generated_fixture_matches_the_emitter():
    edges = parse_edges(EDGES_TSV.read_text(encoding="utf-8"), strict=True)
    rows = parse_scores(SCORES_TSV.read_text(encoding="utf-8"))
    assert len(edges) == 1217 and len(rows) == 787
    shipped = FIXTURE.read_bytes()
    assert shipped == render(edges, rows).encode("utf-8")
    assert b"pub const SYSTEM_COUNT: usize = 787;" in shipped
    assert b"pub const EDGE_COUNT: usize = 1217;" in shipped


def test_score_chain_reproduces_the_frozen_table():
    """The frozen score TSV is exactly what the scorer recomputes today.

    Rebuilds the campaign scores from the edge table via
    ``chokepoint_scores.build_adjacency``/``score_rows`` and compares the four
    columns the fixture carries against the checked-in seven-column table.
    """
    edges = parse_edges(EDGES_TSV.read_text(encoding="utf-8"), strict=True)
    recomputed = chokepoint_scores.score_rows(chokepoint_scores.build_adjacency(edges))
    frozen = parse_scores(SCORES_TSV.read_text(encoding="utf-8"))   # CRLF tolerated
    assert len(recomputed) == len(frozen) == 787

    mismatches = [
        (row["system_id"], row["score"], int(row["is_articulation"]),
         int(row["is_bridge_endpoint"]), system_id, score, articulation, bridge)
        for row, (system_id, score, articulation, bridge) in zip(recomputed, frozen)
        if (row["system_id"], row["score"], int(row["is_articulation"]),
            int(row["is_bridge_endpoint"])) != (system_id, score, articulation, bridge)
    ]
    assert mismatches == []


def test_emit_check_detects_drift(tmp_path):
    edges = tmp_path / "edges.tsv"
    edges.write_text("0\t1\t5\n", encoding="utf-8")
    scores = tmp_path / "scores.tsv"
    scores.write_text(_score_table(787), encoding="utf-8")
    out = tmp_path / "graph_fixture.zig"
    argv = ["--edges", str(edges), "--scores", str(scores), "--out", str(out)]

    assert main(argv) == 0
    assert out.exists()
    good = out.read_bytes()
    assert main([*argv, "--check"]) == 0

    out.write_bytes(good[:-2] + b"  ")          # corrupt one byte
    assert main([*argv, "--check"]) != 0
    out.write_bytes(good)
    assert main([*argv, "--check"]) == 0


def test_main_rejects_a_short_score_table(tmp_path):
    edges = tmp_path / "edges.tsv"
    edges.write_text("0\t1\t5\n", encoding="utf-8")
    scores = tmp_path / "scores.tsv"
    scores.write_text(_score_table(786), encoding="utf-8")
    out = tmp_path / "graph_fixture.zig"
    assert main(["--edges", str(edges), "--scores", str(scores), "--out", str(out)]) == 2
    assert not out.exists()


def test_main_reports_a_missing_input_as_data_error(tmp_path):
    out = tmp_path / "graph_fixture.zig"
    assert main(["--edges", str(tmp_path / "gone.tsv"),
                 "--scores", str(tmp_path / "gone2.tsv"), "--out", str(out)]) == 2
    assert not out.exists()


def test_main_reports_a_unicode_digit_as_data_error(tmp_path):
    """A unicode digit is ``isdigit``-true but ``int``-rejecting.

    Without the ASCII/decimal guard this escaped as an uncaught ValueError, so
    the CLI died with a traceback (rc 1) instead of the documented rc 2.
    """
    edges = tmp_path / "edges.tsv"
    edges.write_text("0\t1\t5\n", encoding="utf-8")
    lines = _score_table(787).split("\n")
    fields = lines[1].split("\t")
    fields[4] = "\u00b2"                     # score column, row 0
    lines[1] = "\t".join(fields)
    scores = tmp_path / "scores.tsv"
    scores.write_text("\n".join(lines), encoding="utf-8")
    out = tmp_path / "graph_fixture.zig"
    assert main(["--edges", str(edges), "--scores", str(scores), "--out", str(out)]) == 2
    assert not out.exists()
