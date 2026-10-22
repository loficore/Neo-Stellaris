"""Contract tests for ``scripts/chokepoint_scores.py`` — edge list -> scores.

Every graph here is a toy graph with a hand-computed answer, so the tests pin
the algorithm rather than the implementation.  Brandes betweenness is
unweighted and undirected (each unordered pair counted once); articulation
points and bridges are Tarjan's, iterative.
"""
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from chokepoint_scores import (
    articulation_points,
    betweenness,
    bridges,
    build_adjacency,
    main,
    score_rows,
)

HEADER = "system_id\tdegree\tbetweenness\tbetweenness_norm\tscore\tis_articulation\tis_bridge_endpoint"


def test_betweenness_path_graph():
    adjacency = build_adjacency([(0, 1, 1.0), (1, 2, 1.0)])
    scores = betweenness(adjacency)
    assert scores[1] == pytest.approx(1.0)
    assert scores[0] == 0.0
    assert scores[2] == 0.0


def test_betweenness_star_graph():
    adjacency = build_adjacency([(1, 0, 1.0), (1, 2, 1.0), (1, 3, 1.0)])
    assert betweenness(adjacency)[1] == pytest.approx(3.0)


def test_articulation_points_and_bridges():
    adjacency = build_adjacency([(0, 1, 1.0), (1, 2, 1.0)])
    assert articulation_points(adjacency) == {1}
    assert bridges(adjacency) == {(0, 1), (1, 2)}


def test_cycle_has_no_articulation_or_bridge():
    # Ruling: the plan sketched a 3-cycle with a 0.5 expectation, but under the
    # specified Brandes a triangle has zero (every pair has a direct edge). A
    # 4-cycle is the smallest cycle where the expectation 0.5 is exact.
    adjacency = build_adjacency(
        [(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0), (3, 0, 1.0)]
    )
    assert articulation_points(adjacency) == set()
    assert bridges(adjacency) == set()
    assert betweenness(adjacency)[0] == pytest.approx(0.5)


def test_score_normalization_bounds():
    adjacency = build_adjacency([(0, 1, 1.0), (1, 2, 1.0)])
    rows = {row["system_id"]: row for row in score_rows(adjacency)}
    assert rows[1]["betweenness_norm"] == pytest.approx(1.0)
    assert rows[1]["score"] == 1000
    assert rows[0]["score"] == 0


def test_empty_edge_list_exits_2(tmp_path):
    path = tmp_path / "empty.tsv"
    path.write_text("")
    with pytest.raises(SystemExit) as excinfo:
        main([str(path), "--out", str(tmp_path / "o.tsv")])
    assert excinfo.value.code == 2


def test_scores_deterministic_and_sorted(tmp_path):
    plain = tmp_path / "edges.tsv"
    plain.write_text("0\t1\t1\n1\t2\t1\n2\t0\t1\n")
    headered = tmp_path / "edges_header.tsv"
    headered.write_text("a\tb\tlength\n0\t1\t1\n1\t2\t1\n2\t0\t1\n")

    first = tmp_path / "first.tsv"
    second = tmp_path / "second.tsv"
    assert main([str(plain), "--out", str(first)]) == 0
    assert main([str(headered), "--out", str(second)]) == 0
    assert first.read_bytes() == second.read_bytes()

    lines = first.read_text().splitlines()
    assert lines[0] == HEADER
    ids = [int(line.split("\t")[0]) for line in lines[1:]]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))


def test_disconnected_graph_metrics():
    adjacency = build_adjacency(
        [(0, 1, 1.0), (1, 2, 1.0), (3, 4, 1.0)]
    )
    scores = betweenness(adjacency)
    assert scores[1] == pytest.approx(1.0)
    assert scores[3] == 0.0 and scores[4] == 0.0
    assert articulation_points(adjacency) == {1}
    assert bridges(adjacency) == {(0, 1), (1, 2), (3, 4)}
    rows = {row["system_id"]: row for row in score_rows(adjacency)}
    assert rows[1]["betweenness_norm"] == pytest.approx(1.0 / 6.0)
    assert rows[1]["score"] == 167
