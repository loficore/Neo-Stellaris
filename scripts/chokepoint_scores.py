#!/usr/bin/env python3
"""Turn a hyperlane edge table into per-system chokepoint scores.

usage: chokepoint_scores.py <edges.tsv> --out <scores.tsv> [--top N]

The input is the TSV produced by ``save_hypergraph.py``: ``a<TAB>b<TAB>length``
with each undirected edge once, optional header.  ``length`` is parsed but the
metrics are unweighted.  Output columns are fixed:

    system_id  degree  betweenness  betweenness_norm  score  is_articulation  is_bridge_endpoint

``betweenness`` is Brandes' unweighted, undirected centrality (each unordered
pair counted once).  ``betweenness_norm`` divides by ``(n-1)(n-2)/2`` and
``score`` is ``round(1000 * betweenness_norm)``.  Booleans are 1/0.  Scores are
save-local: system ids come from one campaign, one game version.

Empty input, malformed rows, self-loops, duplicate edges and bad arguments exit
2 with one stderr line.  Pure standard library; no game process, no network.
"""
from __future__ import annotations

import argparse
import pathlib
import sys
from collections import deque
from typing import Iterable, Optional

HEADER = (
    "system_id\tdegree\tbetweenness\tbetweenness_norm\tscore"
    "\tis_articulation\tis_bridge_endpoint"
)


def build_adjacency(
    edges: Iterable[tuple[int, int, float]]
) -> dict[int, dict[int, float]]:
    adjacency: dict[int, dict[int, float]] = {}
    seen: set[tuple[int, int]] = set()
    for a, b, length in edges:
        if a == b:
            raise ValueError(f"self-loop at system {a}")
        key = (a, b) if a < b else (b, a)
        if key in seen:
            raise ValueError(f"duplicate edge {key[0]}-{key[1]}")
        seen.add(key)
        adjacency.setdefault(a, {})[b] = float(length)
        adjacency.setdefault(b, {})[a] = float(length)
    return adjacency


def betweenness(adjacency: dict[int, dict[int, float]]) -> dict[int, float]:
    nodes = sorted(adjacency)
    scores = {node: 0.0 for node in nodes}
    for source in nodes:
        stack: list[int] = []
        predecessors: dict[int, list[int]] = {node: [] for node in nodes}
        paths = {node: 0.0 for node in nodes}
        paths[source] = 1.0
        distance = {node: -1 for node in nodes}
        distance[source] = 0
        queue = deque([source])
        while queue:
            node = queue.popleft()
            stack.append(node)
            for neighbour in sorted(adjacency[node]):
                if distance[neighbour] < 0:
                    distance[neighbour] = distance[node] + 1
                    queue.append(neighbour)
                if distance[neighbour] == distance[node] + 1:
                    paths[neighbour] += paths[node]
                    predecessors[neighbour].append(node)
        dependency = {node: 0.0 for node in nodes}
        while stack:
            node = stack.pop()
            for previous in predecessors[node]:
                dependency[previous] += (paths[previous] / paths[node]) * (
                    1.0 + dependency[node]
                )
            if node != source:
                scores[node] += dependency[node]
    for node in scores:
        scores[node] /= 2.0
    return scores


def _tarjan(
    adjacency: dict[int, dict[int, float]]
) -> tuple[set[int], set[tuple[int, int]]]:
    discovered: dict[int, int] = {}
    low: dict[int, int] = {}
    parent: dict[int, Optional[int]] = {}
    points: set[int] = set()
    bridge_set: set[tuple[int, int]] = set()
    clock = 0

    for root in sorted(adjacency):
        if root in discovered:
            continue
        parent[root] = None
        discovered[root] = low[root] = clock
        clock += 1
        root_children = 0
        stack: list[tuple[int, list[int], int]] = [
            (root, sorted(adjacency[root]), 0)
        ]
        while stack:
            node, neighbours, index = stack[-1]
            descended = False
            while index < len(neighbours):
                neighbour = neighbours[index]
                index += 1
                if neighbour not in discovered:
                    stack[-1] = (node, neighbours, index)
                    parent[neighbour] = node
                    discovered[neighbour] = low[neighbour] = clock
                    clock += 1
                    if node == root:
                        root_children += 1
                    stack.append((neighbour, sorted(adjacency[neighbour]), 0))
                    descended = True
                    break
                if neighbour != parent[node]:
                    low[node] = min(low[node], discovered[neighbour])
            if descended:
                continue
            stack.pop()
            if stack:
                parent_node = stack[-1][0]
                low[parent_node] = min(low[parent_node], low[node])
                if low[node] > discovered[parent_node]:
                    bridge_set.add(
                        (min(node, parent_node), max(node, parent_node))
                    )
                if parent_node != root and low[node] >= discovered[parent_node]:
                    points.add(parent_node)
        if root_children > 1:
            points.add(root)
    return points, bridge_set


def articulation_points(adjacency: dict[int, dict[int, float]]) -> set[int]:
    return _tarjan(adjacency)[0]


def bridges(adjacency: dict[int, dict[int, float]]) -> set[tuple[int, int]]:
    return _tarjan(adjacency)[1]


def score_rows(adjacency: dict[int, dict[int, float]]) -> list[dict]:
    count = len(adjacency)
    centrality = betweenness(adjacency)
    points, bridge_set = _tarjan(adjacency)
    bridge_endpoints: set[int] = set()
    for a, b in bridge_set:
        bridge_endpoints.add(a)
        bridge_endpoints.add(b)
    denominator = (count - 1) * (count - 2) / 2 if count > 2 else 0.0

    rows = []
    for node in sorted(adjacency):
        normalized = (
            centrality[node] / denominator if denominator > 0 else 0.0
        )
        rows.append(
            {
                "system_id": node,
                "degree": len(adjacency[node]),
                "betweenness": centrality[node],
                "betweenness_norm": normalized,
                "score": int(round(1000 * normalized)),
                "is_articulation": node in points,
                "is_bridge_endpoint": node in bridge_endpoints,
            }
        )
    return rows


def _numeric_row(fields: list[str]) -> bool:
    if len(fields) != 3:
        return False
    try:
        int(fields[0])
        int(fields[1])
        float(fields[2])
    except ValueError:
        return False
    return True


def _read_edges(path: pathlib.Path) -> list[tuple[int, int, float]]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        raise ValueError("empty edge table")
    start = 0 if _numeric_row(lines[0].split("\t")) else 1
    edges = []
    for number, line in enumerate(lines[start:], start + 1):
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError(f"line {number}: expected 3 tab-separated columns")
        try:
            edges.append((int(fields[0]), int(fields[1]), float(fields[2])))
        except ValueError as exc:
            raise ValueError(f"line {number}: non-numeric field") from exc
    if not edges:
        raise ValueError("empty edge table")
    return edges


def _format_row(row: dict) -> str:
    return "\t".join(
        [
            str(row["system_id"]),
            str(row["degree"]),
            f"{row['betweenness']:.6f}",
            f"{row['betweenness_norm']:.6f}",
            str(row["score"]),
            "1" if row["is_articulation"] else "0",
            "1" if row["is_bridge_endpoint"] else "0",
        ]
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("edges", help="edge TSV produced by save_hypergraph.py")
    parser.add_argument("--out", required=True, help="output score TSV")
    parser.add_argument("--top", type=int, default=None, help="print top N to stdout")
    args = parser.parse_args(argv)

    if args.top is not None and args.top < 0:
        print("chokepoint_scores: --top must be non-negative", file=sys.stderr)
        raise SystemExit(2)
    try:
        edges = _read_edges(pathlib.Path(args.edges))
        adjacency = build_adjacency(edges)
    except (ValueError, OSError) as exc:
        print(f"chokepoint_scores: {exc}", file=sys.stderr)
        raise SystemExit(2)

    rows = score_rows(adjacency)
    pathlib.Path(args.out).write_text(
        "\n".join([HEADER] + [_format_row(row) for row in rows]) + "\n",
        encoding="utf-8",
    )

    if args.top is not None:
        top = sorted(
            rows,
            key=lambda row: (row["score"], row["betweenness"], -row["system_id"]),
            reverse=True,
        )[: args.top]
        print(HEADER)
        for row in top:
            print(_format_row(row))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
