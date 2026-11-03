#!/usr/bin/env python3
"""Compile the campaign edge table and score table into a Zig fixture.

usage: graph_fixture_emit.py --edges E --scores S --out PATH [--check]

``--edges`` is the hyperlane table produced by ``save_hypergraph.py``:
``a<TAB>b<TAB>length`` with each undirected edge once, optional header.
``--scores`` is the seven-column chokepoint table from ``chokepoint_scores.py``
(CRLF tolerated); only ``system_id``, ``score``, ``is_articulation`` and
``is_bridge_endpoint`` are carried into the fixture.  The output declares
``SYSTEM_COUNT``/``EDGE_COUNT`` and the ``edges``/``expected_*`` arrays that
``chokepoint_dynamic.zig`` recomputes against in its golden test.

The ids are save-local: they only mean something for the campaign whose tables
were captured.  Regenerate on every new save; ``--check`` renders in memory and
compares byte-for-byte against the file on disk, exiting non-zero on drift.
Edge lengths are parsed for validation only -- the fixture carries topology.

Bad input (malformed rows, self-loops, duplicates, a non-dense or wrongly sized
score table, an endpoint outside the system range, a score outside u16) exits 2
with one stderr line.  Pure standard library; no game process, no network.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

#: Canonical sources, named in the generated file's header.  ``render`` stays a
#: pure function of its two tables, so it cannot read these back from argv.
EDGE_SOURCE = "evidence/xrefs/c5_campaign_edges_4_4_4.tsv"
SCORE_SOURCE = "evidence/xrefs/chokepoint_scores_4_4_4.tsv"

SCORE_HEADER = (
    "system_id\tdegree\tbetweenness\tbetweenness_norm\tscore"
    "\tis_articulation\tis_bridge_endpoint"
)

#: The campaign the shipped fixture belongs to.  ``render`` stays table-generic;
#: this budget check is the CLI's, and is what turns "a different save" into a
#: loud failure instead of a silently re-scaled fixture.
EXPECTED_SYSTEM_COUNT = 787

SCORES_PER_LINE = 16
FLAGS_PER_LINE = 32


class GraphFixtureDataError(ValueError):
    """The edge table, the score table or the requested output breaks the contract."""


def _uint_field(raw: str, line_no: int, name: str) -> int:
    # ``str.isdigit`` is true for non-ASCII digits such as ``²`` that ``int``
    # then rejects, which would escape as an uncaught ValueError (rc 1) instead
    # of the documented GraphFixtureDataError (rc 2).  ``isdecimal`` plus an
    # ASCII guard accepts exactly the strings ``int`` parses.
    if not (raw.isascii() and raw.isdecimal()):
        raise GraphFixtureDataError(
            f"line {line_no}: {name} is not a non-negative integer: {raw!r}"
        )
    return int(raw)


def _flag_field(raw: str, line_no: int, name: str) -> int:
    if raw not in ("0", "1"):
        raise GraphFixtureDataError(f"line {line_no}: {name} is not 0 or 1: {raw!r}")
    return int(raw)


def parse_edges(text: str, *, strict: bool = False) -> list[tuple[int, int, float]]:
    """``a<TAB>b<TAB>length`` rows as ``(a, b, length)`` with ``a < b``.

    Blank lines are skipped, reversed duplicates are dropped (the table lists
    each undirected edge once; the fixture tolerates the other orientation).
    ``strict`` makes a repeated unordered pair an error instead -- the CLI uses
    it, so a table that lists an edge twice fails the drift gate loudly.  A
    self-loop is always an error.
    """
    edges: list[tuple[int, int, float]] = []
    seen: set[tuple[int, int]] = set()
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise GraphFixtureDataError(
                f"line {line_no}: expected 3 tab fields, got {len(fields)}"
            )
        a = _uint_field(fields[0], line_no, "system id")
        b = _uint_field(fields[1], line_no, "system id")
        try:
            length = float(fields[2])
        except ValueError:
            raise GraphFixtureDataError(
                f"line {line_no}: length is not a number: {fields[2]!r}"
            ) from None
        if a == b:
            raise GraphFixtureDataError(f"line {line_no}: self-loop at system {a}")
        key = (a, b) if a < b else (b, a)
        if key in seen:
            if strict:
                raise GraphFixtureDataError(
                    f"line {line_no}: duplicate edge {key[0]}-{key[1]}"
                )
            continue
        seen.add(key)
        edges.append((key[0], key[1], length))
    return edges


def parse_scores(text: str) -> list[tuple[int, int, int, int]]:
    """Seven-column chokepoint rows as ``(system_id, score, articulation, bridge)``.

    CRLF and LF both split cleanly; ``system_id`` must be dense from 0, ``score``
    must fit u16 and the two boolean columns must be 0/1.
    """
    lines = text.splitlines()
    if not lines or lines[0] != SCORE_HEADER:
        raise GraphFixtureDataError(
            "line 1: header does not match the seven-column chokepoint schema"
        )
    rows: list[tuple[int, int, int, int]] = []
    for line_no, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != 7:
            raise GraphFixtureDataError(
                f"line {line_no}: expected 7 tab fields, got {len(fields)}"
            )
        row_id = _uint_field(fields[0], line_no, "system_id")
        if row_id != len(rows):
            raise GraphFixtureDataError(
                f"line {line_no}: system_id {row_id} is not the expected {len(rows)}"
            )
        score = _uint_field(fields[4], line_no, "score")
        if score > 65535:
            raise GraphFixtureDataError(f"line {line_no}: score {score} exceeds u16")
        articulation = _flag_field(fields[5], line_no, "is_articulation")
        bridge = _flag_field(fields[6], line_no, "is_bridge_endpoint")
        rows.append((row_id, score, articulation, bridge))
    return rows


def _format_values(values: list[int], per_line: int) -> list[str]:
    """``per_line`` values per line, colon-aligned like ``chokepoints_emit``.

    The alignment is what keeps the emitted file stable without running
    ``zig fmt``; the last (short) row is left unpadded.
    """
    rows = [values[i : i + per_line] for i in range(0, len(values), per_line)]
    ncols = max(len(row) for row in rows)
    widths = [
        max((len(str(row[j])) for row in rows if j < len(row)), default=1)
        for j in range(ncols)
    ]
    lines = []
    for row in rows:
        cells = [f"{v},".ljust(widths[j] + 2) for j, v in enumerate(row)]
        lines.append(("    " + "".join(cells)).rstrip())
    return lines


def _checked_edges(
    edges: list[tuple[int, int, float]], system_count: int
) -> list[tuple[int, int]]:
    normalized: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    for index, edge in enumerate(edges):
        try:
            a, b = edge[0], edge[1]
        except (TypeError, IndexError, KeyError):
            raise GraphFixtureDataError(f"edge {index}: malformed row {edge!r}") from None
        for name, value in (("a", a), ("b", b)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise GraphFixtureDataError(
                    f"edge {index}: endpoint {name}={value!r} is not a u16 system id"
                )
        if a == b:
            raise GraphFixtureDataError(f"edge {index}: self-loop at system {a}")
        key = (a, b) if a < b else (b, a)
        if key[1] >= system_count:
            raise GraphFixtureDataError(
                f"edge {index}: endpoint {key[1]} is outside 0..{system_count - 1}"
            )
        if key in seen:
            raise GraphFixtureDataError(f"edge {index}: duplicate edge {key[0]}-{key[1]}")
        seen.add(key)
        normalized.append(key)
    return normalized


def _checked_rows(rows: list[tuple[int, int, int, int]]) -> list[tuple[int, int, int, int]]:
    for index, row in enumerate(rows):
        try:
            row_id, score, articulation, bridge = row
        except (TypeError, ValueError):
            raise GraphFixtureDataError(f"row {index}: malformed row {row!r}") from None
        if row_id != index:
            raise GraphFixtureDataError(
                f"row {index}: system_id {row_id!r} is not the expected {index}"
            )
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 65535:
            raise GraphFixtureDataError(f"row {index}: score {score!r} is outside u16")
        for name, flag in (("is_articulation", articulation),
                           ("is_bridge_endpoint", bridge)):
            if flag not in (0, 1):
                raise GraphFixtureDataError(f"row {index}: {name} {flag!r} is not 0/1")
    return rows


def render(edges: list[tuple[int, int, float]], rows: list[tuple[int, int, int, int]]) -> str:
    """The fixture source for these two tables; deterministic and pure.

    Enforces the structural contract (dense score ids, u16 scores, endpoints
    inside the system range, no self-loops or duplicates); the campaign-size
    budget lives in ``main`` so this stays usable on small fixtures.
    """
    if not rows:
        raise GraphFixtureDataError("score table is empty")
    if not edges:
        raise GraphFixtureDataError("edge table is empty")
    rows = _checked_rows(list(rows))
    normalized = _checked_edges(list(edges), len(rows))

    out = [
        "// Generated by scripts/graph_fixture_emit.py; do not edit by hand.",
        f"// Source: {EDGE_SOURCE} (a<TAB>b<TAB>length) and",
        f"//         {SCORE_SOURCE} (seven-column score table).",
        "// System ids are save-local: they only mean something for the campaign",
        "// those tables were captured from (same caveat as chokepoint_table.zig).",
        "// `edges` lists each undirected hyperlane once with a < b; lengths are",
        "// parsed for validation but the fixture carries topology only.",
        "",
        f"pub const SYSTEM_COUNT: usize = {len(rows)};",
        f"pub const EDGE_COUNT: usize = {len(normalized)};",
        "",
        "pub const edges: [EDGE_COUNT][2]u16 = .{",
    ]
    out.extend(f"    .{{ {a}, {b} }}," for a, b in normalized)
    out.append("};")
    out.append("")
    out.append("pub const expected_scores: [SYSTEM_COUNT]u16 = .{")
    out.extend(_format_values([row[1] for row in rows], SCORES_PER_LINE))
    out.append("};")
    out.append("")
    out.append("pub const expected_articulation: [SYSTEM_COUNT]u8 = .{")
    out.extend(_format_values([row[2] for row in rows], FLAGS_PER_LINE))
    out.append("};")
    out.append("")
    out.append("pub const expected_bridge_endpoint: [SYSTEM_COUNT]u8 = .{")
    out.extend(_format_values([row[3] for row in rows], FLAGS_PER_LINE))
    out.append("};")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--edges", required=True, help="edge TSV: a<TAB>b<TAB>length")
    parser.add_argument("--scores", required=True, help="seven-column score TSV")
    parser.add_argument("--out", required=True, help="Zig file to write or check")
    parser.add_argument("--check", action="store_true", help="fail on drift instead of writing")
    args = parser.parse_args(argv)

    try:
        edges = parse_edges(
            pathlib.Path(args.edges).read_text(encoding="utf-8"), strict=True
        )
        rows = parse_scores(pathlib.Path(args.scores).read_text(encoding="utf-8"))
        if len(rows) != EXPECTED_SYSTEM_COUNT:
            raise GraphFixtureDataError(
                f"score table has {len(rows)} rows, expected {EXPECTED_SYSTEM_COUNT}"
            )
        rendered = render(edges, rows).encode("utf-8")
    except (OSError, UnicodeDecodeError, GraphFixtureDataError) as exc:
        print(f"graph_fixture_emit: {exc}", file=sys.stderr)
        return 2

    out = pathlib.Path(args.out)
    if args.check:
        try:
            existing = out.read_bytes()
        except OSError as exc:
            print(f"graph_fixture_emit: {out} cannot be read for --check: {exc}",
                  file=sys.stderr)
            return 2
        if existing != rendered:
            print(
                f"graph_fixture_emit: {out} drifted from {args.edges} + {args.scores};"
                " regenerate it",
                file=sys.stderr,
            )
            return 1
        return 0

    try:
        # write_bytes, not write_text: the fence is byte-exact, and default
        # newline translation would make a Windows checkout write CRLF and then
        # fail its own --check.
        out.write_bytes(rendered)
    except OSError as exc:
        print(f"graph_fixture_emit: cannot write {out}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
