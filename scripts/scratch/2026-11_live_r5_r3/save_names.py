"""save_names.py — dump `id<TAB>name` for every system in a 4.4.4 text save.

This is the R3 feasibility step (C6-4's known gap: `c2_graph_reconcile.py` wants
an id<TAB>name map and the repo has never had one). It answers one question
offline, before any process is started: does the save carry a name for each
`galactic_object` id, in a form comparable with what `[This.GetName]` prints?

The save stays on the Windows host; only the small TSV travels back.

Usage (Windows):
    python C:/temp/save_names.py <save.sav> --out C:/temp/c6_r3_names.tsv
    python C:/temp/save_names.py <save.sav> --probe

`--probe` prints the first system block's keys and the first few names; it is
the "is this the right field?" reading the feasibility step is allowed to take
without committing to a map.

It imports the repo's own tokenizer (`save_hypergraph`, deployed beside it in
C:/temp) rather than re-implementing Clausewitz: the R3 question is about names,
not about the parser.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

from save_hypergraph import Block, parse_clausewitz, read_gamestate


def name_value(block: Block) -> str | None:
    """The `name` field of a system block: a scalar, or `{ key = "..." }`."""
    for entry_key, entry in block.entries:
        if entry_key != "name":
            continue
        if isinstance(entry, str):
            return entry
        if isinstance(entry, Block):
            for sub_key, sub in entry.entries:
                if sub_key == "key" and isinstance(sub, str):
                    return sub
    return None


def system_names(root: Block) -> list[tuple[int, str]]:
    values = [value for key, value in root.entries if key == "galactic_object"]
    if len(values) != 1 or not isinstance(values[0], Block):
        raise ValueError("top level: expected exactly one 'galactic_object' block")
    rows: list[tuple[int, str]] = []
    for key, value in values[0].entries:
        if not isinstance(key, str) or not key.isdigit():
            continue
        if not isinstance(value, Block):
            continue
        name = name_value(value)
        if name is not None:
            rows.append((int(key), name))
    rows.sort()
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("save", help="path to the .sav ZIP")
    parser.add_argument("--out", default=None, help="write id<TAB>name here")
    parser.add_argument("--probe", action="store_true",
                        help="print the first block's keys and a few names, write nothing")
    args = parser.parse_args(argv)
    try:
        text, replacement = read_gamestate(pathlib.Path(args.save))
        root = parse_clausewitz(text)
    except ValueError as exc:
        print(f"SAVENAMES error={exc}", file=sys.stderr)
        return 2
    try:
        rows = system_names(root)
    except ValueError as exc:
        print(f"SAVENAMES error={exc}", file=sys.stderr)
        return 2
    universe = next(value for key, value in root.entries if key == "galactic_object")
    total = sum(1 for key, value in universe.entries
                if isinstance(key, str) and key.isdigit() and isinstance(value, Block))
    print(f"SAVENAMES systems={total} named={len(rows)} replacement_chars={replacement}")
    if args.probe:
        for key, value in universe.entries[:1]:
            if isinstance(value, Block):
                print("PROBE keys=" + ",".join(str(k) for k, _ in value.entries))
                for entry_key, entry in value.entries:
                    if entry_key == "name":
                        print(f"PROBE name_type={type(entry).__name__} repr={entry!r}"[:400])
                        if isinstance(entry, Block):
                            print("PROBE name_keys=" + ",".join(str(k) for k, _ in entry.entries))
        for system_id, name in rows[:5]:
            print(f"PROBE {system_id}\t{name}")
        for system_id, name in rows[-3:]:
            print(f"PROBE {system_id}\t{name}")
        return 0
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            for system_id, name in rows:
                handle.write(f"{system_id}\t{name}\n")
        print(f"SAVENAMES out={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
