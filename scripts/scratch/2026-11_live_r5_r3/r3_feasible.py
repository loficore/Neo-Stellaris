"""r3_feasible.py — one offline question: can the save provide the `--name-map`?

C6-4's known gap (c2_graph_reconcile.py docstring, docs/offline-tooling.md) is
that the repo has no id<->name artifact, so reconcile can only do `tiers_counts`.
This probe answers, without starting a process:

  1. every `galactic_object` id in this save carries a `name`;
  2. the name set equals the set `[This.GetName]` actually printed in a real
     game.log of the same campaign;
  3. names are unique enough that id -> name -> id round-trips (a duplicated
     name would silently collapse two systems in the per-name check).

It prints one verdict line and the first few differences. The save and the log
stay on the host; only this small ASCII report travels back.

Usage (Windows):
    python C:/temp/r3_feasible.py C:/temp/c6_r5_base.sav C:/temp/c6_r3_prev_game.log
"""
from __future__ import annotations

import collections
import pathlib
import re
import sys

from save_hypergraph import Block, parse_clausewitz, read_gamestate

#: Same receipt shape c2_graph_reconcile parses (`NEO_T2 <name>` at line end).
_TIER_LINE = re.compile(r"NEO_(T[0-2])\s+(.+?)\s*$")


def save_names(sav: pathlib.Path) -> dict[int, str]:
    text, _replacement = read_gamestate(sav)
    root = parse_clausewitz(text)
    universe = next((value for key, value in root.entries if key == "galactic_object"), None)
    if not isinstance(universe, Block):
        raise TypeError("no galactic_object block")
    names: dict[int, str] = {}
    for key, value in universe.entries:
        if not isinstance(key, str) or not key.isdigit() or not isinstance(value, Block):
            continue
        for entry_key, entry in value.entries:
            if entry_key != "name":
                continue
            if isinstance(entry, str):
                names[int(key)] = entry
            elif isinstance(entry, Block):
                for sub_key, sub in entry.entries:
                    if sub_key == "key" and isinstance(sub, str):
                        names[int(key)] = sub
                        break
            break
    return names


def log_names(log: pathlib.Path) -> collections.Counter:
    seen: collections.Counter = collections.Counter()
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _TIER_LINE.search(line.strip())
        if match:
            seen[match.group(2)] += 1
    return seen


_DATE = re.compile(r"\[(\d{4}\.\d+\.\d+)\]")


def log_months(log: pathlib.Path) -> tuple[int, int, int]:
    """(months, lines_per_month_min, lines_per_month_max) and duplicate names.

    A per-name map needs one line per system per month. If a month prints fewer
    lines than there are systems, or two systems print the same string, the log
    side cannot be keyed by name.
    """
    per_month: dict[str, list[str]] = {}
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _TIER_LINE.search(line.strip())
        if not match:
            continue
        date = _DATE.search(line)
        per_month.setdefault(date.group(1) if date else "?", []).append(match.group(2))
    counts = [len(names) for names in per_month.values()]
    return len(per_month), (min(counts) if counts else 0), (max(counts) if counts else 0)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    sav, log = pathlib.Path(argv[0]), pathlib.Path(argv[1])
    names = save_names(sav)
    printed = log_names(log)
    months, per_month_min, per_month_max = log_months(log)
    save_values = collections.Counter(names.values())
    duplicated = sorted(name for name, count in save_values.items() if count > 1)
    missing = sorted(set(printed) - set(names.values()))
    extra = sorted(set(names.values()) - set(printed))
    print(f"R3FEAS systems={len(names)} named={len(names)} distinct={len(save_values)} "
          f"dup_names={len(duplicated)}")
    spec = sum(1 for name in save_values if name.startswith("SPEC_"))
    print(f"R3FEAS loc_keys={spec}/{len(save_values)} literal_names={len(save_values) - spec}")
    print(f"R3FEAS log_names_distinct={len(printed)} log_lines={sum(printed.values())} "
          f"missing_from_save={len(missing)} not_printed={len(extra)} "
          f"overlap={len(set(printed) & set(names.values()))}")
    print(f"R3FEAS log_months={months} lines_per_month={per_month_min}..{per_month_max} "
          f"systems_in_save={len(names)}")
    if duplicated:
        print("R3FEAS dup_examples=" + " | ".join(duplicated[:5]))
    if missing:
        print("R3FEAS missing_examples=" + " | ".join(missing[:5]))
    if extra:
        print("R3FEAS unprinted_examples=" + " | ".join(extra[:5]))
    feasible = not missing and not duplicated
    print(f"R3FEAS verdict={'feasible' if feasible else 'not_feasible'} "
          f"reason={'names_roundtrip' if feasible else ('duplicates' if duplicated else 'log_not_subset')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
