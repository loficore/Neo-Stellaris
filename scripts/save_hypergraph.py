#!/usr/bin/env python3
"""Extract the hyperlane graph from a Stellaris 4.4.4 text save.

usage: save_hypergraph.py <save.sav> --edges <out.tsv> [--stats]

The ``.sav`` is a ZIP whose ``gamestate`` entry is text Clausewitz.  The parser
is a small tokenizer that preserves entry order and repeated keys (a plain dict
would drop them) and represents ``{...}`` without a key as an anonymous block
(hyperlane adjacency entries have exactly that shape).  Output is an undirected
edge list ``a<TAB>b<TAB>length`` with ``a < b``, sorted; self-loops are counted
and excluded, never silently repaired.

Hard errors -- not a ZIP, no ``gamestate``, binary ``gamestate``, non-numeric
system/to/length, asymmetric edges, conflicting lengths for one edge -- print
one stderr line and exit 2.  The real save stays on the Windows host; this tool
is read-only and standard-library only.
"""
from __future__ import annotations

import argparse
import pathlib
import sys
import zipfile
from dataclasses import dataclass, field
from typing import Optional, Union

STAT_KEYS = (
    "systems",
    "directed_entries",
    "undirected_edges",
    "components",
    "isolates",
    "self_loops",
    "duplicate_entries",
    "asymmetric_edges",
    "conflicting_edges",
    "replacement_chars",
)


@dataclass
class Block:
    entries: list[tuple[Optional[str], Union[str, "Block"]]] = field(default_factory=list)


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def _skip(self) -> None:
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if char.isspace():
                self.pos += 1
            elif char == "#":
                while self.pos < len(self.text) and self.text[self.pos] != "\n":
                    self.pos += 1
            else:
                return

    def _token(self) -> str:
        if self.pos < len(self.text) and self.text[self.pos] == '"':
            return self._quoted()
        start = self.pos
        while (
            self.pos < len(self.text)
            and not self.text[self.pos].isspace()
            and self.text[self.pos] not in '{}="#'
        ):
            self.pos += 1
        if start == self.pos:
            raise ValueError(f"empty token at character {self.pos}")
        return self.text[start : self.pos]

    def _quoted(self) -> str:
        self.pos += 1
        out: list[str] = []
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if char == "\\" and self.pos + 1 < len(self.text):
                out.append(self.text[self.pos + 1])
                self.pos += 2
                continue
            if char == '"':
                self.pos += 1
                return "".join(out)
            out.append(char)
            self.pos += 1
        raise ValueError("unterminated quoted string")

    def _block(self, top: bool) -> Block:
        block = Block()
        while True:
            self._skip()
            if self.pos >= len(self.text):
                if top:
                    return block
                raise ValueError("unterminated block")
            char = self.text[self.pos]
            if char == "}":
                if top:
                    raise ValueError(f"unexpected '}}' at character {self.pos}")
                self.pos += 1
                return block
            if char == "{":
                block.entries.append((None, self._anonymous_block()))
                continue
            key = self._token()
            self._skip()
            if self.pos >= len(self.text) or self.text[self.pos] != "=":
                # Clausewitz lists (e.g. required_dlcs = { "Horizon Signal" })
                # hold bare scalars with no key.
                block.entries.append((None, key))
                continue
            self.pos += 1
            self._skip()
            if self.pos >= len(self.text):
                raise ValueError(f"missing value for {key!r}")
            if self.text[self.pos] == "{":
                block.entries.append((key, self._anonymous_block()))
            else:
                block.entries.append((key, self._token()))

    def _anonymous_block(self) -> Block:
        self.pos += 1
        return self._block(top=False)

    def parse(self) -> Block:
        return self._block(top=True)


def parse_clausewitz(text: str) -> Block:
    return _Parser(text).parse()


def read_gamestate(sav_path: pathlib.Path) -> tuple[str, int]:
    try:
        with zipfile.ZipFile(sav_path) as archive:
            if "gamestate" not in archive.namelist():
                raise ValueError(f"{sav_path}: zip has no 'gamestate' entry")
            raw = archive.read("gamestate")
    except zipfile.BadZipFile as exc:
        raise ValueError(f"{sav_path}: not a zip file ({exc})") from exc
    except OSError as exc:
        raise ValueError(f"{sav_path}: cannot read save ({exc})") from exc
    text = raw.decode("utf-8", errors="replace")
    if "\x00" in text[:4096]:
        raise ValueError(f"{sav_path}: gamestate looks binary (NUL in first 4096 chars)")
    return text, text.count("\ufffd")


def _decimal(value: object, what: str) -> int:
    if not isinstance(value, str) or not value.isdigit():
        raise ValueError(f"{what} is not a decimal integer: {value!r}")
    return int(value)


def _length(value: object, what: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{what} is not a number: {value!r}") from exc
    return number


def _one_block(block: Block, key: str, what: str) -> Block:
    values = [value for entry_key, value in block.entries if entry_key == key]
    if len(values) != 1 or not isinstance(values[0], Block):
        raise ValueError(f"{what}: expected exactly one '{key}' block")
    return values[0]


def extract_hypergraph(
    root: Block, replacement_chars: int = 0
) -> tuple[dict[int, dict[int, float]], dict]:
    universe = _one_block(root, "galactic_object", "top level")

    system_ids: set[int] = set()
    declaration: dict[tuple[int, int], float] = {}
    directed_entries = 0
    self_loops = 0
    duplicate_entries = 0

    for key, value in universe.entries:
        system_id = _decimal(key, "galactic_object system key")
        if not isinstance(value, Block):
            raise ValueError(f"system {system_id}: block expected")
        system_ids.add(system_id)
        hyperlanes = [v for k, v in value.entries if k == "hyperlane"]
        for hyperlane in hyperlanes:
            if not isinstance(hyperlane, Block):
                raise ValueError(f"system {system_id}: hyperlane is not a block")
            for entry_key, entry in hyperlane.entries:
                if entry_key is not None or not isinstance(entry, Block):
                    raise ValueError(f"system {system_id}: malformed hyperlane entry")
                fields = dict(entry.entries)
                what = f"system {system_id} hyperlane"
                target = _decimal(fields.get("to"), f"{what} 'to'")
                length = _length(fields.get("length"), f"{what} 'length'")
                directed_entries += 1
                if target == system_id:
                    self_loops += 1
                    continue
                pair = (system_id, target)
                if pair in declaration:
                    if declaration[pair] != length:
                        raise ValueError(
                            f"{what}: conflicting length for duplicate edge "
                            f"{system_id}->{target}: {declaration[pair]} vs {length}"
                        )
                    duplicate_entries += 1
                    continue
                declaration[pair] = length

    asymmetric = [(a, b) for (a, b) in declaration if (b, a) not in declaration]
    if asymmetric:
        a, b = asymmetric[0]
        raise ValueError(
            f"{len(asymmetric)} asymmetric hyperlane edge(s), e.g. {a}->{b} has no reverse"
        )

    conflicts = []
    for (a, b), length in declaration.items():
        if a < b and declaration[(b, a)] != length:
            conflicts.append((a, b, length, declaration[(b, a)]))
    if conflicts:
        a, b, first, second = conflicts[0]
        raise ValueError(
            f"{len(conflicts)} conflicting length(s) for one edge, e.g. {a}-{b}: {first} vs {second}"
        )

    adjacency: dict[int, dict[int, float]] = {system_id: {} for system_id in system_ids}
    for (a, b), length in declaration.items():
        adjacency[a][b] = length
        adjacency[b][a] = length

    seen: set[int] = set()
    components = 0
    for start in adjacency:
        if start in seen:
            continue
        components += 1
        seen.add(start)
        stack = [start]
        while stack:
            node = stack.pop()
            for neighbour in adjacency[node]:
                if neighbour not in seen:
                    seen.add(neighbour)
                    stack.append(neighbour)

    stats = {
        "systems": len(system_ids),
        "directed_entries": directed_entries,
        "undirected_edges": len(declaration) // 2,
        "components": components,
        "isolates": sum(1 for system_id in system_ids if not adjacency[system_id]),
        "self_loops": self_loops,
        "duplicate_entries": duplicate_entries,
        "asymmetric_edges": 0,
        "conflicting_edges": 0,
        "replacement_chars": replacement_chars,
    }
    return adjacency, stats


def _format_length(value: float) -> str:
    return str(int(value)) if value.is_integer() else format(value, ".15g")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("save", help="path to the .sav ZIP")
    parser.add_argument("--edges", required=True, help="output edge TSV")
    parser.add_argument("--stats", action="store_true", help="print stats to stdout")
    args = parser.parse_args(argv)

    try:
        text, replacements = read_gamestate(pathlib.Path(args.save))
        adjacency, stats = extract_hypergraph(parse_clausewitz(text), replacements)
    except ValueError as exc:
        print(f"save_hypergraph: {exc}", file=sys.stderr)
        raise SystemExit(2)

    lines = []
    for a in sorted(adjacency):
        for b in sorted(adjacency[a]):
            if a < b:
                lines.append(f"{a}\t{b}\t{_format_length(adjacency[a][b])}")
    pathlib.Path(args.edges).write_text(
        "".join(line + "\n" for line in lines), encoding="utf-8"
    )

    if args.stats:
        for key in STAT_KEYS:
            print(f"{key}={stats[key]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
