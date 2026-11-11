"""Cross-version chain drift: does our five-capability chain survive a new exe?

The manifest (``evidence/xrefs/chain_manifest_4_4_4.tsv``) is the single source of
truth: one row per anchor, each carrying a ``locator`` recipe and the 4.4.4
``expect`` landing.  This tool resolves every recipe against an arbitrary
``stellaris.exe`` copy and reports ``found / moved / ambiguous / zero`` per
address node, then folds each chain to ``green / yellow / red``.

Read-only file parse: no process, no injection, no IDA licence (AGENTS.md
constraint 1).  ``class=structure`` nodes are registered but never judged for
semantics — only for "an entry still exists" — because that class of anchor
fails by reading the right place with the wrong layout, which is undecidable
from bytes alone (``version_drift_4_4_4.md`` §0).

usage: python3 chain_drift.py --exe <path> [--manifest <tsv>] [--chain <name>]...
"""
from dataclasses import dataclass

MANIFEST_COLUMNS = ("chain", "node", "class", "locator", "expect", "depends_on",
                    "witness", "evidence")
CLASSES = ("address", "structure")


@dataclass(frozen=True)
class Node:
    """One manifest row: an anchor, its locator recipe, and its 4.4.4 landing."""
    chain: str
    node: str
    cls: str
    locator: str
    expect: str
    depends_on: tuple[str, ...]
    witness: str
    evidence: str


class ManifestError(Exception):
    """A manifest line that cannot be trusted; ``line_no`` is 1-based."""

    def __init__(self, line_no, message):
        super().__init__(f"manifest line {line_no}: {message}")
        self.line_no = line_no
        self.message = message


def parse_manifest(text):
    """Parse manifest TSV text into Nodes, or raise ManifestError at the first bad line.

    Comments (``#``) and blank lines carry no row.  The first non-comment line must
    be the header, column-for-column: a renamed column would otherwise silently
    shift every value into its neighbour.  A duplicate ``(chain, node)`` pair is an
    error because ``@node:`` references resolve by name — the second row would be
    unreachable while the report still looked complete.
    """
    nodes = []
    seen = set()
    header_seen = False
    for line_no, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not header_seen:
            if tuple(raw.split("\t")) != MANIFEST_COLUMNS:
                raise ManifestError(
                    line_no, "header must be exactly " + "\\t".join(MANIFEST_COLUMNS))
            header_seen = True
            continue
        fields = raw.split("\t")
        if len(fields) != len(MANIFEST_COLUMNS):
            raise ManifestError(
                line_no, f"expected {len(MANIFEST_COLUMNS)} columns, got {len(fields)}")
        chain, node, cls, locator, expect, depends, witness, evidence = fields
        if cls not in CLASSES:
            raise ManifestError(line_no, f"unknown class {cls!r} (want address|structure)")
        if (chain, node) in seen:
            raise ManifestError(line_no, f"duplicate node {chain}/{node}")
        seen.add((chain, node))
        nodes.append(Node(chain=chain, node=node, cls=cls, locator=locator,
                          expect=expect,
                          depends_on=tuple(p for p in depends.split(",") if p),
                          witness=witness, evidence=evidence))
    if not header_seen:
        raise ManifestError(1, "missing header row")
    return nodes
