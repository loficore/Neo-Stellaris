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
from bisect import bisect_right
from dataclasses import dataclass, replace
import hashlib
import os
import re
import struct

import rttibatch

Image = rttibatch.Image

MANIFEST_COLUMNS = ("chain", "node", "class", "locator", "expect", "depends_on",
                    "witness", "evidence")
CLASSES = ("address", "structure")
LOCATOR_KINDS = ("strref", "callshape", "vtable", "global", "bytes")


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


@dataclass(frozen=True)
class Locator:
    """One locator recipe: a kind, its argument, parameters, confirmations and refs.

    ``confirms`` holds the ``&bytes:...`` tails (each a Locator of its own) and
    ``node_refs`` every ``@node:<name>`` name in the whole expression, in the order
    they appear.  Both are resolved later against the chain's already-decided nodes.
    """
    kind: str
    arg: str
    params: tuple[tuple[str, str], ...] = ()
    confirms: tuple["Locator", ...] = ()
    node_refs: tuple[str, ...] = ()


class LocatorError(Exception):
    """A locator recipe that cannot be parsed; carries line_no when a manifest gave it."""

    def __init__(self, message, line_no=0):
        super().__init__(message)
        self.line_no = line_no
        self.message = message


_NODE_REF_RE = re.compile(r"@node:([A-Za-z0-9_]+)")
_HEX_TOKEN_RE = re.compile(r"[0-9A-Fa-f]{2}")


def _parse_segment(segment):
    """Parse one ``kind:...`` segment (the whole expression is segments joined by '&')."""
    kind, sep, rest = segment.partition(":")
    kind = kind.strip()
    if not sep or kind not in LOCATOR_KINDS:
        raise LocatorError(f"unknown locator kind {kind!r}")
    if not rest:
        raise LocatorError(f"{kind}: empty argument")
    if kind == "bytes":
        pattern = rest.strip()
        tokens = pattern.split()
        if not tokens:
            raise LocatorError("bytes: empty pattern")
        for token in tokens:
            if token != "??" and not _HEX_TOKEN_RE.fullmatch(token):
                raise LocatorError(f"bytes: bad pattern token {token!r}")
        return Locator("bytes", pattern)
    if kind == "vtable":
        slot, eq, value = rest.partition("==")
        slot, value = slot.strip(), value.strip()
        if not eq or not slot or not value:
            raise LocatorError("vtable: expected slot<k>==<rva|@node:name>")
        return Locator("vtable", slot, (("eq", value),))
    if kind == "global":
        params = []
        for part in rest.split(","):
            key, eq, value = part.partition("=")
            if not eq or not key.strip() or not value.strip():
                raise LocatorError(f"global: expected key=value, got {part!r}")
            params.append((key.strip(), value.strip()))
        return Locator("global", "-", tuple(params))
    arg, *tail = rest.split("@")
    arg = arg.strip()
    if not arg:
        raise LocatorError(f"{kind}: empty argument")
    params = []
    for part in tail:
        key, eq, value = part.partition("=")
        if not eq or not key.strip():
            raise LocatorError(f"{kind}: expected key=value after '@', got {part!r}")
        params.append((key.strip(), value))
    return Locator(kind, arg, tuple(params))


def parse_locator(text):
    """Parse ``kind:...`` / ``kind:...&bytes:...`` into a Locator.

    A tab is rejected outright: the manifest is tab-separated, so a tab inside a
    pattern is either a broken column split or a pattern that would match
    everything.  An empty pattern is rejected for the same reason — an empty
    ``bytes:`` would make ``found`` unconditionally true.
    """
    if "\t" in text:
        raise LocatorError("locator must not contain a tab")
    segments = text.split("&")
    main = _parse_segment(segments[0])
    confirms = tuple(_parse_segment(s) for s in segments[1:])
    refs = []
    for loc in (main, *confirms):
        refs.extend(_NODE_REF_RE.findall(loc.arg))
        for _key, value in loc.params:
            refs.extend(_NODE_REF_RE.findall(value))
    return replace(main, confirms=confirms, node_refs=tuple(refs))


def parse_manifest(text):
    """Parse manifest TSV text into Nodes, or raise ManifestError at the first bad line.

    Comments (``#``) and blank lines carry no row.  The first non-comment line must
    be the header, column-for-column: a renamed column would otherwise silently
    shift every value into its neighbour.  A duplicate ``(chain, node)`` pair is an
    error because ``@node:`` references resolve by name — the second row would be
    unreachable while the report still looked complete.
    """
    nodes = []
    known = {}
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
        chain_seen = known.setdefault(chain, set())
        if node in chain_seen:
            raise ManifestError(line_no, f"duplicate node {chain}/{node}")
        depends_on = tuple(p for p in depends.split(",") if p)
        for dep in depends_on:
            if dep not in chain_seen:
                raise ManifestError(line_no, f"forward node reference {dep}")
        if locator:
            try:
                parsed_loc = parse_locator(locator)
            except LocatorError as exc:
                raise ManifestError(line_no, exc.message) from None
            for ref in parsed_loc.node_refs:
                if ref not in chain_seen:
                    raise ManifestError(line_no, f"forward node reference {ref}")
        chain_seen.add(node)
        nodes.append(Node(chain=chain, node=node, cls=cls, locator=locator,
                          expect=expect, depends_on=depends_on,
                          witness=witness, evidence=evidence))
    if not header_seen:
        raise ManifestError(1, "missing header row")
    return nodes


# Same three-candidate chain as rttibatch.find_exe (env first, then the Linux copy,
# then the Windows install); the difference is that a miss returns None here, so a
# test can skip instead of the whole run dying with SystemExit.
_EXE_CANDIDATES = (
    "/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe",
    r"D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe",
)


def find_exe_or_none():
    """Path of a readable stellaris.exe copy, or None — never exits."""
    for cand in (os.environ.get("NS_STELLARIS_EXE"), *_EXE_CANDIDATES):
        if cand and os.path.exists(cand):
            return cand
    return None


def load_image(path):
    """Read-only PE load; no process, no injection."""
    with open(path, "rb") as fh:
        return rttibatch.Image(fh.read())


def image_sha256(path):
    """sha256 of the exe copy, for the report's provenance line."""
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


_VERSION_SIGNATURE = b"\xbd\x04\xef\xfe"  # VS_FIXEDFILEINFO.dwSignature, LE


def pe_version(blob):
    """``a.b.c.d`` from the PE's version resource, or ``unknown``.

    Scans for the VS_FIXEDFILEINFO signature rather than walking the resource
    tree: the resource directory is not in any section Image parses, and the
    four version words sit right behind the signature.  A build with no version
    resource reports ``unknown`` — the tool has no version allow-list (that is
    neo_install's job).
    """
    at = blob.find(_VERSION_SIGNATURE)
    while at != -1:
        if at + 16 <= len(blob):
            ms, ls = struct.unpack_from("<II", blob, at + 8)
            return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
        return "unknown"
    return "unknown"


@dataclass(frozen=True)
class PdataIndex:
    """x64 RUNTIME_FUNCTION bounds, sorted by start, for enclosing-function lookup."""
    starts: tuple[int, ...]
    bounds: tuple[tuple[int, int], ...]

    def func_of(self, rva):
        """(begin, end) of the function containing ``rva``, or None."""
        idx = bisect_right(self.starts, rva) - 1
        if idx < 0:
            return None
        begin, end = self.bounds[idx]
        return None if rva >= end else (begin, end)


def pdata_index(img):
    """Index every .pdata RUNTIME_FUNCTION entry (12 bytes: begin, end, unwind)."""
    entries = []
    for i in range(len(img.secs)):
        if rttibatch.section_name(img, i) != ".pdata":
            continue
        _va, vs, praw = img.secs[i]
        blob = img.blob[praw:praw + vs]
        for off in range(0, len(blob) - 11, 12):
            begin, end, _unwind = struct.unpack_from("<III", blob, off)
            if begin == 0 and end == 0:
                continue
            entries.append((begin, end))
    entries.sort()
    return PdataIndex(tuple(begin for begin, _end in entries), tuple(entries))
