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
from __future__ import annotations

from bisect import bisect_right
import argparse
from dataclasses import dataclass, replace
import datetime
import hashlib
import json
import os
import re
import struct
import sys

import rttibatch
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

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
    confirms: tuple[Locator, ...] = ()
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


_MD = Cs(CS_ARCH_X86, CS_MODE_64)
_MD.detail = True
_MD.skipdata = True  # a decode gap must not truncate the scan: that reads as "not found"


def _read_span(img, start, end):
    """Bytes of ``[start, end)``, or b'' when the span leaves the image."""
    try:
        return img.read(start, end - start)
    except KeyError:
        return b""


def find_cstring(img, text):
    """Every RVA in the image where ``text`` ends with a NUL.

    The real image embeds the full build path (``C:\\mnt\\gsg\\...\\scriptedeffect.cpp``),
    so a suffix match is the only stable form: the prefix is build-machine noise.
    """
    needle = text.encode()
    hits = []
    for _va, vs, praw in img.secs:
        blob = img.blob[praw:praw + vs]
        at = blob.find(needle + b"\x00")
        while at != -1:
            hits.append(_va + at)
            at = blob.find(needle + b"\x00", at + 1)
    return sorted(hits)


def rel32_call_targets(img, start, end):
    """Targets of every direct ``E8 rel32`` in ``[start, end)``."""
    code = _read_span(img, start, end)
    out = []
    for i in range(len(code) - 4):
        if code[i] != 0xE8:
            continue
        out.append(start + i + 5 + struct.unpack_from("<i", code, i + 1)[0])
    return out


def memory_disp_set(img, start, end):
    """Every non-RIP ``[reg+disp]`` displacement in ``[start, end)``."""
    disps = set()
    for insn in _MD.disasm(_read_span(img, start, end), img.image_base + start):
        for op in insn.operands:
            if op.type == X86_OP_MEM and op.mem.base != X86_REG_RIP:
                disps.add(op.mem.disp)
    return disps


def indirect_call_disps(img, start, end):
    """Every ``FF /2`` disp8 in ``[start, end)`` — the ``call qword ptr [reg+disp]`` form."""
    code = _read_span(img, start, end)
    out = set()
    for i in range(len(code) - 2):
        if code[i] != 0xFF:
            continue
        modrm = code[i + 1]
        if modrm & 0xC7 != 0x40 or (modrm >> 3) & 7 != 2:
            continue
        out.add(struct.unpack_from("<b", code, i + 2)[0])
    return out


class Resolver:
    """Resolve a Locator recipe against one image, returning candidate RVAs.

    Every kind returns *all* its matches, sorted: the decision of "one hit is
    found, two hits are ambiguous" belongs to ``decide``, never here.  A refinement
    parameter (``calls=``, ``reads=``) is a *must contain* filter on the enclosing
    function, so a candidate that does not satisfy it is dropped rather than
    reported as a weaker match.
    """

    def __init__(self, img, pdata):
        self.img = img
        self.pdata = pdata

    def _function_span(self, start):
        span = self.pdata.func_of(start)
        return span or (start, start)

    def _strref(self, loc):
        funcs = set()
        for rva in find_cstring(self.img, loc.arg):
            for site in rttibatch.lea_sites_to(self.img, rva):
                span = self.pdata.func_of(site)
                if span:
                    funcs.add(span[0])
        params = dict(loc.params)
        wanted_calls = int(params["calls"], 16) if "calls" in params else None
        wanted_disp = _disp_of(params["reads"]) if "reads" in params else None
        out = []
        for start in sorted(funcs):
            _begin, end = self._function_span(start)
            if wanted_calls is not None and \
                    wanted_calls not in rel32_call_targets(self.img, start, end):
                continue
            if wanted_disp is not None and \
                    wanted_disp not in memory_disp_set(self.img, start, end):
                continue
            out.append(start)
        return out

    def _callshape(self, loc):
        prefix, _sep, disp_text = loc.arg.partition("+")
        if prefix != "callptr" or not disp_text:
            raise ValueError(f"callshape: expected callptr+<disp>, got {loc.arg!r}")
        wanted = int(disp_text, 16)
        out = []
        for begin, end in self.pdata.bounds:
            if wanted in indirect_call_disps(self.img, begin, end):
                out.append(begin)
        return sorted(out)

    def _vtable(self, loc):
        slot_key, _sep, slot_text = loc.arg.partition("slot")
        if slot_key or not slot_text:
            raise ValueError(f"vtable: expected slot<k>, got {loc.arg!r}")
        slot = int(slot_text)
        wanted = int(dict(loc.params)["eq"], 16)
        out = []
        for vt, _run, _slots in rttibatch.all_vtables(self.img, min_run=1):
            try:
                value = self.img.u64(vt + 8 * slot) - self.img.image_base
            except KeyError:
                continue
            if value == wanted:
                out.append(vt)
        return out

    def _global(self, loc):
        params = dict(loc.params)
        try:
            writes = int(params["writes_by"], 16)
            reads = int(params["reads_by"], 16)
        except (KeyError, ValueError) as exc:
            raise ValueError("global: needs writes_by=<rva> and reads_by=<rva>") from exc
        targets = set(rip_operand_targets(self.img, *self._function_span(writes)))
        targets &= set(rip_operand_targets(self.img, *self._function_span(reads)))
        return sorted(targets)

    def _bytes(self, loc):
        pattern = parse_bytes_pattern(loc.arg)
        out = []
        for va, vs, _praw in self.img.secs:
            out.extend(match_bytes(self.img, pattern, va, va + vs))
        return sorted(out)

    def _primary(self, loc):
        if loc.kind == "strref":
            return self._strref(loc)
        if loc.kind == "callshape":
            return self._callshape(loc)
        if loc.kind == "vtable":
            return self._vtable(loc)
        if loc.kind == "global":
            return self._global(loc)
        if loc.kind == "bytes":
            return self._bytes(loc)
        raise ValueError(f"unknown locator kind {loc.kind!r}")

    def resolve(self, loc, results):
        """Candidates for ``loc``; ``results`` carries the chain's earlier nodes.

        ``&bytes:`` confirmations run *after* the main locator and only inside the
        candidate's own function: a confirmation that fails drops the candidate
        (that is a ``zero``), never a weaker verdict — a confirmation exists to
        prove this is the same code, and "nearly the same" is not that.
        """
        loc = substitute_node_refs(loc, results)
        candidates = self._primary(loc)
        for confirm in loc.confirms:
            confirm = substitute_node_refs(confirm, results)
            if confirm.kind != "bytes":
                raise ValueError(f"only bytes confirmations are supported, got {confirm.kind!r}")
            pattern = parse_bytes_pattern(confirm.arg)
            candidates = [c for c in candidates if self._confirms(c, pattern)]
        return candidates

    def _confirms(self, candidate, pattern):
        """Does ``pattern`` sit at the candidate (or anywhere in its function body)?"""
        span = self.pdata.func_of(candidate)
        if span:
            return bool(match_bytes(self.img, pattern, *span))
        return bool(match_bytes(self.img, pattern, candidate,
                                candidate + max(len(pattern[0]), 1)))


_DISP_RE = re.compile(r"-?\s*0x([0-9A-Fa-f]+)|\[[^\]]*([+-])\s*0x([0-9A-Fa-f]+)\]")


def _disp_of(text):
    """Pull a displacement out of ``0x38`` / ``[this+0x38]`` / ``[rcx-0x10]``."""
    text = text.strip()
    match = _DISP_RE.search(text)
    if not match:
        raise ValueError(f"cannot read a displacement from {text!r}")
    if match.group(1) is not None:
        return int(match.group(1), 16)
    value = int(match.group(3), 16)
    return -value if match.group(2) == "-" else value


@dataclass(frozen=True)
class NodeResult:
    """One node's verdict.  ``got`` is set for found/moved only; ambiguous keeps all."""
    node: str
    verdict: str
    got: int | None
    candidates: tuple[int, ...]


def substitute_node_refs(loc, results):
    """Replace every ``@node:<name>`` in a Locator with that node's ``got`` address.

    Only found/moved nodes have an address to substitute: a zero or ambiguous
    prerequisite raises LookupError, which the chain walker turns into ``not_run``
    rather than inventing an address.  Substitution is recursive over ``confirms``.
    """
    def _one(value):
        def _repl(match):
            name = match.group(1)
            node = results.get(name)
            if node is None or node.verdict not in ("found", "moved") or node.got is None:
                state = node.verdict if node else "not in results"
                raise LookupError(f"@node:{name} is {state}")
            return hex(node.got)
        return _NODE_REF_RE.sub(_repl, value)

    return replace(loc,
                   arg=_one(loc.arg),
                   params=tuple((key, _one(value)) for key, value in loc.params),
                   confirms=tuple(substitute_node_refs(c, results) for c in loc.confirms),
                   node_refs=())


def parse_bytes_pattern(text):
    """``48 89 ?? 24`` -> (value bytes with ?? as 0, mask bytes with ?? as 0)."""
    values, masks = [], []
    for token in text.split():
        if token == "??":
            values.append(0)
            masks.append(0)
        else:
            values.append(int(token, 16))
            masks.append(0xFF)
    return bytes(values), bytes(masks)


def match_bytes(img, pattern, start_rva, end_rva):
    """Every RVA in ``[start, end)`` where ``pattern`` matches; mask 0 = wildcard."""
    value, mask = pattern
    code = _read_span(img, start_rva, end_rva)
    if not value:
        return []
    hits = []
    for off in range(len(code) - len(value) + 1):
        if all((byte & m) == (v & m) for byte, v, m in zip(code[off:off + len(value)], value, mask)):
            hits.append(start_rva + off)
    return hits


def rip_operand_targets(img, start, end):
    """Targets of ``48/4C 8B|8D <modrm mod=00 rm=101> disp32`` in ``[start, end)``."""
    code = _read_span(img, start, end)
    out = []
    for off in range(len(code) - 6):
        if code[off] not in (0x48, 0x4C) or code[off + 1] not in (0x8D, 0x8B):
            continue
        if code[off + 2] & 0xC7 != 0x05:
            continue
        out.append(start + off + 7 + struct.unpack_from("<i", code, off + 3)[0])
    return out


def decide(cls, expect, candidates):
    """Turn a candidate list into a verdict.

    ``ambiguous`` never picks ``expect`` out of several candidates: a recipe that
    stops converging is a defect in the recipe, and hiding it by preferring the
    familiar address would make the report read "found" while the locator was no
    longer able to say which match is the anchor.  ``structure`` nodes with no
    expectation only judge that an entry exists (single candidate), never that it
    still means the same thing.
    """
    candidates = tuple(sorted(candidates))
    if len(candidates) > 1:
        return NodeResult("", "ambiguous", None, candidates)
    if not candidates:
        return NodeResult("", "zero", None, ())
    got = candidates[0]
    if cls == "structure" or expect in ("", "-"):
        return NodeResult("", "found", got, ())
    return NodeResult("", "found" if got == int(expect, 16) else "moved", got, ())


def evaluate_chain(nodes, resolver):
    """Resolve one chain in manifest order; return (colour, results, structure gaps).

    Dependencies short-circuit: a node whose prerequisite is not found/moved is
    ``not_run`` rather than ``zero``, so a broken top of the chain cannot emit a
    false "this anchor is gone" for everything downstream.  ``structure`` nodes
    without a locator are registered-but-unjudged and listed in ``unverified`` —
    the machine-readable form of "this build can be read, not written".
    """
    done = {}
    results = []
    unverified = []
    for node in nodes:
        deps = [done.get(dep) for dep in node.depends_on]
        if any(res is None or res.verdict not in ("found", "moved") for res in deps):
            result = NodeResult(node.node, "not_run", None, ())
        elif not node.locator:
            result = NodeResult(node.node, "skipped_structure", None, ())
            unverified.append(node.node)
        else:
            try:
                loc = substitute_node_refs(parse_locator(node.locator), done)
            except LookupError:
                result = NodeResult(node.node, "not_run", None, ())
            else:
                result = decide(node.cls, node.expect, resolver.resolve(loc, done))
                result = replace(result, node=node.node)
        done[node.node] = result
        results.append(result)
    verdicts = {result.verdict for result in results}
    if verdicts & {"zero", "ambiguous"}:
        color = "red"
    elif "moved" in verdicts:
        color = "yellow"
    else:
        color = "green"
    return color, results, unverified


DEFAULT_MANIFEST = "evidence/xrefs/chain_manifest_4_4_4.tsv"
REPORT_COLUMNS = ("chain", "node", "class", "verdict", "expect", "got", "delta",
                  "candidates", "witness", "note")


def locator_mix(nodes):
    """``strref=n callshape=n vtable=n global=n bytes=n structure=n`` in a fixed order.

    The counts are the report's own evidence that the recipe set is not pure
    self-证: a manifest made only of ``bytes:`` would be found on every build that
    still has the same bytes, and prove nothing about the anchors.
    """
    counts = dict.fromkeys((*LOCATOR_KINDS, "structure"), 0)
    for node in nodes:
        if not node.locator:
            counts["structure"] += 1
        else:
            counts[node.locator.split(":", 1)[0]] += 1
    return " ".join(f"{kind}={counts[kind]}" for kind in (*LOCATOR_KINDS, "structure"))


def exit_code(colors):
    """0 = no red chain; 2 = at least one red; an empty run is red by construction."""
    if not colors or "red" in colors:
        return 2
    return 0


def format_report(meta, nodes, results):
    """Render the TSV report: meta lines, header, one row per node in manifest order.

    ``note`` only ever carries machine-generated phrases — the report is an
    artifact other tools diff, so prose belongs in the analysis volumes, not here.
    """
    pairs = list(zip(nodes, results))
    chains = []
    for node, _result in pairs:
        if node.chain not in chains:
            chains.append(node.chain)
    colors = {}
    witnesses = {}
    for node, result in pairs:
        colors.setdefault(node.chain, [])
        colors[node.chain].append(result.verdict)
        if node.witness:
            witnesses.setdefault(node.chain, node.witness)
    lines = [
        f"# manifest={meta.get('manifest', DEFAULT_MANIFEST)}",
        f"# exe={meta.get('exe', '')}",
        f"# exe_sha256={meta.get('exe_sha256', '')}",
        f"# target_version={meta.get('target_version', 'unknown')}",
        f"# generated={meta.get('generated', datetime.date.today().isoformat())}",
        "# chains: " + " ".join(
            f"{chain}=" + ("red" if {"zero", "ambiguous"} & set(colors[chain])
                           else "yellow" if "moved" in colors[chain] else "green")
            for chain in chains),
        "# locators: " + locator_mix(nodes),
        "# witness: " + " ".join(f"{chain}={witnesses.get(chain, '-')}" for chain in chains),
        "\t".join(REPORT_COLUMNS),
    ]
    for node, result in pairs:
        got = "" if result.got is None else hex(result.got)
        delta = candidates = note = ""
        if result.verdict == "moved":
            delta = f"{result.got - int(node.expect, 16):+#x}"
            note = f"delta {delta}"
        elif result.verdict == "ambiguous":
            candidates = ";".join(hex(c) for c in result.candidates)
            note = f"{len(result.candidates)} candidates: {candidates}"
        elif result.verdict == "skipped_structure":
            note = "skipped: structure"
        lines.append("\t".join([node.chain, node.node, node.cls, result.verdict,
                                node.expect, got, delta, candidates, node.witness, note]))
    return "\n".join(lines) + "\n"


def mask_rel32(raw):
    """Render bytes as a ``bytes:`` pattern, wildcarding rel32 call/jump displacements.

    ``E8``/``E9 rel32`` and ``0F 80..8F rel32`` carry a displacement, so those
    four bytes move whenever the function is re-laid-out.  Masking them is what
    turns "20 bytes at this RVA" into a pattern that can survive an address shift;
    a plain hexdump would only ever match the build it came from.  Pure opcode
    knowledge, no decoder, so it stays a pure function.
    """
    tokens = []
    at = 0
    while at < len(raw):
        byte = raw[at]
        if byte in (0xE8, 0xE9):
            tokens.append(f"{byte:02x}")
            tokens.extend(["??"] * min(4, len(raw) - at - 1))
            at += 5
        elif byte == 0x0F and at + 1 < len(raw) and 0x80 <= raw[at + 1] <= 0x8F:
            tokens.extend(["0f", f"{raw[at + 1]:02x}"])
            tokens.extend(["??"] * min(4, len(raw) - at - 2))
            at += 6
        else:
            tokens.append(f"{byte:02x}")
            at += 1
    return " ".join(tokens)


def report_path_for(exe_path, version):
    """Default artifact path: ``evidence/xrefs/chain_drift_<version>.tsv`` under the repo."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(repo, "evidence", "xrefs", f"chain_drift_{version}.tsv")


def _bytes_at(exe, rva, count):
    """``--bytes-at``: print a bytes: recipe for the code at ``rva`` and exit 0."""
    img = load_image(exe)
    try:
        raw = img.read(rva, count)
    except KeyError:
        print(f"chain_drift: {rva:#x} is not inside the image")
        return 3
    print(f"bytes: {mask_rel32(raw)}")
    print(f"# rva={rva:#x} count={len(raw)}")
    return 0


def _report_meta(args, exe, version):
    return {"manifest": args.manifest, "exe": exe,
            "exe_sha256": image_sha256(exe), "target_version": version}


def main(argv=None):
    """CLI.  Exit codes: 0 clean, 2 at least one red chain, 3 environment/manifest error."""
    parser = argparse.ArgumentParser(
        prog="chain_drift.py",
        description="Resolve the manifest's locator recipes against one stellaris.exe copy.")
    parser.add_argument("--exe", help="stellaris.exe copy (default: NS_STELLARIS_EXE, then the usual chain)")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST, help="chain manifest TSV")
    parser.add_argument("--chain", action="append", metavar="NAME",
                        help="restrict to this chain (repeatable; default: all)")
    parser.add_argument("--report", help="report path (default: evidence/xrefs/chain_drift_<version>.tsv)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON instead of writing it")
    parser.add_argument("--bytes-at", type=lambda text: int(text, 16), metavar="RVA",
                        help="print a bytes: recipe for the code at this RVA and exit")
    parser.add_argument("-n", "--count", type=int, default=16, help="bytes to read with --bytes-at")
    args = parser.parse_args(argv)

    exe = args.exe or find_exe_or_none()
    if args.bytes_at is not None:
        if not exe or not os.path.exists(exe):
            print("chain_drift: exe not found")
            return 3
        return _bytes_at(exe, args.bytes_at, args.count)

    if args.report and os.path.realpath(args.report) == os.path.realpath(args.manifest):
        print("chain_drift: --report must not overwrite the manifest")
        return 3
    try:
        with open(args.manifest, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"chain_drift: cannot read manifest {args.manifest}: {exc}")
        return 3
    try:
        nodes = parse_manifest(text)
    except ManifestError as exc:
        print(f"chain_drift: {exc}")
        return 3

    all_chains = []
    for node in nodes:
        if node.chain not in all_chains:
            all_chains.append(node.chain)
    if args.chain:
        unknown = [name for name in args.chain if name not in all_chains]
        if unknown:
            print(f"chain_drift: unknown chain {unknown[0]!r} (manifest has {', '.join(all_chains) or 'none'})")
            return 3
        wanted = [name for name in all_chains if name in args.chain]
    else:
        wanted = all_chains

    if not exe or not os.path.exists(exe):
        print("chain_drift: exe not found")
        return 3
    if not nodes:
        print("chain_drift: empty manifest")
        return 2

    img = load_image(exe)
    version = pe_version(img.blob)
    resolver = Resolver(img, pdata_index(img))
    meta = _report_meta(args, exe, version)
    colors = []
    payload = {}
    selected = []
    for chain in wanted:
        chain_nodes = [node for node in nodes if node.chain == chain]
        color, results, unverified = evaluate_chain(chain_nodes, resolver)
        colors.append(color)
        payload[chain] = {"color": color, "structure_unverified": unverified,
                          "results": [result.__dict__ | {"node": result.node} for result in results]}
        selected.extend(zip(chain_nodes, results))
    report = format_report(meta, [node for node, _r in selected],
                           [result for _n, result in selected])
    if args.json:
        print(json.dumps({"meta": meta, "chains": payload}, indent=2))
    else:
        path = args.report or report_path_for(exe, version)
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(report)
        summary = " ".join(chain + "=" + payload[chain]["color"] for chain in wanted)
        print(f"chain_drift: wrote {path} ({summary})")
    return exit_code(colors)


if __name__ == "__main__":
    sys.exit(main())
