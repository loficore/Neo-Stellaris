#!/usr/bin/env python3
"""C4 forensics: read-only execution-frame sampler for base Execute 0x1D08520.

One bounded shot in one game process. The DLL detour records a 1/512 sample of
every base-Execute call: the keyword instance identity at [self], [self+8] and
its vtable shim slot, the first eight qwords of the execution frame (ctx), and
the two scratch slots r8/r9 the dispatch point does not define as parameters.

Four roots are then dereferenced HERE with ReadProcessMemory — self, the frame's
+0x10 helper, r8, r9 — each with its OWN follow budget, so one root cannot starve
the others into silence. Every pointer-shaped qword gets two lookups: its own
first qword is dereferenced and matched against the known CEffect vtable map, and
the qword itself is tested for being a known vtable address. Only values inside
[exe_base, exe_base+SizeOfImage) become RVAs. Nothing is dereferenced inside the
game: a stale pointer can only make one read return None. The shot's own inputs —
base, image size, DLL hash, per-root counts — are written into the TSV as meta
rows, because the artifact is what survives a lost stdout. The old
X=[ctx+0x30] -> S=[X+8] chain is still recorded but no longer carries any verdict
(c1_validation §53.5 falsified it).

Usage: python3 scripts/c2_scope_probe.py [dll] [--poll-s 120] [--settle-s 2]
       [--out C:/temp/c4_scope_probe.tsv] [--census ...] [--id-names ...]
       [--vtables ...]

This is a LIVE shot and requires an explicit naming from the user for the
session (docs/roadmap.md authorization table). Cleanup runs in a finally:
uninstall -> verify -> settle -> assert_game_alive. Never FreeLibrary the DLL,
whatever the rc.

Verdicts: scope_candidate is the only evidence result. no_calls / no_samples /
all_invalid / lexer_only are ENVIRONMENT results — load a running campaign,
unpause, and rerun in a NEW game process (this sampler refuses a process that
already has a detour on 0x1D08520). no_scope_candidate is a real but bounded
code result: the known-vtable map is a floor, so it says "nothing pointed at a
vtable in that set", never "nothing pointed at an object".
"""

import argparse
import hashlib
import os
import struct
import sys
import time

from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll,
    list_exports, call_remote, call_remote_with_arg,
    remote_alloc, read_memory, assert_game_alive,
)

DEFAULT_DLL = r"C:\temp\sqjs_c4.dll"
DEFAULT_OUT = r"C:/temp/c4_scope_probe.tsv"
DEFAULT_CENSUS = os.path.join(
    "evidence", "xrefs", "exec_frame_callers_4_4_4.tsv",
)
DEFAULT_ID_NAMES = os.path.join(
    "evidence", "xrefs", "descriptor_oracle_4_4_4.tsv",
)
DEFAULT_VTABLES = os.path.join(
    "evidence", "xrefs", "ceffect_vtable_map_4_4_4.txt",
)
EXE_MODULE = "stellaris.exe"

POLL_INTERVAL_S = 1.0
POLL_TIMEOUT_S = 120.0
SETTLE_S = 2.0

ENTRY_SIZE = 120
STATS_SIZE = 512
LAYOUT_WORDS = 5
RING_LEN = 256
MAX_FOLLOW = 32
PER_SOURCE_FOLLOW = 8
FOLLOW_SOURCES = ("self", "helper", "arg3", "arg4")
E_LFANEW_OFFSET = 0x3C
SIZE_OF_IMAGE_OFFSET = 0x50
CTX_X_OFFSET = 0x30
CTX_HELPER_OFFSET = 0x10
OBJ_WORDS_BYTES = 64

VERDICT_DIAGNOSIS = {
    "no_calls": (
        "the detour saw no base-Execute call within the poll window. That is an "
        "ENVIRONMENT result, not a code verdict: load a running campaign and "
        "unpause the game, then rerun with a fresh game process."
    ),
    "no_samples": (
        "base Execute ran but the 1/512 gate never fired. A longer --poll-s on a "
        "busy campaign is the only lever; nothing was captured."
    ),
    "all_invalid": (
        "every sample had an implausible self or ctx pointer, so no frame was "
        "recorded. This is an environment/call-shape result; try a fresh process."
    ),
    "lexer_only": (
        "every valid sample carried the lexer sentinel [ctx+0x38]==0xb. These "
        "calls are lexer-path executions, not normal effect fires (section 52); "
        "they cannot answer which object a real execution frame is."
    ),
    "no_scope_candidate": (
        "no qword under self / the frame's +0x10 helper / r8 / r9 pointed at an "
        "object whose vtable is in ceffect_vtable_map_4_4_4.txt. That map is a "
        "FLOOR — it only holds classes whose slot[1] is still base Execute, so "
        "every class overriding Execute is absent. This does NOT say the roots "
        "hold no objects; it says the known set matched nothing. Before reading "
        "it as a negative about any root, check that root's meta counts: "
        "capped_by_source and withheld_by_source both mean it was never read."
    ),
    "scope_candidate": (
        "at least one pointer-shaped qword under the four roots dereferenced to "
        "an object whose vtable RVA is in the known CEffect map. The rows name "
        "which root, which offset, and the matched slot2 entity. Identity of a "
        "CEventScope is still NOT established by this verdict. The member_vtable "
        "rows are a separate datum — a known vtable address sitting AT root+off "
        "describes the root's own class, not what that member points at."
    ),
}

_INT32_MAX = 0x7FFFFFFF
_UINT32_SPAN = 1 << 32

_dispatched = set()


# ---------------------------------------------------------------------------
# Pure decode / judgement layer (imported by test_c2_scope_probe.py)
# ---------------------------------------------------------------------------

def decode_layout(words):
    """Validate the DLL's five layout words; any drift is a ValueError."""
    words = list(words)
    if len(words) != LAYOUT_WORDS:
        raise ValueError(f"layout has {len(words)} words, expected {LAYOUT_WORDS}")
    out = {
        "entry": words[0],
        "stats": words[1],
        "ring": words[2],
        "mask": words[3],
        "version": words[4],
    }
    if out["entry"] != ENTRY_SIZE:
        raise ValueError(f"Entry size drifted: {out['entry']} != {ENTRY_SIZE}")
    if out["stats"] != 56:
        raise ValueError(f"Stats size drifted: {out['stats']} != 56")
    if out["ring"] != RING_LEN:
        raise ValueError(f"ring length drifted: {out['ring']} != {RING_LEN}")
    if out["mask"] != 511:
        raise ValueError(f"sample mask drifted: {out['mask']} != 511")
    if out["version"] != 2:
        raise ValueError(f"unknown layout version {out['version']} != 2")
    return out


def decode_entry(raw):
    """Decode one 120-byte Entry; a short buffer is a ValueError."""
    if len(raw) < ENTRY_SIZE:
        raise ValueError(f"Entry needs {ENTRY_SIZE} bytes, got {len(raw)}")
    (valid, lexer, _pad0, self_vtable_rva, shim_rva, token_id, caller_rva,
     self_ptr, ctx_ptr, *rest) = struct.unpack(
        "<BBHIIII4xQQ8Q2Q", raw[:ENTRY_SIZE]
    )
    return {
        "valid": valid,
        "lexer": lexer,
        "self_vtable_rva": self_vtable_rva,
        "shim_rva": shim_rva,
        "token_id": token_id,
        "caller_rva": caller_rva,
        "self_ptr": self_ptr,
        "ctx_ptr": ctx_ptr,
        "ctx_words": list(rest[:8]),
        "arg3": rest[8],
        "arg4": rest[9],
    }


def decode_stats(text):
    """Parse whitespace-separated ``key=int`` tokens; duplicate keys raise."""
    out = {}
    for tok in text.split():
        if "=" not in tok:
            continue
        key, _, val = tok.partition("=")
        if key in out:
            raise ValueError(f"duplicate key {key!r} in stats text")
        out[key] = int(val)
    return out


def poll_done(now, deadline):
    """The shot samples for the whole window; one early sample is not the end."""
    return now >= deadline


def caller_site(return_rva):
    """The static call site: the engine's ``call rel32`` is 5 bytes."""
    if return_rva < 5:
        raise ValueError(f"return RVA 0x{return_rva:x} cannot precede a call")
    return return_rva - 5


def load_call_census(path):
    """Task 1 site table -> {site: {"func": int|None, "origin": str}}."""
    out = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            cols = line.rstrip("\n").split("\t")
            if len(cols) < 6:
                continue
            try:
                site = int(cols[4], 16)
                func = int(cols[0], 16)
            except ValueError:
                continue
            out[site] = {"func": func, "origin": cols[5]}
    return out


def load_id_names(path):
    """descriptor_oracle TSV -> {id: name}; ids there are decimal."""
    out = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            cols = line.rstrip("\n").split("\t")
            if len(cols) < 2:
                continue
            try:
                out[int(cols[0], 10)] = cols[1]
            except ValueError:
                continue
    return out


def _read_u64(reader, addr):
    raw = reader(addr, 8)
    if raw is None or len(raw) < 8:
        return None
    return struct.unpack("<Q", raw[:8])[0]


def _read_u32(reader, addr):
    raw = reader(addr, 4)
    if raw is None or len(raw) < 4:
        return None
    return struct.unpack("<I", raw[:4])[0]


def follow_chain(reader, ctx_ptr):
    """Follow X=[ctx+0x30] -> S=[X+8] -> id/object with a fallible reader.

    Every step is independent: any unreadable step leaves its fields None and
    ``ok`` False. The caller passes ReadProcessMemory; nothing here trusts an
    address it did not just read.
    """
    out = {
        "x": None, "s": None, "s_vptr": None, "id": None, "object": None,
        "ok": False,
    }
    x = _read_u64(reader, ctx_ptr + CTX_X_OFFSET)
    if x is None:
        return out
    out["x"] = x

    s = _read_u64(reader, x + 8)
    if s is None:
        return out
    out["s"] = s

    out["s_vptr"] = _read_u64(reader, s)
    out["id"] = _read_u32(reader, s + 8)
    out["object"] = _read_u64(reader, s + 0x20)
    out["ok"] = all(
        out[k] is not None for k in ("x", "s", "s_vptr", "id", "object")
    )
    return out


def plausible_user_ptr(addr):
    """Same gate as the DLL's plausible(): ring the unusable reads out here."""
    return (
        isinstance(addr, int)
        and 0x10000 <= addr <= 0x0000_7FFF_FFFF_0000
        and (addr & 7) == 0
    )


def load_vtable_map(path):
    """ceffect_vtable_map_4_4_4.txt -> {vtable_rva: {"slot0", "slot2"}}.

    Keys are MODULE-RELATIVE RVAs, exactly as the file writes them. Lines that
    are comments or do not carry both slot columns are skipped. The set is a
    floor: it only holds classes whose slot[1] is still base Execute.
    """
    out = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            cols = line.split()
            if len(cols) < 6 or cols[0] != "vtable":
                continue
            try:
                vtable_rva = int(cols[1], 16)
                slot0 = int(cols[3], 16)
                slot2 = int(cols[5], 16)
            except ValueError:
                continue
            out[vtable_rva] = {"slot0": slot0, "slot2": slot2}
    return out


def _check_image(exe_base, image_end):
    """Refuse a module span that cannot bound an RVA."""
    if image_end is None or image_end <= exe_base:
        raise ValueError(
            f"image_end={_hex_or_dash(image_end)} must exceed "
            f"exe_base=0x{exe_base:x} — with no upper bound every stale qword "
            "becomes a plausible-looking module RVA"
        )


def follow_object(reader, exe_base, image_end, vtables, root_addr, *,
                  source=""):
    """Read 8 qwords at root_addr and classify every pointer-shaped one.

    Two independent lookups run per candidate and they answer different
    questions. ``known`` dereferences the qword once and matches its vptr — "this
    member points at an object of a known class". ``member_vtable`` asks whether
    the qword is ITSELF a known vtable address; a secondary vtable sitting at
    ``root+off`` is a multiple-inheritance subobject header, so it says something
    about the root's own class. The two must not be merged: the first is a claim
    about a member, the second about the root.

    Values outside [exe_base, image_end) never become RVAs — that is the DLL's
    own ``toRva`` rule, and a fabricated RVA turns a stale pointer into a false
    hit. A failed read stays None instead of becoming 0: an overwritten stack
    helper and a qword that really holds zero are different observations.
    """
    _check_image(exe_base, image_end)

    def to_rva(value):
        if value is None or not (exe_base <= value < image_end):
            return None
        return value - exe_base

    out = {
        "source": source, "root": root_addr, "unreadable": False,
        "words": [], "candidates": [],
    }
    raw = reader(root_addr, OBJ_WORDS_BYTES)
    if raw is None or len(raw) < OBJ_WORDS_BYTES:
        out["unreadable"] = True
        return out
    words = list(struct.unpack("<8Q", raw[:OBJ_WORDS_BYTES]))
    out["words"] = words

    for offset, word in enumerate(words):
        if word == 0 or not plausible_user_ptr(word):
            continue
        vptr = _read_u64(reader, word)
        vptr_rva = to_rva(vptr)
        hit = vtables.get(vptr_rva) if vptr_rva is not None else None
        ptr_rva = to_rva(word)
        member_hit = vtables.get(ptr_rva) if ptr_rva is not None else None
        out["candidates"].append({
            "offset": offset * 8,
            "ptr": word,
            "ptr_rva": ptr_rva,
            "vptr": vptr,
            "vptr_rva": vptr_rva,
            "known": hit is not None,
            "slot2_rva": hit["slot2"] if hit else None,
            "member_vtable": member_hit is not None,
            "member_slot2_rva": member_hit["slot2"] if member_hit else None,
        })
    return out


def summarize(entries, stats, chains, census, id_names, objects=None):
    """Aggregate sampled entries, followed chains and the Task 1 census.

    ``census`` maps a call site to its function/origin; ``id_names`` maps the
    chain's token id to a keyword name. The id is a keyword token id, never a
    system id: an unknown id stays ``-`` instead of being guessed. ``objects``
    carries the four-root dereference results and is what the verdict reads.
    """
    by_caller = {}
    vtables = set()
    valid = 0
    lexer = 0
    for e in entries:
        site = caller_site(e["caller_rva"]) if e["caller_rva"] >= 5 else None
        by_caller[site] = by_caller.get(site, 0) + 1
        if e["valid"]:
            valid += 1
            vtables.add(e["self_vtable_rva"])
            if e["lexer"]:
                lexer += 1

    chain_rows = []
    id_counts = {}
    chain_ok = 0
    for ctx, chain in sorted(chains.items()):
        if chain.get("ok"):
            chain_ok += 1
            if chain.get("id") is not None:
                id_counts[chain["id"]] = id_counts.get(chain["id"], 0) + 1
            name = id_names.get(chain.get("id"), "-")
        else:
            name = "-"
        chain_rows.append({
            "ctx": ctx,
            "ok": bool(chain.get("ok")),
            "x": chain.get("x"),
            "s": chain.get("s"),
            "s_vptr": chain.get("s_vptr"),
            "id": chain.get("id"),
            "object": chain.get("object"),
            "name": name,
        })

    callers = []
    for site, count in sorted(
        by_caller.items(),
        key=lambda kv: (-kv[1], -1 if kv[0] is None else kv[0]),
    ):
        meta = census.get(site, {}) if site is not None else {}
        callers.append({
            "site": site,
            "count": count,
            "func": meta.get("func"),
            "origin": meta.get("origin", "-"),
        })

    ids = sorted(
        ((cid, id_names.get(cid, "-"), n) for cid, n in id_counts.items()),
        key=lambda row: (-row[2], row[0]),
    )

    objects = list(objects or [])
    known_vtable_hits = 0
    member_vtable_hits = 0
    unknown_ptr_hits = 0
    unreadable_roots = 0
    for obj in objects:
        if obj.get("unreadable"):
            unreadable_roots += 1
        for cand in obj.get("candidates", []):
            if cand.get("known"):
                known_vtable_hits += 1
            else:
                unknown_ptr_hits += 1
            if cand.get("member_vtable"):
                member_vtable_hits += 1

    return {
        "calls": stats.get("calls", 0),
        "samples": stats.get("samples", 0),
        "valid": valid,
        "lexer": lexer,
        "chain_ok": chain_ok,
        "known_vtable_hits": known_vtable_hits,
        "member_vtable_hits": member_vtable_hits,
        "unknown_ptr_hits": unknown_ptr_hits,
        "unreadable_roots": unreadable_roots,
        "objects": objects,
        "by_caller": by_caller,
        "distinct_vtables": len(vtables),
        "callers": callers,
        "chains": chain_rows,
        "ids": ids,
    }


def classify(summary):
    """Fixed order: no_calls -> no_samples -> all_invalid -> lexer_only ->
    no_scope_candidate -> scope_candidate.

    The falsified X->S->id chain is deliberately absent from this ladder
    (c1_validation §53.5): chain_ok no longer rescues or sinks a verdict.
    ``member_vtable_hits`` is deliberately absent too — it is a claim about the
    root's own class, not about a member pointing at a known object, so folding
    it in here would let one counter answer two questions.
    """
    if summary.get("calls", 0) == 0:
        return "no_calls"
    if summary.get("samples", 0) == 0:
        return "no_samples"
    if summary.get("valid", 0) == 0:
        return "all_invalid"
    if summary.get("lexer", 0) > 0 and summary.get("lexer", 0) == summary.get("valid", 0):
        return "lexer_only"
    if summary.get("known_vtable_hits", 0) == 0:
        return "no_scope_candidate"
    return "scope_candidate"


def install_decision(words):
    """Decode the DLL's five layout words and say whether a shot may run.

    Returns (layout, reason); reason is None when the layout matches the pinned
    contract. A drifted Entry means every offset the sampler reads is a
    different field than it thinks, so the only safe action is to refuse before
    install — not to sample and print a verdict computed from shifted bytes.
    """
    try:
        return decode_layout(words), None
    except ValueError as exc:
        return None, str(exc)


def exit_code_for(verdict):
    """Only scope_candidate is an evidence result worth exit 0."""
    return 0 if verdict == "scope_candidate" else 1


def image_end_from_header(reader, exe_base):
    """One past the last byte of the exe image, from its live PE header.

    e_lfanew is at +0x3C and SizeOfImage at NT-header +0x50 (PE32+). None when
    either read fails — the caller must then refuse the shot rather than fall
    back to an unbounded image.
    """
    raw = reader(exe_base + E_LFANEW_OFFSET, 4)
    if raw is None or len(raw) < 4:
        return None
    pe_off = struct.unpack("<I", raw)[0]
    raw = reader(exe_base + pe_off + SIZE_OF_IMAGE_OFFSET, 4)
    if raw is None or len(raw) < 4:
        return None
    return exe_base + struct.unpack("<I", raw)[0]


def _hex_or_dash(value):
    return "-" if value is None else f"0x{value:x}"


def _by_source(root_stats, key):
    """One compact meta value per count kind, e.g. 'self=8/helper=0/...'."""
    return "/".join(f"{s}={root_stats[key][s]}" for s in FOLLOW_SOURCES)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_tsv(path, summary, meta=None):
    """Long-form evidence dump; returns the number of data rows written.

    The meta block is not decoration. The shot that produced §56 lost the
    driver's whole stdout to an ssh reset, and the TSV alone could not answer
    which base its RVAs were relative to, how many roots were read, or whether a
    cap had been hit — so a shared cap was read as an absence. Every number the
    verdict depends on is now in the artifact that carries the verdict.
    """
    rows = 0
    with open(path, "w", encoding="utf-8") as f:
        f.write("# kind\tkey\tvalue\tdetail\n")
        for key, value in (meta or {}).items():
            f.write(f"meta\t{key}\t{value}\t-\n")
            rows += 1
        for row in summary.get("callers", []):
            site = "-" if row["site"] is None else f"0x{row['site']:x}"
            func = "-" if row["func"] is None else f"0x{row['func']:x}"
            f.write(
                f"caller\t{site}\t{row['count']}\t"
                f"func={func} origin={row['origin']}\n"
            )
            rows += 1
        for cid, name, count in summary.get("ids", []):
            f.write(f"id\t{cid}\t{count}\tname={name}\n")
            rows += 1
        for chain in summary.get("chains", []):
            f.write(
                f"chain\t0x{chain['ctx']:x}\t{1 if chain['ok'] else 0}\t"
                f"x={_hex_or_dash(chain['x'])} s={_hex_or_dash(chain['s'])} "
                f"vptr={_hex_or_dash(chain['s_vptr'])} "
                f"id={'-' if chain['id'] is None else chain['id']} "
                f"name={chain['name']} "
                f"object={_hex_or_dash(chain['object'])}\n"
            )
            rows += 1
        for obj in summary.get("objects", []):
            if obj.get("unreadable"):
                f.write(
                    f"root_unreadable\t0x{obj['root']:x}\t1\t"
                    f"source={obj['source']}\n"
                )
                rows += 1
            for cand in obj.get("candidates", []):
                f.write(
                    f"object\t0x{obj['root']:x}\t{1 if cand['known'] else 0}\t"
                    f"source={obj['source']} off=0x{cand['offset']:x} "
                    f"ptr=0x{cand['ptr']:x} "
                    f"ptr_rva={_hex_or_dash(cand.get('ptr_rva'))} "
                    f"member_vtable={1 if cand.get('member_vtable') else 0} "
                    f"member_slot2_rva="
                    f"{_hex_or_dash(cand.get('member_slot2_rva'))} "
                    f"vptr={_hex_or_dash(cand.get('vptr'))} "
                    f"vptr_rva={_hex_or_dash(cand.get('vptr_rva'))} "
                    f"slot2_rva={_hex_or_dash(cand.get('slot2_rva'))}\n"
                )
                rows += 1
    return rows


# ---------------------------------------------------------------------------
# Live driver (Windows + game process only)
# ---------------------------------------------------------------------------

def _signed32(raw):
    """Re-bias a thread exit code (unsigned 32-bit) to its C int value."""
    return raw - _UINT32_SPAN if raw > _INT32_MAX else raw


def dispatch_once(pid, base, rva, name, arg=None):
    """Dispatch a remote export at most once per session; return its C int rc."""
    if name in _dispatched:
        raise RuntimeError(
            f"{name} was already dispatched in this session; this probe is "
            "single-shot by design (a second install on the same process would "
            "hit an already-hooked target)"
        )
    _dispatched.add(name)
    if arg is None:
        return _signed32(call_remote(pid, base, rva))
    return _signed32(call_remote_with_arg(pid, base, rva, arg))


def gate_module(pid, dll_path, needed):
    """Inject this copy and clear every gate that must precede a dispatch."""
    dll_name = os.path.basename(dll_path)
    print(f"[scope] pid={pid}  dll={dll_path}")

    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    print(f"[scope] {dll_name} base (64-bit): 0x{base:x}")

    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    print("[scope] MZ header at base OK")

    exports = list_exports(dll_path)
    for name in needed:
        assert name in exports, f"{name} is not an export of {dll_path}"

    sanity = _signed32(call_remote(pid, base, exports["C2Sanity"]))
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch "
        f"against this module copy"
    )
    assert_game_alive(pid)
    print("[scope] C2Sanity == 42, game alive — dispatch authorized")
    return base, exports


def read_layout_words(pid, base, exports):
    """C2ScopeProbeLayout -> the five raw words (validated by install_decision)."""
    buf = remote_alloc(pid, 32)
    call_remote_with_arg(pid, base, exports["C2ScopeProbeLayout"], buf)
    return struct.unpack("<5I", read_memory(pid, buf, LAYOUT_WORDS * 4))


def reset_probe(pid, base, exports):
    """C2ScopeProbeReset must run before install (clears stats and image window)."""
    call_remote(pid, base, exports["C2ScopeProbeReset"])
    assert_game_alive(pid)


def install_probe(pid, base, exports):
    """The one install of this process; -2 means another detour already owns it."""
    rc = dispatch_once(pid, base, exports["C2ScopeProbeInstall"], "C2ScopeProbeInstall")
    assert_game_alive(pid)
    return rc


def read_stats(pid, base, exports, buf):
    """Dispatch C2ScopeProbeStatsInto and decode the NUL-terminated text."""
    call_remote_with_arg(pid, base, exports["C2ScopeProbeStatsInto"], buf)
    raw = read_memory(pid, buf, STATS_SIZE)
    text = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
    return decode_stats(text), text


def drain_entries(pid, base, exports, buf):
    """C2ScopeProbeDrainInto -> oldest-first decoded Entry list."""
    count = call_remote_with_arg(
        pid, base, exports["C2ScopeProbeDrainInto"], buf
    ) & 0xFFFF_FFFF
    count = min(count, RING_LEN)
    if count == 0:
        return []
    blob = read_memory(pid, buf, count * ENTRY_SIZE)
    return [
        decode_entry(blob[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE])
        for i in range(count)
    ]


def _entry_roots(entry):
    """The addresses this record can speak to, as (source, addr, withheld).

    ``withheld`` is a string when the record cannot speak to that root at all.
    capture() writes arg3/arg4 before any validity gate (the Zig test pins that
    ordering), so a rejected sample still says what the dispatch point held in
    r8/r9; self_ptr is written once [self] reads. ctx_words however stay zeroed
    unless the frame passed plausible(ctx), so the helper root is only offered
    for a valid entry — counting a never-captured zero as "rejected by the gate"
    would invent a negative result about a slot that was never read.

    helper is [ctx+0x10]: §53.4.1 recorded it as a pointer (a heap object for the
    long-lived frame, a neighbouring stack helper for the short ones) and no shot
    had ever dereferenced it. arg3/arg4 are r8/r9, which the dispatch point does
    not define as parameters — they are recorded as scratch witnesses.
    """
    yield "self", entry["self_ptr"], None
    if entry["valid"] == 1:
        yield "helper", entry["ctx_words"][CTX_HELPER_OFFSET // 8], None
    else:
        yield "helper", 0, "ctx_not_captured"
    yield "arg3", entry["arg3"], None
    yield "arg4", entry["arg4"], None


def follow_roots(reader, exe_base, image_end, vtables, entries, *,
                 per_source=PER_SOURCE_FOLLOW):
    """Dereference each root's distinct addresses, up to ``per_source`` per root.

    The budget is deliberately PER SOURCE and not one shared cap: with a shared
    cap the self roots consume it first and helper/arg3/arg4 are never read,
    which is indistinguishable in the artifact from "those slots held nothing
    readable" — that is exactly how §56.4 came to report zero arg3/arg4
    observations. Four sources at eight each is the same 32 object reads the
    shot performed before, now spread over the roots instead of spent on one.

    Returns (objects, root_stats). root_stats counts, per source: roots actually
    read, addresses the gate rejected, distinct addresses dropped by the cap, and
    roots withheld because the record never captured them.
    """
    _check_image(exe_base, image_end)
    objects = []
    root_stats = {
        "followed_by_source": {s: 0 for s in FOLLOW_SOURCES},
        "implausible_by_source": {s: 0 for s in FOLLOW_SOURCES},
        "capped_by_source": {s: 0 for s in FOLLOW_SOURCES},
        "withheld_by_source": {s: 0 for s in FOLLOW_SOURCES},
    }
    seen = set()
    for entry in entries:
        for source, addr, withheld in _entry_roots(entry):
            if withheld is not None:
                root_stats["withheld_by_source"][source] += 1
                continue
            if not plausible_user_ptr(addr):
                root_stats["implausible_by_source"][source] += 1
                continue
            key = (source, addr)
            if key in seen:
                continue
            seen.add(key)
            if root_stats["followed_by_source"][source] >= per_source:
                root_stats["capped_by_source"][source] += 1
                continue
            root_stats["followed_by_source"][source] += 1
            objects.append(
                follow_object(reader, exe_base, image_end, vtables, addr,
                              source=source)
            )
    return objects, root_stats


def follow_contexts(pid, entries):
    """Follow the chain for each distinct usable ctx, at most MAX_FOLLOW.

    Reads happen in this process via ReadProcessMemory; any exception becomes
    None for that step, so a stale pointer cannot take the game down.
    """
    def reader(addr, size):
        try:
            return read_memory(pid, addr, size)
        except Exception:  # noqa: BLE001 - an unreadable address is the datum
            return None

    chains = {}
    for entry in entries:
        if entry["valid"] != 1 or entry["ctx_words"][6] == 0:
            continue
        ctx = entry["ctx_ptr"]
        if ctx in chains:
            continue
        if len(chains) >= MAX_FOLLOW:
            break
        chains[ctx] = follow_chain(reader, ctx)
    return chains


def _cleanup(pid, base, exports, installed_ok, settle_s):
    """uninstall -> verify -> settle -> host alive. Returns False if not restored."""
    uninstall_rc = None
    try:
        uninstall_rc = _signed32(call_remote(pid, base, exports["C2ScopeProbeUninstall"]))
    except Exception as exc:  # noqa: BLE001 - cleanup must report, not raise
        print(f"[scope] C2ScopeProbeUninstall raised: {exc}")
    if uninstall_rc not in (0, None):
        print(
            f"[scope] WARNING: C2ScopeProbeUninstall rc={uninstall_rc} — the "
            "engine bytes may still be patched; NEVER FreeLibrary this DLL"
        )
    else:
        print(f"[scope] C2ScopeProbeUninstall rc={uninstall_rc}")

    verify_rc = None
    try:
        verify_rc = _signed32(call_remote(pid, base, exports["C2ScopeProbeVerify"]))
    except Exception as exc:  # noqa: BLE001
        print(f"[scope] C2ScopeProbeVerify raised: {exc}")

    if installed_ok:
        if verify_rc == 0:
            print("[scope] C2ScopeProbeVerify rc=0 (engine bytes intact)")
            restore_ok = True
        else:
            print(
                f"[scope] RESTORE_INCOMPLETE DO_NOT_FREELIBRARY verify={verify_rc}"
            )
            restore_ok = False
    else:
        print(f"[scope] verify={verify_rc} (not installed this run)")
        restore_ok = True

    time.sleep(settle_s)
    try:
        assert_game_alive(pid)
        print("[scope] host alive")
    except Exception as exc:  # noqa: BLE001
        print(f"[scope] HOST DEAD: {exc}")
        return False
    return restore_ok


def run(pid, dll_path, poll_s, settle_s, out_path, census, id_names, vtables,
        exe_base):
    needed = (
        "C2Sanity", "C2ScopeProbeInstall", "C2ScopeProbeUninstall",
        "C2ScopeProbeVerify", "C2ScopeProbeLayout", "C2ScopeProbeStatsInto",
        "C2ScopeProbeDrainInto", "C2ScopeProbeReset",
    )

    def reader(addr, size):
        try:
            return read_memory(pid, addr, size)
        except Exception:  # noqa: BLE001 - an unreadable address is the datum
            return None

    image_end = image_end_from_header(reader, exe_base)
    if image_end is None:
        print(
            f"IMAGE_UNAVAILABLE: SizeOfImage could not be read at "
            f"0x{exe_base:x} — refusing before install. Without an image bound "
            "no pointer can be turned into an RVA, and a verdict computed "
            "against a fabricated bound is worse than no shot."
        )
        return 1

    base = None
    exports = None
    installed_ok = False
    rc = 1
    try:
        base, exports = gate_module(pid, dll_path, needed)
        print(
            f"[scope] exe_base=0x{exe_base:x} image_end=0x{image_end:x} "
            f"known_vtables={len(vtables)}"
        )

        layout, reason = install_decision(read_layout_words(pid, base, exports))
        if layout is None:
            print(f"LAYOUT_DRIFT: {reason} — refusing to install")
        else:
            print(
                f"[scope] LAYOUT entry={layout['entry']} stats={layout['stats']} "
                f"ring={layout['ring']} mask={layout['mask']} "
                f"version={layout['version']}"
            )
            reset_probe(pid, base, exports)

            rc_install = install_probe(pid, base, exports)
            installed_ok = rc_install == 0
            print(f"[scope] C2ScopeProbeInstall rc={rc_install}")
            if not installed_ok:
                print(f"VERDICT: detour_unavailable rc={rc_install}")
            else:
                stats_buf = remote_alloc(pid, STATS_SIZE)
                deadline = time.monotonic() + poll_s
                last_progress = time.monotonic()
                while True:
                    stats, stats_text = read_stats(pid, base, exports, stats_buf)
                    if poll_done(time.monotonic(), deadline):
                        break
                    if time.monotonic() - last_progress >= 10.0:
                        print(
                            f"[scope] waiting: calls={stats.get('calls', 0)} "
                            f"samples={stats.get('samples', 0)} "
                            f"invalid_self={stats.get('invalid_self', 0)} "
                            f"invalid_ctx={stats.get('invalid_ctx', 0)}"
                        )
                        last_progress = time.monotonic()
                    time.sleep(POLL_INTERVAL_S)

                entries_buf = remote_alloc(pid, RING_LEN * ENTRY_SIZE)
                entries = drain_entries(pid, base, exports, entries_buf)
                chains = follow_contexts(pid, entries)
                objects, root_stats = follow_roots(
                    reader, exe_base, image_end, vtables, entries
                )
                summary = summarize(
                    entries, stats, chains, census, id_names, objects=objects
                )
                verdict = classify(summary)
                capped = sum(root_stats["capped_by_source"].values())

                print(f"STATS: {stats_text.strip()}")
                print("CALLERS:")
                for row in summary["callers"]:
                    site = "-" if row["site"] is None else f"0x{row['site']:x}"
                    func = "-" if row["func"] is None else f"0x{row['func']:x}"
                    print(
                        f"  site={site} count={row['count']} "
                        f"func={func} origin={row['origin']}"
                    )
                print("CHAIN:")
                for chain in summary["chains"]:
                    print(
                        f"  ctx=0x{chain['ctx']:x} ok={1 if chain['ok'] else 0} "
                        f"x={_hex_or_dash(chain['x'])} "
                        f"s={_hex_or_dash(chain['s'])} "
                        f"vptr={_hex_or_dash(chain['s_vptr'])} "
                        f"id={'-' if chain['id'] is None else chain['id']} "
                        f"name={chain['name']} "
                        f"object={_hex_or_dash(chain['object'])}"
                    )
                print("OBJECTS:")
                for obj in summary["objects"]:
                    for cand in obj["candidates"]:
                        print(
                            f"  source={obj['source']} root=0x{obj['root']:x} "
                            f"off=0x{cand['offset']:x} ptr=0x{cand['ptr']:x} "
                            f"ptr_rva={_hex_or_dash(cand['ptr_rva'])} "
                            f"member_vtable={1 if cand['member_vtable'] else 0} "
                            f"vptr={_hex_or_dash(cand['vptr'])} "
                            f"vptr_rva={_hex_or_dash(cand['vptr_rva'])} "
                            f"known={1 if cand['known'] else 0} "
                            f"slot2_rva={_hex_or_dash(cand['slot2_rva'])}"
                        )
                print(
                    f"[scope] entries={len(entries)} "
                    f"valid={summary['valid']} lexer={summary['lexer']} "
                    f"chain_ok={summary['chain_ok']} "
                    f"distinct_vtables={summary['distinct_vtables']} "
                    f"ids={summary['ids']}"
                )
                print(
                    f"[scope] roots={len(summary['objects'])} "
                    f"known_vtable_hits={summary['known_vtable_hits']} "
                    f"member_vtable_hits={summary['member_vtable_hits']} "
                    f"unknown_ptr_hits={summary['unknown_ptr_hits']} "
                    f"unreadable_roots={summary['unreadable_roots']} "
                    f"capped_total={capped}"
                )
                for source in FOLLOW_SOURCES:
                    print(
                        f"[scope] root {source}: "
                        f"followed={root_stats['followed_by_source'][source]} "
                        f"implausible={root_stats['implausible_by_source'][source]} "
                        f"capped={root_stats['capped_by_source'][source]} "
                        f"withheld={root_stats['withheld_by_source'][source]}"
                    )
                meta = {
                    "exe_base": f"0x{exe_base:x}",
                    "image_end": f"0x{image_end:x}",
                    "image_size": f"0x{image_end - exe_base:x}",
                    "dll": os.path.basename(dll_path),
                    "dll_sha256": _sha256(dll_path),
                    "vtable_map_count": len(vtables),
                    "layout": (
                        f"entry={layout['entry']} stats={layout['stats']} "
                        f"ring={layout['ring']} mask={layout['mask']} "
                        f"version={layout['version']}"
                    ),
                    "stats": stats_text.strip(),
                    "per_source_follow": PER_SOURCE_FOLLOW,
                    "followed_by_source": _by_source(
                        root_stats, "followed_by_source"),
                    "implausible_by_source": _by_source(
                        root_stats, "implausible_by_source"),
                    "capped_by_source": _by_source(
                        root_stats, "capped_by_source"),
                    "withheld_by_source": _by_source(
                        root_stats, "withheld_by_source"),
                    "calls": summary["calls"],
                    "samples": summary["samples"],
                    "valid": summary["valid"],
                    "lexer": summary["lexer"],
                    "known_vtable_hits": summary["known_vtable_hits"],
                    "member_vtable_hits": summary["member_vtable_hits"],
                    "unknown_ptr_hits": summary["unknown_ptr_hits"],
                    "unreadable_roots": summary["unreadable_roots"],
                    "verdict": verdict,
                }
                rows = write_tsv(out_path, summary, meta=meta)
                print(f"[scope] wrote {rows} rows to {out_path}")

                print(f"VERDICT: {verdict}")
                if verdict in VERDICT_DIAGNOSIS:
                    print(VERDICT_DIAGNOSIS[verdict])
                rc = exit_code_for(verdict)
    finally:
        if base is None:
            print("[scope] nothing was injected — no cleanup to run")
            restore_ok = True
        else:
            restore_ok = _cleanup(
                pid, base, exports, installed_ok, settle_s)
    if not restore_ok:
        return 1
    return rc


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only base-Execute execution-frame sampler (C4 forensics)"
    )
    parser.add_argument("dll", nargs="?", default=DEFAULT_DLL)
    parser.add_argument("--poll-s", type=float, default=POLL_TIMEOUT_S)
    parser.add_argument("--settle-s", type=float, default=SETTLE_S)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--census", default=DEFAULT_CENSUS)
    parser.add_argument("--id-names", dest="id_names", default=DEFAULT_ID_NAMES)
    parser.add_argument("--vtables", default=DEFAULT_VTABLES)
    args = parser.parse_args(argv)

    if not os.path.isfile(args.dll):
        raise SystemExit(
            f"{args.dll} not found — upload the freshly built DLL first (this "
            "script injects THIS file, so it must be the bytes under test)"
        )

    census = {}
    if os.path.isfile(args.census):
        census = load_call_census(args.census)
    else:
        print(
            f"[scope] census missing at {args.census}; CALLERS origin/function "
            "will be '-' (join offline with Task 1's site table)"
        )

    id_names = {}
    if os.path.isfile(args.id_names):
        id_names = load_id_names(args.id_names)
    else:
        print(
            f"[scope] id-name table missing at {args.id_names}; chain names "
            "will be '-' (join offline with descriptor_oracle_4_4_4.tsv)"
        )

    if not os.path.isfile(args.vtables):
        raise SystemExit(
            f"{args.vtables} not found — the known-vtable map is what the verdict "
            "reads. Uploading it is part of the shot procedure (plan Task 6); "
            "running without it could only ever print no_scope_candidate"
        )
    vtables = load_vtable_map(args.vtables)
    if not vtables:
        raise SystemExit(
            f"{args.vtables} parsed to zero vtables — refusing a shot whose "
            "verdict is decided against an empty set"
        )

    pid = resolve_pid("stellaris")
    exe_base = resolve_base_address(pid, EXE_MODULE)
    return run(
        pid, args.dll, args.poll_s, args.settle_s, args.out, census, id_names,
        vtables, exe_base,
    )


if __name__ == "__main__":
    sys.exit(main())
