#!/usr/bin/env python3
"""C4 forensics: read-only witness of an OUT-OF-FAMILY exec shim (0xCC4220, structures §13).

WHAT IT READS.  One bounded shot in one game process.  The DLL detours ``0xCC4220`` — the
first of §13's seven exec shims that each ran exactly 2,090 times in the 2026-09-29 census —
and for every call records only ``[self+0]`` (the vtable pointer of the object it ran for),
joined against the SEVEN vtables §13 tied to those seven shims, plus the return address and
the argument registers as VALUES.  Nothing is written into engine memory except the
install-time JMP and its restore; nothing under ``ctx``/``a3``/``a4`` is ever dereferenced
inside the game (a stale pointer may only make one ReadProcessMemory return None, it must
never fault the host).

WHY THIS TARGET.  §71 pinned the target offline: ``0xCC4220`` is the ``slot[2]``
(``ExecuteActual``) of vtable ``0x25460F0``, whose slot[1] is still base Execute
``0x1D08520`` — the SAME dispatch slot as the family's donor ``0x3AFD30`` and witness
``0x3B01A0``, while its vtable is NOT one of the five family tables (that intersection is
empty; §71.3).  The family's own two instruments came back silent (§67/§69/§70), and a
silent family-internal probe cannot separate "the family is not executing" from "the family
executes but never through that helper" (§57.2 观测 4).  A guard on a table-dispatched
executor that is *outside* those five tables is the independent witness §57.4's third tier
was missing: if it fires, some vtable-dispatched ``ExecuteActual`` really ran.

USAGE.  ``python3 scripts/c2_shim_probe.py [dll] [--mask 0] [--poll-s 120] [--settle-s 2]
[--out C:/temp/c4_shim_probe.tsv]``.  There is no separate ``--freq`` flag: the frequency
window is ``--poll-s 20``, exactly as §69 ran it.

AUTHORIZATION.  This is a LIVE shot: it injects into the running game and therefore needs an
explicit per-session naming from the user — the authorization table in ``docs/roadmap.md``.
The offline plan writes and statically verifies this file only; nothing here runs it.

GATE ORDER (pinned, do not reorder).  ``resolve_pid → resolve_base_address → sha 门 →
gate_module(NEEDED_EXPORTS) → Layout → Reset → SetMask → Install → 轮询 Stats → Drain →
write_tsv → finally: Uninstall → Verify → settle → assert_game_alive``.  Each arrow is a real
dependency, not style:

* ``resolve_base_address`` runs before injection and resolves ``stellaris.exe``, because the
  shot's provenance (base + image size) is what makes every recorded RVA readable afterwards.
* the sha 门 hashes the file it is about to inject.  A whole-file DLL sha is NOT a code
  identity (docs/offline-tooling.md: every relink changes it while ``.text`` stays
  byte-identical), so this gate is a provenance print plus a refusal to inject an unreadable
  file — not an equality assert against a pinned constant.
* ``gate_module`` checks ``NEEDED_EXPORTS`` in the FILE BEFORE injecting: a missing export
  means yesterday's DLL, and finding that out after LoadLibrary leaves an unloadable copy in
  the process forever.
* ``Layout → Reset → SetMask → Install`` is loadable order: ``Reset`` clears counters, the
  ring and the mask but deliberately does NOT uninstall the hook, so it must run before
  ``Install`` (a mid-shot clear would silently restart the sampling denominator).  ``SetMask``
  runs before ``Install`` so the first call is already sampled under the intended mask.

CLEANUP.  The ``finally`` block runs uninstall → verify → settle → assert_game_alive.
**绝不 ``FreeLibrary``** — the detour's trampoline lives in this module's mapping; unloading it
with the patch restored is fine, unloading it at any other moment turns a restore problem into
a crash.  If uninstall reports ``-7`` (or verify comes back non-zero after we installed), the
driver prints ``RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY``: treat that process as untrusted.

``-2`` IS NOT RETRIED.  One process gets one install: ``-2`` means this process already
installed this guard once, or the predicate detour is still armed (``PatchActive``).  The
second cause is the one that would poison the instrument's whole verdict: under an armed
predicate detour ``[self+0]`` points at OUR DLL-owned vtable, so its readings could never join
the seven tables and would land in ``unmatched`` — a code answer manufactured by our own patch.
The module refuses that state outright; the only lever is a fresh game process.

FOUR GUARDS COEXIST IN ONE PROCESS, SERIALLY.  Each guard's state is private to its own module
(``donor_exec_probe.zig`` / ``instantiate_witness_probe.zig`` / this one), and ``-2`` only
fires on "this guard already installed" or "predicate armed", neither of which another guard's
state can cause.  So a window may run shim witness → family witness → donor in one process,
each uninstalled cleanly before the next installs.  That is a serial handoff, not two live
patches at once.

FREQUENCY DISCIPLINE (§57.4: 不要照搬 base Execute 的 1/512).  Default ``--mask 0`` records
EVERY call into the ring (256 slots, ring-buffered).  Before any named shot with a mask, run
a 20-second window (``--poll-s 20``) and read the ``calls`` delta to get this shim's real call
frequency.  The verdict's main readings are the per-call ``hN`` counters and ``unmatched``,
counted BEFORE the sampling gate — the ring is only the witness.  Whoever computes a ratio
from the ring alone is reading a witness as if it were the measurement.

VERIFY CODES (the module's signed convention, passed through unchanged): ``0`` consistent;
``-1`` the hook is gone while the module still believes it is installed; ``-2`` engine bytes do
not match the fingerprint while we are NOT installed; ``-3`` the target was never resolved in
this process.

ARTIFACT.  The TSV's first line is ``#meta`` and carries base, image size, the injected DLL's
sha256, the mask, ``calls``, and the per-tier readings behind the verdict — because the
artifact is what survives a lost stdout (§56 lost a whole stdout to an ssh reset).

Verdict domain (see ``VERDICTS``; it has NO per-system tier on purpose):
``no_calls_inconclusive`` is an ENVIRONMENT result and, for this instrument, a
disqualification — a silent shim has more than one reading (the execution it belongs to did
not happen / it happened outside this window / the 2,090-per-window census from 2026-09-29 no
longer describes the current scene), and this probe cannot separate them.  It only says
本仪器没问出执行在发生 — never 「这一族不执行」.  ``shim_hit_named`` /
``shim_hit_unknown_table`` are the two code answers; ``instrument_broken`` /
``counter_desync`` say the probe, or the shot's bookkeeping, was not sound.  Both code tiers
are gated on ``installed == 1``: ``calls > 0`` with ``installed == 0`` did not come from an
installed probe in this process, so it decodes to ``counter_desync`` rather than a code answer.

判读陷阱（族外证人版，三条，先读再用读数）:

1. **``calls == 0`` 不是 §57.4 第三档的正面证据**,只是「本窗口没观测到」。反过来
   ``calls > 0`` 也只证明这个执行体在跑,**不**证明它按 system 走 —— §13 原话
   ``correlate this number against the live system count … before claiming it``,那次
   相关性是 §74 的事,不是本仪器的读数。
2. **七张表是形状判据,不是身份判据**(§57.5 第 2 条)。``unmatched > 0`` 只能写「不在
   这七张里」;``map``/census 都是**下限**,不能升格成对族外的否定结论。
3. **四把仪器的 ``[self+0]`` 不同源,不得互引**:donor 读的是 Execute 的 effect 对象,
   证人读的是被 instantiate 的父对象,本仪器读的是族外 shim 的 `self`。拿一把的 ``h``
   计数去解释另一把的 ``unmatched`` 分区,就是把两个测量当同一个。
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
DEFAULT_OUT = r"C:/temp/c4_shim_probe.tsv"
DEFAULT_MASK = 0
EXE_MODULE = "stellaris.exe"

TARGET_RVA = 0xCC4220        # offset.keyword_reg.RVA_SHIM_WITNESS_EXECUTE (§71.1)
ENTRY_SIZE = 48              # bytes of one ring record (layoutInto word 0)
STATS_SIZE = 512             # the fixed stats buffer the exports write into
LAYOUT_WORDS = 6             # mask is a u64: two words
RING_LEN = 256
LAYOUT_VERSION = 1
STATS_KEYS = ("calls", "samples", "invalid_self", "unmatched",
              "h0", "h1", "h2", "h3", "h4", "h5", "h6",
              "patch_size", "installed", "mask")

POLL_INTERVAL_S = 1.0
POLL_TIMEOUT_S = 120.0
SETTLE_S = 2.0
PROGRESS_EVERY_S = 10.0
FREQ_WINDOW_S = 20.0         # the §57.4 frequency window (run it as --poll-s 20)

E_LFANEW_OFFSET = 0x3C
SIZE_OF_IMAGE_OFFSET = 0x50

_INT32_MAX = 0x7FFFFFFF
_UINT32_SPAN = 1 << 32

#: Single authority for the verdict value domain.  ``verdict_for`` may only return a
#: member of this tuple.  There is deliberately NO tier that claims per-system behaviour:
#: that claim needs the census-vs-live-system-count correlation (§13 :425, §74), which this
#: instrument does not do.
VERDICTS = (
    "no_calls_inconclusive",
    "shim_hit_named",
    "shim_hit_unknown_table",
    "instrument_broken",
    "counter_desync",
)

#: The two verdicts that answer a question about engine code (exit 0).  The rest are
#: environment / instrumentation readings and must not be reported as a negative.
EVIDENCE_VERDICTS = ("shim_hit_named", "shim_hit_unknown_table")

#: Names the driver requires in the DLL file BEFORE it injects it.
NEEDED_EXPORTS = (
    "C2Sanity",
    "C4ShimProbeInstall",
    "C4ShimProbeSetMask",
    "C4ShimProbeUninstall",
    "C4ShimProbeVerify",
    "C4ShimProbeLayout",
    "C4ShimProbeStatsInto",
    "C4ShimProbeDrainInto",
    "C4ShimProbeReset",
)

_dispatched = set()


# ---------------------------------------------------------------------------
# Pure decode / judgement layer (imported by test_c2_shim_probe.py; no ctypes,
# no handles — the offline tests run on the Linux host, zero shots)
# ---------------------------------------------------------------------------

def table_rvas():
    """The seven out-of-family vtables the module joins ``[self+0]`` against.

    Written as a function, not a module-level dict, to stay inside ruling P10 (the layout
    fence's R-rva rule polices hard-coded ``RVAS`` dicts).  These are the same seven RVAs as
    ``OUT_OF_FAMILY_VTABLES`` in ``src/dll/c2/shim_witness_probe.zig`` and the seven 2,090-call
    rows of ``evidence/xrefs/exec_shim_census_2026_09_29.txt``; ``test_c2_shim_probe.py`` pins
    this list against both, order included (``matched`` is ``1 + index``, so a reorder keeps
    the set and breaks every ``hN`` reading).
    """
    return [0x25460F0, 0x250E188, 0x254FA18, 0x25531E8, 0x2551620, 0x2553178, 0x2553140]


def decode_layout(words):
    """Validate the DLL's six layout words; any drift is a ValueError.

    ``[48, 64, 256, mask_lo, mask_hi, 1]`` — the mask is a u64 and takes TWO words, so a
    driver that copied c2_scope_probe's five-word read would silently answer ``mask=512`` for
    a mask of ``1<<32``.  Stats is 64 here and 56 in the family modules: that single word is
    how a #meta line says WHICH guard was armed, so a driver that accepted 56 would happily
    decode the witness line's ``h5``/``h6`` as ``patch_size``/``installed``.  An unknown
    version word is refused rather than guessed at.
    """
    words = list(words)
    if len(words) != LAYOUT_WORDS:
        raise ValueError(
            f"layout has {len(words)} words, expected {LAYOUT_WORDS} "
            "(mask occupies two)"
        )
    out = {
        "entry": words[0],
        "stats": words[1],
        "ring": words[2],
        "mask": words[3] | (words[4] << 32),
        "mask_lo": words[3],
        "mask_hi": words[4],
        "version": words[5],
    }
    if out["entry"] != ENTRY_SIZE:
        raise ValueError(f"Entry size drifted: {out['entry']} != {ENTRY_SIZE}")
    if out["stats"] != 64:
        raise ValueError(f"Stats size drifted: {out['stats']} != 64")
    if out["ring"] != RING_LEN:
        raise ValueError(f"ring length drifted: {out['ring']} != {RING_LEN}")
    if out["version"] != LAYOUT_VERSION:
        raise ValueError(
            f"unknown layout version {out['version']} != {LAYOUT_VERSION}")
    return out


def decode_entry(raw):
    """Decode one 48-byte ring record; a short buffer is a ValueError.

    ``matched`` is the module's ``1 + table index`` (0 = "not one of the seven"), so
    ``table_index``/``table_rva`` are None for an unmatched record and also for a ``matched``
    outside 1..7 — that would be layout drift, and dressing it up as a table hit is the one
    reading this must not produce.
    """
    if len(raw) < ENTRY_SIZE:
        raise ValueError(f"Entry needs {ENTRY_SIZE} bytes, got {len(raw)}")
    (valid, matched, _pad0, self_vtable_rva, caller_rva,
     self_ptr, ctx_ptr, a3, a4) = struct.unpack(
         "<BBHII4xQQQQ", raw[:ENTRY_SIZE])
    tables = table_rvas()
    index = matched - 1 if matched else None
    if index is not None and not 0 <= index < len(tables):
        index = None
    return {
        "valid": valid,
        "matched": matched,
        "table_index": index,
        "table_rva": None if index is None else tables[index],
        "self_vtable_rva": self_vtable_rva,
        "caller_rva": caller_rva,
        "self_ptr": self_ptr,
        "ctx_ptr": ctx_ptr,
        "a3": a3,
        "a4": a4,
    }


def decode_stats(text):
    """Parse the DLL's one-line stats readout into its fourteen keys.

    ``mask`` is rendered in hex by the module (``mask={x}``) while every other key is
    decimal, so the base is per-key, not per-line.  The key set must match ``STATS_KEYS``
    exactly: the module's ``statsInto`` always writes all fourteen in a fixed order, so a
    missing key (a torn line), a duplicate, or an unknown key (a different module build) means
    this is not a readable stats line — and a half-written line must not silently become a
    verdict.
    """
    out = {}
    for tok in text.split():
        if "=" not in tok:
            continue
        key, _, val = tok.partition("=")
        if key in out:
            raise ValueError(f"duplicate key {key!r} in stats text")
        out[key] = int(val, 16) if key == "mask" else int(val)
    missing = [k for k in STATS_KEYS if k not in out]
    unknown = [k for k in out if k not in STATS_KEYS]
    if missing or unknown:
        raise ValueError(
            f"stats keys drifted: missing={missing} unknown={unknown}")
    return out


def verdict_for(stats):
    """Read the seven-table counters; answer with a member of ``VERDICTS``.

    The ladder reads the per-call counters only, never the ring, because the counters are the
    measurement and the ring is the witness.  Order: a silent window first (``calls == 0`` is
    ENVIRONMENT, and for this instrument it is the disqualification — never a negative about
    any execution), then the all-``invalid_self`` shape (the probe cannot read ``[self+0]``, so
    it can speak about nothing), then the ``installed`` gate, then the two code tiers, then the
    arithmetic residue.

    ``shim_hit_unknown_table`` (tier 2) is a HANDOFF to a 静态查表 of the ring's
    ``self_vtable_rva`` plus the #meta image-span partition — not a conclusion.  ``unmatched``
    also absorbs code-address ``[self+0]`` readings, ``toRva``-refused out-of-image pointers
    (RVA lands as 0), and the tail inside the 64 MiB window but past the real
    ``SizeOfImage``.  So tier 2 只说明「不在**这七张**里」;七张表与那份 census 都是**下限**,
    要想说族外的事,得另做静态查表。不要借其他仪器的 ``[self+0]`` 读数来解释它们
    (判读陷阱 3)。
    """
    calls = stats.get("calls", 0)
    if calls == 0:
        return "no_calls_inconclusive"
    invalid = stats.get("invalid_self", 0)
    unmatched = stats.get("unmatched", 0)
    hits = [stats.get(f"h{i}", 0) for i in range(7)]
    if invalid >= calls and not any(hits) and unmatched == 0:
        return "instrument_broken"
    if stats.get("installed", 0) != 1:
        return "counter_desync"
    if any(hits):
        return "shim_hit_named"
    if unmatched > 0:
        return "shim_hit_unknown_table"
    # calls > 0 but no counter accounts for any of it: the shot's own bookkeeping is broken
    # (a Reset under a live patch, or a stats line from a different module copy).
    return "counter_desync"


def named_table(stats):
    """The table a ``shim_hit_named`` verdict points at (largest hN).

    Ties resolve toward the lowest index, which is the order §13/the census recorded the seven
    in, so a repeat shot names the same table from the same counters.  None when no table was
    hit.
    """
    best, best_index = 0, None
    for i in range(7):
        count = stats.get(f"h{i}", 0)
        if count > best:
            best, best_index = count, i
    return None if best_index is None else table_rvas()[best_index]


def install_decision(words):
    """Decode the layout words and say whether a shot may run: (layout, reason)."""
    try:
        return decode_layout(words), None
    except ValueError as exc:
        return None, str(exc)


def poll_done(now, deadline):
    """The shot samples for the whole window; one early sample is not the end."""
    return now >= deadline


def image_end_from_header(reader, exe_base):
    """One past the last byte of the exe image, from its live PE header.

    e_lfanew is at +0x3C and SizeOfImage at NT-header +0x50 (PE32+).  None when either read
    fails: the shot still has a base to record, but no way to say whether a recorded RVA is
    inside the image, so the caller refuses.
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


def _signed32(raw):
    """Re-bias a thread exit code (unsigned 32-bit) to its C int value."""
    return raw - _UINT32_SPAN if raw > _INT32_MAX else raw


def parse_mask(text):
    """``--mask`` as a u64: decimal or ``0x`` hex, refused outside u64 range.

    No mask value is illegal (``mask=0`` means "record every call"), so the only refusals here
    are range errors — a negative or a >64-bit mask would be silently truncated by the remote
    call and the shot would sample under a mask nobody asked for.
    """
    value = int(text, 0)
    if value < 0 or value >= (1 << 64):
        raise argparse.ArgumentTypeError(
            f"mask {text!r} is not representable as a u64")
    return value


def _sha256(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
    except OSError as exc:
        raise SystemExit(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def write_tsv(path, rows, meta=None):
    """Evidence dump: one ``#meta`` line, then one row per retained record.

    Returns the number of data rows written.  The ``#meta`` line is not decoration — it is the
    reason this file is worth keeping when stdout is lost: base, image size, the injected
    DLL's sha256, the mask the shot ran under, ``calls`` and every tier reading the verdict
    was made from.
    """
    try:
        fh = open(path, "w", encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"cannot write {path}: {exc}") from exc
    with fh as f:
        pairs = " ".join(
            f"{key}={value}" for key, value in (meta or {}).items())
        f.write(f"#meta {pairs}\n")
        f.write("kind\tvalid\tmatched\ttable_index\ttable_rva\t"
                "self_vtable_rva\tcaller_rva\tself_ptr\tctx_ptr\ta3\ta4\n")
        for entry in rows:
            f.write(
                f"entry\t{entry['valid']}\t{entry['matched']}\t"
                f"{'-' if entry['table_index'] is None else entry['table_index']}\t"
                f"{_hex_or_dash(entry['table_rva'])}\t"
                f"0x{entry['self_vtable_rva']:x}\t0x{entry['caller_rva']:x}\t"
                f"0x{entry['self_ptr']:x}\t0x{entry['ctx_ptr']:x}\t"
                f"0x{entry['a3']:x}\t0x{entry['a4']:x}\n"
            )
    return len(rows)


# ---------------------------------------------------------------------------
# Live driver (Windows + game process only; the offline plan never calls any of it)
# ---------------------------------------------------------------------------

def sha_gate(dll_path):
    """Hash the exact file this shot will inject, or refuse before touching a process."""
    if not os.path.isfile(dll_path):
        raise SystemExit(
            f"{dll_path} not found — upload the freshly built DLL first (this "
            "script injects THIS file, so it must be the bytes under test)"
        )
    digest = _sha256(dll_path)
    print(
        f"[shim] dll={dll_path} sha256={digest}\n"
        f"[shim]   compare with `sha256sum zig-out/bin/stellaris_quickjs.dll` — "
        "a whole-file DLL sha changes on every relink and is provenance, not "
        "code identity (docs/offline-tooling.md), so this gate prints and "
        "records rather than asserting a pinned constant"
    )
    return digest


def gate_module(pid, dll_path, needed):
    """Check the export names in the FILE, then inject and clear the live gates."""
    exports = list_exports(dll_path)
    missing = [name for name in needed if name not in exports]
    if missing:
        raise SystemExit(
            f"{dll_path} is missing {missing} — refusing to inject a DLL that "
            "cannot answer this shot's calls (a stale upload would sample "
            "against the wrong target)"
        )

    dll_name = os.path.basename(dll_path)
    print(f"[shim] pid={pid}  dll={dll_path}")
    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    print(f"[shim] {dll_name} base (64-bit): 0x{base:x}")

    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    print("[shim] MZ header at base OK")

    sanity = _signed32(call_remote(pid, base, exports["C2Sanity"]))
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch "
        f"against this module copy"
    )
    assert_game_alive(pid)
    print("[shim] C2Sanity == 42, game alive — dispatch authorized")
    return base, exports


def dispatch_once(pid, base, rva, name, arg=None):
    """Dispatch a single-shot export at most once per session; C int rc back."""
    if name in _dispatched:
        raise RuntimeError(
            f"{name} was already dispatched in this session; one process gets "
            "one install (a second would answer -2 and be read as a verdict)"
        )
    _dispatched.add(name)
    if arg is None:
        return _signed32(call_remote(pid, base, rva))
    return _signed32(call_remote_with_arg(pid, base, rva, arg))


def read_layout_words(pid, base, exports):
    """C4ShimProbeLayout -> the six raw words (validated by install_decision)."""
    buf = remote_alloc(pid, 32)
    call_remote_with_arg(pid, base, exports["C4ShimProbeLayout"], buf)
    return struct.unpack("<6I", read_memory(pid, buf, LAYOUT_WORDS * 4))


def reset_probe(pid, base, exports):
    """C4ShimProbeReset before install: it clears counters/ring/mask, NOT a hook."""
    call_remote(pid, base, exports["C4ShimProbeReset"])
    assert_game_alive(pid)


def set_mask(pid, base, exports, mask):
    """C4ShimProbeSetMask — the mask rides in as the thread parameter (a u64 slot)."""
    rc = _signed32(call_remote_with_arg(
        pid, base, exports["C4ShimProbeSetMask"], mask))
    assert rc == 0, f"C4ShimProbeSetMask returned {rc}; it has no illegal-value tier"
    assert_game_alive(pid)


def install_probe(pid, base, exports):
    """The one install of this process; -2 = already installed / predicate armed."""
    rc = dispatch_once(pid, base, exports["C4ShimProbeInstall"],
                       "C4ShimProbeInstall")
    assert_game_alive(pid)
    return rc


def read_stats(pid, base, exports, buf):
    """Dispatch C4ShimProbeStatsInto and decode the NUL-terminated text."""
    call_remote_with_arg(pid, base, exports["C4ShimProbeStatsInto"], buf)
    raw = read_memory(pid, buf, STATS_SIZE)
    text = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
    return decode_stats(text), text


def drain_entries(pid, base, exports, buf):
    """C4ShimProbeDrainInto -> oldest-first decoded record list."""
    count = call_remote_with_arg(
        pid, base, exports["C4ShimProbeDrainInto"], buf) & 0xFFFF_FFFF
    count = min(count, RING_LEN)
    if count == 0:
        return []
    blob = read_memory(pid, buf, count * ENTRY_SIZE)
    return [
        decode_entry(blob[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE])
        for i in range(count)
    ]


def _tier_readings(stats):
    """The per-tier counters, seven tables in the module's own h0..h6 order."""
    return "/".join(
        [f"h{i}={stats.get(f'h{i}', 0)}" for i in range(7)]
        + [f"unmatched={stats.get('unmatched', 0)}",
           f"invalid_self={stats.get('invalid_self', 0)}"]
    )


def partition_unmatched(entries, image_size):
    """Split the ring's unmatched records by where their self_vtable_rva landed.

    A witness-side refinement only: the per-call ``unmatched`` counter never carried an RVA,
    so it cannot be partitioned — this reads the ring records.  Buckets mirror the three
    sources sharing one counter:

    * ``rva_zero`` — ``toRva`` refused the pointer (outside the module's 64 MiB window), so
      "out of the image" and "in the image but not one of the seven" collapse together;
    * ``in_image`` — a real RVA below the live ``SizeOfImage``;
    * ``at_or_above_image`` — an RVA at/above the real ``SizeOfImage`` but still inside the
      64 MiB ``img_end`` window.

    Records with ``matched != 0`` are table hits, not unmatched rows, and are excluded.
    """
    rva_zero = in_image = at_or_above = 0
    rows = 0
    for entry in entries:
        if entry.get("matched", 0) != 0:
            continue
        rows += 1
        rva = entry["self_vtable_rva"]
        if rva == 0:
            rva_zero += 1
        elif rva < image_size:
            in_image += 1
        else:
            at_or_above += 1
    return {"unmatched_rows": rows, "rva_zero": rva_zero,
            "in_image": in_image, "at_or_above_image": at_or_above}


def build_meta(*, exe_base, image_end, dll_path, dll_sha, mask, poll_s, layout,
               stats, stats_text, entries, verdict, table, install_rc,
               partitions=None, entries_error=None):
    """Assemble the ``#meta`` dict written to the artifact's first line.

    Pure (no handles, no ctypes) so it is testable off-machine: ``run()`` builds the
    meta-only artifact with ``partitions=None``/``entries_error=None`` before draining, then
    the full one after.  The four span numbers and ``entries_error`` are appended only when
    the caller passes them, so the pre-drain line never carries half-known partition data.
    """
    meta = {
        "exe_base": f"0x{exe_base:x}",
        "image_size": f"0x{image_end - exe_base:x}",
        "image_end": f"0x{image_end:x}",
        "dll": os.path.basename(dll_path),
        "dll_sha256": dll_sha,
        "target_rva": f"0x{TARGET_RVA:x}",
        "mask": f"0x{mask:x}",
        "poll_s": poll_s,
        "layout": (
            f"entry={layout['entry']} stats={layout['stats']} "
            f"ring={layout['ring']} mask={layout['mask']} "
            f"version={layout['version']}"
        ),
        "calls": stats.get("calls", 0),
        "samples": stats.get("samples", 0),
        "entries": len(entries),
        "tiers": _tier_readings(stats),
        "verdict": verdict,
        "named_table": _hex_or_dash(table),
        "install_rc": install_rc,
        "stats": stats_text.strip(),
    }
    if partitions is not None:
        meta["unmatched_rows"] = partitions["unmatched_rows"]
        meta["rva_zero"] = partitions["rva_zero"]
        meta["in_image"] = partitions["in_image"]
        meta["at_or_above_image"] = partitions["at_or_above_image"]
    if entries_error is not None:
        meta["entries_error"] = entries_error
    return meta


def _cleanup(pid, base, exports, installed_ok, settle_s):
    """uninstall -> verify -> settle -> host alive. Never FreeLibrary."""
    uninstall_rc = None
    try:
        uninstall_rc = _signed32(
            call_remote(pid, base, exports["C4ShimProbeUninstall"]))
    except Exception as exc:  # noqa: BLE001 - cleanup reports, it does not raise
        print(f"[shim] C4ShimProbeUninstall raised: {exc}")

    verify_rc = None
    try:
        verify_rc = _signed32(call_remote(pid, base, exports["C4ShimProbeVerify"]))
    except Exception as exc:  # noqa: BLE001
        print(f"[shim] C4ShimProbeVerify raised: {exc}")

    restore_ok = True
    if uninstall_rc == -7:
        print(
            "RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY — C4ShimProbeUninstall rc=-7"
            " (the engine bytes did not come back); treat this process as "
            "untrusted and leave the DLL mapped"
        )
        restore_ok = False
    elif uninstall_rc not in (0, None):
        print(f"[shim] WARNING: C4ShimProbeUninstall rc={uninstall_rc}")
        restore_ok = False
    else:
        print(f"[shim] C4ShimProbeUninstall rc={uninstall_rc}")

    # -3 = this process never resolved the target (install never ran here), so the engine
    # bytes were never touched and an uninstalled run stays consistent.  Any OTHER non-zero
    # verify escalates regardless of installed_ok: a -6 (PatchTooWide) armed the patch and
    # then refused it, so the bytes may still be modified even though no install completed.
    if verify_rc not in (0, -3):
        print(
            f"RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY — verify={verify_rc} "
            f"(installed_ok={installed_ok}); a non-zero verify outside -3 can "
            "mean the engine bytes are not back even when this run never "
            "completed an install."
        )
        restore_ok = False
    else:
        print(f"[shim] verify={verify_rc}")

    time.sleep(settle_s)
    try:
        assert_game_alive(pid)
        print("[shim] host alive")
    except Exception as exc:  # noqa: BLE001
        print(f"[shim] HOST DEAD: {exc}")
        return False
    return restore_ok


def run(pid, exe_base, dll_path, dll_sha, mask, poll_s, settle_s, out_path):
    base = None
    exports = None
    installed_ok = False
    rc = 1

    def reader(addr, size):
        try:
            return read_memory(pid, addr, size)
        except Exception:  # noqa: BLE001 - an unreadable address is the datum
            return None

    image_end = image_end_from_header(reader, exe_base)
    if image_end is None:
        print(
            f"IMAGE_UNAVAILABLE: SizeOfImage could not be read at 0x{exe_base:x} "
            "— refusing before install. Without an image bound the #meta line "
            "cannot say which span the recorded RVAs live in."
        )
        return 1

    try:
        base, exports = gate_module(pid, dll_path, NEEDED_EXPORTS)
        print(f"[shim] exe_base=0x{exe_base:x} image_end=0x{image_end:x} "
              f"target_rva=0x{TARGET_RVA:x}")

        layout, reason = install_decision(read_layout_words(pid, base, exports))
        if layout is None:
            print(f"LAYOUT_DRIFT: {reason} — refusing to install")
            return 1

        print(
            f"[shim] LAYOUT entry={layout['entry']} stats={layout['stats']} "
            f"ring={layout['ring']} mask={layout['mask']} "
            f"version={layout['version']}"
        )
        reset_probe(pid, base, exports)
        set_mask(pid, base, exports, mask)

        rc_install = install_probe(pid, base, exports)
        installed_ok = rc_install == 0
        print(f"[shim] C4ShimProbeInstall rc={rc_install}")
        if not installed_ok:
            print(
                f"VERDICT: detour_unavailable rc={rc_install} — "
                + ("-2/-4 mean this process is already spoken for; -2 具体是本 guard "
                   "已装过或 predicate 还 armed（后者会把我们自己的 vtable 造成假 "
                   "tier 2，所以模块直接拒装）。take a FRESH game process, this shot "
                   "does not retry"
                   if rc_install in (-2, -4, -5) else
                   "read the export's code table in exports.zig")
            )
            return 1

        stats_buf = remote_alloc(pid, STATS_SIZE)
        deadline = time.monotonic() + poll_s
        last_progress = time.monotonic()
        last_good = None               # (stats, stats_text) of the last clean read
        while True:
            try:
                last_good = read_stats(pid, base, exports, stats_buf)
            except ValueError as exc:
                # A torn line must not abort the run (§56: the artifact exists to survive a
                # lost stdout). Keep polling on the last good reading.
                print(
                    f"[shim] WARNING: stats read torn ({exc}); "
                    + ("keeping the last good reading" if last_good
                       else "no good reading yet, will keep polling")
                )
            now = time.monotonic()
            if poll_done(now, deadline):
                break
            if last_good is not None and now - last_progress >= PROGRESS_EVERY_S:
                cur = last_good[0]
                print(
                    f"[shim] waiting: calls={cur.get('calls', 0)} "
                    f"samples={cur.get('samples', 0)} "
                    f"unmatched={cur.get('unmatched', 0)} "
                    f"invalid_self={cur.get('invalid_self', 0)}"
                )
                last_progress = now
            time.sleep(POLL_INTERVAL_S)

        if last_good is None:
            # Never got a complete stats line: the artifact still gets written, stamped with
            # the instrumentation tier that means "this run's bookkeeping produced nothing
            # readable" — never a code answer.
            partitions = partition_unmatched([], image_end - exe_base)
            meta = build_meta(
                exe_base=exe_base, image_end=image_end, dll_path=dll_path,
                dll_sha=dll_sha, mask=mask, poll_s=poll_s, layout=layout,
                stats={}, stats_text="", entries=[], verdict="counter_desync",
                table=None, install_rc=rc_install, partitions=partitions)
            write_tsv(out_path, [], meta)
            print(
                f"[shim] no readable stats line all run — wrote a meta-only "
                f"artifact to {out_path} stamped verdict=counter_desync "
                "(the bookkeeping tier: no stats line was ever complete, so no "
                "code tier may fire)"
            )
            return 1

        stats, stats_text = last_good
        verdict = verdict_for(stats)
        table = named_table(stats)

        # Write the artifact BEFORE draining so a torn drain cannot erase the evidence (§56).
        entries_error = None
        meta = build_meta(
            exe_base=exe_base, image_end=image_end, dll_path=dll_path,
            dll_sha=dll_sha, mask=mask, poll_s=poll_s, layout=layout,
            stats=stats, stats_text=stats_text, entries=[], verdict=verdict,
            table=table, install_rc=rc_install)
        write_tsv(out_path, [], meta)

        entries = []
        try:
            entries = drain_entries(
                pid, base, exports, remote_alloc(pid, RING_LEN * ENTRY_SIZE))
        except (ValueError, TypeError) as exc:
            entries_error = str(exc)
            print(f"[shim] WARNING: drain failed ({exc}); "
                  "recording entries_error and keeping entries empty")

        partitions = partition_unmatched(entries, image_end - exe_base)
        meta = build_meta(
            exe_base=exe_base, image_end=image_end, dll_path=dll_path,
            dll_sha=dll_sha, mask=mask, poll_s=poll_s, layout=layout,
            stats=stats, stats_text=stats_text, entries=entries, verdict=verdict,
            table=table, install_rc=rc_install, partitions=partitions,
            entries_error=entries_error)
        rows = write_tsv(out_path, entries, meta)
        print(f"[shim] wrote {rows} rows to {out_path}")
        print(
            "[shim] unmatched 分区(证人侧,计数侧不可分):"
            f"unmatched_rows={partitions['unmatched_rows']} "
            f"rva_zero={partitions['rva_zero']} "
            f"in_image={partitions['in_image']} "
            f"at_or_above_image={partitions['at_or_above_image']}"
            + ("  — mask!=0 时这是 SAMPLE" if mask else "")
        )
        if entries_error is not None:
            print(f"[shim] entries_error={entries_error} — ring not decoded")
        print(f"STATS: {stats_text.strip()}")
        print(f"VERDICT: {verdict}"
              + (f" 表首={_hex_or_dash(table)}" if table else ""))
        if verdict == "no_calls_inconclusive":
            print(
                "[shim] ENVIRONMENT result: a silent out-of-family shim has several "
                "readings this probe cannot separate — 那次执行没发生 / 发生在本窗口之外 / "
                "2026-09-29 那份 2,090 的计数不再描述当前场景。它只说明本仪器没问出执行"
                "在发生,不是对任何一族的否定结论。"
            )
        if mask and entries:
            print(
                f"[shim] mask=0x{mask:x}: the {len(entries)} ring records are a "
                "SAMPLE — take ratios from the tiers= counters, never from these."
            )
        if not mask and stats.get("samples", 0) >= RING_LEN:
            print(
                f"[shim] the ring wrapped at {RING_LEN} records: everything is "
                "still counted, but before naming a masked shot run the "
                f"{FREQ_WINDOW_S:.0f} s ``calls``-delta window (``--poll-s 20``)."
            )
        rc = 0 if verdict in EVIDENCE_VERDICTS else 1
    finally:
        if base is None:
            print("[shim] nothing was injected — no cleanup to run")
            restore_ok = True
        else:
            restore_ok = _cleanup(pid, base, exports, installed_ok, settle_s)
    if not restore_ok:
        return 1
    return rc


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only witness of an out-of-family exec shim "
                    "(0xCC4220, §13/§71). LIVE shot — requires per-session "
                    "naming; the offline plan does not run it."
    )
    parser.add_argument("dll", nargs="?", default=DEFAULT_DLL)
    parser.add_argument("--mask", type=parse_mask, default=DEFAULT_MASK,
                        help="u64 sampling mask; 0 (default) records every call")
    parser.add_argument("--poll-s", dest="poll_s", type=float,
                        default=POLL_TIMEOUT_S)
    parser.add_argument("--settle-s", dest="settle_s", type=float,
                        default=SETTLE_S)
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    # Gate order, pinned in the docstring: the two process lookups come first, then the sha
    # 门 on the file, then injection inside gate_module.
    pid = resolve_pid("stellaris")
    exe_base = resolve_base_address(pid, EXE_MODULE)
    dll_sha = sha_gate(args.dll)
    return run(pid, exe_base, args.dll, dll_sha, args.mask, args.poll_s,
               args.settle_s, args.out)


if __name__ == "__main__":
    sys.exit(main())
