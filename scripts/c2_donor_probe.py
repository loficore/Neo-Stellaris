#!/usr/bin/env python3
"""C4 forensics: read-only probe of the donor-family Execute override (0x3AFD30).

WHAT IT READS.  One bounded shot in one game process.  The DLL detours the
CEffect-family Execute override at RVA 0x3AFD30 — the ``[vptr+0x08]`` slot shared
by the five family vtables of §57.2 观测 4 — and for every call records only
``[self+0]`` (the vtable pointer), joined against those five RVAs, plus the
return address and the four argument registers as VALUES.  Nothing is written
into engine memory except the install-time JMP and its restore; nothing under
``ctx``/``a3``/``a4`` is ever dereferenced inside the game (a stale pointer may
only make one ReadProcessMemory return None, it must never fault the host).
This is NOT the base Execute 0x1D08520: §57 观测 6 established that not one of
this family's five tables ever enters through the base-Execute sampling face,
which is why this probe exists and what it replaces there.

USAGE.  ``python3 scripts/c2_donor_probe.py [dll] [--mask 0] [--poll-s 120]
[--settle-s 2] [--out C:/temp/c4_donor_probe.tsv]``

AUTHORIZATION.  This is a LIVE shot (一枪): it injects into the running game and
therefore needs an explicit per-session naming from the user — the authorization
table in ``docs/roadmap.md`` — and THIS PLAN DOES NOT RUN IT.  Nothing in the
offline plan executes this file; it is written and statically verified only.
No process is spawned, no injection, no ``CreateRemoteThread``, no scp.

GATE ORDER (pinned, do not reorder).  ``resolve_pid → resolve_base_address →
sha 门 → gate_module(NEEDED_EXPORTS) → Layout → Reset → SetMask → Install →
轮询 Stats → Drain → write_tsv → finally: Uninstall → Verify → settle →
assert_game_alive``.  Each arrow is a real dependency, not style:

* ``resolve_base_address`` runs before injection and resolves ``stellaris.exe``,
  because the shot's provenance (base + image size) is what makes every recorded
  RVA readable afterwards.
* the sha 门 hashes the file it is about to inject.  A whole-file DLL sha is NOT
  a code identity (docs/offline-tooling.md measured that every relink changes it
  while ``.text`` stays byte-identical), so this gate is a provenance print plus
  a refusal to inject an unreadable file — not an equality assert against a
  pinned constant, which would block every legitimate shot after a rebuild.
* ``gate_module`` checks ``NEEDED_EXPORTS`` with ``list_exports`` from the FILE
  BEFORE injecting: a missing export means yesterday's DLL, and finding that out
  after LoadLibrary would leave an unloadable copy in the process forever.
* ``Layout → Reset → SetMask → Install`` is loadable-order: ``Reset`` clears
  counters, the ring and the mask but deliberately does NOT uninstall the hook,
  so it must run before ``Install`` (a mid-shot clear would silently restart the
  sampling denominator).  ``SetMask`` runs before ``Install`` so the first call
  is already sampled under the intended mask.

CLEANUP.  The ``finally`` block runs uninstall → verify → settle →
assert_game_alive.  **绝不 ``FreeLibrary``** — the detour's trampoline lives in
this module's mapping, so unloading it with the patch restored is fine but
unloading it at any other moment turns a restore problem into a crash; we never
take that risk for a diagnostic tool.  If uninstall reports ``-7`` (or verify
comes back non-zero after we installed), the driver prints
``RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY``: treat that process as untrusted and
do not unload.

``-2`` IS NOT RETRIED.  One process gets one install: ``-2`` means this process
already installed the donor probe once, or the predicate detour is still armed
(``PatchActive``).  ``[self+0]`` under an armed predicate detour points at OUR
DLL-owned vtable, so its readings could never join the five tables and would be
mislabelled ``unmatched`` — the module refuses that state outright.  The only
lever is a fresh game process.

FREQUENCY DISCIPLINE (§57.4: 不要照搬 base Execute 的 1/512).  Default
``--mask 0`` records EVERY call into the ring (256 slots, ring-buffered).  Before
any named shot with a mask, run a 20-second window and read the ``calls`` delta
to get this family's real call frequency, and only then decide whether a
sampling denominator is needed at all.  三档判据的主读数是 ``table_hits`` /
``unmatched``,ring 只是证人 — the five ``hN`` counters and ``unmatched`` are
per-call and counted BEFORE the sampling gate, so the tier verdict never needs a
denominator.  Whoever reads only the ring to compute a ratio is reading a
witness as if it were the measurement.

VERIFY CODES (the module's signed convention, passed through unchanged — the
export does not re-map them): ``0`` consistent; ``-1`` the hook is gone while the
module still believes it is installed; ``-2`` engine bytes do not match the
fingerprint while we are NOT installed; ``-3`` the target was never resolved in
this process (so no install ever happened here).

ARTIFACT.  The TSV's first line is ``#meta`` and carries base, image size, the
injected DLL's sha256, the mask, ``calls``, and the per-tier readings behind the
verdict — because the artifact is what survives a lost stdout (the §56 shot lost
its entire stdout to an ssh reset and the numbers the verdict depended on were
gone with it).

Verdict domain (see ``VERDICTS``; it has NO third tier on purpose):
``no_calls_inconclusive`` is an ENVIRONMENT result — a silent window in a live
campaign only ever means "unobserved" and must never be read as "这一族不执行".
``donor_family_hit_named`` / ``donor_family_hit_unknown_table`` are the two code
answers; ``instrument_broken`` / ``counter_desync`` say the probe itself, or the
shot's bookkeeping, was not sound.
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
    open_process_handle, close_handle,
)

DEFAULT_DLL = r"C:\temp\sqjs_c4.dll"
DEFAULT_OUT = r"C:/temp/c4_donor_probe.tsv"
DEFAULT_MASK = 0
EXE_MODULE = "stellaris.exe"

TARGET_RVA = 0x3AFD30          # offset.keyword_reg.RVA_EFFECT_DONOR_EXECUTE
ENTRY_SIZE = 48                # bytes of one ring record (layoutInto word 0)
STATS_SIZE = 512               # the fixed stats buffer the exports write into
LAYOUT_WORDS = 6               # mask is a u64: two words, NOT scope_probe's 5
RING_LEN = 256
LAYOUT_VERSION = 1
STATS_KEYS = ("calls", "samples", "invalid_self", "unmatched",
              "h0", "h1", "h2", "h3", "h4", "patch_size", "installed", "mask")

POLL_INTERVAL_S = 1.0
POLL_TIMEOUT_S = 120.0
SETTLE_S = 2.0
PROGRESS_EVERY_S = 10.0
FREQ_WINDOW_S = 20.0           # the §57.4 frequency window, see docstring

E_LFANEW_OFFSET = 0x3C
SIZE_OF_IMAGE_OFFSET = 0x50

_INT32_MAX = 0x7FFFFFFF
_UINT32_SPAN = 1 << 32

#: Single authority for the verdict value domain. ``verdict_for`` may only return
#: a member of this tuple, and ``scripts/test_c2_donor_probe.py`` pins the whole
#: domain — including the absence of a "这一族不执行" tier, which this instrument
#: can never establish (tier (c) of §57.4 needs the sentinel-body wait plus a
#: proven absence, and a live campaign never proves an absence).
VERDICTS = (
    "no_calls_inconclusive",
    "donor_family_hit_named",
    "donor_family_hit_unknown_table",
    "instrument_broken",
    "counter_desync",
)

#: The two verdicts that answer a question about engine code (exit 0). The rest
#: are environment / instrumentation readings and must not be reported as a
#: negative about the family.
EVIDENCE_VERDICTS = ("donor_family_hit_named", "donor_family_hit_unknown_table")

#: Names the driver requires in the DLL file BEFORE it injects it.
NEEDED_EXPORTS = (
    "C2Sanity",
    "C4DonorProbeInstall",
    "C4DonorProbeSetMask",
    "C4DonorProbeUninstall",
    "C4DonorProbeVerify",
    "C4DonorProbeLayout",
    "C4DonorProbeStatsInto",
    "C4DonorProbeDrainInto",
    "C4DonorProbeReset",
)

_dispatched = set()


# ---------------------------------------------------------------------------
# Pure decode / judgement layer (imported by test_c2_donor_probe.py; no
# ctypes, no handles — the offline tests run on the Linux host, zero shots)
# ---------------------------------------------------------------------------

def table_rvas():
    """The five donor-family vtables the module joins ``[self+0]`` against.

    Written as a function, not a module-level dict, to stay inside ruling P10
    (the layout fence's R-rva rule polices hard-coded ``RVAS`` dicts).  These are
    the same five RVAs as ``FAMILY_VTABLES`` in ``src/dll/c2/donor_exec_probe.zig``
    and as §57.2 观测 4 in the 取证卷; ``test_c2_donor_probe.py`` pins this list
    against both authorities, so this copy cannot drift silently.  Index 2 is
    ``0x25F4440`` — the table §57.4 actually observed — and a named verdict is
    spelled out of this list, never out of the driver's memory.
    """
    return [0x24B1D98, 0x24EAAC0, 0x25F4440, 0x2606F00, 0x2606FE0]


def decode_layout(words):
    """Validate the DLL's six layout words; any drift is a ValueError.

    ``[48, 56, 256, mask_lo, mask_hi, 1]`` — the mask is a u64 and takes TWO
    words, so a driver that copied c2_scope_probe's five-word read would silently
    answer ``mask=512`` for a mask of ``1<<32``.  An unknown version word is
    refused rather than guessed at: the only safe reading of a layout the driver
    does not know is "do not install against it".
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
    if out["stats"] != 56:
        raise ValueError(f"Stats size drifted: {out['stats']} != 56")
    if out["ring"] != RING_LEN:
        raise ValueError(f"ring length drifted: {out['ring']} != {RING_LEN}")
    if out["version"] != LAYOUT_VERSION:
        raise ValueError(
            f"unknown layout version {out['version']} != {LAYOUT_VERSION}")
    return out


def decode_entry(raw):
    """Decode one 48-byte ring record; a short buffer is a ValueError.

    ``matched`` is the module's ``1 + table index`` (0 = "not one of the five"),
    so ``table_index``/``table_rva`` are None for an unmatched record and also
    for a ``matched`` outside 1..5 — that would be layout drift, and dressing it
    up as a table hit is the one reading this must not produce.
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
    """Parse the DLL's one-line stats readout into its twelve keys.

    ``mask`` is rendered in hex by the module (``mask={x}``) while every other
    key is decimal, so the base is per-key, not per-line.  The key set must match
    ``STATS_KEYS`` exactly: the module's ``statsInto`` always writes all twelve in
    a fixed order, so a missing key (a torn line), a duplicate, or an unknown key
    (a different module build) means this is not a readable stats line — and a
    half-written line must not silently become a verdict.
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
    """§57.4's three-tier reading, minus the tier this instrument cannot reach.

    The ladder reads the per-call counters only, never the ring, because the
    counters are the measurement and the ring is the witness.  Order matters:
    a silent window is answered first (calls == 0 is ENVIRONMENT), then the
    all-``invalid_self`` shape (the probe cannot read ``[self+0]``, so it can
    speak about nothing), then the two code tiers, then the arithmetic residue.
    """
    calls = stats.get("calls", 0)
    if calls == 0:
        return "no_calls_inconclusive"
    invalid = stats.get("invalid_self", 0)
    unmatched = stats.get("unmatched", 0)
    hits = [stats.get("h%d" % i, 0) for i in range(5)]
    if invalid >= calls and not any(hits) and unmatched == 0:
        return "instrument_broken"
    if any(hits):
        return "donor_family_hit_named"
    if unmatched > 0:
        return "donor_family_hit_unknown_table"
    # calls > 0 but no counter accounts for any of it: the shot's own bookkeeping
    # is broken (a Reset under a live patch, or a stats line from a different
    # module copy). It says nothing about the family.
    return "counter_desync"


def _named_table(stats):
    """The table a ``donor_family_hit_named`` verdict points at (largest hN).

    Ties are resolved toward the lowest index, which is the order §57.2 recorded
    the five tables in, so a repeat shot names the same table from the same
    counters. None when no table was hit.
    """
    hits = [(stats.get("h%d" % i, 0), i) for i in range(5)]
    best, best_index = 0, None
    for count, index in hits:
        if count > best:
            best, best_index = count, index
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

    e_lfanew is at +0x3C and SizeOfImage at NT-header +0x50 (PE32+).  None when
    either read fails: the shot still has a base to record, but no way to say
    whether a recorded RVA is inside the image, so the caller refuses.
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

    No mask value is illegal (``mask=0`` means "record every call"), so the only
    refusals here are range errors — a negative or a >64-bit mask would be
    silently truncated by the remote call and the shot would sample under a mask
    nobody asked for.
    """
    value = int(text, 0)
    if value < 0 or value >= (1 << 64):
        raise argparse.ArgumentTypeError(
            f"mask {text!r} is not representable as a u64")
    return value


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_tsv(path, rows, meta=None):
    """Evidence dump: one ``#meta`` line, then one row per retained record.

    Returns the number of data rows written.  The ``#meta`` line is not
    decoration — it is the reason this file is worth keeping when stdout is
    lost: base, image size, the injected DLL's sha256, the mask the shot ran
    under, ``calls`` and every tier reading the verdict was made from.
    """
    with open(path, "w", encoding="utf-8") as f:
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
# Live driver (Windows + game process only; this plan never calls any of it)
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
        f"[donor] dll={dll_path} sha256={digest}\n"
        f"[donor]   compare with `sha256sum zig-out/bin/stellaris_quickjs.dll` — "
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
    print(f"[donor] pid={pid}  dll={dll_path}")
    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    print(f"[donor] {dll_name} base (64-bit): 0x{base:x}")

    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    print("[donor] MZ header at base OK")

    sanity = _signed32(call_remote(pid, base, exports["C2Sanity"]))
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch "
        f"against this module copy"
    )
    assert_game_alive(pid)
    print("[donor] C2Sanity == 42, game alive — dispatch authorized")
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
    """C4DonorProbeLayout -> the six raw words (validated by install_decision)."""
    buf = remote_alloc(pid, 32)
    call_remote_with_arg(pid, base, exports["C4DonorProbeLayout"], buf)
    return struct.unpack("<6I", read_memory(pid, buf, LAYOUT_WORDS * 4))


def reset_probe(pid, base, exports):
    """C4DonorProbeReset before install: it clears counters/ring/mask, NOT a hook."""
    call_remote(pid, base, exports["C4DonorProbeReset"])
    assert_game_alive(pid)


def set_mask(pid, base, exports, mask):
    """C4DonorProbeSetMask — the mask rides in as the thread parameter (a u64 slot)."""
    rc = _signed32(call_remote_with_arg(
        pid, base, exports["C4DonorProbeSetMask"], mask))
    assert rc == 0, f"C4DonorProbeSetMask returned {rc}; it has no illegal-value tier"
    assert_game_alive(pid)


def install_probe(pid, base, exports):
    """The one install of this process; -2 = already installed / predicate armed."""
    rc = dispatch_once(pid, base, exports["C4DonorProbeInstall"],
                       "C4DonorProbeInstall")
    assert_game_alive(pid)
    return rc


def read_stats(pid, base, exports, buf):
    """Dispatch C4DonorProbeStatsInto and decode the NUL-terminated text."""
    call_remote_with_arg(pid, base, exports["C4DonorProbeStatsInto"], buf)
    raw = read_memory(pid, buf, STATS_SIZE)
    text = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
    return decode_stats(text), text


def drain_entries(pid, base, exports, buf):
    """C4DonorProbeDrainInto -> oldest-first decoded record list."""
    count = call_remote_with_arg(
        pid, base, exports["C4DonorProbeDrainInto"], buf) & 0xFFFF_FFFF
    count = min(count, RING_LEN)
    if count == 0:
        return []
    blob = read_memory(pid, buf, count * ENTRY_SIZE)
    return [
        decode_entry(blob[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE])
        for i in range(count)
    ]


def _tier_readings(stats):
    """The per-tier counters, in the order §57.4 lists them."""
    return "/".join(
        [f"h{i}={stats.get('h%d' % i, 0)}" for i in range(5)]
        + [f"unmatched={stats.get('unmatched', 0)}",
           f"invalid_self={stats.get('invalid_self', 0)}"]
    )


def _cleanup(pid, base, exports, installed_ok, settle_s):
    """uninstall -> verify -> settle -> host alive. Never FreeLibrary."""
    uninstall_rc = None
    try:
        uninstall_rc = _signed32(
            call_remote(pid, base, exports["C4DonorProbeUninstall"]))
    except Exception as exc:  # noqa: BLE001 - cleanup reports, it does not raise
        print(f"[donor] C4DonorProbeUninstall raised: {exc}")

    verify_rc = None
    try:
        verify_rc = _signed32(call_remote(pid, base, exports["C4DonorProbeVerify"]))
    except Exception as exc:  # noqa: BLE001
        print(f"[donor] C4DonorProbeVerify raised: {exc}")

    restore_ok = True
    if uninstall_rc == -7:
        print(
            "RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY — C4DonorProbeUninstall rc=-7"
            " (the engine bytes did not come back); treat this process as "
            "untrusted and leave the DLL mapped"
        )
        restore_ok = False
    elif uninstall_rc not in (0, None):
        print(f"[donor] WARNING: C4DonorProbeUninstall rc={uninstall_rc}")
        restore_ok = False
    else:
        print(f"[donor] C4DonorProbeUninstall rc={uninstall_rc}")

    # -3 = the target was never resolved here (install never ran), so an
    # uninstalled run is consistent; -1/-2 after we installed are not.
    if installed_ok and verify_rc != 0:
        print(
            f"RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY — verify={verify_rc} after "
            "this run installed the detour (see the docstring's three non-zero "
            "meanings)"
        )
        restore_ok = False
    else:
        print(f"[donor] verify={verify_rc}")

    time.sleep(settle_s)
    try:
        assert_game_alive(pid)
        print("[donor] host alive")
    except Exception as exc:  # noqa: BLE001
        print(f"[donor] HOST DEAD: {exc}")
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
        print(f"[donor] exe_base=0x{exe_base:x} image_end=0x{image_end:x} "
              f"target_rva=0x{TARGET_RVA:x}")

        layout, reason = install_decision(read_layout_words(pid, base, exports))
        if layout is None:
            print(f"LAYOUT_DRIFT: {reason} — refusing to install")
            return 1

        print(
            f"[donor] LAYOUT entry={layout['entry']} stats={layout['stats']} "
            f"ring={layout['ring']} mask={layout['mask']} "
            f"version={layout['version']}"
        )
        reset_probe(pid, base, exports)
        set_mask(pid, base, exports, mask)

        rc_install = install_probe(pid, base, exports)
        installed_ok = rc_install == 0
        print(f"[donor] C4DonorProbeInstall rc={rc_install}")
        if not installed_ok:
            print(
                f"VERDICT: detour_unavailable rc={rc_install} — "
                + ("-2/-4 mean this process is already spoken for; take a FRESH "
                   "game process, this shot does not retry"
                   if rc_install in (-2, -4) else
                   "read the export's code table in exports.zig")
            )
            return 1

        stats_buf = remote_alloc(pid, STATS_SIZE)
        deadline = time.monotonic() + poll_s
        last_progress = time.monotonic()
        while True:
            stats, stats_text = read_stats(pid, base, exports, stats_buf)
            if poll_done(time.monotonic(), deadline):
                break
            if time.monotonic() - last_progress >= PROGRESS_EVERY_S:
                print(
                    f"[donor] waiting: calls={stats.get('calls', 0)} "
                    f"samples={stats.get('samples', 0)} "
                    f"unmatched={stats.get('unmatched', 0)} "
                    f"invalid_self={stats.get('invalid_self', 0)}"
                )
                last_progress = time.monotonic()
            time.sleep(POLL_INTERVAL_S)

        entries = drain_entries(
            pid, base, exports, remote_alloc(pid, RING_LEN * ENTRY_SIZE))
        verdict = verdict_for(stats)
        table = _named_table(stats)
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
            "install_rc": rc_install,
            "stats": stats_text.strip(),
        }
        rows = write_tsv(out_path, entries, meta)
        print(f"[donor] wrote {rows} rows to {out_path}")
        print(f"STATS: {stats_text.strip()}")
        print(f"VERDICT: {verdict}"
              + (f" 表首={_hex_or_dash(table)}" if table else ""))
        if verdict == "no_calls_inconclusive":
            print(
                "[donor] ENVIRONMENT result: a silent window is not evidence "
                "that this family does not execute (§57.4 has no third tier for "
                "this instrument). Load a running campaign, unpause, fresh "
                "process, rerun."
            )
        if mask and entries:
            print(
                f"[donor] mask=0x{mask:x}: the {len(entries)} ring records are a "
                "SAMPLE — take ratios from the tiers= counters, never from these "
                "(ring and counters are different sources under a mask)."
            )
        if not mask and stats.get("samples", 0) >= RING_LEN:
            print(
                f"[donor] the ring wrapped at {RING_LEN} records: everything is "
                "still counted, but before naming a masked shot run the "
                f"{FREQ_WINDOW_S:.0f} s ``calls``-delta window in the docstring "
                "(§57.4: do NOT copy base Execute's 1/512 denominator)."
            )
        rc = 0 if verdict in EVIDENCE_VERDICTS else 1
    finally:
        if base is None:
            print("[donor] nothing was injected — no cleanup to run")
            restore_ok = True
        else:
            restore_ok = _cleanup(pid, base, exports, installed_ok, settle_s)
    if not restore_ok:
        return 1
    return rc


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only donor-family Execute probe (0x3AFD30, §57.4). "
                    "LIVE shot — requires per-session naming; the offline plan "
                    "does not run it."
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

    # Gate order, pinned in the docstring: the two process lookups come first,
    # then the sha 门 on the file, then injection inside gate_module.
    pid = resolve_pid("stellaris")
    exe_base = resolve_base_address(pid, EXE_MODULE)
    dll_sha = sha_gate(args.dll)
    return run(pid, exe_base, args.dll, dll_sha, args.mask, args.poll_s,
               args.settle_s, args.out)


if __name__ == "__main__":
    sys.exit(main())
