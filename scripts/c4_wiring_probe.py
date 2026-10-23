"""C4 chokepoint wiring driver (Windows side).

One process, one shot: inject the C4 DLL, install the predicate detour, run a
`capture` pass to find which context offset carries the system id, then run an
`apply` pass that maps that id through the 787-score table in QuickJS and
chains the donor Execute for tier >= 1 (70 systems).

The capture pass is read-only. The only engine writes in the whole run are the
engine's own donor Execute effects (`log` / `set_name`). The driver never
unloads the DLL: patched effect objects hold pointers into it, so the final
cleanup is `C4WireDisarm` (restore the engine bytes, drop the JS arm) and the
module stays loaded for the rest of the process lifetime.

Every failure names a verdict and is written to the JSON file. Exit 0 only
when the verdict is `ok` and cleanup succeeded (host alive, disarm not -6).
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import time

import c2_harness as harness


RECORD_SIZE = 3368
RING_CAP = 2048
CTX_LEN = 944
A3_LEN = 256
PTR_SLOTS = 8
PTR_LEN = 256
SCORE_COUNT = 787
EXPECTED_TIERS = (717, 55, 15)
EXPECTED_CHAIN = 70
MARKER = "NEO_CHOKE_EFFECT"
# The game's log sink drops a message it has already printed this session, so
# markers carry [This.GetName]. On the pinned campaign every_system visits 787
# systems but only 783 distinct rendered names reach game.log (a few low-score
# systems share a rendered name); see §54.
PREFLIGHT_MARKERS = 783
SAVE_SHA = "6f271294bcfe3620a5e7da367a7f3fb0891c77315baffa28601ca48ec5d8d94e"

DLL = r"C:\temp\sqjs_c4.dll"
SAVE = r"C:\temp\stellaris_2226.sav"
GAME_LOG = "~/Documents/Paradox Interactive/Stellaris/logs/game.log"
SUPERVISOR_STATUS = r"C:\temp\ns_game_status.json"
SUPERVISOR_CMD = r"C:\temp\ns_game_cmd.txt"
SHOT = r"C:\temp\ns_game_shot.png"
JSON = r"C:\temp\c4_wiring_result.json"

WIRE_KEYS = ["mode", "records", "dropped", "calls", "resolved", "unresolved",
             "tier0", "tier1", "tier2", "js_err", "chain", "last_id", "last_tier",
             "armed_token", "spec_blob", "spec_deref", "spec_off_a", "spec_off_b",
             "reserved0", "reserved1"]
SCORED_KEYS = ["armed", "token", "budget_left", "scored_calls", "skipped", "busy",
               "js_err", "invalid", "tier0", "tier1", "tier2", "last_id",
               "last_tier"]

CTX_OFF = 56
A3_OFF = CTX_OFF + CTX_LEN
TARGETS_OFF = A3_OFF + A3_LEN
WINDOWS_OFF = TARGETS_OFF + 8 * PTR_SLOTS

PTR_MIN = 0x10000
PTR_MAX = 0x00007FFF_FFFF_0000

REQUIRED_EXPORTS = (
    "C2Sanity", "C2Init", "C1Run", "C1EffectId",
    "C4WireInstall", "C4WireSetMode", "C4WireSetSpec", "C4WireStatsInto",
    "C4WireDrainInto", "C4WireLayout", "C4WireDisarm", "C4ScoredStatsInto",
)

CAPTURE_CONSOLE = ('effect every_system = { neo_action = { '
                   'log = "NEO_CHOKE_EFFECT_[This.GetName]" '
                   'set_name = "NEO_CHOKE" } }')


def preflight_console(pid):
    return ('effect every_system = { log = "C4_PREFLIGHT_%d_[This.GetName]" }'
            % pid)


# ---------------------------------------------------------------------------
# Pure decoders (Linux-testable)
# ---------------------------------------------------------------------------

def decode_records(data):
    if len(data) % RECORD_SIZE != 0:
        raise ValueError(
            f"record blob {len(data)} B is not a multiple of {RECORD_SIZE}")
    out = []
    for base in range(0, len(data), RECORD_SIZE):
        valid, token, serial, _ = struct.unpack_from("<IIII", data, base)
        ctx_ptr, a3_ptr, self_ptr = struct.unpack_from("<QQQ", data, base + 16)
        a3_len, ptr_count, ctx_len, _ = struct.unpack_from("<IIII", data, base + 40)
        ctx_len = min(ctx_len, CTX_LEN)
        a3_len = min(a3_len, A3_LEN)
        ptr_count = min(ptr_count, PTR_SLOTS)
        ctx = data[base + CTX_OFF:base + CTX_OFF + ctx_len]
        a3 = data[base + A3_OFF:base + A3_OFF + a3_len]
        if ptr_count:
            targets = list(struct.unpack_from(
                "<%dQ" % ptr_count, data, base + TARGETS_OFF))
        else:
            targets = []
        windows = [
            data[base + WINDOWS_OFF + PTR_LEN * j:
                 base + WINDOWS_OFF + PTR_LEN * (j + 1)]
            for j in range(ptr_count)
        ]
        out.append({
            "valid": valid, "token": token, "serial": serial,
            "ctx_ptr": ctx_ptr, "a3_ptr": a3_ptr, "self_ptr": self_ptr,
            "a3_len": a3_len, "ptr_count": ptr_count, "ctx_len": ctx_len,
            "ctx": ctx, "a3": a3,
            "ptr_targets": targets, "ptr_windows": windows,
        })
    return out


def decode_wire_stats(data):
    if len(data) != 80:
        raise ValueError(f"wire stats must be exactly 80 B, got {len(data)}")
    return dict(zip(WIRE_KEYS, struct.unpack("<20I", data)))


def decode_scored_stats(text):
    out = {}
    for token in text.split():
        key, sep, raw = token.partition("=")
        if not sep or not key or not raw:
            raise ValueError(f"malformed scored token {token!r}")
        if key in out:
            raise ValueError(f"duplicate scored key {key!r}")
        out[key] = int(raw)
    missing = sorted(set(SCORED_KEYS) - set(out))
    unknown = sorted(set(out) - set(SCORED_KEYS))
    if missing or unknown:
        raise ValueError(
            f"scored stats keys: missing={missing} unknown={unknown}")
    return {key: out[key] for key in SCORED_KEYS}


def _check_offsets(blob, deref, off_a, off_b):
    if blob not in (0, 1):
        raise ValueError("blob must be 0 or 1")
    if deref not in (0, 1):
        raise ValueError("deref must be 0 or 1")
    for name, value in (("off_a", off_a), ("off_b", off_b)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
        if value & 3:
            raise ValueError(f"{name} must be 4-byte aligned")
    blob_len = CTX_LEN if blob == 0 else A3_LEN
    if deref == 0:
        if off_b != 0:
            raise ValueError("direct read requires off_b == 0")
        if off_a + 4 > blob_len:
            raise ValueError("off_a runs past the blob")
    else:
        if off_a + 8 > blob_len:
            raise ValueError("off_a (pointer) runs past the blob")
        if off_b + 4 > PTR_LEN:
            raise ValueError("off_b runs past the pointer window")


def pack_spec(blob, deref, off_a, off_b):
    if not isinstance(blob, int) or not isinstance(deref, int):
        raise ValueError("blob/deref must be integers")
    _check_offsets(blob, deref, off_a, off_b)
    return blob | (deref << 8) | (off_a << 16) | (off_b << 32)


def unpack_spec(packed):
    if not isinstance(packed, int) or isinstance(packed, bool) or packed < 0:
        raise ValueError("packed spec must be a non-negative integer")
    if packed >> 48:
        raise ValueError("reserved spec bits must be zero")
    blob = packed & 0xFF
    deref = (packed >> 8) & 0xFF
    off_a = (packed >> 16) & 0xFFFF
    off_b = (packed >> 32) & 0xFFFF
    _check_offsets(blob, deref, off_a, off_b)
    return {"blob": blob, "deref": deref, "off_a": off_a, "off_b": off_b}


def _plausible(value):
    return PTR_MIN <= value < PTR_MAX and (value & 7) == 0


def _scan_record(rec):
    """Re-run the DLL's pointer scan over the captured bytes."""
    out = []
    seen = set()
    for blob_idx, key in ((0, "ctx"), (1, "a3")):
        blob = rec[key]
        for off in range(0, len(blob) - 7, 8):
            ptr = struct.unpack_from("<Q", blob, off)[0]
            if not _plausible(ptr) or ptr in seen:
                continue
            seen.add(ptr)
            out.append((blob_idx, off, ptr))
    return out


def _locate_targets(rec):
    """Map each recorded pointer target back to the qword that produced it.

    ``ptr_targets`` is authoritative: the DLL caps the list at PTR_SLOTS
    distinct values and drops any whose 256-byte window read failed, so a
    re-scan of the blob can legitimately hold more plausible qwords than
    were recorded. What must hold is that the recorded values appear, in
    order, among the scanned first occurrences (ctx before a3).
    """
    scan = _scan_record(rec)
    located = []
    cursor = 0
    for ptr in rec["ptr_targets"]:
        while cursor < len(scan) and scan[cursor][2] != ptr:
            cursor += 1
        if cursor == len(scan):
            raise ValueError(
                "pointer targets drifted from the captured bytes "
                f"(serial {rec['serial']})")
        located.append(scan[cursor])
        cursor += 1
    return located


def _columns_with_spec(records):
    scans = []
    for rec in records:
        scan = _locate_targets(rec)
        if len(scan) != len(rec["ptr_windows"]):
            raise ValueError(
                "pointer windows do not line up with the recorded targets "
                f"(serial {rec['serial']})")
        scans.append(scan)

    columns = []
    for blob_idx, key in ((0, "ctx"), (1, "a3")):
        limit = CTX_LEN if blob_idx == 0 else A3_LEN
        blobs = [rec[key] for rec in records]
        for off in range(0, limit - 3, 4):
            if any(len(blob) < off + 4 for blob in blobs):
                continue
            seq = [struct.unpack_from("<I", blob, off)[0] for blob in blobs]
            columns.append((f"{key}+0x{off:x}", seq,
                            {"blob": blob_idx, "deref": 0,
                             "off_a": off, "off_b": 0}))

        common = None
        for scan in scans:
            offs = {off for idx, off, _ in scan if idx == blob_idx}
            common = offs if common is None else common & offs
        for off_a in sorted(common or ()):
            indexes = []
            for scan in scans:
                for j, (idx, off, _) in enumerate(scan):
                    if idx == blob_idx and off == off_a:
                        indexes.append(j)
                        break
                else:
                    indexes = None
                    break
            if indexes is None:
                continue
            for off_b in range(0, PTR_LEN - 3, 4):
                seq = [struct.unpack_from(
                    "<I", rec["ptr_windows"][j], off_b)[0]
                    for rec, j in zip(records, indexes)]
                columns.append(
                    (f"{key}->[+0x{off_a:x}]+0x{off_b:x}", seq,
                     {"blob": blob_idx, "deref": 1,
                      "off_a": off_a, "off_b": off_b}))
    return columns


def column_sequences(records):
    return [(name, seq) for name, seq, _ in _columns_with_spec(records)]


def find_scope_column(records):
    found = {"status": "count_mismatch", "column": None,
             "spec": None, "columns": []}
    if len(records) != SCORE_COUNT:
        return found

    expected = list(range(SCORE_COUNT))
    exact = []
    permutation = None
    for name, seq, spec in _columns_with_spec(records):
        if seq == expected:
            exact.append((name, spec))
        elif permutation is None and sorted(seq) == expected:
            permutation = name

    found["columns"] = [name for name, _ in exact]
    if len(exact) == 1:
        found["status"] = "ok"
        found["column"], found["spec"] = exact[0]
    elif len(exact) > 1:
        found["status"] = "ambiguous_column"
    elif permutation is not None:
        found["status"] = "permutation"
        found["column"] = permutation
    else:
        found["status"] = "none"
    return found


def expected_tiers(scores):
    tier0 = tier1 = tier2 = 0
    for score in scores:
        if score >= 200:
            tier2 += 1
        elif score >= 100:
            tier1 += 1
        else:
            tier0 += 1
    return (tier0, tier1, tier2)


def campaign_gate(save_sha, expected_sha, allow_drift):
    if not save_sha:
        return "campaign_unverified"
    if save_sha.lower() == expected_sha.lower():
        return "ok"
    return "drift_allowed" if allow_drift else "campaign_mismatch"


def preflight_gate(count):
    if count == 0:
        return "console_unavailable"
    if count != PREFLIGHT_MARKERS:
        return "campaign_mismatch"
    return "ok"


def count_marker_lines(text, marker):
    return sum(1 for line in text.splitlines()
               if "Log effect, file:" in line and marker in line)


def supervisor_ready(rec, now, max_age_s=5.0):
    if not isinstance(rec, dict):
        return "supervisor_not_running"
    state = rec.get("state")
    if state in ("no_game", "stopped"):
        return "supervisor_not_running"
    try:
        age = now - float(rec.get("epoch"))
    except (TypeError, ValueError):
        return "supervisor_not_running"
    if age > max_age_s:
        return "supervisor_not_running"
    if state != "paused":
        return "supervisor_not_paused"
    return "ok"


def classify_capture(wire, records, find):
    if wire.get("calls", 0) == 0:
        return "no_calls"
    if not records:
        return "no_readable_ctx"
    if (wire.get("calls") != SCORE_COUNT or wire.get("records") != SCORE_COUNT
            or wire.get("dropped", 0) > 0 or len(records) != SCORE_COUNT):
        return "count_mismatch"
    return {
        "ok": "ok",
        "none": "no_scope_column",
        "permutation": "scope_order_unverified",
        "ambiguous_column": "ambiguous_column",
        "count_mismatch": "count_mismatch",
    }[find["status"]]


def classify_apply(before, after, scored, log_hits):
    if after.get("calls", 0) - before.get("calls", 0) == 0:
        return "apply_no_calls"
    if scored.get("js_err", 0) != 0 or scored.get("invalid", 0) != 0:
        return "scored_js_error"
    if after.get("resolved") != SCORE_COUNT or after.get("unresolved") != 0:
        return "apply_count_mismatch"
    if (after.get("tier0"), after.get("tier1"), after.get("tier2")) != EXPECTED_TIERS:
        return "tier_mismatch"
    if after.get("chain") != EXPECTED_CHAIN:
        return "chain_mismatch"
    if log_hits != EXPECTED_CHAIN:
        return "log_mismatch"
    return "ok"


# ---------------------------------------------------------------------------
# Windows-side helpers
# ---------------------------------------------------------------------------

class _Abort(Exception):
    def __init__(self, verdict, detail=""):
        super().__init__(verdict)
        self.verdict = verdict
        self.detail = detail


def _signed32(value):
    return value - (1 << 32) if value >= (1 << 31) else value


def _sha256_file(path):
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _read_text_from(path, offset):
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read().decode("utf-8", errors="replace")


def _read_status(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _write_text_atomic(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    os.replace(tmp, path)


def _seen_key(path):
    try:
        with open(path, encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return None


def _write_command(path, line):
    _write_text_atomic(path, line + "\n")


def _send_console(cmd_path, text):
    seen = cmd_path + ".seen"
    before = _seen_key(seen)
    _write_command(cmd_path, "console " + text)
    deadline = time.time() + 1.0
    while time.time() < deadline:
        if _seen_key(seen) != before:
            return True
        time.sleep(0.05)
    return False


def _wait_marker(path, offset, marker, expected, timeout):
    """Poll until ``expected`` marker lines appear, else keep the max seen.

    The game log is flushed in chunks, so an intermediate count that stops
    moving for one poll is not the final count; returning early undercounts
    and turns a healthy campaign into ``campaign_mismatch``. None means the
    log itself could not be read.
    """
    deadline = time.time() + timeout
    best = 0
    while time.time() < deadline:
        try:
            text = _read_text_from(path, offset)
        except OSError:
            return None
        best = max(best, count_marker_lines(text, marker))
        if best >= expected:
            return best
        time.sleep(0.5)
    return best


def _wait_paused(status_path, cmd_path, timeout=15.0):
    _write_command(cmd_path, "want paused")
    deadline = time.time() + timeout
    rec = None
    while time.time() < deadline:
        rec = _read_status(status_path)
        if supervisor_ready(rec, time.time()) == "ok":
            return rec, None
        time.sleep(0.5)
    rec = _read_status(status_path)
    return rec, supervisor_ready(rec, time.time())


def _read_wire_stats(pid, base, rva, buf):
    size = _signed32(harness.call_remote_with_arg(pid, base, rva, buf))
    if size != 80:
        raise _Abort("stats_drift", f"C4WireStatsInto returned {size}")
    return decode_wire_stats(harness.read_memory(pid, buf, 80))


def _read_snapshots(pid, base, exports, sbuf, cbuf):
    wire = _read_wire_stats(pid, base, exports["C4WireStatsInto"], sbuf)
    size = _signed32(harness.call_remote_with_arg(
        pid, base, exports["C4ScoredStatsInto"], cbuf))
    if size <= 0:
        raise _Abort("scored_stats_unreadable",
                     f"C4ScoredStatsInto returned {size}")
    text = harness.read_memory(pid, cbuf, size).decode("utf-8", errors="replace")
    try:
        scored = decode_scored_stats(text)
    except ValueError as exc:
        raise _Abort("scored_stats_unreadable", str(exc))
    return wire, scored


def _poll_calls(pid, base, rva, buf, target_delta, before_calls, timeout):
    deadline = time.time() + timeout
    stats = None
    while time.time() < deadline:
        stats = _read_wire_stats(pid, base, rva, buf)
        if stats["calls"] - before_calls >= target_delta:
            return stats, True
        time.sleep(0.5)
    return stats, False


# ---------------------------------------------------------------------------
# Windows flow
# ---------------------------------------------------------------------------

def _flow(args, result, state):
    log_path = os.path.expanduser(args.game_log)

    _, verdict = _wait_paused(args.supervisor_status, args.supervisor_cmd)
    if verdict is not None:
        raise _Abort(verdict, f"supervisor state={_read_status(args.supervisor_status)}")

    result["save_sha"] = _sha256_file(args.save)
    gate = campaign_gate(result["save_sha"], SAVE_SHA, args.allow_drift)
    result["campaign_gate"] = gate
    if gate not in ("ok", "drift_allowed"):
        raise _Abort(gate, f"save sha256 {result['save_sha']}")

    exports = harness.list_exports(args.dll)
    missing = sorted(set(REQUIRED_EXPORTS) - set(exports))
    if missing:
        raise _Abort("dll_exports_missing", ",".join(missing))
    state["exports"] = exports

    try:
        pid = harness.resolve_pid("stellaris")
    except RuntimeError as exc:
        raise _Abort("game_not_running", str(exc))
    state["pid"] = result["pid"] = pid

    module = os.path.basename(args.dll)
    try:
        base = harness.resolve_base_address(pid, module)
    except RuntimeError as exc:
        if "is not loaded" not in str(exc):
            raise _Abort("stale_module", str(exc))
        try:
            harness.inject_dll(pid, args.dll)
            base = harness.resolve_base_address(pid, module)
        except RuntimeError as inject_exc:
            raise _Abort("inject_failed", str(inject_exc))
    else:
        raise _Abort("stale_module", f"{module} already loaded at 0x{base:x}")
    state["base"] = result["base"] = base

    sanity = _signed32(harness.call_remote(pid, base, exports["C2Sanity"]))
    if sanity != 42:
        raise _Abort("sanity_failed", f"C2Sanity={sanity}")
    run_rc = harness.call_remote(pid, base, exports["C1Run"])
    if run_rc == 0:
        raise _Abort("c1_failed", f"C1Run={run_rc}")
    effect_id = harness.call_remote(pid, base, exports["C1EffectId"])
    if effect_id == 0:
        raise _Abort("c1_failed", f"C1EffectId={effect_id}")
    result["effect_id"] = effect_id
    init = _signed32(harness.call_remote(pid, base, exports["C2Init"]))
    if init != 0:
        raise _Abort("quickjs_init_failed", f"C2Init={init}")

    lbuf = harness.remote_alloc(pid, 32)
    layout_rc = _signed32(harness.call_remote_with_arg(
        pid, base, exports["C4WireLayout"], lbuf))
    if layout_rc != 8:
        raise _Abort("layout_drift", f"C4WireLayout returned {layout_rc}")
    layout = list(struct.unpack("<8I", harness.read_memory(pid, lbuf, 32)))
    result["layout"] = layout
    expected_layout = [1, 0, RECORD_SIZE, RING_CAP, CTX_LEN, A3_LEN,
                       PTR_SLOTS, PTR_LEN]
    if layout != expected_layout:
        raise _Abort("layout_drift", f"{layout} != {expected_layout}")

    install_rc = _signed32(harness.call_remote_with_arg(
        pid, base, exports["C4WireInstall"], effect_id))
    result["install_rc"] = install_rc
    if install_rc != 0:
        raise _Abort("install_failed", f"C4WireInstall={install_rc}")

    # Preflight: prove the console path and the campaign shape before capture.
    preflight = f"C4_PREFLIGHT_{pid}"
    offset = _file_size(log_path)
    _send_console(args.supervisor_cmd, preflight_console(pid))
    preflight_count = _wait_marker(
        log_path, offset, preflight, PREFLIGHT_MARKERS, timeout=30.0)
    if preflight_count is None:
        raise _Abort("log_unreadable", log_path)
    result["preflight_marker_count"] = preflight_count
    gate = preflight_gate(preflight_count)
    if gate == "console_unavailable":
        raise _Abort(gate, "preflight marker never appeared")
    if gate == "campaign_mismatch":
        raise _Abort(gate,
                     f"preflight markers {preflight_count} != {PREFLIGHT_MARKERS}")

    # Capture: find the scope column.
    sbuf = harness.remote_alloc(pid, 80)
    _send_console(args.supervisor_cmd, CAPTURE_CONSOLE)
    _, reached = _poll_calls(pid, base, exports["C4WireStatsInto"], sbuf,
                             SCORE_COUNT, 0, timeout=30.0)
    if reached:
        time.sleep(3.0)
    mode_rc = _signed32(harness.call_remote_with_arg(
        pid, base, exports["C4WireSetMode"], 0))
    if mode_rc != 0:
        raise _Abort("mode_failed", f"C4WireSetMode(0)={mode_rc}")
    stats = _read_wire_stats(pid, base, exports["C4WireStatsInto"], sbuf)
    result["capture"]["stats"] = stats
    buf = harness.remote_alloc(pid, RING_CAP * RECORD_SIZE)
    n = harness.call_remote_with_arg(pid, base, exports["C4WireDrainInto"], buf)
    if n > RING_CAP:
        raise _Abort("record_drift", f"drain returned {n} > {RING_CAP}")
    try:
        records = (decode_records(harness.read_memory(pid, buf, n * RECORD_SIZE))
                   if n else [])
    except ValueError as exc:
        raise _Abort("record_drift", str(exc))
    try:
        find = find_scope_column(records)
    except ValueError as exc:
        raise _Abort("scan_drift", str(exc))
    result["capture"]["find"] = find
    verdict = classify_capture(stats, records, find)
    if verdict != "ok":
        raise _Abort(verdict, f"capture stats={stats} find={find}")
    result["spec"] = find["spec"]

    # Apply: tier the 787 systems through QuickJS and chain tier >= 1.
    cbuf = harness.remote_alloc(pid, 1024)
    before_wire, _ = _read_snapshots(
        pid, base, exports, sbuf, cbuf)
    apply_offset = _file_size(log_path)
    packed = pack_spec(**find["spec"])
    spec_rc = _signed32(harness.call_remote_with_arg(
        pid, base, exports["C4WireSetSpec"], packed))
    if spec_rc != 0:
        raise _Abort("apply_setup_failed", f"C4WireSetSpec={spec_rc}")
    mode_rc = _signed32(harness.call_remote_with_arg(
        pid, base, exports["C4WireSetMode"], 2))
    if mode_rc != 0:
        raise _Abort("apply_setup_failed", f"C4WireSetMode(2)={mode_rc}")

    _send_console(args.supervisor_cmd, CAPTURE_CONSOLE)
    _, reached = _poll_calls(pid, base, exports["C4WireStatsInto"], sbuf,
                             SCORE_COUNT, before_wire["calls"], timeout=30.0)
    if reached:
        time.sleep(3.0)
    mode_rc = _signed32(harness.call_remote_with_arg(
        pid, base, exports["C4WireSetMode"], 0))
    if mode_rc != 0:
        raise _Abort("mode_failed", f"C4WireSetMode(0)={mode_rc}")
    after_wire, after_scored = _read_snapshots(
        pid, base, exports, sbuf, cbuf)
    log_hits = _wait_marker(
        log_path, apply_offset, MARKER, EXPECTED_CHAIN, timeout=15.0)
    if log_hits is None:
        raise _Abort("log_unreadable", log_path)
    result["apply"] = {
        "before": before_wire, "after": after_wire,
        "delta": after_wire["calls"] - before_wire["calls"],
        "scored": after_scored, "log_hits": log_hits,
    }
    verdict = classify_apply(before_wire, after_wire, after_scored, log_hits)
    if verdict != "ok":
        raise _Abort(verdict, f"apply={result['apply']}")

    _write_command(args.supervisor_cmd, "shot")
    deadline = time.time() + 5.0
    before_mtime = _file_mtime(args.shot)
    while time.time() < deadline and _file_mtime(args.shot) == before_mtime:
        time.sleep(0.25)
    result["screenshot"]["sha256"] = _shot_sha(args.shot, before_mtime)
    result["verdict"] = "ok"


def _file_mtime(path):
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return None


def _shot_sha(path, before_mtime):
    """Hash the screenshot only if the supervisor actually rewrote it."""
    if _file_mtime(path) == before_mtime:
        return None
    return _sha256_file(path)


def _cleanup(state, result):
    pid, base = state["pid"], state["base"]
    exports = state["exports"]
    if pid and base:
        try:
            harness.call_remote_with_arg(
                pid, base, exports["C4WireSetMode"], 0)
        except Exception:
            pass

        rc = None
        for _ in range(6):
            try:
                rc = _signed32(harness.call_remote(
                    pid, base, exports["C4WireDisarm"]))
            except Exception:
                rc = None
                break
            if rc != -1:
                break
            time.sleep(0.5)
        result["cleanup"]["disarm_rc"] = rc
        if rc == -6:
            print("RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY")

        try:
            harness.assert_game_alive(pid)
            result["cleanup"]["host_alive"] = True
        except RuntimeError:
            result["cleanup"]["host_alive"] = False

    if result["cleanup"]["host_alive"] is False:
        result["verdict"] = "host_dead"
        hint = ("host died; run scripts/c2_selfabort_repro.py and "
                "scripts/dll_ubsan_site.py before anything else")
        result["detail"] = (result["detail"] + "; " + hint) if result["detail"] else hint
    elif result["cleanup"]["disarm_rc"] == -6:
        result["verdict"] = "restore_incomplete"
    elif (result["verdict"] == "ok"
          and result["cleanup"]["disarm_rc"] not in (0, -1)):
        result["verdict"] = "cleanup_incomplete"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _empty_result(args):
    return {
        "verdict": None,
        "detail": "",
        "save_sha": None,
        "dll_sha": _sha256_file(args.dll),
        "pid": 0,
        "base": 0,
        "effect_id": 0,
        "layout": None,
        "install_rc": None,
        "preflight_marker_count": None,
        "capture": {"stats": None, "find": None},
        "spec": None,
        "apply": {"before": None, "after": None, "delta": None,
                  "scored": None, "log_hits": None},
        "screenshot": {"path": args.shot, "sha256": None},
        "cleanup": {"disarm_rc": None, "host_alive": None},
        "campaign_gate": None,
    }


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="C4 chokepoint wiring driver (one shot per game process)")
    parser.add_argument("--dll", default=DLL)
    parser.add_argument("--save", default=SAVE)
    parser.add_argument("--json", default=JSON)
    parser.add_argument("--allow-drift", action="store_true")
    parser.add_argument("--game-log", default=GAME_LOG)
    parser.add_argument("--supervisor-status", default=SUPERVISOR_STATUS)
    parser.add_argument("--supervisor-cmd", default=SUPERVISOR_CMD)
    parser.add_argument("--shot", default=SHOT)
    return parser.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
    result = _empty_result(args)
    state = {"pid": 0, "base": 0, "exports": {}}
    try:
        _flow(args, result, state)
    except _Abort as exc:
        result["verdict"], result["detail"] = exc.verdict, exc.detail
    except Exception as exc:
        result["verdict"], result["detail"] = "probe_error", repr(exc)
    finally:
        _cleanup(state, result)

    try:
        _write_text_atomic(args.json, json.dumps(
            result, ensure_ascii=False, indent=2) + "\n")
    except OSError as exc:
        print(f"json write failed: {exc}")
    print(f"VERDICT: {result['verdict']}")
    cleanup = result["cleanup"]
    success = (result["verdict"] == "ok"
               and cleanup["host_alive"] is True
               and cleanup["disarm_rc"] in (0, -1))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
