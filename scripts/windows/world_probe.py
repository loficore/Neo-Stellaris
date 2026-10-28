"""world_probe — one reading of the live Stellaris window, in the R4 shape.

The world-state machine (``scripts/world_state.py``) is pure: it decides what a
reading *means*.  This module is the other half: it goes and **takes** the
reading, using the pixel classifiers that already exist in
``game_supervisor.py`` — ``read_pause`` / ``read_console`` / ``read_window`` /
``classify_window``.  The thresholds are **not** re-implemented here and
**not** changed (spec §10: 「不实现探针的阈值改动：阈值沿用既有常量」); the probe
only gathers what those classifiers saw.

Two properties are load-bearing:

* **raw counts, not just verdicts.**  Every count that produced a verdict
  (``red_px`` / ``green_px`` / ``bright_px`` / ``gold_px`` / ``row_count`` /
  ``option_count`` / ``bbox``) travels with the evidence, so a later
  calibration run can re-grade a verdict against a different threshold
  without re-measuring (spec §10).
* **import has no side effects** (spec §3: 「导入零副作用」).  Nothing is
  created, truncated or captured at import time.  The live modules
  (``game_supervisor``, ``world_state``) are imported **inside** the
  functions that need them, so importing the probe never drags a Windows-only
  dependency in and never touches a file.

The reading's shape is the one the whole plan agrees on (R4)::

    {"pause":   {"state": "playing"|"paused"|"unknown", "red_px": int, "green_px": int},
     "console": {"state": "open"|"closed"|"undecided", "bright_px": int},
     "window":  {"kind": "none"|"choice"|"dialog", "gold_px": int, "row_count": int,
                 "option_count": int, "bbox": list|None},
     "raw": {...}, "pid": int, "hwnd": int}

``build_evidence`` produces the three sections and the raw counts; ``probe``
adds the world identity (``pid`` / ``hwnd``) that the state machine needs to
tell one game process from another.

This module does **not** decide anything, does not persist anything and does
not talk to the state file — that is ``world_state``'s job, and the CLI
(``ns_world.py``) is the only thing allowed to drive both.
"""

# ``world_state`` lives one directory up in the repo and beside this
# module on the wire (C:\\temp), so a bare import is not resolvable by a
# static checker; it IS resolvable at run time on both sides.
# pyright: reportMissingImports=false
from __future__ import annotations

import hashlib
import subprocess
import time

#: The classifier vocabularies spec §5 works with.  A reading outside its
#: vocabulary is an **unreadable** reading, and the state machine puts those
#: on the blocking side — the probe never "fixes" one into a healthy verdict.
PAUSE_STATES = ("playing", "paused", "unknown")
CONSOLE_STATES = ("open", "closed", "undecided")
WINDOW_KINDS = ("none", "choice", "dialog")

#: Where the game's process identity comes from.  spec §7 names the CIM
#: creation date: ``process_identity = (pid, process_start_time)``.  The query
#: is asked once per pid and cached, because the lock's generation check
#: compares the recorded token against a freshly obtained one — a fresh
#: *value*, not a fresh *query*.
_IDENTITY_CACHE: dict[int, str | None] = {}


def build_evidence(pause_state: str, red_px: int, green_px: int,
                   console_state: str, bright_px: int, window_kind: str,
                   gold_px: int, row_count: int, option_count: int,
                   bbox: list | None) -> dict:
    """Assemble one reading's evidence from the counts the classifiers saw.

    Pure: it moves numbers into the R4 shape and decides nothing.  The three
    verdicts go into their own sections; the seven raw counts go into
    ``raw`` **and** into the section that measured them, so a consumer that
    only looks at one of the two still sees the numbers.

    A count that was not measured is **absent**, not zero (the state machine
    draws the same line: 「证据里的 0 必须是测到的 0」).
    """
    return {
        "pause": {"state": pause_state, "red_px": red_px, "green_px": green_px},
        "console": {"state": console_state, "bright_px": bright_px},
        "window": {"kind": window_kind, "gold_px": gold_px,
                   "row_count": row_count, "option_count": option_count,
                   "bbox": bbox},
        "raw": {"red_px": red_px, "green_px": green_px, "bright_px": bright_px,
                "gold_px": gold_px, "row_count": row_count,
                "option_count": option_count, "bbox": bbox},
    }


def crop_sha256(png_bytes: bytes) -> str:
    """The sha256 of a crop's bytes — how a label names *that* crop.

    A label of a frame has to point at the exact pixels it was given, so the
    hash is over the bytes themselves: same bytes ⇒ same hash, one changed
    byte ⇒ a different hash.
    """
    return hashlib.sha256(png_bytes).hexdigest()


def console_state_of(seen) -> str:
    """The console verdict in the state machine's vocabulary.

    ``classify_console`` answers ``True`` (open) / ``False`` (closed) /
    ``None`` (undecided).  The state machine speaks "open" / "closed" /
    "undecided", and the three are one-to-one.

    "undecided" must survive as its own word: it is the reading that lands on
    the **blocking** side (spec §5: 「`unknown` 一律落阻塞侧」), and folding it
    into "closed" would let the daemon act on a panel it cannot see.
    """
    if seen is True:
        return "open"
    if seen is False:
        return "closed"
    return "undecided"


def option_count_from_rows(rows) -> int:
    """How many option rows the classifier saw — the N of spec §5.

    The row thresholds are **reused**, not copied: the same
    ``CHOICE_ROW_LEFT_MIN`` / ``CHOICE_ROW_RIGHT_MIN`` that decide
    ``classify_window`` decide which rows count as options.  Two notions of
    "an option row" would drift, and the drift would only show up as a
    ``WINDOW_EVENT`` whose N is not the N the classifier used.

    ``rows`` is the **normalised** geometry (``_norm_geometry``'s output) —
    the same rows ``classify_window`` is given.
    """
    from game_supervisor import CHOICE_ROW_LEFT_MIN, CHOICE_ROW_RIGHT_MIN
    return sum(1 for row in rows
               if row.get("x0", 0) >= CHOICE_ROW_LEFT_MIN
               and row.get("x1", 0) >= CHOICE_ROW_RIGHT_MIN)


def probe(hwnd: int, pid: int) -> dict:
    """Take one reading of the live window; return it in the R4 shape.

    The three classifiers are called exactly as ``serve`` calls them, and the
    window geometry is normalised the same way, so the probe's verdicts are
    the daemon's verdicts — not a second opinion from a second set of rules.

    The reading carries the world identity (``pid`` / ``hwnd``): the state
    machine's budget is keyed by process identity, and its lease fingerprint
    is pinned to the window instance (a restarted game is a different world).
    """
    import game_supervisor as gs

    pause_state, red_px, green_px = gs.read_pause(hwnd)
    # read_console answers exactly classify_console(bright_px); the verdict is
    # re-derived from the count so the probe's console word comes from the
    # same classifier the daemon uses.
    seen, bright_px = gs.read_console(hwnd)
    console_state = console_state_of(gs.classify_console(bright_px))
    stats = gs.read_window(hwnd)
    rect = gs.window_rect(hwnd)
    rows, bbox, gold = gs._norm_geometry(stats["rows"], stats["bbox"],
                                         stats["gold"], rect)
    window_kind = gs.classify_window(rows, bbox, gold)
    option_count = option_count_from_rows(rows)

    evidence = build_evidence(
        pause_state=pause_state, red_px=red_px, green_px=green_px,
        console_state=console_state, bright_px=bright_px,
        window_kind=window_kind, gold_px=int(gold),
        row_count=len(rows), option_count=option_count, bbox=bbox)
    evidence["pid"] = int(pid)
    evidence["hwnd"] = int(hwnd)
    return evidence


def process_identity(pid: int) -> tuple[int, str]:
    """The game's process identity: ``(pid, CIM CreationDate)``.

    spec §7 names the source: the **CIM** creation date, taken from the same
    query shape the rest of the toolchain uses.  ``wmic`` is gone from recent
    Windows builds, so the query is ``Get-CimInstance Win32_Process``; the
    answer is the creation date rendered as a string, which is stable for the
    life of the process and different for a pid that was recycled.

    Windows-only: the query needs a CIM provider.  On a host without one the
    answer is ``(pid, "")`` — an empty token, which the lock's generation
    check reads as "no generation" (liveness only), never as a false match.
    """
    creation = _query_creation_date(pid)
    return int(pid), creation or ""


def start_time_provider(pid: int) -> str | None:
    """The process-start-time token for ``pid`` — the provider ``world_state`` wants.

    spec §11-4's 「代际不符即抢占」 needs a token that is the same for one
    process and different for a recycled pid.  The CIM creation date is
    exactly that, and it is cached: the lock compares the **recorded** token
    against a **freshly obtained** one, so the value has to be current — but
    a CIM query per comparison would cost more than the lock itself.
    """
    if pid in _IDENTITY_CACHE:
        return _IDENTITY_CACHE[pid]
    token = _query_creation_date(pid)
    _IDENTITY_CACHE[pid] = token
    return token


def _query_creation_date(pid: int) -> str | None:
    """Ask CIM when this process started; ``None`` when it cannot be asked."""
    command = (
        f"Get-CimInstance Win32_Process -Filter \"ProcessId={int(pid)}\" | "
        "ForEach-Object { $_.CreationDate.ToString('o') }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                             capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    value = (out.stdout or "").strip()
    return value or None


def gate_install(guard: str, *, state_path: str | None = None,
                 now: float | None = None) -> str:
    """Refuse the install unless the premise holds; return the lease id.

    This is the shape the shot drivers call: it either returns a lease id or it
    **stops the shot**.  The refusal is a ``SystemExit`` (exit code 2), so the
    driver never reaches ``inject_dll`` — the whole point of the gate (spec §1:
    「今天的失败模式就是『注入了再发现前提不成立』」).

    The reason is printed with the reading it was made on, so the operator sees
    what the machine saw, not only what it was told.

    (This function was written for the drivers, then lost in a revert that also
    removed unrelated lint churn; the fence did not notice because it only
    checked that a gate *call* preceded the injection, never that the name
    resolved.  R-gate-symbol now checks that.)
    """
    ok, reason = assert_install_ready(guard, state_path=state_path, now=now)
    if not ok:
        # Both halves matter: the message an operator reads, and the code a
        # script branches on.  ``SystemExit(str)`` would print the message but
        # exit 1, while the documented contract (and the CLI's) is 2 = refused.
        print(f"REFUSED: {reason}", file=sys.stderr)
        raise SystemExit(2)
    return reason


def assert_install_ready(guard: str, *, state_path: str | None = None,
                         now: float | None = None) -> tuple[bool, str]:
    """May this guard be installed right now?  ``(ok, reason_or_lease_id)``.

    The live half of the gate: find the game, take a reading, and ask the
    pure state machine whether an ``install`` is allowed.  A refusal carries
    the reason **and** the reading it was made on, so the driver can print
    what it saw instead of only what it was told.

    The lease the gate issues is persisted inside the lock, because
    ``Store.save`` refuses to write without it.  The caller (the driver)
    injects the DLL only when this returns ``True``.

    This is the Windows-side wrapper the injection drivers call; the pure
    decision lives in ``world_state.assert_ready`` and is the same function
    the CLI's ``assert-ready`` subcommand runs.
    """
    import game_supervisor as gs
    import world_state as ws

    pid, hwnd = gs.find_game()
    if not pid or not hwnd:
        return False, ("no game window: cannot prove the premise, so the "
                       "install is refused (fail closed)")
    try:
        reading = probe(hwnd, pid)
    except OSError as exc:
        return False, f"the probe could not read the window: {exc!r}"

    stamp = time.time() if now is None else now
    store = ws.Store.load(state_path) if state_path else ws.Store.load()
    with store.locked():
        ok, reason = ws.assert_ready(store, "install", guard=guard,
                                      probe_evidence=reading, now=stamp)
        if ok:
            store.save()
    if not ok:
        return False, (f"{reason} | reading: pause={reading['pause']['state']} "
                       f"console={reading['console']['state']} "
                       f"window={reading['window']['kind']} "
                       f"hwnd={reading['hwnd']} pid={reading['pid']}")
    return True, reason
