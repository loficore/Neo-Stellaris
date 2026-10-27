"""world_state — the pure world-state machine: turn "is the premise still true?"
into data and a code gate.

This module is **pure logic plus a file store**: cross-platform, zero
win32/PIL/numpy imports, zero import-time side effects (no file is created, no
log truncated, no screenshot taken), so it can be unit-tested offline.  It does
**not** collect probe readings (that is ``scripts/windows/world_probe.py``) or
expose a CLI (Task 5).  It answers exactly four questions:

1. which state do the current probe readings mean — ``infer_state(probe)``;
2. may this state move to that state by this action — ``may(from, to, action)``;
3. may this action be attempted at all right now — the attempt budget
   (``record_attempt`` / ``blocked``) and the evidence-gated way out of a
   block (``block`` / ``unblock``);
4. may this action be attempted **at all**, right now, in front of the game —
   the lease layer (``acquire`` / ``consume`` / ``arm`` / ``unarm``) and the
   one gate that combines everything (``assert_ready``).

The state lives in one JSON file beside one lock file (``Store``) because the
Windows side is a one-shot process: nothing that must survive may live in
memory only (spec §3).  The lock covers the read-modify-write of that json and
nothing else — never a screenshot, never a probe (spec §11-4).

Two rules are not negotiable (spec §5):

* ``unknown`` / ``undecided`` / ``None`` always land on the **blocking** side;
  they are never read as ``playing`` / ``closed`` / ``none`` — an unreadable
  classifier is not evidence of a healthy game;
* the evidence always carries the **raw counts** (``red_px`` / ``green_px`` /
  ``bright_px`` / ``gold_px`` / ``row_count`` / ``option_count`` / ``bbox``),
  not only the verdict — a verdict cannot be re-graded into a threshold later
  (spec §10).

One host fact is not in this module: how to read a **process's start time**
on Windows.  Spec §7 names the source — the CIM creation date — and spec
§11-4 makes the start time the *generation* half of the lock's owner
identity (the same pid can come back as a different process).  This module
must stay pure (no win32 imports, cross-platform, offline-testable), so it
cannot ask Windows itself.  Instead it exposes a **provider seam**:
``set_process_start_time_provider(fn)`` installs a callable that answers
"when did this pid start?", and ``_process_start_time`` consults it before
falling back to the Linux ``/proc`` parse.  With no provider installed,
Windows degrades to **liveness-only** — a recycled pid is not detected by
generation, and a stale lock has to be cleared by hand (loud, not silent).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import time
import uuid
from collections.abc import Callable, Iterator
from typing import Any

#: The 11 states of spec §5, in the order the spec lists them.
STATES: tuple[str, ...] = (
    "NO_GAME",
    "LAUNCHING",
    "IN_GAME_RUNNING",
    "IN_GAME_PAUSED_CLEAN",
    "NEEDS_UNPAUSE",
    "CONSOLE_OPEN",
    "WINDOW_EVENT",
    "WINDOW_UNSTABLE",
    "GUARD_ARMED",
    "RESTORE_INCOMPLETE",
    "BLOCKED_WITH_EVIDENCE",
)

#: The five world-changing actions (spec §7: only these are counted against the
#: attempt budget; ``status`` / ``probe`` / ``assert-ready`` / ``lease`` never are).
ACTIONS: tuple[str, ...] = (
    "click_option",
    "unpause",
    "console_close",
    "install",
    "uninstall",
)

#: The attempt budget of each world-changing action (spec §7, exact values).
#: ``status`` / ``probe`` / ``assert-ready`` / ``lease`` are deliberately absent:
#: they never change the world, so counting them would let the agent's own
#: polling loop block itself (spec §11-6).
MAX_ATTEMPTS: dict[str, int] = {
    "click_option": 2,
    "unpause": 3,
    "console_close": 3,
    "install": 1,
    "uninstall": 3,
}

#: The sliding window of the **global** (cross-process) attempt counter, in
#: seconds (spec §7: 另一份 (action, window) 的全局计数，10 分钟滑动窗).  It is
#: what outlives a relaunch — a new pid must not buy a fresh budget (§11-3).
GLOBAL_WINDOW_S = 600

#: How long a lease is valid, in seconds (spec §6: ``"ttl_s": 30``).  A lease
#: is the permission to change the world once: it is issued against one
#: reading of the world and it dies 30 seconds later whether it was used or
#: not.  The constant, not the stored ``ttl_s``, is what expiry is computed
#: from — a hand-edited state file must not be able to renew a lease.
LEASE_TTL_S = 30

#: Reserved marker for a transition that **none** of the five actions causes.
#: It covers three different flavours, and none of them is commandable by an
#: action, so the action slot accepts this marker only — ``may(f, t, "install")``
#: must not be able to talk the machine into a transition an install cannot
#: cause:
#:
#: * a state change the probe observed (most of the edges);
#: * a state change only a signed-evidence ``unblock`` may cause — the two edges
#:   out of ``BLOCKED_WITH_EVIDENCE``, and only a nonce-carrying evidence file
#:   may take them (``unblock`` is not one of the five actions);
#: * a guard's uninstall that did not verify — ``GUARD_ARMED →
#:   RESTORE_INCOMPLETE`` — which is a failure observed, not a successful
#:   ``uninstall`` (so ``may(GUARD_ARMED, RESTORE_INCOMPLETE, "uninstall")`` is
#:   ``False``).
NO_ACTION = "probe"

#: spec §5's transition table, copied row by row (10 rows → 21 edges).  Each row
#: is ``(from, to, action)`` where ``action`` is the action that causes that
#: transition, or ``NO_ACTION`` for the transitions that no action causes.
#: Everything off this table is refused (spec §5: 「表外一律拒绝」).
TRANSITIONS: tuple[tuple[str, str, str], ...] = (
    ("NO_GAME", "LAUNCHING", NO_ACTION),
    ("LAUNCHING", "IN_GAME_RUNNING", NO_ACTION),
    ("LAUNCHING", "IN_GAME_PAUSED_CLEAN", NO_ACTION),
    ("LAUNCHING", "WINDOW_EVENT", NO_ACTION),
    ("LAUNCHING", "BLOCKED_WITH_EVIDENCE", NO_ACTION),
    ("IN_GAME_RUNNING", "GUARD_ARMED", "install"),
    ("IN_GAME_RUNNING", "IN_GAME_PAUSED_CLEAN", NO_ACTION),
    ("IN_GAME_RUNNING", "CONSOLE_OPEN", NO_ACTION),
    ("IN_GAME_RUNNING", "WINDOW_EVENT", NO_ACTION),
    ("IN_GAME_PAUSED_CLEAN", "IN_GAME_RUNNING", "unpause"),
    ("IN_GAME_PAUSED_CLEAN", "WINDOW_EVENT", NO_ACTION),
    ("IN_GAME_PAUSED_CLEAN", "CONSOLE_OPEN", NO_ACTION),
    ("CONSOLE_OPEN", "IN_GAME_PAUSED_CLEAN", "console_close"),
    ("WINDOW_EVENT", "IN_GAME_RUNNING", "click_option"),
    ("WINDOW_EVENT", "WINDOW_UNSTABLE", NO_ACTION),
    ("WINDOW_UNSTABLE", "BLOCKED_WITH_EVIDENCE", NO_ACTION),
    ("GUARD_ARMED", "IN_GAME_RUNNING", "uninstall"),
    ("GUARD_ARMED", "RESTORE_INCOMPLETE", NO_ACTION),
    ("RESTORE_INCOMPLETE", "BLOCKED_WITH_EVIDENCE", NO_ACTION),
    ("BLOCKED_WITH_EVIDENCE", "IN_GAME_RUNNING", NO_ACTION),
    ("BLOCKED_WITH_EVIDENCE", "IN_GAME_PAUSED_CLEAN", NO_ACTION),
)

_ALLOWED = frozenset(TRANSITIONS)

#: The classifier vocabularies of spec §5.  A reading outside its vocabulary is
#: an unreadable reading (``unknown``), never a healthy one.
_PAUSE_STATES = ("playing", "paused")
_CONSOLE_STATES = ("open", "closed")
_WINDOW_KINDS = ("none", "choice", "dialog")
#: The window kinds that mean "a window is up" (a choice or a dialog).
_WINDOW_PRESENT = ("choice", "dialog")


def may(from_state: str, to_state: str, action: str) -> bool:
    """Is the transition ``from_state → to_state`` allowed, driven by ``action``?

    The table is spec §5's, exactly: a triple off the table is refused — an
    unknown state name, an unknown action name, and a ``(from, to)`` pair the
    spec does not list are all ``False``.  Transitions no action causes accept
    ``NO_ACTION`` only (see ``TRANSITIONS``).
    """
    if from_state not in STATES or to_state not in STATES:
        return False
    if action != NO_ACTION and action not in ACTIONS:
        return False
    return (from_state, to_state, action) in _ALLOWED


def legal_actions(state: str) -> tuple[str, ...]:
    """The world-changing actions the transition table allows from ``state``.

    Read off the table, not off a second list that could drift from it: an
    action is legal here when some edge leaves ``state`` **and** that edge
    names the action.  The probe-driven edges (``NO_ACTION``) contribute
    nothing — which is the point: the table says what a *command* may do,
    and the state changes a probe observes are not commands.

    Unknown states answer with an empty tuple, not an exception: the table
    is consulted for "what may I do here", and "nowhere" is a complete
    answer.
    """
    out: list[str] = []
    for from_state, _to_state, action in TRANSITIONS:
        if from_state == state and action in ACTIONS and action not in out:
            out.append(action)
    return tuple(out)


def infer_state(probe: dict) -> tuple[str, dict]:
    """Infer the current state from probe readings; return ``(state, evidence)``.

    ``probe`` has exactly one shape in this repo — the one the Windows-side
    probe builds::

        {"pause":   {"state": "playing"|"paused"|"unknown", "red_px": int, "green_px": int},
         "console": {"state": "open"|"closed"|"undecided", "bright_px": int},
         "window":  {"kind": "none"|"choice"|"dialog", "gold_px": int, "row_count": int,
                     "option_count": int, "bbox": list|None},
         "raw": {...}, "pid": int, "hwnd": int}

    Three further keys are **optional** and filled in by the caller (absent means
    ``False`` / ``None``):

    * ``probe["blocked"]`` — the store says this ``(state, action)`` is blocked;
    * ``probe["restore_incomplete"]`` — a guard's uninstall did not verify
      (spec §5's ``RESTORE_INCOMPLETE``);
    * ``probe["prev_option_count"]`` — the option count N of the previous tick,
      which is what separates ``WINDOW_EVENT`` from ``WINDOW_UNSTABLE``.

    The ``pause`` / ``console`` / ``window`` sections are mandatory: a missing
    section is a programming error and raises ``ValueError``.  Keys inside a
    section may be missing (``bbox`` absent means ``None``).

    The judgements run in spec §5's priority order — ``RESTORE_INCOMPLETE`` >
    ``BLOCKED_WITH_EVIDENCE`` > ``WINDOW_UNSTABLE`` > ``WINDOW_EVENT`` >
    ``CONSOLE_OPEN`` > ``NEEDS_UNPAUSE`` > ``IN_GAME_PAUSED_CLEAN`` >
    ``IN_GAME_RUNNING`` — and an unreadable reading lands on the blocking side
    (``BLOCKED_WITH_EVIDENCE``) instead of being read as a healthy one.

    ``NO_GAME`` and ``LAUNCHING`` are not inferred here: they turn on facts about
    the process and the launcher handoff, which this probe shape does not carry.
    """
    if not isinstance(probe, dict):
        raise ValueError("probe must be a dict")
    for section in ("pause", "console", "window"):
        if not isinstance(probe.get(section), dict):
            raise ValueError(f"probe is missing the {section} section "
                             "(pause/console/window are mandatory)")
    pause = probe["pause"]
    console = probe["console"]
    window = probe["window"]

    pause_state = pause.get("state")
    console_state = console.get("state")
    window_kind = window.get("kind")
    option_count = window.get("option_count")
    prev_option_count = probe.get("prev_option_count")

    untrusted = [name for name, reading, vocabulary in (
        ("pause", pause_state, _PAUSE_STATES),
        ("console", console_state, _CONSOLE_STATES),
        ("window", window_kind, _WINDOW_KINDS),
    ) if reading not in vocabulary]

    window_up = window_kind in _WINDOW_PRESENT
    # WINDOW_EVENT needs "the same option count N on two consecutive ticks".  A
    # window we cannot prove stable is WINDOW_UNSTABLE — the blocking side —
    # because clicking is what changes the world.
    n_stable = (window_up
                and isinstance(option_count, int)
                and isinstance(prev_option_count, int)
                and option_count == prev_option_count)

    if probe.get("restore_incomplete"):
        state = "RESTORE_INCOMPLETE"
        reason = "caller reports a guard uninstall that did not verify"
    elif probe.get("blocked"):
        state = "BLOCKED_WITH_EVIDENCE"
        reason = "caller reports this (state, action) as blocked"
    elif untrusted:
        state = "BLOCKED_WITH_EVIDENCE"
        reason = "unreadable classifier reading: " + "/".join(untrusted)
    elif window_up and not n_stable:
        state = "WINDOW_UNSTABLE"
        reason = "a window is up but N is not proven stable across two ticks"
    elif window_up:
        state = "WINDOW_EVENT"
        reason = f"a window is up and N was {option_count} on two consecutive ticks"
    elif console_state == "open":
        # NEEDS_UNPAUSE (pause=paused and console=open) is a subset of this
        # branch, and spec §5 ranks CONSOLE_OPEN first, so NEEDS_UNPAUSE never
        # fires.  That is self-consistent: spec §5's table has no outgoing edge
        # from NEEDS_UNPAUSE, so a reachable NEEDS_UNPAUSE would strand the
        # machine with no legal move.
        state = "CONSOLE_OPEN"
        reason = "the console is open"
    elif pause_state == "paused":
        state = "IN_GAME_PAUSED_CLEAN"
        reason = "paused, console closed, no window"
    else:
        state = "IN_GAME_RUNNING"
        reason = "running, console closed, no window"

    evidence = {
        "pause": dict(pause),
        "console": dict(console),
        "window": dict(window),
        "raw": _raw_counts(probe),
        "prev_option_count": prev_option_count,
        "blocked": bool(probe.get("blocked")),
        "restore_incomplete": bool(probe.get("restore_incomplete")),
        "hwnd": probe.get("hwnd"),
        "pid": probe.get("pid"),
        "reason": reason,
    }
    return state, evidence


def evidence_fingerprint(evidence: dict) -> str:
    """The sha256 of the canonicalised JSON of ``evidence`` — what a block pins.

    Canonical means sorted keys, no whitespace, UTF-8: two probes that read the
    same must fingerprint the same, on any platform and any Python build.
    """
    return _canonical_sha256(evidence)


def lease_fingerprint(evidence: dict) -> str:
    """The sha256 of spec §6's lease fingerprint: the world's **identity**.

    Exactly five things are hashed (spec §6 rule 3 names them):

    * ``hwnd`` — the world instance (a restarted game has a different one);
    * ``pause.state`` / ``console.state`` / ``window.kind`` — the three
      classifier verdicts;
    * ``window.option_count`` — the N.

    The **raw counts are deliberately not in it**.  Spec §6 rule 3 says the
    mismatch means 「窗口/控制台/暂停**变了**」 — the *classification* changed,
    not the pixels: the pause icon pulses every frame, so a fingerprint over
    ``red_px`` would refuse every call made seconds after the lease was
    issued, with the world untouched.  The counts stay in the evidence and in
    the jsonl (spec §10); the fingerprint's job is identity, not measurement.

    This is a **second** constructor, not a replacement: ``evidence_fingerprint``
    pins the whole evidence (including the raw counts, ``prev_option_count``
    and ``reason``), which is what a *block* wants — the evidence of the
    blocked moment, whole.  A lease cannot want that: those fields move every
    tick, so a lease issued at tick N would die at tick N+1 with the world
    untouched — a fail-closed refusal that is not closed against anything.

    The input is either shape this module has: the R4 probe reading or
    ``infer_state``'s evidence output (both carry ``hwnd`` / ``pause`` /
    ``console`` / ``window``).
    """
    pause = evidence.get("pause")
    pause = pause if isinstance(pause, dict) else {}
    console = evidence.get("console")
    console = console if isinstance(console, dict) else {}
    window = evidence.get("window")
    window = window if isinstance(window, dict) else {}
    subset = {
        "hwnd": evidence.get("hwnd"),
        "pause": {"state": pause.get("state")},
        "console": {"state": console.get("state")},
        "window": {"kind": window.get("kind")},
        "option_count": window.get("option_count"),
    }
    return _canonical_sha256(subset)


def _canonical_sha256(document: Any) -> str:
    """The sha256 of the canonicalised JSON of ``document``.

    Canonical means sorted keys, no whitespace, UTF-8: two readings that are
    the same must hash the same, on any platform and any Python build.
    """
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _raw_counts(probe: dict) -> dict[str, Any]:
    """The raw counts of a probe: its ``raw`` section, overridden by the counts
    the three sections carry — the counts live in the section that measured
    them (``pause``: ``red_px`` / ``green_px``; ``console``: ``bright_px``;
    ``window``: ``gold_px`` / ``row_count`` / ``option_count`` / ``bbox``), so a
    section's own value wins over whatever a caller put in ``raw``.

    A count that was not measured is **not** written as 0 — an absent key means
    "not measured", while a 0 means "measured zero".
    """
    raw = dict(probe.get("raw") or {})
    for section, keys in (
        (probe["pause"], ("red_px", "green_px")),
        (probe["console"], ("bright_px",)),
        (probe["window"], ("gold_px", "row_count", "option_count", "bbox")),
    ):
        for key in keys:
            if key in section:
                raw[key] = section[key]
    return raw


# ---------------------------------------------------------------------------
# Persistence: one JSON state file, one lock file beside it (spec §3)
# ---------------------------------------------------------------------------

#: The state file the Windows side writes.  ``NS_WORLD_STATE`` lets that side
#: point it elsewhere without editing code; reading it at import is not a side
#: effect (no file is touched, nothing is created).
DEFAULT_STATE_PATH: str = os.environ.get("NS_WORLD_STATE") or r"C:\temp\ns_world.json"

#: The state file's schema version.  A file with any other version is refused
#: rather than guessed at.
STATE_VERSION = 1

#: The lock file's name — always in the state file's own directory, never
#: somewhere else (spec §3: ``ns_world.json`` 与 ``ns_world.lock`` 并排).
_LOCK_FILE_NAME = "ns_world.lock"

#: The sections a complete probe reading carries, and the raw counts each one
#: must hold (spec §10: 探针证据必须记**原始计数**而不是只记判词).  This is
#: the shape ``unblock`` demands of an evidence file: the nonce alone is not
#: evidence (spec §7: 唯一被接受的解封证据是 ``ns_world.py probe --out`` 生成
#: 的文件，含 ``block_nonce`` 与**当时的完整探针读数**).
_PROBE_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("pause", ("red_px", "green_px")),
    ("console", ("bright_px",)),
    ("window", ("gold_px", "row_count", "option_count")),
)

#: The installed provider for a process's start time, or ``None``.
#:
#: spec §7 names the source — the CIM creation date — but this module has to
#: stay pure (no win32 imports, cross-platform, offline-testable), so it
#: cannot ask Windows itself.  The Windows side installs the query here
#: (``world_probe.process_identity``, wired up by the CLI); with no provider
#: installed, ``_process_start_time`` falls back to the Linux ``/proc`` parse
#: and, where there is no ``/proc``, to ``None`` — which degrades the lock's
#: generation check to liveness-only (spec §11-4's 代际不符即抢占 is then
#: inert on Windows, and a stale lock waits out the timeout instead).
_PROCESS_START_TIME_PROVIDER: Callable[[int], Any] | None = None


def set_process_start_time_provider(provider: Callable[[int], Any] | None) -> None:
    """Install (or, with ``None``, remove) the process start-time provider.

    The provider is called with a pid and answers "when did this process
    start?" — the **generation** half of spec §7's
    ``process_identity = (pid, process_start_time)``.  It returns a stable
    token for that process (the CIM creation date on the Windows side), or
    ``None`` when it cannot be read.  The same token must come back for the
    same process and a different one for a recycled pid: that difference is
    what lets the lock tell "the holder is gone" from "the holder is
    another process wearing its pid".

    The token is stored in the lock file and compared against a freshly
    obtained one, so a provider that returns a constant would make every
    lock look like a different generation.

    This is a **seam**, not a dependency: the module stays importable and
    testable on any host, with or without a provider.

    A provider that is not callable is refused **here**, with a
    ``TypeError``: a non-callable would be swallowed by the ``except
    Exception`` in ``_process_start_time`` and the lock's generation check
    would go **inert silently** — exactly the failure mode Ruling R15
    exists to avoid.  ``None`` is the only other accepted value: it
    uninstalls the provider.
    """
    if provider is not None and not callable(provider):
        raise TypeError(
            f"process start-time provider must be callable or None, "
            f"got {type(provider).__name__}")
    global _PROCESS_START_TIME_PROVIDER
    _PROCESS_START_TIME_PROVIDER = provider


#: Locks this process holds, by lock path: path -> depth.  A module-level
#: registry rather than an attribute of one ``Store``, so two ``Store`` objects
#: on the same path inside one process cannot deadlock each other.  There are
#: no threads here (spec §3), so the process is the unit of ownership.
_HELD_LOCKS: dict[str, int] = {}

#: How long to wait between attempts to take the lock, and how long a lock file
#: whose owner cannot be read is given before it is treated as garbage.
_LOCK_POLL_S = 0.05
_LOCK_GRACE_S = 2.0


class Store:
    """The state file: one JSON document, loaded, mutated under a lock, saved.

    The document is ``.data`` — a plain, mutable dict on purpose: the lease
    table and the armed guards (Task 3) live in it, so a copy-on-read view
    would silently drop what a caller wrote.

    The layout is::

        {"version": 1,
         "state": <spec §5 state name, or null until one is observed>,
         "attempts": {"by_identity": {"<pid>|<start_time>": {"<action>": counter}},
                      "global": {"<action>": counter}},
         "blocks": {"<action>": {"nonce": ..., "blocked_at": ...,
                                 "attempts": ..., "evidence_fingerprint": ...}},
         "leases": {"<lease_id>": {"lease_id": ..., "action": ..., "guard": ...,
                                  "ttl_s": ..., "fingerprint": ...,
                                  "issued_at": ..., "consumed": bool}},
         "armed": {"<guard>": {"lease_id": ..., "identity": [pid, start_time],
                               "armed_at": ...}}}

    A counter is ``{"attempts": int, "first_t": float, "last_t": float}`` — the
    value shape spec §7 pins.  The global counter also carries ``times``: the
    timestamps of the attempts still inside the window, which is what makes the
    window slide.  ``attempts`` / ``first_t`` / ``last_t`` are recomputed from
    that list, so the list is the single source of truth.
    """

    def __init__(self, path: str, data: dict) -> None:
        self.path = str(path)
        self.data = data

    @property
    def lock_path(self) -> str:
        """The lock file: the state file's own directory, ``ns_world.lock``.

        On the Windows side that is ``C:\\temp\\ns_world.lock`` (spec §3).
        """
        return os.path.join(os.path.dirname(self.path), _LOCK_FILE_NAME)

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> Store:
        """Read the state file; a missing file is a fresh, not-yet-saved store.

        Loading creates nothing (spec §3: import and load have no side
        effects) and never guesses: a corrupt file raises instead of reading as
        an empty budget — an unreadable budget must not read as "no attempts".
        """
        target = str(path) if path is not None else DEFAULT_STATE_PATH
        return cls(target, _read_state(target))

    def save(self, *, unsafe: bool = False) -> None:
        """Write ``.data`` back to the state file, atomically.

        Readers do not take the lock (spec §3), so the file is replaced rather
        than rewritten in place: a reader must never see half a document.

        **The write must happen under the lock.**  A store whose path this
        process does not currently hold the lock on is refused: saving it
        would silently overwrite whatever a concurrent process recorded since
        this store was loaded — the double-spend the lock exists to prevent,
        and one that produces no error at all.  So mutate and save inside
        ``with store.locked():``.

        ``unsafe=True`` is the named escape hatch for the case that genuinely
        has no lock to take: modelling a crashed writer, or a deliberate
        forensic write to a file nobody else is writing.  It means "write
        without the lock; I know what I am doing".

        The state file's directory is created if it is missing — here and on
        the lock path (see ``locked()``): a fresh host has no ``C:\\temp``
        yet, and the write must not die on the way there.
        """
        if not unsafe and self.lock_path not in _HELD_LOCKS:
            raise RuntimeError(
                f"{self.path}: refusing to save without the single-writer "
                f"lock — mutate and save inside `with store.locked():` "
                f"(pass unsafe=True to write anyway)")
        directory = os.path.dirname(self.path)
        tmp = f"{self.path}.tmp"
        try:
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, ensure_ascii=False, sort_keys=True, indent=2)
                fh.write("\n")
            os.replace(tmp, self.path)
        except OSError as exc:
            # Loud, not silent: a state file that cannot be written must stop the
            # caller, never look like a budget that was never spent.
            raise RuntimeError(f"{self.path}: cannot save state ({exc})") from exc

    @contextlib.contextmanager
    def locked(self, timeout_s: float = 5.0) -> Iterator[Store]:
        """Hold the single-writer lock around a read-modify-write of the json.

        The lock covers exactly that — never a screenshot, never a probe
        (spec §11-4).  While it is held, ``.data`` is re-read from disk: that
        read is the first half of the read-modify-write, so a write another
        process made in the meantime is not lost.  Mutate inside the block and
        call ``save()`` inside it too.

        Reentrant: nesting ``locked()`` on the same path is a no-op, not a
        self-deadlock.  An owner that is gone (its pid no longer exists) or
        whose generation (its start time) does not match is **stolen** rather
        than waited on, so a crashed holder cannot wedge the one-shot process.
        A live owner is waited for up to ``timeout_s``; after that a
        ``TimeoutError`` — the CLI turns that into exit code 4, 「锁僵死」.

        The state file's directory is created **before** the lock file is
        taken: the lock file lives in that directory, so on a fresh host
        (``C:\\temp`` need not exist) the very first write would otherwise
        die in ``os.open`` with a bare ``FileNotFoundError``.
        """
        key = self.lock_path
        depth = _HELD_LOCKS.get(key, 0)
        if depth:
            _HELD_LOCKS[key] = depth + 1
            try:
                yield self
            finally:
                _HELD_LOCKS[key] -= 1
            return
        self._acquire(timeout_s)
        _HELD_LOCKS[key] = 1
        try:
            if os.path.exists(self.path):
                self.data = _read_state(self.path)
            yield self
        finally:
            _HELD_LOCKS.pop(key, None)
            self._release()

    def _ensure_directory(self) -> None:
        """Create the state file's own directory, if it is not there yet.

        The lock file (``ns_world.lock``) lives in the state file's directory,
        so the directory must exist **before** ``os.open`` builds the lock —
        on a fresh host ``C:\\temp`` need not exist, and the first write must
        not die with a bare ``FileNotFoundError`` before ``save()`` runs.

        A bare filename (no directory part) is left alone: ``os.makedirs("")``
        would raise.  A directory that cannot be created is reported as the
        module's own loud ``RuntimeError``, not as a stray ``OSError`` from
        deep inside the lock.
        """
        directory = os.path.dirname(self.path)
        if not directory:
            return
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as exc:
            raise RuntimeError(
                f"{self.path}: cannot create the state directory "
                f"({exc})") from exc

    def _acquire(self, timeout_s: float) -> None:
        """Create the lock file, or take it over from an owner that is gone."""
        deadline = time.monotonic() + max(timeout_s, 0.0)
        while True:
            # The lock file lives in the state file's own directory, so that
            # directory must exist before the lock file can be created —
            # otherwise the first write on a fresh host dies in os.open with
            # a bare FileNotFoundError, before save() ever gets a chance.
            self._ensure_directory()
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            except FileExistsError:
                if self._steal_if_stale():
                    continue
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"{self.lock_path} stayed locked for {timeout_s}s "
                        f"(owner: {_owner_text(self.lock_path)})") from None
                time.sleep(_LOCK_POLL_S)
                continue
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"pid": os.getpid(),
                           "start_time": _process_start_time(os.getpid())}, fh)
            return

    def _steal_if_stale(self) -> bool:
        """Take the lock file over if its owner is gone; report whether to retry.

        spec §11-4: 持有者已消失或代际不符即抢占.  The generation is the
        owner's start time: the same pid can come back as a different process,
        and only the start time tells the two apart.
        """
        try:
            with open(self.lock_path, encoding="utf-8") as fh:
                raw = fh.read()
        except FileNotFoundError:
            return True          # it vanished under us — just try again
        except OSError:
            return False         # unreadable: treat it as held, not as free
        if not self._owner_is_gone(raw):
            return False
        try:
            os.unlink(self.lock_path)
        except FileNotFoundError:
            return True          # someone else took it — retry
        except OSError:
            return False
        return True

    def _owner_is_gone(self, raw: str) -> bool:
        """Is the owner the lock file names gone (or of another generation)?"""
        owner = None
        try:
            owner = json.loads(raw)
        except ValueError:
            owner = None
        if not isinstance(owner, dict):
            # A lock file we cannot read names no owner.  A fresh one belongs
            # to a holder that has created it and not yet written it down, so
            # give it a moment; an old one is garbage and is taken over.
            return _age(self.lock_path) > _LOCK_GRACE_S
        pid = owner.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            return True           # no usable owner recorded
        recorded = owner.get("start_time")
        actual = _process_start_time(pid)
        if recorded is not None and actual is not None and recorded != actual:
            return True           # the pid was recycled: another generation
        if pid == os.getpid() and self.lock_path not in _HELD_LOCKS:
            # Our own pid, but this process does not hold the lock: a release
            # that could not unlink its file.  Left behind it would block every
            # later acquire until someone deleted it by hand, so take it over.
            return True
        return not _owner_alive(pid)

    def _release(self) -> None:
        """Drop the lock file — only we can be holding it, so nobody stole it."""
        _unlink(self.lock_path)


class Blocked(Exception):
    """Raised when an action's attempt budget is already spent.

    ``action`` is the action that was refused and ``attempts`` is the count
    that refuses it — the same number ``blocked()`` reports (the count has
    reached ``MAX_ATTEMPTS[action]``).
    """

    def __init__(self, action: str, attempts: int) -> None:
        super().__init__(f"{action}: {attempts} attempts recorded "
                         f"(max {MAX_ATTEMPTS.get(action)}) — blocked")
        self.action = action
        self.attempts = attempts


def record_attempt(store: Store, action: str, identity: tuple[int, str],
                   now: float) -> int:
    """Count one attempt of a world-changing action; return the new count.

    Two counters move (spec §7): one keyed by ``(process_identity, action)``
    and one global one for ``action`` inside ``GLOBAL_WINDOW_S``.  The global
    one is what survives a relaunch — a new pid must not buy a fresh budget
    (spec §11-3).

    ``identity`` is spec §7's ``process_identity = (pid, process_start_time)``
    of the **game** process — the one the action is aimed at, not the caller.
    A game restart therefore starts that tally over, while the global window
    keeps the block sticky.

    Raises ``Blocked`` when the action is already blocked, and counts nothing
    in that case: the refused attempt is not an attempt.  The return value is
    the **identity-scoped** count after the increment — the game process's own
    tally — not the global one, which is the number of attempts by every
    process inside the window.

    ``now`` is wall-clock seconds (``time.time()``): the unblock check
    compares ``blocked_at`` against a file's mtime, and that only makes sense
    on one clock.
    """
    _require_counted(action)
    refused = blocked(store, action, now, identity=identity)
    if refused is not None:
        raise Blocked(action, refused["attempts"])

    per_action = store.data["attempts"]["by_identity"].setdefault(
        _identity_key(identity), {})
    counter = per_action.get(action)
    if counter is None:
        counter = per_action[action] = {"attempts": 0, "first_t": now, "last_t": now}
    counter["attempts"] = _count(counter["attempts"]) + 1
    counter["last_t"] = now

    global_counter = store.data["attempts"]["global"].get(action)
    if global_counter is None:
        global_counter = store.data["attempts"]["global"][action] = {
            "attempts": 0, "first_t": now, "last_t": now, "times": []}
    times = sorted([t for t in global_counter.get("times") or ()
                    if now - t < GLOBAL_WINDOW_S] + [now])
    global_counter["times"] = times
    global_counter["attempts"] = len(times)
    global_counter["first_t"] = times[0]
    global_counter["last_t"] = times[-1]
    return _count(counter["attempts"])


def blocked(store: Store, action: str, now: float, *,
            identity: tuple[int, str] | None = None) -> dict | None:
    """Is ``action`` blocked right now?  Return the block, or ``None``.

    The returned dict has exactly three keys: ``nonce`` and ``blocked_at`` (the
    block ``block()`` recorded — ``None`` while the action is merely over
    budget and no evidence has been asked for yet) and ``attempts`` (the count
    that refuses the action).

    Without an ``identity`` only the global window is consulted; with one,
    both the **game** process's own tally and the global window are.
    """
    _require_counted(action)
    marker = store.data["blocks"].get(action)
    if marker is not None:
        return {"nonce": marker["nonce"], "blocked_at": marker["blocked_at"],
                "attempts": marker["attempts"]}
    counts = [_global_count(store.data["attempts"]["global"].get(action), now)]
    if identity is not None:
        counts.append(_identity_count(store, action, identity))
    over = [count for count in counts if count >= MAX_ATTEMPTS[action]]
    if not over:
        return None
    return {"nonce": None, "blocked_at": None, "attempts": max(over)}


def block_state(store: Store, action: str, now: float, *,
                pid: int | None = None) -> dict | None:
    """The block record for ``action`` right now, or ``None``.

    Three things can block an action (spec §7): a block marker somebody
    recorded with evidence, the global sliding window, and the identity
    tally of the game process.  This answers all three in one place, so a
    caller does not have to know which half of the budget it is looking at
    — and, more importantly, does not have to *reimplement* the answer and
    get it wrong.

    ``pid`` is the **game** process's pid.  With it, that process's
    identity tally counts too.  Without it only the marker and the global
    window are consulted: a caller that cannot name the game must not claim
    the identity half is clear.
    """
    marker = blocked(store, action, now)
    if marker is not None:
        return marker
    if pid is not None:
        count = _identity_count_for_pid(store, action, pid)
        if count >= MAX_ATTEMPTS[action]:
            return {"nonce": None, "blocked_at": None, "attempts": count}
    return None


def block(store: Store, action: str, evidence: dict, now: float) -> str:
    """Put ``action`` behind evidence and return the nonce that clears it.

    The nonce is 16 random bytes, hex-encoded.  It goes into the evidence file
    the CLI writes (``ns_block_<nonce>.json``) — this function does not create
    that file (Task 5 does), and it does not save the state either: the caller
    persists inside ``store.locked()``.

    The evidence itself stays in the append-only file; the state keeps only
    its fingerprint, so the two can be tied together without copying evidence
    into mutable state.
    """
    _require_counted(action)
    nonce = secrets.token_hex(16)
    store.data["blocks"][action] = {
        "nonce": nonce,
        "blocked_at": now,
        "attempts": _attempts_now(store, action, now),
        "evidence_fingerprint": evidence_fingerprint(evidence),
    }
    return nonce


def unblock(store: Store, nonce: str, evidence_path: str,
            now: float) -> tuple[bool, str]:
    """Clear the block ``nonce`` names — but only for machine-made evidence.

    Five checks, first failure wins (spec §7):

    1. the evidence file exists;
    2. it is not empty and is valid JSON;
    3. it carries a ``block_nonce`` equal to ``nonce``;
    4. it carries a **complete probe reading** — the ``pause`` / ``console`` /
       ``window`` sections, each a dict, with the raw counts in place
       (``pause.red_px`` / ``green_px``, ``console.bright_px``,
       ``window.gold_px`` / ``row_count`` / ``option_count``);
    5. its mtime is later than the block's ``blocked_at``.

    Check 4 is what makes the nonce worth something.  The nonce is **not** a
    secret: it sits in the plain-JSON state file, and ``blocked()`` hands it
    back to every caller — so a hand-written twelve-byte
    ``{"block_nonce": "..."}`` with a fresh mtime satisfies checks 1, 2, 3 and
    5, and the agent could brush every block off with it.  spec §7 fixes what
    the accepted evidence *is*: 「唯一被接受的解封证据是 ``ns_world.py probe
    --out <该路径>`` 生成的文件（含 ``block_nonce`` 与**当时的完整探针读数**）」
    — the nonce **and** the complete probe reading taken at the time.  Check 4
    is that definition, enforced; the file must be shown to be the right
    artifact before its timestamp is trusted.

    Check 5 needs the block's own ``blocked_at``, so a nonce no block carries
    is refused as well.

    On success the block is cleared **and** that action's counters are reset —
    otherwise the very next attempt would re-block immediately and 「解封」 would
    be cosmetic.  Other actions' counters are untouched.
    """
    path = str(evidence_path)
    if not os.path.isfile(path):
        return False, f"evidence file not found: {path}"
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        return False, f"evidence file unreadable: {exc}"
    if not text.strip():
        return False, f"evidence file is empty: {path}"
    try:
        document = json.loads(text)
    except ValueError as exc:
        return False, f"evidence file is not valid JSON: {exc}"
    if not isinstance(document, dict):
        return False, "evidence file is not a JSON object"
    if document.get("block_nonce") != nonce:
        return False, (f"evidence block_nonce {document.get('block_nonce')!r} "
                       f"does not match the block {nonce!r}")
    missing = _missing_probe_readings(document)
    if missing:
        return False, (f"evidence file carries no complete probe reading "
                       f"(missing: {', '.join(missing)}) — a nonce alone is "
                       f"not evidence")
    action = None
    marker = None
    for name, candidate in store.data["blocks"].items():
        if candidate.get("nonce") == nonce:
            action, marker = name, candidate
            break
    if action is None or marker is None:
        return False, f"no block recorded with nonce {nonce!r}"
    blocked_at = marker["blocked_at"]
    try:
        mtime = os.path.getmtime(path)
    except OSError as exc:
        return False, f"evidence file cannot be read ({exc})"
    if not mtime > blocked_at:
        return False, (f"evidence mtime {mtime} is not later than "
                       f"blocked_at {blocked_at}")
    del store.data["blocks"][action]
    _reset_counters(store, action)
    return True, f"unblocked {action}"


# ---------------------------------------------------------------------------
# Leases: issue, consume, arm — and the lazy RESTORE_INCOMPLETE (spec §6)
# ---------------------------------------------------------------------------


def acquire(store: Store, action: str, *, guard: str | None, state: str,
            fingerprint: str, now: float) -> dict | None:
    """Issue a lease for one world-changing action; ``None`` if it cannot.

    Two gates, both from spec §6 rule 1 (「只有 ``IN_GAME_RUNNING`` 能签发；
    一次 install 只认一张租约」):

    * ``state`` must be ``IN_GAME_RUNNING`` — every other state is a premise
      that is not currently true;
    * no other **unexpired** lease may be outstanding — one installer at a time.

    A refusal is the **return value**, not an exception: the caller asked
    "may I?", and the honest answer is ``None``.

    The returned dict is the lease, carrying spec §6's fields: ``lease_id``
    (a uuid4), ``action``, ``guard``, ``ttl_s``, ``fingerprint``,
    ``issued_at`` — plus ``consumed``, which ``consume`` flips.

    ``issued_at`` is a **float on the same clock as ``now``** (wall-clock
    seconds).  Spec §6's example writes an ISO string, but every other time
    value in this module is a float epoch and ``now`` is a float: one file
    with two clocks would make 「is it expired?」 a string-parsing question.

    This function only mutates ``store.data``.  The caller persists, inside
    ``with store.locked():`` (R16) — a lease that is not on disk does not
    outlive the process that issued it, and on the Windows side every process
    is a one-shot process (spec §3).

    ``action`` must be one of the five world-changing actions: a lease is
    spec §6's "one install may claim one lease" credential, and a 30-second
    lease handed to ``status`` would block every other lease for 30 seconds.
    ``fingerprint`` must be a non-empty string — a lease pinned to nothing
    pins nothing (spec §6 rule 3), and an empty one is exactly the value the
    load-time validator refuses, i.e. a state file we would then be unable to
    read back.  Both are programming errors, so both raise rather than
    return ``None``.
    """
    _require_counted(action)
    if not isinstance(fingerprint, str) or not fingerprint:
        raise ValueError(
            f"the lease for {action!r} needs a non-empty fingerprint, "
            f"got {fingerprint!r} (spec §6 rule 3: a lease is pinned to one "
            f"reading of the world)")
    if state != "IN_GAME_RUNNING":
        return None
    if _outstanding_lease(store, now) is not None:
        return None
    lease = {
        "lease_id": str(uuid.uuid4()),
        "action": action,
        "guard": guard,
        "ttl_s": LEASE_TTL_S,
        "fingerprint": fingerprint,
        "issued_at": _timestamp(now, "now"),
        "consumed": False,
    }
    store.data["leases"][lease["lease_id"]] = lease
    return lease


def consume(store: Store, lease_id: str, now: float) -> bool:
    """Mark ``lease_id`` used; ``True`` only for the first, unexpired use.

    Spec §6 rule 1: 「用后标记 ``consumed``」 — the second consume of the same
    id is ``False``, and so is an id that no lease carries or that has already
    expired.  An unknown id is never a licence to proceed.

    A consumed lease is **marked**, not deleted: ``expired_while_armed`` still
    needs its ``issued_at`` to decide whether an armed guard's lease died.
    """
    lease = store.data["leases"].get(lease_id)
    if not isinstance(lease, dict):
        return False
    if lease.get("consumed"):
        return False
    if _lease_expired(lease, now):
        return False
    lease["consumed"] = True
    lease["consumed_at"] = _timestamp(now, "now")
    return True


def arm(store: Store, guard: str, lease_id: str, identity: tuple[int, str],
        now: float) -> None:
    """Record that ``guard`` is installed on the strength of ``lease_id``.

    This is spec §5's ``armed[]`` — the record that makes the world state
    remember what is still screwed in.  ``identity`` is the **game** process's
    ``(pid, process_start_time)`` (spec §7), stored as a two-element list:
    JSON has no tuples, and a list is what comes back after a round trip.

    There is no ticker in a one-shot process, so nothing polls this table.
    Instead the next call that reads it performs the check lazily — see
    ``expired_while_armed`` (spec §11-5).

    The caller persists inside ``with store.locked():`` (R16).

    ``lease_id`` must be a non-empty string: an armed record that names no
    lease is unreadable, and the load-time validator refuses it — so accepting
    one here would write a state file this module itself cannot read back.
    A programming error, so it raises rather than returning silently.
    """
    if not isinstance(lease_id, str) or not lease_id:
        raise ValueError(
            f"arm({guard!r}) needs a non-empty lease_id, got {lease_id!r}")
    store.data["armed"][guard] = {
        "lease_id": lease_id,
        "identity": [identity[0], identity[1]],
        "armed_at": _timestamp(now, "now"),
    }


def unarm(store: Store, guard: str, now: float) -> None:
    """Drop ``guard``'s armed record — its uninstall is done.

    **Every driver's uninstall path must call this.**  An armed record does not
    age out on its own; it is only ever read, and it is read as
    ``RESTORE_INCOMPLETE`` the moment its lease is older than
    ``LEASE_TTL_S``.  Leaving it behind is therefore not a harmless leftover:
    it is a standing false accusation of an incomplete restore (spec §6
    rule 4 / §11-5: 「宁可误判不可漏判」 — misjudging is the safe direction,
    so the record stays until it is affirmatively dropped).

    Idempotent: an unarmed guard that is unarm-ed again is a no-op, so a
    driver may call it from its cleanup path without checking first.

    ``now`` is in the signature for symmetry with ``arm`` — every function
    that touches this table takes the same clock — and records nothing: the
    entry itself is deleted.
    """
    store.data["armed"].pop(guard, None)


def expired_while_armed(store: Store, now: float) -> str | None:
    """Which guard is installed with a lease that has run out, or ``None``?

    This is spec §6 rule 4 and §11-5's lazy evaluation, in one function:
    there is no ticker, so a lease expiring while a guard is still installed
    must be discovered **the next time anyone asks the state** — and that
    reading must be ``RESTORE_INCOMPLETE``, because a restore that did not
    verify is exactly the state this machine exists to refuse.

    The criterion is ``issued_at + LEASE_TTL_S <= now`` on the lease the guard
    names.  A guard whose lease record cannot be found counts as expired: an
    unreadable premise is a broken premise, and spec §5's stance is
    「宁可误判不可漏判」.
    """
    for guard, entry in store.data["armed"].items():
        lease_id = entry.get("lease_id") if isinstance(entry, dict) else None
        lease = store.data["leases"].get(lease_id) if isinstance(lease_id, str) else None
        if not isinstance(lease, dict) or _lease_expired(lease, now):
            return guard
    return None


def assert_ready(store: Store, action: str, *, guard: str | None,
                 probe_evidence: dict, now: float) -> tuple[bool, str]:
    """The combined gate: may ``action`` be attempted right now?

    Returns ``(ok, reason_or_lease_id)``.  On refusal the second element is a
    human-readable reason and **no lease is issued**; on success it is the
    lease id.

    Six checks, in this order, first failure wins:

    1. **blocked** — the block marker, the global window, and the **probe's
       pid's** identity tally (spec §7).  The identity half is deliberately
       **not** windowed, so it outlives the global window; a probe that
       carries no pid cannot be checked at all, and the gate refuses rather
       than silently falling back to the window-only answer (fail closed).
    2. **expired_while_armed** — a guard installed whose lease ran out, which
       is ``RESTORE_INCOMPLETE`` (spec §6 rule 4 / §11-5);
    3. **infer_state** must come out ``IN_GAME_RUNNING`` — an ``unknown`` /
       ``undecided`` / ``None`` reading lands on the blocking side (spec §5),
       so an unreadable classifier can never pass this gate;
    4. **complete raw counts** — the probe must carry the readings ``unblock``
       demands (spec §10), or the lease would pin bare verdicts;
    5. **fingerprint** — the live reading must agree with the lease that
       authorises this action (spec §6 rule 3): the **outstanding** lease for
       ``(action, guard)``, and the lease ``guard`` is **armed** against.  A
       mismatch refuses with **both** fingerprints in the reason and issues
       nothing; an outstanding lease that matches *is* the authorisation — it
       is consumed (single use) and handed back;
    6. **acquire** — only now, with every premise true, is a fresh lease issued.

    ``probe_evidence`` is the **probe reading** in the R4 shape — the same
    thing ``infer_state`` takes (``pause`` / ``console`` / ``window`` sections
    plus ``raw`` and ``pid`` / ``hwnd``), *not* ``infer_state``'s evidence
    output (Ruling R17).

    Steps 1 and 2 run **before** ``infer_state``, and each of them returns
    outright when the store disagrees with the caller.  So by the time
    ``infer_state`` runs, the store has nothing left to fold into the
    readings: the ordering already guarantees the two answers agree, and the
    caller's own ``blocked`` / ``restore_incomplete`` flags — the only ones
    ``infer_state`` still sees — are refused by step 3 anyway.

    The identity half of the budget is read from the **state file alone**:
    ``_identity_key`` is ``<pid>|<start_time>``, and the probe carries the
    pid (the R4 shape), so the count for that pid is recoverable without
    asking the host anything.  Asking the host for a start time would put
    R15's silent-degradation trap back into the verdict; this does not.

    The caller persists the lease, inside ``with store.locked():`` (R16).
    """
    _require_counted(action)

    pid = probe_evidence.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int):
        return False, (f"the probe carries no usable pid (got {pid!r}) — the "
                       f"identity-scoped attempt count cannot be checked, and "
                       f"an unchecked budget is not a budget (fail closed)")

    marker = blocked(store, action, now)
    if marker is not None:
        return False, (f"{action} is blocked: {marker['attempts']} attempts on "
                       f"record (max {MAX_ATTEMPTS[action]})")

    identity_attempts = _identity_count_for_pid(store, action, pid)
    if identity_attempts >= MAX_ATTEMPTS[action]:
        return False, (f"{action} is blocked for this game process (pid {pid}): "
                       f"{identity_attempts} attempts on record "
                       f"(max {MAX_ATTEMPTS[action]}) — the identity tally is "
                       f"not windowed, so it outlives the {GLOBAL_WINDOW_S}s "
                       f"global window")

    expired_guard = expired_while_armed(store, now)
    if expired_guard is not None:
        return False, (f"RESTORE_INCOMPLETE: guard {expired_guard!r} is armed and "
                       f"its lease expired (ttl {LEASE_TTL_S}s) — uninstall "
                       f"verified? else unarm it")

    state, evidence = infer_state(probe_evidence)
    if state != "IN_GAME_RUNNING":
        return False, (f"state is {state}, not IN_GAME_RUNNING: "
                       f"{evidence.get('reason', '')}")

    missing = _missing_probe_readings(probe_evidence)
    if missing:
        return False, (f"the probe carries no complete raw reading (missing: "
                       f"{', '.join(missing)}) — a verdict without its counts is "
                       f"not evidence, and a lease would pin bare verdicts "
                       f"(spec §10)")

    live = lease_fingerprint(evidence)

    # (i) The outstanding lease for this action: it is the authorisation, so it
    # must be the one the live reading agrees with.  A match consumes it and
    # hands it back (one lease, one use).
    outstanding = _outstanding_lease_for(store, action, guard, now)
    if outstanding is not None:
        pinned = outstanding.get("fingerprint")
        if pinned != live:
            return False, (f"fingerprint mismatch: the outstanding lease "
                           f"{outstanding.get('lease_id')!r} for {action!r} is "
                           f"pinned to {pinned!r}, the live reading is {live!r} "
                           f"(spec §6 rule 3) — no lease issued")
        if not consume(store, outstanding["lease_id"], now):
            return False, (f"the outstanding lease "
                           f"{outstanding.get('lease_id')!r} for {action!r} could "
                           f"not be consumed — no lease issued")
        return True, outstanding["lease_id"]

    # (ii) The lease this guard is armed against: a guard installed against
    # another world must not license a new action here.
    if guard is not None:
        entry = store.data["armed"].get(guard)
        if isinstance(entry, dict):
            armed_id = entry.get("lease_id")
            armed_lease = (store.data["leases"].get(armed_id)
                           if isinstance(armed_id, str) else None)
            pinned = (armed_lease.get("fingerprint")
                      if isinstance(armed_lease, dict) else None)
            if not isinstance(pinned, str) or not pinned:
                return False, (f"guard {guard!r} is armed but its lease's "
                               f"fingerprint cannot be read — no lease issued")
            if pinned != live:
                return False, (f"fingerprint mismatch: guard {guard!r} is armed "
                               f"against lease {armed_id!r} pinned to {pinned!r}, "
                               f"the live reading is {live!r} (spec §6 rule 3) — "
                               f"the world changed since it was installed; no "
                               f"lease issued")

    lease = acquire(store, action, guard=guard, state=state,
                    fingerprint=live, now=now)
    if lease is None:
        return False, ("no lease issued: another unexpired lease is already "
                       "outstanding")
    return True, lease["lease_id"]


# --- the pieces the budget functions above are made of ---------------------


def _timestamp(value: Any, where: str) -> float:
    """A timestamp as a float; a value we cannot read is a loud error.

    The lease table stores timestamps as floats so that one file carries one
    clock (``now`` is wall-clock seconds everywhere in this module).  A
    timestamp we cannot read is not a timestamp of zero — it is a bug in the
    caller, and it must say so rather than become a plausible number.
    """
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{where} is {value!r}, not a number") from exc


def _outstanding_lease(store: Store, now: float) -> dict | None:
    """The lease that is neither expired nor consumed, or ``None``.

    That is what "one lease at a time" (spec §6 rule 1) means: a lease that
    was used up, or that has run out, no longer holds the world.
    """
    for lease in store.data["leases"].values():
        if isinstance(lease, dict) and not lease.get("consumed") \
                and not _lease_expired(lease, now):
            return lease
    return None


def _outstanding_lease_for(store: Store, action: str, guard: str | None,
                            now: float) -> dict | None:
    """The outstanding lease that authorises ``action`` for ``guard``, or ``None``.

    Scoped to **one** action and **one** guard: a lease issued for
    ``install`` is not the authorisation for an ``uninstall``, and a lease
    issued for another guard belongs to another world.  A lease that is
    consumed or expired is not outstanding at all — it must not trigger a
    fingerprint comparison, or a used-up lease would refuse every later,
    perfectly legal action (spec §6 rule 3 is about a *live* authorisation).
    """
    for lease in store.data["leases"].values():
        if not isinstance(lease, dict):
            continue
        if lease.get("action") != action or lease.get("guard") != guard:
            continue
        if lease.get("consumed") or _lease_expired(lease, now):
            continue
        return lease
    return None


def _lease_expired(lease: dict, now: float) -> bool:
    """Has this lease run out — ``issued_at + LEASE_TTL_S <= now``?

    The constant is used, never the stored ``ttl_s``: the stored value is
    what was issued (spec §6's field, and what the CLI prints), while expiry
    must not be readable out of the file, or a hand-edited state file would
    renew its own leases.  A lease whose ``issued_at`` cannot be read is
    expired — an unreadable premise is a broken premise.
    """
    issued_at = lease.get("issued_at")
    if isinstance(issued_at, bool) or not isinstance(issued_at, (int, float)):
        return True
    return issued_at + LEASE_TTL_S <= now

def _require_counted(action: str) -> None:
    """The budget exists for the five world-changing actions only (spec §7).

    ``status`` / ``probe`` / ``assert-ready`` / ``lease`` never change the
    world; counting them would let the agent's polling loop block itself
    (spec §11-6).  A caller that passes one has a bug, not a budget.
    """
    if action not in MAX_ATTEMPTS:
        raise ValueError(f"{action!r} is not a world-changing action; only "
                         f"{sorted(MAX_ATTEMPTS)} are ever counted")


def _identity_key(identity: tuple[int, str]) -> str:
    """The key of one process identity: ``<pid>|<start_time>``.

    The pid comes first and is a number, so the separator cannot be
    ambiguous: no two identities share a key.
    """
    pid, start_time = identity
    return f"{pid}|{start_time}"


def _count(value: Any) -> int:
    """An attempt counter's stored value, as an int.

    The file is ours, but a hand-edited one must not turn into a silent zero:
    a count that cannot be read is a corrupt budget, and a corrupt budget has
    to be loud — read as "no attempts" it would be the brush hole itself.
    """
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"the state file's attempt count {value!r} is not a number") from exc


def _global_count(counter: dict | None, now: float) -> int:
    """How many attempts of the global counter are still inside the window."""
    if not counter:
        return 0
    return len([t for t in counter.get("times") or () if now - t < GLOBAL_WINDOW_S])


def _identity_count(store: Store, action: str, identity: tuple[int, str]) -> int:
    """How many attempts of ``action`` **the game process** has made.

    ``identity`` is spec §7's ``process_identity = (pid, process_start_time)``
    of the **game** process — not of whichever process happens to be asking.
    That is what makes a game restart reset this tally (a new pid, a new
    start time) while the global window keeps the block sticky: the two
    scopes move for different reasons, on purpose.

    Not windowed: the sliding window is the global counter's (spec §7).
    Within one identity the tally is what it is — a block stays a block until
    someone unblocks it with evidence.
    """
    per_action = store.data["attempts"]["by_identity"].get(_identity_key(identity))
    if not per_action:
        return 0
    counter = per_action.get(action)
    return _count(counter["attempts"]) if counter else 0


def _identity_count_for_pid(store: Store, action: str, pid: int) -> int:
    """How many attempts of ``action`` **any** process wearing ``pid`` has made.

    ``_identity_key`` is ``<pid>|<start_time>``, so every key starting with
    ``<pid>|`` belongs to that pid — however many generations of the process
    have worn it.  The gate has only the pid (the probe carries no start
    time), so it takes the **max** over those keys: the most any generation
    of this pid has spent.  The start-time-scoped answer stays with
    ``_identity_count`` / ``record_attempt``, which do receive the identity.

    Like the identity tally itself, this is **not** windowed — the sliding
    window belongs to the global counter (spec §7), so this count outlives
    it and must be consulted separately.
    """
    prefix = f"{pid}|"
    counts = [0]
    for key, per_action in store.data["attempts"]["by_identity"].items():
        if not isinstance(key, str) or not key.startswith(prefix):
            continue
        counter = per_action.get(action) if isinstance(per_action, dict) else None
        if counter:
            counts.append(_count(counter["attempts"]))
    return max(counts)


def _attempts_now(store: Store, action: str, now: float) -> int:
    """The highest attempt count on record for ``action`` right now."""
    counts = [_global_count(store.data["attempts"]["global"].get(action), now)]
    for per_action in store.data["attempts"]["by_identity"].values():
        counter = per_action.get(action)
        if counter:
            counts.append(_count(counter["attempts"]))
    return max(counts)


def _missing_probe_readings(document: dict) -> list[str]:
    """What a complete probe reading in ``document`` lacks (empty = complete).

    The R4 shape: the ``pause`` / ``console`` / ``window`` sections, each a
    dict, carrying the raw counts spec §10 insists on — ``pause.red_px`` /
    ``green_px``, ``console.bright_px``, ``window.gold_px`` / ``row_count`` /
    ``option_count``.  A section that is not a dict, or a count that is
    missing or not a number, is reported by name so the refusal says what
    was wrong with the file.

    The sections are looked for at the top level first and, failing that,
    under a ``probe`` key — the evidence file is the probe reading plus the
    nonce, and Task 5's CLI may lay it out either way.  Both shapes have to
    carry the complete reading; neither is a way around it.

    ``bbox`` is deliberately not required: it is a rectangle or ``None``, and
    its absence is a normal reading, not a defect.
    """
    readings = document
    if not any(isinstance(document.get(section), dict)
               for section, _ in _PROBE_SECTIONS):
        nested = document.get("probe")
        if isinstance(nested, dict):
            readings = nested
    missing: list[str] = []
    for section, counts in _PROBE_SECTIONS:
        values = readings.get(section)
        if not isinstance(values, dict):
            missing.append(section)
            continue
        for count in counts:
            value = values.get(count)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                missing.append(f"{section}.{count}")
    return missing


def _reset_counters(store: Store, action: str) -> None:
    """Forget one action's counters — both scopes — and leave the rest alone."""
    store.data["attempts"]["global"].pop(action, None)
    identities = store.data["attempts"]["by_identity"]
    for key, per_action in list(identities.items()):
        per_action.pop(action, None)
        if not per_action:
            del identities[key]


def _read_state(path: str) -> dict:
    """Read the state document; a missing file is a fresh (unsaved) store."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except FileNotFoundError:
        return _fresh_state()
    if not raw.strip():
        raise ValueError(f"{path} is empty — refusing to read it as an empty budget")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"{path} is not valid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path} does not hold a JSON object")
    version = data.get("version")
    if version != STATE_VERSION:
        raise ValueError(f"{path}: version {version!r} is not {STATE_VERSION}")
    return _normalize(data)


def _fresh_state() -> dict:
    """A store that has never been saved: no state, no attempts, no blocks."""
    return {"version": STATE_VERSION, "state": None,
            "attempts": {"by_identity": {}, "global": {}},
            "blocks": {},
            "leases": {}, "armed": {}}


def _normalize(data: dict) -> dict:
    """Fill in the parts this module owns that the file happens not to have.

    A file written by an earlier shape still has to be readable — but a file
    whose containers are not containers is refused, not guessed at.
    """
    data.setdefault("state", None)
    data.setdefault("attempts", {})
    data.setdefault("blocks", {})
    data.setdefault("leases", {})
    data.setdefault("armed", {})
    for key in ("attempts", "blocks", "leases", "armed"):
        if not isinstance(data[key], dict):
            raise ValueError(f"the state file's {key!r} is not an object")
    for key in ("by_identity", "global"):
        data["attempts"].setdefault(key, {})
        if not isinstance(data["attempts"][key], dict):
            raise ValueError(f"the state file's attempts.{key} is not an object")
    _validate_counters(data["attempts"])
    _validate_markers(data["blocks"])
    _validate_leases(data["leases"])
    _validate_armed(data["armed"])
    return data


def _validate_markers(blocks: dict) -> None:
    """Refuse a block marker we cannot read — at load time, not at first use.

    ``blocked()`` reports the marker's nonce, timestamp and count; a marker
    that is missing one of them would raise a ``KeyError`` deep inside a
    budget check, long after the file was loaded.  Refusing it at the door
    says what is wrong with the file instead.
    """
    for action, marker in blocks.items():
        where = f"blocks[{action!r}]"
        if not isinstance(marker, dict):
            raise ValueError(f"the state file's {where} is not an object")
        nonce = marker.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            raise ValueError(f"the state file's {where}.nonce is not a nonce")
        for key in ("blocked_at", "attempts"):
            value = marker.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"the state file's {where}.{key} is {value!r}, "
                                 f"not a number")


def _validate_leases(leases: dict) -> None:
    """Refuse a lease we cannot read — at load time, not at first use.

    Expiry compares the lease's ``issued_at`` against the clock, and the
    fingerprint is what spec §6's rule 3 is checked against later; a lease
    missing either would raise deep inside the gate, long after the file was
    read.  Refusing it at the door says what is wrong with the file.
    """
    for lease_id, lease in leases.items():
        where = f"leases[{lease_id!r}]"
        if not isinstance(lease, dict):
            raise ValueError(f"the state file's {where} is not an object")
        for key in ("issued_at", "ttl_s"):
            value = lease.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"the state file's {where}.{key} is {value!r}, "
                                 f"not a number")
        fingerprint = lease.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise ValueError(f"the state file's {where}.fingerprint is missing")


def _validate_armed(armed: dict) -> None:
    """Refuse an armed record we cannot read — at load time.

    ``expired_while_armed`` resolves every armed entry through its
    ``lease_id``; an entry without one cannot be resolved, and it must not
    wait for a ``KeyError`` inside the gate to say so.
    """
    for guard, entry in armed.items():
        where = f"armed[{guard!r}]"
        if not isinstance(entry, dict):
            raise ValueError(f"the state file's {where} is not an object")
        lease_id = entry.get("lease_id")
        if not isinstance(lease_id, str) or not lease_id:
            raise ValueError(f"the state file's {where}.lease_id is missing")


def _validate_counters(attempts: dict) -> None:
    """Refuse a budget we cannot read — at load time, not at first use.

    A count that is not a number is a corrupt budget, and a corrupt budget
    that reads as "no attempts" is exactly the hole an agent would brush its
    budget through.  So the file is checked the moment it is read, rather
    than when somebody happens to ask about one action.
    """
    for identity, per_action in attempts["by_identity"].items():
        if not isinstance(per_action, dict):
            raise ValueError(
                f"the state file's attempts.by_identity[{identity!r}] "
                f"is not an object")
        for action, counter in per_action.items():
            _check_counter(counter, f"attempts.by_identity[{identity!r}][{action!r}]")
    for action, counter in attempts["global"].items():
        _check_counter(counter, f"attempts.global[{action!r}]")


def _check_counter(counter: Any, where: str) -> None:
    """One stored counter must be readable as a count of attempts.

    The count itself must be a number (a hand-edited ``"5"`` is a number
    written as text, not a count); the timestamps must be numbers too — the
    sliding window is computed from them.
    """
    if not isinstance(counter, dict):
        raise ValueError(f"the state file's {where} is not an object")
    count = counter.get("attempts")
    if isinstance(count, bool) or not isinstance(count, int):
        raise ValueError(f"the state file's {where}.attempts is {count!r}, "
                         f"not a count")
    for key in ("first_t", "last_t"):
        value = counter.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"the state file's {where}.{key} is {value!r}, "
                             f"not a timestamp")
    times = counter.get("times")
    if times is None:
        return
    if not isinstance(times, list):
        raise ValueError(f"the state file's {where}.times is not a list")
    for value in times:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"the state file's {where}.times holds {value!r}, "
                             f"which is not a timestamp")


def _unlink(path: str) -> bool:
    """Remove a file, tolerating one that is already gone.

    Returns whether it is gone.  A file that could not be removed (a lock
    file left behind by a release that failed) is recoverable — the next
    acquire sees our own pid with no lock held and takes it over — so this
    never raises: it must not fire out of a ``finally``.
    """
    try:
        os.unlink(path)
    except OSError:
        return False
    return True


def _process_start_time(pid: int) -> str | None:
    """``pid``'s start time as the kernel records it, or ``None`` where this
    host cannot read it.

    The **generation** half of spec §11-4: the same pid can come back as a
    different process, and only the start time tells the two apart.

    Three sources, in order:

    1. the installed provider (see ``set_process_start_time_provider``) —
       the Windows side's CIM creation date, which is what spec §7 names;
    2. Linux: ``/proc/<pid>/stat`` field 22 (``starttime``);
    3. ``None`` — nothing else this host can read.

    With no provider installed, Windows has no ``/proc`` and so answers
    ``None``: the lock's generation check is inert there and the lock
    degrades to **liveness-only** (a stale lock waits out the timeout and
    the CLI reports exit code 4 「锁僵死」 — loud, not silent).

    The value is returned as text, because it is stored in the lock file as
    JSON and compared against a freshly obtained one.
    """
    provider = _PROCESS_START_TIME_PROVIDER
    if provider is not None:
        try:
            value = provider(pid)
        except Exception:
            return None
        if value is None:
            return None
        return str(value)
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii", errors="replace") as fh:
            fields = fh.read().rsplit(") ", 1)[-1].split()
        return fields[19]
    except (OSError, IndexError):
        return None


def _owner_alive(pid: int) -> bool:
    """Is ``pid`` a process that exists right now?

    Doubt is read as "alive": stealing a live owner's lock would break the
    single writer, while waiting on a dead one only costs the timeout.
    """
    if os.name == "nt":
        return _windows_pid_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _windows_pid_alive(pid: int) -> bool:
    """Windows liveness, without ``os.kill`` — on Windows ``os.kill(pid, 0)``
    is ``TerminateProcess``, which would kill the very owner we are asking
    about.  ``OpenProcess`` asks the question instead; ``ctypes`` is stdlib and
    is imported here so this module stays import-clean and dependency-free on
    every host.
    """
    try:
        import ctypes
        # The kernel32 entry points are resolved *before* the call: a symbol
        # lookup in between would reset the thread's last-error code, which is
        # exactly what tells "no such pid" from "access denied".
        kernel32 = ctypes.cdll.LoadLibrary("kernel32")
        open_process = kernel32.OpenProcess
        close_handle = kernel32.CloseHandle
        last_error = kernel32.GetLastError
        open_process.restype = ctypes.c_void_p
        close_handle.argtypes = [ctypes.c_void_p]
        handle = open_process(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
        if handle:
            close_handle(handle)
            return True
        # 87 is ERROR_INVALID_PARAMETER: OpenProcess reports it for a pid that
        # does not exist.  Anything else (5 = ACCESS_DENIED) means it is there.
        return last_error() != 87
    except Exception:
        return True


def _age(path: str) -> float:
    """How many seconds ago the file was last written (inf if it is gone)."""
    try:
        return time.time() - os.path.getmtime(path)
    except OSError:
        return float("inf")


def _owner_text(path: str) -> str:
    """The lock file's raw content, for the timeout message."""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()[:200] or "an empty lock file"
    except OSError:
        return "unknown"
