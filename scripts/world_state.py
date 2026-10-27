"""world_state — the pure world-state machine: turn "is the premise still true?"
into data and a code gate.

This module is **pure logic plus a file store**: cross-platform, zero
win32/PIL/numpy imports, zero import-time side effects (no file is created, no
log truncated, no screenshot taken), so it can be unit-tested offline.  It does
**not** collect probe readings (that is ``scripts/windows/world_probe.py``),
issue leases (Task 3), or expose a CLI (Task 5).  It answers exactly three
questions:

1. which state do the current probe readings mean — ``infer_state(probe)``;
2. may this state move to that state by this action — ``may(from, to, action)``;
3. may this action be attempted at all right now — the attempt budget
   (``record_attempt`` / ``blocked``) and the evidence-gated way out of a
   block (``block`` / ``unblock``).

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
    """The sha256 of the canonicalised JSON of ``evidence`` — what a lease pins.

    Canonical means sorted keys, no whitespace, UTF-8: two probes that read the
    same must fingerprint the same, on any platform and any Python build.
    """
    payload = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
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
    """
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
                                 "attempts": ..., "evidence_fingerprint": ...}}}

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

    def _acquire(self, timeout_s: float) -> None:
        """Create the lock file, or take it over from an owner that is gone."""
        deadline = time.monotonic() + max(timeout_s, 0.0)
        while True:
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


# --- the pieces the four above are made of ---------------------------------

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
            "blocks": {}}


def _normalize(data: dict) -> dict:
    """Fill in the parts this module owns that the file happens not to have.

    A file written by an earlier shape still has to be readable — but a file
    whose containers are not containers is refused, not guessed at.
    """
    data.setdefault("state", None)
    data.setdefault("attempts", {})
    data.setdefault("blocks", {})
    for key in ("attempts", "blocks"):
        if not isinstance(data[key], dict):
            raise ValueError(f"the state file's {key!r} is not an object")
    for key in ("by_identity", "global"):
        data["attempts"].setdefault(key, {})
        if not isinstance(data["attempts"][key], dict):
            raise ValueError(f"the state file's attempts.{key} is not an object")
    _validate_counters(data["attempts"])
    _validate_markers(data["blocks"])
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
