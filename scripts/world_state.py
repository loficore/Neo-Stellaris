"""world_state — the pure world-state machine: turn "is the premise still true?"
into data and a code gate.

This module is **pure functions only**: cross-platform, zero win32/PIL/numpy
imports, zero import-time side effects (no file is created, no log truncated,
no screenshot taken), so it can be unit-tested offline.  It does **not** collect
probe readings (that is ``scripts/windows/world_probe.py``), persist or lock
state (Task 2), issue leases (Task 3), or expose a CLI (Task 5).  It answers
exactly two questions:

1. which state do the current probe readings mean — ``infer_state(probe)``;
2. may this state move to that state by this action — ``may(from, to, action)``.

Two rules are not negotiable (spec §5):

* ``unknown`` / ``undecided`` / ``None`` always land on the **blocking** side;
  they are never read as ``playing`` / ``closed`` / ``none`` — an unreadable
  classifier is not evidence of a healthy game;
* the evidence always carries the **raw counts** (``red_px`` / ``green_px`` /
  ``bright_px`` / ``gold_px`` / ``row_count`` / ``option_count`` / ``bbox``),
  not only the verdict — a verdict cannot be re-graded into a threshold later
  (spec §10).
"""

from __future__ import annotations

import hashlib
import json
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

#: Reserved marker for a transition that **no** of the five actions causes: it is
#: a state change the probe observed, or a state change only a signed-evidence
#: ``unblock`` may cause.  Such a transition is not commandable by an action, so
#: its action slot accepts this marker only — ``may(f, t, "install")`` must not
#: be able to talk the machine into a transition that an install cannot cause.
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
    the three sections carry (R4 puts the counts in the sections).

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
