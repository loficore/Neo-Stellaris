"""game_supervisor — keep a live Stellaris session usable for agents.

Two halves, on purpose:

* the pure core below (constants, classification, policy, command parsing)
  imports on any OS, so ``scripts/windows/tests`` runs on the Linux host;
* the Windows edge (``serve`` and friends, added after the pure-core tests
  are green) owns ctypes/PIL/numpy and is only exercised on the live box.

Wire paths are fixed under ``C:/temp``; the daemon opens no listening port.
The command file is one line, consumed once; every action re-reads the pause
icon because closing an event window can unpause the game by itself.
"""

from __future__ import annotations

import random

CMD_PATH = r"C:\temp\ns_game_cmd.txt"
CMD_SEEN_PATH = r"C:\temp\ns_game_cmd.seen"
STATUS_PATH = r"C:\temp\ns_game_status.json"
LOG_PATH = r"C:\temp\ns_game_log.jsonl"
SHOT_PATH = r"C:\temp\ns_game_shot.png"
TASK_NAME = "NeoStellarisSupervisor"
TASK_SHIM = r"C:\temp\ns_game_supervisor_task.cmd"

# Top-right pause widget, sampled 2026-10-23 at 2160x1440:
# (left margin from window right, right margin, y0, y1) -> box 45 px wide.
PAUSE_BOX_OFFSETS = (243, 198, 5, 50)

# Paused: red 956..965, green 0.  Playing: red 0, green 200..207.
PAUSED_RED_MIN = 300
PAUSED_GREEN_MAX = 50
PLAYING_GREEN_MIN = 100
PLAYING_RED_MAX = 50

# A choice window's option text started at x≈1260 and reached x≈1600; the news
# window ended at x=1420, so "row starts past 1150 and ends past 1450" is the
# discriminator.  Options sat at y≈861/895/929 of 1440.
CHOICE_ROW_LEFT_MIN = 1150
CHOICE_ROW_RIGHT_MIN = 1450
CHOICE_ROW_COUNT_MIN = 2
CHOICE_GOLD_MIN = 8000

PAUSE_STATES = ("playing", "paused", "unknown")
WINDOW_KINDS = ("choice", "dialog", "none")


def classify_pause(red_px: int, green_px: int) -> str:
    """Map the pulse-icon colour counts to ``playing|paused|unknown``."""
    if red_px >= PAUSED_RED_MIN and green_px < PAUSED_GREEN_MAX:
        return "paused"
    if green_px >= PLAYING_GREEN_MIN and red_px < PLAYING_RED_MAX:
        return "playing"
    return "unknown"


def classify_window(rows, bbox, gold_px: int) -> str:
    """``choice`` when golden option rows sit in the right-hand column.

    ``bbox`` is ``[x0, y0, x1, y1]`` of a detected bright panel, or ``None``
    when the band profile found none.  It is informational: the choice
    window is a dark panel, so its rows decide even without a bbox.  Rows
    are golden-text runs in full-resolution window coordinates.
    """
    wide = [r for r in rows
            if r.get("x0", 0) >= CHOICE_ROW_LEFT_MIN
            and r.get("x1", 0) >= CHOICE_ROW_RIGHT_MIN]
    if gold_px >= CHOICE_GOLD_MIN and len(wide) >= CHOICE_ROW_COUNT_MIN:
        return "choice"
    if bbox:
        return "dialog"
    return "none"


def choose_row(policy: str, rows, rng: random.Random):
    """Return a 0-based row index, or ``None`` when the policy cannot apply."""
    if not rows:
        return None
    if policy == "first":
        return 0
    if policy == "last":
        return len(rows) - 1
    if policy == "random":
        return rng.randrange(len(rows))
    if policy.isdigit():
        index = int(policy) - 1
        return index if 0 <= index < len(rows) else None
    return None


def plan_step(want: str | None, paused: str, window: str):
    """Decide one tick's action from the commanded and observed states.

    ``want`` is ``playing``/``paused``/``None`` (observe-only).  The extra
    dict carries ``restore``: the state to enforce after a handled window.
    """
    if paused not in PAUSE_STATES or window not in WINDOW_KINDS:
        return "none", {"reason": "bad_state"}
    if paused == "unknown":
        return "none", {"reason": "unreadable"}
    if want == "paused":
        if paused == "playing":
            return "pause", {}
        if window == "choice":
            return "handle_choice", {"restore": "paused"}
        if window == "dialog":
            return "handle_dialog", {"restore": "paused"}
        return "none", {"reason": "paused_no_window"}
    if want == "playing":
        if paused == "playing":
            return "none", {}
        if window == "choice":
            return "handle_choice", {"restore": "playing"}
        if window == "dialog":
            return "handle_dialog", {"restore": "playing"}
        return "report_paused_no_window", {}
    if paused == "playing":
        return "none", {}
    if window == "choice":
        return "handle_choice", {"restore": None}
    if window == "dialog":
        return "handle_dialog", {"restore": None}
    return "none", {"reason": "paused_no_window"}


def parse_command(line: str):
    """Parse one command-file line; ``None`` means "nothing to do".

    A recognized verb with bad arguments is ignored (``None``); an unknown
    verb comes back as an ``unknown`` record so the daemon can log it.
    """
    parts = line.split()
    if not parts:
        return None
    verb = parts[0].lower()
    args = parts[1:]
    if verb in ("pause", "unpause", "toggle", "shot", "status", "quit", "dismiss"):
        return {"verb": verb}
    if verb == "want":
        if len(args) == 1 and args[0].lower() in ("playing", "paused"):
            return {"verb": "want", "want": args[0].lower()}
        return None
    if verb in ("policy", "choose"):
        if len(args) != 1:
            return None
        policy = args[0].lower()
        if policy in ("first", "last", "random") or policy.isdigit():
            return {"verb": verb, "policy": policy}
        return None
    if verb == "speed":
        if len(args) == 1 and args[0].lower() in ("up", "down"):
            return {"verb": "speed", "direction": args[0].lower()}
        return None
    if verb == "click":
        if len(args) != 2:
            return None
        try:
            return {"verb": "click", "x": int(args[0]), "y": int(args[1])}
        except ValueError:
            return None
    return {"verb": "unknown", "raw": line.strip()}
