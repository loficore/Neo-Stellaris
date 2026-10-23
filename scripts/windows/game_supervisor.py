"""game_supervisor — keep a live Stellaris session usable for agents.

Two halves, on purpose:

* the pure core below (constants, classification, policy, command parsing)
  imports on any OS, so ``scripts/windows/tests`` runs on the Linux host;
* the Windows edge (``serve`` and friends) owns ctypes/PIL/numpy and is only
  exercised on the live box.

Wire paths are fixed under ``C:/temp``; the daemon opens no listening port.
The command file is one line, consumed once; every action re-reads the pause
icon because closing an event window can unpause the game by itself.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time

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

# Paused: red 956..965, green 0 (2026-10-23 spike, bright icon) and 209, 0
# (same day, live 4.4.4 salmon icon).  Playing: red 0, green 200..207.
# 80 keeps both pause looks while the top-bar browns (r<140) stay out.
PAUSED_RED_MIN = 80
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

# The debug-console panel, calibrated live 2026-10-23 on a 2160x1440 window
# (evidence §54.10).  Bright pixels inside this box, read once per state:
#   panel closed: 0, 2, 0, 2      panel open: 2315, 2315, 2315
# The open number repeats exactly because the panel's own text is static, while
# the animated menu background churns by hundreds of thousands of pixels — so
# this is a single-frame count of dense bright text, never a frame difference.
# Fractions of the window, so a different size keeps the same part of the panel.
CONSOLE_BOX_FRACTIONS = (120 / 2160, 640 / 1440, 400 / 2160, 880 / 1440)
CONSOLE_BRIGHT_MIN = 180
CONSOLE_CLOSED_MAX = 120
CONSOLE_OPEN_MIN = 600


def classify_console(bright_px: int):
    """``True`` open, ``False`` closed, ``None`` undecided.

    The undecided band is not a hedge: an ambiguous frame must stop the daemon
    from tapping a toggle key it cannot see the result of.
    """
    if bright_px >= CONSOLE_OPEN_MIN:
        return True
    if bright_px <= CONSOLE_CLOSED_MAX:
        return False
    return None


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


def plan_step(want: str | None, paused: str, window: str,
              resume_commanded: bool = False):
    """Decide one tick's action from the commanded and observed states.

    ``want`` is ``playing``/``paused``/``None`` (observe-only).  The extra
    dict carries ``restore``: the state to enforce after a handled window.
    ``resume_commanded`` is the one-shot override an explicit ``unpause``
    sets; without it a bare pause is treated as a human pause and reported.
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
        if resume_commanded:
            return "resume", {}
        return "report_paused_no_window", {}
    if paused == "playing":
        return "none", {}
    if window == "choice":
        return "handle_choice", {"restore": None}
    if window == "dialog":
        return "handle_dialog", {"restore": None}
    return "none", {"reason": "paused_no_window"}


def reread_after_grace(paused: str, want: str | None, grace_s: float, read, sleep):
    """Re-read the pause icon once the grace window has elapsed.

    The game can be killed while we wait (relaunch, crash); GetWindowRect then
    fails with 1400.  That reading is ``unknown`` — the decide step never acts
    on it — instead of an OSError that takes the whole daemon down with the
    window.
    """
    if paused != "paused" or want == "paused" or not grace_s:
        return paused
    sleep(grace_s)
    try:
        return read()[0]
    except OSError:
        return "unknown"


def parse_command(line: str):
    """Parse one command-file line; ``None`` means "nothing to do".

    A recognized verb with bad arguments is ignored (``None``); an unknown
    verb comes back as an ``unknown`` record so the daemon can log it.
    """
    stripped = line.strip()
    head = stripped.split(None, 1)
    if not head:
        return None
    verb = head[0].lower()
    if verb == "console":
        if len(head) == 1 or not head[1].strip():
            return None
        return {"verb": "console", "text": head[1]}
    if verb == "console_sync":
        if len(head) == 2 and head[1].strip().lower() == "auto":
            return {"verb": "console_sync", "mode": "auto"}
        if len(head) == 2 and head[1].strip().lower() in ("open", "closed"):
            return {"verb": "console_sync", "open": head[1].strip().lower() == "open"}
        return None
    parts = line.split()
    args = parts[1:]
    if verb in ("pause", "unpause", "toggle", "shot", "status", "quit",
                "dismiss", "close", "console_close"):
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


# --------------------------------------------------------------------------
# File channel (filesystem only; covered on the Linux host)
# --------------------------------------------------------------------------

def atomic_write_text(path, text: str) -> None:
    path = os.fspath(path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    os.replace(tmp, path)


def atomic_write_json(path, obj) -> None:
    path = os.fspath(path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)


def rotate_log(path, max_bytes: int = 1_000_000) -> None:
    path = os.fspath(path)
    try:
        if os.path.getsize(path) <= max_bytes:
            return
    except OSError:
        return
    os.replace(path, path + ".1")


def _file_key(st) -> str:
    return f"{st.st_mtime_ns}:{st.st_size}"


def read_command(path, seen_path):
    """One-line command file, consumed once per (mtime_ns, size) key.

    Re-issuing the same text after an atomic replace produces a new key, so a
    repeated command still runs; a daemon restart never replays an old line.
    """
    path = os.fspath(path)
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = _file_key(st)
    try:
        with open(seen_path, encoding="ascii") as f:
            if f.read().strip() == key:
                return None
    except OSError:
        pass
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    atomic_write_text(seen_path, key)
    return text.strip() or None


def task_shim_text(pythonw: str, script: str) -> str:
    """ASCII-only .cmd shim that starts the daemon under pythonw.

    cp936 consoled cmd.exe parses .cmd files in; keeping the shim ASCII means
    a non-ASCII install path fails here instead of producing a task that dies
    silently at logon time.
    """
    text = ("@echo off\r\n"
            f'"{pythonw}" "{script}" serve >> "C:\\temp\\ns_game_supervisor.out" 2>&1\r\n')
    text.encode("ascii")
    return text


# --------------------------------------------------------------------------
# Windows edge
# --------------------------------------------------------------------------

KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_SCANCODE = 0x0008
INPUT_KEYBOARD = 1
SW_RESTORE = 9
SPACE_SCAN = 0x39
SPEED_SCAN = {"up": 0x0D, "down": 0x0C}  # US layout '=' / '-' with KEYEVENTF_SCANCODE
CONSOLE_SCAN = 0x29   # backquote
CTRL_SCAN = 0x1D
PASTE_SCAN = 0x2F     # V
ENTER_SCAN = 0x1C
BACKSPACE_SCAN = 0x0E
BACKSPACE_CLEAR = 64  # clears the '~' the opening tap types into an open console
GMEM_MOVEABLE = 0x0042
CF_UNICODETEXT = 13
REF_W, REF_H = 2160, 1440  # spike reference resolution


def console_tap_plan():
    """The two events that flip the console panel over, with their delays.

    Backquote is a toggle in 4.4.4, so this is the whole of both an open and a
    close — which one it performs depends entirely on the parity the caller
    believes.
    """
    down = KEYEVENTF_SCANCODE
    return [(0, CONSOLE_SCAN, down, 0.08),
            (0, CONSOLE_SCAN, down | KEYEVENTF_KEYUP, 0.08)]


def console_key_plan(open_console: bool = True):
    """Clear the console input, paste with Ctrl+V, submit with Enter.

    The console key is a toggle in 4.4.4 (live 2026-10-23): it opens a closed
    console, and a submitted command leaves the console open — so the next
    command's tap CLOSED it and its keystrokes went to the game (the C4 shot's
    capture command ran zero of its 783 sentinels).  ``open_console`` is False
    once this daemon has submitted a command itself, or when an operator
    declares the console open with ``console_sync open``.  The backspace burst
    clears whatever the input line held.  Each event carries its own delay:
    backspaces go out at 20 ms, everything else at 80 ms.

    Ctrl is held across V: its down/up wrap the paste events, so the plan
    cannot be expressed as ``_send_key_events`` pairs.
    """
    down = KEYEVENTF_SCANCODE
    up = KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP
    plan = []
    if open_console:
        plan += console_tap_plan()
    for _ in range(BACKSPACE_CLEAR):
        plan.append((0, BACKSPACE_SCAN, down, 0.02))
        plan.append((0, BACKSPACE_SCAN, up, 0.02))
    plan += [
        (0, CTRL_SCAN, down, 0.08),
        (0, PASTE_SCAN, down, 0.08), (0, PASTE_SCAN, up, 0.08),
        (0, CTRL_SCAN, up, 0.08),
        (0, ENTER_SCAN, down, 0.08), (0, ENTER_SCAN, up, 0.08),
    ]
    return plan


def console_send_plan(state: dict):
    """``("send", open_console)`` or ``("refuse", reason)`` for a console verb.

    ``state["console_open"]`` is a three-valued belief: ``True`` the panel is
    open, ``False`` it is closed, ``None`` unknown.  The console key is a
    toggle, so a send needs to know the parity — guessing it is what turned the
    C4 capture command into 0 executed sentinels with nothing in the log to say
    so.  Only ``console_sync`` or a fresh process can lift ``None``.
    """
    current = state.get("console_open", False)
    if current is None:
        return ("refuse", "console_state_unknown")
    return ("send", not current)


def send_pause_key(state: dict, hwnd: int) -> str:
    """Press Space to toggle pause unless the console would eat the keystroke.

    While the panel is believed open, Space lands in its input line: the game
    does not pause, the pixel classifier keeps reporting ``playing``, and the
    loop presses again every tick.  ``blocked_console`` makes that visible in
    the status note instead of repeating forever.
    """
    if state.get("console_open") is True:
        return "blocked_console"
    press_space(hwnd)
    return "sent"


def _require_windows() -> None:
    if sys.platform != "win32":
        raise SystemExit("game_supervisor's live half runs on Windows")


def _launch():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import launch_stellaris
    return launch_stellaris


def _user32():
    import ctypes
    return ctypes.windll.user32


def _be_dpi_aware() -> None:
    try:
        _user32().SetProcessDPIAware()
    except Exception:
        pass


def find_window(pid: int) -> int:
    import ctypes
    import ctypes.wintypes as wt
    user32 = _user32()
    found = []

    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def cb(hwnd, _):
        wpid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if wpid.value == pid and user32.IsWindowVisible(hwnd):
            if user32.GetWindowTextLengthW(hwnd):
                found.append(hwnd)
                return False
        return True

    user32.EnumWindows(cb, 0)
    return found[0] if found else 0


def find_game():
    """``(pid, hwnd)`` of the live game, or ``(0, 0)``."""
    _be_dpi_aware()
    try:
        import psutil
    except ImportError:
        return 0, 0
    for p in psutil.process_iter(["name", "pid"]):
        if (p.info["name"] or "").lower() == "stellaris.exe":
            hwnd = find_window(p.info["pid"])
            if hwnd:
                return int(p.info["pid"]), int(hwnd)
    return 0, 0


def window_rect(hwnd: int):
    return _launch()._window_rect(hwnd)


def focus(hwnd: int) -> bool:
    user32 = _user32()
    user32.ShowWindow(hwnd, SW_RESTORE)
    user32.SetForegroundWindow(hwnd)
    deadline = time.time() + 3.0
    ok = False
    while time.time() < deadline:
        if int(user32.GetForegroundWindow() or 0) == int(hwnd):
            ok = True
            break
        time.sleep(0.1)
    time.sleep(0.4)
    return ok


def _send_input_event(vk: int, scan: int, flags: int) -> int:
    """SendInput with the 40-byte INPUT union; a keyboard-only union makes
    SendInput reject every event with ERROR_INVALID_PARAMETER on x64."""
    import ctypes
    import ctypes.wintypes as wt

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [("dx", wt.LONG), ("dy", wt.LONG),
                    ("mouseData", wt.DWORD), ("dwFlags", wt.DWORD),
                    ("time", wt.DWORD), ("dwExtraInfo", ctypes.c_size_t)]

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD),
                    ("dwFlags", wt.DWORD), ("time", wt.DWORD),
                    ("dwExtraInfo", ctypes.c_size_t)]

    class INPUT(ctypes.Structure):
        class _U(ctypes.Union):
            _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT)]
        _anonymous_ = ("u",)
        _fields_ = [("type", wt.DWORD), ("u", _U)]

    ev = INPUT(type=INPUT_KEYBOARD,
               ki=KEYBDINPUT(wVk=vk, wScan=scan, dwFlags=flags,
                             time=0, dwExtraInfo=0))
    return _user32().SendInput(1, ctypes.byref(ev), ctypes.sizeof(INPUT))


def _send_key_events(vk: int, scan: int, base_flags: int):
    sent = []
    for flags in (base_flags, base_flags | KEYEVENTF_KEYUP):
        sent.append(_send_input_event(vk, scan, flags))
        time.sleep(0.08)
    return sent


def _set_clipboard_text(text: str) -> bool:
    """Copy ``text`` to the clipboard; ``False`` on any failure.

    Every handle-returning call declares ``c_void_p``: ctypes defaults to
    ``c_int``, which truncates 64-bit HMEM/HANDLE values on x64.
    """
    import ctypes
    import ctypes.wintypes as wt

    user32 = _user32()
    kernel32 = ctypes.windll.kernel32

    user32.OpenClipboard.argtypes = [wt.HWND]
    user32.OpenClipboard.restype = wt.BOOL
    user32.EmptyClipboard.restype = wt.BOOL
    user32.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
    user32.SetClipboardData.restype = wt.HANDLE
    user32.CloseClipboard.restype = wt.BOOL

    kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.restype = wt.BOOL
    kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.restype = ctypes.c_void_p

    if not user32.OpenClipboard(None):
        return False
    handle = None
    try:
        if not user32.EmptyClipboard():
            return False
        data = text.encode("utf-16-le") + b"\x00\x00"
        handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
        if not handle:
            return False
        ptr = kernel32.GlobalLock(handle)
        if not ptr:
            return False
        ctypes.memmove(ptr, data, len(data))
        kernel32.GlobalUnlock(handle)
        if not user32.SetClipboardData(CF_UNICODETEXT, handle):
            return False
        handle = None  # the clipboard owns the block now
        return True
    finally:
        if handle:
            kernel32.GlobalFree(handle)
        user32.CloseClipboard()


def press_space(hwnd: int) -> None:
    if not focus(hwnd):
        raise OSError("focus refused before Space")
    _send_key_events(0, SPACE_SCAN, KEYEVENTF_SCANCODE)


def press_speed(hwnd: int, direction: str) -> None:
    if not focus(hwnd):
        raise OSError("focus refused before speed key")
    _send_key_events(0, SPEED_SCAN[direction], KEYEVENTF_SCANCODE)


def grab_box(box):
    from PIL import ImageGrab
    return ImageGrab.grab(bbox=box, all_screens=True).convert("RGB")


def _pause_box(rect):
    left, top, right, _ = rect
    lm, rm, y0, y1 = PAUSE_BOX_OFFSETS
    w = right - left
    return (left + w - lm, top + y0, left + w - rm, top + y1)


def read_pause(hwnd: int):
    """``(state, red_px, green_px)`` from the top-right pause glyph."""
    import numpy as np
    rect = window_rect(hwnd)
    im = grab_box(_pause_box(rect))
    a = np.asarray(im, dtype=np.int16)
    r, g, b = a[..., 0], a[..., 1], a[..., 2]
    red = int(((r > 140) & (r > g + 40) & (r > b + 40)).sum())
    green = int(((g > 120) & (g > r + 30) & (g > b + 10)).sum())
    return classify_pause(red, green), red, green


def _console_box(rect):
    left, top, right, bottom = rect
    fx0, fy0, fx1, fy1 = CONSOLE_BOX_FRACTIONS
    w, h = right - left, bottom - top
    return (left + int(w * fx0), top + int(h * fy0),
            left + int(w * fx1), top + int(h * fy1))


def read_console(hwnd: int):
    """``(open|closed|undecided, bright_px)`` from the panel's text box."""
    import numpy as np
    im = grab_box(_console_box(window_rect(hwnd)))
    a = np.asarray(im, dtype=np.int16)
    luma = a.mean(axis=2) if a.ndim == 3 else a
    px = int((luma > CONSOLE_BRIGHT_MIN).sum())
    return classify_console(px), px


def apply_console_observation(state, seen, bright_px: int):
    """Adopt a decisive panel observation; an undecided frame leaves the daemon
    refusing rather than guessing (§54.9 was a belief nothing could correct).

    ``console_sync open|closed`` pins the belief until ``console_sync auto``,
    because this box is calibrated on the main menu and another screen can
    light it for reasons the detector cannot tell apart from the panel.
    """
    if state.get("console_forced"):
        return state.get("console_open")
    state["console_px"] = bright_px
    if state.get("console_open") != seen:
        _log({"event": "console_observed", "open": seen, "px": bright_px})
    state["console_open"] = seen
    return seen


def _gold_rows(mask, ox: int, oy: int):
    import numpy as np
    rowcnt = mask.sum(axis=1)
    ys = np.nonzero(rowcnt > 10)[0]
    runs = []
    for y in ys:
        if runs and y - runs[-1][1] <= 2:
            runs[-1][1] = y
        else:
            runs.append([y, y])
    rows = []
    for y0, y1 in runs:
        band = mask[y0:y1 + 1]
        xs = np.nonzero(band.any(axis=0))[0]
        if xs.size == 0:
            continue
        rows.append({"y0": int(y0) + oy, "y1": int(y1) + oy,
                     "x0": int(xs[0]) + ox, "x1": int(xs[-1]) + ox,
                     "px": int(band.sum())})
    return rows


def _panel_bbox(luma):
    """Best-effort bright-panel bbox in band coordinates, or ``None``.

    Row/column profiles of a high-luma mask; a panel has long, dense runs.
    The choice window is a dark panel, so this is used only to anchor an
    explicit ``dismiss`` and never to decide that a choice window exists.
    """
    import numpy as np
    h, w = luma.shape
    mask = luma > 120
    rows = np.nonzero(mask.sum(axis=1) > max(60, int(w * 0.08)))[0]
    cols = np.nonzero(mask.sum(axis=0) > max(40, int(h * 0.08)))[0]
    if rows.size < 100 or cols.size < 100:
        return None
    bbox = [int(cols[0]), int(rows[0]), int(cols[-1]), int(rows[-1])]
    if bbox[2] - bbox[0] < 300 or bbox[3] - bbox[1] < 250:
        return None
    return bbox


def read_window(hwnd: int):
    """Event-band signals: bright fraction, gold count, gold rows, panel bbox.

    Rows and bbox are in screen coordinates; ``serve`` normalizes a copy to
    the 2160x1440 reference before classification and keeps the raw values
    for clicking.
    """
    import numpy as np
    left, top, right, bottom = window_rect(hwnd)
    w, h = right - left, bottom - top
    x0, y0 = left + int(w * 0.10), top + int(h * 0.15)
    x1, y1 = left + int(w * 0.90), top + int(h * 0.85)
    im = grab_box((x0, y0, x1, y1))
    a = np.asarray(im, dtype=np.int16)
    luma = a.mean(axis=2)
    bright = float((luma > 55).mean())
    r, g, b = a[..., 0], a[..., 1], a[..., 2]
    gold_mask = (r > 110) & (r > b + 50) & (g > 70)
    gold = int(gold_mask.sum())
    rows = _gold_rows(gold_mask, x0, y0)
    bbox = _panel_bbox(luma)
    if bbox is not None:
        bbox = [bbox[0] + x0, bbox[1] + y0, bbox[2] + x0, bbox[3] + y0]
    return {"bright": bright, "gold": gold, "rows": rows, "bbox": bbox}


def _norm_geometry(rows, bbox, gold, rect):
    left, top, right, bottom = rect
    w, h = max(1, right - left), max(1, bottom - top)
    sx, sy = REF_W / w, REF_H / h
    nrows = [{"y0": round((r["y0"] - top) * sy),
              "y1": round((r["y1"] - top) * sy),
              "x0": round((r["x0"] - left) * sx),
              "x1": round((r["x1"] - left) * sx)} for r in rows]
    nbbox = None
    if bbox:
        nbbox = [round((bbox[0] - left) * sx), round((bbox[1] - top) * sy),
                 round((bbox[2] - left) * sx), round((bbox[3] - top) * sy)]
    return nrows, nbbox, int(gold * sx * sy)


def _inside(rect, x, y) -> bool:
    left, top, right, bottom = rect
    return left <= x <= right and top <= y <= bottom


def click_row(hwnd: int, row) -> None:
    rect = window_rect(hwnd)
    x = (row["x0"] + row["x1"]) // 2
    y = (row["y0"] + row["y1"]) // 2
    if not _inside(rect, x, y):
        raise OSError(f"option centre {(x, y)} outside window {rect}")
    if not focus(hwnd):
        raise OSError("focus refused before option click")
    _launch()._click_at(x, y)


def click_close(hwnd: int, bbox) -> None:
    """Click the dialog's top-right glyph: measured offset (96, 51)."""
    rect = window_rect(hwnd)
    x, y = bbox[2] - 96, bbox[1] + 51
    if not (_inside(rect, x, y) and bbox[0] <= x <= bbox[2]
            and bbox[1] <= y <= bbox[3]):
        raise OSError(f"close point {(x, y)} outside dialog {bbox}")
    if not focus(hwnd):
        raise OSError("focus refused before close click")
    _launch()._click_at(x, y)


def speed_label_sha(hwnd: int) -> str:
    import hashlib
    left, top, right, _ = window_rect(hwnd)
    w = right - left
    im = grab_box((left + w - 153, top + 38, left + w - 115, top + 62))
    return hashlib.sha256(im.tobytes()).hexdigest()[:16]


def save_shot(hwnd: int) -> None:
    grab_box(window_rect(hwnd)).save(SHOT_PATH)


def _restore(hwnd: int, restore) -> None:
    """Enforce the commanded state after a handled window.

    A chained window can open the instant the first closes; sending Space then
    would act on the new window, so a detected window defers to the next tick.
    """
    if restore not in ("playing", "paused"):
        return
    state, _, _ = read_pause(hwnd)
    if restore == "paused" and state == "playing":
        press_space(hwnd)
    elif restore == "playing" and state == "paused":
        try:
            stats = read_window(hwnd)
            nrows, nbbox, ngold = _norm_geometry(
                stats["rows"], stats["bbox"], stats["gold"],
                window_rect(hwnd))
        except OSError:
            return
        if classify_window(nrows, nbbox, ngold) != "none":
            return
        press_space(hwnd)


def _log(rec: dict) -> None:
    rotate_log(LOG_PATH)
    rec["t"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _write_status(rec: dict) -> None:
    rec["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    rec["epoch"] = round(time.time(), 3)
    try:
        atomic_write_json(STATUS_PATH, rec)
    except OSError:
        pass


def _read_status():
    try:
        with open(STATUS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _handle_command(cmd, hwnd, state):
    """Apply one parsed command; returns ``(quit_now, one_shot_policy)``."""
    verb = cmd["verb"]
    quit_now = False
    one_shot = None
    if verb == "pause":
        state["want"] = "paused"
        state["resume"] = False
    elif verb == "unpause":
        state["want"] = "playing"
        state["resume"] = True
    elif verb == "want":
        state["want"] = cmd["want"]
        state["resume"] = cmd["want"] == "playing"
    elif verb == "toggle":
        if hwnd and state["paused"] in ("playing", "paused"):
            state["want"] = ("playing" if state["paused"] == "paused" else "paused")
            state["resume"] = state["want"] == "playing"
    elif verb == "policy":
        state["policy"] = cmd["policy"]
    elif verb == "choose":
        one_shot = cmd["policy"]
    elif verb == "quit":
        quit_now = True
    elif verb == "speed" and hwnd:
        before = speed_label_sha(hwnd)
        press_speed(hwnd, cmd["direction"])
        state["console_open"] = None
        time.sleep(0.6)
        state["speed_sha"] = [before, speed_label_sha(hwnd)]
    elif verb == "click" and hwnd:
        rect = window_rect(hwnd)
        if _inside(rect, cmd["x"], cmd["y"]):
            if focus(hwnd):
                _launch()._click_at(cmd["x"], cmd["y"])
                state["console_open"] = None
            else:
                _log({"event": "click_refused", "x": cmd["x"], "y": cmd["y"]})
    elif verb == "console" and hwnd:
        kind, arg = console_send_plan(state)
        if kind == "refuse":
            _log({"event": "console_refused", "hwnd": hwnd, "reason": arg})
        elif not focus(hwnd):
            _log({"event": "console_refused", "hwnd": hwnd, "reason": "focus"})
        elif not _set_clipboard_text(cmd["text"]):
            _log({"event": "console_clipboard_failed", "chars": len(cmd["text"])})
        else:
            for vk, scan, flags, delay in console_key_plan(open_console=arg):
                _send_input_event(vk, scan, flags)
                time.sleep(delay)
            time.sleep(0.3)
            state["console_open"] = True
            _log({"event": "console_sent", "chars": len(cmd["text"]),
                  "opened": arg})
    elif verb == "console_close" and hwnd:
        # The pause key cannot reach the game while the panel is open, so a
        # console the daemon left open needs a way back to a known-closed state.
        if state.get("console_open") is not True:
            _log({"event": "console_refused", "hwnd": hwnd,
                  "reason": "console_state_unknown"})
        elif not focus(hwnd):
            _log({"event": "console_refused", "hwnd": hwnd, "reason": "focus"})
        else:
            for vk, scan, flags, delay in console_tap_plan():
                _send_input_event(vk, scan, flags)
                time.sleep(delay)
            state["console_open"] = False
            _log({"event": "console_closed"})
    elif verb == "console_sync":
        if cmd.get("mode") == "auto":
            state["console_forced"] = False
            _log({"event": "console_sync", "mode": "auto"})
        else:
            state["console_open"] = cmd["open"]
            state["console_forced"] = True
            _log({"event": "console_sync", "console_open": cmd["open"],
                  "forced": True})
    elif verb == "close" and hwnd:
        # WM_CLOSE is the window's own close path (what clicking X does), not
        # TerminateProcess; the plan forbids killing stellaris.exe.
        if not _user32().PostMessageW(hwnd, 0x0010, 0, 0):
            _log({"event": "close_refused", "hwnd": hwnd})
        else:
            _log({"event": "close_posted", "hwnd": hwnd})
    elif verb == "dismiss" and hwnd and state.get("last_bbox") \
            and state.get("paused") == "paused":
        click_close(hwnd, state["last_bbox"])
        state["console_open"] = None
    elif verb == "shot" and hwnd:
        save_shot(hwnd)
        state["shot"] = SHOT_PATH
    elif verb == "unknown":
        _log({"event": "unknown_command", "raw": cmd["raw"]})
    return quit_now, one_shot


def serve(args) -> int:
    _require_windows()
    rng = random.Random()
    state = {"want": "playing", "policy": args.policy, "paused": "unknown",
             "resume": False, "last_bbox": None, "speed_sha": None,
             "shot": None, "console_open": False, "console_forced": False,
             "console_px": None}
    handled = 0
    last_cmd = None
    last_status = 0.0
    last_pid = None
    quit_now = False
    _log({"event": "serve_start", "pid": os.getpid()})
    while not quit_now:
        pid, hwnd = find_game()
        if pid != last_pid:
            # A launched game starts with its console closed; carrying the
            # previous process's belief over would drop the first command.
            state["console_open"] = False
            last_pid = pid
        one_shot = None
        line = read_command(CMD_PATH, CMD_SEEN_PATH)
        cmd = parse_command(line) if line else None
        if cmd:
            last_cmd = line
            _log({"event": "command", "line": line})
            try:
                quit_now, one_shot = _handle_command(cmd, hwnd, state)
            except Exception as e:  # daemon survives one bad command
                _log({"event": "command_error", "line": line, "error": repr(e)})
            if quit_now:
                break
        if not hwnd:
            _write_status({"pid": 0, "hwnd": 0, "state": "no_game",
                           "note": "no_game", "want": state["want"],
                           "policy": state["policy"], "handled": handled,
                           "last_cmd": last_cmd})
            time.sleep(args.interval)
            continue
        try:
            paused, red, green = read_pause(hwnd)
        except OSError as e:
            _write_status({"pid": pid, "hwnd": hwnd, "state": "unknown",
                           "note": f"capture_error: {e}", "want": state["want"],
                           "policy": state["policy"], "handled": handled,
                           "last_cmd": last_cmd})
            time.sleep(args.interval)
            continue
        state["paused"] = paused
        try:
            seen, console_px = read_console(hwnd)
        except OSError:
            seen, console_px = None, -1
        apply_console_observation(state, seen, console_px)
        stats = {"bright": 0.0, "gold": 0, "rows": [], "bbox": None}
        window = "none"
        if paused == "paused":
            paused = reread_after_grace(paused, state["want"], args.grace_s,
                                        lambda: read_pause(hwnd), time.sleep)
            state["paused"] = paused
            if paused == "paused":
                try:
                    stats = read_window(hwnd)
                    rect = window_rect(hwnd)
                except OSError:
                    stats = {"bright": 0.0, "gold": 0, "rows": [], "bbox": None}
                    rect = None
                if rect is not None:
                    if stats["bbox"]:
                        state["last_bbox"] = stats["bbox"]
                    nrows, nbbox, ngold = _norm_geometry(
                        stats["rows"], stats["bbox"], stats["gold"], rect)
                    window = classify_window(nrows, nbbox, ngold)
                    if window == "none":
                        state["last_bbox"] = None
        if window != "choice":
            state["last_sig"] = None
            state["same_hits"] = 0
        if paused == "playing":
            state["resume"] = False
        action, extra = plan_step(state["want"], paused, window,
                                  resume_commanded=state["resume"])
        note = "ok"
        acted = False
        if action == "pause":
            try:
                if send_pause_key(state, hwnd) == "sent":
                    note = "commanded_pause"
                else:
                    note = "pause_blocked_console"
            except OSError as e:
                note = f"pause_failed: {e}"
            time.sleep(0.3)
        elif action == "resume":
            try:
                if send_pause_key(state, hwnd) == "sent":
                    state["resume"] = False
                    note = "commanded_resume"
                else:
                    note = "resume_blocked_console"
            except OSError as e:
                note = f"resume_failed: {e}"
            time.sleep(0.3)
        elif action == "handle_choice":
            rows = stats["rows"]
            sig = tuple((r["y0"], r["x1"]) for r in rows[:4])
            if sig == state.get("last_sig"):
                state["same_hits"] = state.get("same_hits", 1) + 1
            else:
                state["last_sig"] = sig
                state["same_hits"] = 1
            policy = one_shot or state["policy"]
            index = choose_row(policy, rows, rng)
            if index is None:
                note = "choice_unresolved"
            elif state["same_hits"] > 3:
                note = "choice_stuck"
            else:
                try:
                    click_row(hwnd, rows[index])
                    state["console_open"] = None
                    handled += 1
                    acted = True
                    note = f"choice_{index + 1}_of_{len(rows)}"
                    time.sleep(0.4)
                    _restore(hwnd, extra.get("restore"))
                except OSError as e:
                    note = f"choice_click_failed: {e}"
        elif action == "handle_dialog":
            if args.auto_dismiss and stats["bbox"]:
                try:
                    click_close(hwnd, stats["bbox"])
                    state["console_open"] = None
                    acted = True
                    note = "dialog_dismissed"
                    time.sleep(0.4)
                    _restore(hwnd, extra.get("restore"))
                except OSError as e:
                    note = f"dialog_click_failed: {e}"
            else:
                note = "dialog_unknown"
        elif action == "report_paused_no_window":
            note = "paused_no_window"
        elif action == "none" and extra.get("reason") == "unreadable":
            note = "unreadable"
        now = time.time()
        if note != state.get("last_note") or now - last_status >= 1.0:
            last_status = now
            state["last_note"] = note
            _write_status({
                "pid": pid, "hwnd": hwnd, "state": paused, "note": note,
                "want": state["want"], "policy": state["policy"],
                "red": red, "green": green, "handled": handled,
                "window": {"bright": round(stats["bright"], 3),
                           "gold": stats["gold"], "rows": len(stats["rows"]),
                           "bbox": stats["bbox"]},
                "speed_sha": state["speed_sha"], "shot": state["shot"],
                "console_open": state.get("console_open", False),
                "console_px": state.get("console_px"),
                "console_forced": state.get("console_forced", False),
                "last_cmd": last_cmd,
            })
        if acted:
            time.sleep(0.15)
        else:
            time.sleep(args.interval)
    _write_status({"pid": 0, "hwnd": 0, "state": "stopped",
                   "note": "quit", "handled": handled, "last_cmd": last_cmd})
    _log({"event": "serve_stop", "handled": handled})
    return 0


def _status_line(rec) -> str:
    if not rec:
        return "STATUS=absent"
    age = round(time.time() - rec.get("epoch", 0), 1)
    return (f"STATUS={rec.get('state')} note={rec.get('note')} "
            f"pid={rec.get('pid')} hwnd={rec.get('hwnd')} age={age}s "
            f"want={rec.get('want')} policy={rec.get('policy')} "
            f"handled={rec.get('handled')} cmd={rec.get('last_cmd')} "
            f"speed={rec.get('speed_sha')}")


def _delete_task() -> None:
    for verb in ("/end", "/delete"):
        with open(os.devnull, "w") as devnull:
            subprocess.run(["schtasks", verb, "/tn", TASK_NAME, "/f"],
                           stdout=devnull, stderr=devnull)


def is_new_heartbeat(rec, baseline_epoch: float, now: float,
                     max_age: float = 5.0) -> bool:
    """A status written after ``baseline_epoch`` and still fresh.

    ``stop`` leaves a fresh ``stopped`` record behind; without the baseline a
    ``start`` right after it would report that stale record as a success.
    """
    if not rec:
        return False
    epoch = rec.get("epoch", 0)
    return epoch > baseline_epoch and now - epoch < max_age


def cmd_start(args) -> int:
    _require_windows()
    rec = _read_status()
    now = time.time()
    if rec and rec.get("state") != "stopped" and now - rec.get("epoch", 0) < 5:
        print(_status_line(rec))
        return 0
    baseline = rec.get("epoch", 0) if rec else 0
    pythonw = args.pythonw or sys.executable.replace("python.exe", "pythonw.exe")
    atomic_write_text(TASK_SHIM, task_shim_text(pythonw, os.path.abspath(__file__)))
    ru = f"{os.environ.get('COMPUTERNAME', '')}\\{os.environ.get('USERNAME', '')}"
    st = time.strftime("%H:%M", time.localtime(time.time() + 120))
    subprocess.run(["schtasks", "/create", "/tn", TASK_NAME, "/tr", TASK_SHIM,
                    "/sc", "once", "/st", st, "/ru", ru, "/rl", "highest",
                    "/f"], check=True, capture_output=True, text=True)
    subprocess.run(["schtasks", "/run", "/tn", TASK_NAME, "/I"],
                   check=True, capture_output=True, text=True)
    deadline = time.time() + args.timeout_s
    while time.time() < deadline:
        rec = _read_status()
        if is_new_heartbeat(rec, baseline, time.time()):
            print(_status_line(rec))
            return 0
        time.sleep(0.5)
    print("STATUS=timeout")
    return 1


def cmd_stop(args) -> int:
    _require_windows()
    atomic_write_text(CMD_PATH, "quit\n")
    deadline = time.time() + args.timeout_s
    while time.time() < deadline:
        rec = _read_status()
        if rec and rec.get("state") == "stopped":
            _delete_task()
            print(_status_line(rec))
            return 0
        time.sleep(0.5)
    _delete_task()
    print("STATUS=stop_timeout")
    return 1


def cmd_status(args) -> int:
    print(_status_line(_read_status()))
    return 0


def cmd_send(args) -> int:
    _require_windows()
    line = " ".join(args.words).strip()
    if not line:
        print("STATUS=empty_command")
        return 2
    atomic_write_text(CMD_PATH, line + "\n")
    time.sleep(args.wait_s)
    print(_status_line(_read_status()))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="verb", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--interval", type=float, default=0.8)
    s.add_argument("--grace-s", type=float, default=1.2)
    s.add_argument("--policy", default="first")
    s.add_argument("--auto-dismiss", action="store_true")
    start = sub.add_parser("start")
    start.add_argument("--timeout-s", type=int, default=30)
    start.add_argument("--pythonw", default=None)
    sub.add_parser("stop").add_argument("--timeout-s", type=int, default=10)
    sub.add_parser("status")
    c = sub.add_parser("cmd")
    c.add_argument("words", nargs="+")
    c.add_argument("--wait-s", type=float, default=0.8)
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    verbs = {"serve", "start", "stop", "status", "cmd"}
    if argv and argv[0] not in verbs and argv[0] not in ("-h", "--help"):
        # `game pause`, `game choose 2`, ... are command-channel shorthand.
        return cmd_send(argparse.Namespace(words=argv, wait_s=0.8))
    p = build_parser()
    a = p.parse_args(argv)
    if a.verb == "serve":
        return serve(a)
    if a.verb == "start":
        return cmd_start(a)
    if a.verb == "stop":
        return cmd_stop(a)
    if a.verb == "status":
        return cmd_status(a)
    return cmd_send(a)


if __name__ == "__main__":
    sys.exit(main())
