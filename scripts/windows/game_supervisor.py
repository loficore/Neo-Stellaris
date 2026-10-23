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
REF_W, REF_H = 2160, 1440  # spike reference resolution


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


def _send_key_events(vk: int, scan: int, base_flags: int):
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

    user32 = _user32()
    sent = []
    for flags in (base_flags, base_flags | KEYEVENTF_KEYUP):
        ev = INPUT(type=INPUT_KEYBOARD,
                   ki=KEYBDINPUT(wVk=vk, wScan=scan, dwFlags=flags,
                                 time=0, dwExtraInfo=0))
        sent.append(user32.SendInput(1, ctypes.byref(ev), ctypes.sizeof(INPUT)))
        time.sleep(0.08)
    return sent


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
    elif verb == "unpause":
        state["want"] = "playing"
    elif verb == "want":
        state["want"] = cmd["want"]
    elif verb == "toggle":
        if hwnd and state["paused"] in ("playing", "paused"):
            state["want"] = ("playing" if state["paused"] == "paused" else "paused")
    elif verb == "policy":
        state["policy"] = cmd["policy"]
    elif verb == "choose":
        one_shot = cmd["policy"]
    elif verb == "quit":
        quit_now = True
    elif verb == "speed" and hwnd:
        before = speed_label_sha(hwnd)
        press_speed(hwnd, cmd["direction"])
        time.sleep(0.6)
        state["speed_sha"] = [before, speed_label_sha(hwnd)]
    elif verb == "click" and hwnd:
        rect = window_rect(hwnd)
        if _inside(rect, cmd["x"], cmd["y"]):
            if focus(hwnd):
                _launch()._click_at(cmd["x"], cmd["y"])
            else:
                _log({"event": "click_refused", "x": cmd["x"], "y": cmd["y"]})
    elif verb == "dismiss" and hwnd and state.get("last_bbox") \
            and state.get("paused") == "paused":
        click_close(hwnd, state["last_bbox"])
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
             "last_bbox": None, "speed_sha": None, "shot": None}
    handled = 0
    last_cmd = None
    last_status = 0.0
    quit_now = False
    _log({"event": "serve_start", "pid": os.getpid()})
    while not quit_now:
        pid, hwnd = find_game()
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
        stats = {"bright": 0.0, "gold": 0, "rows": [], "bbox": None}
        window = "none"
        if paused == "paused":
            if state["want"] != "paused" and args.grace_s:
                time.sleep(args.grace_s)
                paused, red, green = read_pause(hwnd)
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
        action, extra = plan_step(state["want"], paused, window)
        note = "ok"
        acted = False
        if action == "pause":
            try:
                press_space(hwnd)
                note = "commanded_pause"
            except OSError as e:
                note = f"pause_failed: {e}"
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


def cmd_start(args) -> int:
    _require_windows()
    rec = _read_status()
    if rec and rec.get("state") != "stopped" \
            and time.time() - rec.get("epoch", 0) < 5:
        print(_status_line(rec))
        return 0
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
        if rec and time.time() - rec.get("epoch", 0) < 5:
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


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    verbs = {"serve", "start", "stop", "status", "cmd"}
    if argv and argv[0] not in verbs and argv[0] not in ("-h", "--help"):
        # `game pause`, `game choose 2`, ... are command-channel shorthand.
        return cmd_send(argparse.Namespace(words=argv, wait_s=0.8))
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="verb", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--interval", type=float, default=0.8)
    s.add_argument("--grace-s", type=float, default=1.2)
    s.add_argument("--policy", default="first")
    s.add_argument("--auto-dismiss", action="store_true")
    sub.add_parser("start").add_argument("--timeout-s", type=int, default=30)
    sub.add_parser("start").add_argument("--pythonw", default=None)
    sub.add_parser("stop").add_argument("--timeout-s", type=int, default=10)
    sub.add_parser("status")
    c = sub.add_parser("cmd")
    c.add_argument("words", nargs="+")
    c.add_argument("--wait-s", type=float, default=0.8)
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
