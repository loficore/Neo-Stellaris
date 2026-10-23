"""launch_stellaris — bring up Stellaris via Steam from an unattended SSH session.

See docs/superpowers/specs/2026-09-29-launch-stellaris-design.md for the contract.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import ctypes.wintypes as _wt
import dataclasses
import datetime as _dt
import os
import platform
import subprocess
import sys
import tempfile
import time as _time
import traceback
from typing import Any

import psutil

# Exit codes — see spec §4.
EXIT_OK = 0
EXIT_PREKILL_PERMISSION = 2
EXIT_STEAM_NO_CLIENT = 11
EXIT_STEAM_LOGIN_REQUIRED = 12
EXIT_STELLARIS_UPDATE_REQUIRED = 13
EXIT_LAUNCHER_WINDOW_MISSING = 21
EXIT_LAUNCHER_NO_FOCUS = 22
EXIT_LAUNCHER_NO_ADVANCE = 23
EXIT_LAUNCHER_HANDOFF_STUCK = 24
EXIT_GAME_DID_NOT_SPAWN = 31
EXIT_GAME_EXITED_EARLY = 32
EXIT_JIT_DIALOG = 33
EXIT_WER_DIALOG = 34
# --unpause was requested but the game window could not be found/focused, or
# the Space keystroke was refused (UIPI). The game itself is fine; only the
# optional convenience step failed.
EXIT_GAME_UNPAUSE_FAILED = 35
EXIT_BRIDGE_NO_SESSION = 41
EXIT_BRIDGE_SCHTASKS_DENIED = 42
EXIT_BRIDGE_TIMEOUT = 43
# One code for "the /tr shim payload cannot be delivered to schtasks/cmd":
# over the 261-char ceiling, or not representable in the OEM codepage cmd.exe
# parses .cmd files in. Both are pre-flight checks below — letting schtasks
# reject either produces the opaque 42, and letting cmd.exe misread one
# produces a bare 43.
EXIT_BRIDGE_TR_TOO_LONG = 44
# The inner detected its own outer had stopped listening (the bridge lease file
# vanished) and abandoned the run before doing more harm — see _lease_path.
# Distinct from 43: 43 is the outer giving up on a silent inner, 45 is the
# inner giving up once the outer is provably gone. The abandoned inner writes
# no marker, so this code reaches only the same-session / debug caller.
EXIT_BRIDGE_ABANDONED = 45
EXIT_INTERNAL = 99

# schtasks /create rejects /tr values longer than this with an opaque
# 'cannot be more than 261 characters' error. Measured on Windows_Jiaolong.
SCHTASKS_TR_LIMIT = 261

# Inner chain worst-case phase budgets (seconds) — the bridge default is
# derived from these so a future change to one of them widens the bridge
# automatically. Update test_default_bridge_timeout_reflects_every_phase_budget
# in lockstep with any change here.
_INNER_BUDGET_PREKILL_SPAWN_S = 3     # prekill + steam_spawn worst case (spec §5)
_INNER_BUDGET_STEAM_READY_S = 30      # = --launcher-timeout-s default
_INNER_BUDGET_LAUNCHER_WAIT_S = 30    # = --launcher-timeout-s default
_INNER_BUDGET_LAUNCHER_CLICK_S = 19   # foreground + settle + 3 click/settle rounds
_INNER_BUDGET_GAME_OBSERVE_S = 60     # = --game-timeout-s + --observe-s defaults
_INNER_BUDGET_UNPAUSE_S = 95          # = --unpause-delay-s default + _UNPAUSE_SETTLE_S
_INNER_CHAIN_BUDGET_S = (
    _INNER_BUDGET_PREKILL_SPAWN_S
    + _INNER_BUDGET_STEAM_READY_S
    + _INNER_BUDGET_LAUNCHER_WAIT_S
    + _INNER_BUDGET_LAUNCHER_CLICK_S
    + _INNER_BUDGET_GAME_OBSERVE_S
)  # 142s with all defaults; --unpause adds _INNER_BUDGET_UNPAUSE_S on top
_BRIDGE_TIMEOUT_MARGIN_S = 33          # slack for monitor jitter + log I/O
DEFAULT_BRIDGE_TIMEOUT_S = _INNER_CHAIN_BUDGET_S + _BRIDGE_TIMEOUT_MARGIN_S  # 175s
UNPAUSE_BRIDGE_TIMEOUT_S = (
    _INNER_CHAIN_BUDGET_S + _INNER_BUDGET_UNPAUSE_S + _BRIDGE_TIMEOUT_MARGIN_S
)  # 270s

# Process images this chain looks for. Compared case-insensitively: Windows
# file names are case-insensitive and psutil reports whatever the image has.
LAUNCHER_IMAGE = "Paradox Launcher.exe"
GAME_IMAGE = "stellaris.exe"

# taskkill exit codes, measured on Windows_Jiaolong with the argv _taskkill
# builds. 0 is "killed"; the rest observed there:
TASKKILL_NOT_FOUND_RC = 128
#   128 - "no process with that image name". The accompanying text is English
#         or cp936 depending only on how the process was launched (see
#         prekill); the code is the same either way.
#   255 - "could not be terminated": observed against csrss.exe, which taskkill
#         refuses even for an administrator. A real failure, not an absence.
#    1 - usage/parameter rejection, e.g. an invalid argument or a bad flag.
# Every non-zero code other than 128 is a failure and is reported as
# EXIT_PREKILL_PERMISSION, so a genuine permission problem is never mistaken
# for "already gone".
# A plain ACCESS DENIED from an unelevated token was NOT reproducible here:
# both the SSH token and the bridge's /rl highest token are administrator on
# this box (IsAdmin: True), so probing it risks killing the target process.
# 255 is what taskkill returns for the "could not be terminated" family
# whichever reason it prints.
# mouse_event flags for the left button. The launcher drive clicks, it does not
# type — the CEF launcher (Chrome_WidgetWin_1) ignores Enter/Tab entirely, proven
# on Windows_Jiaolong where the keyboard path always ended in exit 23. See
# launcher_click.
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004

# Where the 「继续」 (Continue) button sits, as a fraction of the launcher window
# rect. The click point is recomputed from a fresh GetWindowRect on every attempt
# so the drive survives the window moving or resizing — this is what makes it
# robust where a raw absolute coordinate is not. Tuned on Windows_Jiaolong in the
# script's own (DPI-aware, physical-pixel) frame against the real maximized
# launcher rect (-11,0,2015,1020): 「继续」 is centered horizontally and sits at
# ~1/3 height, i.e. screen ~(1006,339) = fx 0.502 / fy 0.333. A live click at
# that point booted stellaris.exe within ~5 s. NOTE: once pywinauto/UIA
# initializes, GetWindowRect returns physical pixels; measure fractions in that
# same frame — a DPI-unaware screenshot gives a different (wrong) fraction.
LAUNCHER_CONTINUE_FX = 0.502
LAUNCHER_CONTINUE_FY = 0.333
_CLICK_ATTEMPTS = 3

_FOREGROUND_TIMEOUT_S = 3.0
_FOCUS_SETTLE_S = 1.0
_CLICK_SETTLE_S = 5.0
# A save load lands paused and waits for a keypress. After focusing the game
# window, give the focus a beat to register before the Space goes in.
_UNPAUSE_SETTLE_S = 5.0
_POLL_S = 0.5
_OBSERVE_POLL_S = 1.0

# Space is sent by scancode, never as VK_SPACE. Live on Windows_Jiaolong the
# VK form was accepted by SendInput and silently swallowed before the game saw
# it (the Chinese IME has a context on the game window); the scancode form
# toggled pause on the same window immediately. wVk stays 0 so no layout or IME
# translation happens on the way in.
SPACE_SCANCODE = 0x39
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_SCANCODE = 0x0008
INPUT_KEYBOARD = 1

# psutil status strings that mean the process is no longer running the game.
# 'zombie' is the one psutil actually reports; 'dead' is what a lost handle
# looks like in practice.
_GONE_STATUSES = ("zombie", "dead")

# Marker protocol, for the one channel that survives the bridge. See spec §5a
# step 4. The inner's stderr goes to the schtasks-spawned process tree, so
# the phase timeline rides the marker alongside the exit code and the PID.
#
# LOG: marks a carried line, and that tag is load-bearing: a captured traceback
# or log line that happens to mention DONE:<rc> must not be read back as the
# inner's exit code, and a carried line must never be able to satisfy
# _poll_marker's backward scan.
_MARKER_LOG_PREFIX = "LOG:"
# Bounded tail, not a full log. The outer re-reads the whole marker on every
# 0.5 s poll tick, and the inner logs once per observe tick (30 by default), so
# an unbounded capture turns the marker into the largest file on the box. A full
# chain writes ~20 lines of ~120 chars, so the cap is roughly 10x headroom; the
# tail is kept because the events that end a run are the ones that diagnose it.
_MARKER_TIMELINE_MAX_LINES = 200

# Crash-dialog signals. WER's title markers are substrings, matched
# case-insensitively against both the window text and, when there is none, the
# window class. The images are process names, matched case-insensitively the
# same way psutil reports them.
#
# There is deliberately no JIT title marker. See _is_jit_dialog_visible.
_WER_TITLE_MARKERS = ("problem reporting", "werfault")
_JIT_IMAGE = "vsjitdebugger.exe"
_WER_IMAGE = "werfault.exe"


def _last_error() -> int:
    """ctypes.get_last_error() on Windows, 0 everywhere else.

    The attribute does not exist on Linux, and this module has to import there
    for the host-side unit tests.
    """
    get_last_error = getattr(ctypes, "get_last_error", None)
    return int(get_last_error()) if get_last_error is not None else 0


def timeline_event(phase: str, **fields: Any) -> str:
    """Format one stderr timeline line."""
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = "  ".join(f"{k}={v}" for k, v in fields.items())
    return f"{ts}  {phase}  {parts}" if parts else f"{ts}  {phase}"


def log_event(phase: str, **fields: Any) -> None:
    line = timeline_event(phase, **fields)
    # Collected only while an inner is running (see main); the outer writes to
    # the caller's stderr directly and needs no capture.
    if _active_timeline is not None:
        _active_timeline.add(line)
    print(line, file=sys.stderr, flush=True)


class _Timeline:
    """Bounded tail of the events logged so far, for the marker to carry."""

    def __init__(self, limit: int = _MARKER_TIMELINE_MAX_LINES) -> None:
        self._lines: list[str] = []
        self._limit = limit
        self._dropped = 0

    def add(self, line: str) -> None:
        """Keep `line`, flattened to one line — the marker is a line protocol.

        An embedded newline would write an untagged continuation line into the
        marker, and a continuation that starts with DONE: is exactly what
        _poll_marker's backward scan looks for. Flatten on the way in, with the
        same ' | ' join run_launch_chain's guard uses for its traceback.
        """
        line = line.replace("\n", " | ").replace("\r", " | ")
        if len(self._lines) >= self._limit:
            self._lines.pop(0)
            self._dropped += 1
        self._lines.append(line)

    def lines(self) -> list[str]:
        """The carried lines, oldest first, with a note if any were dropped."""
        if not self._dropped:
            return list(self._lines)
        return [f"... {self._dropped} earlier timeline line(s) dropped "
                f"(cap {_MARKER_TIMELINE_MAX_LINES})"] + list(self._lines)


# Set by main() while the inner chain runs, so log_event knows to collect.
_active_timeline: _Timeline | None = None


class _ArgParser(argparse.ArgumentParser):
    """Resolves --bridge-timeout-s after parsing: its default depends on
    --unpause, which argparse cannot express as another flag's default."""

    def parse_args(self, args=None, namespace=None):
        parsed = super().parse_args(args, namespace)
        if parsed.bridge_timeout_s is None:
            parsed.bridge_timeout_s = (
                UNPAUSE_BRIDGE_TIMEOUT_S if parsed.unpause
                else DEFAULT_BRIDGE_TIMEOUT_S)
        return parsed


def build_arg_parser() -> argparse.ArgumentParser:
    p = _ArgParser(prog="launch_stellaris")
    p.add_argument("--app-id", type=int, default=281990)
    p.add_argument("--launcher-timeout-s", type=int, default=30,
                   help="Steam-ready and launcher-window budget (default 30). "
                        "Raising it above the default may require raising "
                        "--bridge-timeout-s too: the outer derives its own "
                        "budget from the defaults at import time and cannot "
                        "see a non-default inner.")
    p.add_argument("--game-timeout-s", type=int, default=30,
                   help="How long to wait for stellaris.exe to appear after "
                        "the launcher handoff (default 30). Raising it above "
                        "the default may require raising --bridge-timeout-s "
                        "too.")
    p.add_argument("--observe-s", type=int, default=30,
                   help="Post-spawn health observation window (default 30). "
                        "Raising it above the default may require raising "
                        "--bridge-timeout-s too.")
    p.add_argument("--unpause", action="store_true",
                   help="After the observe window, focus the game and press "
                        "Space once. A loaded save starts paused; this is the "
                        "unpause a person would otherwise do by hand. Off by "
                        "default: the keystroke goes to whatever owns the "
                        "foreground.")
    p.add_argument("--unpause-delay-s", type=int, default=90,
                   help="How long to wait after the observe window before the "
                        "unpause keystroke (default 90). Only used with "
                        "--unpause. The default covers a large modded save: "
                        "the game draws its campaign well after handoff, and a "
                        "keypress into the loading screen is lost. Raising it "
                        "above the default may require raising "
                        "--bridge-timeout-s too.")
    p.add_argument("--bridge-timeout-s", type=int, default=None,
                   help="How long the outer waits for the inner's completion "
                        f"marker (default {DEFAULT_BRIDGE_TIMEOUT_S}, or "
                        f"{UNPAUSE_BRIDGE_TIMEOUT_S} with --unpause; derived "
                        "from the phase budgets above it). Raise this whenever "
                        "--launcher-timeout-s, --game-timeout-s, --observe-s "
                        "or --unpause-delay-s is raised past its default, or "
                        "the outer reports 43 before the inner is done.")
    p.add_argument("--inner", action="store_true",
                   help="(bridge only) skip session detection, run launch chain directly")
    p.add_argument("--marker", type=str, default=None,
                   help="(bridge only) path to completion marker file")
    p.add_argument("--lease", type=str, default=None,
                   help="(bridge only) path the outer watches; when it vanishes "
                        "the inner has lost its listener and abandons before the "
                        "next phase. See _lease_path.")
    p.add_argument("--no-prekill", action="store_true", help="debug: skip PREKILL")
    p.add_argument("--dry-run", action="store_true",
                   help="debug: do everything except spawn the URI and click Play")
    p.add_argument("--verbose", action="store_true")
    return p


def _taskkill(image: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["taskkill", "/F", "/IM", image, "/T"],
        capture_output=True, text=True,
    )


def prekill(no_prekill: bool = False) -> int:
    """Kill any stale stellaris.exe and Paradox Launcher.exe. Re-entrant safe.

    Missing processes are OK. Permission errors return EXIT_PREKILL_PERMISSION.

    The absent/killed distinction is made on taskkill's RETURN CODE, never on
    its message. That text is localized, and the localization is not even a
    property of the box: on Windows_Jiaolong one argv, one account and one
    machine printed "ERROR: The process ... not found." when _taskkill ran from
    an SSH shell, and the cp936 "错误: 没有找到进程" when the identical code ran
    as a schtasks task in the bridged session. Matching on text therefore
    depends on how the process happened to be launched, which is how a string
    guessed during planning survived review and then ended the first
    end-to-end run in this very phase. Exit codes do not move.
    """
    if no_prekill:
        log_event("PREKILL", skipped=True)
        return EXIT_OK
    killed = []
    for image in ("stellaris.exe", "Paradox Launcher.exe"):
        r = _taskkill(image)
        if r.returncode == 0:
            killed.append(image)
            continue
        if r.returncode == TASKKILL_NOT_FOUND_RC:
            # The normal crash-recovery state: the game is not running, which is
            # the precondition for relaunching it. Success.
            continue
        log_event("PREKILL", image=image, rc=r.returncode, stderr=r.stderr.strip())
        return EXIT_PREKILL_PERMISSION
    log_event("PREKILL", killed=killed)
    return EXIT_OK


def steam_spawn(app_id: int, dry_run: bool = False) -> int:
    """Fire steam://rungameid/<app_id> via Start-Process. Caller polls for the
    Steam client process afterwards."""
    if dry_run:
        log_event("STEAM_SPAWN", dry_run=True, app_id=str(app_id))
        return EXIT_OK
    uri = f"steam://rungameid/{app_id}"
    # Start-Process goes through ShellExecute, same protocol handler as os.startfile.
    subprocess.run(
        ["powershell", "-NoProfile", "-Command", f"Start-Process '{uri}'"],
        capture_output=True, text=True,
    )
    log_event("STEAM_SPAWN", uri=uri)
    return EXIT_OK


_user32_fns_cache: tuple[Any, Any, Any] | None = None


def _user32_fns() -> tuple[Any, Any, Any]:
    """Bind (EnumWindows, EnumWindowsProc, GetWindowThreadProcessId).

    Bound lazily instead of at module scope: ctypes.WinDLL only exists on
    Windows, and this module must import cleanly on Linux for the host-side
    unit tests. See _session_fns for the same reason.
    """
    global _user32_fns_cache
    if _user32_fns_cache is None:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        enum_windows_proc = ctypes.WINFUNCTYPE(_wt.BOOL, _wt.HWND, _wt.LPARAM)
        enum_windows_proc.argtypes = [_wt.HWND, _wt.LPARAM]
        enum_windows_proc.restype = _wt.BOOL
        enum_windows = user32.EnumWindows
        enum_windows.argtypes = [enum_windows_proc, _wt.LPARAM]
        enum_windows.restype = _wt.BOOL
        get_window_thread_process_id = user32.GetWindowThreadProcessId
        get_window_thread_process_id.argtypes = [_wt.HWND, ctypes.POINTER(_wt.DWORD)]
        get_window_thread_process_id.restype = _wt.DWORD
        _user32_fns_cache = (enum_windows, enum_windows_proc,
                             get_window_thread_process_id)
    return _user32_fns_cache


def _enum_windows_owned_by(pid: int) -> bool:
    """True if any top-level window belongs to `pid`.

    Ownership by PID, deliberately never by window class. Steam's top-level
    window class is whatever its SDL build picks — 'SDL_app' on Windows_Jiaolong,
    'Valve001' elsewhere — so a hardcoded class name silently reports "no
    window" for the whole poll budget. PID ownership has no such dependency.

    NOTE: the callback body must stay exception-free. ctypes swallows anything
    raised inside a WINFUNCTYPE callback, prints it, and reports the call as
    an early stop — so a bug in here silently truncates the walk instead of
    reaching the caller's `except`.
    """
    enum_windows, enum_windows_proc, get_window_thread_process_id = _user32_fns()
    found = False

    @enum_windows_proc
    def _cb(hwnd, _lparam):
        nonlocal found
        owner = _wt.DWORD(0)
        get_window_thread_process_id(hwnd, ctypes.byref(owner))
        if owner.value == pid:
            found = True
            return False  # False stops the EnumWindows walk
        return True

    # EnumWindows returns FALSE both when our callback stops the walk (the
    # `found` path) and when enumeration itself fails. Only the second is an
    # error, and reporting it as "no window" would be the silent 30 s budget
    # burn the PID-ownership fix just eliminated.
    if not enum_windows(_cb, 0) and not found:
        raise OSError(_last_error(), "EnumWindows failed")
    return found


def _steam_has_window(pid: int) -> bool:
    """Best-effort check that the Steam client owning `pid` has a window.

    Fails open: an unexpected binding/enumeration error returns True so a
    probe quirk can never deadlock the launch chain. The failure is logged so
    it stays visible instead of hiding like the class-string bug did.
    """
    if sys.platform != "win32":
        # ctypes.WinDLL is Windows-only. On any other platform assume yes so
        # the production poll loop is not needlessly blocked during local
        # integration tests / cross-platform CI.
        return True
    try:
        return _enum_windows_owned_by(pid)
    except Exception as e:  # noqa: BLE001 — deliberate fail-open, logged below
        log_event("STEAM_WINDOW", pid=pid, error=repr(e))
        return True


def steam_ready(timeout_s: int) -> int | None:
    """Poll for a steam.exe that owns at least one top-level window.

    Returns that PID, or None once the budget is spent.
    """
    deadline = _time.time() + timeout_s
    while _time.time() < deadline:
        for p in psutil.process_iter(["name", "pid"]):
            if p.info["name"] and p.info["name"].lower() == "steam.exe" and _steam_has_window(p.info["pid"]):
                log_event("STEAM_READY", steam_pid=p.info["pid"])
                return p.info["pid"]
        _time.sleep(0.5)
    log_event("STEAM_READY", timeout=True)
    return None


_input_fns_cache: tuple[Any, Any] | None = None


def _input_fns() -> tuple[Any, Any]:
    """Bind (SetForegroundWindow, GetForegroundWindow).

    Bound lazily, same reason as _user32_fns: ctypes.WinDLL does not exist on
    Linux and this module has to import cleanly for the host-side tests.
    """
    global _input_fns_cache
    if _input_fns_cache is None:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        set_foreground_window = user32.SetForegroundWindow
        set_foreground_window.argtypes = [_wt.HWND]
        set_foreground_window.restype = _wt.BOOL
        get_foreground_window = user32.GetForegroundWindow
        get_foreground_window.argtypes = []
        get_foreground_window.restype = _wt.HWND
        _input_fns_cache = (set_foreground_window, get_foreground_window)
    return _input_fns_cache


class _RECT(ctypes.Structure):
    """Win32 RECT. c_long on purpose: the field is a LONG (4 bytes) on every
    Windows build, whereas ctypes.wintypes-based ints vary with the host."""

    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


_cursor_fns_cache: tuple[Any, Any, Any] | None = None


def _cursor_fns() -> tuple[Any, Any, Any]:
    """Bind (GetWindowRect, SetCursorPos, mouse_event), lazily for import.

    The launcher drive clicks rather than types (the CEF launcher ignores
    keyboard input — see launcher_click), so it needs the cursor + rect trio
    instead of SendInput.
    """
    global _cursor_fns_cache
    if _cursor_fns_cache is None:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        get_window_rect = user32.GetWindowRect
        get_window_rect.argtypes = [_wt.HWND, ctypes.POINTER(_RECT)]
        get_window_rect.restype = _wt.BOOL
        set_cursor_pos = user32.SetCursorPos
        set_cursor_pos.argtypes = [ctypes.c_int, ctypes.c_int]
        set_cursor_pos.restype = _wt.BOOL
        mouse_event = user32.mouse_event
        mouse_event.argtypes = [_wt.DWORD, _wt.DWORD, _wt.DWORD,
                               _wt.DWORD, ctypes.c_size_t]
        mouse_event.restype = None
        _cursor_fns_cache = (get_window_rect, set_cursor_pos, mouse_event)
    return _cursor_fns_cache


def _window_rect(hwnd: int) -> tuple[int, int, int, int]:
    """The launcher window's screen rect as (left, top, right, bottom).

    Raises OSError when GetWindowRect fails — a dead or off-screen hwnd. The
    caller turns that into a typed no-focus code rather than letting it escape.
    """
    get_window_rect, _, _ = _cursor_fns()
    rect = _RECT()
    if not get_window_rect(_wt.HWND(hwnd), ctypes.byref(rect)):
        raise OSError(_last_error(), "GetWindowRect failed")
    return (int(rect.left), int(rect.top), int(rect.right), int(rect.bottom))


def _click_at(x: int, y: int) -> None:
    """Move the cursor to (x, y) and click the left button once.

    SetCursorPos + mouse_event rather than SendInput: legacy, but the click a
    synthetic launcher drive needs, with no INPUT-union layout to get wrong on a
    non-Windows import. Raises OSError if SetCursorPos is refused, which is how a
    UIPI-blocked click surfaces instead of becoming a silent no-op.
    """
    _, set_cursor_pos, mouse_event = _cursor_fns()
    if not set_cursor_pos(x, y):
        raise OSError(_last_error(), f"SetCursorPos({x}, {y}) refused")
    mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", _wt.DWORD),
        ("dwFlags", _wt.DWORD),
        ("time", _wt.DWORD),
        ("dwExtraInfo", ctypes.c_void_p),
    ]


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", _wt.WORD),
        ("wScan", _wt.WORD),
        ("dwFlags", _wt.DWORD),
        ("time", _wt.DWORD),
        ("dwExtraInfo", ctypes.c_void_p),
    ]


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", _wt.DWORD),
        ("wParamL", _wt.WORD),
        ("wParamH", _wt.WORD),
    ]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT), ("hi", _HARDWAREINPUT)]


class _INPUT(ctypes.Structure):
    _fields_ = [("type", _wt.DWORD), ("u", _INPUTUNION)]


def _space_key_events() -> list[tuple[int, int, int]]:
    """(wVk, wScan, dwFlags) for the Space down and up events.

    Scancode, not virtual-key — see SPACE_SCANCODE for the live evidence.
    """
    return [
        (0, SPACE_SCANCODE, KEYEVENTF_SCANCODE),
        (0, SPACE_SCANCODE, KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP),
    ]


def _send_space() -> bool:
    """Press and release Space. True when both events were accepted.

    SendInput rather than keybd_event because its return value counts the
    events the input queue took: a UIPI- or desktop-blocked keystroke then
    surfaces as False instead of a silent no-op. Bound lazily — WinDLL does
    not exist on Linux, where this module must still import for the tests.
    """
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    send_input = user32.SendInput
    send_input.argtypes = [_wt.UINT, ctypes.POINTER(_INPUT), ctypes.c_int]
    send_input.restype = _wt.UINT
    events = (_INPUT * 2)()
    for i, (vk, scan, flags) in enumerate(_space_key_events()):
        events[i].type = INPUT_KEYBOARD
        events[i].u.ki = _KEYBDINPUT(wVk=vk, wScan=scan, dwFlags=flags, time=0,
                                     dwExtraInfo=None)
    return send_input(2, events, ctypes.sizeof(_INPUT)) == 2


def _hwnd_for_pid(pid: int) -> int:
    """First top-level HWND owned by `pid`, or 0 when there is none.

    pywinauto is imported inside the function: it is a Windows-only package and
    this module has to import on Linux for the host-side tests. Failures — a
    dead PID, a CEF window that is still spinning up, a missing pywinauto —
    all mean "not yet", and all are logged rather than raised, because
    launcher_wait polls for up to half a minute and a raise there aborts the
    whole chain.
    """
    try:
        import pywinauto.findwindows
        wins = pywinauto.findwindows.find_elements(process=pid)
        return int(wins[0].handle) if wins else 0
    except Exception as e:  # noqa: BLE001 — "not ready yet", retried by the caller
        log_event("LAUNCHER_WINDOW_LOOKUP", pid=pid, error=repr(e))
        return 0


def launcher_wait(timeout_s: int) -> tuple[int, int] | None:
    """Wait for a Paradox Launcher process that owns a window. (pid, hwnd) or None.

    Both halves matter. The process starts well before its CEF window does, and
    on a box running several Paradox games other launchers are already up — so
    a process-only match hands the drive a stale or absent HWND.
    """
    image = LAUNCHER_IMAGE.lower()
    deadline = _time.time() + timeout_s
    while _time.time() < deadline:
        for p in psutil.process_iter(["name", "pid"]):
            info = p.info
            name = info.get("name")
            if name and name.lower() == image:
                hwnd = _hwnd_for_pid(info["pid"])
                if hwnd:
                    log_event("LAUNCHER_WAIT", pid=info["pid"], hwnd=hwnd)
                    return info["pid"], hwnd
        _time.sleep(_POLL_S)
    log_event("LAUNCHER_WAIT", result="timeout", timeout_s=timeout_s)
    return None


def bring_to_foreground(hwnd: int, tag: str = "LAUNCHER_CLICK") -> bool:
    """Raise `hwnd` to the foreground. True once it actually owns it.

    `tag` names the log lines so the launcher click and the game unpause do
    not look alike in the timeline; the default keeps launcher_click's lines
    as they were.
    """
    set_foreground_window, get_foreground_window = _input_fns()
    deadline = _time.time() + _FOREGROUND_TIMEOUT_S
    set_ok = set_foreground_window(hwnd)
    while _time.time() < deadline:
        if get_foreground_window() == hwnd:
            log_event(tag, step="foreground_ok", hwnd=hwnd)
            return True
        _time.sleep(0.1)
    # A refusal (integrity level, wrong desktop, dead hwnd) and a plain
    # timeout are otherwise indistinguishable. SetForegroundWindow's return
    # value and GetLastError are the operator's only evidence, and the
    # locked-desktop case is exactly where they will be reading this line.
    log_event(tag, step="foreground_fail", hwnd=hwnd,
              set_ok=int(set_ok), last_error=_last_error())
    return False


def _handoff_observed() -> bool:
    """True once the launcher has let go: it exited, or the game took over.

    The launcher staying put is the *negative* signal — it means the click did
    not land on the Continue button. Treating it as a handoff would hand the
    next phase a launcher window and no game.
    """
    names = set()
    for p in psutil.process_iter(["name"]):
        name = p.info.get("name")
        if name:
            names.add(name.lower())
    launcher_alive = LAUNCHER_IMAGE.lower() in names
    game_alive = GAME_IMAGE.lower() in names
    return (not launcher_alive) or game_alive


def launcher_click(hwnd: int) -> int:
    """Advance the launcher by clicking 「继续」 (Continue), anchored to the
    window rect. Returns EXIT_OK on handoff, EXIT_LAUNCHER_NO_FOCUS if the window
    cannot be raised or the click cannot be delivered, EXIT_LAUNCHER_NO_ADVANCE
    if every attempt landed and none handed off.

    The launcher is a CEF canvas (Chrome_WidgetWin_1) whose UIA tree exposes a
    single empty Pane — no controls to invoke — and it ignores Enter/Tab outright
    (proven on Windows_Jiaolong, where the keyboard path always ended in 23). A
    click is the only channel that works. To stay robust against the window
    moving or being resized mid-run, the button is addressed as a fraction of the
    window rect and the rect is re-read on every attempt: never a fixed screen
    coordinate.

    An OSError from GetWindowRect or SetCursorPos (a dead hwnd, a UIPI-blocked
    click) is reported as NO_FOCUS rather than allowed to escape: it would exit
    main() with an undocumented code 1, and return before _write_marker runs, so
    the outer bridge would learn nothing and report its own timeout instead.
    """
    try:
        if not bring_to_foreground(hwnd):
            return EXIT_LAUNCHER_NO_FOCUS
        _time.sleep(_FOCUS_SETTLE_S)

        for attempt in range(1, _CLICK_ATTEMPTS + 1):
            left, top, right, bottom = _window_rect(hwnd)
            x = int(left + LAUNCHER_CONTINUE_FX * (right - left))
            y = int(top + LAUNCHER_CONTINUE_FY * (bottom - top))
            _click_at(x, y)
            log_event("LAUNCHER_CLICK", step="click", attempt=attempt,
                      x=x, y=y, rect=(left, top, right, bottom))
            _time.sleep(_CLICK_SETTLE_S)
            if _handoff_observed():
                log_event("LAUNCHER_CLICK", step="handoff_after_click",
                          attempt=attempt)
                return EXIT_OK
        return EXIT_LAUNCHER_NO_ADVANCE
    except OSError as e:
        log_event("LAUNCHER_CLICK", step="click_blocked", error=repr(e))
        return EXIT_LAUNCHER_NO_FOCUS


def launcher_handoff(timeout_s: int) -> int | None:
    """Wait for the launcher to hand off to the game. Returns stellaris.exe's PID.

    Separate from launcher_click on purpose: that phase stops at the first
    handoff *signal*, which launcher_click's own _handoff_observed also
    fires on the launcher simply exiting. This one waits for the thing the
    caller actually needs — a PID it can watch.
    """
    image = GAME_IMAGE.lower()
    deadline = _time.time() + timeout_s
    while _time.time() < deadline:
        for p in psutil.process_iter(["name", "pid"]):
            name = p.info.get("name")
            if name and name.lower() == image:
                log_event("LAUNCHER_HANDOFF", stellaris_pid=p.info["pid"])
                return p.info["pid"]
        _time.sleep(_POLL_S)
    log_event("LAUNCHER_HANDOFF", result="timeout", timeout_s=timeout_s)
    return None


def _top_windows() -> list[tuple[int, str]]:
    """[(pid, window title or class), ...] for top-level windows on the desktop.

    Uses pywinauto's UIA Desktop rather than an EnumWindows walk because it
    spans processes: the dialogs we hunt for (JIT, WER) are owned by processes
    this chain knows nothing about.

    INVARIANT — this returns [] from session 0 and real windows only from the
    interactive window station. Session 0 has its own window station and sees
    none of the user's desktop, which is why every call here happens inside
    the bridged inner. Do not "optimize" this into an EnumWindows call that
    looks tidier and returns nothing: that is exactly the failure already
    fixed for _enum_windows_owned_by.

    Fails soft to [] — pywinauto is a Windows-only package and this module
    has to import on Linux for the host-side suite, so a missing package or a
    dead handle must not abort the observe loop.
    """
    try:
        from pywinauto import Desktop
        out = []
        skipped = 0
        for w in Desktop(backend="uia").windows():
            try:
                out.append((w.process_id(), w.window_text() or w.class_name()))
            except Exception as e:  # noqa: BLE001 — one dead handle must not end the scan
                skipped += 1
                if skipped == 1:
                    # Log the first, not every: a window that closes between
                    # enumeration and access is routine on a live desktop, and
                    # per-window logging would drown the observe timeline.
                    log_event("GAME_WINDOWS", step="window_skipped", error=repr(e))
                continue
        if skipped:
            log_event("GAME_WINDOWS", step="scan_complete", windows=len(out),
                      skipped=skipped)
        return out
    except Exception as e:  # noqa: BLE001 — "nothing observable", retried by the caller
        log_event("GAME_WINDOWS", error=repr(e))
        return []


def _is_jit_dialog_visible() -> bool:
    """True if a Just-In-Time debugger is running — i.e. a crash dialog is up.

    The vsjitdebugger.exe process is the whole of this check. It is the only
    signal that is both locale-independent and tied to something alive, and a
    title is neither.

    Verified on Windows_Jiaolong rather than assumed: HKLM\\SOFTWARE\\Microsoft\\
    Windows NT\\CurrentVersion\\AeDebug\\Debugger is
        "C:\\Windows\\system32\\vsjitdebugger.exe" -p %ld -e %ld -j 0x%p
    and running that image with those arguments leaves the process alive. The
    OS spawns it only when a process takes an unhandled exception, so its
    presence means a JIT event and nothing else — no "a debugger is installed"
    false positive the way devenv.exe would be. It is also not localized: on
    this zh-CN box the dialog's own title is rendered in the Visual Studio UI
    language and never contains "just-in-time debugger".

    WHY THERE IS NO TITLE FALLBACK ANY MORE. There was one, and it fired on a
    healthy launch. csrss.exe hosts the window, and it outlives whatever drew
    the title, so once the debugger process behind a prompt is gone the window
    remains, still titled "Visual Studio Just-In-Time Debugger", owned by pid
    1176 on this box with no vsjitdebugger.exe anywhere. On the first
    game_observe tick that returned EXIT_JIT_DIALOG — the agent told the game
    had crashed while it was loading perfectly well, with the PID withheld.
    Spec §4 gives 33 the meaning "a crash dialog is up right now, refuse and
    report", and an orphaned shell of one is not that.

    The capability the fallback was meant to buy — a box whose AeDebug points at
    some other debugger image — is genuinely given up, because a window owned by
    a different image is indistinguishable from the orphan above without
    guessing. The process name stays a named constant, so pointing it at
    another image is a one-line change.

    A vsjitdebugger.exe left over from an unrelated earlier crash is a false
    positive that costs one spurious EXIT_JIT_DIALOG — the same cheap
    direction the WER check already fails in, because the alternative is
    reporting a crashed game as a healthy one. PREKILL does not reap it, on
    the same footing as WerFault.exe.
    """
    for p in psutil.process_iter(["name"]):
        name = p.info.get("name")
        if name and name.lower() == _JIT_IMAGE:
            return True
    return False


def _is_wer_dialog_visible(windows: list[tuple[int, str]] | None = None) -> bool:
    """True if Windows Error Reporting is up. The WerFault.exe process is the
    locale-independent signal; the title match is a fallback for a report
    dialog hosted inside another process.

    A WerFault.exe left over from an unrelated earlier crash is a false
    positive, and costs one spurious EXIT_WER_DIALOG. That is the cheap
    direction to fail in: the alternative is reporting a crashed game as a
    healthy one.
    """
    for p in psutil.process_iter(["name"]):
        name = p.info.get("name")
        if name and name.lower() == _WER_IMAGE:
            return True
    for _, title in _top_windows() if windows is None else windows:
        lowered = title.lower()
        if any(m in lowered for m in _WER_TITLE_MARKERS):
            return True
    return False


def game_observe(pid: int, observe_s: int) -> int:
    """Watch the game for observe_s seconds. Returns a typed exit code.

    "Healthy" is process-still-running with no JIT or WER dialog — the spec's
    definition, deliberately not a CPU-time delta: Stellaris sits still for
    5-10 s while loading, and a CPU check would call a healthy load a crash.

    Does not raise. Every psutil and pywinauto call in here can fail on a
    process that dies mid-sample, and an exception escaping would be caught by
    run_launch_chain's blanket guard and reported as EXIT_INTERNAL — losing
    the real cause. A dead process is 32, not 99.
    """
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        # Died between handoff and the first sample. 32, not 99.
        log_event("GAME_OBSERVE", step="no_such_process", pid=pid)
        return EXIT_GAME_EXITED_EARLY

    deadline = _time.time() + observe_s
    while _time.time() < deadline:
        try:
            status = proc.status()
            alive = proc.is_running()
        except psutil.NoSuchProcess:
            log_event("GAME_OBSERVE", step="no_such_process", pid=pid)
            return EXIT_GAME_EXITED_EARLY
        if not alive or status in _GONE_STATUSES:
            log_event("GAME_OBSERVE", step="exited", status=status)
            return EXIT_GAME_EXITED_EARLY
        # The JIT probe is process-based and scans on its own — see
        # _is_jit_dialog_visible, which no longer reads the desktop. Only WER
        # still needs a snapshot, and it takes exactly one per tick.
        if _is_jit_dialog_visible():
            log_event("GAME_OBSERVE", step="jit_dialog")
            return EXIT_JIT_DIALOG
        if _is_wer_dialog_visible(_top_windows()):
            log_event("GAME_OBSERVE", step="wer_dialog")
            return EXIT_WER_DIALOG
        _time.sleep(_OBSERVE_POLL_S)
    log_event("GAME_OBSERVE", step="ok", pid=pid, alive_s=observe_s)
    return EXIT_OK


def game_unpause(pid: int, delay_s: int) -> int:
    """Focus the running game and press Space once to leave the paused state.

    Loading a save through the launcher lands paused. This step is opt-in
    (--unpause): the keystroke goes to whatever owns the foreground, so it
    must never be part of a default launch. Waits delay_s first — the game
    keeps streaming during load, and a keypress into the loading screen does
    not reach the game's pause toggle.

    Returns EXIT_OK or EXIT_GAME_UNPAUSE_FAILED; never raises. A missing
    window, a refused focus and a blocked SendInput are the three ways this
    fails, and each is logged before the typed code goes back.
    """
    log_event("GAME_UNPAUSE", step="waiting", pid=pid, delay_s=delay_s)
    _time.sleep(delay_s)
    hwnd = _hwnd_for_pid(pid)
    if not hwnd:
        log_event("GAME_UNPAUSE", step="no_window", pid=pid)
        return EXIT_GAME_UNPAUSE_FAILED
    if not bring_to_foreground(hwnd, tag="GAME_UNPAUSE"):
        log_event("GAME_UNPAUSE", step="no_focus", pid=pid, hwnd=hwnd)
        return EXIT_GAME_UNPAUSE_FAILED
    _time.sleep(_UNPAUSE_SETTLE_S)
    if not _send_space():
        log_event("GAME_UNPAUSE", step="keystroke_refused", pid=pid, hwnd=hwnd,
                  last_error=_last_error())
        return EXIT_GAME_UNPAUSE_FAILED
    log_event("GAME_UNPAUSE", step="ok", pid=pid, hwnd=hwnd)
    return EXIT_OK


_session_fns_cache: tuple[Any, Any, Any] | None = None


def _session_fns() -> tuple[Any, Any, Any]:
    """Bind (GetCurrentProcessId, ProcessIdToSessionId, WTSGetActiveConsoleSessionId).

    Bound lazily instead of at module scope: ctypes.WinDLL only exists on
    Windows, and this module must import cleanly on Linux for the host-side
    unit tests. Only the command builders are exercised there.
    """
    global _session_fns_cache
    if _session_fns_cache is None:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_current_process_id = k32.GetCurrentProcessId
        get_current_process_id.restype = _wt.DWORD
        get_current_process_id.argtypes = []
        process_id_to_session_id = k32.ProcessIdToSessionId
        # POINTER lives on ctypes, not ctypes.wintypes.
        process_id_to_session_id.argtypes = [_wt.DWORD, ctypes.POINTER(_wt.DWORD)]
        process_id_to_session_id.restype = _wt.BOOL
        wts_get_active_console_session_id = k32.WTSGetActiveConsoleSessionId
        wts_get_active_console_session_id.restype = _wt.DWORD
        wts_get_active_console_session_id.argtypes = []
        _session_fns_cache = (get_current_process_id, process_id_to_session_id,
                              wts_get_active_console_session_id)
    return _session_fns_cache


def current_session_id() -> int:
    get_current_process_id, process_id_to_session_id, _ = _session_fns()
    out = _wt.DWORD(0)
    process_id_to_session_id(get_current_process_id(), ctypes.byref(out))
    return int(out.value)


def interactive_session_id() -> int:
    """The session of the user logged on at the console. 0 if there is none."""
    return int(_session_fns()[2]())


def _login_user() -> str:
    """The interactive user from the OS, when $USERNAME is not set.

    GetUserNameW returns the user of the calling thread's access token. Empty
    string on any failure — including the non-Windows import path, where
    ctypes.windll does not exist. The caller turns that into a loud ValueError
    rather than a guessed principal.
    """
    try:
        advapi32 = ctypes.windll.advapi32
        size = _wt.DWORD(256)
        buf = ctypes.create_unicode_buffer(size.value)
        if advapi32.GetUserNameW(buf, ctypes.byref(size)):
            return buf.value or ""
    except Exception:  # noqa: BLE001 — no windll on the host, no name on failure
        return ""
    return ""


def build_bridge_account(computer: str | None = None, user: str | None = None) -> str:
    """The run-as account for the bridge task: <machine>\\<user>.

    COMPUTERNAME, deliberately not USERDOMAIN: on a standalone box USERDOMAIN is
    the workgroup name (WORKGROUP on Windows_Jiaolong), which schtasks cannot
    resolve to a SID — it rejects it with 'No mapping between account names and
    security IDs'. COMPUTERNAME is the prefix `whoami` prints, so it resolves.

    There is no fallback identity. A guessed `machine\\user` that does not exist
    on the box schedules a task whose principal cannot be resolved, and schtasks
    reports that much later and opaquely; failing here, before any task is
    created, names the real problem.
    """
    computer = (computer or os.environ.get("COMPUTERNAME")
                or os.environ.get("USERDOMAIN") or platform.node())
    # USERNAME is what Windows sets; USER/LOGNAME is what a POSIX login sets.
    # Reading the ambient environment is not the guessed identity M-5 removed —
    # it is the real one the shell already carries. On the overnight box USERNAME
    # is always present, so the POSIX names only ever resolve on a host running
    # these unit tests.
    user = (user or os.environ.get("USERNAME") or os.environ.get("USER")
            or os.environ.get("LOGNAME") or _login_user())
    if not computer or not user:
        raise ValueError(
            "cannot determine the bridge run-as account: "
            f"computer={computer!r} user={user!r}; set COMPUTERNAME and USERNAME "
            "(or run where GetUserNameW can resolve the interactive user).")
    return f"{computer}\\{user}"


def build_bridge_task_command(task_name: str, tr: str, st_hhmm: str, ru: str) -> list[str]:
    """The schtasks /create argv for an interactive-session run-as-user task.

    Note: the legacy schtasks.exe on Windows 10/11 does NOT recognize /it. The
    /ru <user> /rl highest pair is what actually runs the task in that user's
    interactive session. /st must be HH:MM in the near future."""
    return [
        "schtasks", "/create", "/tn", task_name,
        "/tr", tr,
        "/sc", "once", "/st", st_hhmm,
        "/ru", ru,
        "/rl", "highest",
        "/f",
    ]


def build_bridge_run_command(task_name: str) -> list[str]:
    """/I is legacy schtasks "ignore schedule constraints, run now"."""
    return ["schtasks", "/run", "/tn", task_name, "/I"]


def _delete_bridge_task(task_name: str) -> None:
    """Stop and remove the one-shot task. Best effort on both halves.

    /delete removes the task *definition*, not a running instance: a task that
    has already started keeps running as an orphan, and that orphan then walks
    its own PREKILL (killing whatever the caller's retry just started) and types
    into the retry's window. /end is what stops the live instance, so it goes
    first. Each call swallows OSError — schtasks may be missing, and a second
    exception out of a cleanup path would replace the real cause with a
    traceback.
    """
    for verb in ("/end", "/delete"):
        with contextlib.suppress(OSError):
            subprocess.run(["schtasks", verb, "/tn", task_name, "/f"],
                           capture_output=True, text=True)


def _default_marker_path(pid: int) -> str:
    """Path of the completion marker file. Short by design: this string gets
    forwarded into the inner command line and carried into /tr, where every
    character counts toward schtasks' 261-char ceiling.

    The 6-hex-char nonce is what stops a recycled PID from landing a new run on
    a stillborn run's DONE: file. It stays 3 bytes precisely so the marker path
    — which is what /tr carries, via the shim — keeps well under the ceiling.
    """
    return os.path.join(
        tempfile.gettempdir(), f"ls_{pid}_{os.urandom(3).hex()}.txt")


def _lease_path(marker: str) -> str:
    """The outer's liveness signal, alongside the marker it is derived from.

    The inner cannot see the outer's process (it lives in the bridged session's
    schtasks tree), so the outer creates this file before it schedules the task
    and removes it on every return path. Its disappearance is the only thing
    the inner can poll to learn the outer gave up — see
    _run_launch_chain_phases for the abandonment check.
    """
    return marker + ".lease"


def _create_lease(lease: str) -> None:
    with open(lease, "w", encoding="utf-8"):
        pass


def _remove_lease(lease: str) -> None:
    """Best effort: the file is already gone on the paths that matter (the
    inner saw it vanish), so a second removal failing is not a reason to fail
    the run — but on the timeout path this is what makes the orphan stop."""
    with contextlib.suppress(OSError):
        os.remove(lease)


def write_bridge_tr_shim(task_name: str, inner_command: str,
                         tempdir: str | None = None) -> str:
    """Write the /tr shim: a .cmd file that runs `inner_command`.

    schtasks rejects a /tr value over 261 characters. The inline inner command
    line is far longer than that, but its length is not a property of this file:
    it is dominated by two absolute paths — the python interpreter and this
    script — so a literal character count here would be wrong on the next box.
    Pointing /tr at a short path to a .cmd shim sidesteps the ceiling entirely.

    The shim starts with `@echo off` so cmd.exe's own banner doesn't drown
    the inner chain's stderr timeline. Returns the shim path; the caller is
    responsible for removing it on every exit path via _delete_bridge_shim.
    """
    tempdir = tempdir or tempfile.gettempdir()
    shim_path = os.path.join(tempdir, f"{task_name}.cmd")
    with open(shim_path, "w", encoding="utf-8", newline="") as f:
        f.write("@echo off\r\n")
        f.write(inner_command + "\r\n")
    return shim_path


def _delete_bridge_shim(shim_path: str) -> None:
    """Best-effort: a leftover shim is a nuisance, never a reason to fail.

    Mirrors _delete_bridge_task. Both call sites in bridge_to_interactive_session
    must invoke this alongside _delete_bridge_task to keep tempdir tidy.
    """
    with contextlib.suppress(OSError):
        os.remove(shim_path)


def _validate_tr_length(tr: str) -> int | None:
    """Pre-flight check on the /tr value before handing it to schtasks.

    Returns None if `tr` fits in the 261-char ceiling, otherwise returns
    EXIT_BRIDGE_TR_TOO_LONG (44). Letting schtasks fail opaquely is what
    produces the misleading EXIT_BRIDGE_SCHTASKS_DENIED (42) — 42 is
    reserved for genuine /create or /run rejections like 'Access is denied'.
    """
    if len(tr) > SCHTASKS_TR_LIMIT:
        log_event("BRIDGE", step="tr_too_long",
                  length=len(tr), limit=SCHTASKS_TR_LIMIT)
        return EXIT_BRIDGE_TR_TOO_LONG
    return None


def _validate_shim_payload(inner_command: str) -> int | None:
    """Reject a shim body cmd.exe cannot read back byte-for-byte.

    write_bridge_tr_shim writes UTF-8 with no BOM, but cmd.exe parses a .cmd
    in the OEM codepage — cp936 on the target box. A CJK character in the
    python path, the script path or the marker path arrives as mojibake, the
    inner never runs, and the run ends as a bare EXIT_BRIDGE_TIMEOUT (43)
    naming none of the real cause. Returns None when the payload is plain
    ASCII, otherwise the typed EXIT_BRIDGE_TR_TOO_LONG (44).
    """
    if not inner_command.isascii():
        log_event("BRIDGE", step="shim_payload_non_ascii",
                  length=len(inner_command))
        return EXIT_BRIDGE_TR_TOO_LONG
    return None


def build_inner_tr(args: argparse.Namespace, marker: str,
                   python: str | None = None,
                   script: str | None = None,
                   lease: str | None = None) -> str:
    """The inner command line — the *body* of the /tr shim, not the /tr value.

    /tr itself receives a short path to a .cmd file (see
    write_bridge_tr_shim); schtasks rejects a /tr over 261 characters and
    this string exceeds that by default. Do not "fix" that ceiling by
    trimming flags out of this string — the shim exists precisely so they
    can all stay.

    The inner is a *separate process* and only knows the flags spelled out
    here. Forwarding every user-settable flag — not just the three that were
    needed when this was first written — is what stops `--launcher-timeout-s
    300` from silently reverting to the 30 s default inside the bridged run.
    Forwarding the defaults too keeps the inner's view pinned to what the
    outer actually parsed, so the two can never drift.
    """
    python = python or sys.executable
    script = script or os.path.abspath(__file__)
    parts = [
        f'"{python}"', f'"{script}"',
        "--inner",
        "--marker", f'"{marker}"',
        "--app-id", str(args.app_id),
        "--launcher-timeout-s", str(args.launcher_timeout_s),
        "--game-timeout-s", str(args.game_timeout_s),
        "--observe-s", str(args.observe_s),
        # Forwarded with its default too, for the same pinned-view reason as
        # the timeouts; --unpause itself only when requested.
        "--unpause-delay-s", str(args.unpause_delay_s),
        # The inner never bridges, so this one is inert there; forwarding it
        # anyway means a future inner-side bridge needs no change here.
        "--bridge-timeout-s", str(args.bridge_timeout_s),
    ]
    if args.unpause:
        parts.append("--unpause")
    if args.no_prekill:
        parts.append("--no-prekill")
    if args.dry_run:
        parts.append("--dry-run")
    if args.verbose:
        parts.append("--verbose")
    if lease is not None:
        parts.append("--lease")
        parts.append(f'"{lease}"')
    return " ".join(parts)


def _poll_marker(marker: str, timeout_s: float) -> str | None:
    """Poll the marker file for a final 'DONE:<int>' line. Returns the line or None."""
    deadline = _time.time() + timeout_s
    while _time.time() < deadline:
        if os.path.exists(marker):
            try:
                with open(marker, encoding="utf-8") as f:
                    content = f.read()
            except OSError:
                content = ""
            for line in reversed(content.splitlines()):
                if line.startswith("DONE:"):
                    return line
        _time.sleep(0.5)
    return None


def _read_marker_pid(marker: str) -> int | None:
    """The game's PID from the marker's PID: line, or None when there is none.

    A separate read from _poll_marker rather than a richer return, because
    test_marker_round_trip_carries_inner_exit_code pins _poll_marker to the
    bare 'DONE:<rc>' string and the bridge's exit-code split depends on it.

    A missing marker, a torn 'PID:' line, a marker written by a failed inner
    and a marker with no PID: line at all all mean the same thing — no PID to
    report — so none of them raise. 0 is rejected for the same reason: it is
    never a real process, and handing it to the caller would parse cleanly
    while naming nothing.
    """
    try:
        with open(marker, encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return None
    for line in reversed(content.splitlines()):
        if line.startswith("PID:"):
            try:
                pid = int(line.split(":", 1)[1])
            except ValueError:
                return None
            return pid if pid > 0 else None
    return None


def _read_marker_timeline(marker: str) -> list[str]:
    """The inner's stderr lines the marker carries, de-tagged and in order.

    Tolerates everything a legacy or hand-written marker can be: missing file
    (OSError), no LOG: lines at all, a line the previous run truncated. The
    outer mirrors whatever it gets, and none of those cases is a reason to
    change the exit code the bridge already parsed.
    """
    try:
        with open(marker, encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return []
    return [line[len(_MARKER_LOG_PREFIX):]
            for line in content.splitlines()
            if line.startswith(_MARKER_LOG_PREFIX)]


def _mirror_inner_timeline(marker: str) -> None:
    """Print the carried timeline on the outer's stderr, verbatim.

    Verbatim so the caller's log reads as one continuous run: the inner's own
    timestamps interleave with the outer's BOOT/BRIDGE lines instead of the
    phases appearing only as a summary, or not at all.
    """
    for line in _read_marker_timeline(marker):
        print(line, file=sys.stderr, flush=True)


def _write_marker(marker: str, code: int, pid: int | None = None,
                  timeline: list[str] | tuple[str, ...] = ()) -> None:
    """Signal the waiting outer process that the inner chain finished.

    Line order is the contract: LOG: lines first, then PID:<pid> when the chain
    has a game to hand back, then DONE:<rc>. DONE: keeps its exact spelling and
    its position as the last line — _poll_marker finds it with a backward scan
    and the bridge splits on it, so neither its name nor its order may drift.
    The LOG: tag is what keeps a carried line from ever satisfying that scan.
    PID: is additive, and deliberately absent when there is no PID: "PID:
    present" has to keep meaning "the game is up", which rules out writing one
    for a failed observe window or a --dry-run.

    Written last and through one open/close so every line lands together; no
    DONE: line means timeout, which is the correct signal for an inner that
    died mid-chain.
    """
    try:
        with open(marker, "w", encoding="utf-8") as f:
            for line in timeline:
                f.write(f"{_MARKER_LOG_PREFIX}{line}\n")
            if pid is not None:
                f.write(f"PID:{pid}\n")
            f.write(f"DONE:{code}\n")
    except OSError as e:
        log_event("MARKER", error=str(e))


def bridge_to_interactive_session(args: argparse.Namespace) -> int:
    """Run the rest of the chain in the logged-on user's interactive session.

    If already in that session, run the chain inline (the inner launches
    immediately) and return its exit code. Otherwise schedule a one-shot task
    via schtasks /create ... /ru <user> /rl highest + schtasks /run /I, poll
    the marker, clean up, and return the inner's exit code.
    """
    my_sid = current_session_id()
    target_sid = interactive_session_id()
    # Two spellings of "nobody to bridge into": 0 is the services window
    # station, 0xFFFFFFFF is WTSGetActiveConsoleSessionId's "no console session
    # at all" — the post-reboot, nobody-logged-in box. Reading the latter as a
    # real session id would schedule into nothing and burn --bridge-timeout-s
    # before reporting 43 instead of 41.
    if target_sid == 0 or target_sid == 0xFFFFFFFF:
        log_event("BRIDGE", result="no_interactive_session", target_sid=target_sid)
        return EXIT_BRIDGE_NO_SESSION
    if my_sid == target_sid:
        log_event("BRIDGE", result="noop", sid=target_sid)
        return run_launch_chain(args)

    # Generate a unique task name + marker. The marker path is forwarded into
    # /tr via the shim, so keep it short.
    pid = os.getpid()
    ts = int(_time.time())
    task_name = f"stellaris-launch-{pid}-{ts}"
    marker = args.marker or _default_marker_path(pid)
    lease = _lease_path(marker)

    # Destroy anything already at the marker path *before* scheduling the
    # inner, not just after it finishes. A marker leaked by a killed outer
    # plus Windows PID reuse puts the new outer's path on the old file, and
    # _poll_marker would then read the old DONE: on its first tick — exit 0
    # carrying the previous run's PID, which is the value the caller feeds to
    # the DLL attach. Cleared here rather than at poll time so every exit path
    # below leaves no stale marker for the next run to trip over.
    #
    # A nonce in the default path would not cover this: --marker is part of
    # the documented CLI, and a caller-supplied path is the one that needs the
    # guarantee most.
    if os.path.exists(marker):
        log_event("BRIDGE", step="stale_marker_cleared", marker=marker)
        with contextlib.suppress(OSError):
            os.remove(marker)

    # Build the inner command line and write the /tr shim. schtasks refuses a
    # /tr over 261 chars; the inline command is longer than that on any real
    # box, so /tr carries a short path to a .cmd shim holding the same command.
    inner_command = build_inner_tr(args, marker, lease=lease)
    # Pre-flight: the shim body has to survive cmd.exe's OEM codepage round
    # trip, or the inner silently never runs and we report a bare 43.
    if (bad_payload := _validate_shim_payload(inner_command)) is not None:
        return bad_payload
    shim_path = write_bridge_tr_shim(task_name, inner_command)

    # Pre-flight: if the shim path is still over the 261-char ceiling (only
    # possible on a box with a pathologically long tempdir), fail loudly with
    # a typed exit code rather than letting schtasks reject it opaquely.
    if (tr_too_long := _validate_tr_length(shim_path)) is not None:
        _delete_bridge_shim(shim_path)
        return tr_too_long

    # /st = HH:MM in the near future (schtasks needs a future scheduled time even
    # with /I on some Windows builds; 1 minute out is enough).
    future = _dt.datetime.now() + _dt.timedelta(minutes=1)
    st_str = future.strftime("%H:%M")
    ru = build_bridge_account()

    # A1: the lease is the inner's only proof that someone is still listening.
    # Create it now — after every pre-flight bail above (none of which may leave
    # a lease behind) and before the task can start (so no phase ever runs
    # without one) — and remove it in the finally below, which fires on every
    # path including a timeout. A vanished lease then unambiguously means "the
    # outer gave up", which is what stops an orphaned inner before its next
    # harmful phase.
    _create_lease(lease)
    task_scheduled = False
    try:
        create = subprocess.run(
            build_bridge_task_command(task_name, shim_path, st_str, ru),
            capture_output=True, text=True,
        )
        if create.returncode != 0:
            log_event("BRIDGE", step="create", rc=create.returncode,
                      stderr=create.stderr.strip())
            # A /create that fails partway can still have registered the task.
            # Mirror the run-failure branch below: clean up before returning.
            _delete_bridge_task(task_name)
            return EXIT_BRIDGE_SCHTASKS_DENIED

        task_scheduled = True
        run = subprocess.run(build_bridge_run_command(task_name),
                             capture_output=True, text=True)
        if run.returncode != 0:
            log_event("BRIDGE", step="run", rc=run.returncode,
                      stderr=run.stderr.strip())
            _delete_bridge_task(task_name)
            return EXIT_BRIDGE_SCHTASKS_DENIED

        log_event("BRIDGE", task=task_name, marker=marker, shim=shim_path)
        done = _poll_marker(marker, args.bridge_timeout_s)
        # Mirror the inner's timeline before anything below deletes the marker:
        # without it the caller sees BOOT + BRIDGE + MARKER and no phase at all
        # (spec §5a step 4). Printed whether or not DONE: arrived — a run that
        # died mid-chain is exactly when its phases are worth reading.
        _mirror_inner_timeline(marker)
        # Read the PID before the cleanup below deletes the marker. DONE: is
        # written last, so _poll_marker returning means the marker is complete
        # and this read cannot race the inner's write.
        game_pid = _read_marker_pid(marker) if done else None
        _delete_bridge_task(task_name)
        with contextlib.suppress(OSError):
            os.remove(marker)

        if not done:
            log_event("BRIDGE", result="timeout")
            return EXIT_BRIDGE_TIMEOUT
        try:
            code = int(done.split(":", 1)[1])
        except (IndexError, ValueError):
            # A torn or truncated marker is unreadable, which is a timeout —
            # not a reason to escape with an undocumented exit code 1.
            log_event("BRIDGE", result="corrupt_marker", line=done)
            return EXIT_BRIDGE_TIMEOUT
        log_event("BRIDGE", result="inner_exit", code=code)
        if code == EXIT_OK and game_pid is not None:
            # spec §4: the caller parses stdout with int(stdout.strip()). The
            # inner's own stdout went to the schtasks-spawned process tree and
            # is gone by now, so this — the marker, read back — is the only
            # channel left that reaches the process the SSH caller is actually
            # talking to.
            print(game_pid, flush=True)
        elif code == EXIT_OK:
            # rc 0 with no PID: an inner that launched nothing (--dry-run) or
            # one that predates the PID: line. Both look identical to the
            # caller — empty stdout, then a ValueError — so stderr is where the
            # distinction goes.
            log_event("BRIDGE", result="no_pid_in_marker", dry_run=args.dry_run)
        return code
    except Exception as e:  # noqa: BLE001 — the outer needs a blanket guard too
        # A3: session detection and the shim path pre-flight are outside this
        # try, but a missing schtasks, an unwritable tempdir, or any OSError out
        # of subprocess.run is not. Letting it escape made main() die with an
        # undocumented exit 1 and leaked the shim into TEMP. Same contract as
        # the inner's guard: a real cause becomes 99, and cleanup still runs.
        log_event("BRIDGE", step="internal_error", error=f"{type(e).__name__}: {e}",
                  traceback=" | ".join(traceback.format_exc().splitlines()))
        if task_scheduled:
            with contextlib.suppress(OSError):
                _delete_bridge_task(task_name)
        return EXIT_INTERNAL
    finally:
        # Runs on every path, including the except above. The shim and lease are
        # the outer's own files; the timeout path in particular must drop the
        # lease so the orphaned inner sees it vanish before its next phase.
        _delete_bridge_shim(shim_path)
        _remove_lease(lease)


@dataclasses.dataclass
class ChainResult:
    """What run_launch_chain learned besides its exit code.

    The PID cannot ride in the return value: that is an EXIT_* int, compared
    against EXIT_OK by main()'s marker write and by every caller and test of
    the chain. So the chain takes an optional result object, fills in the one
    field it has, and main() reads it back to write the PID: line. Optional
    because the callers that only want the exit code — the same-session
    inline path, the tests — should not have to know the channel exists.
    """

    pid: int | None = None


def run_launch_chain(args: argparse.Namespace,
                     result: ChainResult | None = None) -> int:
    """PREKILL .. GAME_OBSERVE. This is the inner's body.

    On success the game's PID goes to stdout as `<pid>\\n` and nothing else —
    the caller parses it with int(stdout.strip()). Diagnostics are stderr only.
    That stdout print only reaches the caller when the chain runs inline in the
    user's session; across the bridge it dies with the schtasks process tree,
    which is why `result` carries the same PID for the marker to hand back.

    Blanket guard around the whole chain. An exception escaping here returns
    from main() *before* _write_marker runs, so the outer bridge never learns
    the inner died — it sits there until its own timeout and reports 43,
    which names none of the real cause. Typed non-zero returns pass through
    untouched; only unexpected exceptions become EXIT_INTERNAL (99).

    Scoped to the inner's chain on purpose: the bridge's own logic (session
    detection, schtasks, marker polling) stays outside it.
    """
    try:
        return _run_launch_chain_phases(args, result)
    except Exception as e:  # noqa: BLE001 — propagating is the failure mode
        # format_exc is multi-line; the timeline is one line per event.
        log_event("CHAIN", step="internal_error",
                  error=f"{type(e).__name__}: {e}",
                  traceback=" | ".join(traceback.format_exc().splitlines()))
        return EXIT_INTERNAL


def _run_launch_chain_phases(args: argparse.Namespace,
                             result: ChainResult | None = None) -> int:
    # A1: the lease is the outer's liveness signal. When the outer stopped
    # listening (a timeout, or a bridge-side crash) it removed the lease, and
    # that disappearance is the only thing an orphaned inner can see. The check
    # runs before *every* phase, not just at startup: the phases that do harm
    # (PREKILL kills whatever a retry just started, the keystrokes drive a
    # window nobody asked us to touch) are the later ones. No --lease is the
    # documented same-session / debug path, where there is no outer and nothing
    # to enforce.
    lease = getattr(args, "lease", None)

    def abandoned() -> bool:
        if lease is not None and not os.path.exists(lease):
            log_event("LEASE", step="abandoned", lease=lease)
            return True
        return False

    if abandoned():
        return EXIT_BRIDGE_ABANDONED
    # A5: spec D4 — a dry run does everything except the URI spawn *and the
    # kill*. Running PREKILL anyway would let the pre-flight check a person runs
    # before trusting the script kill their unsaved game and still exit 0.
    if not args.dry_run:
        rc = prekill(args.no_prekill)
        if rc != EXIT_OK:
            return rc

    if abandoned():
        return EXIT_BRIDGE_ABANDONED
    rc = steam_spawn(args.app_id, args.dry_run)
    if rc != EXIT_OK:
        return rc

    if abandoned():
        return EXIT_BRIDGE_ABANDONED
    steam_pid = steam_ready(args.launcher_timeout_s)
    if steam_pid is None and not args.dry_run:
        return EXIT_STEAM_NO_CLIENT

    if abandoned():
        return EXIT_BRIDGE_ABANDONED
    found = launcher_wait(args.launcher_timeout_s)
    if found is None:
        if not args.dry_run:
            return EXIT_LAUNCHER_WINDOW_MISSING
        return EXIT_OK
    if args.dry_run:
        # A dry run spawns no URI, so a launcher window here is some other
        # game's. Never click into a window nobody asked us to touch.
        return EXIT_OK

    if abandoned():
        return EXIT_BRIDGE_ABANDONED
    rc = launcher_click(found[1])
    if rc != EXIT_OK:
        return rc

    if abandoned():
        return EXIT_BRIDGE_ABANDONED
    game_pid = launcher_handoff(args.game_timeout_s)
    if game_pid is None:
        return EXIT_GAME_DID_NOT_SPAWN

    if abandoned():
        return EXIT_BRIDGE_ABANDONED
    rc = game_observe(game_pid, args.observe_s)
    if rc != EXIT_OK:
        return rc

    if args.unpause:
        if abandoned():
            return EXIT_BRIDGE_ABANDONED
        rc = game_unpause(game_pid, args.unpause_delay_s)
        if rc != EXIT_OK:
            return rc

    # M-2: stdout first, result.pid second. If the write fails (the SSH pipe
    # closed), the blanket guard turns the run into 99 — and if result.pid were
    # already set, the marker would carry PID: next to DONE:99, the one
    # combination _write_marker's docstring says must never happen. A PID that
    # reached the caller is a PID whose marker also claims success.
    print(game_pid, flush=True)
    if result is not None:
        # Clean run only. A PID next to a non-zero DONE: would tell the outer
        # the game is up when the observe window just said otherwise, and the
        # outer prints on EXIT_OK alone.
        result.pid = game_pid
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    global _active_timeline
    try:
        args = build_arg_parser().parse_args(argv)
    except SystemExit as e:
        # A2: argparse exits 2 on a bad command line, and 2 is
        # EXIT_PREKILL_PERMISSION — "permission wall, retrying will not help".
        # The agent builds this command line itself, so a typo would stop the
        # retry loop for a reason that has nothing to do with the game. Help
        # exits 0 and must stay 0; every other usage error is internal (99).
        code = e.code
        return EXIT_OK if code == 0 else EXIT_INTERNAL
    # An inner that writes a marker also has to hand its timeline over: across
    # the bridge nothing else does. Installed before BOOT so the carried lines
    # start where the outer's own stderr starts.
    timeline = _Timeline() if (args.inner and args.marker) else None
    previous = _active_timeline
    _active_timeline = timeline
    try:
        log_event("BOOT", app_id=args.app_id, argv=argv if argv is not None else "default")
        if not args.inner:
            # Outer: bridge into the logged-on user's session. Whatever it
            # returns is the job's exit code — the inner already ran the chain
            # and wrote the marker, so the outer must not run it again. A3: an
            # exception out of session detection happens before the shim exists,
            # so the bridge's own guard cannot cover it; the caller still needs a
            # documented code, not exit 1.
            try:
                return bridge_to_interactive_session(args)
            except Exception as e:  # noqa: BLE001 — main is the last documented-code gate
                log_event("BRIDGE", step="internal_error",
                          error=f"{type(e).__name__}: {e}",
                          traceback=" | ".join(traceback.format_exc().splitlines()))
                return EXIT_INTERNAL
        result = ChainResult()
        rc = run_launch_chain(args, result)
        # An abandoned inner has no outer to tell, so a DONE: file left behind is
        # only litter a future run could read. Skip the marker on that code alone.
        if args.marker and rc != EXIT_BRIDGE_ABANDONED:
            _write_marker(args.marker, rc, result.pid,
                          timeline=timeline.lines() if timeline else ())
        return rc
    finally:
        # Restore rather than clear: main() is the whole run today, but a
        # nested caller must not inherit a half-installed capture.
        _active_timeline = previous


if __name__ == "__main__":
    sys.exit(main())
