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
EXIT_BRIDGE_NO_SESSION = 41
EXIT_BRIDGE_SCHTASKS_DENIED = 42
EXIT_BRIDGE_TIMEOUT = 43
# One code for "the /tr shim payload cannot be delivered to schtasks/cmd":
# over the 261-char ceiling, or not representable in the OEM codepage cmd.exe
# parses .cmd files in. Both are pre-flight checks below — letting schtasks
# reject either produces the opaque 42, and letting cmd.exe misread one
# produces a bare 43.
EXIT_BRIDGE_TR_TOO_LONG = 44
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
_INNER_BUDGET_LAUNCHER_KEYBOARD_S = 24  # Enter + 3x Tab+Enter, 5s wait each
_INNER_BUDGET_GAME_OBSERVE_S = 60     # = --game-timeout-s + --observe-s defaults
_INNER_CHAIN_BUDGET_S = (
    _INNER_BUDGET_PREKILL_SPAWN_S
    + _INNER_BUDGET_STEAM_READY_S
    + _INNER_BUDGET_LAUNCHER_WAIT_S
    + _INNER_BUDGET_LAUNCHER_KEYBOARD_S
    + _INNER_BUDGET_GAME_OBSERVE_S
)  # 147s with all defaults
_BRIDGE_TIMEOUT_MARGIN_S = 33          # slack for monitor jitter + log I/O
DEFAULT_BRIDGE_TIMEOUT_S = _INNER_CHAIN_BUDGET_S + _BRIDGE_TIMEOUT_MARGIN_S  # 180s

# Process images this chain looks for. Compared case-insensitively: Windows
# file names are case-insensitive and psutil reports whatever the image has.
LAUNCHER_IMAGE = "Paradox Launcher.exe"
GAME_IMAGE = "stellaris.exe"

# Virtual keys for the launcher drive. Enter first — the launcher's default
# focus is the Play button — then Tab to move focus, Enter to commit.
VK_TAB = 0x09
VK_RETURN = 0x0D

INPUT_KEYBOARD = 1

_FOREGROUND_TIMEOUT_S = 3.0
_FOCUS_SETTLE_S = 1.0
_KEY_SETTLE_S = 5.0
_TAB_ENTER_ATTEMPTS = 3
_POLL_S = 0.5
_OBSERVE_POLL_S = 1.0

# psutil status strings that mean the process is no longer running the game.
# 'zombie' is the one psutil actually reports; 'dead' is what a lost handle
# looks like in practice.
_GONE_STATUSES = ("zombie", "dead")

# Crash-dialog signals. The title markers are substrings, matched
# case-insensitively against both the window text and, when there is none, the
# window class. The images are process names, matched case-insensitively the
# same way psutil reports them.
_JIT_TITLE_MARKERS = ("just-in-time debugger", "jit debugger",
                      "just in time debugger")
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
    print(timeline_event(phase, **fields), file=sys.stderr, flush=True)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="launch_stellaris")
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
    p.add_argument("--bridge-timeout-s", type=int, default=DEFAULT_BRIDGE_TIMEOUT_S,
                   help="How long the outer waits for the inner's completion "
                        f"marker (default {DEFAULT_BRIDGE_TIMEOUT_S}, derived "
                        "from the phase budgets above it). Raise this whenever "
                        "--launcher-timeout-s, --game-timeout-s or "
                        "--observe-s is raised past its default, or the outer "
                        "reports 43 before the inner is done.")
    p.add_argument("--inner", action="store_true",
                   help="(bridge only) skip session detection, run launch chain directly")
    p.add_argument("--marker", type=str, default=None,
                   help="(bridge only) path to completion marker file")
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
    """
    if no_prekill:
        log_event("PREKILL", skipped=True)
        return EXIT_OK
    killed = []
    for image in ("stellaris.exe", "Paradox Launcher.exe"):
        r = _taskkill(image)
        # rc=0 success; rc=128 with stderr containing 'not found' / '找不到' is OK
        if r.returncode == 0:
            killed.append(image)
            continue
        # Treat "process not found" as success
        if "not found" in r.stderr.lower() or "\u627e\u4e0d\u5230" in r.stderr:
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


_input_fns_cache: tuple[Any, Any, Any] | None = None


def _input_fns() -> tuple[Any, Any, Any]:
    """Bind (SetForegroundWindow, GetForegroundWindow, SendInput).

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
        send_input = user32.SendInput
        send_input.argtypes = [_wt.UINT, ctypes.POINTER(INPUT), _wt.INT]
        send_input.restype = _wt.UINT
        _input_fns_cache = (set_foreground_window, get_foreground_window,
                            send_input)
    return _input_fns_cache


class KEYBDINPUT(ctypes.Structure):
    """Win32 KEYBDINPUT.

    Fixed-width c_uint16/c_uint32 rather than ctypes.wintypes.WORD/DWORD on
    purpose: _wt.DWORD is c_ulong, which is 8 bytes on an LP64 host and 4 on
    Windows, so a _wt-spelled struct is a silently wrong cbsize anywhere but
    the box it is meant for. These keep one layout everywhere, and
    test_input_struct_layout_matches_the_sendinput_abi pins it.
    """

    _fields_ = [
        ("wVk", ctypes.c_uint16),
        ("wScan", ctypes.c_uint16),
        ("dwFlags", ctypes.c_uint32),
        ("time", ctypes.c_uint32),
        ("dwExtraInfo", ctypes.c_size_t),  # ULONG_PTR
    ]


class INPUT(ctypes.Structure):
    """Win32 INPUT: a DWORD tag followed by the union's largest member.

    Only KEYBDINPUT is populated; the trailing pad stands in for MOUSEINPUT
    (32 bytes on x64, the real union size). 40 bytes total on x64.
    """

    _fields_ = [
        ("type", ctypes.c_uint32),
        ("ki", KEYBDINPUT),
        ("_padding", ctypes.c_ubyte * 8),
    ]


def send_key(vk: int) -> None:
    """Send one virtual-key down+up through SendInput.

    Raises OSError when SendInput delivers 0 events, which is what happens when
    the foreground window sits at a higher integrity level (UIPI). Swallowing
    that would make the whole drive a silent no-op that still reports success.
    """
    _, _, send_input = _input_fns()
    ki = KEYBDINPUT(wVk=vk, wScan=0, dwFlags=0, time=0, dwExtraInfo=0)
    inp = INPUT(type=INPUT_KEYBOARD, ki=ki)
    sent = send_input(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
    if sent != 1:
        raise OSError(_last_error(), f"SendInput delivered {sent}/1 events")


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


def bring_to_foreground(hwnd: int) -> bool:
    """Raise `hwnd` to the foreground. True once it actually owns it."""
    set_foreground_window, get_foreground_window, _ = _input_fns()
    deadline = _time.time() + _FOREGROUND_TIMEOUT_S
    set_foreground_window(hwnd)
    while _time.time() < deadline:
        if get_foreground_window() == hwnd:
            log_event("LAUNCHER_KEYBOARD", step="foreground_ok", hwnd=hwnd)
            return True
        _time.sleep(0.1)
    log_event("LAUNCHER_KEYBOARD", step="foreground_fail", hwnd=hwnd)
    return False


def _handoff_observed() -> bool:
    """True once the launcher has let go: it exited, or the game took over.

    The launcher staying put is the *negative* signal — it means the keystrokes
    did not land. Treating it as a handoff would hand the next phase a launcher
    window and no game.
    """
    names = set()
    for p in psutil.process_iter(["name"]):
        name = p.info.get("name")
        if name:
            names.add(name.lower())
    launcher_alive = LAUNCHER_IMAGE.lower() in names
    game_alive = GAME_IMAGE.lower() in names
    return (not launcher_alive) or game_alive


def launcher_keyboard(hwnd: int) -> int:
    """Drive the launcher with Enter, then Tab+Enter, until it hands off.

    The launcher's UIA tree exposes no controls (CEF canvas), so keystrokes are
    the only channel that does not depend on pixel coordinates. Returns
    EXIT_OK on handoff, EXIT_LAUNCHER_NO_FOCUS if the window cannot be raised
    or the keystrokes cannot be delivered, EXIT_LAUNCHER_NO_ADVANCE if the whole
    sequence is spent without one.

    A blocked SendInput (UIPI — a foreground window at a higher integrity
    level) is reported as NO_FOCUS rather than allowed to escape: an OSError out
    of here would exit main() with code 1, which is not a documented code, and
    would return before _write_marker runs, so the outer bridge would learn
    nothing and report its own timeout instead.
    """
    try:
        if not bring_to_foreground(hwnd):
            return EXIT_LAUNCHER_NO_FOCUS
        _time.sleep(_FOCUS_SETTLE_S)

        send_key(VK_RETURN)
        log_event("LAUNCHER_KEYBOARD", step="enter_sent")
        _time.sleep(_KEY_SETTLE_S)
        if _handoff_observed():
            log_event("LAUNCHER_KEYBOARD", step="handoff_after_enter")
            return EXIT_OK

        for attempt in range(1, _TAB_ENTER_ATTEMPTS + 1):
            send_key(VK_TAB)
            send_key(VK_RETURN)
            log_event("LAUNCHER_KEYBOARD", step="tab_enter", attempt=attempt)
            _time.sleep(_KEY_SETTLE_S)
            if _handoff_observed():
                log_event("LAUNCHER_KEYBOARD", step="handoff_after_tab_enter",
                          attempt=attempt)
                return EXIT_OK
        return EXIT_LAUNCHER_NO_ADVANCE
    except OSError as e:
        log_event("LAUNCHER_KEYBOARD", step="send_input_blocked", error=repr(e))
        return EXIT_LAUNCHER_NO_FOCUS


def launcher_handoff(timeout_s: int) -> int | None:
    """Wait for the launcher to hand off to the game. Returns stellaris.exe's PID.

    Separate from launcher_keyboard on purpose: that phase stops at the first
    handoff *signal*, which launcher_keyboard's own _handoff_observed also
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


def _is_jit_dialog_visible(windows: list[tuple[int, str]] | None = None) -> bool:
    """True if a Just-In-Time debugger dialog is up.

    The vsjitdebugger.exe process is the primary, locale-independent signal —
    the same reasoning as WerFault.exe below. A title match cannot carry this
    check on its own: the target box is zh-CN, the JIT dialog's title is
    localized with the Visual Studio UI language, and "just-in-time debugger"
    never appears in it.

    Verified on Windows_Jiaolong rather than assumed: HKLM\\SOFTWARE\\Microsoft\\
    Windows NT\\CurrentVersion\\AeDebug\\Debugger is
        "C:\\Windows\\system32\\vsjitdebugger.exe" -p %ld -e %ld -j 0x%p
    and running that image with those arguments leaves the process alive. The
    OS spawns it only when a process takes an unhandled exception, so its
    presence means a JIT event and nothing else — no "a debugger is installed"
    false positive the way devenv.exe would be.

    The title match stays as a fallback for a dialog hosted in some other
    process, and so the check still fires on a box whose AeDebug points at a
    different debugger image.

    A vsjitdebugger.exe left over from an unrelated earlier crash is a false
    positive that costs one spurious EXIT_JIT_DIALOG — the same cheap
    direction the WER check already fails in, because the alternative is
    reporting a crashed game as a healthy one. PREKILL does not reap it, on
    the same footing as WerFault.exe.

    `windows` is the caller's snapshot for this tick, and covers the title
    half only. Optional so the predicate stands alone; game_observe passes one
    desktop scan to both predicates rather than paying for two. The process
    half scans on its own either way, for the same reason WerFault.exe does.
    """
    for p in psutil.process_iter(["name"]):
        name = p.info.get("name")
        if name and name.lower() == _JIT_IMAGE:
            return True
    for _, title in _top_windows() if windows is None else windows:
        lowered = title.lower()
        if any(m in lowered for m in _JIT_TITLE_MARKERS):
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
        # One desktop scan serves both dialog probes; see _is_jit_dialog_visible.
        windows = _top_windows()
        if _is_jit_dialog_visible(windows):
            log_event("GAME_OBSERVE", step="jit_dialog")
            return EXIT_JIT_DIALOG
        if _is_wer_dialog_visible(windows):
            log_event("GAME_OBSERVE", step="wer_dialog")
            return EXIT_WER_DIALOG
        _time.sleep(_OBSERVE_POLL_S)
    log_event("GAME_OBSERVE", step="ok", pid=pid, alive_s=observe_s)
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


def build_bridge_account(computer: str | None = None, user: str | None = None) -> str:
    """The run-as account for the bridge task: <machine>\\<user>.

    COMPUTERNAME, deliberately not USERDOMAIN: on a standalone box USERDOMAIN is
    the workgroup name (WORKGROUP on Windows_Jiaolong), which schtasks cannot
    resolve to a SID — it rejects it with 'No mapping between account names and
    security IDs'. COMPUTERNAME is the prefix `whoami` prints, so it resolves.
    """
    computer = (computer or os.environ.get("COMPUTERNAME")
                or os.environ.get("USERDOMAIN") or "lofibass")
    user = user or os.environ.get("USERNAME") or "13229"
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
    """Remove the one-shot task. Best effort: a leftover entry is a nuisance,
    never a reason to fail a launch."""
    subprocess.run(["schtasks", "/delete", "/tn", task_name, "/f"],
                   capture_output=True, text=True)


def _default_marker_path(pid: int) -> str:
    """Path of the completion marker file. Short by design: this string gets
    forwarded into the inner command line and carried into /tr, where every
    character counts toward schtasks' 261-char ceiling.
    """
    return os.path.join(tempfile.gettempdir(), f"ls_{pid}.txt")


def write_bridge_tr_shim(task_name: str, inner_command: str,
                         tempdir: str | None = None) -> str:
    """Write the /tr shim: a .cmd file that runs `inner_command`.

    schtasks rejects /tr values longer than 261 characters. With the
    forwarded flag set, the inline command line is 276 chars by default and
    309 with --no-prekill --dry-run --verbose — both well over the limit.
    Pointing /tr at a short path to a .cmd shim sidesteps the ceiling.

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
                   script: str | None = None) -> str:
    """The inner command line — the *body* of the /tr shim, not the /tr value.

    /tr itself receives a short path to a .cmd file (see
    write_bridge_tr_shim); schtasks rejects a /tr over 261 characters and
    this string is 276 by default. Do not "fix" that ceiling by trimming
    flags out of this string — the shim exists precisely so they can all stay.

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
        # The inner never bridges, so this one is inert there; forwarding it
        # anyway means a future inner-side bridge needs no change here.
        "--bridge-timeout-s", str(args.bridge_timeout_s),
    ]
    if args.no_prekill:
        parts.append("--no-prekill")
    if args.dry_run:
        parts.append("--dry-run")
    if args.verbose:
        parts.append("--verbose")
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


def _write_marker(marker: str, code: int, pid: int | None = None) -> None:
    """Signal the waiting outer process that the inner chain finished.

    Two lines: PID:<pid> when the chain has a game to hand back, then DONE:<rc>.
    DONE: keeps its exact spelling and its position as the last line —
    _poll_marker finds it with a backward scan and the bridge splits on it, so
    neither its name nor its order may drift. PID: is additive, and
    deliberately absent when there is no PID: "PID: present" has to keep
    meaning "the game is up", which rules out writing one for a failed observe
    window or a --dry-run.

    Written last and through one open/close so the two lines land together; no
    DONE: line means timeout, which is the correct signal for an inner that
    died mid-chain.
    """
    try:
        with open(marker, "w", encoding="utf-8") as f:
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
    if target_sid == 0:
        log_event("BRIDGE", result="no_interactive_session")
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

    # Build the inner command line and write the /tr shim. schtasks refuses
    # /tr values > 261 chars; the inline command is 276 chars by default and
    # 309 with --no-prekill --dry-run --verbose — both over. The shim replaces
    # the inline command with a short path that points at a .cmd file holding
    # the same command.
    inner_command = build_inner_tr(args, marker)
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

    create = subprocess.run(
        build_bridge_task_command(task_name, shim_path, st_str, ru),
        capture_output=True, text=True,
    )
    if create.returncode != 0:
        log_event("BRIDGE", step="create", rc=create.returncode, stderr=create.stderr.strip())
        # A /create that fails partway can still have registered the task.
        # Mirror the run-failure branch below: clean up before returning.
        _delete_bridge_task(task_name)
        _delete_bridge_shim(shim_path)
        return EXIT_BRIDGE_SCHTASKS_DENIED

    run = subprocess.run(build_bridge_run_command(task_name), capture_output=True, text=True)
    if run.returncode != 0:
        log_event("BRIDGE", step="run", rc=run.returncode, stderr=run.stderr.strip())
        _delete_bridge_task(task_name)
        _delete_bridge_shim(shim_path)
        return EXIT_BRIDGE_SCHTASKS_DENIED

    log_event("BRIDGE", task=task_name, marker=marker, shim=shim_path)
    done = _poll_marker(marker, args.bridge_timeout_s)
    # Read the PID before the cleanup below deletes the marker. DONE: is
    # written last, so _poll_marker returning means the marker is complete and
    # this read cannot race the inner's write.
    pid = _read_marker_pid(marker) if done else None
    _delete_bridge_task(task_name)
    _delete_bridge_shim(shim_path)
    with contextlib.suppress(OSError):
        os.remove(marker)

    if not done:
        log_event("BRIDGE", result="timeout")
        return EXIT_BRIDGE_TIMEOUT
    try:
        code = int(done.split(":", 1)[1])
    except (IndexError, ValueError):
        # A torn or truncated marker is unreadable, which is a timeout — not a
        # reason to escape with an undocumented exit code 1.
        log_event("BRIDGE", result="corrupt_marker", line=done)
        return EXIT_BRIDGE_TIMEOUT
    log_event("BRIDGE", result="inner_exit", code=code)
    if code == EXIT_OK and pid is not None:
        # spec §4: the caller parses stdout with int(stdout.strip()). The
        # inner's own stdout went to the schtasks-spawned process tree and is
        # gone by now, so this — the marker, read back — is the only channel
        # left that reaches the process the SSH caller is actually talking to.
        print(pid, flush=True)
    elif code == EXIT_OK:
        # rc 0 with no PID: an inner that launched nothing (--dry-run) or one
        # that predates the PID: line. Both look identical to the caller —
        # empty stdout, then a ValueError — so stderr is where the distinction
        # goes.
        log_event("BRIDGE", result="no_pid_in_marker", dry_run=args.dry_run)
    return code


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
    rc = prekill(args.no_prekill)
    if rc != EXIT_OK:
        return rc
    rc = steam_spawn(args.app_id, args.dry_run)
    if rc != EXIT_OK:
        return rc
    steam_pid = steam_ready(args.launcher_timeout_s)
    if steam_pid is None and not args.dry_run:
        return EXIT_STEAM_NO_CLIENT
    found = launcher_wait(args.launcher_timeout_s)
    if found is None:
        if not args.dry_run:
            return EXIT_LAUNCHER_WINDOW_MISSING
        return EXIT_OK
    if args.dry_run:
        # A dry run spawns no URI, so a launcher window here is some other
        # game's. Never type into a window nobody asked us to touch.
        return EXIT_OK
    rc = launcher_keyboard(found[1])
    if rc != EXIT_OK:
        return rc
    game_pid = launcher_handoff(args.game_timeout_s)
    if game_pid is None:
        return EXIT_GAME_DID_NOT_SPAWN
    rc = game_observe(game_pid, args.observe_s)
    if rc != EXIT_OK:
        return rc
    if result is not None:
        # Clean run only. A PID next to a non-zero DONE: would tell the outer
        # the game is up when the observe window just said otherwise, and the
        # outer prints on EXIT_OK alone.
        result.pid = game_pid
    print(game_pid, flush=True)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    log_event("BOOT", app_id=args.app_id, argv=argv if argv is not None else "default")
    if not args.inner:
        # Outer: bridge into the logged-on user's session. Whatever it returns
        # is the job's exit code — the inner already ran the chain and wrote
        # the marker, so the outer must not run it again.
        return bridge_to_interactive_session(args)
    result = ChainResult()
    rc = run_launch_chain(args, result)
    if args.marker:
        _write_marker(args.marker, rc, result.pid)
    return rc


if __name__ == "__main__":
    sys.exit(main())
