"""launch_stellaris — bring up Stellaris via Steam from an unattended SSH session.

See docs/superpowers/specs/2026-09-29-launch-stellaris-design.md for the contract.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import ctypes.wintypes as _wt
import datetime as _dt
import os
import subprocess
import sys
import tempfile
import time as _time
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
EXIT_INTERNAL = 99

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
    p.add_argument("--launcher-timeout-s", type=int, default=30)
    p.add_argument("--game-timeout-s", type=int, default=30)
    p.add_argument("--observe-s", type=int, default=30)
    p.add_argument("--bridge-timeout-s", type=int, default=90)
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


def build_inner_tr(args: argparse.Namespace, marker: str,
                   python: str | None = None,
                   script: str | None = None) -> str:
    """The /tr payload: the exact command line the inner will run.

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


def _write_marker(marker: str, code: int) -> None:
    """Signal the waiting outer process that the inner chain finished.

    Written last and with a single write so a torn read by _poll_marker is
    impossible in practice; no DONE: line means timeout, which is the correct
    signal for an inner that died mid-chain.
    """
    try:
        with open(marker, "w", encoding="utf-8") as f:
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

    # Generate a unique task name + marker
    pid = os.getpid()
    ts = int(_time.time())
    task_name = f"stellaris-launch-{pid}-{ts}"
    marker = args.marker or os.path.join(tempfile.gettempdir(), f"launch_inner_{pid}_{ts}.txt")

    # Build /tr: inner invocation. Marker path is the contract.
    tr = build_inner_tr(args, marker)

    # /st = HH:MM in the near future (schtasks needs a future scheduled time even
    # with /I on some Windows builds; 1 minute out is enough).
    future = _dt.datetime.now() + _dt.timedelta(minutes=1)
    st_str = future.strftime("%H:%M")
    ru = build_bridge_account()

    create = subprocess.run(
        build_bridge_task_command(task_name, tr, st_str, ru),
        capture_output=True, text=True,
    )
    if create.returncode != 0:
        log_event("BRIDGE", step="create", rc=create.returncode, stderr=create.stderr.strip())
        # A /create that fails partway can still have registered the task.
        # Mirror the run-failure branch below: clean up before returning.
        _delete_bridge_task(task_name)
        return EXIT_BRIDGE_SCHTASKS_DENIED

    run = subprocess.run(build_bridge_run_command(task_name), capture_output=True, text=True)
    if run.returncode != 0:
        log_event("BRIDGE", step="run", rc=run.returncode, stderr=run.stderr.strip())
        _delete_bridge_task(task_name)
        return EXIT_BRIDGE_SCHTASKS_DENIED

    log_event("BRIDGE", task=task_name, marker=marker)
    done = _poll_marker(marker, args.bridge_timeout_s)
    _delete_bridge_task(task_name)
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
    return code


def run_launch_chain(args: argparse.Namespace) -> int:
    """PREKILL .. GAME_OBSERVE. This is the inner's body; Tasks 5–6 extend it."""
    rc = prekill(args.no_prekill)
    if rc != EXIT_OK:
        return rc
    rc = steam_spawn(args.app_id, args.dry_run)
    if rc != EXIT_OK:
        return rc
    steam_pid = steam_ready(args.launcher_timeout_s)
    if steam_pid is None and not args.dry_run:
        return EXIT_STEAM_NO_CLIENT
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    log_event("BOOT", app_id=args.app_id, argv=argv if argv is not None else "default")
    if not args.inner:
        # Outer: bridge into the logged-on user's session. Whatever it returns
        # is the job's exit code — the inner already ran the chain and wrote
        # the marker, so the outer must not run it again.
        return bridge_to_interactive_session(args)
    rc = run_launch_chain(args)
    if args.marker:
        _write_marker(args.marker, rc)
    return rc


if __name__ == "__main__":
    sys.exit(main())
