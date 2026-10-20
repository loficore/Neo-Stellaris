"""launch_stellaris — bring up Stellaris via Steam from an unattended SSH session.

See docs/superpowers/specs/2026-09-29-launch-stellaris-design.md for the contract.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import subprocess
import sys
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


def _steam_has_window(pid: int) -> bool:
    """Best-effort check that a Steam window is on screen. Uses FindWindow('Valve001'),
    which is the Steam overlay/UI window class. Returns True if any such window exists."""
    try:
        import ctypes
        user32 = ctypes.windll.user32
        user32.FindWindowW.restype = ctypes.c_int
        user32.FindWindowW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
        return user32.FindWindowW("Valve001", None) != 0
    except Exception:
        return True  # assume yes on non-Windows or unexpected failure


def steam_ready(timeout_s: int) -> int | None:
    """Poll for steam.exe with a visible Valve001 window. Returns PID or None."""
    deadline = _time.time() + timeout_s
    while _time.time() < deadline:
        for p in psutil.process_iter(["name", "pid"]):
            if p.info["name"] and p.info["name"].lower() == "steam.exe" and _steam_has_window(p.info["pid"]):
                log_event("STEAM_READY", steam_pid=p.info["pid"])
                return p.info["pid"]
        _time.sleep(0.5)
    log_event("STEAM_READY", timeout=True)
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    log_event("BOOT", app_id=args.app_id, argv=argv if argv is not None else "default")
    # PREKILL runs before every other phase (Task 2). Remaining chain
    # (STEAM_SPAWN .. GAME_OBSERVE) is wired in Tasks 3–6.
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


if __name__ == "__main__":
    sys.exit(main())
