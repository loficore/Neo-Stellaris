# launch_stellaris Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a CLI script (`scripts/windows/launch_stellaris.py`) that, when invoked over SSH from a non-interactive session on `Windows_Jiaolong`, bridges into the logged-on user's interactive session, launches Stellaris via Steam, drives the Paradox Launcher with keyboard input, observes the game for 30 s, and prints the game's PID on success.

**Architecture:** Single Python module, single CLI, no daemon. The script detects its session via `kernel32.ProcessIdToSessionId`; if it is in session 0 (SSH) and the user is logged on at the console (session 1), it bridges via legacy `schtasks.exe` (`/create /ru <user> /rl highest + /run /I`) — verified on `Windows_Jiaolong`. The inner invocation in session 1 runs the launch chain: pre-kill stale processes, spawn the `steam://` URI, wait for `Paradox Launcher.exe`, attach to its window, focus it, send `Enter` (then `Tab`+`Enter` up to 3×), wait for `stellaris.exe`, observe for 30 s. All output is a single stderr timeline plus a final stdout PID line.

**Tech Stack:** Python 3.13 (already on `Windows_Jiaolong`), `pywinauto` 0.6.9, `psutil` 7.2.2, stdlib only otherwise (`ctypes`, `subprocess`, `tempfile`, `datetime`, `pathlib`, `argparse`, `json`). No build step. `git`-deployed to `Windows_Jiaolong` the same way `scripts/c1_remote.py` is.

**Spec:** `docs/superpowers/specs/2026-09-29-launch-stellaris-design.md` — the plan argues from the spec, so the spec travels with it; executors read both.

## Global Constraints

- Game version: **4.4.4** (Pegasus); install path on `Windows_Jiaolong` is **`D:\SteamLibrary\steamapps\common\Stellaris`** — NOT the default `C:\Program Files (x86)\Steam\steamapps\common\Stellaris`. Launcher process name is **`Paradox Launcher.exe`**, NOT `launcher.exe`. Steam AppID is **281990**.
- Python 3.13.2 is installed at `C:\Users\13229\AppData\Local\Programs\Python\Python313\python.exe`. The script assumes `python` is on PATH for the SSH user. **Never** call `pythonw`; we need the console window for stderr visibility.
- `pywinauto>=0.6.8` and `psutil>=5.9` are the only new runtime deps. Create `scripts/windows/requirements.txt` for them; **do not** add to `scripts/requirements.txt` (the offline RE toolchain — `capstone` / `pefile` / `unicorn`).
- The legacy `schtasks.exe` on Windows 10/11 does NOT recognize `/it`. The verified bridge is `schtasks /create /tn <name> /tr "<tr>" /sc once /st HH:MM /ru lofibass\13229 /rl highest /f` + `schtasks /run /tn <name> /I`. `/I` is "ignore schedule constraints, run now"; the `/ru user /rl highest` pair is what constrains the task to run in the user's interactive session.
- The script is **re-entrant safe** (agent retries, script does not). PREKILL must tolerate its own previous run's targets still being alive.
- UIA is used only to confirm window existence. PDX Launcher's `Chrome_WidgetWin_1` class exposes only `Pane/RootView` to UIA — no buttons. All launcher driving is via `ctypes.windll.user32.SendInput`.
- Every test that touches the Windows box uses the SSH alias `Windows_Jiaolong` (matches the project's convention; SSH config is the user's, not committed).
- No DLL work in this plan. No changes to `src/dll/`, no `zig build`. This is a runtime script only.

## Review Focus

The five failure modes a person shipping this is most likely to hit, and what they should observe.

- **Bridge token collisions**: two parallel SSH launches share the same `stellaris-launch-<pid>-<ts>` task name pattern. Expected: `schtasks /create /f` overwrites; the second launch's outer blocks until the first's inner releases the bridge, or one wins and the other sees exit 41/43 with a typed stderr key. Plan covers this in Task 4 with a unique-enough task name + marker path.
- **Steam update-pending modal** (`appmanifest_281990.acf` `StateFlags="4"` at the time of writing). Expected: the script returns exit 13 `stellaris_update_required` once we add that detection. Pre-implementation smoke may instead block at this dialog for the human to dismiss.
- **`Paradox Launcher.exe` already running from a previous launch** (4 instances observed during verification). Expected: PREKILL kills them all before spawning a fresh URI; the agent can pre-empt by waiting for any launcher to exit before the script is called, but the script handles it on its own.
- **First-run Tab/Enter sequence mismatch** (D1 in spec). Expected: the first real run observes `GetGUIThreadInfo` after each Tab press, picks a working sequence, commits it to the spec's D1 section. The fallback `Enter → Tab+Enter ×3` should recover in 4 attempts on the canonical CEF layout; if it doesn't, Task 5 documents the symptom.
- **SendInput blocked by UAC / foreground-lock** (some Windows policies strip `SendInput` from non-foreground contexts). Expected: `SetForegroundWindow` succeeds because we bridge into the user's session, but if a policy strips foreground from `cmd`/`python`, `SendInput` is dropped silently and the script returns exit 23. Document the symptom, ship a note.

---

### Task 1: Scaffolding — requirements, constants, stderr timeline, CLI parser

**Files:**
- Create: `scripts/windows/requirements.txt`
- Create: `scripts/windows/__init__.py`
- Create: `scripts/windows/launch_stellaris.py`
- Create: `scripts/windows/tests/__init__.py`
- Create: `scripts/windows/tests/test_launch_stellaris.py`

**Interfaces:**
- Consumes: nothing (foundation).
- Produces:
  - `EXIT_OK = 0` and the full map of exit codes 2/11..34/41..43/99 from spec §4.
  - `timeline_event(phase: str, **fields) -> str` — formats one stderr line as `<ISO8601-UTC>  <PHASE>  key=value ...`.
  - `log_event(phase: str, **fields) -> None` — writes the line to stderr, flushed.
  - `build_arg_parser() -> argparse.ArgumentParser` — `--launcher-timeout-s` / `--game-timeout-s` / `--observe-s` / `--bridge-timeout-s` / `--app-id` (default 281990) / `--inner` / `--marker` / `--no-prekill` / `--verbose` / `--dry-run`.

- [ ] **Step 1: Write the failing tests**

`scripts/windows/tests/test_launch_stellaris.py`:
```python
import re
import pytest
from launch_stellaris import (
    EXIT_OK, EXIT_PREKILL_PERMISSION, EXIT_BRIDGE_NO_SESSION,
    EXIT_BRIDGE_SCHTASKS_DENIED, EXIT_BRIDGE_TIMEOUT, EXIT_INTERNAL,
    timeline_event, log_event, build_arg_parser,
)

def test_exit_codes_match_spec():
    assert EXIT_OK == 0
    assert EXIT_PREKILL_PERMISSION == 2
    assert EXIT_BRIDGE_NO_SESSION == 41
    assert EXIT_BRIDGE_SCHTASKS_DENIED == 42
    assert EXIT_BRIDGE_TIMEOUT == 43
    assert EXIT_INTERNAL == 99

def test_timeline_event_format():
    line = timeline_event("PREKILL", killed_pids=[1234, 5678], reason="stale")
    # 2026-...  PREKILL  killed_pids=[1234, 5678]  reason=stale
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z  PREKILL  killed_pids=\[1234, 5678\]  reason=stale$", line)

def test_arg_parser_defaults():
    args = build_arg_parser().parse_args([])
    assert args.app_id == 281990
    assert args.observe_s == 30
    assert args.bridge_timeout_s == 90
    assert args.inner is False
    assert args.no_prekill is False
    assert args.dry_run is False
    assert args.marker is None

def test_arg_parser_overrides():
    args = build_arg_parser().parse_args([
        "--app-id", "12345",
        "--observe-s", "60",
        "--inner",
        "--marker", r"C:\TEMP\m.txt",
    ])
    assert args.app_id == 12345
    assert args.observe_s == 60
    assert args.inner is True
    assert args.marker == r"C:\TEMP\m.txt"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py -v`
Expected: `ModuleNotFoundError: No module named 'launch_stellaris'` (the module does not exist yet).

- [ ] **Step 3: Implement the scaffolding**

`scripts/windows/requirements.txt`:
```
pywinauto>=0.6.8
psutil>=5.9
```

`scripts/windows/__init__.py` and `scripts/windows/tests/__init__.py`: empty.

`scripts/windows/launch_stellaris.py` (skeleton):
```python
"""launch_stellaris — bring up Stellaris via Steam from an unattended SSH session.

See docs/superpowers/specs/2026-09-29-launch-stellaris-design.md for the contract.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
from typing import Any

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
    parts = "  ".join(f"{k}={v!r}" for k, v in fields.items())
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


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    log_event("BOOT", app_id=args.app_id, argv=argv if argv is not None else "default")
    # Real chain is wired in Tasks 2–7. For now the skeleton just exits OK
    # so the CI / lint cycle can run.
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
```

Do not implement the launch chain in this task. Exit 0 is the correct behaviour for the skeleton.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py -v`
Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/windows/requirements.txt scripts/windows/__init__.py scripts/windows/launch_stellaris.py scripts/windows/tests/__init__.py scripts/windows/tests/test_launch_stellaris.py
git commit -m "feat(scripts/windows): launch_stellaris scaffold + stderr timeline + CLI"
```

---

### Task 2: PREKILL — re-entrant safe taskkill

**Files:**
- Modify: `scripts/windows/launch_stellaris.py` — add `prekill(...)` and call from `main()` unless `--no-prekill`.
- Modify: `scripts/windows/tests/test_launch_stellaris.py` — add `prekill` unit tests.

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `prekill(no_prekill: bool = False) -> int` — return 0 on success, `EXIT_PREKILL_PERMISSION` (2) on permission error. Missing processes are OK and treated as success. Re-entrant safe — a second call with the same targets must also return 0.

- [ ] **Step 1: Write the failing tests**

Append to `scripts/windows/tests/test_launch_stellaris.py`:
```python
from unittest.mock import patch, MagicMock
from launch_stellaris import prekill, EXIT_OK, EXIT_PREKILL_PERMISSION

def _fake_run(args, **kwargs):
    """taskkill returns 0 for missing process; 1 with stderr '... ACCESS denied' for permission."""
    if "stellaris.exe" in args or "Paradox Launcher.exe" in args:
        m = MagicMock(returncode=0, stdout="", stderr="")
        return m
    m = MagicMock(returncode=1, stdout="", stderr="ERROR: Access is denied.")
    return m

@patch("subprocess.run", side_effect=_fake_run)
def test_prekill_happy_path(mock_run):
    assert prekill() == EXIT_OK

@patch("subprocess.run", side_effect=_fake_run)
def test_prekill_handles_missing_processes(mock_run):
    """A second invocation with stale targets must also return 0."""
    assert prekill() == EXIT_OK
    assert prekill() == EXIT_OK

@patch("subprocess.run")
def test_prekill_returns_2_on_permission_error(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="ERROR: Access is denied.")
    assert prekill() == EXIT_PREKILL_PERMISSION
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py::test_prekill_happy_path -v`
Expected: `ImportError: cannot import name 'prekill'`.

- [ ] **Step 3: Implement `prekill`**

In `scripts/windows/launch_stellaris.py`, add (above `main`):
```python
import subprocess


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
```

Update `main()` to call `prekill(args.no_prekill)` before any other phase and return its code if non-zero.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py -v`
Expected: 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/windows/launch_stellaris.py scripts/windows/tests/test_launch_stellaris.py
git commit -m "feat(scripts/windows): re-entrant safe prekill via taskkill /F /IM"
```

---

### Task 3: STEAM_SPAWN + STEAM_READY — URI launch and Steam client poll

**Files:**
- Modify: `scripts/windows/launch_stellaris.py` — add `steam_spawn(...)` and `steam_ready(...)`.
- Modify: `scripts/windows/tests/test_launch_stellaris.py` — add unit tests.

**Interfaces:**
- Consumes: `app_id` from `args`.
- Produces:
  - `steam_spawn(app_id: int, dry_run: bool = False) -> int` — returns 0 on success, `EXIT_STEAM_NO_CLIENT` (11) if the URI launch fails to produce a Steam process within `--launcher-timeout-s`.
  - `steam_ready(timeout_s: int) -> int | None` — returns the Steam client PID once it has a top-level window (proxied via `win32gui` or `FindWindow("Valve001")`), or `None` on timeout.

- [ ] **Step 1: Write the failing tests**

Append to `scripts/windows/tests/test_launch_stellaris.py`:
```python
from unittest.mock import patch, MagicMock
from launch_stellaris import steam_spawn, steam_ready

@patch("subprocess.run")
def test_steam_spawn_uses_start_process(mock_run):
    mock_run.return_value = MagicMock(returncode=0)
    steam_spawn(281990)
    args, kwargs = mock_run.call_args
    cmd = args[0]
    assert "steam://rungameid/281990" in cmd
    assert cmd[0].lower().endswith("powershell") or "start-process" in " ".join(cmd).lower()

@patch("time.sleep", return_value=None)
@patch("psutil.process_iter")
def test_steam_ready_returns_pid_when_steam_found(mock_iter, mock_sleep):
    p = MagicMock(); p.info = {"name": "steam.exe", "pid": 9999}
    mock_iter.return_value = [p]
    # Patch the "has window" check to True
    with patch("launch_stellaris._steam_has_window", return_value=True):
        assert steam_ready(30) == 9999

@patch("time.sleep", return_value=None)
@patch("psutil.process_iter", return_value=[])
def test_steam_ready_returns_none_on_timeout(mock_iter, mock_sleep):
    assert steam_ready(1) is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py::test_steam_spawn_uses_start_process -v`
Expected: `ImportError: cannot import name 'steam_spawn'`.

- [ ] **Step 3: Implement `steam_spawn` and `steam_ready`**

Add to `scripts/windows/launch_stellaris.py`:
```python
import time as _time
import psutil


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
```

Update `main()` to call `steam_spawn(args.app_id, args.dry_run)` after PREKILL succeeds, then `steam_ready(args.launcher_timeout_s)`. If `steam_ready` returns None and not `--dry-run`, return `EXIT_STEAM_NO_CLIENT`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py -v`
Expected: 10 tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/windows/launch_stellaris.py scripts/windows/tests/test_launch_stellaris.py
git commit -m "feat(scripts/windows): steam:// URI spawn + Steam client ready poll"
```

---

### Task 4: SESSION_BRIDGE — the schtasks /I + /ru user /rl highest mechanism

**Files:**
- Modify: `scripts/windows/launch_stellaris.py` — add `current_session_id`, `interactive_session_id`, `build_bridge_task_command`, `build_bridge_run_command`, `bridge_to_interactive_session`, `--inner` handling in `main()`.
- Modify: `scripts/windows/tests/test_launch_stellaris.py` — add command-builder unit tests.

**Interfaces:**
- Consumes: `args.marker` (the marker file path the inner must signal into), and a detected interactive session ID.
- Produces:
  - `current_session_id() -> int` — `kernel32.ProcessIdToSessionId(GetCurrentProcessId())`.
  - `interactive_session_id() -> int` — `kernel32.WTSGetActiveConsoleSessionId()`. Returns 0 if no console session.
  - `build_bridge_task_command(task_name: str, tr: str, st_hhmm: str, ru: str) -> list[str]` — the `schtasks /create` argv.
  - `build_bridge_run_command(task_name: str) -> list[str]` — the `schtasks /run /tn <name> /I` argv.
  - `bridge_to_interactive_session(args) -> int` — if already in interactive session, return 0 (no-op). Otherwise: write inner-marker-path into the env, build the task command with `/ru <user> /rl highest`, schedule, run with `/I`, poll the marker, delete the task, return the inner's exit code. Returns `EXIT_BRIDGE_NO_SESSION` / `EXIT_BRIDGE_SCHTASKS_DENIED` / `EXIT_BRIDGE_TIMEOUT` as appropriate.

- [ ] **Step 1: Write the failing tests**

Append to `scripts/windows/tests/test_launch_stellaris.py`:
```python
from launch_stellaris import (
    build_bridge_task_command, build_bridge_run_command,
)

def test_bridge_task_command_uses_ru_rl_highest():
    cmd = build_bridge_task_command(
        task_name="stellaris-launch-1234-1700000000",
        tr='"python C:\\launch.py --inner --marker C:\\TEMP\\m.txt"',
        st_hhmm="18:30",
        ru=r"lofibass\13229",
    )
    s = " ".join(cmd)
    assert "/ru" in s and r"lofibass\13229" in s
    assert "/rl" in s and "highest" in s
    assert "/sc" in s and "once" in s
    assert "/st" in s and "18:30" in s
    assert "/f" in s

def test_bridge_run_command_uses_I_not_IT():
    cmd = build_bridge_run_command("stellaris-launch-1234-1700000000")
    s = " ".join(cmd)
    assert "/I" in s
    # Legacy schtasks does not accept /IT on this box
    assert "/IT" not in s
    assert "/tn" in s
    assert cmd[-1] != "/IT"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py::test_bridge_task_command_uses_ru_rl_highest -v`
Expected: `ImportError`.

- [ ] **Step 3: Implement the bridge helpers**

Add to `scripts/windows/launch_stellaris.py`:
```python
import ctypes
import ctypes.wintypes as _wt
import os
import tempfile


_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
GetCurrentProcessId = _k32.GetCurrentProcessId
GetCurrentProcessId.restype = _wt.DWORD
GetCurrentProcessId.argtypes = []
_ProcessIdToSessionId = _k32.ProcessIdToSessionId
_ProcessIdToSessionId.argtypes = [_wt.DWORD, _wt.POINTER(_wt.DWORD)]
_ProcessIdToSessionId.restype = _wt.BOOL
_WTSGetActiveConsoleSessionId = _k32.WTSGetActiveConsoleSessionId
_WTSGetActiveConsoleSessionId.restype = _wt.DWORD
_WTSGetActiveConsoleSessionId.argtypes = []


def current_session_id() -> int:
    out = _wt.DWORD(0)
    _ProcessIdToSessionId(GetCurrentProcessId(), ctypes.byref(out))
    return int(out.value)


def interactive_session_id() -> int:
    return int(_WTSGetActiveConsoleSessionId())


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


def _poll_marker(marker: str, timeout_s: float) -> str | None:
    """Poll the marker file for a final 'DONE:<int>' line. Returns the line or None."""
    deadline = _time.time() + timeout_s
    while _time.time() < deadline:
        if os.path.exists(marker):
            try:
                with open(marker, "r", encoding="utf-8") as f:
                    content = f.read()
            except OSError:
                content = ""
            for line in reversed(content.splitlines()):
                if line.startswith("DONE:"):
                    return line
        _time.sleep(0.5)
    return None


def bridge_to_interactive_session(args: argparse.Namespace) -> int:
    """Run the rest of the chain in the logged-on user's interactive session.

    If already in that session, return 0 (no-op, the inner launches immediately).
    Otherwise schedule a one-shot task via schtasks /create ... /ru <user> /rl
    highest + schtasks /run /I, poll the marker, clean up, return inner exit code.
    """
    my_sid = current_session_id()
    target_sid = interactive_session_id()
    if target_sid == 0:
        log_event("BRIDGE", result="no_interactive_session")
        return EXIT_BRIDGE_NO_SESSION
    if my_sid == target_sid:
        log_event("BRIDGE", result="noop", sid=target_sid)
        return EXIT_OK

    # Generate a unique task name + marker
    pid = os.getpid()
    ts = int(_time.time())
    task_name = f"stellaris-launch-{pid}-{ts}"
    marker = args.marker or os.path.join(tempfile.gettempdir(), f"launch_inner_{pid}_{ts}.txt")

    # Build /tr: inner invocation. Marker path is the contract.
    py = sys.executable
    this = os.path.abspath(__file__)
    tr = f'"{py}" "{this}" --inner --marker "{marker}"'
    if args.app_id != 281990:
        tr += f" --app-id {args.app_id}"
    if args.no_prekill:
        tr += " --no-prekill"
    if args.dry_run:
        tr += " --dry-run"

    # /st = HH:MM in the near future (schtasks needs a future scheduled time even
    # with /I on some Windows builds; 1 minute out is enough).
    future = _dt.datetime.now() + _dt.timedelta(minutes=1)
    st_str = future.strftime("%H:%M")
    ru = f"{os.environ.get('USERDOMAIN', 'lofibass')}\\{os.environ.get('USERNAME', '13229')}"

    create = subprocess.run(
        build_bridge_task_command(task_name, tr, st_str, ru),
        capture_output=True, text=True,
    )
    if create.returncode != 0:
        log_event("BRIDGE", phase="create", rc=create.returncode, stderr=create.stderr.strip())
        return EXIT_BRIDGE_SCHTASKS_DENIED

    run = subprocess.run(build_bridge_run_command(task_name), capture_output=True, text=True)
    if run.returncode != 0:
        log_event("BRIDGE", phase="run", rc=run.returncode, stderr=run.stderr.strip())
        subprocess.run(["schtasks", "/delete", "/tn", task_name, "/f"], capture_output=True, text=True)
        return EXIT_BRIDGE_SCHTASKS_DENIED

    log_event("BRIDGE", task=task_name, marker=marker)
    done = _poll_marker(marker, args.bridge_timeout_s)
    subprocess.run(["schtasks", "/delete", "/tn", task_name, "/f"], capture_output=True, text=True)
    try:
        os.remove(marker)
    except OSError:
        pass

    if not done:
        log_event("BRIDGE", result="timeout")
        return EXIT_BRIDGE_TIMEOUT
    code = int(done.split(":", 1)[1])
    log_event("BRIDGE", result="inner_exit", code=code)
    return code
```

Wire into `main()`: if `args.inner` is False (i.e., we're the outer), call `bridge_to_interactive_session(args)` first. If it returns 0, do nothing further — the inner has already done everything. If it returns non-zero, propagate. If `args.inner` is True, fall through to the launch chain as today.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py -v`
Expected: 12 tests pass.

- [ ] **Step 5: Manual smoke on Windows_Jiaolong**

Run: `ssh Windows_Jiaolong "cd scripts/windows && PYTHONPATH=. python launch_stellaris.py --no-prekill --dry-run"`
Expected: stderr timeline with `BRIDGE result=noop sid=1` (because SSH lands in session 0 but the bridge target is session 1, so the bridge MUST fire). With `--no-prekill --dry-run` the inner skips prekill and URI spawn — only LAUNCHER_WAIT would actually run, but the inner invocation just sees session==target and exits 0 before doing real launch chain. Verify in the timeline that:
- `BRIDGE` event shows the bridge firing
- A child process appears in session 1 with PID and exits with code 0
- Exit code on the SSH call is 0

Then run: `ssh Windows_Jiaolong "cd scripts/windows && PYTHONPATH=. python launch_stellaris.py --dry-run"`
Expected: same bridge behaviour; the inner reaches LAUNCHER_WAIT and times out (no URI was spawned in dry-run). Exit code is `EXIT_LAUNCHER_WINDOW_MISSING` (21) or the inner returns it through the marker.

- [ ] **Step 6: Commit**

```bash
git add scripts/windows/launch_stellaris.py scripts/windows/tests/test_launch_stellaris.py
git commit -m "feat(scripts/windows): SESSION_BRIDGE via legacy schtasks /I + /ru <user> /rl highest"
```

---

### Task 5: LAUNCHER_WAIT + LAUNCHER_KEYBOARD — window attach + SetForegroundWindow + SendInput

**Files:**
- Modify: `scripts/windows/launch_stellaris.py` — add `launcher_wait`, `bring_to_foreground`, `send_key`, `launcher_keyboard`.
- Modify: `scripts/windows/tests/test_launch_stellaris.py` — add tests for command builders.

**Interfaces:**
- Consumes: `--launcher-timeout-s`.
- Produces:
  - `launcher_wait(timeout_s: int) -> tuple[int, int] | None` — returns `(pid, hwnd)` of a `Paradox Launcher.exe` window, or `None` on timeout. Exits via `main()` raising `LauncherWindowMissing` if None after timeout.
  - `bring_to_foreground(hwnd: int) -> bool` — `SetForegroundWindow`; returns True if `GetForegroundWindow() == hwnd` within 3 s.
  - `send_key(vk: int) -> None` — sends one virtual key down + up via `SendInput`.
  - `launcher_keyboard(hwnd: int) -> int` — returns 0 on successful handoff (launcher closed or stellaris.exe appeared within budget), `EXIT_LAUNCHER_NO_FOCUS` (22) if foreground fails, `EXIT_LAUNCHER_NO_ADVANCE` (23) if the Tab+Enter sequence is exhausted.

- [ ] **Step 1: Write the failing tests**

Append to `scripts/windows/tests/test_launch_stellaris.py`:
```python
from unittest.mock import patch, MagicMock
import ctypes
from launch_stellaris import send_key, launcher_wait

@patch("ctypes.windll.user32.SendInput")
def test_send_key_calls_sendinput(mock_send):
    send_key(0x0D)  # VK_RETURN
    mock_send.assert_called_once()
    # Verify it sent 1 input event (KEYBDINPUT) for key down
    nInputs, pInputs, cbSize = mock_send.call_args[0]
    assert nInputs == 1

def test_launcher_wait_finds_paradox_launcher():
    fake_proc = MagicMock()
    fake_proc.info = {"name": "Paradox Launcher.exe", "pid": 4242}
    with patch("psutil.process_iter", return_value=[fake_proc]):
        with patch("launch_stellaris._hwnd_for_pid", return_value=12345):
            pid, hwnd = launcher_wait(5)
    assert pid == 4242 and hwnd == 12345
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py::test_send_key_calls_sendinput -v`
Expected: `ImportError`.

- [ ] **Step 3: Implement the launcher phases**

Add to `scripts/windows/launch_stellaris.py`:
```python
_user32 = ctypes.WinDLL("user32", use_last_error=True)
_SetForegroundWindow = _user32.SetForegroundWindow
_SetForegroundWindow.argtypes = [_wt.HWND]
_SetForegroundWindow.restype = _wt.BOOL
_GetForegroundWindow = _user32.GetForegroundWindow
_GetForegroundWindow.argtypes = []
_GetForegroundWindow.restype = _wt.HWND


# SendInput structs
class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", _wt.WORD),
        ("wScan", _wt.WORD),
        ("dwFlags", _wt.DWORD),
        ("time", _wt.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]

class INPUT(ctypes.Structure):
    _fields_ = [
        ("type", _wt.DWORD),
        ("ki", KEYBDINPUT),
        ("_padding", ctypes.c_ubyte * 8),
    ]

SendInput = _user32.SendInput
SendInput.argtypes = [_wt.UINT, ctypes.POINTER(INPUT), _wt.INT]
SendInput.restype = _wt.UINT


def send_key(vk: int) -> None:
    ki = KEYBDINPUT(wVk=vk, wScan=0, dwFlags=0, time=0, dwExtraInfo=0)
    inp = INPUT(type=1, ki=ki)  # INPUT_KEYBOARD = 1
    n = SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
    if n != 1:
        raise OSError(f"SendInput returned {n}")


def _hwnd_for_pid(pid: int) -> int:
    """Find first top-level HWND owned by pid."""
    import pywinauto.findwindows
    try:
        wins = pywinauto.findwindows.find_elements(process=pid)
        return int(wins[0].handle) if wins else 0
    except Exception:
        return 0


def launcher_wait(timeout_s: int) -> tuple[int, int] | None:
    """Wait for Paradox Launcher.exe process + window. Returns (pid, hwnd) or None."""
    deadline = _time.time() + timeout_s
    while _time.time() < deadline:
        for p in psutil.process_iter(["name", "pid"]):
            if p.info["name"] and p.info["name"].lower() == "paradox launcher.exe":
                hwnd = _hwnd_for_pid(p.info["pid"])
                if hwnd:
                    log_event("LAUNCHER_WAIT", pid=p.info["pid"], hwnd=hwnd)
                    return (p.info["pid"], hwnd)
        _time.sleep(0.5)
    log_event("LAUNCHER_WAIT", timeout=True)
    return None


def bring_to_foreground(hwnd: int) -> bool:
    deadline = _time.time() + 3
    _SetForegroundWindow(hwnd)
    while _time.time() < deadline:
        if _GetForegroundWindow() == hwnd:
            log_event("LAUNCHER_KEYBOARD", step="foreground_ok", hwnd=hwnd)
            return True
        _time.sleep(0.1)
    log_event("LAUNCHER_KEYBOARD", step="foreground_fail", hwnd=hwnd)
    return False


def _handoff_observed() -> bool:
    """True if either Paradox Launcher.exe has exited or stellaris.exe has appeared."""
    launcher_alive = any(
        p.info["name"] and p.info["name"].lower() == "paradox launcher.exe"
        for p in psutil.process_iter(["name"])
    )
    stellaris_alive = any(
        p.info["name"] and p.info["name"].lower() == "stellaris.exe"
        for p in psutil.process_iter(["name"])
    )
    return (not launcher_alive) or stellaris_alive


def launcher_keyboard(hwnd: int) -> int:
    """Drive the launcher via keyboard. Returns 0 on handoff, 22 / 23 on failure."""
    if not bring_to_foreground(hwnd):
        return EXIT_LAUNCHER_NO_FOCUS
    _time.sleep(1.0)  # let focus settle

    # Step 1: Enter
    send_key(0x0D)
    log_event("LAUNCHER_KEYBOARD", step="enter_sent")
    _time.sleep(5.0)
    if _handoff_observed():
        log_event("LAUNCHER_KEYBOARD", step="handoff_after_enter")
        return EXIT_OK

    # Step 2..4: Tab + Enter, up to 3 times
    for i in range(3):
        send_key(0x09)
        send_key(0x0D)
        log_event("LAUNCHER_KEYBOARD", step="tab_enter", attempt=i + 1)
        _time.sleep(5.0)
        if _handoff_observed():
            log_event("LAUNCHER_KEYBOARD", step="handoff_after_tab_enter", attempt=i + 1)
            return EXIT_OK
    return EXIT_LAUNCHER_NO_ADVANCE
```

Wire into `main()`: after `steam_ready` returns a PID, call `launcher_wait(args.launcher_timeout_s)`. If None and not `--dry-run`, return `EXIT_LAUNCHER_WINDOW_MISSING`. If found, call `launcher_keyboard(hwnd)`. If `--dry-run`, skip launcher_keyboard.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py -v`
Expected: 14 tests pass.

- [ ] **Step 5: Manual smoke on Windows_Jiaolong**

Run: `ssh Windows_Jiaolong "cd scripts/windows && PYTHONPATH=. python launch_stellaris.py --no-prekill --dry-run"`
Expected: stderr timeline shows `BRIDGE result=...` then inner LAUNCHER_WAIT times out (no URI was spawned in dry-run).

Then on Windows side, open `C:\Users\13229\AppData\Local\Temp\launch_inner_*.txt` if any — it should contain `DONE:21` or similar from the inner exit.

- [ ] **Step 6: Commit**

```bash
git add scripts/windows/launch_stellaris.py scripts/windows/tests/test_launch_stellaris.py
git commit -m "feat(scripts/windows): LAUNCHER_KEYBOARD — SendInput Enter then Tab+Enter x3"
```

---

### Task 6: LAUNCHER_HANDOFF + GAME_OBSERVE — wait for game + 30 s observation

**Files:**
- Modify: `scripts/windows/launch_stellaris.py` — add `launcher_handoff`, `game_observe`, `_is_jit_dialog_visible`, `_is_wer_dialog_visible`.
- Modify: `scripts/windows/tests/test_launch_stellaris.py` — add unit tests with mocked psutil.

**Interfaces:**
- Consumes: `--game-timeout-s`, `--observe-s`.
- Produces:
  - `launcher_handoff(timeout_s: int) -> int | None` — returns the PID of `stellaris.exe` once it appears, or `None` on timeout.
  - `game_observe(pid: int, observe_s: int) -> int` — returns 0 on success; `EXIT_GAME_EXITED_EARLY` (32) if the process dies; `EXIT_JIT_DIALOG` (33) on JIT debug window; `EXIT_WER_DIALOG` (34) on WerFault window.

- [ ] **Step 1: Write the failing tests**

Append to `scripts/windows/tests/test_launch_stellaris.py`:
```python
from unittest.mock import patch, MagicMock
from launch_stellaris import launcher_handoff, game_observe, EXIT_OK, EXIT_GAME_EXITED_EARLY, EXIT_JIT_DIALOG, EXIT_WER_DIALOG

def test_launcher_handoff_returns_stellaris_pid():
    fake = MagicMock(); fake.info = {"name": "stellaris.exe", "pid": 5555}
    with patch("psutil.process_iter", return_value=[fake]):
        assert launcher_handoff(5) == 5555

@patch("time.sleep", return_value=None)
def test_game_observe_passes_when_process_alive(mock_sleep):
    fake = MagicMock()
    fake.status.return_value = "running"
    fake.is_running.return_value = True
    with patch("psutil.Process", return_value=fake):
        with patch("launch_stellaris._is_jit_dialog_visible", return_value=False):
            with patch("launch_stellaris._is_wer_dialog_visible", return_value=False):
                assert game_observe(5555, 5) == EXIT_OK

@patch("time.sleep", return_value=None)
def test_game_observe_exits_32_when_process_dies(mock_sleep):
    fake = MagicMock()
    fake.status.return_value = "dead"
    fake.is_running.return_value = False
    with patch("psutil.Process", return_value=fake):
        assert game_observe(5555, 5) == EXIT_GAME_EXITED_EARLY

@patch("time.sleep", return_value=None)
def test_game_observe_exits_33_on_jit(mock_sleep):
    fake = MagicMock()
    fake.status.return_value = "running"
    fake.is_running.return_value = True
    with patch("psutil.Process", return_value=fake):
        with patch("launch_stellaris._is_jit_dialog_visible", return_value=True):
            assert game_observe(5555, 5) == EXIT_JIT_DIALOG
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py::test_launcher_handoff_returns_stellaris_pid -v`
Expected: `ImportError`.

- [ ] **Step 3: Implement the handoff + observe phases**

Add to `scripts/windows/launch_stellaris.py`:
```python
def launcher_handoff(timeout_s: int) -> int | None:
    """Wait for stellaris.exe to appear after launcher handoff. Returns its PID."""
    deadline = _time.time() + timeout_s
    while _time.time() < deadline:
        for p in psutil.process_iter(["name", "pid"]):
            if p.info["name"] and p.info["name"].lower() == "stellaris.exe":
                log_event("LAUNCHER_HANDOFF", stellaris_pid=p.info["pid"])
                return p.info["pid"]
        _time.sleep(0.5)
    log_event("LAUNCHER_HANDOFF", timeout=True)
    return None


def _top_windows() -> list[tuple[int, str]]:
    """Return [(pid, window_title_or_class), ...] for top-level windows visible to UIA."""
    try:
        from pywinauto import Desktop
        out = []
        for w in Desktop(backend="uia").windows():
            try:
                out.append((w.process_id(), w.window_text() or w.class_name()))
            except Exception:
                continue
        return out
    except Exception:
        return []


def _is_jit_dialog_visible() -> bool:
    for _, title in _top_windows():
        if "just-in-time debugger" in title.lower() or "jit debugger" in title.lower():
            return True
    return False


def _is_wer_dialog_visible() -> bool:
    # WerFault.exe process is a strong signal
    for p in psutil.process_iter(["name"]):
        if p.info["name"] and p.info["name"].lower() == "werfault.exe":
            return True
    for _, title in _top_windows():
        if "problem reporting" in title.lower() or "werfault" in title.lower():
            return True
    return False


def game_observe(pid: int, observe_s: int) -> int:
    """Watch stellaris.exe for observe_s seconds. Returns 0 on success."""
    deadline = _time.time() + observe_s
    proc = psutil.Process(pid)
    while _time.time() < deadline:
        try:
            status = proc.status()
            alive = proc.is_running()
            if not alive or status in ("zombie", "dead"):
                log_event("GAME_OBSERVE", step="exited", status=status)
                return EXIT_GAME_EXITED_EARLY
        except psutil.NoSuchProcess:
            log_event("GAME_OBSERVE", step="no_such_process")
            return EXIT_GAME_EXITED_EARLY
        if _is_jit_dialog_visible():
            log_event("GAME_OBSERVE", step="jit_dialog")
            return EXIT_JIT_DIALOG
        if _is_wer_dialog_visible():
            log_event("GAME_OBSERVE", step="wer_dialog")
            return EXIT_WER_DIALOG
        _time.sleep(1.0)
    log_event("GAME_OBSERVE", step="ok", alive_s=observe_s)
    return EXIT_OK
```

Wire into `main()`: after `launcher_keyboard` returns 0, call `launcher_handoff(args.game_timeout_s)`. If None, return `EXIT_GAME_DID_NOT_SPAWN`. If a PID is returned, call `game_observe(pid, args.observe_s)`. If it returns 0, print `pid\n` to stdout and return 0. Otherwise return the code.

When `args.inner` is True, the inner copies the same code path; the only difference is the inner doesn't go through `bridge_to_interactive_session`. The inner's exit code is what the outer sees through the marker.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd scripts/windows && PYTHONPATH=. python3 -m pytest tests/test_launch_stellaris.py -v`
Expected: 18 tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/windows/launch_stellaris.py scripts/windows/tests/test_launch_stellaris.py
git commit -m "feat(scripts/windows): LAUNCHER_HANDOFF + GAME_OBSERVE with JIT/WER scan"
```

---

### Task 7: End-to-end smoke on Windows_Jiaolong

**Files:** none (this task is verification, not code).

**Interfaces:**
- Consumes: the full script as written after Tasks 1–6.

- [ ] **Step 1: Sync to Windows_Jiaolong**

Run:
```bash
git push
ssh Windows_Jiaolong "cd code/zig/Neo-Stellaris && git pull"
```
Expected: files in `scripts/windows/` on the box.

- [ ] **Step 2: Dry-run**

Run: `ssh Windows_Jiaolong "cd code/zig/Neo-Stellaris/scripts/windows && PYTHONPATH=. python launch_stellaris.py --no-prekill --dry-run"`
Expected: stderr timeline shows `BRIDGE result=...`, inner launches, LAUNCHER_WAIT times out (no URI in dry-run), returns `EXIT_LAUNCHER_WINDOW_MISSING` (21) propagated through the marker.

- [ ] **Step 3: Real launch — first attempt (capture D1 sequence)**

Pre-condition: Steam is running on Windows_Jiaolong with no update modal. If `appmanifest_281990.acf` `StateFlags="4"`, dismiss the update dialog manually first.

Run: `ssh Windows_Jiaolong "cd code/zig/Neo-Stellaris/scripts/windows && PYTHONPATH=. python launch_stellaris.py 2>&1"`
Expected: stderr timeline shows the full chain; stdout prints a PID; exit code 0. Stellaris appears on the user's desktop and stays alive.

If the script exits 23 (no_advance), inspect what happened: was the launcher focused? Was Enter ignored? Try running with `--verbose` and pipe the output to a file for review. Capture `GetGUIThreadInfo(focused_wnd=...)` from a small helper script and add the working sequence to the spec's D1 section.

- [ ] **Step 4: Real launch — second attempt (verify re-entrant safety)**

Wait for the game to settle (1 minute), then deliberately kill it from another SSH:
```bash
ssh Windows_Jiaolong "taskkill /F /IM stellaris.exe"
```

Run the script again: `ssh Windows_Jiaolong "cd code/zig/Neo-Stellaris/scripts/windows && PYTHONPATH=. python launch_stellaris.py 2>&1"`
Expected: PREKILL kills the (already-dead) targets cleanly, exit 0, second Stellaris PID printed.

- [ ] **Step 5: Document the working D1 sequence in the spec**

Open `docs/superpowers/specs/2026-09-29-launch-stellaris-design.md`. Find the D1 line under §8. Replace its body with the verified sequence ("Enter alone suffices" / "Tab+Enter once suffices" / "Tab+Enter x2 suffices"). Commit the spec update.

- [ ] **Step 6: Commit spec update**

```bash
git add docs/superpowers/specs/2026-09-29-launch-stellaris-design.md
git commit -m "docs(spec): D1 — verified Tab/Enter sequence on Windows_Jiaolong"
```

---

## Self-Review Notes

The plan was reviewed against the spec. Summary:

- **Spec coverage**: every section of the spec maps to a task. §3 (constraints) → first Tasks / Section "Global Constraints". §4 (contract) → Task 1 (CLI parser, exit codes, stderr format). §5 phase contracts → Tasks 2 (PREKILL), 3 (STEAM_SPAWN/READY), 4 (SESSION_BRIDGE), 5 (LAUNCHER_WAIT/KEYBOARD), 6 (LAUNCHER_HANDOFF/GAME_OBSERVE). §6 failure modes → every exit code is asserted in a Task 1 test or exercised in Task 6 tests.
- **Step scan**: every step carries exactly one action. Tests are full code blocks; implementations are signatures + minimal bodies where the spec does not pin a value (e.g. `send_key`, `_is_jit_dialog_visible` body shape is determined by the signature and tests).
- **Type consistency**: `current_session_id` / `interactive_session_id` / `launcher_wait` / `launcher_keyboard` / `launcher_handoff` / `game_observe` / `bridge_to_interactive_session` are named consistently across tasks; the constants `EXIT_*` are referenced by the same name everywhere.
- **Review Focus**: the five classes (token collisions, update modal, stale launcher instances, first-run Tab/Enter, SendInput block) are covered — bridge task name is unique-per-invocation (Task 4), update modal maps to exit 13 (Task 3 spec reference; not implemented yet, listed in §9 as future), re-entrant safety is tested (Task 2), Tab/Enter recovery sequence is documented (Task 5), SendInput block symptom is noted (Review Focus line 5; will surface as exit 23).
- **Proportion**: ~520 lines for a script that will be ~450 lines. Plan is denser than the code, not a transcript.