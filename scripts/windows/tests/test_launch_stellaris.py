import builtins
import contextlib
import ctypes
import ctypes.wintypes as _wt
import os
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import launch_stellaris
from launch_stellaris import (EXIT_BRIDGE_NO_SESSION,
                              EXIT_BRIDGE_SCHTASKS_DENIED, EXIT_BRIDGE_TIMEOUT,
                              EXIT_INTERNAL, EXIT_LAUNCHER_NO_ADVANCE,
                              EXIT_LAUNCHER_NO_FOCUS,
                              EXIT_LAUNCHER_WINDOW_MISSING, EXIT_OK,
                              EXIT_PREKILL_PERMISSION, _enum_windows_owned_by,
                              _poll_marker, _steam_has_window, _write_marker,
                              bridge_to_interactive_session, build_arg_parser,
                              build_bridge_account, build_bridge_run_command,
                              build_bridge_task_command, build_inner_tr,
                              prekill, steam_ready, steam_spawn,
                              timeline_event)


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


@patch("subprocess.run")
def test_prekill_treats_missing_process_as_success(mock_run):
    """taskkill returns rc=128 with 'not found' in stderr when the process is
    already gone. prekill must treat this as success — re-entrant safe
    (spec §3 're-entrant safe').
    """
    mock_run.return_value = MagicMock(
        returncode=128, stdout="",
        stderr='ERROR: The process "stellaris.exe" not found.',
    )
    assert prekill() == EXIT_OK
    # prekill must have issued at least one taskkill call per target image
    # (it iterates both 'stellaris.exe' and 'Paradox Launcher.exe').
    assert mock_run.call_count >= 1


@patch("subprocess.run")
def test_prekill_treats_missing_process_as_success_chinese(mock_run):
    """Chinese-locale taskkill returns '找不到' (not found) on missing process.

    The not-found check must match both English and Chinese localizations,
    otherwise a CN-locale machine breaks the re-entrant safety contract.
    """
    mock_run.return_value = MagicMock(
        returncode=128, stdout="",
        stderr='\u9519\u8bef: \u627e\u4e0d\u5230\u8fdb\u7a0b "stellaris.exe"\u3002',
    )
    assert prekill() == EXIT_OK
    assert mock_run.call_count >= 1


@patch("subprocess.run")
def test_steam_spawn_uses_start_process(mock_run):
    mock_run.return_value = MagicMock(returncode=0)
    steam_spawn(281990)
    args, kwargs = mock_run.call_args
    cmd = args[0]
    # URI is concatenated with 'Start-Process ...' into one -Command argument;
    # join the list to check for the URI substring (matches the sibling
    # assertion's pattern below).
    assert "steam://rungameid/281990" in " ".join(cmd)
    assert cmd[0].lower().endswith("powershell") or "start-process" in " ".join(cmd).lower()


@patch("time.sleep", return_value=None)
@patch("psutil.process_iter")
def test_steam_ready_returns_pid_when_steam_found(mock_iter, mock_sleep):
    p = MagicMock()
    p.info = {"name": "steam.exe", "pid": 9999}
    mock_iter.return_value = [p]
    # Patch the "has window" check to True
    with patch("launch_stellaris._steam_has_window", return_value=True):
        assert steam_ready(30) == 9999


@patch("time.sleep", return_value=None)
@patch("psutil.process_iter", return_value=[])
def test_steam_ready_returns_none_on_timeout(mock_iter, mock_sleep):
    assert steam_ready(1) is None


class _FakeUser32:
    """Stand-in for the three user32 bindings _user32_fns() hands back.

    Only the Win32 calls themselves need Windows; the PID-ownership matching
    is plain Python, so this lets the regressions below be checked on a
    non-Windows host. `owners` maps HWND -> owning PID. `enum_result` is what
    EnumWindows itself reports: True on a clean walk, False both when the
    callback stops it early and when enumeration genuinely fails.
    """

    def __init__(self, owners, enum_result=True):
        self.owners = dict(owners)
        self.visited = []
        self.enum_result = enum_result

    def enum_proc(self, fn):
        return fn  # WINFUNCTYPE wrapping is a no-op for a pure-Python callback

    def enum_windows(self, cb, lparam):
        for hwnd in self.owners:
            self.visited.append(hwnd)
            if not cb(hwnd, lparam):
                break  # Win32 stops the walk when the callback returns False
        return self.enum_result

    def get_thread_pid(self, hwnd, pid_ptr):
        ctypes.cast(pid_ptr, ctypes.POINTER(_wt.DWORD))[0] = self.owners[hwnd]
        return 1


@contextlib.contextmanager
def _bind_fake(owners, enum_result=True):
    """Point launch_stellaris._user32_fns at a _FakeUser32 for the block."""
    fake = _FakeUser32(owners, enum_result=enum_result)
    with patch("launch_stellaris._user32_fns",
               return_value=(fake.enum_windows, fake.enum_proc,
                             fake.get_thread_pid)):
        yield fake


def test_window_ownership_matches_pid_not_window_class():
    """Regression: Steam's real top-level window class on Windows_Jiaolong is
    'SDL_app', not 'Valve001'.

    Matching a hardcoded class string made _steam_has_window return False for
    every steam.exe, so steam_ready burned its whole budget and the run died at
    EXIT_STEAM_NO_CLIENT (11) before the launcher phases. Window ownership by
    PID is the only class-name-independent contract available.
    """
    with _bind_fake({10: 500, 11: 9999, 12: 7777}):
        assert _enum_windows_owned_by(9999) is True
        assert _enum_windows_owned_by(4242) is False


def test_window_ownership_stops_at_first_match():
    """The walk must stop as soon as a window owned by the PID shows up —
    otherwise every poll pays for all ~383 desktop windows on a real box."""
    with _bind_fake({10: 500, 11: 9999, 12: 9999, 13: 9999}) as fake:
        assert _enum_windows_owned_by(9999) is True
    assert fake.visited == [10, 11]


def test_window_ownership_false_when_desktop_has_no_windows():
    """EnumWindows yields nothing -> no window owned by that PID."""
    with _bind_fake({}):
        assert _enum_windows_owned_by(9999) is False


def test_enum_windows_failure_is_not_reported_as_no_window():
    """EnumWindows returns FALSE both when our callback stops the walk and when
    enumeration itself fails. Dropping the return value makes the second case
    indistinguishable from "this PID owns no window" — which is precisely the
    silent EXIT_STEAM_NO_CLIENT shape the PID-ownership fix just repaired.
    """
    with _bind_fake({10: 500}, enum_result=False) as fake, \
            pytest.raises(OSError):
        _enum_windows_owned_by(9999)
    assert fake.visited == [10]


def test_enum_windows_early_stop_is_not_a_failure():
    """The normal hit path stops the walk from the callback, so EnumWindows
    reports FALSE there too. That must not raise — otherwise every successful
    window match turns into a logged error."""
    with _bind_fake({10: 500, 11: 9999, 12: 9999}, enum_result=False) as fake:
        assert _enum_windows_owned_by(9999) is True
    assert fake.visited == [10, 11]


def test_steam_has_window_short_circuits_off_windows():
    """The non-Windows guard must stay ahead of any ctypes.WinDLL binding.

    ctypes.WinDLL does not exist on Linux; binding at import time would break
    the host-side test run this whole suite depends on.
    """
    with patch.object(launch_stellaris.sys, "platform", "linux"), \
            patch("launch_stellaris._user32_fns") as mock_fns:
        assert _steam_has_window(1234) is True
    mock_fns.assert_not_called()


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


def test_bridge_account_uses_computername_not_userdomain():
    """On a standalone box USERDOMAIN is the *workgroup* name (WORKGROUP on
    Windows_Jiaolong), which schtasks cannot resolve to a SID — it fails with
    'No mapping between account names and security IDs'. COMPUTERNAME is the
    prefix `whoami` prints, so it is the one that resolves.
    """
    assert build_bridge_account("lofibass", "13229") == r"lofibass\13229"
    # COMPUTERNAME must win over USERDOMAIN when both are present.
    with patch.dict(os.environ, {"COMPUTERNAME": "lofibass",
                                 "USERDOMAIN": "WORKGROUP",
                                 "USERNAME": "13229"}, clear=False):
        assert build_bridge_account() == r"lofibass\13229"


@patch("subprocess.run")
def test_bridge_returns_timeout_on_corrupt_marker(mock_run):
    """A torn or hand-edited marker must not escape as an uncaught ValueError.

    int() on a truncated 'DONE:' would otherwise kill the outer with a
    traceback and exit code 1, which is not a documented exit code at all.
    A marker we cannot read is a timeout (43), nothing else.
    """
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    args = build_arg_parser().parse_args(["--bridge-timeout-s", "1"])
    with patch("launch_stellaris.current_session_id", return_value=0), \
         patch("launch_stellaris.interactive_session_id", return_value=1), \
         patch("launch_stellaris._poll_marker", return_value="DONE:garbage"):
        assert bridge_to_interactive_session(args) == EXIT_BRIDGE_TIMEOUT


def test_marker_round_trip_carries_inner_exit_code():
    """_write_marker -> _poll_marker is the whole bridge contract: the inner
    writes DONE:<rc>, the outer reads it back. If this pair drifts, every
    bridged run degrades into a silent EXIT_BRIDGE_TIMEOUT (43).
    """
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        _write_marker(marker, EXIT_OK)
        assert _poll_marker(marker, timeout_s=1) == "DONE:0"

        _write_marker(marker, EXIT_LAUNCHER_WINDOW_MISSING)
        assert _poll_marker(marker, timeout_s=1) == "DONE:21"


@patch("time.sleep", return_value=None)
def test_poll_marker_returns_none_when_inner_never_signalled(mock_sleep):
    """No DONE: line means the inner died mid-chain. The outer must treat that
    as a timeout (43), not as a successful launch."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        Path(marker).write_text("", encoding="utf-8")
        assert _poll_marker(marker, timeout_s=1) is None


@patch("subprocess.run")
def test_bridge_create_failure_deletes_the_partial_task(mock_run):
    """A /create that fails after registering leaves a schtasks entry behind.
    The run-failure path right below it already cleans up; the create path has
    to as well, or every retry leaks another task."""
    mock_run.return_value = MagicMock(returncode=1, stdout="",
                                      stderr="ERROR: Access is denied.")
    args = build_arg_parser().parse_args(["--bridge-timeout-s", "1"])
    with patch("launch_stellaris.current_session_id", return_value=0), \
            patch("launch_stellaris.interactive_session_id", return_value=1):
        assert bridge_to_interactive_session(args) == EXIT_BRIDGE_SCHTASKS_DENIED
    invocations = [" ".join(c.args[0]) for c in mock_run.call_args_list]
    assert any("/delete" in i for i in invocations), invocations


@patch("subprocess.run")
def test_bridge_noop_session_runs_the_chain_inline(mock_run):
    """Already inside the logged-on session there is nothing to schedule.

    It must run the launch chain right here: returning 0 without running it —
    the plan's other, self-contradictory reading — turns an
    interactive-console invocation into a silent no-op that reports success
    without ever touching Steam. The inner's own code is what this pins.
    """
    args = build_arg_parser().parse_args([])
    with patch("launch_stellaris.current_session_id", return_value=1), \
            patch("launch_stellaris.interactive_session_id", return_value=1), \
            patch("launch_stellaris.run_launch_chain",
                  return_value=EXIT_LAUNCHER_NO_ADVANCE) as mock_chain:
        assert bridge_to_interactive_session(args) == EXIT_LAUNCHER_NO_ADVANCE
    mock_chain.assert_called_once_with(args)


def test_inner_tr_forwards_every_user_settable_flag():
    """The outer parses the CLI; the inner is a *different process* and only
    sees what the /tr string forwards. Anything dropped silently reverts to the
    argparse default in the inner — which is how a 120 s chain ends up dying on
    a 30 s budget nobody asked for."""
    args = build_arg_parser().parse_args([
        "--app-id", "12345",
        "--launcher-timeout-s", "111",
        "--game-timeout-s", "222",
        "--observe-s", "333",
        "--bridge-timeout-s", "444",
        "--no-prekill", "--dry-run", "--verbose",
    ])
    tr = build_inner_tr(args, marker=r"C:\TEMP\m.txt",
                        python=r"C:\py\python.exe",
                        script=r"C:\work\launch_stellaris.py")
    for expected in ("--inner",
                     '--marker "C:\\TEMP\\m.txt"',
                     "--app-id 12345",
                     "--launcher-timeout-s 111",
                     "--game-timeout-s 222",
                     "--observe-s 333",
                     "--bridge-timeout-s 444",
                     "--no-prekill",
                     "--dry-run",
                     "--verbose"):
        assert expected in tr, (expected, tr)


def test_inner_tr_omits_flags_the_user_did_not_set():
    """Forwarding must not invent flags either: the inner should see exactly
    the shape the user asked for, so a default run stays a default run."""
    args = build_arg_parser().parse_args([])
    tr = build_inner_tr(args, marker=r"C:\TEMP\m.txt")
    assert "--no-prekill" not in tr
    assert "--dry-run" not in tr
    assert "--verbose" not in tr
    assert "--inner" in tr and "--marker" in tr

