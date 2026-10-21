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

import launch_stellaris
import psutil
import pytest
from launch_stellaris import (EXIT_BRIDGE_NO_SESSION,
                              EXIT_BRIDGE_SCHTASKS_DENIED, EXIT_BRIDGE_TIMEOUT,
                              EXIT_BRIDGE_TR_TOO_LONG, EXIT_GAME_DID_NOT_SPAWN,
                              EXIT_GAME_EXITED_EARLY, EXIT_INTERNAL,
                              EXIT_JIT_DIALOG, EXIT_LAUNCHER_NO_ADVANCE,
                              EXIT_LAUNCHER_NO_FOCUS,
                              EXIT_LAUNCHER_WINDOW_MISSING, EXIT_OK,
                              EXIT_PREKILL_PERMISSION,
                              EXIT_STEAM_LOGIN_REQUIRED, EXIT_WER_DIALOG,
                              INPUT, INPUT_KEYBOARD, KEYBDINPUT, VK_RETURN,
                              VK_TAB, _enum_windows_owned_by,
                              _handoff_observed, _hwnd_for_pid,
                              _is_jit_dialog_visible, _is_wer_dialog_visible,
                              _poll_marker, _steam_has_window, _top_windows,
                              _write_marker, bridge_to_interactive_session,
                              bring_to_foreground, build_arg_parser,
                              build_bridge_account, build_bridge_run_command,
                              build_bridge_task_command, build_inner_tr,
                              game_observe, launcher_handoff,
                              launcher_keyboard, launcher_wait, prekill,
                              run_launch_chain, send_key, steam_ready,
                              steam_spawn, timeline_event)


def test_exit_codes_match_spec():
    assert EXIT_OK == 0
    assert EXIT_PREKILL_PERMISSION == 2
    assert EXIT_BRIDGE_NO_SESSION == 41
    assert EXIT_BRIDGE_SCHTASKS_DENIED == 42
    assert EXIT_BRIDGE_TIMEOUT == 43
    assert EXIT_BRIDGE_TR_TOO_LONG == 44
    assert EXIT_INTERNAL == 99


def test_timeline_event_format():
    line = timeline_event("PREKILL", killed_pids=[1234, 5678], reason="stale")
    # 2026-...  PREKILL  killed_pids=[1234, 5678]  reason=stale
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z  PREKILL  killed_pids=\[1234, 5678\]  reason=stale$", line)


def test_arg_parser_defaults():
    args = build_arg_parser().parse_args([])
    assert args.app_id == 281990
    assert args.observe_s == 30
    assert args.bridge_timeout_s == launch_stellaris.DEFAULT_BRIDGE_TIMEOUT_S
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


# ---------------------------------------------------------------------------
# Finding 1: schtasks /tr shim + typed EXIT_BRIDGE_TR_TOO_LONG.
#
# On the live box (Windows_Jiaolong), the inline /tr payload measured:
#   * 276 chars with default flags
#   * 309 chars with --no-prekill --dry-run --verbose
# Both blow schtasks' 261-character ceiling with the opaque error
#   '/tr' 选项值不能超过 261 个字符。
#   (Error: value for '/tr' option cannot be more than 261 characters)
# The shim replaces the inline command with a short path to a .cmd file.
# ---------------------------------------------------------------------------


def test_bridge_tr_shim_path_fits_schtasks_261_char_budget():
    """The whole point of the shim: schtasks refuses /tr values over 261
    characters. With inline command lines we measured 276 chars at default
    flags and 309 with --no-prekill --dry-run --verbose. The shim replaces
    the inline command with a short file path, so /tr carries a path whose
    length is bounded by the tempdir + a short basename.
    """
    from launch_stellaris import write_bridge_tr_shim
    args = build_arg_parser().parse_args([
        "--app-id", "12345",
        "--launcher-timeout-s", "111",
        "--game-timeout-s", "222",
        "--observe-s", "333",
        "--bridge-timeout-s", "444",
        "--no-prekill", "--dry-run", "--verbose",
    ])
    with tempfile.TemporaryDirectory() as td:
        shim = write_bridge_tr_shim(
            task_name="ls_smoke",
            inner_command=build_inner_tr(args, marker=r"C:\TEMP\m.txt"),
            tempdir=td,
        )
    assert len(shim) <= 261, (len(shim), shim)


def test_bridge_tr_shim_writes_echo_off_and_inner_command():
    """cmd.exe needs the @echo off prefix to suppress its own banner from
    drowning the inner chain's stderr timeline. The inner command itself
    must follow verbatim — that string is what build_inner_tr's tests pin.
    """
    from launch_stellaris import write_bridge_tr_shim
    args = build_arg_parser().parse_args([
        "--app-id", "12345",
        "--launcher-timeout-s", "111",
        "--no-prekill",
    ])
    with tempfile.TemporaryDirectory() as td:
        shim = write_bridge_tr_shim(
            task_name="ls_smoke",
            inner_command=build_inner_tr(args, marker=r"C:\TEMP\m.txt"),
            tempdir=td,
        )
        content = Path(shim).read_text(encoding="utf-8")
    # Header (case-insensitive — cmd accepts both, schtasks shims do too).
    assert content[:9].lower() == "@echo off"
    # Inner command: same shape build_inner_tr already pins.
    for expected in ("--inner", "--marker",
                     "--app-id 12345",
                     "--launcher-timeout-s 111",
                     "--no-prekill"):
        assert expected in content, (expected, content)


def test_bridge_tr_shim_naming_is_unique_per_task():
    """Two writes with the same content but different task names must not
    collide on disk — the bridge would otherwise race against its own prior
    shim during the cleanup window."""
    from launch_stellaris import write_bridge_tr_shim
    with tempfile.TemporaryDirectory() as td:
        a = write_bridge_tr_shim("ls_a", "echo a", tempdir=td)
        b = write_bridge_tr_shim("ls_b", "echo b", tempdir=td)
    assert a != b
    assert os.path.basename(a).startswith("ls_a")
    assert os.path.basename(b).startswith("ls_b")


def test_bridge_tr_shim_returns_loud_failure_when_path_still_too_long():
    """A tempdir whose own absolute path exceeds ~250 chars would push the
    shim path past 261. The bridge must not silently hand schtasks an
    over-budget /tr and let it fail opaquely — log the actual length and
    return the typed exit code.
    """
    from launch_stellaris import EXIT_BRIDGE_TR_TOO_LONG, _validate_tr_length

    # Build a string that is provably > 261 chars without tripping Linux's
    # NAME_MAX (255 bytes per component) — a single string is one component.
    long_tr = "C:\\" + ("very_long_segment" * 30) + "\\ls_shim.cmd"
    assert len(long_tr) > 261
    rc = _validate_tr_length(long_tr)
    assert rc == EXIT_BRIDGE_TR_TOO_LONG
    assert EXIT_BRIDGE_TR_TOO_LONG != EXIT_BRIDGE_SCHTASKS_DENIED, (
        "44 must be its own code — 42 already means schtasks rejected /create"
    )


def test_validate_tr_length_accepts_short_paths():
    """The pre-flight check must not return 44 on paths that fit. A 50-char
    shim path is what we get on every normal Windows box."""
    from launch_stellaris import _validate_tr_length
    assert _validate_tr_length(
        r"C:\Users\13229\AppData\Local\Temp\ls_99.cmd"
    ) is None


def test_validate_tr_length_boundary_accepts_exactly_the_limit():
    """Exactly 261 chars must still be accepted — schtasks treats the limit
    as inclusive on every build we tested."""
    from launch_stellaris import SCHTASKS_TR_LIMIT, _validate_tr_length

    # Path shape: "C:\\" (3 chars: C, :, \) + pad + ".cmd" (4 chars) = 7 fixed.
    # So pad is SCHTASKS_TR_LIMIT - 7. Using only 'a' avoids accidental separators.
    pad = "a" * (SCHTASKS_TR_LIMIT - 7)
    candidate = f"C:\\{pad}.cmd"
    assert len(candidate) == SCHTASKS_TR_LIMIT
    assert _validate_tr_length(candidate) is None


def test_validate_tr_length_rejects_one_char_over_the_limit():
    """One char over the limit must trigger 44 — the failure must not wait
    until the next multiple of some arbitrary bucket."""
    from launch_stellaris import (EXIT_BRIDGE_TR_TOO_LONG, SCHTASKS_TR_LIMIT,
                                  _validate_tr_length)
    pad = "a" * (SCHTASKS_TR_LIMIT - 7 + 1)  # one char over the limit
    assert _validate_tr_length(f"C:\\{pad}.cmd") == EXIT_BRIDGE_TR_TOO_LONG


def test_bridge_marker_path_is_short():
    """The marker path is forwarded into /tr too. Long names do not
    exhaust the 261 budget by themselves, but the shim's whole point is to
    keep the payload compact — start by trimming the marker."""
    from launch_stellaris import _default_marker_path
    path = _default_marker_path(pid=12345)
    # Old name: launch_inner_<pid>_<ts>.txt. New: ls_<pid>.txt.
    basename = os.path.basename(path)
    assert basename.startswith("ls_")
    assert "launch_inner" not in basename
    assert "12345" in basename


def test_bridge_tr_shim_is_deleted_by_the_cleanup_helper():
    """Cleanup must match create: every shim written gets removed on the
    same call site as the schtasks /delete, never leaking a .cmd into TEMP
    across runs."""
    from launch_stellaris import _delete_bridge_shim
    with tempfile.TemporaryDirectory() as td:
        shim = os.path.join(td, "ls_x.cmd")
        Path(shim).write_text("@echo off\r\necho x\r\n", encoding="utf-8")
        assert os.path.exists(shim)
        _delete_bridge_shim(shim)
        assert not os.path.exists(shim)


def test_bridge_tr_shim_cleanup_swallows_missing_file():
    """A shim that was already gone (manual cleanup, antivirus, prior run's
    retry) must not raise out of the cleanup path."""
    from launch_stellaris import _delete_bridge_shim

    # Should not raise even though the file does not exist.
    _delete_bridge_shim("/nonexistent/path/ls_already_gone.cmd")


def test_bridge_returns_44_when_shim_path_exceeds_schtasks_ceiling():
    """End-to-end: when the shim path is too long, bridge_to_interactive_session
    must short-circuit before /create with EXIT_BRIDGE_TR_TOO_LONG (44) and
    clean up the shim — never pass an over-budget /tr to schtasks."""
    from launch_stellaris import EXIT_BRIDGE_TR_TOO_LONG
    args = build_arg_parser().parse_args(["--bridge-timeout-s", "1"])
    long_tr = "C:\\" + ("very_long_segment" * 30) + "\\ls_shim.cmd"
    with patch("launch_stellaris.current_session_id", return_value=0), \
            patch("launch_stellaris.interactive_session_id", return_value=1), \
            patch("launch_stellaris.write_bridge_tr_shim",
                  return_value=long_tr) as mock_shim:
        rc = bridge_to_interactive_session(args)
    assert rc == EXIT_BRIDGE_TR_TOO_LONG
    # /create must not have been called — the pre-flight guard must reject
    # the payload before schtasks is ever invoked.
    mock_shim.assert_called_once()


# ---------------------------------------------------------------------------
# Finding 2: derive --bridge-timeout-s default from inner chain phase budgets.
#
# Phase budgets the inner traverses with all defaults:
#   prekill + steam_spawn   3s
#   steam_ready            30s   (= --launcher-timeout-s)
#   launcher_wait          30s   (= --launcher-timeout-s)
#   launcher_keyboard      24s   (Enter + 3x Tab+Enter, 5s wait each)
#   game_timeout           30s   (= --game-timeout-s, Task 6)
#   observe                30s   (= --observe-s, Task 6)
#                         ------
#                          147s
#
# The hard-coded 90 s default drifted below that as soon as Task 6 added
# 60 s of game-observe. A future change to any phase budget widens the
# bridge automatically because the default is derived from the sum.
# ---------------------------------------------------------------------------


def test_default_bridge_timeout_covers_inner_chain_phase_budgets():
    """A second magic number (90) drifted below the inner chain's worst case
    as soon as Task 6 added game-timeout + observe windows. The default must
    always exceed the sum of phase budgets — that's what stops a Task-7
    agent invocation from reporting 43 (bridge timeout) when the real
    failure is a launcher that never showed up.
    """
    inner = launch_stellaris._INNER_CHAIN_BUDGET_S
    default = launch_stellaris.DEFAULT_BRIDGE_TIMEOUT_S
    assert default > inner, (default, inner)


def test_default_bridge_timeout_reflects_every_phase_budget():
    """If any phase budget widens the default must widen with it. Pin the
    derivation so a future change to one of the constants without the other
    fails the test loudly.
    """
    components = [
        launch_stellaris._INNER_BUDGET_PREKILL_SPAWN_S,
        launch_stellaris._INNER_BUDGET_STEAM_READY_S,
        launch_stellaris._INNER_BUDGET_LAUNCHER_WAIT_S,
        launch_stellaris._INNER_BUDGET_LAUNCHER_KEYBOARD_S,
        launch_stellaris._INNER_BUDGET_GAME_OBSERVE_S,
    ]
    assert sum(components) == launch_stellaris._INNER_CHAIN_BUDGET_S
    assert launch_stellaris.DEFAULT_BRIDGE_TIMEOUT_S == (
        launch_stellaris._INNER_CHAIN_BUDGET_S
        + launch_stellaris._BRIDGE_TIMEOUT_MARGIN_S
    )


def test_inner_budget_table_tracks_the_argparse_defaults():
    """The budget constants are hand-written literals that *mirror* the CLI
    defaults, so summing them is self-consistent by construction — the
    derivation test above cannot fail unless someone edits the module. This
    one anchors them to build_arg_parser() instead: editing a CLI default
    without updating the table now fails here, instead of silently leaving the
    bridge (180 s) shorter than the inner chain it has to contain.

    Reachable today: --launcher-timeout-s 90 makes the inner traverse ~269 s
    against an unchanged 180 s bridge, so the outer reports a spurious 43.
    """
    args = build_arg_parser().parse_args([])
    assert args.launcher_timeout_s == launch_stellaris._INNER_BUDGET_STEAM_READY_S
    assert args.launcher_timeout_s == launch_stellaris._INNER_BUDGET_LAUNCHER_WAIT_S
    assert (args.game_timeout_s + args.observe_s) == (
        launch_stellaris._INNER_BUDGET_GAME_OBSERVE_S)


def test_inner_budget_keyboard_matches_the_key_sequence_it_covers():
    """The keyboard budget has no CLI flag, so nothing else ties it to the
    constants it is derived from: 1 focus settle, 1 Enter + 3x Tab+Enter, each
    followed by _KEY_SETTLE_S, inside a _FOREGROUND_TIMEOUT_S bring-to-front."""
    assert (launch_stellaris._FOREGROUND_TIMEOUT_S
            + launch_stellaris._FOCUS_SETTLE_S
            + launch_stellaris._KEY_SETTLE_S
            * (launch_stellaris._TAB_ENTER_ATTEMPTS + 1)) == (
        launch_stellaris._INNER_BUDGET_LAUNCHER_KEYBOARD_S)


def test_phase_timeout_help_flags_the_bridge_coupling():
    """--bridge-timeout-s is derived from the CLI defaults at import time, not
    recomputed from whatever the inner will actually do. Overriding a phase
    timeout past its default can therefore outlive the bridge, and the only
    hint the operator gets is a 43 that names nothing. Say so in --help.

    Read the action help rather than format_help(): the rendered output wraps
    to the terminal width, so a flag name can straddle a line break and make
    this pass or fail with the COLUMNS the suite happens to run under."""
    helps = {a.dest: a.help for a in build_arg_parser()._actions if a.help}
    # Each phase flag points at the bridge flag...
    for dest in ("launcher_timeout_s", "game_timeout_s", "observe_s"):
        assert "--bridge-timeout-s" in helps[dest], (dest, helps.get(dest))
    # ...and the bridge flag names the flags that can outrun it.
    for flag in ("--launcher-timeout-s", "--game-timeout-s", "--observe-s"):
        assert flag in helps["bridge_timeout_s"], (flag, helps["bridge_timeout_s"])


def test_build_inner_tr_docstring_documents_the_shim_not_the_tr_payload():
    """build_inner_tr returns the *shim body*; /tr receives the shim's path.

    The stale wording — "The /tr payload: the exact command line the inner
    will run" — reads as though this string is what schtasks length-checks,
    which invites "fixing" the 261-char ceiling by trimming forwarded flags.
    That is the exact regression the shim exists to prevent.
    """
    doc = build_inner_tr.__doc__ or ""
    assert "The /tr payload: the exact command line" not in doc
    assert "shim" in doc.lower(), doc


def test_bridge_rejects_a_non_ascii_shim_payload():
    """cmd.exe parses a .cmd shim in the OEM codepage (cp936 on the target
    box), not the utf-8 write_bridge_tr_shim uses. A CJK character in the
    python path, script path or marker path becomes mojibake, the inner never
    runs, and the run ends as a bare EXIT_BRIDGE_TIMEOUT (43) that names none
    of the real cause. Fail loudly and typed instead.

    Current paths are ASCII, so this does not bite yet — it is one line of
    guard against a box whose TEMP or checkout path is not."""
    args = build_arg_parser().parse_args(["--bridge-timeout-s", "1"])
    inner = (r'"C:\Python\python.exe" "D:\项目\scripts\launch_stellaris.py" '
             r'--inner --marker "C:\Users\用户\AppData\Local\Temp\ls_1.txt"')
    assert not inner.isascii()
    with patch("launch_stellaris.current_session_id", return_value=0), \
            patch("launch_stellaris.interactive_session_id", return_value=1), \
            patch("launch_stellaris.build_inner_tr", return_value=inner), \
            patch("subprocess.run") as mock_run:
        rc = bridge_to_interactive_session(args)
    assert rc == EXIT_BRIDGE_TR_TOO_LONG
    # Rejected before schtasks is ever invoked.
    mock_run.assert_not_called()


def test_bridge_accepts_an_ascii_shim_payload():
    """The guard must not reject the shape every real run uses."""
    args = build_arg_parser().parse_args(["--bridge-timeout-s", "1"])
    assert build_inner_tr(args, marker=r"C:\TEMP\m.txt",
                          python=r"C:\Python\python.exe",
                          script=r"D:\work\launch_stellaris.py").isascii()


@patch("launch_stellaris.prekill", side_effect=RuntimeError("psutil exploded"))
def test_run_launch_chain_converts_unexpected_exceptions_to_99(mock_prekill, capsys):
    """Carried in from the Task 5 review. Task 6 adds psutil and pywinauto
    calls that can raise; letting one escape returns from main() before
    _write_marker runs, so the outer bridge never learns the inner died, burns
    its whole budget, and reports 43 — hiding the real cause behind a timeout
    that means something else entirely."""
    assert run_launch_chain(build_arg_parser().parse_args([])) == EXIT_INTERNAL
    err = capsys.readouterr().err
    assert "internal_error" in err
    # The traceback has to be logged, not swallowed into a bare 99.
    assert "psutil exploded" in err
    assert "_run_launch_chain_phases" in err


@patch("launch_stellaris.prekill", side_effect=RuntimeError("psutil exploded"))
def test_run_launch_chain_guard_logs_one_line_per_event(mock_prekill, capsys):
    """The stderr timeline is one line per event; log_event joins fields with
    spaces, so a raw traceback would turn one broken run into a dozen
    unparseable lines for whoever is tailing the log."""
    run_launch_chain(build_arg_parser().parse_args([]))
    events = [ln for ln in capsys.readouterr().err.splitlines()
              if "internal_error" in ln]
    assert len(events) == 1, events


@patch("launch_stellaris.steam_spawn", return_value=EXIT_OK)
@patch("launch_stellaris.prekill", return_value=EXIT_STEAM_LOGIN_REQUIRED)
def test_run_launch_chain_guard_leaves_typed_failures_alone(
        mock_prekill, mock_spawn, capsys):
    """The guard catches exceptions, not non-zero returns. A typed phase code
    must still reach the marker verbatim — DONE:<rc> is the only thing the
    outer process learns about the inner."""
    rc = run_launch_chain(build_arg_parser().parse_args([]))
    assert rc == EXIT_STEAM_LOGIN_REQUIRED
    assert "internal_error" not in capsys.readouterr().err
    mock_spawn.assert_not_called()


def test_arg_parser_bridge_timeout_uses_derived_default():
    """The argparse default for --bridge-timeout-s must be the derived
    constant — the brief's whole point is that no second magic number
    lives in the parser.
    """
    args = build_arg_parser().parse_args([])
    assert args.bridge_timeout_s == launch_stellaris.DEFAULT_BRIDGE_TIMEOUT_S
    # The 90 s value is the one that drifted below 147 s. Keep it as a
    # reference point so a regression to the old default shows up as a
    # specific number, not a generic inequality.
    assert args.bridge_timeout_s > 147
    assert args.bridge_timeout_s != 90


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


def test_input_struct_layout_matches_the_sendinput_abi():
    """INPUT is 40 bytes on x64 and 28 on x86; SendInput rejects anything else.

    The brief's version spells the fields ctypes.wintypes.WORD/DWORD, which are
    c_ulong: 2 bytes and 8 bytes on this LP64 host but 2 and 4 on Windows. The
    struct would therefore be a silently wrong cbsize on any non-Windows import
    of this module. Fixed-width c_uint16/c_uint32 keeps one layout everywhere,
    and this assertion is what stops a future 'cleanup' back to _wt.
    """
    is_64 = ctypes.sizeof(ctypes.c_void_p) == 8
    assert ctypes.sizeof(KEYBDINPUT) == (24 if is_64 else 16)
    assert ctypes.sizeof(INPUT) == (40 if is_64 else 28)


def test_send_key_requests_one_keyboard_event_carrying_the_vk():
    send_input = MagicMock(return_value=1)
    with patch("launch_stellaris._input_fns",
               return_value=(MagicMock(), MagicMock(), send_input)):
        send_key(VK_RETURN)
    send_input.assert_called_once()
    n_inputs, p_inputs, cb_size = send_input.call_args[0]
    assert n_inputs == 1
    assert cb_size == ctypes.sizeof(INPUT)
    sent = ctypes.cast(p_inputs, ctypes.POINTER(INPUT))[0]
    assert sent.type == INPUT_KEYBOARD
    assert sent.ki.wVk == VK_RETURN


def test_send_key_raises_when_sendinput_delivers_nothing():
    """SendInput returns 0 when the keystroke was blocked — UIPI against a
    higher-integrity foreground window, typically. Swallowing that makes the
    whole Tab/Enter sequence a silent no-op that still reports success."""
    send_input = MagicMock(return_value=0)
    with patch("launch_stellaris._input_fns",
               return_value=(MagicMock(), MagicMock(), send_input)), \
            pytest.raises(OSError):
        send_key(VK_RETURN)


@contextlib.contextmanager
def _fake_pywinauto(elements=(), side_effect=None):
    """Stand in for the pywinauto package _hwnd_for_pid imports.

    Both keys are needed: `import pywinauto.findwindows` resolves the parent
    package first, and patching only the submodule leaves the parent missing.
    The yield value is the findwindows module stand-in, so find_elements can be
    asserted on.
    """
    fake_fw = MagicMock()  # stands in for pywinauto.findwindows
    if side_effect is not None:
        fake_fw.find_elements.side_effect = side_effect
    else:
        fake_fw.find_elements.return_value = list(elements)
    fake_parent = MagicMock()  # stands in for the pywinauto package
    fake_parent.findwindows = fake_fw
    with patch.dict(sys.modules, {"pywinauto": fake_parent,
                                  "pywinauto.findwindows": fake_fw},
                    clear=False):
        yield fake_fw


def test_hwnd_for_pid_returns_zero_when_the_lookup_fails():
    """pywinauto raises for a process that died between the scan and the
    lookup. A raise here kills launcher_wait's poll loop mid-budget and the
    whole run ends at EXIT_LAUNCHER_WINDOW_MISSING (21)."""
    with _fake_pywinauto(side_effect=RuntimeError("no such pid")):
        assert _hwnd_for_pid(4242) == 0


def test_hwnd_for_pid_returns_zero_for_a_process_with_no_window():
    with _fake_pywinauto(elements=[]):
        assert _hwnd_for_pid(4242) == 0


def test_hwnd_for_pid_returns_the_first_window_handle():
    with _fake_pywinauto(elements=[MagicMock(handle=12345)]) as fake_fw:
        assert _hwnd_for_pid(4242) == 12345
    fake_fw.find_elements.assert_called_once_with(process=4242)


def test_hwnd_for_pid_absorbs_a_missing_pywinauto():
    """pywinauto is a requirements.txt entry, not a hard dependency. Without it
    every lookup returns 0 and the run dies at EXIT_LAUNCHER_WINDOW_MISSING
    (21) — but crashing mid-poll would be worse than a clean 21."""
    real_import = builtins.__import__

    def no_pywinauto(name, *a, **kw):
        if name.split(".")[0] == "pywinauto":
            raise ModuleNotFoundError("No module named 'pywinauto'")
        return real_import(name, *a, **kw)

    with patch("builtins.__import__", side_effect=no_pywinauto):
        assert _hwnd_for_pid(4242) == 0


class _Clock:
    """Fake _time: advances only when the code under test sleeps."""

    def __init__(self):
        self.t = 0.0
        self.slept = []

    def time(self):
        return self.t

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.t += seconds


@contextlib.contextmanager
def _fake_clock():
    clock = _Clock()
    with patch("launch_stellaris._time", clock):
        yield clock


def _fake_proc(name, pid=1):
    p = MagicMock()
    p.info = {"name": name, "pid": pid}
    return p


@contextlib.contextmanager
def _launcher_visible(name="Paradox Launcher.exe", pid=4242, hwnd=12345):
    with _fake_clock(), \
            patch("psutil.process_iter",
                  return_value=[_fake_proc(name, pid)]), \
            patch("launch_stellaris._hwnd_for_pid", return_value=hwnd):
        yield


def test_launcher_wait_returns_pid_and_hwnd():
    with _launcher_visible():
        assert launcher_wait(30) == (4242, 12345)


def test_launcher_wait_matches_the_process_name_case_insensitively():
    """Windows file names are case-insensitive and psutil reports whatever
    the image has. 'paradox launcher.exe' vs 'Paradox Launcher.exe' must not
    decide whether the run gets an HWND at all."""
    with _launcher_visible(name="PARADOX LAUNCHER.EXE"):
        assert launcher_wait(30) == (4242, 12345)


def test_launcher_wait_returns_none_when_the_launcher_never_appears():
    with _fake_clock(), patch("psutil.process_iter", return_value=[]):
        assert launcher_wait(30) is None


def test_launcher_wait_keeps_polling_until_the_window_shows_up():
    """The Paradox Launcher process exists before its CEF window does. A
    single-shot probe would report EXIT_LAUNCHER_WINDOW_MISSING on every real
    launch, and a window-less launcher would hand a null HWND to SendInput."""
    attempts = []

    def hwnd_for_pid(pid):
        attempts.append(pid)
        return 777 if len(attempts) >= 3 else 0

    with _fake_clock(), \
            patch("psutil.process_iter",
                  return_value=[_fake_proc("Paradox Launcher.exe", 4242)]), \
            patch("launch_stellaris._hwnd_for_pid", side_effect=hwnd_for_pid):
        assert launcher_wait(30) == (4242, 777)
    assert attempts == [4242, 4242, 4242]


def test_bring_to_foreground_succeeds_once_it_owns_the_foreground():
    set_fg, get_fg = MagicMock(), MagicMock(return_value=4242)
    with _fake_clock(), \
            patch("launch_stellaris._input_fns",
                  return_value=(set_fg, get_fg, MagicMock())):
        assert bring_to_foreground(4242) is True
    set_fg.assert_called_once_with(4242)


def test_bring_to_foreground_gives_up_when_another_window_keeps_focus():
    """Bring-to-front is refused across integrity levels and when the calling
    process does not own the foreground. Keystrokes then land in whatever
    window the user last touched."""
    set_fg, get_fg = MagicMock(), MagicMock(return_value=9999)
    with _fake_clock(), \
            patch("launch_stellaris._input_fns",
                  return_value=(set_fg, get_fg, MagicMock())):
        assert bring_to_foreground(4242) is False


def test_handoff_observed_when_the_launcher_exits():
    with patch("psutil.process_iter", return_value=[_fake_proc("steam.exe", 1)]):
        assert _handoff_observed() is True


def test_handoff_observed_when_stellaris_appears_beside_the_launcher():
    procs = [_fake_proc("Paradox Launcher.exe", 2), _fake_proc("stellaris.exe", 3)]
    with patch("psutil.process_iter", return_value=procs):
        assert _handoff_observed() is True


def test_handoff_not_observed_while_only_the_launcher_is_alive():
    """The launcher staying put means the keystrokes did not land. Reporting a
    handoff here hands Task 6 a launcher window and no game."""
    with patch("psutil.process_iter",
               return_value=[_fake_proc("Paradox Launcher.exe", 2)]):
        assert _handoff_observed() is False


@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.send_key")
@patch("launch_stellaris.bring_to_foreground", return_value=True)
def test_launcher_keyboard_returns_22_when_focus_fails(mock_fg, mock_key, mock_sleep):
    """Keystrokes sent to a window that is not foreground go to the window that
    is. Refuse instead of typing into whatever the user had open."""
    mock_fg.return_value = False
    assert launcher_keyboard(4242) == EXIT_LAUNCHER_NO_FOCUS
    mock_key.assert_not_called()


@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.send_key", side_effect=OSError(5, "access denied"))
@patch("launch_stellaris.bring_to_foreground", return_value=True)
def test_launcher_keyboard_reports_no_focus_when_sendinput_is_blocked(
        mock_fg, mock_key, mock_sleep):
    """SendInput returning 0 means UIPI refused the keystroke. Letting that
    OSError escape would exit main() with code 1 — undocumented, and worse, the
    run returns before _write_marker, so the outer bridge never learns the inner
    died and sits there until its own timeout, reporting 43 instead."""
    assert launcher_keyboard(4242) == EXIT_LAUNCHER_NO_FOCUS


@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.send_key")
@patch("launch_stellaris.bring_to_foreground", return_value=True)
@patch("launch_stellaris._handoff_observed", return_value=False)
def test_launcher_keyboard_returns_23_after_exhausting_the_sequence(
        mock_handoff, mock_fg, mock_key, mock_sleep):
    assert launcher_keyboard(4242) == EXIT_LAUNCHER_NO_ADVANCE
    # Enter, then Tab+Enter three times — the whole documented sequence, in order.
    assert [c.args[0] for c in mock_key.call_args_list] == [
        VK_RETURN, VK_TAB, VK_RETURN, VK_TAB, VK_RETURN, VK_TAB, VK_RETURN]
    # One probe after Enter, one after each Tab+Enter: no probe is missing.
    assert mock_handoff.call_count == 4


@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.send_key")
@patch("launch_stellaris.bring_to_foreground", return_value=True)
@patch("launch_stellaris._handoff_observed", return_value=True)
def test_launcher_keyboard_stops_when_plain_enter_is_enough(
        mock_handoff, mock_fg, mock_key, mock_sleep):
    """The launcher's default focus is the Play button. Every extra keystroke
    after handoff types into a game that is already loading."""
    assert launcher_keyboard(4242) == EXIT_OK
    assert [c.args[0] for c in mock_key.call_args_list] == [VK_RETURN]
    assert mock_handoff.call_count == 1


@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.send_key")
@patch("launch_stellaris.bring_to_foreground", return_value=True)
@patch("launch_stellaris._handoff_observed", side_effect=[False, True])
def test_launcher_keyboard_stops_at_the_first_tab_enter_that_works(
        mock_handoff, mock_fg, mock_key, mock_sleep):
    assert launcher_keyboard(4242) == EXIT_OK
    assert [c.args[0] for c in mock_key.call_args_list] == [
        VK_RETURN, VK_TAB, VK_RETURN]
    assert mock_handoff.call_count == 2


@patch("launch_stellaris.game_observe", return_value=EXIT_OK)
@patch("launch_stellaris.launcher_handoff", return_value=5555)
@patch("launch_stellaris.launcher_keyboard", return_value=EXIT_OK)
@patch("launch_stellaris.launcher_wait", return_value=(4242, 12345))
@patch("launch_stellaris.steam_ready", return_value=10748)
@patch("launch_stellaris.steam_spawn", return_value=EXIT_OK)
@patch("launch_stellaris.prekill", return_value=EXIT_OK)
def test_run_launch_chain_waits_for_the_launcher_window_then_drives_it(
        mock_prekill, mock_spawn, mock_ready, mock_wait, mock_keyboard,
        mock_handoff, mock_observe):
    assert run_launch_chain(build_arg_parser().parse_args([])) == EXIT_OK
    mock_wait.assert_called_once_with(30)  # --launcher-timeout-s default
    mock_keyboard.assert_called_once_with(12345)
    # Task 6: the drive is not the end of the chain — the game has to appear
    # and then survive its observation window.
    mock_handoff.assert_called_once_with(30)  # --game-timeout-s default
    mock_observe.assert_called_once_with(5555, 30)  # --observe-s default


@patch("launch_stellaris.launcher_keyboard", return_value=EXIT_LAUNCHER_NO_ADVANCE)
@patch("launch_stellaris.launcher_wait", return_value=(4242, 12345))
@patch("launch_stellaris.steam_ready", return_value=10748)
@patch("launch_stellaris.steam_spawn", return_value=EXIT_OK)
@patch("launch_stellaris.prekill", return_value=EXIT_OK)
def test_run_launch_chain_propagates_a_keyboard_failure(
        mock_prekill, mock_spawn, mock_ready, mock_wait, mock_keyboard):
    """The launcher's own exit code has to reach the bridge marker verbatim —
    that DONE:<rc> is the only thing the outer process learns."""
    assert run_launch_chain(build_arg_parser().parse_args([])) == EXIT_LAUNCHER_NO_ADVANCE


@patch("launch_stellaris.launcher_wait", return_value=None)
@patch("launch_stellaris.steam_ready", return_value=10748)
@patch("launch_stellaris.steam_spawn", return_value=EXIT_OK)
@patch("launch_stellaris.prekill", return_value=EXIT_OK)
def test_run_launch_chain_returns_21_when_no_launcher_window_appears(
        mock_prekill, mock_spawn, mock_ready, mock_wait):
    assert run_launch_chain(build_arg_parser().parse_args([])) == EXIT_LAUNCHER_WINDOW_MISSING


@patch("launch_stellaris.launcher_keyboard", return_value=EXIT_OK)
@patch("launch_stellaris.launcher_wait", return_value=(4242, 12345))
@patch("launch_stellaris.steam_ready", return_value=None)
@patch("launch_stellaris.steam_spawn", return_value=EXIT_OK)
@patch("launch_stellaris.prekill", return_value=EXIT_OK)
def test_run_launch_chain_dry_run_skips_the_keyboard(
        mock_prekill, mock_spawn, mock_ready, mock_wait, mock_keyboard):
    """--dry-run spawns no URI, so no launcher exists and there is no window to
    type into. Typing anyway would hammer whatever window the user has open."""
    args = build_arg_parser().parse_args(["--dry-run"])
    assert run_launch_chain(args) == EXIT_OK
    mock_keyboard.assert_not_called()


@patch("launch_stellaris.launcher_wait", return_value=None)
@patch("launch_stellaris.steam_ready", return_value=None)
@patch("launch_stellaris.steam_spawn", return_value=EXIT_OK)
@patch("launch_stellaris.prekill", return_value=EXIT_OK)
def test_run_launch_chain_dry_run_tolerates_a_missing_launcher_window(
        mock_prekill, mock_spawn, mock_ready, mock_wait):
    """Same reasoning as the Steam-client branch above: a dry run legitimately
    finds nothing, and reporting 21 there would make --dry-run unusable as the
    pre-flight check it exists to be."""
    args = build_arg_parser().parse_args(["--dry-run"])
    assert run_launch_chain(args) == EXIT_OK


# ---------------------------------------------------------------------------
# Task 6: LAUNCHER_HANDOFF + GAME_OBSERVE.
#
# The launcher drive is not the end of the chain. These two phases turn
# "we pressed some keys" into "here is a PID you can watch", and that PID
# into a typed verdict.
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _game_spawning(game_name="stellaris.exe", pid=5555, other_name="steam.exe"):
    """A desktop where `game_name` is present from the very first poll."""
    procs = [_fake_proc(other_name, 1)]
    if game_name:
        procs.append(_fake_proc(game_name, pid))
    with _fake_clock(), patch("psutil.process_iter", return_value=procs):
        yield


def test_launcher_handoff_returns_the_stellaris_pid():
    with _game_spawning():
        assert launcher_handoff(30) == 5555


def test_launcher_handoff_matches_the_game_image_case_insensitively():
    """Windows image names are case-insensitive and psutil reports whatever
    the process has. A case-sensitive match here is EXIT_GAME_DID_NOT_SPAWN
    (31) on a real run, for no reason at all."""
    with _game_spawning(game_name="STELLARIS.EXE"):
        assert launcher_handoff(30) == 5555


def test_launcher_handoff_returns_none_when_the_game_never_appears():
    """The launcher exited without ever producing a game. 31, not a hang —
    --game-timeout-s exists precisely so this terminates."""
    with _fake_clock(), patch("psutil.process_iter", return_value=[]):
        assert launcher_handoff(30) is None


def test_launcher_handoff_keeps_polling_until_the_game_appears():
    """launcher_keyboard stops at the first handoff *signal*, which also fires
    when the launcher merely exits. The game can lag that by seconds — a
    single-shot probe reports 31 on every real launch."""
    scans = []

    def process_iter(*_a, **_kw):
        scans.append(1)
        return [_fake_proc("stellaris.exe", 5555)] if len(scans) >= 3 else []

    with _fake_clock(), patch("psutil.process_iter", side_effect=process_iter):
        assert launcher_handoff(30) == 5555
    assert len(scans) == 3, scans


def test_launcher_handoff_ignores_a_still_running_launcher():
    """The launcher outliving its own window is normal — it is the *game's*
    appearance that ends this phase, not the launcher's absence."""
    procs = [_fake_proc("Paradox Launcher.exe", 4242),
             _fake_proc("stellaris.exe", 5555)]
    with _fake_clock(), patch("psutil.process_iter", return_value=procs):
        assert launcher_handoff(30) == 5555


def test_launcher_handoff_stops_polling_within_its_budget():
    """A spent budget must terminate the phase rather than spin — this loop
    is one of the terms the bridge timeout is derived from."""
    with _fake_clock() as clock, patch("psutil.process_iter", return_value=[]):
        assert launcher_handoff(30) is None
    assert clock.t <= 30, clock.t


def _fake_window(pid=100, text="Steam", cls="#32770"):
    w = MagicMock()
    w.process_id.return_value = pid
    w.window_text.return_value = text
    w.class_name.return_value = cls
    return w


@contextlib.contextmanager
def _fake_desktop(windows=(), side_effect=None):
    """Stand in for the `pywinauto` package _top_windows imports."""
    fake = MagicMock()  # stands in for the pywinauto package
    if side_effect is not None:
        fake.Desktop.side_effect = side_effect
    else:
        fake.Desktop.return_value.windows.return_value = list(windows)
    with patch.dict(sys.modules, {"pywinauto": fake}, clear=False):
        yield fake


def test_top_windows_returns_pid_and_title_pairs():
    with _fake_desktop([_fake_window(10748, "Steam"),
                        _fake_window(4242, "Paradox Launcher")]):
        assert _top_windows() == [(10748, "Steam"), (4242, "Paradox Launcher")]


def test_top_windows_falls_back_to_the_class_when_there_is_no_title():
    """A dialog with an empty window text still has a class, and a JIT or WER
    dialog routinely has one. Dropping it loses the match entirely."""
    with _fake_desktop([_fake_window(7, text="", cls="#32770")]):
        assert _top_windows() == [(7, "#32770")]


def test_top_windows_uses_the_uia_backend():
    """UIA is the only backend that spans processes — the JIT and WER dialogs
    belong to processes this chain knows nothing about."""
    with _fake_desktop([]) as fake:
        _top_windows()
    fake.Desktop.assert_called_once_with(backend="uia")


def test_top_windows_survives_one_window_dying_mid_scan():
    """A window can close between enumeration and access. One dead handle
    must not truncate the scan — that is how a crash dialog sitting *after*
    it in the list gets missed, which is the one false negative that matters
    here."""
    alive = _fake_window(4242, "WerFault.exe")
    dead = MagicMock()
    dead.process_id.side_effect = RuntimeError("handle is gone")
    with _fake_desktop([dead, alive]):
        assert _top_windows() == [(4242, "WerFault.exe")]


def test_top_windows_absorbs_a_missing_pywinauto():
    """pywinauto is a requirements.txt entry, not a hard dependency. Raising
    here escapes game_observe and surfaces as EXIT_INTERNAL (99), blaming our
    own code for a perfectly healthy game."""
    real_import = builtins.__import__

    def no_pywinauto(name, *a, **kw):
        if name.split(".")[0] == "pywinauto":
            raise ModuleNotFoundError("No module named 'pywinauto'")
        return real_import(name, *a, **kw)

    with patch("builtins.__import__", side_effect=no_pywinauto):
        assert _top_windows() == []


def test_is_jit_dialog_visible_matches_the_dialog_title():
    with _fake_desktop([_fake_window(7, "Visual Studio Just-In-Time Debugger")]):
        assert _is_jit_dialog_visible() is True


def test_is_jit_dialog_visible_ignores_ordinary_windows():
    """A false positive here ends a healthy run at EXIT_JIT_DIALOG (33),
    telling the agent the game crashed while it is loading perfectly well."""
    with _fake_desktop([_fake_window(10748, "Steam"),
                        _fake_window(4242, "Paradox Launcher"),
                        _fake_window(5555, "stellaris.exe")]):
        assert _is_jit_dialog_visible() is False


def test_is_wer_dialog_visible_matches_the_werfault_process():
    """The process is the locale-independent signal — a CN-locale box never
    says "problem reporting" in the title."""
    with patch("psutil.process_iter", return_value=[_fake_proc("WerFault.exe", 900)]):
        assert _is_wer_dialog_visible() is True


def test_is_wer_dialog_visible_matches_a_report_dialog_title():
    with _fake_desktop([_fake_window(9, "Problem Reporting")]), \
            patch("psutil.process_iter", return_value=[]):
        assert _is_wer_dialog_visible() is True


def test_is_wer_dialog_visible_is_false_for_a_clean_desktop():
    procs = [_fake_proc("steam.exe", 1), _fake_proc("stellaris.exe", 5555)]
    with _fake_desktop([_fake_window(5555, "stellaris.exe")]), \
            patch("psutil.process_iter", return_value=procs):
        assert _is_wer_dialog_visible() is False


@contextlib.contextmanager
def _observing(status="running", alive=True):
    """A game process with fixed status()/is_running(), and a clean desktop."""
    proc = MagicMock()
    proc.status.return_value = status
    proc.is_running.return_value = alive
    with _fake_clock(), \
            patch("psutil.Process", return_value=proc), \
            patch("launch_stellaris._top_windows", return_value=[]), \
            patch("launch_stellaris._is_jit_dialog_visible", return_value=False), \
            patch("launch_stellaris._is_wer_dialog_visible", return_value=False):
        yield proc


def test_game_observe_passes_when_the_game_survives_the_window():
    with _observing():
        assert game_observe(5555, 30) == EXIT_OK


def test_game_observe_exits_32_when_the_process_dies():
    with _observing(status="dead", alive=False):
        assert game_observe(5555, 30) == EXIT_GAME_EXITED_EARLY


def test_game_observe_exits_32_for_a_zombie():
    """A zombie still answers psutil.Process and still owns a PID, so
    is_running() can be True while the game itself is long gone."""
    with _observing(status="zombie", alive=True):
        assert game_observe(5555, 30) == EXIT_GAME_EXITED_EARLY


def test_game_observe_exits_32_when_the_process_is_already_gone():
    """psutil.Process() itself raises here, *outside* the brief's try block.
    Letting that escape becomes EXIT_INTERNAL (99) via the chain guard, which
    blames our own code for a game that merely died on its own."""
    with _fake_clock(), patch("psutil.Process", side_effect=psutil.NoSuchProcess(5555)):
        assert game_observe(5555, 30) == EXIT_GAME_EXITED_EARLY


def test_game_observe_exits_32_when_the_process_dies_mid_sample():
    proc = MagicMock()
    proc.status.side_effect = psutil.NoSuchProcess(5555)
    with _fake_clock(), patch("psutil.Process", return_value=proc):
        assert game_observe(5555, 30) == EXIT_GAME_EXITED_EARLY


def test_game_observe_exits_33_on_a_jit_dialog():
    with _observing(), \
            patch("launch_stellaris._is_jit_dialog_visible", return_value=True):
        assert game_observe(5555, 30) == EXIT_JIT_DIALOG


def test_game_observe_exits_34_on_a_wer_dialog():
    with _observing(), \
            patch("launch_stellaris._is_wer_dialog_visible", return_value=True):
        assert game_observe(5555, 30) == EXIT_WER_DIALOG


def test_game_observe_prefers_the_dead_process_over_the_dialog():
    """Both true: the game died AND a dialog is up. 32 is the root cause; 33
    or 34 would send the agent chasing a debugger that is not the problem."""
    proc = MagicMock()
    proc.status.return_value = "dead"
    proc.is_running.return_value = False
    with _fake_clock(), \
            patch("psutil.Process", return_value=proc), \
            patch("launch_stellaris._is_jit_dialog_visible",
                  return_value=True) as jit, \
            patch("launch_stellaris._is_wer_dialog_visible",
                  return_value=True) as wer:
        assert game_observe(5555, 30) == EXIT_GAME_EXITED_EARLY
    jit.assert_not_called()
    wer.assert_not_called()


def test_game_observe_scans_the_desktop_once_per_tick():
    """UIA top-level enumeration is the most expensive thing in this loop and
    both dialog probes need the same snapshot. Two scans a second for 30 s is
    a wasted desktop walk on every single launch."""
    with _observing(), \
            patch("launch_stellaris._top_windows", return_value=[]) as scan, \
            patch("launch_stellaris._is_jit_dialog_visible",
                  side_effect=lambda wins: False) as jit, \
            patch("launch_stellaris._is_wer_dialog_visible",
                  side_effect=lambda wins: False) as wer:
        assert game_observe(5555, 5) == EXIT_OK
    assert scan.call_count == 5, scan.call_count  # t=0,1,2,3,4
    # Both predicates saw the same snapshot rather than forcing fresh scans.
    assert jit.call_args_list == wer.call_args_list


def test_game_observe_actually_waits_the_whole_window():
    """observe_s is the contract with the agent — "up for half a minute and
    nothing is wrong". Returning early hands back a PID for a game that dies
    two seconds later."""
    with _observing(), _fake_clock() as clock:
        assert game_observe(5555, 10) == EXIT_OK
    assert clock.t >= 10, clock.t


def test_game_observe_zero_window_succeeds_immediately():
    with _observing():
        assert game_observe(5555, 0) == EXIT_OK


_HANDOFF_DEFAULT = object()


@contextlib.contextmanager
def _full_chain(game_pid=5555, handoff_rc=_HANDOFF_DEFAULT, observe_rc=EXIT_OK):
    """Patch every phase up to and including Task 6; yields the mocks in
    chain order (prekill, spawn, ready, wait, keyboard, handoff, observe).

    handoff_rc=None is a meaningful value — launcher_handoff returning None is
    the EXIT_GAME_DID_NOT_SPAWN case — so the default needs a sentinel
    distinct from None rather than `handoff_rc or game_pid`."""
    specs = [
        patch("launch_stellaris.prekill", return_value=EXIT_OK),
        patch("launch_stellaris.steam_spawn", return_value=EXIT_OK),
        patch("launch_stellaris.steam_ready", return_value=10748),
        patch("launch_stellaris.launcher_wait", return_value=(4242, 12345)),
        patch("launch_stellaris.launcher_keyboard", return_value=EXIT_OK),
        patch("launch_stellaris.launcher_handoff",
              return_value=game_pid if handoff_rc is _HANDOFF_DEFAULT
              else handoff_rc),
        patch("launch_stellaris.game_observe", return_value=observe_rc),
    ]
    mocks = [s.start() for s in specs]
    try:
        yield mocks
    finally:
        for s in specs:
            s.stop()


def test_run_launch_chain_prints_the_game_pid_and_nothing_else(capsys):
    """The stdout contract: `<pid>\\n`, parseable with int(stdout.strip()).
    Any diagnostic leaking onto stdout breaks the caller's parse."""
    with _full_chain(game_pid=5555):
        rc = run_launch_chain(build_arg_parser().parse_args([]))
    captured = capsys.readouterr()
    assert rc == EXIT_OK
    assert captured.out == "5555\n", repr(captured.out)
    assert int(captured.out.strip()) == 5555


def test_run_launch_chain_returns_31_when_the_game_never_spawns():
    with _full_chain(handoff_rc=None):
        assert run_launch_chain(
            build_arg_parser().parse_args([])) == EXIT_GAME_DID_NOT_SPAWN


def test_run_launch_chain_does_not_observe_when_the_game_never_spawns():
    with _full_chain(handoff_rc=None) as mocks:
        run_launch_chain(build_arg_parser().parse_args([]))
    mocks[6].assert_not_called()


def test_run_launch_chain_propagates_an_observe_failure(capsys):
    """32/33/34 have to reach the marker verbatim — DONE:<rc> is the only
    thing the outer process learns about the inner."""
    with _full_chain(game_pid=5555, observe_rc=EXIT_JIT_DIALOG):
        assert run_launch_chain(
            build_arg_parser().parse_args([])) == EXIT_JIT_DIALOG
    # A failed run must not also claim success on stdout.
    assert capsys.readouterr().out == ""


def test_run_launch_chain_honours_non_default_game_windows():
    """The inner is a separate process: --game-timeout-s / --observe-s reach
    it only because the chain reads them off args. Hardcoded 30s here would
    make an agent's --observe-s 120 a silent no-op."""
    args = build_arg_parser().parse_args(
        ["--game-timeout-s", "90", "--observe-s", "120"])
    with _full_chain(game_pid=5555) as mocks:
        assert run_launch_chain(args) == EXIT_OK
    mocks[5].assert_called_once_with(90)
    mocks[6].assert_called_once_with(5555, 120)


def test_run_launch_chain_does_not_drive_or_wait_in_a_dry_run():
    """--dry-run spawns no URI, so there is no launcher and no game. The
    handoff and observe phases must not run: a 30 s poll for a game that was
    never asked to start is a hang, not a dry run."""
    args = build_arg_parser().parse_args(["--dry-run"])
    with _full_chain() as mocks:
        assert run_launch_chain(args) == EXIT_OK
    mocks[4].assert_not_called()  # launcher_keyboard
    mocks[5].assert_not_called()  # launcher_handoff
    mocks[6].assert_not_called()  # game_observe
