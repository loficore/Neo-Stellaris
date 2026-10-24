import builtins
import contextlib
import ctypes
import ctypes.wintypes as _wt
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import launch_stellaris
import psutil
import pytest
from launch_stellaris import (EXIT_BRIDGE_ABANDONED, EXIT_BRIDGE_NO_SESSION,
                              EXIT_BRIDGE_SCHTASKS_DENIED, EXIT_BRIDGE_TIMEOUT,
                              EXIT_BRIDGE_TR_TOO_LONG, EXIT_DESKTOP_UNREACHABLE,
                              EXIT_GAME_DID_NOT_SPAWN,
                              EXIT_GAME_EXITED_EARLY, EXIT_GAME_UNPAUSE_FAILED,
                              EXIT_INTERNAL,
                              EXIT_JIT_DIALOG, EXIT_LAUNCHER_NO_ADVANCE,
                              EXIT_LAUNCHER_NO_FOCUS,
                              EXIT_LAUNCHER_WINDOW_MISSING, EXIT_OK,
                              EXIT_PREKILL_PERMISSION,
                              EXIT_STEAM_LOGIN_REQUIRED, EXIT_WER_DIALOG,
                              LAUNCHER_CONTINUE_FX, LAUNCHER_CONTINUE_FY,
                              MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
                              ChainResult, _click_at, _enum_windows_owned_by,
                              _handoff_observed, _hwnd_for_pid,
                              _is_jit_dialog_visible, _is_wer_dialog_visible,
                              _poll_marker, _read_marker_pid,
                              _run_launch_chain_phases,
                              _steam_has_window, _top_windows, _window_rect,
                              _write_marker, bridge_to_interactive_session,
                              bring_to_foreground, build_arg_parser,
                              build_bridge_account, build_bridge_run_command,
                              build_bridge_task_command, build_inner_tr,
                              click_diagnosis, click_trace,
                              game_observe, game_unpause, launcher_click, launcher_handoff,
                              launcher_wait, main, prekill,
                              read_awake_status, run_launch_chain, steam_ready,
                              steam_spawn, timeline_event)


def _unlocked_desktop(path=None):
    """A fresh reachable-desktop observation, for tests whose subject is a phase
    downstream of the gate. Built per call, so the 15 s heartbeat window cannot
    expire between collection and the assertion."""
    return {"desktop": "unlocked", "epoch": time.time(), "state": "serving"}


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
    """rc=128 is 'no such image', which for prekill is the desired end state —
    re-entrant safe (spec §3).

    The English rendering taskkill produced on this box when the probe ran from
    an SSH shell. Only the return code is load-bearing here; see
    test_prekill_checks_return_codes_not_localized_text.
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
    """The zh-CN not-found message, decoded from bytes captured on the box.

    Captured, not composed. The string this test used to assert was typed from
    memory during planning and never run against the box. The real stderr,
    captured from the bridged session, decodes from

        b4edcef33a20c3bbd3d0d5d2b5bdbdf8b3cc20227374656c6c617269732e65786522a1a30d0a

    under OEM codepage 936 as 错误: 没有找到进程 "stellaris.exe"。—
    没有找到 (U+6CA1 U+6709 U+627E U+5230), not 找不到 (U+627E U+4E0D U+5230).
    Both the implementation and this test asserted the same wrong substring,
    which is why the first end-to-end smoke died in PREKILL on a box where
    neither game process was running.

    rc is 128 either way, so the fix branches on that. The fixture is decoded
    from the captured hex rather than retyped, so it cannot drift away from
    what the box actually produces.
    """
    captured = bytes.fromhex(
        "b4edcef33a20c3bbd3d0d5d2b5bdbdf8b3cc20"
        "227374656c6c617269732e65786522a1a30d0a").decode("gbk")
    assert captured == '错误: 没有找到进程 "stellaris.exe"。\r\n'
    # The string the first version of this test asserted is not in the real
    # message. Pinned so the original defect cannot be reintroduced by editing
    # a fixture back to it.
    assert "找不到" not in captured
    mock_run.return_value = MagicMock(
        returncode=128, stdout="", stderr=captured)
    assert prekill() == EXIT_OK
    assert mock_run.call_count >= 1


@patch("subprocess.run")
def test_prekill_treats_rc_128_as_missing_whatever_the_message_says(mock_run):
    """The decisive regression: rc 128 alone decides, message ignored.

    A localized message is not a contract. taskkill emitted the English text
    when the same Python probe ran from an SSH shell, and the cp936 Chinese
    text when the identical code ran as a schtasks task in the bridged
    session — same user, same box, same argv. Any check that reads the text
    therefore passes or fails depending on how the process was launched, which
    is exactly how a guessed string survived review and then broke a live run.
    """
    mock_run.return_value = MagicMock(
        returncode=128, stdout="",
        stderr="<a language this script has no string for>",
    )
    assert prekill() == EXIT_OK


@patch("subprocess.run")
def test_prekill_reports_permission_for_the_cannot_terminate_code(mock_run):
    """rc 255 is 'the process exists and could not be terminated'.

    Measured on Windows_Jiaolong against csrss.exe: taskkill refuses a critical
    system process even for an administrator. That is a real failure to kill,
    not an absent process, so it must stay EXIT_PREKILL_PERMISSION — the fix
    may not buy its robustness by swallowing every non-zero code.
    """
    mock_run.return_value = MagicMock(
        returncode=255, stdout="",
        stderr="ERROR: The process with PID 1060 could not be terminated.",
    )
    assert prekill() == EXIT_PREKILL_PERMISSION


@patch("subprocess.run")
def test_prekill_reports_permission_for_the_invalid_option_code(mock_run):
    """rc 1 is a usage/parameter rejection, e.g. 'Invalid argument/option'.

    Measured on Windows_Jiaolong by handing taskkill a malformed flag. Not an
    absent process, so it must not be read as one.
    """
    mock_run.return_value = MagicMock(
        returncode=1, stdout="",
        stderr="ERROR: Invalid syntax. Neither /FI nor /PID nor /IM were specified.",
    )
    assert prekill() == EXIT_PREKILL_PERMISSION


@patch("subprocess.run")
def test_prekill_still_fails_when_the_second_image_cannot_be_killed(mock_run):
    """A genuine failure on the *second* image must survive the first one's 128.

    Both images missing is the state the smoke hit, so the missing-process path
    now runs on every crash recovery — which is exactly the run in which a real
    permission error on the launcher would be easiest to swallow.
    """
    calls = {"n": 0}

    def _side_effect(args, **kwargs):
        calls["n"] += 1
        rc = 128 if calls["n"] == 1 else 255
        return MagicMock(returncode=rc, stdout="", stderr="ERROR: denied")

    mock_run.side_effect = _side_effect
    assert prekill() == EXIT_PREKILL_PERMISSION


@patch("subprocess.run")
def test_prekill_checks_return_codes_not_localized_text(mock_run):
    """Discipline guard: no hand-typed localized string may decide prekill.

    Written against a defect this file itself encoded — a guessed CN substring
    lived in both the implementation and its test, so the suite agreed with
    itself while the box disagreed with both. A fixture genuinely decoded from
    captured bytes is fine; a literal localized substring used as a *matcher*
    is not.
    """
    code = source_of(prekill)
    # The docstring is documentation and does quote the message on purpose; what
    # must not exist is a localized literal the *decision* can read.
    consts = [c for c in code.co_consts if c is not code.co_consts[0]]
    matchers = [c for c in consts
                if isinstance(c, str) and not c.isascii() and c.strip()]
    assert matchers == [], (
        f"prekill matches on localized text {matchers!r}; branch on the return "
        f"code instead (taskkill's message language depends on how the process "
        f"was launched)"
    )


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
#   launcher_click         19s   (foreground + settle + 3 click/settle rounds)
#   game_timeout           30s   (= --game-timeout-s, Task 6)
#   observe                30s   (= --observe-s, Task 6)
#                         ------
#                          142s
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
        launch_stellaris._INNER_BUDGET_LAUNCHER_CLICK_S,
        launch_stellaris._INNER_BUDGET_GAME_OBSERVE_S,
    ]
    assert sum(components) == launch_stellaris._INNER_CHAIN_BUDGET_S
    assert launch_stellaris.DEFAULT_BRIDGE_TIMEOUT_S == (
        launch_stellaris._INNER_CHAIN_BUDGET_S
        + launch_stellaris._BRIDGE_TIMEOUT_MARGIN_S
    )


def test_default_bridge_timeout_excludes_the_unpause_budget():
    """--unpause adds ~95 s of inner work most callers never do. The derived
    default must stay at the no-unpause sum: widening it for everyone turns an
    inner that hangs into a failure reported 95 s later than it used to be.
    """
    mandatory = [
        launch_stellaris._INNER_BUDGET_PREKILL_SPAWN_S,
        launch_stellaris._INNER_BUDGET_STEAM_READY_S,
        launch_stellaris._INNER_BUDGET_LAUNCHER_WAIT_S,
        launch_stellaris._INNER_BUDGET_LAUNCHER_CLICK_S,
        launch_stellaris._INNER_BUDGET_GAME_OBSERVE_S,
    ]
    assert launch_stellaris._INNER_CHAIN_BUDGET_S == sum(mandatory)
    assert launch_stellaris.DEFAULT_BRIDGE_TIMEOUT_S == (
        launch_stellaris._INNER_CHAIN_BUDGET_S
        + launch_stellaris._BRIDGE_TIMEOUT_MARGIN_S)
    args = build_arg_parser().parse_args([])
    assert args.bridge_timeout_s == launch_stellaris.DEFAULT_BRIDGE_TIMEOUT_S


def test_unpause_widens_the_bridge_default_by_exactly_the_unpause_budget():
    args = build_arg_parser().parse_args(["--unpause"])
    assert args.bridge_timeout_s == (
        launch_stellaris.DEFAULT_BRIDGE_TIMEOUT_S
        + launch_stellaris._INNER_BUDGET_UNPAUSE_S)


def test_explicit_bridge_timeout_wins_over_the_unpause_widening():
    for argv in (["--unpause", "--bridge-timeout-s", "999"],
                 ["--bridge-timeout-s", "999", "--unpause"]):
        args = build_arg_parser().parse_args(argv)
        assert args.bridge_timeout_s == 999, argv


def test_inner_budget_table_tracks_the_argparse_defaults():
    """The budget constants are hand-written literals that *mirror* the CLI
    defaults, so summing them is self-consistent by construction — the
    derivation test above cannot fail unless someone edits the module. This
    one anchors them to build_arg_parser() instead: editing a CLI default
    without updating the table now fails here, instead of silently leaving the
    bridge (175 s) shorter than the inner chain it has to contain.

    Reachable today: --launcher-timeout-s 90 makes the inner traverse ~269 s
    against an unchanged 175 s bridge, so the outer reports a spurious 43.
    """
    args = build_arg_parser().parse_args([])
    assert args.launcher_timeout_s == launch_stellaris._INNER_BUDGET_STEAM_READY_S
    assert args.launcher_timeout_s == launch_stellaris._INNER_BUDGET_LAUNCHER_WAIT_S
    assert (args.game_timeout_s + args.observe_s) == (
        launch_stellaris._INNER_BUDGET_GAME_OBSERVE_S)
    assert (args.unpause_delay_s + launch_stellaris._UNPAUSE_SETTLE_S) == (
        launch_stellaris._INNER_BUDGET_UNPAUSE_S)


def test_inner_budget_click_matches_the_click_sequence_it_covers():
    """The click budget has no CLI flag, so nothing else ties it to the
    constants it is derived from: a _FOREGROUND_TIMEOUT_S bring-to-front, one
    focus settle, then _CLICK_ATTEMPTS clicks each followed by _CLICK_SETTLE_S."""
    assert (launch_stellaris._FOREGROUND_TIMEOUT_S
            + launch_stellaris._FOCUS_SETTLE_S
            + launch_stellaris._CLICK_SETTLE_S
            * launch_stellaris._CLICK_ATTEMPTS) == (
        launch_stellaris._INNER_BUDGET_LAUNCHER_CLICK_S)


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
            patch("launch_stellaris.write_bridge_tr_shim") as mock_shim, \
            patch("subprocess.run") as mock_run:
        rc = bridge_to_interactive_session(args)
    assert rc == EXIT_BRIDGE_TR_TOO_LONG
    # Rejected before schtasks is ever invoked.
    mock_run.assert_not_called()
    # ...and before the shim is written, not merely before schtasks. The
    # guard and write_bridge_tr_shim are two adjacent statements; moving the
    # validation below the write still passes every assertion above and leaks
    # a .cmd into TEMP on every non-ASCII run.
    mock_shim.assert_not_called()


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


def test_window_rect_reads_the_four_edges_and_raises_on_failure():
    """The click is anchored to the rect, so reading it wrong (or not at all)
    silently clicks the desktop. GetWindowRect returning FALSE is that failure,
    and _window_rect has to surface it rather than hand back a zero rect."""
    with patch("launch_stellaris._cursor_fns",
               return_value=(MagicMock(return_value=1), MagicMock(),
                             MagicMock())):
        edges = _window_rect(4242)
    assert len(edges) == 4 and all(isinstance(v, int) for v in edges), edges

    # GetWindowRect returning FALSE means the hwnd is dead or off-screen.
    with patch("launch_stellaris._cursor_fns",
               return_value=(MagicMock(return_value=0), MagicMock(),
                             MagicMock())):
        with pytest.raises(OSError):
            _window_rect(4242)


def test_click_at_moves_the_cursor_then_clicks_left_down_and_up():
    set_pos = MagicMock(return_value=1)
    mouse = MagicMock()
    with patch("launch_stellaris._cursor_fns",
               return_value=(MagicMock(), set_pos, mouse)):
        _click_at(640, 360)
    set_pos.assert_called_once_with(640, 360)
    flags = [c.args[0] for c in mouse.call_args_list]
    assert flags == [MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP]


def test_click_at_raises_when_setcursorpos_is_refused():
    """SetCursorPos returning 0 means the click was blocked — UIPI against a
    higher-integrity foreground window, typically. Swallowing that makes the
    whole drive a silent no-op that still reports success."""
    with patch("launch_stellaris._cursor_fns",
               return_value=(MagicMock(), MagicMock(return_value=0),
                             MagicMock())):
        with pytest.raises(OSError):
            _click_at(640, 360)


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
                  return_value=(set_fg, get_fg)):
        assert bring_to_foreground(4242) is True
    set_fg.assert_called_once_with(4242)


def test_bring_to_foreground_gives_up_when_another_window_keeps_focus():
    """Bring-to-front is refused across integrity levels and when the calling
    process does not own the foreground. Keystrokes then land in whatever
    window the user last touched."""
    set_fg, get_fg = MagicMock(), MagicMock(return_value=9999)
    with _fake_clock(), \
            patch("launch_stellaris._input_fns",
                  return_value=(set_fg, get_fg)):
        assert bring_to_foreground(4242) is False


def test_handoff_observed_when_the_launcher_exits():
    with patch("psutil.process_iter", return_value=[_fake_proc("steam.exe", 1)]):
        assert _handoff_observed() is True


def test_handoff_observed_when_stellaris_appears_beside_the_launcher():
    procs = [_fake_proc("Paradox Launcher.exe", 2), _fake_proc("stellaris.exe", 3)]
    with patch("psutil.process_iter", return_value=procs):
        assert _handoff_observed() is True


def test_handoff_not_observed_while_only_the_launcher_is_alive():
    """The launcher staying put means the click did not land on Continue.
    Reporting a handoff here hands Task 6 a launcher window and no game."""
    with patch("psutil.process_iter",
               return_value=[_fake_proc("Paradox Launcher.exe", 2)]):
        assert _handoff_observed() is False


@patch("launch_stellaris._click_at")
@patch("launch_stellaris._window_rect", return_value=(0, 0, 1000, 1000))
@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.bring_to_foreground", return_value=True)
def test_launcher_click_returns_22_when_focus_fails(mock_fg, mock_sleep,
                                                     mock_rect, mock_click):
    """A click lands wherever the cursor is, which is whatever window the user
    last touched when the launcher is not foreground. Refuse before clicking."""
    mock_fg.return_value = False
    assert launcher_click(4242) == EXIT_LAUNCHER_NO_FOCUS
    mock_click.assert_not_called()


@patch("launch_stellaris._click_at", side_effect=OSError(5, "access denied"))
@patch("launch_stellaris._window_rect", return_value=(0, 0, 1000, 1000))
@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.bring_to_foreground", return_value=True)
def test_launcher_click_reports_no_focus_when_the_click_is_blocked(
        mock_fg, mock_sleep, mock_rect, mock_click):
    """SetCursorPos returning 0 means UIPI refused the click. Letting that
    OSError escape would exit main() with code 1 — undocumented, and worse, the
    run returns before _write_marker, so the outer bridge never learns the inner
    died and sits there until its own timeout, reporting 43 instead."""
    assert launcher_click(4242) == EXIT_LAUNCHER_NO_FOCUS


@patch("launch_stellaris._handoff_observed", return_value=False)
@patch("launch_stellaris._click_at")
@patch("launch_stellaris._window_rect", return_value=(0, 0, 1000, 1000))
@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.bring_to_foreground", return_value=True)
def test_launcher_click_returns_23_after_exhausting_the_attempts(
        mock_fg, mock_sleep, mock_rect, mock_click, mock_handoff):
    """Every attempt landed on the Continue point and none handed off — the
    button moved, or this launcher variant has no save to continue. That is the
    documented 'click did not advance the launcher' failure, not a hang."""
    assert launcher_click(4242) == EXIT_LAUNCHER_NO_ADVANCE
    assert mock_click.call_count == launch_stellaris._CLICK_ATTEMPTS
    assert mock_handoff.call_count == launch_stellaris._CLICK_ATTEMPTS


@patch("launch_stellaris._handoff_observed", return_value=True)
@patch("launch_stellaris._click_at")
@patch("launch_stellaris._window_rect", return_value=(0, 0, 1000, 1000))
@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.bring_to_foreground", return_value=True)
def test_launcher_click_stops_at_the_first_handoff(
        mock_fg, mock_sleep, mock_rect, mock_click, mock_handoff):
    """A second click after the game is launching would land in the loading
    screen. The drive stops the moment the handoff signal fires."""
    assert launcher_click(4242) == EXIT_OK
    assert mock_click.call_count == 1
    assert mock_handoff.call_count == 1


@patch("launch_stellaris._handoff_observed", return_value=False)
@patch("launch_stellaris._click_at")
@patch("launch_stellaris._window_rect")
@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.bring_to_foreground", return_value=True)
def test_launcher_click_clicks_the_continue_fraction_of_the_rect(
        mock_fg, mock_sleep, mock_rect, mock_click, mock_handoff):
    """The button position is a fraction of the window rect, so a maximised
    launcher and a floating one are both aimed correctly from the same code."""
    mock_rect.return_value = (0, 0, 1000, 1000)
    launcher_click(4242)
    expected_x = int(0 + LAUNCHER_CONTINUE_FX * 1000)
    expected_y = int(0 + LAUNCHER_CONTINUE_FY * 1000)
    mock_click.assert_called_with(expected_x, expected_y)


@patch("launch_stellaris._handoff_observed", return_value=False)
@patch("launch_stellaris._click_at")
@patch("launch_stellaris._window_rect")
@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.bring_to_foreground", return_value=True)
def test_launcher_click_re_reads_the_rect_every_attempt(
        mock_fg, mock_sleep, mock_rect, mock_click, mock_handoff):
    """Plan B's whole point: the user can move the launcher mid-drive, so the
    rect is re-read per attempt and the click tracks it. A single startup read
    would click the old position the moment the window moved."""
    mock_rect.side_effect = [(0, 0, 1000, 1000), (1000, 1000, 2000, 2000),
                             (500, 0, 1500, 1000)]
    launcher_click(4242)
    assert mock_rect.call_count == launch_stellaris._CLICK_ATTEMPTS
    coords = [c.args[0:2] for c in mock_click.call_args_list]
    fx = LAUNCHER_CONTINUE_FX
    fy = LAUNCHER_CONTINUE_FY
    assert coords == [
        (int(fx * 1000), int(fy * 1000)),
        (int(1000 + fx * 1000), int(1000 + fy * 1000)),
        (int(500 + fx * 1000), int(fy * 1000)),
    ], coords


@patch("launch_stellaris.read_awake_status", side_effect=_unlocked_desktop)
@patch("launch_stellaris.game_observe", return_value=EXIT_OK)
@patch("launch_stellaris.launcher_handoff", return_value=5555)
@patch("launch_stellaris.launcher_click", return_value=EXIT_OK)
@patch("launch_stellaris.launcher_wait", return_value=(4242, 12345))
@patch("launch_stellaris.steam_ready", return_value=10748)
@patch("launch_stellaris.steam_spawn", return_value=EXIT_OK)
@patch("launch_stellaris.prekill", return_value=EXIT_OK)
def test_run_launch_chain_waits_for_the_launcher_window_then_drives_it(
        mock_prekill, mock_spawn, mock_ready, mock_wait, mock_click,
        mock_handoff, mock_observe, mock_gate):
    assert run_launch_chain(build_arg_parser().parse_args([])) == EXIT_OK
    mock_wait.assert_called_once_with(30)  # --launcher-timeout-s default
    mock_click.assert_called_once_with(12345, 4242)
    # Task 6: the drive is not the end of the chain — the game has to appear
    # and then survive its observation window.
    mock_handoff.assert_called_once_with(30)  # --game-timeout-s default
    mock_observe.assert_called_once_with(5555, 30)  # --observe-s default


@patch("launch_stellaris.read_awake_status", side_effect=_unlocked_desktop)
@patch("launch_stellaris.launcher_click", return_value=EXIT_LAUNCHER_NO_ADVANCE)
@patch("launch_stellaris.launcher_wait", return_value=(4242, 12345))
@patch("launch_stellaris.steam_ready", return_value=10748)
@patch("launch_stellaris.steam_spawn", return_value=EXIT_OK)
@patch("launch_stellaris.prekill", return_value=EXIT_OK)
def test_run_launch_chain_propagates_a_click_failure(
        mock_prekill, mock_spawn, mock_ready, mock_wait, mock_click, mock_gate):
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


@patch("launch_stellaris.launcher_click", return_value=EXIT_OK)
@patch("launch_stellaris.launcher_wait", return_value=(4242, 12345))
@patch("launch_stellaris.steam_ready", return_value=None)
@patch("launch_stellaris.steam_spawn", return_value=EXIT_OK)
@patch("launch_stellaris.prekill", return_value=EXIT_OK)
def test_run_launch_chain_dry_run_skips_the_click(
        mock_prekill, mock_spawn, mock_ready, mock_wait, mock_click):
    """--dry-run spawns no URI, so no launcher exists and there is no window to
    click into. Clicking anyway would hammer whatever window the user has open."""
    args = build_arg_parser().parse_args(["--dry-run"])
    assert run_launch_chain(args) == EXIT_OK
    mock_click.assert_not_called()


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
# "we clicked Continue" into "here is a PID you can watch", and that PID
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
    """launcher_click stops at the first handoff *signal*, which also fires
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


def test_is_jit_dialog_visible_matches_a_dialog_owned_by_the_debugger_process():
    """A JIT-dialog title is only evidence when the debugger process owns it.

    Restated rather than kept as a bare title match: see the orphan-window tests
    below for why the title alone cannot decide this.
    """
    with patch("psutil.process_iter",
               return_value=[_fake_proc("vsjitdebugger.exe", 4123)]), \
            _fake_desktop([_fake_window(4123, "Visual Studio Just-In-Time Debugger")]):
        assert _is_jit_dialog_visible() is True


# The exact window observed on Windows_Jiaolong, captured from the bridged
# session's pywinauto UIA scan while no vsjitdebugger.exe process was running:
#     pid=1176  'Visual Studio Just-In-Time Debugger'   (csrss.exe)
# An orphan like this ends a healthy run at EXIT_JIT_DIALOG (33) — the agent is
# told the game crashed while it is loading perfectly well — so the predicate has
# to look past the title at who owns the window.
_ORPHAN_JIT_WINDOW = (1176, "Visual Studio Just-In-Time Debugger")


def test_is_jit_dialog_visible_ignores_an_orphan_window_with_a_jit_title():
    """A JIT-looking title on csrss.exe with no vsjitdebugger.exe is not a dialog.

    csrss.exe is the process that *hosts* the window, and it outlives whatever
    drew the title: once the debugger process behind the prompt is gone the
    window remains, still titled as a JIT dialog, with nothing left to attach
    to. Spec §4 gives exit 33 the meaning "a crash dialog is up right now,
    refuse and report", which an orphaned shell of one is not.
    """
    with patch("psutil.process_iter", return_value=[_fake_proc("csrss.exe", 1176)]), \
            _fake_desktop([_fake_window(*_ORPHAN_JIT_WINDOW)]):
        assert _is_jit_dialog_visible() is False


@contextlib.contextmanager
def _observing_real_probes(windows, procs):
    """game_observe with the real _is_jit_dialog_visible driving the decision.

    _observing() stubs both dialog predicates, so it cannot catch a predicate
    that is wrong. This leaves _is_jit_dialog_visible alone and feeds it the same
    two inputs the box produces — a desktop snapshot and a process list — so the
    exit code under test is the one the real predicate produces.
    """
    proc = MagicMock()
    proc.status.return_value = "running"
    proc.is_running.return_value = True
    with _fake_clock(), \
            patch("psutil.Process", return_value=proc), \
            patch("launch_stellaris._top_windows", return_value=list(windows)), \
            patch("psutil.process_iter", return_value=list(procs)), \
            patch("launch_stellaris._is_wer_dialog_visible", return_value=False):
        yield proc


def test_game_observe_does_not_report_33_for_the_orphan_csrss_jit_window():
    """The end-to-end regression: a healthy game must observe clean.

    Same window, same process list as the box showed — a csrss.exe-hosted
    "Visual Studio Just-In-Time Debugger" and no vsjitdebugger.exe. Before the
    fix the first observe tick returned 33, which would have turned the first
    green end-to-end run into a reported crash with the PID withheld.
    """
    with _observing_real_probes([_ORPHAN_JIT_WINDOW],
                                [_fake_proc("csrss.exe", 1176),
                                 _fake_proc("stellaris.exe", 5555)]):
        assert game_observe(5555, 30) == EXIT_OK


def test_game_observe_still_reports_33_for_a_real_vsjitdebugger_process():
    """Dropping the title fallback must not blind the check to a real prompt.

    The process half is the signal that survives, so it has to end the observe
    window on its own — with a desktop full of ordinary windows and no JIT title
    anywhere.
    """
    with _observing_real_probes([(10748, "Steam"), (4242, "Paradox Launcher")],
                                [_fake_proc("vsjitdebugger.exe", 4123),
                                 _fake_proc("stellaris.exe", 5555)]):
        assert game_observe(5555, 30) == EXIT_JIT_DIALOG


def test_is_jit_dialog_visible_matches_the_vsjitdebugger_process():
    """The process is the locale-independent signal, exactly as WerFault.exe is
    for WER. The title match alone only works on an English VS: the box this
    script targets runs a zh-CN Windows, where the dialog's own title is
    localized and the substring never matches.

    Verified on Windows_Jiaolong rather than assumed: HKLM\\SOFTWARE\\Microsoft\\
    Windows NT\\CurrentVersion\\AeDebug\\Debugger is
        "C:\\Windows\\system32\\vsjitdebugger.exe" -p %ld -e %ld -j 0x%p
    and launching that image with those arguments leaves the process alive
    (the OS spawns it only on an unhandled exception, so it is a JIT event and
    nothing else). psutil's name is the image basename, matching WerFault."""
    with patch("psutil.process_iter",
               return_value=[_fake_proc("vsjitdebugger.exe", 4123)]), \
            patch("launch_stellaris._top_windows", return_value=[]):
        assert _is_jit_dialog_visible() is True


def test_is_jit_dialog_visible_ignores_unrelated_processes():
    """The process check must not widen into "some debugger is installed"."""
    procs = [_fake_proc("steam.exe", 1), _fake_proc("stellaris.exe", 5555),
             _fake_proc("devenv.exe", 900)]
    with patch("psutil.process_iter", return_value=procs), \
            patch("launch_stellaris._top_windows", return_value=[]):
        assert _is_jit_dialog_visible() is False


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
    """UIA top-level enumeration is the most expensive thing in this loop. Two
    scans a second for 30 s is a wasted desktop walk on every single launch.

    WER is the only probe left that reads the desktop — the JIT probe is
    process-based and no longer takes a snapshot — so the budget this pins is
    one scan per tick for it, not one shared between two.
    """
    with _observing(), \
            patch("launch_stellaris._top_windows", return_value=[]) as scan, \
            patch("launch_stellaris._is_jit_dialog_visible",
                  return_value=False), \
            patch("launch_stellaris._is_wer_dialog_visible",
                  side_effect=lambda wins: False) as wer:
        assert game_observe(5555, 5) == EXIT_OK
    assert scan.call_count == 5, scan.call_count  # t=0,1,2,3,4
    # Every scan fed the WER probe from the same tick rather than a second walk.
    assert wer.call_count == 5, wer.call_count
    assert wer.call_args_list == [((scan.return_value,),)] * 5


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
    chain order (prekill, spawn, ready, wait, keyboard, handoff, observe) plus
    the desktop gate stub last.

    handoff_rc=None is a meaningful value — launcher_handoff returning None is
    the EXIT_GAME_DID_NOT_SPAWN case — so the default needs a sentinel
    distinct from None rather than `handoff_rc or game_pid`."""
    specs = [
        patch("launch_stellaris.prekill", return_value=EXIT_OK),
        patch("launch_stellaris.steam_spawn", return_value=EXIT_OK),
        patch("launch_stellaris.steam_ready", return_value=10748),
        patch("launch_stellaris.launcher_wait", return_value=(4242, 12345)),
        patch("launch_stellaris.launcher_click", return_value=EXIT_OK),
        patch("launch_stellaris.launcher_handoff",
              return_value=game_pid if handoff_rc is _HANDOFF_DEFAULT
              else handoff_rc),
        patch("launch_stellaris.game_observe", return_value=observe_rc),
        # The desktop gate is stubbed last on purpose: existing tests index the
        # phases positionally (mocks[0]..mocks[6]), and appending keeps those
        # numbers meaning the same call. Chain order would put it between
        # launcher_wait and launcher_click.
        patch("launch_stellaris.read_awake_status", side_effect=_unlocked_desktop),
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


def test_unpause_flag_defaults_off():
    """Loading a save lands paused; leaving it to the caller's hands was the
    behavior before this flag existed. It stays the default so a launcher run
    never injects a keystroke nobody asked for.

    The 90 s default covers a large modded save: live on Windows_Jiaolong the
    campaign first drew ~95 s after handoff, so the 30 s default fired while
    the loading screen still held the window and the Space was lost."""
    args = build_arg_parser().parse_args([])
    assert args.unpause is False
    assert args.unpause_delay_s == 90


def test_unpause_flag_and_delay_are_settable():
    args = build_arg_parser().parse_args(
        ["--unpause", "--unpause-delay-s", "45"])
    assert args.unpause is True
    assert args.unpause_delay_s == 45


def test_inner_tr_forwards_unpause():
    """The inner is a separate process: a flag dropped here makes
    `--unpause` a silent no-op in the bridged run."""
    args = build_arg_parser().parse_args(
        ["--unpause", "--unpause-delay-s", "45"])
    tr = build_inner_tr(args, marker=r"C:\TEMP\m.txt",
                        python=r"C:\py\python.exe",
                        script=r"C:\work\launch_stellaris.py")
    tokens = tr.split()
    assert "--unpause" in tokens
    assert "--unpause-delay-s 45" in tr


def test_inner_tr_omits_unpause_when_not_requested():
    args = build_arg_parser().parse_args([])
    tr = build_inner_tr(args, marker=r"C:\TEMP\m.txt")
    assert "--unpause" not in tr.split()


def test_unpause_waits_then_focuses_and_sends_space():
    with patch("launch_stellaris._time.sleep") as sleep, \
            patch("launch_stellaris._hwnd_for_pid", return_value=4242), \
            patch("launch_stellaris.bring_to_foreground",
                  return_value=True) as foreground, \
            patch("launch_stellaris._send_space", return_value=True) as send:
        rc = game_unpause(5555, 45)
    assert rc == EXIT_OK
    sleep.assert_any_call(45)
    foreground.assert_called_once_with(4242, tag="GAME_UNPAUSE")
    send.assert_called_once_with()


def test_unpause_without_a_game_window_fails_typed():
    with patch("launch_stellaris._time.sleep"), \
            patch("launch_stellaris._hwnd_for_pid", return_value=0):
        assert game_unpause(5555, 0) == EXIT_GAME_UNPAUSE_FAILED


def test_unpause_reports_a_blocked_keystroke():
    with patch("launch_stellaris._time.sleep"), \
            patch("launch_stellaris._hwnd_for_pid", return_value=4242), \
            patch("launch_stellaris.bring_to_foreground", return_value=True), \
            patch("launch_stellaris._send_space", return_value=False):
        assert game_unpause(5555, 0) == EXIT_GAME_UNPAUSE_FAILED


def test_space_is_sent_as_a_scancode_not_a_virtual_key():
    """Live 2026-10-23: SendInput with wVk=0x20 was silently eaten. ESC and
    Space changed nothing while the game held verified foreground focus and a
    click on its pause button worked; the scancode form (wVk=0, wScan=0x39,
    KEYEVENTF_SCANCODE) toggled pause on the same window in the same second.
    With the CM_IME attached to the game window, VK events are translated and
    consumed before the game's input queue sees them; scancodes are not.
    Pin the event shape so a revert to the VK path cannot pass this suite.
    """
    events = launch_stellaris._space_key_events()
    assert events == [
        (0, 0x39, launch_stellaris.KEYEVENTF_SCANCODE),
        (0, 0x39,
         launch_stellaris.KEYEVENTF_SCANCODE | launch_stellaris.KEYEVENTF_KEYUP),
    ]


def test_run_launch_chain_unpauses_after_observe_when_requested(capsys):
    args = build_arg_parser().parse_args(
        ["--unpause", "--unpause-delay-s", "45"])
    with _full_chain(game_pid=5555), \
            patch("launch_stellaris.game_unpause", return_value=EXIT_OK) as unpause:
        assert run_launch_chain(args) == EXIT_OK
    unpause.assert_called_once_with(5555, 45)
    assert capsys.readouterr().out == "5555\n"


def test_run_launch_chain_skips_unpause_by_default():
    with _full_chain(game_pid=5555), \
            patch("launch_stellaris.game_unpause") as unpause:
        assert run_launch_chain(build_arg_parser().parse_args([])) == EXIT_OK
    unpause.assert_not_called()


def test_run_launch_chain_propagates_unpause_failure(capsys):
    args = build_arg_parser().parse_args(["--unpause"])
    with _full_chain(game_pid=5555), \
            patch("launch_stellaris.game_unpause",
                  return_value=EXIT_GAME_UNPAUSE_FAILED):
        assert run_launch_chain(args) == EXIT_GAME_UNPAUSE_FAILED
    assert capsys.readouterr().out == ""


def test_run_launch_chain_does_not_drive_or_wait_in_a_dry_run():
    """--dry-run spawns no URI, so there is no launcher and no game. The
    handoff and observe phases must not run: a 30 s poll for a game that was
    never asked to start is a hang, not a dry run."""
    args = build_arg_parser().parse_args(["--dry-run"])
    with _full_chain() as mocks:
        assert run_launch_chain(args) == EXIT_OK
    mocks[4].assert_not_called()  # launcher_click
    mocks[5].assert_not_called()  # launcher_handoff
    mocks[6].assert_not_called()  # game_observe


# ---------------------------------------------------------------------------
# The PID channel across the bridge.
#
# spec §4: on success stdout carries a bare `<pid>\n` and the caller parses it
# with int(stdout.strip()). In a bridged run the inner's stdout goes to the
# schtasks-spawned process tree, so the PID has to travel the marker file —
# the only channel that already works — and the outer has to print it. Before
# this, a fully successful bridged launch returned 0 with an empty stdout: the
# agent that called the script got no PID to re-attach the DLL to.


def test_marker_carries_the_pid_alongside_the_done_line():
    """Both lines, or the PID has nowhere to go. DONE: stays last and keeps
    its exact spelling — _poll_marker scans backwards for it and the bridge's
    exit-code split depends on it."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        _write_marker(marker, EXIT_OK, pid=5555)
        assert _poll_marker(marker, timeout_s=1) == "DONE:0"
        assert _read_marker_pid(marker) == 5555


def test_marker_omits_the_pid_line_when_there_is_no_pid():
    """A failed run has no PID worth carrying, and a PID line on a non-zero
    DONE: would invite a caller to read a dead game's handle as success."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        _write_marker(marker, EXIT_WER_DIALOG)
        assert _poll_marker(marker, timeout_s=1) == "DONE:34"
        assert _read_marker_pid(marker) is None


def test_read_marker_pid_returns_none_for_a_torn_pid_line():
    """int() on a half-written "PID:" raises. A marker we cannot read is a
    marker with no PID, not an exception out of the bridge."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        Path(marker).write_text("PID:\nDONE:0\n", encoding="utf-8")
        assert _read_marker_pid(marker) is None


def test_read_marker_pid_returns_none_when_the_marker_is_missing():
    with tempfile.TemporaryDirectory() as td:
        assert _read_marker_pid(str(Path(td) / "never-written.txt")) is None


def test_run_launch_chain_reports_the_game_pid_on_its_result():
    """run_launch_chain still returns an EXIT_* int — 100+ tests and the
    marker write in main() depend on that — so the PID rides out on a result
    object rather than by changing the return type."""
    result = ChainResult()
    with _full_chain(game_pid=5555):
        assert run_launch_chain(build_arg_parser().parse_args([]), result) == EXIT_OK
    assert result.pid == 5555


def test_run_launch_chain_leaves_the_pid_unset_when_observe_fails():
    """The PID is only meaningful if the run succeeded. Carrying it on a 33
    would make "PID present" stop meaning "healthy"."""
    result = ChainResult()
    with _full_chain(game_pid=5555, observe_rc=EXIT_JIT_DIALOG):
        assert run_launch_chain(build_arg_parser().parse_args([]), result) == EXIT_JIT_DIALOG
    assert result.pid is None


def test_run_launch_chain_leaves_the_pid_unset_on_a_dry_run():
    """--dry-run launches no game, so there is no PID to report."""
    result = ChainResult()
    with _full_chain():
        assert run_launch_chain(
            build_arg_parser().parse_args(["--dry-run"]), result) == EXIT_OK
    assert result.pid is None


def test_main_inner_writes_the_game_pid_into_the_marker():
    """The whole inner half of the contract: chain -> result -> marker, so the
    PID survives the hop the caller cannot see stdout across."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        with _full_chain(game_pid=5555):
            rc = main(["--inner", "--marker", marker])
        assert rc == EXIT_OK
        assert _poll_marker(marker, timeout_s=1) == "DONE:0"
        assert _read_marker_pid(marker) == 5555


def test_main_inner_marker_carries_no_pid_when_the_chain_fails():
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        with _full_chain(game_pid=5555, observe_rc=EXIT_GAME_EXITED_EARLY):
            assert main(["--inner", "--marker", marker]) == EXIT_GAME_EXITED_EARLY
        assert _poll_marker(marker, timeout_s=1) == "DONE:32"
        assert _read_marker_pid(marker) is None


@patch("launch_stellaris.prekill", side_effect=RuntimeError("psutil exploded"))
def test_main_inner_marker_carries_the_guard_code_when_a_phase_raises(mock_prekill):
    """M-1: the guard around the chain exists for one reason — to stop an
    exception from returning out of main() *before* _write_marker runs, which
    leaves the outer bridge burning its whole budget and reporting 43 with no
    idea what happened. So the return value is not enough to prove the guard
    works: 99 has to be the thing the outer actually reads. main()'s marker
    write is the exact line the guard protects, and inspecting it is not the
    same as exercising it."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        assert main(["--inner", "--marker", marker]) == EXIT_INTERNAL
        assert _poll_marker(marker, timeout_s=1) == "DONE:99"
        # No PID next to it: a 99 means the chain broke, not that a game is up.
        assert _read_marker_pid(marker) is None


@contextlib.contextmanager
def _bridged(marker, content):
    """Run bridge_to_interactive_session against a marker the inner writes,
    as if a real inner had finished. Yields the mocked subprocess.run.

    The marker is written from inside the mocked `schtasks /run` call, not
    before the bridge starts: the bridge clears any pre-existing marker
    (I-1, a leftover from a killed outer would otherwise hand the caller a
    stale DONE:/PID: pair), so a helper that pre-wrote the file would be
    describing a state the bridge is required to destroy."""
    mock_run = MagicMock()

    def _fake_run(cmd, *a, **kw):
        if isinstance(cmd, list) and "/run" in cmd:
            Path(marker).write_text(content, encoding="utf-8")
        return MagicMock(returncode=0, stdout="", stderr="")

    mock_run.side_effect = _fake_run
    with patch("subprocess.run", mock_run), \
            patch("launch_stellaris.current_session_id", return_value=0), \
            patch("launch_stellaris.interactive_session_id", return_value=1):
        yield mock_run


def test_bridge_prints_the_game_pid_from_the_marker_on_success(capsys):
    """The contract the SSH caller actually parses: a bare integer, nothing
    else, so int(stdout.strip()) works."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        args = build_arg_parser().parse_args(
            ["--marker", marker, "--bridge-timeout-s", "1"])
        with _bridged(marker, "PID:5555\nDONE:0\n"):
            assert bridge_to_interactive_session(args) == EXIT_OK
    out = capsys.readouterr().out
    assert out == "5555\n", repr(out)
    assert int(out.strip()) == 5555


def test_bridge_prints_nothing_when_the_inner_reported_a_failure(capsys):
    """A failed launch must not put a PID on stdout: the caller's parse would
    happily hand the agent a handle to a dead or never-started process."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        args = build_arg_parser().parse_args(
            ["--marker", marker, "--bridge-timeout-s", "1"])
        with _bridged(marker, "DONE:31\n"):
            assert bridge_to_interactive_session(args) == EXIT_GAME_DID_NOT_SPAWN
    assert capsys.readouterr().out == ""


def test_bridge_prints_nothing_when_the_marker_has_no_pid(capsys):
    """rc 0 with no PID line: either an older inner or a dry run. Empty stdout
    is the honest answer — the caller gets a ValueError, which it can act on,
    instead of a plausible-looking wrong PID."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        args = build_arg_parser().parse_args(
            ["--marker", marker, "--bridge-timeout-s", "1"])
        with _bridged(marker, "DONE:0\n"):
            assert bridge_to_interactive_session(args) == EXIT_OK
    assert capsys.readouterr().out == ""


def test_bridge_prints_no_pid_for_a_dry_run(capsys):
    """--dry-run reaches EXIT_OK through the chain, not through a launch. It
    must look like any other rc-0-with-no-PID run, not like a game started."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        args = build_arg_parser().parse_args(
            ["--marker", marker, "--dry-run", "--bridge-timeout-s", "1"])
        with _bridged(marker, "DONE:0\n"):
            assert bridge_to_interactive_session(args) == EXIT_OK
    assert capsys.readouterr().out == ""


def test_bridge_reads_the_pid_before_deleting_the_marker(capsys):
    """Regression guard for the ordering: cleanup removes the marker file, so a
    PID read after it would come back empty on every single run."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        args = build_arg_parser().parse_args(
            ["--marker", marker, "--bridge-timeout-s", "1"])
        with _bridged(marker, "PID:4242\nDONE:0\n"):
            assert bridge_to_interactive_session(args) == EXIT_OK
        assert not os.path.exists(marker)  # cleanup still happens
    assert capsys.readouterr().out == "4242\n"


def test_bridge_clears_a_stale_marker_before_it_starts_polling(capsys):
    """I-1: a marker left behind by a killed outer, landing on a path a reused
    PID hands to a new one, makes _poll_marker return the *old* DONE: line on
    its first tick. Before the PID: line that was exit 0 with empty stdout;
    now it is exit 0 plus a stale PID — and that PID is the value the agent
    feeds to the DLL attach. A wrong PID fails later and further from the
    cause than a missing one, and may name an unrelated process.

    So the bridge has to destroy anything at that path before it schedules the
    inner, not just after it finishes. Both halves are asserted: the file is
    gone by the time `schtasks /create` runs, and the poll then waits for a
    fresh write instead of accepting the leftover."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        Path(marker).write_text("PID:31337\nDONE:0\n", encoding="utf-8")
        args = build_arg_parser().parse_args(
            ["--marker", marker, "--bridge-timeout-s", "1"])
        marker_existed = []

        def _fake_run(cmd, *a, **kw):
            if isinstance(cmd, list) and "/create" in cmd:
                marker_existed.append(os.path.exists(marker))
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=_fake_run), \
                patch("launch_stellaris.current_session_id", return_value=0), \
                patch("launch_stellaris.interactive_session_id", return_value=1):
            rc = bridge_to_interactive_session(args)

    assert marker_existed == [False], (
        "the stale marker survived until /create — the poll would accept it")
    # No inner wrote anything, so there is nothing to report: a timeout, not
    # the stale success the leftover claimed.
    assert rc == EXIT_BRIDGE_TIMEOUT
    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# I-2: the inner's stderr timeline, carried across the bridge.
#
# Across the bridge the inner's stderr goes to the schtasks-spawned process
# tree, so the caller saw BOOT + BRIDGE and no phase at all — not PREKILL, not
# STEAM_READY, not the launcher drive, not GAME_OBSERVE. spec §5a step 4 has
# claimed the marker receives the inner's stderr lines since Task 4; it did
# not. The marker is the channel already proven to work, so the timeline rides
# it too, and the outer mirrors it to its own stderr so the caller's log reads
# as one continuous run.
#
# LOG: marks a carried line. The tag is what keeps a captured traceback that
# happens to mention DONE:<rc> from being read back as the inner's exit code.
# ---------------------------------------------------------------------------


def test_marker_writes_the_timeline_above_pid_and_done():
    """Order is the contract: LOG: lines, then PID:, then DONE: last. DONE:
    has to stay last and keep its spelling — _poll_marker scans backwards for
    it and the bridge splits its exit code on it."""
    from launch_stellaris import _read_marker_timeline
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        _write_marker(marker, EXIT_OK, pid=5555,
                      timeline=["ts  PREKILL  killed=[]", "ts  GAME_OBSERVE  step=ok"])
        assert Path(marker).read_text(encoding="utf-8").splitlines() == [
            "LOG:ts  PREKILL  killed=[]",
            "LOG:ts  GAME_OBSERVE  step=ok",
            "PID:5555",
            "DONE:0",
        ]
        assert _poll_marker(marker, timeout_s=1) == "DONE:0"
        assert _read_marker_pid(marker) == 5555
        assert _read_marker_timeline(marker) == [
            "ts  PREKILL  killed=[]", "ts  GAME_OBSERVE  step=ok"]


def test_marker_timeline_lines_cannot_be_mistaken_for_the_exit_code():
    """The tag exists for this: a carried line that happens to start with or
    contain DONE: must not be read back as the inner's exit code."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        _write_marker(marker, EXIT_GAME_EXITED_EARLY,
                      timeline=["ts  CHAIN  saw marker DONE:0 in a traceback"])
        assert _poll_marker(marker, timeout_s=1) == "DONE:32"


def test_captured_timeline_lines_are_flattened_to_one_line_each():
    """A carried line that keeps an embedded newline writes a continuation
    line into the marker that carries no LOG: tag — and if that continuation
    happens to start with DONE:, _poll_marker's backward scan reads it as the
    inner's exit code. Flatten on capture: one event, one line, same ' | '
    join the chain guard already uses for its traceback."""
    from launch_stellaris import _Timeline
    tl = _Timeline(limit=10)
    tl.add("ts  CHAIN  boom\nDONE:0")
    assert tl.lines() == ["ts  CHAIN  boom | DONE:0"]
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        _write_marker(marker, EXIT_INTERNAL, timeline=tl.lines())
        assert Path(marker).read_text(encoding="utf-8").splitlines() == [
            "LOG:ts  CHAIN  boom | DONE:0", "DONE:99"]
        assert _poll_marker(marker, timeout_s=1) == "DONE:99"


def test_main_inner_marker_carries_the_phase_timeline(tmp_path):
    """The inner half: what the chain logged has to reach the marker, or there
    is nothing for the outer to mirror. Patching the phases out would leave
    only BOOT, so let one of them fail for real — the guard's internal_error
    line is exactly the diagnostic Task 7 needs and exactly what was missing."""
    from launch_stellaris import _read_marker_timeline
    marker = str(tmp_path / "inner.txt")
    with patch("launch_stellaris.prekill",
               side_effect=RuntimeError("psutil exploded")):
        rc = main(["--inner", "--marker", marker])
    assert rc == EXIT_INTERNAL
    carried = _read_marker_timeline(marker)
    assert any("internal_error" in line for line in carried), carried
    assert any("BOOT" in line for line in carried), carried
    assert _poll_marker(marker, timeout_s=1) == "DONE:99"


def test_bridge_mirrors_the_inner_timeline_to_its_own_stderr(capsys):
    """The outer half: the caller's log has to read as one continuous run, so
    the carried lines are printed verbatim (de-tagged) and in order — not
    summarised, not reordered after the BRIDGE result line."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        args = build_arg_parser().parse_args(
            ["--marker", marker, "--bridge-timeout-s", "1"])
        with _bridged(marker, "LOG:ts  PREKILL  killed=[]\n"
                              "LOG:ts  GAME_OBSERVE  step=ok\nPID:5555\nDONE:0\n"):
            assert bridge_to_interactive_session(args) == EXIT_OK
    captured = capsys.readouterr()
    carried = [ln for ln in captured.err.splitlines()
               if "PREKILL" in ln or "GAME_OBSERVE" in ln]
    assert carried == ["ts  PREKILL  killed=[]", "ts  GAME_OBSERVE  step=ok"]
    # The stdout contract is unchanged by the timeline.
    assert captured.out == "5555\n"


def test_bridge_still_delivers_the_pid_from_a_timeline_free_marker(capsys):
    """Degrade quietly: an inner that predates the timeline, or one whose
    marker was written with none, still has to deliver its PID and its code.
    Several tests pin exactly that shape."""
    from launch_stellaris import _read_marker_timeline
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        args = build_arg_parser().parse_args(
            ["--marker", marker, "--bridge-timeout-s", "1"])
        with _bridged(marker, "PID:4242\nDONE:0\n"):
            assert bridge_to_interactive_session(args) == EXIT_OK
        assert _read_marker_timeline(marker) == []
    assert capsys.readouterr().out == "4242\n"


def test_marker_timeline_is_bounded_to_the_tail():
    """The outer re-reads the whole marker on every 0.5 s poll tick, so the
    carried lines cannot grow without limit — an inner that logs once per
    observe tick would otherwise turn the marker into the largest thing on the
    box. The tail is the part that diagnoses a run."""
    from launch_stellaris import _Timeline
    tl = _Timeline(limit=3)
    for i in range(6):
        tl.add(f"line{i}")
    lines = tl.lines()
    assert lines[-3:] == ["line3", "line4", "line5"], lines
    assert len(lines) == 4, lines
    assert "dropped" in lines[0], lines


def test_marker_stays_small_for_a_realistic_inner_run():
    """The practical bound, stated as a fact rather than left implicit: a full
    chain run writes ~20 lines of ~120 chars, so the marker is a couple of KB
    and the 200-line cap is roughly 10x headroom. Nothing here touches
    schtasks — /tr carries only the shim path, not the marker."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        with _full_chain(game_pid=5555):
            main(["--inner", "--marker", marker])
        size = os.path.getsize(marker)
    assert size < 8 * 1024, size


def source_of(func):
    """Code object of `func`, for tests that assert on how it decides."""
    return func.__code__


# ---------------------------------------------------------------------------
# Final whole-branch review fixes.
#
# A1  a bridge timeout must not orphan a live inner (schtasks /end, a per-run
#     marker nonce, and a lease file the inner watches).
# A2  argparse usage errors must not exit 2 — 2 is EXIT_PREKILL_PERMISSION.
# A3  an outer-side exception must become 99 and leave no shim behind.
# A4  0xFFFFFFFF is "nobody is on the console", not a session to bridge into.
# A5  --dry-run must not kill the running game.
# A6  bring_to_foreground must say why it failed.
# ---------------------------------------------------------------------------

def test_usage_error_exits_99_not_prekill_permission(capsys):
    """A2: argparse exits 2 on a bad command line, and 2 is
    EXIT_PREKILL_PERMISSION — "permission wall, retrying will not help". The
    agent builds this command line itself, so a typo would stop the retry loop
    for a reason that has nothing to do with the game."""
    assert main(["--bogus-flag"]) == EXIT_INTERNAL
    err = capsys.readouterr().err
    assert "usage" in err.lower()
    assert "--bogus-flag" in err
    assert EXIT_INTERNAL != EXIT_PREKILL_PERMISSION


def test_help_still_exits_zero(capsys):
    """The usage-error override must not swallow argparse's help path, which
    exits 0 through a different method."""
    assert main(["--help"]) == EXIT_OK
    assert "usage" in capsys.readouterr().out.lower()


def test_no_console_session_reports_41_without_scheduling_anything():
    """A4: WTSGetActiveConsoleSessionId returns 0xFFFFFFFF — not 0 — when
    nothing is attached to the console. That is the post-reboot,
    nobody-logged-in box, i.e. exactly the overnight case this script exists
    for. Reading it as a real session id sends the run down the scheduling
    path, where it burns the whole --bridge-timeout-s and reports 43
    (timeout) instead of 41 (no session)."""
    args = build_arg_parser().parse_args(["--bridge-timeout-s", "1"])
    with patch("launch_stellaris.current_session_id", return_value=0), \
            patch("launch_stellaris.interactive_session_id",
                  return_value=0xFFFFFFFF), \
            patch("subprocess.run") as mock_run:
        assert bridge_to_interactive_session(args) == EXIT_BRIDGE_NO_SESSION
    mock_run.assert_not_called()


def test_session_zero_also_reports_41():
    """0 is the services window station, which no window can ever be raised
    from. Both spellings of "no interactive session" have to land on 41."""
    args = build_arg_parser().parse_args(["--bridge-timeout-s", "1"])
    with patch("launch_stellaris.current_session_id", return_value=0), \
            patch("launch_stellaris.interactive_session_id", return_value=0), \
            patch("subprocess.run") as mock_run:
        assert bridge_to_interactive_session(args) == EXIT_BRIDGE_NO_SESSION
    mock_run.assert_not_called()


def test_run_launch_chain_dry_run_never_kills_anything():
    """A5: spec D4 says a dry run does everything except the URI spawn *and
    the kill*. Running PREKILL anyway means the pre-flight check a person
    runs before trusting the script kills their unsaved game and exits 0."""
    args = build_arg_parser().parse_args(["--dry-run"])
    with _full_chain() as mocks:
        assert run_launch_chain(args) == EXIT_OK
    mocks[0].assert_not_called()  # prekill


def test_bring_to_foreground_logs_why_the_foreground_was_refused(capsys):
    """A6: a refusal (integrity level, wrong desktop, dead hwnd) and a plain
    timeout are indistinguishable without SetForegroundWindow's return value
    and GetLastError. This line is the operator's only evidence, and the
    locked-desktop case is exactly where they will be reading it."""
    set_fg = MagicMock(return_value=0)
    get_fg = MagicMock(return_value=9999)
    with _fake_clock(), \
            patch("launch_stellaris._input_fns",
                  return_value=(set_fg, get_fg)), \
            patch("launch_stellaris._last_error", return_value=5):
        assert bring_to_foreground(4242) is False
    err = capsys.readouterr().err
    assert "foreground_fail" in err
    assert "set_ok=0" in err
    assert "last_error=5" in err


@patch("subprocess.run")
def test_delete_bridge_task_ends_a_running_instance_before_deleting(mock_run):
    """A1: /delete /f removes the task *definition*, not a running instance.
    A task already started keeps running as an orphan — which then walks its
    own PREKILL (killing whatever the caller's retry just started) and types
    into whatever window the retry is driving. /end is what stops it."""
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    launch_stellaris._delete_bridge_task("ls_t")
    cmds = [" ".join(c.args[0]) for c in mock_run.call_args_list]
    assert len(cmds) == 2, cmds
    assert "/end" in cmds[0], cmds
    assert "/delete" in cmds[1], cmds


@patch("subprocess.run")
def test_bridge_cleanup_survives_a_missing_schtasks(mock_run):
    """Cleanup is best effort: it runs on the exception path too, and a second
    exception out of it would replace the real cause with a traceback."""
    mock_run.side_effect = OSError("schtasks is not on PATH")
    launch_stellaris._delete_bridge_task("ls_t")  # must not raise


def test_default_marker_path_is_unique_per_run():
    """A1: keying the marker on the outer PID alone lets a recycled PID put a
    new run on an old file. A per-run nonce makes the path unique regardless
    of what the OS reuses."""
    a = launch_stellaris._default_marker_path(12345)
    b = launch_stellaris._default_marker_path(12345)
    assert a != b, (a, b)
    name = os.path.basename(a)
    assert re.fullmatch(r"ls_12345_[0-9a-f]{6}\.txt", name), name


def test_marker_nonce_keeps_the_shim_path_within_the_ceiling():
    """The nonce rides into the shim *body*, never into /tr, but the shim path
    still has to fit — it is what /tr carries."""
    with tempfile.TemporaryDirectory() as td:
        marker = launch_stellaris._default_marker_path(os.getpid())
        assert len(marker) < 120, marker
        shim = launch_stellaris.write_bridge_tr_shim(
            "stellaris-launch-12345-1760000000",
            launch_stellaris.build_inner_tr(
                build_arg_parser().parse_args([]), marker=marker),
            tempdir=td)
    assert len(shim) <= launch_stellaris.SCHTASKS_TR_LIMIT, (len(shim), shim)


def test_bridge_creates_the_lease_before_it_schedules_and_removes_it(capsys):
    """A1: the lease is the inner's only proof that someone is still
    listening. It has to exist before the task can start, and it has to be
    gone once the outer returns — the disappearance is the signal."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        lease = launch_stellaris._lease_path(marker)
        args = build_arg_parser().parse_args(
            ["--marker", marker, "--bridge-timeout-s", "1"])
        seen = {}

        def _fake_run(cmd, *a, **kw):
            if isinstance(cmd, list) and "/create" in cmd:
                seen["lease_at_create"] = os.path.exists(lease)
            if isinstance(cmd, list) and "/run" in cmd:
                Path(marker).write_text("PID:5555\nDONE:0\n", encoding="utf-8")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=_fake_run), \
                patch("launch_stellaris.current_session_id", return_value=0), \
                patch("launch_stellaris.interactive_session_id", return_value=1):
            assert bridge_to_interactive_session(args) == EXIT_OK
        assert seen["lease_at_create"] is True
        assert not os.path.exists(lease)
    assert capsys.readouterr().out == "5555\n"


def test_bridge_timeout_ends_the_task_and_removes_the_lease():
    """The 43 path is where the orphan is created. Both halves of A1 have to
    fire there: /end stops the instance, and the vanished lease stops it
    again before its next phase if it somehow survived."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        lease = launch_stellaris._lease_path(marker)
        args = build_arg_parser().parse_args(
            ["--marker", marker, "--bridge-timeout-s", "1"])
        with patch("subprocess.run",
                   return_value=MagicMock(returncode=0, stdout="", stderr="")) as run, \
                patch("launch_stellaris.current_session_id", return_value=0), \
                patch("launch_stellaris.interactive_session_id", return_value=1):
            assert bridge_to_interactive_session(args) == EXIT_BRIDGE_TIMEOUT
        cmds = [" ".join(c.args[0]) for c in run.call_args_list]
        assert any("/end" in c for c in cmds), cmds
        assert not os.path.exists(lease)


def test_inner_aborts_before_prekill_when_the_lease_is_gone():
    """A1: an orphaned inner whose outer gave up must stop before its next
    phase. PREKILL is the phase that does harm — it would kill whatever the
    caller's retry just started."""
    with tempfile.TemporaryDirectory() as td:
        lease = str(Path(td) / "never-created.lease")
        args = build_arg_parser().parse_args(["--inner", "--lease", lease])
        with patch("launch_stellaris.prekill") as mock_prekill:
            assert run_launch_chain(args) == EXIT_BRIDGE_ABANDONED
        mock_prekill.assert_not_called()


def test_inner_aborts_between_phases_when_the_lease_disappears():
    """Checking once at startup would only cover the phases that do no harm.
    The check runs again before every phase, so a lease removed while PREKILL
    was running still stops the run before STEAM_SPAWN and, crucially, before
    any click into the launcher."""
    with tempfile.TemporaryDirectory() as td:
        lease = Path(td) / "live.lease"
        lease.write_text("", encoding="utf-8")
        args = build_arg_parser().parse_args(["--inner", "--lease", str(lease)])
        with _full_chain() as mocks:
            def _prekill(*a, **kw):
                lease.unlink()
                return EXIT_OK
            mocks[0].side_effect = _prekill
            assert run_launch_chain(args) == EXIT_BRIDGE_ABANDONED
        mocks[1].assert_not_called()  # steam_spawn


def test_inner_runs_normally_while_the_lease_exists():
    with tempfile.TemporaryDirectory() as td:
        lease = Path(td) / "live.lease"
        lease.write_text("", encoding="utf-8")
        args = build_arg_parser().parse_args(["--inner", "--lease", str(lease)])
        with _full_chain():
            assert run_launch_chain(args) == EXIT_OK


def test_inner_without_a_lease_never_checks_one():
    """`--inner --marker` on its own is a documented debug path and nothing
    creates a lease for it, so nothing may be enforced."""
    args = build_arg_parser().parse_args(["--inner"])
    with _full_chain():
        assert run_launch_chain(args) == EXIT_OK


def test_abandoned_inner_writes_no_marker():
    """The marker is the channel to the outer. When the outer is gone there is
    nobody to tell, and leaving a DONE: file behind would litter TEMP with a
    line that a future run could read."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        lease = str(Path(td) / "never-created.lease")
        with _full_chain():
            rc = main(["--inner", "--marker", marker, "--lease", lease])
        assert rc == EXIT_BRIDGE_ABANDONED
        assert not os.path.exists(marker)


def _shim_in(directory, name, command):
    """Write the shim into a tempdir the test owns, so a leak is observable."""
    path = os.path.join(directory, f"{name}.cmd")
    Path(path).write_text("@echo off\r\n" + command + "\r\n", encoding="utf-8")
    return path


def test_bridge_side_oserror_becomes_99_and_leaves_no_shim():
    """A3: the inner has a blanket guard; the outer did not. A missing
    schtasks, an unwritable tempdir or any other OSError out of subprocess.run
    escaped main() as an undocumented exit 1 and leaked the .cmd shim into
    TEMP. The caller has to get a documented code."""
    with tempfile.TemporaryDirectory() as td:
        marker = str(Path(td) / "inner.txt")
        before = set(os.listdir(td))
        args = build_arg_parser().parse_args(
            ["--marker", marker, "--bridge-timeout-s", "1"])
        with patch("subprocess.run", side_effect=OSError("no schtasks")), \
                patch("launch_stellaris.current_session_id", return_value=0), \
                patch("launch_stellaris.interactive_session_id", return_value=1), \
                patch("launch_stellaris.write_bridge_tr_shim",
                      side_effect=lambda name, cmd, tempdir=None:
                          _shim_in(td, name, cmd)):
            assert bridge_to_interactive_session(args) == EXIT_INTERNAL
        assert set(os.listdir(td)) == before, os.listdir(td)


class _Parser:
    """A parser whose parse_args always returns the given namespace."""

    def __init__(self, args):
        self._args = args

    def parse_args(self, argv=None):
        return self._args


def test_main_outer_path_returns_the_bridge_exit_code():
    """main() was only ever tested with --inner. The outer path is the one the
    SSH caller actually takes, and its whole contract is 'return what the
    bridge returned'."""
    args = build_arg_parser().parse_args([])
    with patch("launch_stellaris.build_arg_parser",
               return_value=_Parser(args)), \
            patch("launch_stellaris.bridge_to_interactive_session",
                  return_value=EXIT_BRIDGE_NO_SESSION) as mock_bridge:
        assert main([]) == EXIT_BRIDGE_NO_SESSION
    mock_bridge.assert_called_once()


def test_main_outer_path_converts_an_unexpected_exception_to_99():
    """A3: an exception out of session detection happens before the shim
    exists, so bridge_to_interactive_session's own guard cannot cover it. The
    caller must still get a documented code rather than exit 1."""
    args = build_arg_parser().parse_args([])
    with patch("launch_stellaris.build_arg_parser",
               return_value=_Parser(args)), \
            patch("launch_stellaris.bridge_to_interactive_session",
                  side_effect=RuntimeError("session probe exploded")):
        assert main([]) == EXIT_INTERNAL


def test_every_exit_constant_is_returned_somewhere():
    """A constant nobody returns is a code a caller can branch on that can
    never arrive — worse than no code, because it reads as a handled case.

    12, 13 and 24 are deliberately unreachable and named below: 12/13 need
    live Steam modal state to detect (spec §4 marks them reserved) and 24 is
    superseded by launcher_handoff's own timeout (spec §6). A new constant
    with no return, or a reserved code that quietly starts being returned
    without this list changing, fails here."""
    reserved = {
        12: "Steam login modal is not detected (spec §4, reserved)",
        13: "Stellaris update modal is not detected (spec §4, reserved)",
        24: "superseded by launcher_handoff's timeout (spec §6)",
    }
    source = Path(launch_stellaris.__file__).read_text(encoding="utf-8")
    module = vars(launch_stellaris)
    dead = sorted(
        name for name, value in module.items()
        if name.startswith("EXIT_") and isinstance(value, int)
        and value not in reserved
        # 1 = the definition itself, so 2+ means something returns or raises it.
        and source.count(name) < 2
    )
    assert not dead, dead


def test_build_bridge_account_fails_loudly_rather_than_guessing():
    """M-5: the fallback used to be this box's literal identity
    (`lofibass` / `13229`) baked into a general script, which on any other box
    schedules a task as a principal that does not exist — and schtasks reports
    that much later as 'No mapping between account names and security IDs'."""
    with patch.dict(os.environ, {}, clear=True), \
            patch("launch_stellaris._login_user", return_value=""), \
            patch("platform.node", return_value=""):
        with pytest.raises(ValueError):
            build_bridge_account()


def test_pid_is_not_recorded_when_the_stdout_write_fails():
    """M-2: result.pid used to be set *before* print(game_pid). If the print
    raises, the guard turns the run into 99 — and the marker would then carry
    PID: next to DONE:99, which is the one combination _write_marker's
    docstring says must never happen."""
    result = ChainResult()

    def _print(*args, **kwargs):
        if kwargs.get("file") is None:
            raise OSError("stdout is gone")
        return None

    with _full_chain(game_pid=5555), \
            patch("builtins.print", side_effect=_print):
        assert run_launch_chain(
            build_arg_parser().parse_args([]), result) == EXIT_INTERNAL
    assert result.pid is None


def test_write_bridge_tr_shim_docstring_states_a_measurable_basis():
    """M-6: the docstring claimed '276 chars by default and 309 with
    --no-prekill --dry-run --verbose'. The second number is gone with the flag,
    and neither number is a property of this file — the length is dominated by
    two absolute paths. What matters is that it says so."""
    doc = launch_stellaris.write_bridge_tr_shim.__doc__ or ""
    assert "276" not in doc, doc
    assert "309" not in doc, doc
    assert "261" in doc, doc


def _status(tmp_path, desktop):
    p = tmp_path / "ns_awake_status.json"
    p.write_text(json.dumps({"desktop": desktop, "epoch": time.time(),
                             "state": "serving"}), encoding="utf-8")
    return str(p)


def test_read_awake_status_returns_none_for_a_half_written_file(tmp_path):
    p = tmp_path / "ns_awake_status.json"
    p.write_text('{"desktop": "unloc', encoding="utf-8")   # 原子写被进程打断的形状
    assert read_awake_status(str(p)) is None
    assert read_awake_status(str(tmp_path / "absent.json")) is None


@patch("launch_stellaris.launcher_click")
@patch("launch_stellaris.launcher_wait", return_value=(4321, 0x10))
@patch("launch_stellaris.steam_ready", return_value=4242)
@patch("launch_stellaris.steam_spawn", return_value=EXIT_OK)
@patch("launch_stellaris.prekill", return_value=EXIT_OK)
def test_phases_refuse_before_clicking_when_desktop_is_locked(
        _prekill, _spawn, _ready, _wait, click, tmp_path):
    rc = _run_launch_chain_phases(
        build_arg_parser().parse_args(["--keep-awake-status", _status(tmp_path, "locked")]))
    assert rc == EXIT_DESKTOP_UNREACHABLE          # 25,不是 22
    click.assert_not_called()


@patch("launch_stellaris.game_observe", return_value=EXIT_OK)
@patch("launch_stellaris.launcher_handoff", return_value=999)
@patch("launch_stellaris.launcher_click", return_value=EXIT_OK)
@patch("launch_stellaris.launcher_wait", return_value=(4321, 0x10))
@patch("launch_stellaris.steam_ready", return_value=4242)
@patch("launch_stellaris.steam_spawn", return_value=EXIT_OK)
@patch("launch_stellaris.prekill", return_value=EXIT_OK)
def test_phases_still_click_when_desktop_is_unlocked(
        _prekill, _spawn, _ready, _wait, click, _handoff, _observe, tmp_path):
    rc = _run_launch_chain_phases(
        build_arg_parser().parse_args(["--keep-awake-status", _status(tmp_path, "unlocked")]))
    assert rc == EXIT_OK
    assert click.call_args[0][0] == 0x10           # 只断言第一个位置参数是 hwnd


@patch("launch_stellaris.read_awake_status", side_effect=AssertionError("gate ran"))
@patch("launch_stellaris.launcher_wait", return_value=(4321, 0x10))
@patch("launch_stellaris.steam_ready", return_value=4242)
@patch("launch_stellaris.steam_spawn", return_value=EXIT_OK)
@patch("launch_stellaris.prekill", return_value=EXIT_OK)
def test_dry_run_does_not_consult_the_desktop_gate(
        _prekill, _spawn, _ready, _wait, _gate):
    # 与既有 dry-run 口径一致:dry run 不 spawn URI,也就不该被一台机的桌面状态挡住
    assert _run_launch_chain_phases(
        build_arg_parser().parse_args(["--dry-run"])) == EXIT_OK


def test_click_diagnosis_says_not_delivered_when_cursor_never_reached_target():
    traces = [click_trace((0, 0, 100, 100), 0x10, 0x10, (5, 5), True)]
    # cursor_at 每轮都不在点击坐标上 ⇒ 输入没送达(UIPI / 别的窗口吃掉)
    assert click_diagnosis(traces) == "click_not_delivered"


def test_click_diagnosis_says_wrong_window_when_it_never_owns_the_foreground():
    traces = [click_trace((0, 0, 100, 100), 0x99, 0x10, (50, 33), True)]
    assert click_diagnosis(traces) == "wrong_window"


def test_click_diagnosis_says_handoff_never_fired_when_everything_landed():
    traces = [click_trace((0, 0, 100, 100), 0x10, 0x10, (50, 33), True)]
    assert click_diagnosis(traces) == "handoff_never_fired"


def test_click_diagnosis_is_inconclusive_on_empty_or_contradictory_traces():
    assert click_diagnosis([]) == "inconclusive"
    assert click_diagnosis([{"rect": None}]) == "inconclusive"


def test_click_diagnosis_reads_the_launcher_closing_as_no_longer_alive():
    # launcher 进程没了但 _handoff_observed 没判成交接 ⇒ 不是「点击没送达」
    traces = [click_trace((0, 0, 100, 100), 0x10, 0x10, (50, 33), False)]
    assert click_diagnosis(traces) == "handoff_never_fired"


class _FakeTraceUser32:
    """GetForegroundWindow + GetCursorPos, the two read-backs the trace needs.

    `GetCursorPos` fills the POINT through the pointer the caller passed, the way
    _FakeUser32.get_thread_pid already does for a DWORD pointer.
    """

    def __init__(self, foreground=0x10, cursor=(50, 33), cursor_ok=True):
        self.foreground = foreground
        self.cursor = cursor
        self.cursor_ok = cursor_ok

    def get_foreground_window(self):
        return self.foreground

    def get_cursor_pos(self, pt_ptr):
        if not self.cursor_ok:
            return 0
        pt = ctypes.cast(pt_ptr, ctypes.POINTER(launch_stellaris._POINT))
        pt[0].x, pt[0].y = self.cursor
        return 1


@patch("launch_stellaris._handoff_observed", return_value=False)
@patch("launch_stellaris._click_at")
@patch("launch_stellaris._window_rect", return_value=(0, 0, 100, 100))
@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.bring_to_foreground", return_value=True)
@patch("launch_stellaris._trace_fns",
       return_value=(None, None))
def test_launcher_click_logs_one_trace_per_attempt_and_a_diagnosis(
        _trace, mock_fg, mock_sleep, mock_rect, mock_click, mock_handoff,
        capsys):
    """exit 23 今天只有「点了没推进」这一个信息。三档诊断的证人必须是每轮读回的
    观测(谁在前台、光标真在哪),而不是一句结论 —— 结论可以现在不下(Task 8 才下)。"""
    fake = _FakeTraceUser32(foreground=0x10, cursor=(5, 5))
    _trace.return_value = (fake.get_foreground_window, fake.get_cursor_pos)
    assert launcher_click(0x10, pid=None) == EXIT_LAUNCHER_NO_ADVANCE
    lines = [l for l in capsys.readouterr().err.splitlines()
             if "LAUNCHER_CLICK" in l]
    traces = [l for l in lines if "step=trace" in l]
    assert len(traces) == launch_stellaris._CLICK_ATTEMPTS
    for line in traces:
        assert "cursor_at=(5, 5)" in line, line
        assert "owns_foreground=True" in line, line
        assert "rect=" not in line, line          # rect 已在 step=click 那行记过
    diagnosis = [l for l in lines if "step=diagnosis" in l]
    assert len(diagnosis) == 1 and "diagnosis=click_not_delivered" in diagnosis[0]


@patch("launch_stellaris._handoff_observed", return_value=False)
@patch("launch_stellaris._click_at")
@patch("launch_stellaris._window_rect", return_value=(0, 0, 100, 100))
@patch("launch_stellaris._time.sleep", return_value=None)
@patch("launch_stellaris.bring_to_foreground", return_value=True)
def test_a_failing_trace_readback_never_changes_the_exit_code(
        mock_fg, mock_sleep, mock_rect, mock_click, mock_handoff, capsys):
    """回归钉,不是 RED:这台主机上 `ctypes.WinDLL` 根本不存在,读回必然抛。
    一条诊断日志不值得把 23 变成未记录的 1(docstring 里 OSError → NO_FOCUS 讲的
    正是同一件事)。既有那四条 launcher_click 测试全走这条路,它们只断退出码。"""
    assert launcher_click(4242) == EXIT_LAUNCHER_NO_ADVANCE
    err = capsys.readouterr().err
    assert "step=diagnosis  diagnosis=inconclusive" in err
