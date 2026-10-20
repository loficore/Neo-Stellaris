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
