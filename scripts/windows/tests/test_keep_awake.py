"""Pure-core tests for keep_awake.

The numbers in these assertions come from the read-only survey of the host on
2026-10-24(见 docs/superpowers/plans/2026-10-24-keep-awake-desktop-guard.md 的「现场现状」表);
they are the contract the Windows edge feeds into the pure core, so the whole
decision table stays testable on Linux with no ctypes, PIL or numpy.
"""

import keep_awake as ka


def test_execution_flags_are_continuous_display_and_system():
    assert ka.execution_flags() == 0x80000003


def test_default_is_the_only_reachable_state():
    assert ka.classify_desktop("Default", 0, 1, 1) == "unlocked"
    assert ka.desktop_reachable("unlocked") is True
    for state in ka.DESKTOP_STATES:
        if state != "unlocked":
            assert ka.desktop_reachable(state) is False


def test_winlogon_input_desktop_is_locked_and_screensaver_is_named_apart():
    assert ka.classify_desktop("Winlogon", 0, 1, 1) == "locked"
    assert ka.classify_desktop("ScreenSaver", 0, 1, 1) == "screensaver"


def test_access_denied_is_unreadable_not_unlocked():
    assert ka.classify_desktop(None, ka.ERROR_ACCESS_DENIED, 1, 1) == "unreadable_denied"
    assert ka.classify_desktop(None, 87, 1, 1) == "unreadable_error"


def test_a_foreign_session_is_wrong_session_before_the_desktop_name():
    assert ka.classify_desktop("Default", 0, 0, 1) == "wrong_session"


def test_an_unlisted_desktop_name_is_unknown_name():
    assert ka.classify_desktop("RDP-WinStation", 0, 1, 1) == "unknown_name"


def test_fresh_is_a_strict_max_age_boundary():
    now = 1000.0
    assert ka.is_fresh({"epoch": now - 14.9}, now) is True
    assert ka.is_fresh({"epoch": now - 15.1}, now) is False
    assert ka.is_fresh({}, now) is False
    assert ka.is_fresh(None, now) is False
    assert ka.is_fresh({"epoch": "x"}, now) is False


def test_reassert_only_after_the_interval():
    assert ka.should_reassert(1000.0, 1024.9) is False
    assert ka.should_reassert(1000.0, 1025.0) is True
    assert ka.should_reassert(0.0, 100.0) is True


def test_plan_tick_pairs_the_two_loop_decisions():
    do_assert, changed = ka.plan_tick(1025.0, 1000.0, "unlocked", "locked")
    assert (do_assert, changed) == (True, True)
    assert ka.plan_tick(1010.0, 1000.0, "locked", "locked") == (False, False)
    assert ka.plan_tick(1010.0, 1000.0, "unlocked", "locked") == (False, True)


def test_status_record_keys_are_the_wire_contract():
    rec = ka.build_status_record(pid=7, now=1000.0, desktop_state="unlocked",
                                 desktop_detail="Default", own_session=1,
                                 console_session=1, assert_rc=0x80000003,
                                 asserted_at=999.0)
    assert set(rec) == {"pid", "epoch", "state", "note", "desktop",
                        "desktop_detail", "session", "console_session",
                        "assert_rc", "asserted_at"}
    assert rec["state"] == "serving" and rec["note"] == ""
    assert rec["desktop"] == "unlocked" and rec["epoch"] == 1000.0


def test_status_line_names_state_desktop_age_rc_and_pid():
    rec = ka.build_status_record(pid=7, now=1000.0, desktop_state="locked",
                                 desktop_detail="Winlogon", own_session=1,
                                 console_session=1, assert_rc=0, asserted_at=999.0)
    line = ka.status_line(rec, now=1002.0)
    assert "STATE=serving" in line
    assert "DESKTOP=locked" in line and "detail=Winlogon" in line
    assert "age=2.0s" in line and "pid=7" in line and "assert_rc=0" in line
    assert ka.status_line(None, now=1000.0) == "DESKTOP=absent"


def test_task_shim_starts_the_serve_verb_and_is_ascii():
    text = ka.task_shim_text(r"C:\py\pythonw.exe", r"C:\temp\keep_awake.py")
    text.encode("ascii")                       # 非 ASCII 装路径要在这里炸,不是任务静默死掉
    assert text.startswith("@echo off\r\n")
    assert 'keep_awake.py" serve >> ' in text
    assert text.rstrip().endswith("2>&1")        # 与 game_supervisor 的 shim 同形:stdout/err 归 OUT_PATH
