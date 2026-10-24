"""Pure-core tests for keep_awake.

The numbers in these assertions come from the read-only survey of the host on
2026-10-24(见 docs/superpowers/plans/2026-10-24-keep-awake-desktop-guard.md 的「现场现状」表);
they are the contract the Windows edge feeds into the pure core, so the whole
decision table stays testable on Linux with no ctypes, PIL or numpy.
"""

import ctypes

import pytest

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


def test_start_plan_skips_the_launch_only_for_a_beat_that_is_current():
    # 心跳新鲜不等于守护活着:它可能写完这条就死了。所以「不重复拉起」的分支仍把
    # 这条的 epoch 交回去当 baseline —— start 的成功判据是**更新**的心跳,不是这条。
    live = {"state": "serving", "epoch": 1000.0}
    assert ka.start_plan(live, 1003.0) == (False, 1000.0)
    assert ka.start_plan({"state": "stopped", "epoch": 1000.0}, 1003.0) == (True, 1000.0)
    assert ka.start_plan(live, 1016.0) == (True, 1000.0)   # 僵尸心跳:重新拉起
    assert ka.start_plan(None, 1000.0) == (True, 0.0)
    assert ka.start_plan({"state": "serving"}, 1000.0) == (True, 0.0)


def test_windows_edge_primitives_refuse_to_run_off_windows(monkeypatch):
    monkeypatch.setattr(ka.sys, "platform", "linux")
    for fn in (ka.desktop_snapshot, ka.assert_execution):
        with pytest.raises(SystemExit) as exc:
            fn()
    assert "Windows" in str(exc.value)


class _Fn:
    """一个带 `restype`/`argtypes` 属性的假 WinDLL 函数(与真 ctypes 同形)。"""

    def __init__(self, impl):
        self._impl = impl
        self.restype = None
        self.argtypes = None

    def __call__(self, *args):
        return self._impl(self, *args)


def _ret(fn, raw):
    """ctypes 的还值规则:没声明 `restype` ⇒ 按 32 位**有符号**重读那四个字节。"""
    if fn.restype is None:
        return ctypes.c_int32(raw).value
    return fn.restype(raw).value


def _arg(fn, n, value):
    """ctypes 的编组规则:没声明 `argtypes` ⇒ 按 C `int` 收,64 位句柄在这里就炸。

    2026-10-24 实机第一条 tick 就是这么死的:`GetCurrentProcess()` 声明了
    `restype = c_void_p`,于是还回 `2**64-1`,而 `ProcessIdToSessionId` 没声明
    `argtypes`,第一参默认 `c_int` ⇒ `ArgumentError: OverflowError: int too long to
    convert`(原始 traceback 逐字进了 `evidence/logs/keep_awake_live_4_4_4.log`)。
    「构造 `c_int32(huge)`」不会抛(它按 C 规则截断),抛的是**函数调用时的参数编组**,
    而那条路径只在 `_ctypes` 里有,所以这里把规则本身写出来:超出 32 位有符号范围 ⇒ 拒。
    """
    if not fn.argtypes:
        if isinstance(value, int) and not -(2 ** 31) <= value < 2 ** 31:
            raise ctypes.ArgumentError(
                f"argument {n + 1}: OverflowError: int too long to convert")
        return value
    return fn.argtypes[n].from_param(value)


class _FakeKernel32:
    HANDLE = 0xFFFFFFFFFFFFFFFF          # Windows 的 GetCurrentProcess() 就是这个伪句柄

    def __init__(self, prev_state=0x80000003, session=1, console=7, pid=4242):
        self.prev_state = prev_state
        self.session = session
        self.console = console
        self.pid = pid
        self.GetCurrentProcess = _Fn(self._get_current_process)
        self.GetCurrentProcessId = _Fn(self._get_current_process_id)
        self.ProcessIdToSessionId = _Fn(self._pid_to_session)
        self.WTSGetActiveConsoleSessionId = _Fn(self._console_session)
        self.SetThreadExecutionState = _Fn(self._set_thread_execution_state)

    def _get_current_process(self, fn):
        return _ret(fn, self.HANDLE)

    def _get_current_process_id(self, fn):
        return _ret(fn, self.pid)

    def _pid_to_session(self, fn, pid, out):
        # 真 API 的第一参是 **进程号**,不是句柄。2026-10-24 实机:传伪句柄 -1 和传
        # OpenProcess 回来的真句柄,两者一律 `FALSE` + `gle=87`(ERROR_INVALID_PARAMETER)
        # —— 句柄值当 PID 用,查不到那个进程。这里按同样方向拒:不是 pid 就答不出来。
        if pid != self.pid:
            return _ret(fn, 0)
        _arg(fn, 0, pid)
        out._obj.value = self.session
        return _ret(fn, 1)

    def _console_session(self, fn):
        return _ret(fn, self.console)

    def _set_thread_execution_state(self, fn, flags):
        _arg(fn, 0, flags)
        return _ret(fn, self.prev_state)


class _FakeUser32:
    def __init__(self, name="Default"):
        self.name = name
        self.sizes = []
        self.classes = []
        self.closed = []
        self.OpenInputDesktop = _Fn(self._open)
        self.CloseDesktop = _Fn(self._close)
        self.GetUserObjectInformationW = _Fn(self._info)

    def _open(self, fn, flags, inherit, access):
        _arg(fn, 0, flags)
        return _ret(fn, 0x2C4)

    def _close(self, fn, handle):
        self.closed.append(handle)
        return _ret(fn, 1)

    def _info(self, fn, handle, info_class, buf, n_size, needed):
        _arg(fn, 0, handle)
        self.classes.append(info_class)
        self.sizes.append(n_size)
        # 只有 UO_NAME 会往缓冲里写字符串;问别的信息号拿到的是一个数,读成宽字符串
        # 就是实机那次 `desktop_detail="\u0301"` —— 那是被当名字读回来的标志位。
        if info_class == 2:
            buf.value = self.name
        return _ret(fn, 1)


def _fake_dll(monkeypatch, kernel32, user32):
    libs = {"kernel32": kernel32, "user32": user32}
    monkeypatch.setattr(ka, "_dll", lambda name: libs[name])
    monkeypatch.setattr(ka, "_require_windows", lambda: None)


def test_win_session_ids_asks_for_the_pid_not_a_handle(monkeypatch):
    # `ProcessIdToSessionId` 的名字里就写着它的第一个参数是进程号;实机把
    # `GetCurrentProcess()` 的句柄递进去,两次(伪句柄、OpenProcess 真句柄)都是
    # `FALSE` + `gle=87`,于是守护永远报 `session=-1`、桌面判决永远 `wrong_session`。
    _fake_dll(monkeypatch, _FakeKernel32(), _FakeUser32())
    assert ka._win_session_ids() == (1, 7)


def test_assert_execution_returns_the_unsigned_dword_the_status_file_stores(monkeypatch):
    # 状态文件里的 assert_rc 与 serve 测试钉的 0x80000003 是同一份字节契约;
    # 默认 c_int 会把它读成 -2147483645,而传参那一步在真 ctypes 上直接炸。
    _fake_dll(monkeypatch, _FakeKernel32(prev_state=0x80000003), _FakeUser32())
    assert ka.assert_execution() == 0x80000003


def test_desktop_snapshot_reads_the_name_index_and_its_own_buffer_size(monkeypatch):
    # 信息号 4 不是名字(`UO_NAME = 2`),nSize 是**字节**数,不是字符数 × sizeof(wchar)。
    user32 = _FakeUser32(name="Default")
    _fake_dll(monkeypatch, _FakeKernel32(session=1, console=1), user32)
    assert ka.desktop_snapshot()[0] == "unlocked"
    assert user32.classes == [2]
    assert user32.sizes == [ctypes.sizeof(ctypes.create_unicode_buffer(256))]
    assert user32.closed == [0x2C4]

