"""Host-side tests for keep_awake's file channel, serve loop and CLI verbs.

The live half is Windows-only; these are plain filesystem/clock code and stay
covered on the Linux host — same split as test_game_supervisor_io.py.  Every
test redirects the four module globals to ``tmp_path``: nothing here may touch
a real ``C:\\temp`` (the R-stray fence is the executor of that rule), and the
two ``serve`` tests drive a scripted clock so tick counts are decided by the
script rather than by wall time.
"""

import json
import time
import types

import keep_awake as ka


def _redirect(monkeypatch, tmp_path):
    for name in ("STATUS_PATH", "CMD_PATH", "CMD_SEEN_PATH", "LOG_PATH"):
        monkeypatch.setattr(ka, name, str(tmp_path / name.lower()))
    return tmp_path


def _clock(monkeypatch, start, step):
    t = {"now": start}
    monkeypatch.setattr(ka.time, "sleep",
                        lambda s: t.__setitem__("now", t["now"] + step))
    monkeypatch.setattr(ka.time, "time", lambda: t["now"])


def test_serve_writes_the_contract_record_then_a_stopped_one(monkeypatch, tmp_path):
    # 假的 Windows 边缘:serve 的循环决策必须只靠 plan_tick,不靠 ctypes。
    calls = []
    _redirect(monkeypatch, tmp_path)
    _clock(monkeypatch, 1000.0, 1.0)
    monkeypatch.setattr(ka, "desktop_snapshot",
                        lambda: ("unlocked", "Default", 1, 1))
    monkeypatch.setattr(ka, "assert_execution",
                        lambda: calls.append(1) or 0x80000003)
    assert ka.serve(types.SimpleNamespace(interval=0.0, assert_every=0.0,
                                          stop_after_s=2.5)) == 0
    assert len(calls) == 4          # now=1000..1003;1003 那次写完 serving 才判停
    rec = ka.read_status()
    assert rec["state"] == "stopped" and rec["note"] == "stop_after"
    assert rec["desktop"] == "unlocked"         # 停后仍带最后观测,靠 state 拒
    assert rec["assert_rc"] == 0x80000003 and rec["pid"] == 0


def test_serve_logs_exactly_one_line_per_desktop_change(monkeypatch, tmp_path):
    _redirect(monkeypatch, tmp_path)
    _clock(monkeypatch, 1000.0, 1.0)
    seen = iter([("unlocked", "Default", 1, 1), ("locked", "Winlogon", 1, 1),
                 ("locked", "Winlogon", 1, 1), ("unlocked", "Default", 1, 1)])
    monkeypatch.setattr(ka, "desktop_snapshot", lambda: next(seen))
    monkeypatch.setattr(ka, "assert_execution", lambda: 0x80000003)
    cmds = iter([None, None, None, "quit"])     # 第四 tick 才收到停止命令
    monkeypatch.setattr(ka, "read_command", lambda p, s: next(cmds))
    assert ka.serve(types.SimpleNamespace(interval=0.0, assert_every=0.0,
                                          stop_after_s=0.0)) == 0
    lines = [json.loads(l) for l in open(ka.LOG_PATH, encoding="utf-8")]
    assert [x["event"] for x in lines] == ["desktop_change", "desktop_change"]
    assert [x["desktop"] for x in lines] == ["locked", "unlocked"]
    assert ka.read_status()["note"] == "quit"


def test_check_exit_code_table(monkeypatch, tmp_path, capsys):
    _redirect(monkeypatch, tmp_path)
    assert ka.cmd_check(types.SimpleNamespace()) == 2      # 状态文件不存在
    monkeypatch.setattr(ka.time, "time", lambda: 101.0)
    ka.atomic_write_json(ka.STATUS_PATH, {"pid": 7, "state": "serving",
                                         "epoch": 100.0, "desktop": "unlocked",
                                         "desktop_detail": "Default"})
    assert ka.cmd_check(types.SimpleNamespace()) == 0
    monkeypatch.setattr(ka.time, "time", lambda: 120.0)
    assert ka.cmd_check(types.SimpleNamespace()) == 1      # 僵尸心跳
    monkeypatch.setattr(ka.time, "time", lambda: 121.0)
    ka.atomic_write_json(ka.STATUS_PATH, {"pid": 0, "state": "stopped",
                                         "epoch": 120.0, "desktop": "unlocked",
                                         "desktop_detail": "Default"})
    assert ka.cmd_check(types.SimpleNamespace()) == 1      # 守护已停:新鲜也不放行
    assert "STATE=stopped" in capsys.readouterr().out


def test_stop_writes_quit_and_deletes_the_task(monkeypatch, tmp_path):
    _redirect(monkeypatch, tmp_path)
    deleted = []
    monkeypatch.setattr(ka, "_delete_task", lambda: deleted.append(1))
    monkeypatch.setattr(ka, "read_status",
                        lambda path=None: {"state": "stopped",
                                           "epoch": time.time()})
    monkeypatch.setattr(ka.time, "sleep", lambda s: None)
    assert ka.cmd_stop(types.SimpleNamespace(timeout_s=2)) == 0
    assert ka.read_command(ka.CMD_PATH, ka.CMD_SEEN_PATH) is None   # 去重键已记,不重放
    assert deleted == [1]


def test_status_verb_reports_absent_without_failing(monkeypatch, tmp_path, capsys):
    _redirect(monkeypatch, tmp_path)
    assert ka.cmd_status(types.SimpleNamespace()) == 0
    assert capsys.readouterr().out.startswith("DESKTOP=absent")
