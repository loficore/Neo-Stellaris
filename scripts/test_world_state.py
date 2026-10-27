"""Offline fence for ``scripts/world_state.py`` — the pure world-state machine.

Three fences, one per plan Task 1 requirement:

* the transition table is spec §5's table, row by row — checked exhaustively
  over ``states × states × actions``, never sampled;
* ``unknown`` / ``undecided`` / ``None`` always land on the blocking side and
  never on ``IN_GAME_RUNNING`` (plan Review Focus 1: an unreadable classifier
  must not be consumed as "playing");
* the evidence keeps the raw counts, not just the verdicts (spec §10) — those
  counts are what a later calibration run needs, and a verdict cannot be
  re-graded into a threshold.

No shot, no pixel, no Windows: every fixture is a dict in, a tuple out.
"""
from __future__ import annotations

import itertools
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from world_state import (  # noqa: E402 - the sys.path setup above must precede this import
    ACTIONS,
    NO_ACTION,
    STATES,
    evidence_fingerprint,
    infer_state,
    may,
)

#: spec §5 的转移表，逐条抄下来（10 行 → 21 条边）。第三列是**促成这条转移的动作**：
#: ``NO_ACTION`` 表示这条转移不由那五个世界改变动作促成 —— 它是探针读到的状态变化，
#: 或者必须带证据文件的 ``unblock``（解封不是五个动作之一）。
ALLOWED: frozenset[tuple[str, str, str]] = frozenset({
    ("NO_GAME", "LAUNCHING", NO_ACTION),
    ("LAUNCHING", "IN_GAME_RUNNING", NO_ACTION),
    ("LAUNCHING", "IN_GAME_PAUSED_CLEAN", NO_ACTION),
    ("LAUNCHING", "WINDOW_EVENT", NO_ACTION),
    ("LAUNCHING", "BLOCKED_WITH_EVIDENCE", NO_ACTION),
    ("IN_GAME_RUNNING", "GUARD_ARMED", "install"),
    ("IN_GAME_RUNNING", "IN_GAME_PAUSED_CLEAN", NO_ACTION),
    ("IN_GAME_RUNNING", "CONSOLE_OPEN", NO_ACTION),
    ("IN_GAME_RUNNING", "WINDOW_EVENT", NO_ACTION),
    ("IN_GAME_PAUSED_CLEAN", "IN_GAME_RUNNING", "unpause"),
    ("IN_GAME_PAUSED_CLEAN", "WINDOW_EVENT", NO_ACTION),
    ("IN_GAME_PAUSED_CLEAN", "CONSOLE_OPEN", NO_ACTION),
    ("CONSOLE_OPEN", "IN_GAME_PAUSED_CLEAN", "console_close"),
    ("WINDOW_EVENT", "IN_GAME_RUNNING", "click_option"),
    ("WINDOW_EVENT", "WINDOW_UNSTABLE", NO_ACTION),
    ("WINDOW_UNSTABLE", "BLOCKED_WITH_EVIDENCE", NO_ACTION),
    ("GUARD_ARMED", "IN_GAME_RUNNING", "uninstall"),
    ("GUARD_ARMED", "RESTORE_INCOMPLETE", NO_ACTION),
    ("RESTORE_INCOMPLETE", "BLOCKED_WITH_EVIDENCE", NO_ACTION),
    ("BLOCKED_WITH_EVIDENCE", "IN_GAME_RUNNING", NO_ACTION),
    ("BLOCKED_WITH_EVIDENCE", "IN_GAME_PAUSED_CLEAN", NO_ACTION),
})

#: 一份「什么都没发生」的干净探针：运行中、控制台关着、没有窗口。
CLEAN_PROBE: dict = {
    "pause": {"state": "playing", "red_px": 61, "green_px": 40},
    "console": {"state": "closed", "bright_px": 300},
    "window": {"kind": "none", "gold_px": 0, "row_count": 0, "option_count": 0,
               "bbox": None},
    "raw": {},
    "pid": 4242,
    "hwnd": 0x1A0B2,
}


def test_transition_table_matches_spec():
    # 每条合法边逐条必须为 True（不做抽样）。
    for from_state, to_state, action in ALLOWED:
        assert may(from_state, to_state, action) is True, (from_state, to_state, action)

    # 穷举 states × states ×（五个动作 + NO_ACTION）：ALLOWED 之外一律 False。
    # 动作维含 NO_ACTION，否则「表外一律拒绝」对那 15 条探针驱动的边根本没被问过。
    for from_state, to_state, action in itertools.product(
            STATES, STATES, ACTIONS + (NO_ACTION,)):
        assert may(from_state, to_state, action) is ((from_state, to_state, action) in ALLOWED), \
            (from_state, to_state, action)

    # 未知状态名、未知动作名 —— 表外，必须拒绝。
    assert may("NOT_A_STATE", "IN_GAME_RUNNING", "install") is False
    assert may("IN_GAME_RUNNING", "NOT_A_STATE", "install") is False
    assert may("IN_GAME_RUNNING", "GUARD_ARMED", "teleport") is False

    # 动作维不是装饰：装 guard 不是把游戏按暂停，点窗口也不是卸 guard。
    assert may("IN_GAME_RUNNING", "IN_GAME_PAUSED_CLEAN", "install") is False
    assert may("WINDOW_EVENT", "IN_GAME_RUNNING", "install") is False
    assert may("BLOCKED_WITH_EVIDENCE", "IN_GAME_RUNNING", "install") is False


def test_unknown_never_maps_to_running():
    # 对照组：同一份探针，读数干净 ⇒ IN_GAME_RUNNING。没有它，
    # 下面三条断言可以因为「这份探针本来就什么都不是」而空过。
    state, _ = infer_state(CLEAN_PROBE)
    assert state == "IN_GAME_RUNNING"

    # 三种读不到：pause=unknown、console=undecided、window.kind=None。
    # 每种都必须落阻塞侧（spec §5「unknown 一律落阻塞侧」）。
    cases = {
        "pause unknown": dict(CLEAN_PROBE,
                              pause={"state": "unknown", "red_px": 61, "green_px": 40}),
        "console undecided": dict(CLEAN_PROBE,
                                  console={"state": "undecided", "bright_px": 300}),
        "window kind None": dict(CLEAN_PROBE,
                                 window={"kind": None, "gold_px": 0, "row_count": 0,
                                         "option_count": 0, "bbox": None}),
    }
    for label, probe in cases.items():
        state, evidence = infer_state(probe)
        assert state != "IN_GAME_RUNNING", label
        assert state == "BLOCKED_WITH_EVIDENCE", label
        assert evidence["reason"], label            # 拒绝必须带得出理由

    # 三段缺一不可 —— 少了是编程错误，不是「读不到」：抛 ValueError，
    # 不许当成 unknown 静默落阻塞侧（那样调用方永远发现不了自己形状写错了）。
    for section in ("pause", "console", "window"):
        probe = dict(CLEAN_PROBE)
        probe.pop(section)
        try:
            infer_state(probe)
        except ValueError:
            pass
        else:
            raise AssertionError(f"缺 {section} 段必须抛 ValueError")


def test_infer_state_evidence_keeps_raw_counts():
    probe = dict(CLEAN_PROBE,
                 pause={"state": "playing", "red_px": 61, "green_px": 40},
                 console={"state": "closed", "bright_px": 300},
                 window={"kind": "none", "gold_px": 0, "row_count": 0,
                         "option_count": 0, "bbox": None})
    state, evidence = infer_state(probe)
    assert state == "IN_GAME_RUNNING"

    # 原始计数逐字在证据里，且类型是 int —— 只记判词就永远没法标定阈值（spec §10）。
    for key, value in (("red_px", 61), ("green_px", 40), ("bright_px", 300),
                       ("gold_px", 0), ("row_count", 0), ("option_count", 0)):
        assert evidence["raw"][key] == value, key
        assert isinstance(evidence["raw"][key], int), key
    assert evidence["raw"]["bbox"] is None

    # 三段原文照抄，不是转述。
    assert evidence["pause"] == probe["pause"]
    assert evidence["console"] == probe["console"]
    assert evidence["window"] == probe["window"]

    # 租约要用指纹：同一份读数指纹稳定，读数动一位就变。
    assert evidence_fingerprint(evidence) == evidence_fingerprint(dict(evidence))
    assert len(evidence_fingerprint(evidence)) == 64
    bumped = dict(CLEAN_PROBE, pause={"state": "playing", "red_px": 62, "green_px": 40})
    _, other = infer_state(bumped)
    assert evidence_fingerprint(other) != evidence_fingerprint(evidence)
