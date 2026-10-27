"""Offline fence for ``scripts/world_state.py`` — the world-state machine.

Task 1's three fences, one per plan requirement:

* the transition table is spec §5's table, row by row — checked exhaustively
  over ``states × states × actions``, never sampled;
* ``unknown`` / ``undecided`` / ``None`` always land on the blocking side and
  never on ``IN_GAME_RUNNING`` (plan Review Focus 1: an unreadable classifier
  must not be consumed as "playing");
* the evidence keeps the raw counts, not just the verdicts (spec §10) — those
  counts are what a later calibration run needs, and a verdict cannot be
  re-graded into a threshold.

Task 2's four fences, one per plan requirement:

* the attempt budget blocks: over the cap the action is blocked and the next
  attempt is refused (``Blocked``), and the count survives a restart because
  it is on disk;
* a relaunch does not buy a fresh budget (plan Review Focus 4) — the global
  window is what outlives the pid;
* a hand-written / ``touch``ed evidence file does not unblock anything (plan
  Review Focus 5) — only machine-made evidence carrying the nonce does, and
  only if it is newer than the block;
* the lock is reentrant, steals a dead owner, and waits for a live one — it
  serialises the read-modify-write of the json and nothing else.

No shot, no pixel, no Windows: every fixture is a dict in, a tuple out; the
only files touched are the ones under ``tmp_path``.
"""
from __future__ import annotations

import itertools
import json
import os
import pathlib
import subprocess
import sys

import pytest

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


# ---------------------------------------------------------------------------
# Task 2: 持久化、锁、尝试预算、阻塞与解封
#
# 新名字在每个测试里**函数内** import：这样每条围栏各自在自己的名字上失败
# （红时是 4 failed，不是一次 collection error），而顶部的 import 仍只钉 Task 1。
# ---------------------------------------------------------------------------

#: 一个确定不存在的 pid：Linux 的 pid 上限是 2**22（PID_MAX_LIMIT），所以
#: 2**30 永远不是一个活着的进程 —— 拿它伪造「持有者已消失」的僵死锁。
DEAD_PID = 2 ** 30


def test_attempts_block_after_max(tmp_path):
    """预算记满就阻塞，下一次尝试被拒 —— 而且计数在盘上（Windows 侧一次性进程）。"""
    from world_state import (
        MAX_ATTEMPTS,
        Blocked,
        Store,
        blocked,
        record_attempt,
    )

    path = tmp_path / "ns_world.json"
    store = Store.load(path)
    # 读状态不建文件：import 与 load 都零副作用（spec §3）。
    assert not path.exists()

    now = 1_700_000_000.0
    identity = (100, "t0")
    assert record_attempt(store, "click_option", identity, now) == 1
    assert record_attempt(store, "click_option", identity, now + 1) == 2

    # 记满 click_option 的上限（2）即视为超预算。
    info = blocked(store, "click_option", now + 2)
    assert info is not None
    assert set(info) == {"nonce", "blocked_at", "attempts"}
    assert info["attempts"] == MAX_ATTEMPTS["click_option"] == 2

    # 第三次必须抛 Blocked，并带上动作名与次数；这一次**不**计数。
    with pytest.raises(Blocked) as caught:
        record_attempt(store, "click_option", identity, now + 3)
    assert caught.value.action == "click_option"
    assert caught.value.attempts == 2

    # 预算按动作分账：别的动作没被记过，不受牵连。
    assert blocked(store, "unpause", now + 3) is None

    # 只有改变世界的五个动作记账：轮询动作根本不该进预算（spec §11-6，
    # 否则 agent 自己的轮询循环会把自己封死）。
    with pytest.raises(ValueError):
        record_attempt(store, "status", identity, now)
    with pytest.raises(ValueError):
        record_attempt(store, "assert-ready", identity, now)

    # 落盘后仍然是阻塞的 —— 状态必须活过进程（spec §3：Windows 侧一次性进程）。
    store.save()
    assert path.exists()
    reloaded = Store.load(path)
    assert blocked(reloaded, "click_option", now + 4) is not None


def test_relaunch_does_not_reset_global_window(tmp_path):
    """换 pid 不是解封：全局窗（10 分钟）跨进程活着（plan Review Focus 4）。"""
    from world_state import (
        GLOBAL_WINDOW_S,
        Blocked,
        Store,
        blocked,
        record_attempt,
    )

    path = tmp_path / "ns_world.json"
    now = 1_700_000_000.0
    store = Store.load(path)
    store.save()
    with store.locked(timeout_s=1.0):
        assert record_attempt(store, "click_option", (100, "t0"), now) == 1
        assert record_attempt(store, "click_option", (100, "t0"), now + 1) == 2
        store.save()

    # 重启游戏：新 pid、新 start_time ⇒ 身份计数是空的，全局窗还在。
    relaunched = Store.load(path)
    fresh = (200, "t1")
    assert blocked(relaunched, "click_option", now + 2, identity=fresh) is not None
    assert blocked(relaunched, "click_option", now + 2) is not None
    # 连记一次都不行：刷不动预算才是预算。
    with pytest.raises(Blocked):
        record_attempt(relaunched, "click_option", fresh, now + 2)

    # 10 分钟之外，全局窗过期，预算重新开始（spec §7：窗只管全局那条计数）。
    outside = Store.load(path)
    assert blocked(outside, "click_option", now + GLOBAL_WINDOW_S + 1) is None
    # 而这个进程自己记的那条账不随窗过期 —— 阻塞要一直粘着，直到有人带证据解封。
    assert blocked(outside, "click_option", now + GLOBAL_WINDOW_S + 1,
                   identity=(100, "t0")) is not None


def test_unblock_rejects_file_without_nonce(tmp_path):
    """手写/touch 出来的证据解不了封：nonce 与 mtime 两道都要过（plan Review Focus 5）。"""
    from world_state import (
        MAX_ATTEMPTS,
        Store,
        block,
        blocked,
        record_attempt,
        unblock,
    )

    path = tmp_path / "ns_world.json"
    evidence = tmp_path / "ns_block_evidence.json"
    now = 1_700_000_000.0
    store = Store.load(path)
    store.save()
    with store.locked(timeout_s=1.0):
        for _ in range(MAX_ATTEMPTS["click_option"]):
            record_attempt(store, "click_option", (100, "t0"), now)
        # 另一个动作也记满，用来证明解封只清自己那笔账。
        for _ in range(MAX_ATTEMPTS["unpause"]):
            record_attempt(store, "unpause", (100, "t0"), now)
        nonce = block(store, "click_option", {"reason": "over budget"}, now)
        store.save()
    assert nonce

    # (1) 证据文件不存在。
    ok, why = unblock(store, nonce, str(tmp_path / "missing.json"), now + 5)
    assert ok is False and "not found" in why

    # (2) 空文件：不是合法 JSON。
    evidence.write_text("", encoding="utf-8")
    ok, why = unblock(store, nonce, str(evidence), now + 5)
    assert ok is False and "empty" in why

    # (3) 合法 JSON 但没有 block_nonce —— 机器没写过它。
    evidence.write_text(json.dumps({"probe": "readings"}), encoding="utf-8")
    ok, why = unblock(store, nonce, str(evidence), now + 5)
    assert ok is False and "block_nonce" in why

    # (4) nonce 对了，但 mtime 早于阻塞时刻 —— 旧证据不算数。
    evidence.write_text(json.dumps({"block_nonce": nonce}), encoding="utf-8")
    os.utime(evidence, (now - 10, now - 10))
    ok, why = unblock(store, nonce, str(evidence), now + 5)
    assert ok is False and "mtime" in why

    # 前面四次失败没有动过封锁。
    assert blocked(store, "click_option", now + 5) is not None

    # (5) 机器产的证据（nonce 相符 + mtime 晚于阻塞时刻）⇒ 解封。
    evidence.write_text(json.dumps({"block_nonce": nonce}), encoding="utf-8")
    os.utime(evidence, (now + 5, now + 5))
    ok, why = unblock(store, nonce, str(evidence), now + 5)
    assert ok is True and why

    # 解封必须连预算一起清：不清的话下一次尝试立刻再堵，「解封」就成了装饰。
    store.save()
    fresh = Store.load(path)
    assert blocked(fresh, "click_option", now + 6) is None
    assert record_attempt(fresh, "click_option", (100, "t0"), now + 6) == 1
    # 别的动作的账不许被顺手清掉。
    assert blocked(fresh, "unpause", now + 6) is not None


def test_lock_is_reentrant_safe_and_steals_dead_owner(tmp_path):
    """锁只包住 json 的读-改-写：可重入、僵死持有者抢得走、活着的持有者要等。"""
    from world_state import Store, _process_start_time

    path = tmp_path / "ns_world.json"
    store = Store.load(path)
    store.save()
    lock = pathlib.Path(store.lock_path)

    def nested_section() -> None:
        """A section that takes the same lock again — the reentrancy case."""
        with store.locked(timeout_s=1.0):
            assert store.data["version"] == 1

    # (1) 同一个 Store 再拿一次锁：拿得到（不是自锁死），且内层退出不把外层的锁丢掉。
    with store.locked(timeout_s=1.0):
        nested_section()
        assert lock.exists(), "内层退出不能把外层的锁丢掉"
    assert not lock.exists(), "最外层退出必须释放锁"

    # (2) 僵死持有者（pid 根本不存在）⇒ 抢占，不等。
    lock.write_text(json.dumps({"pid": DEAD_PID, "start_time": "gone"}),
                    encoding="utf-8")
    with store.locked(timeout_s=1.0):
        owner = json.loads(lock.read_text(encoding="utf-8"))
        assert owner["pid"] == os.getpid()
    assert not lock.exists()

    # (3) 代际不符（pid 活着，但 start_time 不是它的）⇒ 也抢（pid 被回收过）。
    #     Windows 读不到别人的 start_time，那边只剩「持有者是否活着」这一条。
    if os.name != "nt":
        lock.write_text(json.dumps({"pid": os.getpid(), "start_time": "recycled"}),
                        encoding="utf-8")
        with store.locked(timeout_s=1.0):
            owner = json.loads(lock.read_text(encoding="utf-8"))
            assert owner["pid"] == os.getpid()

    # (4) 活着的别人持有 ⇒ 等到超时，而不是抢（锁是单写者，不是先到先得）。
    def steal_from_a_live_owner() -> None:
        with store.locked(timeout_s=0.3):
            raise AssertionError("活着的持有者的锁不能被抢走")

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        lock.write_text(json.dumps(
            {"pid": child.pid, "start_time": _process_start_time(child.pid)}),
            encoding="utf-8")
        with pytest.raises(TimeoutError):
            steal_from_a_live_owner()
    finally:
        child.kill()
        child.wait()
