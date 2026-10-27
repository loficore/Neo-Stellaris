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

Task 2's fix round adds four more fences, one per finding:

* the nonce alone is not evidence — the file must also carry the complete
  probe reading it was taken with (a hand-written 12-byte
  ``{"block_nonce": ...}`` is refused);
* the lock's generation half is read through a provider seam, so the
  Windows side can supply the CIM creation date without this module
  growing a win32 dependency;
* the single-writer rule is enforced, not merely documented — saving
  without holding the lock raises;
* a corrupt budget never reads as "no attempts".

Task 2's fix round 2 adds two more fences:

* the state file's directory is created **before** the lock file, so the
  very first write on a fresh host (``C:\\temp`` need not exist) does not
  die in ``os.open``;
* the start-time provider seam refuses a non-callable, instead of quietly
  degrading the lock's generation check to nothing.

Task 3's fences, one per plan requirement:

* only ``IN_GAME_RUNNING`` can issue a lease (spec §6 rule 1) — every other
  state is refused;
* a lease is single-use: the second ``consume`` of the same id is ``False``;
* an armed guard whose lease expired reads as ``RESTORE_INCOMPLETE`` on the
  next call (spec §6 rule 4 / §11-5's lazy evaluation — no ticker exists);
* an ``unknown`` classifier reading refuses the gate and issues **no** lease;
* the gate's check order is pinned observably (the first refusal is the one
  that is spoken; the later steps never run);
* the lease fingerprint pins only the fields spec §6 names, so a tick that
  moves a tick-volatile field does not invalidate an untouched world;
* a lease and its armed guard survive a save/load round trip (spec §3: the
  state must outlive the one-shot Windows process).

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

import world_state as store_module  # noqa: E402 - the sys.path setup above must precede this import
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

#: 一份**完整的探针读数**（R4 形状）—— 机器产的证据文件必须带的那三段，
#: 段里还必须有原始计数（spec §10：只记判词就永远没法标定阈值）。
#: spec §7：「唯一被接受的解封证据是 `ns_world.py probe --out <该路径>` 生成的文件
#: （含 `block_nonce` 与当时的完整探针读数）」—— 缺的证据不是证据。
FULL_READING: dict = {
    "pause": {"state": "paused", "red_px": 61, "green_px": 40},
    "console": {"state": "closed", "bright_px": 300},
    "window": {"kind": "none", "gold_px": 0, "row_count": 0, "option_count": 0,
               "bbox": None},
}


def _attempt(store, action, identity, now):
    """记一次尝试 —— **在锁内**。

    生产上的形状就是「读-改-写」：改动与落盘都在 ``with store.locked():``
    里。不持锁就改内存、改完就写盘，会把并发进程刚记的账覆盖掉（那正是
    锁要防的重复花销），所以围栏自己也不许走那条路。
    """
    with store.locked(timeout_s=1.0):
        return store_module.record_attempt(store, action, identity, now)


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
    # 记账是「读-改-写」：改动与落盘都在锁内（单写者，spec §11-4）。
    with store.locked(timeout_s=1.0):
        assert record_attempt(store, "click_option", identity, now) == 1
        assert record_attempt(store, "click_option", identity, now + 1) == 2
        store.save()
    assert path.exists()

    # 记满 click_option 的上限（2）即视为超预算。
    info = blocked(store, "click_option", now + 2)
    assert info is not None
    assert set(info) == {"nonce", "blocked_at", "attempts"}
    assert info["attempts"] == MAX_ATTEMPTS["click_option"] == 2

    # 第三次必须抛 Blocked，并带上动作名与次数；这一次**不**计数。
    with pytest.raises(Blocked) as caught:
        _attempt(store, "click_option", identity, now + 3)
    assert caught.value.action == "click_option"
    assert caught.value.attempts == 2

    # 被拒的那一次不许把账推上去 —— 账上的数还是 2（内存里的与盘上的都是）。
    still = blocked(store, "click_option", now + 3)
    assert still is not None and still["attempts"] == 2
    reloaded = Store.load(path)
    still_on_disk = blocked(reloaded, "click_option", now + 3)
    assert still_on_disk is not None and still_on_disk["attempts"] == 2

    # 预算按动作分账：别的动作没被记过，不受牵连。
    assert blocked(store, "unpause", now + 3) is None

    # 只有改变世界的五个动作记账：轮询动作根本不该进预算（spec §11-6，
    # 否则 agent 自己的轮询循环会把自己封死）。
    with pytest.raises(ValueError):
        _attempt(store, "status", identity, now)
    with pytest.raises(ValueError):
        _attempt(store, "assert-ready", identity, now)

    # 落盘后仍然是阻塞的 —— 状态必须活过进程（spec §3：Windows 侧一次性进程）。
    with store.locked(timeout_s=1.0):
        store.save()
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
    with store.locked(timeout_s=1.0):
        store.save()
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
        _attempt(relaunched, "click_option", fresh, now + 2)

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
    with store.locked(timeout_s=1.0):
        store.save()
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

    # (4) nonce 对了、探针读数也全，但 mtime 早于阻塞时刻 —— 旧证据不算数。
    evidence.write_text(json.dumps(dict(FULL_READING, block_nonce=nonce)), encoding="utf-8")
    os.utime(evidence, (now - 10, now - 10))
    ok, why = unblock(store, nonce, str(evidence), now + 5)
    assert ok is False and "mtime" in why

    # 前面四次失败没有动过封锁。
    assert blocked(store, "click_option", now + 5) is not None

    # (5) 机器产的证据（nonce 相符 + 完整探针读数 + mtime 晚于阻塞时刻）⇒ 解封。
    evidence.write_text(json.dumps(dict(FULL_READING, block_nonce=nonce)), encoding="utf-8")
    os.utime(evidence, (now + 5, now + 5))
    with store.locked(timeout_s=1.0):
        ok, why = unblock(store, nonce, str(evidence), now + 5)
        assert ok is True and why
        # 解封必须连预算一起清：不清的话下一次尝试立刻再堵，「解封」就成了装饰。
        store.save()
    fresh = Store.load(path)
    assert blocked(fresh, "click_option", now + 6) is None
    assert _attempt(fresh, "click_option", (100, "t0"), now + 6) == 1
    # 别的动作的账不许被顺手清掉。
    assert blocked(fresh, "unpause", now + 6) is not None


def test_unblock_rejects_nonce_without_probe_readings(tmp_path):
    """nonce 不是秘密：光有 nonce 的手写文件不算证据（R14）。

    spec §7：「唯一被接受的解封证据是 `ns_world.py probe --out <该路径>` 生成的文件
    （含 `block_nonce` 与**当时的完整探针读数**）」。nonce 就在明文的 json 里，
    ``blocked()`` 还把它交回给每一个调用方 —— 只查 nonce 等于没查。
    """
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
    with store.locked(timeout_s=1.0):
        store.save()
        for _ in range(MAX_ATTEMPTS["click_option"]):
            record_attempt(store, "click_option", (100, "t0"), now)
        nonce = block(store, "click_option", {"reason": "over budget"}, now)
        store.save()
    assert nonce

    # (a) 手写的十二字节文件：nonce 对、mtime 新，但没有探针读数 ⇒ 拒。
    evidence.write_text(json.dumps({"block_nonce": nonce}), encoding="utf-8")
    os.utime(evidence, (now + 5, now + 5))
    ok, why = unblock(store, nonce, str(evidence), now + 5)
    assert ok is False and "probe reading" in why

    # (b) 三段都在，但原始计数缺了 ⇒ 还是拒（读数必须是完整的）。
    partial = {"block_nonce": nonce,
               "pause": {"state": "paused", "red_px": 61},
               "console": {"state": "closed", "bright_px": 300},
               "window": {"kind": "none", "gold_px": 0, "row_count": 0}}
    evidence.write_text(json.dumps(partial), encoding="utf-8")
    os.utime(evidence, (now + 5, now + 5))
    ok, why = unblock(store, nonce, str(evidence), now + 5)
    assert ok is False and "probe reading" in why

    # (c) 拒绝没有动过封锁。
    assert blocked(store, "click_option", now + 5) is not None

    # (d) 真的探针读数（`ns_world.py probe --out` 产出的那种）⇒ 放行。
    evidence.write_text(json.dumps(dict(FULL_READING, block_nonce=nonce)), encoding="utf-8")
    os.utime(evidence, (now + 5, now + 5))
    with store.locked(timeout_s=1.0):
        ok, why = unblock(store, nonce, str(evidence), now + 5)
        assert ok is True and why
        store.save()


def test_save_outside_the_lock_is_refused(tmp_path):
    """单写者必须是被强制的，不只是被写进文档（R16）。

    锁外读-改-写会把并发进程刚记的账覆盖掉 —— 那正是这把锁要防的重复花销，
    而且它一声不吭。所以 ``save()`` 在没持锁时必须响亮地拒。
    """
    from world_state import Store

    path = tmp_path / "ns_world.json"
    store = Store.load(path)
    store.data["state"] = "IN_GAME_RUNNING"

    # 锁外写盘 ⇒ RuntimeError，说清是哪个文件、该怎么写。
    with pytest.raises(RuntimeError) as caught:
        store.save()
    message = str(caught.value)
    assert str(path) in message
    assert "store.locked()" in message

    # 拒了就是没写：盘上还是什么都没有。
    assert not path.exists()

    # 逃生口：显式地「我知道我在做什么」—— 模拟一个崩掉的写入者 / 取证写盘。
    store.save(unsafe=True)
    assert path.exists()
    assert Store.load(path).data["state"] == "IN_GAME_RUNNING"

    # 持锁时照常写。
    with store.locked(timeout_s=1.0):
        store.data["state"] = "CONSOLE_OPEN"
        store.save()
    assert Store.load(path).data["state"] == "CONSOLE_OPEN"


def test_corrupt_state_file_raises_instead_of_reading_empty_budget(tmp_path):
    """读不出来的预算绝不能读成 0 —— 那正是刷预算的洞（fail-closed 读路径）。"""
    from world_state import Store

    path = tmp_path / "ns_world.json"

    # (1) 半个 JSON。
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError):
        Store.load(path)

    # (2) 结构对，但计数不是数字 —— 读不出来就不能当作 0。
    path.write_text(json.dumps(
        {"version": 1, "attempts": {"global": {"install": {"attempts": "x"}}}}),
        encoding="utf-8")
    with pytest.raises(ValueError):
        Store.load(path)

    # 对照组：一个真的、读得出来的文件读得出来，而且读成它自己的数。
    path.write_text(json.dumps(
        {"version": 1, "state": None,
         "attempts": {"by_identity": {}, "global": {}}, "blocks": {}}),
        encoding="utf-8")
    assert Store.load(path).data["attempts"]["global"] == {}


def test_process_start_time_provider_seam(tmp_path):
    """锁的代际检查必须能被外部喂进去（R15）。

    Windows 没有 ``/proc``，代际只能由 CIM 查出来；而 ``world_state`` 必须保持
    纯（不 import win32、跨平台、离线可测）。所以这里留一个 provider 挂载点：
    Windows 侧装上它，Linux 侧不装 —— 不装时 Windows 降级成「只看存活」。
    """
    from world_state import (
        Store,
        _process_start_time,
        set_process_start_time_provider,
    )

    try:
        # provider 装上后，它说了算。
        set_process_start_time_provider(lambda pid: f"gen-{pid}")
        assert _process_start_time(4242) == "gen-4242"

        path = tmp_path / "ns_world.json"
        store = Store.load(path)
        with store.locked(timeout_s=1.0):
            owner = json.loads(
                pathlib.Path(store.lock_path).read_text(encoding="utf-8"))
            assert owner["pid"] == os.getpid()
            # 锁文件记的就是 provider 给的那一代 —— 代际比较才有东西可比。
            assert owner["start_time"] == f"gen-{os.getpid()}"
    finally:
        set_process_start_time_provider(None)

    # 卸掉 provider 之后回到本机的读法（Linux 读 /proc，别的平台读不到）。
    assert _process_start_time(4242) != "gen-4242"


def test_lock_generation_is_compared_against_the_provider(tmp_path):
    """代际比较必须拿「记录的值」对「现读的 provider 值」（R15）。

    同一个 pid 可以被回收给别的进程：只有代际对不上才认得出「持有者换人了」。
    这一条用 provider 把代际换掉，钉住比较发生在那两个值之间。
    """
    from world_state import (
        Store,
        set_process_start_time_provider,
    )

    path = tmp_path / "ns_world.json"
    store = Store.load(path)
    lock = pathlib.Path(store.lock_path)

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        tokens = {child.pid: f"gen-{child.pid}"}

        def provider(pid):
            return tokens.get(pid, f"gen-{pid}")

        set_process_start_time_provider(provider)
        try:
            # (1) 锁文件记的代际与 provider 现读的一致 ⇒ 活着的持有者，不抢。
            lock.write_text(json.dumps(
                {"pid": child.pid, "start_time": tokens[child.pid]}),
                encoding="utf-8")

            def steal_from_a_live_owner() -> None:
                with store.locked(timeout_s=0.3):
                    raise AssertionError("代际相符的活持有者的锁不能被抢走")

            with pytest.raises(TimeoutError):
                steal_from_a_live_owner()

            # (2) 同一个 pid，但代际换了（被回收给别的进程）⇒ 抢，不等。
            tokens[child.pid] = "gen-recycled"
            with store.locked(timeout_s=1.0):
                owner = json.loads(lock.read_text(encoding="utf-8"))
                assert owner["pid"] == os.getpid()
        finally:
            set_process_start_time_provider(None)
    finally:
        child.kill()
        child.wait()


def test_lock_is_reentrant_safe_and_steals_dead_owner(tmp_path):
    """锁只包住 json 的读-改-写：可重入、僵死持有者抢得走、活着的持有者要等。"""
    from world_state import Store, _process_start_time

    path = tmp_path / "ns_world.json"
    store = Store.load(path)
    # 落盘也要在锁内：锁外写盘会把并发进程的账覆盖掉（单写者，spec §11-4）。
    with store.locked(timeout_s=1.0):
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


def test_lock_creates_the_state_directory_before_taking_the_lock(tmp_path):
    """全新机器上的第一次写盘不能死在 os.open（复审发现 A）。

    锁文件住在状态文件自己的目录里，而目录在 fresh host 上可能根本不存在
    （生产路径是 ``C:\\temp\\ns_world.json``，``C:\\temp`` 不必存在）。
    若取锁时不先建目录，``os.open`` 会抛裸的 ``FileNotFoundError`` ——
    一个连模块自己那套清楚的 ``RuntimeError`` 都不是的错误，状态机连
    「第一次尝试」都记不下来。
    """
    from world_state import Store

    path = tmp_path / "sub" / "ns_world.json"
    assert not path.parent.exists(), "前置条件：目录此刻还不存在"

    store = Store.load(path)
    # 目录不存在时，load 不许有任何副作用（spec §3）。
    assert not path.parent.exists(), "load 不得建目录"

    # 取锁 + 写盘，全程不需要 unsafe=True。
    with store.locked(timeout_s=1.0):
        store.data["state"] = "IN_GAME_RUNNING"
        store.save()

    assert path.exists(), "锁路径必须把目录建出来并落盘"
    assert Store.load(path).data["state"] == "IN_GAME_RUNNING"
    assert not (path.parent / "ns_world.lock").exists(), "锁必须释放"


def test_lock_works_with_a_bare_filename_path(tmp_path, monkeypatch):
    """裸文件名（没有目录部分）不能让 os.makedirs("") 抛异常。

    ``os.path.dirname("ns_world.json")`` 是空串；建目录时必须跳过空目录，
    否则 ``makedirs("")`` 会抛 FileNotFoundError。
    """
    from world_state import Store

    monkeypatch.chdir(tmp_path)
    store = Store.load("ns_world.json")
    assert os.path.dirname(store.lock_path) == "", "前置条件：锁路径没有目录部分"

    with store.locked(timeout_s=1.0):
        store.save()

    assert (tmp_path / "ns_world.json").exists()
    assert not (tmp_path / "ns_world.lock").exists(), "锁必须释放"


def test_provider_setter_refuses_a_non_callable():
    """provider 挂载点必须拒绝不可调用的东西（复审发现 B）。

    一个不可调用的 provider 会被 ``_process_start_time`` 里的
    ``except Exception`` 吞掉，代际检查就**静默地**失效了 —— 那正是
    R15 要防的失效模式。宁可当场 TypeError。
    """
    from world_state import set_process_start_time_provider

    with pytest.raises(TypeError):
        set_process_start_time_provider("not callable")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        set_process_start_time_provider(42)  # type: ignore[arg-type]

    # None 仍然是「卸掉 provider」，不是一个错误。
    set_process_start_time_provider(None)
    set_process_start_time_provider(lambda pid: f"gen-{pid}")
    set_process_start_time_provider(None)


# ---------------------------------------------------------------------------
# Task 3: 租约、惰性 RESTORE_INCOMPLETE、综合门 assert_ready
#
# 与 Task 2 的围栏同一条规矩：新名字在每个测试里**函数内** import，每条围栏
# 各自失败，而不是一次 collection error。
# ---------------------------------------------------------------------------


def _arm_a_consumed_lease(store, now, *, guard="shim"):
    """走一遍生产路径 ``acquire → consume → arm``，但租约在 ``now`` 时已过期。

    为什么必须是**已消费**的租约：生产上 install 之后就是 consume 再 arm，所以
    armed 表里记的那张租约永远是 ``consumed=1`` 的。若 ``expired_while_armed``
    认为「消费过的租约不算数」，这条围栏会空过而生产上永远判不出
    ``RESTORE_INCOMPLETE``。

    返回那张租约。
    """
    from world_state import LEASE_TTL_S, acquire, arm, consume

    issued = now - LEASE_TTL_S - 1
    with store.locked(timeout_s=1.0):
        lease = acquire(store, "install", guard=guard, state="IN_GAME_RUNNING",
                        fingerprint="f" * 64, now=issued)
        assert lease is not None
        assert consume(store, lease["lease_id"], issued) is True
        arm(store, guard, lease["lease_id"], (4242, "t0"), issued)
        store.save()
    return lease


def test_lease_requires_running_state(tmp_path):
    """只有 ``IN_GAME_RUNNING`` 能签发租约（spec §6 规则 1）—— 其它状态一律 None。"""
    from world_state import LEASE_TTL_S, STATES, Store, acquire

    path = tmp_path / "ns_world.json"
    store = Store.load(path)
    now = 1_700_000_000.0

    # 对照组：running ⇒ 签发。没有它，下面的 None 可以因为「本来就什么都签不出」而空过。
    with store.locked(timeout_s=1.0):
        lease = acquire(store, "install", guard="shim", state="IN_GAME_RUNNING",
                        fingerprint="f" * 64, now=now)
        store.save()
    assert lease is not None
    # 租约带齐 spec §6 点名的字段。
    for field in ("lease_id", "action", "guard", "ttl_s", "fingerprint", "issued_at"):
        assert field in lease, field
    assert lease["action"] == "install"
    assert lease["guard"] == "shim"
    assert lease["fingerprint"] == "f" * 64
    assert lease["ttl_s"] == LEASE_TTL_S == 30
    # issued_at 与 now 同一个钟（浮点 epoch）—— 本模块里所有时间都是浮点；
    # spec §6 的示例写 ISO 字符串，偏离说明在报告里。
    assert isinstance(lease["issued_at"], float)
    assert lease["issued_at"] == now

    # running 之外的每一个状态都签不出租约 —— 穷举，不抽样。
    for state in STATES:
        if state == "IN_GAME_RUNNING":
            continue
        with store.locked(timeout_s=1.0):
            refused = acquire(store, "install", guard="shim", state=state,
                              fingerprint="f" * 64, now=now)
            assert refused is None, state

    # 拒发不留痕：表里只有对照组那一张。
    assert len(store.data["leases"]) == 1


def test_lease_second_consume_is_false(tmp_path):
    """租约用后作废：二次消费 False（spec §6 规则 1），未知 id 与过期租约也是。"""
    from world_state import LEASE_TTL_S, Store, acquire, consume

    path = tmp_path / "ns_world.json"
    store = Store.load(path)
    now = 1_700_000_000.0

    with store.locked(timeout_s=1.0):
        lease = acquire(store, "install", guard="shim", state="IN_GAME_RUNNING",
                        fingerprint="f" * 64, now=now)
        store.save()
    assert lease is not None
    lease_id = lease["lease_id"]

    with store.locked(timeout_s=1.0):
        assert consume(store, lease_id, now + 1) is True
        store.save()
    # 第二次：同一次 install 只认一张租约。
    with store.locked(timeout_s=1.0):
        assert consume(store, lease_id, now + 2) is False
        store.save()
    # 没签发过的 id：认不出来就不许动。
    with store.locked(timeout_s=1.0):
        assert consume(store, "no-such-lease", now + 2) is False

    # 过期的租约也不能被兑现（到期的授权就是作废）。
    with store.locked(timeout_s=1.0):
        second = acquire(store, "install", guard="witness", state="IN_GAME_RUNNING",
                         fingerprint="f" * 64, now=now + 10)
        store.save()
    assert second is not None
    with store.locked(timeout_s=1.0):
        assert consume(store, second["lease_id"], now + 10 + LEASE_TTL_S) is False


def test_expired_lease_while_armed_forces_restore_incomplete(tmp_path):
    """armed 且租约过期 ⇒ 下一次调用读出 ``RESTORE_INCOMPLETE``（spec §6 规则 4 / §11-5）。

    没有 ticker：一次性进程不会自己醒来判过期，判定发生在**有人问**的时候。
    """
    from world_state import (
        LEASE_TTL_S,
        Store,
        acquire,
        arm,
        expired_while_armed,
        unarm,
    )

    path = tmp_path / "ns_world.json"
    store = Store.load(path)
    now = 1_700_000_000.0

    with store.locked(timeout_s=1.0):
        lease = acquire(store, "install", guard="shim", state="IN_GAME_RUNNING",
                        fingerprint="f" * 64, now=now)
        assert lease is not None
        arm(store, "shim", lease["lease_id"], (4242, "t0"), now)
        store.save()

    # 还没到点：什么都不报。
    assert expired_while_armed(store, now + LEASE_TTL_S - 1) is None
    # issued_at + ttl <= now ⇒ 返回那个 guard 名。
    assert expired_while_armed(store, now + LEASE_TTL_S) == "shim"
    assert expired_while_armed(store, now + LEASE_TTL_S + 1) == "shim"

    # unarm 之后不再报 —— 所以每个驱动的卸载路径都必须调它。
    with store.locked(timeout_s=1.0):
        unarm(store, "shim", now + LEASE_TTL_S + 1)
        store.save()
    assert expired_while_armed(store, now + LEASE_TTL_S + 1) is None
    # 对没 arm 过的 guard 是无害的（幂等），卸载路径可以放心重复调。
    unarm(store, "never-armed", now + LEASE_TTL_S + 1)


def test_assert_ready_refuses_unknown_pause(tmp_path):
    """``unknown`` 一律落阻塞侧：综合门拒绝，且**一张租约都不签**。"""
    from world_state import Store, assert_ready

    path = tmp_path / "ns_world.json"
    store = Store.load(path)
    now = 1_700_000_000.0

    probe = dict(CLEAN_PROBE, pause={"state": "unknown", "red_px": 61, "green_px": 40})
    with store.locked(timeout_s=1.0):
        ok, why = assert_ready(store, "install", guard="shim",
                               probe_evidence=probe, now=now)
        store.save()
    assert ok is False
    assert why and "BLOCKED_WITH_EVIDENCE" in why
    # 拒发不许留下租约 —— 租约是注入的凭据。
    assert store.data["leases"] == {}

    # 对照组：读数干净 ⇒ 放行，并真签出一张租约（否则上面那条可以因为空表而空过）。
    with store.locked(timeout_s=1.0):
        ok, lease_id = assert_ready(store, "install", guard="shim",
                                    probe_evidence=CLEAN_PROBE, now=now)
        store.save()
    assert ok is True
    assert lease_id in store.data["leases"]


def test_assert_ready_check_order_is_pinned(tmp_path, monkeypatch):
    """综合门的顺序必须可观测地钉住：blocked → expired_while_armed → infer_state → acquire。

    钉法：把**后面的**步骤换成会抛异常的桩。前一步已经拒绝的话，那个桩根本
    不会被调用 —— 于是「顺序」成了可观测的事实（桩没炸 + 理由是前一步的），
    而不是「实现里恰好这么写」的注释。之所以不用「计数被调了几次」，是因为
    调用次数属于实现细节，而「先拒绝的先说话」是行为。
    """
    from world_state import Store, assert_ready, block

    now = 1_700_000_000.0

    def boom(*args, **kwargs):
        raise AssertionError("这一步不该被跑到：前面的检查已经拒绝了")

    def clean_gate(store, **kwargs):
        return assert_ready(store, "install", guard="shim",
                            probe_evidence=CLEAN_PROBE, now=now)

    # (1) 两条检查都会拒绝（封锁在先、armed 过期在后）⇒ 理由必须是**先**那条。
    store = Store.load(tmp_path / "blocked.json")
    with store.locked(timeout_s=1.0):
        block(store, "install", {"reason": "over budget"}, now)
        store.save()
    _arm_a_consumed_lease(store, now)
    with monkeypatch.context() as m:
        m.setattr(store_module, "infer_state", boom)
        m.setattr(store_module, "acquire", boom)
        with store.locked(timeout_s=1.0):
            ok, why = clean_gate(store)
    assert ok is False
    assert "blocked" in why.lower(), why
    assert "RESTORE_INCOMPLETE" not in why, why

    # (2) 只剩 armed 过期 ⇒ 理由换它，而且 infer_state/acquire 依然没被跑到。
    store = Store.load(tmp_path / "expired.json")
    _arm_a_consumed_lease(store, now)
    with monkeypatch.context() as m:
        m.setattr(store_module, "infer_state", boom)
        m.setattr(store_module, "acquire", boom)
        with store.locked(timeout_s=1.0):
            ok, why = clean_gate(store)
    assert ok is False
    assert "RESTORE_INCOMPLETE" in why, why

    # (3) 前两条都过 ⇒ 轮到 infer_state：读数 unknown 在这一层被拒。
    store = Store.load(tmp_path / "unknown.json")
    probe = dict(CLEAN_PROBE, pause={"state": "unknown", "red_px": 61, "green_px": 40})
    with monkeypatch.context() as m:
        m.setattr(store_module, "acquire", boom)   # acquire 是最后一步：不许先跑
        with store.locked(timeout_s=1.0):
            ok, why = assert_ready(store, "install", guard="shim",
                                   probe_evidence=probe, now=now)
    assert ok is False
    assert "BLOCKED_WITH_EVIDENCE" in why, why

    # (4) 三道都过 ⇒ acquire 真的跑了，租约真的签了。
    store = Store.load(tmp_path / "clean.json")
    with store.locked(timeout_s=1.0):
        ok, lease_id = clean_gate(store)
        store.save()
    assert ok is True
    assert lease_id in store.data["leases"]


def test_only_one_unexpired_lease_outstanding(tmp_path):
    """同一时刻只允许一张未过期的租约：用掉或到期之后才签得出下一张。"""
    from world_state import LEASE_TTL_S, Store, acquire, consume

    path = tmp_path / "ns_world.json"
    store = Store.load(path)
    now = 1_700_000_000.0

    with store.locked(timeout_s=1.0):
        first = acquire(store, "install", guard="shim", state="IN_GAME_RUNNING",
                        fingerprint="f" * 64, now=now)
        store.save()
    assert first is not None

    # 第一张还在手上 ⇒ 第二张拒。
    with store.locked(timeout_s=1.0):
        assert acquire(store, "install", guard="witness", state="IN_GAME_RUNNING",
                       fingerprint="f" * 64, now=now + 1) is None
    # 用掉第一张之后，它就不再是 outstanding ⇒ 签得出第二张。
    with store.locked(timeout_s=1.0):
        assert consume(store, first["lease_id"], now + 2) is True
        second = acquire(store, "install", guard="witness", state="IN_GAME_RUNNING",
                         fingerprint="f" * 64, now=now + 3)
        store.save()
    assert second is not None
    with store.locked(timeout_s=1.0):
        assert acquire(store, "install", guard="donor", state="IN_GAME_RUNNING",
                       fingerprint="f" * 64, now=now + 4) is None
    # 到期的租约也不再是 outstanding。
    with store.locked(timeout_s=1.0):
        third = acquire(store, "install", guard="donor", state="IN_GAME_RUNNING",
                        fingerprint="f" * 64,
                        now=now + 3 + LEASE_TTL_S + 1)
        store.save()
    assert third is not None


def test_consumed_lease_while_armed_still_expires(tmp_path):
    """生产路径 acquire → consume → arm：**已消费**的租约过期后照样判 RESTORE_INCOMPLETE。

    而且综合门读到它就要拒绝，一张新租约都不许签。
    """
    from world_state import Store, assert_ready, expired_while_armed

    path = tmp_path / "ns_world.json"
    store = Store.load(path)
    now = 1_700_000_000.0
    lease = _arm_a_consumed_lease(store, now)

    assert expired_while_armed(store, now) == "shim"
    assert store.data["leases"][lease["lease_id"]]["consumed"] is True

    with store.locked(timeout_s=1.0):
        ok, why = assert_ready(store, "install", guard="shim",
                               probe_evidence=CLEAN_PROBE, now=now)
        store.save()
    assert ok is False
    assert "RESTORE_INCOMPLETE" in why, why
    # 拒绝时表里只有那一张已过期的租约 —— 没签出新的。
    assert len(store.data["leases"]) == 1


def test_lease_fingerprint_pins_only_the_spec_fields(tmp_path):
    """租约指纹只钉 spec §6 点名的字段（hwnd, pause, console, window, N）。

    ``evidence_fingerprint`` 钉的是**整份证据**，含 tick 间会变的
    ``prev_option_count`` 与 ``reason``；拿它当租约指纹，第 N tick 签的租约在
    第 N+1 tick 就会自己作废 —— 世界没变也拒，那是假的 fail-closed。
    """
    from world_state import evidence_fingerprint, infer_state, lease_fingerprint

    a = dict(CLEAN_PROBE, prev_option_count=0)
    b = dict(CLEAN_PROBE, prev_option_count=3)
    _, ev_a = infer_state(a)
    _, ev_b = infer_state(b)
    # 整份证据的指纹：会变（那个字段在证据里）。
    assert evidence_fingerprint(ev_a) != evidence_fingerprint(ev_b)
    # 租约指纹：不变。
    assert lease_fingerprint(ev_a) == lease_fingerprint(ev_b)
    assert len(lease_fingerprint(ev_a)) == 64

    # 真的读数变了 ⇒ 租约指纹必须变（spec §6 规则 3 的前提）。
    moved = dict(CLEAN_PROBE, prev_option_count=0,
                 pause={"state": "playing", "red_px": 62, "green_px": 40})
    assert lease_fingerprint(infer_state(moved)[1]) != lease_fingerprint(ev_a)
    # N（option_count）也在指纹里。
    window_5 = {"kind": "choice", "gold_px": 40, "row_count": 5,
                "option_count": 5, "bbox": [1, 2, 3, 4]}
    window_4 = dict(window_5)
    window_4["option_count"] = 4
    base = dict(CLEAN_PROBE, prev_option_count=0, window=window_5)
    other = dict(CLEAN_PROBE, prev_option_count=0, window=window_4)
    assert lease_fingerprint(infer_state(base)[1]) != lease_fingerprint(infer_state(other)[1])
    # 窗口 hwnd 变了 ⇒ 变。
    assert lease_fingerprint(infer_state(dict(base, hwnd=1))[1]) != lease_fingerprint(infer_state(base)[1])


def test_lease_and_armed_survive_save_and_load(tmp_path):
    """租约与 armed 都必须活过进程（spec §3：Windows 侧是一次性进程）。"""
    from world_state import (
        LEASE_TTL_S,
        Store,
        acquire,
        arm,
        consume,
        expired_while_armed,
    )

    path = tmp_path / "ns_world.json"
    store = Store.load(path)
    now = 1_700_000_000.0

    with store.locked(timeout_s=1.0):
        lease = acquire(store, "install", guard="shim", state="IN_GAME_RUNNING",
                        fingerprint="f" * 64, now=now)
        assert lease is not None
        arm(store, "shim", lease["lease_id"], (4242, "t0"), now)
        store.save()

    reloaded = Store.load(path)
    assert lease["lease_id"] in reloaded.data["leases"]
    assert reloaded.data["armed"]["shim"]["lease_id"] == lease["lease_id"]
    # 重载之后这张租约还能被消费（盘上记的就是它）。
    with reloaded.locked(timeout_s=1.0):
        assert consume(reloaded, lease["lease_id"], now + 1) is True
        reloaded.save()
    # 重载之后的 armed 也能被读成过期。
    assert expired_while_armed(reloaded, now + LEASE_TTL_S + 1) == "shim"

    # 旧文件（没有 leases/armed 两键）必须被补成空表，而不是读不出来。
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps({"version": 1, "state": None,
                                  "attempts": {"by_identity": {}, "global": {}},
                                  "blocks": {}}), encoding="utf-8")
    old = Store.load(legacy)
    assert old.data["leases"] == {}
    assert old.data["armed"] == {}
