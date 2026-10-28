"""Host-side fence for the daemon's lease deference (spec §12(a) point 2).

The world-state machine hands out leases so that exactly one thing changes the
world at a time.  The daemon is the other thing that changes the world — it
clicks options and taps the pause key on its own schedule — so the design's
answer is cooperation, not locking: every tick, before it does anything, it
asks whether a lease is outstanding and stands aside if one is.

This file pins that cooperation on the Linux host, where ``serve`` is
importable: no game window, no pixels, no clicks.  What it proves is the
decision, not the drawing.
"""

import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))          # scripts/windows
sys.path.insert(0, str(HERE.parent.parent))   # scripts/

import game_supervisor as gs
import world_state as ws  # pyright: ignore[reportMissingImports]


def _take_install_lease(tmp_path, now):
    """Leave one outstanding ``install`` lease on disk, as the agent does."""
    store = ws.Store.load(tmp_path / "ns_world.json")
    with store.locked():
        lease = ws.acquire(store, "install", guard="shim",
                           state="IN_GAME_RUNNING", fingerprint="f" * 64, now=now)
        assert lease is not None
        store.save()
    return lease


def test_serve_yields_when_lease_outstanding(tmp_path, monkeypatch):
    """With a lease outstanding the daemon must change nothing, and say so.

    Review Focus 3: 并发改世界 —— daemon 与 agent 同时动作时,一个reasonable的人
    期望「同一时刻只有一个改世界的人」。The assertion is on the **counters**, not on
    a return value: what matters is that no click and no pause key was sent.
    """
    # The lease is taken on the **real** clock, because that is the clock the
    # daemon reads: a lease issued at a synthetic epoch would be expired by the
    # time ``serve`` looked at it, and the test would pass for the wrong reason.
    now = time.time()
    path = tmp_path / "ns_world.json"
    lease = _take_install_lease(tmp_path, now)

    # The gate the daemon itself uses — the same pure function the CLI and the
    # drivers call, reading the same store.
    reloaded = ws.Store.load(path)
    assert ws.yield_to_lease(reloaded, now) == lease["lease_id"]

    clicks = []
    unpauses = []
    logged = []
    monkeypatch.setattr(gs, "_log", lambda rec: logged.append(rec))
    monkeypatch.setattr(gs, "_write_status", lambda rec: None)
    monkeypatch.setattr(gs, "CMD_PATH", str(tmp_path / "cmd.txt"))
    monkeypatch.setattr(gs, "CMD_SEEN_PATH", str(tmp_path / "cmd.seen"))
    monkeypatch.setattr(gs, "STATUS_PATH", str(tmp_path / "status.json"))
    monkeypatch.setattr(gs, "LOG_PATH", str(tmp_path / "log.jsonl"))
    monkeypatch.setattr(gs, "SHOT_PATH", str(tmp_path / "shot.png"))
    monkeypatch.setattr(gs, "find_game", lambda: (0, 0))
    monkeypatch.setattr(gs, "click_row", lambda *a, **k: clicks.append(a))
    monkeypatch.setattr(gs, "send_pause_key", lambda *a, **k: unpauses.append(a) or "sent")
    monkeypatch.setattr(gs, "_require_windows", lambda: None)

    gs.serve(gs.build_parser().parse_args(["serve", "--state-path", str(path)]),
             once=True)

    assert clicks == [], "the daemon clicked while a lease was outstanding"
    assert unpauses == [], "the daemon tapped the pause key while a lease was outstanding"
    assert any(rec.get("event") == "YIELD_TO_LEASE" for rec in logged), (
        "a deferral must be audible: the whole point of cooperating in code is "
        f"that a stuck window says so. Logged: {logged}")


def test_yield_is_none_without_a_lease(tmp_path):
    """No lease ⇒ no deference: the daemon drives the game as before."""
    store = ws.Store.load(tmp_path / "ns_world.json")
    assert ws.yield_to_lease(store, 1_000.0) is None


def test_an_expired_lease_does_not_make_the_daemon_yield(tmp_path):
    """A lease that no longer holds the world must not freeze the world.

    The other half of the same judgement: if an expired lease still stopped the
    daemon, a crashed agent would leave the game paused forever — and spec §6
    rule 4's expiry exists precisely so that a stale claim stops being a claim.
    """
    now = 1_000.0
    _take_install_lease(tmp_path, now)
    reloaded = ws.Store.load(tmp_path / "ns_world.json")
    assert ws.yield_to_lease(reloaded, now + ws.LEASE_TTL_S) is None
