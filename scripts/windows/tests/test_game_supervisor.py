"""Host-side tests for the game supervisor's pure core.

Numbers in these tests are the spike measurements of 2026-10-23 (see the
plan's Spec section); they are the contract the Windows edge feeds in.
No Windows API, no PIL, no numpy.
"""

import inspect
import json
import os
import pathlib
import random
import time

import pytest

import game_supervisor as gs
import popup_guard as gs_popup_guard


def test_pause_signature_from_spike():
    assert gs.classify_pause(960, 0) == "paused"
    assert gs.classify_pause(965, 0) == "paused"
    assert gs.classify_pause(0, 204) == "playing"
    assert gs.classify_pause(0, 200) == "playing"
    assert gs.classify_pause(0, 0) == "unknown"
    assert gs.classify_pause(120, 120) == "unknown"
    # 4.4.4 live icon is salmon, not pure red: measured 209 mask pixels
    # 2026-10-23 while the date read "暂停".
    assert gs.classify_pause(209, 0) == "paused"
    assert gs.classify_pause(40, 0) == "unknown"


def test_choice_window_requires_wide_box_and_rows_past_news_width():
    rows = [{"y0": 858, "y1": 864, "x0": 1260, "x1": 1600},
            {"y0": 892, "y1": 898, "x0": 1262, "x1": 1594},
            {"y0": 926, "y1": 932, "x0": 1260, "x1": 1590}]
    assert gs.classify_window(rows, [400, 280, 1760, 1080], 16399) == "choice"


def test_news_window_is_a_dialog_not_a_choice():
    rows = [{"y0": 700, "y1": 720, "x0": 900, "x1": 1300},
            {"y0": 760, "y1": 780, "x0": 905, "x1": 1310}]
    assert gs.classify_window(rows, [880, 450, 1420, 940], 29930) == "dialog"


def test_choice_rows_decide_even_without_a_panel_bbox():
    rows = [{"y0": 858, "y1": 864, "x0": 1260, "x1": 1600},
            {"y0": 892, "y1": 898, "x0": 1262, "x1": 1594}]
    assert gs.classify_window(rows, None, 16399) == "choice"
    assert gs.classify_window(rows, [400, 280, 1760, 1080], 16399) == "choice"


def test_map_gold_without_a_window_is_none():
    rows = [{"y0": 500, "y1": 505, "x0": 200, "x1": 400},
            {"y0": 600, "y1": 605, "x0": 210, "x1": 405}]
    assert gs.classify_window(rows, None, 14616) == "none"


def test_left_column_rows_are_not_options():
    rows = [{"y0": 858, "y1": 864, "x0": 900, "x1": 1600}] * 3
    assert gs.classify_window(rows, [880, 450, 1420, 940], 16399) == "dialog"


def test_policies_and_index_clamp():
    rows = [{"y0": 858, "y1": 864, "x0": 1260, "x1": 1600}] * 3
    rng = random.Random(0)
    assert gs.choose_row("first", rows, rng) == 0
    assert gs.choose_row("last", rows, rng) == 2
    assert gs.choose_row("2", rows, rng) == 1
    assert gs.choose_row("3", rows, rng) == 2
    assert gs.choose_row("9", rows, rng) is None
    assert gs.choose_row("0", rows, rng) is None
    assert gs.choose_row("random", rows, rng) in (0, 1, 2)
    assert gs.choose_row("first", [], rng) is None
    assert gs.choose_row("bogus", rows, rng) is None


def test_human_pause_without_window_is_not_resumed():
    action, _ = gs.plan_step("playing", "paused", "none")
    assert action == "report_paused_no_window"
    action, _ = gs.plan_step(None, "paused", "none")
    assert action == "none"


def test_commanded_unpause_resumes_a_bare_pause_once():
    action, _ = gs.plan_step("playing", "paused", "none", resume_commanded=True)
    assert action == "resume"
    action, extra = gs.plan_step("playing", "paused", "choice",
                                 resume_commanded=True)
    assert action == "handle_choice" and extra["restore"] == "playing"


def test_commanded_paused_is_enforced_and_preserved():
    action, _ = gs.plan_step("paused", "playing", "none")
    assert action == "pause"
    action, extra = gs.plan_step("paused", "paused", "choice")
    assert action == "handle_choice" and extra["restore"] == "paused"


def test_commanded_playing_resumes_only_through_a_handled_window():
    action, extra = gs.plan_step("playing", "paused", "choice")
    assert action == "handle_choice" and extra["restore"] == "playing"
    action, extra = gs.plan_step("playing", "paused", "dialog")
    assert action == "handle_dialog" and extra["restore"] == "playing"
    action, _ = gs.plan_step("playing", "playing", "none")
    assert action == "none"


def test_observe_mode_still_handles_events_but_restores_nothing():
    action, extra = gs.plan_step(None, "paused", "choice")
    assert action == "handle_choice" and extra["restore"] is None


def test_unknown_pause_state_never_acts():
    action, _ = gs.plan_step("playing", "unknown", "choice")
    assert action == "none"


def test_command_vocabulary():
    assert gs.parse_command("") is None
    assert gs.parse_command("   ") is None
    assert gs.parse_command("pause") == {"verb": "pause"}
    assert gs.parse_command("UNPAUSE") == {"verb": "unpause"}
    assert gs.parse_command("toggle") == {"verb": "toggle"}
    assert gs.parse_command("want playing") == {"verb": "want", "want": "playing"}
    assert gs.parse_command("policy random") == {"verb": "policy", "policy": "random"}
    assert gs.parse_command("choose 2") == {"verb": "choose", "policy": "2"}
    assert gs.parse_command("speed up") == {"verb": "speed", "direction": "up"}
    assert gs.parse_command("click 1400 861") == {"verb": "click", "x": 1400, "y": 861}
    assert gs.parse_command("click 1400") is None
    assert gs.parse_command("click a b") is None
    assert gs.parse_command("shot") == {"verb": "shot"}
    assert gs.parse_command("status") == {"verb": "status"}
    assert gs.parse_command("quit") == {"verb": "quit"}
    assert gs.parse_command("dismiss") == {"verb": "dismiss"}
    assert gs.parse_command("frobnicate 3") == {"verb": "unknown", "raw": "frobnicate 3"}


def test_console_verb_preserves_text():
    cmd = gs.parse_command('console effect = { every_system = { log = "X Y" } }')
    assert cmd == {"verb": "console",
                   "text": 'effect = { every_system = { log = "X Y" } }'}
    assert gs.parse_command("CONSOLE  abc  def")["text"] == "abc  def"
    assert gs.parse_command("console") is None
    assert gs.parse_command("console   ") is None


def test_grace_reread_survives_a_window_that_disappears():
    # A game killed while the daemon waits out grace_s used to raise OSError
    # 1400 (GetWindowRect) straight out of serve and kill the supervisor.
    slept = []

    def dead():
        raise OSError(1400, "GetWindowRect failed")

    assert gs.reread_after_grace("paused", "playing", 10.0, dead,
                                 slept.append) == "unknown"
    assert slept == [10.0]


def test_grace_reread_returns_the_fresh_reading_only_when_it_applies():
    def playing():
        return "playing", 0, 204

    def never(_):
        raise AssertionError("slept without a grace window")

    assert gs.reread_after_grace("paused", "playing", 2.0, playing,
                                 lambda s: None) == "playing"
    assert gs.reread_after_grace("paused", "paused", 2.0, playing, never) == "paused"
    assert gs.reread_after_grace("playing", "playing", 2.0, playing, never) == "playing"


def _console_tail():
    down, up = 0x0008, 0x000A
    burst = [(0, 0x0E, down, 0.02), (0, 0x0E, up, 0.02)] * gs.BACKSPACE_CLEAR
    return burst + [
        (0, 0x1D, down, 0.08),
        (0, 0x2F, down, 0.08), (0, 0x2F, up, 0.08),
        (0, 0x1D, up, 0.08),
        (0, 0x1C, down, 0.08), (0, 0x1C, up, 0.08),
    ]


def test_console_key_plan_taps_only_to_open_a_closed_console():
    down, up = 0x0008, 0x000A
    tap = [(0, 0x29, down, 0.08), (0, 0x29, up, 0.08)]
    assert gs.console_key_plan(open_console=True) == tap + _console_tail()
    # Live 2026-10-23 (C4 shot): a submitted command leaves the console OPEN,
    # and the console key toggles — the capture command's opening tap closed
    # it and its keystrokes went to the game.  0 of 783 sentinel lines ran.
    assert gs.console_key_plan(open_console=False) == _console_tail()


def test_console_command_does_not_tap_a_console_it_left_open(monkeypatch, tmp_path):
    monkeypatch.setattr(gs, "LOG_PATH", str(tmp_path / "supervisor.jsonl"))
    monkeypatch.setattr(gs, "STATUS_PATH", str(tmp_path / "status.json"))
    sent = []
    monkeypatch.setattr(gs, "focus", lambda hwnd: True)
    monkeypatch.setattr(gs, "_set_clipboard_text", lambda text: True)
    monkeypatch.setattr(gs, "_send_input_event",
                        lambda vk, scan, flags: sent.append((vk, scan)))
    monkeypatch.setattr(gs.time, "sleep", lambda s: None)
    state = {"want": "paused"}
    gs._handle_command({"verb": "console", "text": "one"}, 7, state)
    first = list(sent)
    sent.clear()
    gs._handle_command({"verb": "console", "text": "two"}, 7, state)
    second = list(sent)
    assert first[:2] == [(0, 0x29), (0, 0x29)]
    assert (0, 0x29) not in second
    assert state["console_open"] is True


def test_close_is_a_graceful_verb_not_a_kill():
    # The plan forbids killing stellaris.exe; `close` posts WM_CLOSE (the
    # window's own close path) so a relaunch does not need taskkill.
    assert gs.parse_command("close") == {"verb": "close"}


def test_console_sync_lets_an_operator_declare_the_console_state(monkeypatch,
                                                                 tmp_path):
    monkeypatch.setattr(gs, "LOG_PATH", str(tmp_path / "supervisor.jsonl"))
    monkeypatch.setattr(gs, "STATUS_PATH", str(tmp_path / "status.json"))
    state = {"want": "paused", "console_open": False}
    gs._handle_command({"verb": "console_sync", "open": True}, 7, state)
    assert state["console_open"] is True
    assert gs.parse_command("console_sync closed") == {"verb": "console_sync",
                                                       "open": False}
    assert gs.parse_command("console_sync sideways") is None


def _input_stub(monkeypatch, tmp_path):
    """Shared scaffolding: a supervisor whose keystrokes and clicks are recorded."""
    monkeypatch.setattr(gs, "LOG_PATH", str(tmp_path / "supervisor.jsonl"))
    monkeypatch.setattr(gs, "STATUS_PATH", str(tmp_path / "status.json"))
    sent = []
    monkeypatch.setattr(gs, "focus", lambda hwnd: True)
    monkeypatch.setattr(gs, "_set_clipboard_text", lambda text: True)
    monkeypatch.setattr(gs, "_send_input_event",
                        lambda vk, scan, flags: sent.append((vk, scan)))
    monkeypatch.setattr(gs, "press_space", lambda hwnd: sent.append(("space",)))
    monkeypatch.setattr(gs, "speed_label_sha", lambda hwnd: "0" * 16)
    monkeypatch.setattr(gs, "window_rect", lambda hwnd: (0, 0, 2000, 1000))
    # click_close re-reads the window after the click; without this stub the
    # re-read would drag every _input_stub test into the real screenshot path.
    monkeypatch.setattr(gs, "read_window",
                        lambda hwnd: {"bright": 0.0, "gold": 0, "rows": [],
                                      "bbox": None})
    class _Launcher:
        def _click_at(self, x, y):
            sent.append(("click", x, y))

    monkeypatch.setattr(gs, "_launch", lambda: _Launcher())
    monkeypatch.setattr(gs.time, "sleep", lambda s: None)
    return sent


def _logged_events(tmp_path):
    with open(tmp_path / "supervisor.jsonl", encoding="utf-8") as f:
        return [json.loads(line)["event"] for line in f]


def _logged_events_full(tmp_path):
    with open(tmp_path / "supervisor.jsonl", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def test_console_command_refuses_instead_of_guessing_when_state_is_unknown(
        monkeypatch, tmp_path):
    # Live 2026-10-23: the C4 capture command was sent with opened=False on a
    # console the daemon only *believed* was open.  The keystrokes went to the
    # game, 0 of 783 sentinels ran, and the log could not tell the two cases
    # apart.  An unknown state must be a loud refusal, never a guess.
    sent = _input_stub(monkeypatch, tmp_path)
    state = {"want": "paused", "console_open": None}
    gs._handle_command({"verb": "console", "text": "log = 1"}, 7, state)
    assert sent == []
    assert state["console_open"] is None
    assert "console_refused" in _logged_events(tmp_path)


def _armed_state(tmp_path, action, **over):
    """A ``state`` dict carrying a lease for ``action``, as ``serve`` builds it.

    Since spec §12(a) point 1 the world-changing verbs go through the lease, so
    a test that exercises one has to arm it first — the gate is not a detail of
    the verb, it *is* the verb's precondition.
    """
    import sys
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
    import world_state as ws

    probe = {
        "pause": {"state": "playing", "red_px": 61, "green_px": 40},
        "console": {"state": "closed", "bright_px": 300},
        "window": {"kind": "none", "gold_px": 0, "row_count": 0,
                   "option_count": 0, "bbox": None},
        "raw": {}, "pid": 4242, "hwnd": 7,
    }
    # One store per call: ``acquire`` allows a single outstanding lease, so a
    # shared file would make the second verb in a loop fail for the wrong reason.
    path = tmp_path / f"ns_world_{len(list(tmp_path.glob('ns_world*.json')))}.json"
    store = ws.Store.load(path)
    with store.locked():
        lease = ws.acquire(store, action, guard=None, state="IN_GAME_RUNNING",
                           fingerprint=ws.lease_fingerprint(probe), now=time.time())
        assert lease is not None
        store.save()
    state = {"want": "paused", "console_open": True, "probe": probe,
             "state_path": str(path)}
    state.update(over)
    return state


def test_game_input_verbs_invalidate_the_console_belief(monkeypatch, tmp_path):
    # A click in the game area or a speed key can close or defocus the panel;
    # after any input aimed at the game the panel state is no longer known.
    for verb, cmd in (("speed", {"verb": "speed", "direction": "up"}),
                      ("click", {"verb": "click", "x": 10, "y": 20}),
                      ("dismiss", {"verb": "dismiss"})):
        sent = _input_stub(monkeypatch, tmp_path)
        action = "click_option" if verb == "click" else "unpause"
        state = _armed_state(tmp_path, action,
                             last_bbox=(100, 100, 200, 200), paused="paused")
        gs._handle_command(cmd, 7, state)
        assert state["console_open"] is None, verb


def test_pause_key_is_not_typed_into_an_open_console(monkeypatch, tmp_path):
    # Space is the console's text field while the panel is open: it neither
    # pauses the game nor closes the panel, and pixel detection then reports
    # "playing" forever.  The daemon must not send it there.
    sent = _input_stub(monkeypatch, tmp_path)
    assert gs.send_pause_key({"console_open": True}, 7) == "blocked_console"
    assert sent == []
    assert gs.send_pause_key({"console_open": False}, 7) == "sent"
    assert gs.send_pause_key({"console_open": None}, 7) == "sent"
    assert sent == [("space",), ("space",)]


def test_console_close_taps_once_only_when_the_panel_is_believed_open(
        monkeypatch, tmp_path):
    # Without this verb a daemon that left the console open can never pause the
    # game again, because the pause key is blocked while the panel is believed
    # open.  Toggling is only safe when the parity is known.
    assert gs.parse_command("console_close") == {"verb": "console_close"}
    sent = _input_stub(monkeypatch, tmp_path)
    state = _armed_state(tmp_path, "console_close")
    gs._handle_command({"verb": "console_close"}, 7, state)
    assert sent == [(0, 0x29), (0, 0x29)]
    assert state["console_open"] is False

    sent = _input_stub(monkeypatch, tmp_path)
    state = _armed_state(tmp_path, "console_close", console_open=None)
    gs._handle_command({"verb": "console_close"}, 7, state)
    assert sent == []
    assert "console_refused" in _logged_events(tmp_path)


def test_serve_loop_invalidates_the_belief_after_every_auto_click():
    # The auto window handlers click in the game area, which can close the
    # console panel.  The serve loop itself is not reachable from a host test,
    # so this fence pins the invalidation right next to each click it makes.
    # Two sites since the popup path landed: the choice click is inline, and
    # the dialog click moved into apply_popup_decision, so what serve shows is
    # the popup_dismissed verdict that the click produced.
    src = inspect.getsource(gs.serve).splitlines()
    clicks = [i for i, line in enumerate(src)
              if "click_row(hwnd" in line or 'note == "popup_dismissed"' in line]
    assert len(clicks) == 2, "serve no longer has both auto-click sites"
    for i in clicks:
        assert any('state["console_open"] = None' in line
                   for line in src[i:i + 4]), src[i]


def test_serve_forgets_the_popup_reading_while_no_dialog_is_up():
    # Same source-fence style as the two above: the wiring that makes a new
    # dialog a fresh OCR edge is in the loop, not in popup_tick.
    src = inspect.getsource(gs.serve)
    assert 'forget_popup_reading(state)' in src
    assert 'window != "dialog"' in src


# --- console panel OBSERVATION (calibrated live 2026-10-23, evidence §54.10) ---
# Two more states were captured by tapping the console key and re-reading
# pixels only.  Bright(>180) pixels inside the panel's text box:
#   closed: 0, 2, 0, 2      open: 2315, 2315, 2315
# The band in between must report "undecided"; §54.9's failure was a belief no
# observation could correct, so an ambiguous frame buys no keystroke.

def test_console_box_is_the_calibrated_text_area_of_the_panel():
    assert gs._console_box((0, 0, 2160, 1440)) == (120, 640, 400, 880)


def test_classify_console_reports_the_three_measured_outcomes():
    assert gs.classify_console(0) is False
    assert gs.classify_console(2) is False
    assert gs.classify_console(2315) is True
    assert gs.classify_console(300) is None


def test_a_decisive_observation_replaces_the_belief(monkeypatch, tmp_path):
    monkeypatch.setattr(gs, "LOG_PATH", str(tmp_path / "supervisor.jsonl"))
    state = {"console_open": False, "console_forced": False}
    assert gs.apply_console_observation(state, True, 2315) is True
    assert state["console_open"] is True
    assert state["console_px"] == 2315
    assert "console_observed" in _logged_events(tmp_path)


def test_an_undecided_frame_leaves_the_daemon_refusing(monkeypatch, tmp_path):
    monkeypatch.setattr(gs, "LOG_PATH", str(tmp_path / "supervisor.jsonl"))
    state = {"console_open": True, "console_forced": False}
    assert gs.apply_console_observation(state, None, 300) is None
    assert state["console_open"] is None


def test_console_sync_pins_the_belief_against_the_observation(monkeypatch, tmp_path):
    # The escape hatch has to survive the tick loop, or an observation that is
    # wrong for the current screen (calibrated on the main menu) is unfixable.
    monkeypatch.setattr(gs, "LOG_PATH", str(tmp_path / "supervisor.jsonl"))
    monkeypatch.setattr(gs, "STATUS_PATH", str(tmp_path / "status.json"))
    assert gs.parse_command("console_sync auto") == {"verb": "console_sync",
                                                    "mode": "auto"}
    _input_stub(monkeypatch, tmp_path)
    state = {"want": "paused", "console_open": None}
    gs._handle_command({"verb": "console_sync", "open": False}, 7, state)
    assert state["console_forced"] is True
    gs.apply_console_observation(state, True, 2315)
    assert state["console_open"] is False
    gs._handle_command({"verb": "console_sync", "mode": "auto"}, 7, state)
    assert state["console_forced"] is False
    gs.apply_console_observation(state, True, 2315)
    assert state["console_open"] is True


def test_serve_loop_observes_the_panel_before_it_plans_an_action():
    src = inspect.getsource(gs.serve)
    assert "apply_console_observation(" in src
    assert src.index("apply_console_observation(") < src.index("plan_step(")


# --- dialog close point (Task 5: pure close_point + observable dismiss) ---
# §59.2: the hardcoded offset landed on the wrong pixel on the one counter-
# sample we have (computed x=1843, true X glyph ~1343) and a "successful"
# dismiss with the window still up was undiagnosable.  The first version is
# pure fixed-offset only — no geometric rule is invented from one sample.

def test_close_point_uses_the_measured_inset_from_bbox():
    assert gs.close_point([1000, 466, 1939, 840]) == (1939 - 96, 466 + 51, "fixed_inset")


def test_close_point_refuses_a_point_outside_the_bbox():
    # 框太小时仍把「本来会点的点」交出去,但标 refused —— 日志要能还原那次尝试
    assert gs.close_point([1000, 466, 1010, 480]) == (1010 - 96, 466 + 51, "refused")


def test_dismiss_logs_the_point_and_whether_the_window_survived(monkeypatch, tmp_path):
    sent = _input_stub(monkeypatch, tmp_path)
    monkeypatch.setattr(gs, "read_window",
                        lambda hwnd: {"bright": 0.4, "gold": 10, "rows": [], "bbox": None})
    state = {"want": "paused", "console_open": None, "paused": "paused",
             "last_bbox": [1000, 466, 1939, 840]}
    gs._handle_command({"verb": "dismiss"}, 7, state)
    assert ("click", 1843, 517) in sent
    events = _logged_events_full(tmp_path)      # 同 _logged_events,但返回整个 dict 而非 event 名
    attempt = next(e for e in events if e["event"] == "dismiss_attempt")
    assert attempt["point"] == [1843, 517] and attempt["method"] == "fixed_inset"
    done = next(e for e in events if e["event"] == "dismiss")
    assert done["no_effect"] is False and done["bbox_after"] is None


def test_dismiss_reports_no_effect_when_the_window_is_still_there(monkeypatch, tmp_path):
    sent = _input_stub(monkeypatch, tmp_path)
    monkeypatch.setattr(gs, "read_window",
                        lambda hwnd: {"bright": 0.4, "gold": 10, "rows": [],
                                      "bbox": [1000, 466, 1939, 840]})
    gs._handle_command({"verb": "dismiss"}, 7,
                       {"want": "paused", "console_open": None, "paused": "paused",
                        "last_bbox": [1000, 466, 1939, 840]})
    assert any(e["event"] == "dismiss" and e["no_effect"] is True
               for e in _logged_events_full(tmp_path))


def test_dismiss_verb_accepts_an_inset_override():
    assert gs.parse_command("dismiss") == {"verb": "dismiss"}
    assert gs.parse_command("dismiss 120 40") == {"verb": "dismiss",
                                                  "inset": [120, 40]}
    assert gs.parse_command("dismiss 120") is None
    assert gs.parse_command("dismiss a b") is None


def test_refused_close_point_logs_the_attempt_and_never_clicks(monkeypatch, tmp_path):
    # refused must still record the would-be point — that is the whole
    # diagnostic value — but must not click and must not write a dismiss event.
    sent = _input_stub(monkeypatch, tmp_path)
    state = {"want": "paused", "console_open": True, "paused": "paused",
             "last_bbox": [1000, 466, 1010, 480]}
    with pytest.raises(OSError):
        gs._handle_command({"verb": "dismiss"}, 7, state)
    assert not any(s[0] == "click" for s in sent)
    events = _logged_events_full(tmp_path)
    attempt = next(e for e in events if e["event"] == "dismiss_attempt")
    assert attempt["method"] == "refused" and attempt["point"] == [914, 517]
    assert not any(e["event"] == "dismiss" for e in events)


def test_parsed_dismiss_inset_flows_through_to_the_click(monkeypatch, tmp_path):
    # End-to-end for the override: parse_command's inset must reach the actual
    # click.  Each half was covered separately (the lexeme, the default wiring);
    # without this the connection between them is untested.
    sent = _input_stub(monkeypatch, tmp_path)
    state = {"want": "paused", "console_open": None, "paused": "paused",
             "last_bbox": [1000, 466, 1939, 840]}
    gs._handle_command(gs.parse_command("dismiss 120 40"), 7, state)
    assert ("click", 1939 - 120, 466 + 40) in sent
    assert ("click", 1843, 517) not in sent      # the default inset was not used
    attempt = next(e for e in _logged_events_full(tmp_path)
                   if e["event"] == "dismiss_attempt")
    assert attempt["inset"] == [120, 40] and attempt["method"] == "fixed_inset"


def test_serve_loop_surfaces_the_refused_dismiss_as_its_own_note():
    # Refused geometry must stay distinguishable from generic click failures
    # in the serve loop; same source-fence style as the invalidation fences.
    assert "dismiss_refused" in inspect.getsource(gs.apply_popup_decision)


def test_popup_tick_runs_ocr_only_when_the_panel_shape_changes():
    calls = []
    def fake_ocr(path):
        calls.append(path)
        return ["news flash"], "ok", 12.0
    state = {"popup_id": None, "popup_attempts": 0, "popup_same_hits": 0,
             "popup_last_ocr_ts": 0.0}
    for tick in range(3):                        # now 固定:时钟要可注入才谈得上测退避
        gs.popup_tick(0, "C:/temp/live.png", [0, 0, 900, 400], 0, state,
                      fake_ocr, now=1000.0 + tick)
    assert len(calls) == 1                       # 几何没变且上次 ok ⇒ 不再问 OCR
    assert state["popup_ocr_status"] == "ok"


def test_a_failed_ocr_retries_on_the_backoff_interval_not_every_tick():
    calls = []
    gs.popup_tick(0, "p.png", [0, 0, 900, 400], 0,
                  st := {"popup_id": None, "popup_attempts": 0,
                         "popup_same_hits": 0, "popup_last_ocr_ts": 0.0},
                  lambda p: calls.append(p) or ([], "error", 4.0), now=100.0)
    gs.popup_tick(0, "p.png", [0, 0, 900, 400], 0, st,
                  lambda p: calls.append(p) or ([], "error", 4.0), now=103.0)
    gs.popup_tick(0, "p.png", [0, 0, 900, 400], 0, st,
                  lambda p: calls.append(p) or ([], "error", 4.0), now=161.0)
    assert len(calls) == 2                       # 100 首问、103 太近不问、161 过 60 s 重试


def test_popup_tick_stops_asking_ocr_once_the_session_budget_is_spent():
    # The per-read cost is derived from the budget rather than written down:
    # the budget is a measured quantity (spec §14.4 re-derived it to 2 000 ms
    # on 2026-10-27), and a test that hard-codes the old 24 s arithmetic would
    # have to be rewritten every time somebody re-measures.  One read that
    # costs the whole budget spends it.
    cost = gs.POPUP_OCR_BUDGET_MS
    calls = []
    st = {"popup_id": None, "popup_attempts": 0, "popup_same_hits": 0,
          "popup_last_ocr_ts": 0.0, "popup_ocr_ms": 0.0}
    boxes = [[0, 0, 900, 400], [0, 0, 900, 500], [0, 0, 900, 600], [0, 0, 900, 700]]
    for tick, box in enumerate(boxes):           # 四个几何互不相同的窗 = 四次边沿触发
        got = gs.popup_tick(0, "p.png", box, 0, st,
                            lambda p: calls.append(p) or (["x"], "ok", cost),
                            now=1_000.0 + tick)
    assert len(calls) == 1                       # 第一次就花光,其后一律不再问
    assert st["popup_ocr_ms"] == cost
    assert got["ocr_status"] == "budget_spent" and got["ms"] == 0.0
    assert got["ocr_ms_total"] == cost
    assert got["popup_id"].startswith("geom:")   # 没文本就只能用几何 id,而几何 id 不在名单
    assert got["action"] == "hold"


def test_console_belief_true_holds_even_an_allowlisted_id(monkeypatch):
    monkeypatch.setattr(gs, "load_allowlist",
                        lambda path: ({"text:aaa": "dismiss"}, "ok"))
    state = {"popup_id": None, "popup_attempts": 0, "popup_same_hits": 0,
             "popup_last_ocr_ts": 0.0, "console_open": True}
    got = gs.popup_tick(0, "p.png", [0, 0, 900, 400], 0, state,
                        lambda p: (["Continue?"], "ok", 9.0), now=1000.0)
    assert got["popup_id"].startswith("text:")
    assert (got["action"], got["reason"]) == ("hold", "console_panel")


def test_unknown_fingerprint_holds_and_comes_back_geometry_only():
    got = gs.popup_tick(0, "p.png", [0, 0, 700, 300], 0,
                        {"popup_id": None, "popup_attempts": 0,
                         "popup_same_hits": 0, "popup_last_ocr_ts": 0.0,
                         "console_open": False},
                        lambda p: ([], "model_missing", 3.0), now=1000.0)
    assert (got["action"], got["reason"]) == ("hold", "unclassified_hold")
    assert got["source"] == "geometry" and got["ocr_status"] == "model_missing"


def test_hold_path_never_touches_the_clicker():
    clicked, saved, logged = [], [], []
    note = gs.apply_popup_decision(
        0, [0, 0, 700, 300],
        {"popup_id": "geom:700x300:r0", "action": "hold",
         "reason": "unclassified_hold", "source": "geometry",
         "ocr_status": "model_missing", "ms": 3.0, "attempts": 0,
         "same_hits": 1, "texts_n": 0},
        {"popup_id": None, "popup_attempts": 0, "popup_same_hits": 0},
        clicker=lambda h, b: clicked.append(b),
        saver=lambda h, b, png, pid: saved.append(pid) or "p.png",
        logger=lambda rec: logged.append(rec))
    assert clicked == [] and saved == ["geom:700x300:r0"]
    assert note == "popup_hold_unclassified"
    assert [r["event"] for r in logged] == ["popup_seen", "popup_evidence",
                                            "popup_decision"]


def test_dismiss_path_clicks_once_and_burns_one_attempt():
    clicked = []
    state = {"popup_id": "text:aaa", "popup_attempts": 0, "popup_same_hits": 1}
    note = gs.apply_popup_decision(
        0, [0, 0, 900, 400],
        {"popup_id": "text:aaa", "action": "dismiss", "reason": "allowlisted",
         "source": "text", "ocr_status": "ok", "ms": 9.0, "attempts": 0,
         "same_hits": 1, "texts_n": 1},
        state, clicker=lambda h, b: clicked.append(b),
        saver=lambda h, b, png, pid: "p.png", logger=lambda rec: None)
    assert clicked and state["popup_attempts"] == 1
    assert note == "popup_dismissed"


def test_a_refused_click_still_burns_the_budget():
    def refuse(h, b):
        raise gs.CloseRefused("close point outside dialog")
    state = {"popup_id": "text:aaa", "popup_attempts": 0, "popup_same_hits": 1}
    note = gs.apply_popup_decision(
        0, [0, 0, 900, 400],
        {"popup_id": "text:aaa", "action": "dismiss", "reason": "allowlisted",
            "source": "text", "ocr_status": "ok", "ms": 9.0, "attempts": 0,
            "same_hits": 1, "texts_n": 1},
        state, clicker=refuse, saver=lambda h, b, png, pid: "p.png",
        logger=lambda rec: None)
    assert note == "dismiss_refused" and state["popup_attempts"] == 1


def test_three_refusals_burn_the_same_budget_as_three_clicks():
    state = {"popup_id": "text:aaa", "popup_attempts": 2, "popup_same_hits": 3,
             "popup_last_ocr_ts": 0.0}
    gs.count_attempt(state, "text:aaa")
    assert gs.decide_action(popup_id="text:aaa", allow={"text:aaa": "dismiss"},
                            attempts=state["popup_attempts"],
                            same_id_hits=state["popup_same_hits"],
                            console_open=False, has_bbox=True)[1] == \
          "attempt_budget_spent"


def test_prune_evidence_keeps_the_newest_n(tmp_path):
    for i in range(5):
        (tmp_path / f"popup_{i}.png").write_bytes(b"x")
    removed = gs.prune_evidence(str(tmp_path), keep=3)
    assert len(removed) == 2 and (tmp_path / "popup_4.png").exists()


def test_no_ocr_flag_leaves_the_whole_identity_path_geometry_only():
    state = {"popup_id": None, "popup_attempts": 0, "popup_same_hits": 0,
             "popup_last_ocr_ts": 0.0}
    got = gs.popup_tick(0, "p.png", [0, 0, 900, 400], 0, state,
                        lambda p: ([], "disabled", 0.0), ocr_enabled=False)
    assert got["source"] == "geometry" and got["ocr_status"] == "disabled"


def test_evidence_filename_carries_no_colon_ntfs_reserves(tmp_path, monkeypatch):
    monkeypatch.setattr(gs, "POPUP_DIR", str(tmp_path))
    asked = []
    gs.apply_popup_decision(
        0, [0, 0, 700, 300],
        {"popup_id": "geom:700x300:r0", "action": "hold",
         "reason": "unclassified_hold", "source": "geometry",
         "ocr_status": "model_missing", "ms": 3.0, "attempts": 0,
         "same_hits": 1, "texts_n": 0},
        {"popup_id": None, "popup_attempts": 0, "popup_same_hits": 0},
        clicker=lambda h, b: None,
        saver=lambda h, b, png, pid: asked.append(png),
        logger=lambda rec: None)
    assert asked == [os.path.join(str(tmp_path), "geom_700x300_r0.png")]


def test_a_click_that_never_happened_does_not_burn_the_dismiss_budget():
    def focus_refused(h, b):
        raise OSError("focus refused before close click")
    state = {"popup_id": "text:aaa", "popup_attempts": 0, "popup_same_hits": 1}
    note = gs.apply_popup_decision(
        0, [0, 0, 900, 400],
        {"popup_id": "text:aaa", "action": "dismiss", "reason": "allowlisted",
         "source": "text", "ocr_status": "ok", "ms": 9.0, "attempts": 0,
         "same_hits": 1, "texts_n": 1},
        state, clicker=focus_refused, saver=lambda h, b, png, pid: "p.png",
        logger=lambda rec: None)
    assert note.startswith("dialog_click_failed")
    assert state["popup_attempts"] == 0


def test_forgetting_the_reading_makes_the_next_dialog_an_edge_again():
    state = {"popup_id": None, "popup_attempts": 0, "popup_same_hits": 0,
             "popup_last_ocr_ts": 0.0, "popup_ocr_ms": 0.0}
    calls = []
    box = [0, 0, 900, 400]

    def ocr(path):
        calls.append(path)
        return (["first dialog"] if len(calls) == 1 else ["second dialog"],
                "ok", 10.0)
    gs.popup_tick(0, "p.png", box, 0, state, ocr, now=1_000.0)
    gs.popup_tick(0, "p.png", box, 0, state, ocr, now=1_001.0)
    assert len(calls) == 1                       # 同一扇窗:几何没变就不再问
    first_id = state["popup_id"]
    gs.forget_popup_reading(state)
    got = gs.popup_tick(0, "p.png", box, 0, state, ocr, now=1_002.0)
    assert len(calls) == 2                       # 换了窗、几何一模一样,也得重看
    assert got["source"] == "text" and got["popup_id"] != first_id


def test_a_second_dialog_of_the_same_shape_is_not_dismissed_as_the_first(monkeypatch):
    # The failure this pins: inheriting an allowlisted identity across two
    # different dialogs that bucket to the same 10 px geometry, and clicking a
    # window the allowlist never named.
    allow = {}
    monkeypatch.setattr(gs, "load_allowlist", lambda path: (dict(allow), "ok"))
    state = {"popup_id": None, "popup_attempts": 0, "popup_same_hits": 0,
             "popup_last_ocr_ts": 0.0, "popup_ocr_ms": 0.0,
             "console_open": False}
    box = [0, 0, 900, 400]
    lines = iter([["proceed?"], ["something else"]])

    def ocr(path):
        return next(lines), "ok", 10.0
    first = gs.popup_tick(0, "p.png", box, 0, state, ocr, now=1_000.0)
    allow[first["popup_id"]] = "dismiss"
    again = gs.popup_tick(0, "p.png", box, 0, state, ocr, now=1_001.0)
    assert again["action"] == "dismiss"           # 同一扇窗:读数就用
    gs.forget_popup_reading(state)                # 窗下了,读数作废
    fresh = gs.popup_tick(0, "p.png", box, 0, state, ocr, now=1_002.0)
    assert fresh["popup_id"] != first["popup_id"]
    assert fresh["action"] == "hold"


def test_a_dialog_without_geometry_holds_and_records_no_evidence_path():
    # Ruling R11: no geometry means nothing to crop, so the saver must not be
    # called -- but the decision still has to leave an evidence event behind.
    state = {"popup_id": None, "popup_attempts": 0, "popup_same_hits": 0,
             "popup_last_ocr_ts": 0.0}
    clicked, saved, logged = [], [], []
    got = gs.popup_tick(0, "p.png", None, 0, state,
                        lambda p: (["some text"], "ok", 5.0), now=1_000.0)
    assert (got["action"], got["reason"]) == ("hold", "no_bbox")
    note = gs.apply_popup_decision(
        0, None, got, state, clicker=lambda h, b: clicked.append(b),
        saver=lambda h, b, png, pid: saved.append(pid),
        logger=lambda rec: logged.append(rec))
    assert note == "popup_hold_no_bbox"
    assert clicked == [] and saved == []
    assert [r["event"] for r in logged] == ["popup_seen", "popup_evidence",
                                            "popup_decision"]
    assert logged[1]["path"] is None


def test_popup_seen_gains_three_geometry_keys_and_nothing_else():
    # 「窗 vs 切片」的证人:每条 popup_seen 自带 bbox、窗 rect 与候选数。
    # 只加事件字段,不动 reason/note —— 词汇表围栏(Review Focus 3)必须原样绿。
    state = {"popup_id": None, "popup_attempts": 0, "popup_same_hits": 0,
             "popup_last_ocr_ts": 0.0}
    clicked, saved, logged = [], [], []
    box = [10, 20, 910, 420]
    got = gs.popup_tick(0, "p.png", box, 0, state,
                        lambda p: (["some text"], "ok", 5.0), now=1_000.0)
    gs.apply_popup_decision(
        0, box, got, state, clicker=lambda h, b: clicked.append(b),
        saver=lambda h, b, png, pid: saved.append(pid),
        logger=lambda rec: logged.append(rec))
    seen = logged[0]
    assert set(seen) == {"event"} | set(got) | {
        "bbox", "window_rect", "candidates_n"}
    assert seen["bbox"] == list(box)
    # state 没写 window_rect / window_candidates_n ⇒ 离线默认 None。
    assert seen["window_rect"] is None and seen["candidates_n"] is None
    state["window_rect"] = [0, 0, 1920, 1080]
    state["window_candidates_n"] = 3
    gs.apply_popup_decision(
        0, box, got, state, clicker=lambda h, b: clicked.append(b),
        saver=lambda h, b, png, pid: saved.append(pid),
        logger=lambda rec: logged.append(rec))
    seen = logged[3]
    assert seen["window_rect"] == [0, 0, 1920, 1080]
    assert seen["candidates_n"] == 3


def test_popup_seen_records_null_bbox_when_no_geometry():
    state = {"popup_id": None, "popup_attempts": 0, "popup_same_hits": 0,
             "popup_last_ocr_ts": 0.0}
    logged = []
    got = gs.popup_tick(0, "p.png", None, 0, state,
                        lambda p: (["some text"], "ok", 5.0), now=1_000.0)
    gs.apply_popup_decision(
        0, None, got, state, clicker=lambda h, b: None,
        saver=lambda h, b, png, pid: None,
        logger=lambda rec: logged.append(rec))
    assert logged[0]["bbox"] is None


def test_every_reason_the_guard_can_return_has_a_supervisor_note():
    # POPUP_NOTES[reason] 在副作用层查表且没有兜底:新增一个 reason 忘了补
    # note,会在 serve 里 KeyError 并把守护进程打死(心跳一断,后面全被判成
    # 「守护坏了」)。所以 reason 面由这张矩阵钉住,而不是靠人记得。
    reasons = set()
    for console in (True, False, None):
        for bbox in (None, [0, 0, 900, 400]):
            for hits in (1, 99):
                for attempts in (0, 99):
                    for allow in ({}, {"text:aaa": "dismiss"}):
                        reasons.add(gs.decide_action(
                            popup_id="text:aaa", allow=allow, attempts=attempts,
                            same_id_hits=hits, console_open=console,
                            has_bbox=bbox is not None)[1])
    assert reasons <= set(gs.POPUP_NOTES)
    # 反向也要成立:HOLD_REASONS 是那份词汇表的声明处,漏一个 reason 就等于
    # 写下一份会骗下一个读它的人(今天它没有读者,但它长得像规范)。
    assert reasons - {"allowlisted"} == set(gs_popup_guard.HOLD_REASONS)


def test_a_dismiss_listed_geometry_id_in_the_file_still_holds(tmp_path):
    # Review Focus 1 的前提「几何 id 天生不在名单里」现在由 parse 层守:操作者
    # 照旧模板抄一行 geom,也换不到一次点击。
    p = tmp_path / "allow.json"
    p.write_text(json.dumps({"allow": [
        {"popup_id": "geom:900x400:r0", "action": "dismiss"}]}), encoding="utf-8")
    state = {"popup_id": None, "popup_attempts": 0, "popup_same_hits": 0,
             "popup_last_ocr_ts": 0.0, "console_open": False}
    got = gs.popup_tick(0, "p.png", [0, 0, 900, 400], 0, state,
                        lambda path: ([], "model_missing", 3.0), now=1_000.0,
                        allow_path=str(p))
    assert got["popup_id"].startswith("geom:") and got["allow_status"] == "ok"
    assert (got["action"], got["reason"]) == ("hold", "unclassified_hold")


def test_outliner_only_rows_are_not_a_window():
    rows = [{"x0": 1849, "x1": 1943, "y0": y, "y1": y + 6} for y in (216, 390, 480, 570)]
    assert gs.classify_window(rows, None, 2846, 2160, 1440) != "dialog"
    assert gs.classify_window(rows, None, 2846, 2160, 1440) != "choice"


def test_first_contact_window_is_a_dialog():
    rows = [{"x0": 1090, "x1": 1121, "y0": 868, "y1": 897},
            {"x0": 1284, "x1": 1452, "y0": 814, "y1": 816}]
    assert gs.classify_window(rows, None, 2846, 2160, 1440) == "dialog"


def test_click_without_lease_logs_and_does_not_raise(monkeypatch):
    logged = []
    monkeypatch.setattr(gs, "acquire_or_refuse", lambda *a, **k: None)
    monkeypatch.setattr(gs, "window_rect", lambda hwnd: (0, 0, 2160, 1440))
    monkeypatch.setattr(gs, "_log", lambda rec: logged.append(rec))

    def no_click(*a, **k):
        raise AssertionError("a refused click must not reach the clicker")

    monkeypatch.setattr(gs, "_launch", no_click)
    state = {"probe": {"pause": {"state": "paused"},
                       "console": {"state": "closed"},
                       "window": {"kind": "none", "bbox": None}}}
    quit_now, one_shot = gs._handle_command(
        {"verb": "click", "x": 1105, "y": 846}, 67634, state)
    assert (quit_now, one_shot) == (False, None)
    refused = [r for r in logged if r.get("event") == "click_refused"]
    assert len(refused) == 1
    rec = refused[0]
    assert rec["action"] == "click_option" and rec["reason"] == "lease_denied"
    assert (rec["pause"], rec["console"], rec["window"]) == ("paused", "closed", "none")
    assert state["cmd_refused"] is True


def test_click_refused_makes_the_cli_exit_2():
    rec = {"last_cmd": "click 1105 846", "cmd_refused": True,
           "state": "paused", "note": "ok", "pid": 10680, "hwnd": 67634,
           "want": "playing", "policy": "first", "handled": 14,
           "speed_sha": [0, 0],
           "window": {"kind": "none", "bbox": None}}
    assert gs.command_refused(rec, "click 1105 846") is True
    assert gs.command_refused(rec, "click 1 2") is False
    assert gs.command_refused({"last_cmd": "click 1105 846"}) is False
    assert gs.EXIT_REFUSED == 2
    line = gs._status_line(rec)
    assert "window=none" in line and "bbox=" in line


def test_reference_classifier_turns_the_outliner_rule_on():
    outliner = [{"x0": 1849, "x1": 1943, "y0": y, "y1": y + 6}
                for y in (216, 390, 480, 570)]
    central = [{"x0": 1090, "x1": 1121, "y0": 868, "y1": 897},
               {"x0": 1284, "x1": 1452, "y0": 814, "y1": 816}]
    # The daemon normalizes to REF_W/REF_H; the 3-arg call would keep the old
    # rule and read this window as none (issue #31's silent drop).
    assert gs.classify_window_at_reference(outliner, None, 2846) == "none"
    assert gs.classify_window_at_reference(central, None, 2846) == "dialog"
