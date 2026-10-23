"""Host-side tests for the game supervisor's pure core.

Numbers in these tests are the spike measurements of 2026-10-23 (see the
plan's Spec section); they are the contract the Windows edge feeds in.
No Windows API, no PIL, no numpy.
"""

import random

import game_supervisor as gs


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


def test_console_command_does_not_tap_a_console_it_left_open(monkeypatch):
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


def test_console_sync_lets_an_operator_declare_the_console_state():
    state = {"want": "paused", "console_open": False}
    gs._handle_command({"verb": "console_sync", "open": True}, 7, state)
    assert state["console_open"] is True
    assert gs.parse_command("console_sync closed") == {"verb": "console_sync",
                                                       "open": False}
    assert gs.parse_command("console_sync sideways") is None
