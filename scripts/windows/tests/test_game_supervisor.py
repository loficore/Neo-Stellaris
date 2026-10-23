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
