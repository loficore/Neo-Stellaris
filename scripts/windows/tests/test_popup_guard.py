"""Host-side tests for the popup guard pure core.

The brief's six cases: console panel outranking an allowlisted id, unknown
ids held not clicked, the attempt budget, an absent allowlist file,
bump resetting attempts on a new id, and same-id stuck-watch accumulation.
No Windows API, no PIL, no numpy.
"""

from popup_guard import MAX_DISMISS_ATTEMPTS, bump, decide_action
from popup_identity import load_allowlist


def test_console_panel_beats_even_an_allowlisted_id():
    assert decide_action(popup_id="text:aaa", allow={"text:aaa": "dismiss"},
                         attempts=0, same_id_hits=1, console_open=True,
                         has_bbox=True) == ("hold", "console_panel")

def test_unknown_id_is_held_not_clicked():
    assert decide_action(popup_id="geom:900x400:r0", allow={}, attempts=0,
                         same_id_hits=1, console_open=False,
                         has_bbox=True) == ("hold", "unclassified_hold")

def test_attempt_budget_spent_after_three_real_clicks():
    assert decide_action(popup_id="text:aaa", allow={"text:aaa": "dismiss"},
                         attempts=MAX_DISMISS_ATTEMPTS, same_id_hits=1,
                         console_open=False, has_bbox=True) == \
           ("hold", "attempt_budget_spent")

def test_a_missing_allowlist_file_holds_everything(tmp_path):
    allow, status = load_allowlist(str(tmp_path / "gone.json"))
    assert status == "absent"
    assert decide_action(popup_id="text:aaa", allow=allow, attempts=0,
                         same_id_hits=1, console_open=False,
                         has_bbox=True) == ("hold", "unclassified_hold")

def test_a_new_id_resets_the_attempt_budget_but_keeps_stuck_watch():
    state = {"popup_id": "text:aaa", "popup_attempts": 3, "popup_same_hits": 4}
    assert bump(state, "text:bbb") == (0, 1)
    assert state["popup_attempts"] == 0 and state["popup_id"] == "text:bbb"

def test_the_same_id_across_ticks_toward_the_stuck_limit():
    state = {"popup_id": "text:aaa", "popup_attempts": 0, "popup_same_hits": 5}
    assert bump(state, "text:aaa") == (0, 6)
    assert decide_action(popup_id="text:aaa", allow={"text:aaa": "dismiss"},
                         attempts=state["popup_attempts"],
                         same_id_hits=state["popup_same_hits"],
                         console_open=False, has_bbox=True) == \
           ("hold", "id_stuck")
