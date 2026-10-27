"""Offline fence for the load-path click ladder (Task 5; zero shots, no process).

Why the tests hand ``click_plan`` their own ladder instead of reading module
``STEPS``: Task 7 appends real, human-confirmed coordinates into
``load_path.py`` and re-runs this file.  A test that pinned ``STEPS == []``
would turn that bookkeeping into a red suite, and a red suite in a live window
reads like an instrument failure.  ``STEPS`` therefore enters only through the
default argument, and one test below checks the default is empty *today*.

Host-only: an import and four function calls, no ``just game``, no screenshot,
no Windows API.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import load_path  # noqa: E402
from load_path import STOP_POPUP, STOP_UNCONFIRMED, click_plan  # noqa: E402

A = {"x": 100, "y": 200, "expect": "main_menu", "confirmed": False}
B = {"x": 300, "y": 400, "expect": "load_list", "confirmed": False}


def _confirmed(step, label=None):
    out = dict(step)
    out["confirmed"] = True
    if label is not None:
        out["expect"] = label
    return out


def test_empty_sequence_is_stop():
    """No ladder means no coordinate anybody confirmed — so no click."""
    assert click_plan({"confirmed_steps": [], "last_shot": "-"}, steps=[]) \
        == STOP_UNCONFIRMED


def test_module_sequence_starts_empty():
    """Today's authority: the ladder in the file is still empty (Task 5 shape).

    Task 7 fills it; this is the one assertion expected to change on purpose,
    which is why it reads ``load_path.STEPS`` directly and says so here.
    """
    assert load_path.STEPS == []


def test_first_click_needs_no_previous_confirmation():
    """The head of a confirmed ladder is issuable: nothing precedes it."""
    action = click_plan({"confirmed_steps": [], "last_shot": "shot1.png"},
                        steps=[_confirmed(A)])
    assert action == ("click", 100, 200, "main_menu")


def test_next_click_requires_confirmation_of_previous():
    """Review Focus 4: an unconfirmed previous step must not be continued past.

    Both shapes of "the ladder and the shot-reader disagree" stop: the previous
    step is not marked confirmed in the file, and a confirmation that names a
    label the ladder does not have at that position.
    """
    # ladder: A landed as expected, B is next — but B was written while A's
    # expect had not been confirmed, so its coordinates are unsanctioned.
    assert click_plan({"confirmed_steps": ["main_menu"], "last_shot": "shot2.png"},
                      steps=[A, B]) == STOP_UNCONFIRMED
    # the file says A is confirmed, the reader never confirmed that label
    assert click_plan({"confirmed_steps": ["wrong_label"], "last_shot": "shot2.png"},
                      steps=[_confirmed(A), B]) == STOP_UNCONFIRMED
    # two authorities, one answer: the reader confirms "load_list" while the
    # ladder's own `confirmed` flag for that step is still False
    assert click_plan({"confirmed_steps": ["main_menu", "load_list"],
                       "last_shot": "shot3.png"},
                      steps=[_confirmed(A), B, {"x": 5, "y": 6,
                                                "expect": "loaded",
                                                "confirmed": False}]) == \
        STOP_UNCONFIRMED


def test_confirmed_prefix_advances_one_step():
    """The ladder advances exactly as far as the confirmations, not further."""
    steps = [_confirmed(A), _confirmed(B, "load_list"), {"x": 5, "y": 6,
              "expect": "selected_save", "confirmed": False}]
    assert click_plan({"confirmed_steps": ["main_menu"], "last_shot": "s.png"},
                      steps=steps) == ("click", 300, 400, "load_list")
    assert click_plan({"confirmed_steps": ["main_menu", "load_list"],
                       "last_shot": "s.png"}, steps=steps) == \
        ("click", 5, 6, "selected_save")


def test_exhausted_ladder_is_stop():
    """Every step confirmed ⇒ there is no further click to authorize."""
    steps = [_confirmed(A), _confirmed(B, "load_list")]
    assert click_plan({"confirmed_steps": ["main_menu", "load_list"],
                       "last_shot": "s.png"}, steps=steps) == STOP_UNCONFIRMED


def test_popup_flag_stops_the_ladder():
    """roadmap :40 — the popup allow-list is empty, so a red window is a stop.

    The flag is checked before the ladder: a popup on screen makes every
    coordinate below it unsafe to click, confirmed or not.
    """
    steps = [_confirmed(A), B]
    assert click_plan({"confirmed_steps": [], "last_shot": "s.png",
                       "red_window": True}, steps=steps) == STOP_POPUP
    # it also outranks the empty-ladder and exhausted-ladder answers
    assert click_plan({"confirmed_steps": [], "last_shot": "-",
                       "red_window": True}, steps=[]) == STOP_POPUP
