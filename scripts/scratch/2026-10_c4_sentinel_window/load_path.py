"""Load-path click ladder: the decision core for reaching the save list.

WHAT THIS IS FOR.  Task 7 of this window has to get a running game from the main
menu to the load screen by clicking, and every click must be justified by a
screenshot a human read.  This file is where that justification lives: ``STEPS``
is the ladder, and ``click_plan`` is the only question the driver may ask it —
"what may I click next, given what has been confirmed?"  Coordinates are never
invented here; each row is appended by the person who just looked at the shot
(`just game shot` / `just game status` / `just game click x y`), and the row's
``expect`` is what that shot had to show.

THE LADDER RULE.  A click is issued for step ``k`` only when the ``k`` steps
before it are confirmed by **both** authorities: the reader's
``confirmed_steps`` labels name ``STEPS[:k]`` in order, and each of those steps
carries ``confirmed=True`` in this file.  Anything else — a label that does not
match the row, a row still unflagged, a ladder that runs out — is
``STOP_UNCONFIRMED``.  A red popup window on screen is ``STOP_POPUP`` and is
checked first: with the popup allow-list empty (docs/roadmap.md :40) there is no
coordinate that a popup makes safe to click.

ZERO SHOTS.  This module is a pure decision core: no process, no screenshot, no
Windows API, no supervisor call.  ``test_load_path.py`` covers it offline.
"""

STOP_UNCONFIRMED = "STOP_UNCONFIRMED"
STOP_POPUP = "STOP_POPUP"

#: The click ladder, appended by whoever read the screenshot that authorises it.
#: Each row: ``x``, ``y``, ``expect`` (what the shot after the click must show),
#: ``confirmed`` (True once a human read that shot and said so).
#:
#: Empty at write time — Task 7 fills it in the live window and re-runs the test.
STEPS: list[dict] = []


def click_plan(state, steps=None):
    """Next action for the ladder: ``("click", x, y, expect)`` or a STOP.

    ``state`` is ``{"confirmed_steps": [...], "last_shot": basename}`` with an
    optional ``"red_window": True`` from the popup-identity check.  ``steps``
    defaults to this module's ``STEPS``; tests pass their own ladder so Task 7's
    appends cannot redden the suite (see the header of ``test_load_path.py``).
    """
    ladder = STEPS if steps is None else steps
    if state.get("red_window"):
        return STOP_POPUP
    if not ladder:
        return STOP_UNCONFIRMED
    confirmed_labels = list(state.get("confirmed_steps", []))
    if len(confirmed_labels) > len(ladder):
        return STOP_UNCONFIRMED
    for index, label in enumerate(confirmed_labels):
        row = ladder[index]
        if row["expect"] != label or not row["confirmed"]:
            return STOP_UNCONFIRMED
    if len(confirmed_labels) >= len(ladder):
        return STOP_UNCONFIRMED
    row = ladder[len(confirmed_labels)]
    return ("click", row["x"], row["y"], row["expect"])
