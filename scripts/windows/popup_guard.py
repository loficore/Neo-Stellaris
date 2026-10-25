"""Popup guard pure core: the dismiss/hold decision and the circuit-breaker budget.

Orientation decided 2026-10-25: 分类放行 ⇒ 名单外一律不动手 -- only ids the
allowlist explicitly maps to "dismiss" are ever clicked; everything else is
held. ``console_panel`` ranks first in the priority chain because of trap 10's
two-way misreport: a bright panel can be the console, and clicking X on it
means clicking into the console -- so no allowlist entry can override it.

This file is the pure core (纯核). It must NOT import PIL/numpy/ctypes:
`just host-tests` runs it on Linux with stdlib only.
"""

from __future__ import annotations

MAX_DISMISS_ATTEMPTS = 3
# Same family as the option-box `same_hits > 3` but counted independently:
# this one pins "the same popup identity keeps reappearing", not
# "the same golden rows".
SAME_ID_STUCK_LIMIT = 5

HOLD_REASONS = ("unclassified_hold", "attempt_budget_spent", "id_stuck",
                "console_panel", "no_bbox")
POPUP_ACTIONS = ("dismiss", "hold")


def decide_action(*, popup_id: str, allow: dict[str, str] | None,
                  attempts: int, same_id_hits: int,
                  console_open: bool | None,
                  has_bbox: bool) -> tuple[str, str]:
    """Pure priority chain, highest first, mutually exclusive.

    The first two ranks sit before the allowlist on purpose: a bright panel
    that is the console, or a popup we cannot even locate, must never be
    clicked no matter what the allowlist says.
    """
    if console_open is True:
        return ("hold", "console_panel")
    if not has_bbox:
        return ("hold", "no_bbox")
    if same_id_hits > SAME_ID_STUCK_LIMIT:
        return ("hold", "id_stuck")
    if attempts >= MAX_DISMISS_ATTEMPTS:
        return ("hold", "attempt_budget_spent")
    if (allow or {}).get(popup_id) == "dismiss":
        return ("dismiss", "allowlisted")
    return ("hold", "unclassified_hold")


def bump(state: dict, popup_id: str) -> tuple[int, int]:
    """Track popup identity across ticks, in place.

    A new id resets the real-click budget but starts a fresh stuck watch at 1;
    the same id keeps attempts and increments same_hits. Returns
    ``(attempts, same_hits)``.
    """
    if state.get("popup_id") != popup_id:
        state["popup_id"] = popup_id
        state["popup_attempts"] = 0
        state["popup_same_hits"] = 1
    else:
        state["popup_same_hits"] = state.get("popup_same_hits", 0) + 1
    return (state["popup_attempts"], state["popup_same_hits"])


def count_attempt(state: dict, popup_id: str) -> int:
    """Burn one real dismiss attempt: call only after X was actually clicked.

    If the id changed since the last click, the budget zeroes first. Returns
    the new attempts value.
    """
    if state.get("popup_id") != popup_id:
        state["popup_id"] = popup_id
        state["popup_attempts"] = 1
    else:
        state["popup_attempts"] = state.get("popup_attempts", 0) + 1
    return state["popup_attempts"]
