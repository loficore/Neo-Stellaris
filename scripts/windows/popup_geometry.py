"""Pure screen/crop geometry for the unattended popup line.

Zero OS dependencies: no numpy, no PIL, no ctypes. ``panel_bbox`` consumes
per-row and per-column bright-pixel counts (the ``luma > 120`` threshold is
deliberately left with the caller — it is a per-pixel predicate with no
pure form) and returns the envelope of the indices that clear the density
gates. That envelope is NOT a connected component: two bright faces
separated by a dark seam yield one bbox spanning both, which is exactly
the "window vs slice" ambiguity the next named batch has to adjudicate.
"""

from __future__ import annotations

# Mirror of game_supervisor.CLOSE_INSET; the close_point tracking test in
# tests/test_popup_geometry.py pins the two against each other.
CLOSE_INSET = (96, 51)

# Where an event window's options sit, as a fraction of the window width.
# Measured on the 2026-10-29 first-contact window (2160x1440): the option
# circle/text rows end at x=1121/1452 (0.52/0.67), while the galaxy map's
# outliner rows start at x>=1520 (0.70).  The 0.70 right edge is the whole
# rule: an outliner row is not an option, no matter how wide it is.
CENTRAL_X1 = (0.30, 0.70)
OUTLINER_X0 = 0.70


def is_outliner_row(row, w: int) -> bool:
    """``True`` for a row that starts in the right-edge outliner band."""
    return row.get("x0", 0) >= OUTLINER_X0 * w


def row_kind(rows, w: int, h: int) -> str:
    """``"outliner" | "central" | "empty"`` by horizontal band, not by width.

    ``w``/``h`` are the window size (rows are absolute screen coordinates;
    only the x fractions are used).  ``central`` needs at least two rows whose
    right edge lands inside ``[0.30w, 0.70w]`` -- the first-contact window's
    option circle and option text both do.  ``h`` is accepted for callers
    that also scale vertically; the band itself is horizontal.
    """
    if not rows:
        return "empty"
    lo, hi = CENTRAL_X1[0] * w, CENTRAL_X1[1] * w
    central = [r for r in rows if lo <= r.get("x1", 0) <= hi]
    if len(central) >= 2:
        return "central"
    if any(is_outliner_row(r, w) for r in rows):
        return "outliner"
    return "empty"


def option_rows(rows, w: int):
    """Rows that can be options: everything that does not start in the outliner."""
    return [r for r in rows if not is_outliner_row(r, w)]


def panel_bbox(row_bright: list[int], col_bright: list[int]) -> list[int] | None:
    """Bright-panel envelope ``[x0, y0, x1, y1]`` (inclusive) or ``None``.

    ``row_bright[y]`` / ``col_bright[x]`` count bright pixels per line;
    ``h = len(row_bright)``, ``w = len(col_bright)``. Gates, verbatim from
    the old numpy-side ``_panel_bbox``: row gate ``max(60, int(w * 0.08))``,
    column gate ``max(40, int(h * 0.08))`` (both strict ``>``), at least 100
    gated rows and 100 gated columns, and an envelope at least 300 wide and
    250 tall.
    """
    h = len(row_bright)
    w = len(col_bright)
    row_gate = max(60, int(w * 0.08))
    col_gate = max(40, int(h * 0.08))
    rows = [y for y, n in enumerate(row_bright) if n > row_gate]
    cols = [x for x, n in enumerate(col_bright) if n > col_gate]
    if len(rows) < 100 or len(cols) < 100:
        return None
    bbox = [cols[0], rows[0], cols[-1], rows[-1]]
    if bbox[2] - bbox[0] < 300 or bbox[3] - bbox[1] < 250:
        return None
    return bbox


def close_point_in_crop(bbox, inset: tuple[int, int] = CLOSE_INSET) -> tuple[int, int]:
    """Screen close point mapped into crop-local coordinates.

    ``crop_to_png`` grabs ``grab_box(tuple(bbox))`` with no padding, so the
    crop origin is ``(bbox[0], bbox[1])`` and the x can come out negative:
    an envelope narrower than the inset has no ✖ inside the crop at all, and
    that must be a readable number, not an after-the-fact explanation.
    """
    dx, dy = inset
    return (bbox[2] - dx - bbox[0], bbox[1] + dy - bbox[1])


def window_enum_record(pid: int, candidates: list, chosen: int) -> dict:
    """One offline-readable record of every enumeration candidate.

    ``candidates`` is ``[(hwnd, rect_or_None), ...]`` in enumeration order;
    the whole point is "who else was on screen", so a candidate whose rect
    failed to read is still kept, with ``rect: None``.
    """
    return {"event": "window_candidates", "pid": pid, "chosen": chosen,
            "candidates_n": len(candidates),
            "rects": [{"hwnd": hwnd,
                       "rect": list(rect) if rect is not None else None}
                      for hwnd, rect in candidates]}
