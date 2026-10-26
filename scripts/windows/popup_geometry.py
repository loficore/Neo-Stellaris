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
