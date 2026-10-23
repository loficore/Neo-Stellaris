"""One-off probe: observe the debug-console panel over pixels (Windows, needs the game).

Why this exists: ``console_open`` in the supervisor is a belief, and §54.9 showed a
belief that no observation can correct.  This probe produces the two reference
states the missing detector needs -- panel closed and panel open -- as numbers.

Printing a whole luminance map over ssh is not an option: stdout above roughly
1 KB resets the connection (docs/offline-tooling.md, and 700 B is the size that
has held).  So a ``snap`` writes its full detail to a file on the host and prints
one short line; ``diff`` compares two saved snaps and prints only what moved.

Run from C:/temp on the host, next to ``game_supervisor.py`` (it reuses that
module's pixel and input primitives instead of reimplementing them):

    python C:/temp/panel_pixel_map.py snap closed   # pixels only, no input
    python C:/temp/panel_pixel_map.py tap           # focus + press console key once
    python C:/temp/panel_pixel_map.py snap open
    python C:/temp/panel_pixel_map.py tap           # press again to close it
    python C:/temp/panel_pixel_map.py snap closed2
    python C:/temp/panel_pixel_map.py diff closed closed2   # must be ~0: sanity
    python C:/temp/panel_pixel_map.py diff closed open      # the panel's footprint

Snap files land in C:/temp/ns_panel_<tag>.txt and full-res frames in
C:/temp/ns_panel_<tag>.png.  Keep the png frames: evidence §54.10 cites them as
the calibration record, and `stats`/`footprint`/`bbox` recompute straight from
those bytes with no desktop session (plain ssh is enough).

Throwaway: the deliverable is the numbers, which go into the detector in
``game_supervisor.py``; this file stays here and keeps its bytes.
"""

import json
import os
import sys

GRID_W, GRID_H = 32, 18
BANDS = 8


def _gs():
    import game_supervisor as gs
    return gs


def _hwnd():
    pid, hwnd = _gs().find_game()
    if not hwnd:
        raise SystemExit("no_game")
    return pid, hwnd


def _path(tag):
    return os.path.join("C:\\temp", "ns_panel_%s.txt" % tag)


def _measure():
    """(rect, pause label, 32x18 digit grid, per-band dark/light fractions)."""
    gs = _gs()
    _, hwnd = _hwnd()
    rect = gs.window_rect(hwnd)
    im = gs.grab_box(rect)
    lum = im.convert("L")
    w, h = lum.size
    grid = [min(15, v // 16) for v in lum.resize((GRID_W, GRID_H)).getdata()]
    bands = []
    data = lum.load()
    for band in range(BANDS):
        y0 = h * band // BANDS
        y1 = h * (band + 1) // BANDS
        dark = light = total = 0
        for y in range(y0, y1, 3):
            for x in range(0, w, 3):
                v = data[x, y]
                total += 1
                dark += v < 40
                light += v > 180
        bands.append([y0, y1, round(dark / max(1, total), 4),
                      round(light / max(1, total), 4)])
    paused, red, green = gs.read_pause(hwnd)
    return rect, (paused, red, green), grid, bands


def snap(tag):
    rect, pause, grid, bands = _measure()
    with open(_path(tag), "w", encoding="ascii") as f:
        json.dump({"rect": list(rect), "pause": list(pause),
                   "grid": grid, "bands": bands}, f)
    print("SAVED %s pause=%s/%s grid=%s" % (tag, pause[0], pause[1],
                                            "%08x" % (sum(grid) * 1000003 + len(grid))))


def diff(tag_a, tag_b):
    a = json.load(open(_path(tag_a), encoding="ascii"))
    b = json.load(open(_path(tag_b), encoding="ascii"))
    ga, gb = a["grid"], b["grid"]
    moved = sum(1 for x, y in zip(ga, gb) if x != y)
    weight = sum(abs(x - y) for x, y in zip(ga, gb))
    print("MOVED %d/%d weight=%d rect_eq=%s" % (
        moved, len(ga), weight, a["rect"] == b["rect"]))
    print("PAUSE %s -> %s" % (a["pause"], b["pause"]))
    print("ROWW %s" % " ".join(
        "%d:%d" % (r, sum(abs(ga[r * GRID_W + c] - gb[r * GRID_W + c])
                           for c in range(GRID_W)))
        for r in range(GRID_H)))
    print("BAND a|b")
    for (y0, y1, da, la), (by0, by1, db, lb) in zip(a["bands"], b["bands"]):
        print("%d-%d %.3f/%.3f %.3f/%.3f" % (y0, y1, da, db, la, lb))


def grid(tag):
    """The saved grid as 18 lines of 32 hex digits -- the shape of the change."""
    g = json.load(open(_path(tag), encoding="ascii"))["grid"]
    print("GRID %s rect=%s" % (tag, json.load(open(_path(tag), encoding="ascii"))["rect"]))
    for r in range(GRID_H):
        print("".join("%x" % v for v in g[r * GRID_W:(r + 1) * GRID_W]))


def tap_console_key():
    import time
    gs = _gs()
    _, hwnd = _hwnd()
    if not gs.focus(hwnd):
        raise SystemExit("focus_refused")
    for vk, scan, flags, delay in gs.console_tap_plan():
        gs._send_input_event(vk, scan, flags)
        time.sleep(delay)
    print("TAPPED")


def _img_path(tag):
    return os.path.join("C:\\temp", "ns_panel_%s.png" % tag)


def png(tag):
    """Full-resolution luminance frame -- the 32x18 average grid cannot see a
    translucent text panel, so keep the bytes and diff them later."""
    gs = _gs()
    _, hwnd = _hwnd()
    rect = gs.window_rect(hwnd)
    im = gs.grab_box(rect).convert("L")
    im.save(_img_path(tag))
    print("PNG %s size=%s rect=%s" % (tag, im.size, list(rect)))


def bbox(tag_a, tag_b, thr=30):
    """Where did two full-res frames actually differ? Prints the count, the
    bounding box of changed pixels, and an 8x16 density map (one hex cell per
    block, 0-f = that block's share of all changed pixels)."""
    import numpy as np
    from PIL import Image
    a = np.asarray(Image.open(_img_path(tag_a)), dtype=np.int16)
    b = np.asarray(Image.open(_img_path(tag_b)), dtype=np.int16)
    if a.shape != b.shape:
        print("SHAPE_MISMATCH %s %s" % (a.shape, b.shape))
        return
    d = np.abs(a - b)
    m = d > thr
    n = int(m.sum())
    print("N=%d/%d max=%d p99=%d" % (n, m.size, int(d.max()),
                                     int(np.percentile(d, 99))))
    if not n:
        return
    ys, xs = np.nonzero(m)
    print("BOX x%d-%d y%d-%d" % (xs.min(), xs.max(), ys.min(), ys.max()))
    h, w = m.shape
    rows, cols = 8, 16
    print("DENSITY")
    for r in range(rows):
        line = []
        for c in range(cols):
            blk = m[h * r // rows:h * (r + 1) // rows, w * c // cols:w * (c + 1) // cols]
            line.append("%x" % min(15, round(15 * blk.sum() / max(1, n))))
        print("".join(line))


def chain(spec):
    """One process, one focus, the whole tap/read/tap/read sequence. Steps are
    separated by ';' and a step's argv words by ',' -- no spaces, so the spec
    survives cmd /c inside schtasks /tr without a second layer of quoting.
    'sleep,<ms>' pauses so the panel has a frame to render."""
    import time
    for step in spec.split(";"):
        parts = step.split(",")
        if parts[0] == "sleep":
            time.sleep(float(parts[1]) / 1000.0)
            continue
        main(parts)
        time.sleep(0.6)


def brightmap(tag, cols=72, rows=24, thr=180):
    """Where is DENSE small bright text, in one frame -- no diffing, so the
    animated menu background (dim, sparse stars) cannot fake it. Each cell
    counts pixels above `thr`; a console panel's text fills a cell, a star
    dot does not."""
    import numpy as np
    from PIL import Image
    a = np.asarray(Image.open(_img_path(tag)))
    h, w = a.shape
    out = ["BM %s %dx%d thr=%d" % (tag, w, h, thr)]
    for r in range(rows):
        line = []
        for c in range(cols):
            blk = a[h * r // rows:h * (r + 1) // rows,
                    w * c // cols:w * (c + 1) // cols]
            n = int((blk > thr).sum())
            line.append(" .-+*#@"[0 if n == 0 else 1 if n <= 3 else 2 if n <= 10
                                 else 3 if n <= 25 else 4 if n <= 60 else 5
                                 if n <= 150 else 6])
        out.append("".join(line))
    print("\n".join(out))
    with open(os.path.join("C:\\temp", "ns_bm_%s.txt" % tag), "w", encoding="ascii") as f:
        f.write("\n".join(out) + "\n")


def _cell_counts(tag, cols=54, rows=18, thr=180):
    import numpy as np
    from PIL import Image
    a = np.asarray(Image.open(_img_path(tag)))
    h, w = a.shape
    m = a > thr
    out = np.zeros((rows, cols), dtype=np.int32)
    for r in range(rows):
        for c in range(cols):
            out[r, c] = int(m[h * r // rows:h * (r + 1) // rows,
                              w * c // cols:w * (c + 1) // cols].sum())
    return out, (w, h, cols, rows)


def footprint(tag_open, *tags_closed):
    """Which cells light up in `tag_open` but not in any closed frame, while the
    closed frames agree with each other? That is the panel's footprint, and the
    cell grid is what a single-frame detector can use."""
    import numpy as np
    o, (w, h, cols, rows) = _cell_counts(tag_open)
    cs = [_cell_counts(t)[0] for t in tags_closed]
    base = np.max(np.stack(cs), axis=0)
    spread = np.max(np.stack(cs), axis=0) - np.min(np.stack(cs), axis=0)
    delta = o - base
    sel = [(r, c, int(base[r, c]), int(o[r, c]), int(delta[r, c]), int(spread[r, c]))
           for r in range(rows) for c in range(cols)
           if delta[r, c] > 10]
    sel.sort(key=lambda x: -x[4])
    print("FP %s vs %s cells>10=%d sum=%d" % (tag_open, ",".join(tags_closed),
                                              len(sel), int(delta[delta > 0].sum())))
    for r, c, b, ov, d, sp in sel[:16]:
        print("%d,%d base=%d open=%d d=%d churn=%d" % (r, c, b, ov, d, sp))
    if sel:
        rs = [x[0] for x in sel]
        cs2 = [x[1] for x in sel]
        print("RECT x%d-%d y%d-%d (cell %dx%d px, win %dx%d)" % (
            min(cs2) * w // cols, (max(cs2) + 1) * w // cols,
            min(rs) * h // rows, (max(rs) + 1) * h // rows,
            w // cols, h // rows, w, h))


CANDS = {
    "A": (120, 640, 400, 880),    # the eight heaviest footprint cells
    "B": (40, 480, 900, 880),     # the whole footprint column band
    "C": (40, 80, 900, 160),      # row 1 -- text near the top of the panel
    "W": (0, 0, 2160, 1440),      # whole window, the churn control
}


def stats(tag):
    """Bright-pixel count per candidate box, at three thresholds, for one frame."""
    import numpy as np
    from PIL import Image
    a = np.asarray(Image.open(_img_path(tag)))
    parts = []
    for key in sorted(CANDS):
        x0, y0, x1, y1 = CANDS[key]
        blk = a[y0:y1, x0:x1]
        parts.append("%s=%d/%d/%d" % (key, int((blk > 140).sum()),
                                      int((blk > 180).sum()), int((blk > 220).sum())))
    print("STATS %s %s" % (tag, " ".join(parts)))


def diag():
    """Live read of the screen the daemon is looking at -- pixels and window
    identity only, no input.  Used when status says unreadable and the question
    is 'is the frame black, or is this a different screen?'"""
    import ctypes
    import numpy as np
    gs = _gs()
    pid, hwnd = _hwnd()
    buf = ctypes.create_unicode_buffer(256)
    gs._user32().GetWindowTextW(hwnd, buf, 256)
    title = "".join(c if 32 <= ord(c) < 127 else "?" for c in buf.value)[:48]
    rect = gs.window_rect(hwnd)
    a = np.asarray(gs.grab_box(rect).convert("L"), dtype=np.int16)
    x0, y0, x1, y1 = CANDS["A"]
    paused, red, green = gs.read_pause(hwnd)
    print("DIAG pid=%d hwnd=%d title=%s" % (pid, hwnd, title))
    print("RECT %s pause=%s r=%d g=%d" % (list(rect), paused, red, green))
    print("WIN mean=%.1f bright=%d/%d" % (float(a.mean()),
                                          int((a > 180).sum()), a.size))
    print("BOXA bright=%d" % int((a[y0:y1, x0:x1] > 180).sum()))


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    name, rest = argv[0], argv[1:]
    if name == "chain" and len(rest) == 1:
        chain(rest[0])
    elif name == "snap" and len(rest) == 1:
        snap(rest[0])
    elif name == "diff" and len(rest) == 2:
        diff(*rest)
    elif name == "stats" and len(rest) == 1:
        stats(rest[0])
    elif name == "footprint" and len(rest) >= 2:
        footprint(rest[0], *rest[1:])
    elif name == "brightmap" and 1 <= len(rest) <= 4:
        brightmap(rest[0], *[int(x) for x in rest[1:]])
    elif name == "grid" and len(rest) == 1:
        grid(rest[0])
    elif name == "png" and len(rest) == 1:
        png(rest[0])
    elif name == "bbox" and len(rest) == 2:
        bbox(*rest)
    elif name == "tap" and not rest:
        tap_console_key()
    elif name == "diag" and not rest:
        diag()
    else:
        raise SystemExit(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
