"""Localize the brightest glyph cluster in a saved popup crop's title strip.

Read-only measurement used by the live batch to compare the fixed close-point
inset against where a bright mark actually is.  Prints a handful of numbers.
"""
import glob
import os

import PIL.Image

TARGET = "1060x320"
BBOX = (879, 555, 1939, 872)          # the window this crop came from

paths = sorted(glob.glob(r"C:\temp\ns_popup\*.png"), key=os.path.getmtime)
print("N", len(paths))

hits = [p for p in paths if TARGET in os.path.basename(p)]
if not hits:
    raise SystemExit("TARGET_CROP_MISSING")
path = hits[-1]
print("P", os.path.basename(path), os.path.getsize(path))
im = PIL.Image.open(path).convert("L")
w, h = im.size
strip_h = min(90, h)
px = im.load()
vals = [px[x, y] for y in range(strip_h) for x in range(w)]
hi = max(vals)
lo = min(vals)
thr = hi - 40
cols = [sum(1 for y in range(strip_h) if px[x, y] >= thr) for x in range(w)]
runs = []
x = 0
while x < w:
    if cols[x] > 0:
        j = x
        while j + 1 < w and cols[j + 1] > 0:
            j += 1
        runs.append((x, j, sum(cols[x:j + 1])))
        x = j + 1
    else:
        x += 1
runs.sort(key=lambda r: -r[2])
print("CROP", w, h, "HI", hi, "LO", lo, "THR", thr, "RUNS", len(runs))
for x0, x1, tot in runs[:5]:
    cx = (x0 + x1) // 2
    # mass-weighted centre over the run
    mass = sum((xx + 1) * cols[xx] for xx in range(x0, x1 + 1))
    wf = mass / max(tot, 1) - 0.5
    print("G", "local=%.1f" % wf, "screen=%.0f" % (BBOX[0] + wf),
          "span=%d" % (x1 - x0 + 1), "mass=%d" % tot)
