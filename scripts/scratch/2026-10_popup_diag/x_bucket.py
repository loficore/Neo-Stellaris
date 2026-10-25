"""Bucket the title-strip brightness mass so the far right can be read as
present-or-absent, and describe the rightmost band's colour.

Read-only. Used by the live batch to state whether a close glyph exists where
the fixed inset would click.
"""
import glob
import os

import PIL.Image

TARGET = "1060x320"
BBOX = (879, 555, 1939, 872)

paths = sorted(glob.glob(r"C:\temp\ns_popup\*.png"), key=os.path.getmtime)
path = [p for p in paths if TARGET in os.path.basename(p)][-1]
rgb = PIL.Image.open(path).convert("RGB")
w, h = rgb.size
g = rgb.convert("L")
px = g.load()
strip = min(90, h)
thr = 215
B = 100
buckets = []
for b in range(0, w, B):
    buckets.append(sum(1 for x in range(b, min(b + B, w))
                       for y in range(strip) if px[x, y] >= thr))
print("BUCK", buckets)
right = rgb.crop((w - 190, 0, w, strip))
colors = right.getcolors(maxcolors=100000)
colors.sort(key=lambda c: -c[0])
print("TOPC", [(n, "#%02x%02x%02x" % c) for n, c in colors[:4]])
rowmax = [max(px[x, y] for x in range(w - 190, w)) for y in range(strip)]
print("RIGHTMAX", rowmax)
