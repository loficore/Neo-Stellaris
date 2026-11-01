#!/usr/bin/env python3
"""crop_fixture.py — 把这一发的整图裁成事件带,并断言裁前/裁后判定一致(issue #31)。

`read_window` 只取窗口的 `x ∈ [0.10w, 0.90w]`、`y ∈ [0.15h, 0.85h]`(事件带)。
本脚本用**同一套阈值**在两张图上各跑一次 `panel_bbox` 与 `classify_window`:

  A. 整图 2160×1440,窗口 = 整图;
  B. 裁出来的事件带 1728×1008,窗口 = 该裁片(再按 10%/15% 取一次带)。

断言:两张图的 `classify_window` 结果相同、`panel_bbox` 的**有无**相同,且裁片判 `dialog`
(真窗不能因为裁剪掉出判据)。整图留在 `.superpowers/tmp/`,只有裁片进 git。

用法:
    python3 scripts/scratch/2026-10_popup_fixture/crop_fixture.py
"""
from __future__ import annotations

import pathlib
import sys

from PIL import Image

REPO = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts" / "windows"))

import game_supervisor as gs  # noqa: E402
import popup_geometry as pg  # noqa: E402

SRC = REPO / ".superpowers" / "tmp" / "first_contact_2160x1440.png"
OUT = REPO / "scripts" / "windows" / "tests" / "fixtures" / "first_contact_2160x1440.png"


def band_rect(w: int, h: int):
    """The event band `read_window` samples, in window coordinates."""
    return (int(w * 0.10), int(h * 0.15), int(w * 0.90), int(h * 0.85))


def gold_rows(mask, bw: int, ox: int, oy: int):
    """Same run rule as game_supervisor._gold_rows (row count > 10, gap <= 2)."""
    rowcnt = [0] * (len(mask) // bw)
    xmin = [None] * len(rowcnt)
    xmax = [None] * len(rowcnt)
    for i, on in enumerate(mask):
        if not on:
            continue
        y, x = divmod(i, bw)
        rowcnt[y] += 1
        xmin[y] = x if xmin[y] is None else min(xmin[y], x)
        xmax[y] = x if xmax[y] is None else max(xmax[y], x)
    ys = [y for y, n in enumerate(rowcnt) if n > 10]
    runs = []
    for y in ys:
        if runs and y - runs[-1][1] <= 2:
            runs[-1][1] = y
        else:
            runs.append([y, y])
    rows = []
    for y0, y1 in runs:
        xs = [xmin[y] for y in range(y0, y1 + 1) if xmin[y] is not None]
        xe = [xmax[y] for y in range(y0, y1 + 1) if xmax[y] is not None]
        if not xs:
            continue
        rows.append({"y0": y0 + oy, "y1": y1 + oy, "x0": min(xs) + ox,
                     "x1": max(xe) + ox,
                     "px": sum(rowcnt[y0:y1 + 1])})
    return rows


def stats(im):
    """`read_window`'s numbers for a window-sized image."""
    w, h = im.size
    x0, y0, x1, y1 = band_rect(w, h)
    band = im.crop((x0, y0, x1, y1)).convert("RGB")
    bw, bh = band.size
    px = list(band.getdata())
    luma = [(r + g + b) / 3 for r, g, b in px]
    gold = [(r > 110 and r > b + 50 and g > 70) for r, g, b in px]
    row_bright = [0] * bh
    col_bright = [0] * bw
    for i, v in enumerate(luma):
        if v > 120:
            y, x = divmod(i, bw)
            row_bright[y] += 1
            col_bright[x] += 1
    bbox = pg.panel_bbox(row_bright, col_bright)
    if bbox is not None:
        bbox = [bbox[0] + x0, bbox[1] + y0, bbox[2] + x0, bbox[3] + y0]
    return {"w": w, "h": h, "band": (x0, y0, x1, y1),
            "bright": sum(1 for v in luma if v > 55) / len(luma),
            "gold": sum(gold), "rows": gold_rows(gold, bw, x0, y0),
            "bbox": bbox}


def verdict(s):
    return gs.classify_window(s["rows"], s["bbox"], s["gold"], s["w"], s["h"])


def main() -> int:
    if not SRC.exists():
        print(f"[crop] 整图不在:{SRC}(它是本次的临时输入,不进 git)")
        return 2
    full = Image.open(SRC).convert("RGB")
    a = stats(full)
    x0, y0, x1, y1 = a["band"]
    crop = full.crop((x0, y0, x1, y1))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    crop.save(OUT, optimize=True)
    b = stats(crop)

    va, vb = verdict(a), verdict(b)
    print(f"A 整图 {full.size}: rows={len(a['rows'])} gold={a['gold']} "
          f"bbox={'yes' if a['bbox'] else 'none'} → {va}")
    print(f"B 裁片 {crop.size}: rows={len(b['rows'])} gold={b['gold']} "
          f"bbox={'yes' if b['bbox'] else 'none'} → {vb}")
    assert (a["bbox"] is None) == (b["bbox"] is None), "裁前/裁后的 bbox 有无不一致"
    assert va == vb, f"裁前/裁后的 classify_window 不一致:{va} vs {vb}"
    assert vb == "dialog", f"裁片没判成 dialog:{vb}"
    print(f"[crop] ok → {OUT.relative_to(REPO)} ({OUT.stat().st_size} B)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
