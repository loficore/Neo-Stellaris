#!/usr/bin/env python3
"""host_options.py — 在 `ns_game_shot.png` 里找事件窗的选项圆圈(主机侧一次性探针)。

为什么在主机上算:这台 Linux 没有 numpy,而主机上 PIL/numpy 是部署件。
`save_shot` 存的是 `window_rect` 的 **1:1** 抓取,所以 PNG 像素坐标 = 窗口坐标,
`just game click <x> <y>` 直接吃这组数(窗口原点 (0,0) 时屏幕坐标 = 窗口坐标)。

输出每个候选圆圈的圆心与像素数;颜色分三档(绿/黄/红),按 y 聚成行。
"""
from __future__ import annotations

import sys

import numpy as np
from PIL import Image

SHOT = r"C:\temp\ns_game_shot.png"


def _rows(mask, w, h, x0, x1, y0, y1, min_px=40):
    sub = mask[y0:y1, x0:x1]
    ys, xs = np.nonzero(sub)
    if len(xs) == 0:
        return []
    order = np.argsort(ys)
    ys, xs = ys[order], xs[order]
    groups, cur = [], [0]
    for i in range(1, len(ys)):
        if ys[i] - ys[cur[-1]] <= 6:
            cur.append(i)
        else:
            groups.append(cur)
            cur = [i]
    groups.append(cur)
    out = []
    for gp in groups:
        if len(gp) < min_px:
            continue
        yy = int(ys[gp].mean()) + y0
        xx = int(xs[gp].mean()) + x0
        out.append((xx, yy, len(gp)))
    return out


def main() -> int:
    im = Image.open(SHOT).convert("RGB")
    w, h = im.size
    print(f"png={w}x{h}")
    a = np.asarray(im, dtype=np.int16)
    r, g, b = a[..., 0], a[..., 1], a[..., 2]
    x0, x1 = int(w * 0.48), int(w * 0.56)
    y0, y1 = int(h * 0.50), int(h * 0.72)
    masks = {
        "green": (g > 110) & (g > r + 25) & (g > b + 25),
        "yellow": (r > 150) & (g > 110) & (b < 90) & (np.abs(r - g) < 70),
        "red": (r > 140) & (r > g + 60) & (r > b + 60),
    }
    for name, mask in masks.items():
        for xx, yy, n in _rows(mask, w, h, x0, x1, y0, y1):
            print(f"{name}\t{xx}\t{yy}\t{n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
