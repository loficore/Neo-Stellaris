#!/usr/bin/env python3
"""host_rows.py — 打印 daemon 眼里的窗口读数(rows / bbox / gold)与分类结果。

主机会话 1 才有窗口句柄,所以这个探针要走 `session_bridge`。
一次性诊断:用来判断 `classify_window` 说的 "choice" 到底指向哪些金色行。
"""
from __future__ import annotations

import sys

sys.path.insert(0, r"C:\temp")

import game_supervisor as gs  # noqa: E402


def main() -> int:
    pid, hwnd = gs.find_game()
    print(f"pid={pid} hwnd={hwnd}")
    if not hwnd:
        return 1
    rect = gs.window_rect(hwnd)
    print(f"rect={rect}")
    stats = gs.read_window(hwnd)
    print(f"bright={stats['bright']:.4f} gold={stats['gold']} bbox={stats['bbox']}")
    rows = stats["rows"]
    print(f"rows={len(rows)}")
    for i, row in enumerate(rows):
        print(f"  [{i}] x0={row['x0']} x1={row['x1']} y0={row['y0']} y1={row['y1']}")
    nrows, nbbox, ngold = gs._norm_geometry(rows, stats["bbox"], stats["gold"], rect)
    print(f"norm: rows={len(nrows)} bbox={nbbox} gold={ngold}")
    print(f"classify={gs.classify_window(nrows, nbbox, ngold)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
