#!/usr/bin/env python3
"""host_rect.py — 打印游戏窗口的矩形与暂停读数(主机侧一次性探针)。

`just game shot` 存下来的 PNG 是 `window_rect(hwnd)` 的 **1:1** 抓取(见
`game_supervisor.save_shot`),所以「图上的坐标 + 窗口原点」就是 `just game click`
要的屏幕绝对坐标。这个脚本只回答那个原点,以及当前的暂停读数。
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
    print(f"rect={gs.window_rect(hwnd)}")
    state, red, green = gs.read_pause(hwnd)
    print(f"pause={state} red={red} green={green}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
