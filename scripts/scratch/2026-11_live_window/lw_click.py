"""lw_click.py — one physical-coordinate left click on the interactive desktop.

Usage (Windows, via session_bridge): python C:/temp/lw_click.py X Y

Why: game_supervisor's `click` verb passes coordinates through its own
DPI-unaware metric and lands off-target on this 2160x1440 screen; this script
declares per-monitor DPI awareness first, so X/Y are the same physical pixels
GetWindowRect reports.
"""
import ctypes
import sys
import time

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass

MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004


def main(argv):
    if len(argv) != 2:
        print("usage: lw_click.py X Y")
        return 2
    x, y = int(argv[0]), int(argv[1])
    u = ctypes.windll.user32
    fg = u.GetForegroundWindow()
    u.SetCursorPos(x, y)
    time.sleep(0.15)
    u.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
    time.sleep(0.08)
    u.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
    print(f"CLICK {x},{y} fg={fg} screen={u.GetSystemMetrics(0)}x{u.GetSystemMetrics(1)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
