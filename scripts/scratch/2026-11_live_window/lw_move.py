"""lw_move.py — move the pointer without clicking (scratch).

Usage (Windows, via session_bridge): python C:/temp/lw_move.py X Y

The bottom-right iShell dock is always-on-top and overlaps the game; it counts
as gold rows in world_probe's sampler and flips the reading to `dialog`. Moving
the pointer away lets it auto-hide before the next probe.
"""
import ctypes
import sys
import time

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass


def main(argv):
    if len(argv) != 2:
        print("usage: lw_move.py X Y")
        return 2
    x, y = int(argv[0]), int(argv[1])
    ctypes.windll.user32.SetCursorPos(x, y)
    time.sleep(0.2)
    print(f"MOVE {x},{y}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
