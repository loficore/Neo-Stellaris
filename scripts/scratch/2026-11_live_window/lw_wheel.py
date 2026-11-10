"""lw_wheel.py — scroll the mouse wheel at a screen point (scratch).

Usage (Windows, via session_bridge): python C:/temp/lw_wheel.py X Y N
N > 0 = wheel up, N < 0 = wheel down (zoom out on the galaxy map).

Why: world_probe calls the clean starmap a `dialog` when >=2 gold rows land in
the central band (x1 in [0.30w,0.70w], y0 in [0.45h,0.75h]). Star/fleet labels
near the camera centre land there; zooming changes which labels sit inside the
band, so the gate can read `none` without touching the game state.
"""
import ctypes
import sys
import time

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass

WHEEL = 0x0800


def main(argv):
    if len(argv) != 3:
        print("usage: lw_wheel.py X Y N")
        return 2
    x, y, n = int(argv[0]), int(argv[1]), int(argv[2])
    u = ctypes.windll.user32
    u.SetCursorPos(x, y)
    time.sleep(0.2)
    for _ in range(abs(n)):
        delta = 120 if n > 0 else -120
        u.mouse_event(WHEEL, 0, 0, delta, 0)
        time.sleep(0.12)
    print(f"WHEEL {x},{y} n={n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
