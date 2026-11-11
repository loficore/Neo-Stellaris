"""lw_drag.py — left-drag on the desktop (scratch).

Usage (Windows, via session_bridge): python C:/temp/lw_drag.py X0 Y0 X1 Y1 [steps]

Used to pan the galaxy map so the central band (world_probe's option band,
x1 in [0.30w,0.70w] and y0 in [0.45h,0.75h]) holds no star/fleet label; the
gate then reads `window=none` on a genuinely empty screen.
"""
import ctypes
import sys
import time

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass

DOWN = 0x0002
UP = 0x0004


def main(argv):
    if len(argv) < 4:
        print("usage: lw_drag.py X0 Y0 X1 Y1 [steps]")
        return 2
    x0, y0, x1, y1 = (int(v) for v in argv[:4])
    steps = int(argv[4]) if len(argv) > 4 else 12
    u = ctypes.windll.user32
    u.SetCursorPos(x0, y0)
    time.sleep(0.2)
    u.mouse_event(DOWN, 0, 0, 0, 0)
    time.sleep(0.2)
    for i in range(1, steps + 1):
        u.SetCursorPos(x0 + (x1 - x0) * i // steps, y0 + (y1 - y0) * i // steps)
        time.sleep(0.03)
    time.sleep(0.2)
    u.mouse_event(UP, 0, 0, 0, 0)
    print(f"DRAG {x0},{y0} -> {x1},{y1} steps={steps}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
