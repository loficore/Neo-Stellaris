"""lw_winrect.py — report the game window geometry and foreground (scratch).

Usage (Windows): python C:/temp/lw_winrect.py [hwnd]
Read-only: GetWindowRect / GetForegroundWindow / GetSystemMetrics.
"""
import ctypes
import ctypes.wintypes as wt
import sys

u = ctypes.windll.user32
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass


class RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


def main(argv):
    if not argv:
        print("need hwnd")
        return 2
    hwnd = int(argv[0], 0)
    r = RECT()
    u.GetWindowRect(hwnd, ctypes.byref(r))
    w, h = r.right - r.left, r.bottom - r.top
    cl = RECT()
    u.GetClientRect(hwnd, ctypes.byref(cl))
    print(f"RECT hwnd={hwnd} l={r.left} t={r.top} r={r.right} b={r.bottom} w={w} h={h}")
    print(f"CLIENT w={cl.right} h={cl.bottom}")
    print(f"SCREEN {u.GetSystemMetrics(0)}x{u.GetSystemMetrics(1)}")
    print(f"FOREGROUND {u.GetForegroundWindow()}")
    print(f"VISIBLE {u.IsWindowVisible(hwnd)} ICONIC {u.IsIconic(hwnd)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
