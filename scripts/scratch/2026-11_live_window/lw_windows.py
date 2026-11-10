"""lw_windows.py — list visible top-level windows (hwnd, pid, title) on the
interactive desktop. Read-only; run via session_bridge so it sees session 1.
"""
import ctypes
import ctypes.wintypes as wt

u = ctypes.windll.user32
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass

EnumProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)


def cb(hwnd, _lparam):
    if not u.IsWindowVisible(hwnd):
        return True
    n = u.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(n + 1)
    u.GetWindowTextW(hwnd, buf, n + 1)
    pid = wt.DWORD()
    u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    cls = ctypes.create_unicode_buffer(128)
    u.GetClassNameW(hwnd, cls, 128)
    print(f"WIN hwnd={int(hwnd)} pid={pid.value} class={cls.value!r} title={buf.value!r}")
    return True


def main():
    fg = int(u.GetForegroundWindow() or 0)
    print(f"FOREGROUND {fg}")
    u.EnumWindows(EnumProc(cb), 0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
