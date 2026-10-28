"""One-off probe: what top-level windows exist right now, and which process owns them.

Written for the 2026-10-28 window when ``Get-Process stellaris`` showed
MainWindowHandle=0 and both ``ns_world probe`` and ``game_supervisor status``
said "no game window to read".  Read-only: EnumWindows + GetWindowRect +
GetWindowThreadProcessId, nothing is touched.

Usage (on the Windows host):  python C:/temp/whoami_windows.py [pid ...]
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import sys

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def window_text(hwnd: int) -> str:
    n = user32.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(n + 2)
    user32.GetWindowTextW(hwnd, buf, n + 2)
    return buf.value


def class_name(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, buf, 256)
    return buf.value


def process_name(pid: int) -> str:
    h = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not h:
        return "?"
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wt.DWORD(1024)
        if not kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return "?"
        return buf.value
    finally:
        kernel32.CloseHandle(h)


def main(argv: list[str]) -> int:
    wanted = {int(a) for a in argv[1:]}

    rows: list[str] = []

    def cb(hwnd, _lparam):
        pid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if wanted and pid.value not in wanted:
            return True
        visible = bool(user32.IsWindowVisible(hwnd))
        rect = wt.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        title = window_text(hwnd)
        if not visible and not title:
            return True
        rows.append(
            f"pid={pid.value:<6} hwnd={hwnd:<12} vis={int(visible)} "
            f"rect=({rect.left},{rect.top},{rect.right},{rect.bottom}) "
            f"class={class_name(hwnd)!r} title={title!r} "
            f"exe={process_name(pid.value)}"
        )
        return True

    user32.EnumWindows(EnumWindowsProc(cb), 0)
    print(f"windows={len(rows)}")
    for row in rows:
        print(row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
