"""One-off on-box probe: list the visible top-level windows of session 1.

The agent's win-desktop MCP server reports "No windows found" on this box even
while an application owns the foreground, so window inventories come from here
instead: the script runs **inside** session 1 via ``session_bridge`` and
enumerates with ``EnumWindows`` itself.

    python C:/temp/session_bridge.py C:/temp/ns_bridge_windows.py
"""

import ctypes
import ctypes.wintypes as wt

_u = ctypes.windll.user32
_EnumProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def _text(hwnd):
    buf = ctypes.create_unicode_buffer(512)
    _u.GetWindowTextW(hwnd, buf, 512)
    return buf.value


def _class(hwnd):
    buf = ctypes.create_unicode_buffer(256)
    _u.GetClassNameW(hwnd, buf, 256)
    return buf.value


def _esc(text):
    """ASCII-only rendering: the bridge reads this back through a cp936 pipe."""
    return text.encode("unicode_escape").decode("ascii")


def main():
    rows = []

    def cb(hwnd, _):
        if not _u.IsWindowVisible(hwnd):
            return True
        title, cls = _text(hwnd), _class(hwnd)
        if not title and not cls:
            return True
        pid = wt.DWORD()
        _u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        rect = wt.RECT()
        _u.GetWindowRect(hwnd, ctypes.byref(rect))
        rows.append((hwnd, pid.value, _esc(cls), _esc(title),
                     (rect.left, rect.top, rect.right, rect.bottom)))
        return True

    _u.EnumWindows(_EnumProc(cb), 0)
    fg = _u.GetForegroundWindow()
    print(f"WINDOWS={len(rows)} FOREGROUND={fg} FG_TITLE={_esc(_text(fg))}")
    for hwnd, pid, cls, title, rect in rows:
        print(f"WIN hwnd={hwnd} pid={pid} rect={rect} class={cls} title={title}")


if __name__ == "__main__":
    main()
