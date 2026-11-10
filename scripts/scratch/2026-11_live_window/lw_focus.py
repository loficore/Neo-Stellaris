"""lw_focus.py — bring a window to the foreground from a background process.

Usage (Windows, via session_bridge): python C:/temp/lw_focus.py 591656

Plain SetForegroundWindow is refused when the caller is not the foreground
process (the Orca browser is foreground here, so game_supervisor's focus() can
return False and its Space press never reaches the game). Tries, in order:
AttachThreadInput + SetForegroundWindow, SwitchToThisWindow, and the Alt-key
unlock trick.
"""
import ctypes
import sys
import time

u = ctypes.windll.user32
k = ctypes.windll.kernel32

SW_RESTORE = 9


def _fg():
    return int(u.GetForegroundWindow() or 0)


def _try(label, fn, hwnd):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - report, do not abort the ladder
        print(f"  {label}: {exc}")
        return False
    time.sleep(0.25)
    ok = _fg() == hwnd
    print(f"  {label}: fg={_fg()} ok={ok}")
    return ok


def main(argv):
    if not argv:
        print("usage: lw_focus.py <hwnd>")
        return 2
    hwnd = int(argv[0], 0)
    fg = _fg()
    if fg == hwnd:
        print(f"FOCUS already target={hwnd} foreground={fg} ok=True")
        return 0

    def attach_set():
        tid_fg = u.GetWindowThreadProcessId(fg, None) if fg else 0
        tid_me = k.GetCurrentThreadId()
        attached = bool(u.AttachThreadInput(tid_me, tid_fg, True)) if tid_fg else False
        u.ShowWindow(hwnd, SW_RESTORE)
        u.BringWindowToTop(hwnd)
        u.SetForegroundWindow(hwnd)
        if attached:
            u.AttachThreadInput(tid_me, tid_fg, False)

    def switch():
        u.SwitchToThisWindow(hwnd, True)

    def alt_set():
        u.keybd_event(0x12, 0, 0, 0)  # Alt down unlocks the foreground lock
        u.SetForegroundWindow(hwnd)
        u.keybd_event(0x12, 0, 2, 0)  # Alt up

    for label, fn in (("attach+set", attach_set), ("switch", switch), ("alt+set", alt_set)):
        if _try(label, fn, hwnd):
            print(f"FOCUS target={hwnd} foreground={_fg()} ok=True via={label}")
            return 0

    print(f"FOCUS target={hwnd} foreground={_fg()} ok=False")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
