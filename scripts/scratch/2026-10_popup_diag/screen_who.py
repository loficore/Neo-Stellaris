"""What is on screen right now: the supervisor's hwnd plus every titled window.

Read-only. Used by the live batch to tell "game window collapsed" apart from
"another window took the foreground".
"""
import win32gui
import win32process

SUPERVISOR_HWND = 199030

if win32gui.IsWindow(SUPERVISOR_HWND):
    _, pid = win32process.GetWindowThreadProcessId(SUPERVISOR_HWND)
    print("SUP", SUPERVISOR_HWND, "pid", pid, "vis",
          bool(win32gui.IsWindowVisible(SUPERVISOR_HWND)),
          "iconic", bool(win32gui.IsIconic(SUPERVISOR_HWND)),
          "rect", win32gui.GetWindowRect(SUPERVISOR_HWND),
          "txt", repr(win32gui.GetWindowText(SUPERVISOR_HWND))[:40])
else:
    print("SUP_GONE", SUPERVISOR_HWND)


def cb(hwnd, acc):
    if not win32gui.IsWindowVisible(hwnd):
        return
    t = win32gui.GetWindowText(hwnd)
    if not t:
        return
    _, pid = win32process.GetWindowThreadProcessId(hwnd)
    r = win32gui.GetWindowRect(hwnd)
    acc.append((pid, t, r[2] - r[0], r[3] - r[1]))


acc = []
win32gui.EnumWindows(cb, acc)
acc.sort(key=lambda a: -(a[2] * a[3]))
for pid, t, w, h in acc[:8]:
    print("W", pid, t[:22], w, h)
