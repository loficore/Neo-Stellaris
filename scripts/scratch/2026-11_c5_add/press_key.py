"""Send one keystroke to the stellaris.exe window (session 1).

Written for the 2026-11-02 C5-ADD window, where ``game_supervisor.py`` still
records a previous session's pid, so its ``unpause``/``speed`` verbs target a
stale handle.  This finds the game window by PID, brings it forward and posts
a key with the real input path (``keybd_event``), which §81.4 showed is the
half that actually reaches the game on this box (injected mouse clicks do not).

    python C:/temp/session_bridge.py C:/temp/press_key.py space
"""
import ctypes
import ctypes.wintypes as wt
import subprocess
import sys
import time

VK = {"space": 0x20, "enter": 0x0D, "esc": 0x1B, "1": 0x31, "2": 0x32,
      "3": 0x33, "4": 0x34, "5": 0x35, "plus": 0xBB, "minus": 0xBD}
KEYEVENTF_KEYUP = 0x0002


def stellaris_pids():
    out = subprocess.run(
        ["tasklist", "/fi", "imagename eq stellaris.exe", "/fo", "csv", "/nh"],
        capture_output=True, text=True, check=False).stdout
    pids = []
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == "stellaris.exe":
            try:
                pids.append(int(parts[1]))
            except ValueError:
                pass
    return pids


def main(argv) -> int:
    key = (argv[1] if len(argv) > 1 else "space").lower()
    if key not in VK:
        print(f"unknown key {key!r}; known: {sorted(VK)}")
        return 2
    pids = stellaris_pids()
    if not pids:
        print("NO_PROCESS")
        return 1
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    enum_proc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    found = []

    def _cb(hwnd, _lparam):
        owner = wt.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value in pids and user32.IsWindowVisible(hwnd):
            title_len = user32.GetWindowTextLengthW(hwnd)
            if title_len > 0:
                found.append(hwnd)
                return False
        return True

    user32.EnumWindows(enum_proc(_cb), 0)
    if not found:
        print(f"NO_WINDOW pids={pids}")
        return 1
    hwnd = found[0]
    user32.ShowWindow(hwnd, 9)          # SW_RESTORE
    user32.BringWindowToTop(hwnd)
    # A schtasks-run process is not the foreground process, so plain
    # SetForegroundWindow is refused by the foreground lock.  Attaching to the
    # current foreground thread is the documented way around it.
    fg = user32.GetForegroundWindow()
    fg_tid = user32.GetWindowThreadProcessId(fg, None)
    my_tid = ctypes.windll.kernel32.GetCurrentThreadId()
    attached = bool(user32.AttachThreadInput(my_tid, fg_tid, True))
    try:
        user32.SetForegroundWindow(hwnd)
        user32.SetFocus(hwnd)
    finally:
        if attached:
            user32.AttachThreadInput(my_tid, fg_tid, False)
    time.sleep(0.5)
    front = user32.GetForegroundWindow()
    # SendInput with an explicit scan code: legacy keybd_event leaves scan=0,
    # and the game's raw-input path ignores that on this box.  The MCP's
    # `Shortcut` (the one that worked in §81.4) goes through the same API.
    scan = user32.MapVirtualKeyW(VK[key], 0)

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD),
                    ("time", wt.DWORD), ("dwExtraInfo", ctypes.POINTER(wt.ULONG))]

    class INPUT(ctypes.Structure):
        class _U(ctypes.Union):
            _fields_ = [("ki", KEYBDINPUT), ("pad", ctypes.c_byte * 32)]
        _anonymous_ = ("u",)
        _fields_ = [("type", wt.DWORD), ("u", _U)]

    KEYEVENTF_SCANCODE = 0x0008
    inputs = (INPUT * 2)(
        INPUT(type=1, u=INPUT._U(ki=KEYBDINPUT(0, scan, KEYEVENTF_SCANCODE, 0, None))),
        INPUT(type=1, u=INPUT._U(ki=KEYBDINPUT(0, scan, KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP, 0, None))),
    )
    sent = user32.SendInput(2, inputs, ctypes.sizeof(INPUT))
    print(f"KEY={key} scan={scan} sent={sent} hwnd={hwnd} foreground={front} "
          f"front_ok={front == hwnd} pids={pids}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
