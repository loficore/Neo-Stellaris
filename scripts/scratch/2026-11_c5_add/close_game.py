"""Post WM_CLOSE to every top-level window owned by ``stellaris.exe``.

One-off for the 2026-11-02 C5-ADD window.  ``game_supervisor.py`` still records
pid **16100** (a previous session), so ``just game stop`` and
``ns_world.py quit`` both report ``stop_timeout`` while pid 7940 keeps running.
This is the same message the supervisor posts — only the handle comes from a
PID lookup instead of the stale record, and it must run in session 1
(``session_bridge.py``), because that is where the window lives.

    python C:/temp/session_bridge.py C:/temp/close_game.py
"""
import ctypes
import ctypes.wintypes as wt
import subprocess
import sys
import time

WM_CLOSE = 0x0010


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


def main() -> int:
    pids = stellaris_pids()
    if not pids:
        print("NO_PROCESS")
        return 1
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    enum_proc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    posted = []

    def _cb(hwnd, _lparam):
        owner = wt.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value in pids and user32.PostMessageW(hwnd, WM_CLOSE, 0, 0):
            posted.append((hwnd, owner.value))
        return True

    user32.EnumWindows(enum_proc(_cb), 0)
    print(f"PIDS={pids} POSTED={posted}")
    deadline = time.time() + 30
    while time.time() < deadline:
        if not stellaris_pids():
            print("GONE")
            return 0
        time.sleep(1)
    print(f"STILL_ALIVE={stellaris_pids()}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
