"""One-shot live diagnostic: window geometry, visibility, and evidence inventory.

Read-only. Prints one line per fact so the controller can classify the shot
without transferring pixels.
"""
import glob
import os

import win32con
import win32gui
import win32process

SHOT = r"C:\temp\ns_game_shot.png"



try:
    import psutil

    pids = {p.pid for p in psutil.process_iter(['pid', 'name'])
            if p.info['name'] and 'stellaris' in p.info['name'].lower()}
except Exception as exc:                        # noqa: BLE001
    print("PIDS_ERR", exc)
    pids = set()


def cb2(hwnd, acc):
    if not win32gui.IsWindowVisible(hwnd):
        return
    _, pid = win32process.GetWindowThreadProcessId(hwnd)
    if pid not in pids:
        return
    acc.append((hwnd, pid, win32gui.GetWindowText(hwnd),
                win32gui.GetWindowRect(hwnd), bool(win32gui.IsIconic(hwnd))))


found = []
win32gui.EnumWindows(cb2, found)
for hwnd, pid, text, rect, iconic in found:
    print("WIN", hwnd, pid, repr(text), rect, iconic)

print("MT", int(os.path.getmtime(SHOT)) if os.path.exists(SHOT) else -1)
if os.path.exists(SHOT):
    import PIL.Image

    with PIL.Image.open(SHOT) as im:
        print("SHOT_SIZE", im.size, "EXTREMA", im.getextrema())

ev = sorted(glob.glob(r"C:\temp\ns_popup\*.png"), key=os.path.getmtime)
print("EVIDENCE_N", len(ev))
print("EV_NEWEST", os.path.basename(ev[-1]) if ev else "-")
