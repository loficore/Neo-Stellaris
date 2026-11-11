"""lw_key.py — send one key press to the interactive desktop (scratch).

Usage (Windows, must go through session_bridge):
    python C:/temp/lw_key.py enter
    python C:/temp/lw_key.py esc
    python C:/temp/lw_key.py space

Why a script instead of the supervisor's verbs: the supervisor's click path
normalises coordinates through its own (DPI-unaware) metric, so a physical
coordinate lands off-target; and its popup route refuses to act on an
unclassified dialog. The documented way to answer an event window is the
default option = Enter (docs/offline-tooling.md, win-desktop trap 5).
"""
import ctypes
import sys
import time

VK = {
    "enter": 0x0D,
    "esc": 0x1B,
    "space": 0x20,
    "tab": 0x09,
    "1": 0x31,
    "2": 0x32,
    "3": 0x33,
    "4": 0x34,
    "grave": 0xC0,
    "left": 0x25,
    "up": 0x26,
    "right": 0x27,
    "down": 0x28,
}


def main(argv):
    if not argv or argv[0].lower() not in VK:
        print("usage: lw_key.py enter|esc|space|tab")
        return 2
    vk = VK[argv[0].lower()]
    u = ctypes.windll.user32
    u.keybd_event(vk, 0, 0, 0)
    time.sleep(0.08)
    u.keybd_event(vk, 0, 2, 0)
    print(f"KEY {argv[0].lower()} vk={vk} fg={u.GetForegroundWindow()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
