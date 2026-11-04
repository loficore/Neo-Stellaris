"""One-off session-1 control probe for the window fixtures (P0/P1 plan, Task 2).

Runs **inside** session 1 via ``session_bridge`` (a hidden ``.vbs`` task after
Task 1), because only that session can see or drive the game window.

    python C:/temp/session_bridge.py --timeout-s 300 C:/temp/ns_win_ctl.py launch
    python C:/temp/session_bridge.py C:/temp/ns_win_ctl.py status
    python C:/temp/session_bridge.py C:/temp/ns_win_ctl.py shot <tag>
    python C:/temp/session_bridge.py C:/temp/ns_win_ctl.py console "event foo.1"
    python C:/temp/session_bridge.py C:/temp/ns_win_ctl.py quit

``shot`` writes the event-band crop (the same box ``read_window`` samples) to
``C:/temp/nsfix_<tag>.png`` and prints one JSON line with the readings the
classifier used.  The PNG is the fixture; the JSON is a convenience copy that a
later offline pass can recompute from the PNG alone.
"""

import json
import os
import subprocess
import sys
import time

EXE = r"D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe"
OUT_DIR = r"C:\temp"


def _bring(hwnd):
    """Raise a window even when this process is not the foreground one.

    ``SetForegroundWindow`` is refused for a background caller; attaching to the
    current foreground thread's input queue is the documented workaround.
    """
    import ctypes
    u = ctypes.windll.user32
    k = ctypes.windll.kernel32
    u.ShowWindow(hwnd, 9)                      # SW_RESTORE
    fg = u.GetForegroundWindow()
    tid_fg = u.GetWindowThreadProcessId(fg, None)
    tid_me = k.GetCurrentThreadId()
    u.AttachThreadInput(tid_me, tid_fg, True)
    u.SetForegroundWindow(hwnd)
    u.BringWindowToTop(hwnd)
    u.AttachThreadInput(tid_me, tid_fg, False)
    time.sleep(0.4)
    return int(u.GetForegroundWindow() or 0) == int(hwnd)


def _gs():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import game_supervisor as gs
    return gs


def _pid():
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq stellaris.exe", "/NH"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0].lower() == "stellaris.exe":
            return int(parts[1])
    return 0


def cmd_launch(argv):
    args = [EXE, "--continuelastsave"] if "--continue" in argv else [EXE]
    proc = subprocess.Popen(args, cwd=os.path.dirname(EXE))
    print(f"LAUNCHED pid={proc.pid} argv={args}")


def cmd_status(argv):
    gs = _gs()
    pid = _pid()
    if not pid:
        print("GAME=none")
        return
    hwnd = gs.find_window(pid)
    print(f"GAME=pid:{pid} hwnd={hwnd} rect={gs.window_rect(hwnd) if hwnd else None}")


def cmd_shot(argv):
    gs = _gs()
    tag = argv[1] if len(argv) > 1 else "shot"
    pid = _pid()
    if not pid:
        print("GAME=none")
        return 1
    hwnd = gs.find_window(pid)
    if not hwnd:
        print("GAME=none")
        return 1
    rect = gs.window_rect(hwnd)
    left, top, right, bottom = rect
    w, h = right - left, bottom - top
    band = (left + int(w * 0.10), top + int(h * 0.15),
            left + int(w * 0.90), top + int(h * 0.85))
    im = gs.grab_box(band).convert("RGB")
    path = os.path.join(OUT_DIR, f"nsfix_{tag}.png")
    im.save(path)

    stats = gs.read_window(hwnd)
    rows, bbox, gold = gs._norm_geometry(stats["rows"], stats["bbox"],
                                         stats["gold"], rect)
    paused, red, green = gs.read_pause(hwnd)
    print(json.dumps({
        "tag": tag,
        "pid": pid,
        "hwnd": hwnd,
        "rect": list(rect),
        "band": list(band),
        "png": path,
        "png_size": list(im.size),
        "paused": paused,
        "red_px": int(red),
        "green_px": int(green),
        "gold_px": int(gold),
        "row_count": len(rows),
        "option_count": sum(1 for r in rows
                            if r.get("x0", 0) >= gs.CHOICE_ROW_LEFT_MIN
                            and r.get("x1", 0) >= gs.CHOICE_ROW_RIGHT_MIN),
        "bbox": bbox,
        "classify": gs.classify_window(rows, bbox, gold),
        "classify_ref": gs.classify_window_at_reference(rows, bbox, gold),
        "rows": rows,
    }, ensure_ascii=True))


def cmd_full(argv):
    """Whole-window capture: used to locate buttons in a modal."""
    gs = _gs()
    tag = argv[1] if len(argv) > 1 else "full"
    pid = _pid()
    hwnd = gs.find_window(pid) if pid else 0
    if not hwnd:
        print("GAME=none")
        return 1
    rect = gs.window_rect(hwnd)
    im = gs.grab_box(rect).convert("RGB")
    path = os.path.join(OUT_DIR, f"nsfull_{tag}.png")
    im.save(path)
    print(json.dumps({"tag": tag, "rect": list(rect), "png": path,
                      "png_size": list(im.size)}, ensure_ascii=True))


def cmd_click(argv):
    gs = _gs()
    x, y = int(argv[1]), int(argv[2])
    pid = _pid()
    hwnd = gs.find_window(pid) if pid else 0
    if not hwnd:
        print("GAME=none")
        return 1
    ok = gs.focus(hwnd)
    gs._launch()._click_at(x, y)
    print(f"CLICK x={x} y={y} focus={ok}")


def cmd_clickraw(argv):
    """Click a screen point **without** raising the game: modals from other apps
    (Steam's cloud-sync warning) sit on top of the game's rect."""
    gs = _gs()
    x, y = int(argv[1]), int(argv[2])
    gs._launch()._click_at(x, y)
    print(f"CLICKRAW x={x} y={y}")


def cmd_focusclick(argv):
    """Raise a specific hwnd (any app), then click. CEF dialogs ignore the first
    click on an unfocused window, so the click has to follow the raise."""
    gs = _gs()
    hwnd, x, y = int(argv[1]), int(argv[2]), int(argv[3])
    ok = _bring(hwnd)
    time.sleep(0.4)
    gs._launch()._click_at(x, y)
    print(f"FOCUSCLICK hwnd={hwnd} focus={ok} x={x} y={y}")


def cmd_keys(argv):
    """Send a scancode key to the foreground window (Enter = 0x1C)."""
    gs = _gs()
    scan = int(argv[1], 0)
    for flags in (gs.KEYEVENTF_SCANCODE, gs.KEYEVENTF_SCANCODE | gs.KEYEVENTF_KEYUP):
        gs._send_input_event(0, scan, flags)
        time.sleep(0.08)
    print(f"KEYS scan={scan:#x}")


def cmd_steam(argv):
    """Spawn the Steam client in session 1 (a session-0 spawn would be invisible)."""
    exe = r"C:\Program Files (x86)\Steam\steam.exe"
    proc = subprocess.Popen([exe, "-silent"], cwd=os.path.dirname(exe))
    print(f"STEAM_SPAWNED pid={proc.pid}")


def cmd_minimize(argv):
    """Minimise windows whose title contains the given text (SW_MINIMIZE).

    Third-party apps (loopMIDI) sit inside the event band and corrupt readings.
    """
    import ctypes
    import ctypes.wintypes as wt
    needle = " ".join(argv[1:])
    u = ctypes.windll.user32
    found = []

    def cb(hwnd, _):
        if not u.IsWindowVisible(hwnd):
            return True
        buf = ctypes.create_unicode_buffer(512)
        u.GetWindowTextW(hwnd, buf, 512)
        if needle.lower() in buf.value.lower():
            u.ShowWindow(hwnd, 6)   # SW_MINIMIZE
            found.append((hwnd, buf.value))
        return True

    u.EnumWindows(ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)(cb), 0)
    print(f"MINIMIZED n={len(found)} {found}")


def cmd_tap(argv):
    """One backquote: the console panel is a toggle in 4.4.4."""
    gs = _gs()
    pid = _pid()
    hwnd = gs.find_window(pid) if pid else 0
    if not hwnd or not _bring(hwnd):
        print("TAP refuse=focus")
        return 1
    for vk, scan, flags, delay in gs.console_tap_plan():
        gs._send_input_event(vk, scan, flags)
        time.sleep(delay)
    print("TAP ok")


def cmd_bring(argv):
    gs = _gs()
    pid = _pid()
    hwnd = gs.find_window(pid) if pid else 0
    print(f"BRING hwnd={hwnd} ok={_bring(hwnd) if hwnd else False}")


def cmd_console(argv):
    gs = _gs()
    rest = argv[1:]
    open_console = "--noopen" not in rest
    text = " ".join(a for a in rest if a != "--noopen")
    pid = _pid()
    hwnd = gs.find_window(pid) if pid else 0
    if not hwnd:
        print("GAME=none")
        return 1
    if not _bring(hwnd):
        print("CONSOLE refuse=focus")
        return 1
    if not gs._set_clipboard_text(text):
        print("CONSOLE refuse=clipboard")
        return 1
    for vk, scan, flags, delay in gs.console_key_plan(open_console=open_console):
        gs._send_input_event(vk, scan, flags)
        time.sleep(delay)
    print(f"CONSOLE sent={text!r}")


def cmd_quit(argv):
    subprocess.run(["taskkill", "/IM", "stellaris.exe", "/F"], capture_output=True)
    print("QUIT")


def main(argv):
    verb = argv[0] if argv else "status"
    table = {"launch": cmd_launch, "status": cmd_status, "shot": cmd_shot,
             "console": cmd_console, "quit": cmd_quit, "full": cmd_full,
             "click": cmd_click, "clickraw": cmd_clickraw,
             "focusclick": cmd_focusclick, "keys": cmd_keys,
             "steam": cmd_steam, "minimize": cmd_minimize,
             "bring": cmd_bring, "tap": cmd_tap}
    if verb not in table:
        print(__doc__)
        return 2
    return table[verb](argv) or 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
