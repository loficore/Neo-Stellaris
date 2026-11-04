"""One-off on-box probe: measure the console window the launcher creates.

Deployed as ``C:/temp/ns_bridge_hold.py`` and fired through ``session_bridge``.
Used for issue #32 (Task 1): a ``.cmd`` task run with ``/run /I`` creates a
**visible** console on the interactive desktop, which takes the foreground and
makes Stellaris pause itself.  The hidden ``.vbs`` launcher must create none.

The measurement is taken inside the launched process, i.e. where the window
would exist: ``GetConsoleWindow`` + ``IsWindowVisible`` on that handle answer
"is there a console window on the ground that a person could see", and the
foreground hwnd answers "who owns the desktop right now".

    python C:/temp/session_bridge.py --timeout-s 60 C:/temp/ns_bridge_hold.py
"""

import ctypes
import time

_u = ctypes.windll.user32
_k = ctypes.windll.kernel32


def _class_of(hwnd):
    buf = ctypes.create_unicode_buffer(256)
    _u.GetClassNameW(hwnd, buf, 256)
    return buf.value


def _title_of(hwnd):
    buf = ctypes.create_unicode_buffer(256)
    _u.GetWindowTextW(hwnd, buf, 256)
    return buf.value


def report(tag):
    console = _k.GetConsoleWindow()
    visible = _u.IsWindowVisible(console) if console else 0
    fg = _u.GetForegroundWindow()
    print(
        f"{tag} CONSOLE_HWND={console} CONSOLE_VISIBLE={visible} "
        f"FOREGROUND={fg} FG_CLASS={_class_of(fg) if fg else ''!r} "
        f"FG_TITLE={_title_of(fg) if fg else ''!r}",
        flush=True,
    )


report("HOLD_START")
time.sleep(8)          # let the launcher settle, then read the same facts again
report("HOLD_MID")
time.sleep(12)
report("HOLD_END")
