"""r5_launch.py — start stellaris.exe in the current (interactive) session.

Used for R5 trip A, where no DLL is injected but the launch shape must be the
same one `c2_boot_inject.py --launch` uses (`stellaris.exe --continuelastsave`,
cwd beside the exe). Run it through `session_bridge.py`, never from the SSH
shell: an SSH login is session 0 and the window it makes is not the desktop's.

Usage:
    python C:/temp/r5_launch.py D:/SteamLibrary/.../stellaris.exe --continuelastsave
"""
from __future__ import annotations

import os
import subprocess
import sys


def main(argv: list[str]) -> int:
    if not argv:
        print("LAUNCH need exe path")
        return 2
    exe, extra = argv[0], argv[1:]
    child = subprocess.Popen([exe, *extra], cwd=os.path.dirname(exe) or None)
    print(f"LAUNCH pid={child.pid} argv={[exe, *extra]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
