"""Launch stellaris.exe in the current session without injecting anything.

Used by the C6-5 A/B pair: the base run must have no DLL in the process, so
`c2_boot_inject.py` (which requires a DLL for its export checks) is not usable.

The argv shape and the cwd are the ones `c2_boot_inject.boot()` uses
(`cwd=os.path.dirname(exe)`), so trip A and trip B differ in exactly one thing:
whether the DLL is in the process. Run it through `session_bridge.py` — an SSH
login is session 0 and the window it makes is not the desktop's.

Usage (Windows):
    python C:/temp/lw_launch.py
"""
import os
import subprocess

EXE = r"D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe"

if __name__ == "__main__":
    child = subprocess.Popen([EXE, "--continuelastsave"],
                             cwd=os.path.dirname(EXE) or None)
    print("LAUNCHED", EXE, "pid=%d" % child.pid)
