"""c65_close.py — C6-5 一趟的**原子收尾段**（实机，Windows 侧）。

顺序是有讲究的：**先切窗口、再拆钩子、最后杀进程** —— 窗口文件和 `error.log` 的副本必须
在 `taskkill` 之前落盘，否则进程被杀时那一趟的日志就没了；而 `--uninstall` 必须在进程还活着
的时候跑（它要读/改进程里的 detour 状态）。

产出：
* `C:/temp/c65_<trip>_game.log`  —— marker 窗口（前 N 个 `C65_HIT` 的字节段）
* `C:/temp/c65_<trip>_error.log` —— 该趟的整份 `error.log`
* `C:/temp/c65_<trip>_close.txt` —— 收尾回执（`WINDOW` / `ERRORLOG` / `UNINSTALL` / `KILL`）

用法（Windows）：
    python C:/temp/c65_close.py B 12
"""
from __future__ import annotations

import os
import subprocess
import sys

DRIVER = r"C:\temp\c2_boot_inject.py"
DLL = r"C:\temp\sqjs_c6r1.dll"
WINDOW_TOOL = r"C:\temp\c65_window.py"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    trip, months = argv[0], argv[1]
    receipt = rf"C:\temp\c65_{trip}_close.txt"
    out_lines: list[str] = []

    cut = subprocess.run([sys.executable, WINDOW_TOOL, trip, months],
                         capture_output=True, text=True, timeout=120)
    for line in (cut.stdout or "").splitlines():
        print(line)
        out_lines.append(line)
    if cut.returncode != 0:
        print(f"FAIL window_rc={cut.returncode}")
        out_lines.append(f"FAIL window_rc={cut.returncode}")

    uninstall = subprocess.run([sys.executable, DRIVER, "--uninstall", DLL],
                               capture_output=True, text=True, timeout=180)
    for line in (uninstall.stdout or "").splitlines():
        print(line)
        out_lines.append(line)
    if uninstall.stderr.strip():
        for line in uninstall.stderr.splitlines():
            print("STDERR " + line)

    kill = subprocess.run(["taskkill", "/F", "/IM", "stellaris.exe"],
                          capture_output=True, text=True, timeout=60)
    kill_text = (kill.stdout or "").strip() or (kill.stderr or "").strip()
    print("KILL " + kill_text.replace("\n", " "))
    out_lines.append("KILL " + kill_text.replace("\n", " "))

    with open(receipt, "w", encoding="utf-8", newline="\n") as handle:
        for line in out_lines:
            handle.write(line + "\n")
    print(f"RECEIPT {receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
