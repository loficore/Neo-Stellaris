"""c65_count.py — 一次读数：这一趟走到第几个 `C65_HIT` 了。

窗口长度是**游戏月**，不是墙钟；弹窗会把模拟暂停，所以「等 12 个 marker」得反复读这一行。
把读数做成脚本是为了让 ssh 断线或 shell 超时都不会让读数本身变得不可复现。

用法（Windows）：python C:/temp/c65_count.py [needle]
输出：`COUNT=<n> LAST=<最后一个 marker 行的游戏日期或 ->`
"""
from __future__ import annotations

import os
import re
import sys

LOGS = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\13229"), "Documents",
                    "Paradox Interactive", "Stellaris", "logs")
DATE_RE = re.compile(r"\[(\d{3,4}\.\d{1,2}\.\d{1,2})\]")


def main(argv: list[str]) -> int:
    needle = argv[0] if argv else "C65_HIT"
    path = os.path.join(LOGS, "game.log")
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = [line for line in handle if needle in line]
    except OSError as exc:
        print(f"COUNT=- ERROR={exc.__class__.__name__}")
        return 2
    last = "-"
    if lines:
        found = DATE_RE.findall(lines[-1])
        last = found[-1] if found else "-"
    print(f"COUNT={len(lines)} LAST={last}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
