"""c65_hold_saves.py — 把「比固定存档更新」的 autosave 移出战役目录（C6-5 对照组的前提）。

**为什么需要这个**：`stellaris.exe --continuelastsave` 不是按 mtime 选存档。2026-11-14 实测：
把固定存档（`2329.07.01`）拷成 `autosave_9999.01.01.sav` 并把 mtime 刷成 now，趟 B 起来仍然
载入 **`2331.01.01`** —— 也就是**趟 A 自己写出来的**那份 autosave。所以「同一份存档字节」这个
对照组前提，靠 mtime 是保不住的；保它的办法是**目录里不能有更新的存档**。

于是这一发：把文件名日期**大于**固定存档日期的 `.sav` 移到 `C:/temp/c65_saves_hold/`
（移动不是删除 —— 那是我们自己的读数产物，留着以后核对），再让 `c65_boot.py` 的守卫在启动前
复查一遍目录。

用法（Windows）：python C:/temp/c65_hold_saves.py
"""
from __future__ import annotations

import os
import re
import shutil

DOCS = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\13229"), "Documents",
                     "Paradox Interactive", "Stellaris")
SAVE_DIR = os.path.join(DOCS, "save games", "_1474567734")
HOLD_DIR = r"C:\temp\c65_saves_hold"
#: 固定存档的**游戏内日期**（文件名里的那一段）。
FROZEN_DATE = (2329, 7, 1)
#: 我们自己拷进去的那份「最新」替身，文件名是哨兵日期，不能当成更新的存档。
TARGET_NAME = "autosave_9999.01.01.sav"
DATE_RE = re.compile(r"(\d{4})\.(\d{2})\.(\d{2})")


def save_date(name: str) -> tuple[int, int, int] | None:
    found = DATE_RE.search(name)
    if not found:
        return None
    return tuple(int(part) for part in found.groups())  # type: ignore[return-value]


def newer_saves() -> list[str]:
    """目录里日期大于固定存档的存档名（不含我们的 `autosave_9999.01.01.sav`）。"""
    if not os.path.isdir(SAVE_DIR):
        return []
    out = []
    for name in sorted(os.listdir(SAVE_DIR)):
        if not name.endswith(".sav") or name == TARGET_NAME:
            continue
        date = save_date(name)
        if date and date > FROZEN_DATE:
            out.append(name)
    return out


def main() -> int:
    print("BEFORE " + ",".join(sorted(n for n in os.listdir(SAVE_DIR) if n.endswith(".sav"))))
    pending = newer_saves()
    if pending:
        os.makedirs(HOLD_DIR, exist_ok=True)
        for name in pending:
            src = os.path.join(SAVE_DIR, name)
            dst = os.path.join(HOLD_DIR, name)
            shutil.move(src, dst)
            print(f"MOVED {name} -> {dst}")
    print("HOLD " + ",".join(pending or ["-"]))
    print("AFTER " + ",".join(sorted(n for n in os.listdir(SAVE_DIR) if n.endswith(".sav"))))
    left = newer_saves()
    hanging = [name for name in left if name != TARGET_NAME]
    if hanging:
        print("FAIL newer_saves_still_present " + ",".join(hanging))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
