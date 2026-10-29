#!/usr/bin/env python3
"""host_saves.py — 列出主机上的 Stellaris 存档,并把最新的一个复制到 C:\\temp\\current.sav。

一次性的主机侧小工具:用 python 跑就绕开了 `just win` 那层 shell 对引号与 `$` 的破坏。

用法:
    python C:/temp/host_saves.py [--copy]

输出(每行一条):`路径 | 字节数 | mtime` —— 按 mtime 倒序。
`--copy` 会把**最新**的那个复制到 `C:/temp/current.sav`,并打印 `COPIED <path>`。
"""
from __future__ import annotations

import os
import shutil
import sys

CANDIDATES = [
    os.path.expandvars(r"%USERPROFILE%\Documents\Paradox Interactive\Stellaris\save games"),
    os.path.expandvars(r"%USERPROFILE%\OneDrive\Documents\Paradox Interactive\Stellaris\save games"),
    os.path.expandvars(r"%USERPROFILE%\OneDrive\文档\Paradox Interactive\Stellaris\save games"),
    os.path.expandvars(r"%USERPROFILE%\Documents\Paradox Interactive\Stellaris\saved games"),
    r"C:\Users\Public\Documents\Paradox Interactive\Stellaris\save games",
    os.path.expandvars(r"%USERPROFILE%\AppData\Roaming\Paradox Interactive\Stellaris\save games"),
    r"C:\temp",
]


def main() -> int:
    copy = "--copy" in sys.argv
    found = []
    for root in CANDIDATES:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                if not name.lower().endswith(".sav"):
                    continue
                path = os.path.join(dirpath, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                found.append((st.st_mtime, st.st_size, path))
    found.sort(reverse=True)
    for mtime, size, path in found[:20]:
        print(f"{path} | {size} | {mtime:.0f}")
    # The copy target itself must not be a candidate: it would always be the newest.
    skip = {"shot_campaign.sav", "current.sav"}
    candidates = [f for f in found if os.path.basename(f[2]).lower() not in skip]
    if copy and candidates:
        newest = candidates[0][2]
        dst = r"C:\temp\shot_campaign.sav"
        shutil.copyfile(newest, dst)
        print(f"COPIED {newest} -> {dst}")
    elif not found:
        print("NO_SAVES_FOUND")
    return 0


if __name__ == "__main__":
    sys.exit(main())
