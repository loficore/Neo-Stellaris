"""c65_modules.py — 一行读数：某个 pid 里有没有 `sqjs*` 模块。

C6-5 的对照组要求两趟只差「DLL 装没装」，所以这条读数是判据的一部分，不是附带说明：

* 趟 A（base）：`SQJS=0`，另外报总 DLL 数，证明「列表读到了、只是没有我们的 DLL」；
* 趟 B（with）：`SQJS>=1`，并打印命中模块的 pid/文件名。

判读陷阱：只凭「没跑注入脚本」不算证明 base 趟干净 —— 模块列表才是读数。

用法（Windows）：python C:/temp/c65_modules.py [pid]
"""
from __future__ import annotations

import subprocess
import sys


def pids() -> list[int]:
    out = subprocess.check_output(["tasklist", "/fi", "imagename eq stellaris.exe",
                                   "/fo", "csv", "/nh"], text=True, errors="replace")
    found = []
    for line in out.splitlines():
        parts = [part.strip('" ') for part in line.split('","')]
        if len(parts) >= 2 and parts[0].lower().startswith("stellaris.exe"):
            found.append(int(parts[1]))
    return found


def main(argv: list[str]) -> int:
    import psutil

    targets = [int(argv[0])] if argv else pids()
    if not targets:
        print("SQJS=- ERROR=no_process")
        return 2
    for pid in targets:
        try:
            proc = psutil.Process(pid)
            maps = proc.memory_maps()
        except Exception as exc:  # noqa: BLE001 - 读数工具，报错就是读数
            print(f"PID={pid} SQJS=- ERROR={exc.__class__.__name__}")
            continue
        hits = [m.path for m in maps if "sqjs" in m.path.lower() or "quickjs" in m.path.lower()]
        dlls = [m for m in maps if m.path.lower().endswith(".dll")]
        print(f"PID={pid} SQJS={len(hits)} DLLS={len(dlls)} "
              f"HITS={','.join(sorted({p.rsplit(chr(92), 1)[-1] for p in hits})) or '-'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
