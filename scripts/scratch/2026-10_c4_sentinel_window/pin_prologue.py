#!/usr/bin/env python3
"""pin_prologue —— 打印 `0x3B01A0`(donor 表 slot[2])的 24 字节原前序。

C4 证人窗口(§57.4 第三档)的靶子偏移。install 侧的前置指纹逐字节比对这 24 字节,
所以它们必须来自 exe 拷贝本身,而不是任何反汇编的转述:本脚本就是那份指纹的**权威产出**。

口径照仓库既有离线 PE 读法:`disrva.resolve_exe()` 走 `NS_STELLARIS_EXE` →
`/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe` → `D:\SteamLibrary\…` 候选链,
`disrva.rd()` 用节表把 RVA 折成文件偏移并顺带报出它落在哪一节。

跑法:
    python3 scripts/scratch/2026-10_c4_sentinel_window/pin_prologue.py [rva_hex] [count]

默认 rva = `3b01a0`,count = 24。输出就一行小写十六进制、空格分隔;另两行是出处
(读到的文件、命中的节名),便于把指纹记进文档时同时钉住来源。

**退出码**:0 = 读到满 24 字节且落在可执行节;1 = 读到的字节不够,或命中的节名不是
`.text`(那是「靶子读错」的发现,不是成功);2 = 调用形态不对(exe 找不到 / rva 非十六进制)。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from disrva import rd, resolve_exe  # noqa: E402

DEFAULT_RVA = 0x3B01A0
PROLOGUE_BYTES = 24
CODE_SECTION = ".text"


def prologue(rva: int, count: int) -> tuple[bytes, str]:
    """(前序字节, 命中的节名)。rd() 对越界 RVA 返回 (b'', '?'),这里原样透出。"""
    return rd(rva, count)


def main(argv: list[str]) -> int:
    exe = resolve_exe()
    if exe is None:
        print("no stellaris.exe on the NS_STELLARIS_EXE candidate chain", file=sys.stderr)
        return 2
    try:
        rva = int(argv[1], 16) if len(argv) > 1 else DEFAULT_RVA
        count = int(argv[2], 16) if len(argv) > 2 else PROLOGUE_BYTES
    except ValueError:
        print("usage: pin_prologue.py [rva_hex] [count_hex]", file=sys.stderr)
        return 2

    data, section = prologue(rva, count)
    print(f"# exe={exe}")
    print(f"# rva=0x{rva:x} bytes={len(data)}/{count} section={section}")
    print(" ".join(f"{b:02x}" for b in data))
    if len(data) < count:
        print(f"short read: {len(data)} < {count} — rva outside every section", file=sys.stderr)
        return 1
    if section != CODE_SECTION:
        print(f"unexpected section {section!r}, expected {CODE_SECTION!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
