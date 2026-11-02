#!/usr/bin/env python3
"""c2_neo_effect_check.py — §93 的判据:`game.log` 里 `Neo: system <id>` 的增量行数。

判据(spec §1):引擎按星系调用我们的 `neo_action` 后,我们调官方 `log` 效果,
于是 `game.log` **每轮每个命中星系一行**。这里只读**增量**:
先记下窗口开始时的字节偏移,窗口结束后数 offset 之后的行 —— 787 个星系 × 游戏时长
会让整份日志膨胀,拿总行数当判据第二天就会假绿。

用法(Windows 侧或本地副本都行,只要路径对):

    python C:/temp/c2_neo_effect_check.py --log "<...>/logs/game.log" --offset 123456 \\
        --marker "Neo: system" --expect 787

判决词:`neo_lines_ok`(精确等于)/ `neo_lines_short`(少)/ `neo_lines_extra`(多)。
多一行也是异常:重复注册、同一星系跑两次、或别的来源也在写这行。
"""
from __future__ import annotations

import argparse
import sys

VERDICTS = ("neo_lines_ok", "neo_lines_short", "neo_lines_extra")


def count_since(path, offset, marker: str):
    """Lines containing `marker` after byte `offset`; `None` when it cannot be measured.

    `offset=None` means "we never recorded the window start" — that is *not* the
    same as 0, and reporting a total as if it were a delta is how a stale log
    turns into a false `ok`.
    """
    if offset is None:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            text = handle.read()
    except OSError:
        return None
    return sum(1 for line in text.splitlines() if marker in line)


def verdict(seen, expected: int) -> str:
    if seen is None:
        return "neo_lines_short"
    if seen == expected:
        return "neo_lines_ok"
    return "neo_lines_short" if seen < expected else "neo_lines_extra"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True)
    parser.add_argument("--offset", type=int, default=None,
                        help="byte offset where the window started (omit = unmeasured)")
    parser.add_argument("--marker", default="Neo: system")
    parser.add_argument("--expect", type=int, required=True)
    args = parser.parse_args(argv)

    seen = count_since(args.log, args.offset, args.marker)
    word = verdict(seen, args.expect)
    print(f"seen={seen} expect={args.expect} marker={args.marker!r} verdict={word}")
    return 0 if word == "neo_lines_ok" else 1


if __name__ == "__main__":
    sys.exit(main())
