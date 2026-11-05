#!/usr/bin/env python3
"""c2_neo_effect_check.py — §93 的判据:`game.log` 里 `Neo: system <id>` 的增量行数。

判据(spec §1):引擎按星系调用我们的 `neo_action` 后,我们调官方 `log` 效果,
于是 `game.log` **每轮每个命中星系一行**。这里只读**增量**:
先记下窗口开始时的字节偏移,窗口结束后数 offset 之后的行 —— 787 个星系 × 游戏时长
会让整份日志膨胀,拿总行数当判据第二天就会假绿。

用法(Windows 侧或本地副本都行,只要路径对):

    python C:/temp/c2_neo_effect_check.py --log "<...>/logs/game.log" --offset 123456 \\
        --marker "Neo: system" --expect 787

判决词:`neo_lines_ok`(精确等于)/ `neo_lines_short`(少)/ `neo_lines_extra`(多)/
`neo_lines_unmeasured`(没量到:`--offset` 缺省或日志读不了)。
多一行也是异常:重复注册、同一星系跑两次、或别的来源也在写这行。
"""
from __future__ import annotations

import argparse
import re
import sys

VERDICTS = ("neo_lines_ok", "neo_lines_short", "neo_lines_extra", "neo_lines_unmeasured")


def count_since(path, offset, marker: str):
    """Lines containing `marker` after byte `offset`; `None` when it cannot be measured.

    `offset=None` means "we never recorded the window start" — that is *not* the
    same as 0, and reporting a total as if it were a delta is how a stale log
    turns into a false `ok`.
    """
    if offset is None:
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            text = handle.read()
    except OSError:
        return None
    return sum(1 for line in text.splitlines() if marker in line)


_ID_RE = {
    marker: re.compile(re.escape(marker) + r"\s+(\d+)") for marker in ("Neo: system",)
}


def histogram(path, offset, marker: str):
    """`{id: occurrences}` for marker lines after `offset`; `None` when unmeasurable.

    This is the reading behind §93.4's strongest sentence ("787 ids, each
    exactly 12 times") — line counts alone cannot tell one-line-per-system from
    twelve lines for one system.
    """
    if offset is None:
        return None
    pattern = _ID_RE.get(marker) or re.compile(re.escape(marker) + r"\s+(\d+)")
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            text = handle.read()
    except OSError:
        return None
    counts: dict = {}
    for line in text.splitlines():
        match = pattern.search(line)
        if match:
            value = int(match.group(1))
            counts[value] = counts.get(value, 0) + 1
    return counts


def verdict(seen, expected: int) -> str:
    if seen is None:
        # An unmeasured window is an *environment* failure, not evidence that
        # too few lines were written (review M-6).  Still never `ok`.
        return "neo_lines_unmeasured"
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
    parser.add_argument("--histogram", action="store_true",
                        help="also print ids=<n> occurrences_min_max=<a>-<b>")
    args = parser.parse_args(argv)

    seen = count_since(args.log, args.offset, args.marker)
    word = verdict(seen, args.expect)
    print(f"seen={seen} expect={args.expect} marker={args.marker!r} verdict={word}")
    if args.histogram:
        counts = histogram(args.log, args.offset, args.marker)
        if counts:
            values = list(counts.values())
            print(f"ids={len(counts)} occurrences_min_max={min(values)}-{max(values)}")
        else:
            print("ids=0 occurrences_min_max=0-0")
    return 0 if word == "neo_lines_ok" else 1


if __name__ == "__main__":
    sys.exit(main())
