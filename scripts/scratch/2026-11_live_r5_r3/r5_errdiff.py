"""r5_errdiff.py — are the two trips' error.logs the same file up to timestamps?

`c6_acceptance.py` only counts `Script Error` / `Unexpected token` lines. C6-5
also wants "no newly added script error", and the pair is only a control group
if the rest of the error log did not move either. This prints the line count,
the number of lines that differ after stripping the `[HH:MM:SS]` prefix, and the
first few differences. ASCII-only summary; the files stay on the host.

Usage (Windows):
    python C:/temp/r5_errdiff.py C:/temp/c6_r5_A_error.log C:/temp/c6_r5_B_error.log
"""
from __future__ import annotations

import re
import sys

_TIME = re.compile(r"^\[\d{2}:\d{2}:\d{2}\]")


def lines(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return [_TIME.sub("[T]", line.rstrip("\n")) for line in handle]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    left, right = lines(argv[0]), lines(argv[1])
    diffs = [(index, a, b) for index, (a, b) in enumerate(zip(left, right)) if a != b]
    print(f"ERRDIFF a_lines={len(left)} b_lines={len(right)} shape_equal={len(left) == len(right)} "
          f"differ_lines={len(diffs)}")
    for index, a, b in diffs[:3]:
        print(f"ERRDIFF line={index}\n  A: {a[:200]}\n  B: {b[:200]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
