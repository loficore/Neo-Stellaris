"""c65_window.py — close a C6-5 trip: turn `game.log` into the 12-pulse window.

The window is defined by the probe, not by wall clock: exactly the first N
`C65_HIT` lines the mod wrote after loading the frozen save. One line per
monthly pulse, so `--months 12` is 12 pulses on the same save in both trips —
that is what makes the pair a control group.

Why not hand the whole `game.log` to `c6_acceptance.py`: `official_markers`
scans every line for standalone uppercase tokens, so a whole log carries the
trip's own event stream (`playerEventId` counter, first-contact events, …) which
has nothing to do with our DLL and would differ between trips. Trimming to the
marker window keeps the comparison on the lines the probe wrote. Same shape as
`r5_window.py` (R5, 2026-11-11).

Byte offsets are read off the file (never re-derived from line numbers) and
printed, so the ledger can cite them. Prints the two error-log counters the C6-5
judgement uses. ASCII only; the files stay on the host.

Usage (Windows):
    python C:/temp/c65_window.py A 12
    python C:/temp/c65_window.py B 12
"""
from __future__ import annotations

import hashlib
import os
import sys

LOGS = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\13229"), "Documents",
                    "Paradox Interactive", "Stellaris", "logs")
NEEDLE = b"C65_HIT"
ERROR_MARKERS = (b"Script Error", b"Unexpected token")


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def line_offsets(data: bytes, needle: bytes) -> list[int]:
    """Start offset of every line containing `needle`."""
    offsets: list[int] = []
    start = 0
    while True:
        index = data.find(needle, start)
        if index < 0:
            return offsets
        offsets.append(data.rfind(b"\n", 0, index) + 1)
        start = data.find(b"\n", index) + 1
        if start == 0:
            return offsets


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    trip, months = argv[0], int(argv[1])
    game = os.path.join(LOGS, "game.log")
    error = os.path.join(LOGS, "error.log")
    with open(game, "rb") as handle:
        data = handle.read()
    offsets = line_offsets(data, NEEDLE)
    print(f"WINDOW trip={trip} game_bytes={len(data)} sha256={sha256(game)} pulses={len(offsets)}")
    if len(offsets) < months:
        print(f"WINDOW error=need_{months}_pulses_got_{len(offsets)}")
        return 2
    start = offsets[0]
    # End = start of the (months+1)-th marker line, so the window holds exactly
    # `months` marker lines. With exactly `months` pulses the window runs to EOF.
    end = offsets[months] if len(offsets) > months else len(data)
    dst = f"C:/temp/c65_{trip}_game.log"
    with open(dst, "wb") as handle:
        handle.write(data[start:end])
    print(f"WINDOW start={start} end={end} bytes={end - start} dst={dst} sha256={sha256(dst)}")
    with open(error, "rb") as handle:
        err = handle.read()
    lines = err.split(b"\n")
    counts = {marker.decode("ascii"): sum(1 for line in lines if marker in line)
              for marker in ERROR_MARKERS}
    err_dst = f"C:/temp/c65_{trip}_error.log"
    with open(err_dst, "wb") as handle:
        handle.write(err)
    print(f"ERRORLOG bytes={len(err)} sha256={sha256(error)} script_error={counts['Script Error']} "
          f"unexpected_token={counts['Unexpected token']} dst={err_dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
