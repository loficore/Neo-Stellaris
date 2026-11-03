"""One-off (2026-11-03): show/backup the neo_ps_probe test mod on the host.

The Documents path has spaces, so `just win` cannot carry it.  Prints:
  - `dlc_load.json`'s enabled_mods (the only list the game reads, evidence §84.1)
  - the mod descriptor's name/path/version
  - the events file's sha256 + size, and backs it up on request
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import sys

DOCS = pathlib.Path.home() / "Documents/Paradox Interactive/Stellaris"
MOD_DIR = DOCS / "mod" / "neo_ps_probe"
EVENTS = MOD_DIR / "events" / "neo_ps_probe_events.txt"


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup", default=None, help="copy the events file here")
    parser.add_argument("--print-events", action="store_true")
    args = parser.parse_args()

    load = DOCS / "dlc_load.json"
    if load.is_file():
        data = json.loads(load.read_text(encoding="utf-8", errors="replace"))
        print(f"enabled_mods={data.get('enabled_mods')}")
    else:
        print(f"NO_DLC_LOAD {load}")

    descriptor = MOD_DIR / "descriptor.mod"
    if descriptor.is_file():
        print(f"descriptor=present sha256={sha256(descriptor)}")
        print(descriptor.read_text(encoding="utf-8", errors="replace"))
    else:
        print(f"NO_DESCRIPTOR {descriptor}")

    if EVENTS.is_file():
        print(f"events={EVENTS} size={EVENTS.stat().st_size} sha256={sha256(EVENTS)}")
        if args.print_events:
            print("--- events ---")
            print(EVENTS.read_text(encoding="utf-8", errors="replace"))
    else:
        print(f"NO_EVENTS {EVENTS}")

    if args.backup and EVENTS.is_file():
        target = pathlib.Path(args.backup)
        shutil.copy2(EVENTS, target)
        print(f"backup={target} sha256={sha256(target)} size={target.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
