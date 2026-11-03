"""One-off (2026-11-03): read the other driver's leftovers + every python on the box."""
import pathlib
import sys

import psutil

TEMP = pathlib.Path("C:/temp")


def show(name: str, limit: int = 40) -> None:
    path = TEMP / name
    print(f"--- {path}")
    if not path.is_file():
        print("MISSING")
        return
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[:limit]:
        print(line)


def pythons() -> None:
    print("--- python processes (all)")
    for proc in psutil.process_iter(["pid", "name", "create_time", "cmdline"]):
        if "python" not in (proc.info["name"] or "").lower():
            continue
        print(f"pid={proc.info['pid']} created={int(proc.info['create_time'] or 0)} "
              f"{' '.join(proc.info['cmdline'] or [])}")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    pythons()
    show("launch_only.py")
    show("load_only.py")
    show("c1_result.log")
    show("ns_game_cmd.txt", 5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
