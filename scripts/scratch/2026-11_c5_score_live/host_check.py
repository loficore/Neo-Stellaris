"""One-off (2026-11-03): host-side facts for the C5-SCORE window.

`just win` cannot carry quoted one-liners (local sh splits, the host shell is
PowerShell), so every read goes through a script with space-free argv.

  --exe PATH     report whether the game binary exists
  --logs         game.log / error.log size + mtime (the window's byte offsets)
  --procs        stellaris.exe / Steam processes
"""
import argparse
import pathlib

import psutil

DOCS = pathlib.Path.home() / "Documents/Paradox Interactive/Stellaris"
LOG_DIR = DOCS / "logs"


def report_exe(path: str) -> None:
    p = pathlib.Path(path)
    print(f"exe={p} exists={p.is_file()} size={p.stat().st_size if p.is_file() else -1}")


def report_logs() -> None:
    for name in ("game.log", "error.log"):
        p = LOG_DIR / name
        if not p.is_file():
            print(f"{name}=MISSING path={p}")
            continue
        stat = p.stat()
        print(f"{name} bytes={stat.st_size} mtime={int(stat.st_mtime)} path={p}")


def report_procs() -> None:
    for proc in psutil.process_iter(["pid", "name", "create_time"]):
        name = (proc.info["name"] or "").lower()
        if name in ("stellaris.exe", "steam.exe", "steamwebhelper.exe"):
            print(f"pid={proc.info['pid']} name={proc.info['name']} "
                  f"created={int(proc.info['create_time'] or 0)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", default=None)
    parser.add_argument("--logs", action="store_true")
    parser.add_argument("--procs", action="store_true")
    args = parser.parse_args()
    if args.exe:
        report_exe(args.exe)
    if args.logs:
        report_logs()
    if args.procs:
        report_procs()
    if not (args.exe or args.logs or args.procs):
        report_logs()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
