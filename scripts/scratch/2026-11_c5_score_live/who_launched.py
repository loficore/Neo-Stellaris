"""One-off (2026-11-03): who launched the game, and what else is afoot on the host.

Two agents on one box would invalidate both readings, so this prints the game's
parent chain, the `C:/temp/sqjs_c4*.dll` inventory, our scheduled tasks, and any
agent-side python (session_bridge / c2_* drivers) still running.
"""
import hashlib
import pathlib
import subprocess
import sys

import psutil

TEMP = pathlib.Path("C:/temp")


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    for proc in psutil.process_iter(["pid", "name", "create_time"]):
        if (proc.info["name"] or "").lower() != "stellaris.exe":
            continue
        print(f"game pid={proc.info['pid']} created={int(proc.info['create_time'])}")
        try:
            parents = proc.parents()
        except psutil.Error as exc:
            print(f"  parent=UNREADABLE {exc}")
            parents = []
        for parent in parents[:4]:
            try:
                print(f"  parent pid={parent.pid} name={parent.name()} cmdline={parent.cmdline()}")
            except psutil.Error as exc:
                print(f"  parent pid={parent.pid} UNREADABLE {exc}")

    print("--- C:/temp sqjs dlls")
    for path in sorted(TEMP.glob("sqjs_c4*.dll")):
        stat = path.stat()
        print(f"{int(stat.st_mtime)} {stat.st_size} {path} sha256={sha256(path)[:16]}")

    print("--- python processes")
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        if (proc.info["name"] or "").lower() != "python.exe":
            continue
        line = " ".join(proc.info["cmdline"] or [])
        if any(key in line for key in ("session_bridge", "c2_", "boot_inject", "ns_world")):
            print(f"pid={proc.info['pid']} {line}")

    print("--- our scheduled tasks")
    out = subprocess.run(["schtasks", "/query", "/fo", "LIST"],
                         capture_output=True, text=True, timeout=90)
    current = ""
    for line in (out.stdout or "").splitlines():
        if line.startswith("TaskName:"):
            current = line.split(":", 1)[1].strip()
        elif line.startswith("Status:") and current and "ns_" in current.lower():
            print(f"{current} {line.strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
