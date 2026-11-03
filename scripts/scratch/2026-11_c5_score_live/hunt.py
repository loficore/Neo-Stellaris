"""One-off (2026-11-03): hunt for whoever created C:/temp/sqjs_c46.dll and launched the game.

Reads only: recent files in C:/temp, leftover bridge .cmd payloads, scheduled tasks
run today, established SSH peers, and the PowerShell history tail.
"""
import datetime
import pathlib
import subprocess
import sys

TEMP = pathlib.Path("C:/temp")
NOW = datetime.datetime.now()


def recent_files(minutes: int = 40) -> None:
    print(f"--- C:/temp files in the last {minutes} min")
    cutoff = (NOW - datetime.timedelta(minutes=minutes)).timestamp()
    rows = [p for p in TEMP.iterdir() if p.is_file() and p.stat().st_mtime >= cutoff]
    for path in sorted(rows, key=lambda p: p.stat().st_mtime):
        stat = path.stat()
        stamp = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%H:%M:%S")
        print(f"{stamp} {stat.st_size} {path.name}")


def cmd_payloads() -> None:
    print("--- C:/temp *.cmd")
    for path in sorted(TEMP.glob("*.cmd")):
        stat = path.stat()
        stamp = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%m-%d %H:%M:%S")
        body = path.read_text(encoding="utf-8", errors="replace").strip().replace("\n", " | ")
        print(f"{stamp} {path.name}: {body[:300]}")


def tasks_today() -> None:
    print("--- scheduled tasks that ran in the last 2 hours")
    out = subprocess.run(["schtasks", "/query", "/fo", "LIST", "/v"],
                         capture_output=True, text=True, timeout=120)
    text = (out.stdout or "")
    blocks = text.split("\n\n")
    cutoff = NOW - datetime.timedelta(hours=2)
    for block in blocks:
        name = action = last = ""
        for line in block.splitlines():
            if line.startswith("TaskName:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Task To Run:"):
                action = line.split(":", 1)[1].strip()
            elif line.startswith("Last Run Time:"):
                last = line.split(":", 1)[1].strip()
        if not name or not last:
            continue
        for fmt in ("%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
            try:
                when = datetime.datetime.strptime(last, fmt)
                break
            except ValueError:
                when = None
        if when and when >= cutoff:
            print(f"{last} {name} -> {action[:200]}")


def ssh_peers() -> None:
    print("--- established :22 (netstat)")
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=60)
    for line in (out.stdout or "").splitlines():
        if ":22 " in line and "ESTABLISHED" in line.upper():
            print(line.strip())


def ps_history() -> None:
    path = pathlib.Path.home() / "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
    print(f"--- {path}")
    if not path.is_file():
        print("MISSING")
        return
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-25:]:
        print(line)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    recent_files()
    cmd_payloads()
    tasks_today()
    ssh_peers()
    ps_history()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
