"""One-off (2026-11-03): what killed the game — application-error events, precisely."""
import subprocess
import sys


def run(*args: str) -> str:
    out = subprocess.run(list(args), capture_output=True, text=True, timeout=90)
    return (out.stdout or "") + (out.stderr or "")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    query = "*[System[(EventID=1000 or EventID=1001) and TimeCreated[timediff(@SystemTime) <= 7200000]]]"
    text = run("wevtutil", "qe", "Application", f"/q:{query}", "/c:10", "/rd:true", "/f:text")
    keep = False
    for line in text.splitlines():
        if line.startswith("Event["):
            keep = False
        if "Date:" in line or "Event[" in line:
            print(line.strip())
        if "错误应用程序名称" in line or "错误模块名称" in line or "异常代码" in line \
                or "错误进程 ID" in line or "报告 ID" in line:
            print("   " + line.strip())
            keep = True
    if not keep:
        print("(no stellaris application-error event for the new process)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
