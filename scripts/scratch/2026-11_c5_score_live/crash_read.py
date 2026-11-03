"""One-off (2026-11-03): read the host's crash evidence after a dead window."""
import pathlib
import subprocess
import sys

DOCS = pathlib.Path.home() / "Documents/Paradox Interactive/Stellaris"
LOCAL = pathlib.Path.home() / "AppData/Local/Paradox Interactive/Stellaris"


def tail(path: pathlib.Path, lines: int = 30) -> None:
    if not path.is_file():
        print(f"--- {path}: MISSING")
        return
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    print(f"--- {path} ({len(text)} lines, tail {lines})")
    for line in text[-lines:]:
        print(line)


def recent(root: pathlib.Path, pattern: str, limit: int = 6) -> None:
    if not root.is_dir():
        print(f"--- {root}: MISSING")
        return
    files = sorted((p for p in root.rglob(pattern) if p.is_file()),
                   key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
    print(f"--- {root}\\{pattern}: {len(files)} newest")
    for p in files:
        stat = p.stat()
        print(f"{int(stat.st_mtime)} {stat.st_size} {p}")


def events() -> None:
    query = ("*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 3600000]]]")
    cmd = ["wevtutil", "qe", "Application", f"/q:{query}", "/c:8", "/rd:true", "/f:text"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as exc:  # noqa: BLE001 - one-off diagnostic
        print(f"--- events: FAILED {exc}")
        return
    print(f"--- Application errors/warnings (last hour), rc={out.returncode}")
    text = (out.stdout or "") + (out.stderr or "")
    for line in text.splitlines()[:80]:
        print(line)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    tail(DOCS / "logs" / "error.log", 40)
    tail(DOCS / "logs" / "game.log", 20)
    recent(DOCS / "crashes", "*")
    recent(LOCAL, "*")
    events()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
