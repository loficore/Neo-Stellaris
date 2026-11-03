"""One-off (2026-11-03): list Stellaris saves newest-first, stage one for scp.

The host path contains spaces, which `just win` mangles twice (local shell, then
the remote POSIX shell).  A script takes argv with no spaces at all.
"""
import argparse
import hashlib
import pathlib
import shutil

ROOT = pathlib.Path.home() / "Documents/Paradox Interactive/Stellaris/save games"


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--stage", default=None, help="copy the newest save here")
    args = parser.parse_args()

    root = pathlib.Path(args.root)
    if not root.is_dir():
        print(f"NO_SAVE_DIR {root}")
        return 2
    saves = sorted(root.rglob("*.sav"), key=lambda f: f.stat().st_mtime, reverse=True)
    print(f"save_dir={root} count={len(saves)}")
    for path in saves[:args.limit]:
        stat = path.stat()
        print(f"{int(stat.st_mtime)} {stat.st_size} {path}")
    if args.stage and saves:
        newest = saves[0]
        target = pathlib.Path(args.stage)
        shutil.copy2(newest, target)
        print(f"staged={target} sha256={sha256(target)}")
        print(f"source_sha256={sha256(newest)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
