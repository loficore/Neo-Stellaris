"""r5_host.py — host-side file plumbing for the R5/R3 window (scratch).

Why this exists: `just win` goes through `sh` and re-splits the command line, so
any path with a space ("save games", "Paradox Interactive") dies before Python
sees it. This helper knows the two directories internally and takes only
space-free arguments. Output is ASCII-only, one line per fact.

Read-mostly. The mutating verbs are the ones the R5 save discipline needs:
`freeze` (autosave -> C:/temp base copy), `park` (move every game-written .sav
out of `save games/`), `restore` (put the frozen base back as the only save),
`empty` (clear a stale command file), `rm`, and `kill` (teardown).

Usage (Windows):
    python C:/temp/r5_host.py procs
    python C:/temp/r5_host.py freeze C:/temp/c6_r5_base.sav
    python C:/temp/r5_host.py park C:/temp/r5_parked_A
    python C:/temp/r5_host.py restore C:/temp/c6_r5_base.sav _1474567734 autosave_2314.07.01.sav
    python C:/temp/r5_host.py saves 6
    python C:/temp/r5_host.py stat <path>
    python C:/temp/r5_host.py sha <path>
    python C:/temp/r5_host.py cat <path>
    python C:/temp/r5_host.py empty <path>
    python C:/temp/r5_host.py rm <path>
    python C:/temp/r5_host.py copy <src> <dst>
    python C:/temp/r5_host.py newest <dst>
    python C:/temp/r5_host.py kill
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import time

DOCS = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\13229"), "Documents",
                    "Paradox Interactive", "Stellaris")
SAVES = os.path.join(DOCS, "save games")
LOGS = os.path.join(DOCS, "logs")


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sav_rows() -> list[tuple[float, int, str]]:
    rows = []
    for root, _dirs, files in os.walk(SAVES):
        for name in files:
            if name.lower().endswith(".sav"):
                path = os.path.join(root, name)
                rows.append((os.path.getmtime(path), os.path.getsize(path), path))
    rows.sort(reverse=True)
    return rows


def newest_sav() -> str:
    rows = sav_rows()
    if not rows:
        raise SystemExit("R5 no save found")
    return rows[0][2]


def cmd_info(path: str) -> int:
    if not os.path.exists(path):
        print(f"INFO missing={path}")
        return 2
    st = os.stat(path)
    print(f"INFO bytes={st.st_size} sha256={sha256(path)} mtime="
          f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))} path={path}")
    return 0


def cmd_saves(limit: int) -> int:
    rows = sav_rows()
    print(f"SAVES count={len(rows)} root={SAVES}")
    for mtime, size, path in rows[:limit]:
        print(f"  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))}\t{size}\t{path}")
    return 0


def cmd_freeze(dst: str) -> int:
    src = newest_sav()
    shutil.copyfile(src, dst)
    print(f"FREEZE src={src} dst={dst} bytes={os.path.getsize(dst)} sha256={sha256(dst)}")
    return 0


def cmd_park(dstroot: str) -> int:
    moved = 0
    for _mtime, _size, path in sav_rows():
        campaign = os.path.basename(os.path.dirname(path))
        target_dir = os.path.join(dstroot, campaign)
        os.makedirs(target_dir, exist_ok=True)
        target = os.path.join(target_dir, os.path.basename(path))
        if os.path.exists(target):
            stem, ext = os.path.splitext(target)
            target = f"{stem}.{int(time.time())}{ext}"
        shutil.move(path, target)
        moved += 1
    print(f"PARK dst={dstroot} moved={moved} remaining={len(sav_rows())}")
    return 0


def cmd_restore(src: str, campaign: str, name: str) -> int:
    target_dir = os.path.join(SAVES, campaign)
    os.makedirs(target_dir, exist_ok=True)
    target = os.path.join(target_dir, name)
    shutil.copyfile(src, target)
    os.utime(target, None)
    print(f"RESTORE src={src} dst={target} bytes={os.path.getsize(target)} "
          f"sha256={sha256(target)} total={len(sav_rows())}")
    return 0


def cmd_copy(src: str, dst: str) -> int:
    shutil.copyfile(src, dst)
    print(f"COPY src={src} dst={dst} bytes={os.path.getsize(dst)} sha256={sha256(dst)}")
    return 0


def cmd_install_mod(src_dir: str, name: str) -> int:
    """Put a local mod tree in `mod/<name>/` and write the outer `mod/<name>.mod`."""
    target = os.path.join(DOCS, "mod", name)
    if os.path.isdir(target):
        shutil.rmtree(target)
    shutil.copytree(src_dir, target)
    descriptor_src = os.path.join(target, "descriptor.mod")
    with open(descriptor_src, encoding="utf-8") as handle:
        text = handle.read()
    if 'path="' not in text:
        text = text.rstrip("\n") + f'\npath="{target.replace(os.sep, "/")}"\n'
    outer = os.path.join(DOCS, "mod", name + ".mod")
    with open(outer, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    print(f"MODINSTALL name={name} dir={target} outer={outer} "
          f"files={sum(len(f) for _, _, f in os.walk(target))}")
    return 0


def cmd_remove_mod(name: str) -> int:
    target = os.path.join(DOCS, "mod", name)
    outer = os.path.join(DOCS, "mod", name + ".mod")
    if os.path.isdir(target):
        shutil.rmtree(target)
    if os.path.exists(outer):
        os.remove(outer)
    print(f"MODREMOVE name={name} dir_exists={os.path.isdir(target)} "
          f"outer_exists={os.path.exists(outer)}")
    return 0


def cmd_modcat(name: str) -> int:
    path = os.path.join(DOCS, "mod", name + ".mod")
    print(f"MODCAT {path}")
    return cmd_cat(path)


def cmd_dlcload() -> int:
    import json
    path = os.path.join(DOCS, "dlc_load.json")
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    print(f"DLCLOAD enabled={data.get('enabled_mods')} disabled_dlcs={len(data.get('disabled_dlcs') or [])}")
    return 0


def cmd_grephead(path: str, needle: str, limit: int) -> int:
    shown = 0
    hits = 0
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if needle in line:
                hits += 1
                if shown < limit:
                    print(line.rstrip("\n"))
                    shown += 1
    print(f"GREP needle={needle} hits={hits} shown={shown}")
    return 0


def cmd_grepgame(needle: str, limit: int) -> int:
    return cmd_grephead(os.path.join(LOGS, "game.log"), needle, limit)


def cmd_greperror(needle: str, limit: int) -> int:
    return cmd_grephead(os.path.join(LOGS, "error.log"), needle, limit)


def cmd_logstat(name: str) -> int:
    path = os.path.join(LOGS, name + ".log")
    st = os.stat(path)
    print(f"LOGSTAT name={name} size={st.st_size} sha256={sha256(path)} mtime="
          f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))} path={path}")
    return 0


def cmd_cat(path: str) -> int:
    with open(path, encoding="utf-8", errors="replace") as handle:
        sys.stdout.write(handle.read())
    return 0


def cmd_empty(path: str) -> int:
    with open(path, "w", encoding="ascii") as handle:
        handle.write("")
    print(f"EMPTY path={path} bytes={os.path.getsize(path)}")
    return 0


def cmd_rm(path: str) -> int:
    try:
        os.remove(path)
        print(f"RM path={path}")
    except FileNotFoundError:
        print(f"RM absent={path}")
    return 0


def cmd_procs() -> int:
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq stellaris.exe",
                          "/FO", "CSV", "/NH"], capture_output=True, text=True,
                         errors="replace", check=False)
    rows = [line.strip() for line in out.stdout.splitlines()
            if line.strip().lower().startswith('"stellaris.exe"')]
    print(f"PROCS count={len(rows)}")
    for row in rows:
        print("  " + row)
    return 0


def cmd_kill() -> int:
    out = subprocess.run(["taskkill", "/F", "/IM", "stellaris.exe"],
                         capture_output=True, text=True, errors="replace", check=False)
    print(f"KILL rc={out.returncode} stdout={(out.stdout or '').strip()} "
          f"stderr={(out.stderr or '').strip()}")
    return cmd_procs()


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    verb, rest = argv[0], argv[1:]
    if verb == "procs":
        return cmd_procs()
    if verb == "saves":
        return cmd_saves(int(rest[0]) if rest else 6)
    if verb == "freeze":
        return cmd_freeze(rest[0])
    if verb == "park":
        return cmd_park(rest[0])
    if verb == "restore":
        return cmd_restore(rest[0], rest[1], rest[2])
    if verb == "stat" or verb == "info" or verb == "sha":
        return cmd_info(rest[0])
    if verb == "copy" or verb == "cp":
        return cmd_copy(rest[0], rest[1])
    if verb == "cat":
        return cmd_cat(rest[0])
    if verb == "empty":
        return cmd_empty(rest[0])
    if verb == "rm":
        return cmd_rm(rest[0])
    if verb == "newest":
        return cmd_copy(newest_sav(), rest[0])
    if verb == "kill":
        return cmd_kill()
    if verb == "install_mod":
        return cmd_install_mod(rest[0], rest[1])
    if verb == "remove_mod":
        return cmd_remove_mod(rest[0])
    if verb == "modcat":
        return cmd_modcat(rest[0])
    if verb == "dlcload":
        return cmd_dlcload()
    if verb == "grepgame":
        return cmd_grepgame(rest[0], int(rest[1]) if len(rest) > 1 else 5)
    if verb == "greperror":
        return cmd_greperror(rest[0], int(rest[1]) if len(rest) > 1 else 5)
    if verb == "logstat":
        return cmd_logstat(rest[0])
    if verb == "grephead":
        return cmd_grephead(rest[0], rest[1], int(rest[2]) if len(rest) > 2 else 10)
    print(f"unknown verb {verb}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
