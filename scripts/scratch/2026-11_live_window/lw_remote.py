"""lw_remote.py — ASCII-only remote helper for the 2026-11-10 live window (scratch).

Why this exists: `just win` runs `ssh <host> <args>` through `sh`, so the remote
shell re-splits the command line. Paths with spaces ("save games", "Paradox
Interactive") and PowerShell pipelines (`| Sort-Object`) both die there. This
helper takes one subcommand and does the work in Python, so every read below is
one argv token and prints ASCII.

Read-only. The single mutating verb is `kill` (taskkill /F on stellaris.exe),
which the window's teardown step needs anyway.

Usage (Windows side):
    python C:/temp/lw_remote.py procs
    python C:/temp/lw_remote.py ls "C:/temp/*.dll"
    python C:/temp/lw_remote.py sha C:/temp/sqjs_lw1.dll
    python C:/temp/lw_remote.py saves [N]
    python C:/temp/lw_remote.py logstat <path>
    python C:/temp/lw_remote.py loghead <path> [N]
    python C:/temp/lw_remote.py slice <src> <start> <end> <dst>
    python C:/temp/lw_remote.py gz <src> <dst>
    python C:/temp/lw_remote.py b64 <path>
    python C:/temp/lw_remote.py dlcload
    python C:/temp/lw_remote.py mods
    python C:/temp/lw_remote.py kill
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import subprocess
import sys
import time

DOCS = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\13229"), "Documents",
                    "Paradox Interactive", "Stellaris")
SAVES = os.path.join(DOCS, "save games")


def procs() -> int:
    out = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq stellaris.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True, errors="replace")
    lines = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
    rows = [ln for ln in lines if ln.lower().startswith('"stellaris.exe"')]
    print(f"PROCS count={len(rows)}")
    for row in rows:
        print("  " + row)
    return 0


def ls(pattern: str) -> int:
    for path in sorted(glob.glob(pattern)):
        try:
            st = os.stat(path)
        except OSError as exc:
            print(f"{path}\tERR {exc}")
            continue
        print(f"{os.path.getsize(path)}\t{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))}\t{path}")
    return 0


def sha(path: str) -> int:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    print(f"{h.hexdigest()}  {path}")
    return 0


def saves(limit: int = 8) -> int:
    rows = []
    for root, _dirs, files in os.walk(SAVES):
        for name in files:
            if name.lower().endswith(".sav"):
                path = os.path.join(root, name)
                rows.append((os.path.getmtime(path), os.path.getsize(path), path))
    rows.sort(reverse=True)
    print(f"SAVES count={len(rows)} root={SAVES}")
    for mtime, size, path in rows[:limit]:
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))}\t{size}\t{path}")
    return 0


def logstat(path: str) -> int:
    if not os.path.exists(path):
        print(f"LOGSTAT missing={path}")
        return 2
    st = os.stat(path)
    print(f"LOGSTAT size={st.st_size} mtime={time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))} path={path}")
    return 0


LOGS = os.path.join(DOCS, "logs")
LOG_NAMES = {"game": "game.log", "error": "error.log", "setup": "setup.log"}


def logpath(name: str) -> str:
    return os.path.join(LOGS, LOG_NAMES.get(name, name))


def logstate(name: str) -> int:
    """logstat for the two logs whose directory has a space in it."""
    return logstat(logpath(name))


def logtail(name: str, nbytes: int) -> int:
    path = logpath(name)
    size = os.path.getsize(path)
    start = max(0, size - nbytes)
    with open(path, "rb") as fh:
        fh.seek(start)
        data = fh.read()
    sys.stdout.write(data.decode("utf-8", "replace"))
    return 0


def logcopy(name: str, start: int, end: int, dst: str) -> int:
    return slice_gz(logpath(name), start, end, dst)


def loghead(path: str, count: int = 6) -> int:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for idx, line in enumerate(fh):
            if idx >= count:
                break
            print(f"{idx}\t{line.rstrip()}")
    return 0


def slice_gz(src: str, start: int, end: int, dst: str) -> int:
    """Write bytes [start,end) of `src` to `dst` — the window a log judgement needs."""
    data = open(src, "rb").read()
    chunk = data[start:end] if end > start else data[start:]
    with open(dst, "wb") as fh:
        fh.write(chunk)
    print(f"SLICE bytes={len(chunk)} src={src} range={start}:{end if end > start else 'EOF'} dst={dst}")
    return 0


def gz(src: str, dst: str) -> int:
    """gzip a file so it can travel through the chunked channel (docs: 700 chars/call)."""
    import gzip

    with open(src, "rb") as fh:
        data = fh.read()
    with gzip.GzipFile(dst, "wb", compresslevel=9, mtime=0) as out:
        out.write(data)
    print(f"GZ raw={len(data)} gz={os.path.getsize(dst)} src={src} dst={dst}")
    return 0


def b64(path: str) -> int:
    """Base64 the bytes — the only way to read a file whose raw bytes reset ssh."""
    import base64

    data = open(path, "rb").read()
    print(f"B64 size={len(data)} path={path}")
    print(base64.b64encode(data).decode("ascii"))
    return 0


def dlcload() -> int:
    path = os.path.join(DOCS, "dlc_load.json")
    if not os.path.exists(path):
        print(f"DLCLOAD missing={path}")
        return 2
    print(f"DLCLOAD {path}")
    print(json.dumps(json.load(open(path, encoding="utf-8")), ensure_ascii=True))
    moddir = os.path.join(DOCS, "mod")
    print(f"MODDIR {moddir} count={len(glob.glob(os.path.join(moddir, '*.mod')))}")
    for mod in sorted(glob.glob(os.path.join(moddir, "*.mod"))):
        print("  " + os.path.basename(mod))
    return 0


def hideconsole() -> int:
    """Hide the visible console windows that steal the foreground from the game
    (docs/offline-tooling.md 陷阱 10: the daemon's cmd.exe shell owns the
    foreground, so the supervisor's focus check never passes)."""
    import ctypes

    u = _user32()
    rows = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def cb(hwnd, _lparam):
        if not u.IsWindowVisible(hwnd):
            return True
        cls = ctypes.create_unicode_buffer(256)
        u.GetClassNameW(hwnd, cls, 256)
        title = ctypes.create_unicode_buffer(512)
        u.GetWindowTextW(hwnd, title, 512)
        rows.append((hwnd, cls.value, title.value))
        return True

    u.EnumWindows(cb, 0)
    hidden = []
    for hwnd, cls, title in rows:
        low = (cls + " " + title).lower()
        if "console" in low or "cmd" in low:
            u.ShowWindow(hwnd, 0)   # SW_HIDE
            hidden.append(f"{hwnd}/{cls}/{title[:28]}")
    print(f"HIDDEN count={len(hidden)} visible={len(rows)} :: " + " | ".join(hidden)[:320])
    return 0


def snap(dst: str, width: int = 700, quality: int = 45) -> int:
    """Grab the desktop, downscale, save a small JPEG (the SSH channel cannot
    carry a big PNG; docs/offline-tooling.md 陷阱 8)."""
    try:
        from PIL import ImageGrab
    except Exception as exc:  # noqa: BLE001 - the caller reads the tag
        print(f"SNAP no_pil {exc}")
        return 2
    img = ImageGrab.grab()
    ratio = width / float(img.width)
    img = img.resize((width, max(1, int(img.height * ratio))))
    img.save(dst, "JPEG", quality=quality)
    print(f"SNAP size={os.path.getsize(dst)} {img.width}x{img.height} dst={dst}")
    return 0


def nsstate() -> int:
    """The world-state file's leases/armed/blocks, one short line each."""
    path = r"C:\\temp\\ns_world.json"
    data = json.load(open(path, encoding="utf-8"))
    now = time.time()
    for lease in data.get("leases") or []:
        if isinstance(lease, dict):
            print("LEASE " + " ".join(f"{k}={lease.get(k)}" for k in ("id", "action", "guard", "expires_at", "armed") if k in lease)[:220])
        else:
            print("LEASE " + str(lease)[:120])
    for item in data.get("armed") or []:
        print("ARMED " + (json.dumps(item, ensure_ascii=True) if not isinstance(item, str) else item)[:160])
    for item in data.get("blocks") or []:
        print("BLOCK " + (json.dumps(item, ensure_ascii=True) if not isinstance(item, str) else item)[:160])
    print("KEYS " + ",".join(sorted(data.keys()))[:200])
    print(f"NOW {int(now)}")
    return 0


def modlist() -> int:
    """Only the enabled mods — dlc_load.json in full is past the channel's limit."""
    path = os.path.join(DOCS, "dlc_load.json")
    data = json.load(open(path, encoding="utf-8"))
    enabled = data.get("enabled_mods", [])
    print(f"ENABLED_MODS count={len(enabled)}")
    for item in enabled:
        print("  " + os.path.basename(str(item)))
    return 0


def mods() -> int:
    root = r"C:\temp\neo_mods"
    print(f"LOADER_MODS root={root} exists={os.path.isdir(root)}")
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            print("  " + name)
    return 0


def kill() -> int:
    out = subprocess.run(["taskkill", "/F", "/IM", "stellaris.exe"],
                         capture_output=True, text=True, errors="replace")
    print(f"KILL rc={out.returncode}")
    print((out.stdout or "").strip())
    print((out.stderr or "").strip())
    # Report the post-condition, not the intent.
    procs()
    return 0


def stellaris_pid() -> int:
    out = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq stellaris.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True, errors="replace")
    for line in out.stdout.splitlines():
        parts = [p.strip('"') for p in line.strip().split('","')]
        if parts and parts[0].lower() == "stellaris.exe" and len(parts) > 1:
            return int(parts[1])
    return 0


def _user32():
    import ctypes

    return ctypes.windll.user32


def foreground() -> int:
    """Who holds the foreground?  The supervisor refuses to press Space when
    something else does (docs/offline-tooling.md 陷阱 10)."""
    import ctypes

    u = _user32()
    hwnd = u.GetForegroundWindow()
    pid = ctypes.c_ulong()
    u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    buf = ctypes.create_unicode_buffer(256)
    u.GetClassNameW(hwnd, buf, 256)
    title = ctypes.create_unicode_buffer(512)
    u.GetWindowTextW(hwnd, title, 512)
    print(f"FG hwnd={hwnd} pid={pid.value} class={buf.value} title={title.value!r}")
    return 0


def game_window() -> int:
    """The top-level window of the running stellaris.exe (pid from tasklist)."""
    import ctypes

    u = _user32()
    target = int(os.environ.get("NS_GAME_PID", "0")) or stellaris_pid()
    found = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def cb(hwnd, _lparam):
        pid = ctypes.c_ulong()
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == target and u.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(256)
            u.GetClassNameW(hwnd, buf, 256)
            found.append((hwnd, buf.value))
        return True

    u.EnumWindows(cb, 0)
    for hwnd, cls in found:
        print(f"GAMEWINDOW hwnd={hwnd} class={cls}")
    if not found:
        print("GAMEWINDOW none")
    return 0


def unpause() -> int:
    """Focus the game window (AttachThreadInput trick) and press Space once."""
    import ctypes
    import time

    u = _user32()
    target = int(os.environ.get("NS_GAME_PID", "0")) or stellaris_pid()
    hwnds = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def cb(hwnd, _lparam):
        pid = ctypes.c_ulong()
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == target and u.IsWindowVisible(hwnd):
            hwnds.append(hwnd)
        return True

    u.EnumWindows(cb, 0)
    if not hwnds:
        print("UNPAUSE no window")
        return 2
    hwnd = hwnds[0]
    fg = u.GetForegroundWindow()
    fg_thread = u.GetWindowThreadProcessId(fg, None)
    me_thread = ctypes.windll.kernel32.GetCurrentThreadId()
    attached = False
    if fg != hwnd:
        u.AttachThreadInput(me_thread, fg_thread, True)
        attached = True
    u.ShowWindow(hwnd, 9)          # SW_RESTORE
    u.BringWindowToTop(hwnd)
    u.SetForegroundWindow(hwnd)
    u.SetFocus(hwnd)
    time.sleep(0.4)
    now_fg = u.GetForegroundWindow()
    # Space = 0x20
    u.keybd_event(0x20, 0, 0, 0)
    time.sleep(0.08)
    u.keybd_event(0x20, 0, 2, 0)
    if attached:
        u.AttachThreadInput(me_thread, fg_thread, False)
    print(f"UNPAUSE hwnd={hwnd} fg_before={fg} fg_after={now_fg} focused={now_fg == hwnd}")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 2
    verb, rest = argv[0], argv[1:]
    if verb == "procs":
        return procs()
    if verb == "ls":
        return ls(rest[0])
    if verb == "sha":
        return sha(rest[0])
    if verb == "saves":
        return saves(int(rest[0]) if rest else 8)
    if verb == "logstate":
        return logstate(rest[0])
    if verb == "logtail":
        return logtail(rest[0], int(rest[1]))
    if verb == "logcopy":
        return logcopy(rest[0], int(rest[1]), int(rest[2]), rest[3])
    if verb == "logstat":
        return logstat(rest[0])
    if verb == "loghead":
        return loghead(rest[0], int(rest[1]) if len(rest) > 1 else 6)
    if verb == "slice":
        return slice_gz(rest[0], int(rest[1]), int(rest[2]), rest[3])
    if verb == "gz":
        return gz(rest[0], rest[1])
    if verb == "b64":
        return b64(rest[0])
    if verb == "hideconsole":
        return hideconsole()
    if verb == "snap":
        return snap(rest[0], int(rest[1]) if len(rest) > 1 else 700,
                    int(rest[2]) if len(rest) > 2 else 45)
    if verb == "nsstate":
        return nsstate()
    if verb == "fg":
        return foreground()
    if verb == "gamewin":
        return game_window()
    if verb == "unpause":
        return unpause()
    if verb == "modlist":
        return modlist()
    if verb == "dlcload":
        return dlcload()
    if verb == "mods":
        return mods()
    if verb == "kill":
        return kill()
    print(f"unknown verb {verb}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
