"""ns_admin.py — ASCII-only remote admin helper for the 2026-11 live window.

Why this exists: the Windows box runs in a cp936 locale, and the OpenSSH channel
drops with `Connection reset by peer` whenever a child writes bytes that are not
valid UTF-8 (measured: `cmd /c dir C:\\temp` kills the session after the first
Chinese line).  Every read below therefore re-encodes its output to ASCII with
`backslashreplace`, so a Chinese path or a cp936 error message shows up as
`\\uXXXX` escapes instead of killing the channel.

Read-mostly.  The mutating verbs (`cp`, `rm`, `rmdir`, `backup-dlc`,
`restore-dlc`) exist because the shot's teardown needs them, and doing them with
`cmd /c copy` over ssh re-parses quotes through two shells.

Usage (Windows side):
    python C:/temp/ns_admin.py procs
    python C:/temp/ns_admin.py sha C:/temp/sqjs_lw2.dll
    python C:/temp/ns_admin.py stat "C:/Users/.../logs/game.log"
    python C:/temp/ns_admin.py head <path> 20
    python C:/temp/ns_admin.py tail <path> 40
    python C:/temp/ns_admin.py count <path> <regex>
    python C:/temp/ns_admin.py read <path> [maxbytes]
    python C:/temp/ns_admin.py ls <dir>
    python C:/temp/ns_admin.py cp <src> <dst>
    python C:/temp/ns_admin.py rm <path>
    python C:/temp/ns_admin.py rmdir <path>
    python C:/temp/ns_admin.py backup-dlc
    python C:/temp/ns_admin.py restore-dlc <backup>
    python C:/temp/ns_admin.py kill
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

DOCS = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\13229"), "Documents",
                    "Paradox Interactive", "Stellaris")
DLC_LOAD = os.path.join(DOCS, "dlc_load.json")


def out(text: str = "") -> None:
    sys.stdout.write(str(text).encode("ascii", "backslashreplace").decode("ascii") + "\n")


def procs() -> int:
    res = subprocess.run(["tasklist", "/FI", "IMAGENAME eq stellaris.exe", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True, errors="replace")
    rows = [ln.strip() for ln in res.stdout.splitlines()
            if ln.strip().lower().startswith('"stellaris.exe"')]
    out(f"PROCS count={len(rows)}")
    for row in rows:
        out("  " + row)
    return 0


def sha(path: str) -> int:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    out(f"{h.hexdigest()}  {path}")
    return 0


def stat(path: str) -> int:
    try:
        st = os.stat(path)
    except OSError as exc:
        out(f"STAT missing path={path} err={type(exc).__name__}")
        return 2
    out(f"STAT path={path} size={st.st_size} mtime={int(st.st_mtime)}")
    return 0


def head(path: str, n: int) -> int:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i >= n:
                break
            out(line.rstrip("\n"))
    return 0


def tail(path: str, n: int) -> int:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    for line in lines[-n:]:
        out(line.rstrip("\n"))
    return 0


def count(path: str, pattern: str) -> int:
    rx = re.compile(pattern)
    hits = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if rx.search(line):
                hits += 1
    out(f"COUNT pattern={pattern} hits={hits}")
    return 0


def grep(path: str, pattern: str, limit: int = 12) -> int:
    """Matching lines only, clipped — the channel cannot carry more than ~2 KB."""
    rx = re.compile(pattern)
    shown = 0
    total = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if rx.search(line):
                total += 1
                if shown < limit:
                    out(line.rstrip("\n")[:200])
                    shown += 1
    out(f"GREP pattern={pattern} total={total} shown={shown}")
    return 0


def read(path: str, maxbytes: int = 1 << 22) -> int:
    with open(path, "rb") as fh:
        data = fh.read(maxbytes)
    out(data.decode("utf-8", "replace"))
    return 0


def pngascii(path: str, cols: int = 78, rows: int = 26, x0: float = 0.0, x1: float = 1.0,
             y0: float = 0.0, y1: float = 1.0, page: int = 0) -> int:
    """Render a PNG as ASCII luminance blocks (pure stdlib zlib).

    Why: the ssh channel cannot carry ~400 KB, and `scp` downloads are refused by
    this host, so the only way to look at the screen is to print it small.
    """
    import struct
    import zlib

    data = open(path, "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    pos = 8
    idat = b""
    w = h = bitdepth = colortype = interlace = 0
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if ctype == b"IHDR":
            w, h, bitdepth, colortype, _comp, _filt, interlace = struct.unpack(">IIBBBBB", body)
        elif ctype == b"IDAT":
            idat += body
        elif ctype == b"IEND":
            break
    assert bitdepth == 8 and interlace == 0, f"unsupported png {bitdepth}/{interlace}"
    channels = {0: 1, 2: 3, 4: 2, 6: 4}[colortype]
    raw = zlib.decompress(idat)
    stride = w * channels
    prev = bytearray(stride)
    grid = [[0] * cols for _ in range(rows)]
    counts = [[0] * cols for _ in range(rows)]
    off = 0
    for y in range(h):
        ftype = raw[off]
        off += 1
        line = bytearray(raw[off:off + stride])
        off += stride
        if ftype == 1:
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                a = line[i - channels] if i >= channels else 0
                b = prev[i]
                c = prev[i - channels] if i >= channels else 0
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
        prev = line
        if y < int(y0 * h) or y >= int(y1 * h):
            continue
        ry = (y - int(y0 * h)) * rows // max(1, int(y1 * h) - int(y0 * h))
        for x in range(int(x0 * w), int(x1 * w)):
            i = x * channels
            cx = (x - int(x0 * w)) * cols // max(1, int(x1 * w) - int(x0 * w))
            grid[ry][cx] += (line[i] + line[i + 1] + line[i + 2]) // 3 if channels >= 3 else line[i]
            counts[ry][cx] += 1
    ramp = " .:-=+*#%@"
    out(f"ASCII {path} {w}x{h} crop=({x0},{y0})-({x1},{y1}) -> {cols}x{rows} page={page}")
    half = rows // 2
    lo, hi = (0, half) if page == 0 else (half, rows)
    for ry in range(lo, hi):
        row = ""
        for rx in range(cols):
            c = counts[ry][rx] or 1
            v = grid[ry][rx] // c
            row += ramp[min(len(ramp) - 1, v * len(ramp) // 256)]
        out(row)
    return 0


def b64(path: str, maxbytes: int = 1 << 26) -> int:
    """Base64 a file onto stdout.

    Why: this host's sshd resets the channel on `scp` *downloads* (uploads are
    fine), so the only way out is the exec channel, and it only survives ASCII.
    """
    import base64
    with open(path, "rb") as fh:
        data = fh.read(maxbytes)
    out("B64BEGIN " + str(len(data)))
    for i in range(0, len(data), 3 * 1024):
        out(base64.b64encode(data[i:i + 3 * 1024]).decode("ascii"))
    out("B64END")
    return 0


def wins(want_pid: str = "0") -> int:
    """Top-level windows: pid, visibility, rect, title. ASCII-escaped.

    The sshd channel dies above ~2 KB of output, so this prints at most 40 rows
    with titles clipped to 60 chars.
    """
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    rows = []
    only = int(want_pid or 0)

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _lparam):
        if len(rows) >= 40:
            return True
        n = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(n + 1)
        user32.GetWindowTextW(hwnd, buf, n + 1)
        r = wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(r))
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if only and pid.value != only:
            return True
        rows.append((hwnd, pid.value, bool(user32.IsWindowVisible(hwnd)),
                     (r.left, r.top, r.right, r.bottom), buf.value[:60]))
        return True

    user32.EnumWindows(cb, 0)
    out(f"WINS n={len(rows)}")
    for hwnd, pid, vis, rect, title in rows:
        if title or vis:
            out(f"  hwnd={hwnd} pid={pid} vis={int(vis)} rect={rect} title={title}")
    return 0


def dlls(pid: str) -> int:
    """Module names of `pid` that look like ours (sqjs / stellaris_quickjs)."""
    cmd = ["powershell", "-NoProfile", "-Command",
           "(Get-Process -Id %s).Modules | Where-Object { $_.ModuleName -match 'sqjs|quickjs|neo' } | ForEach-Object { $_.FileName }" % pid]
    res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    found = [ln for ln in (res.stdout or "").splitlines() if ln.strip()]
    out(f"DLLS pid={pid} n={len(found)}")
    for ln in found[:6]:
        out("  " + ln.strip()[:160])
    return 0


def evt(n: int = 5) -> int:
    """Last `n` Application-log Error/Critical events, clipped to 200 chars."""
    cmd = ["powershell", "-NoProfile", "-Command",
           "$e=Get-WinEvent -FilterHashtable @{LogName='Application';Level=2;StartTime=(Get-Date).AddHours(-2)} -MaxEvents %d -ErrorAction SilentlyContinue;"
           "foreach($x in $e){'{0}|{1}|{2}|{3}' -f $x.TimeCreated,$x.Id,$x.ProviderName,($x.Message -replace '\\s+',' ').Substring(0,[Math]::Min(200,($x.Message -replace '\\s+',' ').Length))}" % n]
    res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    for line in (res.stdout or "").splitlines():
        out(line[:220])
    out(f"EVT rc={res.returncode}")
    return 0


def ls(path: str) -> int:
    try:
        names = sorted(os.listdir(path))
    except OSError as exc:
        out(f"LS missing path={path} err={type(exc).__name__}")
        return 2
    out(f"LS path={path} n={len(names)}")
    for name in names:
        full = os.path.join(path, name)
        try:
            st = os.stat(full)
            out(f"  {st.st_size}\t{int(st.st_mtime)}\t{name}")
        except OSError:
            out(f"  ?\t?\t{name}")
    return 0


def cp(src: str, dst: str) -> int:
    shutil.copyfile(src, dst)
    out(f"CP ok {src} -> {dst}")
    return 0


def rm(path: str) -> int:
    try:
        os.remove(path)
    except FileNotFoundError:
        out(f"RM absent {path}")
        return 0
    out(f"RM ok {path}")
    return 0


def rmdir(path: str) -> int:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        out(f"RMDIR absent {path}")
        return 0
    out(f"RMDIR ok {path}")
    return 0


def backup_dlc() -> int:
    dst = r"C:\temp\dlc_load.before_flag.json"
    shutil.copyfile(DLC_LOAD, dst)
    out(f"BACKUP ok {dst} sha={hashlib.sha256(open(dst, 'rb').read()).hexdigest()}")
    return 0


def restore_dlc(backup: str) -> int:
    shutil.copyfile(backup, DLC_LOAD)
    d = json.loads(open(DLC_LOAD, "r", encoding="utf-8-sig").read())
    out(f"RESTORE ok {DLC_LOAD} mods={d.get('enabled_mods')}")
    return 0


def kill() -> int:
    res = subprocess.run(["taskkill", "/F", "/IM", "stellaris.exe"],
                         capture_output=True, text=True, errors="replace")
    out(f"KILL rc={res.returncode}")
    return 0


VERBS = {
    "procs": procs, "sha": sha, "stat": stat, "head": head, "tail": tail,
    "b64": b64, "pngascii": pngascii, "dlls": dlls, "wins": wins, "count": count, "grep": grep, "evt": evt, "read": read, "ls": ls, "cp": cp, "rm": rm, "rmdir": rmdir,
    "backup-dlc": backup_dlc, "restore-dlc": restore_dlc, "kill": kill,
}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in VERBS:
        out("VERBS " + " ".join(sorted(VERBS)))
        return 2
    verb, rest = argv[0], argv[1:]
    try:
        if verb in ("head", "tail"):
            return VERBS[verb](rest[0], int(rest[1]) if len(rest) > 1 else 20)
        if verb == "pngascii":
            g = lambda i, d: float(rest[i]) if len(rest) > i else d  # noqa: E731
            gi = lambda i, d: int(rest[i]) if len(rest) > i else d  # noqa: E731
            return VERBS[verb](rest[0], gi(1, 78), gi(2, 26), g(3, 0.0), g(4, 1.0),
                               g(5, 0.0), g(6, 1.0), gi(7, 0))
        if verb == "evt":
            return VERBS[verb](int(rest[0]) if rest else 5)
        if verb == "grep":
            return VERBS[verb](rest[0], rest[1], int(rest[2]) if len(rest) > 2 else 12)
        if verb == "read":
            return VERBS[verb](rest[0], int(rest[1]) if len(rest) > 1 else (1 << 22))
        return VERBS[verb](*rest)
    except IndexError:
        out(f"ERR {verb} needs more arguments")
        return 2
    except Exception as exc:  # noqa: BLE001 - one line, ASCII, never a traceback
        out(f"ERR {verb} {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
