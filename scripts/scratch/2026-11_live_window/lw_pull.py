"""lw_pull.py — pull one file off the Windows host in base64 chunks (scratch).

Why: the ssh channel resets on remote->local transfers past a few KB
(measured 2026-11-10: `cat` of an 18 KB file delivered 6098 bytes then
"Connection reset by peer"; a 6.6 KB base64 response arrived as 0 bytes).
Uploads are fine, so the repo's documented workaround is chunked base64
(docs/offline-tooling.md §「传输陷阱」/ 陷阱 8).  This driver automates it:
one `ssh ... pull_b64.py <path> <off> <len>` per chunk, validate, append,
retry, then check the sha256 against the one the host computes.

Usage:
    python3 scripts/scratch/2026-11_live_window/lw_pull.py REMOTE_PATH LOCAL_PATH \
        [--chunk 1400] [--retries 4] [--host Windows_Jiaolong]
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import pathlib
import subprocess
import sys
import time

REMOTE_HELPER = "C:/temp/pull_b64.py"


def ssh(host: str, argv: str, timeout: float = 90.0) -> subprocess.CompletedProcess:
    return subprocess.run(["ssh", host, argv], capture_output=True, text=True,
                          timeout=timeout, errors="replace")


def remote_size(host: str, path: str) -> int:
    out = ssh(host, f"python C:/temp/lw_remote.py logstat {path}")
    text = (out.stdout or "").strip()
    for token in text.split():
        if token.startswith("size="):
            return int(token.split("=", 1)[1])
    raise SystemExit(f"cannot read size of {path}: {text!r} {(out.stderr or '')[-200:]!r}")


def remote_sha(host: str, path: str) -> str:
    out = ssh(host, f"python C:/temp/lw_remote.py sha {path}")
    text = (out.stdout or "").strip()
    if len(text.split()) >= 1 and len(text.split()[0]) == 64:
        return text.split()[0]
    raise SystemExit(f"cannot read sha of {path}: {text!r}")


def fetch_chunk(host: str, path: str, off: int, length: int, retries: int) -> bytes:
    last = ""
    for attempt in range(retries):
        out = ssh(host, f"python {REMOTE_HELPER} {path} {off} {length}")
        raw = (out.stdout or "").strip()
        if raw:
            try:
                data = base64.b64decode(raw, validate=True)
            except (binascii.Error, ValueError) as exc:
                last = f"bad b64 ({exc}) len={len(raw)}"
            else:
                if 0 < len(data) <= length:
                    return data
                last = f"unexpected decoded length {len(data)}"
        else:
            last = f"empty (rc={out.returncode})"
        time.sleep(0.8)
    raise SystemExit(f"chunk {off}+{length} failed after {retries}: {last}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("remote")
    parser.add_argument("local")
    parser.add_argument("--chunk", type=int, default=1400)
    parser.add_argument("--retries", type=int, default=4)
    parser.add_argument("--host", default="Windows_Jiaolong")
    parser.add_argument("--expect-sha", default=None)
    args = parser.parse_args(argv)

    size = remote_size(args.host, args.remote)
    want = args.expect_sha or remote_sha(args.host, args.remote)
    dst = pathlib.Path(args.local)
    dst.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    total = 0
    with open(dst, "wb") as fh:
        while total < size:
            data = fetch_chunk(args.host, args.remote, total, min(args.chunk, size - total),
                               args.retries)
            fh.write(data)
            digest.update(data)
            total += len(data)
            if total % (args.chunk * 40) < args.chunk:
                print(f"[pull] {total}/{size}", file=sys.stderr, flush=True)
    got = digest.hexdigest()
    print(f"PULL bytes={total} expected={size} sha256={got} remote={want} match={got == want}")
    return 0 if got == want and total == size else 1


if __name__ == "__main__":
    raise SystemExit(main())
