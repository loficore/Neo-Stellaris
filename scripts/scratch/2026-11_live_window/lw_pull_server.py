"""lw_pull_server.py — receive files pushed by the Windows host over HTTP (scratch).

The SSH channel resets on any remote->local transfer past a few KB
(docs/offline-tooling.md: 「scp 上传可用,批量下载会把 SSH 连接重置」, and the
2026-11-10 window measured the same at ~4-8 KB).  Uploads work, so the Windows
host pushes: `curl.exe -X POST --data-binary @<file> http://10.66.0.1:8099/upload/<name>`.

GET /status -> one JSON line with the files received so far.
Nothing is executed; the body is written verbatim under --out-dir.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import pathlib
import socketserver


class Handler(http.server.BaseHTTPRequestHandler):
    out_dir = pathlib.Path(".")
    received: list[dict] = []

    def log_message(self, fmt, *args):  # noqa: A003 - quiet the default stderr noise
        print("[pull] " + fmt % args, flush=True)

    def _reply(self, code: int, body: bytes, ctype: str = "text/plain") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - http.server API
        if self.path.startswith("/status"):
            self._reply(200, (json.dumps(self.received) + "\n").encode(), "application/json")
            return
        self._reply(404, b"no\n")

    def do_POST(self):  # noqa: N802 - http.server API
        name = os.path.basename(self.path.split("?")[0])
        length = int(self.headers.get("Content-Length") or 0)
        dst = self.out_dir / name
        digest = hashlib.sha256()
        got = 0
        with open(dst, "wb") as fh:
            while got < length:
                chunk = self.rfile.read(min(1 << 20, length - got))
                if not chunk:
                    break
                fh.write(chunk)
                digest.update(chunk)
                got += len(chunk)
        record = {"name": name, "bytes": got, "expected": length,
                  "sha256": digest.hexdigest()}
        Handler.received.append(record)
        print(f"[pull] {json.dumps(record)}", flush=True)
        self._reply(200, (json.dumps(record) + "\n").encode(), "application/json")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--bind", default="10.66.0.1")
    parser.add_argument("--out-dir", default="/mnt/cache/tmp/opencode/lw_pull")
    args = parser.parse_args(argv)
    Handler.out_dir = pathlib.Path(args.out_dir)
    Handler.out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[pull] listening on {args.bind}:{args.port} -> {Handler.out_dir}", flush=True)
    with Server((args.bind, args.port), Handler) as httpd:
        httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
