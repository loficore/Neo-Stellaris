#!/usr/bin/env bash
# Pull one file off the Windows host through the small base64 channel.
#
# scp download from this host resets the connection past a few KB
# (docs/offline-tooling.md trap 8: <=700 base64 chars per call is stable), so
# each call asks the host helper ns_pull.py for a 525-byte slice. ControlMaster
# collapses the per-call handshake, which is what makes a few hundred slices
# take seconds instead of minutes.
#
#   ./pull_slice.sh <remote-file-in-C-temp> <local-out>
set -euo pipefail

HOST="${NS_WIN_HOST:-Windows_Jiaolong}"
REMOTE="${1:?remote file name under C:\\temp}"
OUT="${2:?local output path}"
SLICE=525

B64="$(mktemp)"
trap 'rm -f "$B64"' EXIT

size=$(ssh -o ControlMaster=auto -o ControlPath=/tmp/ns.cm-%r@%h-%p -o ControlPersist=120 \
    "$HOST" "powershell -NoProfile -Command (Get-Item C:/temp/$REMOTE).Length" | tr -dc '0-9')
echo "[pull] $REMOTE size=$size" >&2

off=0
while [ "$off" -lt "$size" ]; do
    chunk=$(ssh -o ControlPath=/tmp/ns.cm-%r@%h-%p "$HOST" \
        "cd C:\\temp; python ns_pull.py $REMOTE $off $SLICE" | tr -d ' \r\n')
    if [ -z "$chunk" ]; then
        echo "[pull] EMPTY SLICE at offset $off — aborting, output would be short" >&2
        exit 1
    fi
    printf '%s' "$chunk" >> "$B64"
    off=$((off + SLICE))
done

base64 -d "$B64" > "$OUT"
got=$(stat -c %s "$OUT")
if [ "$got" != "$size" ]; then
    echo "[pull] size mismatch: got $got want $size" >&2
    exit 1
fi
echo "[pull] wrote $OUT ($got bytes)" >&2
