"""Tail the supervisor event log with the fields the batch report needs.

Read-only. Prints the last N records compactly so a long session stays legible
through one ssh call.
"""
import json
import sys

PATH = r"C:\temp\ns_game_log.jsonl"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 8

rows = [ln for ln in open(PATH, encoding="utf-8").read().splitlines() if ln.strip()]
print("TOTAL", len(rows))
for ln in rows[-N:]:
    try:
        r = json.loads(ln)
    except Exception:                                   # noqa: BLE001
        print("BAD", ln[:40])
        continue
    keep = {k: r[k] for k in ("t", "event", "note", "state", "popup_id",
                              "reason", "bbox", "ocr", "method", "point")
            if k in r}
    print(json.dumps(keep, ensure_ascii=False, separators=(",", ":"))[:200])
