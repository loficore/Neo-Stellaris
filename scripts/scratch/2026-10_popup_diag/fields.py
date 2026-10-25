"""Field inventory for the batch's popup records (Task 7 table input)."""
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "ns_game_log.jsonl"
rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
today = [r for r in rows if r.get("t", "").startswith("2026-10-25T1")]

for r in today:
    if r.get("event") == "popup_seen" and r.get("source") == "text":
        print("TEXT_KEYS", sorted(r.keys()))
        print("TEXT_REC", json.dumps(r, ensure_ascii=False)[:500])
        break

for r in today:
    if r.get("event") == "popup_decision":
        print("DEC_KEYS", sorted(r.keys()))
        break

for r in today:
    if r.get("event") == "popup_evidence":
        print("EVI_KEYS", sorted(r.keys()))
        break
