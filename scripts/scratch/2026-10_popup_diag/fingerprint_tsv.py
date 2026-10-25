"""Build the Task 7 fingerprint table from the batch's deduped popup slice.

Content column is a human read of the evidence contact sheet (23 crops): the
debug console's text panel, or a slice of the main UI.  Everything else is
mechanical: counts, bbox, ocr status, first-seen time from the log.
"""
import collections
import json
import sys

SLICE = "slice.jsonl"
OUT = sys.argv[1] if len(sys.argv) > 1 else "popup_fingerprints.tsv"

# Human read of each crop, from the contact sheet.  Anything not listed here
# was read as the console text panel (the default for this batch).
UI_SLICES = {"geom:1060x320:r11", "text:26f8c449"}

rows = [json.loads(line) for line in open(SLICE, encoding="utf-8") if line.strip()]
seen = [r for r in rows if r.get("event") == "popup_seen"]

agg = collections.OrderedDict()
for r in seen:
    pid = r["popup_id"]
    a = agg.setdefault(pid, {"id": pid, "count": 0, "source": r.get("source"),
                             "ocr": r.get("ocr_status"), "first": r.get("t"),
                             "reasons": collections.Counter(), "texts_n": None})
    a["count"] += r.get("count", 1)
    a["reasons"][r.get("reason")] += r.get("count", 1)
    if r.get("texts_n") is not None:
        a["texts_n"] = r["texts_n"]
    if r.get("ocr_status") == "ok":
        a["ocr"] = "ok"

HDR = ["popup_id", "source", "样本数", "bbox", "ocr_状态", "文本头行", "有无选项行",
       "首见", "reason_分布", "人眼内容", "判读结论", "是否进名单"]

lines = ["\t".join(HDR)]
for pid, a in sorted(agg.items(), key=lambda kv: -kv[1]["count"]):
    bbox = (pid[len("geom:"):] if pid.startswith("geom:")
            else "1060x317(与 geom:1060x320:r11 同 bbox)")
    reasons = " ".join("%s=%d" % (k, v) for k, v in a["reasons"].most_common())
    if a["source"] == "text":
        head = "未存原文(日志只记 texts_n=%s);人眼: 舰队列表舰名与「工程/科研」标签" % a["texts_n"]
    else:
        head = "not_asked(会话总额已用尽)"
    content = ("主 UI 切片: 星图 + 舰船立绘 + 舰队侧栏,无 ✖ glyph"
               if pid in UI_SLICES else "调试控制台文本面板")
    lines.append("\t".join([
        pid, a["source"], str(a["count"]), bbox, a["ocr"] or "-", head, "无",
        a["first"], reasons, content, "只留证", "否"]))

open(OUT, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("rows", len(lines) - 1, "out", OUT)
print("可自动dismiss", sum(1 for l in lines[1:] if "可自动" in l))
