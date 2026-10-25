"""Popup identity pure core: normalization, stable fingerprints, allowlist parsing.

This file is the pure core (纯核). It must NOT import PIL/numpy/ctypes:
`just host-tests` runs it on Linux with stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import re


def normalize_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\d+", "#", text)
    return text.strip()


def text_signature(texts: list[str]) -> str:
    normalized = [normalize_text(t) for t in texts]
    if all(n == "" for n in normalized):
        return ""
    joined = "\n".join(normalized)
    return "text:" + hashlib.sha1(joined.encode("utf-8")).hexdigest()[:8]


def geometry_signature(nbbox: list[int] | None, row_count: int) -> str:
    if nbbox is None:
        return "geom:none"
    w = round((nbbox[2] - nbbox[0]) / 10) * 10
    h = round((nbbox[3] - nbbox[1]) / 10) * 10
    return f"geom:{w}x{h}:r{row_count}"


def fingerprint(*, texts: list[str], nbbox: list[int] | None,
                row_count: int, ocr_status: str) -> dict:
    if nbbox is None:
        w = h = 0
    else:
        w = nbbox[2] - nbbox[0]
        h = nbbox[3] - nbbox[1]
    features = {"w": w, "h": h, "rows": row_count, "ocr": ocr_status}
    sig = text_signature(texts)
    if ocr_status == "ok" and sig:
        return {"popup_id": sig, "source": "text", "features": features}
    return {"popup_id": geometry_signature(nbbox, row_count),
            "source": "geometry", "features": features}


def parse_allowlist(text: str) -> tuple[dict[str, str], int]:
    try:
        data = json.loads(text)
    except ValueError:
        return {}, 0
    if not isinstance(data, dict):
        return {}, 0
    entries = data.get("allow")
    if not isinstance(entries, list):
        return {}, 0
    allow: dict[str, str] = {}
    dropped = 0
    for entry in entries:
        if (isinstance(entry, dict) and entry.get("action") == "dismiss"
                and isinstance(entry.get("popup_id"), str)):
            allow[entry["popup_id"]] = "dismiss"
        else:
            dropped += 1
    return allow, dropped


def load_allowlist(path: str) -> tuple[dict[str, str], str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        return {}, "absent"
    except OSError:
        return {}, "malformed"
    try:
        data = json.loads(text)
    except ValueError:
        return {}, "malformed"
    if not isinstance(data, dict) or not isinstance(data.get("allow"), list):
        return {}, "malformed"
    allow, _dropped = parse_allowlist(text)
    return allow, "ok"
