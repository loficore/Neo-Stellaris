"""Host-side tests for the popup identity pure core.

The brief's six cases: digit masking, empty text, geometry buckets,
OCR fallback, allowlist filtering, and absent-file load status.
No Windows API, no PIL, no numpy.
"""

import json

from popup_identity import (
    fingerprint,
    geometry_signature,
    load_allowlist,
    parse_allowlist,
    text_signature,
)


def test_countdown_digits_do_not_change_the_signature():
    a = text_signature(["Continue playing?", "Auto-resume in 30 s"])
    b = text_signature(["Continue playing?", "auto-resume in 29 S"])
    assert a == b and a.startswith("text:")

def test_empty_or_whitespace_texts_have_no_text_signature():
    assert text_signature(["", "   ", "\t"]) == ""

def test_geometry_signature_rounds_the_box_to_ten_pixel_buckets():
    assert geometry_signature([1000, 466, 1939, 840], 0) == \
           geometry_signature([1003, 470, 1940, 838], 0)
    assert geometry_signature(None, 3) == "geom:none"

def test_failed_ocr_falls_back_to_a_geometry_id():
    got = fingerprint(texts=["whatever"], nbbox=[0, 0, 900, 400],
                      row_count=0, ocr_status="model_missing")
    assert got["source"] == "geometry" and got["popup_id"].startswith("geom:")
    assert got["features"]["ocr"] == "model_missing"

def test_unreadable_or_unknown_action_entries_are_dropped_not_allowed():
    allow, dropped = parse_allowlist(json.dumps({"version": 1, "allow": [
        {"popup_id": "text:aaa", "action": "dismiss"},
        {"popup_id": "text:bbb", "action": "press_enter"}]}))
    assert allow == {"text:aaa": "dismiss"} and dropped == 1
    assert parse_allowlist("{not json") == ({}, 0)
    assert parse_allowlist('{"version": 1, "allow": "oops"}') == ({}, 0)

def test_load_allowlist_reports_absent_instead_of_raising(tmp_path):
    allow, status = load_allowlist(str(tmp_path / "nope.json"))
    assert allow == {} and status == "absent"
