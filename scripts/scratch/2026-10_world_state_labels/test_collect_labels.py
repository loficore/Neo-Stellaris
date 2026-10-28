"""Pure tests for the golden-set collector (spec §13).

The collector's job is to refuse rows that cannot be evidence, so most of what
is tested here is refusal.  A golden set built from guessed labels is worse
than no golden set: it looks like the reference a future threshold change
would be measured against.
"""

from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import collect_labels as cl  # pyright: ignore[reportMissingImports]


def _frame(tmp_path, name="f.png", payload=b"\x89PNG\r\n\x1a\npixels"):
    path = tmp_path / name
    path.write_bytes(payload)
    return path


def test_row_requires_a_label_from_the_classifier_vocabulary_and_a_real_frame(tmp_path):
    """Only the three classifiers' words are verdicts; only bytes are a frame."""
    frame = _frame(tmp_path)

    row = cl.build_row(
        frame=str(frame),
        label="playing",
        source="human",
        raw={"red_px": 0, "green_px": 203},
    )
    assert row["label"] == "playing"
    assert row["source"] == "human"
    assert row["raw"] == {"red_px": 0, "green_px": 203}
    assert len(row["crop_sha256"]) == 64
    assert row["frame"] == "f.png"

    # "looks fine" is not a verdict this set can carry.
    for bad in ("looks_fine", "PLAYING", "", "maybe"):
        try:
            cl.build_row(frame=str(frame), label=bad, source="human", raw={})
        except ValueError as exc:
            assert "label" in str(exc)
        else:
            raise AssertionError(f"label {bad!r} must be refused")

    # Nor is a row whose frame is not there: a label must name real pixels.
    try:
        cl.build_row(
            frame=str(tmp_path / "absent.png"), label="playing", source="human", raw={}
        )
    except ValueError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("a missing frame must be refused")

    # §13.4's tiers are closed; a fourth one is a new claim about provenance.
    try:
        cl.build_row(frame=str(frame), label="playing", source="vibes", raw={})
    except ValueError as exc:
        assert "source" in str(exc)
    else:
        raise AssertionError("an unknown source must be refused")


def test_raw_counts_parse_verbatim_and_refuse_unknown_or_non_integer(tmp_path):
    """The counts are the calibration material; they travel unchanged.

    A dropped count makes "measured zero" and "never measured" the same thing,
    which is precisely the distinction the evidence rules exist to keep.
    """
    parsed = cl.parse_raw(["red_px=61", "bright_px=300", "option_count=0"])
    assert parsed == {"red_px": 61, "bright_px": 300, "option_count": 0}

    for bad, why in (
        (["red_pixels=61"], "unknown raw count"),
        (["red_px=sixty"], "is not an integer"),
        (["red_px"], "is not key=value"),
    ):
        try:
            cl.parse_raw(bad)
        except ValueError as exc:
            assert why in str(exc), str(exc)
        else:
            raise AssertionError(f"{bad!r} must be refused")

    # And the row keeps them as ints, because the counts are what a later
    # calibration re-grades (spec §10).
    frame = _frame(tmp_path, payload=b"other-pixels")
    row = cl.build_row(
        frame=str(frame),
        label="console_open",
        source="agent",
        raw=cl.parse_raw(["bright_px=2315"]),
    )
    assert isinstance(row["raw"]["bright_px"], int)

    # Agreement reporting keeps abstentions apart from disagreements, and
    # singles out console_open (the plan's Review Focus 2).
    rows = [
        {"label": "playing", "classifier": "pause=playing;console=closed"},
        {"label": "console_open", "classifier": "console=open"},
        {"label": "playing", "classifier": "pause=paused"},
        {"label": "unknown", "classifier": "pause=unknown"},
    ]
    report = cl.agreement(rows)
    assert report["total"] == 4
    assert report["agree"] == 2
    assert report["disagree"] == 1
    assert report["abstain"] == 1
    assert report["console_open"] == {"total": 1, "agree": 1}

    out = tmp_path / "labels.jsonl"
    cl.append_row(row, out)
    written = json.loads(out.read_text(encoding="utf-8").strip())
    assert written["crop_sha256"] == row["crop_sha256"]
