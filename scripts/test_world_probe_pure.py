"""Offline fence for ``scripts/windows/world_probe.py`` — the probe's pure half.

The probe is the Windows-side half of the world-state machine: it reads the
live window through the **existing** classifiers in ``game_supervisor.py``
(``read_pause`` / ``read_console`` / ``read_window`` / ``classify_window``) and
hands back a reading in the R4 shape.  The thresholds are NOT re-implemented
here — spec §10 forbids changing them, so the probe reuses them and records
the **raw counts** that produced every verdict (spec §10: 「探针证据必须记
原始计数…否则以后永远没法标定」).

Three fences, zero shots:

* every raw count survives into the evidence, with its type intact;
* the crop hash is stable for the same bytes and changes when the bytes
  change — a label of a frame has to name *that* frame;
* importing the probe has **no side effects** (spec §3: 导入零副作用 — no
  file created, no log truncated, no screenshot taken).  The import runs in a
  fresh interpreter in an empty directory, so an import-time capture would
  show up as a file in that directory.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
WINDOWS_DIR = REPO / "scripts" / "windows"
sys.path.insert(0, str(WINDOWS_DIR))

import world_probe  # noqa: E402  # pyright: ignore[reportMissingImports]


def test_build_evidence_keeps_every_raw_count():
    """Every count the classifiers produced is in the evidence, verbatim.

    The plan's 「九个参数」 is a miscount: the raw section carries **seven**
    keys — six integers and ``bbox`` (``list | None``).  The three verdicts
    (``pause`` / ``console`` / ``window``) are not raw counts; they live in
    their own sections.  A reading that kept only the verdicts could never be
    re-graded against a different threshold later, which is exactly what the
    raw counts are for.
    """
    evidence = world_probe.build_evidence(
        pause_state="paused", red_px=61, green_px=40,
        console_state="open", bright_px=300,
        window_kind="choice", gold_px=8000, row_count=4, option_count=2,
        bbox=[10, 20, 30, 40])

    raw = evidence["raw"]
    for key, value in (("red_px", 61), ("green_px", 40), ("bright_px", 300),
                       ("gold_px", 8000), ("row_count", 4), ("option_count", 2)):
        assert raw[key] == value, key
        assert isinstance(raw[key], int), key
    assert raw["bbox"] == [10, 20, 30, 40]
    assert isinstance(raw["bbox"], list)

    # The verdicts live in their sections, not in the raw section.
    assert evidence["pause"]["state"] == "paused"
    assert evidence["console"]["state"] == "open"
    assert evidence["window"]["kind"] == "choice"
    assert "state" not in raw and "kind" not in raw

    # A missing bbox is "not measured", not a zero-width box.
    without = world_probe.build_evidence(
        pause_state="playing", red_px=0, green_px=200,
        console_state="closed", bright_px=0,
        window_kind="none", gold_px=0, row_count=0, option_count=0,
        bbox=None)
    assert without["raw"]["bbox"] is None
    assert without["window"]["bbox"] is None


def test_crop_sha256_is_stable_and_content_sensitive():
    """The crop hash names *that* crop: same bytes ⇒ same hash, changed ⇒ new."""
    payload = b"\x89PNG\r\n\x1a\n" + b"not-really-a-png-but-bytes-are-bytes"

    first = world_probe.crop_sha256(payload)
    assert first == world_probe.crop_sha256(payload)
    assert len(first) == 64
    assert all(c in "0123456789abcdef" for c in first)

    flipped = bytearray(payload)
    flipped[-1] ^= 0x01
    assert world_probe.crop_sha256(bytes(flipped)) != first

    assert world_probe.crop_sha256(b"") != first


def test_import_has_no_side_effects(tmp_path):
    """Importing the probe must not create, truncate or capture anything.

    The import runs in a **fresh interpreter** whose working directory is an
    empty ``tmp_path``: an import-time screenshot or log truncation would land
    there.  The whole chain the probe pulls in is imported, not just the probe
    module, so a side effect hidden behind the lazy ``game_supervisor`` import
    would still be caught.
    """
    code = "import world_probe, game_supervisor"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(WINDOWS_DIR)
    result = subprocess.run([sys.executable, "-c", code], cwd=tmp_path,
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert os.listdir(tmp_path) == [], (
        "importing the probe wrote into the working directory: "
        f"{os.listdir(tmp_path)}")
