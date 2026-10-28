"""Host-side fence for the small rec-only OCR engine (spec §14).

Spec §14 replaces ``surya`` with a PP-OCRv4 mobile **recognition-only** model
because the old one was "用一个尺寸不对的模型做一件很小的事": surya on CPU costs
about 0.7 s per line and the popup budget is 24 s, so 12 lines already blew
through it.

Three things this file pins, and each is a way the swap could quietly fail:

* **the cache is real.**  The popup is re-read on a timer, and the same crop
  comes back unchanged most of the time — if a cache "hit" still ran the model,
  the engine swap would buy nothing at all.  The fence counts model calls.
* **a missing dependency is a status, not a traceback.**  ``popup_ocr``'s whole
  contract is 「永不 raise」: the daemon dies with the heartbeat, and the
  heartbeat gates every real action.
* **the budget is derived from a measurement.**  ``POPUP_OCR_BUDGET_MS`` is a
  *cost account*, so it has to be tied to a number somebody measured, not to a
  number that felt safe.  The fence reads the recorded measurement.

No model, no torch, no onnxruntime, no game: every engine call is a stub.
"""

from __future__ import annotations

import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "windows"))

import popup_ocr  # pyright: ignore[reportMissingImports]
import game_supervisor as gs  # pyright: ignore[reportMissingImports]

#: The measured p95 of one rec-only call, in ms — written by Task 8's Step 4
#: into the live artifact.  The fence reads that file, so the budget cannot be
#: quietly re-tuned without re-measuring.
SWAP_ARTIFACT = REPO / "evidence" / "logs" / "ocr_swap_4_4_4.tsv"


def test_cache_hit_does_not_call_model(tmp_path, monkeypatch):
    """The same bytes twice ⇒ ONE model call (spec §14.3's cache).

    Two files with identical bytes stand in for "the same crop seen on two
    ticks": the key is the content, not the path, because the daemon
    overwrites its live crop every tick.
    """
    calls = []

    def fake_engine(png_path):
        calls.append(png_path)
        return ["Fleet Power 1234"]

    monkeypatch.setattr(popup_ocr, "_predict", fake_engine)
    popup_ocr.clear_cache()

    first = tmp_path / "crop_a.png"
    second = tmp_path / "crop_b.png"
    payload = b"\x89PNG\r\n\x1a\nsame-crop-bytes"
    first.write_bytes(payload)
    second.write_bytes(payload)

    texts_one, status_one, ms_one = popup_ocr.ocr_texts(str(first))
    texts_two, status_two, ms_two = popup_ocr.ocr_texts(str(second))

    assert calls == [str(first)], f"the cache did not hold: {calls}"
    assert texts_one == texts_two == ["Fleet Power 1234"]
    assert status_one == status_two == "ok"
    assert ms_one >= 0 and ms_two >= 0

    # A different crop is a different key: it must reach the model.
    third = tmp_path / "crop_c.png"
    third.write_bytes(payload + b"\x00")
    popup_ocr.ocr_texts(str(third))
    assert len(calls) == 2, calls


def test_missing_dependency_is_a_status_not_a_traceback(monkeypatch):
    """An unimportable engine maps onto the module's own vocabulary.

    ``ocr_texts`` never raises — a missing wheel is ``"unavailable"``, and the
    daemon keeps its heartbeat.  This is the difference between "OCR is broken
    today" and "the daemon is dead".
    """
    def boom(png_path):
        raise ImportError("No module named 'rapidocr_onnxruntime'")

    monkeypatch.setattr(popup_ocr, "_predict", boom)
    popup_ocr.clear_cache()

    texts, status, ms = popup_ocr.ocr_texts("whatever.png")
    assert texts == []
    assert status in popup_ocr.OCR_STATUSES
    assert status == "unavailable"
    assert ms >= 0

    # And the recorded `warm()` path classifies the same way.
    monkeypatch.setattr(popup_ocr, "_load",
                        lambda: (_ for _ in ()).throw(ImportError("no wheel")))
    assert popup_ocr.warm() == "unavailable"


def test_budget_ms_is_derived_from_measurement():
    """``POPUP_OCR_BUDGET_MS`` must be ≤ 3× the measured p95 (spec §14.4).

    The budget is a cost account, so it is tied to a measurement somebody took
    and wrote down.  A budget invented without one — or left at the old
    engine's number — is the failure this fence exists for.
    """
    assert SWAP_ARTIFACT.exists(), (
        f"{SWAP_ARTIFACT.name} is missing: the swap needs a measurement, not a "
        "guess (spec §14.4)")

    # The artifact carries "#" comment lines above the header (operator notes:
    # which call shape each engine label means, and why the surya rows are
    # zero-length), so the header is the first non-comment line — not line 0.
    data_lines = [line for line in
                  SWAP_ARTIFACT.read_text(encoding="utf-8").splitlines()
                  if line.strip() and not line.startswith("#")]
    header = data_lines[0].split("\t")
    ms_index = header.index("ms")
    engine_index = header.index("engine")
    rows = []
    for line in data_lines[1:]:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        rows.append(parts)

    new_ms = sorted(float(row[ms_index]) for row in rows
                    if row[engine_index].startswith(popup_ocr.ENGINE))
    assert new_ms, f"no rows for engine {popup_ocr.ENGINE!r} in {SWAP_ARTIFACT.name}"
    p95 = new_ms[min(len(new_ms) - 1, round(0.95 * (len(new_ms) - 1)))]

    assert gs.POPUP_OCR_BUDGET_MS <= 3 * p95, (
        f"budget {gs.POPUP_OCR_BUDGET_MS} ms is more than 3x the measured p95 "
        f"{p95} ms — re-measure or re-derive it (spec §14.4)")

    # The engine is named, so a silent swap back to the old wheel is visible.
    assert popup_ocr.ENGINE != "surya", (
        "ENGINE still says surya: the swap did not happen (spec §14.2)")
    assert "rapidocr" in popup_ocr.ENGINE or "windows" in popup_ocr.ENGINE
