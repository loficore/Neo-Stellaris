"""Measure the OCR swap on the real crops (spec §14.4).  Scratch-grade.

    python C:/temp/ocr_swap_measure.py C:/temp/ns_popup C:/temp/ocr_swap.tsv

Three engines, because the interesting question is not "is the new one faster"
but "faster *at what*":

``rapidocr-rec-band``
    The new engine as spec §14.3 describes it: **one text region in, its text
    out**.  The panels on disk are whole popups, so this script slices each
    ``text_*.png`` into ``r`` horizontal bands (the row count is in the file
    name) and reads them one at a time.  This is the number the 50 ms target
    is about.

``rapidocr-full-panel``
    The same wheel, but detection left on, on the **whole panel**.  This is
    what the pre-swap pipeline did with surya, so it is the honest comparison
    for "what happens if nobody re-crops".

``surya-panel``
    The old engine on the same whole panel, through the pre-swap call shape.

``agree_with_human`` is written as ``unverified`` on every row.  A human
verdict is not something this script can produce, and putting a machine guess
in a column named "human" is the kind of evidence this project keeps having to
retract.

Nothing here is imported by the product; it is an instrument.
"""

# Windows-host-only instrument: ``surya``, ``rapidocr_onnxruntime`` and
# ``popup_ocr`` all live on the game host (reached through the ``sys.path``
# line above), so a static checker on the Linux host cannot resolve them.
# pyright: reportMissingImports=false
from __future__ import annotations

import hashlib
import pathlib
import re
import sys
import time

sys.path.insert(0, r"C:\temp")

FIELDS = ("crop_sha256", "engine", "ms", "text_len", "agree_with_human")
_ROWS_RE = re.compile(r"_r(\d+)\.png$")


def crop_sha256(png_bytes: bytes) -> str:
    return hashlib.sha256(png_bytes).hexdigest()


def _timed(fn, *args):
    start = time.monotonic()
    try:
        texts = fn(*args)
        err = ""
    except Exception as exc:  # noqa: BLE001 - a failed read is a reading too
        texts, err = [], repr(exc)
    return texts, (time.monotonic() - start) * 1000.0, err


def _bands(png_path: pathlib.Path, rows: int):
    """Slice a panel into ``rows`` horizontal bands — a mechanical row split.

    Not detection: the row count comes from the file name, which is what the
    geometry pass already measured.  The point is to give the rec-only engine
    the input spec §14.3 says it gets (one region), without importing a
    detector to produce it.
    """
    import PIL.Image

    with PIL.Image.open(png_path) as image:
        width, height = image.size
        step = max(1, height // rows)
        out = []
        for index in range(rows):
            top = index * step
            bottom = height if index == rows - 1 else (index + 1) * step
            if bottom - top < 4:
                continue
            band = image.crop((0, top, width, bottom))
            path = png_path.with_name(f"{png_path.stem}_band{index:02d}.png")
            band.save(path)
            out.append(path)
        return out


def _old_surya_texts(png_path: str) -> list[str]:
    """The pre-swap engine, called the way the pre-swap module called it."""
    import os

    os.environ["TORCH_DEVICE"] = "cpu"
    import PIL.Image
    from surya.detection import DetectionPredictor
    from surya.recognition import RecognitionPredictor

    det = DetectionPredictor(device="cpu")
    rec = RecognitionPredictor(device="cpu")
    with PIL.Image.open(png_path) as image:
        preds = rec([image], det_predictor=det)
    return [line.text for line in preds[0].text_lines]


def measure(crop_dir: pathlib.Path, out_path: pathlib.Path, surya_limit: int) -> int:
    from rapidocr_onnxruntime import RapidOCR

    import popup_ocr

    rows = []

    warm_start = time.monotonic()
    status = popup_ocr.warm()
    sys.stderr.write(f"[swap] rec-only warm={status} "
                     f"ms={(time.monotonic() - warm_start) * 1000:.0f}\n")
    full_start = time.monotonic()
    full_engine = RapidOCR()
    sys.stderr.write(f"[swap] full warm ms={(time.monotonic() - full_start) * 1000:.0f}\n")

    def full_panel(path):
        out = full_engine(str(path))
        result = out[0]
        if not result:
            return []
        return [str(line[1]) for line in result if len(line) > 1]

    panels = sorted(crop_dir.glob("text_*.png"))
    sys.stderr.write(f"[swap] {len(panels)} text panels\n")

    for panel in panels:
        digest = crop_sha256(panel.read_bytes())
        match = _ROWS_RE.search(panel.name)
        band_rows = int(match.group(1)) if match else 14

        band_files = _bands(panel, band_rows)
        band_times, band_lines = [], 0
        for band in band_files:
            texts, ms, err = _timed(popup_ocr.rec_texts, str(band))
            band_times.append(ms)
            band_lines += len(texts)
            if err:
                sys.stderr.write(f"[swap] band {band.name} error: {err}\n")
            band.unlink(missing_ok=True)
        band_times.sort()
        p95 = band_times[min(len(band_times) - 1,
                             round(0.95 * (len(band_times) - 1)))] if band_times else 0.0
        rows.append((digest, "rapidocr-rec-band", round(p95, 1), band_lines,
                     "unverified"))

        texts, ms, err = _timed(full_panel, panel)
        rows.append((digest, "rapidocr-full-panel", round(ms, 1), len(texts),
                     "unverified"))
        if err:
            sys.stderr.write(f"[swap] full {panel.name} error: {err}\n")
        sys.stderr.write(f"[swap] {panel.name} bands={len(band_files)} "
                         f"band_p95={p95:.1f} full={ms:.0f}\n")

    for panel in panels[:surya_limit]:
        digest = crop_sha256(panel.read_bytes())
        texts, ms, err = _timed(_old_surya_texts, str(panel))
        rows.append((digest, "surya-panel", round(ms, 1), len(texts), "unverified"))
        if err:
            sys.stderr.write(f"[swap] surya {panel.name} error: {err}\n")
        sys.stderr.write(f"[swap] surya {panel.name} ms={ms:.0f} lines={len(texts)}\n")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        fh.write("\t".join(FIELDS) + "\n")
        for row in rows:
            fh.write("\t".join(str(v) for v in row) + "\n")
    return len(rows)


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        print(__doc__)
        return 2
    written = measure(pathlib.Path(args[0]), pathlib.Path(args[1]), int(args[2]) if len(args) > 2 else 3)
    print(f"STATUS=ok ROWS={written} OUT={args[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
