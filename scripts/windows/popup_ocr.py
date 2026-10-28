"""OCR 单一出口 (single OCR exit) for the unattended popup handling.

This module is the ONLY place the popup pipeline touches OCR.  It runs on the
Windows host where ``rapidocr_onnxruntime`` (PP-OCRv4 mobile) is installed, but
it must import cleanly on Linux (where it is NOT installed), because
``just host-tests`` runs its tests there.  Hence: the engine is imported only
inside function bodies, never at module top.

**Engine history.**  Until 2026-10-27 this module ran ``surya`` on CPU.  That
was 用一个尺寸不对的模型做一件很小的事: ≈0.7 s per line measured on the host,
against a 24 s budget, so a 12-line popup cost ≈27 s and every OCR read was a
stall bought with the heartbeat (spec §14.1).  The replacement is PP-OCRv4
mobile **recognition only** — the UI slot coordinates are already known
(``popup_geometry``), so detection was doing work the layout already answers
(spec §14.3).

Three hard rules, unchanged by the swap:

* ``ocr_texts()`` NEVER raises.  Any failure becomes ``([], status, ms)`` with
  a real measured ``ms`` — failures must report their elapsed time too,
  because in an unattended run "slow to unusable" and "broken" are different
  accounts.  If the daemon dies on an OCR exception, the heartbeat that gates
  every real action dies with it.
* **No ``--engine`` switch, no environment variable.**  A switch is a door left
  open for the next person to swap wheels without measuring (spec §14.2);
  the old implementation lives in git history, which is where it belongs.
* The module does NO cost-saving *policy* — it reports an honest ``ms`` and
  hands the account to whoever keeps the books (the daemon's
  ``POPUP_OCR_BUDGET_MS``).  What it does do is cache **identical crops**: the
  popup is re-read on a timer and the same crop comes back unchanged most
  ticks, so a hash hit skips the model entirely (spec §14.3).
"""

# ``rapidocr_onnxruntime`` is installed on the Windows host only (this
# module must still import on Linux, where the host tests run).  A static
# checker here cannot resolve it; it resolves where the daemon runs.
# pyright: reportMissingImports=false
from __future__ import annotations

import hashlib
import os
import sys
import time
from collections import OrderedDict
from typing import Any

#: The engine this module speaks to.  Named, not switched: a silent swap back
#: to the old wheel is exactly what spec §14.2 forbids.
ENGINE = "rapidocr-ppocr-mobile"

#: CPU is the 2026-10-25 decision (the host has no usable GPU for this), kept
#: through the swap: onnxruntime would otherwise pick an execution provider the
#: machine cannot run.
DEVICE = "cpu"

#: The statuses the daemon reads.  ``unavailable`` is "the wheel is not
#: installed", ``model_missing`` is "the wheel is there but its model files are
#: not" — the two look the same to an operator and are not the same problem.
OCR_STATUSES = ("ok", "unavailable", "model_missing", "error")

#: How many crops to remember.  The popup is re-read on a timer; a handful of
#: distinct crops per screen is all there is, and a bound keeps a long-running
#: daemon from growing without limit.
CACHE_SIZE = 64

_MODEL: Any = None
_LOAD_STATUS = ""
_CACHE: OrderedDict[str, list[str]] = OrderedDict()


def clear_cache() -> None:
    """Forget every cached crop (tests and the daemon's per-session reset)."""
    _CACHE.clear()


def crop_cache_key(png_bytes: bytes) -> str:
    """The sha256 of a crop's bytes — the cache key, and an evidence label.

    Content, not path: the daemon overwrites its live crop every tick, so a
    path-keyed cache would either miss always or return the previous tick's
    text for this tick's pixels.
    """
    return hashlib.sha256(png_bytes).hexdigest()


def _load() -> Any:
    """Import the rec-only predictor and cache it (survives across calls).

    Raises on any failure; the caller classifies by exception type.  The cache
    short-circuits ONLY when the cached status is ``"ok"`` (ruling R5): a
    failed load is retried on the next call, so a transient failure is not
    frozen in for the whole daemon life.
    """
    global _MODEL, _LOAD_STATUS
    if _LOAD_STATUS == "ok":
        return _MODEL
    # Pinned before the import: onnxruntime picks its execution provider at
    # session creation, and the host's GPU is not usable for this.
    os.environ.setdefault("OMP_NUM_THREADS", "4")
    from rapidocr_onnxruntime import RapidOCR

    # ``use_text_det=False`` is read from the **configuration** at construction;
    # in rapidocr 1.2.3 the per-call ``use_det=`` / ``use_rec=`` keywords are
    # accepted and then silently ignored, so passing them would look right and
    # quietly run detection (measured 2026-10-27 on the host: 3-5 s per panel
    # with detection, 10-24 ms per text band without).
    _MODEL = RapidOCR(use_text_det=False, use_angle_cls=False)
    _LOAD_STATUS = "ok"
    return _MODEL


def _classify(exc: Exception) -> str:
    """Map an exception raised by the engine path onto ``OCR_STATUSES``."""
    if isinstance(exc, ImportError):
        return "unavailable"
    if isinstance(exc, FileNotFoundError):
        return "model_missing"
    return "error"


def warm() -> str:
    """Load the model and return the status string, nothing else.

    Used to measure 「加载成本」 apart from 「每帧成本」.  Repeated calls do not
    reload once the cached status is ``"ok"``; a failed load is retried.
    """
    global _LOAD_STATUS
    try:
        _load()
    except Exception as exc:                # 永不 raise:加载失败只报状态串
        _LOAD_STATUS = _classify(exc)
    return _LOAD_STATUS


def _predict(png_path: str) -> list[str]:
    """The real engine call, quarantined in one private function.

    PP-OCRv4 mobile **recognition only**: the crop is already the region of
    interest (``popup_geometry`` decides it from the known UI slots), so
    running detection would spend most of the budget finding text boxes in a
    picture that contains one column of text.  The rec-only switches are passed
    **per call** (``use_det=False, use_cls=False, use_rec=True``) — the
    documented way to ask rapidocr for this, and one that does not depend on
    which submodule re-exports the recogniser class.

    The call answers ``(result, elapse)`` where ``result`` is a list of
    ``[text, score]`` — or ``None`` when it recognised nothing, which is not an
    error and must not become one.

    Raises ``ImportError`` / ``FileNotFoundError`` / anything else;
    ``ocr_texts()`` is what turns those into a status.
    """
    recognizer = _load()

    # A path, not a PIL image: the engine's ``img_content`` is
    # ``str | ndarray | bytes | Path`` and a PIL image is not one of them.
    payload, _elapse = recognizer(str(png_path))
    if not payload:
        return []
    texts = []
    for line in payload:
        # Rec-only answers ``[text, score]``; the full pipeline answers
        # ``[box, text, score]``.  Accept both rather than trusting a shape.
        if isinstance(line, (list, tuple)):
            value = line[1] if len(line) > 2 else line[0]
            texts.append(str(value))
    return texts


def rec_texts(png_path: str) -> list[str]:
    """Recognise one crop; return its text lines.  **Recognition only.**

    This is the narrow entry spec §14.3 asks for: one region in, its text out,
    no detection, no page layout, no batch policy.  It raises on failure —
    ``ocr_texts`` is the never-raising door the daemon uses.
    """
    return _predict(png_path)


def ocr_texts(png_path: str) -> tuple[list[str], str, float]:
    """OCR one PNG crop; return ``(texts, status, ms)``.  **Never raises.**

    A crop whose bytes were seen before returns the cached lines without
    touching the model — that is the whole point of the swap for a popup the
    daemon re-reads on a timer.  ``ms`` is this call's wall-clock
    milliseconds, measured on failures too, and it stays honest on a cache hit
    (it reports the small real number, not a fabricated one).

    Classification is by the exception type escaping ``_predict``: package
    import failure (``ImportError``) ⇒ ``"unavailable"``, missing model
    snapshot (``FileNotFoundError``) ⇒ ``"model_missing"``, anything else ⇒
    ``"error"``.
    """
    start = time.monotonic()
    key = None
    try:
        with open(png_path, "rb") as fh:
            key = crop_cache_key(fh.read())
    except OSError:
        # No bytes to key on: fall through to the engine, which will classify
        # the failure for us.  A crop we cannot read is not a cache question.
        key = None

    if key is not None and key in _CACHE:
        _CACHE.move_to_end(key)
        return list(_CACHE[key]), "ok", (time.monotonic() - start) * 1000.0

    try:
        texts = _predict(png_path)
        status = "ok"
    except Exception as exc:                # daemon 不许因为 OCR 而死
        texts = []
        status = _classify(exc)
    if status == "ok" and key is not None:
        _CACHE[key] = list(texts)
        _CACHE.move_to_end(key)
        while len(_CACHE) > CACHE_SIZE:
            _CACHE.popitem(last=False)
    return texts, status, (time.monotonic() - start) * 1000.0


def is_available() -> bool:
    """``_LOAD_STATUS == "ok"``, the way drivers and docs read availability."""
    return _LOAD_STATUS == "ok"


def main(argv=None) -> int:
    """One-line cost probe: ``popup_ocr.py warm|<png>`` -> ``STATUS=… MS=… LINES=…``.

    ``MS`` alone cannot answer "did this cost 8 s because the machine is slow
    or because the window has many lines", so ``LINES`` rides along.  ``warm``
    times the model load alone (``LINES=0``); a PNG path reads via
    ``ocr_texts`` and reports that call's own ms.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    target = args[0] if args else "warm"
    if target == "warm":
        start = time.monotonic()
        status = warm()
        ms = (time.monotonic() - start) * 1000.0
        lines = 0
    else:
        texts, status, ms = ocr_texts(target)
        lines = len(texts)
    print(f"STATUS={status} MS={int(round(ms))} LINES={lines}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
