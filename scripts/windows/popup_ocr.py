"""OCR 单一出口 (single OCR exit) for the unattended popup handling.

This module is the ONLY place the popup pipeline touches OCR. It runs on the
Windows host where ``surya-ocr 0.17.0`` + ``torch 2.9.1+cpu`` are installed,
but it must import cleanly on Linux (where they are NOT installed), because
``just host-tests`` runs its tests there. Hence: ``surya``/``torch``/``PIL``
are imported only inside function bodies, never at module top.

Two hard rules, both from the 2026-10-25 plan:

* ``ocr_texts()`` NEVER raises. Any failure becomes ``([], status, ms)``
  with a real measured ``ms`` — failures must report their elapsed time too,
  because in an unattended run "slow to unusable" and "broken" are different
  accounts. If the daemon dies on an OCR exception, the heartbeat that gates
  every real action dies with it.
* This module does NO cost-saving and must not add any: no downscaling, no
  batch tuning, no line caps. All three were measured dead ends on
  2026-10-25 (downscale to 256 px: 20 284 ms and only 9/19 lines still
  recognized; CPU defaults are already detect 8 / recognize 32, and a single
  frame is ≤ 20 lines, i.e. one batch anyway). "Can we afford this OCR" is
  the CALLER's account — Task 4 gates it with edge triggering and
  ``POPUP_OCR_BUDGET_MS``; ``ocr_texts`` only returns honest ``ms`` and hands
  the measurement back to whoever keeps the books.
"""

from __future__ import annotations

import os
import time

ENGINE = "surya"
# CPU 是 2026-10-25 的决定,不是当前环境的巧合。不做开关、不读环境变量 ——
# 留开关等于给「以后偷偷换轮子」开门。见 _load() 里对 TORCH_DEVICE 的钉。
DEVICE = "cpu"
OCR_STATUSES = ("ok", "unavailable", "model_missing", "error")

_MODEL = None
_LOAD_STATUS = ""


def _load():
    """Import surya and load (DetectionPredictor, RecognitionPredictor).

    Raises on any failure; the caller classifies by exception type.
    Module-level cache short-circuits ONLY when the cached status is "ok"
    (ruling R5): a failed load is retried on the next call, so a transient
    failure is not frozen in for the whole daemon life — and Task 4's
    backoff-retry stays meaningful.
    """
    global _MODEL, _LOAD_STATUS
    if _LOAD_STATUS == "ok":
        return _MODEL
    # 必须设在 import surya 之前:surya/settings.py:34-39 的 TORCH_DEVICE_MODEL
    # 是「TORCH_DEVICE 环境变量 → torch.cuda.is_available() 则 cuda → xla/mps →
    # cpu」的自动选课。今天落到 cpu 只因为装的是 CPU 轮子;哪天这台机换了轮子,
    # 同一份我们的代码就会静默跑到 GPU 上去。所以显式钉成 DEVICE。
    # warm() 与 _predict() 都经由这里,两条路径都先设环境变量再 import。
    os.environ["TORCH_DEVICE"] = DEVICE
    from surya.detection import DetectionPredictor
    from surya.foundation import FoundationPredictor
    from surya.recognition import RecognitionPredictor

    det = DetectionPredictor(device=DEVICE)
    rec = RecognitionPredictor(FoundationPredictor(device=DEVICE))
    _MODEL = (det, rec)
    _LOAD_STATUS = "ok"
    return _MODEL


def _classify(exc: Exception) -> str:
    """Map an exception raised by the engine path onto OCR_STATUSES."""
    if isinstance(exc, ImportError):
        return "unavailable"
    if isinstance(exc, FileNotFoundError):
        return "model_missing"
    return "error"


def warm() -> str:
    """Load the model and return the status string, nothing else.

    Task 6 uses this to measure 「加载成本」 apart from 「每帧成本」.
    Repeated calls do not reload once the cached status is "ok".
    """
    global _LOAD_STATUS
    try:
        _load()
    except Exception as exc:                # 永不 raise:加载失败只报状态串
        _LOAD_STATUS = _classify(exc)
    return _LOAD_STATUS


def _predict(png_path: str) -> list[str]:
    """The real engine call, quarantined in one private function.

    surya 0.17.0 的调用形状已在宿主上量过(2026-10-25,读 surya/models.py 的
    load_predictors() 与 inspect.signature),就这几行,不要再猜也不要再挖::

        from surya.detection import DetectionPredictor
        from surya.foundation import FoundationPredictor
        from surya.recognition import RecognitionPredictor
        det = DetectionPredictor(device=DEVICE)                       # DEVICE = "cpu"
        rec = RecognitionPredictor(FoundationPredictor(device=DEVICE))
        preds = rec([PIL.Image.open(png_path)], det_predictor=det)    # 必须走关键字
        texts = [tl.text for tl in preds[0].text_lines]

    第二 positional 参数是 task_names,把 det 按位置传进去会静默走错分支 ——
    这就是上面必须写 det_predictor= 的原因。Raises ImportError /
    FileNotFoundError / anything else; ocr_texts() 负责吞成分状态。
    """
    det, rec = _load()
    import PIL.Image

    with PIL.Image.open(png_path) as image:
        preds = rec([image], det_predictor=det)
    return [tl.text for tl in preds[0].text_lines]


def ocr_texts(png_path: str) -> tuple[list[str], str, float]:
    """OCR one PNG crop; return ``(texts, status, ms)``. 永不 raise。

    ``status`` is "ok" only on a successful read; ``texts`` is always a
    ``list[str]`` (``[]`` on failure). ``ms`` is this call's wall-clock
    milliseconds — measured on failures too. Classification is by the
    exception type escaping ``_predict``: package import failure
    (ImportError) ⇒ "unavailable", missing model snapshot
    (FileNotFoundError) ⇒ "model_missing", anything else ⇒ "error".
    """
    start = time.monotonic()
    try:
        texts = _predict(png_path)
        status = "ok"
    except Exception as exc:                # daemon 不许因为 OCR 而死
        texts = []
        status = _classify(exc)
    return texts, status, (time.monotonic() - start) * 1000.0


def is_available() -> bool:
    """``_LOAD_STATUS == "ok"``, the way drivers and docs read availability."""
    return _LOAD_STATUS == "ok"
