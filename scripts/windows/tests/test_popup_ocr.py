"""Host-side tests for the OCR single-exit module `popup_ocr`.

The brief's four cases: importing the module never touches surya, a raising
engine degrades to status "error" instead of an exception, a missing engine
package is "unavailable", and a missing model snapshot is named apart from a
crash. Everything goes through monkeypatch — surya is not installed on the
Linux host that runs these tests.
"""

import sys

import popup_ocr


def test_import_never_touches_surya():
    assert "surya" not in sys.modules
    import popup_ocr                                    # 必须成功

def test_a_raising_engine_degrades_to_error_not_an_exception(monkeypatch):
    def boom(path):
        raise RuntimeError("model backend failed")
    monkeypatch.setattr(popup_ocr, "_predict", boom)
    texts, status, ms = popup_ocr.ocr_texts("whatever.png")
    assert texts == [] and status == "error" and ms >= 0

def test_missing_engine_package_is_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "surya", None)
    assert popup_ocr.warm() == "unavailable"
    assert popup_ocr.ocr_texts("x.png")[1] == "unavailable"

def test_model_missing_is_named_apart_from_a_crash(monkeypatch):
    monkeypatch.setattr(popup_ocr, "_predict",
                        lambda path: (_ for _ in ()).throw(FileNotFoundError("no snapshot")))
    assert popup_ocr.ocr_texts("x.png")[1] == "model_missing"


def test_warm_cli_prints_one_status_line_with_zero_lines(capsys):
    # The CLI exists so Task 6 can measure load cost without starting the
    # daemon (same one-liner shape as `keep_awake.py check`).
    assert popup_ocr.main(["warm"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("STATUS=")
    assert "MS=" in out and out.endswith("LINES=0\n")
