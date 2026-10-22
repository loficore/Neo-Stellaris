"""§50 one-off live stress probe (scratch, not a maintained tool).

Runs ON WINDOWS from C:/temp/, alongside c2_harness.py (ruling P5):

    python C:/temp/quickjs_stress_live.py [dll_path]  # default C:\\temp\\sqjs_s50.dll

Purpose: §48 removed UBSan instrumentation from eight fallback `container_of`
expressions; only `js_rc` was exercised by Task 5/6 live. This probe drives the
others through the fixed stress script in quickjs_wrapper.c
(`C2EvalStress` → `C2EvalStressOne`): string-builder growth and array growth
(js_realloc2 → __js_realloc + __js_malloc_usable_size) and per-round refcount
drops (__js_free).

Gate order is the Task 6 shape: inject → alive → base by filename (P8) → MZ →
exports reparsed from the injected Windows-side copy (P10) → C2Sanity == 42 +
alive. Then C2Init once, then C2EvalStressOne once. Expected: C2Init rc 0 and
stress rc 63619, i.e. n = 15904 = (63619 - 3) / 4, computed independently with
Node from the same source text and pinned by the native test. The host must be
alive after each dispatch.
"""
from __future__ import annotations

import os
import sys

from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll,
    list_exports, call_remote, read_memory, assert_game_alive,
)

DEFAULT_DLL = r"C:\temp\sqjs_s50.dll"
EXPECTED_RC = 63619
EXPECTED_N = 15904


def main(argv):
    dll_path = argv[1] if len(argv) > 1 else DEFAULT_DLL
    pid = resolve_pid("stellaris.exe")
    dll_name = os.path.basename(dll_path)
    print(f"[stress] pid={pid}  dll={dll_path}")

    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    print(f"[stress] {dll_name} base (64-bit): 0x{base:x}")

    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    print("[stress] MZ header at base OK")

    exports = list_exports(dll_path)
    for name in ("C2Sanity", "C2Init", "C2EvalStressOne"):
        assert name in exports, f"{name} is not an export of {dll_path}"
    print(f"[stress] C2Init RVA from PE reparse:         0x{exports['C2Init']:x}")
    print(f"[stress] C2EvalStressOne RVA from PE reparse: 0x{exports['C2EvalStressOne']:x}")

    sanity = call_remote(pid, base, exports["C2Sanity"])
    assert sanity == 42, f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch"
    assert_game_alive(pid)
    print("[stress] C2Sanity == 42, game alive — dispatch authorized")

    init_rc = call_remote(pid, base, exports["C2Init"])
    assert_game_alive(pid)
    assert init_rc == 0, f"C2Init rc={init_rc}, expected 0"
    print("[stress] C2Init rc == 0, game alive")

    rc = call_remote(pid, base, exports["C2EvalStressOne"])
    assert_game_alive(pid)
    print(f"[stress] C2EvalStressOne rc = {rc} (expected {EXPECTED_RC})")
    assert rc == EXPECTED_RC, f"stress rc={rc}, expected {EXPECTED_RC}"
    n = (rc - 3) // 4
    assert n == EXPECTED_N, f"decoded n={n}, expected {EXPECTED_N}"
    print(f"[stress] decoded n = {n}; host alive after the churn")
    print("§50: stress script evaluated; realloc/usable-size/free paths survived live")


if __name__ == "__main__":
    main(sys.argv)
