"""Task 3: capture the QuickJS JS_NewContext failure STEP from the live game.

This is OBSERVATION ONLY (Task 4 owns any fix). It runs the step-by-step
diagnostic baked into the DLL (`C2DiagQuickJS` in quickjs_wrapper.c, delegating
to `JS_NewContextDiag` in libs/quickjs/quickjs.c) against the running game and
records: the numeric step code, the decoded step, and the raw log string.

Run this ON WINDOWS (the game box) after uploading, into C:/temp/ (ruling P5):
  * scripts/c2_harness.py            (bare-name import, cwd resolves it)
  * the freshly built DLL under a NEW filename (ruling P12: PID 20564 already
    holds sqjs_c2.dll loaded + file-locked, so we cannot overwrite it; the new
    export C2DiagQJSInto only exists in this rebuilt copy).

    python C:/temp/c2_task3_diag.py [dll_path]   # default C:\\temp\\sqjs_c3.dll

Mechanism (ruling P4): the log lives in a DLL .data static above 2^32, so its
ADDRESS cannot survive GetExitCodeThread (32-bit truncation) — the brief's
"C2DiagGetLogAddr + read_memory" approach reads an unmapped low-32 address.
Instead we `remote_alloc` a 512-byte buffer, pass its address as the single
CreateRemoteThread lpParameter to `C2DiagQJSInto`, take the 32-bit return as the
step code, and `read_memory` the buffer for the log. One call, no pointer ever
crosses the exit code. The DLL-side symbol bound is OUR wrapper, never a QuickJS
C symbol (global constraint / docs/roadmap.md segment 5 C-wrapper workaround).

Decode table (ruling P7) is derived from the ACTUAL code, not the brief's table.
See evidence §32 for the derivation and how it differs from the brief.

Gates around the diag dispatch:
  * `C2Sanity` (zero-arg, must return 42) is called FIRST through this module
    copy, and the game must still be alive afterwards; only then may
    `C2DiagQJSInto` be dispatched.
  * rc==0 is accepted as success ONLY if the log carries a `ctx=` token whose
    pointer is non-NULL (the token is emitted only on the JS_NewContextDiag
    path; Windows `%p` renders NULL as 0000000000000000). An rc==0 without a
    non-NULL ctx is a loud failure, never a PASS line.
"""
import sys, os
from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll,
    list_exports, call_remote, call_remote_with_arg, remote_alloc, read_memory,
    assert_game_alive,
)

# ---------------------------------------------------------------------------
# Derived decode tables — from quickjs_wrapper.c c2_diag_sequence (outer gates)
# and libs/quickjs/quickjs.c JS_NewContextDiag (inner steps).
#
# §36: the two ranges are DISJOINT now. They used to share 2/3/4/10/11, which is
# what made the 2026-10-21 live rc=3 undecodable; the outer gates moved to
# 100..104. The log text still disambiguates the inner steps further — a failing
# intrinsic now carries ` err=[<Stage>: <pending exception message>]`, captured
# inside JS_NewContextDiag before the context was freed (quickjs.c:2663).
# ---------------------------------------------------------------------------
OUTER_SENTINELS = {
    # (substring in log) -> meaning, source line in quickjs_wrapper.c
    "no_process_heap": "OUTER: GetProcessHeap() returned NULL  [rc 100, quickjs_wrapper.c:290]",
    "heap_alloc_failed": "OUTER: test HeapAlloc(256) failed     [rc 101, quickjs_wrapper.c:292]",
    "runtime2_null": "OUTER: JS_NewRuntime2 returned NULL        [rc 102, quickjs_wrapper.c:296]",
    "opaque_mismatch": "OUTER: runtime opaque write+read mismatch   [rc 103, quickjs_wrapper.c:302-303]",
    "raw_ctx_null": "OUTER: JS_NewContextRaw (standalone) NULL   [rc 104, quickjs_wrapper.c:310]",
}
DIAG = {  # JS_NewContextDiag return codes (quickjs.c:2709-2740)
    0:  "OK: raw ctx + all 11 intrinsics succeeded, context created  [quickjs.c:2739-2740]",
    1:  "DIAG: JS_NewContextRaw failed (allocation)                 [quickjs.c:2723]",
    2:  "DIAG: JS_AddIntrinsicBaseObjects failed                    [quickjs.c:2725]",
    3:  "DIAG: JS_AddIntrinsicDate failed                           [quickjs.c:2726]",
    4:  "DIAG: JS_AddIntrinsicEval failed                           [quickjs.c:2727]",
    5:  "DIAG: JS_AddIntrinsicStringNormalize failed                [quickjs.c:2728]",
    6:  "DIAG: JS_AddIntrinsicRegExp failed                         [quickjs.c:2729]",
    7:  "DIAG: JS_AddIntrinsicJSON failed                           [quickjs.c:2730]",
    8:  "DIAG: JS_AddIntrinsicProxy failed                          [quickjs.c:2731]",
    9:  "DIAG: JS_AddIntrinsicMapSet failed                         [quickjs.c:2732]",
    10: "DIAG: JS_AddIntrinsicTypedArrays failed                    [quickjs.c:2733]",
    11: "DIAG: JS_AddIntrinsicPromise failed                        [quickjs.c:2734]",
    12: "DIAG: JS_AddIntrinsicWeakRef failed                        [quickjs.c:2735]",
}


def parse_ctx(log):
    """Decode the '%p'-rendered pointer after 'ctx=' in a diag log string.

    Returns the pointer as an int — NULL decodes to 0, because Windows '%p'
    renders NULL as 0000000000000000 — or None when the 'ctx=' token is absent
    or malformed. The DLL emits the token only on the JS_NewContextDiag path
    (`DLOG("diag_rc=%d ctx=%p", ...)`), so None means the log never came from
    that path.
    """
    idx = log.find("ctx=")
    if idx < 0:
        return None
    token = log[idx + len("ctx="):].split(" ", 1)[0]
    if token[:2].lower() == "0x":
        token = token[2:]
    if not token:
        return None
    try:
        return int(token, 16)
    except ValueError:
        return None


def decode(rc, log):
    """Interpret rc TOGETHER with the log text (the ranges are disjoint since
    §36, but the log is what carries the failing intrinsic's own message)."""
    for sentinel, meaning in OUTER_SENTINELS.items():
        if sentinel in log:
            return meaning
    if "diag_rc=" in log:
        # The diag path: rc == the "diag_rc=%d" echoed in the log. Cross-check.
        if rc == 0:
            ctx = parse_ctx(log)
            if ctx is None:
                return "FAIL: rc=0 but log has no parsable 'ctx=' token — rc 0 did not come from the JS_NewContextDiag path"
            if ctx == 0:
                return "FAIL: rc=0 but ctx=NULL — JS_NewContextDiag reported success without a context"
        return DIAG.get(rc, f"DIAG: rc {rc} NOT in derived table (unexpected code)")
    return f"rc {rc} — no outer sentinel and no diag_rc marker (misaligned harness?)"


def main():
    pid = resolve_pid("stellaris")
    dll_path = sys.argv[1] if len(sys.argv) > 1 else r"C:\temp\sqjs_c3.dll"
    dll_name = os.path.basename(dll_path)
    print(f"[task3] pid={pid}  dll={dll_path}")

    # The new export exists only in this rebuilt copy -> one injection (P12).
    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    print(f"[task3] {dll_name} base (64-bit): 0x{base:x}")

    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    print("[task3] MZ header at base OK")

    exports = list_exports(dll_path)  # Windows-side copy (P10)
    into_rva = exports["C2DiagQJSInto"]
    print(f"[task3] C2DiagQJSInto RVA from PE reparse: 0x{into_rva:x}")

    # Gate 0: this module copy must pass the pure sanity call (zero-arg,
    # constant 42) BEFORE anything with side effects is dispatched, and the
    # game must still be alive after it.
    sanity_rva = exports["C2Sanity"]
    sanity = call_remote(pid, base, sanity_rva)
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch "
        f"C2DiagQJSInto against this module copy"
    )
    assert_game_alive(pid)
    print("[task3] C2Sanity == 42, game alive — diag dispatch authorized")

    # P4: caller-supplied buffer; alloc is page-granular (>=4096 committed).
    # The buffer ADDRESS is passed IN via lpParameter as a full 64-bit value, so
    # VirtualAllocEx may return a low address (<2^32) — that is fine and is NOT
    # the truncation risk P4 addresses (that risk is a *returned* pointer, which
    # this design never crosses the exit code). Only require a real allocation.
    buf = remote_alloc(pid, 512)
    assert buf, "remote_alloc returned NULL"
    print(f"[task3] remote diag buffer @ 0x{buf:x}")

    # ONE diag call per hypothesis (C2DiagQuickJS mutates g_test_rt/g_test_ctx).
    rc = call_remote_with_arg(pid, base, into_rva, buf, timeout_ms=60000)
    assert_game_alive(pid)

    raw = read_memory(pid, buf, 512)
    log = raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")

    print(f"[task3] C2DiagQJSInto rc = {rc}")
    print(f"[task3] decoded step     = {decode(rc, log)}")
    print(f"[task3] diag log         = {log!r}")

    # rc==0 is only believable as "context created" with a non-NULL ctx= token.
    if rc == 0:
        ctx_ptr = parse_ctx(log)
        assert ctx_ptr is not None, (
            f"rc=0 but no parsable 'ctx=' token in log {log!r} — rc 0 did not "
            "come from the JS_NewContextDiag path; refusing to report success"
        )
        assert ctx_ptr != 0, (
            f"rc=0 but ctx=NULL in log {log!r} — JS_NewContextDiag reported "
            "success without a context; refusing to report success"
        )

    # Cross-check: if the log carries diag_rc=N, it must equal rc.
    if "diag_rc=" in log:
        echoed = log.split("diag_rc=", 1)[1].split(" ", 1)[0].split(")", 1)[0]
        try:
            echoed_n = int(echoed)
        except ValueError:
            echoed_n = None
        assert echoed_n == rc, f"log says diag_rc={echoed!r} but exit code rc={rc}"
        print(f"[task3] cross-check OK: log diag_rc == exit-code rc == {rc}")

    assert_game_alive(pid)
    print("[task3] game alive at end — PASS (observation recorded)")


if __name__ == "__main__":
    main()
