"""Task 5: prove the live C2Init returns 0 and the real g_test_rt / g_test_ctx.

Run this ON WINDOWS (the game box) after uploading, into C:/temp/ (ruling P5):
  * scripts/c2_harness.py            (bare-name import, cwd resolves it)
  * the freshly built DLL under a NEW filename (ruling P12: nothing has ever
    held this name loaded, so no file lock / stale copy can interfere; the
    exports C2QuickJSPointersInto and C2LogInto only exist in this rebuilt
    copy — the PE reparse below keys on both).

    python C:/temp/c2_task5_init.py [dll_path]   # default C:\\temp\\sqjs_c5.dll

SINGLE-RUN PROBE — one C2Init dispatch per session, and the script refuses a
second. C2TestQuickJS (which C2Init delegates to) resets g_test_rt/g_test_ctx
on every dispatch WITHOUT freeing the previous runtime (ledgered minor from
the Task 3/4 review), so a re-dispatch leaks the previous QuickJS runtime and
silently replaces the pointers being observed.

Mechanism (ruling P4): no pointer ever crosses a 32-bit thread exit code, and
C2DiagGetLogAddr is never used (it is `usize` and injector-unusable). Instead
`remote_alloc` a 16-byte buffer, pass its address as the single
CreateRemoteThread lpParameter to `C2QuickJSPointersInto`, then `read_memory`
the 16 bytes and decode with the pure helper `parse_pointers` below — the two
REAL 64-bit native-width little-endian pointers, rt at +0, ctx at +8.

Gate order (same shape as c2_task3_diag.py): inject once -> assert_game_alive
-> resolve_base_address (full 64-bit base from PowerShell, keyed on the exact
filename we injected) -> MZ header check -> list_exports of THE WINDOWS-SIDE
DLL COPY we actually injected (ruling P10: reparse per build, no hard-coded
RVAs) -> C2Sanity == 42 + alive-check. Only after that may C2Init be
dispatched.
"""
from __future__ import annotations

import os
import struct
import sys

from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll,
    list_exports, call_remote, call_remote_with_arg, remote_alloc, read_memory,
    assert_game_alive,
)


def parse_pointers(raw: bytes) -> tuple[int, int]:
    """Decode a 16-byte C2QuickJSPointersInto buffer into (rt, ctx).

    ``raw`` must be exactly 16 bytes: two native-width (x86-64: 8-byte)
    little-endian unsigned pointers, rt at +0, ctx at +8. Raises ValueError on
    any other length. Returns plain ints; 0 means the C-side pointer was NULL
    — distinguishing rt-NULL from ctx-NULL is the caller's diagnosis job (one
    is a different failure than both).
    """
    if len(raw) != 16:
        raise ValueError(f"pointer buffer must be exactly 16 bytes, got {len(raw)}")
    rt, ctx = struct.unpack_from("<QQ", raw, 0)
    return rt, ctx


# --- C2Init exit-code decoder (evidence §36.4) ------------------------------
#
# C2Init delegates to C2TestQuickJS, which returns one of THREE disjoint groups
# (quickjs_wrapper.c). The ranges are the whole point: until 2026-10-21 the
# outer and inner groups shared the numbers 2/3/4, so a bare rc could not be
# read — the live `rc = 3` has two mutually exclusive explanations. The outer
# steps now return 100..104, the inner intrinsic steps stay 1..12.
#
#   0            success: g_test_rt and g_test_ctx are both set.
#   100..104     quickjs_wrapper.c's own gates, EVERY one of which returns
#                before JS_NewContextDiag is reached — i.e. no JS context ever
#                existed, so no pending exception is possible on these paths.
#   1..12        JS_NewContextDiag (libs/quickjs/quickjs.c): 1 = the raw-context
#                allocation itself, 2..12 = the first failing intrinsic, in the
#                order quickjs.c adds them. These are the paths that had a
#                context, and the only ones that can carry an exception message.

_OUTER_NAMES = {
    100: "no_process_heap",
    101: "heap_alloc_failed",
    102: "runtime2_null",
    103: "opaque_mismatch",
    104: "raw_ctx_null",
}

# 1 is not an intrinsic — it is JS_NewContextRaw returning NULL inside
# JS_NewContextDiag, before any JS code has been evaluated.
_INNER_NAMES = {
    1: "raw_ctx_alloc",
    2: "BaseObjects",
    3: "Date",
    4: "Eval",
    5: "StringNormalize",
    6: "RegExp",
    7: "JSON",
    8: "Proxy",
    9: "MapSet",
    10: "TypedArrays",
    11: "Promise",
    12: "WeakRef",
}


def decode_init_rc(rc: int) -> tuple[str, str | None]:
    """Decode a C2Init exit code into ``(bucket, name)``.

    ``bucket`` is ``"ok"`` (name ``None``), ``"outer"`` (wrapper gates, no
    context ever existed) or ``"intrinsic"`` (``JS_NewContextDiag`` step, a
    context existed and was freed). Anything outside the two encoded ranges
    raises ``ValueError`` rather than being bucketed by guess: an unmapped
    number means either the module that answered is not this build or the exit
    code was not produced by C2Init at all, and both deserve a loud stop.

    ``call_remote`` returns an UNSIGNED ``ctypes.c_uint``, so a C ``int`` that
    was negative would arrive wrapped; no C2Init path returns a negative value
    today, and a wrapped one is not a code we can read, so it raises too.
    """
    if rc > 0x7FFFFFFF:
        raise ValueError(
            f"rc={rc} is above 0x7FFFFFFF — a wrapped negative, not a C2Init step code"
        )
    if rc < 0:
        raise ValueError(f"rc={rc} is negative — C2Init has no negative step codes")
    if rc == 0:
        return ("ok", None)
    if rc in _OUTER_NAMES:
        return ("outer", _OUTER_NAMES[rc])
    if rc in _INNER_NAMES:
        return ("intrinsic", _INNER_NAMES[rc])
    raise ValueError(
        f"rc={rc} is not a C2Init code in this build (valid: 0, 1..12, 100..104) "
        "— wrong/stale module copy, or the exit code came from somewhere else"
    )


_c2_init_dispatched = False


def fetch_diag_log(pid: int, base: int, log_rva: int) -> str:
    """Read the DLL's `g_diag_log` through `C2LogInto` — a pure copy of a static.

    Why this exists (evidence §36.4): the 2026-10-21 live shot answered `rc = 3`
    and nothing else, because the C2Init path wrote no log and the only buffer-
    filling export (`C2DiagQJSInto`) RE-RUNS the whole init sequence. On a host
    where reaching QuickJS init lost the process 2 times out of 2 (§36.3), a
    "fetch the diagnostic" step must not be another init in disguise; C2LogInto
    touches no engine code (its native test asserts byte-identity with what the
    init path wrote and that the runtime is still healthy afterwards).

    Passes the 512-byte buffer as CreateRemoteThread lpParameter (ruling P4 — the
    only value crossing the exit code is the returned length).
    """
    buf = remote_alloc(pid, 512)
    assert buf, "remote_alloc returned NULL"
    n = call_remote_with_arg(pid, base, log_rva, buf, timeout_ms=60000)
    raw = read_memory(pid, buf, 512)
    log = raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    if n != len(log):
        print(
            f"[task5] WARNING: C2LogInto reported {n} bytes but the buffer holds "
            f"{len(log)} — read back through a different module copy?"
        )
    return log


def report_init_failure(pid: int, base: int, log_rva: int, rc: int) -> str:
    """Print everything a nonzero C2Init rc can tell us, then hand back the line.

    Runs BEFORE the assert so the operator reads the step text and the captured
    exception message instead of a bare number in a traceback. A dead host is
    reported as such rather than raising an unrelated RuntimeError from the
    read-back dispatch.
    """
    try:
        bucket, name = decode_init_rc(rc)
        decoded = f"bucket={bucket} name={name}"
    except ValueError as exc:
        decoded = f"UNMAPPED — {exc}"
    print(f"[task5] decoded rc   = {decoded}")
    try:
        assert_game_alive(pid)
    except RuntimeError as exc:
        print(f"[task5] diag log   = (host gone before the read-back: {exc})")
        return decoded
    print(f"[task5] diag log   = {fetch_diag_log(pid, base, log_rva)!r}")
    return decoded


def dispatch_c2_init_once(pid: int, base: int, rva: int) -> int:
    """Dispatch C2Init exactly once per session; refuse a second dispatch.

    C2TestQuickJS resets g_test_rt/g_test_ctx without freeing the previous
    runtime (module docstring), so re-dispatching leaks QuickJS state and
    invalidates the pointers this probe is meant to observe.
    """
    global _c2_init_dispatched
    if _c2_init_dispatched:
        raise RuntimeError(
            "C2Init was already dispatched in this session; this probe is "
            "single-run by design (re-dispatch leaks the previous runtime)"
        )
    _c2_init_dispatched = True
    return call_remote(pid, base, rva)


def main():
    pid = resolve_pid("stellaris")
    dll_path = sys.argv[1] if len(sys.argv) > 1 else r"C:\temp\sqjs_c5.dll"
    dll_name = os.path.basename(dll_path)
    print(f"[task5] pid={pid}  dll={dll_path}")

    # --- gate: prove the copy we inject is live and sane before any side
    # --- effect leaves C2Init untouched (c2_task3_diag.py pattern).
    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    print(f"[task5] {dll_name} base (64-bit): 0x{base:x}")

    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    print("[task5] MZ header at base OK")

    exports = list_exports(dll_path)  # Windows-side copy (P10)
    init_rva = exports["C2Init"]
    into_rva = exports["C2QuickJSPointersInto"]
    log_rva = exports["C2LogInto"]
    print(f"[task5] C2Init RVA from PE reparse:                  0x{init_rva:x}")
    print(f"[task5] C2QuickJSPointersInto RVA from PE reparse:   0x{into_rva:x}")
    print(f"[task5] C2LogInto RVA from PE reparse:               0x{log_rva:x}")

    sanity = call_remote(pid, base, exports["C2Sanity"])
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch "
        f"C2Init against this module copy"
    )
    assert_game_alive(pid)
    print("[task5] C2Sanity == 42, game alive — C2Init dispatch authorized")

    # --- the one and only C2Init dispatch.
    rc = dispatch_c2_init_once(pid, base, init_rva)
    print(f"[task5] C2Init rc = {rc}")
    if rc != 0:
        # §36.4: a failing shot has to interpret itself — decode the range and
        # fetch g_diag_log (which since §36 also carries the failing intrinsic's
        # exception text) BEFORE asserting, so the number never arrives alone.
        decoded = report_init_failure(pid, base, log_rva, rc)
        raise AssertionError(f"C2Init rc = {rc} — {decoded}")
    assert_game_alive(pid)
    print("[task5] C2Init rc == 0, game alive")

    # --- observe the real 64-bit pointers (ruling P4): caller-supplied
    # --- 16-byte buffer, never an exit code.
    buf = remote_alloc(pid, 16)
    assert buf, "remote_alloc returned NULL"
    print(f"[task5] pointer buffer @ 0x{buf:x}")

    call_remote_with_arg(pid, base, into_rva, buf)
    assert_game_alive(pid)

    raw = read_memory(pid, buf, 16)
    rt, ctx = parse_pointers(raw)
    print(f"[task5] g_test_rt  = 0x{rt:016x}")
    print(f"[task5] g_test_ctx = 0x{ctx:016x}")

    if rt == 0 or ctx == 0:
        if rt == 0 and ctx == 0:
            detail = "both are NULL — C2Init reported rc=0 yet neither global was set"
        elif rt == 0:
            detail = "rt is NULL while ctx is non-NULL — no C2TestQuickJS path can produce that; suspect a wrong/stale module copy being called"
        else:
            # rc == 0 already proves JS_NewContextDiag completed and set both
            # globals, so "init got partway" is unreachable here — the only
            # live reading matches c2_task3_diag.py's rc=0-but-ctx=NULL check.
            detail = "ctx is NULL while rt is live — rc=0 already proves the context call completed and set both globals, so no path in the module that returned it can produce this; suspect a wrong/stale module copy being called"
        raise AssertionError(f"C2QuickJSPointersInto returned a NULL pointer: {detail}")

    assert_game_alive(pid)
    print("Task 5: C2Init returns 0 and pointers are non-NULL (real 64-bit values above)")


if __name__ == "__main__":
    main()
