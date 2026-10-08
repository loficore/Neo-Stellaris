"""Task 5: prove the live C2Init returns 0 and the real g_test_rt / g_test_ctx.

Run this ON WINDOWS (the game box) after uploading, into C:/temp/ (ruling P5):
  * scripts/c2_harness.py            (bare-name import, cwd resolves it)
  * the freshly built DLL under a NEW filename (ruling P12: nothing has ever
    held this name loaded, so no file lock / stale copy can interfere; the
    export C2QuickJSPointersInto only exists in this rebuilt copy).

    python C:/temp/c2_task5_init.py [dll_path]   # default C:\\temp\\sqjs_c4.dll

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


_c2_init_dispatched = False


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
    dll_path = sys.argv[1] if len(sys.argv) > 1 else r"C:\temp\sqjs_c4.dll"
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
    print(f"[task5] C2Init RVA from PE reparse:                  0x{init_rva:x}")
    print(f"[task5] C2QuickJSPointersInto RVA from PE reparse:   0x{into_rva:x}")

    sanity = call_remote(pid, base, exports["C2Sanity"])
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch "
        f"C2Init against this module copy"
    )
    assert_game_alive(pid)
    print("[task5] C2Sanity == 42, game alive — C2Init dispatch authorized")

    # --- the one and only C2Init dispatch.
    rc = dispatch_c2_init_once(pid, base, init_rva)
    assert rc == 0, f"C2Init rc = {rc} (nonzero = failing step code, see §32/§33 decode tables)"
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
            detail = "ctx is NULL while rt is live — init got partway (runtime created, JS_NewContextDiag did not complete)"
        raise AssertionError(f"C2QuickJSPointersInto returned a NULL pointer: {detail}")

    assert_game_alive(pid)
    print("Task 5: C2Init returns 0 and pointers are non-NULL (real 64-bit values above)")


if __name__ == "__main__":
    main()
