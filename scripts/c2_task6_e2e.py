"""Task 6: the C2 acceptance gate — QuickJS really evaluates JS inside the injected DLL.

Runs ``1+1`` through the DLL's own ``JS_Eval`` path and reads the integer back
through the CreateRemoteThread exit code, using the encoding the plan fixes:

    rc = 0          g_test_ctx is NULL  (C2Init has not run in THIS module copy)
    rc = 1          JS_Eval threw
    rc = 2          eval succeeded but the value is not an int32
    rc = n*4 + 3    eval succeeded with int32 n   ->  decode n = (rc - 3) // 4

``1+1`` is ``n = 2``, so the expected rc is **11**. Ruling P20: the plan's
"expected 7" is an arithmetic slip (`1+1` is 2, not 1). The *encoding* is the
contract and stands — ``n*4+3`` is always congruent to 3 (mod 4), so no value of
``n`` can be mistaken for the three sentinels.

Run this ON WINDOWS (the game box) after uploading into C:/temp/ (ruling P5):

  * ``scripts/c2_harness.py`` — the bare-name import below resolves it from cwd.
  * Task 6's freshly built DLL under the NEW name (rulings P12/P22 — nothing has
    that name loaded, so no file lock and no stale copy can be mistaken for it):

      ``python C:/temp/c2_task6_e2e.py           [dll_path]``  # default C:\\temp\\sqjs_c5.dll

  * the brief's Step 6 no-init case: the SAME bytes uploaded a second time under
    their own filename. Windows loads per-path, so that instance gets its own
    zero-initialised ``g_test_ctx`` — which is what makes Step 6 a real test of
    the guard rather than a state leak (ruling P22):

      ``python C:/temp/c2_task6_e2e.py --noinit  [dll_path]``  # default C:\\temp\\sqjs_c5_noinit.dll

SINGLE-RUN PROBE — this script dispatches ``C2Init`` at most once and
``C2EvalProbeOnePlusOne`` at most once and refuses a second dispatch of either.
``C2TestQuickJS``/``C2DiagQuickJS`` reset the DLL-static ``g_test_rt``/
``g_test_ctx`` on every dispatch WITHOUT freeing the previous runtime (ledgered
minor from the Task 3/4 review), and the probe evaluates into that same context,
so re-dispatching leaks QuickJS state and a second probe would no longer be
observing the ``C2Init`` that ran.

Gate order is the same shape as ``c2_task3_diag.py``/``c2_task5_init.py`` and is
deliberately duplicated per probe instead of moved into ``c2_harness.py`` —
ruling P18 (the harness is a reviewed primitive layer whose host tests are its
contract): inject once -> assert_game_alive -> resolve_base_address keyed on the
exact filename injected (full 64-bit base from PowerShell, never a thread exit
code) -> assert the MZ header at that base -> list_exports of THE WINDOWS-SIDE
COPY actually injected (ruling P10: no hard-coded RVAs) -> ``C2Sanity == 42`` +
alive check. Nothing with side effects runs before that gate passes.

The no-init mode never dispatches ``C2Init``, and every address it uses comes
from its own instance's base plus its own reparse of its own file, so it cannot
dispatch into the first instance (rulings P8/P22).
"""
import os
import sys

from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll,
    list_exports, call_remote, read_memory, assert_game_alive,
)

DEFAULT_DLL = r"C:\temp\sqjs_c5.dll"
DEFAULT_NOINIT_DLL = r"C:\temp\sqjs_c5_noinit.dll"

# The gate's expected encoding (ruling P20): n = 2 -> 2*4 + 3 = 11.
EXPECTED_RC_ONE_PLUS_ONE = 11
EXPECTED_N_ONE_PLUS_ONE = 2

# rc -> sentinel name, exactly as C2EvalProbe documents them (quickjs_wrapper.c).
SENTINELS = {0: "no_ctx", 1: "exception", 2: "not_int32"}
VALUE = "int32"

# rc -> the diagnosis whoever reads the live output needs. The three sentinels
# are three different failures, so they get three different messages.
SENTINEL_DIAGNOSIS = {
    0: (
        "g_test_ctx is NULL — C2Init has not run in the module copy that was "
        "dispatched. In no-init mode that is the expected guard result; in the "
        "main case it means the base resolved to a different copy than the one "
        "whose C2Init returned 0 (wrong/stale module — see P8/P10/P22)"
    ),
    1: (
        "JS_Eval threw on the fixed source `1+1` — QuickJS was reached and a "
        "context exists, but it cannot evaluate even trivial code (e.g. base "
        "intrinsics missing from the context, or the parser rejecting global code)"
    ),
    2: (
        "JS_Eval succeeded but JS_ToInt32 produced no int32 — the context "
        "evaluated `1+1` into something that is not a number, so global "
        "arithmetic is not the expected one"
    ),
}

_INT32_MAX = 0x7FFFFFFF
_UINT32_SPAN = 1 << 32


def decode_probe_rc(raw_rc):
    """Map a C2EvalProbe exit code to ``(kind, n_or_None)``.

    Pure and host-testable — no remote call. ``raw_rc`` is what
    ``c2_harness.call_remote`` returns: the low 32 bits of the thread exit code
    as an *unsigned* Python int (``ctypes.c_uint``). ``C2EvalProbe`` returns a C
    ``int``, so a negative result arrives wrapped (``-1`` -> ``4294967295``) and
    is re-biased here before decoding. After that the decode is exact for the
    ``rc`` it is given: ``rc`` is in int32 and congruent to 3 (mod 4), so
    ``(rc - 3) // 4`` divides exactly. Caveat (same as the P20 deferred minor
    recorded at ``quickjs_wrapper.c``'s return-encoding comment and §35): for
    ``|n| >= 2^29`` (more precisely, outside ``-2^29 <= n < 2^29``) the C
    encoding ``n * 4 + 3`` itself overflows int32 and wraps, so this decode
    recovers an aliased ``n`` — it differs from the encoded value by a multiple
    of ``2^30``, the period of the wrap — not the value that went in. The
    fixed ``1+1`` probe never reaches that range, but callers must not treat a
    decoded ``n`` as faithful outside it.

    Returns ``(name, None)`` for a sentinel (0/1/2) and ``(VALUE, n)`` otherwise.
    Raises ``ValueError`` for anything that cannot be a probe rc: negative (an
    unsigned exit code never is), or — after the sentinel test — not congruent to
    3 (mod 4), which means a misaligned harness or a different function.
    """
    if raw_rc < 0:
        raise ValueError(
            f"rc {raw_rc} is negative; a thread exit code is unsigned 32-bit, so "
            "this cannot have come from call_remote"
        )
    rc = raw_rc - _UINT32_SPAN if raw_rc > _INT32_MAX else raw_rc
    if rc in SENTINELS:
        return SENTINELS[rc], None
    if (rc - 3) % 4 != 0:
        raise ValueError(
            f"rc {raw_rc} is neither a sentinel (0/1/2) nor congruent to 3 mod 4, "
            "so it is not a C2EvalProbe encoding of any int32"
        )
    return VALUE, (rc - 3) // 4


_dispatched = set()


def dispatch_once(pid, base, rva, name):
    """Dispatch a remote export exactly once per session; return its exit code."""
    if name in _dispatched:
        raise RuntimeError(
            f"{name} was already dispatched in this session; this probe is "
            "single-run by design (re-dispatch leaks the previous QuickJS runtime "
            "and invalidates the context the observation depends on)"
        )
    _dispatched.add(name)
    return call_remote(pid, base, rva)


def gate_module(pid, dll_path, needed):
    """Inject this copy and clear every gate that must precede a C2 dispatch.

    Returns ``(base, exports)`` for THIS copy only: the base is keyed on the exact
    filename injected (P8), and the RVAs are reparsed from the same Windows-side
    file that gets injected (P10), never from a remembered number.
    """
    dll_name = os.path.basename(dll_path)
    print(f"[task6] pid={pid}  dll={dll_path}")

    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    print(f"[task6] {dll_name} base (64-bit): 0x{base:x}")

    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    print("[task6] MZ header at base OK")

    exports = list_exports(dll_path)
    for name in needed:
        assert name in exports, f"{name} is not an export of {dll_path}"

    # Gate 0: this module copy must answer the zero-side-effect sanity call with
    # 42, and the game must still be alive afterwards, before anything else here
    # is dispatched.
    sanity = call_remote(pid, base, exports["C2Sanity"])
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch against "
        f"this module copy"
    )
    assert_game_alive(pid)
    print("[task6] C2Sanity == 42, game alive — dispatch authorized")
    return base, exports


def run_live_case(pid, dll_path, noinit):
    needed = ("C2EvalProbeOnePlusOne",) if noinit else ("C2Init", "C2EvalProbeOnePlusOne")
    base, exports = gate_module(pid, dll_path, needed)
    probe_rva = exports["C2EvalProbeOnePlusOne"]
    print(f"[task6] C2EvalProbeOnePlusOne RVA from PE reparse: 0x{probe_rva:x}")

    if noinit:
        # Brief Step 6. The ABSENCE of a C2Init dispatch is the thing under test;
        # this tripwire keeps it that way if this function is ever edited.
        assert "C2Init" not in _dispatched, "no-init mode must never dispatch C2Init"
        rc = dispatch_once(pid, base, probe_rva, "C2EvalProbeOnePlusOne")
        assert_game_alive(pid)
        assert rc == 0, (
            f"no-init case expected the !g_test_ctx guard (rc 0), got rc={rc} "
            "— this instance evaluated, so C2Init ran in it "
            "or the resolved base belongs to an already-initialized copy (P22)"
        )
        # Decode runs only after the rc == 0 assert, so a misaligned or garbage
        # rc (e.g. 42 from dispatching the wrong symbol) fails with the
        # assertion text above, never with decode_probe_rc's bare ValueError.
        kind, n = decode_probe_rc(rc)
        assert_game_alive(pid)
        print("Task 6 (Step 6): C2EvalProbeOnePlusOne returned 0 with no C2Init in "
              "this module copy — the !g_test_ctx guard holds and did not crash")
        return

    rc_init = dispatch_once(pid, base, exports["C2Init"], "C2Init")
    assert rc_init == 0, (
        f"C2Init rc = {rc_init} (nonzero = failing step code, see the §32/§33 "
        "decode tables) — not dispatching the eval probe against a context that "
        "was never built"
    )
    assert_game_alive(pid)
    print("[task6] C2Init rc == 0, game alive")

    rc = dispatch_once(pid, base, probe_rva, "C2EvalProbeOnePlusOne")
    assert_game_alive(pid)

    if rc in SENTINEL_DIAGNOSIS:
        raise AssertionError(
            f"C2EvalProbeOnePlusOne returned {rc} (sentinel {SENTINELS[rc]}): "
            f"{SENTINEL_DIAGNOSIS[rc]}"
        )

    kind, n = decode_probe_rc(rc)
    assert kind == VALUE, f"expected an int32 encoding, got kind {kind!r}"
    assert rc == EXPECTED_RC_ONE_PLUS_ONE, (
        f"`1+1` decoded to n={n} (rc={rc}); expected rc={EXPECTED_RC_ONE_PLUS_ONE} "
        f"(n={EXPECTED_N_ONE_PLUS_ONE}). Ruling P20: 1+1 is 2, so 2*4+3 = 11 — the "
        "plan's 7 was an arithmetic slip; the encoding is the contract."
    )
    assert n == EXPECTED_N_ONE_PLUS_ONE, f"decode mismatch: rc={rc} -> n={n}"

    assert_game_alive(pid)
    print(f"Task 6: `1+1` evaluated inside the game process and returned int32 {n} "
          f"(rc={rc} = {n}*4+3)")


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    noinit = "--noinit" in args
    args = [a for a in args if a != "--noinit"]
    dll_path = args[0] if args else (DEFAULT_NOINIT_DLL if noinit else DEFAULT_DLL)
    if not os.path.isfile(dll_path):
        raise SystemExit(
            f"{dll_path} not found — upload the freshly built DLL first (rulings "
            "P5/P10/P22: this script reparses and injects THIS file, so it must be "
            "the bytes that go into the game)"
        )
    pid = resolve_pid("stellaris")
    run_live_case(pid, dll_path, noinit)


if __name__ == "__main__":
    main()
