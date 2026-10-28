"""c2_test_sanity — P5 historical name: inject the DLL, gate on C2Sanity == 42.

Run this ON WINDOWS (the game box), after uploading this file and
scripts/c2_harness.py to C:/temp/ (ruling P5 keeps this basename and the argv
order — this line still works verbatim):

    python C:/temp/c2_test_sanity.py <pid> <dll_path> [--also-diag]

argv[2] is the on-box path of the exact copy that gets injected, so the
export re-parse below and the remote LoadLibraryA act on the same file
(ruling P10 — no built-in RVA table; the printed sha256 is the identity check
that the answer comes from the copy on disk, and inject_dll then asserts
resolve_base_address matches the injected module).

What does this still do that c2_task2_load.py does not: **nothing**. The
base-resolution + C2Sanity flow is c2_task2_load.py's job; the optional diag
dispatch is covered operationally by the watch channel. 历史名保留 = P5 的线上
契约;能力已被 c2_task2_load.py + c2_control_watch.py 覆盖.

The four defects of the previous build this rewrite fixes:

  * P10 — the old file shipped a hard-coded RVA dict from that build. All
    RVAs now come from ``list_exports(dll_path)``, re-parsed from the copy
    on disk; ``resolve_targets`` refuses stale names with a KeyError before
    anything is dispatched.
  * P4 — the old file recovered the 64-bit module base from the 32-bit
    LoadLibrary thread exit code and added RVAs to it inside stellaris.exe.
    The base now comes from ``resolve_base_address`` (filename-keyed
    PowerShell query), exactly like c2_task2_load.py.
  * The C2DiagQJS dispatch — the call path that has killed the game host
    2-for-2 (§36.3/§39) — no longer runs unconditionally after a failed
    sanity gate. C2Sanity is the only default dispatch; a failed gate
    returns before any further dispatch, and the diag sequence needs an
    explicit ``--also-diag``.
  * P3 — no ctypes.WinDLL and no ctypes.get_last_error in this file at all;
    every Win32 touch goes through c2_harness's lazy bindings, which is
    what makes this module import cleanly on the Linux host for the guard
    tests in scripts/test_scripts_layout.py.
"""

import hashlib
import os
import sys

from c2_harness import (
    list_exports,
    resolve_base_address,
    inject_dll,
    call_remote,
    assert_game_alive,
)

USAGE = (
    "usage: python C:/temp/c2_test_sanity.py <pid> <dll_path> [--also-diag]\n"
    "  --also-diag  additionally run the C2DiagQJS / C2DiagGetLogAddr\n"
    "               sequence. WARNING: C2DiagQJS is the dispatch that has\n"
    "               killed the game host 2-for-2 (§36.3/§39) — it only ever\n"
    "               runs after the C2Sanity gate passed. C2DiagGetLogAddr\n"
    "               returns a 64-bit pointer through a 32-bit thread exit\n"
    "               code; a truncated log address must be recovered by\n"
    "               log_rva_from_truncated, never read at the low-32 value\n"
    "               (ruling P4), so this script prints it but never\n"
    "               dereferences it — the print exists only as input to\n"
    "               log_rva_from_truncated, never as an address to read at."
)


def resolve_targets(exports: dict, wanted: tuple[str, ...]) -> dict[str, int]:
    """Map wanted export names to RVAs from the re-parsed table.

    Raises ``KeyError`` listing every wanted name missing from ``exports``,
    so a stale or renamed export refuses the run instead of dispatching a
    guessed address (ruling P10).
    """
    missing = [name for name in wanted if name not in exports]
    if missing:
        raise KeyError(
            "export names missing from the re-parsed table: " + ", ".join(missing)
        )
    return {name: exports[name] for name in wanted}


def sanity_gate(rc: int) -> bool:
    """The one gate: only C2Sanity's 42 lets any further dispatch proceed."""
    return rc == 42


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(USAGE)
        return 2
    if "-h" in argv or "--help" in argv:
        print(USAGE)
        return 0

    pid = int(argv[1])
    dll_path = argv[2]
    also_diag = "--also-diag" in argv[3:]

    with open(dll_path, "rb") as fh:
        blob = fh.read()
    print(f"dll identity sha256: {hashlib.sha256(blob).hexdigest()}")
    exports = list_exports(dll_path)

    if also_diag:
        wanted = ("C2Sanity", "C2DiagQJS", "C2DiagGetLogAddr")
    else:
        wanted = ("C2Sanity",)
    targets = resolve_targets(exports, wanted)
    for name in wanted:
        print(f"{name} RVA from PE reparse: 0x{targets[name]:x}")

    # The world-state gate (spec §1): a shot that cannot prove the premise
    # must not inject.  The refusal happens BEFORE inject_dll — "injected,
    # then noticed the premise was false" is the failure mode this removes.
    from world_probe import gate_install  # pyright: ignore[reportMissingImports]
    gate_install('sanity')
    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, os.path.basename(dll_path))
    print(f"DLL base (real, 64-bit): 0x{base:x}")

    rc = call_remote(pid, base, targets["C2Sanity"])
    print(f"C2Sanity -> {rc}")
    if not sanity_gate(rc):
        print(
            f"REFUSED: expected 42, got {rc}. The injected copy is not the "
            "code under test — no further dispatch, --also-diag ignored."
        )
        return 1
    print(">>> SUCCESS: new DLL code is loaded and answers.")

    if also_diag:
        rc_diag = call_remote(pid, base, targets["C2DiagQJS"])
        print(f"C2DiagQJS -> {rc_diag}")
        assert_game_alive(pid)
        rc_addr = call_remote(pid, base, targets["C2DiagGetLogAddr"])
        print(f"C2DiagGetLogAddr truncated exit-code value: 0x{rc_addr:x}")
        print(
            "NOT reading the log at that value — it is the low 32 bits of a "
            "64-bit pointer (ruling P4). Recover the full address via "
            "log_rva_from_truncated instead."
        )

    assert_game_alive(pid)
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
