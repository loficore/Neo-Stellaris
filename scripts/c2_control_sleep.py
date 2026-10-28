"""§39 discriminator: a long remote thread that executes NO code of ours.

What is established (evidence §36.3, §38, §39, all measured on Windows_Jiaolong):
  * dispatching the C2 init sequence kills ``stellaris.exe`` in every shot where the
    sequence was reached, and the log always stops at the tag `new_rt `, i.e. inside
    ``JS_NewRuntime2``;
  * injecting the same DLL and dispatching the no-op ``C2Sanity``, then watching for
    20 s with NO init dispatch, leaves the host alive with flat counters
    (``c2_control_watch.py``: 59 samples, rss delta -448 KiB);
  * the c39/c40 shots' memory series shows the host RELEASED memory before it went
    unreadable (`vms` 8,171,300K -> 129,764K over 2.5 s), so the death looks like
    the game tearing itself down rather than being torn down by an exception.

So the remaining variable is TIME, not code: does the host die because a remote
thread has been running in it for ~5 s, whatever that thread executes? This script
answers it with `kernel32!Sleep`, which touches no QuickJS, no engine symbol and no
byte of our module:

  * host dies during ``Sleep(8000)``   => a long-running remote thread is enough —
    the QuickJS call is a red herring and every "the sequence crashed the game"
    reading of §36 is wrong;
  * host survives, thread returns      => only OUR sequence kills it, and the
    trigger is inside ``JS_NewRuntime2`` specifically.

The address is not trusted on argument. ``inject_dll`` already starts a remote
thread at a ``kernel32`` export resolved in THIS process and the game's loader runs
it, so the base is shared; on top of that the first dispatch is a 1 s calibration —
if the wall time is not ~1 s, the address is not Sleep and the script refuses to
continue.

Run ON WINDOWS (ruling P5: uploaded to C:/temp, bare-name imports):
    python C:/temp/c2_control_sleep.py [dll_path]
"""
from __future__ import annotations

import os
import sys
import time

import psutil

from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll, list_exports, remote_alloc,
    read_memory, call_remote, assert_game_alive, dispatch_watching_buffer,
    dispatch_watching_buffer,
    inject_dll,
    kernel32_call_address,
    list_exports,
    read_memory,
    remote_alloc,
    resolve_base_address,
    resolve_pid,
)
from c2_task5_init import (
    MEM_SAMPLE_EVERY_MS,
    log_rva_from_truncated,
    memory_growth_lines,
    poll_report_lines,
    psutil_memory_sampler,
)

# Long enough to span the whole observed death (unreadable at ~7.9 s, handle
# signalled at ~8.3 s) so "survived" cannot mean "the window was too short".
LONG_SLEEP_MS = 8000
# Short enough that a wrong address cannot do much damage while we are still
# deciding whether the address is right.
CALIBRATION_SLEEP_MS = 1000

# ±50 % of the requested duration: scheduler jitter and the poll loop's own
# overhead are bounded, and a value outside this band means we are not looking at
# a timer at all.
_CALIBRATION_SLACK = 0.5


def plausible_sleep_ms(wall_ms: float, expected_ms: int) -> bool:
    """Whether a measured wall time is consistent with ``Sleep(expected_ms)``."""
    return (expected_ms * (1 - _CALIBRATION_SLACK) <= wall_ms
            <= expected_ms * (1 + _CALIBRATION_SLACK))


def _print(prefix: str, message: str) -> None:
    print(f"[{prefix}] {message}")


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    dll_path = args[0] if args else r"C:\temp\sqjs_c39.dll"
    dll_name = os.path.basename(dll_path)
    pid = resolve_pid("stellaris")
    print(f"[sleep] pid={pid}  dll={dll_path}  long_sleep={LONG_SLEEP_MS}ms")

    # Gates identical to the init shot's, so the ONLY difference between this run
    # and a shot is what the remote thread executes.
    # The world-state gate (spec §1): a shot that cannot prove the premise
    # must not inject.  The refusal happens BEFORE inject_dll — "injected,
    # then noticed the premise was false" is the failure mode this removes.
    from world_probe import gate_install  # pyright: ignore[reportMissingImports]
    gate_install('control_sleep')
    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    exports = list_exports(dll_path)  # Windows-side copy (P10)
    sanity = call_remote(pid, base, exports["C2Sanity"])
    assert sanity == 42, f"C2Sanity returned {sanity}, expected 42"
    assert_game_alive(pid)
    print(f"[sleep] {dll_name} base 0x{base:x}, C2Sanity == 42, game alive")

    # A second, independent readability witness: the DLL's own g_diag_log static,
    # which stays `enter ...`-free here because no sequence runs. Polling it too
    # means "unreadable" can only mean the address space, not our page.
    truncated_log_addr = call_remote(pid, base, exports["C2DiagGetLogAddr"])
    log_static_addr = base + log_rva_from_truncated(truncated_log_addr, base)
    print(f"[sleep] witness g_diag_log @ 0x{log_static_addr:x}")

    sleep_addr = kernel32_call_address(b"Sleep")
    print(f"[sleep] kernel32!Sleep resolved here @ 0x{sleep_addr:x}")

    # --- calibration: is that address really Sleep? ---
    cal_buf = remote_alloc(pid, 512)
    t0 = time.monotonic()
    cal_rc, _cal_text = dispatch_watching_buffer(
        pid, sleep_addr, 0, CALIBRATION_SLEEP_MS, 512, poll_addr=cal_buf,
        timeout_ms=15000, note=lambda m: _print("sleep", f"calib poll: {m}"),
    )
    cal_wall_ms = (time.monotonic() - t0) * 1000.0
    print(f"[sleep] calibration    = Sleep({CALIBRATION_SLEEP_MS}) took "
          f"{cal_wall_ms:.1f}ms, rc={cal_rc}")
    assert plausible_sleep_ms(cal_wall_ms, CALIBRATION_SLEEP_MS), (
        f"the resolved address did not behave like Sleep({CALIBRATION_SLEEP_MS}) — "
        f"it took {cal_wall_ms:.1f}ms; refusing the long dispatch"
    )
    assert_game_alive(pid)
    print("[sleep] calibration plausible, game alive — the address is a timer")

    # --- the discriminator ---
    buf = remote_alloc(pid, 512)
    report: dict = {}
    t0 = time.monotonic()
    rc, text = dispatch_watching_buffer(
        pid, sleep_addr, 0, LONG_SLEEP_MS, 512, poll_addr=buf,
        timeout_ms=30000, note=lambda m: _print("sleep", f"poll: {m}"),
        witnesses=(("g_diag_log", log_static_addr, 512),),
        report=report,
        sampler=psutil_memory_sampler(psutil.Process(pid)),
        sample_every_ms=MEM_SAMPLE_EVERY_MS,
    )
    wall_ms = (time.monotonic() - t0) * 1000.0
    print(f"[sleep] Sleep({LONG_SLEEP_MS}) rc={rc} buffer={text!r} wall={wall_ms:.1f}ms")
    for line in poll_report_lines(rc, report):
        print(f"[sleep] poll report      = {line}")
    for ms, sample in report.get("samples", []):
        print(f"[sleep] mem @ {ms:8.1f}ms = {sample}")
    for line in memory_growth_lines(report):
        print(f"[sleep] mem growth       = {line}")

    alive = True
    try:
        assert_game_alive(pid)
    except RuntimeError as exc:
        alive = False
        print(f"[sleep] host gone        = {exc}")
    print(f"[sleep] VERDICT: a remote thread that executes only kernel32!Sleep for "
          f"{LONG_SLEEP_MS}ms left the host alive={alive}, "
          f"thread_returned_while_alive={report.get('thread_returned_while_alive')}")
    return 0 if alive else 1


if __name__ == "__main__":
    sys.exit(main())
