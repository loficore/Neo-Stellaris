"""§39 control: watch the host's memory counters with NO init dispatch.

Why this exists. The c39 shot (pid 7820) sampled the game's own memory counters
while `C2DiagQJSInto` ran, and what it recorded rules the allocation-storm reading
OUT: over the first 5 s of the call `vms` did not move at all (8,158,532K) and
`rss` moved by 1,080 KiB, then both FELL — `vms` to 3,788,488K and `rss` to
1,981,468K by 8.0 s — which is a process releasing memory, and `ReadProcessMemory`
of the whole address space started failing with ERROR_PARTIAL_COPY (gle 299) at
7,931 ms with the process handle signalled at 8,263 ms. `JS_NewRuntime2` was never
observed allocating anything.

That leaves the opposite question, and it is the one this script answers: does this
host tear itself down about five seconds after we start watching it *whatever* we
do? The shot and this control differ in exactly one respect — no init sequence is
dispatched here — so:

  * control survives, counters flat  => the init dispatch is what kills the host,
    and the death is downstream of `JS_NewRuntime2` rather than inside it;
  * control dies the same way        => the game exits on its own and every rc ever
    read from a killed remote thread (the `rc = 3` of §36.4) was the game's own
    exit code, exactly as §38's WARNING suspected.

Gate order is copied from `c2_task5_init.py` on purpose — LoadLibrary of the same
module copy, the same base/MZ checks, the same no-op `C2Sanity` dispatch — because
any difference in outcome has to be attributable to the one variable, not to the
DLL being absent, unloaded, or uninspected.

Run ON WINDOWS (ruling P5: uploaded into C:/temp, bare-name imports resolve there):
    python C:/temp/c2_control_watch.py [dll_path] [watch_ms]
"""
from __future__ import annotations

import os
import sys

import psutil

from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll, list_exports, remote_alloc,
    read_memory, call_remote, assert_game_alive, dispatch_watching_buffer,
    inject_dll,
    list_exports,
    read_memory,
    resolve_base_address,
    resolve_pid,
)
from c2_task5_init import (
    MEM_SAMPLE_EVERY_MS,
    memory_growth_lines,
    psutil_memory_sampler,
    sample_window,
)

# The shot's window was ~8 s from dispatch to unreadable; 20 s of watching gives
# the same elapsed span plus margin, so "flat and alive" cannot be a too-short
# sample of a slower teardown.
DEFAULT_WATCH_MS = 20_000


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    dll_path = args[0] if args else r"C:\temp\sqjs_c39.dll"
    watch_ms = int(args[1]) if len(args) > 1 else DEFAULT_WATCH_MS
    dll_name = os.path.basename(dll_path)

    pid = resolve_pid("stellaris")
    print(f"[control] pid={pid}  dll={dll_path}  watch={watch_ms}ms "
          f"every={MEM_SAMPLE_EVERY_MS}ms")

    # The world-state gate (spec §1): a shot that cannot prove the premise
    # must not inject.  The refusal happens BEFORE inject_dll — "injected,
    # then noticed the premise was false" is the failure mode this removes.
    from world_probe import gate_install  # pyright: ignore[reportMissingImports]
    gate_install('control_watch')
    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    exports = list_exports(dll_path)  # Windows-side copy (P10)
    sanity = call_remote(pid, base, exports["C2Sanity"])
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — this is not the module copy "
        f"the shot ran, so the control would prove nothing"
    )
    print(f"[control] {dll_name} base 0x{base:x}, C2Sanity == 42 — "
          f"NO init dispatch will be made")

    sampler = psutil_memory_sampler(psutil.Process(pid))
    samples = sample_window(sampler, watch_ms, MEM_SAMPLE_EVERY_MS)
    for ms, text in samples:
        print(f"[control] mem @ {ms:8.1f}ms = {text}")
    for line in memory_growth_lines({"samples": samples}):
        print(f"[control] growth         = {line}")

    alive = True
    try:
        assert_game_alive(pid)
    except RuntimeError as exc:
        alive = False
        print(f"[control] host gone        = {exc}")
    print(f"[control] watched {watch_ms}ms, samples={len(samples)}, "
          f"init dispatch made=none, host alive={alive}")
    return 0 if alive else 1


if __name__ == "__main__":
    sys.exit(main())
