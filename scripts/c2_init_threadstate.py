"""§44 shot: what is OUR remote thread doing during the frozen ~6.9 s window?

Established so far (evidence §40-§43): dispatching the init sequence kills
``stellaris.exe`` every time the sequence is reached; the log witness freezes at
`new_rt MmMmMm` — three `heap_malloc` calls, all entered and all returned — and
stays frozen for 6.9 s before the address space goes unreadable
(``c1_validation`` §42); §39/§40 rule out an allocation storm and rule out "any
long thread kills it"; §43 replays the whole allocation stream of
``JS_NewRuntime2`` offline against the vendored `quickjs.c` and shows the frozen
window contains **no allocation at all**, and also refutes the two readings that
would have put the death inside QuickJS's own bookkeeping (the cross-thread stack
guard, a corrupt hash/free-chain walk).

That leaves exactly two survivors, and memory counters cannot tell them apart:

  * the thread is **executing** — `JS_NewRuntime2` is burning real time in a loop
    we have not named; the next step is hooking QuickJS, i.e. a capability
    escalation;
  * the thread is **alive but blocked** — it is parked somewhere that is not our
    code waiting on something the host is not answering; then C2 is
    environment-blocked and the pivot is the environment, not QuickJS.

This shot reads the thread itself. `GetThreadContext` gives the instruction
pointer of our remote thread; `GetThreadTimes`/`GetProcessTimes` give the CPU
time charged to it and to the game. Those two, sampled while the call runs,
separate the readings on their own:

  * `Rip` inside our module **and** thread CPU time advancing => executing;
    §43's localization is real and the escalation question is back on the table;
  * `Rip` outside our module **and** thread CPU time flat => blocked; the frozen
    window was never QuickJS working, it was QuickJS waiting.

Every other witness the proven shots use is kept running in parallel (the
`g_diag_log` static, the caller's buffer, psutil's memory counters) because the
verdict only means something against the same frozen tail those shots recorded.

Instrumentation boundary (the authorization is 点名 and read-only): this script
adds **no hook, no `WriteProcessMemory`, no code inside the target, no new
export**. It reuses the DLL bytes already shot in §42 under a fresh filename
(ruling P12), and the only Win32 calls it adds are
`SuspendThread`/`GetThreadContext`/`ResumeThread` (suspension is required by
`GetThreadContext`; the resume is in a `finally`) and the two time queries, all
against handles the harness already holds. `SuspendThread` is a perturbation of
the thread being measured, but it is a bounded one: a single context copy per
sample, and the CPU counters that carry the verdict are read without suspension.

Run ON WINDOWS (ruling P5: upload alongside c2_harness.py and c2_task5_init.py,
whose poll/decoder helpers this reuses; bare-name imports resolve in C:/temp):
    python C:/temp/c2_init_threadstate.py [dll_path] [sample_every_ms]
"""
from __future__ import annotations

import hashlib
import os
import sys
import time

import psutil

from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll, list_exports, pe_image_size,
    call_remote, remote_alloc, read_memory, assert_game_alive,
    dispatch_watching_buffer, capture_thread_state, format_thread_state,
    classify_rip,
)
from c2_task5_init import (
    MEM_SAMPLE_EVERY_MS, describe_init_rc, diag_file_path, diag_file_rc,
    log_rva_from_truncated, memory_growth_lines, poll_report_lines,
    psutil_memory_sampler, read_diag_file, clear_diag_file, last_diag_line,
)

# Default artifact for this shot: the §42 instrumented build, no filename ever
# held loaded before (ruling P12). The bytes are the point — this shot must be
# comparable with §41/§42, so `quickjs_wrapper.c` is NOT rebuilt with changes.
DEFAULT_DLL_PATH = r"C:\temp\sqjs_s43.dll"

# The bytes §42 shot (`C:/temp/sqjs_c42.dll`, recorded in `c1_validation` §42 from
# `Get-FileHash` on the Windows side and from the local build). This shot's whole
# point is a NEW observation over a window §42 already characterized, so a
# different artifact would make the comparison void — the gate refuses it rather
# than trusting that nobody touched `quickjs_wrapper.c`. Rebuilding from an
# unchanged tree is reproducible: `zig build --prefix /tmp/s44build` from this
# commit yields exactly this hash.
S42_DLL_SHA256 = ("863917f2579ae8c4472be13baeca4bed64dc2ccffc7b620fdb2b0161"
                  "34a86617")


def sha256_of(path: str) -> str:
    """Hex sha256 of a file, read in chunks (the DLL is 7 MiB)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assert_same_bytes_as_s42(dll_path: str) -> str:
    """Refuse any artifact but §42's, and return the hash for the transcript."""
    actual = sha256_of(dll_path)
    assert actual == S42_DLL_SHA256, (
        f"{dll_path} is sha256 {actual}, not §42's {S42_DLL_SHA256} — this shot "
        f"only measures what §42 measured if it runs those bytes; rebuild into a "
        f"new filename and land the §42 comparison separately if the DLL changed"
    )
    return actual

# The §42 window was 6,947 ms of frozen log. Sampling every 100 ms records ~70
# observations of it, which is what a "parked at one address" claim needs — at
# 250 ms (the memory channel's rate) six samples cannot distinguish parked from
# alternating. Faster than that costs suspension time we are measuring.
THREAD_SAMPLE_EVERY_MS = 100

# One millisecond of CPU charged to the thread across a multi-second window.
# A thread spinning in a QuickJS loop accrues seconds; a thread sitting in a
# wait accrues nothing. The threshold sits two-and-a-half orders of magnitude
# below "obviously running" and above the accounting granularity of the probes
# own syscalls (which are charged to THIS process, not the game's).
MIN_ADVANCING_CPU_US = 1000

EXECUTING_IN_DLL = "executing_in_dll"
EXECUTING_ELSEWHERE = "executing_elsewhere"
BLOCKED = "blocked"
INCONCLUSIVE = "inconclusive"


def thread_cpu_us(state: dict) -> int | None:
    """Total CPU charged to the remote thread in a capture, or None if unread."""
    kernel, user = state.get("thread_kernel_us"), state.get("thread_user_us")
    if kernel is None or user is None:
        return None
    return kernel + user


def _first_last(values: list) -> tuple:
    filled = [v for v in values if v is not None]
    if len(filled) < 2:
        return None, None
    return filled[0], filled[-1]


def thread_state_verdict(records: list, base: int, image_size: int) -> tuple[str, str]:
    """Name what the series says about our remote thread — or say why it can't.

    `records` is the list of `capture_thread_state` dicts the probe appended, in
    time order. The label is decided by the two independent axes (§44's whole
    point): was CPU time charged to the thread, and did the instruction pointer
    ever sit inside our module.
    """
    reads = [r for r in records if classify_rip(r.get("rip"), base, image_size)
             != "unknown"]
    if len(reads) < 2:
        return INCONCLUSIVE, (
            f"{len(reads)} of {len(records)} captures yielded a readable Rip — "
            f"a single address cannot show motion, and a flat CPU series needs two "
            f"endpoints")

    inside = [r for r in reads if classify_rip(r["rip"], base, image_size)
              == "inside_dll"]
    distinct = {r["rip"] for r in reads}

    cpu = [thread_cpu_us(r) for r in reads]
    cpu = [c for c in cpu if c is not None]
    if len(cpu) < 2:
        return INCONCLUSIVE, (
            f"no two captures both carried readable thread CPU counters — the "
            f"execution/blocked axis is unanswered ({len(inside)}/{len(reads)} "
            f"Rip values inside the DLL)")
    advanced_us = cpu[-1] - cpu[0]
    running = advanced_us >= MIN_ADVANCING_CPU_US

    if running and inside:
        return EXECUTING_IN_DLL, (
            f"thread CPU advanced {advanced_us} us over "
            f"{reads[-1]['ms'] - reads[0]['ms']:.1f} ms and "
            f"{len(inside)}/{len(reads)} Rips landed inside the DLL "
            f"({len(distinct)} distinct) — the window is real execution")
    if running:
        return EXECUTING_ELSEWHERE, (
            f"thread CPU advanced {advanced_us} us but no Rip landed inside the DLL "
            f"({len(distinct)} distinct, all outside) — the thread runs, somewhere "
            f"that is not our module")
    if not inside:
        return BLOCKED, (
            f"thread CPU advanced {advanced_us} us (< {MIN_ADVANCING_CPU_US}) and "
            f"every Rip was outside the DLL — the thread is alive but not running "
            f"our code")
    return INCONCLUSIVE, (
        f"thread CPU advanced {advanced_us} us (< {MIN_ADVANCING_CPU_US}) while "
        f"{len(inside)}/{len(reads)} Rips were inside the DLL — a parked thread "
        f"can still show its own last in-DLL address, so neither axis holds")


def thread_state_lines(records: list, base: int, image_size: int) -> list[str]:
    """Compact human-readable summary of the series, verdict last."""
    lines = [f"captures={len(records)}"]
    reads = [r for r in records if r.get("rip") is not None]
    lines.append(f"with_rip={len(reads)}")
    if reads:
        inside = sum(1 for r in reads
                     if classify_rip(r["rip"], base, image_size) == "inside_dll")
        lines.append(f"inside_dll={inside}/{len(reads)} "
                     f"range=0x{base:x}..0x{base + image_size:x}")
        lines.append("rips=" + ",".join(f"{r['rip']:#x}" for r in reads[:12]))
        if len(reads) > 12:
            lines[-1] += f",...({len(reads) - 12} more)"
        cpu = [thread_cpu_us(r) for r in reads]
        first, last = _first_last(cpu)
        if first is not None:
            lines.append(f"thread_cpu_us={first}->{last} (delta {last - first}) "
                         f"over {reads[-1]['ms'] - reads[0]['ms']:.1f}ms")
        else:
            lines.append("thread_cpu_us=unreadable")
    else:
        lines.append("rips=none readable")
    label, reason = thread_state_verdict(records, base, image_size)
    lines.append(f"VERDICT {label}: {reason}")
    return lines


def make_thread_probe(base: int, image_size: int, records: list,
                      clock=time.monotonic):
    """The ``thread_probe`` callable for ``dispatch_watching_buffer``.

    Appends each capture's dict to `records` (the analysis input) and returns the
    one-line rendering (the record kept in ``report["thread_samples"]``).
    """
    t0 = clock()

    def probe(thread_handle, process_handle) -> str:
        state = capture_thread_state(thread_handle, process_handle)
        state["ms"] = (clock() - t0) * 1000.0
        records.append(state)
        return format_thread_state(state, base, image_size)

    return probe


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    dll_path = args[0] if args else DEFAULT_DLL_PATH
    sample_every_ms = int(args[1]) if len(args) > 1 else THREAD_SAMPLE_EVERY_MS
    dll_name = os.path.basename(dll_path)

    pid = resolve_pid("stellaris")
    print(f"[s44] pid={pid}  dll={dll_path}  every={sample_every_ms}ms")

    # Identity before side effects: everything this shot says is a comparison with
    # §42, and that comparison needs the same artifact.
    assert_same_bytes_as_s42(dll_path)
    print(f"[s44] sha256           = {S42_DLL_SHA256} — §42's bytes")

    # --- gate order copied from c2_task5_init.py, unchanged, so a different
    # --- outcome is attributable to the new channel and not to the module copy.
    # The world-state gate (spec §1): a shot that cannot prove the premise
    # must not inject.  The refusal happens BEFORE inject_dll — "injected,
    # then noticed the premise was false" is the failure mode this removes.
    from world_probe import gate_install  # pyright: ignore[reportMissingImports]
    gate_install('threadstate')
    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    image_size = pe_image_size(dll_path)  # Windows-side copy (P10)
    print(f"[s44] {dll_name} base 0x{base:x} SizeOfImage 0x{image_size:x} "
          f"=> span 0x{base:x}..0x{base + image_size:x}")

    exports = list_exports(dll_path)
    diag_into_rva = exports["C2DiagQJSInto"]
    log_rva = exports["C2LogInto"]
    sanity = call_remote(pid, base, exports["C2Sanity"])
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch the "
        f"init sequence against this module copy"
    )
    assert_game_alive(pid)
    print("[s44] C2Sanity == 42, game alive — init dispatch authorized")

    # --- the witnesses that made §41/§42 comparable, kept as they were.
    diag_path = diag_file_path(pid)
    stale = clear_diag_file(diag_path)
    print(f"[s44] diag file        = {diag_path} "
          f"({'stale copy deleted' if stale else 'absent before dispatch'})")

    truncated_log_addr = call_remote(pid, base, exports["C2DiagGetLogAddr"])
    log_static_addr = base + log_rva_from_truncated(truncated_log_addr, base)
    print(f"[s44] g_diag_log       @ 0x{log_static_addr:x} (C2LogInto rva "
          f"0x{log_rva:x})")

    log_buf = remote_alloc(pid, 512)
    assert log_buf, "remote_alloc(512) returned NULL"

    report: dict = {}
    records: list = []
    rc, buffer_log = dispatch_watching_buffer(
        pid, base, diag_into_rva, log_buf, 512, timeout_ms=60000,
        note=lambda message: print(f"[s44] poll: {message}"),
        witnesses=(("g_diag_log", log_static_addr, 512),),
        report=report,
        sampler=psutil_memory_sampler(psutil.Process(pid)),
        sample_every_ms=sample_every_ms,
        thread_probe=make_thread_probe(base, image_size, records),
    )
    print(f"[s44] C2DiagQJSInto rc = {rc}")
    print(f"[s44] decoded rc       = {describe_init_rc(rc)}")
    for line in poll_report_lines(rc, report):
        print(f"[s44] poll report      = {line}")
    for ms, text in report.get("samples", []):
        print(f"[s44] mem @ {ms:8.1f}ms = {text}")
    for line in memory_growth_lines(report):
        print(f"[s44] mem growth       = {line}")
    for ms, text in report.get("thread_samples", []):
        print(f"[s44] thr @ {ms:8.1f}ms = {text}")
    for line in thread_state_lines(records, base, image_size):
        print(f"[s44] thread state     = {line}")

    print(f"[s44] buffer log       = {buffer_log!r}")
    disk_line = last_diag_line(read_diag_file(diag_path))
    print(f"[s44] on-disk log      = {disk_line!r}")
    disk_rc = diag_file_rc(disk_line)
    if disk_rc is not None and disk_rc != rc:
        print(f"[s44] WARNING: the diag file's last line says rc={disk_rc} but the "
              f"dispatch answered {rc} — the file is not this dispatch's output")
    witness_text = report.get("witness", {}).get("g_diag_log", {}).get(
        "best_text", "")
    print(f"[s44] g_diag_log best  = {witness_text!r}")

    alive = True
    try:
        assert_game_alive(pid)
    except RuntimeError as exc:
        alive = False
        print(f"[s44] host gone        = {exc}")
    print(f"[s44] host alive after dispatch = {alive}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
