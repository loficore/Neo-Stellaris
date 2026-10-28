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

Mechanism (ruling P4): no pointer ever crosses a 32-bit thread exit code, so the
pointers of interest are never taken from a return value. Instead `remote_alloc`
a 16-byte buffer, pass its address as the single CreateRemoteThread lpParameter
to `C2QuickJSPointersInto`, then `read_memory` the 16 bytes and decode with the
pure helper `parse_pointers` below — the two REAL 64-bit native-width
little-endian pointers, rt at +0, ctx at +8. `C2DiagGetLogAddr` DOES get used
(§38), and only for what a truncated pointer can legitimately give: the RVA of
the module's own `g_diag_log` static, recovered exactly by
`log_rva_from_truncated` because an in-image offset always fits in 32 bits.

Gate order (same shape as c2_task3_diag.py): inject once -> assert_game_alive
-> resolve_base_address (full 64-bit base from PowerShell, keyed on the exact
filename we injected) -> MZ header check -> list_exports of THE WINDOWS-SIDE
DLL COPY we actually injected (ruling P10: reparse per build, no hard-coded
RVAs) -> C2Sanity == 42 + alive-check. Only after that may the init sequence be
dispatched.

Shot shape (learned the expensive way on 2026-10-21, evidence §38): the FIRST
init dispatch is `C2DiagQJSInto` with a 512-byte buffer allocated BEFORE it, and
that buffer is POLLED WHILE THE CALL RUNS (`dispatch_watching_buffer`) — the
callee copies its log in before returning, so the text is caught while the
address space is still there. Both later shapes lose: a two-dispatch read
(`C2Init`, then `C2LogInto`) lost the 22:41 race, and a single read placed after
the wait lost the 22:47 one to ERROR_PARTIAL_COPY. A third channel is polled in
parallel as a WITNESS: `g_diag_log` itself, whose address comes back from
`C2DiagGetLogAddr` through the low-32-bit exit code (`log_rva_from_truncated`).
Whether that static is readable while our buffer is not is what separates "the
address space went away" from "only our page did" — the ambiguity the 23:44 shot
left open. The disk file the sequence also appends (§38,
`C:/temp/c2_diag_<pid>.log`, deleted right before the
dispatch) is the second witness — the 23:03 shot showed the game process did not
create it, so it is treated as confirmation, not as the only channel. Since §37
`C2DiagQJSInto` and `C2Init` run the identical C sequence, the one-shot costs no
fidelity; `C2Init` is still dispatched afterwards, only on the success path, to
keep the Task 5 acceptance claim on the export the brief names.

Fourth channel (§39, host-side only): while the first dispatch runs, the probe
samples the GAME's own memory counters with psutil every `MEM_SAMPLE_EVERY_MS`
and prints the series plus a per-counter delta. The 00:01 shot's log ended at the
tag `new_rt ` — `JS_NewRuntime2` never returned — and ~7 s later the whole address
space went unreadable. Whether that is the call allocating until the host dies or a
slow-but-fine call dying of something else is only answerable from outside the
target, and process queries cost no dispatch and add no bytes to the game.
"""
from __future__ import annotations

import os
import re
import struct
import sys
import time

import psutil

from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll,
    list_exports, call_remote, call_remote_with_arg, remote_alloc, read_memory,
    assert_game_alive, dispatch_watching_buffer,
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


def log_rva_from_truncated(truncated_addr: int, base: int) -> int:
    """Recover a module-relative offset from the LOW 32 bits of its absolute address.

    ``C2DiagGetLogAddr`` returns ``const char *`` and only 32 bits of a remote
    thread's return value survive ``GetExitCodeThread`` (ruling P4), which is why
    the pointer was ruled injector-unusable. The RVA is a different story: an
    address inside the loaded image is ``base + rva`` with ``rva < 2**32``, so
    ``rva = (truncated - low32(base)) mod 2**32`` is exact even when the addition
    wrapped past 32 bits.

    Raises on an out-of-range ``truncated_addr`` — a value that cannot be 32 bits
    did not come from ``GetExitCodeThread``, and silently masking it would produce
    a plausible-looking offset at a garbage address.
    """
    if truncated_addr < 0 or truncated_addr > 0xFFFFFFFF:
        raise ValueError(
            f"truncated_addr={truncated_addr:#x} is not a 32-bit exit code — "
            "it did not come from GetExitCodeThread"
        )
    return (truncated_addr - (base & 0xFFFFFFFF)) & 0xFFFFFFFF


def poll_report_lines(rc: int, report: dict) -> list[str]:
    """Render the polling dispatcher's measurements as printable lines.

    Pure over the dict ``dispatch_watching_buffer`` fills, so the judgement it has
    to make — whether the exit code is a step code at all — is testable without a
    process. That judgement is the reason this exists: a thread killed by process
    termination reports the PROCESS exit code, so a number that decodes neatly to
    ``intrinsic/Date`` can also be the game's own exit status. Silence about which
    one it is would be the loudest error this probe could make.
    """
    lines = [
        f"primed={report.get('primed_bytes')} reads={report.get('reads')} "
        f"failures={report.get('read_failures')} "
        f"first_read_ms={report.get('first_read_ms')} "
        f"first_failure_ms={report.get('first_failure_ms')}",
        f"thread exit code={report.get('thread_exit_code')} "
        f"process exit code={_hex_or_none(report.get('process_exit_code'))} "
        f"thread_returned_while_alive={report.get('thread_returned_while_alive')}",
    ]
    if not report.get("thread_returned_while_alive"):
        lines.append(
            f"WARNING: the thread never returned while the process was alive, so rc={rc} "
            f"is not proven to be a step code — a terminated thread reports the PROCESS "
            f"exit code (here {_hex_or_none(report.get('process_exit_code'))}); "
            "treat decode_init_rc's answer as unconfirmed"
        )
    for label in sorted(report.get("witness", {})):
        w = report["witness"][label]
        lines.append(
            f"witness {label}: oks={w.get('oks')} fails={w.get('fails')} "
            f"text={w.get('best_text')!r}"
        )
    return lines


def _hex_or_none(value) -> str:
    return "-" if value is None else f"{value:#x}"


# --- §39 host-memory sampling (pure half) -----------------------------------
#
# The 00:01 shot ended the ambiguity about WHERE the sequence dies and opened a
# worse one: the log's last tag was `new_rt `, i.e. the remote thread never
# returned from JS_NewRuntime2 at all, and ~7 s later the whole address space
# became unreadable. Two shapes fit that and they need opposite fixes:
#   (a) the call is slow but fine and the host dies of something else entirely;
#   (b) the call is allocating until the host cannot survive it — the §33
#       heap_free use-after-free lineage, where a corrupted size makes the
#       allocator's bookkeeping run away.
# The target side cannot answer this without adding code to the thing under
# measurement, and a second dispatch cannot either (it lands after the death).
# So the sampler reads the host's OWN counters from outside, through process
# queries — no extra remote call, no bytes written into the game.

_SAMPLE_COUNTER = re.compile(r"(\w+)=(\d+)K")
_SAMPLER_FAILED = "sampler raised "

# The window to cover is the ~7 s the 00:01 shot showed between entering
# JS_NewRuntime2 and the address space going unreadable. 250 ms gives ~28
# readings across it — enough to see a ramp, few enough that the queries
# themselves are not the load on a host that is already dying.
MEM_SAMPLE_EVERY_MS = 250


def format_memory_sample(rss_bytes: int, vms_bytes: int, private_bytes) -> str:
    """Render one memory reading as ``rss=…K vms=…K private=…`` in whole KiB.

    The labels are the psutil field names verbatim so the shot's log needs no
    re-interpretation later, and KiB integers because the values being compared
    are gigabytes apart: a byte-exact number would only add digits.
    ``private_bytes`` is ``None`` when the private working set could not be
    queried (``memory_full_info`` needs a privilege ``memory_info`` does not) and
    renders ``NA`` — an unmeasured counter must never be readable as a zero,
    which in a growth log is the difference between "the host allocated nothing"
    and "we could not look".
    """
    private = "NA" if private_bytes is None else f"{private_bytes // 1024}K"
    return (f"rss={rss_bytes // 1024}K vms={vms_bytes // 1024}K private={private}")


def memory_growth_lines(report: dict) -> list[str]:
    """Summarise ``report["samples"]`` as one first->last line per counter.

    Pure over the dict ``dispatch_watching_buffer`` fills. The question the
    samples exist to answer is whether the working set ran away during the
    ``JS_NewRuntime2`` window, so each line carries the net delta, how many
    readings it came from, and the millisecond span they cover — a big delta over
    a short window is the allocation storm, a flat one is shape (a).
    ``sampler raised …`` entries carry no counters: they are reported as their own
    line (the moment sampling stopped is itself a measurement of when the host
    became unreadable) and skipped by the per-counter series.
    """
    samples = report.get("samples") or []
    if not samples:
        return []

    series: dict[str, list[tuple[float, int]]] = {}
    failures: list[str] = []
    for ms, text in samples:
        if _SAMPLER_FAILED in text:
            failures.append(text)
            continue
        for name, value in _SAMPLE_COUNTER.findall(text):
            series.setdefault(name, []).append((ms, int(value)))

    lines = []
    for name in sorted(series):
        readings = series[name]
        first, last = readings[0][1], readings[-1][1]
        window = readings[-1][0] - readings[0][0]
        lines.append(f"{name} KiB: first={first} last={last} delta={last - first:+d} "
                    f"samples={len(readings)} window={window:.1f}ms")
    for text in failures:
        lines.append(f"sampler raised: {text[len(_SAMPLER_FAILED):]}")
    return lines


def psutil_memory_sampler(proc) -> callable:
    """Return a zero-arg sampler over a psutil process object's memory counters.

    Takes the process *object* rather than the pid so the counters — which are the
    whole measurement — can be pinned by a fake in ``test_c2_harness.py``, with no
    process involved. psutil itself is imported by the caller that has a pid.

    ``memory_full_info()`` is asked for the private working set and its failure is
    swallowed into ``private=NA`` — losing one of three counters is not worth
    losing the series, and ``format_memory_sample`` makes the loss visible.
    """
    def sample() -> str:
        info = proc.memory_info()
        try:
            full = proc.memory_full_info()
        except Exception:  # noqa: BLE001 - partial counters beat no counters
            full = None
        return format_memory_sample(info.rss, info.vms, getattr(full, "private", None))

    return sample


def sample_window(sampler, duration_ms: int, every_ms: int = 250,
                  clock=time.monotonic, pause=time.sleep) -> list[tuple[float, str]]:
    """Collect ``sampler()`` readings for ``duration_ms``, one per ``every_ms``.

    The control shot (§39) needs the same series the dispatch produced, but with
    NO init dispatch in it: the c39 shot's counters were flat for ~5 s and then
    FELL by 4.4 GiB before the address space went unreadable, which is a process
    releasing memory — so the open question is whether the host tears itself down
    about five seconds into being watched no matter what we ask it to do. A window
    with no dispatch answers that, and the series must be collectable without a
    process present, hence the injected clock and pause.

    Stops at the first raising sample and records it, matching
    ``dispatch_watching_buffer``'s policy: the host vanishing mid-window is the
    outcome, not an error to propagate.
    """
    t0 = clock()
    samples: list[tuple[float, str]] = []
    next_sample_ms = 0.0
    while True:
        ms = (clock() - t0) * 1000.0
        if ms >= duration_ms:
            return samples
        if ms >= next_sample_ms:
            next_sample_ms = ms + every_ms
            try:
                samples.append((ms, str(sampler())))
            except Exception as exc:  # noqa: BLE001 - same reason as the dispatcher
                samples.append((ms, f"sampler raised {exc}"))
                return samples
        pause(every_ms / 1000.0)


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


# --- the on-disk diagnostic channel (evidence §38) --------------------------
#
# Must match C2_DIAG_FILE_DIR in src/dll/quickjs/quickjs_wrapper.c. This is a
# LOCAL file — the probe runs on the game box — and that is the entire point: the
# in-process alternatives all read the target's address space, and on this host
# the address space can disappear between the dispatch returning and the read.
#   * 22:41 shot: C2Init answered rc=3, the follow-up C2LogInto dispatch found no
#     host at all.
#   * 22:47 shot: the one-shot shape (log copied into the caller's remote buffer
#     INSIDE the dispatch) then failed the very next ReadProcessMemory with
#     ERROR_PARTIAL_COPY (gle 299). The bytes had been written; they died with the
#     process.
# Text appended to a file by the sequence before it returns cannot be lost that
# way, so the disk copy is the authoritative one and the buffer is the fast path.
DIAG_FILE_DIR = r"C:/temp"


def diag_file_path(pid: int) -> str:
    """Path the DLL appends its step log to, keyed on the pid we injected into."""
    return f"{DIAG_FILE_DIR}/c2_diag_{pid}.log"


def clear_diag_file(path: str) -> bool:
    """Delete the diag file before the dispatch; True if a stale copy existed.

    Absence after the dispatch is only meaningful if it was absent before, so this
    runs unconditionally: no file ⇒ the sequence never reached its finish block (or
    the module predates §38), which is a different finding from stale text.
    """
    try:
        os.remove(path)
        return True
    except FileNotFoundError:
        return False


def read_diag_file(path: str) -> str:
    """Whole file decoded as ascii; ``""`` when it is not there. Never raises."""
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("ascii", errors="replace")
    except FileNotFoundError:
        return ""


def last_diag_line(text: str) -> str:
    """The newest ``rc=<n> <log>`` line, or ``""`` for empty/whitespace text.

    Append mode means one line per sequence run (C2DiagQJSInto, then C2Init on the
    success path), so the last non-blank line is the run that just happened.
    """
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def diag_file_rc(line: str) -> int | None:
    """The ``rc=<n>`` prefix of a diag line, or None if it has no such prefix."""
    if not line.startswith("rc="):
        return None
    digits = line[3:].split(" ", 1)[0]
    try:
        return int(digits)
    except ValueError:
        return None


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


def describe_init_rc(rc: int) -> str:
    """One-line rendering of a C2Init step code, unmapped values included.

    Never raises: an unmapped code is itself the finding worth printing, so it
    comes back as ``UNMAPPED — <why>`` instead of aborting the report.
    """
    try:
        bucket, name = decode_init_rc(rc)
    except ValueError as exc:
        return f"UNMAPPED — {exc}"
    return f"bucket={bucket} name={name}"


def report_init_failure(pid: int, base: int, log_rva: int, rc: int) -> str:
    """Print everything a nonzero C2Init rc can tell us, then hand back the line.

    The PRIMARY read path is the one-shot dispatch in ``main``: C2DiagQJSInto
    fills our buffer with the log in the same thread call that runs the
    sequence. This is the fallback for when that buffer comes back empty — it
    dispatches `C2LogInto` separately, which is a race the 2026-10-21 shot lost
    (C2Init answered rc=3, then the host was gone before any second dispatch). A
    dead host is therefore reported as such rather than raising an unrelated
    RuntimeError from the read-back dispatch.
    """
    decoded = describe_init_rc(rc)
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
    # The world-state gate (spec §1): a shot that cannot prove the premise
    # must not inject.  The refusal happens BEFORE inject_dll — "injected,
    # then noticed the premise was false" is the failure mode this removes.
    from world_probe import gate_install  # pyright: ignore[reportMissingImports]
    gate_install('task5')
    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    print(f"[task5] {dll_name} base (64-bit): 0x{base:x}")

    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    print("[task5] MZ header at base OK")

    exports = list_exports(dll_path)  # Windows-side copy (P10)
    init_rva = exports["C2Init"]
    diag_into_rva = exports["C2DiagQJSInto"]
    into_rva = exports["C2QuickJSPointersInto"]
    log_rva = exports["C2LogInto"]
    print(f"[task5] C2Init RVA from PE reparse:                  0x{init_rva:x}")
    print(f"[task5] C2DiagQJSInto RVA from PE reparse:           0x{diag_into_rva:x}")
    print(f"[task5] C2QuickJSPointersInto RVA from PE reparse:   0x{into_rva:x}")
    print(f"[task5] C2LogInto RVA from PE reparse:               0x{log_rva:x}")

    sanity = call_remote(pid, base, exports["C2Sanity"])
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch "
        f"the init sequence against this module copy"
    )
    assert_game_alive(pid)
    print("[task5] C2Sanity == 42, game alive — init dispatch authorized")

    # --- SHOT 1, the one-shot: C2DiagQJSInto runs the SAME sequence C2Init runs
    # --- (since §37 both are one-line wrappers over c2_diag_sequence) AND copies
    # --- g_diag_log into our buffer inside that same thread call.
    #
    # Why not C2Init + a separate log read: the 2026-10-21 22:41 shot did exactly
    # that and lost the race — C2Init returned rc = 3 (so the remote thread ran
    # to completion) and the process was gone before the follow-up C2LogInto
    # dispatch, taking the step text and the captured exception with it. One
    # dispatch means the text is already in our hands the moment the rc is.
    #
    # And why the buffer is now POLLED rather than read once (§38): the 22:47 shot
    # proved the plain one-shot read loses — the dispatch returned, then
    # ReadProcessMemory of the buffer the remote thread had already filled failed
    # with ERROR_PARTIAL_COPY. The poller catches the copy while the thread is still
    # running, and the sequence ALSO appends its log to a file before returning, so
    # the disk file stays as a second witness (on the 23:03 shot it produced
    # nothing, which is what the WARNING below is for).
    diag_path = diag_file_path(pid)
    stale = clear_diag_file(diag_path)
    print(f"[task5] diag file        = {diag_path} "
          f"({'stale copy deleted' if stale else 'absent before dispatch'})")

    # --- §38 the witness address: the DLL's OWN g_diag_log static.
    #
    # The 23:44 shot found the caller's buffer unreadable (gle 299) from the first
    # poll iteration while the remote thread still ran to completion. Two opposite
    # readings fit that: the address space was already gone, or only our page was.
    # Polling an address the module itself owns settles it — and if the process is
    # readable at all, the static carries the log as each step appends to it, so the
    # text stops depending on the callee's end-of-sequence copy reaching our buffer.
    #
    # C2DiagGetLogAddr returns `const char *` and only its low 32 bits cross the
    # thread exit code (ruling P4) — enough to recover the RVA exactly. The dispatch
    # is a pure address read: no QuickJS, and the non-init dispatches (LoadLibrary,
    # C2Sanity) are 0/2 host losses (§36.3), so this costs no fidelity and no life.
    # What it does NOT give is a pre-dispatch proof the mapping is right: the static
    # is empty until the sequence runs, so an all-zero read is consistent with both
    # a correct and a wrong-but-mapped address. The content's shape (`rt=0x…`) is the
    # verifier, and it only exists on a shot that produces text.
    truncated_log_addr = call_remote(pid, base, exports["C2DiagGetLogAddr"])
    log_static_rva = log_rva_from_truncated(truncated_log_addr, base)
    log_static_addr = base + log_static_rva
    print(f"[task5] C2DiagGetLogAddr → truncated 0x{truncated_log_addr:x} "
          f"→ g_diag_log rva 0x{log_static_rva:x} @ 0x{log_static_addr:x}")
    pre = read_memory(pid, log_static_addr, 512).split(b"\x00", 1)[0]
    print(f"[task5] g_diag_log before the dispatch = {pre.decode('ascii', 'replace')!r}")
    assert_game_alive(pid)

    log_buf = remote_alloc(pid, 512)
    assert log_buf, "remote_alloc(512) returned NULL"
    print(f"[task5] log buffer @ 0x{log_buf:x} (allocated BEFORE the dispatch)")

    # --- §39 the third channel: the host's own memory counters, read while the call
    # --- runs. The 00:01 shot pinned the last log tag to `new_rt ` (JS_NewRuntime2
    # --- never returned) with ~7 s before the address space vanished, and only the
    # --- process's counters over that window say whether it was allocating itself to
    # --- death or dying of something the sequence has nothing to do with. psutil
    # --- queries the same handle access the reads already require, so this adds no
    # --- dispatch and no bytes inside the game.
    mem_proc = psutil.Process(pid)
    print(f"[task5] mem sampler      = psutil {psutil.__version__} over pid {pid}, "
          f"every {MEM_SAMPLE_EVERY_MS}ms")

    report: dict = {}
    rc, buffer_log = dispatch_watching_buffer(
        pid, base, diag_into_rva, log_buf, 512, timeout_ms=60000,
        note=lambda message: print(f"[task5] poll: {message}"),
        witnesses=(("g_diag_log", log_static_addr, 512),),
        report=report,
        sampler=psutil_memory_sampler(mem_proc),
        sample_every_ms=MEM_SAMPLE_EVERY_MS,
    )
    # The rc is printed the instant the call returns and the text was already
    # caught DURING it: in the 22:47 shot a read_memory placed after the wait sat
    # between the dispatch and this print, threw, and lost the rc as well.
    print(f"[task5] C2DiagQJSInto rc = {rc}")
    print(f"[task5] decoded rc       = {describe_init_rc(rc)}")
    for line in poll_report_lines(rc, report):
        print(f"[task5] poll report      = {line}")
    for ms, text in report.get("samples", []):
        print(f"[task5] mem @ {ms:8.1f}ms = {text}")
    for line in memory_growth_lines(report):
        print(f"[task5] mem growth       = {line}")
    print(f"[task5] buffer log       = {buffer_log!r}")

    disk_line = last_diag_line(read_diag_file(diag_path))
    print(f"[task5] on-disk log      = {disk_line!r}")
    disk_rc = diag_file_rc(disk_line)
    if disk_rc is not None and disk_rc != rc:
        print(f"[task5] WARNING: the diag file's last line says rc={disk_rc} but the "
              f"dispatch answered {rc} — the file is not this dispatch's output")
    # Most to least trustworthy: the callee's own copy into our buffer, then the
    # static as it was being built, then the disk file (which on the 23:03 and
    # 23:44 shots produced nothing at all).
    witness_text = report.get("witness", {}).get("g_diag_log", {}).get("best_text", "")
    log = buffer_log or witness_text or disk_line

    if rc != 0:
        if not log:
            # Neither channel produced text: last resort is a separate pure read,
            # which reports honestly if there is no host left to read from.
            decoded = report_init_failure(pid, base, log_rva, rc)
        else:
            decoded = describe_init_rc(rc)
        raise AssertionError(
            f"C2 init sequence rc = {rc} — {decoded} — log {log!r}"
        )
    assert_game_alive(pid)
    print("[task5] shared sequence rc == 0, game alive")

    # --- SHOT 2, the literal Task 5 gate: C2Init itself, so the acceptance claim
    # --- rests on the export named in the brief rather than on its §37 twin. Only
    # --- dispatched when the sequence already returned 0 — i.e. the host survived
    # --- one full QuickJS init, the case where a second init is affordable. It
    # --- runs LAST so the pointers read below belong to it.
    rc2 = dispatch_c2_init_once(pid, base, init_rva)
    print(f"[task5] C2Init rc = {rc2}")
    if rc2 != 0:
        decoded = report_init_failure(pid, base, log_rva, rc2)
        raise AssertionError(
            f"DIVERGENCE: the shared sequence returned 0 through C2DiagQJSInto but "
            f"C2Init returned {rc2} ({decoded}). Since §37 both exports call the same "
            "C function, so this cannot be a code difference — suspect a wrong/stale "
            "module copy, or a host that died between the two dispatches."
        )
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
