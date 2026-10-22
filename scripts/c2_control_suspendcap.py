"""§44 follow-up: can this session read a remote thread's ``Rip`` at all?

Why this exists. The §44 shot captured 22 thread states and every single one came
back ``err=SuspendThread gle=5``, so the ``Rip`` axis — the axis the authorization
asked for — produced no data. Two explanations fit that, and they say opposite
things about the next shot:

  * **capability**: the ssh logon session cannot suspend ``stellaris.exe``, in which
    case the fix is a token/session that can (SeDebugPrivilege actually enabled, or
    the launcher's interactive-session bridge) and §44's ``Rip`` question is still
    open;
  * **thread state**: the session can suspend, and ``gle=5`` was about *that*
    thread — ``SuspendThread`` on a thread that has already exited is documented to
    fail with ``ERROR_ACCESS_DENIED``. If so, the §44 window had already lost its
    remote thread and no change of session would have bought a single ``Rip``.

This script decides between them without touching anything: no DLL, no injection, no
dispatch, no byte written. It opens the game's *own* threads — the ones a healthy
main-menu process has ~120 of — and runs the exact §44 instrument
(``capture_thread_state``: ``GetThreadTimes`` then ``SuspendThread`` →
``GetThreadContext`` → ``ResumeThread``) on each, then resumes immediately.

  * at least one readable ``Rip``  => the channel works from this session. §44's
    ``gle=5`` was the thread, and the escalation question ("do we have to hook
    QuickJS?") stays answerable with the read-only probe;
  * every thread ``gle=5``        => the session is the wall. Fix the session before
    spending another killed shot on a thread-state probe;
  * some work, some do not        => per-thread (a protected or exiting thread);
    the probe is usable, just not universal.

The game's own ``Rip`` values are a bonus calibration for ``classify_rip``: waiting
threads should read back inside ``ntdll``/``win32u`` and running ones inside
``stellaris.exe``, which is the first on-device proof that our hand-pinned
``CONTEXT`` layout decodes real values.

Run ON WINDOWS (ruling P5: uploaded to C:/temp, bare-name imports):
    python C:/temp/c2_control_suspendcap.py [max_threads]
"""
from __future__ import annotations

import sys

import psutil

from c2_harness import (
    resolve_pid, resolve_base_address, pe_image_size,
    capture_thread_state, format_thread_state, open_process_handle,
    open_thread_handle, close_handle,
)

# Enough threads to make "all of them failed" mean something, few enough that a
# brief suspension of each is over before anything notices. A main-menu Stellaris
# had 120 threads in the §44 baseline control.
DEFAULT_MAX_THREADS = 12

CAPABLE = "capable"
INCAPABLE = "incapable"
PARTIAL = "partial"
NO_SAMPLES = "no-samples"


def thread_ids(proc, limit: int) -> list:
    """The game's own thread ids, capped at `limit`.

    Sorted so two runs describe the same set of threads with the same names.
    """
    return sorted(t.id for t in proc.threads())[:limit]


def suspend_cap_verdict(results: list) -> tuple:
    """Classify per-thread capture attempts into one claim about this session.

    `results` is a list of ``{"tid", "open_err", "state"}`` dicts, `state` being
    what ``capture_thread_state`` returned (or ``None`` when the open failed). The
    axes are the two ways a thread can answer: a readable ``Rip``, or a
    ``SuspendThread gle=5`` refusal.
    """
    if not results:
        return NO_SAMPLES, "no thread was attempted"
    readable = [r for r in results if (r.get("state") or {}).get("rip") is not None]
    denied = [r for r in results
              if ((r.get("state") or {}).get("context_err") or "")
              .startswith("SuspendThread gle=5")]
    unopened = [r for r in results if r.get("open_err")]
    total = len(results)
    reason = (f"readable_rip={len(readable)}/{total} "
              f"suspend_denied_gle5={len(denied)}/{total} "
              f"openthread_failed={len(unopened)}/{total}")
    if readable and len(denied) == 0 and not unopened:
        return CAPABLE, reason
    if readable:
        return PARTIAL, reason
    if len(denied) == total:
        return INCAPABLE, reason + " — every thread refused identically"
    return INCAPABLE, reason + " — no thread produced a Rip"


def cap_lines(results: list, base: int, image_size: int) -> list:
    """One rendered line per attempt, in attempt order."""
    lines = []
    for r in results:
        if r.get("open_err"):
            lines.append(f"tid={r['tid']} open_err={r['open_err']}")
            continue
        lines.append(f"tid={r['tid']} "
                     + format_thread_state(r["state"], base, image_size))
    return lines


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    max_threads = int(args[0]) if args else DEFAULT_MAX_THREADS

    pid = resolve_pid("stellaris")
    proc = psutil.Process(pid)
    exe_path = proc.exe()
    base = resolve_base_address(pid, "stellaris.exe")
    image_size = pe_image_size(exe_path)
    print(f"[cap] pid={pid} exe={exe_path} base 0x{base:x} "
          f"image=0x{image_size:x} dll=none injected=none dispatched=none")

    handle = open_process_handle(pid)
    results = []
    try:
        for tid in thread_ids(proc, max_threads):
            entry = {"tid": tid, "open_err": None, "state": None}
            try:
                th = open_thread_handle(tid)
            except RuntimeError as exc:
                entry["open_err"] = str(exc)
                results.append(entry)
                print(f"[cap] {cap_lines(results[-1:], base, image_size)[0]}")
                continue
            try:
                entry["state"] = capture_thread_state(th, handle)
            finally:
                close_handle(th)
            results.append(entry)
            print(f"[cap] {cap_lines(results[-1:], base, image_size)[0]}")
    finally:
        close_handle(handle)

    alive = proc.is_running()
    label, reason = suspend_cap_verdict(results)
    print(f"[cap] attempts={len(results)} host_still_running={alive}")
    print(f"[cap] VERDICT {label}: {reason}")
    return 0 if label == CAPABLE else 1


if __name__ == "__main__":
    sys.exit(main())
