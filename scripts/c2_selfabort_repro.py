"""§45's self-checker, maintained: does this DLL terminate its host by itself?

Formerly ``scripts/scratch/2026-10_abortexit/dll_abort_repro.py``; that frozen original
stays exactly where it is, because §45's evidence log quotes it by basename. This copy is
the interface the §45 fix loop runs after every rebuild — edit → ``zig build`` → scp the
new bytes to the Windows host under any name → run this — so it lives at ``scripts/`` top
level, keeps the ``c2_`` prefix and the ``C:/temp/<name>.py`` wire contract (ruling P5),
and takes the DLL path as an argument instead of defaulting to one hard-coded file.

Why it exists: the §44 shot's process exit code was ``0x3``, and the thread exit code read
``3`` too — which the harness already warns is not independent evidence, because a thread
killed by process termination reports the process status. The matrix probe
(``2026-10_threadhandle_matrix/threadhandle_matrix.py``) then proved the session can
suspend and read a live thread's context perfectly well (12/12 readable ``Rip`` on the
game's own threads), so ``SuspendThread gle=5`` on all 22 §44 captures means one thing
only: **that thread was not suspendable at every sample instant**, which is the state of a
thread in a process that has already begun terminating.

That points at a mechanism nobody had written down: UCRT ``abort()`` terminates the
process with **exit status 3** — measured on this host in 2026-10-22 with
``ctypes.cdll.msvcrt.abort()`` in a child (returncode 3), while ``os.abort()`` fastfails
with 0xC0000409. ``libs/quickjs/quickjs.c`` calls plain ``abort()`` in 30 places, and the
DLL compiles that file straight in (``build.zig:8-14``).

So: load the same artifact the game loaded, in a process this script owns, and see whether
it dies without being touched. Zero game, zero injection, zero dispatch.

    python C:/temp/c2_selfabort_repro.py <dll_path>

Expected if the hypothesis holds: the child never prints ``SURVIVED rc=``, and its return
code is 3. Expected once the defect is fixed: the child returns a step code and lives.
Exit code 0 = the abort signature was reproduced, 1 = it was not (the child timed out, or
it never got as far as loading the DLL — that case says nothing about the artifact and
says so on its own ``VERDICT`` line), 2 = the DLL path is missing or unreadable.

**This copy adds one observation channel over the original — Task 1's ring recorder — and
it adds it as a second READER THREAD, not as a call after the sequence.**

    Do not "simplify" the recorder watcher into a single `C2DiagMfRecordsInto` dump placed
    after `C2DiagQJSInto`. That line is unreachable on the artifact under investigation.

§45 measured why: the child's main thread aborts **inside** ``C2DiagQJSInto`` (witness
stops at ``new_rt MmMmMm``, ``SURVIVED rc=`` never prints), so anything the main thread
would print after that call never runs, and Task 3 would have no recorder data to
classify. The watcher therefore polls ``C2DiagMfRecordsInto`` about every 2 ms, emits a
change-gated ``MFREC <seq> watch '<rendering>'`` line, caps itself at 400 emissions, and
starts **before** the gate order runs. The post-call emission is kept as well: same
``MFREC`` shape with the tag ``post``, printed unconditionally rather than change-gated,
because once Task 4 fixes the defect the call returns and that line is what its
acceptance reads.

The cost of that design is stated rather than hidden: a second thread reading a dying
process is a perturbation, and the recorder's own notes say a row can be torn if a writer
rewrites its slot mid-snapshot (the renderer degrades such a row to the ``_`` + dash form,
so a torn row is a race artefact, never a claim about the allocator). If the child ever
comes back **alive** while the defect is still supposed to be present, that is
Task 3's stop-and-report condition, not a pass.

Key lines on this tool's stdout (the child's lines are echoed verbatim between the two
``--- child … (verbatim) ---`` markers; the parent's carry the ``[repro] `` prefix and
``VERDICT`` is always last):

    BASE <name> 0x<base>           the child's module base — turns panic frames into RVAs
    LOGADDR 0x<addr>               g_diag_log, via C2DiagGetLogAddr
    RECORDER ok | RECORDER absent  whether C2DiagMfRecordsInto is in this artifact
    SANITY <rc>                    C2Sanity, expected 42 — the same gate order the shot uses
    WITNESS '<g_diag_log text>'     change-gated, 0.2 ms reader thread
    MFREC <seq> <tag> '<rendering>' ring recorder: change-gated (watch) / final (post)
    SURVIVED rc=<n>                 only if C2DiagQJSInto returned
    LOG '<caller buffer>'           ditto
    [repro] VERDICT: ...            the abort signature, or its absence

**Provenance note for the next log**: §45's record quotes the frozen original's
``[repro] child stdout = '<one repr of everything>'`` line. This copy echoes the child's
lines one-per-line instead, because an ``MFREC`` rendering is 8 rows and a repr collapses
them into a single unreadable line. Same bytes, different framing — when comparing a new
run against `evidence/logs/c2_selfabort_4_4_4.log`, compare the ``WITNESS``/``BASE``
*values*, not the parent's line shape.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from collections import Counter

# The key-line vocabulary this tool's stdout is built from. MFREC is in it because the
# recorder is a first-class channel of the self-checker, not an extra dump.
KEY_LINES = ("BASE", "LOGADDR", "RECORDER", "SANITY", "WITNESS", "MFREC",
             "SURVIVED", "LOG", "VERDICT")

CHILD = r"""
import ctypes, sys, threading, time

dll_path = sys.argv[1]
dll = ctypes.WinDLL(dll_path)
k32 = ctypes.windll.kernel32
k32.GetModuleHandleW.restype = ctypes.c_void_p
name = dll_path.split("\\")[-1]
base = k32.GetModuleHandleW(ctypes.c_wchar_p(name))

# Two reader threads plus the main thread all print; one lock keeps every key line to
# exactly one line of stdout, so a reader never has to reassemble a torn record.
out_lock = threading.Lock()

def emit(line):
    with out_lock:
        print(line, flush=True)

emit("BASE %s 0x%x" % (name, base or 0))

dll.C2DiagGetLogAddr.restype = ctypes.c_void_p
log_addr = ctypes.c_void_p(dll.C2DiagGetLogAddr())
emit("LOGADDR 0x%x" % (log_addr.value or 0))

def watch_witness():
    last = None
    for _ in range(20000):
        try:
            text = ctypes.string_at(log_addr.value, 96).split(b"\x00", 1)[0]
        except Exception:
            return
        if text != last:
            emit("WITNESS %r" % text.decode("ascii", "replace"))
            last = text
        time.sleep(0.0002)

# --- Task 1's ring recorder, read concurrently (see the module docstring: the post-call
# --- dump alone is unreachable, because the main thread dies inside C2DiagQJSInto).
# The export writes into the CALLER's buffer and returns the byte count; the 4096 is the
# size baked into the export's contract (exports.zig passes 4096 to C2DiagMfRecords),
# not something the caller chooses — C2DiagQJSInto above over-allocates it the same way.
# Each reader owns ONE buffer and reuses it: this thread runs inside the process under
# test, so per-poll allocations are churn in the thing being measured.
MFREC_MAX = 400
MFREC_POLL_S = 0.002
mf_seq = [0]

def read_mf_records(buf):
    if dll.C2DiagMfRecordsInto(buf) < 0:
        return ""
    return buf.value.decode("ascii", "replace")

def emit_mfrec(tag, text):
    with out_lock:
        seq = mf_seq[0]
        mf_seq[0] = seq + 1
        print("MFREC %d %s %r" % (seq, tag, text), flush=True)

def watch_mf_records():
    buf = ctypes.create_string_buffer(4096)
    last = None
    emitted = 0
    while emitted < MFREC_MAX:
        try:
            text = read_mf_records(buf)
        except Exception:
            return
        if text != last:
            emit_mfrec("watch", text)
            last = text
            emitted += 1
        time.sleep(MFREC_POLL_S)

try:
    dll.C2DiagMfRecordsInto.restype = ctypes.c_int
    dll.C2DiagMfRecordsInto.argtypes = [ctypes.c_char_p]
    have_recorder = True
    emit("RECORDER ok")
except AttributeError as exc:
    have_recorder = False
    emit("RECORDER absent %r" % str(exc))

threading.Thread(target=watch_witness, daemon=True).start()
if have_recorder:
    threading.Thread(target=watch_mf_records, daemon=True).start()

# The shot's gate order, so the standalone witness is comparable with the live one
# and both watchers have started before the sequence runs.
dll.C2Sanity.restype = ctypes.c_int
emit("SANITY %d" % dll.C2Sanity())

dll.C2DiagQJSInto.restype = ctypes.c_int
buf = ctypes.create_string_buffer(4096)
rc = dll.C2DiagQJSInto(buf)
emit("SURVIVED rc=%d" % rc)
emit("LOG %r" % buf.value.decode("ascii", "replace"))

# The post-call dump: silent on the defective artifact (unreachable), and the line
# Task 4's acceptance reads once the sequence returns. Printed unconditionally, so
# "the recorder never changed" and "the recorder was never read" stay distinguishable.
if have_recorder:
    emit_mfrec("post", read_mf_records(ctypes.create_string_buffer(4096)))
"""


def key_lines_in(stdout: str):
    """Every key line this tool's stdout carries, in order, one entry per line.

    Parent lines are recognised through their ``[repro] `` prefix, so ``VERDICT`` counts
    like the child's lines; anything else (``child returncode =``, an empty line, a raw
    panic frame) is not a key line.
    """
    found = []
    for line in (stdout or "").splitlines():
        if line.startswith("[repro] "):
            line = line[len("[repro] "):]
        head = line.split(" ", 1)[0].rstrip(":")
        if head in KEY_LINES:
            found.append(head)
    return found


def key_line_counts(stdout: str):
    """key -> how many times it appeared, for the summary line and for a quick eyeball."""
    return dict(Counter(key_lines_in(stdout)))


def child_loaded_the_dll(stdout: str) -> bool:
    """Did the child get as far as loading the module? It must have printed ``BASE``.

    This exists because return code 1 is ambiguous the way §45's own lesson reads: a
    child that loaded the artifact and survived, and a child that could not even load it
    (wrong platform, bad path, a loader failure), both end with status != 3. Without this
    check the second one prints the negative ``VERDICT`` and reads like evidence that the
    artifact does not self-terminate. It is not evidence about the artifact at all.
    """
    return "BASE" in key_line_counts(stdout)


def verdict(returncode: int, stdout: str) -> bool:
    """The §45 signature: the child died with UCRT ``abort()``'s exit status 3 **and**
    never printed ``SURVIVED``.

    Both halves are load-bearing. Status 3 alone is not this finding — the harness already
    reports a killed thread's process status as its exit code — and ``SURVIVED`` with a
    later status 3 means the sequence completed and something else terminated the process,
    which is a different event and must not be read as a reproduction. A fastfail
    (0xC0000409, what ``os.abort()`` gives) is deliberately not status 3.
    """
    return returncode == 3 and "SURVIVED" not in (stdout or "")


def rvas(stdout: str, stderr: str, dll_path: str):
    """Every address inside the loaded DLL, as an RVA, from the child's output.

    The panic trace prints absolute addresses under a different ASLR base each run; the
    ``BASE`` line is what turns them into something a symbol table can answer. The owner
    filter is the DLL under test's own basename, because a maintained tool gets whatever
    filename the fix loop scp'd it to, not one fixed name.
    """
    base = None
    for line in (stdout or "").splitlines():
        m = re.match(r"BASE \S+ 0x([0-9a-f]+)", line)
        if m:
            base = int(m.group(1), 16)
    if base is None:
        return []
    want = os.path.basename(dll_path).lower()
    module = re.compile(r"0x([0-9a-f]+) in \?\?\? \(([^)]+)\)")
    addrs = [int(a, 16) for a, owner in module.findall(stderr or "")
             if owner.lower().endswith(".dll") and want in owner.lower()]
    return sorted({a - base for a in addrs if a >= base})


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    usage = "[repro] usage: python C:/temp/c2_selfabort_repro.py <dll_path>"
    if not argv:
        print(usage)
        return 2
    dll_path = argv[0]
    if not os.path.exists(dll_path):
        print(f"[repro] {dll_path} does not exist — scp the artifact first (ruling P5: "
              "this tool takes a path, it does not fetch one)")
        print(usage)
        return 2

    print(f"[repro] dll={dll_path}")
    try:
        proc = subprocess.run([sys.executable, "-c", CHILD, dll_path],
                              capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print("[repro] the child did not exit within 120 s; no exit status was observed")
        print("[repro] VERDICT: inconclusive — the child neither died with status 3 nor "
              "returned; treat a hang as a stop-and-report condition, not a reproduction")
        return 1

    print("[repro] --- child stdout (verbatim) ---")
    print(proc.stdout.rstrip("\n"))
    print("[repro] --- child stderr (verbatim) ---")
    print(proc.stderr.rstrip("\n"))

    counts = key_line_counts(proc.stdout)
    print(f"[repro] child returncode = {proc.returncode} "
          f"(0x{proc.returncode & 0xFFFFFFFF:x})")
    print("[repro] child key lines = "
          + (", ".join(f"{k}={counts[k]}" for k in sorted(counts)) or "none"))
    print("[repro] in-DLL RVAs from the panic stack: "
          + ", ".join(f"{r:#x}" for r in rvas(proc.stdout, proc.stderr, dll_path)))
    if verdict(proc.returncode, proc.stdout):
        print("[repro] VERDICT: the DLL terminated its own host with exit status 3 "
              "— the abort() signature, reproduced with no game involved")
        return 0
    if not child_loaded_the_dll(proc.stdout):
        print("[repro] VERDICT: inconclusive — the child never printed BASE, so the DLL was "
              "never loaded (wrong platform, bad path, or a loader failure); this says "
              "nothing about whether the artifact self-terminates")
        return 1
    print("[repro] VERDICT: the child did not die with status 3; this artifact does "
          "not self-terminate on this path")
    return 1


if __name__ == "__main__":
    sys.exit(main())
