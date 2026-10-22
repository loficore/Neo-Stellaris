"""One-off discriminator: does this DLL terminate its host by itself?

The §44 shot's process exit code was ``0x3``, and the thread exit code read ``3``
too — which the harness already warns is not independent evidence, because a thread
killed by process termination reports the process status. The matrix probe
(``2026-10_threadhandle_matrix/threadhandle_matrix.py``) then proved the session can
suspend and read a live thread's context perfectly well (12/12 readable ``Rip`` on
the game's own threads), so ``SuspendThread gle=5`` on all 22 §44 captures means one
thing only: **that thread was not suspendable at every sample instant**, which is
the state of a thread in a process that has already begun terminating.

That points at a mechanism nobody had written down: UCRT ``abort()`` terminates the
process with **exit status 3** — measured on this host in 2026-10-22 with
``ctypes.cdll.msvcrt.abort()`` in a child (returncode 3), while ``os.abort()``
fastfails with 0xC0000409. ``libs/quickjs/quickjs.c`` calls plain ``abort()`` in 30
places, and the DLL compiles that file straight in (``build.zig:8-14``).

So: load the same artifact the game loaded, in a process this script owns, and see
whether it dies without being touched.

    python C:/temp/dll_abort_repro.py

Expected if the hypothesis holds: the child never prints "child survived", and its
return code is 3. Expected if it does not: the child returns a step code and lives.

Scratch probe (frozen after this run). No game, no injection, no dispatch.
"""
import subprocess
import sys

DLL_PATH = sys.argv[1] if len(sys.argv) > 1 else r"C:\temp\sqjs_s43.dll"

CHILD = r"""
import ctypes, sys, threading, time

dll_path = sys.argv[1]
dll = ctypes.WinDLL(dll_path)
k32 = ctypes.windll.kernel32
k32.GetModuleHandleW.restype = ctypes.c_void_p
base = k32.GetModuleHandleW(ctypes.c_wchar_p(dll_path.split("\\")[-1]))
print("BASE %s 0x%x" % (dll_path.split("\\")[-1], base or 0), flush=True)

dll.C2DiagGetLogAddr.restype = ctypes.c_void_p
log_addr = ctypes.c_void_p(dll.C2DiagGetLogAddr())
print("LOGADDR 0x%x" % (log_addr.value or 0), flush=True)

def watch():
    last = None
    for _ in range(20000):
        try:
            text = ctypes.string_at(log_addr.value, 96).split(b"\x00", 1)[0]
        except Exception:
            return
        if text != last:
            print("WITNESS %r" % text.decode("ascii", "replace"), flush=True)
            last = text
        time.sleep(0.0002)

threading.Thread(target=watch, daemon=True).start()

# The shot's gate order, so the standalone witness is comparable with the live one
# and the watcher has started before the sequence runs.
dll.C2Sanity.restype = ctypes.c_int
print("SANITY %d" % dll.C2Sanity(), flush=True)

dll.C2DiagQJSInto.restype = ctypes.c_int
buf = ctypes.create_string_buffer(4096)
rc = dll.C2DiagQJSInto(buf)
print("SURVIVED rc=%d" % rc, flush=True)
print("LOG %r" % buf.value.decode("ascii", "replace"), flush=True)
"""


def rvas(stdout: str, stderr: str):
    """Every address inside the loaded DLL, as an RVA, from the child's output.

    The panic trace prints absolute addresses under a different ASLR base each
    run; the ``BASE`` line is what turns them into something a symbol table can
    answer.
    """
    import re
    base = None
    for line in stdout.splitlines():
        m = re.match(r"BASE \S+ 0x([0-9a-f]+)", line)
        if m:
            base = int(m.group(1), 16)
    if base is None:
        return []
    module = re.compile(r"0x([0-9a-f]+) in \?\?\? \(([^)]+)\)")
    addrs = [int(a, 16) for a, owner in module.findall(stderr)
             if owner.lower().endswith(".dll") and "sqjs" in owner.lower()]
    return sorted({a - base for a in addrs if a >= base})


def main() -> int:
    proc = subprocess.run([sys.executable, "-c", CHILD, DLL_PATH],
                          capture_output=True, text=True, timeout=120)
    print(f"[repro] dll={DLL_PATH}")
    print(f"[repro] child returncode = {proc.returncode} "
          f"(0x{proc.returncode & 0xFFFFFFFF:x})")
    print(f"[repro] child stdout = {proc.stdout.strip()!r}")
    print(f"[repro] child stderr = {proc.stderr.strip()!r}")
    print("[repro] in-DLL RVAs from the panic stack: "
          + ", ".join(f"{r:#x}" for r in rvas(proc.stdout, proc.stderr)))
    if proc.returncode == 3 and "SURVIVED" not in proc.stdout:
        print("[repro] VERDICT: the DLL terminated its own host with exit status 3 "
              "— the abort() signature, reproduced with no game involved")
        return 0
    print("[repro] VERDICT: the child did not die with status 3; this artifact does "
          "not self-terminate on this path")
    return 1


if __name__ == "__main__":
    sys.exit(main())
