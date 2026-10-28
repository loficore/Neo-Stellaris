"""One-off discriminator: why did EVERY §44 capture get ``SuspendThread gle=5``?

The §44 shot probed the handle returned by ``CreateRemoteThread``; the read-only
control ``c2_control_suspendcap.py`` probed the game's own threads through
``OpenThread`` and got 12/12 readable ``Rip`` values with zero refusals. So the
session is not the wall. Two structural differences are left, and this script
measures both against a child process this session owns — no game, no DLL, no
injection, nothing of ours executed by anybody else:

  * **handle kind**: a thread handle from ``CreateRemoteThread`` may not carry the
    suspend right the way an ``OpenThread`` handle does;
  * **thread state**: ``SuspendThread`` on a thread that has already exited is
    known to report ``ERROR_ACCESS_DENIED`` rather than "gone".

Matrix, on the same still-sleeping remote thread and then again after it exits:
``created-handle`` / ``opened-handle`` x ``alive`` / ``exited``.

    python C:/temp/threadhandle_matrix.py

Scratch probe (frozen after this run); it does not build or inject anything.
"""

import ctypes
import subprocess
import sys
import time

import c2_harness
from c2_harness import (
    kernel32_call_address,
    capture_thread_state,
    open_process_handle,
    open_thread_handle,
    close_handle,
)


def probe(label, thread_handle, process_handle):
    state = capture_thread_state(thread_handle, process_handle)
    err = state["context_err"] or state["times_err"] or "none"
    rip = state["rip"]
    print(
        f"    {label:32s} rip={'none' if rip is None else hex(rip)} "
        f"th_kernel_us={state['thread_kernel_us']} err={err}"
    )
    return state


def main() -> int:
    # The child is spawned by explicit interpreter path rather than
    # ``sys.executable``: a first attempt through ``sys.executable`` produced a
    # child with no visible threads at all, which would have made every row of
    # this matrix meaningless.
    python = (
        sys.executable
        if sys.executable and "Python" in sys.executable
        else r"C:\Users\13229\AppData\Local\Programs\Python\Python313\python.exe"
    )
    child = subprocess.Popen([python, "-c", "import time; time.sleep(60)"])
    pid = child.pid
    sleep_addr = kernel32_call_address(b"Sleep")
    k32 = c2_harness._kernel32()
    print(
        f"[matrix] our python={sys.executable} child pid={pid} "
        f"kernel32!Sleep=0x{sleep_addr:x}"
    )

    tid = ctypes.c_uint(0)
    launch_handle = open_process_handle(pid)
    created = k32.CreateRemoteThread(
        launch_handle, None, 0, sleep_addr, ctypes.c_void_p(8000), 0, ctypes.byref(tid)
    )
    close_handle(launch_handle)
    if not created:
        print(f"[matrix] CreateRemoteThread failed gle={ctypes.get_last_error()}")
        return 1
    print(f"[matrix] remote thread tid={tid.value} created")

    proc_handle = open_process_handle(pid)
    opened = open_thread_handle(tid.value)
    try:
        print("[matrix] while the thread is sleeping (8 s):")
        probe("created-handle alive", created, proc_handle)
        probe("opened-handle  alive", opened, proc_handle)

        k32.WaitForSingleObject(created, 20000)
        print("[matrix] after the thread returned:")
        probe("created-handle exited", created, proc_handle)
        probe("opened-handle  exited", opened, proc_handle)
    finally:
        close_handle(opened)
        close_handle(proc_handle)
        k32.CloseHandle(created)
        child.kill()
        child.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
