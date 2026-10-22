"""§44 baseline: does an UNTOUCHED game accrue process USER CPU time?

Why this exists. The §44 shot read the game's own process CPU counters while the init
sequence ran, and across all 22 captures `pr_user_us` never moved from 42,218,750 us
while `pr_kernel_us` advanced by 218,750 us. Nothing in the process was executing
user-mode instructions during the frozen window — that is the reading that excludes
"QuickJS is computing inside a loop" (user-mode work) and points host-side. But that
reading only means something if an alive, untouched main-menu game DOES accrue user
time in a window this short. If it does not — if a main-menu Stellaris simply sits in
waits and accrues zero user CPU for seconds — then "user time frozen" is the normal
shape of this host and the §44 inference collapses into a description of idleness.

This script is the control for that question, and it is the cheapest possible answer:
no DLL, no injection, no dispatch, no thread handle, no bytes added to the game. It
reads `psutil.Process.cpu_times()` — which is `GetProcessTimes` under the hood — of a
running game and prints the series.

  * user time advances while nothing of ours runs => the §44 frozen-user reading is
    real: the process stopped executing user code, host-side;
  * user time is flat here too => the §44 CPU axis says nothing about our sequence,
    and the only live axis left is the thread `Rip` (which §44 could not read:
    `SuspendThread` gle=5).

Run ON WINDOWS (ruling P5: upload alongside c2_harness.py; bare-name imports):
    python C:/temp/c2_control_cpuwatch.py [watch_ms] [every_ms]
"""
from __future__ import annotations

import sys
import time

import psutil

from c2_harness import resolve_pid, assert_game_alive
from c2_task5_init import MEM_SAMPLE_EVERY_MS

# The §44 window was 2,219 ms from dispatch to host loss; 20 s of watching an
# untouched game spans that many times over, so "flat" here cannot be "too short".
DEFAULT_WATCH_MS = 20_000


def format_cpu_sample(user_s: float, system_s: float, num_threads: int) -> str:
    """One line of the series, in the same microsecond units the shot printed."""
    return (f"user_us={int(user_s * 1_000_000)} system_us="
            f"{int(system_s * 1_000_000)} threads={num_threads}")


def cpu_advance_us(samples: list) -> tuple[int, int]:
    """(user, system) microseconds advanced between the first and last sample."""
    if len(samples) < 2:
        return 0, 0
    first_user, first_sys = samples[0][1], samples[0][2]
    last_user, last_sys = samples[-1][1], samples[-1][2]
    return (int((last_user - first_user) * 1_000_000),
            int((last_sys - first_sys) * 1_000_000))


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    watch_ms = int(args[0]) if args else DEFAULT_WATCH_MS
    every_ms = int(args[1]) if len(args) > 1 else MEM_SAMPLE_EVERY_MS

    pid = resolve_pid("stellaris")
    proc = psutil.Process(pid)
    print(f"[cpuwatch] pid={pid} watch={watch_ms}ms every={every_ms}ms "
          f"dll=none injected=none dispatched=none")

    raw = []
    try:
        assert_game_alive(pid)
    except RuntimeError as exc:
        print(f"[cpuwatch] host gone before sampling = {exc}")
        return 1

    t0 = time.monotonic()
    while True:
        try:
            times, threads = proc.cpu_times(), proc.num_threads()
            user_s, system_s = times.user, times.system
        except psutil.Error:
            print(f"[cpuwatch] counters unreadable at "
                  f"{(time.monotonic() - t0) * 1000:.1f}ms — host went away")
            break
        raw.append(((time.monotonic() - t0) * 1000.0, user_s, system_s))
        print(f"[cpuwatch] @ {raw[-1][0]:8.1f}ms = "
              f"{format_cpu_sample(user_s, system_s, threads)}")
        if (time.monotonic() - t0) * 1000.0 >= watch_ms:
            break
        time.sleep(every_ms / 1000.0)

    if not raw:
        print("[cpuwatch] no sample was ever readable — nothing to adjudicate")
        return 1

    user_us, system_us = cpu_advance_us(raw)
    print(f"[cpuwatch] samples={len(raw)} user advanced {user_us}us, "
          f"system advanced {system_us}us over "
          f"{raw[-1][0] - raw[0][0]:.1f}ms with NO dispatch of ours")
    if user_us > 0:
        print("[cpuwatch] VERDICT: untouched game accrues user CPU, so §44's "
              "frozen pr_user_us is a real stop and not idleness")
    else:
        print("[cpuwatch] VERDICT: untouched game accrues ZERO user CPU, so §44's "
              "frozen pr_user_us says nothing about our sequence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
