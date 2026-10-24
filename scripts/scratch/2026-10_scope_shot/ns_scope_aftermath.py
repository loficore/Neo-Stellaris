"""Read the sampler's own flags after a shot whose stdout was lost.

The ssh channel died mid-run, so the driver's final lines -- Uninstall,
C2ScopeProbeVerify rc, "host alive" -- are gone.  The DLL stays loaded either
way (constraint 5 forbids FreeLibrary), so the only way to learn whether the
detour is still on the hot path is to ask the module itself.  This prints the
stats block twice, two seconds apart: ``installed`` is the flag, and a frozen
``calls`` between the two reads is the independent confirmation that no engine
call is reaching our code any more.

    python ns_scope_aftermath.py [dll-path]
"""

import os
import sys
import time

import c2_scope_probe as s  # noqa: E402


def main():
    dll = sys.argv[1] if len(sys.argv) > 1 else r"C:\temp\sqjs_c4_scope_v2.dll"
    name = os.path.basename(dll)
    pid = s.resolve_pid("stellaris")
    base = s.resolve_base_address(pid, name)
    print(f"PID {pid} MODULE {name} BASE 0x{base:x}")
    if base == 0:
        print("NOT_LOADED — the module is not mapped in this process")
        return 1
    exports = s.list_exports(dll)
    buf = s.remote_alloc(pid, s.STATS_SIZE)
    for attempt in (1, 2):
        stats, text = s.read_stats(pid, base, exports, buf)
        print(f"READ {attempt}: {text.strip()}")
        if attempt == 1:
            time.sleep(2.0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
