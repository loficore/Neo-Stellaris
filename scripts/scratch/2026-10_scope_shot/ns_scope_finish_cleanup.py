"""One-off: finish the cleanup half of a scope shot whose ssh stdout died.

The v3 shot lost its connection mid-poll (docs/offline-tooling.md trap 11 / §56.3),
and the driver died before it reached Uninstall — the artifact's live stats row
reads `installed=1 verified=-1`. This calls the driver's OWN `_cleanup` against the
orphaned install, in the driver's own order (Uninstall -> Verify -> settle -> assert
host alive). It does not install, reset, drain, or FreeLibrary anything.

    python ns_scope_finish_cleanup.py <pid> <dll-on-host>
"""

import sys

import c2_scope_probe as p

NEEDED = ("C2Sanity", "C2ScopeProbeUninstall", "C2ScopeProbeVerify",
          "C2ScopeProbeStatsInto", "C2ScopeProbeLayout")


def main():
    pid = int(sys.argv[1], 0)
    dll_path = sys.argv[2]
    base, exports = p.gate_module(pid, dll_path, NEEDED)
    buf = p.remote_alloc(pid, p.STATS_SIZE)
    before, before_text = p.read_stats(pid, base, exports, buf)
    print("BEFORE", before_text)
    ok = p._cleanup(pid, base, exports, installed_ok=True, settle_s=2.0)
    after, after_text = p.read_stats(pid, base, exports, buf)
    print("AFTER", after_text)
    print("RESTORE_OK" if ok else "RESTORE_INCOMPLETE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
