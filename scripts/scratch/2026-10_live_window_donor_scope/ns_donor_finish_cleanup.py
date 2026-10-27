"""One-off: finish the cleanup half of a donor shot whose ssh stdout died.

The donor driver polls over a foreground ssh connection, and that connection can
lose the whole stdout at any moment (docs/offline-tooling.md donor 判读陷阱 3 /
§59.2). If it breaks after Install and before Uninstall, this walks the cleanup
half to completion against the orphaned install, using the driver's OWN `_cleanup`
in the driver's own order (Uninstall -> Verify -> settle -> assert host alive).
It does not install, reset, drain, or FreeLibrary anything, and it prints the
stats text before and after so the residual counters are still on the record.

    python ns_donor_finish_cleanup.py <pid> <dll-on-host>
"""

import sys

import c2_donor_probe as p

NEEDED = ("C4DonorProbeUninstall", "C4DonorProbeVerify",
          "C4DonorProbeStatsInto", "C4DonorProbeLayout")


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
