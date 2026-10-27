"""One-off: finish the cleanup half of a witness shot whose ssh stdout died.

The witness driver polls over a foreground ssh connection, and that connection can
lose the whole stdout at any moment (docs/offline-tooling.md 证人节 / donor 节判读陷阱 3、
§56 与 §67 各踩过一次)。If it breaks after Install and before Uninstall, this walks the
cleanup half to completion against the orphaned install, using the driver's OWN
`_cleanup` in the driver's own order (Uninstall -> Verify -> settle -> assert host alive).
It does not install, reset, drain, or FreeLibrary anything, and it prints the stats text
before and after so the residual counters are still on the record —— that before/after
pair is the whole reason this file exists: a lost stdout must not also lose the proof
that the engine bytes came back.

Same-process note: run this for whichever guard is actually armed. The witness and donor
guards have private guard variables, so `installed_ok=True` here only ever speaks about
the witness install; if a donor install were also orphaned, run its own
`ns_donor_finish_cleanup.py` too, in the same serial order the shots ran in.

    python ns_witness_finish_cleanup.py <pid> <dll-on-host>
"""

import sys

import c2_witness_probe as p

NEEDED = ("C4WitnessProbeUninstall", "C4WitnessProbeVerify",
          "C4WitnessProbeStatsInto", "C4WitnessProbeLayout")


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
