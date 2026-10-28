"""One-off: finish the cleanup half of a shim-witness shot whose ssh stdout died.

The driver polls over a foreground ssh connection, and that connection can lose the whole
stdout at any moment (docs/offline-tooling.md donor 节 / witness 节判读陷阱 3; §56 and §67
each lost one).  If it breaks after Install and before Uninstall, this walks the cleanup
half to completion against the orphaned install, using the driver's OWN ``_cleanup`` in the
driver's own order (Uninstall -> Verify -> settle -> assert host alive).  It does not
install, reset, drain, or FreeLibrary anything.

The three numbers this prints by name —— ``INSTALLED`` / ``VERIFIED`` / ``HOST_ALIVE`` ——
are the ones a window's record needs after a lost stdout: they say whether a patch is still
in the process, whether the engine bytes came back, and whether the host survived.  They are
printed on their own lines so a partially captured log still carries them.

Same-process note: run this for whichever guard is actually armed.  Each guard's state is
private to its module, so ``INSTALLED=1`` here only ever speaks about the shim install; if a
witness/donor/scope install were also orphaned, run its own finish-cleanup too, in the same
serial order the shots ran in.

    python ns_shim_finish_cleanup.py <pid> <dll-on-host>
"""

import sys

import c2_shim_probe as p

NEEDED = ("C4ShimProbeUninstall", "C4ShimProbeVerify",
          "C4ShimProbeStatsInto", "C4ShimProbeLayout")


def _installed_flag(stats):
    return int(stats.get("installed", 0))


def main():
    pid = int(sys.argv[1], 0)
    dll_path = sys.argv[2]
    base, exports = p.gate_module(pid, dll_path, NEEDED)
    buf = p.remote_alloc(pid, p.STATS_SIZE)

    before, before_text = p.read_stats(pid, base, exports, buf)
    print(f"INSTALLED={_installed_flag(before)}")
    print("BEFORE", before_text)

    ok = p._cleanup(pid, base, exports, installed_ok=True, settle_s=2.0)

    # Verify is asked again AFTER the cleanup half so the number is the final state, not the
    # snapshot _cleanup already printed.  0 = consistent, -3 = never resolved here.
    try:
        verified = p._signed32(p.call_remote(pid, base, exports["C4ShimProbeVerify"]))
    except Exception as exc:  # noqa: BLE001 - cleanup reports, it does not raise
        print(f"VERIFY_RAISED={exc}")
        verified = None
    print(f"VERIFIED={verified}")

    try:
        after, after_text = p.read_stats(pid, base, exports, buf)
        print(f"INSTALLED_AFTER={_installed_flag(after)}")
        print("AFTER", after_text)
    except Exception as exc:  # noqa: BLE001 - a dead process must still print HOST_ALIVE
        print(f"AFTER_RAISED={exc}")

    try:
        p.assert_game_alive(pid)
        print("HOST_ALIVE=1")
    except Exception as exc:  # noqa: BLE001
        print(f"HOST_ALIVE=0 ({exc})")
        ok = False

    print("RESTORE_OK" if ok else "RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
