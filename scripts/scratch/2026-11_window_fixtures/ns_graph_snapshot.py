"""One-off on-box reader: dump the live edge set as a `a<TAB>b<TAB>1` TSV.

`c2_graph_read.py` refuses to run when its DLL name is already resident (that
guard exists for its own injection path); this shot's process already has the
DLL loaded, so the read is done here with the driver's own read primitives
(``Reset → Read → StatsInto → DrainInto`` — all read-only).

    python C:/temp/session_bridge.py C:/temp/ns_graph_snapshot.py base  C:/temp/sig.base
    python C:/temp/session_bridge.py C:/temp/ns_graph_snapshot.py add   C:/temp/sig.add
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import c2_boot_inject as boot  # noqa: E402
import c2_graph_read as graph  # noqa: E402
import c2_harness as harness  # noqa: E402

DLL = r"C:\temp\sqjs_p1.dll"


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    tag, out = argv
    pid = harness.resolve_pid("stellaris.exe")
    base = harness.resolve_base_address(pid, os.path.basename(DLL))
    exports = boot._require_exports(DLL)
    if exports is None:
        print("SNAP refuse=exports")
        return 1
    stats_buf = harness.remote_alloc(pid, graph.STATS_SIZE)
    drain_buf = harness.remote_alloc(pid, graph.DRAIN_BYTES)
    rc, stats, rows = graph.read_once(pid, base, exports, stats_buf, drain_buf)
    with open(out, "w", encoding="utf-8") as handle:
        for a, b in rows:
            handle.write(f"{a}\t{b}\t1\n")
    print(f"SNAP {tag} rc={rc} systems={stats['systems']} edges={stats['edges']} "
          f"skipped={stats['skipped']} rows={len(rows)} out={out}")
    return 0 if rc in (0, -4) and len(rows) == stats["edges"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
