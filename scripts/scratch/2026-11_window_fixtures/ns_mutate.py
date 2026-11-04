"""One-off on-box driver: one `C5GraphMutateAdd` / `C5GraphMutateRemove` call.

`c2_graph_read.py --mutate` does add→read→remove→read in one shot, which is the
wrong shape for the §7.7 reconcile: the engine has to *see* the added edge on a
monthly pulse, so the add has to persist between two windows.  This driver calls
exactly one export and exits.

    python C:/temp/session_bridge.py C:/temp/ns_mutate.py add 5 9
    python C:/temp/session_bridge.py C:/temp/ns_mutate.py remove 5 9

Both exports take one u64 (low 32 = from, high 32 = to) because
`CreateRemoteThread` hands over a single register.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import c2_boot_inject as boot  # noqa: E402
import c2_harness as harness  # noqa: E402

DLL = r"C:\temp\sqjs_p1.dll"
EXPORTS = {"add": "C5GraphMutateAdd", "remove": "C5GraphMutateRemove"}


def main(argv):
    if len(argv) != 3 or argv[0] not in EXPORTS:
        print(__doc__)
        return 2
    verb, a, b = argv[0], int(argv[1]), int(argv[2])
    pid = harness.resolve_pid("stellaris.exe")
    base = harness.resolve_base_address(pid, os.path.basename(DLL))
    exports = boot._require_exports(DLL)
    if exports is None:
        print("MUTATE refuse=exports")
        return 1
    packed = (a & 0xFFFFFFFF) | ((b & 0xFFFFFFFF) << 32)
    rc = harness.call_remote_with_arg(pid, base, exports[EXPORTS[verb]], packed)
    print(f"MUTATE {verb} {a}-{b} rc={rc} pid={pid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
