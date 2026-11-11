#!/usr/bin/env python3
"""cap_read.py — 只读:读 C3CapabilityLayout + 56 B 矩阵,并打印七行。

不装、不拆、不 reset:一次 `CreateRemoteThread` 调两个导出。用法(Windows 侧):

    python C:/temp/cap_read.py
"""
import struct
import sys

sys.path.insert(0, r"C:/temp")

import c2_harness as harness  # noqa: E402

NAMES = ("scope", "token", "descriptor", "graph", "state", "vtable", "fingerprint")
STATUS = {0: "skip", 1: "ok", 2: "fail", 3: "presence_only"}
REASON = {0: "none", 1: "unreadable", 2: "mismatch", 3: "no_scope", 4: "out_of_range",
          5: "write_rejected", 6: "not_cleared"}


def main() -> int:
    pid = harness.resolve_pid("stellaris.exe")
    base = harness.resolve_base_address(pid, "sqjs_cap1.dll")
    # list_exports 读的是文件,不是模块;这里按导出名在文件里解析 RVA 再调。
    table = harness.list_exports(r"C:\temp\sqjs_cap1.dll")
    layout_buf = harness.remote_alloc(pid, 8)
    stats_buf = harness.remote_alloc(pid, 56)
    harness.call_remote_with_arg(pid, base, table["C3CapabilityLayout"], layout_buf)
    layout = struct.unpack("<2I", harness.read_memory(pid, layout_buf, 8))
    rc = harness.call_remote_with_arg(pid, base, table["C3CapabilityStatsInto"], stats_buf)
    blob = harness.read_memory(pid, stats_buf, 56)
    print(f"LAYOUT version={layout[0]} check_count={layout[1]} stats_rc={rc}")
    for i, name in enumerate(NAMES):
        status, reason = struct.unpack_from("<II", blob, i * 8)
        print(f"CAP {name}\t{STATUS.get(status, status)}\t{REASON.get(reason, reason)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
