#!/usr/bin/env python3
"""cap_systems.py — 只读:当前战役的星系条数(容器原始计数)+ 索引对象地址。

`[[exe_base+0x3260BB0]+0x59C]`,与 `c2_capability_probe.py --systems` 同源。
一次 `ReadProcessMemory`,不写任何东西、不装任何东西。用法(Windows 侧):

    python C:/temp/cap_systems.py
"""
import struct
import sys

sys.path.insert(0, r"C:/temp")

import c2_harness as harness  # noqa: E402  (bare name on the wire, ruling P5)

GALAXY_DB_RVA = 0x3260BB0
COUNT_OFF = 0x59C
IDS_OFF = 0x590


def main() -> int:
    pid = harness.resolve_pid("stellaris.exe")
    exe_base = harness.resolve_base_address(pid, "stellaris.exe")
    obj = struct.unpack("<Q", harness.read_memory(pid, exe_base + GALAXY_DB_RVA, 8))[0]
    count = struct.unpack("<I", harness.read_memory(pid, obj + COUNT_OFF, 4))[0]
    vec = struct.unpack("<Q", harness.read_memory(pid, obj + IDS_OFF, 8))[0]
    print(f"SYSTEMS pid={pid} exe_base=0x{exe_base:x} container=0x{obj:x} "
          f"count={count} vec=0x{vec:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
