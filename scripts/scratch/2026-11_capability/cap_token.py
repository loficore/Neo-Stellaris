#!/usr/bin/env python3
"""cap_token.py — 只读:把 `token` 那一项的原始字节摊出来(不改任何东西)。

`[[module+0x37347A0]+0x70] + 10104*0x30` 的 0x38 字节按 u32/u64 + ASCII 打一遍,
再把 `0x337B400` 里 `add_modifier` 的槽号与 id 扫出来对账。
"""
import struct
import sys

sys.path.insert(0, r"C:/temp")

import c2_harness as harness  # noqa: E402

DB_RVA = 0x37347A0
NAME_TABLE_OFF = 0x70
HOLDER_STRIDE = 0x30
KEYWORD_ID = 10104
DESC_RVA = 0x337B400
DESC_STRIDE = 0x120
DESC_SLOTS = 9863


def dump(tag, addr, blob):
    print(f"{tag} @0x{addr:x} ({len(blob)} B)")
    for off in range(0, len(blob) - len(blob) % 8, 8):
        chunk = blob[off:off + 8]
        qword = struct.unpack("<Q", chunk)[0]
        print(f"  +0x{off:02x} {qword:016x}  {chunk!r}")


def main() -> int:
    pid = harness.resolve_pid("stellaris.exe")
    exe_base = harness.resolve_base_address(pid, "stellaris.exe")
    db = exe_base + DB_RVA
    db_head = harness.read_memory(pid, db, 0x90)
    dump("db", db, db_head)
    table = struct.unpack_from("<Q", db_head, NAME_TABLE_OFF)[0]
    print(f"name_table=0x{table:x}")
    if table:
        entry = table + KEYWORD_ID * HOLDER_STRIDE
        dump(f"holder[{KEYWORD_ID}]", entry, harness.read_memory(pid, entry, 0x38))
        # 邻居两个 holder:确认步长是不是 0x30
        for i in (KEYWORD_ID - 1, KEYWORD_ID + 1):
            other = table + i * HOLDER_STRIDE
            dump(f"holder[{i}]", other, harness.read_memory(pid, other, 0x38))
    base = exe_base + DESC_RVA
    found = 0
    for slot in range(DESC_SLOTS):
        addr = base + slot * DESC_STRIDE
        blob = harness.read_memory(pid, addr, 0x30)
        name = blob[0x20:].split(b"\0", 1)[0]
        if name == b"add_modifier":
            ident = struct.unpack_from("<I", blob, 0)[0]
            print(f"descriptor slot={slot} id={ident} name={name!r}")
            found += 1
            if found > 2:
                break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
