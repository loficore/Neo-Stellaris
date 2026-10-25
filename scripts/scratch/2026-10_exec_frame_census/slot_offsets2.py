#!/usr/bin/env python3
"""slot_offsets2 —— 用仓里已有的 vtable 基址把「被共享的虚实现落在哪个槽」定出来。

上一版(slot_offsets.py)的游程起点启发式在 .rdata 里失效:vtable 是紧挨着排的,游程并成
1400+ 槽的大块,偏移全是垃圾。这里改读 `evidence/xrefs/ceffect_vtable_map_4_4_4.txt` 的
1,805 个 vtable 基址(floor:只含 +0x08 仍是 base Execute 的那批),对每个基址按槽解引用,
命中目标 RVA 就记 (vtable, slot_index)。基址外部的命中单独计成 orphan,不当偏移用。

跑法:
    python3 scripts/scratch/2026-10_exec_frame_census/slot_offsets2.py [rva]
默认 rva = 1bcd120。
"""
import os
import struct
import sys
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(_REPO, "scripts"))

from disrva import resolve_exe  # noqa: E402

BASE = 0x140000000
ANCHOR_RVA = 0x1bcd120
MAP = os.path.join(_REPO, "evidence", "xrefs", "ceffect_vtable_map_4_4_4.txt")
MAX_SLOTS = 200


def sections(path):
    with open(path, "rb") as fh:
        data = fh.read()
    pe = data.find(b"PE\0\0")
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    off = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    out = []
    for i in range(nsec):
        o = off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize = struct.unpack_from("<I", data, o + 8)[0]
        va = struct.unpack_from("<I", data, o + 12)[0]
        rawsz = struct.unpack_from("<I", data, o + 16)[0]
        praw = struct.unpack_from("<I", data, o + 20)[0]
        out.append((name, BASE + va, vsize, praw, rawsz,
                    struct.unpack_from("<I", data, o + 36)[0]))
    return data, out


def va_to_off(secs, va):
    for name, lo, vsize, praw, rawsz, chars in secs:
        if lo <= va < lo + min(vsize, rawsz):
            return data[praw + (va - lo):praw + min(vsize, rawsz)]
    return None


def main():
    rva = int(sys.argv[1], 16) if len(sys.argv) > 1 else ANCHOR_RVA
    path = resolve_exe()
    if path is None:
        print("[slot_offsets2] 没有可读的 stellaris.exe 拷贝(设 NS_STELLARIS_EXE)")
        return 2
    global data
    data, secs = sections(path)
    text = [s for s in secs if s[0] == ".text"][0]
    t_lo, t_hi = text[1], text[1] + text[2]
    anchor = BASE + rva

    vtabs = []
    with open(MAP) as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "vtable":
                vtabs.append(int(parts[1], 16))
    vtabs.sort()
    print(f"map vtables={len(vtabs)}")

    hits = []
    for name, lo, vsize, praw, rawsz, chars in secs:
        if not (chars & 0x40):
            continue
        body = data[praw:praw + min(vsize, rawsz)]
        for pos in range(0, len(body) - 7, 8):
            if struct.unpack_from("<Q", body, pos)[0] == anchor:
                hits.append(lo + pos)
    print(f"aligned qword hits={len(hits)}")

    inside, orphan = Counter(), 0
    per_vtable = []
    for hit in hits:
        best = None
        for vt in vtabs:
            if vt + BASE <= hit:
                best = vt
            else:
                break
        if best is None:
            orphan += 1
            continue
        seg = va_to_off(secs, best + BASE)
        if seg is None:
            orphan += 1
            continue
        slot = None
        for k in range(MAX_SLOTS):
            if k * 8 + 7 >= len(seg):
                break
            v = struct.unpack_from("<Q", seg, k * 8)[0]
            if v == anchor:
                slot = k
                break
            if not (t_lo <= v < t_hi):
                break          # 游程到头,这张表里没有
        if slot is None:
            orphan += 1
        else:
            inside[slot] += 1
            per_vtable.append((best, slot))
    print("slot_index 分布(前 20):", dict(sorted(list(inside.items())[:20])))
    print(f"orphan(不在任何已知 vtable 的槽位前缀里)={orphan}")
    for vt, slot in per_vtable[:8]:
        print(f"  vtable 0x{vt:x} slot[{slot}] = +0x{slot * 8:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
