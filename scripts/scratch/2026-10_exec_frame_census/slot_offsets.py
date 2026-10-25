#!/usr/bin/env python3
"""slot_offsets —— 某个虚实现被 N 张 vtable 共享时,它落在**哪个槽位**。

§60.6 的 one-shot 只数了「0x1bcd120 出现在 365 个 .rdata 槽」,没答偏移;而普查路线
(§60.7-5)要的是**上游调用形态**:`call [reg + off]` 的 `off` 必须是那个槽位,否则找到的
调用点跟这条链无关。本探针把一次对齐 qword 扫描升级成「命中 + 所属指针游程 + 槽位偏移」。

游程口径:从命中处往前/往后走,只要 8 对齐的 LE-qword 落在 `.text` 的 VA 区间就继续。
游程起点当 vtable 基址。**相邻两张 vtable 之间若无零填充会并成一条游程** ⇒ 偏移偏大,
所以同时打印游程长度分布,长度异常(远超该类槽数)就是并表的信号,不能当偏移证据用。

跑法:
    python3 scripts/scratch/2026-10_exec_frame_census/slot_offsets.py [rva]
默认 rva = 1bcd120。节表字段偏移照 scripts/find_refs.py(nsec@nh+6、
SizeOfOptionalHeader@nh+20、节表 vsize@o+8 / va,rawsz,praw@o+12.. / chars@o+36,
过滤 chars & 0x40)。
"""
import os
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from disrva import resolve_exe  # noqa: E402

BASE = 0x140000000
ANCHOR_RVA = 0x1bcd120


def sections(path):
    with open(path, "rb") as fh:
        data = fh.read()
    mz = data.find(b"PE\0\0")
    nsec = struct.unpack_from("<H", data, mz + 6)[0]
    off = mz + 24 + struct.unpack_from("<H", data, mz + 20)[0]
    out = []
    for i in range(nsec):
        o = off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize = struct.unpack_from("<I", data, o + 8)[0]
        va = struct.unpack_from("<I", data, o + 12)[0]
        rawsz = struct.unpack_from("<I", data, o + 16)[0]
        praw = struct.unpack_from("<I", data, o + 20)[0]
        chars = struct.unpack_from("<I", data, o + 36)[0]
        out.append((name, BASE + va, vsize, praw, rawsz, chars))
    return data, out


def main():
    rva = int(sys.argv[1], 16) if len(sys.argv) > 1 else ANCHOR_RVA
    path = resolve_exe()
    if path is None:
        print("[slot_offsets] 没有可读的 stellaris.exe 拷贝(设 NS_STELLARIS_EXE)")
        return 2
    data, secs = sections(path)
    text = [s for s in secs if s[0] == ".text"][0]
    t_lo, t_hi = text[1], text[1] + text[2]
    anchor = BASE + rva
    hits = []
    for name, va, vsize, praw, rawsz, chars in secs:
        if not (chars & 0x40):
            continue
        body = data[praw:praw + min(vsize, rawsz)]
        for pos in range(0, len(body) - 7, 8):
            if struct.unpack_from("<Q", body, pos)[0] != anchor:
                continue
            hit_va = va + pos
            # 游程:只在 .text 指针之间扩展,起点当 vtable 基址
            seg = [s for s in secs if s[1] <= hit_va < s[1] + s[2]][0]
            s_body = data[seg[3]:seg[3] + min(seg[2], seg[4])]
            s_off = hit_va - seg[1]
            start = s_off
            while start - 8 >= 0:
                v = struct.unpack_from("<Q", s_body, start - 8)[0]
                if not (t_lo <= v < t_hi):
                    break
                start -= 8
            end = s_off
            while end + 8 <= len(s_body) - 8:
                v = struct.unpack_from("<Q", s_body, end + 8)[0]
                if not (t_lo <= v < t_hi):
                    break
                end += 8
            hits.append((name, hit_va, hit_va - (seg[1] + start), (end - start) // 8 + 1))
    print(f"anchor=0x{rva:x} hits={len(hits)}")
    print("slot_offset 分布:", dict(sorted(Counter(h[2] for h in hits).items())))
    print("run_len 分布:", dict(sorted(Counter(h[3] for h in hits).items())))
    print("节分布:", dict(Counter(h[0] for h in hits)))
    for h in hits[:6]:
        print(f"  {h[0]} va=0x{h[1]:x} off=+0x{h[2]:x} run={h[3]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
