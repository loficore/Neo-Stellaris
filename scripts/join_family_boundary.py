#!/usr/bin/env python3
"""join_family_boundary —— 族外证人窗口(§71)的离线定形:三张表 join 出「非族内」执行体。

要回答的问题只有一个:**§13 那七把各 2,090 次的 exec shim,在不在 CEffect 家族的五张 vtable 里?**
判据口径全部照抄仓库既有读法,本脚本不发明新判据:

- 段① : `evidence/xrefs/exec_frame_callers_4_4_4.tsv` 的 28 个 `func_start` 里,哪些出现在
         `ceffect_vtable_map_4_4_4.txt` 的 `ExecuteActual(slot2)` 列(= 该函数确实是某张 vtable 的
         slot[2]);缺席的那批才是「静态集合里没登记的候选」。
- 段② : §13 七把 shim 的 vtable 与家族五张 `0x24B1D98/0x24EAAC0/0x25F4440/0x2606F00/0x2606FE0`
         求交集 —— 期望空集。
- 段③ : 对段①的每个缺席候选跑 §62.2 的三条独立口径:
         1) `.rdata` 内该地址的 8 对齐 LE-qword 命中数;
         2) 每个命中的前一槽(`hit-8`)是否 `0x1d08520`;
         3) 命中回退 `0x10` 当 vtable 基址,是否落在 map 的 1,805 个基址里。

口径边界(写进 §71 时逐字带上):**map 是下限,不是全量** —— 「不在 map」只能写「不在这份静态
集合里」,不能写「族外没有另一份表」。`join_family_boundary` 的 `join` 指三张表的连接,不是 SQL 的 JOIN。
map 与 census 里的地址一律是 **RVA**;只有扫 `.rdata` 字节时才加 `BASE`(`0x140000000`)。

跑法:
    python3 scripts/join_family_boundary.py [rva_hex ...]

无参时跑段①②③(段③的对象 = 段①的缺席清单);带 RVA 参数时只跑段③,对象就是这些 RVA
(定靶时用它点名量一个候选的三口径读数)。**退出码**:0 = 读完(含「预期没达成」,读数归读数);
2 = exe 拷贝找不到或输入表读不到(那是环境问题,不是判据问题)。

**旧路径**(本文件 2026-10-28 从那里提升上来,原件冻结留档、字节不动,取证卷 §71 正文引的是那个路径):
`scripts/scratch/2026-10_live_window_shim_witness/join_family_boundary.py`。
本副本与原件的差别是**两处路径**(仓库根少上两层,见下 `_REPO`;上面「跑法」那一行)外加两行说明文字
(本段旧路径记述与 `_REPO` 旁的注释);判据逻辑逐字未动 —— 它是 §71 三口径读数的**生产者**,提升的原因是
「只读 exe 拷贝 = 工具,需要进程 = 探针」(AGENTS「scripts/ 命名与目录约定」),而 §71 的数被新的 RVA 行与
新节引用。
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
# 本文件住在 scripts/ 顶层 ⇒ 仓库根是上一层(原件在 scratch/2026-10_live_window_shim_witness/ 下要上三层)。
_REPO = os.path.abspath(os.path.join(_HERE, ".."))
sys.path.insert(0, os.path.join(_REPO, "scripts"))

from disrva import resolve_exe  # noqa: E402

BASE = 0x140000000
CALLERS_TSV = os.path.join(_REPO, "evidence", "xrefs", "exec_frame_callers_4_4_4.tsv")
VTABLE_MAP = os.path.join(_REPO, "evidence", "xrefs", "ceffect_vtable_map_4_4_4.txt")
CENSUS = os.path.join(_REPO, "evidence", "xrefs", "exec_shim_census_2026_09_29.txt")

BASE_EXECUTE = 0x1D08520
# CEffect 家族的五张 vtable(§57.2 观测 4 / §60.6 的 family 表)。
FAMILY_FIVE = (0x24B1D98, 0x24EAAC0, 0x25F4440, 0x2606F00, 0x2606FE0)
# §13 的七把同计数 shim(每把 2,090 次)。段②按体检,不假定文件里正好只有这七行。
SEVEN_SHIM_ROW_COUNT = 2090
# 段③ 的逐条明细只印前这么多命中 —— 计数永远全算,明细只是给判读用的可读样本
# (`0x1bcd120` 有 365 处命中,全印会把 §71 的 artifact 淹掉)。
DETAIL_ROWS = 12


def _read_bytes(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc


def _read_lines(path):
    try:
        with open(path, newline="") as fh:
            return fh.read().splitlines()
    except OSError as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc


def _sections(data):
    """PE 节表 -> [(名, RVA 起, vsize, raw 起, rawsz)]。"""
    pe = data.find(b"PE\0\0")
    if pe < 0:
        raise SystemExit("no PE header (image is not a PE file)")
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    off = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    secs = []
    for i in range(nsec):
        o = off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, va, rawsz, praw = struct.unpack_from("<IIII", data, o + 8)
        secs.append((name, va, vsize, praw, rawsz))
    return secs


def _section_bytes(data, secs, name):
    for sec_name, _va, _vsize, praw, rawsz in secs:
        if sec_name == name:
            return data[praw:praw + rawsz]
    raise SystemExit(f"section {name} not found")


def read_caller_funcs(path=CALLERS_TSV):
    """(func_start 的有序去重列表, 原始行数)。"""
    seen, rows = [], 0
    for line in _read_lines(path):
        if line.startswith("#") or not line.strip():
            continue
        rows += 1
        rva = int(line.split("\t")[0], 16)
        if rva not in seen:
            seen.append(rva)
    return seen, rows


def read_vtable_map(path=VTABLE_MAP):
    """({vtable RVA -> slot2 RVA}, {全部 vtable RVA})。文件是 CRLF,按空白切。"""
    slot2, bases = {}, set()
    for line in _read_lines(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        # 形态: vtable <base> slot0 <f> ExecuteActual(slot2) <f>  ⇒ 槽名在 [4]、函数在 [5]
        if len(parts) < 6 or parts[0] != "vtable":
            continue
        base = int(parts[1], 16)
        bases.add(base)
        if parts[4] == "ExecuteActual(slot2)":
            slot2[base] = int(parts[5], 16)
    return slot2, bases


def read_census(path=CENSUS):
    """[(shim RVA, vtable RVA, count)] —— 只认 `shim 0x.. vtable 0x.. xNNNN` 那种行。"""
    out = []
    for line in _read_lines(path):
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "shim" and parts[2] == "vtable":
            try:
                out.append((int(parts[1], 16), int(parts[3], 16),
                            int(parts[4].lstrip("x"))))
            except ValueError:
                continue
    return out


def qword_hits(rdata, func_rva):
    """§62.2 口径 1+2:8 对齐 LE-qword 命中,以及每个命中的前一槽。

    返回 [(节内偏移, 前一槽的 VA)]。偏移是**节内**偏移 —— 与既有 `slot_offsets2.py` 的扫描
    口径一致(节一律 0x1000 对齐,故节内 8 对齐 = RVA 8 对齐)。
    """
    needle = struct.pack("<Q", BASE + func_rva)
    hits, start = [], 0
    while True:
        at = rdata.find(needle, start)
        if at < 0:
            break
        start = at + 1
        if at % 8:
            continue                      # 非 8 对齐的命中不算(§62.2 口径)
        prev = struct.unpack_from("<Q", rdata, at - 8)[0] if at >= 8 else None
        hits.append((at, prev))
    return hits


def three_readings(data, secs, func_rva, bases):
    """§62.2 的三条口径 -> dict(逐条计数 + 明细)。base set 与读数都在 RVA 空间。"""
    rdata = _section_bytes(data, secs, ".rdata")
    rdata_rva = next(va for name, va, _vsize, _praw, _rawsz in secs if name == ".rdata")
    hits = qword_hits(rdata, func_rva)
    prev_ok = sum(1 for _at, prev in hits if prev is not None and prev - BASE == BASE_EXECUTE)
    in_map = sum(1 for at, _prev in hits if (rdata_rva + at - 0x10) in bases)
    return {
        "hits": len(hits),
        "prev_is_base_execute": prev_ok,
        "hit_minus_0x10_in_map": in_map,
        "rows": [(at, None if prev is None else prev - BASE) for at, prev in hits],
    }


def fmt_rva(value):
    return f"0x{value:x}"


def main(argv):
    exe = resolve_exe()
    if exe is None:
        print("no stellaris.exe on the NS_STELLARIS_EXE candidate chain", file=sys.stderr)
        return 2
    data = _read_bytes(exe)
    secs = _sections(data)
    print(f"# exe={exe}")
    print(f"# base={fmt_rva(BASE)} base_execute={fmt_rva(BASE_EXECUTE)} "
          f"(map 只收 slot[1] 仍是它的那批 = floor)")

    slot2, bases = read_vtable_map()
    census = read_census()
    print(f"# map_vtables={len(bases)} map_distinct_slot2={len(set(slot2.values()))} "
          f"census_shim_rows={len(census)}")

    if len(argv) > 1:
        targets = [int(tok, 16) for tok in argv[1:]]
        print(f"# mode=explicit_rvas {' '.join(fmt_rva(t) for t in targets)}")
    else:
        funcs, rows = read_caller_funcs()
        print(f"# callers_tsv_rows={rows} distinct_func_start={len(funcs)}")

        slot2_values = set(slot2.values())
        present = [f for f in funcs if f in slot2_values]
        absent = sorted(f for f in funcs if f not in slot2_values)
        print("")
        print("## ① 普查表 func_start 与 map 的 ExecuteActual(slot2) 列")
        print(f"of {len(funcs)} distinct func_start, {len(present)} appear as some vtable's "
              f"slot2; {len(absent)} do not —— 缺席 = 不在**这份静态集合**里,不是「族外」的证明")
        print(f"present={len(present)} absent={len(absent)}")
        for func in absent:
            print(f"  absent {fmt_rva(func)}")

        seven = [(s, v, c) for s, v, c in census if c == SEVEN_SHIM_ROW_COUNT]
        others = [(s, v, c) for s, v, c in census if c != SEVEN_SHIM_ROW_COUNT]
        print("")
        print("## ② §13 七把 shim 的 vtable × 家族五张")
        print(f"family_five={' '.join(fmt_rva(v) for v in FAMILY_FIVE)}")
        print(f"census_rows_with_count_{SEVEN_SHIM_ROW_COUNT}={len(seven)} "
              f"(其余 {len(others)} 行计数不同,单列)")
        for shim, vtable, count in seven:
            in_family = "YES" if vtable in FAMILY_FIVE else "no"
            print(f"  shim {fmt_rva(shim)} vtable {fmt_rva(vtable)} x{count} family={in_family}")
        for shim, vtable, count in others:
            print(f"  other shim {fmt_rva(shim)} vtable {fmt_rva(vtable)} x{count} "
                  f"(不计入七把)")
        inter = sorted({v for _s, v, _c in seven} & set(FAMILY_FIVE))
        shown = "{" + ", ".join(fmt_rva(v) for v in inter) + "}" if inter else "{}"
        print(f"intersection={shown} EXPECT_EMPTY={not inter}")
        targets = absent

    print("")
    print("## ③ §62.2 三口径(8 对齐 qword 命中 / 命中前一槽 == base Execute / "
          "命中-0x10 落进 map)")
    for func in targets:
        r = three_readings(data, secs, func, bases)
        print(f"target {fmt_rva(func)} hits={r['hits']} "
              f"prev_is_base_execute={r['prev_is_base_execute']}/{r['hits']} "
              f"hit_minus_0x10_in_map={r['hit_minus_0x10_in_map']}/{r['hits']}")
        for at, prev in r["rows"][:DETAIL_ROWS]:
            shown = "None" if prev is None else fmt_rva(prev)
            print(f"  hit@rdata+0x{at:x} prev={shown}")
        if len(r["rows"]) > DETAIL_ROWS:
            print(f"  ... {len(r['rows']) - DETAIL_ROWS} more hit(s) (计数已全算, 明细只印前 "
                  f"{DETAIL_ROWS} 条)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
