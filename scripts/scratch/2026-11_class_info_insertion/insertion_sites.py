#!/usr/bin/env python3
"""insertion_sites.py — class_info A 族(switch / inverted_switch)的插入点交叉校验(计划 Task 2 的生产者,§85)。

只读 `stellaris.exe` 拷贝(`NS_STELLARIS_EXE` 未设时走 disrva 候选链),零 shot。

引用口径(Task 2 裁定,打印进产物):计划原文只查 `0x260F498`,但全镜像对该地址**零引用**——
`0x260F498` 是 create 槽 qword,class_info **块头**在 `0x260F490`(A 族)与 `0x260F480`(B 族),
注册 stub 用 `lea rcx,[rip+->块头]` 把指针写进 `new(0x10)` 的 value 块,再**尾跳** `jmp 0x3AEF60`。
所以引用目标集 = {0x260F490, 0x260F498, 0x260F480, 0x260F488},插入形式 = call **或** 尾 jmp。

三件事:
  ① 两个解码器交叉校验:`find_refs.py` 口径(全量线性解码 + 逐字节重同步,结果缓存在
     `/mnt/cache/tmp/class_info_insertion/find_refs_hits.json`,按 exe sha + 目标集键控)对
     `riprefs.py --verify` 口径(rip 字节扫 + 按 .pdata 对齐重解码)。差集每一条必须给出标注
     (mid_instruction / opcode 覆盖面 / 节区差),否则 FAIL。
  ② 每个引用点按 `.pdata`(合并重叠 start)归桶;引用点必须落在某个 extent 内。
  ③ 每个桶函数报有没有到 0x3AEF60 / 0x348150 的 call/jmp;有则报调用点、调用形态与
     实参写入(`mov edx=<token id>` / `mov rcx=<db>` / `mov r8=<value 块>`)。

判决词(值域来自计划 Task 2,定义按上面的口径读;换定义要重判):
  insertion_named         同一函数里既有对 class_info 的 lea,又有 call/jmp 0x3AEF60,指针经 value 块交给插入函数
  insertion_through_field 引用点把 class_info 存进某对象字段,插入调用在别处读该字段
  insertion_not_found     没有引用点落在含插入调用的函数里

family_def = `neighborhood`:vtable ±0x200 内出现 {0x3AFD30, 0x3B1330, 0x3B01A0, 0x3B1420,
0x3B0F80, 0x3B1230} 任一(§83.2 补记 ① 采用的口径);本表所有行固定带这个词。

何时被调:本探针不回答(离线,零 shot)。

旧名/来历:本脚本由计划 `2026-11-01-offline-static-round` 的 Task 2 建立。
"""
from __future__ import annotations

import bisect
import json
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve()
REPO = HERE.parents[3]
sys.path.insert(0, str(REPO / "scripts"))

import disrva  # noqa: E402
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from capstone.x86 import X86_REG_RIP  # noqa: E402

BASE = 0x140000000
REF_TARGETS = {
    0x260F490: "class_info head A(switch dtor@+0 create@+8)",
    0x260F498: "class_info create-slot A(§83.2 所记)",
    0x260F480: "class_info head B(inverted_switch)",
    0x260F488: "class_info create-slot B",
}
INSERT_CALLS = {0x3AEF60: "effect_insert", 0x348150: "trigger_insert"}
FAMILY_DEF = "neighborhood"
CACHE = pathlib.Path("/mnt/cache/tmp/class_info_insertion")
HITS_CACHE = CACHE / "find_refs_hits.json"
ALL_TARGETS = sorted(set(REF_TARGETS) | set(INSERT_CALLS))

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

_image = disrva._image()
assert _image is not None, "stellaris.exe not found (set NS_STELLARIS_EXE)"
_EXE, BLOB, SECS = _image
EXE_PATH = pathlib.Path(_EXE)


def sec(name):
    return next(s for s in SECS if s[0] == name)


def rd(rva, n):
    for _n, va, vsize, rawsz, praw, _ch in SECS:
        if va <= rva < va + max(vsize, rawsz):
            return BLOB[praw + (rva - va):praw + (rva - va) + n]
    return b""


def _pdata():
    _n, _va, _vs, rawsz, praw, _ch = sec(".pdata")
    merged = {}
    for i in range(rawsz // 12):
        b, e, _u = struct.unpack_from("<III", BLOB, praw + i * 12)
        b &= ~1
        merged[b] = max(merged.get(b, 0), e)
    return merged


FUNC_END = _pdata()
STARTS = sorted(FUNC_END)


def func_of(rva):
    i = bisect.bisect_right(STARTS, rva) - 1
    if i < 0:
        return None
    s = STARTS[i]
    return (s, FUNC_END[s]) if rva < FUNC_END[s] else None


_SHA = None


def _sha():
    global _SHA
    if _SHA is None:
        import hashlib
        h = hashlib.sha256()
        with open(_EXE, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 22), b""):
                h.update(chunk)
        _SHA = h.hexdigest()
    return _SHA


def find_refs_hits():
    """find_refs.py 口径的全量解码结果;缓存按 (exe sha, 目标集) 双键控。"""
    targets_hex = [f"{t:x}" for t in ALL_TARGETS]
    if HITS_CACHE.exists():
        data = json.loads(HITS_CACHE.read_text())
        st = EXE_PATH.stat()
        if (data.get("exe_size") == st.st_size and data.get("exe_sha") == _sha()
                and data.get("targets") == targets_hex):
            print("## find_refs hits cached", flush=True)
            return {int(k, 16): [tuple(v) for v in lst]
                    for k, lst in data["hits"].items()}
    argv_save = sys.argv
    sys.argv = ["find_refs.py"] + targets_hex
    try:
        import find_refs  # noqa: E402  (模块级执行 = 全量扫描,~15 min)
    finally:
        sys.argv = argv_save
    hits = {t: list(v) for t, v in find_refs.hits.items()}
    CACHE.mkdir(parents=True, exist_ok=True)
    HITS_CACHE.write_text(json.dumps({
        "exe_size": EXE_PATH.stat().st_size, "exe_sha": _sha(),
        "targets": targets_hex,
        "hits": {f"{t:x}": [list(v) for v in lst] for t, lst in hits.items()},
    }))
    return hits


def riprefs_hits():
    """riprefs.py --verify 口径:字节扫 + 按 .pdata 对齐重解码(只 .text)。"""
    import riprefs  # noqa: E402
    h = riprefs.refs_for(set(REF_TARGETS), ".text", True)
    return {t: {site for site, _enc in h.get(t, [])} for t in REF_TARGETS}


def decode_at(rva):
    fb = func_of(rva)
    if fb is None:
        return None
    for ins in md.disasm(rd(fb[0], rva - fb[0] + 16), BASE + fb[0]):
        if ins.address - BASE == rva:
            return ins
    return None


def rip_raw_sites():
    """未 verify 的字节扫集合(用来判定差集条目是不是 mid-instruction)。"""
    import riprefs  # noqa: E402
    h = riprefs.refs_for(set(REF_TARGETS), ".text", False)
    return {t: {site for site, _enc in h.get(t, [])} for t in REF_TARGETS}


def argtrace(site, tag, fs, fe):
    """插入点前 12 条指令里对 rcx/rdx/r8 的最后一次写入;rdx 的立即数即 token id."""
    want = {"rcx", "rdx", "r8"}
    ins_list = [i for i in md.disasm(rd(fs, site - fs + 5), BASE + fs)
                if i.address - BASE < site][-12:]
    last = {}
    for ins in ins_list:
        if not ins.operands:
            continue
        op0 = ins.operands[0]
        if op0.type == 1 and op0.reg in ins.regs_write:
            rn = ins.reg_name(op0.reg).lower()
            if rn in want:
                last[rn] = ins
    lines = []
    for rn in ("rcx", "rdx", "r8"):
        ins = last.get(rn)
        if ins is not None:
            lines.append(f"{rn}<-{ins.mnemonic} {ins.op_str}@{ins.address - BASE:x}")
    return lines


def main() -> int:
    ok = True
    print(f"## family_def={FAMILY_DEF} 定义=vtable ±0x200 内出现 "
          "{{0x3AFD30,0x3B1330,0x3B01A0,0x3B1420,0x3B0F80,0x3B1230}} 任一(§83.2 补记①)")
    print(f"## ref_targets={['0x%x' % t for t in REF_TARGETS]} insert={dict((hex(t), n) for t, n in INSERT_CALLS.items())}")

    hits = find_refs_hits()
    refs_find = {t: {r[0]: r for r in hits.get(t, [])} for t in REF_TARGETS}
    for t in REF_TARGETS:
        refs_find[t] = set(refs_find[t])
    refs_rip = riprefs_hits()
    raw_rip = rip_raw_sites()

    for t in REF_TARGETS:
        print(f"## target 0x{t:x}: refs_find={len(refs_find[t])} "
              f"refs_rip={len(refs_rip[t])} "
              f"diff={len(refs_find[t] ^ refs_rip[t])}")
    for t in REF_TARGETS:
        for s in sorted(refs_find[t] - refs_rip[t]):
            why = ("mid_instruction(字节扫原始集可见,--verify 重解码丢弃)"
                   if s in raw_rip[t] else "find_only(非 rip 形态,riprefs 口径不含)")
            ins = decode_at(s)
            print(f"## DIFF find_only {s:#x} ->0x{t:x}: "
                  f"{ins.mnemonic if ins else '?'} {ins.op_str if ins else '?'} ({why})")
        for s in sorted(refs_rip[t] - refs_find[t]):
            print(f"## DIFF rip_only {s:#x} ->0x{t:x}: 全量解码未见(应不可能)")
            ok = False

    # ② 归桶 + ③ 相交
    cols = ["ref_site", "func_start", "func_end", "insn", "ref_kind",
            "contains_insert_call", "insert_call_site", "family_def"]
    print("\t".join(cols))
    buckets = {}
    for t in REF_TARGETS:
        for s in sorted(refs_find[t] | refs_rip[t]):
            fb = func_of(s)
            if fb is None:
                print(f"## FAIL: ref site {s:#x} ->0x{t:x} 不在任何 .pdata extent 内")
                ok = False
                continue
            buckets.setdefault(fb, []).append((s, t))

    named, field, orphan = [], [], []
    for (fs, fe), sites in sorted(buckets.items()):
        insert_hits = []
        for t, tag in INSERT_CALLS.items():
            for r in hits.get(t, []):
                if fs <= r[0] < fe:
                    insert_hits.append((r[0], tag, r[1]))
        for s, t in sites:
            ins = decode_at(s)
            if ins is None:
                print(f"## FAIL: ref site {s:#x} 对齐重解码失败")
                ok = False
                row_insn = "<undecoded>"
                row_kind = "?"
                row_store = None
            else:
                row_insn = f"{ins.mnemonic} {ins.op_str} ; ->0x{t:x}"
                row_kind = ins.mnemonic
                row_store = next((o for o in ins.operands if o.type == 3), None)
            print("\t".join([f"{s:x}", f"{fs:x}", f"{fe:x}", row_insn, row_kind,
                             "1" if insert_hits else "0",
                             ";".join(f"{a:x}:{tag}:{form}"
                                      for a, tag, form in sorted(insert_hits)),
                             FAMILY_DEF]))
            if insert_hits:
                named.append((fs, fe, s, t))
        if insert_hits:
            for a, tag, form in sorted(insert_hits):
                print(f"## insert {form}@{a:x}({tag}) in {fs:x}..{fe:x} "
                      + " ".join(argtrace(a, tag, fs, fe)))
        else:
            orphan.append((fs, fe))

    # 字段存储检测:引用 insn 是 lea 且同函数里后面跟着
    # `mov [reg+disp], <lea 目的寄存器>`(寄存器名匹配)
    named_starts = {n[0] for n in named}
    for (fs, fe), sites in sorted(buckets.items()):
        if fs in named_starts:
            continue
        ins_list = list(md.disasm(rd(fs, fe - fs), BASE + fs))
        lea_writes = {}
        for ins in ins_list:
            if ins.mnemonic == "lea" and ins.operands and ins.operands[0].type == 1:
                src_reg = ins.reg_name(ins.operands[0].reg).lower()
                tgt = None
                for o in ins.operands[1:]:
                    if o.type == 3 and o.mem.base == X86_REG_RIP:
                        tgt = ins.address + ins.size + o.mem.disp - BASE
                if tgt in REF_TARGETS:
                    lea_writes.setdefault(src_reg, []).append((ins.address - BASE, tgt))
        for ins in ins_list:
            if ins.mnemonic != "mov" or not ins.operands:
                continue
            dst, src = ins.operands[0], ins.operands[1]
            if dst.type != 3 or src.type != 1:
                continue
            rn = ins.reg_name(src.reg).lower()
            for addr, tgt in lea_writes.get(rn, []):
                if addr < ins.address - BASE:
                    disp = dst.mem.disp
                    base_rn = ins.reg_name(dst.mem.base).lower()
                    print(f"## field-store: func {fs:x} 把 0x{tgt:x} 的 lea 结果写入"
                          f" [{base_rn}+0x{disp:x}] @ {ins.address - BASE:x}")
                    field.append((fs, fe, tgt, disp))

    if named:
        verdict = "insertion_named"
    elif field:
        verdict = "insertion_through_field"
    else:
        verdict = "insertion_not_found"
    print(f"## verdict={verdict}")
    print("## 何时被调: 未观测(离线,零 shot)")
    if not ok:
        print("FAIL")
        return 1
    if not named and not orphan and not refs_any(hits):
        print("FAIL")
        return 1
    print("PASS")
    return 0


def refs_any(hits):
    return any(hits.get(t) for t in REF_TARGETS)


if __name__ == "__main__":
    sys.exit(main())
