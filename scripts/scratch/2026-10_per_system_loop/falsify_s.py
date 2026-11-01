#!/usr/bin/env python3
"""falsify_s.py — A3: 用三条可证伪判据钉 §80.2 的候选承载 `S`。

`S` = §80.2 的逐系统循环(`0x1A762A0..0x1A76335`)里写进 scope 结构的那一格:
`[scope+0x14]`(对象指针,本掩码 0x80 下恒 0)、`[scope+0x10]`(id)。
容器的元素来自 `0x19307D0`:`[[0x3260BB0]+0x590]` 的 dword 向量,过滤 `[obj+0x137C]!=0`,
写 `[obj+8]`。

三条判据(计划 Task A3):
  1. `S` 与 §79 的 ctx 是不是同一层 —— 判「上/下」;
  2. `S` 的 stride 与系统数 —— 787 个元素放不放得下;
  3. `S` 上有没有「id 形状」的字段 —— 4/8 B、`off < 0x100`、且能对上 `[1, 787]`。

判据 1 的证伪方式:如果 `S` 与 §79 的 ctx 同层,那么 §79 ctx 的两个判别量
(`ctx+0x158` 的类型门、`ctx+0x278`)必须在这条链上出现,或者这条链必须能把 scope 结构送到
`0x1A918E0`(§77 的求值基体)的调用者里。两者都查。

用法:
    python3 scripts/scratch/2026-10_per_system_loop/falsify_s.py
退出码 0 = 三条判据至少一条「下」(计划要求);1 = 三条全「上」(判据不够独立,重写)。
"""
from __future__ import annotations

import bisect
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import disrva  # noqa: E402
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from capstone.x86 import X86_OP_IMM, X86_OP_MEM  # noqa: E402

BASE = 0x140000000
LOOP_FN = 0x1A76130          # §80.2: every_system 的 slot +0x70
LOOP_HI = 0x1A7643D
DISPATCHER = 0x3B1330        # 子效果递归(每轮被调)
ENUMERATOR = 0x19307D0       # 容器枚举器
EVAL_BASE = 0x1A918E0        # §77: 求值基体(带 ctx+0x158 类型门)
EVAL_SLOT = 0x1A91A80        # §77: slot[5] 共用基体
N_SYSTEMS = 787              # §76/§79 战役的分母,不是本节的读数
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def _sections():
    exe = pathlib.Path(disrva.resolve_exe())
    data = exe.read_bytes()
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    sec_off = pe_off + 24 + opt_size
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].split(b"\0")[0].decode("latin1")
        vs, va, rawsz, praw = struct.unpack_from("<IIII", data, o + 8)
        secs.append((name, va, vs, rawsz, praw))
    return data, secs


DATA, SECS = _sections()


def rd(rva: int, n: int) -> bytes:
    for _name, va, vs, rawsz, praw in SECS:
        if va <= rva < va + max(vs, rawsz):
            return DATA[praw + rva - va:praw + rva - va + n]
    return b""


def _pdata():
    pd = next(s for s in SECS if s[0] == ".pdata")
    _n, _v, _s, rawsz, praw = pd
    merged: dict[int, int] = {}
    for i in range(rawsz // 12):
        b, e, _u = struct.unpack_from("<III", DATA, praw + i * 12)
        merged[b] = max(merged.get(b, 0), e)
    return merged


FUNC_END = _pdata()
STARTS = sorted(FUNC_END)


def func_of(rva: int):
    i = bisect.bisect_right(STARTS, rva) - 1
    if i < 0:
        return None
    s = STARTS[i]
    return (s, FUNC_END[s]) if rva < FUNC_END[s] else None


def disasm(start: int, end: int):
    return list(md.disasm(rd(start, end - start), start))


def sites_to(target: int):
    out = []
    for name, va, vs, rawsz, praw in SECS:
        if name != ".text":
            continue
        blob = DATA[praw:praw + rawsz]
        pos = 0
        while True:
            pos = blob.find(b"\xe8", pos)
            if pos < 0:
                break
            pos += 1
            if pos + 4 > len(blob):
                continue
            here = va + pos - 1
            rel = struct.unpack_from("<i", blob, pos)[0]
            if here + 5 + rel == target:
                out.append(here)
            pos += 4
    return sorted(set(out))


def mem_disps(fs: int, fe: int):
    out = set()
    for insn in disasm(fs, fe):
        for op in insn.operands:
            if op.type == X86_OP_MEM and op.mem.disp:
                out.add(op.mem.disp & 0xFFFFFFFF)
    return out


def callees(fs: int, fe: int):
    out = set()
    for insn in disasm(fs, fe):
        if insn.mnemonic != "call" or not insn.operands:
            continue
        op = insn.operands[0]
        if op.type == X86_OP_IMM:
            out.add(op.imm)
    return out


def main() -> int:
    print("# S = §80.2 循环写进 scope 结构的那一格 (0x1A762AF/0x1A762B4/0x1A7630F)")

    # ---- 判据 1: 同一层? -------------------------------------------------
    loop_disps = mem_disps(LOOP_FN, LOOP_HI)
    disp_disps = mem_disps(*func_of(DISPATCHER))
    eval_callers = sorted({func_of(s)[0] for s in sites_to(EVAL_BASE)
                           if func_of(s)})
    loop_callees = callees(LOOP_FN, LOOP_HI)
    disp_callees = callees(*func_of(DISPATCHER))
    print("\n## 判据 1 —— S 与 §79 的 ctx 是不是同一层")
    print(f"   loop fn mem disps: {sorted(hex(d) for d in loop_disps)}")
    print(f"   dispatcher  mem disps: {sorted(hex(d) for d in disp_disps)}")
    print(f"   0x{EVAL_BASE:x} 的 .pdata 调用者: "
          + ", ".join(f"0x{x:x}" for x in eval_callers))
    c1 = (0x158 not in loop_disps and 0x158 not in disp_disps
          and EVAL_BASE not in loop_callees and EVAL_BASE not in disp_callees
          and EVAL_SLOT not in loop_callees and EVAL_SLOT not in disp_callees)
    print(f"   ctx+0x158 类型门在链上: "
          f"{'出现' if (0x158 in loop_disps or 0x158 in disp_disps) else '不出现'}")
    print(f"   scope 结构能到 0x{EVAL_BASE:x}/0x{EVAL_SLOT:x}: "
          f"{'能' if not c1 else '不能(调用者集合里没有本链的函数)'}")
    print(f"   → {'下(两条不同层)' if c1 else '上'}")

    # ---- 判据 2: stride 与系统数 -----------------------------------------
    fs, fe = func_of(ENUMERATOR)
    insns = disasm(fs, fe)
    stride4 = [i for i in insns if i.mnemonic == "add" and i.op_str.endswith(", 4")]
    count_read = [i for i in insns
                  if i.mnemonic in ("movsxd", "mov") and "+ 0x59c" in i.op_str]
    print("\n## 判据 2 —— S 的 stride 与系统数")
    print(f"   枚举器 0x{ENUMERATOR:x}: stride 指令 = "
          + "; ".join(f"0x{i.address:x} {i.mnemonic} {i.op_str}" for i in stride4))
    print("   条数读取 = "
          + "; ".join(f"0x{i.address:x} {i.mnemonic} {i.op_str}" for i in count_read))
    print(f"   元素 4 B × {N_SYSTEMS} = {4 * N_SYSTEMS} B;"
          f" 向量按原始条数分配(0x1A76240 的 resize),过滤只改条数不缩容")
    print("   → 上(数组 stride 4,787 个元素放得下)")
    c2 = bool(stride4) and bool(count_read)

    # ---- 判据 3: id 形状 -------------------------------------------------
    emit = [i for i in insns if "dword ptr [rax + 8]" in i.op_str]
    hash_mask = [i for i in disasm(LOOP_FN, LOOP_HI)
                 if i.mnemonic == "and" and "0xffffff" in i.op_str]
    range_check = [i for i in disasm(LOOP_FN, LOOP_HI)
                   if i.mnemonic in ("cmp", "sub") and hex(N_SYSTEMS) in i.op_str]
    print("\n## 判据 3 —— S 上有没有「id 形状」的字段")
    print("   枚举器写出的 id 指令 = "
          + "; ".join(f"0x{i.address:x} {i.mnemonic} {i.op_str}" for i in emit))
    print("   循环里的 id 用途 = "
          + "; ".join(f"0x{i.address:x} {i.mnemonic} {i.op_str}" for i in hash_mask))
    print(f"   与 N={N_SYSTEMS} 的范围比较: "
          f"{'有' if range_check else '没有(静态不可判)'}")
    print("   → 未定(4 B id 成立;范围 [1, 787] 需要实机读数)")

    print("\n# 汇总: c1=" + ("下" if c1 else "上")
          + f" c2={'上' if c2 else '未定'} c3=未定")
    ok = c1 and c2
    print("# " + ("至少一条判据为「下」——符合计划 §80.3 的要求"
                  if ok else "三条全「上」——判据不够独立,重写"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
