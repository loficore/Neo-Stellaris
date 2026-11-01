#!/usr/bin/env python3
"""find_iterator.py — A1: `every_system` 迭代器的名字拼接器与注册点(§80.1,零 shot)。

背景(计划里已经实跑过,本探针不再重复验证):`b"every_system\\0"` 与
`b"every_owned_system\\0"` 在 exe 里都不存在,`b"every_"` 只命中名字池 ——
所以名字是**运行时拼的**(§19 的 104 个拼接器)。本探针只走拼接器:

  1. 扫 `0x195A580..0x19A7268` 里的每一条 `lea reg,[rip+disp32]`,
     解出目标 RVA,若该 RVA 处的 C 串以 `system` 开头(或等于 `system`),
     记 `(registrar_rva, name_rva, 字符串)`;
  2. 对命中的 registrar 调 `scripts/fastcalls.py` 找调用者,
     标出落在 §19 注册函数区间 `0x1930E70..0x196D3E6` 里的那些;
  3. 对每个 registrar,把「名字怎么拼出来的 / 铸的哪个 token / 建的对象」
     逐条打印:每个 `call 0x1D13270`(GetOrAddToken)近旁的名字拼接调用
     (拼接器里读到的前缀字面量)、`call 0x2185218`(new)的尺寸、
     class_info 的 `lea` 目标、`call 0x3AEF60`(BST insert)的落点。

`.pdata` 有 chained unwind 记录(同一个函数起点多条 RUNTIME_FUNCTION),
所以函数表按「同起点取最大 end」归并 —— 不归并会把一个函数拆成几条、还会重复命中。

用法:
    python3 scripts/scratch/2026-10_per_system_loop/find_iterator.py

不碰游戏、不联网;exe 路径走 `disrva.resolve_exe()` 的候选链
(`NS_STELLARIS_EXE` 优先),不内联受保护的路径。
"""
from __future__ import annotations

import bisect
import pathlib
import re
import struct
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import disrva  # noqa: E402
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP  # noqa: E402

BASE = 0x140000000
CONCAT_LO, CONCAT_HI = 0x195A580, 0x19A7268      # §19: 104 个名字拼接器
REGISTER_LO, REGISTER_HI = 0x1930E70, 0x196D3E6  # §19: 101 个注册函数
GET_OR_ADD_TOKEN = 0x1D13270
OPERATOR_NEW = 0x2185218
BST_INSERT = 0x3AEF60
DB_CTOR = 0x3AEBA0
REPO = pathlib.Path(__file__).resolve().parents[3]
FASTCALLS = REPO / "scripts" / "fastcalls.py"

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def _sections():
    """(image_bytes, [(name, va, vsize, raw_size, raw_ptr), ...]) for the exe."""
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


def cstr(rva: int, cap: int = 96) -> str | None:
    raw = rd(rva, cap)
    end = raw.find(b"\0")
    if end <= 0:
        return None
    try:
        s = raw[:end].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if all(32 <= ord(c) < 127 for c in s) else None


def _pdata_functions():
    """start -> end, merging chained unwind records (same start, keep max end)."""
    pd = next(s for s in SECS if s[0] == ".pdata")
    _name, _va, _vs, rawsz, praw = pd
    merged: dict[int, int] = {}
    for i in range(rawsz // 12):
        b, e, _u = struct.unpack_from("<III", DATA, praw + i * 12)
        if e > merged.get(b, 0):
            merged[b] = e
    return merged


FUNC_END = _pdata_functions()
FUNC_STARTS = sorted(FUNC_END)


def func_of(rva: int):
    i = bisect.bisect_right(FUNC_STARTS, rva) - 1
    if i < 0:
        return None
    s = FUNC_STARTS[i]
    return (s, FUNC_END[s]) if rva < FUNC_END[s] else None


def disasm(start: int, end: int):
    return list(md.disasm(rd(start, end - start), start))


def rip_target(insn) -> int | None:
    if not insn.operands:
        return None
    op = insn.operands[-1]
    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
        return insn.address + insn.size + op.mem.disp
    return None


def imm_call_target(insn) -> int | None:
    if insn.mnemonic != "call" or not insn.operands:
        return None
    op = insn.operands[0]
    # disasm() is fed RVA addresses, so capstone's absolute operand is already an RVA.
    if op.type == X86_OP_IMM:
        return op.imm
    return None


def join_prefix(fn: int) -> str | None:
    """The literal prefix a name-joiner prepends (`every_`, `random_`, `any_`).

    The joiners in this binary all materialise the prefix with the same three
    loads (`mov eax,[rip+X]` + `movzx word [rip+X+4]` + `movzx byte [rip+X+6]`).
    """
    fx = func_of(fn)
    if fx is None:
        return None
    fs, fe = fx
    insns = disasm(fs, fe)
    for i, insn in enumerate(insns):
        if insn.mnemonic != "mov" or "eax" not in insn.op_str.split(",")[0]:
            continue
        tgt = rip_target(insn)
        if tgt is None:
            continue
        for nxt in insns[i + 1:i + 4]:
            tgt2 = rip_target(nxt)
            if tgt2 is not None and tgt2 - tgt in (4, 6):
                s = cstr(tgt, 24)
                if s and s.endswith("_"):
                    return s
    # movabs rax, 0x5f6465726564726f  -> "ordered_"
    for insn in insns[:20]:
        if insn.mnemonic != "movabs":
            continue
        try:
            raw = int(insn.op_str.split(",")[-1].strip(), 0)
        except ValueError:
            continue
        b = raw.to_bytes(8, "little")
        if all(32 <= c < 127 for c in b.rstrip(b"\0")):
            s = b.rstrip(b"\0").decode()
            if s.endswith("_"):
                return s
    return None


def concat_hits():
    """(registrar_rva, name_rva, string) — one row per distinct function+literal."""
    seen = set()
    hits = []
    for fs in FUNC_STARTS:
        if not (CONCAT_LO <= fs < CONCAT_HI):
            continue
        for insn in disasm(fs, FUNC_END[fs]):
            if insn.mnemonic != "lea":
                continue
            target = rip_target(insn)
            if target is None:
                continue
            s = cstr(target)
            if s and (s == "system" or s.startswith("system")):
                key = (fs, target)
                if key not in seen:
                    seen.add(key)
                    hits.append((fs, target, s))
    return hits


def callers_of(target: int):
    proc = subprocess.run(
        [sys.executable, str(FASTCALLS), f"0x{target:x}", "--top", "500"],
        capture_output=True, text=True, check=False)
    out = proc.stdout
    first = out.splitlines()[0] if out.splitlines() else ""
    m = re.match(r"(\d+) direct code sites", first)
    funcs = [m2.groups() for m2 in
             (re.match(r"\s*\d+ sites\s+0x([0-9a-f]+)\.\.0x([0-9a-f]+)", ln)
              for ln in out.splitlines()) if m2]
    return (int(m.group(1)) if m else None), [(int(a, 16), int(b, 16))
                                             for a, b in funcs]


def mint_sites(register_fn: int):
    """One row per GetOrAddToken call: base literal, join prefix, object window."""
    fs, fe = func_of(register_fn)
    insns = disasm(fs, fe)
    rows = []
    for i, insn in enumerate(insns):
        if imm_call_target(insn) != GET_OR_ADD_TOKEN:
            continue
        row = {"at": insn.address, "base": None, "join": None, "prefix": None,
               "class_info": None, "insert": None, "window": []}
        for prev in reversed(insns[max(0, i - 12):i]):
            tgt = rip_target(prev)
            if prev.mnemonic == "lea" and tgt is not None and cstr(tgt, 32):
                row["base"] = (tgt, cstr(tgt, 32))
                break
        for prev in reversed(insns[max(0, i - 12):i]):
            callee = imm_call_target(prev)
            if callee is not None and join_prefix(callee):
                row["join"], row["prefix"] = callee, join_prefix(callee)
                break
        j = i
        while j < len(insns) and imm_call_target(insns[j]) != BST_INSERT:
            j += 1
        row["window"] = insns[max(0, i - 12):min(len(insns), j + 1)]
        if j < len(insns):
            row["insert"] = insns[j].address
        for w in row["window"]:
            tgt = rip_target(w)
            if (w.mnemonic == "lea" and tgt is not None
                    and 0x2600000 <= tgt < 0x2700000 and "rcx" in w.op_str):
                row["class_info"] = tgt
        rows.append(row)
    return rows


def fmt(insn) -> str:
    return f"0x{insn.address:x}  {insn.mnemonic:<7} {insn.op_str}"


def main() -> int:
    hits = concat_hits()
    print(f"# functions in 0x{CONCAT_LO:x}..0x{CONCAT_HI:x} with a "
          f"'system' lea: {len(hits)} (deduped; .pdata chained records merged)")
    exact = [h for h in hits if h[2] == "system"]
    print(f"# of which the literal is exactly 'system': {len(exact)}")
    for register_fn, name_rva, s in exact:
        fs, fe = func_of(register_fn)
        print(f"\n## registrar=0x{register_fn:x} (0x{fs:x}..0x{fe:x}, "
              f"{fe - fs:#x} B) name_rva=0x{name_rva:x} string={s!r}")
        n_sites, callers = callers_of(register_fn)
        print(f"   fastcalls: {n_sites} direct code sites in {len(callers)} functions")
        in_reg = [(b, e) for b, e in callers if REGISTER_LO <= b < REGISTER_HI]
        for b, e in in_reg:
            print(f"   caller in §19 register range: 0x{b:x}..0x{e:x} "
                  f"({'IS' if b == fs else 'not'} the registrar itself)")
        if not in_reg:
            print("   callers: " + ", ".join(f"0x{b:x}..0x{e:x}" for b, e in callers))
        for row in mint_sites(register_fn):
            base = row["base"] or (None, None)
            base_s = (f"0x{base[0]:x} {base[1]!r}" if base[0] is not None
                      else "None (literal not in window)")
            print(f"   mint @0x{row['at']:x}  base={base_s}  "
                  f"join={hex(row['join']) if row['join'] else None} "
                  f"prefix={row['prefix']!r}  class_info="
                  f"{hex(row['class_info']) if row['class_info'] else None}")
            for insn in row["window"]:
                print("      " + fmt(insn))
            if row["class_info"]:
                qw = struct.unpack_from("<4Q", rd(row["class_info"], 32), 0)
                print("      class_info qwords: " +
                      ", ".join(hex(x) for x in qw))
    return 0 if exact else 1


if __name__ == "__main__":
    sys.exit(main())
