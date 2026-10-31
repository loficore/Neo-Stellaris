#!/usr/bin/env python3
"""loop_body.py — A2: `every_system` 的「按系统」循环在哪。

入口链(§80.1):class_info 0x2666670 -> create 0x1A74EB0 -> new(0x188) + ctor 0x17F7860;
`[obj] = 0x26562D0`、`[obj+8] = 0x2615DB8`、`[obj+0x180] = 0x80`、`[obj+0xC0]` = `limit` 触发器。

已读到的形状(本探针的出发点):
  - slot[2] (`[vptr+0x10]`) = 0x17F7920:  `cmp r8d, 0x3f92`(system 的 scope 类型 id)
    → 命中时 `jmp [&obj[0xC0]][0x28]`(CTrigger::Evaluate,即 `limit`);否则 `jmp 0x3B01A0`。
  - slot[1] (`[vptr+0x08]`) = 0x3AFD30: 逐 token 的派发器,`r8d = [ctx+0x38]`(当前 scope 类型)
    然后 `call [rax+0x10]`(ExecuteActual)。

所以「每系统一次」不在这两个槽里 —— 它必须是**把 ctx 的当前 scope 换成每一颗星、再调
Execute/ExecuteActual 的那个循环**。本探针:

  1. `--callers <rva>`: 找 `E8 rel32` 直接调用点,按 `.pdata` 归函数;
  2. 对每个调用者,找包含该调用点的**回跳循环**(循环头 <= site <= 回跳);
  3. 打印循环边界、回跳指令、循环里的容器读点(`mov reg,[reg+disp]` / `[reg+disp*stride]`)
     与 `mov regd,[reg+disp]` 形态的「scope 类型」读点。

用法:
    python3 scripts/scratch/2026-10_per_system_loop/loop_body.py --callers 0x1D08520
    python3 scripts/scratch/2026-10_per_system_loop/loop_body.py --vtables      # A1 那个对象的槽
"""
from __future__ import annotations

import bisect
import pathlib
import re
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import disrva  # noqa: E402
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from capstone.x86 import X86_OP_IMM, X86_OP_MEM  # noqa: E402

BASE = 0x140000000
CREATE = 0x1A74EB0
VTBLS = (0x26562D0, 0x2615DB8)
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


def qword(rva: int) -> int:
    return struct.unpack_from("<Q", rd(rva, 8), 0)[0]


def fmt(insn) -> str:
    return f"0x{insn.address:x}  {insn.mnemonic:<7} {insn.op_str}"


def branch_target(insn):
    if not insn.operands:
        return None
    if not (insn.mnemonic.startswith("j") or insn.mnemonic == "loop"):
        return None
    op = insn.operands[0]
    return op.imm if op.type == X86_OP_IMM else None


def call_sites(target: int):
    """Direct `E8 rel32` / `FF 15` sites of `target` (same shapes as fastcalls)."""
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
        pos = 0
        while True:
            pos = blob.find(b"\xff\x15", pos)
            if pos < 0:
                break
            pos += 1
            if pos + 6 > len(blob):
                continue
            here = va + pos
            disp = struct.unpack_from("<i", blob, pos + 2)[0]
            ptr = here + 6 + disp
            raw = rd(ptr, 8)
            if len(raw) == 8 and struct.unpack_from("<Q", raw, 0)[0] - BASE == target:
                out.append(here)
            pos += 6
    return sorted(set(out))


def loops_containing(fs: int, fe: int, site: int):
    insns = disasm(fs, fe)
    out = []
    for insn in insns:
        tgt = branch_target(insn)
        if tgt is None or tgt >= insn.address:
            continue
        if tgt <= site <= insn.address:
            out.append((tgt, insn))
    return out


def container_reads(fs: int, fe: int, lo: int, hi: int):
    rows = []
    for insn in disasm(max(lo, fs), min(hi, fe)):
        if insn.mnemonic not in ("mov", "movsxd", "movzx") or len(insn.operands) != 2:
            continue
        src = insn.operands[1]
        if src.type != X86_OP_MEM:
            continue
        if src.mem.disp or src.mem.index:
            rows.append(fmt(insn))
    return rows


def main() -> int:
    if "--callers" in sys.argv:
        target = int(sys.argv[sys.argv.index("--callers") + 1], 16)
        sites = call_sites(target)
        print(f"# {len(sites)} direct sites to 0x{target:x}")
        seen = set()
        for site in sites:
            fx = func_of(site)
            if fx is None:
                print(f"0x{site:x}  (site not in any .pdata function)")
                continue
            fs, fe = fx
            loops = loops_containing(fs, fe, site)
            if not loops:
                if fs not in seen:
                    print(f"0x{site:x}  func 0x{fs:x}..0x{fe:x}  (site NOT inside a loop)")
                    seen.add(fs)
                continue
            for lo, branch in loops:
                key = (fs, lo, branch.address)
                if key in seen:
                    continue
                seen.add(key)
                print(f"\n0x{site:x}  func 0x{fs:x}..0x{fe:x}  "
                      f"loop 0x{lo:x}..0x{branch.address:x} "
                      f"({branch.mnemonic} {branch.op_str})")
                print("   branch site:")
                for back in disasm(branch.address - 24, branch.address + branch.size):
                    print("     " + fmt(back))
                print("   container / field reads in the loop:")
                for row in container_reads(fs, fe, lo, branch.address)[:40]:
                    print("     " + row)
        return 0

    print(f"# create 0x{CREATE:x}: new(0x188), ctor 0x17F7860")
    for vt in VTBLS:
        print(f"\n## vtable 0x{vt:x}")
        for slot in range(0x28):
            target = qword(vt + slot * 8)
            if not (BASE <= target < BASE + 0x4000000):
                print(f"  [+0x{slot * 8:02x}] 0x{target:x} (not an image address)")
                continue
            t = target - BASE
            fx = func_of(t)
            if fx is None:
                print(f"  [+0x{slot * 8:02x}] 0x{t:x} (not a .pdata function start)")
                continue
            fs, fe = fx
            loops = [b for b in (branch_target(i) for i in disasm(fs, fe))
                     if b is not None and b < fs + (fe - fs) and b >= fs]
            print(f"  [+0x{slot * 8:02x}] 0x{t:x} func 0x{fs:x}..0x{fe:x} "
                  f"({fe - fs:#x} B)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
