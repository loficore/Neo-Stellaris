#!/usr/bin/env python3
"""patch_point.py — 第七把 guard 的离线靶位闸（§81.1 的生产者）。

只读 `stellaris.exe` 拷贝，不起进程、不注入。五条 assert 全过才打印 PASS：

1. `0x3B1330` 的前 15 字节 = 3 条 5 B 指令（`mov [rsp+8],rbx` / `mov [rsp+0x10],rbp` /
   `mov [rsp+0x18],rsi`），第 4 条从 `0x3B133F`（`push rdi`）开始 ⇒ detour 的
   `decodePrologueLength(≥14)` 落在**唯一**的边界上。
2. `every_system` 的 vtable `0x26562D0`：`+0x70 = 0x1A76130`（逐系统循环体）、
   `+0x98 = 0x3B1420`（effect 谓词基体）。
3. 循环体每轮的下发是**直接** `call 0x3B1330`（`0x1A76324`，`rcx = r14` = self）。
4. 容器全局 `0x3260BB0` 在枚举器里被读两次：`+0x590`（dword 向量）、`+0x59C`（原始条数）；
   `0x1930815` 读到的容器元素就是完整 32 位 id，`0x1930839` 用它核对 `[obj+8]`。
5. **反证**：循环头 `0x1A762A0` 之后有 `mov [rsp+0x28],rax`（`0x1A762AF`）与
   `cmp esi,[rbp+0xC0]`（`0x1A7632F`）—— C-ABI detour 会让被调函数体跑在 detour 的帧上，
   所以那里不是合法补丁点。补丁窗口必须是**函数入口**。

旧名/来历：本脚本由计划 `2026-10-30-per-system-loop-shot` 的 Task 1 建立。
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
import disrva  # noqa: E402

from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402

TARGET = 0x3B1330
VTABLE = 0x26562D0
LOOP_HEAD = 0x1A762A0
CALL_SITE = 0x1A76324
ENUMERATOR = 0x19307DA
GALAXY_DB = 0x3260BB0

EXPECT = bytes.fromhex("48895c240848896c24104889742418")


def reader():
    image = disrva._image()
    assert image is not None, "stellaris.exe not found (set NS_STELLARIS_EXE)"
    _exe, blob, secs = image

    def rd(rva, n):
        for _name, va, vsize, rawsz, praw, _ch in secs:
            if va <= rva < va + max(vsize, rawsz):
                off = praw + (rva - va)
                return blob[off:off + n]
        raise ValueError(f"rva 0x{rva:x} is not inside any section")

    return rd


def disasm(rd, rva, n):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True          # operand detail is what `_rip_targets` reads
    return list(md.disasm(rd(rva, n), rva))


def main():
    rd = reader()

    # 1. 15 B 补丁窗口：3 条 5 B 指令，第 4 条在 +15。
    head = rd(TARGET, 32)
    assert head[:15] == EXPECT, head[:15].hex()
    insns = disasm(rd, TARGET, 24)
    lengths = [len(i.bytes) for i in insns[:3]]
    assert lengths == [5, 5, 5], lengths
    assert insns[3].address == TARGET + 15, hex(insns[3].address)
    print(f"patch window 0x{TARGET:x}..0x{TARGET + 15:x} = {EXPECT.hex()}")
    print(f"  next instruction 0x{insns[3].address:x}: {insns[3].mnemonic} {insns[3].op_str}")

    # 2. vtable 的两格。
    import struct

    slot_70 = struct.unpack("<Q", rd(VTABLE + 0x70, 8))[0]
    slot_98 = struct.unpack("<Q", rd(VTABLE + 0x98, 8))[0]
    assert slot_70 - 0x140000000 == 0x1A76130, hex(slot_70)
    assert slot_98 - 0x140000000 == 0x3B1420, hex(slot_98)
    print(f"vtable 0x{VTABLE:x}: +0x70 -> 0x{slot_70 - 0x140000000:x}, "
          f"+0x98 -> 0x{slot_98 - 0x140000000:x}")

    # 3. 循环里的下发是直接 call，且前一条把 rcx 设成 r14。
    site = disasm(rd, CALL_SITE - 8, 16)
    call = [i for i in site if i.address == CALL_SITE]
    assert call and call[0].mnemonic == "call", site
    assert call[0].op_str == hex(TARGET), call[0].op_str   # disassembled at RVA addresses
    prev = [i for i in site if i.address < CALL_SITE][-1]
    assert prev.mnemonic == "mov" and prev.op_str == "rcx, r14", prev.op_str
    print(f"call site 0x{CALL_SITE:x}: {prev.mnemonic} {prev.op_str} ; call 0x{TARGET:x}")

    # 4. 容器全局的两个偏移 + id 的核对等式。
    enum = disasm(rd, ENUMERATOR, 0x90)
    loads = [i for i in enum if GALAXY_DB in _rip_targets(i)]
    assert loads, "no rip reference to the galaxy db"
    # 直接核两条汇编：+0x590 的向量与 +0x59C 的计数
    text = {i.address: f"{i.mnemonic} {i.op_str}" for i in enum}
    assert text.get(0x19307E7) == "mov rdx, qword ptr [rax + 0x590]", text.get(0x19307E7)
    assert text.get(0x19307EE) == "movsxd rax, dword ptr [rax + 0x59c]", text.get(0x19307EE)
    assert text.get(0x1930815) == "mov r8d, dword ptr [rdx]", text.get(0x1930815)
    assert text.get(0x1930839) == "cmp dword ptr [rax + 8], r8d", text.get(0x1930839)
    print(f"galaxy db 0x{GALAXY_DB:x}: +0x590 vector, +0x59c count, "
          "id = [obj+8] and the element is the full 32-bit id")

    # 5. 反证：循环头之后的 rsp/rbp 用法。
    loop = disasm(rd, LOOP_HEAD, 0xA0)
    ltext = {i.address: f"{i.mnemonic} {i.op_str}" for i in loop}
    assert ltext.get(0x1A762AF) == "mov qword ptr [rsp + 0x28], rax", ltext.get(0x1A762AF)
    assert ltext.get(0x1A762B4) == "mov dword ptr [rsp + 0x30], r8d", ltext.get(0x1A762B4)
    assert ltext.get(0x1A7632F) == "cmp esi, dword ptr [rbp + 0xc0]", ltext.get(0x1A7632F)
    print("loop head is NOT a patch point: 0x1A762AF writes [rsp+0x28], "
          "0x1A7632F reads [rbp+0xc0]")

    print("PASS")


def _rip_targets(insn):
    """All absolute targets a rip-relative operand resolves to."""
    out = []
    if "rip" not in insn.op_str:
        return out
    try:
        from capstone.x86 import X86_OP_MEM, X86_REG_RIP

        for op in insn.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                out.append(insn.address + insn.size + op.mem.disp)
    except Exception:  # noqa: BLE001 — scratch probe: detail is enough
        pass
    return out


if __name__ == "__main__":
    main()
