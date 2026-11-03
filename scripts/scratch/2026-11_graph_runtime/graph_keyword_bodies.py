#!/usr/bin/env python3
"""graph_keyword_bodies.py — 五个图相关 keyword 的「执行体/求值槽」锚点表(Task 1,零 shot)。

一次性离线探针:读本地 `stellaris.exe` 拷贝(`disrva._image()`),对每组
`(keyword, class_info)` 打印一行 —— class_info 的 `+0x00`(deleter)与 `+0x08`(factory /
create)、factory 反汇编到第一个 `ret` 得到的 vtable、以及 vtable 的四个槽
`+0x20`/`+0x28`/`+0x48`/`+0x80`(都是 module-base-relative RVA)。

用法:
    python3 scripts/scratch/2026-11_graph_runtime/graph_keyword_bodies.py
    python3 scripts/scratch/2026-11_graph_runtime/graph_keyword_bodies.py \
        --emit-c evidence/disasm/graph_keywords_4_4_4.c

`--emit-c` 落的反汇编原件就是 `evidence/disasm/graph_keywords_4_4_4.c` 的生成命令。
**只有与计划期 Expected 表逐项核对通过时才落盘**:任一不等 → `exit 1`、不写文件,避免从一次
失败的探针里产出一份好看的证据表。

vtable 判定口径(为什么不是简报里那句字面启发式):
    简报写的是「`lea rax,[rip+X]` 后紧跟 `mov [rbx],rax`」。字面照搬会**错两处**,
    这两处都记录在 Task 1 报告里:
      1. `has_hyperlane_to` 的 factory 先 `mov [rbx], base_vtable`(0x26a2cc0)、
         再 `mov [rbx], derived_vtable`(0x269fde8);有效 vtable 是**最后一次**写入,
         字面启发式会停在第一次。
      2. `num_neighbor_systems` 把新对象停在 **rdi**(`call new; mov rdi, rax`),
         不是 rbx,字面启发式一条都匹配不到。
    所以这里改成:先找 `call 0x2185218`(`operator new`)后面 `mov <reg>, rax` 记下**对象
    寄存器**,再在 factory 里找 `qword ptr [<对象寄存器>]`(偏移 0)**最后**一次被
    `lea rax,[rip+X]` 写入的那一对 —— 最后一次写才是活着的 vtable。

exe 路径走 `disrva.resolve_exe()` 的候选链(`NS_STELLARIS_EXE` 优先),不内联受保护的路径。
不碰游戏、不联网、不改 exe。
"""
from __future__ import annotations

import pathlib
import re
import struct
import sys

# scratch/<dir>/file.py -> parents[2] 是 scripts/,disrva 在那里
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import disrva  # noqa: E402

BASE = disrva.BASE
OPERATOR_NEW_RVA = 0x2185218
SLOT_OFFSETS = (0x20, 0x28, 0x48, 0x80)
DISASM_WINDOW = 0x400  # 每条 factory 取这么多字节,遇到第一个 ret 停

CASES = [
    ("add_hyperlane",        0x260D4E0),
    ("remove_hyperlane",     0x260D4D0),
    ("has_hyperlane_to",     0x269DB28),
    ("num_neighbor_systems", 0x269C3C8),
    ("spawn_system",         0x26097F8),
]

# 计划期侦察核实的值(简报 Step 2 的 Expected 表)。只用来**核对**探针的推导出值,
# 绝不参与推导本身 —— 表里所有数都是启发式从字节里读出来的。
EXPECTED = {
    "add_hyperlane":        {"factory": 0x189D510, "vtable": 0x25F7448,
                             "slots": {0x48: 0x1874540}},
    "remove_hyperlane":     {"factory": 0x189D580, "vtable": 0x25F7368,
                             "slots": {0x48: 0x1874A00}},
    "has_hyperlane_to":     {"factory": 0x1B2A510, "vtable": 0x269FDE8,
                             "slots": {0x20: 0x1AFDE20, 0x28: 0x1A91A80}},
    "num_neighbor_systems": {"factory": 0x1B33930, "vtable": 0x266C108,
                             "slots": {0x28: 0x1A92450}},
    "spawn_system":         {"factory": 0x18A52B0, "vtable": 0x25ECC10,
                             "slots": {0x48: 0x18F6B90}},
}

_RIP_RE = re.compile(r"\[rip \+ (0x[0-9a-f]+)\]")
# 只认「qword ptr [reg]」——偏移 0,不是 [reg + 8] 那种次 vtable
_QWORD_REG0_RE = re.compile(r"^qword ptr \[([a-z0-9]+)\]$")

# §77 那张「352 张表共用的触发求值槽」。只是给派生出的槽值加一条**值条件**注记:
# 只有当某 keyword 的 +0x28 读数等于它时才附注,不参与任何取值。
SHARED_EVAL_SLOT_RVA = 0x1A91A80


def _md():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def _qword(rva: int) -> int:
    raw, _sec = disrva.rd(rva, 8)
    if len(raw) != 8:
        raise RuntimeError(f"读不到 8 字节 @ 0x{rva:x}")
    return struct.unpack_from("<Q", raw, 0)[0] - BASE


def _section(rva: int) -> str:
    return disrva.rd(rva, 1)[1]


def _disasm_to_ret(factory: int):
    """从 factory 线性反汇编到第一个 ret(含),返回 (insn 列表, 每条的 rip/call 注记)."""
    md = _md()
    code, _sec = disrva.rd(factory, DISASM_WINDOW)
    out = []
    for ins in md.disasm(code, BASE + factory):
        note = ""
        m = _RIP_RE.search(ins.op_str)
        if m:
            note = f"  ; -> 0x{ins.address + ins.size + int(m.group(1), 16) - BASE:x}"
        elif ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            note = f"  ; -> 0x{int(ins.op_str, 16) - BASE:x}"
        out.append((ins, note))
        if ins.mnemonic == "ret":
            break
    return out


def _object_registers(insns) -> list[str]:
    """`call operator_new; mov <reg>, rax` 里的对象寄存器(按出现顺序)。"""
    regs = []
    new_target = f"0x{BASE + OPERATOR_NEW_RVA:x}"
    for i, (ins, _n) in enumerate(insns):
        if ins.mnemonic == "call" and ins.op_str == new_target and i + 1 < len(insns):
            nxt = insns[i + 1][0]
            if nxt.mnemonic == "mov" and nxt.op_str.endswith(", rax"):
                reg = nxt.op_str.split(",")[0].strip()
                if reg not in regs:
                    regs.append(reg)
    return regs


def _find_vtable(insns, obj_regs) -> tuple[int | None, list[tuple[int, int]]]:
    """对象寄存器偏移 0 上**最后**一次 `lea rax,[rip+X]; mov [reg],rax` 的 X。"""
    pairs = []
    for i, (ins, _n) in enumerate(insns):
        if ins.mnemonic != "lea" or not ins.op_str.startswith("rax, [rip"):
            continue
        m = _RIP_RE.search(ins.op_str)
        if not m or i + 1 >= len(insns):
            continue
        nxt = insns[i + 1][0]
        if nxt.mnemonic != "mov" or not nxt.op_str.endswith(", rax"):
            continue
        dest = nxt.op_str.split(",")[0].strip()
        d = _QWORD_REG0_RE.match(dest)
        if not d:
            continue
        if obj_regs and d.group(1) not in obj_regs:
            continue
        target = ins.address + ins.size + int(m.group(1), 16) - BASE
        pairs.append((target, ins.address - BASE))
    if not pairs:
        return None, pairs
    return pairs[-1][0], pairs


def _direct_target(rva: int) -> int | None:
    """若该 RVA 的首条指令是 `jmp/call <imm>`,返回那个目标(用于标出 thunk)。"""
    md = _md()
    code, _sec = disrva.rd(rva, 16)
    for ins in md.disasm(code, BASE + rva):
        if ins.mnemonic in ("jmp", "call") and ins.op_str.startswith("0x"):
            return int(ins.op_str, 16) - BASE
        return None
    return None


def analyse() -> list[dict]:
    rows = []
    for keyword, ci in CASES:
        deleter = _qword(ci)
        factory = _qword(ci + 8)
        insns = _disasm_to_ret(factory)
        obj_regs = _object_registers(insns)
        vtable, pairs = _find_vtable(insns, obj_regs)
        slots = {}
        if vtable is not None:
            for off in SLOT_OFFSETS:
                target = _qword(vtable + off)
                slots[off] = {"rva": target, "sec": _section(target),
                              "thunk": _direct_target(target)}
        rows.append({
            "keyword": keyword, "class_info": ci, "ci_sec": _section(ci),
            "deleter": deleter, "factory": factory,
            "factory_sec": _section(factory), "obj_regs": obj_regs,
            "vtable": vtable, "vtable_sec": _section(vtable) if vtable else "?",
            "vtable_pairs": pairs, "insns": insns, "slots": slots,
        })
    return rows


def print_table(rows) -> None:
    hdr = (f"{'keyword':<22} {'class_info':<10} {'factory':<10} {'vtable':<10} "
           f"{'+20':<10} {'+28':<10} {'+48':<10} {'+80':<10}")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        cells = []
        for off in SLOT_OFFSETS:
            s = r["slots"].get(off)
            cells.append(f"0x{s['rva']:x}" if s else "-")
        print(f"{r['keyword']:<22} 0x{r['class_info']:x}  0x{r['factory']:x}   "
              f"{('0x%x' % r['vtable']) if r['vtable'] is not None else '-':<10} "
              + " ".join(f"{c:<10}" for c in cells))
    print()
    for r in rows:
        for off in SLOT_OFFSETS:
            s = r["slots"].get(off)
            if s and s["thunk"] is not None:
                print(f"  note: {r['keyword']} +0x{off:x} = 0x{s['rva']:x} "
                      f"({s['sec']}) 是 thunk -> 0x{s['thunk']:x}")


def print_check(rows) -> bool:
    print("[check] 推导值 vs 计划期 Expected 表")
    ok = True
    for r in rows:
        exp = EXPECTED.get(r["keyword"], {})
        if exp.get("factory") is not None and exp["factory"] != r["factory"]:
            print(f"  MISMATCH {r['keyword']}: factory 0x{r['factory']:x} != "
                  f"expected 0x{exp['factory']:x}")
            ok = False
        if exp.get("vtable") is not None:
            if r["vtable"] != exp["vtable"]:
                print(f"  MISMATCH {r['keyword']}: vtable "
                      f"{('0x%x' % r['vtable']) if r['vtable'] is not None else None} != "
                      f"expected 0x{exp['vtable']:x}")
                ok = False
        for off, want in exp.get("slots", {}).items():
            got = r["slots"].get(off, {}).get("rva")
            if got != want:
                print(f"  MISMATCH {r['keyword']}: +0x{off:x} "
                      f"{('0x%x' % got) if got is not None else None} != 0x{want:x}")
                ok = False
    print("  " + ("全部逐项相等 OK" if ok else "存在不一致 —— 见上"))
    return ok


def render_c(rows) -> str:
    exe = disrva.resolve_exe()
    size = pathlib.Path(exe).stat().st_size
    lines = [
        "; graph_keywords_4_4_4.c — 图相关 keyword 的「执行体/求值槽」锚点表(Task 1,零 shot 静态 RE)",
        ";",
        "; exe        : stellaris.exe 4.4.4 (46,253,688 bytes; sha256",
        ";              9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56)",
        "; image base : 0x140000000 (ASLR on) —— 下表中每个数都是 module-base-relative RVA",
        "; exe path   : 走 disrva.resolve_exe() 候选链(NS_STELLARIS_EXE 优先)",
        ";",
        "; 生成命令(重跑同一条即得本文件):",
        ";   python3 scripts/scratch/2026-11_graph_runtime/graph_keyword_bodies.py \\",
        ";       --emit-c evidence/disasm/graph_keywords_4_4_4.c",
        ";",
        "; 校验(简报 Step 4 的原命令;这一行里的 0x1A92450 是命令的模式串本身,",
        ";       数据行按本仓库约定一律写小写 0x1a92450):",
        ";   grep -E \"add_hyperlane|0x1874540|0x1A92450\" evidence/disasm/graph_keywords_4_4_4.c",
        ";",
        "; 口径:class_info 是 .rdata 里 16 B 的记录 {+0x00 deleter, +0x08 factory/create}。",
        "; factory 反汇编到第一个 ret;vtable = factory 对**对象寄存器**(call operator_new",
        "; 0x2185218 后的 `mov <reg>, rax`)偏移 0 处**最后**一次 `lea rax,[rip+X]; mov [reg],rax`",
        "; 写入的 X(最后一次写才是活着的 vtable)。槽值直接读 vtable+off 的 qword。",
        "; 每条 factory 的字节窗口 0x400,遇到第一个 ret 停。",
        ";",
        f"; exe 实际读取: {exe}  ({size} bytes)",
        ";",
        "; ==================== 锚点表 ====================",
        "; keyword                class_info  factory     vtable      +0x20      +0x28      +0x48      +0x80",
    ]
    for r in rows:
        cells = []
        for off in SLOT_OFFSETS:
            s = r["slots"].get(off)
            cells.append(f"0x{s['rva']:x}" if s else "-")
        vt = f"0x{r['vtable']:x}" if r["vtable"] is not None else "-"
        lines.append(f"; {r['keyword']:<22} 0x{r['class_info']:x}  0x{r['factory']:x}   "
                     f"{vt:<10} " + " ".join(f"{c:<10}" for c in cells))
    lines.append(";")
    lines.append("; 执行/求值槽(简报 Expected 表点名的那些;**值全部由上面的读数格式化**,"
                 "不是手写常量):")
    for r in rows:
        parts = []
        for off in sorted(EXPECTED[r["keyword"]]["slots"]):
            s = r["slots"].get(off)
            if s is None:
                parts.append(f"+0x{off:02x} = -")
                continue
            txt = f"+0x{off:02x} = 0x{s['rva']:x}"
            if s["thunk"] is not None:
                txt += f" (thunk -> 0x{s['thunk']:x})"
            if s["rva"] == SHARED_EVAL_SLOT_RVA:
                txt += " (352 张表共用的求值槽)"
            parts.append(txt)
        lines.append(f";   {r['keyword']:<21}" + ", ".join(parts))
    lines.append(";")
    lines.append("; ==================== 逐 keyword 原件 ====================")
    for r in rows:
        lines.append(";")
        lines.append("; " + "-" * 70)
        lines.append(f"; {r['keyword']}  (class_info 0x{r['class_info']:x} @ {r['ci_sec']})")
        lines.append(f";   +0x00 deleter = 0x{r['deleter']:x} @ {_section(r['deleter'])}")
        lines.append(f";   +0x08 factory = 0x{r['factory']:x} @ {r['factory_sec']}")
        lines.append(f";   vtable        = "
                     f"{('0x%x' % r['vtable']) if r['vtable'] is not None else '-'} @ {r['vtable_sec']}"
                     f"  (对象寄存器 {', '.join(r['obj_regs']) or '-'})")
        if r["vtable"] is not None:
            for off in SLOT_OFFSETS:
                s = r["slots"][off]
                thunk = f"  (thunk -> 0x{s['thunk']:x})" if s["thunk"] is not None else ""
                lines.append(f";     vtable+0x{off:02x} = 0x{s['rva']:x} @ {s['sec']}{thunk}")
            extra = [p for p in r["vtable_pairs"][:-1]]
            for target, site in extra:
                lines.append(f";     (被覆盖的 vtable 候选:较前写于 0x{site:x} -> 0x{target:x})")
        lines.append(f"; factory 0x{r['factory']:x} 反汇编到第一个 ret:")
        for ins, note in r["insns"]:
            lines.append(f"  {ins.address - BASE:08x}  {ins.mnemonic:<7} {ins.op_str}{note}")
    lines.append(";")
    lines.append("; ==================== 校验 ====================")
    lines.append("; 本文件由 --emit-c **只在校验通过时**写出:探针先与计划期 Expected 表逐项核对,"
                 "任一不等就")
    lines.append("; 拒绝落盘(exit 1、不写文件)。所以本文件的内容必然与探针这一次的读数一致,"
                 "不可能从一次")
    lines.append("; 失败的探针里产出一份好看的证据表。")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    emit_c = None
    if "--emit-c" in argv:
        i = argv.index("--emit-c")
        if i + 1 >= len(argv):
            print("用法: graph_keyword_bodies.py [--emit-c <path>]", file=sys.stderr)
            return 2
        emit_c = argv[i + 1]

    if disrva.resolve_exe() is None:
        print("[graph_keyword_bodies] 找不到 stellaris.exe 拷贝(设 NS_STELLARIS_EXE)",
              file=sys.stderr)
        return 2

    print(f"exe = {disrva.resolve_exe()}")
    rows = analyse()
    print_table(rows)
    ok = print_check(rows)

    if emit_c is not None:
        if not ok:
            # 交叉校验没过 —— 绝不落盘:否则一份「好看」的证据文件会来自一次失败的探针。
            print("[emit-c] 交叉校验失败 —— 拒绝落盘(不写文件)", file=sys.stderr)
            return 1
        out = pathlib.Path(emit_c)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_c(rows), encoding="utf-8")
        print(f"[emit-c] 写入 {out} ({out.stat().st_size} bytes)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
