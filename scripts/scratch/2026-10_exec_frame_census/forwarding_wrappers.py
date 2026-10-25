#!/usr/bin/env python3
"""§61.4-1 的续读:普查表里 12 个 `origin=incoming_arg` 站点,**逐函数**核对
「帧是透传还是有独立构造点」。一次性探针,不是维护接口。

每函数回答四件事:
1. 站点 `call` 的目标(是不是 base Execute `0x1d08520`,还是 `call [..]` 间接);
2. 承载寄存器(把帧交给 rdx 的那个)在函数体内的**全部写点**;
3. 函数体内有没有**对帧的写**(`mov [rdx+..]` / `mov [承载+..]`,排除 `[..+8]` 深度字段);
4. rdx 有没有从 `lea rdx,[rsp/rbp+..]` 取得 —— 那就是 §60.7-1 要的**栈上构造点**。

口径:寄存器读写用「操作符字符串 + x86 别名表」判定。**不用 capstone 的
`regs_write`** —— 本环境的 capstone 对 x86 该属性恒空,第一版探针因此把
`frame_writes` 读成 0(假阴性,已在 §62 记为坑)。自校验:第 1 行函数
`0x1bcd120` 的承载写点必须复现 §61.2 的 `mov rbx, rdx @0x1bcd131`。
"""
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(_REPO, "scripts"))

from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from disrva import BASE, rd  # noqa: E402

CENSUS = os.path.join(_REPO, "evidence", "xrefs", "exec_frame_callers_4_4_4.tsv")
BACKSCAN = 12          # 站点向前找 `mov rdx, <reg>` 的指令窗口
DEPTH_OFF = 0x8        # §53:帧 +8 是净零深度计数,不算构造

# 64 位原名 -> 所有更窄的别名(mov ebx,... 同样写 rbx)
ALIAS = {
    "rax": {"rax", "eax", "ax", "al"},
    "rbx": {"rbx", "ebx", "bx", "bl"},
    "rcx": {"rcx", "ecx", "cx", "cl"},
    "rdx": {"rdx", "edx", "dx", "dl"},
    "rsi": {"rsi", "esi", "si", "sil"},
    "rdi": {"rdi", "edi", "di", "dil"},
    "rbp": {"rbp", "ebp", "bp", "bpl"},
    "rsp": {"rsp", "esp", "sp", "spl"},
    **{f"r{r}": {f"r{r}", f"r{r}d", f"r{r}w", f"r{r}b"} for r in range(8, 16)},
}

WRITING = re.compile(r"^(mov|lea|add|sub|and|or|xor|adc|sbb|inc|dec|neg|"
                     r"cmov\w*|movzx|movsx|movbe|pop|xchg|shl|shr|sar|set\w+)$")
MEM_BASE = re.compile(r"^\[(?:(\w+)(?:\s*\+\s*(0x[0-9a-f]+|\w+))?)\]")


def incoming_rows():
    rows, head = [], None
    with open(CENSUS, encoding="utf-8") as f:
        for line in f:
            if line.startswith("# kind"):
                break
            if line.startswith("# "):
                head = [c.strip() for c in line[2:].rstrip("\n").split("\t")]
                continue
            rec = dict(zip(head, line.rstrip("\n").split("\t")))
            if rec.get("rdx_origin") == "incoming_arg":
                rows.append(rec)
    return rows


def decode(start, end):
    code, sec = rd(start, end - start)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = []
    for ins in md.disasm(code, BASE + start):
        if ins.address - BASE >= end:
            break
        insns.append(ins)
    return sec, insns


def dst_reg(ins):
    """目的操作符是寄存器时返回其 64 位原名,否则 None。"""
    if not ins.op_str or not WRITING.match(ins.mnemonic):
        return None
    if ins.mnemonic.startswith("set"):
        name = ins.op_str.split(",")[0].strip()
    else:
        name = ins.op_str.split(",")[0].strip()
    for big, names in ALIAS.items():
        if name in names:
            return big
    return None


MEM_WRITE = ("mov", "add", "sub", "inc", "dec", "and", "or", "xor", "neg",
             "not", "shl", "shr", "sar", "sbb", "adc", "xchg")


def mem_base_of(ins):
    """目的为内存时返回 (基址寄存器, 偏移 int|None)。含 `add [rdx+8],1` 这类
    就地改写 —— 只认 `mov` 会把深度自增读成 0(与 §62 docstring 说的 regs_write
    恒空同一类假阴性)。"""
    if ins.mnemonic not in MEM_WRITE:
        return None
    first = ins.op_str.split(",")[0].strip()
    first = re.sub(r"^(byte|word|dword|qword|XMMWORD|xmmword)\s+ptr\s+", "", first)
    m = MEM_BASE.match(first)
    if not m:
        return None
    off = m.group(2)
    val = None
    if off:
        val = int(off, 16) if off.startswith("0x") else (
            int(off) if off.isdigit() else off)
    return m.group(1), val


def analyze(func_start, func_end, sites):
    sec, insns = decode(func_start, func_end)
    site_set = set(sites)
    out = {"sec": sec, "insns": len(insns), "sites": [], "ctor": [],
           "rdx_writes": [], "carrier_writes": {}, "frame_writes": [],
           "depth_writes": []}
    carriers = set()
    for i, ins in enumerate(insns):
        rva = ins.address - BASE
        if rva not in site_set or ins.mnemonic != "call":
            continue
        target = (int(ins.op_str, 16) - BASE
                  if ins.op_str.startswith("0x") else ins.op_str)
        rec = {"site": rva, "target": target, "carrier": None}
        for prev in reversed(insns[max(0, i - BACKSCAN):i]):
            if prev.mnemonic == "mov" and prev.op_str.startswith("rdx,"):
                src = prev.op_str.split(",", 1)[1].strip()
                for big, names in ALIAS.items():
                    if src in names and big != "rdx":
                        carriers.add(big)
                        rec["carrier"] = big
                break
            if prev.mnemonic == "lea" and prev.op_str.startswith("rdx,[r"):
                out["ctor"].append((rva, prev.op_str))
                break
        out["sites"].append(rec)
    for ins in insns:
        rva = ins.address - BASE
        d = dst_reg(ins)
        if d == "rdx":
            out["rdx_writes"].append((rva, ins.mnemonic, ins.op_str))
        elif d in carriers:
            out["carrier_writes"].setdefault(d, []).append(
                (rva, ins.mnemonic, ins.op_str))
        mb = mem_base_of(ins)
        if mb:
            reg, off = mb
            big = None
            for name, names in ALIAS.items():
                if reg in names:
                    big = name
                    break
            if big == "rdx" or big in carriers:
                (out["depth_writes"] if off == DEPTH_OFF
                 else out["frame_writes"]).append((rva, big, off, ins.op_str))
    return out


def main():
    rows = incoming_rows()
    by_func = {}
    for r in rows:
        by_func.setdefault((int(r["func_start"], 16), int(r["func_end"], 16)),
                           []).append(int(r["site"], 16))
    print(f"incoming_arg rows = {len(rows)} / functions = {len(by_func)}")
    totals = {"depth": 0, "assign": 0}
    for (fs, fe), sites in sorted(by_func.items()):
        res = analyze(fs, fe, sites)
        print(f"\n== func 0x{fs:x}..0x{fe:x} ({res['sec']}, "
              f"{res['insns']} insns) sites={[hex(s) for s in sites]}")
        for s in res["sites"]:
            t = s["target"]
            print(f"   site 0x{s['site']:x} -> "
                  f"{('0x%x' % t) if isinstance(t, int) else t}"
                  f"  carrier={s['carrier']}")
        for c, w in sorted(res["carrier_writes"].items()):
            print(f"   carrier[{c}] writes={len(w)}: " +
                  "; ".join(f"0x{a:x} {m} {o}" for a, m, o in w[:6]))
        print(f"   rdx_writes={len(res['rdx_writes'])}: " +
              "; ".join(f"0x{a:x} {m} {o}" for a, m, o in res["rdx_writes"][:6]))
        print(f"   frame_writes={len(res['frame_writes'])}: " +
              "; ".join(f"0x{a:x} [{r}+{o}]"
                        for a, r, o, _ in res["frame_writes"][:6]))
        dcount = {}
        for _, reg, _, body in res["depth_writes"]:
            parts = [x.strip() for x in body.split(",")]
            key = (parts[0], parts[1] if len(parts) > 1 else "-")
            dcount[key] = dcount.get(key, 0) + 1
        print(f"   depth[<frame>+8] n={len(res['depth_writes'])}: " +
              "; ".join(f"{dst} <- {src} x{n}" for (dst, src), n
                        in sorted(dcount.items(), key=lambda kv: -kv[1])))
        print(f"   ctor_lea_rdx_from_stack={[(hex(a), o) for a, o in res['ctor']]}")
        carrs = set(res["carrier_writes"])
        on_frame = [w for w in res["depth_writes"] if w[1] in carrs]
        assign = [w for w in on_frame if "," in w[3]]
        totals["depth"] += len(on_frame)
        totals["assign"] += len(assign)
        print(f"   [<frame>+8] carrier 基={len(on_frame)} "
              f"inc/dec={len(on_frame) - len(assign)} "
              f"赋值={len(assign)}: " +
              "; ".join(f"0x{a:x} {o}" for a, _, _, o in assign))
        other = [w for w in res["depth_writes"] if w[1] not in carrs]
        print(f"   [<frame>+8] 非承载基(rdx 复用可疑)={len(other)}: " +
              "; ".join(f"0x{a:x} {o}" for a, _, _, o in other[:3]))
    print(f"\nSUM carrier 基 [<frame>+8] 写 = {totals['depth']} "
          f"(inc/dec {totals['depth'] - totals['assign']}, "
          f"赋值 {totals['assign']})")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()


def site_gap_check():
    """每个站点:承载寄存器在「入参留底 → 站点」之间有没有被第三次写过。
    有写 = 该站点交回的 rdx 未必是原帧。"""
    rows = incoming_rows()
    by_func = {}
    for r in rows:
        by_func.setdefault((int(r["func_start"], 16), int(r["func_end"], 16)),
                           []).append((int(r["site"], 16),
                                       r["evidence"]))
    bad = 0
    for (fs, fe), pairs in sorted(by_func.items()):
        _, insns = decode(fs, fe)
        for site, ev in pairs:
            m = re.search(r"rbx <- rdx @0x([0-9a-f]+)|r14 <- rdx @0x([0-9a-f]+)", ev)
            save = int(m.group(1) or m.group(2), 16) if m else None
            carr = "r14" if "r14" in ev.split(";")[0] else "rbx"
            inter = [(i.address - BASE, i.mnemonic, i.op_str) for i in insns
                     if save is not None and save < (i.address - BASE) < site
                     and dst_reg(i) == carr]
            if inter:
                bad += 1
                print(f"  GAP site 0x{site:x} carrier {carr} after save "
                      f"0x{save:x}: " + "; ".join(
                          f"0x{a:x} {mm} {oo}" for a, mm, oo in inter[:3]))
        print(f"  func 0x{fs:x}: {len(pairs)} sites, intervening "
              f"carrier writes counted above")
    print(f"TOTAL sites with intervening carrier write = {bad}")
