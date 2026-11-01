#!/usr/bin/env python3
"""§88 探针(离线,零 shot):星连图容器 0x3260BB0 读者里 disp ∈ [0x580,0x5C0) 的两侧站点。

口径:
① `riprefs.refs_for({0x3260BB0}, ".text", verify=True)` 给出全部读者站点,按 `.pdata` 归桶;
② 每个桶函数按 extent 对齐反汇编,收所有 `disp ∈ [0x580,0x5C0)` 的内存操作(无 index;
   base 为 rsp/rbp 的**栈**访问剔除 —— 同 disp 不同对象,§87 的陷阱在这里同样成立);
③ base 需回溯确认为「装载体指针的那次 rip 装载」:线性回扫(≤64 条)找
   `mov/lea <base>, [rip->0x3260BB0]`,允许 `mov <b>, <r2>` 逐跳跟随;遇对 base 的其它写、
   ret/jmp 停;`call` 只对 caller-saved 是界(沿用 §87 裁定②)。追不确认为 global_ptr 的行
   base_confirmed=0,不进候选口径的判决,只出现在表里作背景。
④ 写点向后 4 条找 inc/add/mov imm 形态 ⇒ 该 offset 标 counter_update。
⑤ near_vector = offset ∈ [0x588,0x5A0)(含已钉的 +0x590 id 向量与 +0x59C 条数区)。

判决词(只看 base_confirmed=1 的行):
  version_signal_found —— 某 offset 同时有写(含 increment/assignment)与读侧比较(cmp/test)
  no_version_signal    —— 所有 offset 只有单侧
  container_unconfirmed—— confirmed 行一条没有 ⇒ 读者口径/偏移已过期(记欠账)
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM, X86_REG_RIP
import disrva, riprefs

BASE = 0x140000000
GLOBAL = 0x3260BB0
LO, HI = 0x580, 0x5C0
VEC_LO, VEC_HI = 0x588, 0x5A0
STOP = ("ret", "jmp")
CALLEE_SAVED = {"rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"}
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True
_EXE_PATH, BLOB, SECS = disrva._image()


def rd(rva, n):
    for nm, va, vs, rsz, rp, ch in SECS:
        if va <= rva < va + vs and rp:
            return BLOB[rp + rva - va: rp + rva - va + n]
    return b""


def decode(fs, fe, over=16):
    ins = [i for i in MD.disasm(rd(fs, fe - fs + over), BASE + fs)]
    return [i for i in ins if i.address - BASE < fe + over]


def rn(ins, rid):
    return ins.reg_name(rid).lower()


def mem_at(ins, disp_lo, disp_hi):
    """该指令所有 disp∈[lo,hi) 且无 index、base 非栈的 mem 操作数。"""
    out = []
    for op in ins.operands:
        if op.type != X86_OP_MEM or op.mem.index:
            continue
        b = rn(ins, op.mem.base) if op.mem.base else ""
        if b in ("rsp", "rbp") or op.mem.base == X86_REG_RIP:
            continue
        if disp_lo <= op.mem.disp < disp_hi:
            out.append((b, op.mem.disp))
    return out


def is_write(ins):
    m = ins.mnemonic
    if m in ("cmp", "test"):
        return False
    if m in ("idiv", "div", "imul", "mul"):
        # 这些指令的 mem 第一操作数是**读**(除数/乘数),写的是 eax/edx,不是内存
        return False
    if m.startswith(("rep",)):
        return True
    return bool(ins.operands) and ins.operands[0].type == X86_OP_MEM


def base_confirmed(ins_list, idx, base):
    """回扫 base 是否来自 [rip->GLOBAL] 装载;返回 (0|1, 证据串)。"""
    reg = base
    hops = []
    for k in range(idx - 1, max(-1, idx - 65), -1):
        i = ins_list[k]
        ops = i.operands
        if not hops and i.mnemonic in STOP:
            return 0, "-"
        if i.mnemonic == "call" and reg in CALLEE_SAVED and hops:
            continue
        if ops and ops[0].type == X86_OP_REG and rn(i, ops[0].reg) == reg:
            if i.mnemonic in ("mov", "lea") and len(ops) > 1 and ops[1].type == X86_OP_MEM \
                    and ops[1].mem.base == X86_REG_RIP \
                    and i.address - BASE + i.size + ops[1].mem.disp == GLOBAL:
                hops.append(f"{reg}<-{i.mnemonic} [rip->0x{GLOBAL:x}]@{i.address - BASE:x}")
                return 1, "|".join(hops)
            if i.mnemonic in ("mov",) and len(ops) > 1 and ops[1].type == X86_OP_REG:
                nxt = rn(i, ops[1].reg)
                hops.append(f"{reg}<-mov {ops[1].reg and rn(i, ops[1].reg)}@{i.address - BASE:x}")
                reg = nxt
                continue
            return 0, "-"  # base 被别的来源写
        if i.mnemonic in ("push", "pop", "call", "ret", "jmp"):
            pass
    return 0, f"{reg}(窗口内无 rip 装载)"


def counter_update(ins_list, idx):
    for k in range(idx + 1, min(len(ins_list), idx + 5)):
        i = ins_list[k]
        if i.mnemonic in ("inc", "dec") or \
           (i.mnemonic == "add" and i.operands and i.operands[-1].type == X86_OP_IMM) or \
           (i.mnemonic == "mov" and i.operands and i.operands[-1].type == X86_OP_IMM):
            return 1
    return 0


def main() -> int:
    ok = True
    hits = riprefs.refs_for({GLOBAL}, ".text", True)[GLOBAL]
    sites = sorted(s for s, _ in hits)
    print(f"## refs_of_0x{GLOBAL:x}_in_.text={len(sites)}")
    buckets = {}
    for s in sites:
        fb = riprefs.func_of(s)
        assert fb is not None, f"站点 {s:x} 不在 .pdata 内"
        buckets.setdefault(fb, []).append(s)
    print(f"## bucket_funcs={len(buckets)}")

    rows = []  # (offset, func_start, site, insn, access, near_vector, confirmed, counter)
    for (fs, fe), _ in sorted(buckets.items()):
        ins_list = decode(fs, fe)
        for k, i in enumerate(ins_list):
            for b, disp in mem_at(i, LO, HI):
                conf, _ev = base_confirmed(ins_list, k, b)
                acc = "write" if is_write(i) else "read"
                cu = counter_update(ins_list, k) if acc == "write" else 0
                rows.append((disp, fs, i.address - BASE,
                             f"{i.mnemonic} {i.op_str}", acc,
                             1 if VEC_LO <= disp < VEC_HI else 0, conf, cu))
    rows.sort(key=lambda r: (r[0], r[1], r[2]))

    print("func_start\tsite_rva\tinsn\toffset\taccess\tnear_vector")
    for disp, fs, site, insn, acc, nv, conf, cu in rows:
        assert LO <= disp < HI, f"offset 越界 {disp:x}"
        assert riprefs.func_of(site) is not None
        print(f"{fs:x}\t{site:x}\t{insn}\t{disp:x}\t{acc}\t{nv}")

    conf_rows = [r for r in rows if r[6] == 1]
    per_off = {}
    for disp, fs, site, insn, acc, nv, conf, cu in conf_rows:
        d = per_off.setdefault(disp, {"writes": 0, "reads": 0, "cmps": 0, "counter": 0})
        if acc == "write":
            d["writes"] += 1
            d["counter"] = max(d["counter"], cu)
        else:
            d["reads"] += 1
            if insn.startswith(("cmp", "test")):
                d["cmps"] += 1
    print("## per_offset(base_confirmed 口径)")
    for disp in sorted(per_off):
        d = per_off[disp]
        print(f"## offset={disp:x} writes={d['writes']} reads={d['reads']} "
              f"cmps={d['cmps']} counter_update={d['counter']}")

    cand = {o for o, d in per_off.items() if d["writes"] >= 1}
    trivial = {o for o, d in per_off.items() if d["writes"] == 0}
    print("## candidate_offsets=" + ",".join(f"{o:x}" for o in sorted(cand)))
    print("## trivial_count_offsets=" + ",".join(f"{o:x}" for o in sorted(trivial)))
    if 0x59C not in per_off:
        print("## 欠账:+0x59C 在 confirmed 口径内零站点(§80.2 已钉字段,本口径没复现)")

    if not conf_rows:
        verdict = "container_unconfirmed"
    elif any(per_off[o]["writes"] >= 1 and per_off[o]["cmps"] >= 1 for o in per_off):
        verdict = "version_signal_found"
    else:
        verdict = "no_version_signal"
    print(f"## rows={len(rows)} confirmed={len(conf_rows)}")
    print(f"## verdict={verdict}")
    print("## 静态推断,未验证;何时被调 = 未观测(离线,零 shot)")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
