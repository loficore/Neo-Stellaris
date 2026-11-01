#!/usr/bin/env python3
"""§87 探针(离线,零 shot):备用靶 0x1A76324 `call 0x3B1330` 下游的 [scope+0x10] 读点。

0x1A76324 本身是循环里每轮的调用点,不是读点;本节问:0x3B1330 本体与它的**一层 E8 目标**里,
谁读 `disp == 0x10`,base 是不是能追到 scope 帧(= 0x3B1330 的入参 rdx,由
`0x1a7631c lea rdx,[rsp+0x20]` 传入)。

与计划 brief 的偏差(已裁定,见 §87 口径):base 回溯窗口从「前 6 条」放宽为**整个 extent 的
线性回扫**,只在 ret/jmp 与「对 caller-saved 的 call」停(`je/jne` 等条件跳转对寄存器值透明,
继续往回;rbx/rbp/rsi/rdi/r12-r15 跨 call 存活,回扫穿过 call 成立);每行给出
`insn_distance`(站点到 base 最后一条写的指令距离)。分类结果只会更强,不会更松:
- base 追到函数入参 rdx ⇒ `rdx(scope帧)`;
- 追到 rcx(self)/别的入参/内存加载 ⇒ `self_or_other(...)`;
- 一层 E8 目标内追到入参的,用调用点前的实参绑定(同样回扫)接回 caller 侧,链写进 base_source;
- 真追不动(窗口内先撞上 call/ret/jmp 界) ⇒ `-`。

判决词:
  scope_id_read_named / no_scope_id_read_depth1 / undetermined(仍有 `-` 行时不许升前两者)
两个同形字段:0x3B1330 里 `lea rdx,[rsp+0x20]`(0x3b1353)是**它自己的栈槽**,不是循环帧 ——
同 disp 不同栈,不许混。
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG
import disrva, pdata

BASE = 0x140000000
LOOP_FUNC = (0x1A76130, 0x1A7643D)
PARSE = (0x3B1330, 0x3B1413)
CALL_SITE = 0x1A76324
LEA_SITE = 0x1A7631C
STOP = ("call", "ret", "jmp")
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


def writes_reg(i, reg):
    if i.mnemonic == "push":  # push 是读，不是写（pop 才是写，但本口径里 pop 落在 STOP 外不成问题）
        return False
    return i.operands and i.operands[0].type == X86_OP_REG and rn(i, i.operands[0].reg) == reg


def trace(ins_list, idx, reg, stop_words=STOP):
    """回扫 reg 的最后一条写;返回 (描述, 距写点的指令条数)。

    call 只对 caller-saved 寄存器是界;x64 ABI 下 rbx/rbp/rsi/rdi/r12-r15 跨 call 存活，
    回扫穿过 call 仍然成立（§87 口径裁定②）。"""
    for k in range(idx - 1, -1, -1):
        i = ins_list[k]
        if writes_reg(i, reg):
            d = f"{reg}<-{i.mnemonic} {i.op_str}@{i.address - BASE:x}"
            return d, idx - k
        if i.mnemonic in stop_words and not (i.mnemonic == "call" and reg in CALLEE_SAVED):
            return "-", idx - k
    return f"{reg}(入参,函数内无写)", 0


def site_rows(fs, fe, rows, tag, argbind=None):
    ins = decode(fs, fe)
    for k, i in enumerate(ins):
        for op in i.operands:
            if op.type == X86_OP_MEM and op.mem.disp == 0x10 and not op.mem.index:
                b = rn(i, op.mem.base) if op.mem.base else "?"
                src, dist = trace(ins, k, b)
                # 追到入参且给了绑定表 ⇒ 接回 caller 侧
                while "(入参" in src and argbind:
                    arg = src.split("(")[0]
                    up = argbind.get(arg)
                    if not up:
                        break
                    src = f"{arg}(入参)<-{up}"
                    break
                if b in ("rsp", "rbp"):
                    cls = "stack"
                elif src.endswith("rdx<-入参)") or "入参 rdx" in src or src == "rdx(入参,函数内无写)":
                    cls = "rdx(scope帧)"
                else:
                    cls = f"self_or_other({src})" if src != "-" else "-"
                rows.append((f"{i.address - BASE:x}", f"{fs:x}",
                             f"{i.mnemonic} {i.op_str}", b, "0x10", cls, src,
                             str(dist), tag))
    return ins


def caller_args(ins_list, idx):
    """call 站点往前 ≤12 条,取 rcx/rdx/r8 最后一次写的目标表达式。"""
    out = {}
    for k in range(idx - 1, max(-1, idx - 13), -1):
        i = ins_list[k]
        for reg in ("rcx", "rdx", "r8"):
            if reg not in out and writes_reg(i, reg):
                out[reg] = f"{i.mnemonic} {i.op_str}@{i.address - BASE:x}"
    return out


def main() -> int:
    ok = True
    for probe_rva, want in ((CALL_SITE, LOOP_FUNC), (0x3B1330, PARSE)):
        fb = pdata.func_of(probe_rva)
        got = (fb[0], fb[1]) if fb else None
        print(f"## func_of({probe_rva:x}) = {got} expect ({want[0]:x},{want[1]:x})")
        if got != want:
            print("FAIL: 边界不符"); ok = False
    loop_ins = decode(LOOP_FUNC[0], LOOP_FUNC[1])
    ci = next((k for k, i in enumerate(loop_ins) if i.address - BASE == CALL_SITE), None)
    call_i = loop_ins[ci] if ci is not None else None
    tgt = int(call_i.op_str[2:], 16) - BASE if call_i and call_i.op_str.startswith("0x14") else -1
    print(f"## {CALL_SITE:x}: {call_i.mnemonic if call_i else '?'} {tgt:x} (expect call 3b1330)")
    if not (call_i and call_i.mnemonic == "call" and tgt == 0x3B1330):
        print("FAIL: 调用点形态不符"); ok = False
    li = next((k for k, i in enumerate(loop_ins) if i.address - BASE == LEA_SITE), None)
    lea = loop_ins[li] if li is not None else None
    print(f"## {LEA_SITE:x}: {lea.mnemonic if lea else '?'} {lea.op_str if lea else '?'}"
          f" (expect lea rdx,[rsp+0x20])")
    if not (lea and lea.mnemonic == "lea" and "rdx" in lea.op_str and "[rsp + 0x20]" in lea.op_str):
        print("FAIL: lea 站点不符"); ok = False
    call_path = (f"{LEA_SITE:x}:lea rdx,[rsp+0x20] -> {CALL_SITE:x}:call 0x3b1330"
                 f"(rcx=self, r8=r15)")

    rows = []
    body = site_rows(PARSE[0], PARSE[1], rows, "parse_body")
    # 一层 E8 目标
    e8_idx = [(k, int(i.op_str[2:], 16) - BASE) for k, i in enumerate(body)
              if i.mnemonic == "call" and i.op_str.startswith("0x14")
              and i.address - BASE < PARSE[1]]
    e8 = sorted({t for _, t in e8_idx})
    print("## one_level_E8_targets=" + ",".join(f"{t:x}" for t in e8))
    for k, t in sorted(set(e8_idx), key=lambda x: x[1]):
        fb = pdata.func_of(t)
        if not (fb and fb[0] == t):
            print(f"## skip {t:x}:不是 .pdata 函数首(一层口径不追半截)")
            continue
        bind = {a: f"caller@{body[k].address - BASE:x}:{v}"
                for a, v in caller_args(body, k).items()}
        print(f"## args->{t:x}: " + "; ".join(f"{a}={v}" for a, v in sorted(bind.items())))
        site_rows(t, fb[1], rows, f"e8_target({t:x})", argbind=bind)

    cols = ["site_rva", "func_start", "insn", "base_register", "disp",
            "base_source", "trace", "insn_distance", "call_path"]
    print("\t".join(cols))
    for r in rows:
        print("\t".join(r[:8] + (call_path if r[8] == "parse_body" else r[8],)))
    for r in rows:
        if not (r[0] and r[5]):
            print(f"FAIL: 行必需列缺 {r}"); ok = False
        if r[4] != "0x10":
            print(f"FAIL: disp 非 0x10: {r}"); ok = False

    named = [r for r in rows if r[5] == "rdx(scope帧)"]
    dash = [r for r in rows if r[5] == "-"]
    if named and not dash:
        verdict = "scope_id_read_named"
    elif dash:
        verdict = "undetermined"
    else:
        verdict = "no_scope_id_read_depth1"
    print(f"## rows={len(rows)} named={len(named)} self_or_other="
          f"{sum(1 for r in rows if r[5].startswith('self_or_other'))} stack="
          f"{sum(1 for r in rows if r[5] == 'stack')} dash={len(dash)}")
    print(f"## verdict={verdict}")
    print("## 何时被调: 未观测(离线,零 shot)")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
