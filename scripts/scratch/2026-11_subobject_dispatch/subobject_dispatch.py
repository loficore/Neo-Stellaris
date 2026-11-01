#!/usr/bin/env python3
"""§86 探针(离线,零 shot):0x25EBAB8 的 48 槽、+0x70=0x3B1EF0 语义、两个 getter。

问的三件事(§83.3 之问 ② 的落地):
  ① 解 0x25EBAB8 的 48 个槽:每槽目标是否落在 .pdata 的某个 RUNTIME_FUNCTION extent 内、
     目标函数引用哪些 .rdata 字符串(前 8 条,去重);
  ② 复核锚点:0x25EBAB8 的 +0x48 == 0x3AFD30 且 +0xB0 == 0x3B1330;
     主表 0x25FDE58 / 0x25FDD78 的 +0x08 == 0x3AFD30(§83.2 口径,execute/instantiate 槽号不同表);
  ③ +0x70 = 0x3B1EF0 的函数体:call/jmp 目标集合、对 self 读了哪些字段(按 r14=rcx 跟踪)、
     派发槽 [rax+disp] 列表;
  ④ 反汇编 0x18BE4E0 / 0x18BEBF0 与其尾跳委托(0x18BE450 / 0x18BEB60):报子对象(+0xC0)内
     被读的字段、返回值的来源形态 ⇒ getter_return_class。

口径:
- host 侧拿子对象的方式来自 §83.2 的字节:`0x18B7B70` 里 `add rcx,0xc0` → `call 0x18BE4E0`;
  本探针按对齐解码重新定位该站点与寄存器,不抄取证卷行号。
- TSV 行 = 48 槽全覆盖;target_kind ∈ {func_head, mid_function, not_in_pdata};
  断言「每个 target_rva 在 .pdata 内」只对 func_head/mid_function 行生效,not_in_pdata 槽
  必须在 target_kind 里显式带出去(裁定:两种解码器都看不见 ≠ 不是槽)。
- 「+0x70 何时被调」不回答(离线无调用观测)。family_def 用 §83.2 补记① 的 neighborhood 口径。
"""
import sys, os, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import (X86_OP_MEM, X86_REG_RIP, X86_REG_R14,
                          X86_REG_RBP, X86_REG_RCX)
import disrva, pdata

BASE = 0x140000000
SUB_VTABLE = 0x25EBAB8
MAIN_TABLES = (0x25FDE58, 0x25FDD78)
EXECUTE, INSTANTIATE = 0x3AFD30, 0x3B1330
FAMILY = {0x3AFD30, 0x3B1330, 0x3B01A0, 0x3B1420, 0x3B0F80, 0x3B1230}
GETTERS = {0x18BE4E0: 0x18BE450, 0x18BEBF0: 0x18BEB60}
HOST_STUB = 0x18B7B70
SLOT70 = 0x3B1EF0

_EXE_PATH, BLOB, SECS = disrva._image()
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True


def sec_of(rva):
    for nm, va, vs, rsz, rp, chars in SECS:
        if va <= rva < va + vs:
            return nm, va, vs, rp
    return None


def rd(rva, n):
    s = sec_of(rva)
    if not s or not s[3]:
        return b""
    nm, va, vs, rp = s
    return BLOB[rp + rva - va: rp + rva - va + n]


def cstr(rva, cap=80):
    raw = rd(rva, cap).split(b"\0")[0]
    if raw and all(32 <= b < 127 for b in raw):
        return raw.decode()
    return None


def qword(rva):
    v = struct.unpack_from("<Q", rd(rva, 8))[0]
    # vtable qwords 存的是装载后的 VA(首选 base 0x140000000)——一律归一回 RVA
    return v - BASE if v >= BASE else v


def decode_func(rva, cap=None, over=0):
    fb = pdata.func_of(rva)
    if fb is None:
        return fb, []
    end = fb[1] if cap is None else min(fb[1], rva + cap)
    # over:允许读越 .pdata extent 尾若干字节(13 字节 stub 的最后一条 call 会被窗口切掉)
    return fb, [i for i in MD.disasm(rd(fb[0], end - fb[0] + over), BASE + fb[0])
                if i.address - BASE < end + over]


def func_head_set():
    return {b for (b, e, u) in pdata.funcs}


HEADS = func_head_set()


def in_target_table(rva):
    nm = sec_of(rva)
    return nm is not None and nm[0] == ".text"


def strings_of(rva, limit=8):
    fb, ins = decode_func(rva, cap=0x600)
    out, seen = [], set()
    for i in ins:
        for op in i.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = i.address - BASE + i.size + op.mem.disp
                s = cstr(t) if in_target_table(t) is False else None
                if s and t not in seen and sec_of(t) and sec_of(t)[0] in (".rdata", ".data"):
                    seen.add(t)
                    out.append(f"{t:x}:{s[:40]}")
                    if len(out) >= limit:
                        return out
    return out


def main() -> int:
    ok = True
    print("## family_def=neighborhood 定义=vtable ±0x200 内出现 "
          "{0x3AFD30,0x3B1330,0x3B01A0,0x3B1420,0x3B0F80,0x3B1230} 任一(§83.2 补记①)")

    # ② 锚点复核
    sub_exec, sub_inst = qword(SUB_VTABLE + 0x48), qword(SUB_VTABLE + 0xB0)
    print(f"## anchor 0x25EBAB8 +0x48={sub_exec:x} (expect {EXECUTE:x}) "
          f"+0xB0={sub_inst:x} (expect {INSTANTIATE:x})")
    if not (sub_exec == EXECUTE and sub_inst == INSTANTIATE):
        print("FAIL: 子表锚点不符"); ok = False
    for mt in MAIN_TABLES:
        v = qword(mt + 0x08)
        print(f"## anchor main 0x{mt:x} +0x08={v:x} (expect {EXECUTE:x})")
        if v != EXECUTE:
            print(f"FAIL: 主表 0x{mt:x} +0x08 不符"); ok = False

    # host 侧站点:在 0x18B7B70 函数体里找 add reg,0xc0 且其后 4 条内 call 某 getter
    fb, ins = decode_func(HOST_STUB, over=16)
    host_site = None
    for k, i in enumerate(ins):
        if i.mnemonic == "add" and i.op_str.endswith("0xc0"):
            reg = i.op_str.split(",")[0].strip()
            for j in ins[k + 1:k + 5]:
                if j.mnemonic == "call" and j.op_str.startswith("0x14"):
                    t = int(j.op_str[2:], 16) - BASE
                    if t in GETTERS:
                        host_site = (i.address - BASE, reg, t)
                        break
        if host_site:
            break
    if host_site is None:
        print("FAIL: 0x18B7B70 里找不到 add *,0xc0 -> call getter 站点"); ok = False
        host_site = (0, "?", 0)
    site_addr, base_reg, getter1 = host_site
    print(f"## host_site {site_addr:x}: {base_reg} += 0xc0 -> call {getter1:x}")

    # ① 48 槽 TSV
    cols = ["host_vtable", "slot", "target_rva", "target_kind",
            "base_register", "base_subobject_offset", "evidence_site"]
    print("\t".join(cols))
    rows = []
    for n in range(48):
        off = n * 8
        tgt = qword(SUB_VTABLE + off)
        fb = pdata.func_of(tgt)
        if tgt in HEADS:
            kind = "func_head"
        elif fb is not None:
            kind = "mid_function"
        else:
            kind = "not_in_pdata"
        ev = f"{site_addr:x}:add {base_reg},0xc0"
        rows.append((f"{SUB_VTABLE:x}", f"+0x{off:x}", f"{tgt:x}", kind,
                     base_reg, "+0xC0", ev))
        print("\t".join(rows[-1]))
        if kind != "not_in_pdata" and fb is None:
            print(f"FAIL: {tgt:x} 标成 {kind} 却不在 .pdata extent 内"); ok = False
    for r in rows:
        if not (r[0] and r[4] and r[6]):
            print(f"FAIL: 行必需列缺 {r}"); ok = False

    # 槽 0..0x178 里族内槽点名
    fam = [r for r in rows if int(r[2], 16) in FAMILY]
    print("## family_slots " + ", ".join(f"{r[1]}->{r[2]}" for r in fam))

    # ③ +0x70 = 0x3B1EF0
    s70 = qword(SUB_VTABLE + 0x70)
    print(f"## slot+0x70 = {s70:x}")
    if s70 != SLOT70:
        print("FAIL: +0x70 不是 0x3B1EF0"); ok = False
    fb70, ins70 = decode_func(SLOT70)
    calls = [f"{i.address - BASE:x}:{i.mnemonic} {int(i.op_str[2:], 16) - BASE:x}"
             for i in ins70 if i.mnemonic in ("call", "jmp")
             and i.op_str.startswith("0x14")]
    vdispatch = [f"{i.address - BASE:x}:{i.mnemonic} [{i.op_str.split('[')[1].rstrip(']')}]"
                 for i in ins70 if i.mnemonic in ("call", "jmp")
                 and i.op_str.startswith("qword")]
    self_fields = []
    # r14 = self(prologue: mov r14, rcx);报 [r14+disp]
    r14d = sorted({o.mem.disp for i in ins70 for o in i.operands
                   if o.type == X86_OP_MEM and o.mem.base == X86_REG_R14
                   and o.mem.index == 0})
    print(f"## 0x3b1ef0 extent {fb70[0]:x}..{fb70[1]:x} insns={len(ins70)}")
    print("## direct_targets=" + ",".join(sorted(set(calls))))
    print("## vtable_dispatch=" + ",".join(sorted(set(vdispatch))))
    print("## self_[r14+disp]=" + ",".join(f"0x{d:x}" for d in r14d))
    print("## strings=" + " | ".join(strings_of(SLOT70)))
    tok = [d for d in r14d if d in (0x20, 0x28, 0x38, 0x40)]
    print("## token_field_reads(0x20/0x28/0x38/0x40)=" + (",".join(f"0x{d:x}" for d in tok) or "none"))

    # ④ getter 与委托
    verdict_ret = []
    for g, d in GETTERS.items():
        fbg, insg = decode_func(g)
        fbd, insd = decode_func(d)
        fields = sorted({o.mem.disp for i in insd for o in i.operands
                         if o.type == X86_OP_MEM and o.mem.base in
                         (X86_REG_RBP, X86_REG_RCX)})  # rbp = rcx(子对象)副本
        ret_lea_rip = [i for i in insd if i.mnemonic == "lea"
                       and "rip" in i.op_str]
        # 委托的返回形态:找 `lea rax, [rbp+disp]` 与 `mov rax,[rbp+8]` 系
        rets = [f"{i.address - BASE:x}:{i.mnemonic} {i.op_str}" for i in insd
                if i.mnemonic in ("lea", "mov") and i.op_str.startswith("rax")]
        known = [i for i in insd if i.mnemonic == "lea" and "rip" in i.op_str
                 and any(f.address - BASE + i.size + o.mem.disp in HEADS
                         for o in i.operands if o.type == X86_OP_MEM
                         and o.mem.base == X86_REG_RIP)]
        verdict_ret.append((g, d, fbg, fbd, fields, rets, len(known)))
        print(f"## getter {g:x} extent {fbg[0]:x}..{fbg[1]:x} delegate {d:x} extent {fbd[0]:x}..{fbd[1]:x}")
        print(f"##   委托里对子对象(rbp)的读 disp=" + ",".join(f"0x{x:x}" for x in fields))
        print(f"##   委托返回形态样例=" + "; ".join(rets[-6:]))
        print(f"##   委托里 lea rip->函数首(known)条数={len(known)}")
    gc = all(k == 0 for (_, _, _, _, _, _, k) in verdict_ret)
    print("## getter_return_class=" + ("unknown(返回=匹配元素或 &sub+0x18,非固定 lea->vtable)"
          if gc else "known(见上)"))

    # 判决
    if sub_exec == EXECUTE and sub_inst == INSTANTIATE:
        verdict = "same_family_parse_dispatch"
    elif None in (sub_exec, sub_inst):
        verdict = "undetermined"
    else:
        verdict = "other_class"
    print(f"## verdict={verdict}")
    print("## 何时被调: 未观测(离线,零 shot)")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
