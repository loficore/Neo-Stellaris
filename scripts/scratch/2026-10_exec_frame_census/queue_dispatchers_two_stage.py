#!/usr/bin/env python3
"""queue_dispatchers_two_stage —— §63 口径边界外的两段形态派发方(零 shot,离线)。

问题:§63 判的是 `call [reg+0x28]` 直接形态(= `dispatchers_partial`,限于该口径);
`mov reg,[obj+0x28]; call reg` 两段形态不在其口径内。本节把那条边界补上。

口径(与 §63/§62.4 同一族解码纪律,候选=字节形态,复核=从 `.pdata` 函数首对齐解码):
  A' 校准   字节候选 `[\x48-\x4f]\x8b[\x48-\x7f]\x28`(mov r64,[r64+0x28],无 SIB)+ 函数首对齐复核。
            硬门 = 候选恰好 8330,且校准对 load 0x24d7e4 / call 0x24d800(函数 0x24d4d0,
            load 之后第 7 条指令;2026-10-26 逐条反汇编在案)必须找到 —— 不过即停,不出数。
  B' 下限   `call <reg>` 直接形态候选 `[\x40-\x4f]?\xff[\xd0-\xd7]`。硬门 = 恰好 14998;
            且 mov/call 两侧候选各 >= 1000 才许继续(否则「配对 0」不可信)。
  C' 配对   同一函数体内(限定「函数内同时含两种候选」),load 之后 <= 24 条指令内出现
            `call <dst>`,其间 <dst> 未被任何写目的地的 mov 重定义(按寄存器家族归一,
            如 R10D 的写算重定义 R10)。复核只对候选所在函数从函数首解码 ——
            一次性 disasm 整段 .text 会撞不可解码字节静默停止(§62.4 坑 1),不作集合用。

判决词三档(逐字,与 §63 同形但不同义、不合并):
  two_stage_dispatchers_named   某配对的承载函数在 _object_ref_functions() 集合里(需逐字节反汇编复核后才许写 §66)
  two_stage_dispatchers_partial 配对集合非空但无一配上对象
  no_two_stage_pair_static      A'/B' 全绿而配对归约后为空

读数校准说明(与计划 brief 的出入,不静默改判据):brief 的 C' 行写「样本 132 条」。
本探针按上面钉死的语义全量扫得 105;所有可区分变体(size==4 松紧、寄存器家族归一松紧、
skipdata、disp 复核松紧、load/call 取候选位或解码流、窗口 16..全函数)里严格配对从 105 到
116、无重定义上界 118(窗口<=24),132 在任何钉死语义组合下都构造不出(详见取证卷 §66.4
变体表)。A'/B' 的硬门(8330/14998/校准对/两侧>=1000)与 C' 的两条钉死判据(配对非空、
§63 四对象函数内配对=0)全部复现,仪器健康;132 是计划探得值与最终钉死语义的读数漂移,
按「报告而非迁就」处理:artifact 与 §66 记实际全量读数 105。

解码口径直接 import 同族 `queue_dispatchers`(§63),保证两节读数可比。
读 exe 走 disrva.resolve_exe()/CANDIDATES(NS_STELLARIS_EXE 可覆盖),不写死绝对路径。
失败语义:任一硬门不过 => 退出码 1,不写 artifact,不出负结论。
旧名:无(新建;家族成员 = queue_dispatchers.py / §63)。
"""
import os
import random
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import queue_dispatchers as qd  # noqa: E402  (§63 同族:read_image/_blob/_md/_object_ref_functions/BASE)

from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_RIP  # noqa: E402
from pdata import func_of  # noqa: E402

# 字节候选形态(计划的钉死模式):
MOV_PAT = re.compile(rb"[\x48-\x4f]\x8b[\x48-\x7f]\x28")   # mov r64,[r64+0x28],无 SIB,disp8
CALL_PAT = re.compile(rb"[\x40-\x4f]?\xff[\xd0-\xd7]")     # call <reg>
DISP = 0x28
WINDOW = 24                    # load 之后最多 24 条指令
SEED = 444                     # A' 抽样复核的固定种子(可复现)
SAMPLE_N = 400
EXPECT_MOV_CANDS = 8330        # 计划钉死读数(A' 硬门)
EXPECT_CALL_CANDS = 14998      # 计划钉死读数(B' 硬门)
SIDE_FLOOR = 1000              # 「配对 0 不可信」下限
CALIB_LOAD = 0x24D7E4
CALIB_CALL = 0x24D800
CALIB_FUNC = 0x24D4D0
OBJ_FNS_EXPECT = {0x1C42D30, 0x1C42DE0, 0x1BA6D20, 0x1BA72A0}   # §63 的四个对象引用函数

_GPR64 = {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
          "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}


def canon_gpr(name):
    """把任意宽度的 GPR 名归一到 64 位家族名(R10D/R10W/R10B/EAX/AX/AL/AH -> R10/RAX...)。"""
    n = (name or "").upper()
    if re.fullmatch(r"R\d+[DWB]", n):
        return n[:-1]
    if n.startswith("E") and len(n) == 3:
        return "R" + n[1:]
    if n.startswith("R") and n.endswith("B") and n[1:-1].isdigit():
        return n[:-1]
    two = {"AX": "RAX", "BX": "RBX", "CX": "RCX", "DX": "RDX",
           "SI": "RSI", "DI": "RDI", "BP": "RBP", "SP": "RSP"}
    eight = {"AL": "RAX", "AH": "RAX", "BL": "RBX", "BH": "RBX",
             "CL": "RCX", "CH": "RCX", "DL": "RDX", "DH": "RDX",
             "SPL": "RSP", "BPL": "RBP", "SIL": "RSI", "DIL": "RDI"}
    return two.get(n) or eight.get(n) or n


def mov_load_form(md, ins):
    """已核复的 `mov r64,[r64+0x28]`:4 字节长、mod=01 disp8、无 SIB、非 rip。
    返回 (dst64, base64, 反汇原文) 或 None。"""
    if ins.mnemonic != "mov" or ins.size != 4 or len(ins.operands) != 2:
        return None
    op0, op1 = ins.operands
    if op0.type != X86_OP_REG or op1.type != X86_OP_MEM:
        return None
    if op1.mem.base == X86_REG_RIP or op1.mem.disp != DISP:
        return None
    dst = canon_gpr(md.reg_name(op0.reg))
    base = canon_gpr(md.reg_name(op1.mem.base))
    if dst not in _GPR64 or base not in _GPR64:
        return None
    return dst, base, f"{ins.mnemonic} {ins.op_str}"


def call_reg_form(md, ins):
    """已核复的 `call <reg>`(直接形态,寄存器操作数)。返回 dst64 或 None。"""
    if ins.mnemonic != "call" or len(ins.operands) != 1:
        return None
    op0 = ins.operands[0]
    if op0.type != X86_OP_REG:
        return None
    d = canon_gpr(md.reg_name(op0.reg))
    return d if d in _GPR64 else None


def mov_writes(md, ins, dst):
    """该指令是否是「写目的地 dst(mov 家族归一后相同)」的 mov。"""
    if ins.mnemonic != "mov" or not ins.operands:
        return False
    op0 = ins.operands[0]
    return op0.type == X86_OP_REG and canon_gpr(md.reg_name(op0.reg)) == dst


def group_by_func(cands):
    """候选 -> {函数首: [候选...]};返回 (by_func, off_function_count)。"""
    by, off = {}, 0
    for c in cands:
        f = func_of(c)
        if f is None:
            off += 1
            continue
        by.setdefault(f[0], []).append(c)
    return by, off


def decode_func(md, blob, va, fstart, fend):
    """从函数首对齐解码一条函数(与 §63 _call_mem_disp_sites 同一口径,+16 字节尾窗)。"""
    return list(md.disasm(blob[fstart - va:fend - va + 16], qd.BASE + fstart))


def sample_verify(md, blob, va, mov_cands):
    """A' 抽样复核:SEED 固定抽 SAMPLE_N 条,函数首对齐解码验证形态。"""
    rng = random.Random(SEED)
    samp = sorted(rng.sample(mov_cands, SAMPLE_N))
    by, off = group_by_func(samp)
    verified, bad = 0, []
    for fstart, items in by.items():
        fend = func_of(fstart)[1]
        pos = {i.address - qd.BASE: i for i in decode_func(md, blob, va, fstart, fend)}
        for c in items:
            ins = pos.get(c)
            if ins is not None and mov_load_form(md, ins):
                verified += 1
            else:
                bad.append(hex(c))
    return verified, len(samp) - verified - len(bad), bad   # true, off-function, not-verified


def channel_a(md, blob, va):
    """A':候选计数 + 抽样复核 + 校准对(0x24d7e4 -> 0x24d800,同函数)。"""
    mov_cands = sorted(va + m.start() for m in MOV_PAT.finditer(blob))
    true_n, off_n, bad = sample_verify(md, blob, va, mov_cands)
    calib = check_calibration(md, blob, va)
    gates_ok = (len(mov_cands) == EXPECT_MOV_CANDS) and (calib is not None)
    return {"cands": mov_cands, "sample_true": true_n, "sample_off": off_n,
            "sample_bad": bad, "calib": calib, "ok": gates_ok}


def check_calibration(md, blob, va):
    """校准对必须存在且逐条符合:load 在 0x24d7e4、函数首 0x24d4d0、
    0x24d800 处是 call <dst>、load->call 间隔 1..WINDOW 条、其间 dst 未被 mov 重定义。"""
    f = func_of(CALIB_LOAD)
    if f is None or f[0] != CALIB_FUNC:
        return None
    ins = decode_func(md, blob, va, f[0], f[1])
    pos = {i.address - qd.BASE: k for k, i in enumerate(ins)}
    li, ci = pos.get(CALIB_LOAD), pos.get(CALIB_CALL)
    if li is None or ci is None:
        return None
    ldst = mov_load_form(md, ins[li])
    cdst = call_reg_form(md, ins[ci])
    if not ldst or cdst is None or cdst != ldst[0]:
        return None
    gap = ci - li
    if not 1 <= gap <= WINDOW:
        return None
    for k in range(li + 1, ci):
        if mov_writes(md, ins[k], cdst):
            return None
    return gap


def channel_b(md, blob, va, a):
    """B':call 候选计数(硬门)+ 两侧 >= SIDE_FLOOR 下限门。"""
    call_cands = sorted(va + m.start() for m in CALL_PAT.finditer(blob))
    ok = (len(call_cands) == EXPECT_CALL_CANDS
          and len(call_cands) >= SIDE_FLOOR and len(a["cands"]) >= SIDE_FLOOR)
    return {"cands": call_cands, "ok": ok}


def channel_c(md, blob, va, a, b):
    """C':「函数内同时含两种候选」限定下的配对全量扫描。

    返回 (pairs, stats)。pairs 元素:(load_rva, call_rva, func_begin, func_end,
    load_form, base_reg, call_reg, gap)。"""
    fmov, mov_off = group_by_func(a["cands"])
    fcall, call_off = group_by_func(b["cands"])
    both = sorted(set(fmov) & set(fcall))
    pairs, ndec = [], []
    for fstart in both:
        fend = func_of(fstart)[1]
        ins = decode_func(md, blob, va, fstart, fend)
        pos = {i.address - qd.BASE: k for k, i in enumerate(ins)}
        loads = []
        for c in fmov[fstart]:
            k = pos.get(c)
            if k is None:
                ndec.append(c)
                continue
            d = mov_load_form(md, ins[k])
            if d:
                loads.append((k, d[0], d[1], d[2]))
        calls = {}
        for c in fcall[fstart]:
            k = pos.get(c)
            if k is None:
                ndec.append(c)
                continue
            d = call_reg_form(md, ins[k])
            if d:
                calls.setdefault(d, []).append(k)
        for li, dst, base, text in loads:
            for ci in calls.get(dst, []):
                gap = ci - li
                if not 1 <= gap <= WINDOW:
                    continue
                if any(mov_writes(md, ins[k], dst) for k in range(li + 1, ci)):
                    continue
                pairs.append({"load": ins[li].address - qd.BASE, "call": ins[ci].address - qd.BASE,
                              "fbegin": fstart, "fend": fend, "load_form": text,
                              "base": base, "dst": dst, "gap": gap})
    stats = {"both_fns": len(both), "mov_off": mov_off, "call_off": call_off,
             "undecodable_in_both": len(ndec)}
    return pairs, stats


def verdict_of(pairs, fn_objs):
    """三档(逐字)。named = 任一配对承载函数引用 A/B 对象(§63 那四个)。"""
    named = [p for p in pairs if p["fbegin"] in fn_objs]
    if named:
        return "two_stage_dispatchers_named", named
    if pairs:
        return "two_stage_dispatchers_partial", named
    return "no_two_stage_pair_static", named


def write_artifact(exe, a, b, pairs, obj_pairs, verdict):
    path = os.path.join(_REPO, "evidence", "xrefs", "queue_dispatchers_two_stage_4_4_4.tsv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("channel\tload_rva\tcall_rva\tfunc_begin\tfunc_end\tload_form\t"
                "base_reg\tcall_reg\tobject_ref\tnote\n")
        f.write(f"#verdict\t{verdict}\tmov_cands={len(a['cands'])}\tcall_cands={len(b['cands'])}\t"
                f"pairs={len(pairs)}\tobject_fn_pairs={len(obj_pairs)}\t"
                f"calib_pair=(0x{CALIB_LOAD:x},0x{CALIB_CALL:x})\t"
                f"A'/B' 硬门 + C' 两条钉死判据(非空/四对象函数=0)全绿才写本文件;"
                f"窗口<= {WINDOW} 条指令、同函数、mov 重定义剔除;exe={os.path.basename(exe)}\n")
        cal = a["calib"]
        f.write(f"A'\t{_hx(CALIB_LOAD)}\t{_hx(CALIB_CALL)}\t{_hx(CALIB_FUNC)}\t"
                f"{_hx(func_of(CALIB_FUNC)[1])}\tmov r10, qword ptr [rax + 0x28]\t"
                f"rax\tr10\t-\t校准对,load 后第 {cal} 条指令 = call r10(逐条反汇编在案 §66)\n")
        for p in sorted(pairs, key=lambda x: (x["fbegin"], x["load"], x["call"])):
            obj = fn_objs_note(p)
            f.write("C'\t{load}\t{call}\t{fb}\t{fe}\t{form}\t{base}\t{dst}\t{oref}\t{note}\n".format(
                load=_hx(p["load"]), call=_hx(p["call"]), fb=_hx(p["fbegin"]), fe=_hx(p["fend"]),
                form=p["load_form"].replace("\t", " "), base=p["base"].lower(),
                dst=p["dst"].lower(), oref=obj,
                note=f"gap={p['gap']}; func {p['fbegin']:x}..{p['fend']:x}"))
    return path


def fn_objs_note(p):
    """对象引用列:承载函数在 _object_ref_functions() 集合里才非 '-'。"""
    objs = p.get("object_ref")
    if not objs:
        return "-"
    return "|".join(f"0x{o:x}" for o in sorted(objs))


def _hx(v):
    return "-" if v is None else f"0x{v:x}"


def bulk_disasm_trap(md, blob):
    """判读陷阱记数(§62.4 坑 1 同族):一次性 disasm 整段 .text 会在不可解码字节处
    静默停止,报出的 call-reg 数是假数。返回该一次性口径的站点数,仅作记录。"""
    n = 0
    for ins in md.disasm(blob, qd.BASE):
        if ins.mnemonic == "call" and len(ins.operands) == 1 and ins.operands[0].type == X86_OP_REG:
            n += 1
    return n


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="queue_dispatchers_two_stage.py")
    ap.add_argument("--only", choices="ABC", help="只跑一条口径(A/B 带硬门)")
    args = ap.parse_args(argv)

    exe, image, secs = qd.read_image()
    va, blob = qd._blob(image, secs, ".text")
    md = qd._md()

    a = channel_a(md, blob, va)
    if args.only != "A" and not a["ok"]:
        # 失败语义不分单跑/全量:A' 硬门坏 = 仪器坏,任何后续口径都无权出数
        print(f"channel A': mov_candidates={len(a['cands'])} self_check=FAIL "
              f"(期望 {EXPECT_MOV_CANDS},calib_pair={a['calib']}) —— 检测器坏了,停")
        return 1
    if args.only in (None, "A"):
        if not a["ok"]:
            print(f"channel A': mov_candidates={len(a['cands'])} self_check=FAIL "
                  f"(期望 {EXPECT_MOV_CANDS},calib_pair={a['calib']}) —— 检测器坏了,停,"
                  f"不进 B'/C',不落盘")
            return 1
        print(f"channel A': mov_candidates={len(a['cands'])} self_check=ok "
              f"calibration_pair=(0x{CALIB_LOAD:x},0x{CALIB_CALL:x})")
        print(f"channel A' sample: seed={SEED} n={SAMPLE_N} verified_true={a['sample_true']} "
              f"off_function={a['sample_off']} not_verified={len(a['sample_bad'])} "
              f"{a['sample_bad'][:5]}")
        if args.only == "A":
            return 0

    b = channel_b(md, blob, va, a)
    if args.only == "C" and not b["ok"]:
        print(f"channel B': call_candidates={len(b['cands'])} self_check=FAIL "
              f"(期望 {EXPECT_CALL_CANDS},两侧下限 {SIDE_FLOOR}) —— 检测器坏了,停")
        return 1
    if args.only in (None, "B"):
        if not b["ok"]:
            print(f"channel B': call_candidates={len(b['cands'])} self_check=FAIL "
                  f"(期望 {EXPECT_CALL_CANDS},两侧下限 {SIDE_FLOOR}) —— 检测器坏了,停")
            return 1
        print(f"channel B': call_candidates={len(b['cands'])} self_check=ok "
              f"side_floor=ok(mov={len(a['cands'])},call={len(b['cands'])})")
        if args.only == "B":
            return 0

    fn_objs = qd._object_ref_functions(image, secs)
    pairs, stats = channel_c(md, blob, va, a, b)
    for p in pairs:
        p["object_ref"] = fn_objs.get(p["fbegin"])
    obj_pairs = [p for p in pairs if p["fbegin"] in OBJ_FNS_EXPECT and p["object_ref"]]
    named_any = [p for p in pairs if p["object_ref"]]
    gates_ok = bool(pairs) and not obj_pairs and set(fn_objs) == OBJ_FNS_EXPECT
    verdict, _ = verdict_of(pairs, fn_objs)
    if args.only in (None, "C"):
        if not gates_ok:
            print(f"channel C': self_check=FAIL pairs={len(pairs)} "
                  f"object_fn_pairs={len(obj_pairs)} fn_objs={sorted(hex(x) for x in fn_objs)} "
                  f"—— 与 §63 钉死判据不符,停,不落盘")
            return 1
        print(f"channel C': pairs={len(pairs)} both_form_funcs={stats['both_fns']} "
              f"window<={WINDOW} object_fn_pairs={len(obj_pairs)} "
              f"named={len(named_any)} self_check=ok "
              f"(undecodable-in-both={stats['undecodable_in_both']}, "
              f"off-fn mov/call={stats['mov_off']}/{stats['call_off']})")
        if args.only == "C":
            return 0

    if verdict == "two_stage_dispatchers_named":
        print("warning: named 档 —— 归约结果本身不足以具名,§66 必须附上该承载函数的"
              "逐字节反汇编复核后才允许断言(预期不成立,出现即人工介入)")

    trap = bulk_disasm_trap(md, blob)
    path = write_artifact(exe, a, b, pairs, obj_pairs, verdict)
    print(f"verdict={verdict} pairs={len(pairs)} -> {os.path.relpath(path, _REPO)}")
    print(f"trap-note: 一次性 disasm 整段 .text 的 call-reg 计数 = {trap}(desync 假数,§62.4 坑 1 同族)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
