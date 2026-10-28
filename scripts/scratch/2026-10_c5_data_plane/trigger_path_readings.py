#!/usr/bin/env python3
"""trigger_path_readings —— §75 的四条静态读数(零 shot,只读本地 exe 拷贝)。

口径(读数写进取证卷 §75,执行者照抄或按本脚本的实跑订正):
  1 class_info 0x269CAA8 的四个 qword —— [0]/? [8]/create [0x10]/? [0x18]/?
  2 create 0x1B30450 里那条 `lea reg,[rip+disp32]` 落到哪张表,并且同一小段里有
    `mov [rbx],rax` 把它存成对象的 vtable。
  3 那张表的 slot[5](+0x28)与 slot[16](+0x80)各是谁。
  4 exe 的 CNT_INITIALIZED_DATA 段里等于 BASE+0x349230 的 qword 个数与 8 对齐分布
    —— 判据是「它是不是一个共用基体」,不是「它属于哪张表」。
  5 0x349230 与 effect 谓词 0x3B1420 的前 32 字节逐字节比对 —— 前 21 字节相同,
    差别只在偏移 24..26 的调用槽。

失败语义:自校验不过 ⇒ 检测器坏了或 exe 不是 4.4.4,退出码 1,不写 artifact,更不写负结论。
读 exe 走 disrva.resolve_exe(),不写死绝对路径。
"""
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
if os.path.join(_REPO, "scripts") not in sys.path:
    sys.path.insert(0, os.path.join(_REPO, "scripts"))

from capstone import Cs, CS_ARCH_X86, CS_MODE_64          # noqa: E402
from capstone.x86 import X86_OP_MEM, X86_REG_RIP          # noqa: E402

from disrva import BASE, _image, rd, resolve_exe          # noqa: E402

CLASS_INFO_TRIGGER = 0x269CAA8
CREATE_TRIGGER = 0x1B30450
TRIGGER_PREDICATE = 0x349230
EFFECT_PREDICATE = 0x3B1420
TRIGGER_INSTANTIATE = 0x349AE0

# §75 的数条不变量:哪一条不成立都说明检测器坏了,不是「读数变了」。
EXPECT_TRIGGER_PRED = 0x349230


def qwords(rva, n):
    blob, _ = rd(rva, 8 * n)
    if len(blob) != 8 * n:
        raise SystemExit(f"unreadable at {rva:#x}")
    return list(struct.unpack("<%dQ" % n, blob))


def _md():
    m = Cs(CS_ARCH_X86, CS_MODE_64)
    m.detail = True
    return m


def lea_targets(rva, count=48):
    """Return [(insn_address, target)] for every `lea reg, [rip+disp]` in the window."""
    blob, _ = rd(rva, 256)
    md = _md()
    out = []
    for ins in md.disasm(blob, BASE + rva):
        if len(out) >= count:
            break
        if ins.mnemonic == "lea" and ins.operands:
            op = ins.operands[-1]
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                out.append((ins.address - BASE, ins.address + ins.size + op.mem.disp - BASE))
    return out


def stores_rax_to_rbx(rva, span=0x60):
    blob, _ = rd(rva, span)
    md = _md()
    hits = []
    for ins in md.disasm(blob, BASE + rva):
        if ins.mnemonic == "mov" and "qword ptr [rbx], rax" in ins.op_str:
            hits.append(ins.address - BASE)
    return hits


def count_initialized_qwords(value):
    _exe, f, secs = _image()
    pat = struct.pack("<Q", value)
    total = 0
    mods = {}
    for _nm, va, _vs, rawsz, praw, chars in secs:
        if not (chars & 0x40):  # CNT_INITIALIZED_DATA
            continue
        blob = f[praw:praw + rawsz]
        i = blob.find(pat)
        while i != -1:
            total += 1
            mods[va + i & 7] = mods.get(va + i & 7, 0) + 1
            i = blob.find(pat, i + 1)
    return total, mods


def main():
    exe = resolve_exe()
    if exe is None:
        print("FAIL: stellaris.exe not found (set NS_STELLARIS_EXE)", file=sys.stderr)
        return 1
    print(f"exe: {exe}  base: {BASE:#x}")
    bad = []

    # --- 1. class_info -------------------------------------------------------
    cls = qwords(CLASS_INFO_TRIGGER, 4)
    print("\n[1] class_info 0x269CAA8 =", [hex(q) for q in cls])
    if cls[1] != BASE + CREATE_TRIGGER:
        bad.append("create 不在 class_info+8")

    # --- 2. create -> vtable -------------------------------------------------
    leas = [t for _a, t in lea_targets(CREATE_TRIGGER)]
    stores = stores_rax_to_rbx(CREATE_TRIGGER)
    vtable = leas[0] if leas else 0
    print(f"[2] create lea targets = {[hex(t) for t in leas[:4]]}")
    print(f"    `mov [rbx], rax` at {[hex(s) for s in stores]}")
    if not vtable or not stores:
        bad.append("create 里找不到 lea/stores 对")

    # --- 3. slots ------------------------------------------------------------
    slot5 = qwords(vtable + 5 * 8, 1)[0]
    slot16 = qwords(vtable + 16 * 8, 1)[0]
    print(f"[3] vtable {vtable:#x}: slot[5](+0x28) = {slot5:#x}   slot[16](+0x80) = {slot16:#x}")
    if slot16 != BASE + EXPECT_TRIGGER_PRED:
        bad.append(f"slot[16] 不是 {EXPECT_TRIGGER_PRED:#x}")

    # --- 4. shared base ------------------------------------------------------
    total, mods = count_initialized_qwords(BASE + TRIGGER_PREDICATE)
    print(f"[4] initialized qwords == {BASE + TRIGGER_PREDICATE:#x}: {total}   align={mods}")
    if total == 0:
        bad.append("基体一个引用都没有")

    # --- 5. 32-byte fingerprints --------------------------------------------
    trig, _ = rd(TRIGGER_PREDICATE, 32)
    eff, _ = rd(EFFECT_PREDICATE, 32)
    print(f"[5] {TRIGGER_PREDICATE:#x}: {trig.hex(' ')}")
    print(f"    {EFFECT_PREDICATE:#x}: {eff.hex(' ')}")
    same21 = trig[:21] == eff[:21]
    print(f"    first 21 bytes equal: {same21}; offset 26 = {trig[26]:#x} vs {eff[26]:#x}")
    if not same21:
        bad.append("前 21 字节不再相同 —— 与 §75 记录冲突")
    if trig[26] == eff[26]:
        bad.append("偏移 26 相同 —— 32 字节指纹分不开两个函数")

    # --- 6. instantiate path (读数,不是断言) ---------------------------------
    print(f"\n[6] 触发实例化路径 = {TRIGGER_INSTANTIATE:#x}(实参形状见 §75 读数 3;"
          f"本条只是把地址钉出来,形状由 pe_disrva 逐条读)")

    if bad:
        print("\nFAIL: " + "; ".join(bad), file=sys.stderr)
        return 1
    print("\nOK: 六块读数自校验通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
