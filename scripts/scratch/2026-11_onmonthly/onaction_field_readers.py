#!/usr/bin/env python3
"""全局 `onMonthly` 的入口在哪 —— 这一支的**唯一生产者**(只读 exe 拷贝,零 shot)。

回答四件事,每件一行读数:

1. `on_monthly_pulse` / `on_yearly_pulse` 这两个名字在 `.rdata` 里有几个**真串起点**,
   谁 `lea` 它们(riprefs 口径,`--verify`)。
2. `0x407330`(唯一读名字的函数)那 14 个 `lea rdx,[名字]` + `mov [r14+0xNN], rdi` 的
   **字段映射表**(没数出来就说明口径错了)。
3. 全镜像里谁读 on_action DB(`[0x3374840]`)的**固定字段** `+0x28`(= `on_monthly_pulse`):
   先跟「从全局取指针、`mov` 复制、再取 `[reg+disp]`」,再把「rcx = db 的调用点」逐个目标
   读一遍看有没有 `[this+0x28]`。
4. 计划台账里五个候选:每个函数体内的**间接调用槽**(`call [reg+disp]`)与**对已知锚点的直调**
   (`E8`),用来证明「没有 effect 派发」不是看着不像。

用法:
    python3 scripts/scratch/2026-11_onmonthly/onaction_field_readers.py

判读纪律(与 `docs/offline-tooling.md` 一致):函数边界一律取 `.pdata`(合并后的逻辑范围),
裸数字区间会跨进下一个函数 —— 本脚本的每个 `--len` 都由 `.pdata` 算。

**边界(写进卷里)**:第 3 项只覆盖「经 rip 相对引用从全局取到 db」的那些函数;db 若经非 `rcx`
实参或经别的结构体字段传出去,本脚本看不见。第 3 项的第二个口径(rcx = db 的调用点)是给这条
缺口补的一层围栏,不是证明。
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, SCRIPTS)

import rttibatch as R          # noqa: E402  (find_exe / Image: 只读 PE)
import riprefs                 # noqa: E402  (pdata 桶 + rip 相对引用,`--verify` 同口径)
from capstone import Cs, CS_ARCH_X86, CS_MODE_64              # noqa: E402
from capstone.x86 import X86_REG_RIP, X86_OP_IMM, X86_OP_MEM, X86_OP_REG  # noqa: E402

BASE = 0x140000000
DB_RVA = 0x3374840            # on_action DB 的全局**指针**(不是对象本体)
NAME_MAPPER = 0x407330        # 唯一引用 on_monthly_pulse / on_yearly_pulse 真串的函数
MONTHLY_READER = 0x265DD0     # 唯一读 DB+0x28 的函数

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# 效果/事件侧的已知锚点,用来把「没有派发」变成一条可复核的读数
ANCHORS = {
    0x1D08520: 'CEffect::Execute (base, [vptr+0x08] 家族基体)',
    0x3AFD30: 'donor Execute 覆写 (slot[1])',
    0x3B1330: '[vptr+0x70] base impl (递归 parse)',
    0x3B01A0: 'instantiate-by-token-id (slot[2])',
    0x1D092C0: 'parse-error 表追加器',
    0x3AF130: '全树枚举 create',
    0x3B0F80: '家族公共槽 slot[8]',
    0x402C50: 'trigger event',
    0x406F90: 'Perform OnAction',
    0x406F00: 'PerformOnActionByName',
    0x37BB70: 'FindOnAction(name)',
}

CANDIDATES = {
    0x9F5750: 'Event command handler (eventcommands.cpp)',
    0x9F6420: 'Event command handler (eventcommands.cpp)',
    0x9F65E0: 'Event command handler (eventcommands.cpp)',
    0x18B7B70: 'effect vtable +0x70 派发候选 (§83)',
    0x18B7E30: 'effect vtable +0x70 派发候选 (§83)',
}

FIELD_NAMES = {
    0x24EED00: 'on_monthly_pulse',
    0x24EECF0: 'on_yearly_pulse',
    0x24EECD8: 'on_bi_yearly_pulse',
    0x24EECC0: 'on_five_year_pulse',
    0x24EECB0: 'on_decade_pulse',
    0x24EEC98: 'on_mid_game_pulse',
    0x24EEC80: 'on_late_game_pulse',
    0x24EEC60: 'on_monthly_pulse_country',
    0x24EEDD8: 'on_yearly_pulse_country',
    0x24EEDB8: 'on_bi_yearly_pulse_country',
    0x24EED98: 'on_five_year_pulse_country',
    0x24EED80: 'on_decade_pulse_country',
    0x24EED60: 'on_mid_game_pulse_country',
    0x24EED40: 'on_late_game_pulse_country',
}


def insns_of(start, length=None):
    """`start` 所在 `.pdata` 逻辑函数的指令流;`length` 给了就截到那个长度。"""
    fb = riprefs.func_of(start)
    if fb is None:
        return []
    end = fb[1] if length is None else min(fb[1], start + length)
    code = riprefs.rd(start, end - start, '.text')
    return list(md.disasm(code, BASE + start))


def holder_slots(insns, target):
    """跟「从 [rip+..] 取 target 的寄存器」,返回 [(site, disp)],不跨函数。"""
    held = {}
    out = []
    for ins in insns:
        ops = ins.operands
        if len(ops) >= 2 and ops[0].type == X86_OP_REG:
            dst, src = ops[0], ops[1]
            if src.type == X86_OP_MEM and src.mem.base == X86_REG_RIP:
                tgt = ins.address - BASE + ins.size + src.mem.disp
                if tgt == target:
                    held[ins.reg_name(dst.reg)] = ins.address - BASE
                    continue
            if src.type == X86_OP_REG and ins.mnemonic == 'mov' and ins.reg_name(src.reg) in held:
                held[ins.reg_name(dst.reg)] = held[ins.reg_name(src.reg)]
                continue
            if src.type == X86_OP_MEM and src.mem.base not in (0, X86_REG_RIP):
                base = ins.reg_name(src.mem.base)
                if base in held:
                    out.append((ins.address - BASE, src.mem.disp, held[base]))
            if dst.reg and ins.reg_name(dst.reg) in held:
                del held[ins.reg_name(dst.reg)]
    return out


def e8_sites(target):
    """`E8 rel32` 直调 `target` 的站点(字节扫描,与 fastcalls.py 同口径)。"""
    import struct
    text = next(s for s in riprefs.secs if s[0] == '.text')
    blob = riprefs.f[text[4]:text[4] + text[3]]
    out = []
    for i in range(len(blob) - 5):
        if blob[i] == 0xE8:
            rel = struct.unpack_from('<i', blob, i + 1)[0]
            if text[1] + i + 5 + rel == target:
                out.append(text[1] + i)
    return out


def report_names():
    print('== 1. 名字串与它的引用点')
    for name, rva in (('on_monthly_pulse', 0x24EED00), ('on_yearly_pulse', 0x24EECF0)):
        hits = riprefs.refs_for({rva}, '.text', True)[rva]
        fns = sorted({riprefs.func_of(s)[0] for s, _ in hits if riprefs.func_of(s)})
        print(f'   {name} @0x{rva:x}: refs={len(hits)} functions={[hex(f) for f in fns]}')


def report_field_map():
    print('== 2. 0x407330 的名字→DB 字段映射(lea rdx,[名字] 后跟 mov [db+0xNN],rdi)')
    insns = insns_of(NAME_MAPPER)
    db_regs = {i.reg_name(i.operands[0].reg) for i in insns
               if len(i.operands) == 2 and i.operands[0].type == X86_OP_REG
               and i.operands[1].type == X86_OP_MEM
               and i.operands[1].mem.base == X86_REG_RIP
               and i.address - BASE + i.size + i.operands[1].mem.disp == DB_RVA}
    pending = None
    rows = 0
    for ins in insns:
        ops = ins.operands
        if (ins.mnemonic == 'lea' and len(ops) == 2 and ops[0].type == X86_OP_REG
                and ops[1].type == X86_OP_MEM and ops[1].mem.base == X86_REG_RIP
                and ins.reg_name(ops[0].reg) == 'rdx'):
            tgt = ins.address - BASE + ins.size + ops[1].mem.disp
            pending = (tgt, ins.address - BASE)
            continue
        if pending and ins.mnemonic == 'mov' and len(ops) == 2:
            if (ops[0].type == X86_OP_MEM
                    and ins.reg_name(ops[0].mem.base) in db_regs
                    and ins.reg_name(ops[1].reg) == 'rdi'):
                name = FIELD_NAMES.get(pending[0], hex(pending[0]))
                print(f'   +0x{ops[0].mem.disp:<3x} = {name:<26s}'
                      f' (lea@0x{pending[1]:x}, store@0x{ins.address - BASE:x})')
                rows += 1
            pending = None
    print(f'   rows={rows}')


def report_db_field_readers():
    print('== 3a. 从全局取到 DB 指针后读固定字段的函数')
    hits = riprefs.refs_for({DB_RVA}, '.text', True)[DB_RVA]
    fstarts = sorted({riprefs.func_of(s)[0] for s, _ in hits if riprefs.func_of(s)})
    print(f'   global 0x{DB_RVA:x}: refs={len(hits)} functions={len(fstarts)}')
    for start in fstarts:
        for site, disp, load in holder_slots(insns_of(start), DB_RVA):
            if 0x28 <= disp <= 0x90:
                name = FIELD_NAMES.get(0x24EECF0 + 0, '')
                print(f'   func 0x{start:x}: site 0x{site:x} [+0x{disp:x}] (load@0x{load:x})')

    print('== 3b. 以 rcx = DB 调用的目标,自己再读 [this+0x28]')
    callees = {}
    for start in fstarts:
        held = {}
        for ins in insns_of(start):
            ops = ins.operands
            if len(ops) >= 2 and ops[0].type == X86_OP_REG:
                dst, src = ops[0], ops[1]
                if src.type == X86_OP_MEM and src.mem.base == X86_REG_RIP:
                    tgt = ins.address - BASE + ins.size + src.mem.disp
                    if tgt == DB_RVA:
                        held[ins.reg_name(dst.reg)] = ins.address - BASE
                        continue
                if src.type == X86_OP_REG and ins.mnemonic == 'mov' and ins.reg_name(src.reg) in held:
                    held[ins.reg_name(dst.reg)] = held[ins.reg_name(src.reg)]
                    continue
                if dst.reg and ins.reg_name(dst.reg) in held:
                    del held[ins.reg_name(dst.reg)]
            if (ins.mnemonic == 'call' and ops and ops[0].type == X86_OP_IMM
                    and 'rcx' in held):
                callees.setdefault(ops[0].imm - BASE, []).append(ins.address - BASE)
    print(f'   distinct callees with rcx=db: {len(callees)}')
    for tgt, n in sorted(callees.items()):
        fb = riprefs.func_of(tgt)
        reads = []
        if fb:
            held = {'rcx'}
            for ins in md.disasm(riprefs.rd(fb[0], fb[1] - fb[0], '.text'), BASE + fb[0]):
                ops = ins.operands
                for op in ops:
                    if (op.type == X86_OP_MEM and op.mem.base not in (0, X86_REG_RIP)
                            and op.mem.disp == 0x28
                            and ins.reg_name(op.mem.base) in held):
                        reads.append(hex(ins.address - BASE))
                if len(ops) >= 2 and ops[0].type == X86_OP_REG:
                    dst, src = ops[0], ops[1]
                    if src.type == X86_OP_REG and ins.mnemonic == 'mov' \
                            and ins.reg_name(src.reg) in held:
                        held.add(ins.reg_name(dst.reg))
                        continue
                    if ins.reg_name(dst.reg) in held and ins.reg_name(dst.reg) != 'rcx':
                        held.discard(ins.reg_name(dst.reg))
        label = ANCHORS.get(tgt, '')
        sites = callees.get(tgt, [])
        print(f'   0x{tgt:x} callsites={len(sites):<3d} first_site={hex(sites[0]):<10s}'
              f' [+0x28] reads={reads or "-"} {label}')


def report_candidates():
    print('== 4. 五个候选的间接调用槽 + 对已知锚点的直调')
    for start, label in CANDIDATES.items():
        insns = insns_of(start)
        slots = [(hex(i.address - BASE), i.op_str) for i in insns
                 if i.mnemonic in ('call', 'jmp') and i.operands
                 and i.operands[0].type == X86_OP_MEM
                 and i.operands[0].mem.base not in (0, X86_REG_RIP)]
        direct = {i.operands[0].imm - BASE for i in insns
                  if i.mnemonic == 'call' and i.operands and i.operands[0].type == X86_OP_IMM}
        anchor_hits = sorted(f'0x{t:x}({ANCHORS[t]})' for t in direct if t in ANCHORS)
        print(f'   0x{start:x} {label}')
        print(f'      indirect={slots}')
        print(f'      E8_callers={[hex(x) for x in e8_sites(start)]} anchors={anchor_hits or "-"}')


def main():
    exe = R.find_exe()
    print(f'# exe={exe}')
    report_names()
    report_field_map()
    report_db_field_readers()
    report_candidates()


if __name__ == '__main__':
    main()
