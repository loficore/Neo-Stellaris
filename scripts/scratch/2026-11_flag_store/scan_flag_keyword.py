#!/usr/bin/env python3
"""一次性扫描器(2026-11 批次,不进顶层 scripts/)。

给定一个官方 keyword,走 `TSV → class_info → create → vtable → 每个 slot`,
按 **消费形状** 给每个 slot 打标:它读不读一个 MSVC 形状的名字串、读不读 u16、
按顺序调了谁。用于 `evidence/analysis/flag_store_4_4_4.md` 的 Task 2/3

它只读本地 `stellaris.exe` 拷贝(**不执行、不注入、不写**),不解析 `.data` 的值,
所以「0x326D110 那张表当前有几个元素」这类运行时状态它答不了 —— 它只回答
「哪条指令流在消费字符串 / u16」。

usage:
    scan_flag_keyword.py --keyword set_star_flag
    scan_flag_keyword.py --create 0x1895620

输出(stdout,TSV,带一行 `#` 注释头):
    slot_off  slot_rva  func_rva  func_len  string_reads  id_reads  callees

判据(与取证卷 §2 同口径):
    string_reads=true  见到下列任一:
                       * `cmp qword ptr [rX + 0x18], 0x10`(MSVC std::string 的 SSO 容量门)
                       * `cmp qword ptr [rX + 0x30], 0x10` / `+0x28`,0x10(同上,不同基址)
                       * 调 0x15F770 / 0x15F590 / 0x15EA40(串构造/赋值)
                       * 调 0x158300(把串 append 进 0x2A00DE0 那张 vector)
                       * 调 0x1C9E350(对串做哈希)
    id_reads=true      见到 `movzx <reg>, word ptr [...]`
"""
import argparse
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG

EXE_CANDIDATES = [
    os.environ.get('NS_STELLARIS_EXE'),
    '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe',
    r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe',
]
TSV = 'evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv'
OPERATOR_NEW = 0x2185218

#: 见到这几条 `cmp qword ptr [rX + disp], 0x10` 就算「在读一个 MSVC 形状的串」。
SSO_CAP_DISPS = {0x18, 0x28, 0x30}
STRING_CALLEES = {
    0x15F770: 'string_assign',
    0x15F590: 'string_ctor_copy',
    0x15EA40: 'string_ctor_from_cstr',
    0x158300: 'name_vector_append',   # 0x2A00DE0: flag-name 表的 append
    0x1C9E350: 'string_hash',
}


def _rva_num(va):
    """capstone 在这个脚本里按 RVA 作 address 反汇编,但 PE 里的 qword 是 VA。两边都收。"""
    return va - 0x140000000 if va >= 0x140000000 else va


def _rva(op_str):
    try:
        return _rva_num(int(op_str, 16))
    except ValueError:
        return None


def resolve_exe():
    for c in EXE_CANDIDATES:
        if c and os.path.exists(c):
            return c
    sys.exit('scan_flag_keyword.py: no stellaris.exe found (set NS_STELLARIS_EXE)')


class Image:
    def __init__(self, path):
        self.f = open(path, 'rb').read()
        mz = struct.unpack_from('<I', self.f, 0x3c)[0]
        nsec = struct.unpack_from('<H', self.f, mz + 6)[0]
        no = mz + 24 + struct.unpack_from('<H', self.f, mz + 20)[0]
        self.secs = []
        for i in range(nsec):
            nm = self.f[no + i * 40:no + i * 40 + 8].rstrip(b'\0').decode('latin1')
            vs, va, rsz, rp = struct.unpack_from('<IIII', self.f, no + i * 40 + 8)
            self.secs.append((nm, va, vs, rsz, rp))
        self.text = [s for s in self.secs if s[0] == '.text'][0]
        self.pdata = self._pdata()

    def _pdata(self):
        pd = [s for s in self.secs if s[0] == '.pdata'][0]
        raw = self.f[pd[4]:pd[4] + pd[3]]
        out = []
        for o in range(0, len(raw), 12):
            b = raw[o:o + 12]
            if len(b) < 12:
                break
            st, en, _un = struct.unpack('<III', b)
            if st == 0 and en == 0:
                break
            out.append((st, en))
        return sorted(set(out))

    def func_of(self, rva):
        lo, hi = 0, len(self.pdata)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.pdata[mid][0] <= rva:
                lo = mid + 1
            else:
                hi = mid
        i = lo - 1
        if i >= 0 and self.pdata[i][0] <= rva < self.pdata[i][1]:
            return self.pdata[i]
        return None

    def bytes_at(self, rva, n):
        _, va, vs, rsz, rp = self.text
        if not (va <= rva < va + vs):
            return b''
        off = rp + (rva - va)
        return self.f[off:off + n]

    def raw_at(self, rva, n):
        """任意 section 的字节(class_info / vtable 在 .rdata,不在 .text)。"""
        for _nm, va, vs, rsz, rp in self.secs:
            if va <= rva < va + vs:
                off = rp + (rva - va)
                return self.f[off:off + n]
        return b''

    def qword(self, rva):
        b = self.raw_at(rva, 8)
        return struct.unpack('<Q', b)[0] if len(b) == 8 else None

    def dword(self, rva):
        b = self.raw_at(rva, 4)
        return struct.unpack('<I', b)[0] if len(b) == 4 else None


def tsv_row(keyword):
    with open(TSV, encoding='utf-8') as fh:
        for line in fh:
            if line.startswith('#'):
                continue
            cols = line.rstrip('\n').split('\t')
            if len(cols) >= 7 and cols[5] == keyword:
                return cols
    sys.exit(f'scan_flag_keyword.py: {keyword!r} not in {TSV}')


def create_from_class_info(img, ci_rva):
    """class_info 是 16 B 的 {deleter, create} 对;create 是第二个 qword。"""
    q = img.qword(ci_rva + 8)
    return None if q is None else q - 0x140000000


def new_size_and_vptrs(img, create_rva):
    """在 create 的 .pdata 范围内找 new(size) 的立即数与发布出去的 vptr。"""
    span = img.func_of(create_rva)
    if not span:
        return None, []
    code = img.bytes_at(span[0], span[1] - span[0])
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    size = None
    vptrs = []
    prev_mov_ecx = None
    last_leas = {}
    for insn in md.disasm(code, span[0]):
        if insn.mnemonic == 'mov' and insn.op_str.startswith('ecx, ') and \
                'ptr' not in insn.op_str:
            try:
                prev_mov_ecx = int(insn.op_str.split(', ')[1], 16)
            except ValueError:
                prev_mov_ecx = None
        if insn.mnemonic == 'call':
            if _rva(insn.op_str) == OPERATOR_NEW and prev_mov_ecx:
                size = size or prev_mov_ecx
        if insn.mnemonic == 'lea':
            for op in insn.operands:
                if op.type == X86_OP_MEM and insn.reg_name(op.mem.base) == 'rip':
                    target = (insn.address + insn.size + op.mem.disp) & 0xffffffffffffffff
                    last_leas[insn.reg_name(insn.operands[0].reg)] = _rva_num(target)
        if insn.mnemonic == 'mov' and 'ptr [' in insn.op_str and ', rax' in insn.op_str:
            src = last_leas.get('rax')
            if src is not None:
                vptrs.append(src)
    return size, sorted(set(vptrs))


def classify(img, func_rva):
    span = img.func_of(func_rva)
    if not span:
        return None
    code = img.bytes_at(span[0], span[1] - span[0])
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    string_reads = []
    id_reads = []
    callees = []
    for insn in md.disasm(code, span[0]):
        if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
            tgt = _rva(insn.op_str)
            if tgt is not None:
                callees.append(tgt)
                if tgt in STRING_CALLEES:
                    string_reads.append(f"{hex(insn.address)}:{STRING_CALLEES[tgt]}")
        if insn.mnemonic == 'cmp':
            ops = insn.operands
            if len(ops) == 2 and ops[0].type == X86_OP_MEM and ops[1].type != X86_OP_MEM:
                disp = ops[0].mem.disp & 0xffffffff
                try:
                    imm = ops[1].imm
                except AttributeError:
                    imm = None
                if disp in SSO_CAP_DISPS and imm == 0x10:
                    string_reads.append(f"{hex(insn.address)}:sso_cap_cmp(+{disp:#x},0x10)")
        if insn.mnemonic == 'movzx' and '<' not in insn.op_str:
            ops = insn.operands
            if len(ops) == 2 and ops[1].type == X86_OP_MEM:
                width = ops[1].size
                if width == 2:
                    id_reads.append(f"{hex(insn.address)}:movzx_word")
    return {
        'func_rva': span[0],
        'func_len': span[1] - span[0],
        'string_reads': string_reads,
        'id_reads': id_reads,
        'callees': callees,
    }


def slots_of(img, vptr_rva, limit=64):
    """走到第一个 .pdata 函数起点不再前移为止(`vtable.py --first` 同口径的简化版)。"""
    out = []
    seen = set()
    for i in range(limit):
        q = img.qword(vptr_rva + i * 8)
        if q is None:
            break
        tgt = _rva_num(q)
        span = img.func_of(tgt)
        if span and span[0] == tgt:
            if tgt in seen:
                break
            seen.add(tgt)
            out.append((i * 8, tgt))
        # 非函数起点:继续看下一槽(vtable 里有非代码槽是常态)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--keyword')
    ap.add_argument('--create')
    ap.add_argument('--ci')
    args = ap.parse_args()
    img = Image(resolve_exe())

    ci_rva = create_rva = None
    if args.keyword:
        cols = tsv_row(args.keyword)
        ci_rva = int(cols[6], 16)
        # TSV 的 col[7] 是 field0_target(全表共享的 deleting destructor 0x34C090),
        # 不是 create。create 只能从 class_info 的第二个 qword 读(见 cinfo.py 的口径)。
        create_rva = create_from_class_info(img, ci_rva)
    elif args.create:
        create_rva = int(args.create, 16)
    elif args.ci:
        ci_rva = int(args.ci, 16)
        create_rva = create_from_class_info(img, ci_rva)
    else:
        ap.error('need --keyword, --create or --ci')

    size, vptrs = new_size_and_vptrs(img, create_rva)
    print(f"# keyword={args.keyword} class_info={hex(ci_rva) if ci_rva else '?'} "
          f"create={hex(create_rva)} new={hex(size) if size else '?'} "
          f"vptrs={[hex(v) for v in vptrs]}")
    print("slot_off\tslot_rva\tfunc_rva\tfunc_len\tstring_reads\tid_reads\tcallees")
    for vptr in vptrs:
        for off, tgt in slots_of(img, vptr):
            info = classify(img, tgt)
            if not info:
                continue
            sr = ';'.join(info['string_reads']) or '-'
            ir = ';'.join(info['id_reads']) or '-'
            cal = ' '.join(hex(c) for c in info['callees']) or '-'
            print(f"{off:#06x}\t{hex(vptr + off)}\t{hex(info['func_rva'])}\t"
                  f"{info['func_len']:#x}\t{sr}\t{ir}\t{cal}")


if __name__ == '__main__':
    main()
