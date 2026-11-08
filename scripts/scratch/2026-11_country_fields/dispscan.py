#!/usr/bin/env python3
"""一次性扫描:在 .text 里找所有 `[reg + disp]` 访存,disp 取自命令行参数。

属于 `evidence/analysis/country_fields_4_4_4.md` 的 §1/§2(不是维护中工具,不进
`docs/offline-tooling.md`)。存在的理由:`disrva.py` 只反汇编一段;要判「某个对象
偏移被哪一族代码读/写」必须全量扫 `.text`,而 `.pdata` 是唯一可靠的函数起点集合
(见 `vptrslots.py` 的 docstring:窗口重新同步会发明指令)。

用法:
    python3 scripts/scratch/2026-11_country_fields/dispscan.py 0x2530 0x2570 0x2c68

输出每行:`func_rva  insn_rva  disp  read/write  mnemonic  op_str`。
解码**只从 `.pdata` 的每个函数起点对齐开始**,不跨函数拼接。
"""
import bisect
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_READ, CS_AC_WRITE
from capstone.x86 import X86_OP_MEM

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

EXE = os.environ.get('NS_STELLARIS_EXE',
                     '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe')
BASE = 0x140000000

with open(EXE, 'rb') as _fh:
    F = _fh.read()
_mz = struct.unpack_from('<I', F, 0x3c)[0]
_nsec = struct.unpack_from('<H', F, _mz + 6)[0]
_no = _mz + 24 + struct.unpack_from('<H', F, _mz + 20)[0]

SECS = []
for _i in range(_nsec):
    _o = _no + _i * 40
    _nm = F[_o:_o + 8].split(b'\0')[0].decode('latin1')
    _vs, _va, _rsz, _rp = struct.unpack_from('<IIII', F, _o + 8)
    SECS.append((_nm, _va, _rsz, _rp))


def section(name):
    return next(s for s in SECS if s[0] == name)


def funcs():
    nm, va, rsz, rp = section('.pdata')
    raw = F[rp:rp + rsz]
    out = []
    for i in range(0, len(raw) - 11, 12):
        b, e = struct.unpack_from('<II', raw, i)
        out.append((b, e))
    out.sort()
    return out


def main(argv):
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    wanted = {int(a, 16) for a in argv}
    nm, va, rsz, rp = section('.text')
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    hits = 0
    for b, e in funcs():
        if not (va <= b < va + rsz) or e <= b:
            continue
        code = F[rp + b - va: rp + min(e, va + rsz) - va]
        for ins in md.disasm(code, BASE + b):
            for op in ins.operands:
                if op.type != X86_OP_MEM or op.mem.disp & 0xffffffffffffffff not in (wanted | {d - (1 << 64) for d in wanted}):
                    continue
                if op.mem.base == 0 and op.mem.index == 0:
                    continue  # 绝对地址,不是对象字段
                rw = 'W' if op.access & CS_AC_WRITE else ('R' if op.access & CS_AC_READ else '?')
                print(f'func 0x{b:x}  insn 0x{ins.address - BASE:x}  '
                      f'disp {op.mem.disp & 0xffffffffffffffff:#x}  {rw}  '
                      f'{ins.mnemonic} {ins.op_str}')
                hits += 1
    print(f'; {hits} hits for ' + ' '.join(argv), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
