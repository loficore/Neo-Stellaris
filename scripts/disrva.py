#!/usr/bin/env python3
"""Disassemble an RVA range of stellaris.exe offline, annotating every
rip-relative operand with the RVA it resolves to and every call target.

Usage: python scripts/disrva.py <start_rva_hex> [<count>|<length>|--end=<rva>|--len=<n>]

第二个参数的口径全部写在 `parse_range` 里:裸数字沿用历史启发式(`<=0xFF` 是**指令
条数**,`>0xFF` 是**字节长度**而不是结束 RVA —— §30 就是在这一条上读错过),
`--end=<rva>` / `--len=<n>` 是 §59.9 起才有的显式形式。

**导入本模块没有副作用**:既不读 46 MB 镜像,也不 `sys.exit`
(`scripts/test_disrva.py` 只要 `import disrva` 就能用纯函数 `parse_range` 与
`resolve_exe`)。镜像在第一次真要取字节时才打开(`_image()`)。
"""
import sys, os, struct, re

BASE = 0x140000000
DEFAULT_INSN = 80        # 无第二参时的指令条数(历史默认值)
INSN_MAX = 15            # x86-64 一条指令的最长编码(前缀+opcode+modrm+sib+disp+imm)
FETCH_PER_INSN = 16      # 历史每条取 16 字节,原样保留 => 旧读数逐字节可复现

RIP = re.compile(r'\[(?:rip|eip)\s*([+-])\s*(0x[0-9a-f]+)\]', re.I)

CANDIDATES = [os.environ.get('NS_STELLARIS_EXE'),
              '/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe',
              r'D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe']


def resolve_exe():
    """候选链里第一个存在的 stellaris.exe;全都不存在就返回 None(绝不 sys.exit)。"""
    for c in CANDIDATES:
        if c and os.path.exists(c):
            return c
    return None


_image_state = None


def _image():
    """(exe_path, image_bytes, sections) —— 懒加载,取代旧的模块级读取与退出。"""
    global _image_state
    if _image_state is None:
        exe = resolve_exe()
        if exe is None:
            return None
        f = open(exe, 'rb').read()
        mz = struct.unpack_from('<I', f, 0x3c)[0]
        nsec = struct.unpack_from('<H', f, mz + 6)[0]
        nsec_off = mz + 24 + struct.unpack_from('<H', f, mz + 20)[0]
        secs = []
        for i in range(nsec):
            o = nsec_off + i * 40
            nm = f[o:o + 8].split(b'\0')[0].decode('latin1')
            vs, va, rawsz, praw = struct.unpack_from('<IIII', f, o + 8)
            ch = struct.unpack_from('<I', f, o + 36)[0]
            secs.append((nm, va, vs, rawsz, praw, ch))
        _image_state = (exe, f, secs)
    return _image_state


def rd(rva, n):
    _exe, f, secs = _image()
    for nm, va, vs, rawsz, praw, ch in secs:
        if va <= rva < va + max(vs, rawsz):
            off = praw + rva - va
            return f[off:off + n], nm
    return b'', '?'


def _num(value, what):
    """一个数字 token 按十六进制解析(与历史 `int(tok, 16)` 同口径);不可判就拒绝。"""
    try:
        n = int(value, 16)
    except ValueError:
        raise ValueError(f'{what}不是十六进制数:{value!r}') from None
    if n < 0:
        raise ValueError(f'{what}为负数:{value!r}')
    return n


def parse_range(start_tok, second_tok):
    """两个原始 CLI *token* -> (begin_rva, end_rva, mode)。

    纯函数:不读文件、不碰 `sys.argv`、不做 argparse 式的多参拼接 —— 第二个参数若
    是 `--end=0x1D09330` 就整串是一个 token。mode 四种:

      "count"      无第二参,或裸数字 `<= 0xFF`:那是**指令条数**。此时
                   `end_rva = begin + 条数 * INSN_MAX` 只是**估算上界**,仅供取字节
                   用,不是函数边界(要边界用 `pdata.py`)。
      "legacy_len" 裸数字 `> 0xFF`:那是**字节长度**,不是结束 RVA。历史口径,
                   不改写 —— 取证卷里的旧命令要能原样复现。
      "end"        显式 `--end=<rva>`:`end_rva` 就是那个 RVA。
      "len"        显式 `--len=<n>`:字节长度,与 "legacy_len" 同算法,只是写明意图。

    任何不可判的形态一律 `ValueError`(拒绝),绝不静默退化成某种猜测。
    """
    begin = _num(start_tok, '起始 RVA ')
    if second_tok is None:
        return begin, begin + DEFAULT_INSN * INSN_MAX, 'count'
    if second_tok.startswith('--'):
        flag, sep, val = second_tok.partition('=')
        if not sep:
            raise ValueError(f'缺少数值:{second_tok!r}(应为 --end=<rva> 或 --len=<n>)')
        if flag == '--end':
            end = _num(val, '--end 的 RVA ')
            if end < begin:
                raise ValueError(f'--end=0x{end:x} below start 0x{begin:x}')
            return begin, end, 'end'
        if flag == '--len':
            return begin, begin + _num(val, '--len 的长度 '), 'len'
        raise ValueError(f'无法判定第二个参数:{second_tok!r}')
    a = _num(second_tok, '第二参数 ')
    if a > 0xFF:                       # 历史启发式:大数 = 字节长度
        return begin, begin + a, 'legacy_len'
    return begin, begin + a * INSN_MAX, 'count'


def main():
    if len(sys.argv) < 2:
        print('[disrva] 用法:disrva.py <start_rva> '
              '[<count>|<length>|--end=<rva>|--len=<n>]', file=sys.stderr)
        sys.exit(2)
    exe = resolve_exe()
    if exe is None:
        print('[disrva] 没有可读的 stellaris.exe 拷贝(设 NS_STELLARIS_EXE);'
              f'候选链 {", ".join(str(c) for c in CANDIDATES)}', file=sys.stderr)
        sys.exit(2)
    try:
        start, end, mode = parse_range(sys.argv[1],
                                       sys.argv[2] if len(sys.argv) > 2 else None)
    except ValueError as exc:
        print(f'[disrva] {exc}', file=sys.stderr)
        sys.exit(2)

    # count 模式按 (end-start)/INSN_MAX 还原条数,并保留历史的每条 16 B 取字节,
    # 使改动前的读数逐字节不变;其余模式 end 就是真边界。
    cnt = (end - start) // INSN_MAX if mode == 'count' else None
    n_bytes = cnt * FETCH_PER_INSN if cnt is not None else end - start

    code, sec = rd(start, n_bytes)
    print(f'; {os.path.basename(exe)}  {sec} RVA 0x{start:x}'
          + (f'-0x{end:x}' if cnt is None else f'  ({cnt} insns)'))
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    n = 0
    for ins in md.disasm(code, BASE + start):
        if cnt is None and ins.address >= BASE + end:
            break
        note = ''
        m = RIP.search(ins.op_str)
        if m:
            d = int(m.group(2), 16)
            t = ins.address + ins.size + (d if m.group(1) == '+' else -d)
            note = f'  ; -> 0x{t - BASE:x}'
        elif ins.mnemonic in ('call', 'jmp') and ins.op_str.startswith('0x'):
            note = f'  ; -> 0x{int(ins.op_str, 16) - BASE:x}'
        print(f'  {ins.address - BASE:08x}  {ins.mnemonic:<7} {ins.op_str}{note}')
        n += 1
        if cnt and n >= cnt:
            break


if __name__ == '__main__':
    # 历史的 UTF-8 重配置放在 CLI 入口而不是 main() 里:import 本模块的人
    # (纯函数、或把 main() 嵌进自己流程的脚本)不该被动改掉 stdout。
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    main()
