#!/usr/bin/env python3
"""exec_frame_sites —— 按字节反解 CEffect::Execute 调用点的**真实站点**,不是 -5 估值。

背景(§59.7):实机 shot 记录的是**返回 RVA**。旧产物把 `return_rva - 5` 当站点写进
caller 行,于是 3 B 的 `call qword ptr [rax+8]`(每一次 vtable 槽派发都是这个形状)
的站点被画进前一条指令中间,census join 落空,`func=-` 被误读成「没人调用」。
`c2_scope_probe.py` 已把 caller 行键改为返回 RVA、`-5` 降级为 `est_site=`;**精确站点由本工具离线反解**:
重读 exe 拷贝里返回 RVA 前面的字节,枚举真正能「恰好结束于返回点」的 call/jmp 编码边界。

用法(下面就是默认路径的跑法,不传参即读同一组取证产物):

    python3 scripts/exec_frame_sites.py --probe evidence/logs/scope_probe_v4_4_4_4.tsv \
        [--census evidence/xrefs/exec_frame_callers_4_4_4.tsv] \
        [--out evidence/xrefs/exec_frame_sites_4_4_4.tsv]

产物 TSV:头行 `# ret_rva<TAB>count<TAB>site_rva<TAB>form<TAB>insn<TAB>func_start
<TAB>func_end<TAB>census_origin<TAB>site_in_census`,数据行,再接 `write_tsv` 同款
`# kind<TAB>key<TAB>value<TAB>detail` 汇总块(resolved / ambiguous / none / mem_form /
assumed 计数 + 输入出处)。

**候选边界怎么枚举**(不许盲信从指令中间开始的解码):对回看窗
`[return_rva - SITE_WINDOW, return_rva)` 内的**每一个字节偏移** s 起解码 capstone 的
第一条指令;只保留「指令长度恰好为 `return_off - s`」(即**结束地址正好落在返回点**)
且 `mnemonic ∈ {call, jmp}` 的候选。从指令中间开始的错位解码若碰不出一条恰好收尾的
call/jmp 就会被丢弃;碰得出来的就是真实存在的边界歧义(例:REX 重叠
`48 FF 50 08` / `FF 50 08`),此时**不选最短也不选最长** —— `form=ambiguous`、
`site=None`,把判读留给取证卷。

`form` 词汇表(五档,不多不少):
  rel32    候选是 `E8 rel32`(5 B),且目标首字节不是跳板;
  mem      候选是 `FF /2`(`call qword ptr [...]`;寄存器间接 `FF D0` 同档,insn 列给真实反汇编);
  thunk    `E8` 的目标首字节是 `EB`/`E9`(跳板),或候选本身就是一条 `jmp`;
  ambiguous 候选 >1,站点不可判;
  none     回看窗内没有任何 call/jmp 边界 —— **只说明窗口内没有,不等于没人调用**(判读陷阱 11)。

**拒绝语义(任何不可判 = 拒绝,绝不静默降级)**:
  - 没有可读的 exe 拷贝(`resolve_exe()` 为 None)→ 一行 `[exec_frame_sites] …` stderr、退出码 2,无 traceback;
  - `pdata` import/查找失败 → 同口径诊断退出,不是静默 `func=-`;
  - 覆盖候选边界的前 SITE_WINDOW 字节读不出来 → `SiteDecodeError`(main 转成诊断退出);
    返回点**之后**的字节只是尽力多读(读满 SITE_WINDOW+64),缺失不拒绝 —— 唯一被
    拒绝的情形就是回看窗本身不完整。

exe 字节只读一次(`make_reader` 解析 PE 段表后按段映射);`resolve_exe` 从
`disrva` import 复用候选链,**不复制它的 BASE 常量** —— 本工具全部地址运算都在 RVA
空间做(rel32 目标 = site + size + disp32,镜像基址在减法里对消),不需要镜像基址。

census 解析复用 `c2_scope_probe.load_call_census`;但该模块顶层 `from c2_harness
import ...` 把 Windows 侧依赖一起拖进来,在缺它的机器上 import 会炸 —— 故本文件带一
份同样语义的 6 列 TSV 解析(`_load_call_census_local`)作 fallback,只在该 import 真的
失败时才用。两份实现语义相同:census 头 7 列(首行 `#`),取 col0=func_start、
col4=site、col5=rdx_origin。
"""
import argparse
import os
import re
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from disrva import CANDIDATES, resolve_exe   # 候选链 + NS_STELLARIS_EXE 的唯一出处(不复制第二份路径表)

SITE_WINDOW = 16                   # 回看字节数:一条 x64 指令最长 15 B,16 B 窗口必然罩住紧邻边界
FORWARD_BYTES = 64                 # 返回点之后尽力多读:让错位解码有完整上下文(census/pdata 不依赖它)
INSN_MAX = 15                      # x86-64 最长编码;取字节只需 SITE_WINDOW+INSN_MAX
DEFAULT_CENSUS = "evidence/xrefs/exec_frame_callers_4_4_4.tsv"
DEFAULT_OUT = "evidence/xrefs/exec_frame_sites_4_4_4.tsv"

_PREFIX_BYTES = frozenset({0x26, 0x2E, 0x36, 0x3A, 0x3E, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
                          | set(range(0x40, 0x50)))
_JMP_STUB_OPCODES = (0xEB, 0xE9)   # jmp rel8 / jmp rel32:call 目标首字节是这两个 ⇒ thunk

_MD = None


def _md():
    """capstone 句柄,一次 `Cs(CS_ARCH_X86, CS_MODE_64)`,与测试模块同配置。"""
    global _MD
    if _MD is None:
        _MD = Cs(CS_ARCH_X86, CS_MODE_64)
    return _MD


class SiteDecodeError(Exception):
    """回看窗读不出来/解不出来 —— 拒绝,而不是把「没读到」写成 `form=none`。"""


def make_reader(exe_path):
    """读一次 exe,解析 PE 段表,返回 `read(rva, n) -> bytes | None`(按段映射)。

    None 的口径:RVA 为负、不在任何段的虚拟区间内、或 n 字节不能同时落在该段的
    文件原始数据里。**不取镜像基址** —— 一切运算在 RVA 空间,基址会对消。
    """
    with open(exe_path, "rb") as f:
        image = f.read()
    mz = struct.unpack_from("<I", image, 0x3C)[0]
    nsec = struct.unpack_from("<H", image, mz + 6)[0]
    tab = mz + 24 + struct.unpack_from("<H", image, mz + 20)[0]
    secs = []
    for i in range(nsec):
        o = tab + i * 40
        # PE 段表在 o+8 处的序是 VirtualSize **先**、VirtualAddress 后(与 disrva 同口径);
        # 读反了会把 .text 的界错拼成 (0x2390710, 0x1000),每个读都落在界外被拒绝。
        vs, va, rawsz, praw = struct.unpack_from("<IIII", image, o + 8)
        secs.append((va, vs, rawsz, praw))

    def read(rva, n):
        if rva < 0 or n <= 0:
            return None
        for va, vs, rawsz, praw in secs:
            if va <= rva < va + vs and rva + n <= va + rawsz:
                off = praw + rva - va
                return image[off:off + n]
        return None
    return read


def _boundary_insns(win, return_off, md, base=0):
    """逐偏移枚举边界:对 s ∈ [0, return_off) 解码第一条指令,保留「结束地址恰好
    等于 return_off」且 mnemonic ∈ {call, jmp} 的 (s, insn)。base 让 op_str 直接落在 RVA 空间。"""
    out = []
    for s in range(return_off):
        for ins in md.disasm(win[s:s + INSN_MAX], base + s):
            if ins.address - base + ins.size == return_off and ins.mnemonic in ("call", "jmp"):
                out.append((s, ins))
            break                        # 只要从 s 起的第一条;解不出来(非法/截断)就跳过
    return out


def candidate_call_sites(win, return_off, md):
    """窗口内所有「恰好结束于 `return_off`」的 call/jmp 边界 → [(win 内起始偏移, mnemonic)]。"""
    return [(s, ins.mnemonic) for s, ins in _boundary_insns(win, return_off, md)]


def _opcode_index(win, off):
    i = off
    while i < len(win) and win[i] in _PREFIX_BYTES:
        i += 1
    return i


def resolve_call_site(return_rva, read):
    """返回 {"site": int|None, "form": rel32|mem|thunk|ambiguous|none, "insn": str|None}。

    内部即「`read(return_rva - SITE_WINDOW, SITE_WINDOW + 64)` → `candidate_call_sites`」
    加 form 判读;回看窗读不满(前 SITE_WINDOW 字节缺任何一个)→ `SiteDecodeError`。
    """
    start = return_rva - SITE_WINDOW
    win = None if start < 0 else read(start, SITE_WINDOW)
    if win is None:
        raise SiteDecodeError(
            f"返回 RVA 0x{return_rva:x} 的回看窗(0x{start:x} 起 {SITE_WINDOW} B)读不出来 —— 拒绝,"
            "这不是 `none`(读不出来 ≠ 窗口里没有)")
    # 返回点之后的 64 B 只是给错位解码多读的上下文,读不满不拒绝(边界判定只看回看窗);
    # 但回看窗本身缺任何一个字节都必须拒绝,否则 `none` 会说谎。
    forward = read(start, SITE_WINDOW + FORWARD_BYTES)
    if forward is not None:
        win = forward
    md = _md()
    cands = _boundary_insns(win, SITE_WINDOW, md, base=start)
    if not cands:
        return {"site": None, "form": "none", "insn": None}
    if len(cands) > 1:
        listing = "; ".join(f"0x{start + s:x} {ins.mnemonic} {ins.op_str}" for s, ins in cands)
        return {"site": None, "form": "ambiguous", "insn": listing}
    off, ins = cands[0]
    site = start + off
    insn_text = f"{ins.mnemonic} {ins.op_str}"
    op_i = _opcode_index(win, off)
    opcode = win[op_i] if op_i < len(win) else None

    if ins.mnemonic == "call":
        if opcode == 0xE8:                       # call rel32:disp32 在 op_i+1..op_i+4
            disp = int.from_bytes(win[op_i + 1:op_i + 5], "little", signed=True)
            target = site + ins.size + disp
            head = read(target, 1)
            form = "thunk" if head and head[0] in _JMP_STUB_OPCODES else "rel32"
        elif opcode == 0xFF:                     # FF /2:call qword ptr [...] / call reg
            form = "mem"
        else:                                    # 词汇表之外的 call 编码:拒绝,不硬塞一档
            raise SiteDecodeError(
                f"0x{site:x} 处 call 编码无法判定(opcode 0x{opcode:02x})—— 拒绝")
        return {"site": site, "form": form, "insn": insn_text}
    # 唯一边界是 jmp:它本身不产生返回地址,记录到返回点的只能是被重打的跳板形状 ⇒ thunk
    return {"site": site, "form": "thunk", "insn": insn_text}


def parse_probe_caller_rows(path):
    """shot 产物的 caller 行 → [{"ret": int, "count": int, "assumed": bool}]。

    新版 `c2_scope_probe.py` 的行 detail 带 `ret=0x…`,直接用;v4 及更早键是 `ret-5` 估值,
    `ret = key + 5` 且 `assumed=True`(站点最终由本工具反解,估值只用于对账)。
    """
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            if line.startswith("#") or not line.strip():
                continue
            cols = line.rstrip("\n").split("\t")
            if cols[0] != "caller":
                continue
            if len(cols) < 3:
                raise ValueError(f"{path}:{lineno}: caller 行列数不足:{line!r}")
            detail = cols[3] if len(cols) > 3 else ""
            m = re.search(r"\bret=(0x[0-9a-fA-F]+)", detail)
            if m:
                rows.append({"ret": int(m.group(1), 16), "count": int(cols[2]),
                             "assumed": False})
            else:
                rows.append({"ret": int(cols[1], 16) + 5, "count": int(cols[2]),
                             "assumed": True})
    return rows


def frame_rows(rows, resolve, func_of, census):
    """每行 join .pdata 函数边界与 census(键是**反解出的真站点**,不是估值)。

    站点不可判(ambiguous/none)时 `func_start`/`func_end` 退回用返回 RVA 查 ——
    返回地址与调用点同在一个 RUNTIME_FUNCTION 内,函数归属仍是 datum;
    census 两列则只认真站点(`site_in_census=0` 诚实表达「没 join 上」,不解释原因)。
    """
    out = []
    for r in rows:
        res = resolve(r["ret"])
        site = res["site"]
        fx = func_of(site if site is not None else r["ret"])
        hit = census.get(site) if site is not None else None
        out.append({
            "ret": r["ret"], "count": r["count"], "site": site,
            "form": res["form"], "insn": res["insn"],
            "func_start": fx[0] if fx else None,
            "func_end": fx[1] if fx else None,
            "census_origin": hit["origin"] if hit else "-",
            "site_in_census": 1 if hit else 0,
        })
    return out


def _hx(v):
    return "-" if v is None else f"0x{v:x}"


def write_sites_tsv(path, framed, rows, meta):
    """头行 + 数据行 + `write_tsv` 同款汇总块(# kind\tkey\tvalue\tdetail,meta 行)。"""
    counts = {
        "resolved": sum(1 for r in framed if r["site"] is not None),
        "ambiguous": sum(1 for r in framed if r["form"] == "ambiguous"),
        "none": sum(1 for r in framed if r["form"] == "none"),
        "mem_form": sum(1 for r in framed if r["form"] == "mem"),
        "assumed": sum(1 for r in rows if r["assumed"]),
    }
    with open(path, "w", encoding="utf-8") as f:
        f.write("# ret_rva\tcount\tsite_rva\tform\tinsn\tfunc_start\tfunc_end"
                "\tcensus_origin\tsite_in_census\n")
        for r in framed:
            f.write("\t".join([_hx(r["ret"]), str(r["count"]), _hx(r["site"]), r["form"],
                               r["insn"] or "-", _hx(r["func_start"]), _hx(r["func_end"]),
                               r["census_origin"], str(r["site_in_census"])]) + "\n")
        f.write("# kind\tkey\tvalue\tdetail\n")
        for key in ("resolved", "ambiguous", "none", "mem_form", "assumed"):
            f.write(f"meta\t{key}\t{counts[key]}\t-\n")
        for key, value in meta.items():
            f.write(f"meta\t{key}\t{value}\t-\n")
    return counts


def _load_census(path):
    """census 优先复用 `c2_scope_probe.load_call_census`;import 失败(Windows 侧依赖
    `c2_harness` 被顶层拖进来)才落到本文件的同款解析 —— 见模块 docstring。"""
    try:
        from c2_scope_probe import load_call_census
    except Exception:
        return _load_call_census_local(path)
    return load_call_census(path)


def _load_call_census_local(path):
    """同款 6 列 TSV 解析:{site: {"func": int|None, "origin": str}}(跳注释/空行/坏行)。"""
    out = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            cols = line.rstrip("\n").split("\t")
            if len(cols) < 6:
                continue
            try:
                site = int(cols[4], 16)
                func = int(cols[0], 16)
            except ValueError:
                continue
            out[site] = {"func": func, "origin": cols[5]}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="exec_frame_sites.py",
        description="按字节反解 shot 记录的返回 RVA 的真实 call site,join .pdata 与 census。")
    ap.add_argument("--probe", required=True, help="实机产物 TSV(caller 行)")
    ap.add_argument("--census", default=DEFAULT_CENSUS)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    exe = resolve_exe()
    if exe is None:
        print("[exec_frame_sites] 没有可读的 stellaris.exe 拷贝(设 NS_STELLARIS_EXE);"
              f"候选链 {[str(c) for c in CANDIDATES]}", file=sys.stderr)
        return 2
    try:
        rows = parse_probe_caller_rows(args.probe)
    except (OSError, ValueError) as exc:
        print(f"[exec_frame_sites] 读不了 probe {args.probe}:{exc}", file=sys.stderr)
        return 2
    try:
        import pdata                    # 顶层即读 exe —— 必须延迟 import 并把失败变成诊断
        func_of = pdata.func_of
    except Exception as exc:
        print("[exec_frame_sites] .pdata 查找不可用(pdata import 失败):"
              f"{type(exc).__name__}: {exc};设 NS_STELLARIS_EXE 指向 exe 拷贝后重试",
              file=sys.stderr)
        return 2
    try:
        census = _load_census(args.census)
    except OSError as exc:
        print(f"[exec_frame_sites] 读不了 census {args.census}:{exc}", file=sys.stderr)
        return 2

    read = make_reader(exe)
    try:
        framed = frame_rows(rows, lambda ret: resolve_call_site(ret, read), func_of, census)
    except SiteDecodeError as exc:
        print(f"[exec_frame_sites] {exc}", file=sys.stderr)
        return 2

    meta = {"probe": args.probe, "census": args.census, "exe": exe, "rows": len(framed)}
    counts = write_sites_tsv(args.out, framed, rows, meta)
    for r in framed:
        print(f"0x{r['ret']:x} site={_hx(r['site'])} form={r['form']} "
              f"func={_hx(r['func_start'])}..{_hx(r['func_end'])} "
              f"census_origin={r['census_origin']} site_in_census={r['site_in_census']}")
    print(f"rows={len(framed)} resolved={counts['resolved']} ambiguous={counts['ambiguous']} "
          f"none={counts['none']} mem_form={counts['mem_form']} assumed={counts['assumed']} "
          f"-> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
