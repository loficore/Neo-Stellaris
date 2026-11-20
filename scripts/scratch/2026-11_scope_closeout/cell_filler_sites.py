#!/usr/bin/env python3
"""cell_filler_sites —— scope cell 的 `+0x1c`(缓存指针)/`+0x14`(内联对象指针)写点普查。

usage: python3 scripts/scratch/2026-11_scope_closeout/cell_filler_sites.py [--json OUT]

一次性的离线探针(只读 exe 拷贝,零实机),服务 `runtime_444_scope_tables_4_4_4.md`
§4.4 第 3 条:已知的 `0x394200` 只**建 cell**(抄 id → 两槽清零 → 写 mask `0x20`),
**填充**方未读。本探针不按地址找,按**形态**扫 `.text` 整段(0x2390800 B)。

形态口径(长度与 ModRM/SIB 一起看,不按助记符猜):

    命中 A   `mov qword ptr [base + 0x1c], reg`      ; 8 B 写 = §2.0 的缓存指针槽
    命中 B   `mov qword ptr [base + 0x14], reg`      ; 8 B 写 = 内联对象槽
    反例 C   `mov dword ptr [base + 0x1c|0x14], r32` ; 4 B 写 —— 另一个字段(可能别的类)
    反例 D   `mov qword ptr [base + 0x1c|0x14], imm` ; 立刻数,常是清零

**判读写别用 `insn.regs_write`**:本环境该属性恒空(见
`scripts/scratch/2026-10_exec_frame_census/README.md` 第三个坑),第一版会因此把
一切「对槽的写」读成 0 —— 一个「太干净」的 0 先怀疑检测器。本探针更退一步:用
`disasm_lite`(不带 detail)**只读 `op_str` 文本**,把操作数尺寸/位移/基址从
`qword ptr [rcx + 0x1c], rax` 这种逐字串里取。第一版用 `detail=True` 全段线性解码,
在本机跑了 >4 min 还没出第一行,开场即放弃(`disasm_lite` 全段约 10 s)。

分桶:`.pdata`(130,645 条)优先;`0x394190`/`0x394200`/`0x394e60` 这一族是**叶子函数,
没有 `.pdata` 条目** —— 对它们退化成「线性解码的连续段」:段首 = 上一条 `ret` 之后第一个
非 `int3` 指令,段尾 = 本段最后一条非 `int3` 指令。`skipdata` 的伪指令(`db`)意味着
脱 Sync,直接切断当前段(否则一个错位会把后面整段归错函数)。

三层筛(§4.4 第 3 条 + 计划 Review Focus 3),三条**同时**满足才算候选:

    ① 类型门:同段里有 `cmp/test qword ptr [base + 0x8], ...`(mask 门,与 getter 同形)
    ② 对象来源:同段里有 `mov <r32>, dword ptr [base + 0x10]`(读 cell 的 id)或
       `mov dword ptr [base + 0x10], <r32>`(抄 id,与 `0x394200` 同形)—— 两者都记,
       判词里写清候选走的是哪一条
    ③ 槽的写:命中 A/B 的基址寄存器与 ①/② 相同,且源寄存器**不是**同段 `xor r,r` /
       `mov r,0` 之后未再被写过的零值(那是清零,不是填充)

`0x394200` 必须被 ③ 排除 —— 这是**探针自检**:若第一轮只剩它,说明筛子把真候选一起
滤掉了(口径错),不是「找到了」。
"""
from __future__ import annotations

import bisect
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
import pdata  # noqa: E402  (导入即读 exe 段表 + .pdata;46 MB,一次性)

from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402

CACHE_SLOT = "0x1c"
INLINE_SLOT = "0x14"

ADDR = r"\[(r[a-z0-9]+)(?: \+ (r[a-z0-9]+))? \+ (0x1c|0x14)\]"
R_SLOT_Q = re.compile(r"^qword ptr " + ADDR + r", (r[a-z0-9]+)$")
R_SLOT_D = re.compile(r"^dword ptr " + ADDR + r", (e[a-z]+|r\d+d)$")
R_SLOT_I = re.compile(r"^qword ptr " + ADDR + r", (0x[0-9a-f]+)$")
# 命中 F:先 `lea rX, [base + 0x1c|0x14]`,再经 rX 存 —— 目的操作数是裸 [rX],位移不出现在这条指令里
R_SLOT_F = re.compile(r"^qword ptr \[(r[a-z0-9]+)\], (r[a-z0-9]+)$")
R_LEA = re.compile(r"^(r[a-z0-9]+), \[(r[a-z0-9]+)(?: \+ (r[a-z0-9]+))? \+ (0x1c|0x14)\]$")
# 命中 E:16 B 向量写落在 +0x14,一条指令**同时**覆盖 +0x14 与 +0x1c 两个槽
R_SLOT_V = re.compile(r"^(?:xmmword|oword) ptr " + ADDR + r", (xmm[0-9]+)$")
R_GATE = re.compile(r"^qword ptr \[(r[a-z0-9]+) \+ 8\], ")
# 「写 mask」形态(构造器/填充方):`mov qword ptr [base + 8], <imm>` —— 与「判 mask」(cmp)分开
R_MASK_W = re.compile(r"^qword ptr \[(r[a-z0-9]+)(?: \+ (r[a-z0-9]+))? \+ 8\], (0x[0-9a-f]+)$")
R_ID_W = re.compile(r"^dword ptr \[(r[a-z0-9]+) \+ 0x10\], (e[a-z]+|r\d+d)$")
R_ID_R = re.compile(r"^(e[a-z]+|r\d+d), dword ptr \[(r[a-z0-9]+) \+ 0x10\]$")

_FULL = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
         "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp"}


def full_reg(name):
    """`eax`→`rax`、`r8d`→`r8`;64 位名原样返回。`xor eax,eax` 清的是整个 `rax`。"""
    if name in _FULL:
        return _FULL[name]
    if len(name) > 2 and name[0] == "r" and name[-1] == "d" and name[1].isdigit():
        return name[:-1]
    return name


def text_section():
    """(.text bytes, 其 RVA) —— 复用 pdata 已经解析好的段表,不重复解析 PE。"""
    for nm, va, rsz, rp in pdata.secs:
        if nm == ".text":
            return pdata.f[rp:rp + rsz], va
    raise SystemExit("[cell_filler_sites] 没有 .text 段")


class Chunk:
    """一段连续代码(`.pdata` 函数,或叶子函数的解码连续段)的特征累计。"""

    __slots__ = ("start", "end", "pdata", "hits", "dword_hits", "imm_hits",
                 "mask_gate_bases", "id_read_bases", "id_write_bases", "zeroed",
                 "vec_hits", "ptr_hits", "slot_ptr", "mask_write")

    def __init__(self, start, is_pdata):
        self.start = start
        self.end = start
        self.pdata = is_pdata
        self.hits = []          # (rva, slot, base, src, src_was_zero)
        self.dword_hits = []    # (rva, slot, base)
        self.imm_hits = []      # (rva, slot, imm_text)
        self.vec_hits = []      # (rva, slot, base, xmm) —— 16 B 写,覆盖两个槽
        self.ptr_hits = []      # (rva, slot, base, src, src_zero) —— 经 lea 指针的写
        self.slot_ptr = {}      # 寄存器 -> (slot, base):最近一次 `lea rX,[base+slot]` 还活着
        self.mask_write = {}    # base 寄存器 -> 写进 [base+8] 的 mask 立刻数
        self.mask_gate_bases = set()
        self.id_read_bases = set()
        self.id_write_bases = set()
        self.zeroed = set()

    def as_dict(self):
        return {
            "start": hex(self.start), "end": hex(self.end), "pdata": self.pdata,
            "hits": [[hex(a), s, b, c, z] for a, s, b, c, z in self.hits],
            "dword_hits": [[hex(a), s, b] for a, s, b in self.dword_hits],
            "imm_hits": [[hex(a), s, v] for a, s, v in self.imm_hits],
            "vec_hits": [[hex(a), s, b, x] for a, s, b, x in self.vec_hits],
            "ptr_hits": [[hex(a), s, b, c, z] for a, s, b, c, z in self.ptr_hits],
            "mask_write": {k: hex(v) for k, v in self.mask_write.items()},
            "mask_gate_bases": sorted(self.mask_gate_bases),
            "id_read_bases": sorted(self.id_read_bases),
            "id_write_bases": sorted(self.id_write_bases),
        }


def scan():
    code, va = text_section()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True

    starts = pdata.STARTS
    bounds = pdata.funcs
    chunks = {}
    cur = None
    pending_new = True
    db_bytes = db_runs = 0

    for addr, size, mn, op_str in md.disasm_lite(code, va):
        i = bisect.bisect_right(starts, addr) - 1
        in_pd = i >= 0 and addr < bounds[i][1]
        if mn == "db":                          # 脱 Sync:切断,别把后面归错函数
            if cur is None:
                db_runs += 1
            db_bytes += size
            cur = None
            pending_new = True
            continue
        if in_pd and addr == bounds[i][0]:
            pending_new = True
        if mn == "int3":
            if not in_pd:
                pending_new = True
            continue
        if pending_new or cur is None:
            if cur is not None:
                chunks.setdefault(cur.start, cur)
            cur = Chunk(addr, in_pd)
            pending_new = False
        cur.end = addr + size

        # 零值跟踪(先判本条是不是写这个寄存器)。
        # 第一版这里拿 `R_XOR.match(op_str.replace(" ", ""))` 去比 `^(e[a-z]+|r\d+d), \1$`
        # —— 去掉空格后模式里的 ", " 永远不匹配,于是 `xor eax,eax` 从未被记成零值,
        # 自检靶 `0x394200` 的 `mov [rcx+0x1c], rax` 被判成「非清零填充」。
        # 现在按 `, ` 切操作数比字符串,不信任何正则的空白假设。
        parts = [p.strip() for p in op_str.split(",")]
        dest = parts[0]
        if parts and "[" not in dest and re.fullmatch(r"e[a-z]+|r[a-z0-9]+", dest):
            d = full_reg(dest)
            is_zero = ((mn == "xor" and len(parts) == 2 and parts[0] == parts[1])
                       or (mn == "mov" and len(parts) == 2 and parts[1] in ("0", "0x0")))
            if is_zero:
                cur.zeroed.add(d)
            else:
                cur.zeroed.discard(d)
            if mn != "lea":
                cur.slot_ptr.pop(d, None)

        if mn != "mov":
            if mn in ("cmp", "test"):
                m = R_GATE.match(op_str)
                if m:
                    cur.mask_gate_bases.add(m.group(1))
            continue

        m = R_MASK_W.match(op_str)
        if m:
            cur.mask_write[m.group(1)] = int(m.group(3), 16)
            continue
        m = R_LEA.match(op_str)
        if m:
            cur.slot_ptr[m.group(1)] = (m.group(4), m.group(2))
            continue
        m = R_SLOT_F.match(op_str)
        if m:
            slotbase = cur.slot_ptr.get(m.group(1))
            if slotbase is not None:
                cur.ptr_hits.append((addr, slotbase[0], slotbase[1], m.group(2),
                                     full_reg(m.group(2)) in cur.zeroed))
            continue
        m = R_SLOT_V.match(op_str)
        if m:
            cur.vec_hits.append((addr, m.group(3), m.group(1), m.group(4)))
            continue
        m = R_SLOT_Q.match(op_str)
        if m:
            base, slot, src = m.group(1), m.group(3), m.group(4)
            cur.hits.append((addr, slot, base, src, full_reg(src) in cur.zeroed))
            continue
        m = R_SLOT_D.match(op_str)
        if m:
            cur.dword_hits.append((addr, m.group(3), m.group(1)))
            continue
        m = R_SLOT_I.match(op_str)
        if m:
            cur.imm_hits.append((addr, m.group(3), m.group(4)))
            continue
        m = R_ID_W.match(op_str)
        if m:
            cur.id_write_bases.add(m.group(1))
            continue
        m = R_ID_R.match(op_str)
        if m:
            cur.id_read_bases.add(m.group(2))
            continue

    if cur is not None:
        chunks.setdefault(cur.start, cur)
    scan.db_bytes, scan.db_runs, scan.text_len = db_bytes, db_runs, len(code)
    return chunks


def main(argv):
    chunks = scan()
    hits = []
    for c in chunks.values():
        for rva, slot, base, src, zero in c.hits:
            hits.append(dict(rva=hex(rva), slot=slot, base=base, src=src,
                             src_zero=zero, chunk=hex(c.start), chunk_end=hex(c.end),
                             pdata=c.pdata, mask_gate=base in c.mask_gate_bases,
                             id_write=base in c.id_write_bases,
                             id_read=base in c.id_read_bases))
    hits.sort(key=lambda r: int(r["rva"], 16))

    print(f"[cell_filler_sites] chunks={len(chunks)} "
          f"chunks_with_hits={sum(1 for c in chunks.values() if c.hits)} "
          f"hit_insns={len(hits)}")
    print(f"[cell_filler_sites] 第一个命中(A/B 全局序)= "
          f"{hits[0]['rva'] if hits else '-'}  (自检靶 0x394200)")

    if "--json" in argv:
        path = argv[argv.index("--json") + 1]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(dict(chunks=[c.as_dict() for c in chunks.values()], hits=hits),
                      fh, indent=1)
        print(f"[cell_filler_sites] json -> {path}")

    def show(title, rows, limit=40):
        print(f"\n== {title}: {len(rows)}")
        for r in rows[:limit]:
            print(f"  {r['rva']:<12} slot={r['slot']} base={r['base']:<4} src={r['src']:<4}"
                  f" zero={int(r['src_zero'])} chunk={r['chunk']}..{r['chunk_end']}"
                  f" pd={int(r['pdata'])} gate={int(r['mask_gate'])}"
                  f" idW={int(r['id_write'])} idR={int(r['id_read'])}")
        if len(rows) > limit:
            print(f"  ... (+{len(rows) - limit})")

    show("A/B:8 B 写 +0x1c/+0x14(全部)", hits)
    survivors = [r for r in hits if r["mask_gate"] and (r["id_write"] or r["id_read"])
                 and not r["src_zero"]]
    show("三层筛存活(mask 门 + id 同基址 + 非清零)", survivors)
    show("被 ③ 排除:源寄存器是同段零值(清零形态)", [r for r in hits if r["src_zero"]])
    show("mask 门成立但 id 读写不同基址",
         [r for r in hits if r["mask_gate"] and not (r["id_write"] or r["id_read"])
          and not r["src_zero"]])
    show("无 mask 门(基址上没判 [base+8])", [r for r in hits if not r["mask_gate"]])

    ptr = [(hex(a), s, b, src, int(z), hex(c.start))
           for c in chunks.values() for a, s, b, src, z in c.ptr_hits]
    print(f"\n== 命中 F(经 `lea rX,[base+slot]` 再 `mov [rX], rY`): {len(ptr)}")
    for r in ptr[:25]:
        print("  ", r)
    fam = [(hex(c.start), hex(c.end), {k: hex(v) for k, v in c.mask_write.items()},
            [(hex(a), slot, b, src, int(z)) for a, slot, b, src, z in c.hits])
           for c in chunks.values() if c.mask_write and c.hits]
    print(f"\n== 「写 mask + 写槽」同段的函数(构造器/填充方族): {len(fam)}")
    for r in sorted(fam):
        print("  ", r)
    print(f"\n== 扫过什么:.text {scan.text_len} B;skipdata 脱 Sync 段 {scan.db_runs} 次、"
          f"共 {scan.db_bytes} B({scan.db_bytes / scan.text_len:.3%})")
    for c in chunks.values():
        if c.ptr_hits and (c.mask_gate_bases or c.id_write_bases or c.id_read_bases):
            print("   F 且同段有 mask 门/id 抄写:", hex(c.start), hex(c.end), c.ptr_hits)
    dword = [(hex(a), s, b, hex(c.start)) for c in chunks.values() for a, s, b in c.dword_hits]
    print(f"\n== 反例 C(dword 4 B 写 +0x1c/+0x14): {len(dword)}")
    for r in dword[:20]:
        print("  ", r)
    vec = [(hex(a), s, b, x, hex(c.start)) for c in chunks.values() for a, s, b, x in c.vec_hits]
    print(f"\n== 命中 E(16 B 向量写落在 +0x14,一条盖住两槽): {len(vec)}")
    for r in vec[:20]:
        print("  ", r)
    imms = [(hex(a), s, v, hex(c.start)) for c in chunks.values() for a, s, v in c.imm_hits]
    print(f"== 反例 D(qword 写立即数): {len(imms)}")
    for r in imms[:20]:
        print("  ", r)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
