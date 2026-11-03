#!/usr/bin/env python3
"""add_remove_hyperlane_scan.py — `add_hyperlane` / `remove_hyperlane` 写路径的
id→系统对象解析器与边存储的离线复现(Task 2,零 shot)。

一次性离线探针:读本地 `stellaris.exe` 拷贝(`disrva._image()`),把 Task 2 的每条结论
重新从字节里读出来并**与计划期读数逐项核对**。任一不等 → 打印 MISMATCH、**不打印
判决字段**、退出码 1 —— 这样一份「好看」的结论不可能来自一次失败的探针。

口径(与 `evidence/analysis/runtime_444_graph_runtime.md` §1 同源):

  * 所有地址都是 **module-base-relative RVA**(image base 0x140000000,ASLR on);
  * 函数边界取自 `.pdata`(RUNTIME_FUNCTION);**注意 MSVC 会把一个逻辑函数拆成多个
    RUNTIME_FUNCTION 分块**,所以本探针同时给出「分块」与「逻辑范围」两行;
  * 「基址来源(base provenance)」= 某次访存所用的基址寄存器**最后一次被写入**的那条
    指令;本探针把「写入该寄存器的那条指令」+「它前面那条 call」一起打出来,读数
    不靠位移猜;
  * 同位移在别处也出现(§87 口径)—— 探针数一遍 `.text` 里 `+0x590` / `+0x59c` /
    `+0x588` 这三个 disp32 的字节模式命中数,证明**位移本身不能识别容器**;
  * rip 相对目标(元素 vtable `0x8bbb42`、两侧脏/世代位全局 `0x8bbb85` / `0x8bbd65`)
    **由字节解出**,再与计划期常量比对 —— 不是把常量写进结论;
  * 解析器读的两个全局(`0x3260b98` / `0x325d880`)与脏位全局(`0x296cc68`)的**文件字节**
    也读出来:BSS/未初始化 与 file-init 由字节区分。

用法:
    python3 scripts/scratch/2026-11_graph_runtime/add_remove_hyperlane_scan.py

exe 路径走 `disrva.resolve_exe()` 的候选链(`NS_STELLARIS_EXE` 优先),不内联受保护的
路径。不碰游戏、不联网、不改 exe。
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import sys

# scratch/<dir>/file.py -> parents[2] 是 scripts/,disrva/pdata 在那里
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import disrva  # noqa: E402

BASE = disrva.BASE

_exe = disrva.resolve_exe()
if _exe is None:
    print("[add_remove_hyperlane_scan] 找不到 stellaris.exe 拷贝(设 NS_STELLARIS_EXE)",
          file=sys.stderr)
    sys.exit(2)
# pdata.py 读 exe 的路径也走同一个环境变量,免得两个工具看两份不同的字节
os.environ.setdefault("NS_STELLARIS_EXE", _exe)
import pdata  # noqa: E402

from capstone.x86 import X86_OP_MEM, X86_REG_INVALID, X86_REG_RIP  # noqa: E402


# --------------------------------------------------------------------------
# 计划期读数(Task 2 手工追出来的)。**只用来核对**,不参与推导:
# 探针先从字节里读出实际值,再逐项比。
# --------------------------------------------------------------------------
RESOLVER = 0x3939F0          # id(scope) -> 系统对象
EDGE_ADD = 0x8BBAA0          # 边增包装(self, other)
EDGE_REMOVE = 0x8BBC20       # 边删包装(self, &id)
VEC_INSERT = 0x8CF8D0        # 通用 vector push_back(container, index, &value)

ADD_EXEC = 0x1874540         # add_hyperlane 的 +0x48 执行槽
REMOVE_EXEC = 0x1874A00      # remove_hyperlane 的 +0x48 执行槽

CONTAINER_OFF = 0x588        # 系统对象内 边容器的基址
DATA_OFF = 0x590             # 容器内 数据指针
CAP_OFF = 0x598              # 容器内 容量
COUNT_OFF = 0x59C            # 容器内 计数
ELEM_STRIDE = 0x20           # 元素步长

REGISTRY_GLOBAL = 0x3260B98  # 解析器读的系统索引全局
FALLBACK_GLOBAL = 0x325D880  # 解析器失败时的默认对象
DIRTY_GLOBAL = 0x296CC68     # 脏/世代位掩码字(广义,不是边专属)
ELEM_VTABLE = 0x24B5480      # 边元素的 vtable(在 .rdata)

# 三个 rip 目标**由字节解出**,不断言:解出的值与上面的常量比对。
ELEM_VTABLE_SITE = 0x8BBB42      # edge_add 装元素 vtable 的 lea
DIRTY_FLAG_ADD_SITE = 0x8BBB85   # edge_add 的 or [rip+..],1
DIRTY_FLAG_REM_SITE = 0x8BBD65   # edge_remove 的 or [rip+..],1

# (标签, 函数起, 站点 rva, "助记符 操作数") —— 逐字比对 capstone 的输出
EXPECTED_SITES: list[tuple[str, int, int, str]] = [
    # ---- add_hyperlane ---------------------------------------------------
    ("add_hyperlane", ADD_EXEC, 0x187457E, "call 0x1403939f0"),
    ("add_hyperlane", ADD_EXEC, 0x1874583, "mov rbx, rax"),
    ("add_hyperlane", ADD_EXEC, 0x18745F1, "call 0x1403939f0"),
    ("add_hyperlane", ADD_EXEC, 0x18745F6, "mov rdi, rax"),
    ("add_hyperlane", ADD_EXEC, 0x18746EE, "movsxd rax, dword ptr [rbx + 0x59c]"),
    ("add_hyperlane", ADD_EXEC, 0x1874701, "mov rax, qword ptr [rbx + 0x590]"),
    ("add_hyperlane", ADD_EXEC, 0x1874720, "mov rdx, rdi"),
    ("add_hyperlane", ADD_EXEC, 0x1874723, "mov rcx, rbx"),
    ("add_hyperlane", ADD_EXEC, 0x1874726, "call 0x1408bbaa0"),
    ("add_hyperlane", ADD_EXEC, 0x187472B, "mov rdx, rbx"),
    ("add_hyperlane", ADD_EXEC, 0x187472E, "mov rcx, rdi"),
    ("add_hyperlane", ADD_EXEC, 0x1874731, "call 0x1408bbaa0"),
    # ---- remove_hyperlane ------------------------------------------------
    ("remove_hyperlane", REMOVE_EXEC, 0x1874A3E, "call 0x1403939f0"),
    ("remove_hyperlane", REMOVE_EXEC, 0x1874A43, "mov rbx, rax"),
    ("remove_hyperlane", REMOVE_EXEC, 0x1874AB1, "call 0x1403939f0"),
    ("remove_hyperlane", REMOVE_EXEC, 0x1874AB6, "mov rdi, rax"),
    ("remove_hyperlane", REMOVE_EXEC, 0x1874BB1, "movsxd rax, dword ptr [rbx + 0x59c]"),
    ("remove_hyperlane", REMOVE_EXEC, 0x1874BC4, "mov rax, qword ptr [rbx + 0x590]"),
    ("remove_hyperlane", REMOVE_EXEC, 0x1874CBD, "mov dword ptr [rbp + 0x290], edx"),
    ("remove_hyperlane", REMOVE_EXEC, 0x1874CCA, "mov rcx, rbx"),
    ("remove_hyperlane", REMOVE_EXEC, 0x1874CCD, "call 0x1408bbc20"),
    ("remove_hyperlane", REMOVE_EXEC, 0x1874CD2, "mov eax, dword ptr [rbx + 8]"),
    ("remove_hyperlane", REMOVE_EXEC, 0x1874CE2, "mov rcx, rdi"),
    ("remove_hyperlane", REMOVE_EXEC, 0x1874CE5, "call 0x1408bbc20"),
    # ---- 解析器(**全 24 条**,一条都不许漏) ------------------------------
    # id 的来源链:`cmp [rcx+8],0x80` 判 scope 类型 -> `mov eax,[rcx+0x10]`
    # 取 id -> `mov [rsp+8],eax` 落到栈局部 -> `lea rcx,[rsp+8]` 让 rcx 指向
    # **局部** -> `mov edx,[rcx]` 读的是局部。scope+0 全程没被读过。
    ("resolver", RESOLVER, 0x3939F0, "cmp qword ptr [rcx + 8], 0x80"),
    ("resolver", RESOLVER, 0x3939F8, "jne 0x140393a03"),
    ("resolver", RESOLVER, 0x3939FA, "mov eax, dword ptr [rcx + 0x10]"),
    ("resolver", RESOLVER, 0x3939FD, "mov dword ptr [rsp + 8], eax"),
    ("resolver", RESOLVER, 0x393A01, "jmp 0x140393a0b"),
    ("resolver", RESOLVER, 0x393A03, "mov dword ptr [rsp + 8], 0xffffffff"),
    ("resolver", RESOLVER, 0x393A0B, "mov rax, qword ptr [rip + 0x2ecd186]"),
    ("resolver", RESOLVER, 0x393A12, "lea rcx, [rsp + 8]"),
    ("resolver", RESOLVER, 0x393A17, "test rax, rax"),
    ("resolver", RESOLVER, 0x393A1A, "je 0x140393a41"),
    ("resolver", RESOLVER, 0x393A1C, "mov edx, dword ptr [rcx]"),
    ("resolver", RESOLVER, 0x393A1E, "mov ecx, edx"),
    ("resolver", RESOLVER, 0x393A20, "and ecx, 0xffffff"),
    ("resolver", RESOLVER, 0x393A26, "cmp ecx, dword ptr [rax + 0x20]"),
    ("resolver", RESOLVER, 0x393A29, "jae 0x140393a41"),
    ("resolver", RESOLVER, 0x393A2B, "mov rax, qword ptr [rax + 0x18]"),
    ("resolver", RESOLVER, 0x393A2F, "add rcx, rcx"),
    ("resolver", RESOLVER, 0x393A32, "mov rax, qword ptr [rax + rcx*8 + 8]"),
    ("resolver", RESOLVER, 0x393A37, "test rax, rax"),
    ("resolver", RESOLVER, 0x393A3A, "je 0x140393a41"),
    ("resolver", RESOLVER, 0x393A3C, "cmp dword ptr [rax + 8], edx"),
    ("resolver", RESOLVER, 0x393A3F, "je 0x140393a48"),
    ("resolver", RESOLVER, 0x393A41, "mov rax, qword ptr [rip + 0x2ec9e38]"),
    ("resolver", RESOLVER, 0x393A48, "ret"),
    # ---- 边增包装 ---------------------------------------------------------
    ("edge_add", EDGE_ADD, 0x8BBAAF, "mov rsi, rdx"),
    ("edge_add", EDGE_ADD, 0x8BBAB2, "mov rdi, rcx"),
    # 坐标来自 `[system+0x28]` 的 vtable 槽 +8 返回的**子对象**,不是系统对象本身
    ("edge_add", EDGE_ADD, 0x8BBAB5, "lea rcx, [rdx + 0x28]"),
    ("edge_add", EDGE_ADD, 0x8BBAB9, "mov rax, qword ptr [rcx]"),
    ("edge_add", EDGE_ADD, 0x8BBABC, "call qword ptr [rax + 8]"),
    ("edge_add", EDGE_ADD, 0x8BBABF, "mov rbx, rax"),
    ("edge_add", EDGE_ADD, 0x8BBAC2, "lea rcx, [rdi + 0x28]"),
    ("edge_add", EDGE_ADD, 0x8BBAC6, "mov r8, qword ptr [rcx]"),
    ("edge_add", EDGE_ADD, 0x8BBAC9, "call qword ptr [r8 + 8]"),
    ("edge_add", EDGE_ADD, 0x8BBACD, "mov rcx, qword ptr [rbx + 0x10]"),
    ("edge_add", EDGE_ADD, 0x8BBAD1, "sub rcx, qword ptr [rax + 0x10]"),
    ("edge_add", EDGE_ADD, 0x8BBAD5, "mov r8, qword ptr [rbx + 8]"),
    ("edge_add", EDGE_ADD, 0x8BBAD9, "sub r8, qword ptr [rax + 8]"),
    ("edge_add", EDGE_ADD, 0x8BBB42, "lea rcx, [rip + 0x1bf9937]"),
    ("edge_add", EDGE_ADD, 0x8BBB53, "lea rcx, [rdi + 0x588]"),
    ("edge_add", EDGE_ADD, 0x8BBB5F, "mov edx, dword ptr [rcx + 0x14]"),
    ("edge_add", EDGE_ADD, 0x8BBB62, "call 0x1408cf8d0"),
    ("edge_add", EDGE_ADD, 0x8BBB73, "or byte ptr [rdi + 0x137d], al"),
    ("edge_add", EDGE_ADD, 0x8BBB85, "or dword ptr [rip + 0x20b10dc], 1"),
    ("edge_add", EDGE_ADD, 0x8BBB94, "mov qword ptr [rdi + 0x5a0], rax"),
    # ---- 边删包装 ---------------------------------------------------------
    ("edge_remove", EDGE_REMOVE, 0x8BBC29, "movsxd rax, dword ptr [rcx + 0x59c]"),
    ("edge_remove", EDGE_REMOVE, 0x8BBC3F, "mov r11, qword ptr [rcx + 0x590]"),
    ("edge_remove", EDGE_REMOVE, 0x8BBC51, "cmp dword ptr [rax + 8], r10d"),
    ("edge_remove", EDGE_REMOVE, 0x8BBC5D, "add rax, 0x20"),
    # 末元素 -> 命中槽的搬运在**虚析构之前**
    ("edge_remove", EDGE_REMOVE, 0x8BBC71, "shl r9, 5"),
    ("edge_remove", EDGE_REMOVE, 0x8BBC86, "mov eax, dword ptr [r9 + r11 - 0x18]"),
    ("edge_remove", EDGE_REMOVE, 0x8BBC8F, "mov dword ptr [rcx + r11 + 8], eax"),
    ("edge_remove", EDGE_REMOVE, 0x8BBC94, "mov rax, qword ptr [r9 + r11 - 0x10]"),
    ("edge_remove", EDGE_REMOVE, 0x8BBC99, "mov qword ptr [rcx + r11 + 0x10], rax"),
    ("edge_remove", EDGE_REMOVE, 0x8BBC9E, "movzx eax, byte ptr [r9 + r11 - 8]"),
    ("edge_remove", EDGE_REMOVE, 0x8BBCA4, "mov byte ptr [rcx + r11 + 0x18], al"),
    ("edge_remove", EDGE_REMOVE, 0x8BBCF7, "call qword ptr [r8]"),
    ("edge_remove", EDGE_REMOVE, 0x8BBD1D, "mov dword ptr [rdi + 0x59c], eax"),
    ("edge_remove", EDGE_REMOVE, 0x8BBD53, "mov byte ptr [rdi + 0x137d], al"),
    ("edge_remove", EDGE_REMOVE, 0x8BBD65, "or dword ptr [rip + 0x20b0efc], 1"),
    # ---- 通用 vector push_back ------------------------------------------
    ("vec_insert", VEC_INSERT, 0x8CF8E8, "movsxd rax, dword ptr [rcx + 0x14]"),
    ("vec_insert", VEC_INSERT, 0x8CF8EF, "mov ecx, dword ptr [rcx + 0x10]"),
    ("vec_insert", VEC_INSERT, 0x8CF93E, "shl rdi, 5"),
    ("vec_insert", VEC_INSERT, 0x8CF942, "lea rax, [rip + 0x1be5b37]"),
    # 容器 vtable 在容器基址 +0:读 vtable 后调它的 +0x18 槽
    ("vec_insert", VEC_INSERT, 0x8CF9B1, "mov rax, qword ptr [r14]"),
    ("vec_insert", VEC_INSERT, 0x8CF9B4, "mov rcx, r14"),
    ("vec_insert", VEC_INSERT, 0x8CF9B7, "call qword ptr [rax + 0x18]"),
    ("vec_insert", VEC_INSERT, 0x8CF9E0, "add rcx, qword ptr [r14 + 8]"),
    ("vec_insert", VEC_INSERT, 0x8CFA02, "inc dword ptr [r14 + 0x14]"),
]

# §1.8 的排除项:自带区间(不在本探针的函数表里),逐字比对 capstone 的输出
LOOKALIKE_SITES: list[tuple[str, int, int, int, str]] = [
    # 别的 vector:元素 0x48 字节
    ("lookalike_vec_0x48", 0x34C9A0, 0x34C9E0, 0x34C9AB, "mov eax, 0x48"),
    ("lookalike_vec_0x48", 0x34C9A0, 0x34C9E0, 0x34C9C3, "call 0x14218525c"),
    ("lookalike_vec_0x48", 0x34C9A0, 0x34C9E0, 0x34C9C8, "lea rdi, [rbx + rbx*8]"),
    ("lookalike_vec_0x48", 0x34C9A0, 0x34C9E0, 0x34C9D2, "lea rbx, [rax + rdi*8]"),
    # 别的 vector:元素 0x38 字节
    ("lookalike_vec_0x38", 0x34CB20, 0x34CB50, 0x34CB33, "call 0x14218525c"),
    ("lookalike_vec_0x38", 0x34CB20, 0x34CB50, 0x34CB38, "imul rdi, rbx, 0x38"),
    ("lookalike_vec_0x38", 0x34CB20, 0x34CB50, 0x34CB42, "lea rbx, [rdi + rax]"),
    # rsp 基址的 +0x590(栈帧/栈展开,不是容器)
    ("lookalike_stack", 0x531630, 0x531660, 0x53163F, "movaps xmmword ptr [rsp + 0x590], xmm6"),
    ("lookalike_stack", 0x54D540, 0x54D560, 0x54D54D, "lea r11, [rsp + 0x590]"),
]


def _md():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


MD = _md()


def disasm(start: int, end: int) -> list:
    """[start, end) 的线性反汇编(不含 end)。"""
    code, _sec = disrva.rd(start, end - start)
    return list(MD.disasm(code, BASE + start))


def text(ins) -> str:
    return f"{ins.mnemonic} {ins.op_str}".strip()


def rip_target(ins) -> int | None:
    """rip 相对操作数解析出的 module-base-relative RVA。"""
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            return ins.address + ins.size + op.mem.disp - BASE
    return None


def mem_base_and_disp(ins):
    """(基址寄存器名, displacement) —— 只取第一个内存操作数。"""
    for op in ins.operands:
        if op.type == X86_OP_MEM:
            base = ins.reg_name(op.mem.base) if op.mem.base else None
            return base, op.mem.disp
    return None, None


def last_write(insns, reg: str, before: int):
    """`before` 之前最后一次写 `reg` 的指令(用 capstone 的 regs_access,不是猜助记符)。"""
    for i in range(before - 1, -1, -1):
        ins = insns[i]
        try:
            _read, written = ins.regs_access()
        except Exception:
            continue
        if reg in (ins.reg_name(r) for r in written if r != X86_REG_INVALID):
            return i
    return None


def provenance(insns, site_index: int, reg: str) -> list[str]:
    """访存的基址来源:写入基址寄存器的那条指令 + 它前面那条 call。"""
    out = []
    w = last_write(insns, reg, site_index)
    if w is None:
        return [f"      基址 {reg}: 找不到写入点"]
    w_ins = insns[w]
    out.append(f"      基址 {reg} 来源: 0x{w_ins.address - BASE:x}  {text(w_ins)}")
    if w >= 1:
        p = insns[w - 1]
        out.append(f"        前一条: 0x{p.address - BASE:x}  {text(p)}")
    return out


# .pdata 全表:start -> end(MSVC 会把一个逻辑函数切成多个连续分块)
PDATA_BY_START = {b: e for b, e, _u in pdata.funcs}


def pdata_chunks(start: int) -> list[tuple[int, int]]:
    """从 `start` 起**连续**的 RUNTIME_FUNCTION 分块(按链走,不是只看首块)。"""
    out = []
    cur = start
    while cur in PDATA_BY_START:
        end = PDATA_BY_START[cur]
        out.append((cur, end))
        cur = end
    return out


def pdata_span(start: int) -> tuple[int, int] | None:
    """从 `start` 起的所有连续分块合起来的逻辑范围;不在 .pdata 里则 None。"""
    chunks = pdata_chunks(start)
    if not chunks:
        return None
    return (chunks[0][0], chunks[-1][1])


def disp32_hits(disp: int) -> int:
    """.text 里 disp32 == `disp` 的字节模式命中数(位移本身不能识别容器的证据)。"""
    _exe_path, blob, secs = disrva._image()
    text_sec = next(s for s in secs if s[0] == ".text")
    _nm, _va, _vs, rawsz, praw, _ch = text_sec
    raw = blob[praw:praw + rawsz]
    return raw.count(disp.to_bytes(4, "little"))


def main() -> int:
    exe = disrva.resolve_exe()
    sha = hashlib.sha256(pathlib.Path(exe).read_bytes()).hexdigest()

    print("=" * 78)
    print("add_remove_hyperlane_scan —— 写路径:解析器 / 边容器 / 增删(零 shot 静态 RE)")
    print("=" * 78)
    print(f"exe        : {exe}")
    print(f"sha256     : {sha}")
    print(f"image base : 0x{BASE:x}(ASLR on)—— 下列所有地址都是 module-base-relative RVA")

    # ---- 1. 函数边界(.pdata) ----------------------------------------------
    print("\n[1] .pdata 函数边界(RUNTIME_FUNCTION)")
    # 解析器是叶子函数,**不在 .pdata 里**;边界只能靠 `ret` 定(0x393a48 的 ret
    # 之后是 int3 填充到 0x393a50),这里把上限写死并**核对 ret 的位置**。
    MANUAL_END = {"resolver": 0x393A49}
    bounds = {}
    for label, fn in (("add_hyperlane", ADD_EXEC),
                      ("remove_hyperlane", REMOVE_EXEC),
                      ("resolver", RESOLVER),
                      ("edge_add", EDGE_ADD),
                      ("edge_remove", EDGE_REMOVE),
                      ("vec_insert", VEC_INSERT)):
        chunks = pdata_chunks(fn)
        if chunks:
            lo, hi = pdata_span(fn)
            print(f"  {label:<16} 0x{fn:x}  分块 "
                  + " ".join(f"0x{b:x}..0x{e:x}" for b, e in chunks)
                  + f"  => 逻辑范围 0x{lo:x}..0x{hi:x} ({hi - lo:#x} bytes)")
            bounds[label] = (lo, hi)
        else:
            hi = MANUAL_END[label]
            ins = disasm(fn, hi)
            last = ins[-1] if ins else None
            if last and last.mnemonic == "ret":
                note = f"边界取到第一个 ret: 0x{last.address - BASE:x}  {text(last)}"
            else:
                note = f"边界人工指定 0x{fn:x}..0x{hi:x}"
            print(f"  {label:<16} 0x{fn:x}  **不在 .pdata 里**(叶子函数,无 unwind 记录);"
                  f"{note}")
            bounds[label] = (fn, hi)

    # ---- 2. 逐站点核对 ---------------------------------------------------
    print("\n[2] 逐站点核对(读数 vs 计划期)")
    bodies = {}
    ok = True
    for label, fn, site, want in EXPECTED_SITES:
        lo, hi = bounds[label]
        if label not in bodies:
            bodies[label] = disasm(lo, hi)
        insns = bodies[label]
        got_ins = next((i for i in insns if i.address - BASE == site), None)
        if got_ins is None:
            print(f"  MISMATCH {label} 0x{site:x}: 站点不在函数体里")
            ok = False
            continue
        got = text(got_ins)
        if got != want:
            print(f"  MISMATCH {label} 0x{site:x}: '{got}' != '{want}'")
            ok = False
    print(f"  {len(EXPECTED_SITES)} 个站点逐字核对 —— "
          + ("全部相等 OK" if ok else "**存在不一致**"))

    # §1.8 的排除项:同位移、不同对象的站点(各自带区间),同样逐字核对 ——
    # 排除结论必须建立在**读到的字节**上,不能只写在文档里。
    print(f"\n[2b] §1.8 同位移排除站点逐字核对({len(LOOKALIKE_SITES)} 个)")
    look_ok = True
    _bodies = {}
    for label, lo, hi, site, want in LOOKALIKE_SITES:
        if (lo, hi) not in _bodies:
            _bodies[(lo, hi)] = disasm(lo, hi)
        got_ins = next((i for i in _bodies[(lo, hi)] if i.address - BASE == site), None)
        if got_ins is None:
            print(f"  MISMATCH {label} 0x{site:x}: 站点不在区间 0x{lo:x}..0x{hi:x}")
            look_ok = False
            continue
        got = text(got_ins)
        if got != want:
            print(f"  MISMATCH {label} 0x{site:x}: '{got}' != '{want}'")
            look_ok = False
    print(f"  {len(LOOKALIKE_SITES)} 个排除站点逐字核对 —— "
          + ("全部相等 OK" if look_ok else "**存在不一致**"))
    ok = ok and look_ok

    # ---- 3. add / remove 的写路径站点与基址来源 --------------------------
    for label, fn in (("add_hyperlane", ADD_EXEC), ("remove_hyperlane", REMOVE_EXEC)):
        lo, hi = bounds[label]
        insns = bodies.get(label) or disasm(lo, hi)
        print(f"\n[3] {label} (0x{fn:x}..0x{hi:x}) —— 解析器调用、容器访存、增删调用")
        for i, ins in enumerate(insns):
            t = text(ins)
            if ins.mnemonic == "call" and ins.op_str == f"0x{BASE + RESOLVER:x}":
                nxt = insns[i + 1] if i + 1 < len(insns) else None
                dest = nxt.op_str.split(",")[0].strip() if nxt else "?"
                print(f"  0x{ins.address - BASE:x}  {t}"
                      f"   ; scope/id -> 系统对象,返回值进 {dest}")
            base, disp = mem_base_and_disp(ins)
            if base in ("rbx", "rdi") and disp in (DATA_OFF, COUNT_OFF):
                print(f"  0x{ins.address - BASE:x}  {t}"
                      f"   ; 容器访问,基址 {base},displacement {disp:#x}")
                for line in provenance(insns, i, base):
                    print(line)
            if ins.mnemonic == "call" and ins.op_str in (f"0x{BASE + EDGE_ADD:x}",
                                                        f"0x{BASE + EDGE_REMOVE:x}"):
                arg = insns[i - 2:i]
                print(f"  0x{ins.address - BASE:x}  {t}   ; 边增/删调用,实参装配:")
                for a in arg:
                    print(f"      0x{a.address - BASE:x}  {text(a)}")

    # ---- 4. 解析器 --------------------------------------------------------
    print(f"\n[4] 解析器 0x{RESOLVER:x}(scope/id -> 系统对象)")
    rlo, rhi = bounds["resolver"]
    rinsns = disasm(rlo, rhi) if rlo != rhi else disasm(RESOLVER, RESOLVER + 0x60)
    globals_seen = []
    for ins in rinsns:
        if ins.mnemonic == "mov" and ins.op_str.startswith("rax, qword ptr [rip"):
            tgt = rip_target(ins)
            globals_seen.append((ins.address - BASE, tgt))
            print(f"  0x{ins.address - BASE:x}  {text(ins)}   ; -> 全局 0x{tgt:x}")
    reg_global = globals_seen[0][1] if globals_seen else None
    fallback_global = globals_seen[1][1] if len(globals_seen) > 1 else None
    print(f"  系统索引全局 = 0x{reg_global:x}(期望 0x{REGISTRY_GLOBAL:x})"
          + ("  OK" if reg_global == REGISTRY_GLOBAL else "  **MISMATCH**"))
    print(f"  失败回退对象 = 0x{fallback_global:x}(期望 0x{FALLBACK_GLOBAL:x})"
          + ("  OK" if fallback_global == FALLBACK_GLOBAL else "  **MISMATCH**"))
    if reg_global != REGISTRY_GLOBAL or fallback_global != FALLBACK_GLOBAL:
        ok = False

    # 两个全局在文件里的字节:**空 = BSS/未初始化**(它们保存运行时填充的指针,
    # 不是 file-init 数据)——由字节判定,不是断言。
    for name, g in (("系统索引全局", REGISTRY_GLOBAL), ("失败回退对象", FALLBACK_GLOBAL)):
        b, sec = disrva.rd(g, 8)
        if not b:
            print(f"  0x{g:x} {name} 文件字节:空({sec},BSS/未初始化)  OK")
        else:
            print(f"  0x{g:x} {name} 文件字节:{b.hex()}({sec})  **MISMATCH(应为 BSS)**")
            ok = False

    # ---- 5. 边容器布局 ----------------------------------------------------
    print(f"\n[5] 边容器 = 系统对象 + 0x{CONTAINER_OFF:x}"
          f"(数据 +0x{DATA_OFF:x} / 容量 +0x{CAP_OFF:x} / 计数 +0x{COUNT_OFF:x})")
    print(f"  容器基址来自 `lea rcx, [rdi + 0x{CONTAINER_OFF:x}]`(0x8bbb53),"
          f"rdi = 解析器返回的系统对象")
    print(f"  元素步长 = 0x{ELEM_STRIDE:x}(删除侧 0x8bbc5d `add rax, 0x20`;"
          f"插入侧 0x8cf93e `shl rdi, 5` = 32)")

    # rip 目标**由字节解出**:元素 vtable、脏标志全局 —— 不是断言,是推导。
    print("  rip 目标解析(从字节解出,再与常量比对):")
    rip_ok = True
    for label, site, want, what in (
        ("edge_add", ELEM_VTABLE_SITE, ELEM_VTABLE, "元素 vtable"),
        ("edge_add", DIRTY_FLAG_ADD_SITE, DIRTY_GLOBAL, "脏标志(add 侧)"),
        ("edge_remove", DIRTY_FLAG_REM_SITE, DIRTY_GLOBAL, "脏标志(remove 侧)"),
    ):
        insns = bodies.get(label) or disasm(*bounds[label])
        ins = next((i for i in insns if i.address - BASE == site), None)
        tgt = rip_target(ins) if ins is not None else None
        if tgt is None:
            print(f"    0x{site:x} {what}: **MISMATCH(站点不在函数体里)**")
            rip_ok = False
            continue
        mark = "OK" if tgt == want else "**MISMATCH**"
        print(f"    0x{site:x} {text(ins)} -> 0x{tgt:x}(期望 0x{want:x})  {mark}")
        if tgt != want:
            rip_ok = False
    ok = ok and rip_ok

    print(f"  元素布局: +0x00 vtable(0x{ELEM_VTABLE:x}) / +0x08 id(dword) /"
          f" +0x10 距离(qword) / +0x18 标志(byte)")
    print(f"  脏/世代位掩码全局 = 0x{DIRTY_GLOBAL:x}"
          f"(add 侧 0x8bbb85 `or dword ptr [rip + 0x20b10dc], 1`;"
          f"remove 侧 0x8bbd65 `or dword ptr [rip + 0x20b0efc], 1` —— 两侧同址)")
    db, dsec = disrva.rd(DIRTY_GLOBAL, 4)
    if db == b"\x01\x00\x00\x00":
        print(f"    文件字节 {db.hex()}({dsec})=> file-init dword = 1(**不是 BSS**)  OK")
    else:
        print(f"    文件字节 {db.hex() or '(空)'}({dsec})"
              f"  **MISMATCH(期望 01000000)**")
        ok = False

    # ---- 6. 同位移排除 ----------------------------------------------------
    print("\n[6] 同位移在别处也出现(§87 口径)—— 位移本身不能识别容器")
    for name, disp in (("+0x588", CONTAINER_OFF),
                       ("+0x590", DATA_OFF),
                       ("+0x59c", COUNT_OFF)):
        print(f"  .text 里 disp32 == {name} 的字节模式命中: {disp32_hits(disp)} 处")
    print("  排除依据: 基址来源 —— 访存的基址寄存器最后一次写入是"
          "`mov rbx/rdi, rax`,其前一条是 `call 0x3939f0`(解析器)")

    # ---- 7. 判决字段 ------------------------------------------------------
    if not ok:
        print("\n[check] 交叉校验失败 —— 不打印判决字段(退出码 1)", file=sys.stderr)
        return 1
    print("\n[check] 全部读数与计划期一致")
    print("  resolver_rva        = 0x3939f0")
    print("  edge_owner          = system_object(解析器返回) + 0x588")
    print("  neighbor_vector_off = 0x590(容器基址 0x588)")
    print("  neighbor_count_off  = 0x59c")
    print("  insert_fn           = 0x8bbaa0(通用 push_back 0x8cf8d0)")
    print("  remove_fn           = 0x8bbc20")
    return 0


if __name__ == "__main__":
    sys.exit(main())
