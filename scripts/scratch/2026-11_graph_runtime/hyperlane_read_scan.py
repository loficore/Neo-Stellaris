#!/usr/bin/env python3
"""hyperlane_read_scan.py — 图 keyword **读路径**(trigger 侧)的离线复现(Task 3,零 shot)。

一次性离线探针:读本地 `stellaris.exe` 拷贝(`disrva._image()`),把 Task 3 的每条结论
重新从字节里读出来并**与计划期读数逐项核对**。任一不等 → 打印 MISMATCH、**不打印
判决字段**、退出码 1 —— 这样一份「好看」的结论不可能来自一次失败的探针。

口径(与 `evidence/analysis/runtime_444_graph_runtime.md` §2 同源):

  * 所有地址都是 **module-base-relative RVA**(image base 0x140000000,ASLR on);
  * 函数边界取自 `.pdata`(RUNTIME_FUNCTION);MSVC 会把一个逻辑函数拆成多个连续
    RUNTIME_FUNCTION 分块,本探针按链走并同时给出「分块」与「逻辑范围」;
  * **基址来源(base provenance)= 某次访存所用基址寄存器最后一次被写入的那条指令**;
    位移本身不能识别容器(§87 口径),所以本探针把「写入该寄存器的那条指令」+「它前面
    那条 call」打出来;
  * rip 相对目标(解析器全局 `0x3260b98`、回退 `0x325d880`、§88 全局 `0x3260bb0`、
    has_hyperlane_to vtable `0x269fde8`)**由字节解出**,再与计划期常量比对;
  * **负对照**:通用解释器 `0x348db0..0x349212` 里既没有 `0x165` 立即数,也没有
    `+0x588/+0x590/+0x59c/+0x78` 任何访存;`has_hyperlane_to` 的 `+0x20` 槽
    (`0x1afde20`)同样没有邻居容器访存、没有间接 call/jmp —— 两条都由字节数出来;
  * **三条读路径**(A `has_hyperlane_to` `+0x18`、B `closest_system` `+0x18`、
    C `num_neighbor_systems` `+0xf0`)各自内联 §1 的解析器,并且都读同一组
    `{+0x590 data, +0x59c count, stride 0x20, 元素 +8 = id}` —— 这是本探针的三角互证;
    C 的 `+0x18` 槽(`0x1b3cbc0`)本身是**比较体**,不是读路径,它只是把邻居收集
    (`+0xf0` -> `0x1b87240` -> `0x1b86e30`)当作比较的输入。

用法:
    python3 scripts/scratch/2026-11_graph_runtime/hyperlane_read_scan.py

exe 路径走 `disrva.resolve_exe()` 的候选链(`NS_STELLARIS_EXE` 优先),不内联受保护的
路径。不碰游戏、不联网、不改 exe。
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import struct
import sys

# scratch/<dir>/file.py -> parents[2] 是 scripts/,disrva/pdata 在那里
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import disrva  # noqa: E402

BASE = disrva.BASE

_exe = disrva.resolve_exe()
if _exe is None:
    print("[hyperlane_read_scan] 找不到 stellaris.exe 拷贝(设 NS_STELLARIS_EXE)",
          file=sys.stderr)
    sys.exit(2)
# pdata.py 读 exe 的路径也走同一个环境变量,免得两个工具看两份不同的字节
os.environ.setdefault("NS_STELLARIS_EXE", _exe)
import pdata  # noqa: E402

from capstone.x86 import X86_OP_MEM, X86_REG_INVALID, X86_REG_RIP  # noqa: E402


# --------------------------------------------------------------------------
# 计划期读数(Task 3 手工追出来的)。**只用来核对**,不参与推导:
# 探针先从字节里读出实际值,再逐项比。
# --------------------------------------------------------------------------
HAS_VTABLE = 0x269FDE8       # has_hyperlane_to 的 vtable(.rdata)
FACTORY = 0x1B2A510          # has_hyperlane_to 的工厂(new(0x3c0) 后写 +0x78 / vtable)
OPDISPATCH = 0x1A92090       # 读 [self+0x78] 并派发比较运算符的共享基体
OP_FIELD_OFF = 0x78          # 存比较运算符 token id 的字段
HAS_OP_VALUE = 0x165         # 该字段的**族默认值**(见下:两侧工厂都把它写成 0x165)
NN_FACTORY = 0x1B33930       # num_neighbor_systems 的工厂(它自己**不直接**写 +0x78)
SHARED_CTOR = 0x187B9E0      # num_neighbor_systems 工厂调用的**共享基类构造器**:
                             #   0x187b9f7 写 `[rdi+0x78] = 0x165` —— 所以 0x165 不是
                             #   has_hyperlane_to 专属,而是这一族的默认比较运算符 id

NN_THUNK_END = 0x1A92455     # 0x1a92450 是裸 thunk(不在 .pdata),边界人工定
SHARED_BASE = 0x1A91A80      # 比较 trigger 的共享基体(尾跳 [vtable+0x20])
HHT_READ = 0x1AFE500         # has_hyperlane_to 的 +0x18 槽(读路径入口)
HHT_CORE = 0xA6AA10          # has_hyperlane_to 的核心邻居读体
HHT_CMP = 0x1AFDE20          # has_hyperlane_to 的 +0x20 槽(比较,不是读)
CS_READ = 0x1AE3700          # closest_system 的 +0x18 槽(读路径入口)
CS_DISPATCH_A = 0x8C24D0     # closest_system 搜索派发 A
CS_DISPATCH_B = 0x8C25F0     # closest_system 搜索派发 B
CS_BFS = 0x8CBB30            # hyperlane 步数 BFS(读邻居容器的那个)
CS_EXPAND = 0x8CDAE0         # B 派发的另一候选(只核调用点存在)
NN_CMP = 0x1B3CBC0           # num_neighbor_systems 的 +0x18 槽(本身是**比较体**)
NN_EVAL = 0x1B87240          # num_neighbor_systems vtable 的 +0xf0 槽(邻居收集器入口)
NN_COLLECT = 0x1B86E30       # NN_EVAL 调的收集器(真正读 §1 容器的地方)

GENERIC_INTERP = 0x348DB0    # 通用解释器(简报 Step 1 以为的分派处)
GENERIC_INTERP_END = 0x349212
NN_THUNK = 0x1A92450         # num_neighbor_systems 的 +0x28 = jmp 0x348db0
SHARED_CMP = 0x349230        # 三个 trigger 共用的 +0x80 比较体

RESOLVER_GLOBAL = 0x3260B98  # §1 解析器读的系统索引全局
FALLBACK_GLOBAL = 0x325D880  # §1 解析器失败回退对象

DATA_OFF = 0x590             # 容器数据指针(§1)
COUNT_OFF = 0x59C            # 容器计数(§1)
CONTAINER_OFF = 0x588        # 容器基址(§1)
ELEM_STRIDE = 0x20           # 元素步长(§1)
S88_GLOBAL = 0x3260BB0       # §88 的对象(同位移、不同对象)

# 三个 trigger class 的 vtable(.rdata);读路径在 +0x18 槽
VTABLES: list[tuple[str, int, list[tuple[int, int]]]] = [
    ("num_neighbor_systems", 0x266C108,
     [(0x18, NN_CMP), (0x20, 0x1A92070), (0x28, 0x1A92450), (0x80, 0x349230),
      (0xF0, NN_EVAL)]),
    ("has_hyperlane_to", 0x269FDE8,
     [(0x18, HHT_READ), (0x20, HHT_CMP), (0x28, SHARED_BASE), (0x80, 0x349230)]),
    ("closest_system", 0x267FAA0,
     [(0x18, CS_READ), (0x20, 0x159730), (0x28, GENERIC_INTERP), (0x80, 0x349230)]),
]

# rip 目标由字节解出,再与上面的常量比对
RIP_TARGETS: list[tuple[str, int, int, str]] = [
    ("has_factory", FACTORY, HAS_VTABLE, "has_hyperlane_to vtable"),
    ("hht_read", HHT_READ, RESOLVER_GLOBAL, "解析器全局"),
    ("hht_read", HHT_READ, FALLBACK_GLOBAL, "解析器回退对象"),
    ("hht_core", HHT_CORE, RESOLVER_GLOBAL, "解析器全局"),
    ("hht_core", HHT_CORE, FALLBACK_GLOBAL, "解析器回退对象"),
    ("cs_read", CS_READ, RESOLVER_GLOBAL, "解析器全局"),
    ("cs_read", CS_READ, FALLBACK_GLOBAL, "解析器回退对象"),
    ("cs_disp_a", CS_DISPATCH_A, FALLBACK_GLOBAL, "解析器回退对象"),
    ("cs_disp_b", CS_DISPATCH_B, FALLBACK_GLOBAL, "解析器回退对象"),
    ("cs_bfs", CS_BFS, S88_GLOBAL, "§88 全局(只用来量 frontier 大小)"),
    ("cs_bfs", CS_BFS, RESOLVER_GLOBAL, "解析器全局"),
    ("cs_bfs", CS_BFS, FALLBACK_GLOBAL, "解析器回退对象"),
    ("nn_eval", NN_EVAL, RESOLVER_GLOBAL, "解析器全局"),
    ("nn_eval", NN_EVAL, FALLBACK_GLOBAL, "解析器回退对象"),
    ("nn_collect", NN_COLLECT, RESOLVER_GLOBAL, "解析器全局"),
    ("nn_collect", NN_COLLECT, FALLBACK_GLOBAL, "解析器回退对象"),
]

# (标签, 函数起, 站点 rva, "助记符 操作数") —— 逐字比对 capstone 的输出
EXPECTED_SITES: list[tuple[str, int, int, str]] = [
    # ---- §2.1 `+0x78` 是**比较运算符 token id**,不是 opcode ------------------
    # `+0x78 = 0x165` 是这一族的**默认值**,两个工厂都给:
    #   (a) has_hyperlane_to 工厂自己写:0x1b2a53b `mov dword ptr [rbx+0x78],0x165`,
    #       紧接着 0x1b2a54f 把 vtable 换成 0x269fde8(所以 0x165 **不是**
    #       num_neighbor_systems 专属 —— 简报那半句是对的,错的是把它当 opcode);
    #   (b) num_neighbor_systems 工厂 **不直接写** +0x78,而是 0x1b33964 调共享基类
    #       构造器 0x187b9e0,由 0x187b9f7 `mov dword ptr [rdi+0x78],0x165` 写进去。
    # 两条合起来 ⇒ 0x165 是**族默认的比较运算符 id**,不是「图的 opcode」。
    ("has_factory", FACTORY, 0x1B2A53B, "mov dword ptr [rbx + 0x78], 0x165"),
    ("has_factory", FACTORY, 0x1B2A54F, "lea rax, [rip + 0xb75892]"),
    ("nn_factory", NN_FACTORY, 0x1B33964, "call 0x14187b9e0"),
    ("shared_ctor", SHARED_CTOR, 0x187B9F7, "mov dword ptr [rdi + 0x78], 0x165"),
    # 共享基体 0x1a92090:把 [self+0x78] 当**比较运算符 id** 派发
    ("op_dispatch", OPDISPATCH, 0x1A920D3, "mov ecx, dword ptr [rbx + 0x78]"),
    ("op_dispatch", OPDISPATCH, 0x1A920D6, "cmp ecx, 0x3cb"),
    ("op_dispatch", OPDISPATCH, 0x1A920E0, "sub ecx, 1"),
    ("op_dispatch", OPDISPATCH, 0x1A920E3, "je 0x141a92126"),
    ("op_dispatch", OPDISPATCH, 0x1A920E5, "sub ecx, 0x1d2"),
    ("op_dispatch", OPDISPATCH, 0x1A920EB, "je 0x141a9210e"),
    ("op_dispatch", OPDISPATCH, 0x1A920ED, "cmp ecx, 1"),
    ("op_dispatch", OPDISPATCH, 0x1A920F0, "jne 0x141a92193"),
    ("op_dispatch", OPDISPATCH, 0x1A92100, "setl al"),
    ("op_dispatch", OPDISPATCH, 0x1A92118, "setg al"),
    ("op_dispatch", OPDISPATCH, 0x1A92130, "sete al"),
    ("op_dispatch", OPDISPATCH, 0x1A92148, "setge al"),
    ("op_dispatch", OPDISPATCH, 0x1A9215E, "cmp ecx, 0x5b"),
    ("op_dispatch", OPDISPATCH, 0x1A92161, "jne 0x141a92193"),
    ("op_dispatch", OPDISPATCH, 0x1A9216D, "setne al"),
    ("op_dispatch", OPDISPATCH, 0x1A92185, "setle al"),
    # ---- §2.2 has_hyperlane_to `+0x18` = 0x1afe500 -------------------------
    # 先把 scope 解成系统对象(内联的 §1 解析器),再 call 核心读体
    ("hht_read", HHT_READ, 0x1AFE5AF, "cmp qword ptr [rbx + 8], 0x80"),
    ("hht_read", HHT_READ, 0x1AFE5B9, "mov eax, dword ptr [rbx + 0x10]"),
    ("hht_read", HHT_READ, 0x1AFE5BC, "mov dword ptr [rsp + 0x1b0], eax"),
    ("hht_read", HHT_READ, 0x1AFE5D0, "mov rdx, qword ptr [rip + 0x17625c1]"),
    ("hht_read", HHT_READ, 0x1AFE5EF, "cmp eax, dword ptr [rdx + 0x20]"),
    ("hht_read", HHT_READ, 0x1AFE5F6, "mov rax, qword ptr [rdx + 0x18]"),
    ("hht_read", HHT_READ, 0x1AFE607, "cmp dword ptr [rdx + 8], r8d"),
    ("hht_read", HHT_READ, 0x1AFE60D, "mov rdx, qword ptr [rip + 0x175f26c]"),
    ("hht_read", HHT_READ, 0x1AFE614, "mov r9b, 1"),
    ("hht_read", HHT_READ, 0x1AFE617, "lea rcx, [rdi + 0x3080]"),
    ("hht_read", HHT_READ, 0x1AFE61E, "mov r8b, 2"),
    ("hht_read", HHT_READ, 0x1AFE621, "call 0x140a6aa10"),
    # ---- §2.2 核心读体 0xa6aa10:读的就是 §1 的那个容器 ---------------------
    ("hht_core", HHT_CORE, 0xA6AA3A, "mov rdi, rdx"),
    ("hht_core", HHT_CORE, 0xA6AAE3, "mov rdx, qword ptr [rdi + 0x590]"),
    ("hht_core", HHT_CORE, 0xA6AAEA, "movsxd r9, dword ptr [rdi + 0x59c]"),
    ("hht_core", HHT_CORE, 0xA6AAF1, "mov r11, qword ptr [rip + 0x27f60a0]"),
    ("hht_core", HHT_CORE, 0xA6AAF8, "mov r10, qword ptr [rip + 0x27f2d81]"),
    ("hht_core", HHT_CORE, 0xA6AAFF, "shl r9, 5"),
    ("hht_core", HHT_CORE, 0xA6AB16, "mov r8d, dword ptr [rdx + 8]"),
    ("hht_core", HHT_CORE, 0xA6AB2A, "mov rax, qword ptr [r11 + 0x18]"),
    ("hht_core", HHT_CORE, 0xA6AB3B, "cmp dword ptr [rax + 8], r8d"),
    ("hht_core", HHT_CORE, 0xA6AB50, "add rdx, 0x20"),
    # ---- §2.3 closest_system `+0x18` = 0x1ae3700 ---------------------------
    ("cs_read", CS_READ, 0x1AE372E, "mov rdx, qword ptr [rip + 0x177d463]"),
    ("cs_read", CS_READ, 0x1AE3746, "cmp eax, dword ptr [rdx + 0x20]"),
    ("cs_read", CS_READ, 0x1AE3750, "mov rax, qword ptr [rdx + 0x18]"),
    ("cs_read", CS_READ, 0x1AE375E, "cmp dword ptr [rdi + 8], r8d"),
    ("cs_read", CS_READ, 0x1AE3764, "mov rdi, qword ptr [rip + 0x177a115]"),
    ("cs_read", CS_READ, 0x1AE383B, "mov rcx, rdi"),
    ("cs_read", CS_READ, 0x1AE384C, "call 0x1408c24d0"),
    ("cs_read", CS_READ, 0x1AE3853, "call 0x1408c25f0"),
    # ---- §2.3 派发 0x8c24d0 / 0x8c25f0:rdx = 系统对象 ----------------------
    ("cs_disp_a", CS_DISPATCH_A, 0x8C24E0, "mov rdi, rcx"),
    ("cs_disp_a", CS_DISPATCH_A, 0x8C2502, "mov rax, qword ptr [rip + 0x299b377]"),
    ("cs_disp_a", CS_DISPATCH_A, 0x8C2520, "mov rdx, rdi"),
    ("cs_disp_a", CS_DISPATCH_A, 0x8C2545, "call 0x1408cbb30"),
    ("cs_disp_b", CS_DISPATCH_B, 0x8C2600, "mov rdi, rcx"),
    ("cs_disp_b", CS_DISPATCH_B, 0x8C2622, "mov rax, qword ptr [rip + 0x299b257]"),
    ("cs_disp_b", CS_DISPATCH_B, 0x8C2640, "mov rdx, rdi"),
    ("cs_disp_b", CS_DISPATCH_B, 0x8C2665, "call 0x1408cdae0"),
    # ---- §2.3 BFS 0x8cbb30:frontier 里放系统对象指针,读它的 +0x590/+0x59c --
    ("cs_bfs", CS_BFS, 0x8CBB61, "mov rax, qword ptr [rip + 0x2995048]"),
    ("cs_bfs", CS_BFS, 0x8CBB68, "movsxd r9, dword ptr [rax + 0x59c]"),
    ("cs_bfs", CS_BFS, 0x8CBC72, "mov esi, dword ptr [rdx + 8]"),
    ("cs_bfs", CS_BFS, 0x8CBC88, "lea rbx, [r13*2]"),
    ("cs_bfs", CS_BFS, 0x8CBC90, "add rbx, r13"),
    ("cs_bfs", CS_BFS, 0x8CBC93, "mov qword ptr [r15 + rbx*8], rdx"),
    ("cs_bfs", CS_BFS, 0x8CBF93, "lea rax, [r8 + r8*2]"),
    ("cs_bfs", CS_BFS, 0x8CBF97, "lea r12, [r15 + rax*8]"),
    ("cs_bfs", CS_BFS, 0x8CBF9F, "mov rax, qword ptr [r12]"),
    ("cs_bfs", CS_BFS, 0x8CBFA3, "mov ecx, dword ptr [rax + 8]"),
    ("cs_bfs", CS_BFS, 0x8CC030, "mov rax, qword ptr [r12]"),
    ("cs_bfs", CS_BFS, 0x8CC034, "mov ebx, dword ptr [rax + 0x59c]"),
    ("cs_bfs", CS_BFS, 0x8CC03F, "mov rax, qword ptr [rax + 0x590]"),
    ("cs_bfs", CS_BFS, 0x8CC046, "mov ebx, dword ptr [rcx + rax + 8]"),
    ("cs_bfs", CS_BFS, 0x8CC0F1, "mov rdx, qword ptr [rip + 0x2994aa0]"),
    ("cs_bfs", CS_BFS, 0x8CC121, "mov rdi, qword ptr [rip + 0x2991758]"),
    ("cs_bfs", CS_BFS, 0x8CC45D, "add rcx, 0x20"),
    # ---- r15 = frontier 缓冲(栈上对象)的**写入链**,逐条核对 -----------------
    # r15 就是容器访问 [r12] 的基址;r12 又由 [r15+rax*8] 得到(rax = 3*idx)。
    ("cs_bfs", CS_BFS, 0x8CBBF8, "lea r15, [rsp + 0x20]"),
    ("cs_bfs", CS_BFS, 0x8CBBFD, "mov qword ptr [rbp + 8], r15"),
    ("cs_bfs", CS_BFS, 0x8CBD75, "mov r15, qword ptr [rbp + 8]"),
    ("cs_bfs", CS_BFS, 0x8CBF9B, "mov qword ptr [rbp + 0x18], r12"),
    # ---- §2.4 num_neighbor_systems:比较体 -> vtable+0xf0 -> 收集器 ----------
    # +0x18 槽本身是**比较体**:它按 self 的 vtable 取 +0xf0 槽再 call。
    ("nn_cmp", NN_CMP, 0x1B3CBCA, "mov rax, qword ptr [rcx]"),
    ("nn_cmp", NN_CMP, 0x1B3CBE0, "call qword ptr [rax + 0xf0]"),
    # +0xf0 槽 = 0x1b87240:它内联 §1 解析器,把解出的**系统对象**交给收集器
    ("nn_eval", NN_EVAL, 0x1B87281, "mov r9, qword ptr [rip + 0x16d9910]"),
    ("nn_eval", NN_EVAL, 0x1B872A2, "mov rax, qword ptr [r9 + 0x18]"),
    ("nn_eval", NN_EVAL, 0x1B872B0, "cmp dword ptr [r15 + 8], edx"),
    ("nn_eval", NN_EVAL, 0x1B872B6, "mov r15, qword ptr [rip + 0x16d65c3]"),
    ("nn_eval", NN_EVAL, 0x1B873D5, "mov edx, dword ptr [r15 + 8]"),
    ("nn_eval", NN_EVAL, 0x1B873DC, "call 0x141b86e30"),
    # 收集器 0x1b86e30:再解一次系统对象,遍历 §1 的容器
    ("nn_collect", NN_COLLECT, 0x1B86E64, "mov rbx, qword ptr [rip + 0x16d9d2d]"),
    ("nn_collect", NN_COLLECT, 0x1B86E6B, "mov r14, qword ptr [rip + 0x16d6a0e]"),
    ("nn_collect", NN_COLLECT, 0x1B86E8C, "mov rax, qword ptr [rax + rcx*8 + 8]"),
    ("nn_collect", NN_COLLECT, 0x1B86E96, "cmp dword ptr [rax + 8], edx"),
    ("nn_collect", NN_COLLECT, 0x1B86E9E, "mov r8d, dword ptr [rax + 0x59c]"),
    ("nn_collect", NN_COLLECT, 0x1B86EBF, "mov rax, qword ptr [rax + rcx*8 + 8]"),
    ("nn_collect", NN_COLLECT, 0x1B86ED1, "movsxd rax, dword ptr [rax + 0x59c]"),
    ("nn_collect", NN_COLLECT, 0x1B86F5A, "mov r14, r8"),
    ("nn_collect", NN_COLLECT, 0x1B86F5D, "movsxd r13, dword ptr [r14 + 0x59c]"),
    ("nn_collect", NN_COLLECT, 0x1B86F80, "mov rax, qword ptr [r14 + 0x590]"),
    ("nn_collect", NN_COLLECT, 0x1B86F87, "mov ebx, dword ptr [r15 + rax + 8]"),
    ("nn_collect", NN_COLLECT, 0x1B870FC, "add r15, 0x20"),
    # ---- §2.1 负对照:通用解释器是 thunk 目标;比较体不是 evaluate ----------
    ("nn_thunk", NN_THUNK, 0x1A92450, "jmp 0x140348db0"),
    ("shared_base", SHARED_BASE, 0x1A91AA4, "lea rdx, [rbx + 0x278]"),
    ("shared_base", SHARED_BASE, 0x1A91AC0, "jmp qword ptr [rax + 0x20]"),
    ("shared_cmp", SHARED_CMP, 0x349248, "call qword ptr [rax + 0x70]"),
    ("shared_cmp", SHARED_CMP, 0x34925C, "setne al"),
]

# 负对照的**区间字节**读数:区间里出现的原始 dword / 访存助记符计数
# assert_indirect = 该区间是否断言「零间接 call/jmp」(通用解释器按 vtable 槽派发,
# 本来就有间接调用 —— 那正是「不按 opcode 派发」的反证,所以只报数不断言 0)。
NEGATIVE_RANGES: list[tuple[str, int, int, bool, bool]] = [
    # 标签, 起, 止, 断言 0x165 与邻居访存为 0, 断言间接 call/jmp 为 0
    ("generic_interp", GENERIC_INTERP, GENERIC_INTERP_END, True, False),
    ("hht_cmp", HHT_CMP, 0x1AFE4F2, True, True),
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


_REG_ALIAS = {f"r{i}d": f"r{i}" for i in range(8, 16)}
_REG_ALIAS.update({"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
                   "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp"})


def last_write(insns, reg: str, before: int):
    """`before` 之前最后一次写 `reg` 的指令(用 capstone 的 regs_access,不是猜助记符)。

    32 位子寄存器(r15d/r8d/…)算作写父寄存器 —— 否则 `xor r15d,r15d` 会被漏掉。
    """
    for i in range(before - 1, -1, -1):
        ins = insns[i]
        try:
            _read, written = ins.regs_access()
        except Exception:
            continue
        for r in written:
            if r == X86_REG_INVALID:
                continue
            name = ins.reg_name(r)
            if _REG_ALIAS.get(name, name) == reg:
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


def main() -> int:
    exe = disrva.resolve_exe()
    sha = hashlib.sha256(pathlib.Path(exe).read_bytes()).hexdigest()

    print("=" * 78)
    print("hyperlane_read_scan —— 读路径(trigger 侧):与 §1 写路径的三角互证(零 shot 静态 RE)")
    print("=" * 78)
    print(f"exe        : {exe}")
    print(f"sha256     : {sha}")
    print(f"image base : 0x{BASE:x}(ASLR on)—— 下列所有地址都是 module-base-relative RVA")

    # ---- 1. 函数边界(.pdata) ----------------------------------------------
    print("\n[1] .pdata 函数边界(RUNTIME_FUNCTION)")
    labels = {
        "has_factory": FACTORY,
        "nn_factory": NN_FACTORY,
        "shared_ctor": SHARED_CTOR,
        "op_dispatch": OPDISPATCH,
        "hht_read": HHT_READ,
        "hht_core": HHT_CORE,
        "cs_read": CS_READ,
        "cs_disp_a": CS_DISPATCH_A,
        "cs_disp_b": CS_DISPATCH_B,
        "cs_bfs": CS_BFS,
        "generic": GENERIC_INTERP,
        "shared_base": SHARED_BASE,
        "shared_cmp": SHARED_CMP,
        "nn_cmp": NN_CMP,
        "nn_eval": NN_EVAL,
        "nn_collect": NN_COLLECT,
    }
    bounds = {}
    ok = True
    # 0x1a92450 是裸 thunk(不在 .pdata 里);0x8cdae0/0x8cd040 只核调用点存在
    for label, fn in labels.items():
        chunks = pdata_chunks(fn)
        if not chunks:
            print(f"  {label:<14} 0x{fn:x}  **不在 .pdata 里**")
            ok = False
            continue
        lo, hi = chunks[0][0], chunks[-1][1]
        print(f"  {label:<14} 0x{fn:x}  分块 "
              + " ".join(f"0x{b:x}..0x{e:x}" for b, e in chunks)
              + f"  => 逻辑范围 0x{lo:x}..0x{hi:x} ({hi - lo:#x} bytes)")
        bounds[label] = (lo, hi)
    print(f"  {'nn_thunk':<14} 0x{NN_THUNK:x}  **不在 .pdata 里**(裸 thunk);"
          f"边界人工指定 0x{NN_THUNK:x}..0x{NN_THUNK_END:x}")
    bounds["nn_thunk"] = (NN_THUNK, NN_THUNK_END)

    # ---- 1b. vtable(.rdata)槽位:读路径挂在 +0x18 ---------------------------
    print("\n[1b] vtable(.rdata)槽位 —— 读路径在 +0x18,不在 +0x28(通用解释器)")
    vt_ok = True
    for name, vt, slots in VTABLES:
        raw, sec = disrva.rd(vt, max(o for o, _ in slots) + 8)
        parts = []
        row_ok = True
        for off, want in slots:
            got = struct.unpack_from("<Q", raw, off)[0] - BASE
            hit = got == want
            parts.append(f"+0x{off:x}=0x{got:x}" + ("" if hit else f"(期望 0x{want:x})"))
            if not hit:
                row_ok = False
                vt_ok = False
        print(f"  {name:<22} 0x{vt:x} ({sec}): " + "  ".join(parts)
              + ("  OK" if row_ok else "  **MISMATCH**"))
    ok = ok and vt_ok

    # ---- 2. 逐站点核对 ---------------------------------------------------
    print("\n[2] 逐站点核对(读数 vs 计划期)")
    bodies: dict[str, list] = {}
    for label, fn, site, want in EXPECTED_SITES:
        if label not in bounds:
            continue
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
    print("  §2.1 `+0x78 = 0x165` 的两个写入点(族默认比较运算符 id,不是 opcode):")
    print("    0x1b2a53b  has_hyperlane_to 工厂内联写 [rbx+0x78]")
    print("    0x187b9f7  共享基类构造器 0x187b9e0 写 [rdi+0x78]"
          "(num_neighbor_systems 工厂 0x1b33964 调它)")

    # ---- 2b. 负对照:区间字节(通用解释器 / 比较槽) ------------------------
    print("\n[2b] 负对照 —— 读路径不在通用解释器、也不在 +0x20 比较槽")
    for name, lo, hi, assert_zero, assert_indirect in NEGATIVE_RANGES:
        code, sec = disrva.rd(lo, hi - lo)
        insns = disasm(lo, hi)
        op_hits = [i for i in insns
                   if any(op.type == X86_OP_MEM
                          and op.mem.disp in (CONTAINER_OFF, DATA_OFF, COUNT_OFF,
                                              OP_FIELD_OFF)
                          for op in i.operands)]
        ind_hits = [i for i in insns
                    if i.mnemonic in ("call", "jmp") and "qword ptr" in i.op_str]
        print(f"  {name} 0x{lo:x}..0x{hi:x} ({sec}, {len(insns)} 条指令):")
        for nm, d in (("0x165 立即数", HAS_OP_VALUE), ("+0x588", CONTAINER_OFF),
                      ("+0x590", DATA_OFF), ("+0x59c", COUNT_OFF)):
            cnt = code.count(d.to_bytes(4, "little"))
            if nm.startswith("0x165") and not assert_zero:
                print(f"    原始 dword {nm} 出现 {cnt} 处(本区间不作断言)")
                continue
            print(f"    原始 dword {nm} 出现 {cnt} 处"
                  + ("  OK(期望 0)" if cnt == 0 else "  **MISMATCH(期望 0)**"))
            if cnt:
                ok = False
        print(f"    含 +0x588/+0x590/+0x59c/+0x78 位移的访存指令 {len(op_hits)} 条"
              + ("  OK(期望 0)" if not op_hits else "  **MISMATCH(期望 0)**"))
        if op_hits:
            ok = False
            for i in op_hits[:6]:
                print(f"      0x{i.address - BASE:x}  {text(i)}")
        if assert_indirect:
            print(f"    间接 call/jmp [reg+..] {len(ind_hits)} 条"
                  + ("  OK(期望 0)" if not ind_hits else "  **MISMATCH(期望 0)**"))
            if ind_hits:
                ok = False
        else:
            print(f"    间接 call/jmp [reg+..] {len(ind_hits)} 条"
                  f"(**不断言 0**:本区间按 vtable 槽派发,这正是「不按 opcode 派发」的反证)")
            for i in ind_hits:
                print(f"      0x{i.address - BASE:x}  {text(i)}")

    # ---- 3. rip 目标解码比对 ---------------------------------------------
    print("\n[3] rip 目标解码(从字节解出,再与常量比对)")
    rip_ok = True
    for label, fn, want, what in RIP_TARGETS:
        insns = bodies.get(label) or disasm(*bounds[label])
        tgt = None
        # 同一 (label, fn) 可能有多个 rip 站点,按期望值匹配任一个
        cands = []
        for ins in insns:
            t = rip_target(ins)
            if t is not None:
                cands.append((ins.address - BASE, t))
        hit = next((c for c in cands if c[1] == want), None)
        mark = "OK" if hit else "**MISMATCH**"
        shown = f"0x{hit[0]:x} -> 0x{hit[1]:x}" if hit else "无匹配站点"
        print(f"  {label:<12} {what:<24} 期望 0x{want:x}  实读 {shown}  {mark}")
        if not hit:
            rip_ok = False
    ok = ok and rip_ok

    # ---- 4. §2.2 has_hyperlane_to 读路径 + 基址来源 ------------------------
    print("\n[4] §2.2 has_hyperlane_to 读路径:"
          f"vtable+0x18 = 0x{HHT_READ:x} -> 0x{HHT_CORE:x} 核心读体")
    core = bodies.get("hht_core") or disasm(*bounds["hht_core"])
    for site in (0xA6AAE3, 0xA6AAEA):
        idx = next((k for k, i in enumerate(core) if i.address - BASE == site), None)
        if idx is None:
            continue
        base, disp = mem_base_and_disp(core[idx])
        print(f"  0x{site:x}  {text(core[idx])}   ; 容器访问,基址 {base},disp {disp:#x}")
        for line in provenance(core, idx, base):
            print(line)
    # 关键:0xa6aa10 的 rdi = rdx 参数 = 调用方解出的系统对象;调用点是 0x1afe621
    print("  核心读体的基址链:0xa6aa3a `mov rdi, rdx`(rdx = 第二实参 = 系统对象)")
    hht = bodies.get("hht_read") or disasm(*bounds["hht_read"])
    for site in (0x1AFE5FD, 0x1AFE60D):
        ins = next((i for i in hht if i.address - BASE == site), None)
        if ins is not None:
            tag = "命中分支:解出的系统对象 -> rdx" if site == 0x1AFE5FD else \
                  "未命中分支:回退对象 -> rdx"
            print(f"  0x{site:x}  {text(ins)}   ; {tag}")

    # ---- 5. §2.3 closest_system 读路径 + 基址来源 -------------------------
    print("\n[5] §2.3 closest_system 读路径:"
          f"vtable+0x18 = 0x{CS_READ:x} -> 0x{CS_DISPATCH_A:x}/0x{CS_DISPATCH_B:x}"
          f" -> 0x{CS_BFS:x} BFS")
    bfs = bodies.get("cs_bfs") or disasm(*bounds["cs_bfs"])
    for site in (0x8CC034, 0x8CC03F, 0x8CC046):
        idx = next((k for k, i in enumerate(bfs) if i.address - BASE == site), None)
        if idx is None:
            continue
        base, disp = mem_base_and_disp(bfs[idx])
        print(f"  0x{site:x}  {text(bfs[idx])}   ; 容器访问,基址 {base},disp {disp:#x}")
    # r12 是 frontier 三元组指针;它的 +0 字段是系统对象指针
    idx12 = next((k for k, i in enumerate(bfs) if i.address - BASE == 0x8CC030), None)
    if idx12 is not None:
        print(f"  0x8cc030  {text(bfs[idx12])}   ; frontier 元素 +0 = 系统对象指针")
        for line in provenance(bfs, idx12, "r12"):
            print(line)
        idxw = last_write(bfs, "r12", idx12)
        if idxw is not None:
            print(f"    r12 的写入点 0x{bfs[idxw].address - BASE:x}  {text(bfs[idxw])}")
            for line in provenance(bfs, idxw, "r15"):
                print(f"    ({line.strip()})")
    # r15 的写入链:栈上缓冲区地址 —— 由字节逐条钉住
    print("  r15(frontier 缓冲基址)写入链:"
          "0x8cbbf8 `lea r15,[rsp+0x20]` -> 0x8cbbfd `mov [rbp+8],r15`"
          " -> 0x8cbd75 `mov r15,[rbp+8]`(复用)")
    # frontier 的 +0 字段由函数入参 rdx(系统对象)装入;id 取自 [rdx+8]
    print("  frontier 装入:0x8cbc93 `mov [r15 + rbx*8], rdx`(rbx = 3*id,"
          "即 stride 0x18 的三元组),rdx = 函数入参 = 系统对象;")
    print("                 0x8cbc72 `mov esi, [rdx + 8]` —— 系统 id 在 +8(与 §1 一致)")

    # ---- 5b. §2.4 num_neighbor_systems 读路径 ------------------------------
    print("\n[5b] §2.4 num_neighbor_systems 读路径:"
          f"vtable+0x18 = 0x{NN_CMP:x}(比较体)-> vtable+0xf0 = 0x{NN_EVAL:x}"
          f" -> 0x{NN_COLLECT:x} 收集器")
    nnc = bodies.get("nn_collect") or disasm(*bounds["nn_collect"])
    for site in (0x1B86E9E, 0x1B86ED1, 0x1B86F5D, 0x1B86F80):
        idx = next((k for k, i in enumerate(nnc) if i.address - BASE == site), None)
        if idx is None:
            continue
        base, disp = mem_base_and_disp(nnc[idx])
        print(f"  0x{site:x}  {text(nnc[idx])}   ; 容器访问,基址 {base},disp {disp:#x}")
        for line in provenance(nnc, idx, base):
            print(line)
    print("  基址链:0x1b86f5a `mov r14, r8` —— r8 是 §1 解析器在全局 0x"
          f"{RESOLVER_GLOBAL:x} 的表里按 id 查到的**系统对象**(entry +8 == id);")
    print("         0x1b86e8c/0x1b86ebf `mov rax, [rax + rcx*8 + 8]` —— 同一个解析器")
    print("         (表基址 = [global+0x18],边界 = [global+0x20]),rax = 系统对象;")
    print("  合流说明(线性扫描只看到**最近一次**写,这里两路都到同一站点):")
    print("    0x1b86e99 `je 0x141b86e9e`(rax = 0x1b86e8c 解出的 entry)"
          " / 0x1b86e9b `mov rax, r14`(回退对象 0x325d880)")
    print("    0x1b86ecc `je 0x141b86ed1`(rax = 0x1b86ebf 解出的 entry)"
          " / 0x1b86ece `mov rax, r14`(回退对象 0x325d880)")
    print("    0x1b86f58 `jne 0x141b86f5d`(r14 保持回退) / 0x1b86f5a `mov r14, r8`(解出的)")
    print("    —— 两路的基址都是**系统对象**,位移相同 ⇒ 与 §1 的容器是同一个")
    print("  步长与元素:0x1b86f80 `mov rax, [r14 + 0x590]`(数据指针)")
    print("             0x1b86f87 `mov ebx, [r15 + rax + 8]`(r15 = 字节偏移,元素 +8 = id)")
    print("             0x1b86f6d `xor r15d, r15d` -> 0x1b870fc `add r15, 0x20`(stride 0x20)")
    print("             0x1b8700b `jne 0x141b86f80`(循环回到取数据指针那一条)")

    # ---- 6. §2.5 与 §1 的三角互证 -----------------------------------------
    print("\n[6] §2.5 与 §1 的三角互证 —— 同一组 offsets、同一 base provenance")
    print(f"  §1 写侧: resolver=0x3939f0, container=system+0x{CONTAINER_OFF:x},"
          f" data=+0x{DATA_OFF:x}, count=+0x{COUNT_OFF:x}, stride=0x{ELEM_STRIDE:x},"
          f" 元素 +8 = id")
    print(f"  读侧 A : 0x{HHT_CORE:x} 读 [rdi+0x{DATA_OFF:x}] / [rdi+0x{COUNT_OFF:x}],"
          f" shl 5 = stride 0x{ELEM_STRIDE:x}, 元素 +8 取 id;rdi = 解析器解出的系统对象")
    print(f"  读侧 B : 0x{CS_BFS:x} 读 [obj+0x{DATA_OFF:x}] / [obj+0x{COUNT_OFF:x}],"
          f" add 0x20 = stride 0x{ELEM_STRIDE:x}, 元素 +8 取 id;obj = frontier 里的系统对象")
    print(f"  读侧 C : 0x{NN_COLLECT:x} 读 [r14+0x{DATA_OFF:x}] / [r14+0x{COUNT_OFF:x}],"
          f" add 0x20 = stride 0x{ELEM_STRIDE:x}, 元素 +8 取 id;r14 = 解析器解出的系统对象")
    print(f"  三条读路径都内联了 §1 的解析器(全局 0x{RESOLVER_GLOBAL:x} 表 [+0x18]/[+0x20],"
          f" 元素 [+8]==id,回退 0x{FALLBACK_GLOBAL:x})")
    print(f"  §1.10 边界:0x8cbb61 读的是 §88 全局 0x{S88_GLOBAL:x}(同位移、不同对象),"
          f"只用来量 frontier 大小")

    # ---- 7. 判决字段(仅当全部通过) ---------------------------------------
    if not ok:
        print("\n[check] 交叉校验失败 —— 不打印判决字段(退出码 1)", file=sys.stderr)
        return 1
    print("\n[check] 全部读数与计划期一致")
    print(f"  read_handler_rva    = 0x{HHT_READ:x}(has_hyperlane_to vtable+0x18)"
          f" / 0x{CS_READ:x}(closest_system vtable+0x18)"
          f" / 0x{NN_COLLECT:x}(num_neighbor_systems vtable+0xf0 -> 0x{NN_EVAL:x})")
    print(f"  neighbor_vector_off = 0x{DATA_OFF:x}")
    print(f"  neighbor_count_off  = 0x{COUNT_OFF:x}")
    print(f"  elem_stride         = 0x{ELEM_STRIDE:x}")
    print(f"  elem_id_off         = +8")
    print(f"  owner               = system_object(解析器解出 / frontier 装载)")
    print(f"  op_field_off        = 0x{OP_FIELD_OFF:x}(比较运算符 token id,不是 opcode)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
