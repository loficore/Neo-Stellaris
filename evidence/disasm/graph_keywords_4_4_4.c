; graph_keywords_4_4_4.c — 图相关 keyword 的「执行体/求值槽」锚点表(Task 1,零 shot 静态 RE)
;
; exe        : stellaris.exe 4.4.4 (46,253,688 bytes; sha256
;              9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56)
; image base : 0x140000000 (ASLR on) —— 下表中每个数都是 module-base-relative RVA
; exe path   : 走 disrva.resolve_exe() 候选链(NS_STELLARIS_EXE 优先)
;
; 生成命令(重跑同一条即得本文件):
;   python3 scripts/scratch/2026-11_graph_runtime/graph_keyword_bodies.py \
;       --emit-c evidence/disasm/graph_keywords_4_4_4.c
;
; 校验(简报 Step 4 的原命令;这一行里的 0x1A92450 是命令的模式串本身,
;       数据行按本仓库约定一律写小写 0x1a92450):
;   grep -E "add_hyperlane|0x1874540|0x1A92450" evidence/disasm/graph_keywords_4_4_4.c
;
; 口径:class_info 是 .rdata 里 16 B 的记录 {+0x00 deleter, +0x08 factory/create}。
; factory 反汇编到第一个 ret;vtable = factory 对**对象寄存器**(call operator_new
; 0x2185218 后的 `mov <reg>, rax`)偏移 0 处**最后**一次 `lea rax,[rip+X]; mov [reg],rax`
; 写入的 X(最后一次写才是活着的 vtable)。槽值直接读 vtable+off 的 qword。
; 每条 factory 的字节窗口 0x400,遇到第一个 ret 停。
;
; exe 实际读取: /var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe  (46253688 bytes)
;
; ==================== 锚点表 ====================
; keyword                class_info  factory     vtable      +0x20      +0x28      +0x48      +0x80
; add_hyperlane          0x260d4e0  0x189d510   0x25f7448  0x3b1770   0x1874820  0x1874540  0x1b4550  
; remove_hyperlane       0x260d4d0  0x189d580   0x25f7368  0x3b1770   0x1874cf0  0x1874a00  0x1b4550  
; has_hyperlane_to       0x269db28  0x1b2a510   0x269fde8  0x1afde20  0x1a91a80  0x1afe750  0x349230  
; num_neighbor_systems   0x269c3c8  0x1b33930   0x266c108  0x1a92070  0x1a92450  0x1b875b0  0x349230  
; spawn_system           0x26097f8  0x18a52b0   0x25ecc10  0x3b1770   0x18f7770  0x18f6b90  0x1b4550  
;
; 执行/求值槽(简报 Expected 表点名的那些;**值全部由上面的读数格式化**,不是手写常量):
;   add_hyperlane        +0x48 = 0x1874540
;   remove_hyperlane     +0x48 = 0x1874a00
;   has_hyperlane_to     +0x20 = 0x1afde20, +0x28 = 0x1a91a80 (352 张表共用的求值槽)
;   num_neighbor_systems +0x28 = 0x1a92450 (thunk -> 0x348db0)
;   spawn_system         +0x48 = 0x18f6b90
;
; ==================== 逐 keyword 原件 ====================
;
; ----------------------------------------------------------------------
; add_hyperlane  (class_info 0x260d4e0 @ .rdata)
;   +0x00 deleter = 0x34c090 @ .text
;   +0x08 factory = 0x189d510 @ .text
;   vtable        = 0x25f7448 @ .rdata  (对象寄存器 rbx)
;     vtable+0x20 = 0x3b1770 @ .text
;     vtable+0x28 = 0x1874820 @ .text
;     vtable+0x48 = 0x1874540 @ .text
;     vtable+0x80 = 0x1b4550 @ .text
; factory 0x189d510 反汇编到第一个 ret:
  0189d510  push    rbx
  0189d512  sub     rsp, 0x20
  0189d516  mov     ecx, 0x400
  0189d51b  call    0x142185218  ; -> 0x2185218
  0189d520  mov     rbx, rax
  0189d523  mov     qword ptr [rsp + 0x38], rax
  0189d528  xor     edx, edx
  0189d52a  mov     r8d, 0x400
  0189d530  mov     rcx, rax
  0189d533  call    0x142188170  ; -> 0x2188170
  0189d538  mov     rcx, rbx
  0189d53b  call    0x1403afb40  ; -> 0x3afb40
  0189d540  nop     
  0189d541  lea     rax, [rip + 0xd59f00]  ; -> 0x25f7448
  0189d548  mov     qword ptr [rbx], rax
  0189d54b  lea     rax, [rip + 0xd59df6]  ; -> 0x25f7348
  0189d552  mov     qword ptr [rbx + 8], rax
  0189d556  lea     rcx, [rbx + 0xc0]
  0189d55d  call    0x140353bd0  ; -> 0x353bd0
  0189d562  nop     
  0189d563  lea     rcx, [rbx + 0x260]
  0189d56a  call    0x140353bd0  ; -> 0x353bd0
  0189d56f  nop     
  0189d570  mov     rax, rbx
  0189d573  add     rsp, 0x20
  0189d577  pop     rbx
  0189d578  ret     
;
; ----------------------------------------------------------------------
; remove_hyperlane  (class_info 0x260d4d0 @ .rdata)
;   +0x00 deleter = 0x34c090 @ .text
;   +0x08 factory = 0x189d580 @ .text
;   vtable        = 0x25f7368 @ .rdata  (对象寄存器 rbx)
;     vtable+0x20 = 0x3b1770 @ .text
;     vtable+0x28 = 0x1874cf0 @ .text
;     vtable+0x48 = 0x1874a00 @ .text
;     vtable+0x80 = 0x1b4550 @ .text
; factory 0x189d580 反汇编到第一个 ret:
  0189d580  push    rbx
  0189d582  sub     rsp, 0x20
  0189d586  mov     ecx, 0x400
  0189d58b  call    0x142185218  ; -> 0x2185218
  0189d590  mov     rbx, rax
  0189d593  mov     qword ptr [rsp + 0x38], rax
  0189d598  xor     edx, edx
  0189d59a  mov     r8d, 0x400
  0189d5a0  mov     rcx, rax
  0189d5a3  call    0x142188170  ; -> 0x2188170
  0189d5a8  mov     rcx, rbx
  0189d5ab  call    0x1403afb40  ; -> 0x3afb40
  0189d5b0  nop     
  0189d5b1  lea     rax, [rip + 0xd59db0]  ; -> 0x25f7368
  0189d5b8  mov     qword ptr [rbx], rax
  0189d5bb  lea     rax, [rip + 0xd59d86]  ; -> 0x25f7348
  0189d5c2  mov     qword ptr [rbx + 8], rax
  0189d5c6  lea     rcx, [rbx + 0xc0]
  0189d5cd  call    0x140353bd0  ; -> 0x353bd0
  0189d5d2  nop     
  0189d5d3  lea     rcx, [rbx + 0x260]
  0189d5da  call    0x140353bd0  ; -> 0x353bd0
  0189d5df  nop     
  0189d5e0  mov     rax, rbx
  0189d5e3  add     rsp, 0x20
  0189d5e7  pop     rbx
  0189d5e8  ret     
;
; ----------------------------------------------------------------------
; has_hyperlane_to  (class_info 0x269db28 @ .rdata)
;   +0x00 deleter = 0x34c090 @ .text
;   +0x08 factory = 0x1b2a510 @ .text
;   vtable        = 0x269fde8 @ .rdata  (对象寄存器 rbx)
;     vtable+0x20 = 0x1afde20 @ .text
;     vtable+0x28 = 0x1a91a80 @ .text
;     vtable+0x48 = 0x1afe750 @ .text
;     vtable+0x80 = 0x349230 @ .text
;     (被覆盖的 vtable 候选:较前写于 0x1b2a531 -> 0x26a2cc0)
; factory 0x1b2a510 反汇编到第一个 ret:
  01b2a510  push    rbx
  01b2a512  sub     rsp, 0x20
  01b2a516  mov     ecx, 0x3c0
  01b2a51b  call    0x142185218  ; -> 0x2185218
  01b2a520  mov     rbx, rax
  01b2a523  mov     qword ptr [rsp + 0x38], rax
  01b2a528  mov     rcx, rax
  01b2a52b  call    0x1403488e0  ; -> 0x3488e0
  01b2a530  nop     
  01b2a531  lea     rax, [rip + 0xb78788]  ; -> 0x26a2cc0
  01b2a538  mov     qword ptr [rbx], rax
  01b2a53b  mov     dword ptr [rbx + 0x78], 0x165
  01b2a542  lea     rcx, [rbx + 0x80]
  01b2a549  call    0x140353bd0  ; -> 0x353bd0
  01b2a54e  nop     
  01b2a54f  lea     rax, [rip + 0xb75892]  ; -> 0x269fde8
  01b2a556  mov     qword ptr [rbx], rax
  01b2a559  lea     rcx, [rbx + 0x220]
  01b2a560  mov     qword ptr [rsp + 0x40], rcx
  01b2a565  mov     edx, 0x2c8c
  01b2a56a  call    0x1403549d0  ; -> 0x3549d0
  01b2a56f  nop     
  01b2a570  mov     rax, rbx
  01b2a573  add     rsp, 0x20
  01b2a577  pop     rbx
  01b2a578  ret     
;
; ----------------------------------------------------------------------
; num_neighbor_systems  (class_info 0x269c3c8 @ .rdata)
;   +0x00 deleter = 0x34c090 @ .text
;   +0x08 factory = 0x1b33930 @ .text
;   vtable        = 0x266c108 @ .rdata  (对象寄存器 rdi)
;     vtable+0x20 = 0x1a92070 @ .text
;     vtable+0x28 = 0x1a92450 @ .text  (thunk -> 0x348db0)
;     vtable+0x48 = 0x1b875b0 @ .text
;     vtable+0x80 = 0x349230 @ .text
; factory 0x1b33930 反汇编到第一个 ret:
  01b33930  mov     qword ptr [rsp + 8], rbx
  01b33935  mov     qword ptr [rsp + 0x18], rsi
  01b3393a  push    rdi
  01b3393b  sub     rsp, 0x20
  01b3393f  mov     ecx, 0x7b8
  01b33944  call    0x142185218  ; -> 0x2185218
  01b33949  mov     rdi, rax
  01b3394c  mov     qword ptr [rsp + 0x38], rax
  01b33951  xor     edx, edx
  01b33953  mov     r8d, 0x7b8
  01b33959  mov     rcx, rax
  01b3395c  call    0x142188170  ; -> 0x2188170
  01b33961  mov     rcx, rdi
  01b33964  call    0x14187b9e0  ; -> 0x187b9e0
  01b33969  nop     
  01b3396a  lea     rax, [rip + 0xb38797]  ; -> 0x266c108
  01b33971  mov     qword ptr [rdi], rax
  01b33974  lea     rcx, [rdi + 0x2a8]
  01b3397b  call    0x14034ecd0  ; -> 0x34ecd0
  01b33980  lea     rsi, [rip + 0x9945f9]  ; -> 0x24c7f80
  01b33987  mov     qword ptr [rdi + 0x2a8], rsi
  01b3398e  mov     dword ptr [rdi + 0x4c8], 1
  01b33998  lea     rcx, [rdi + 0x4d0]
  01b3399f  call    0x14034ecd0  ; -> 0x34ecd0
  01b339a4  mov     qword ptr [rdi + 0x4d0], rsi
  01b339ab  mov     dword ptr [rdi + 0x6f0], 1
  01b339b5  lea     rcx, [rdi + 0x6f8]
  01b339bc  call    0x14034ba00  ; -> 0x34ba00
  01b339c1  nop     
  01b339c2  mov     rax, rdi
  01b339c5  mov     rbx, qword ptr [rsp + 0x30]
  01b339ca  mov     rsi, qword ptr [rsp + 0x40]
  01b339cf  add     rsp, 0x20
  01b339d3  pop     rdi
  01b339d4  ret     
;
; ----------------------------------------------------------------------
; spawn_system  (class_info 0x26097f8 @ .rdata)
;   +0x00 deleter = 0x34c090 @ .text
;   +0x08 factory = 0x18a52b0 @ .text
;   vtable        = 0x25ecc10 @ .rdata  (对象寄存器 rbx)
;     vtable+0x20 = 0x3b1770 @ .text
;     vtable+0x28 = 0x18f7770 @ .text
;     vtable+0x48 = 0x18f6b90 @ .text
;     vtable+0x80 = 0x1b4550 @ .text
; factory 0x18a52b0 反汇编到第一个 ret:
  018a52b0  mov     qword ptr [rsp + 8], rbx
  018a52b5  push    rdi
  018a52b6  sub     rsp, 0x20
  018a52ba  mov     ecx, 0x1f8
  018a52bf  call    0x142185218  ; -> 0x2185218
  018a52c4  mov     rbx, rax
  018a52c7  mov     qword ptr [rsp + 0x38], rax
  018a52cc  xor     edx, edx
  018a52ce  mov     r8d, 0x1f8
  018a52d4  mov     rcx, rax
  018a52d7  call    0x142188170  ; -> 0x2188170
  018a52dc  mov     qword ptr [rbx + 0xc0], 0xffffffffffffffff
  018a52e7  mov     qword ptr [rbx + 0xc8], 0xf4240
  018a52f2  mov     qword ptr [rbx + 0xd0], 0x4c4b40
  018a52fd  xor     edi, edi
  018a52ff  mov     qword ptr [rbx + 0xd8], rdi
  018a5306  mov     rax, qword ptr [rip + 0x19c804b]  ; -> 0x326d358
  018a530d  mov     qword ptr [rbx + 0xe0], rax
  018a5314  mov     dword ptr [rbx + 0xe8], edi
  018a531a  mov     byte ptr [rbx + 0xec], 1
  018a5321  mov     rcx, rbx
  018a5324  call    0x1403afb40  ; -> 0x3afb40
  018a5329  nop     
  018a532a  lea     rax, [rip + 0xd478df]  ; -> 0x25ecc10
  018a5331  mov     qword ptr [rbx], rax
  018a5334  lea     rax, [rip + 0xd478b5]  ; -> 0x25ecbf0
  018a533b  mov     qword ptr [rbx + 8], rax
  018a533f  mov     dword ptr [rbx + 0xf0], edi
  018a5345  mov     qword ptr [rbx + 0xf8], rdi
  018a534c  mov     qword ptr [rbx + 0x100], rdi
  018a5353  mov     qword ptr [rbx + 0x110], rdi
  018a535a  mov     qword ptr [rbx + 0x118], 0xf
  018a5365  mov     word ptr [rbx + 0x120], 1
  018a536e  lea     rcx, [rbx + 0x128]
  018a5375  call    0x1403afb40  ; -> 0x3afb40
  018a537a  mov     qword ptr [rbx + 0x1e8], rdi
  018a5381  mov     byte ptr [rbx + 0x1f0], dil
  018a5388  mov     rax, rbx
  018a538b  mov     rbx, qword ptr [rsp + 0x30]
  018a5390  add     rsp, 0x20
  018a5394  pop     rdi
  018a5395  ret     
;
; ==================== 校验 ====================
; 本文件由 --emit-c **只在校验通过时**写出:探针先与计划期 Expected 表逐项核对,任一不等就
; 拒绝落盘(exit 1、不写文件)。所以本文件的内容必然与探针这一次的读数一致,不可能从一次
; 失败的探针里产出一份好看的证据表。
