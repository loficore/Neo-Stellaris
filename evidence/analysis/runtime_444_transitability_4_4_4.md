## §2 owner 写侧:`set_owner` 走到哪、字段落在哪

### §2.1 factory → 最终 vptr

```text
$ python3 scripts/disrva.py 0x1893b30 60
; stellaris.exe  .text RVA 0x1893b30  (96 insns)
  01893b30  push    rbx
  01893b32  sub     rsp, 0x20
  01893b36  mov     ecx, 0x260
  01893b3b  call    0x142185218  ; -> 0x2185218
  01893b40  mov     rbx, rax
  01893b48  xor     edx, edx
  01893b4a  mov     r8d, 0x260
  01893b50  mov     rcx, rax
  01893b53  call    0x142188170  ; -> 0x2188170
  01893b58  mov     rcx, rbx
  01893b5b  call    0x1403afb40  ; -> 0x3afb40
  01893b61  lea     rax, [rip + 0xd82390]  ; -> 0x2615ef8
  01893b68  mov     qword ptr [rbx], rax
  01893b6b  lea     rax, [rip + 0xd57686]  ; -> 0x25eb1f8
  01893b72  mov     qword ptr [rbx + 8], rax
  01893b76  lea     rcx, [rbx + 0xc0]
  01893b7d  mov     qword ptr [rsp + 0x40], rcx
  01893b82  mov     edx, 0x2c8b
  01893b87  call    0x1403549d0  ; -> 0x3549d0
  01893b8d  lea     rax, [rip + 0xd74264]  ; -> 0x2607df8
  01893b94  mov     qword ptr [rbx], rax
  01893b97  lea     rax, [rip + 0xd5765a]  ; -> 0x25eb1f8
  01893b9e  mov     qword ptr [rbx + 8], rax
  01893ba2  mov     rax, rbx
  01893ba5  add     rsp, 0x20
  01893ba9  pop     rbx
  01893baa  ret
```

- 对象大小 `0x260`;基类 ctor `0x3afb40`(= CEffect,`pinned(§17)` 的家族)。
- vptr #1 = `0x2615ef8`(中间基类),**最终 vptr = `0x2607df8`**,副 vptr(`[obj+8]`)= `0x25eb1f8`。
- 成员 ctor:`0x3549d0(this = obj+0xc0, edx = 0x2c8b)` —— 这个 `0x2c8b` 是**成员的类型/令牌 id**,
  不是 owner。§2.2 会看到 slot[1] 把解析结果 copy-assign 进这一格。

### §2.2 slot[1] 是 parse,不是执行

```text
$ python3 scripts/vtable.py 0x2607df8 --slots 30        # 摘录
  [0x0] +0x00 -> 17f3640  bounds 17f3640..17f3683
  [0x1] +0x08 -> 17f2fe0  bounds 17f2fe0..17f3053
  [0x2] +0x10 -> 3b01a0  bounds 3b01a0..3b0f7e
  [0x5] +0x28 -> 1801930  bounds 1801930..1801e53
          str 2618db0 "SET_OWNER_EFFECT"
          str 2511714 "OWNER"
          str 253c4e8 "OBJECT"
  [0x9] +0x48 -> 18015f0  bounds 18015f0..180192d
          str 247f510 "set_owner"
          str 2618e50 "Trying to assign a regular owner to empty uncolonizable planet %"
  [0x12] +0x90 -> 17f3060  bounds 17f3060..17f3636
          str 2616028 "Effect has invalid target: '%s' at %s"
  [0x13] +0x98 -> 3b1420  bounds 3b1420..3b1467          ; bool 谓词(pinned(§23.1/§52))
```

`slot[0]` = deleting destructor(`call 0x2185254` + `edx=0x260`),`slot[1]` = `0x17f2fe0`,`slot[2]` =
`0x3b01a0`(instantiate,`pinned(§57.2)`)。

```text
$ python3 scripts/disrva.py 0x17f2fe0 40
  017f2ff2  mov     rdi, r8
  017f2ff5  mov     rsi, rcx
  017f2ff8  add     rdx, 0x278
  017f2fff  lea     rcx, [rsp + 0x20]
  017f3004  call    0x141d156e0  ; -> 0x1d156e0
  017f3009  lea     r9, [rsi + 0x28]                 ; self->name / id
  017f300d  mov     r8, rdi
  017f3010  mov     rdx, rax
  017f3013  lea     rcx, [rsp + 0x140]
  017f301b  call    0x140354260  ; -> 0x354260      ; ctor of a ~0x1a0 B value object
  017f3021  lea     rcx, [rsi + 0xc0]                ; 成员
  017f3028  mov     rdx, rax
  017f302b  call    0x140345860  ; -> 0x345860      ; copy-assign into self+0xc0
```

`0x345860` 逐字是字段拷贝(`+0/+0x30/+0x60/+0x68/+0x188/+0x190/+0x194/+0x198/+0x199`),
不是语义写。⇒ **`set_owner` 的执行体只能是 slot[9] = `0x18015f0`。**

### §2.3 `set_owner` 的 ExecuteActual 按 scope 编码分派

```text
$ python3 scripts/disrva.py 0x18015f0 --len=0x300        # 摘录(全量 0x33d B)
  018015f0  mov     qword ptr [rsp + 0x10], rbx
  01801604  mov     rbx, rdx                             ; ctx
  01801607  mov     rbp, rcx                             ; self
  0180160a  add     rcx, 0xc0
  01801611  lea     r8, [rbp + 0x28]
  01801615  lea     r9, [rip + 0xc7def4]  ; -> 0x247f510   ; "set_owner"
  0180161c  call    0x14035eee0  ; -> 0x35eee0           ; 取参数
  01801621  mov     rdi, rax
  01801624  lea     rcx, [rax + 0x18]
  01801628  mov     r8, qword ptr [rcx]
  0180162b  call    qword ptr [r8 + 8]
  0180162f  test    al, al
  01801631  je      0x141801917
  01801637  mov     rcx, qword ptr [rbx + 8]             ; ctx+8 = 分派键
  0180163b  cmp     rcx, 2
  0180163f  jne     0x141801767
  01801645  mov     rcx, rbx
  01801648  call    0x140393be0  ; -> 0x393be0
  0180164d  mov     rsi, rax
  01801650  mov     ecx, dword ptr [rax + 0xe0]          ; id @ +0xe0
  01801656  mov     r8, qword ptr [rip + 0x1a5fa0b]  ; -> 0x3261068
  01801662  mov     eax, ecx
  01801664  and     eax, 0xffffff
  01801669  cmp     eax, dword ptr [r8 + 0x20]
  01801682  cmp     dword ptr [rdx + 0x10], ecx
  ...
  01801767  movabs  rax, 0x10000000000
  01801771  cmp     rcx, rax                             ; 键 = 0x10000000000
  ...
  018017d2  cmp     rcx, 0x40                            ; 键 = 0x40
  018017dc  mov     rcx, rbx
  018017df  call    0x140393f30  ; -> 0x393f30           ; 键 0x40 的解析器
  ...
  01801820  cmp     dword ptr [rbx + 0x32c], 0
  01801829  mov     rdx, qword ptr [rbx + 0x320]
  01801830  mov     rax, qword ptr [rip + 0x1a5f379]  ; -> 0x3260bb0
  01801845  mov     edx, dword ptr [rdx]
  01801847  call    0x1409c0fd0  ; -> 0x9c0fd0
  01801865  xor     r8d, r8d
  01801868  mov     r9b, 6
  0180186b  mov     rdx, rdi
  0180186e  mov     rcx, rsi
  01801871  call    0x140816dd0  ; -> 0x816dd0
  01801876  mov     rcx, rbx
  01801879  call    0x140cf4bd0  ; -> 0xcf4bd0
  0180189e  cmp     rcx, 0x200
  018018a5  jne     0x1418018bc
  018018a7  mov     rcx, rbx
  018018aa  call    0x140394330  ; -> 0x394330
  018018b5  call    0x14084f810  ; -> 0x84f810
  018018bc  cmp     rcx, 0x20000
  018018c5  xor     r8d, r8d
  018018cb  call    0x1403949e0  ; -> 0x3949e0
  018018d9  call    0x140816dd0  ; -> 0x816dd0
```

读出来的四条:

1. **分派键是 `[ctx+8]`,取值 `2 / 0x40 / 0x100 / 0x200 / 0x20000 / 0x10000000000`**。
   这套编码**与** scope mask(`0x80` = system、`0x04` = country,`pinned(country_scope_4_4_4 §6)`)**不是同一套**;
   本卷**不给**两者的映射,只记「`set_owner` 按它分派」。
2. `set_owner` 的**参数**是 `0x35eee0(self+0xc0, ctx, self+0x28, "set_owner")` 的返回,
   即「从已解析的成员里按名字取出那个值对象」;`slot[1]` 解析时写的就是 `self+0xc0`。⇒ §2.2 与本节是同一格。
3. 每个分支最后都把参数交给一个**下游写体**:键 `2` 走 `[rsi+0x20]` 的 vtable `+0x138`,
   键 `0x40` 走 `0x816dd0(rsi, param, 0, 6)`,键 `0x20000` 也走 `0x816dd0`。
4. 键 `0x40` 的「owner 从哪来」是 `[接受者 + 0x320]` 的一层指针再取 `dword`,经全局 `0x3260bb0` 的
   `+0x948/+0xed8` 子库解析 —— **不是** §3 那条 `[obj+0x1370]` 的路。

### §2.4 判决:效应路径 `unresolved`,字段本身可定

**`unresolved`,卡在 `0x816dd0`。** 这条 effect 的具体 store 指令没有在 `0x18015f0` 内部,
而在 `0x816dd0(rsi, param, 0, 6)` 里;`0x816dd0` 的入参 `rsi` 是「经 `[+0x320]` 指针 → `dword` →
`[[0x3260bb0]+0x948]+0xed8` 子库」解出的对象,**不是** scope 本身。把 `0x816dd0` 展开需要先定
「`[接受者+0x320]` 指向什么」这一格,而它没有离线读数(见 §6 N3)。

**字段本身可以定,靠的是另外四条互不依赖的读数(不是 `set_owner` 这条 effect 走的路):**

```text
$ python3 scripts/scratch/2026-11_transitability/field_xrefs.py 0x1370 --width dword --writes-only --limit 20
# module /var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe
# .text bytes=37291792 pdata funcs=130615

## [reg+0x1370]  width=dword hits=5 writes=5
  0x3797fc  W  mov dword ptr [rbp + 0x1370], ebx   (in func 0x3797c0)
  0x37afd1  W  mov dword ptr [rbp + 0x1370], r12d   (in func 0x3797c0)
  0x8af119  W  mov dword ptr [rbx + 0x1370], 0xffffffff   (in func 0x8ae8b0)
  0x8c2c6d  W  mov dword ptr [rsi + 0x1370], ecx   (in func 0x8c2b70)
  0x8cb17c  W  mov dword ptr [rbp + 0x1370], eax   (in func 0x8caff0)
```

三条 `[rbp+…]` 是栈帧(同一 displacement 的栈槽,与对象无关),真正落在堆对象上的只有两条:

```text
$ python3 scripts/disrva.py 0x8ae8b0 24          # ctor 开头(逐字)
  008ae8b0  mov     qword ptr [rsp + 0x18], rbx
  008ae8ba  mov     qword ptr [rsp + 8], rcx
  008ae8ca  mov     rbx, rcx
  008ae8cd  mov     dword ptr [rcx + 8], 0xffffffff
  008ae8e6  lea     rax, [rip + 0x1c6afdb]  ; -> 0x25198c8
  008ae8ed  mov     qword ptr [rcx], rax
  008ae8f0  lea     rax, [rip + 0x1c6b051]  ; -> 0x2519948
  008ae8f7  mov     qword ptr [rcx + 0x10], rax
  008ae8fb  lea     rax, [rip + 0x1c6b07e]  ; -> 0x2519980
  008ae902  mov     qword ptr [rcx + 0x18], rax
  008ae906  lea     rax, [rip + 0x1c6afd3]  ; -> 0x25198e0
  008ae90d  mov     qword ptr [rcx + 0x28], rax
  008ae911  lea     rax, [rip + 0x1c6aff8]  ; -> 0x2519910
  008ae918  mov     qword ptr [rcx + 0x38], rax
  008ae920  call    0x1408af240  ; -> 0x8af240
  008ae92d  mov     qword ptr [rbx + 0x408], rax
  008ae937  movups  xmmword ptr [rbx + 0x410], xmm0
  008ae94f  mov     dword ptr [rbx + 0x428], 0xffffffff
```

**(a) 构造期初始化 = 「无主」哨兵**(`0x8ae8b0` 是这个大对象的 ctor,`find_refs.py` 有 3 个调用点):

```text
$ python3 scripts/disrva.py 0x8af0e3 24          # 同一 ctor 的尾段(摘录)
  008af0e3  mov     dword ptr [rbx + 0x1140], ecx
  008af0f0  mov     qword ptr [rbx + 0x1148], rax
  008af0f7  mov     qword ptr [rbx + 0x1268], 0x20
  008af102  mov     qword ptr [rbx + 0x1258], rcx
  008af109  lea     rax, [rbx + 0x1270]
  008af110  mov     qword ptr [rbx + 0x1260], rax
  008af117  mov     dword ptr [rbx + 0x1370], 0xffffffff    ; owner id = none
  008af121  xor     eax, eax
  008af123  mov     dword ptr [rbx + 0x1374], eax
  008af129  mov     word ptr [rbx + 0x1378], ax             ; busy + changed 两个 byte
  008af130  mov     dword ptr [rbx + 0x137c], eax
  008af136  mov     qword ptr [rbx + 0x1380], r14
  008af13d  mov     dword ptr [rbx + 0x1388], r14d
  008af147  movups  xmmword ptr [rbx + 0x1390], xmm0
  008af163  mov     qword ptr [rbx + 0x13a8], 0xffffffffffffffff
  008af16e  mov     byte ptr [rbx + 0x42d], 1
```

`+0x1370` 紧挨着 `+0x1374`(锁)/`+0x1378`(两个旗标 byte)/`+0x137c`,并被初始化成 `0xFFFFFFFF` ——
**这是「一个带锁的单值格 + 无主哨兵」**的构造形状,不是别的字段的巧合。

**(b) 写体:把新国家的 id 写进去**(`0x8c2b70`,唯一调用点是 `0x8c2cb8`):

```text
$ python3 scripts/disrva.py 0x8c2b70 120          # 摘录
  008c2b82  mov     rsi, rcx
  008c2b88  movzx   eax, byte ptr [rcx + 0x1378]
  008c2b98  lea     rdx, [rcx + 0x1374]
  008c2bb0  mov     eax, dword ptr [rdx]
  008c2bb6  lock cmpxchg dword ptr [rdx], ebp          ; 自旋锁 = obj+0x1374
  008c2bc5  call    0x1408bc8c0  ; -> 0x8bc8c0      ; 新 owner 候选
  008c2bca  mov     rdi, rax
  008c2bcd  mov     r8, qword ptr [rip + 0x299e404]  ; -> 0x3260fd8
  008c2bd4  mov     rdx, qword ptr [rip + 0x299c7b5]  ; -> 0x325f390
  008c2be0  mov     r9d, dword ptr [rsi + 0x1370]     ; 旧 owner id
  008c2c1d  xchg    byte ptr [rsi + 0x1379], al       ; changed 旗标
  008c2c23  lea     rcx, [rdi + 0x18]
  008c2c2a  call    qword ptr [rax + 8]
  008c2c2d  test    al, al
  008c2c2f  je      0x1408c2c39
  008c2c31  mov     eax, ebp
  008c2c33  xchg    byte ptr [rdi + 0x3798], al       ; ← 新国家侧的同步位
  008c2c39  lea     rcx, [rbx + 0x18]
  008c2c3d  mov     rax, qword ptr [rcx]
  008c2c40  call    qword ptr [rax + 8]
  008c2c45  je      0x1408c2c4e
  008c2c47  xchg    byte ptr [rbx + 0x3798], bpl      ; ← 旧国家侧的同步位
  008c2c53  xchg    byte ptr [rsi + 0x1378], al
  008c2c5e  add     rdi, 0x20
  008c2c69  mov     ecx, dword ptr [rdi]              ; = [country+0x20] 国家 id(B+,§7)
  008c2c6b  mov     dword ptr [rsi + 0x1370], ecx     ; ★ owner 写点
```

**(c) 读体:同一个 displacement 被当国家 id 查表**(见 §3.1 的 `0x8bc870`)。

**(d) 变更钩子:前后各读一次 `+0x1370`,不等就通知**

```text
$ python3 scripts/disrva.py 0x8c2c90 40          # 摘录
  008c2ca0  mov     qword ptr [rsp + 8], rbx
  008c2ca5  mov     qword ptr [rsp + 0x10], rsi
  008c2caf  mov     ebx, dword ptr [rcx + 0x1370]     ; old
  008c2cb8  call    0x1408c2b70  ; -> 0x8c2b70
  008c2cbd  mov     r10d, dword ptr [rdi + 0x1370]    ; new
  008c2cc7  cmp     ebx, r10d
  008c2cca  je      0x1408c2d50
  008c2cd0  mov     r9, qword ptr [rip + 0x299e301]  ; -> 0x3260fd8
  008c2d44  mov     rcx, rdi
  008c2d47  call    0x1408bcaa0  ; -> 0x8bcaa0          ; (obj, old_country, new_country)
```

```text
$ python3 scripts/find_refs.py 0x8c2b70 0x8ae8b0
== 0x8c2b70: 1 references ==
  .text 0x8c2cb8: call 0x1408c2b70
== 0x8ae8b0: 3 references ==
  .text 0x1df280: call 0x1408ae8b0
  .text 0x26e5a7: call 0x1408ae8b0
  .text 0x30d1a1: call 0x1408ae8b0
```

### §2.5 §2 的三行判决

```text
候选写点: [galactic_object + 0x1370] (u32) <- [country_object + 0x20] (国家 id);"无主" = 0xFFFFFFFF
          命令: field_xrefs.py 0x1370 --width dword --writes-only  →  0x8c2c6d / 0x8af119 两处堆写
               disrva.py 0x8c2b70 120                            →  0x8c2c6b mov [rsi+0x1370], ecx
          档: 静态推断(未验证)
不能说的: ① 这不是 `set_owner` 这条 effect 自己的 store —— effect 的执行体 0x18015f0 按 `[ctx+8]` 分派,
          具体写体在 0x816dd0 内且入参对象不是 scope,本卷判 unresolved(§2.4);
          ② `+0x1370` 同时被当作一个内联小对象的基址(`0x72b960 lea rcx,[rdi+0x1370]` 传给 0xb544e0),
          所以「它是裸 u32」只在「该小对象第一个 dword」的意义上成立;
          ③ 零 live 读数:这条写体在 4.4.4 里到底由谁触发、一局触发几次,一个数都没有。
下一发升级条件: 在活体里对 3 个已知归属不同的星系读 [obj+0x1370] 的 u32,三值互不相同且都落在
          国家 id 集合内(低 24 位口径),同时 [obj+0x1374..0x1379] 呈现「锁 + 两旗标」形状。
```
## §3 owner 读侧:`has_owner` / `original_owner` / `is_original_owner` / `is_owned_by`

四个类的 factory、vptr、槽表见 §1.3。本节只读 **slot[3](subject resolver)**,因为 9 个触发类的
slot[5] 全 = `0x1a91a80`(`pinned(§77)`:`尾部 jmp [self_vtable+0x20]`),slot[4] 只有三个不同值,
**唯一逐类不同的就是 slot[3]** —— 谁读哪个字段,答案只在那一格。

### §3.1 `has_owner` slot[3] = `0x1a97650`:mask 0x80 分支读 `[obj+0x1370]`

```text
$ python3 scripts/disrva.py 0x1a97650 --len=0xc0
; stellaris.exe  .text RVA 0x1a97650-0x1a97710
  01a97650  mov     qword ptr [rsp + 0x10], rbx
  01a97655  push    rdi
  01a9765a  xor     bl, bl
  01a9765c  mov     rdi, rcx                                   ; self
  01a9765f  cmp     qword ptr [rdx + 8], 0x80                  ; scope mask == 0x80 (system)
  01a97667  jne     0x141a97698
  01a97669  mov     r9, qword ptr [rip + 0x17c9968]  ; -> 0x3260fd8   ; 国家对象表
  01a97675  mov     rcx, rdx
  01a97678  call    0x140393970  ; -> 0x393970                 ; scope -> 系统对象
  01a9767d  mov     edx, dword ptr [rax + 0x1370]              ; ★ owner id
  01a97683  mov     eax, edx
  01a97685  and     eax, 0xffffff                              ; 24 位索引
  01a9768a  cmp     eax, dword ptr [r9 + 0x20]                 ; bound
  01a9768e  jae     0x141a976ea
  01a97690  mov     ecx, eax
  01a97692  mov     rax, qword ptr [r9 + 0x18]                 ; root
  01a976d8  add     rcx, rcx
  01a976db  mov     rcx, qword ptr [rax + rcx*8 + 8]           ; entry = root + idx*16 + 8
  01a976e0  test    rcx, rcx
  01a976e3  je      0x141a976ea
  01a976e5  cmp     dword ptr [rcx + 0x20], edx                ; 对象 id == 查的 id
  01a976e8  je      0x141a976f1
  01a976ea  mov     rcx, qword ptr [rip + 0x17c7c9f]  ; -> 0x325f390   ; 空对象回退
  01a976f1  mov     rax, qword ptr [rcx + 0x18]
  01a976f5  add     rcx, 0x18
  01a976f9  call    qword ptr [rax + 8]                        ; 对象合法性槽
  01a976fc  movzx   ebx, al
  01a976ff  cmp     bl, byte ptr [rdi + 0x220]                 ; 与 self+0x220 的缓存 byte 比
  01a97705  mov     rbx, qword ptr [rsp + 0x38]
  01a9770a  sete    al
```

非 system 分支(`0x141a97698`)走另一条路:

```text
  01a97698  mov     rcx, rdx
  01a9769b  call    0x140a54d70  ; -> 0xa54d70                 ; scope -> 某个带 vtable 的对象
  01a976a0  test    rax, rax
  01a976a3  je      0x141a976ff
  01a976a5  mov     rcx, qword ptr [rax]
  01a976ad  mov     r8, qword ptr [rcx + 0x58]                 ; vtable +0x58 = 取 id
  01a976b4  call    r8
  01a976c3  mov     edx, dword ptr [rax]
  01a976c5  mov     eax, edx
  01a976c7  and     eax, 0xffffff
  ...同一张 0x3260fd8 表
```

### §3.2 同一个格子的第二次独立读数:`0x8bc870(系统) → 国家对象`

`0x8bc870` 不带任何 mask 判断,直接 `[rcx+0x1370]` —— 这是 §3.1 那条分支的**裸版本**,
两条读路径互相独立:

```text
$ python3 scripts/disrva.py 0x8bc870 40
  008bc870  mov     rdx, qword ptr [rip + 0x29a4761]  ; -> 0x3260fd8
  008bc877  test    rdx, rdx
  008bc87a  je      0x1408bc8a9
  008bc87c  mov     r8d, dword ptr [rcx + 0x1370]              ; ★ owner id
  008bc883  mov     eax, r8d
  008bc886  and     eax, 0xffffff
  008bc88b  cmp     eax, dword ptr [rdx + 0x20]
  008bc88e  jae     0x1408bc8a9
  008bc890  mov     ecx, eax
  008bc892  mov     rax, qword ptr [rdx + 0x18]
  008bc896  add     rcx, rcx
  008bc899  mov     rax, qword ptr [rax + rcx*8 + 8]
  008bc89e  test    rax, rax
  008bc8a1  je      0x1408bc8a9
  008bc8a3  cmp     dword ptr [rax + 0x20], r8d
  008bc8a7  je      0x1408bc8b0
  008bc8a9  mov     rax, qword ptr [rip + 0x29a2ae0]  ; -> 0x325f390
  008bc8b0  ret
```

### §3.3 `scope → 系统对象` 的解析器与已验过的系统表同格

```text
$ python3 scripts/disrva.py 0x393970 30
  00393970  mov     rdx, qword ptr [rcx + 0x1c]                 ; 缓存对象指针
  00393974  test    rdx, rdx
  00393977  je      0x14039398d
  00393979  cmp     qword ptr [rcx + 8], 0x80
  00393981  mov     rax, qword ptr [rip + 0x2ec9ef8]  ; -> 0x325d880
  00393988  cmove   rax, rdx
  0039398c  ret
  0039398d  cmp     qword ptr [rcx + 8], 0x80
  00393995  jne     0x1403939a0
  00393997  mov     eax, dword ptr [rcx + 0x10]                 ; scope+0x10 = id
  003939a8  mov     rdx, qword ptr [rip + 0x2ecd1e9]  ; -> 0x3260b98   ; 系统对象表
  003939bc  mov     eax, r8d
  003939bf  and     eax, 0xffffff
  003939c4  cmp     eax, dword ptr [rdx + 0x20]
  003939d2  mov     rax, qword ptr [rax + rcx*8 + 8]
  003939dc  cmp     dword ptr [rax + 8], r8d                    ; 系统对象 id 在 +8
  003939e2  mov     rax, qword ptr [rip + 0x2ec9e97]  ; -> 0x325d880
```

`0x3260b98` + `+0x18/+0x20` + `entry = base+idx*16+8` + `[entry+8] == id` 与
`runtime_444_graph_runtime.md §1.2/§1.3` 的解析器**逐字同形**,而那个解析器返回的对象带
`+0x588` 边容器(`pinned(图卷 §1.3)`)⇒ 本卷说的「系统对象」就是图卷那个「系统对象」,不是另一个类。

### §3.4 `is_owned_by` slot[3] = `0x1a9bd10`:按 `[scope+8]` 分派的九路 switch

```text
$ python3 scripts/disrva.py 0x1a9bd10 45
  01a9bd18  mov     rbx, qword ptr [rip + 0x17c3671]  ; -> 0x325f390   ; 空对象回退
  01a9bd22  mov     rcx, rdx
  01a9bd25  mov     rdi, rdx                                    ; scope
  01a9bd28  call    0x140a54d70  ; -> 0xa54d70
  01a9bd30  test    rax, rax
  01a9bd33  je      0x141a9bd84
  01a9bd35  mov     rax, qword ptr [rax]
  01a9bd3d  call    qword ptr [rax + 0x58]
  01a9bd40  mov     rdx, qword ptr [rip + 0x17c5291]  ; -> 0x3260fd8
  ...（命中路径与 §3.1 同形）
  01a9bd84  mov     rax, qword ptr [rdi + 8]                    ; scope mask
  01a9bd88  cmp     rax, 0x40000
  01a9bd9a  cmp     rax, 0x100
  01a9bdac  sub     rax, 1                                      ; mask 1
  01a9bdb6  sub     rax, 0xf                                    ; mask 0x10
  01a9bdc0  sub     rax, 0x10                                   ; mask 0x20
  01a9bdc6  sub     rax, 0x20                                   ; mask 0x40
  01a9bdd0  jne     0x141a9c23a
  01a9bdd6  mov     rcx, rdi
  01a9bdd9  call    0x140393970  ; -> 0x393970
  01a9bdde  mov     rcx, rax
  01a9bde1  call    0x1408bc870  ; -> 0x8bc870                  ; ★ 与 §3.1/§3.2 同一格
  01a9bde6  mov     rbx, rax
```

mask `0x20` 一路(同一函数的另一分支)读**另一个**偏移:

```text
  01a9bdee  mov     r8, qword ptr [rip + 0x17c51e3]  ; -> 0x3260fd8
  01a9bdfe  mov     rcx, rdi
  01a9be01  call    0x140393ec0  ; -> 0x393ec0
  01a9be06  mov     edx, dword ptr [rax + 0x434]                ; ★ 另一格:+0x434
  01a9be0e  and     eax, 0xffffff
```

⇒ **owner 不是「一个偏移」,是「按 scope 种类分派的一组偏移」**;本卷只钉住
`mask 0x80`(系统)那一格 = `+0x1370`,其余分支的偏移**逐条未读完**,见 §3.7。

### §3.5 `original_owner` / `is_original_owner`:另一条链,另一张表

```text
$ python3 scripts/disrva.py 0x1a97900 48
  01a97907  mov     rax, qword ptr [rdx + 8]                    ; scope mask
  01a9790e  movabs  rcx, 0x10000000000
  01a9791b  cmp     rax, rcx
  01a97920  test    al, 0xa
  01a97928  cmp     rax, 2
  01a9792e  mov     eax, dword ptr [rdx + 0x10]                 ; mask 2 → 直接用 scope id
  01a9793c  cmp     rax, 8
  01a97945  call    0x140393fb0  ; -> 0x393fb0                 ; mask 8
  01a9794f  lea     rcx, [rax + 0x40]
  01a97953  mov     rax, qword ptr [rax + 0x40]
  01a97957  call    qword ptr [rax + 0x120]                     ; vtable +0x120 取 id
  01a9795f  mov     eax, 0xffffffff
  01a97972  call    0x14039c850  ; -> 0x39c850                 ; mask 0x10000000000
  01a97977  mov     rcx, qword ptr [rax + 0xf78]               ; ★ 该分支的另一格
  01a97992  mov     r8, qword ptr [rip + 0x17c91df]  ; -> 0x3260b78   ; ← 不是 0x3260fd8
  01a9799e  mov     qword ptr [rsp + 0x20], rdi
  01a979aa  and     ecx, 0xffffff
  01a979b4  jae     0x141a979ce
```

`is_original_owner` 的 slot[3] = `0x1a98280` 是**同一段逻辑的孪生**(mask 2 / mask 8 / mask
`0x10000000000` 三分支、同一张 `0x3260b78` 表),差别在尾部:

```text
$ python3 scripts/disrva.py 0x1a98280 45
  01a982bb  mov     rcx, qword ptr [rbx + 8]
  01a982bf  movabs  rax, 0x10000000000
  01a982c9  test    cl, 0xa
  01a982d7  cmp     rcx, 2
  01a982dd  mov     eax, dword ptr [rbx + 0x10]
  01a982e2  cmp     rcx, 8
  01a982eb  call    0x140393fb0  ; -> 0x393fb0
  01a982f5  lea     rcx, [rax + 0x40]
  01a982fd  call    qword ptr [rax + 0x120]
  01a9830d  call    0x14039c850  ; -> 0x39c850
  01a98312  mov     rcx, qword ptr [rax + 0xf78]
  01a98339  mov     r8, qword ptr [rip + 0x17c8838]  ; -> 0x3260b78
  01a98347  and     ecx, 0xffffff
  01a98366  cmp     dword ptr [rcx + 0x18], eax                  ; 表项 id 在 +0x18(不是 +0x20)
  01a9836b  mov     rcx, qword ptr [rip + 0x17c6dfe]  ; -> 0x325f170
  01a98372  call    0x140e70d10  ; -> 0xe70d10
  01a98377  cmp     rax, rdi                                    ; 与参数对象比
  01a9837a  sete    al
```

**这三条读的是「原始主人」,与 §3.1 的 `+0x1370` 不是同一格**:表不同(`0x3260b78` vs `0x3260fd8`)、
表项 id 位置不同(`+0x18` vs `+0x20`)、失败回退不同(`0x325f170` vs `0x325f390`)。但它们**都**先按
mask 从 scope 取一个 id 再去表里换对象,所以「原始主人」在引擎里看起来也是**id → 对象**,不是指针。

### §3.6 判决:读侧与写侧是 `same_slot`(**仅限系统分支**)

```text
判定: same_slot(限 mask 0x80 分支)
  —— 读:[系统对象 + 0x1370] (u32, `and 0xffffff` 后查 0x3260fd8,`[entry+0x20]==id`)
     写:[系统对象 + 0x1370] (u32, 写 `[country+0x20]`,无主 = 0xFFFFFFFF)
  —— 两侧的「系统对象」都来自同一张 `0x3260b98` 表(§3.3),不是两个类。
不成立的部分:
  —— 其余 scope 种类各读各的偏移(mask 0x20 → `+0x434`,§3.4),那些格子与 §2 的写点无关;
     本卷**不**把 `+0x434`/`+0xf78`/`+0x120` 记成 owner 的别名。
  —— `original_owner` 家族走 `0x3260b78`,与 owner 那一格是两张表;两者是否同值,本卷无读数。
```

`is_owned_by` 的其余六个分支(`mask 1 / 0x10 / 0x100 / 0x40000` 等)本卷**逐条未读完** ——
`未观测`,不给偏移。

### §3.7 读侧不能说的

1. **布尔语义没判。** 本卷只读「谁读哪个格子」,没有读 `slot[4]`(`0x1a91ad0` / `0x1a92a90` /
   `0x1a97c40`)的完整比较逻辑,所以「`has_owner` 与 `original_owner` 语义差在哪」是 `未观测`。
   已知的只有:两者 slot[4] **同为 `0x1a92a90`**,差别在 slot[3]。
2. **scope mask 的值来自 `pinned(country_scope_4_4_4 §6)`**(system `0x80`、country `0x04`,
   两侧读点都读过)。本卷没有新的 mask 实机读数。
3. **`0xa54d70(scope)` 是什么对象,`未观测`。** 它在非 system 分支里兜底,返回一个带 vtable、
   `+0x58` 槽能取 id 的东西;本卷没展开它。
4. **`+0x1370` 在「系统对象」上的宽度是 dword 这一条,只有三处静态见证**(§2.5);它旁边
   `+0x1374`/`+0x1378`/`+0x1379` 的锁/旗标形状是**旁证**,不是证明。
