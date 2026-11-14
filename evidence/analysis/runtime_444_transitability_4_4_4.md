# runtime_444_transitability_4_4_4 — #46 第二半:可通行语义的静态取证

零 shot、零 Windows。输入只有 exe 拷贝与仓内 TSV/存档。置信档:`pinned(§N)` / `静态推断(未验证)` / `未观测`。

```text
exe  = /var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe
sha256(实测) = 9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56
date = 2026-11-14
```

本卷只回答一个问题的**静态可达性**:「星系 → 所属国家」与「国家 → 外交状态」这两条
语义,在 4.4.4 的执行体里分别落到**哪个对象、哪个偏移、哪个函数**。它**不**回答
「运行期那个格子里真的是这个值」—— 那要一发 `install → 读 → uninstall`,清单在 §6。

**引文口径(全卷适用)**:所有 `disrva.py` / `vtable.py` / `find_refs.py` / 探针的输出块都是
**逐字摘录** —— 省略的行直接不列或写成 `...（略）`,保留下来的每一行与原始输出逐字符相同,
**不改写任何操作数**。凡是结论依赖被省略的行,正文会在那一行旁边说明。

---

## §1 线索台账:12 个 keyword → class_info → factory → vptr

### §1.1 取 12 个 lead 的 class_info(Task 1 Step 2)

```text
$ awk -F'\t' 'NR>1 && $6 ~ /^(has_owner|original_owner|is_original_owner|is_owned_by|set_owner|is_at_war_with|has_closed_borders|is_rival|is_in_federation_with|is_hostile_to|set_closed_borders|join_alliance)$/ {print $6"\t"$5"\t"$4"\t"$7}' \
    evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv | sort
has_closed_borders	18394	0x32611c8	0x269d908
has_owner	17965	0x32611c8	0x269f528
is_at_war_with	18075	0x32611c8	0x269f658
is_hostile_to	18282	0x32611c8	0x269eef8
is_in_federation_with	18244	0x32611c8	0x269efd8
is_original_owner	18333	0x32611c8	0x269f548
is_owned_by	17972	0x32611c8	0x269f578
is_rival	18293	0x32611c8	0x269ef78
join_alliance	16512	0x33746e8	0x260ff60
original_owner	13581	0x32611c8	0x269f538
set_closed_borders	10347	0x33746e8	0x260ee70
set_owner	10008	0x33746e8	0x2611430
```

12 行全出,`class_info` 列与计划预量表**逐项相等** ⇒ TSV 未漂。TSV 列序(`# array_rva index
thunk_rva db_global_rva token_id keywords field0_rva ...`)由首行确认。

### §1.2 class_info 是 16 字节 `{deleter, factory}`(Task 1 Step 3)

```text
$ python3 -   # 读 12 个 class_info 的两个 qword,减 image base
image_base 0x140000000
has_owner                 0x269f528 deleter=0x34c090 factory=0x1b1ea10
original_owner            0x269f538 deleter=0x34c090 factory=0x1b1ea80
is_original_owner         0x269f548 deleter=0x34c090 factory=0x1b1eaf0
is_owned_by               0x269f578 deleter=0x34c090 factory=0x1b1ef70
set_owner                 0x2611430 deleter=0x34c090 factory=0x1893b30
is_at_war_with            0x269f658 deleter=0x34c090 factory=0x1b1f230
has_closed_borders        0x269d908 deleter=0x34c090 factory=0x1b29460
is_rival                  0x269ef78 deleter=0x34c090 factory=0x1b222c0
is_in_federation_with     0x269efd8 deleter=0x34c090 factory=0x1b22590
is_hostile_to             0x269eef8 deleter=0x34c090 factory=0x1b21f40
set_closed_borders        0x260ee70 deleter=0x34c090 factory=0x189b900
join_alliance             0x260ff60 deleter=0x34c090 factory=0x1897690
```

`deleter` 12/12 都是 `0x34c090`(共享 deleting destructor,与 §17/§22.2 同一格),
factory 与 §1.1 的 `field0_rva` **逐项相等** ⇒ 台账成立。

### §1.3 factory → 最终 vptr → 三个语义槽

每个 factory 都走同一条形状:`new(size)` → `memset` → 基类 ctor → **写两次 vptr**
(第一次是中间基类、第二次才是本类最终 vptr)。「两次」这件事在 `set_owner` 与
`is_owned_by` 上各读过一次,余下 10 个同形。

```text
$ python3 scripts/disrva.py 0x1893b30 60          # 计划里的 set_owner factory
  01893b36  mov     ecx, 0x260
  01893b3b  call    0x142185218  ; -> 0x2185218       ; operator new(0x260)
  01893b53  call    0x142188170  ; -> 0x2188170       ; memset
  01893b5b  call    0x1403afb40  ; -> 0x3afb40        ; CEffect 基类 ctor
  01893b61  lea     rax, [rip + 0xd82390]  ; -> 0x2615ef8
  01893b68  mov     qword ptr [rbx], rax             ; vptr #1(中间基类)
  01893b8d  lea     rax, [rip + 0xd74264]  ; -> 0x2607df8
  01893b94  mov     qword ptr [rbx], rax             ; vptr #2 = 本类最终 vptr
```

`is_owned_by` 的「先 `0x26A2CC0` 后 `0x268ADD0`」在计划里已实测,本次复现一致
(`01b1efa1 lea rax,[rip+0xb83d18] ; -> 0x26a2cc0` / `01b1efbf lea rax,[rip+0xb6be0a] ; -> 0x268add0`)。

**槽号语义(本卷全程使用,必须与 §77 一起读):**

| 槽 | 偏移 | 触发类(trigger) | 效果类(effect) |
|---|---|---|---|
| slot[1] | `+0x08` | 无 | **parse / 语法校验**:把脚本文本解析进 `self` 的成员 |
| slot[3] | `+0x18` | **subject resolver**:从 scope 取「被比较的那个值」 | — |
| slot[4] | `+0x20` | **evaluator**:把 subject 与参数(`+0x80`)比较 | — |
| slot[5] | `+0x28` | `0x1A91A80` 共用包装,尾跳 slot[4](`pinned(§77)`) | — |
| slot[9] | `+0x48` | describe / 报错串 | **ExecuteActual**(本卷 §2/§4 的全部写点都在这里) |

「slot[3] = subject、slot[4] = evaluator」是本卷从 9 个触发类**同形**归纳出来的:
9 个类的 slot[5] 全 = `0x1a91a80`,slot[4] 只有三个不同值,而 slot[3] 个个不同且
每个都在读一个不同的字段。这是 `静态推断(未验证)`。

| keyword | factory | 最终 vptr | slot[3] subject | slot[4] evaluator | slot[9] |
|---|---|---|---|---|---|
| `has_owner` | `0x1b1ea10` | `0x2699538` | `0x1a97650` | `0x1a92a90` | `0x1a97720` (HAS_OWNER) |
| `original_owner` | `0x1b1ea80` | `0x2699628` | `0x1a97900` | `0x1a92a90` | `0x1a97a70` (HAS_ORIGINAL_OWNER) |
| `is_original_owner` | `0x1b1eaf0` | `0x2699718` | `0x1a98280` | `0x1a97c40` | `0x1a983a0` (IS_ORIGINAL_OWNER) |
| `is_owned_by` | `0x1b1ef70` | `0x268add0` | `0x1a9bd10` | `0x1a91ad0` | `0x1a9c290` (IS_OWNED_BY) |
| `is_at_war_with` | `0x1b1f230` | `0x268b280` | `0x1a9d980` | `0x1a91ad0` | `0x1a9da10` |
| `has_closed_borders` | `0x1b29460` | `0x26a0930` | `0x1af5550` | `0x1a97c40` | `0x1af55f0` |
| `is_rival` | `0x1b222c0` | `0x2687f40` | `0x1b38b40` | `0x1a91ad0` | `0x1b388f0` |
| `is_in_federation_with` | `0x1b22590` | `0x2688b78` | `0x1b38060` | `0x1a91ad0` | `0x1b37e10` |
| `is_hostile_to` | `0x1b21f40` | `0x26877c0` | `0x1b3a1c0` | `0x1a91ad0` | `0x1b39f70` |
| `set_owner` | `0x1893b30` | `0x2607df8` | — | — | `0x18015f0` |
| `set_closed_borders` | `0x189b900` | `0x25fbee0` | — | — | `0x185a8f0` |
| `join_alliance` | `0x1897690` | `0x26146b0` | — | — | `0x18307e0` |

命令(每个 vptr 一次 `vtable.py`,每个槽一次 `disrva.py`;下面给两条原文,其余同形):

```text
$ python3 scripts/vtable.py 0x268add0 --slots 12
  [0x0] +0x00 -> 1a9b380  bounds 1a9b380..1a9b3c0
  [0x1] +0x08 -> 1ba340  NOT CODE
  [0x2] +0x10 -> 348b60  bounds 348b60..348d4e
  [0x3] +0x18 -> 1a9bd10  bounds 1a9bd10..1a9c28d
          str 24aafb0 "is_owned_by"
  [0x4] +0x20 -> 1a91ad0  bounds 1a91ad0..1a9206e
  [0x5] +0x28 -> 1a91a80  bounds 1a91a80..1a91ac4
  [0x6] +0x30 -> 349220  NOT CODE
  [0x7] +0x38 -> 349640  NOT CODE
  [0x8] +0x40 -> 349700  bounds 349700..3497c9
  [0x9] +0x48 -> 1a9c290  bounds 1a9c290..1a9c5c0
          str 26a3760 "IS_NOT_OWNED_BY"
          str 24fdf2c "EMPIRE"
          str 26a3750 "IS_OWNED_BY"
          str 24fdf2c "EMPIRE"
  [0xa] +0x50 -> 1b4d60  NOT CODE
  [0xb] +0x58 -> 349550  bounds 349550..349582
(12 slots shown; extent is NOT proven by this listing — see docstring)

$ python3 scripts/vtable.py 0x25fbee0 --slots 24          # set_closed_borders(此处略去 slot 6/7/0xa–0x11/0x14–0x17 的 12 行,只抄有语义的 8 行)
  [0x0] +0x00 -> 182f140  bounds 182f140..182f18f
  [0x1] +0x08 -> 17f6130  NOT CODE
  [0x2] +0x10 -> 185a250  bounds 185a250..185a31d
  [0x3] +0x18 -> 17f60b0  bounds 17f60b0..17f60cb
  [0x4] +0x20 -> 3b1770  bounds 3b1770..3b1ef0
  [0x5] +0x28 -> 185a9f0  bounds 185a9f0..185aa8f
          str 24811e8 "set_closed_borders"
          str 2629b28 "SET_CLOSED_BORDERS_EFFECT_OPEN"
          str 2629ef8 "SET_CLOSED_BORDERS_EFFECT_CLOSED"
          str 24f6fd8 "TARGET"
  [0x8] +0x40 -> 3b0f80  bounds 3b0f80..3b1155
  [0x9] +0x48 -> 185a8f0  bounds 185a8f0..185a9e6
          str 24811e8 "set_closed_borders"
          str 26162c0 "C:\mnt\gsg\stellaris\augustus\augustus\source\effect_impl\effect"
          str 2629eb8 "set_closed_borders effect at %s failed to access relation!"
  [0x12] +0x90 -> 185a320  bounds 185a320..185a8e6
          str 2629e78 "set_closed_borders effect at %s has an undefined target!"
  [0x13] +0x98 -> 3b1420  bounds 3b1420..3b1467
```

### §1.4 台账里不能说的

1. **`class_info` 的 factory 是「建对象」不是「执行」**。factory 只 `new` + 写 vptr +
   跑成员 ctor;真正的读写全在 vtable 槽里。把 factory RVA 当锚点做 detour 没有价值
   (与 §28.5 同一条理由)。
2. **槽号在 trigger 与 effect 两族不同义**。effect 的 slot[9] 是执行体,trigger 的
   slot[9] 是描述串产出;trigger 的执行体是 slot[3]/slot[4] 这一对。跨族复用槽号会读错。
3. **`+0x78` 不是语义字段**。12 个 factory 里 9 个触发类都写
   `mov dword ptr [rbx + 0x78], 0x165`,四个 owner 家族**完全同值**;它在
   `0x1a92a90` 里的用法是 `cmp dword ptr [rbx + 0x78], 0x427`(与常量比之后做取反)。
   ⇒ 它是**变体/运算符判别位**,不是 owner,也不是比较运算符 id。计划 Review Focus 的
   第 2 条成立,本卷据此不把 `+0x78` 记入任何一格。

---

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

> `AGENTS.md` 的 RVA 表把 donor `hidden_effect` 的 `[vptr+0x08]` 记作「Execute 覆写」。
> 本卷对 `join_alliance` 的 slot[1] = `0x3afd30` 只读到「参数语法校验 + 报错串」形状
> (`Expected "` / ` = {", but got "`),**没有**读到它转调 slot[9];两者措辞的差异本卷
> 不解,也不需要解 —— §2 只需要「写点不在 slot[1]」这一条。

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

> (§7 已收口:`[接受者+0x320]` 指向的 id 经哈希表 `0x9c0fd0` 解出的对象 **Z**,
> 它 `+0x98` → X → `+0x990` → Y → `+0x434` → 参数国家;`0x816dd0` 自己只写 `[系统+0x580]`
> 与 `[系统+0x1378]`,真正的 store 仍是 `0x8c2b70` 的 `mov dword ptr [rsi+0x1370], ecx`
> ⇒ 与本节候选**同一格**。`unresolved` 这个判词因此在 §7.4 改为 `same_slot`(仍是静态推断)。)

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

> (§8 已读完:不是「九路」,是 **20 个 mask 叶子 + 1 条兜底路径**;本节尾部把 `+0x434`
> 标成「mask 0x20 一路」也是错位 —— 那是 **mask `0x40`**。原读数保留,更正见 §8.1/§8.2。)

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
(§8 已把 20 个 mask 的字段与落地方式补齐;§3.7 那条限制只被解除一半 —— 字段表齐了,类名仍 `未观测`。)

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
## §4 外交家族:战争 / 关闭边界 / 竞争 / 联邦

五个读侧、两个写侧。**结论先写:这五个状态没有一个落在「country 上的一个 int」上**——
四个落在**关系/态度容器**里,一个落在**联邦对象**上。计划 Review Focus 第 5 条成立。

### §4.1 五个谓词的 slot[3]:先分「对象来源」

| keyword | slot[3] | 第一个对象是谁 | 二级来源 |
|---|---|---|---|
| `is_at_war_with` | `0x1a9d980` | `0x393dd0(scope)` → 本国对象 | 关系对象 `+0xf4` |
| `has_closed_borders` | `0x1af5550` | `0x393dd0(scope)` → 本国对象 | 关系对象 `+0x120` bit 15 |
| `is_rival` | `0x1b38b40` | `0x393dd0(scope)` → 本国对象 | `[country+0x2c78]` 的对等名单 `+0x28/+0x34` |
| `is_hostile_to` | `0x1b3a1c0` | `0x393dd0(scope)` → 本国对象 | `[country+0x1d78]` 的态度表 `+0x490/+0x49c` |
| `is_in_federation_with` | `0x1b38060` → 尾跳 `0x7561f0` | 本国对象 | `[country+0x1e88]` → 联邦对象 `+0x98/+0xa4` |

`0x393dd0` 是 **mask 4(country)解析器**,与 `pinned(country_scope_4_4_4 §6)` 的国家 mask 一致:

```text
$ python3 scripts/disrva.py 0x393dd0 30
  00393dd0  mov     rdx, qword ptr [rcx + 0x1c]                 ; 缓存对象
  00393dd9  cmp     qword ptr [rcx + 8], 4                      ; mask == 4 (country)
  00393dde  mov     rax, qword ptr [rip + 0x2ecb5ab]  ; -> 0x325f390
  00393de5  cmove   rax, rdx
  00393dea  cmp     qword ptr [rcx + 8], 4
  00393df1  mov     eax, dword ptr [rcx + 0x10]                 ; scope+0x10 = id
  00393e02  mov     rax, qword ptr [rip + 0x2ecd1cf]  ; -> 0x3260fd8   ; 国家对象表
  00393e15  and     ecx, 0xffffff
  00393e1d  cmp     ecx, dword ptr [rax + 0x20]
  00393e29  mov     rax, qword ptr [rax + rcx*8 + 8]
  00393e33  cmp     dword ptr [rax + 0x20], edx
  00393e38  mov     rax, qword ptr [rip + 0x2ecb551]  ; -> 0x325f390
```

### §4.2 战争:`is_at_war_with` 读关系对象 `+0xf4`

```text
$ python3 scripts/disrva.py 0x1a9d980 40
  01a9d98d  mov     r10, rdx
  01a9d990  mov     rcx, rdx
  01a9d993  call    0x140393dd0  ; -> 0x393dd0                  ; scope -> 本国
  01a9d998  lea     rcx, [r9 + 0x80]                            ; 参数存储
  01a9d99f  mov     rdx, r10
  01a9d9a2  lea     r8, [r9 + 0x40]
  01a9d9a6  mov     rdi, rax
  01a9d9a9  lea     r9, [rip + 0xa0de90]  ; -> 0x24ab840        ; "is_at_war_with"
  01a9d9b0  call    0x14035eee0  ; -> 0x35eee0                   ; 取参数(对国)
  01a9d9b5  mov     rdx, qword ptr [rdi + 0x18]
  01a9d9b9  lea     rcx, [rdi + 0x18]
  01a9d9c0  call    qword ptr [rdx + 8]                         ; 本国有效?
  01a9d9c7  mov     rdx, qword ptr [rbx + 0x18]
  01a9d9cf  call    qword ptr [rdx + 8]                         ; 参数有效?
  01a9d9d6  mov     rdx, rbx
  01a9d9d9  mov     rcx, rdi
  01a9d9dc  call    0x140742670  ; -> 0x742670                 ; ★ 取关系对象
  01a9d9e1  cmp     dword ptr [rax + 0xf4], 0                   ; ★ 战争旗标
  01a9d9e8  setne   al
```

关系对象从哪来:

```text
$ python3 scripts/disrva.py 0x742670 45
  0074267a  mov     rbx, rcx                                    ; 本国
  00742680  mov     rcx, qword ptr [rcx + 0x2c78]               ; 本国 +0x2c78 = 外交对象
  00742687  mov     rax, qword ptr [rcx]
  0074268a  call    qword ptr [rax + 0x80]                      ; 外交对象有效?
  00742694  mov     rcx, qword ptr [rbx + 0x2c78]
  0074269d  mov     rcx, qword ptr [rip + 0x2b1cffc]  ; -> 0x325f6a0   ; 空回退
  007426a4  mov     rcx, qword ptr [rcx + 0x10]
  007426a8  mov     rdx, rdi                                    ; 对国
  007426ab  add     rcx, 0x2d60                                 ; 关系表基址
  007426bc  jmp     0x140b1d470  ; -> 0xb1d470                 ; ★ 查表
```

```text
$ python3 scripts/disrva.py 0xb1d470 50
  00b1d475  cmp     rdx, qword ptr [rcx + 8]                    ; 对国 == 自己?
  00b1d47b  mov     r11, qword ptr [rcx + 0x60]                 ; ★ 键数组(升序 dword)
  00b1d47f  movsxd  r9, dword ptr [rcx + 0x6c]                 ; ★ 键条数
  00b1d486  mov     ebx, dword ptr [rdx + 0x20]                 ; 键 = [对国+0x20] 国家 id
  00b1d491  lea     rdi, [r11 + r9*4]
  00b1d4a0  mov     rdx, r9
  00b1d4a3  shr     rdx, 1                                      ; 二分
  00b1d4a9  cmp     dword ptr [r8 + rdx*4], ebx
  00b1d4dc  mov     rax, qword ptr [r10 + 0x18]                 ; ★ 值数组
  00b1d4e0  mov     rax, qword ptr [rax + rcx*8]
  00b1d4e6  mov     rax, qword ptr [rip + 0x274277b]  ; -> 0x325fc68   ; 空回退
```

⇒ **关系 = `[[本国+0x2c78]+0x10] + 0x2d60` 上的一个「按对国 id 升序」的键值表**
(键数组 `+0x60`、条数 `+0x6c`、值数组 `+0x18`、空值回退 `0x325fc68`)。**存储是单向的**:
本国那张表里按对国 id 索引。

### §4.3 关闭边界:`has_closed_borders` 读关系对象 `+0x120` 的 bit 15

```text
$ python3 scripts/disrva.py 0x1af5550 30
  01af555a  mov     r9, rcx
  01af555d  mov     r10, rdx
  01af5560  mov     rcx, rdx
  01af5563  call    0x140393dd0  ; -> 0x393dd0                  ; scope -> 本国
  01af5568  lea     rcx, [r9 + 0x220]
  01af556f  mov     rdx, r10
  01af5572  lea     r8, [r9 + 0x40]
  01af5576  mov     rdi, rax
  01af5579  lea     r9, [rip + 0x9b7d88]  ; -> 0x24ad308        ; "has_closed_borders"
  01af5580  call    0x14035eee0  ; -> 0x35eee0                   ; 取参数
  01af5585  mov     rdx, qword ptr [rdi + 0x18]
  01af5590  call    qword ptr [rdx + 8]
  01af5597  mov     rdx, qword ptr [rbx + 0x18]
  01af559f  call    qword ptr [rdx + 8]
  01af55a6  mov     rdx, rbx
  01af55a9  mov     rcx, rdi
  01af55ac  call    0x140742670  ; -> 0x742670                 ; ★ 同一张关系表
  01af55b1  mov     ecx, dword ptr [rax + 0x120]                ; ★ 关系对象 +0x120
  01af55b7  shr     ecx, 0xf                                    ; bit 15
  01af55ba  test    cl, 1
  01af55bf  xor     r8d, r8d
  01af55c2  mov     rdx, rbx
  01af55c5  mov     rcx, rdi
  01af55c8  call    0x14075be90  ; -> 0x75be90                 ; 附加判据(未展开)
```

### §4.4 竞争:`is_rival` 读本国「对等名单」

```text
$ python3 scripts/disrva.py 0x1b38b40 30
  01b38b4a  lea     r8, [rcx + 0x40]
  01b38b4e  mov     rbx, rdx
  01b38b51  sub     rcx, -0x80                                  ; self+0x80 = 参数存储
  01b38b55  lea     r9, [rip + 0xb8ec84]  ; -> 0x26c77e0        ; "attitude trigger"
  01b38b5c  call    0x14035eee0  ; -> 0x35eee0
  01b38b61  mov     r8, qword ptr [rax + 0x18]
  01b38b6c  call    qword ptr [r8 + 8]
  01b38b74  mov     rcx, rbx
  01b38b77  call    0x140393dd0  ; -> 0x393dd0
  01b38b7c  cmp     qword ptr [rax + 0x1d78], 0                  ; 态度容器非空?
  01b38b84  je      0x141b38ba2
  01b38b86  mov     rdx, rdi
  01b38b89  mov     rcx, rax
  01b38b8c  call    0x14076dfc0  ; -> 0x76dfc0
  01b38b91  test    al, al
```

```text
$ python3 scripts/disrva.py 0x76dfc0 45
  0076dfd0  mov     rcx, qword ptr [rcx + 0x2c78]                ; 本国 +0x2c78
  0076dfda  call    qword ptr [rax + 0x80]
  0076dff4  movsxd  rcx, dword ptr [rax + 0x34]                 ; ★ 对等名单条数
  0076dffe  mov     r8d, dword ptr [rdi + 0x20]                 ; 对国 id
  0076e005  mov     rax, qword ptr [rax + 0x28]                  ; ★ 对等名单数组
  0076e010  cmp     dword ptr [rax], r8d                         ; 线性搜
  0076e023  mov     edx, 0xffffffff
  0076e02d  cmp     edx, -1
  0076e030  setne   al
```

⇒ **竞争不是关系对象上的一个位,是本国 `+0x2c78` 外交对象里的一个 id 向量**(`+0x28` 数据、
`+0x34` 条数)。这一点与战争/边界**不同源**。

### §4.5 敌对:`is_hostile_to` 读本国的态度表

```text
$ python3 scripts/disrva.py 0x1b3a1c0 30
  01b3a1ca  lea     r8, [rcx + 0x40]
  01b3a1ce  mov     rbx, rdx
  01b3a1d1  sub     rcx, -0x80
  01b3a1d5  lea     r9, [rip + 0xb8d604]  ; -> 0x26c77e0
  01b3a1dc  call    0x14035eee0  ; -> 0x35eee0
  01b3a1f7  call    0x140393dd0  ; -> 0x393dd0
  01b3a1fc  mov     rcx, qword ptr [rax + 0x1d78]                ; ★ 态度容器
  01b3a203  test    rcx, rcx
  01b3a206  je      0x141b3a22d
  01b3a208  mov     edx, dword ptr [rdi + 0x20]                  ; 对国 id
  01b3a20b  call    0x140be3710  ; -> 0xbe3710                   ; 查态度
  01b3a210  mov     rcx, qword ptr [rip + 0x1724a61]  ; -> 0x325ec78
  01b3a217  cmp     rax, qword ptr [rcx + 0x98]                  ; 与「敌对态度」比
  01b3a21e  jne     0x141b3a22d
```

```text
$ python3 scripts/disrva.py 0xbe3710 40
  00be3710  mov     r9d, dword ptr [rcx + 0x49c]                 ; ★ 条数
  00be371e  mov     r10, qword ptr [rcx + 0x490]                 ; ★ 数组
  00be3733  lea     rcx, [r8 + r8*2]
  00be3737  add     rcx, rcx                                     ; idx*6
  00be373a  cmp     dword ptr [r10 + rcx*8 + 8], edx              ; 键在 +8(步长 0x30)
  00be3748  mov     rax, qword ptr [rip + 0x267b529]  ; -> 0x325ec78
  00be374f  mov     rax, qword ptr [rax + 0x168]                  ; 空回退
  00be3763  mov     rax, qword ptr [r10 + rax*8 + 0x10]           ; 值在 +0x10
```

⇒ **敌对 = 「态度对象 == 全局敌对态度」**,键值表在 `[本国+0x1d78]`(条数 `+0x49c`、数组
`+0x490`、元素步长 `0x30`、键 `+8`、值 `+0x10`)。`0x325ec78` 是态度库全局。

### §4.6 联邦:`is_in_federation_with` 读 `[country+0x1e88]` → 联邦对象

```text
$ python3 scripts/disrva.py 0x7561f0 45
  007561fa  mov     r8, qword ptr [rip + 0x2b0ae17]  ; -> 0x3261018   ; 联邦对象表
  00756209  mov     edx, dword ptr [rcx + 0x1e88]                 ; ★ 本国 +0x1e88 = 联邦 id
  00756211  and     eax, 0xffffff
  00756216  cmp     eax, dword ptr [r8 + 0x20]
  00756225  mov     rbx, qword ptr [rax + rcx*8 + 8]
  0075622f  cmp     dword ptr [rbx + 8], edx                      ; 表项 id 在 +8
  00756234  mov     rbx, qword ptr [rip + 0x2b09ab5]  ; -> 0x325fcf0   ; 空联邦
  0075623b  mov     rax, qword ptr [rbx]
  00756241  call    qword ptr [rax + 8]
  00756248  movsxd  rax, dword ptr [rbx + 0xa4]                 ; ★ 成员条数
  0075625c  mov     rax, qword ptr [rbx + 0x98]                  ; ★ 成员 id 数组
  00756255  mov     r8d, dword ptr [rdi + 0x20]                  ; 对国 id
  00756265  cmp     dword ptr [rax], r8d                          ; 线性搜
  00756285  cmp     edx, -1
  0075628a  mov     al, 1
```

⇒ **联邦成员 = 联邦对象上的一个 dword id 数组**(`+0x98` 数据、`+0xa4` 条数);
本国到联邦的**反向指针**在 `[country+0x1e88]`。

### §4.7 写侧两条:`set_closed_borders` / `join_alliance`

**`set_closed_borders` 写关系对象,不写 country 字段:**

```text
$ python3 scripts/disrva.py 0x185a8f0 --len=0x100
  0185a8ff  mov     rdi, rcx                                    ; self
  0185a902  mov     rsi, rdx                                    ; scope
  0185a905  mov     rcx, rdx
  0185a908  call    0x140393e40  ; -> 0x393e40                  ; scope -> 本国(mask 4)
  0185a90d  lea     rcx, [rdi + 0x2e8]                          ; 参数存储
  0185a914  mov     rdx, rsi
  0185a917  lea     r8, [rdi + 0x28]
  0185a91b  mov     rbx, rax
  0185a91e  lea     r9, [rip + 0xc268c3]  ; -> 0x24811e8        ; "set_closed_borders"
  0185a925  call    0x14035eee0  ; -> 0x35eee0                   ; 取参数(对国)
  0185a92a  mov     rdx, rax
  0185a92d  mov     rcx, rbx
  0185a930  call    0x14073ec40  ; -> 0x73ec40                 ; ★ find-or-create 关系
  0185a935  mov     rcx, rax
  0185a938  mov     rbx, rax
  0185a93b  mov     rdx, qword ptr [rax]
  0185a93e  call    qword ptr [rdx + 0x38]                      ; 关系有效?
  0185a941  test    al, al
  0185a943  jne     0x14185a990
  ...
  0185a990  movzx   eax, byte ptr [rdi + 0x488]                 ; 效果自己的 open/closed 旗标
  0185a997  lea     rcx, [rdi + 0xc0]
  0185a99e  neg     eax                                         ; 1 → 0xFFFFFFFF
  0185a9a3  xor     eax, dword ptr [rbx + 0x120]               ; 与关系对象 +0x120 异或
  0185a9a9  and     eax, 0x8000                                 ; 只留 bit 15
  0185a9ae  xor     dword ptr [rbx + 0x120], eax                ; ★ 写点:关系对象 +0x120 bit15
  0185a9b4  call    0x1403526b0  ; -> 0x3526b0
  0185a9bd  imul    ecx, eax, 0x21c0
  0185a9c3  mov     rax, qword ptr [rip + 0x1a061e6]  ; -> 0x3260bb0
  0185a9ca  add     ecx, dword ptr [rax + 0xc0]
  0185a9d0  mov     dword ptr [rbx + 0x148], ecx                ; 关系对象 +0x148(缓存年代值)
```

`0x73ec40` 是 `0x742670` 的**写孪生**:同一条 `[country+0x2c78]` → `[[..]+0x10]+0x2d60` →
`0xb1d4f0`(find-or-create),只是找不到时会建。

```text
$ python3 scripts/disrva.py 0x73ec40 --len=0xd0
  0073ec50  mov     rcx, qword ptr [rcx + 0x2c78]
  0073ec5a  call    qword ptr [rax + 0x80]
  0073ec64  mov     rbx, qword ptr [rbx + 0x2c78]
  0073ec74  mov     rax, qword ptr [rbx]
  0073ec7a  call    qword ptr [rax + 0x80]
  0073ec96  mov     rcx, qword ptr [rbx + 0x10]
  0073ec9d  add     rcx, 0x2d60
  0073eca9  add     rsp, 0x20
  0073ecae  jmp     0x140b1d4f0  ; -> 0xb1d4f0                 ; find-or-create
```

`xor dword [rel+0x120], mask` 这个写法本身说明它是**翻转**而不是赋值:方向(开/关)
由 `self+0x488` 的旗标取反后决定,所以 `neg eax` 为 0 时写 0 位(不动),为 `0xFFFFFFFF` 时翻位。
这也是本卷不敢断言「哪个方向叫关闭」的原因之一(见 §4.9)。

**`join_alliance` 落在联邦对象上:**

```text
$ python3 scripts/disrva.py 0x18307e0 --len=0x150
  0183080d  mov     rcx, rdx
  01830810  call    0x140393e40  ; -> 0x393e40                  ; scope -> 本国
  01830815  mov     r14, rax
  0183087b  call    0x140356be0  ; -> 0x356be0                  ; self+0xc0 参数 → 值对象
  01830880  mov     rcx, rax
  01830883  call    0x1403947f0  ; -> 0x3947f0                  ; 值 → 联邦类型
  01830888  mov     rbx, rax
  ...
  018308f6  mov     rdx, qword ptr [rip + 0x1a306db]  ; -> 0x3260fd8
  0183090b  mov     r8d, dword ptr [rbx + 0x100]                 ; ★ 联邦类型 +0x100 = 一个 id
  01830915  and     eax, 0xffffff
```

⇒ 写侧的落点既不是 country 字段也不是关系表,而是**联邦对象 / 联邦类型对象**;与 §4.6 的读侧
(`[country+0x1e88]` + 联邦成员数组)是**同一个对象家族的两头**,但本卷**没有**读到
`join_alliance` 往 `[fed+0x98]` 里 push 的那条指令(stall 在 `0x3947f0` 之后),记为 `未观测`。

### §4.8 §4 的表

| 状态 | 读侧来源 | 写侧来源 | 档 | 证伪条件 |
|---|---|---|---|---|
| 战争 | 关系对象 `+0xf4`(dword ≠ 0) | `未观测` | 静态推断(未验证) | 在 3 对已知交战国上读 `[rel+0xf4]`,不是非零 / 与非交战国同值 |
| 关闭边界 | 关系对象 `+0x120` bit 15 | 关系对象 `+0x120` bit 15(`0x185a9ae` 的 xor) | 静态推断(未验证) | 在已知互相闭边界的 2 国上读同一个 bit,读侧与写侧不同位 |
| 竞争 | 本国 `[+0x2c78]` 的 id 向量 `+0x28`/`+0x34` | `未观测` | 静态推断(未验证) | 已知宿敌对的 id 不在本国向量里 |
| 敌对 | `[country+0x1d78]` 态度表 `+0x490`/`+0x49c`,值 `+0x10` | `未观测` | 静态推断(未验证) | 已知敌对国查表返回的不是 `[[0x325ec78]+0x98]` |
| 联邦 | `[country+0x1e88]` → 联邦对象 `+0x98`/`+0xa4` | 联邦类型对象 `+0x100`(`0x183090b`)(§9 已更正:写侧是 `0x7563d9` 写 `[country+0x1e88]` + `0x6b440c` push 进 `[fed+0x90]` 容器;「联邦类型」这个类名见 §9.5) | 静态推断(未验证) | 同联邦两国中有一方 `+0x1e88` 指向的联邦对象里查不到另一方 |

### §4.9 §4 的三条「不能说」

1. **不能证明「可通行性」的语义。** 本卷钉住的是「哪个位存着闭边界」,不是「哪一侧不能过」。
   `xor` 写 + `self+0x488` 取反的写法说明「开/关」是效果参数决定的,而**方向**(从本国看对国,
   还是反过来)没有读数。要做到「A 的船进不去 B 的星系」,还需要一条**取对象方向**的读数。
2. **关系表是单向存储,方向未定。** `0xb1d470` 在**本国**的容器里按**对国 id** 二分查找 ⇒
   `relation(a→b)` 存在 a 的表里。引擎是否保证 b 的表也有一条对称项,本卷**未读到同步写**;
   因此「闭边界是对称的」这句话不能出口。
3. **没有 live 读数。** 五个谓词一次都没在活体里求值过;`0x325ec78`(态度库)、`0x325f6a0`
   (外交对象空回退)、`0x325fc68`(关系空回退)、`0x325fcf0`(空联邦)四个全局在文件里是 BSS,
   **静态不可定值**(与图卷 §1.11 对 `0x3260B98`/`0x325D880` 的口径相同)。

补充一条:**存档侧独立印证「关系是独立对象」**。同一份 `autosave_2257.07.01.sav` 的顶层块是
`war=3` / `truce=9` / `federation=0`,而 `country` 块里没有任何 `war=`/`truce=` 标量
(脚本与原始输出见 §5)。这与「战争/停战/联邦是独立顶层对象」的静态结论同向 ——
但存档只能作旁证,不能证明偏移。
## §5 存档 oracle(只证伪)

### §5.1 计划预期与实测的差异(**Ruling**)

计划 §5 Step 1 预期脚本打出 `systems=N owners=<distinct>` / `owner_range=min..max` / `owner_missing=<count>`。
**实测:4.4.4 存档的 `galactic_object` 块里根本没有 `owner=` 标量。** 787 个系统,
带 `owner=` 的 **0** 个。

原因(`claims` 的 `owner=` 是冒名货):

```text
$ python3 -   # 数第一个 400 kB 的 galactic_object 块里的 owner=
owner= count in first 400k: 76
colony= ? 56
'...planet=176\n\t\t\tclaims=\n\t\t\t{\n\t\t\t\t\n\t\t\t\t{\n\t\t\t\t\towner=16777247\n\t\t\t\t\tdate=\t\t\t\t"2256.07.10"\n\t\t\t\t\tclaims=1\n\t\t\t\t}\n \n\t\t\t}\n...'
```

`owner=16777247` = `0x00FFFFFF`,是**索赔记录里的「无人」哨兵**,不是系统的主人。
用 `grep owner=` 会把这 76 条算进去,得到「8 个 owner / 345 个系统」这种假读数 ——
所以脚本必须**解析树**而不是 grep。

⇒ **Ruling:** 存档 oracle **不能**对「系统 owner 字段」这一格开火(存档里没有这一格的对应物);
它能开火的是**国家 id 的值域**。§5.2 给出那个值域,§5.3 给出用它判死候选偏移的规则。
代价:如果将来发现 4.4.4 存档其实**有**别的写法记系统归属(比如某个 `flags` 子键),
本节的值域仍然有效,但「系统 owner 字段」那一格就多了一个旁证 —— 不影响本卷的字段结论。

### §5.2 脚本与原始输出

脚本:`scripts/scratch/2026-11_transitability/owner_domain.py`(一次性探针,按 `scripts/` 约定进 `scratch/`)。

```text
$ python3 scripts/scratch/2026-11_transitability/owner_domain.py /mnt/cache/tmp/opencode/autosave_2257.07.01.sav
save=/mnt/cache/tmp/opencode/autosave_2257.07.01.sav
systems=787 owners=0 owned=0 owner_missing=787
countries=41 ids=0..100663316
first10 systems (id -> owner):
  0 -> None
  1 -> None
  2 -> None
  3 -> None
  4 -> None
  5 -> None
  6 -> None
  7 -> None
  8 -> None
  9 -> None

# fallback domain: the top-level blocks that DO carry an `owner=`
# scalar, plus the raw/masked test against the country id set
spy_networks: children_with_owner=486 distinct=37 range=0..100663316 raw_subset=True masked_subset=True
army: children_with_owner=1166 distinct=22 range=0..100663316 raw_subset=True masked_subset=True
missile: children_with_owner=1 distinct=1 range=5122..5122 raw_subset=False masked_subset=False
megastructures: children_with_owner=5 distinct=4 range=16777220..16777228 raw_subset=True masked_subset=True
sectors: children_with_owner=31 distinct=18 range=0..100663316 raw_subset=True masked_subset=True
country_ids_fit_in_24_bits=False

war_blocks=3
truce_blocks=9
federation_blocks=0
dead_war_blocks=0
dead_federation_blocks=0
```

读出来的四条:

1. **系统数 787** —— 与 `AGENTS.md` 记的 `systems=788` 差 1(语料里 787/788 本就并存:
   图卷 §91.6 的派发窗是 787 行,M4 是 788),量级一致 ⇒ 这份存档确实是 4.4.4 的真实存档。
2. **国家 id 集合:41 个,`0 .. 100663316`**。`100663316 = 0x06000014` —— id **带高位标志位**,
   低 24 位(`& 0xffffff`)才是表索引。这与引擎里每一处 `and eax, 0xffffff` 同口径
   (`country_scope_4_4_4 §2.7` 的 A 级读数也是这个口径)。
3. **凡是有 `owner=` 的块,owner 值都 ⊆ 国家 id 集合**(`raw_subset=True`);唯一的例外是
   `missile`(owner=5122),它是舰队 id 不是国家 id —— 不当异常,单独记。
4. `war_blocks=3` / `truce_blocks=9` / `federation_blocks=0`:战争与停战是**顶层独立块**,
   `country` 块里没有对应标量 ⇒ §4「关系是独立对象」有存档侧旁证。

### §5.3 §5 的第一行(降级写法,逐字)

```text
§5 存档 oracle(只证伪):systems=787 countries=41 owner⊆country=yes(除 missile 的 5122,
  它是舰队 id);
  候选偏移 [obj+0xNN] 的读数若落在国家 id 集合外(原值或 &0xffffff 掩码后)⇒ 判死;
  落在集合内 ⇒ 不构成证据。
  —— 存档里**没有** galactic_object.owner,所以这条规则**不能**用来证伪
    「[系统对象+0x1370] 是 owner」;它只能证伪「某格是某个国家 id」。
```

### §5.4 §5 不能说的

1. **「owner 落在国家 id 集合内」不证明任何偏移。** 值域相符是最弱的证据;
   §2/§3 的偏移结论完全由静态执行体支撑,存档不参与。
2. **存档里的 `id` 与运行时读到的 `id` 不是同一口径。** 存档写的是带高位标志的原值,
   引擎读的是掩码后的索引;两者在本卷里已经用 `raw_subset` / `masked_subset` 两列分开记。
3. **这份存档没有联邦、没有 `federation` 块**,所以 §4.6 的联邦结论**没有**存档侧旁证。
## §6 判决与「下一发」清单

### §6.1 候选字段表(一页,不再加新读数)

| 候选 | 对象 | 偏移 | 读它的函数 | 档 | 证伪条件 | 升级需要的读数 |
|---|---|---|---|---|---|---|
| 系统 → 所属国家 id | 系统对象(`0x3260b98` 表) | `+0x1370` (u32,无主 = `0xFFFFFFFF`) | `0x8bc870` / `0x1a97650` / `0x8c2b70`(写)/ `0x8ae8b0`(ctor)(§7 已收口:`set_owner` 的 store 路径 = `0x816dd0` → `0x8c2ca0` → `0x8c2b70`,与本行同一格;档不变,仍缺活体读数) | 静态推断(未验证) | 3 个已知归属不同的星系上读出同值,或落在国家 id 集合外 | 活体读 3 个已知归属不同的星系(N1) |
| 关系对象:战争 | 关系对象(见「关系表」行) | `+0xf4` (dword,≠0 = 交战) | `0x1a9d980` | 静态推断(未验证) | 交战国对读出 0,或非交战对读出非 0 | 活体读 2 对交战国 + 1 对非交战(N2) |
| 关系对象:关闭边界 | 关系对象 | `+0x120` bit 15 (`0x8000`) | `0x1af5550`(读)/ `0x185a8f0`(写) | 静态推断(未验证) | 已知互相闭边界的一对读出 0,或已开放的一对读出 1 | 同 N2 一发里读同一对 |
| 关系表容器 | 国家对象 | `+0x2c78` → `[[..]+0x10] + 0x2d60` | `0x742670`(读)/ `0x73ec40`(写) | 静态推断(未验证) | 指针为 0 或 `+0x2d60` 处不是有序键表 | N2 同发里顺带读指针形状 |
| 关系键/值数组 | 关系表 | 键 `+0x60` / 条数 `+0x6c` / 值 `+0x18` | `0xb1d470` | 静态推断(未验证) | 二分搜不到已知对国 id | N2 同发 |
| 竞争:对等名单 | `[国家+0x2c78]` 外交对象 | `+0x28`(id 向量)/ `+0x34`(条数) | `0x76dfc0` | 静态推断(未验证) | 已知宿敌对不在本国的向量里 | N4 |
| 敌对:态度表 | `[国家+0x1d78]` | 数组 `+0x490` / 条数 `+0x49c` / 元素步长 `0x30`(键 `+8`、值 `+0x10`) | `0xbe3710` | 静态推断(未验证) | 查已知敌对国得到的不是 `[[0x325ec78]+0x98]` | N4 |
| 联邦:本国 → 联邦 | 国家对象 | `+0x1e88` (u32 联邦 id) | `0x7561f0`(§9 已补写侧:全 `.text` 唯一 dword 写点 `0x7563d9`,`0x7562a0(country, fed_id)` 内) | 静态推断(未验证) | 同联邦两国读出不同联邦 id | N5 |
| 联邦:成员表 | 联邦对象(`0x3261018` 表) | `+0x98`(id 数组)/ `+0xa4`(条数)(§9 已补写侧:push 在 `0x6b440c`,容器基址 `[fed+0x90]`,数据 `+0x98`、容量 `+0xa0`、条数 `+0xa4`) | `0x7561f0` | 静态推断(未验证) | 成员数组里查不到同联邦的另一国 | N5 |
| 原始主人 id | 表 `0x3260b78`(项 id 在 `+0x18`) | (按 mask 从 scope 取,再查表) | `0x1a97900` / `0x1a98280` | 静态推断(未验证) | 与 owner 那一格读到同一值(那是另一张表,应当不同) | N6 |
| 其他 scope 种类的 owner | 各种 | `+0x434`(mask **0x40** 一路)等;20 个 mask 的字段表见 §8.2 | `0x1a9bd10` | **未观测** → **静态推断(未验证)**(§8 已补齐:20 个叶子全部解出国家对象;§3.4 把这一支标成「mask 0x20」是错位,`+0x434` 属 mask `0x40`) | — | N1 同发里顺带扫 `0x1a9bd10` 的其余分支 |

### §6.2 下一发清单(每条一次 `install → 读 → uninstall`;引擎一进程只许 install 一次)

```text
下一发 N1(读侧,最便宜,先发这一发):
  读: 3 个已知归属不同的星系的对象指针,从系统索引(0x3260b98)解出,各读 u32 [obj+0x1370];
      顺带读 [obj+0x1374](锁)、[obj+0x1378..0x1379](两个旗标 byte)。
  判据: 三个 u32 互不相同,且 (值 & 0xffffff) 全部落在国家 id 集合内(掩码口径,§5.2);
        且 [obj+0x1374..0x1379] 呈现「锁 + 两旗标」形状。
  失败判词: owner_constant(三值相同) / owner_out_of_domain(有值不在国家 id 集合内)
             / owner_lock_shape_mismatch(锁/旗标形状不符 ⇒ 那一格不是「带锁的单值格」)。

下一发 N2(战争 + 闭边界,一发读两格):
  读: 2 对已知交战国 + 1 对已知非交战国的「关系对象」指针
      (路径:国家对象 +0x2c78 → [[..]+0x10] + 0x2d60 → 按对国 id 二分),
      各读 dword [rel+0xf4] 与 dword [rel+0x120];
      顺带读关系表的键数组 [base+0x60] 与条数 [base+0x6c]、值数组 [base+0x18]。
  判据: 交战对的 [rel+0xf4] ≠ 0;非交战对 = 0。
        已知互相闭边界的一对:[rel+0x120] & 0x8000 ≠ 0;已知开放的一对 = 0。
  失败判词: war_flag_constant / borders_flag_constant / relation_lookup_miss
             (键数组里找不到对国 id ⇒ 索引口径错了,不是「没有这一对」)。

下一发 N3(写侧,需要一发 mod 触发 set_owner):
  读: 同一个星系对象在 set_owner 生效前后的 [obj+0x1370] 各一次。
  判据: 写后值 & 0xffffff == 目标国家的 id(或低 24 位),且旧值 != 新值。
  失败判词: set_owner_writes_elsewhere(写后这一格没变 ⇒ §2.4 的 effect 路径与
             「[obj+0x1370] 是 owner」是两条不相干的线,§2 的字段结论要重审)。

下一发 N4(竞争 + 敌对):
  读: 本国对象 +0x2c78 → 外交对象,读 dword [+0x28]/[+0x34];对已知宿敌对做线性搜;
      读 [国家+0x1d78] 态度表的 [+0x490]/[+0x49c],对已知敌对国查键,比对
      [[0x325ec78]+0x98]。
  判据: 宿敌对的 id 出现在本国 +0x28 向量里;敌对国查表返回的对象 == [0x325ec78]+0x98。
  失败判词: rival_not_in_vector / hostile_attitude_mismatch。

下一发 N5(联邦):
  读: 2 个同联邦国家的 [country+0x1e88];解出联邦对象,读 [+0x98]/[+0xa4]。
  判据: 两国的 +0x1e88 相同(掩码后);联邦的 +0x98 数组里能查到对方 id。
  失败判词: federation_backlink_mismatch / federation_member_miss。
```

### §6.3 现在不能写实现

capability flag 的默认关闭与权限声明**要等 §6.1 表里「系统 → 所属国家 id」那一格到
`pinned(§N)`** —— 现在它只是 `静态推断(未验证)`。在那之前把
「`[obj+0x1370]` 是这个星系的主人」当成 API 契约公开出去,等于把一个**未验证的字段**
暴露给 mod 作者:一个读错偏移不会崩,只会安静地给出**看起来合理**的邻居值(这正是
`country_scope_4_4_4 §8` 拒绝给「看起来对」的偏移的理由)。同一条约束适用于外交五格:
它们的**方向语义**还没定(§4.9 第 1、2 条),所以「闭边界 ⇒ 不可通行」这句话现在**不能**
作为 API 语义写出去。

### §6.4 本卷与既有卷的关系(一页索引)

| 本卷的读数 | 既有出处 | 关系 |
|---|---|---|
| `scope+0x08` = mask / `scope+0x10` = id | `country_scope_4_4_4 §6`(A 级) | 直接引用;本卷没有新的 mask 读数 |
| 国家对象 id 在 `+0x20`;国家对象表 `0x3260FD8`(项 id `+0x20`,步长 `0x10`,取 `+8`) | `country_scope_4_4_4 §7`(B+) | 直接引用(§2.5 的写源、§3.1 的读源) |
| 系统对象 id 在 `+0x08`;系统索引 `0x3260B98` | `runtime_444_graph_runtime.md §1.2`(A 级) | 直接引用(§3.3 的「同一个系统对象」判定) |
| `0x2185218` = `operator new` | `runtime_444_c1_validation §17/§21` | 直接引用(§1.3/§2.1 的形状) |
| 触发求值槽 = slot[5] (`+0x28`),基体 `0x1A91A80`,尾跳 slot[4] (`+0x20`) | `runtime_444_c1_validation §77` | 直接引用;本卷的「slot[3] = subject」是**新增**归纳 |
| effect slot[2] `+0x10` = instantiate helper `0x3B01A0` | `runtime_444_c1_validation §57.2` | 直接引用(§2.2) |
| opinion 矩阵 `[[0x33794D0]]` | `country_fields_4_4_4 §2`(A) | **不冲突**:那是**意见值**矩阵;本卷的 `0x3260fd8`/关系对象是**外交状态**,两张表两个对象 |

### §6.5 下一卷(交给谁)

1. `0x816dd0`(`set_owner` 分支的下游写体)展开:定「`[接受者+0x320]` 指向什么」,把 §2.4 的
   `unresolved` 收成一条可读的路径(这是本卷唯一明确卡住的地方)。
2. `0x1a9bd10`(`is_owned_by` slot[3])剩余分支(mask `1 / 0x10 / 0x100 / 0x40000`)读完,
   把「owner 按 scope 种类分派」的表补齐 —— 目前只钉了 `0x80` 一格。
3. `0x3947f0` 之后:「`join_alliance` 往联邦成员数组 push」那条指令(§4.7 的 stall 点)。
4. `0x35eee0`(参数按名取值)与 `0x742670`/`0x73ec40` 的**方向**语义:同一对国家在两边的
   表里各有没有一条 —— 这一条决定 §4.9 第 2 条能不能销。

---

## §7 `0x816DD0` 展开:`set_owner` 的 store 路径落到哪一格

(收 §6.5 第 1 条。)§2.4 判 `unresolved` 的原因是「`0x816dd0` 的入参不是 scope」。
本节把那个入参追到**系统对象**,并给出它与 `[系统对象+0x1370]` 的关系。
**结论先写:`same_slot`** —— 这条 effect 最终仍由 `0x8c2b70` 写 `[系统对象+0x1370]`,
`0x816dd0` 只是替它把「待更新」旗标置起来。

### §7.1 入参对象是什么:`0x816dd0` 的前 36 条指令

```text
$ python3 scripts/disrva.py 0x816dd0 --len=0xa0
; stellaris.exe  .text RVA 0x816dd0-0x816e70
  00816dd0  mov     qword ptr [rsp + 0x10], rbx
  00816dd5  mov     qword ptr [rsp + 0x18], r8
  00816dda  push    rbp
  00816ddb  push    rsi
  00816ddc  push    rdi
  00816ddd  push    r12
  00816ddf  push    r13
  00816de1  push    r14
  00816de3  push    r15
  00816de5  lea     rbp, [rsp - 0x580]
  00816ded  sub     rsp, 0x680
  00816df4  movzx   ebx, r9b
  00816df8  mov     rsi, rdx                                    ; 2nd arg = 参数(国家)
  00816dfb  mov     r14, rcx                                    ; 1st arg = 输入对象
  00816dfe  call    0x140812ec0  ; -> 0x812ec0                 ; r15 = 输入对象 -> 国家
  00816e03  mov     r15, rax
  00816e06  mov     rcx, r14
  00816e09  call    0x140818010  ; -> 0x818010
  00816e0e  mov     rdx, qword ptr [rip + 0x2a4a1bb]  ; -> 0x3260fd0
  00816e15  test    rdx, rdx
  00816e18  je      0x140816e4e
  00816e1a  mov     r8d, dword ptr [r14 + 0x98]                 ; ★ 输入对象 +0x98 = 一个 id
  00816e21  mov     eax, r8d
  00816e24  and     eax, 0xffffff
  00816e29  cmp     eax, dword ptr [rdx + 0x20]
  00816e2c  jae     0x140816e4e
  00816e2e  mov     ecx, eax
  00816e30  add     ecx, ecx
  00816e33  mov     rax, qword ptr [rdx + 0x18]
  00816e37  mov     rdi, qword ptr [rax + rcx*8 + 8]            ; X
  00816e3c  mov     qword ptr [rbp + 0x5c0], rdi
  00816e43  test    rdi, rdi
  00816e46  je      0x140816e4e
  00816e48  cmp     dword ptr [rdi + 0x18], r8d                 ; 表项 id 在 +0x18
  00816e4c  je      0x140816e5c
  00816e4e  mov     rdi, qword ptr [rip + 0x2a48b8b]  ; -> 0x325f9e0   ; 空回退
  00816e55  mov     qword ptr [rbp + 0x5c0], rdi
  00816e5c  mov     rcx, r14
  00816e5f  call    0x1408176f0  ; -> 0x8176f0
  00816e64  movzx   r9d, al
  00816e68  mov     byte ptr [rbp + 0x5d8], al
```

三个 helper 用**同一个第一跳**:`[输入对象 + 0x98]` → 表 `0x3260fd0`(表项 id 在 `+0x18`,
空回退 `0x325f9e0`)→ 记作 **X**。之后各走各的:

```text
$ python3 scripts/disrva.py 0x8168b0 --len=0x60        ; 输入对象 -> 系统对象
  008168b0  mov     rdx, qword ptr [rip + 0x2a4a719]  ; -> 0x3260fd0
  008168b7  test    rdx, rdx
  008168ba  je      0x1408168e9
  008168bc  mov     r8d, dword ptr [rcx + 0x98]                ; 第一跳 = X 的 id
  008168c3  mov     eax, r8d
  008168c6  and     eax, 0xffffff
  008168cb  cmp     eax, dword ptr [rdx + 0x20]
  008168ce  jae     0x1408168e9
  008168d0  mov     ecx, eax
  008168d2  mov     rax, qword ptr [rdx + 0x18]
  008168d6  add     rcx, rcx
  008168d9  mov     rax, qword ptr [rax + rcx*8 + 8]
  008168de  test    rax, rax
  008168e1  je      0x1408168e9
  008168e3  cmp     dword ptr [rax + 0x18], r8d
  008168e7  je      0x1408168f0
  008168e9  mov     rax, qword ptr [rip + 0x2a490f0]  ; -> 0x325f9e0
  008168f0  mov     rdx, qword ptr [rip + 0x2a4a2a1]  ; -> 0x3260b98   ; 系统对象表
  008168f7  test    rdx, rdx
  008168fa  je      0x140816929
  008168fc  mov     r8d, dword ptr [rax + 0xa00]                ; ★ X + 0xa00 = 系统 id
  00816903  mov     eax, r8d
  00816906  and     eax, 0xffffff
  0081690b  cmp     eax, dword ptr [rdx + 0x20]
  0081690e  jae     0x140816929
```

```text
$ python3 scripts/disrva.py 0x812ec0 --len=0x60        ; 输入对象 -> 国家
  00812ec0  mov     rdx, qword ptr [rip + 0x2a4e109]  ; -> 0x3260fd0
  00812ec7  test    rdx, rdx
  00812eca  je      0x140812ef9
  00812ecc  mov     r8d, dword ptr [rcx + 0x98]                ; 第一跳 = X
  00812ed3  mov     eax, r8d
  00812ed6  and     eax, 0xffffff
  00812edb  cmp     eax, dword ptr [rdx + 0x20]
  00812ede  jae     0x140812ef9
  00812ee0  mov     ecx, eax
  00812ee2  mov     rax, qword ptr [rdx + 0x18]
  00812ee6  add     ecx, ecx
  00812ee9  mov     rax, qword ptr [rax + rcx*8 + 8]
  00812eee  test    rax, rax
  00812ef1  je      0x140812ef9
  00812ef3  cmp     dword ptr [rax + 0x18], r8d
  00812ef7  je      0x140812f00
  00812ef9  mov     rax, qword ptr [rip + 0x2a4cae0]  ; -> 0x325f9e0
  00812f00  mov     rdx, qword ptr [rip + 0x2a4bff9]  ; -> 0x325ef00   ; 表 0x325ef00
  00812f07  test    rdx, rdx
  00812f0a  je      0x140812f39
  00812f0c  mov     r8d, dword ptr [rax + 0x990]                ; ★ X + 0x990 = Y 的 id
  00812f13  mov     eax, r8d
  00812f16  and     eax, 0xffffff
  00812f1b  cmp     eax, dword ptr [rdx + 0x20]
  00812f1e  jae     0x140812f39
  00812f20  mov     ecx, eax
  00812f22  mov     rax, qword ptr [rdx + 0x18]
  00812f26  add     ecx, ecx
  00812f29  mov     rax, qword ptr [rax + rcx*8 + 8]
  00812f2e  test    rax, rax
  00812f31  je      0x140812f39
  00812f33  cmp     dword ptr [rax + 0x30], r8d                 ; Y 的 id 在 +0x30
  00812f37  je      0x140812f40
  00812f39  mov     rax, qword ptr [rip + 0x2a4cae0]  ; -> 0x325fa20
```

```text
$ python3 scripts/disrva.py 0x812f40 --len=0x40        ; 第三跳:Y -> 国家
  00812f40  mov     rdx, qword ptr [rip + 0x2a4e091]  ; -> 0x3260fd8   ; 国家对象表
  00812f47  test    rdx, rdx
  00812f4a  je      0x140812f79
  00812f4c  mov     r8d, dword ptr [rax + 0x434]                ; ★ Y + 0x434 = 国家 id
  00812f53  mov     eax, r8d
  00812f56  and     eax, 0xffffff
  00812f5b  cmp     eax, dword ptr [rdx + 0x20]
  00812f5e  jae     0x140812f79
  00812f60  mov     ecx, eax
  00812f62  mov     rax, qword ptr [rdx + 0x18]
  00812f66  add     ecx, ecx
  00812f69  mov     rax, qword ptr [rax + rcx*8 + 8]
  00812f6e  test    rax, rax
  00812f71  je      0x140812f79
  00812f73  cmp     dword ptr [rax + 0x20], r8d
  00812f77  je      0x140812f80
  00812f79  mov     rax, qword ptr [rip + 0x2a4c410]  ; -> 0x325f390   ; 空国家
  00812f80  ret
```

⇒ **`0x812ec0` = 「输入对象 → X → Y → 国家」**,第三跳的 `[Y+0x434]` 正是 `is_owned_by`
分派树里读 `+0x434` 的那一支(§8.2 的 **mask `0x40`**,分支体 `0x1a9bdee`)——
两条完全独立的代码路径落在同一格 ⇒ `+0x434` 这一格的可信度从「单点」升到「两点同形」。
(注:§3.4 把这一支标成「mask 0x20」,**那是数错了** —— `sub` 链上 `+0x434` 属于
**mask `0x40`**,mask `0x20`(`0x1a9be28`)读的是 `+0x3a8`。见 §8.2。)

**输入对象的结构(逐条读出,类名 `未观测`):**

| 对象 | 从哪来 | 读出的字段 |
|---|---|---|
| 输入对象(记作 Z) | 见 §7.2 | `+0x98` = X 的 id;`+0x880` / `+0x884` = 两个 id(`0x816f3b` / `0x816f4a` 各喂给 `0x8174e0`);`+0xa0`(容器基址,`0x817163`);`+0xbb8`(带 vptr 的子对象,`0x816f67` 调 vtable `+0x40`) |
| X | 表 `0x3260fd0`,表项 id `+0x18` | `+0x990` = Y 的 id;`+0xa00` = 系统 id;`+0x988`(qword 写,`0x81715c`) |
| Y | 表 `0x325ef00`,表项 id `+0x30` | `+0x434` = 国家 id;`+0x1248`(byte,`0x8176f0` 比 `0xa`)、`+0x1240` 的 bit 9、`+0x664`(同一函数继续读) |

### §7.2 哪个调用点把 scope 换成 Z

`0x18015f0` 的分派键 `0x40` 分支(§2.3 已抄过前半):

```text
$ python3 scripts/disrva.py 0x18017d2 --len=0xb0
  018017d2  cmp     rcx, 0x40
  018017d6  jne     0x14180189e
  018017dc  mov     rcx, rbx
  018017df  call    0x140393f30  ; -> 0x393f30                  ; scope -> Y(表 0x325ef00)
  018017e7  cmp     byte ptr [rax + 0x1248], 0xa
  01801820  cmp     dword ptr [rbx + 0x32c], 0
  01801827  je      0x141801851
  01801829  mov     rdx, qword ptr [rbx + 0x320]                 ; ★ Y + 0x320 = 指向 id 的指针
  01801830  mov     rax, qword ptr [rip + 0x1a5f379]  ; -> 0x3260bb0
  01801837  mov     rcx, qword ptr [rax + 0x948]
  0180183e  add     rcx, 0xed8                                   ; 哈希表 db
  01801845  mov     edx, dword ptr [rdx]                         ; id
  01801847  call    0x1409c0fd0  ; -> 0x9c0fd0                  ; ★ db+id -> Z
  0180184c  mov     rsi, rax
  01801865  xor     r8d, r8d
  01801868  mov     r9b, 6
  0180186b  mov     rdx, rdi                                     ; 参数(国家)
  0180186e  mov     rcx, rsi                                     ; Z
  01801871  call    0x140816dd0  ; -> 0x816dd0                  ; ★ 这里
```

`0x9c0fd0` 是一个**开放寻址哈希表查表**(不是对象表):

```text
$ python3 scripts/disrva.py 0x9c0fd0 --len=0x70
  009c0fd0  movsxd  r9, dword ptr [rcx + 0x4c]                 ; 掩码
  009c0fd4  mov     r10, qword ptr [rcx + 0x40]                 ; 桶数组
  009c0fd8  mov     r8, r9
  009c0fdb  movsxd  rax, edx
  009c0fde  and     r8, rax
  009c0fe1  lea     rax, [r8 + r8*2]
  009c0fe5  mov     r8b, 1
  009c0fe8  cmp     byte ptr [r10 + rax*8 + 4], r8b             ; 步长 0x18
  009c0fed  lea     rax, [r10 + rax*8]
  009c0ff1  jb      0x1409c1005
  009c0ff3  cmp     edx, dword ptr [rax + 8]                     ; 键在 +8
  009c0ff6  je      0x1409c1038
  009c0ff8  add     rax, 0x18
  009c0ffc  inc     r8b
  009c0fff  cmp     r8b, byte ptr [rax + 4]
  009c1003  jbe     0x1409c0ff3                                 ; 链式探测
```

⇒ **调用点在 `0x1801871`**:`Z = HashMapLookup([[0x3260bb0]+0x948] + 0xed8, dword[[0x393f30(scope)] + 0x320])`。
同一条 effect 的另一个分支也走 `0x816dd0`(`0x18018d9`,键 `0x20000`),
但那个分支的入参来自 `0x3949e0`,不是本节这条。

### §7.3 `0x816dd0` 自己怎么写:置旗标 + 刷新,不是直接落盘

```text
$ python3 scripts/disrva.py 0x816e79 --len=0x50
  00816e79  mov     eax, 8
  00816e7e  test    r9b, r9b                                     ; = 0x8176f0(Z) 的结果
  00816e81  je      0x140816eb9
  00816e83  cmp     r15, rsi                                     ; r15 = 0x812ec0(Z) = 当前国家
  00816e86  je      0x140816e9c
  00816e88  lea     rcx, [r15 + 0x20]
  00816e8c  test    r15, r15
  00816e8f  cmove   rcx, rax
  00816e93  mov     ecx, dword ptr [rcx]
  00816e95  mov     dword ptr [r13 + 0x580], ecx                 ; ★ 系统 +0x580 = 旧国家 id
  00816e9c  mov     eax, 1
  00816ea1  xchg    byte ptr [r13 + 0x1378], al                  ; ★ 系统 +0x1378 = 待更新旗标
  00816ea8  cmp     byte ptr [rip + 0x2b61ce5], 0  ; -> 0x3378b94
  00816eaf  je      0x140816eb9
  00816eb1  mov     rcx, r13
  00816eb4  call    0x1408c2ca0  ; -> 0x8c2ca0                  ; ★ §2.4(d) 的刷新包装
  00816eb9  mov     rcx, rsi
  00816ebc  call    0x140243600  ; -> 0x243600
```

`0x8c2ca0` 就是 §2.4(d) 抄过的那一段:读旧 `[+0x1370]` → 调 `0x8c2b70` → 读新 `[+0x1370]`
→ 不等则 `0x8bcaa0(obj, old, new)`。而 `0x8c2b70` 的写点是 `0x8c2c6b mov dword ptr [rsi+0x1370], ecx`。

⇒ **链路闭合:`set_owner` → `0x816dd0` → `0x8168b0` 解出系统对象 → 置 `+0x1378` →
`0x8c2ca0` → `0x8c2b70` → `mov dword [系统+0x1370], [国家+0x20]`。与 §2 的候选同一格。**

顺带把 §2.4「第二次写」那一行也解释了:同一个 `0x8c2b70` 里
`xchg byte ptr [rdi + 0x3798], al` / `xchg byte ptr [rbx + 0x3798], bpl`
(`0x8c2c33` / `0x8c2c47`)就是「新旧两国各置一次 dirty」,不是另一张 owner 表。

### §7.4 §7 的三行判决

```text
结论: same_slot —— `set_owner` 的 store 路径就是 `[系统对象+0x1370]`,写手与 §2.4 的 0x8c2b70
      同一个;`0x816dd0` 自己只写 `+0x580`(旧 id 快照)与 `+0x1378`(待更新旗标)。
      命令: disrva.py 0x816dd0 --len=0xa0 / 0x8168b0 --len=0x60 / 0x816e79 --len=0x50
           disrva.py 0x812ec0 --len=0x60 / 0x812f40 --len=0x40
           disrva.py 0x18017d2 --len=0xb0 / 0x9c0fd0 --len=0x70
      档: 静态推断(未验证)
不能说的: ① 输入对象 Z / X 的**类名**没读到(`未观测`);能说的只是「Z 的 +0x98 → X 的 +0x990 → Y
          的 +0x434 → 国家」这条 id 链,和「X 的 +0xa00 → 系统对象」这一跳;
          ② 「参数国家的 id 从哪条指令进到 `[[系统+0x570]]`」没定位到 —— 新 owner 由
          `0x8bc8c0(系统)` 读 `[系统+0x570]` 的指向物算出(§2.4 b),而 `0x816dd0` 体内只写
          `+0x580`、`+0x1378`、`[X+0x988]`,没有一条直接写 `[[系统+0x570]]`;
          ③ 零 live 读数。
下一发升级条件: N3(§6.2)不变 —— 一发里读 set_owner 前后的 `[系统+0x1370]`;判据与失败判词照抄 §6.2。
          追加一个字据: 同一发里顺带读 `[系统+0x580]`(期望 = 写入**前**的 owner id)与
          `[系统+0x1378]`(期望写完后回到 0)。若 `+0x580` 在写后仍等于新 owner,则本节的
          「+0x580 = 旧 id 快照」判死。
```

---

## §8 `is_owned_by` slot[3] = `0x1a9bd10` 的全部叶子

(收 §6.5 第 2 条。)§3.4 写的是「九路 switch」—— **那是我按前 45 条指令数出来的,数错了**。
把它读完:**20 个 mask 叶子 + 1 条 switch 之前的兜底路径**。本节逐叶列出,
并把 §6.1 最后一行从 `未观测` 升成 `静态推断(未验证)`。

### §8.1 分派树(逐字)

```text
$ python3 scripts/disrva.py 0x1a9bd84 --len=0x50
  01a9bd84  mov     rax, qword ptr [rdi + 8]                 ; ★ scope mask
  01a9bd88  cmp     rax, 0x40000
  01a9bd8e  ja      0x141a9c04a                              ; > 0x40000 → 第三层
  01a9bd94  je      0x141a9c02d                              ; 0x40000
  01a9bd9a  cmp     rax, 0x100
  01a9bda0  ja      0x141a9bf99                              ; > 0x100 → 第二层
  01a9bda6  je      0x141a9bf76                              ; 0x100
  01a9bdac  sub     rax, 1
  01a9bdb0  je      0x141a9bf53                              ; 1
  01a9bdb6  sub     rax, 0xf
  01a9bdba  je      0x141a9beba                              ; 0x10
  01a9bdc0  sub     rax, 0x10
  01a9bdc4  je      0x141a9be28                              ; 0x20
  01a9bdc6  sub     rax, 0x20
  01a9bdca  je      0x141a9bdee                              ; 0x40
  01a9bdcc  cmp     rax, 0x40
  01a9bdd0  jne     0x141a9c23a                              ; 无匹配 → 空对象
  01a9bdd6  mov     rcx, rdi
  01a9bdd9  call    0x140393970  ; -> 0x393970                ; 0x80
  01a9bdde  mov     rcx, rax
  01a9bde1  call    0x1408bc870  ; -> 0x8bc870                ; → [obj+0x1370]
  01a9bde6  mov     rbx, rax
```

```text
$ python3 scripts/disrva.py 0x1a9bf99 --len=0x3c        ; 第二层(0x100 < mask ≤ 0x40000)
  01a9bf99  cmp     rax, 0x200
  01a9bf9f  je      0x141a9c015
  01a9bfa1  cmp     rax, 0x1000
  01a9bfa7  je      0x141a9bff5
  01a9bfa9  cmp     rax, 0x4000
  01a9bfaf  je      0x141a9bfd5
  01a9bfb1  cmp     rax, 0x20000
  01a9bfb7  jne     0x141a9c23a
  01a9bfbd  mov     rcx, rdi
  01a9bfc0  call    0x140394960  ; -> 0x394960
  01a9bfc5  mov     rcx, rax
  01a9bfc8  call    0x140816990  ; -> 0x816990                ; ★ 与 §7 同一条链
  01a9bfcd  mov     rbx, rax
  01a9bfd0  jmp     0x141a9c23a  ; -> 0x1a9c23a
```

```text
$ python3 scripts/disrva.py 0x1a9c04a --len=0x38        ; 第三层(0x40000 < mask ≤ 0x2000000)
  01a9c04a  cmp     rax, 0x2000000
  01a9c050  ja      0x141a9c17f
  01a9c056  je      0x141a9c12c
  01a9c05c  cmp     rax, 0x100000
  01a9c062  je      0x141a9c109
  01a9c068  cmp     rax, 0x400000
  01a9c06e  je      0x141a9c0c4
  01a9c070  cmp     rax, 0x800000
  01a9c076  je      0x141a9c09c
  01a9c078  cmp     rax, 0x1000000
  01a9c07e  jne     0x141a9c23a
  01a9c084  mov     rcx, rdi
  01a9c087  call    0x140394ca0  ; -> 0x394ca0
  01a9c08c  mov     rcx, rax
  01a9c08f  call    0x140648b80  ; -> 0x648b80
```

```text
$ python3 scripts/disrva.py 0x1a9c17f --len=0x30        ; 第四层(mask > 0x2000000)
  01a9c17f  cmp     rax, 0x10000000
  01a9c185  je      0x141a9c1f7
  01a9c187  cmp     rax, 0x20000000
  01a9c18d  je      0x141a9c1db
  01a9c18f  cmp     rax, 0x40000000
  01a9c195  je      0x141a9c1c2
  01a9c197  mov     ecx, 0x80000000
  01a9c19c  cmp     rax, rcx
  01a9c19f  jne     0x141a9c23a
  01a9c1a5  mov     rcx, rdi
  01a9c1a8  call    0x140395200  ; -> 0x395200
  01a9c1ad  lea     rdx, [rsp + 0x24]
  01a9c1b2  lea     rcx, [rax + 0x70]
  01a9c1b6  mov     rax, qword ptr [rax + 0x70]
  01a9c1ba  call    qword ptr [rax + 0x58]                    ; vtable +0x58 取 id
```

### §8.2 20 个叶子逐条

表里三列的定义:

- **scope → 对象**:每支第一步把 scope 换成哪个对象(第一个 `call`)。
- **读出的 id 来源**:从那个对象(或再下一跳)读哪个字段才是国家 id。
- **落地方式**:最后一步怎么把 id 变成**国家对象**。

| mask | scope → 对象 | 读出的 id 来源 | 落地方式 |
|---|---|---|---|
| `1` | `0x394870` | `[obj+0x1b8]` | 表 `0x3260fd8`(国家表) |
| `0x10` | `0x394190` | `[obj+0x18]` → 表 `0x3260ff0`(项 id `+0x10`)→ `[entry+0x3a8]` → 表 `0x3261068`(项 id `+0x10`)→ `[entry+0xf78]` → `0xd3b4d0` → vtable `+0x58` | 表 `0x3260fd8` |
| `0x20` | `0x2b6470` | `[obj+0x3a8]` → 表 `0x3261068` → `[entry+0xf78]` → `0xd3b4d0` → vtable `+0x58` | 表 `0x3260fd8` |
| `0x40` | `0x393ec0` | `[obj+0x434]` | 表 `0x3260fd8` |
| `0x80` | `0x393970` → `0x8bc870` | (系统对象的 `+0x1370`) | **`0x8bc870` 直接返回国家对象**(§3.2) |
| `0x100` | `0x393a70` | `[obj+0xd8]` | 表 `0x3260fd8` |
| `0x200` | `0x3942b0` → `0x8577d0` | `[obj+0x16c]` | `0x8577d0` 内部查表 `0x3260fd8` |
| `0x1000` | `0x3952e0` → `0x35fb20` → `0x8bc870` | `[obj+0x78]` → 表 `0x3260b98`(系统表)→ 系统对象 | **`0x8bc870` 直接返回国家对象** |
| `0x4000` | `0x3945b0` | `[obj+0x20]` | 表 `0x3260fd8` |
| `0x20000` | `0x394960` → `0x816990` | `0x816990` → `0x812ec0`:Z `+0x98` → X → Y `+0x434` | `0x812ec0` 内部查表 `0x3260fd8`(**与 §7 同一条链**) |
| `0x40000` | `0x394a60` | `[obj+0x30]` + `[obj+0x34]` → `0xec3b00` → vtable `+0x58` | 表 `0x3260fd8` |
| `0x100000` | `0x394b40` | `[obj+0x168]` | 表 `0x3260fd8` |
| `0x400000` | `0x394bc0` | `[obj+0xa0]` + `[obj+0xa4]` → `0x89a2e0` → vtable `+0x8` → `0x34e340` → `[rax+0x1370]` | 表 `0x3260fd8` ⚠ 这里的 `+0x1370` 在 `0x34e340` 返回的**另一个对象**上,不保证是系统对象 |
| `0x800000` | `0x394d80` → `0x3538f0` | `[rax+0x20]` | 表 `0x3260fd8` |
| `0x1000000` | `0x394ca0` → `0x648b80` | `[obj+0x18]` | `0x648b80` 内部查表 `0x3260fd8` |
| `0x2000000` | `0x394e60` | `[obj+0xac]` → 表 `0x3261030`(项 id `+0x8`)→ `[entry+0x18]` → `0x648b80` | `0x648b80` 内部查表 `0x3260fd8` |
| `0x10000000` | `0x394fc0` | `[obj+0x18]` | 表 `0x3260fd8` |
| `0x20000000` | `0x3950a0` | `[obj+0x204]` | 表 `0x3260fd8` |
| `0x40000000` | `0x395180` | `[obj+0x38]` | 表 `0x3260fd8` |
| `0x80000000` | `0x395200` | `[obj+0x70]` 的 vtable `+0x58` | 表 `0x3260fd8` |

**三个落地 helper 的原文**(它们的字段就是上表的 id 来源):

```text
$ python3 scripts/disrva.py 0x8577d0 --len=0x40
  008577d0  mov     rdx, qword ptr [rip + 0x2a09801]  ; -> 0x3260fd8
  008577d7  test    rdx, rdx
  008577da  je      0x140857809
  008577dc  mov     r8d, dword ptr [rcx + 0x16c]
  008577e3  mov     eax, r8d
  008577e6  and     eax, 0xffffff
  008577eb  cmp     eax, dword ptr [rdx + 0x20]
  008577ee  jae     0x140857809
  008577f0  mov     ecx, eax
  008577f2  mov     rax, qword ptr [rdx + 0x18]
  008577f6  add     ecx, ecx
  008577f9  mov     rax, qword ptr [rax + rcx*8 + 8]
  008577fe  test    rax, rax
  00857801  je      0x140857809
  00857803  cmp     dword ptr [rax + 0x20], r8d
  00857807  je      0x14057810
  00857809  mov     rax, qword ptr [rip + 0x2a07b80]  ; -> 0x325f390
```

```text
$ python3 scripts/disrva.py 0x648b80 --len=0x40
  00648b80  mov     rdx, qword ptr [rip + 0x2c18451]  ; -> 0x3260fd8
  00648b87  test    rdx, rdx
  00648b8a  je      0x140648bb6
  00648b8c  mov     r8d, dword ptr [rcx + 0x18]
  00648b90  mov     eax, r8d
  00648b93  and     eax, 0xffffff
  00648b98  cmp     eax, dword ptr [rdx + 0x20]
  00648b9b  jae     0x140648bb6
  00648b9d  mov     ecx, eax
  00648b9f  mov     rax, qword ptr [rdx + 0x18]
  00648ba3  add     ecx, ecx
  00648ba6  mov     rax, qword ptr [rax + rcx*8 + 8]
  00648bab  test    rax, rax
  00648bae  je      0x140648bb6
  00648bb0  cmp     dword ptr [rax + 0x20], r8d
  00648bb4  je      0x140648bbd
  00648bb6  mov     rax, qword ptr [rip + 0x2c167d3]  ; -> 0x325f390
  00648bbd  ret
```

```text
$ python3 scripts/disrva.py 0x35fb20 --len=0x40
  0035fb20  mov     rdx, qword ptr [rip + 0x2f01071]  ; -> 0x3260b98   ; 系统表
  0035fb27  test    rdx, rdx
  0035fb2a  je      0x14035fb56
  0035fb2c  mov     r8d, dword ptr [rcx + 0x78]
  0035fb30  mov     eax, r8d
  0035fb33  and     eax, 0xffffff
  0035fb38  cmp     eax, dword ptr [rdx + 0x20]
  0035fb3b  jae     0x14035fb56
  0035fb3d  mov     ecx, eax
  0035fb3f  mov     rax, qword ptr [rdx + 0x18]
  0035fb43  add     ecx, ecx
  0035fb46  mov     rax, qword ptr [rax + rcx*8 + 8]
  0035fb4b  test    rax, rax
  0035fb4e  je      0x14035fb56
  0035fb50  cmp     dword ptr [rax + 8], r8d
  0035fb54  je      0x14035fb5d
  0035fb56  mov     rax, qword ptr [rip + 0x2efdd23]  ; -> 0x325d880
  0035fb5d  ret
```

**switch 之前的兜底路径**(`0x1a9bd18`,任何 mask 都先试一次):

```text
$ python3 scripts/disrva.py 0x1a9bd18 --len=0x30
  01a9bd18  mov     rbx, qword ptr [rip + 0x17c3671]  ; -> 0x325f390   ; 空国家
  01a9bd1f  mov     rsi, rcx
  01a9bd22  mov     rcx, rdx
  01a9bd25  mov     rdi, rdx                                     ; scope
  01a9bd28  call    0x140a54d70  ; -> 0xa54d70
  01a9bd2d  mov     rcx, rax
  01a9bd30  test    rax, rax
  01a9bd33  je      0x141a9bd84                                  ; 失败才进 switch
  01a9bd35  mov     rax, qword ptr [rax]
  01a9bd38  lea     rdx, [rsp + 0x50]
  01a9bd3d  call    qword ptr [rax + 0x58]                       ; vtable +0x58 取 id
  01a9bd40  mov     rdx, qword ptr [rip + 0x17c5291]  ; -> 0x3260fd8
```

⇒ 共 **21 条**取对象的路径。

### §8.3 20 个叶子合流的尾部:全部比「国家对象 == 参数」

```text
$ python3 scripts/disrva.py 0x1a9c23a --len=0x50
  01a9c23a  lea     r8, [rsi + 0x40]
  01a9c23e  mov     rdx, rdi                                     ; scope
  01a9c241  lea     rcx, [rsi + 0x80]
  01a9c248  lea     r9, [rip + 0xa0ed61]  ; -> 0x24aafb0       ; "is_owned_by"
  01a9c24f  call    0x14035eee0  ; -> 0x35eee0                  ; 取参数
  01a9c254  mov     rdx, qword ptr [rbx + 0x18]
  01a9c258  lea     rcx, [rbx + 0x18]
  01a9c25c  mov     rdi, rax
  01a9c25f  call    qword ptr [rdx + 8]                          ; rbx(解出的国家)有效性
  01a9c262  test    al, al
  01a9c264  je      0x141a9c283
  01a9c266  mov     rdx, qword ptr [rdi + 0x18]
  01a9c26a  lea     rcx, [rdi + 0x18]
  01a9c26e  call    qword ptr [rdx + 8]                          ; 参数有效性
  01a9c271  test    al, al
  01a9c273  je      0x141a9c283
  01a9c275  cmp     rbx, rdi
  01a9c278  sete    al                                           ; ★ 对象身份比较
```

⇒ **20 个叶子产出的都是同一个类型(国家对象),尾部只做「对象 == 参数」**。
没有一支返回「布尔」「计数」或别的类型 —— 这与 §3.6 记的「owner 不是一格,是一组分派」
一致,只是分派的宽度从 9 变成 20。

### §8.4 §6.1 最后一行的升级

| 原行 | 原档 | 现在 | 依据 |
|---|---|---|---|
| 「其他 scope 种类的 owner」 | `未观测` | **`静态推断(未验证)`** | §8.2 的 20 行表:每个 mask 各自读一个字段,21 条路径**全部**最终产出一个国家对象(18 条经国家表 `0x3260fd8`,2 条经 `0x8bc870` 直接返回) |

能升级到什么、不能升级到什么,写清楚:

- **可以写**:「`is_owned_by` 对任何一种 scope 都解出一个**国家对象**;那个对象对应的 id 在
  哪个字段上,由 `[scope+8]` 的 mask 决定,表在 §8.2」。
- **不可以写**:「那 20 个字段都是 `owner`」。它们是「这个 scope 的**归属国**」不同视图:
  有的直接在对象上(`+0x1370` 系统、`+0x434`)、有的要过三张表(mask `0x10`/`0x20`)、
  有的取的是 id 对(`0x40000` 的 `+0x30/+0x34`)、有一支的 `+0x1370` 还不保证是系统对象
  (`0x400000`)。**把它们当成同一语义的别名会读错。**

### §8.5 §8 不能说的

1. **类名全未观测。** 20 个第一跳函数(`0x394870` / `0x394190` / `0x2b6470` / … )的返回类型
   本卷一个都没命名;能给的只有「表 → 表项 id 位移 → 字段位移」。
2. **四个中继体没读**:`0x34e340`(mask `0x400000`)、`0x3538f0`(mask `0x800000`)、
   `0xec3b00`(mask `0x40000`)、`0xd3b4d0`(mask `0x10`/`0x20`)。
   它们决定那四支到底落在谁的 `+0x1370` / vtable `+0x58` 上。
3. **20 个 mask 值里有几个真的会在 4.4.4 里出现,一个都不知道**;零 live 读数。

---

## §9 `join_alliance` 与联邦成员数组:push 在哪一条指令

(收 §6.5 第 3 条。)

### §9.1 成员容器:基址 `+0x90`,数据 `+0x98`,条数 `+0xa4`

`[fed+0x98]`(数据)与 `[fed+0xa4]`(条数)是 §4.6 读侧用过的两格。把**写侧**的同族代码读出来,
三格的从属关系就定了 —— `+0x98`/`+0xa4` 是**容器内部**,容器基址在 `+0x90`:

```text
$ python3 scripts/disrva.py 0x6b4240 --len=0x1e0        ; 摘录
  006b4240  mov     qword ptr [rsp + 0x10], rbx
  ...
  006b4260  mov     rbp, rdx                                 ; 2nd arg = 本国
  006b4263  mov     r12, rcx                                 ; 1st arg = 联邦对象
  ...
  006b428c  movsxd  rax, dword ptr [r12 + 0xa4]              ; ★ 成员条数
  006b4294  test    eax, eax
  006b4296  jle     0x1406b42ce
  006b4298  mov     r8d, dword ptr [rbp + 0x20]               ; 本国 id
  006b429c  mov     r9, rax
  006b429f  mov     ecx, r13d
  006b42a2  mov     rax, qword ptr [r12 + 0x98]               ; ★ 成员数组(数据指针)
  006b42b0  cmp     dword ptr [rax], r8d                      ; 已经在成员表里?
  006b42b3  je      0x1406b42c5
  006b42b5  inc     edx
  006b42b7  inc     ecx
  006b42ba  add     rax, 4
  006b42be  cmp     rcx, r9
  006b42c1  jl      0x1406b42b0
  006b42c3  jmp     0x1406b42ce  ; -> 0x6b42ce
  006b42c5  cmp     edx, -1
  006b42c8  jne     0x1406b4af2                              ; 已是成员 → 直接返回
  ...
  006b43eb  mov     edx, dword ptr [r12 + 8]                  ; 联邦 id(表项 id 在 +8)
  006b43f0  mov     rcx, rbp                                  ; 本国
  006b43f3  call    0x1407562a0  ; -> 0x7562a0               ; ★ SetFederation(本国, 联邦 id)
  006b43f8  mov     eax, dword ptr [rbp + 0x20]               ; 本国 id
  006b43fb  mov     dword ptr [rsp + 0x60], eax
  006b43ff  lea     rdx, [rsp + 0x60]
  006b4404  lea     rcx, [r12 + 0x90]                         ; ★ 容器基址 = fed + 0x90
  006b440c  call    0x1402a4990  ; -> 0x2a4990               ; ★★ push(本国 id)
  006b4411  mov     rdx, qword ptr [rip + 0x2bacbc0]  ; -> 0x3260fd8
```

(`0x6b4af2` 是本函数的尾声:`mov rbx,[rsp+0x68] … ret`,即「已是成员」时的提前返回。)

`0x2a4990` 本身是**向量 append**,把容器的内部布局钉死:

```text
$ python3 scripts/disrva.py 0x2a4990 --len=0x80
  002a4990  push    rbx
  002a4992  push    r14
  002a4994  push    r15
  002a4996  sub     rsp, 0x20
  002a499a  movsxd  rbx, dword ptr [rcx + 0x14]               ; ★ 条数
  002a499e  mov     r15, rdx
  002a49a1  mov     eax, dword ptr [rcx + 0x10]               ; ★ 容量
  002a49a4  mov     r14, rcx
  002a49a7  cmp     ebx, eax
  002a49a9  jne     0x1402a4a7a
  ...
  002a49f1  call    0x14218525c  ; -> 0x218525c               ; 扩容
  002a49f6  mov     ecx, dword ptr [r15]                      ; ★ 取要压入的 dword
  002a49f9  lea     r8, [rbx*4]
  002a4a04  mov     rdi, rbx
  002a4a07  mov     dword ptr [rax + rbx*4], ecx              ; ★★ 写值
  002a4a0a  mov     rcx, rax
```

```text
$ python3 scripts/disrva.py 0x2a4a0a --len=0x60
  002a4a0a  mov     rcx, rax
  002a4a0d  mov     rdx, qword ptr [r14 + 8]                  ; ★ 数据指针在 +8
  002a4a11  call    0x142187ac0  ; -> 0x2187ac0
  002a4a16  mov     r9, qword ptr [r14 + 8]
  ...
  002a4a3a  mov     ebx, dword ptr [r14 + 0x14]               ; ★ 条数在 +0x14
  002a4a3e  mov     rcx, r14
  002a4a41  mov     rax, qword ptr [r14]
  002a4a44  inc     ebx
  002a4a46  mov     dword ptr [r14 + 0x14], 0
  002a4a4e  call    qword ptr [rax + 0x18]
  002a4a51  lea     rax, [rsi + rdi*4]
  002a4a55  mov     qword ptr [r14 + 8], rsi                   ; ★ 回填数据指针
  ...
  002a4a63  mov     dword ptr [r14 + 0x10], ebp               ; ★ 回填容量(+0x10)
```

**答案(三条,逐条对应问题):**

1. **哪条指令**:`0x6b440c call 0x1402a4990`,实参 `rcx = 联邦对象 + 0x90`(容器基址)、
   `rdx = &本国 id`;真正的写值在 `0x2a4a07 mov dword ptr [rax + rbx*4], ecx`。
2. **写的是 `[联邦对象+0x98]` 数组还是别的**:**写的是容器 `[联邦+0x90]`**;
   `[联邦+0x98]` 是这个容器的**数据指针**,`[联邦+0xa4]` 是它的**条数** ——
   即「`+0x98`/`+0xa4` 是对的,但它们是容器内部,不是容器本身」。容器基址 = `+0x90`,
   数据 = 基址 `+0x8`,容量 = 基址 `+0x10`,条数 = 基址 `+0x14`。
3. **长度字段是 `+0xa4` 还是别的**:**`+0xa4`**(容器基址 `+0x14`),与 §4.6 读侧用的同一格。

### §9.2 反向指针:全 `.text` 里唯一的 dword 写点

```text
$ python3 scripts/scratch/2026-11_transitability/field_xrefs.py 0x1e88 --width dword --writes-only --limit 10
# module /var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe
# .text bytes=37291792 pdata funcs=130615

## [reg+0x1e88]  width=dword hits=1 writes=1
  0x7563db  W  mov dword ptr [rbp + 0x1e88], ebx   (in func 0x7562a0)
```

> 地址口径提醒:`field_xrefs.py` 打的是 **disp32 字节的地址**,不是指令首地址 ——
> 同一条指令在 `disrva.py` 里是 `0x7563d9`(见下)。本卷 §2.4 那张 `[+0x1370]` 表
> (`0x8c2c6d` 那行)用的是同一个口径,两处相差 2 字节,指的是**同一条指令**。

`0x7562a0(country, fed_id)` 就是 §4.6 里 `[country+0x1e88]` 的写侧:

```text
$ python3 scripts/disrva.py 0x7562a0 --len=0x40
  007562a0  mov     qword ptr [rsp + 8], rbx
  007562a5  mov     qword ptr [rsp + 0x10], rbp
  007562aa  mov     qword ptr [rsp + 0x18], rsi
  007562af  push    rdi
  007562b0  push    r14
  007562b2  push    r15
  007562b4  sub     rsp, 0x30
  007562b8  mov     ebx, edx                                  ; 新联邦 id
  007562ba  mov     rbp, rcx                                 ; 本国
  007562bd  cmp     edx, dword ptr [rcx + 0x1e88]            ; 没变就返回
  007562c3  je      0x14075641d
  007562c9  mov     rdx, qword ptr [rip + 0x2b0ad48]  ; -> 0x3261018   ; 联邦对象表
  007562d0  test    rdx, rdx
  007562d3  je      0x1407562f9
  007562d5  mov     eax, ebx
  007562d7  and     eax, 0xffffff
  007562dc  cmp     eax, dword ptr [rdx + 0x20]
  007562df  jae     0x1407562f9
  007562e1  mov     ecx, eax
  007562e3  add     ecx, ecx
  007562e6  mov     rax, qword ptr [rdx + 0x18]
  007562ea  mov     rsi, qword ptr [rax + rcx*8 + 8]         ; 联邦对象
  007562ef  test    rsi, rsi
  007562f2  je      0x1407562f9
  007562f4  cmp     dword ptr [rsi + 8], ebx
  007562f7  je      0x140756300
  007562f9  mov     rsi, qword ptr [rip + 0x2b099f0]  ; -> 0x325fcf0   ; 空联邦
```

```text
$ python3 scripts/disrva.py 0x756300 --len=0x40
  00756300  mov     rax, qword ptr [rsi]
  00756303  mov     rcx, rsi
  00756306  call    qword ptr [rax + 8]                       ; 联邦有效?
  00756309  test    al, al
  0075630b  je      0x14075631d
  0075630d  lea     rdx, [rsi + 0x28]
  00756311  lea     rcx, [rbp + 0x1e30]
  00756318  call    0x14030f5f0  ; -> 0x30f5f0              ; 联邦的名字/标签 → 本国 +0x1e30
  0075631d  cmp     qword ptr [rip + 0x2b0a88b], 0  ; -> 0x3260bb0
  00756325  je      0x1407563cd
```

```text
$ python3 scripts/disrva.py 0x7563c6 --len=0x30
  007563c6  mov     byte ptr [rip + 0x22165d3], r15b  ; -> 0x296c9a0
  007563cd  lea     rcx, [rbp + 0x1bc8]
  007563d4  call    0x140213300  ; -> 0x213300
  007563d9  mov     dword ptr [rbp + 0x1e88], ebx            ; ★★ 本国 +0x1e88 = 联邦 id
  007563df  mov     rax, qword ptr [rsi]
  007563e2  mov     rcx, rsi
  007563e5  call    qword ptr [rax + 8]
```

### §9.3 `join_alliance` 自己做了什么 —— push **不在它体内**,但它**够得到**

`join_alliance` 的执行体是 `0x18307e0`(§1.3 的 slot[9])。它对联邦对象的最后一处写是:

```text
$ python3 scripts/disrva.py 0x1830be4 --len=0x70
  01830be4  mov     rdx, qword ptr [rip + 0x1a3042d]  ; -> 0x3261018   ; 联邦对象表
  01830beb  test    rdx, rdx
  01830bee  je      0x141830c1d
  01830bf0  mov     r8d, dword ptr [rdi + 0x1e88]                    ; ★ 参数国的 +0x1e88
  01830bf7  mov     eax, r8d
  01830bfa  and     eax, 0xffffff
  01830bff  cmp     eax, dword ptr [rdx + 0x20]
  01830c02  jae     0x141830c1d
  01830c04  mov     ecx, eax
  01830c06  add     ecx, ecx
  01830c09  mov     rax, qword ptr [rdx + 0x18]
  01830c0d  mov     rbx, qword ptr [rax + rcx*8 + 8]                 ; 联邦对象
  01830c12  test    rbx, rbx
  01830c15  je      0x141830c1d
  01830c17  cmp     dword ptr [rbx + 8], r8d
  01830c1b  je      0x141830c24
  01830c1d  mov     rbx, qword ptr [rip + 0x1a2f0cc]  ; -> 0x325fcf0
  01830c24  cmp     qword ptr [rsp + 0x58], 0
  01830c2a  jne     0x141830c32
  01830c2c  cmp     dword ptr [rbp - 0x7c], 0
  01830c30  je      0x141830c4d
  01830c32  mov     rax, qword ptr [rbx]
  01830c35  mov     rcx, rbx
  01830c38  call    qword ptr [rax + 8]                             ; 联邦有效?
  01830c3b  test    al, al
  01830c3d  je      0x141830c4d
  01830c3f  lea     rdx, [rsp + 0x30]                              ; 消息文本
  01830c44  mov     rcx, rbx                                      ; 联邦对象
  01830c47  call    0x1406b4b10  ; -> 0x6b4b10                     ; ★ effect 的最后一处联邦写
```

`0x6b4b10` 写的是 **`[联邦+0x28]`** 与 **`[联邦+0x1f8]`(一张哈希表)**,不是成员数组:

```text
$ python3 scripts/disrva.py 0x6b4b10 --len=0x30
  006b4b10  mov     rax, rsp
  006b4b13  mov     qword ptr [rax + 0x10], rbx
  006b4b17  mov     qword ptr [rax + 0x18], rbp
  006b4b1b  mov     qword ptr [rax + 0x20], rsi
  006b4b1f  push    rdi
  006b4b20  sub     rsp, 0xc0
  006b4b27  movaps  xmmword ptr [rax - 0x18], xmm6
  006b4b2b  movaps  xmmword ptr [rax - 0x28], xmm7
  006b4b2f  movaps  xmmword ptr [rax - 0x38], xmm8
  006b4b34  mov     rsi, rcx                                  ; 联邦对象
  006b4b37  add     rcx, 0x28
  006b4b3b  call    0x14030f5f0  ; -> 0x30f5f0              ; 把消息拷进 [联邦+0x28]
```

```text
$ python3 scripts/disrva.py 0x6b4c60 --len=0x30
  006b4c6c  mov     eax, dword ptr [rdi]
  006b4c6e  mov     rcx, rdi
  006b4c71  call    qword ptr [rax + 8]
  006b4c74  mov     rbx, rax
  006b4c77  mov     rcx, qword ptr [rsi + 0x1f8]              ; ★ 哈希表在 [联邦+0x1f8]
  006b4c7e  mov     rdx, qword ptr [rcx]
  006b4c81  call    qword ptr [rdx]                           ; 插入
  006b4c83  mov     qword ptr [rsi + 0x1f8], rbx              ; ★★ 写 [联邦+0x1f8]
```

```text
$ python3 scripts/find_refs.py 0x7562a0 0x6b4b10
stellaris.exe  targets: 0x7562a0, 0x6b4b10
scanning .text (0x2390800 bytes) ...

== 0x7562a0: 2 references ==
  .text 0x6b43f3: call 0x1407562a0
  .text 0x6b4ecc: call 0x1407562a0

== 0x6b4b10: 6 references ==
  .text 0x6b3f52: call 0x1406b4b10
  .text 0x704954: jmp 0x1406b4b10
  .text 0xa0b45a: call 0x1406b4b10
  .text 0xa1100c: call 0x1406b4b10
  .text 0x1824556: call 0x1406b4b10
  .text 0x1830c47: call 0x1406b4b10
```

`0x6b4b10` 的 6 个调用点里含 `0x1830c47`(= `join_alliance`);`0x7562a0` 的 2 个调用点
**都不在 `join_alliance` 体内**。而成员数组的 push(`0x6b440c`)在
`0x6b4240..0x6b4b0f` 这个大函数里(`.pdata` 边界),`join_alliance` 不直接调它。

`0x6b4240`(真正做加入的那一支)的引用也只有三个,其中一个在它自己体内:

```text
$ python3 scripts/find_refs.py 0x6b4240
stellaris.exe  targets: 0x6b4240
scanning .text (0x2390800 bytes) ...

== 0x6b4240: 3 references ==
  .text 0x6b45e4: call 0x1406b4240
  .text 0xa0b36f: call 0x1406b4240
  .text 0xa0ba6b: call 0x1406b4240
```

三个地址里 `0x6b45e4` 落在 `0x6b4240..0x6b4b0f` 之内(函数内调用),
`0xa0b36f` / `0xa0ba6b` 落在 `0xa0aec0..0xa0babc`(另一个函数,`.pdata` 边界)。
`0xa0b36f` 那一次传的第三参 `r8d = 0`(`xor r8d, r8d`),`0xa0ba6b` 那一次传 `r8b = 1`。

而 `0xa0aec0` 的**唯一**调用方就在 `join_alliance` 体内 —— **链闭合了**:

```text
$ python3 scripts/find_refs.py 0xa0aec0
stellaris.exe  targets: 0xa0aec0
scanning .text (0x2390800 bytes) ...

== 0xa0aec0: 1 references ==
  .text 0x1830bd2: call 0x140a0aec0
```

```text
$ python3 scripts/disrva.py 0x1830b40 --len=0xa0
  01830b40  mov     al, 0x41
  01830b42  mov     eax, dword ptr [rsi + 0x20]
  01830b45  mov     dword ptr [rbp - 0x4c], eax
  01830b48  mov     rax, qword ptr [rip + 0x1a2e841]  ; -> 0x325f390
  01830b4f  cmp     rdi, rax
  01830b52  jne     0x141830ba5
  01830b54  cmp     r14, rax
  01830b57  jne     0x141830ba5
  01830b59  mov     rax, qword ptr [rip + 0x1a2df08]  ; -> 0x325ea68
  01830b60  cmp     dword ptr [rax + 0x5c], 0
  01830b64  jne     0x141830b9c
  01830b66  lea     rax, [rip + 0xccb893]  ; -> 0x24fc400
  01830b6d  mov     qword ptr [rsp + 0x20], rax
  01830b72  mov     dword ptr [rsp + 0x28], 0x13c
  01830b7a  mov     dword ptr [rsp + 0x2c], 0x1000
  01830b82  lea     rdx, [rip + 0xccb8ef]  ; -> 0x24fc478
  01830b89  lea     rcx, [rsp + 0x20]
  01830b8e  call    0x141c91c30  ; -> 0x1c91c30
  01830b93  mov     rax, qword ptr [rip + 0x1a2f126]  ; -> 0x325fcc0
  01830b9a  jmp     0x141830bb0  ; -> 0x1830bb0
  01830b9c  mov     rax, qword ptr [rax + 0x50]
  01830ba0  mov     rax, qword ptr [rax]
  01830ba3  jmp     0x141830bb0  ; -> 0x1830bb0
  01830ba5  mov     rdx, r14
  01830ba8  mov     rcx, rdi
  01830bab  call    0x1405814d0  ; -> 0x5814d0
  01830bb0  mov     qword ptr [rbp + 0x40], rax
  01830bb4  xor     r8d, r8d
  01830bb7  xor     edx, edx
  01830bb9  lea     rcx, [rbp - 0x70]                          ; ★ 本国句柄
  01830bbd  call    0x140a0c970  ; -> 0xa0c970                  ; 「能不能加入?」判定
  01830bc2  test    al, al
  01830bc4  jne     0x141830bce
  01830bc6  cmp     byte ptr [rsi + 0x290], al
  01830bcc  je      0x141830bd7
  01830bce  lea     rcx, [rbp - 0x70]
  01830bd2  call    0x140a0aec0  ; -> 0xa0aec0                  ; ★ 加入
  01830bd7  mov     rax, qword ptr [rbx]
  01830bda  mov     rcx, rbx
  01830bdd  call    qword ptr [rax + 8]
```

`rbp-0x70` 那个句柄是**国家对象**:`0xa0aec0` 开头读 `[rcx+0x20]` 再经国家表
`0x3260fd8` 换成国家对象(§2.5 记的 id 位 `+0x20`)。

⇒ **完整链:
`join_alliance`(0x18307e0)→ `0x1830bd2 call 0xa0aec0` → `0xa0b36f`/`0xa0ba6b call 0x6b4240`
→ `0x6b43f3 call 0x7562a0`(写 `[country+0x1e88]`)+ `0x6b440c`(push 进 `[fed+0x90]`)。**

`join_alliance` 自己读的两处联邦字段是:`0x1830985` 读 scope 国家的 `[+0x1e88]`
(它现在属于哪个联邦),`0x1830bf0` 读**参数**国家的 `[+0x1e88]` —— 后者正是被交给
`0x6b4b10` 的那个联邦对象。

### §9.4 §9 的判决

```text
结论: 联邦成员数组的 push 是 `0x6b440c call 0x1402a4990(rcx = [联邦+0x90], rdx = &本国 id)`;
      容器基址 = 联邦对象 + 0x90,数据 = +0x98,容量 = +0xa0,条数 = +0xa4(与 §4.6 读侧同一格);
      本国 → 联邦的反向指针写点是 `0x7563d9 mov dword ptr [rbp+0x1e88], ebx`(全 .text 唯一 dword 写点)。
      这两条都在 `0x6b4240` 这一个函数里;`join_alliance` **不直接 push**,但它**够得到**:
      `0x1830bd2` 调 `0xa0aec0`(该函数唯一调用方),`0xa0aec0` 调 `0x6b4240` ⇒ 链闭合。
      `join_alliance` 对联邦的**直接**写只有一处:`0x6b4b10` → `[联邦+0x28]` + `[联邦+0x1f8]`(哈希表)。
      命令: disrva.py 0x6b4240 --len=0x1e0 / 0x2a4990 --len=0x80 / 0x2a4a0a --len=0x60
           disrva.py 0x7562a0 --len=0x40 / 0x756300 --len=0x40 / 0x7563c6 --len=0x30
           disrva.py 0x1830b40 --len=0xa0 / 0x1830be4 --len=0x70
           disrva.py 0x6b4b10 --len=0x30 / 0x6b4c60 --len=0x30 / 0xa0c970 --len=0x40
           find_refs.py 0x7562a0 0x6b4b10 / find_refs.py 0x6b4240 / find_refs.py 0xa0aec0
           field_xrefs.py 0x1e88 --width dword --writes-only
      档: 静态推断(未验证)
不能说的: ① `0xa0aec0` 体内有**两条** `0x6b4240` 调用点(`0xa0b36f` 第三参 `r8d=0`、
          `0xa0ba6b` 第三参 `r8b=1`),两条都通向同一个 push;哪一条在实机上执行、
          第三参(疑似「是否公告」)的语义,以及 `0xa0c970` 那条「能不能加入」判定的真值条件,
          都未观测;
          ② `[联邦+0x90]` 容器语义(成员 id 向量)只由读侧与这一次 push 交叉确定,没有独立命名;
          ③ §4.7 那句「联邦类型对象 +0x100」**要改口**:`0x3947f0` 的返回值与本节的联邦对象
          (`0x3261018` 表项,id 在 `+0x8`)**很可能**是同一个类,但本卷没有独立证明 ⇒
          「联邦类型(federation_type)」这个叫法仍是 `未观测`,见 §9.5;
          ④ 零 live 读数。
下一发升级条件: N5(§6.2)不变;追加一条字据: 同一发里读两个同联邦国家的 `[country+0x1e88]`
          (期望相等)与联邦对象的 `[fed+0x98]` 数组(期望含这两个国家的 id,且 `[fed+0xa4]` = 数组长度)。
```

### §9.5 §4.8 / §4.7 的两处要改口(不改写旧节,在这里记账)

1. **§4.8 联邦行的「写侧来源」** 写的是「联邦类型对象 `+0x100`(`0x183090b`)」。
   本节读到的写侧是:`[country+0x1e88]`(反向指针)+ `[fed+0x90]` 容器(成员 id 向量)。
   `0x183090b` 的 `mov r8d, dword ptr [rbx + 0x100]` 里 `rbx = 0x3947f0(...)` 的返回值 ——
   本节证明 `[fed+0x100]` 这个偏移出现在**联邦对象**上,但 `0x3947f0` 的返回值**是不是**
   联邦对象,本卷**没有**独立证明 ⇒「联邦类型」这个类名仍是 `未观测`。
2. **§4.6 读侧的「成员数组 `+0x98` / 条数 `+0xa4`」** 现在多了一条写侧印证
   (§9.1 的 `0x6b440c` / `0x2a4a07`),从「只有读点」变成「读点 + 写点同格」。
