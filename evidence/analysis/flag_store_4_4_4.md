# Stellaris 4.4.4 — star flag 存储再定位（静态）

**日期**:2026-11-08 **授权级别**:离线(只读本地 `stellaris.exe` 4.4.4 拷贝;不启动游戏、
不注入、不调用 `just win` / `session_bridge.py` / `c2_*` / 任何 `C:/temp` 的东西)。
**计划**:`docs/superpowers/plans/2026-11-08-flag-store-rederivation.md`。
**上游读数**:`evidence/logs/runtime_js_p2_1b_flags_4_4_4.log`(两发实机判负)、
`evidence/analysis/save_flag_storage_4_4_4.md`(存档 `flags=` 是 `名字=时间戳`)。

本卷只补静态面。**Task C(实机判别)未执行**;文件名 `flag_store_4_4_4.md`,
一次性脚本在 `scripts/scratch/2026-11_flag_store/`(复现命令见该目录 README)。

判据等级沿用 A1 卷的口径:
`pinned` = 每一格都从字节读出;`static_inference` = 由两条以上官方 body 互证但没有
一条该 keyword 自己的执行体被读到;`unresolved` = 没有可安全调用的官方路径;
`refuted` = 有读数与断言直接冲突。

---

## 0. 结论先行(映射表在 §4)

**A1 的错不是"容器错了",而是"键空间错了"。**

重新读出来的链路是:

```
flag 名字串(std::string)
   ├─ 0x1BCF030 : 查/插 [0x326D110] 那张 0x40 步长的 名→u16 表,分配新 id 时
   │              从 [0x326D118] 取号;名字副本 append 进 [0x2A00DE0] 那张 0x30 步长的 vector
   ↓  u16 "flag id"(**不是** lexer token id)
[obj+0xC0]  (effect 侧 set_star_flag 对象) / [obj+0x220] (trigger 侧 has_star_flag 对象)
   ↓
0x1BCE180(container, flag_id, date_ptr, 0xFFFFFFFF)   ← 写
0x397490(scope) → 系统对象 +0x5F8                      ← container 的出处
container: { +0x10 = u16 id 数组, +0x1C = 计数 }
   ↓
官方 has_star_flag 的读体(0x1AA6AE0)走同一个 +0x1C/+0x10 线性扫描,
并在命中时从 container 的 +0x40 取那个 **u32 时间戳**
```

三条判据(计划 Task 3 Step 3)的落点:

1. **同一个成员偏移**:两侧都是 `scope → +0x5F8`(`0x397490` 的 mask 0x80 分支与
   `0x1AA6460` 的 `lea rax,[rbx+0x5f8]` 同值)。**中**。
2. **同一族 helper**:两侧都对**同一张** `[0x326D110]` 名→u16 表做"哈希+探测",
   插入走同一个 `0x1BCF030`。读侧 `0x1AA5D10` 与写侧 `0x180F590` 是逐指令同形的
   两个副本(0x2A2 字节、同一序列)。**中**。
3. **形状与存档 `flags=` 一致**:container = `u16 id[]` + 并行 `u32[]`(时间戳)。
   flag id 在 `[0x2A00DE0]` 那张 vector 里能反查回名字串 ⇒ 序列化成
   `名字 = 时间戳`。**中**(反查表结构 pinned,序列化函数本身未读)。

**⇒ 判词:`same_store`。** 但键**不是** A1 假设的 lexer token id
(`0x1D13270` / `0x37347A0` 那套),而是**另一张独立的 flag 名表**
(`0x326D110` / `0x2A00DE0` / `0x1BCF030`)。A1 拿 token id 去写 / 去读,
**两套 id 空间不同**,写进去的 id 和官方脚本解析出来的 id 永远不相等 ——
这与两发实机的三条负读数("写返回 ok、自己读回 true、官方 0 命中、存档没有")
全部吻合,**不需要**假设"容器选错了"。

---

## 1. 旧链的证伪登记(计划 Task 1)

### 1.1 `set_star_flag` 的 TSV 行(逐字)

```console
$ grep -P '\tset_star_flag\t' evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv
0x23ac600	108	0xf64e0	0x33746e8	10139	set_star_flag	0x2610e80	0x34c090	0x261ca50	Sets an arbitrarily-named flag on the scoped system	0x3aef60
```

列序(`scripts/thunkarrays.py` 的输出约定,表头在文件第一行):
`array_rva · index · thunk_rva · db_global_rva · token_id · keywords · class_info ·
deleter(全表共享 0x34c090)· docstring · doc_first_line · insert_fn_rva`。

同卷 `has_star_flag`:

```console
$ grep -P '\thas_star_flag\t' evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv
0x23af628	75	0x1184e0	0x32611c8	18125	has_star_flag	0x269f1d8	0x34c090	0x26a5a90	Checks if the solar system has a specific flag	0x348150
```

### 1.2 `class_info` → `create`(逐字)

```console
$ python3 scripts/cinfo.py /tmp/cinfo.tsv && grep -i '0x2610e80\|0x269f1d8' /tmp/cinfo.tsv
0x2610e80	0x34c090	0x1895620	False		0x298	operator_new 0x2188170 0x1840700	0x26049b0 0x25f2b08
0x269f1d8	0x34c090	0x1b1ff60	False		0x3f8	operator_new 0x2188170 0x1af63b0	0x268cf48
```

`cinfo.py` 的列序:`array_rva index thunk_rva db_global_rva token_id keywords field0_rva
field0_target field8_doc_rva doc_first_line insert_fn_rva`。`field0_rva` 就是
`class_info`,它的第二个 qword 才是 `create`。

⇒ `set_star_flag`:new `0x298`,发布 vptr `0x26049b0`(primary)+ `0x25f2b08`(secondary)。
⇒ `has_star_flag`:new `0x3f8`,发布 vptr `0x268cf48`。
**这与 A1 卷 §2.1 / §3.1 的数字一致** —— 旧链在这两格上是**对的**。

### 1.3 旧链 body `0x180F8E0`:它消费 u16,**没有**名字串比较(逐字)

```console
$ python3 scripts/disrva.py 0x180F8E0 --len=0xA0
  0180f8e0  mov     qword ptr [rsp + 0x10], rbx
  0180f8e5  mov     qword ptr [rsp + 0x18], rsi
  0180f8ea  push    rdi
  0180f8eb  sub     rsp, 0x30
  0180f8ef  cmp     qword ptr [rcx + 0xe8], 0
  0180f8f7  mov     rsi, rdx
  0180f8fa  mov     rdi, rcx
  0180f8fd  je      0x14180f927
  0180f8ff  lea     rax, [rcx + 0x28]
  0180f903  lea     r9, [rcx + 0xc8]
  0180f90a  mov     qword ptr [rsp + 0x20], rax
  0180f90f  lea     r8, [rcx + 0xf8]
  0180f916  lea     rcx, [rsp + 0x40]
  0180f91b  call    0x140a56800  ; -> 0xa56800
  0180f920  movzx   ebx, word ptr [rsp + 0x40]
  0180f925  jmp     0x14180f92e  ; -> 0x180f92e
  0180f927  movzx   ebx, word ptr [rcx + 0xc0]
  0180f92e  mov     rax, qword ptr [rdi]
  0180f931  mov     rdx, rsi
  0180f934  mov     rcx, rdi
  0180f937  call    qword ptr [rax + 0xe0]
  0180f93d  mov     r8, qword ptr [rip + 0x1a5126c]  ; -> 0x3260bb0
  0180f944  mov     r9d, 0xffffffff
  0180f94a  add     r8, 0xc0
  0180f951  mov     dword ptr [rsp + 0x20], 0
  0180f959  movzx   edx, bx
  0180f95c  mov     rcx, rax
  0180f95f  call    0x141bce180  ; -> 0x1bce180
```

`movzx ebx, word ptr [rcx + 0xc0]` —— **body 自己消费的是 u16**,确实是 token/id
而不是名字串。这一点计划 Step 3 的预期成立。

**但这条推论不能用来否定整条链**:名字串的消费发生在**同族的 parse slot**
(`0x180F590`,见 §2.2),它把 AST 里的 FLAGNAME 串解析成 u16 存进 `[obj+0xC0]`,
body 只是取用。计划 Review Focus #1 的"只读 id 的 body 不可能是写手"这条判据,
**对 body 成立、对整个 keyword 不成立** —— 这正是 A1 卷被判负后最容易走偏的一步。

### 1.4 证伪登记表

| 断言 | 等级 | 依据 |
|---|---|---|
| `set_star_flag` 的 `class_info` = `0x2610e80`,docstring = `0x261ca50` | **pinned** | §1.1 TSV 行 |
| `create` = `0x1895620`,new `0x298`,vptr `0x26049b0`/`0x25f2b08` | **pinned** | §1.2 cinfo + A1 §2.1 的逐字节 |
| `has_star_flag` 的 `create` = `0x1b1ff60`,new `0x3f8`,vptr `0x268cf48` | **pinned** | §1.2 cinfo |
| body `0x180F8E0` 消费 u16 (`[obj+0xC0]`),不做名字比较 | **pinned** | §1.3 |
| 「body 只读 u16 ⇒ 它不可能是真正的写手」 | **refuted** | §1.3 + §2.2:名字→id 的转换在同族 parse slot `0x180F590`,body 只取用;A1 判负的原因是**id 空间**(§3),不是 body 选错 |
| `+0x5F8` = star flag 存储 | **pinned**(由 §3 升格) | §3.1 写侧 `0x397490` mask 0x80 分支 → `0x393970+0x5f8`;**§3.2 读侧 `0x1AA6460`(`has_star_flag` 自己的 vtable slot +0xF0,错误串点名该 keyword)直接 `lea rax,[rbx+0x5f8]`** |
| vtable `0x26049b0` 的 slot[9] `+0x48` = `0x180F8E0` | **pinned** | `vtable.py 0x26049B0` |
| flag id 就是 lexer token id(`0x1D13270`) | **refuted** | §3.3:两侧解析都走 `0x326D110`,分配号来自 `0x326D118`,与 token DB(`0x37347A0`)不同对象 |

### 1.5 复现(§1)

```bash
grep -P '\tset_star_flag\t' evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv
grep -P '\thas_star_flag\t' evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv
python3 scripts/cinfo.py /tmp/cinfo.tsv && grep -i '0x2610e80\|0x269f1d8' /tmp/cinfo.tsv
python3 scripts/disrva.py 0x180F8E0 --len=0xA0
python3 scripts/vtable.py 0x26049B0 --slots 24
python3 scripts/vtable.py 0x268CF48 --slots 40
```

---

## 2. effect 侧:消费名字的写手(计划 Task 2)

### 2.1 vtable `0x26049b0` 的槽位读数(逐字,节选)

```console
$ python3 scripts/vtable.py 0x26049B0 --slots 24
  [0x2] +0x10 -> 3b01a0  bounds 3b01a0..3b0f7e
          str 24ea600 "C:\mnt\gsg\stellaris\augustus\augustus\source\effect.cpp"
          str 24ea640 "An effect with id = "%s" already exist. id has to be unique"
  [0x3] +0x18 -> 180f590  bounds 180f590..180f832      <-- parse(消费名字)
  [0x6] +0x30 -> 180f980  bounds 180f980..180fc54
          str 261a298 "SET_FLAG"
          str 261a288 "FLAGNAME"
  [0x9] +0x48 -> 180f8e0  bounds 180f8e0..180f974      <-- body(A1 打过的那个)
  [0xe] +0x70 -> 3b1330  bounds 3b1330..3b1413         <-- 递归 parse(基类)
```

**关键**:`+0x18` = `0x180F590` 是**同一个对象的 parse slot**,它才是消费
`FLAGNAME` 字符串的地方;`+0x48` 只是取 parse 结果。`+0x30` = `0x180F980`
是"把 id 渲染回 `SET_FLAG`/`FLAGNAME` 文本"的反查(*读*方向,不是写)。

### 2.2 `0x180F590` = 名字串 → u16 id(逐字)

```console
$ python3 scripts/disrva.py 0x180F590 --len=0x2A2      # 节选,行号为原文
  0180f5b4  mov     rdi, qword ptr [rdx + 0x10]        ; AST 节点的串数据指针
  0180f5dc  mov     rbx, 0xffffffffffffffff
  0180f5e6  inc     r8
  0180f5e9  cmp     byte ptr [rdi + r8], r12b           ; 内联 strlen
  0180f5f6  call    0x14015f770  ; -> 0x15f770          ; 构造 std::string
  0180f616  call    0x140a55db0  ; -> 0xa55db0          ; 解析 "flag@scope" 形式
  0180f6b8  cmp     byte ptr [rax], 0x20                ; 跳过前导空格
  0180f6d4  call    0x141c9e350  ; -> 0x1c9e350          ; 哈希字符串
  0180f6d9  mov     r12, qword ptr [rip + 0x1a5da3c]  ; -> 0x326d11c  (mask)
  0180f6e0  and     eax, r12d
  0180f6e6  shl     rbx, 6                              ; 槽步长 0x40
  0180f6ea  add     rbx, qword ptr [rip + 0x1a5da1f]  ; -> 0x326d110  (桶数组)
  0180f714  cmp     qword ptr [rbx + 0x30], 0x10        ; 桶内串的 SSO 容量门
  0180f733  call    0x142188310  ; -> 0x2188310          ; memcmp
  0180f76b  movzx   eax, word ptr [rbx + 0x38]          ; 命中:取 u16
  ...
  0180f778  movzx   eax, word ptr [rip + 0x1a5d999]  ; -> 0x326d118  未命中:取号
  0180f7b7  call    0x141bcf030  ; -> 0x1bcf030          ; 插入表
  0180f7df  call    0x140158300  ; -> 0x158300           ; 名字 append 进 [0x2A00DE0]
  0180f7fb  mov     word ptr [r15 + 0xc0], ax          ; **写进 [obj+0xC0]**
```

判读,逐条:

* **字符串消费**:`mov rdi,[rdx+0x10]` + 内联 strlen + `0x15F770` 构造 +
  `0x1C9E350` 哈希 + 桶内 `cmp qword [rbx+0x30],0x10`(**MSVC SSO 容量门**)
  ⇒ 这是货真价实的"消费一个 MSVC 形状的名字串"。
* **不是日志文案**:串的来源是 `[rdx+0x10]` = AST 节点(形参),不是 `.rdata` 常量;
  且它的哈希结果直接决定桶地址。
* **id 从哪来**:命中时 `word [rbx+0x38]`;未命中时 `word [0x326D118]`(号数)
  + `0x1BCF030` 插入 + `0x158300` 把名字 append 进 `[0x2A00DE0]`。
  ⇒ **u16 是这张 名→id 表发的号,不是 lexer token id**(见 §3.3)。

### 2.3 三个不同 id 空间的边界(本节的核心读数)

| 全局 | 形状 | 谁在用 | 证据 |
|---|---|---|---|
| `0x326D110` + `0x326D118`(号数)+ `0x326D11C`(mask)+ `0x326D120`/`0x326D124` | 桶步长 **0x40**,桶内 `+0x18` = 串数据、`+0x28` = 长度、`+0x30` = 容量、`+0x38` = **u16 id** | **flag 名 → u16**(本卷的主角) | §2.2;初始化 `0x135E40` 把 `0x326D110` 置为 `0x1BCEFD0()` 的返回值、`0x326D118` 清零 |
| `0x2A00DE0`(+8 数据 / +0x14 计数) | 元素 **0x30**、`+0x10` = 名字串 | flag id → 名字(反查;`0x158300` 追加) | §2.2 的 `0x180f7df`;`0x180F980` 用 `[0x2A00DE8]+id*0x30+0x10` 渲染 |
| `0x37347A0`(token DB,`0x1D12C60` 返回) | `[db+0x70]` 桶步长 **0x30**、`+0x10` = 串、计数 `[db+0x7c]`、`0x1D12CD0` 重建 | **lexer token id**(A1 用的那套,`0x1D13270` 发号) | `python3 scripts/disrva.py 0x1D12C60 --len=0x30` |

三张表**互不相同**:地址不同、元素步长不同(0x30 vs 0x40)、发号器不同
(`0x326D118` vs token DB 内部计数器)。**这就是 A1 判负的根因**:A1 拿
`0x1D13270` 发的 token id 去写 `+0x5F8`,而官方脚本读的时候用的是 flag 表的
u16 id,两者永不相等。

```console
$ python3 scripts/disrva.py 0x1D12C60 --len=0x30
  01d12c60  sub     rsp, 0x28
  01d12c64  mov     edx, 0x14
  01d12c69  mov     rax, qword ptr gs:[0x58]
  01d12c72  mov     rcx, qword ptr [rax]
  01d12c75  mov     eax, dword ptr [rdx + rcx]
  01d12c78  cmp     dword ptr [rip + 0x1a21b12], eax  ; -> 0x3734790
  01d12c7e  jg      0x141d12c8c
  01d12c80  lea     rax, [rip + 0x1a21b19]  ; -> 0x37347a0     <-- token DB 对象
```

### 2.4 时间戳来源(计划 Step 4)

`0x180F8E0` 在调写手前:

```console
  0180f93d  mov     r8, qword ptr [rip + 0x1a5126c]  ; -> 0x3260bb0
  0180f944  mov     r9d, 0xffffffff
  0180f94a  add     r8, 0xc0
```

`0x1BCE180` 里 `r8 → rdi`,然后 `mov eax, dword ptr [rdi]`(`0x1bce213`)——
即**读 `[[0x3260BB0]+0xC0]` 那个 dword**当时间戳,写进 container 的并行 u32 数组
(`[rbx+0x28]`/`[rbx+0x40]`,`0x1bce226..0x1bce23e`)。`r9d = 0xFFFFFFFF` 是
"无到期时间"哨兵。

⇒ **时间戳来源找到了**:`[[0x3260BB0]+0xC0]`(当期 gamestate 的日期 dword)。
这是"写手调用链里有当前日期来源"的正面读数,**不需要降级**。
(`[0x3260BB0]` 与 AGENTS.md 里星连图的 galaxy 全局同址族;本卷不重复论证它是什么。)

### 2.5 写手候选表(Task 2 的产出接口)

| slot | RVA | consumes | 关键证据 | 等级 |
|---|---|---|---|---|
| `+0x18` | `0x180F590` | **string**(FLAGNAME → u16) | §2.2 的 SSO/哈希/memcmp 全序列;`0x158300` 把名字落进反查表 | `pinned` |
| `+0x48` | `0x180F8E0` | **u16**(`[obj+0xC0]`) | §1.3;`+0xE8 != 0` 时先走 `0xA56800` 解析成 u16 再取 | `pinned` |
| `+0x30` | `0x180F980` | u16 → string(**读/渲染**,不是写) | 用 `[0x2A00DE8]+id*0x30+0x10` 取名字,唯一副作用是 `SET_FLAG`/`FLAGNAME` 文案 | `pinned` |

**进 §4 映射表的是 `+0x18`(消费名字)+ `+0x48`(落盘动作)这一对**,
它们同属 `class_info 0x2610e80` → `create 0x1895620` → vtable `0x26049b0` 的
**同一个对象**。

### 2.6 复现(§2)

```bash
python3 scripts/disrva.py 0x180F590 --len=0x2A2
python3 scripts/disrva.py 0x1D12C60 --len=0x30
python3 scripts/disrva.py 0x135E40  --len=0x40
python3 scripts/scratch/2026-11_flag_store/scan_flag_keyword.py --keyword set_star_flag
```

---

## 3. trigger 侧读手 + 读写同源交叉验证(计划 Task 3)

### 3.1 读侧的容器出处:`0x1AA6460`(由它自己的错误串点名)

`has_star_flag` 的 vtable `0x268cf48` 在 `+0xF0` 有一格 `0x1AA6460`,它引用的字符串
是 **`"has_star_flag trigger at %d has Invalid Scope"`** —— 这是官方自己给该
keyword 的命名,判据强度高于任何推断。

```console
$ python3 scripts/vtable.py 0x268CF48 --slots 40
  [0x1e] +0xf0 -> 1aa6460  bounds 1aa6460..1aa64eb
          str 26a5b28 "has_star_flag trigger at %d has Invalid Scope"
  [0x4]  +0x20 -> 1aa5d10  bounds 1aa5d10..1aa5fb2     <-- parse(消费名字)
  [0x5]  +0x28 -> 1a91a80  bounds 1a91a80..1a91ac4     <-- 共用求值基体(§77)
```

```console
$ python3 scripts/disrva.py 0x1AA6460 --len=0x90
  01aa6460  push    rdi
  01aa6462  sub     rsp, 0x30
  01aa6466  cmp     qword ptr [rdx + 8], 0x8000000     ; galaxy scope 特例
  01aa646e  mov     rdi, rcx
  01aa6471  jne     0x141aa6481
  01aa6473  mov     rax, qword ptr [rdx + 0x24]
  01aa6477  add     rax, 0x20
  01aa647b  add     rsp, 0x30
  01aa647f  pop     rdi
  01aa6480  ret                                       ; galaxy: [scope+0x24]+0x20
  01aa6481  mov     rcx, rdx
  01aa6489  call    0x140393970  ; -> 0x393970          ; scope → 系统对象
  ...
  01aa64d4  call    0x141c91c30  ; -> 0x1c91c30          ; 报 Invalid Scope
  01aa64d9  lea     rax, [rbx + 0x5f8]                   ; **container = 系统对象 + 0x5F8**
  01aa64e0  mov     rbx, qword ptr [rsp + 0x40]
  01aa64e5  add     rsp, 0x30
  01aa64e9  pop     rdi
  01aa64ea  ret
```

写侧的容器出处(§1.3 已读):`0x180F8E0` 的 `call [rax+0xE0]` → `0x180F8D0`
(`mov rcx,rdx; jmp 0x397490`),`0x397490` 的 mask `0x80` 分支:

```console
$ python3 scripts/disrva.py 0x397490 --len=0x110
  0039756e  call    0x140393970  ; -> 0x393970
  00397573  add     rax, 0x5f8
  00397579  add     rsp, 0x28
  0039757d  ret
```

⇒ **两侧落到同一个 `scope(0x393970) + 0x5F8`**。判据 1(同成员偏移)**中**。

### 3.2 container 的形状(逐字)

```console
$ python3 scripts/disrva.py 0x1BCE180 --len=0xD0
  01bce180  mov     qword ptr [rsp + 8], rbx
  01bce185  mov     dword ptr [rsp + 0x20], r9d          ; 第 4 参:0xFFFFFFFF 哨兵
  01bce18a  mov     word ptr [rsp + 0x10], dx           ; 第 2 参:flag id (u16)
  01bce194  mov     eax, 0xffff
  01bce199  mov     rdi, r8                            ; 第 3 参:&日期 dword
  01bce19c  mov     rbx, rcx                           ; 第 1 参:container
  01bce19f  cmp     dx, ax
  01bce1a2  je      0x141bce1ff                        ; id == 0xFFFF ⇒ **什么都不做**
  01bce1a4  movsxd  rax, dword ptr [rcx + 0x1c]         ; container+0x1C = 计数
  01bce1af  mov     r8, rax
  01bce1b5  mov     rax, qword ptr [rbx + 0x10]        ; container+0x10 = u16 id 数组
  01bce1c0  cmp     word ptr [rax], dx                 ; 线性扫描,逐 u16 比较
  01bce1cb  add     rax, 2                             ; 元素宽度 2
```

命中分支(`0x1bce20a` 起):`mov r8,[rbx+0x28]` / `mov eax,[rdi]` /
`mov [r8],eax`(`0x1bce226..0x1bce23e`)—— **把那个 dword 写进 `container+0x28`
这张并行 u32 数组**,`r9d = 0xFFFFFFFF` 写进 `container+0x40`。
未命中分支(`0x1bce1d4` 起):`0x1BCEE10`(压 id)+ `0x2A4990`(压值)+ `0x2C0520`。

⇒ container 的实际布局:

| 偏移 | 含义 |
|---|---|
| `+0x10` | **u16 flag id 数组** |
| `+0x1C` | 元素计数(dword) |
| `+0x28` | 并行 u32 数组(写手把日期写这里) |
| `+0x40` | 并行 u32 数组(`0xFFFFFFFF` = 无到期) |

这与存档 `flags = { 名字 = 时间戳 }` **同形**:名字由 flag id 经 §2.2 的
`0x2A00DE0` 反查表还原,时间戳就是 `+0x28` 那一路的 dword。判据 3 **中**。

### 3.3 判据 2:`0x180F590` 与 `0x1AA5D10` 是同一函数的两个副本

这是本卷最硬的一条读数。把两个 parse 体规范化(抹掉地址/栈偏移/注释)后逐条对比:

```
set_star_flag parse instrs: 176   has_star_flag parse instrs: 176
-lea r14, [rcx + 0x28]
+lea r14, [rcx + 0x40]
-lea r8, [r15 + 0xf8]
-lea rdx, [r15 + 0xc8]
+lea r8, [r15 + 0x258]
+lea rdx, [r15 + 0x228]
-mov word ptr [r15 + 0xc0], ax
+mov word ptr [r15 + 0x220], ax
```

**176 条指令,只差 5 条**,且差异全部是**对象自身字段偏移**
(effect 对象用 `+0xC0/+0xC8/+0xF8`,trigger 对象用 `+0x220/+0x228/+0x258`)。
哈希、探测、SSO 容量门、`0x1BCF030` 插入、`0x158300` 落名字、`[0x326D110]` /
`[0x326D118]` / `[0x326D11C]` 三个全局 —— **一个字节都不差**。

```console
$ python3 scripts/scratch/2026-11_flag_store/scan_flag_keyword.py --keyword has_star_flag
# keyword=has_star_flag class_info=0x269f1d8 create=0x1b1ff60 new=0x3f8 vptrs=['0x268cf48']
slot_off	slot_rva	func_rva	func_len	string_reads	id_reads	callees
0x0020	0x268cf68	0x1aa5d10	0x2a2	... 0x1aa5e54:string_hash ... 0x1aa5f5f:name_vector_append	0x1aa5eeb:movzx_word ...	...
```

```console
$ python3 scripts/scratch/2026-11_flag_store/scan_flag_keyword.py --keyword set_star_flag
# keyword=set_star_flag class_info=0x2610e80 create=0x1895620 new=0x298 vptrs=['0x25f2b08', '0x26049b0']
0x0038	0x25f2b40	0x180f590	0x2a2	0x180f5f6:string_assign;...;0x180f7df:name_vector_append	0x180f76b:movzx_word ...	...
```

**同一 `func_len` = `0x2a2`,同一 `string_reads`/`id_reads` 指纹。** 判据 2 **中**。

### 3.4 唯一读 container 的那条 eval 体:`0x1AA6AE0`

`has_star_flag` 的 `+0x20` slot `0x1AA5D10` 只做"名字→id 存进 `[obj+0x220]`"
(它 `mov word [r15+0x220], ax` 后直接 `mov al,1; ret`,不返回谓词)。
真正扫 container 的是同族里偏移 `+0x2A8` 的那一版:

```console
$ python3 scripts/disrva.py 0x1AA6AE0 --len=0x140
  01aa6ae6  cmp     qword ptr [rcx + 0x2d0], 0
  01aa6b2d  movzx   ebx, word ptr [rcx + 0x2a8]      ; 本对象自己的 u16 flag id
  01aa6b37  call    0x140397490  ; -> 0x397490       ; **同一个 scope→container 解析器**
  01aa6b49  movsxd  rax, dword ptr [rax + 0x1c]       ; 计数
  01aa6b51  mov     rcx, qword ptr [r11 + 0x10]      ; u16 数组
  01aa6b58  cmp     word ptr [rcx], bx               ; 线性扫描
  01aa6b5d  inc     r9d
  01aa6b63  add     rcx, 2
  01aa6bbf  mov     rax, qword ptr [r11 + 0x40]      ; **命中后读并行 u32 数组**
  01aa6bc6  mov     r8d, dword ptr [rax + rcx*4]
  01aa6b75  imul    rcx, rax, 0x186a0                ; ×100000(定点)
```

**它走的是同一个 `0x397490`、同一个 `+0x1C`/`+0x10` 布局、同一张 `+0x40`
并行数组** —— 与写手 `0x1BCE180` 逐字段对齐。这坐实了 container 的语义,
也说明 `+0x5F8` 确实是**读写共用的那个 store**。

**边界(必须写)**:`0x1AA6AE0` 在 vtable `0x268ddb8` 族里,"has_star_flag"这个名字
是 `0x1AA6460` 的错误串给的,不是 `0x1AA6AE0` 自己的。所以:
"container 布局与读写同源" = `pinned`;**`has_star_flag` 的那条 `+0x28` 求值槽
(共用基体 `0x1A91A80` 尾跳 `[vptr+0x20]`)在 §77 已读成 `0x1AA5D10`,
而 `0x1AA5D10` 只做 parse/存 id、返回 `al=1`** —— 缺口是"谁来把 `[obj+0x220]`
和 container 比一次"。本卷**没有**读到 `has_star_flag` 自己的比较指令
(候选是 `0x348B60` 那条 `[vptr+0xb8]` → `[vptr+0x18]` 的通用 trigger 求值基体),
所以该格标 `unresolved`(见 §4 的 `eval_body`)。

### 3.5 交叉验证判决:三条判据逐条落点

| 判据 | 读数 | 判词 |
|---|---|---|
| 1. 同一个对象成员偏移 | 写:`0x397490` mask 0x80 → `0x393970(scope)+0x5F8`;读:`0x1AA6460` → `lea rax,[rbx+0x5f8]` | **中** |
| 2. 同一族 map/hash helper | `0x180F590` 与 `0x1AA5D10` 176 条指令只差 5 条字段偏移;同用 `0x1C9E350`/`0x1BCF030`/`0x158300`/`[0x326D110]` | **中** |
| 3. 形状与存档 `flags=` 一致 | container = `u16 id[](+0x10)` + 计数(`+0x1C`) + 并行 u32 日期(`+0x28`/`+0x40`);id 经 `0x2A00DE0` 反查回名字 | **中**(反查表 pinned,序列化函数未读) |

⇒ **判词 `same_store`**(三条全中)。**但键空间是 flag 表,不是 token 表** ——
A1 的失败在这一格,不在容器选择。

### 3.6 复现(§3)

```bash
python3 scripts/disrva.py 0x1AA6460 --len=0x90
python3 scripts/disrva.py 0x397490  --len=0x110
python3 scripts/disrva.py 0x1BCE180 --len=0xD0
python3 scripts/disrva.py 0x1AA6AE0 --len=0x140
python3 scripts/scratch/2026-11_flag_store/scan_flag_keyword.py --keyword has_star_flag
# 176 vs 176 那条 diff:
python3 scripts/scratch/2026-11_flag_store/diff_parse_bodies.py --a 0x180F590 --b 0x1AA5D10
```

---

## 4. 映射表 + falsifier + host 契约(计划 Task 4)

### 4.1 映射表(两行,六个字段;缺字段一律写 `unknown`,不留空)

| keyword | class_info | create | vtable | write_slot | eval_slot | store_offset | consumes |
|---|---|---|---|---|---|---|---|
| `set_star_flag` | `0x2610e80` | `0x1895620` (new `0x298`) | `0x26049b0` (+ secondary `0x25f2b08`) | **`+0x18` = `0x180F590`**(名字→u16)+ **`+0x48` = `0x180F8E0`**(落盘) | n/a(effect) | **`scope(0x393970)+0x5F8`** | **`string`**(`FLAGNAME` → u16 flag id) |
| `has_star_flag` | `0x269f1d8` | `0x1b1ff60` (new `0x3f8`) | `0x268cf48` | n/a(trigger) | **`+0x20` = `0x1AA5D10`**(名字→u16,存 `[obj+0x220]`)+ `+0x28` = `0x1a91a80`(共用基体) | **`scope(0x393970)+0x5F8`** | **`string`** |

机器可读(一行一条,`|` 分隔):

```
set_star_flag | class_info=0x2610e80 | create=0x1895620 | vtable=0x26049b0 | write_slot=0x180f590+0x180f8e0 | store_offset=0x5f8 | consumes=string
has_star_flag | class_info=0x269f1d8 | create=0x1b1ff60 | vtable=0x268cf48 | eval_slot=0x1aa5d10 | store_offset=0x5f8 | consumes=string
```

**`eval_body`(谁把 `[obj+0x220]` 和 container 比一次)**:`unresolved`。
`+0x28` 的共用基体 `0x1A91A80` 尾跳 `[vptr+0x20]` = `0x1AA5D10`,而 `0x1AA5D10`
只做名字→id 并 `mov al,1; ret`;通用 trigger 求值基体候选是 `0x348B60`
(`call [vptr+0xb8]` 后 `call [vptr+0x18]`),**没有读到比较指令本身**。
原因:该槽的真正求值体要么被 `0x349700` 一族代劳(只回 `+0x14` 的 dword),
要么在 `.pdata` 之外内联;本卷的离线预算里没有收口。

### 4.2 键空间(必须与映射表一起读)

```console
$ python3 scripts/disrva.py 0x135E40 --len=0x40    # flag 名表的初始化
  00135e44  call    0x141bcefd0  ; -> 0x1bcefd0        ; 分配桶数组
  00135e58  mov     qword ptr [rip + 0x31372b1], rax  ; -> 0x326d110   (桶基址)
  00135e61  mov     qword ptr [rip + 0x31372b0], rax  ; -> 0x326d118   (号数清零)
  00135e68  mov     byte ptr [rip + 0x31372b2], al   ; -> 0x326d120
```

| 全局 | 作用 |
|---|---|
| `0x326D110` | flag 名→u16 的桶数组基址(步长 `0x40`,id 在 `+0x38`) |
| `0x326D118` | 下一个 flag id(u16) |
| `0x326D11C` | 桶掩码 |
| `0x2A00DE0` | flag id→名字 的 vector(`+8` 数据、`+0x14` 计数、元素 `0x30`、名字在 `+0x10`) |
| `0x1BCF030` | 插入桶表 |
| `0x158300` | 把名字 append 进 `0x2A00DE0` |
| `0x1C9E350` | 字符串哈希 |

**与 token DB(`0x37347A0`,`0x1D13270` 发号)不是同一张表。**

### 4.3 falsifier(至少四条;出现即判本卷映射是错的)

| # | 读数 | 判错的哪一格 |
|---|---|---|
| F1 | 用 `0x180F590`(或让引擎自己解析 `set_star_flag = probe`)写一个 flag 后,**最新存档的 `flags=` 块里不出现 `probe`** | `set_star_flag` 写链(§2)错 —— 要么容器偏移错,要么写的不是 star flag |
| F2 | 官方脚本 `set_star_flag = probe` 之后,**同一进程里读 `[0x393970(scope)+0x5F8]` 的 u16 数组不含该 id**(或用 `0x1BCE180` 的线性扫描找不到) | `store_offset=0x5F8` 错 |
| F3 | `has_star_flag = probe` 在官方脚本里命中,但用 `0x1AA6460` 拿到的 container 扫描**不命中** | 读侧 `0x1AA6460` 不是 `has_star_flag` 的容器出处(§3.1 错) |
| F4 | 写手调用链里**读不到** `[[0x3260BB0]+0xC0]`(或它不是当期日期),或写进 `container+0x28` 的值与存档 `flags=` 右侧的数不相等 | 时间戳那一格(§2.4)错 |
| F5 | 同一个名字在 `[0x326D110]` 表里查到的 u16 **等于** `0x1D13270` 给它的 token id | 键空间判词(§4.2)错 —— 那 A1 的写法本来就该能命中 |
| F6 | `movzx ..., word ptr [obj+0x220]` 在 `has_star_flag` 的求值链上**根本不存在**(即 `+0x220` 不是它的 flag id 字段) | 读侧字段偏移错 |
| F7 | `flags=` 块里的时间戳与 `container+0x28` / `container+0x40` 哪一张对不上(两张都在,写手写 `+0x28`、读体 `0x1AA6AE0` 读 `+0x40`) | container 并行数组的语义(§3.2 / §4.5 第 2 条)错 |

### 4.4 host 契约(**只写形状,不写实现**)

将来 `neo_js_host` 要正确写/读 star flag,调用形状必须是:

**写(`setStarFlag(name)`)**:

1. 名字串放**堆上 NUL 结尾的 char***,长度上限沿用 MSVC SSO 边界 `≤ 15`
   (超过 `0x10` 会让 `cmp qword [rbx+0x30],0x10` 走堆指针分支,语义不变但要求
   调用方保证生命周期;引擎侧是复制进表的,所以只要调用期间有效即可)。
2. **不要**调 `0x1D13270` 拿 id。id 必须由 flag 表发:
   `0x1BCF030(name, hash, ...)` 插入/查找 → `word [bucket+0x38]`。
   等价的官方入口就是 `0x180F590`(它把这一串全做了)。
3. 得到 u16 后写 `[obj+0xC0]`,再调 `0x180F8E0`(或直接用 `0x1BCE180`)。
   `0x1BCE180` 的四个参数:`(container, id, &u32_date, 0xFFFFFFFF)`。
4. **返回值怎么解释**:`0x180F8E0` 没有返回值(`ret` 前不设 `al`);
   成败只能靠"事后扫 container"判定。
5. **失败如何 fail-closed**:`id == 0xFFFF` 时 `0x1BCE180` 直接返回(什么都不做),
   所以 host 侧必须把 `0xFFFF` 当**硬失败**(名字解析失败),不要当成"写成功"。
   §2.2 的 `0x180F7F6`(`mov eax,0xffff`)就是这条的来源。

**读(`hasStarFlag(name)`)**:

1. 同样先用 `0x180F590`/`0x1BCF030` 解析出 u16(**不要**用 token id)。
2. container 用 `0x1AA6460(scope, ...)` 取(它内部 `0x393970` + `+0x5F8`,
   并对 galaxy scope 走 `[scope+0x24]+0x20` 特例);或直接用 `0x397490` 的 mask 0x80 分支。
3. 线性扫 `container+0x10` 的 `u16[container+0x1C]`,比较目标 id。
4. **返回 bool 从哪读**:命中即 true。container 有两张并行 u32 数组:
   `0x1BCE180` 把 `[[0x3260BB0]+0xC0]`(日期)写进 `+0x28`,把 `0xFFFFFFFF`
   (−1,哨兵)写进 `+0x40`(`0x1BCE20F..0x1BCE23E`);而 `0x1AA6AE0` 这个官方样本
   **读的是 `+0x40` 并乘 `0x186A0`**(`0x1AA6BBF..0x1AA6BC6`)。
   两者谁是"存档右侧那个时间戳"**本卷没有收口**(见 §4.5),
   所以 host **不要**现在就把任一张当时间戳硬编码 —— 只读 bool 是安全的。
5. **fail-closed**:container 指针为空 / 计数为 0 / id 为 `0xFFFF` ⇒ 一律返回
   **false**(不要抛,不要回 true)。

### 4.5 仍未收口的断言(诚实清单)

| 断言 | 等级 | 为什么 |
|---|---|---|
| `has_star_flag` 把 `[obj+0x220]` 与 container 比较的那条指令 | `unresolved` | §4.1 的 `eval_body`;`+0x28` 的尾跳落到 parse 体,通用基体 `0x348B60` 的 `[vptr+0x18]` 目标未读到比较 |
| 存档序列化把 `+0x28` 的 dword 写成 `flags=` 右侧 | `static_inference` | 反查表(`0x2A00DE0`,0x30 步长,name 在 +0x10)与 container 布局都 pinned,但**序列化函数本身没读** |
| `+0x28` 与 `+0x40` 哪一张是"存档右侧那个时间戳" | **`unresolved`** | 写手 `0x1BCE180` 把日期写 `+0x28`、`0xFFFFFFFF` 写 `+0x40`;而官方读体 `0x1AA6AE0` 读的却是 `+0x40` 并乘 `0x186A0`。两条读数方向相反,本卷没有第三条证据裁决 |
| `[0x3260BB0]+0xC0` 就是"当期日期" | `static_inference` | 写手确实读它并写进 `+0x28`(§2.4 逐字);它是"日期"而非别的计数器,靠 `0x1BCE180` 的用法(与 `0xFFFFFFFF` 到期哨兵并列)推断 |
| `0x1AA6460` 的 galaxy 特例 `[scope+0x24]+0x20` 也是 star flag 容器 | `unverified` | 有指令(§3.1),但没有第二个消费者印证;`has_star_flag` 在 galaxy scope 下的语义不在本卷范围 |
| `0xFFFF` 在 flag 表里是"无效/未分配" | `pinned` | §2.2 `0x180F7F6`;§3.2 `0x1BCE19F` 的早退 |

### 4.6 复现(§4)

```bash
python3 scripts/disrva.py 0x135E40  --len=0x40
python3 scripts/disrva.py 0x1BCF030 --len=0x120
python3 scripts/disrva.py 0x158300  --len=0xD0
python3 scripts/disrva.py 0x180F980 --len=0x2E0
python3 scripts/disrva.py 0x1AA6460 --len=0x90
```

---

## 5. 没做的事(边界)

* **Task C 未执行** —— 未启动游戏、未注入、未跑 `just win` / `session_bridge.py` /
  `c2_*` / 任何 `C:/temp` 的东西。§4.3 的七条 falsifier 一条都没有被实机检验。
* **未改 `src/dll/**`**、未改 SDK、未改既有取证卷与 `evidence/xrefs/` 的表。
* **未验证 `0x3260BB0` 的完整语义**(只读它 `+0xC0` 的 dword)。
* **未读存档序列化函数**(`flags=` 的生产者),所以 §4.5 第 2 条停在 `static_inference`。
* **未查 C1/C2/C4 的既有锚点是否受影响** —— 本卷只服务 flag 存储。
* **未解释** P2-1b 里 `neo_tier1` 的 `NEO_JS_PREMINT` 为什么在安装期拿不到表项
  (那是读档时序,`0x1D13270` 那条线的事,与本卷的 flag 表不是同一对象)。

---

## 6. 插入原语与计数器归属(2026-11-08,离线;计划 Task 1)

**判决:`(a) 插入函数自己递增`。** `0x1BCF030` 体内有 **3 个** `inc dword ptr [0x326d118]`;
`0x180F590` 对 `0x326d118` **只有一次读**(`0x180f778`),没有写。`rip` 引用全量普查
(`scripts/riprefs.py 0x326d118`,5 条)只有这两个函数 `+` 初始化器。
⇒ 运行时插入合法;`ensure` 的写法是「读号 → 把号交给插入 → 插入落条目并递增」,
**调用方不递增**。

### 6.1 `0x1BCF030` 的签名与返回(逐字)

`.pdata` 边界 `0x1bcf030..0x1bcf3f3`(0x3c3 B,`python3 scripts/pdata.py 0x1BCF030`)。

| 寄存器 | 含义 | 逐字依据 |
|---|---|---|
| `rcx` | **不用** —— 函数体第一行就覆盖 | `01bcf057 movsxd rcx, dword ptr [rip + 0x169e0be] ; -> 0x326d11c` |
| `rdx` | 出参记录指针 = `{ qword bucket_ptr; u8 inserted }` | 尾部 `mov [rsi], rbx` / `mov byte [rsi+8], 1\|0`,`mov rax, rsi` |
| `r8d` | 名字哈希(`0x1C9E350` 的返回值) | `01bcf064 movsxd r12, r8d` → `and rbx, r12` 决定槽位 |
| `r9` | **0x30 B 引擎串对象**指针:`+0x10` 内联字符 / `+0x20` 长度(dword 读)/ `+0x28` 容量(qword) | `01bcf081 movsxd r15, dword [r9+0x20]`;`01bcf085 mov r12, [r9+0x28]`;`01bcf09e lea rcx,[r13+0x10]` |
| `[rsp+0x20]`(callee `[rbp+0x50]`) | `u16` 候选 id 的**指针** | `01bcf162 mov rax, [rbp+0x50]` / `movzx ecx, word [rax]` |

返回值:`rax = rdx`(出参记录本身)。`inserted = 1` ⇒ 新建条目(把候选 id 写进
`bucket+0x38` 并递增计数器);`inserted = 0` ⇒ 已存在,`bucket_ptr` 指向旧条目,
**计数器不动**。

槽位算法:`bucket = [0x326d110] + (hash & [0x326d11c]) * 0x40`(逐字
`01bcf067 and rbx, r12` / `01bcf06d shl rbx, 6` / `01bcf074 add rbx, [0x326d110]`)。

### 6.2 桶与串的布局(逐字)

```
01bcf090  cmp     qword ptr [rbx + 0x30], 0x10    ; 桶内串的容量门
01bcf095  lea     rdx, [rbx + 0x18]               ; 内联字符
01bcf099  jb      0x141bcf09e
01bcf09b  mov     rdx, qword ptr [rdx]            ; 容量 >= 0x10 ⇒ 堆指针
01bcf0ac  cmp     r15d, dword ptr [rbx + 0x28]    ; 长度
01bcf0b5  call    0x142188310                     ; memcmp
01bcf0bc  je      0x141bcf17f                     ; 命中
...
01bcf169  mov     word ptr [rbx + 0x38], cx       ; 命中/新建都往 +0x38 写 u16
```

| 桶偏移 | 含义 |
|---|---|
| `+0x00` | `u32` 名字哈希 |
| `+0x04` | `u8` 探测距离(0 = 空槽,插入时从 1 起;`0xFF` = 尾部哨兵) |
| `+0x08` | 0x30 B 引擎串对象(`+0x10` 字符 / `+0x20` 长度 / `+0x28` 容量) |
| `+0x38` | **`u16` flag id** |

步长 `0x40`;`0x08 + 0x30 = 0x38` 正好接上 id。

### 6.3 计数器归属(逐字:3 个写点 + 1 个读点)

```
01bcf0e6  mov     eax, dword ptr [rip + 0x169e02c]  ; -> 0x326d118   ; 读:装填因子
01bcf0ec  inc     eax
01bcf0f5  cvtdq2ps xmm1, xmm1
01bcf100  comiss  xmm1, dword ptr [rip + 0x169e01d] ; -> 0x326d124  ; 0.9

01bcf162  mov     rax, qword ptr [rbp + 0x50]        ; &候选 id
01bcf166  movzx   ecx, word ptr [rax]
01bcf169  mov     word ptr [rbx + 0x38], cx
01bcf16d  inc     dword ptr [rip + 0x169dfa5]  ; -> 0x326d118   ; 写点 1(空槽直接落)

01bcf1f0  call    0x141bcf7a0                     ; 把 victim 挪到下一空槽前先构造我们
01bcf1f5  inc     dword ptr [rip + 0x169df1d]  ; -> 0x326d118   ; 写点 2

01bcf396  inc     dword ptr [rip + 0x169dd7c]  ; -> 0x326d118   ; 写点 3(victim 落位后)
```

完整 `rip` 普查(`python3 scripts/riprefs.py 0x326d118 --verify`):

```
== 5 refs to 326d118 (.text) [verified] ==
      4  func 1bcf030..1bcf3f3      ; 1 读 + 3 写(上面四条)
      1  func 135e40..135e7f        ; 初始化:`mov qword [0x326d118], rax`(清零 counter+mask)
```

`0x180F590` 的唯一引用是 `0180f778 movzx eax, word ptr [rip + ...] ; -> 0x326d118`
—— 它把**当前**计数值当候选 id 读出来(`mov word [rbp+0x38], ax`),再在
`0x180f7b7` 把这个局部地址作为第 5 参交给 `0x1BCF030`。**号值由调用方读,递增由插入函数做**。

⇒ `[0x326D118]` 就是这张表的 **size** 字段(与 `+0x14` 的 mask 同属 map 对象的
`+0x10/+0x14` 两个 dword):id 稠密、从 0 起、每次成功插入 +1。`0xFFFF` 是引擎自己的
「发不出来」档(`0180f783 mov ecx, 0xffff` / `cmp ax, cx` / `je 0x180f7f0` 不改
`[obj+0xC0]`),`0x180f7f6 mov eax, 0xffff` 是名字串为空时的落点。

### 6.4 `0x158300` = 反查 vector 的 append(**复制**名字)

`.pdata` `0x158300..0x158324`(0x24 B),慢路径 tail-jump 到 `0x15848F`(同函数)。

| 寄存器 | 含义 |
|---|---|
| `rcx` | vector 对象 = 全局 `0x2A00DE0`(对象本体,不是指针);`+8` 数据、`+0x10` 容量(dword)、`+0x14` 计数(dword) |
| `edx` | 新元素下标(调用方读 `[0x2A00DF4]` = 追加前的计数) |
| `r8` | 0x30 B 引擎串对象指针 |

逐字:

```
00158308  movsxd  rax, dword ptr [rcx + 0x14]   ; size
0015830f  mov     ecx, dword ptr [rcx + 0x10]   ; capacity
00158318  cmp     eax, ecx
0015831a  jne     0x14015848f                   ; 未满 ⇒ 直接 append(下面)
...
00158496  shl     rcx, 4                        ; 索引 × 3 << 4 = ×0x30
0015849a  add     rcx, qword ptr [rdi + 8]      ; data + index*0x30
0015849e  call    0x14015f590                   ; 拷构造(深拷贝)
001584ab  inc     dword ptr [rdi + 0x14]        ; size++
```

`0x15F590` 是**拷贝构造**:它自己 `add rdx,0x10` / 读源容量 `[rdx+0x18]` / 内联或
解引用取源字符,再调 `0x15F770`(分配 + memcpy + NUL)。⇒ **名字被复制进 vector,
调用返回后调用方那份可以失效**;`ensure` 传栈上对象是安全的。

### 6.5 `lookup` 能否只靠哈希 + 桶扫描(不调插入)

**能,且这就是引擎自己的 find。** `0x180F590` 在决定要不要调 `0x1BCF030` 之前,
先内联了一整段只读扫描(`0x180f6d4..0x180f747`),逐指令与 §2.2 的读法同形:

```
0180f6d4  call    0x141c9e350                  ; hash(seed=0, chars, len)
0180f6e0  and     eax, r12d                    ; & mask
0180f6e6  shl     rbx, 6
0180f6ea  add     rbx, [0x326d110]
0180f6f1  mov     dil, 1                      ; 探测距离从 1 起
0180f700  cmp     byte ptr [rbx + 4], dil
0180f704  jb      0x14180f749                 ; 该槽探测距离 < 当前距离 ⇒ 停,未命中
...                                             ; 长度 + memcmp(同上)
0180f73c  inc     dil
0180f73f  add     rbx, 0x40
0180f743  cmp     dil, byte ptr [rbx + 4]
0180f747  jbe     0x14180f710
```

三个独立的引擎 parse 体(`0x180F590`、`0x1AA5D10`、`0x1BCE3F0`)是同一段扫描的
三个副本 ⇒ 这不是推断,是引擎自己反复写的同一个 find。

**尾部哨兵是死代码(所以 lookup 不需要它)**:`0x1BCF400`(扩容)给新表分配
`(1<<n) + (n+2) + 1` 个槽,把 `DIB` 清零后单独把**最后那一槽**置 `0xFF`:

```
01bcf602  shl     ebx, cl                      ; ebx = 1 << n(bucket 数)
01bcf604  add     cl, 2
01bcf61b  mov     dword ptr [rbp + 0x14], eax   ; 新 mask = ebx - 1
01bcf621  mov     byte ptr [rbp + 0x18], al     ; tail = n + 2
01bcf630  lea     ecx, [rax + 1]                ; tail + 1
01bcf633  mov     eax, 0x40
01bcf638  add     ecx, ebx                      ; tail + 1 + capacity
01bcf63a  mul     rcx                           ; 槽数 → 字节数
...
01bcf670  mov     byte ptr [rax + 4], r15b      ; 逐个槽 DIB = 0
01bcf674  add     rax, 0x40
01bcf67d  mov     byte ptr [rdx + 4], 0xff      ; 哨兵 = 下标 capacity+tail
```

而插入在落位前就检查 `cmp sil, byte [rdi + 0x18]`(tail)/ `cmp cl, [0x326d120]`,
**探测距离 > tail 就扩容**;哨兵槽的下标是 `(mask+1)+tail`,从任何起点走到它都
至少是 `tail+2` 距离 ⇒ 永不可能落条目,`[哨兵+4]` 恒 `0xFF`
(`0x180f765 cmp byte [rbx+4],0xff` / `je` 就是这条永真判断)。lookup 在
「`DIB < 距离`」的第一个空槽停下即可返回 `null`。

### 6.6 复现(§6)

```bash
python3 scripts/pdata.py 0x1BCF030         # 0x1bcf030..0x1bcf3f3
python3 scripts/disrva.py 0x1BCF030 --len=0x3C3
python3 scripts/disrva.py 0x158300  --len=0x24
python3 scripts/disrva.py 0x15F590  --len=0x57     # 拷贝构造
python3 scripts/disrva.py 0x1BCF400 --len=0x1F8    # 扩容的分配算关(哨兵)
python3 scripts/riprefs.py 0x326d118 --verify      # 5 条,只有两个函数
python3 scripts/disrva.py 0x180F590 --len=0x2A2    # 扫描 + 取号,零写
```

**边界**:本节全部是静态读数;没有实机(§5 的边界仍然成立,Task C 未执行)。


