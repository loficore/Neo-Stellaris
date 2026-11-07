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

