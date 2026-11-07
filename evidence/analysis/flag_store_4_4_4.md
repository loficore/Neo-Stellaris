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
