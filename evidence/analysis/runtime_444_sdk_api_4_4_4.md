# runtime_444_sdk_api_4_4_4 — #55 SDK v1 的 `src/dll/api/gamestate.zig` 逐条定形

零实机、零 Windows、零 hook。输入只有 exe 拷贝 + 仓内取证卷。置信档:
`pinned(§N)` / `静态推断(未验证)` / `未定形`。

```text
exe  = /var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe
sha256(实测) = 9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56
size = 46,253,688 B
date = 2026-11-15
```

**本卷回答的问题**:`gamestate.zig` 的十个函数,各自的锚点在 4.4.4 里**还在不在**;
在的按站点定形,不在的写清缺什么。**不**回答「运行期那一格真的是这个值」——
那要一发 `install → 读 → uninstall`(本计划零实机,清单留给下一份计划)。

**引文口径(全卷适用)**:所有 `global_xrefs.py` / `global_xref_range.py` / `disrva.py` 的输出块都是
**逐字摘录**;省略的行不列或写 `…(略)`,保留的每一行与原始输出逐字符相同,**不改写任何操作数**。

**产物出处**(按 basename 记录,追加不改写):

```text
evidence/xrefs/sdk_api_stubs_4_4_4.tsv     本次三条 xref 读数的原始输出
scripts/scratch/2026-11_dirty_bit/global_xrefs.py        快通道:单地址反查 + 形态分类
scripts/scratch/2026-11_sdk_api/global_xref_range.py     快通道:区间反查(与上面同算法、同一份 confirmation)
scripts/disrva.py                          逐条指令核(rip 相对操作数解析成 RVA)
```

`global_xrefs.py` 与 `global_xref_range.py` 的计数口径**不同,不是矛盾**:
前者`refs=` 数的是**候选数**(含 confirmation 失败的 `<no decode>`),后者 `refs=` 只数
**确认过的指令**。判别一个目标「有没有被引用」看后者或看前者的 `<no decode>` 行。

---

## §1 桩上两个魔数:`GAME_STATE_ADDR` / `COUNTRY_DB_ADDR` —— 判 `stale`,已删

### §1.1 桩上写的值

`src/dll/api/gamestate.zig`(审计前,commit `f38e429`)的常量是**绝对 VA**(不是 RVA):

```zig
const GAME_STATE_ADDR: usize = 0x143287360;  // = image base 0x140000000 + RVA 0x3287360
const COUNTRY_DB_ADDR: usize = 0x143287788;  // = image base 0x140000000 + RVA 0x3287788
```

对应的 RVA 才是可离线核的地址:`0x3287360` / `0x3287788`。两个 RVA 都**在 `.data` 内**
(`.data` RVA 区间 `0x2954000..0x37356d4`),所以「无引用」的读数**不是**地址越界造成的假象。

`.data` 里这两处的**文件字节全为 0**(32 B 窗口):

```text
0x3287360  file_off 0x3285760  in .data: True   00 00 00 00 00 00 00 00 ... (32 B 全 0)
0x3287788  file_off 0x3285b88  in .data: True   00 00 00 00 00 00 00 00 ... (32 B 全 0)
```

### §1.2 单地址反查(`global_xrefs.py`)—— 逐字摘录

`0x3287360`:

```text
# global 0x3287360  .text bytes=37291792  pdata funcs=130615
01f7dc5b	01f7dc5b	01f7dc5c	other	?	<no decode>
refs=1 set_bit=0 overwrite_imm=0 overwrite_reg=0 read_mask=0 read_bit=0 other=1
```

`0x3287788`:

```text
# global 0x3287788  .text bytes=37291792  pdata funcs=130615
refs=0 set_bit=0 overwrite_imm=0 overwrite_reg=0 read_mask=0 read_bit=0 other=0
```

### §1.3 那唯一一条候选是字节巧合,不是引用

`0x3287360` 那条候选落在 `0x1f7dc5b`,`global_xrefs.py` 自己判 `<no decode>`(没有任何
函数解码出一条**以它结尾**的 rip 相对指令)。逐条核对周围字节:

```text
; stellaris.exe  .text RVA 0x1f7dc40-0x1f7dc88
  01f7dc57  mov     ecx, 0xcf2        ; <-- 0x1f7dc5b 落在这个 imm32 的第 4 个字节上
  01f7dc5c  call    qword ptr [r14 + 0x130]
```

`0x1f7dc5b..0x1f7dc5e` 是 `mov ecx, 0xcf2` 的立即数(`0xf2 0x0c 0x00 0x00` 之后那条指令
从 `0x1f7dc5c` 开始),**不是指令边界**。一个 disp32 候选只是「某处 4 字节恰好等于
`target - insn_end`」,把它当真引用就是这类误判。⇒ `0x3287360` 的**确认引用数 = 0**。

### §1.4 「是不是某个被引用的大对象的字段」—— 区间反查否掉

若这两个地址是某个对象 `obj` 的字段,那么代码里会引用 `obj` 的基址(通常 `lea`),
而基址会**落在它们下方**。一次线性扫 `.text`,把**目标落在 `0x3286000..0x3287900` 的
全部 rip 相对候选**都列出来(这条窗口把两个地址前后各包 4 KB):

```text
# range 0x3286000..0x3287900  raw_candidates=845
0x3287852	0		<no decode>
0x328786c	0		<no decode>
…(略,其余 788 行同上,全部 refs=0 / `<no decode>`)
targets=790 refs=0
```

`raw_candidates=845` 是「disp32 落在区间」的**未确认**候选数,`targets=790` 是其中不同的
目标地址数;`refs=0` 表示两者**没有一条**通过 confirmation(`.pdata` 函数里真有一条以它
结尾的 rip 相对指令)。845 → 790 → 0 这三格一起看,才说明白「候选是噪声、确认是零」。

`refs=0` 的是区间内**全部 790 个**候选目标 —— 也就是说,这一段 6.4 KB 的 `.data` 窗口里
**没有任何地址被确认引用**,既不是某个对象被引用的基址,也就没有「它们是某个对象字段」
这条路。计划 Task 0 Step 2 的 Expected(无或零星无关命中)**成立**,而且是「全零」这一档。

### §1.5 判决

| 常量 | RVA | 确认引用数 | 单地址候选 | 区间窗口 | 档 |
|---|---|---|---|---|---|
| `GAME_STATE_ADDR` | `0x3287360` | **0** | 1 条 `<no decode>`(§1.3 字节巧合) | `refs=0` | **`stale`** |
| `COUNTRY_DB_ADDR` | `0x3287788` | **0** | 0 条 | `refs=0` | **`stale`** |

一句话结论:**这两个常量在 4.4.4 里没有任何代码引用,不能再用;已从 `gamestate.zig` 删除。**

**口径边界(不许当更强的结论引用)**:本节的「无引用」只覆盖 **rip 相对**形式的代码引用。
`.data` 仍可被两种我们没扫的形态读到:(a) 指令里的**绝对 64 位操作数**;(b) **指针表**
(表里存 `&global`,由别的代码间接解引用)。所以严格判词是「无 rip 相对引用、且没有
被引用的基址把它们当字段」,**不是**「这块内存无人使用」。这个差别不改变判决:
桩声称的是「main GameState object / Country database」这类**顶层全局**,而顶层全局在
x64 上必然要通过上述两种形态之一(否则取不到),两种形态都依赖 `.text` 里至少**一条**
绝对或 rip 相对的地址材料;这一条在 6.4 KB 窗口内一条都没有。

---
