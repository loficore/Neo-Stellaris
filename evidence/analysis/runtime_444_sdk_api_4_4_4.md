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

---

## §2 `getSystem` —— 唯一有现成静态锚点的一道,已定形

**判 `verified`,并已实现**(`src/dll/api/gamestate.zig` 的 `getSystem`)。

### §2.1 站点(全部是引擎自己的解析器 `0x3939f0`,逐条对得上)

```console
  00393a0b  mov  rax, qword ptr [rip + 0x2ecd186]  ; -> 0x3260b98   系统索引全局
  00393a17  test rax, rax                                           ; 未初始化(载入战役前 BSS = 0)
  00393a1a  je   0x140393a41
  00393a1c  mov  edx, dword ptr [rcx]                               ; id(来自 scope +0x10)
  00393a1e  mov  ecx, edx
  00393a20  and  ecx, 0xffffff                                      ; slot = id & 0xFFFFFF
  00393a26  cmp  ecx, dword ptr [rax + 0x20]                        ; 槽数上界 = index+0x20
  00393a29  jae  0x140393a41
  00393a2b  mov  rax, qword ptr [rax + 0x18]                        ; 槽表指针 = index+0x18
  00393a2f  add  rcx, rcx                                           ; slot * 2
  00393a32  mov  rax, qword ptr [rax + rcx*8 + 8]                   ; 表项 = qword[表 + slot*16 + 8]
  00393a37  test rax, rax                                           ; 空槽/陈旧表项
  00393a3a  je   0x140393a41
  00393a3c  cmp  dword ptr [rax + 8], edx                           ; **复核:entry+8 == id**
  00393a3f  je   0x140393a48
```

复现:`python3 scripts/disrva.py 0x3939F0 --len=0x58`。

### §2.2 16 B 步长(§1.11 的勘误,这里再钉一次)

`0x393a2f add rcx,rcx` 把槽号**翻倍**后才在 `0x393a32` 做 `[rax + rcx*8 + 8]`:
记录步长 = `2 × 8` = **16 B**,**对象指针在记录的 `+8`**。这不是一个 8 B 的 qword 数组 ——
按 8 B 步长读会落到记录的头上,静默读到错对象。

两个 `+8` 不是同一个东西,读的时候不要混:

| 偏移 | 载体 | 含义 |
|---|---|---|
| `qword[表 + slot*16 + 8]` | 槽表记录 | **系统对象指针**(`0x393a32`) |
| `dword[对象 + 8]` | 系统对象头 | **系统 id**(`0x393a3c` 的复核对象) |

所以 `getSystem` 返回的是 `0x393a32` 读出来的那个指针,而 `0x393a3c` 的复核发生在它**之后**,
落在对象头上(`offsets.graph.SYSTEM_ID_OFF = 0x08`)。

### §2.3 实现的六条 fail-closed(逐条对应上面的站点)

| 条件 | 处置 | 对应站点 |
|---|---|---|
| 全局槽读不到 / 为 0(`0x3260B98` 在 BSS,载入战役前是 0) | `null` | `0x393a17` 一族 |
| 槽数读不到 / 为 0 / `> MAX_TABLE_SLOTS`(1<<16) | `null`(按容器损坏) | `0x393a26` |
| 槽表指针读不到 / 为 0 | `null` | `0x393a2b` |
| `slot = id & 0xFFFFFF` 且 `slot >= 槽数` | `null` | `0x393a20/26` |
| 表项 qword 读不到 / 为 0(空槽) | `null` | `0x393a32/37` |
| `dword[表项+8] != id`(陈旧/别名表项) | `null` | `0x393a3c` |

外加**地址算术**一律走检查过的加/乘加:内存派生指针回绕 ⇒ 当读不到
(Debug 出货构建里未检查的 `+` 会 panic,约束 8)。

### §2.4 可测性:注入缝,不是改别人的签名

`getSystem` 不接受外部读函数(签名由 `bridge.zig` 的 JS 桥固定),所以本模块内部留一个缝:

```zig
pub const Memory = struct {                     // 与 galaxy_graph / graph_probe 的 Memory 同形状
    ctx: *anyopaque,
    read: *const fn (ctx: *anyopaque, addr: usize, len: usize, buf: []u8) bool,
};
pub const SystemSource = struct { mem: Memory, base: usize };
var test_source: ?SystemSource = null;          // 生产恒为 null
pub fn setSystemSourceForTest(src: ?SystemSource) void;   // 仅测试调用
```

生产侧 `source()` 现场装配 `base = windows.moduleFunction(0)`、`mem.read` = 进程内
`windows.readProcessMemory` 适配器。**这个缝必须带模块基址**:全局槽是 module-base-relative
(系统 `RVA 0x3260B98`、国家 `RVA 0x3260FD8`),而 Linux 测试宿主上没有模块基址可解析
(`windows.moduleFunction` 直接 `error.ModuleNotFound`)—— 只注入读函数,测试根本走不到槽。
带**基址**而不是带「某个全局槽的绝对地址」,是因为同一份读源要服务**两张表**(系统与国家
各 `+` 自己的 RVA),见 §4。`graph_probe` 的签名一个没动;`setSystemSourceForTest` 不是
能力开关,也不进导出表。

### §2.5 测试(宿主单测,假内存;三条都真跑过)

`src/dll/api/gamestate.zig` 内:

1. `getSystem resolves a slot through the index table and verifies the id` ——
   8 槽表:槽 0 → A(id 0)、槽 1 → stale(id 7)、槽 7 → B(id 7)。判据:`getSystem(0)=A`、
   `getSystem(7)=B`、**`getSystem(1)=null`(槽位与 id 不自洽)**、空槽 null、越界 null。
2. `getSystem fails closed when the index global is null or unreadable` ——
   八种坏形态(无区域 / 全局槽 0 / 头部读不到 / 表指针 0 / 槽数 0 / 槽数超上限 / 空槽 /
   索引指针贴近 usize 上界使 `+0x18` 回绕)全部 `null`,不 panic。
3. `getSystem: 宿主构建没有可用的读入口时返回 null(fail closed)` —— 不注入时走生产路径,
   宿主上模块基址解析失败 ⇒ null。

跑法(测试根因模块路径约束改到 `src/dll/api_tests.zig`,见 §2.6):

```console
$ zig build test --summary all      # Build Summary: 31/31 steps succeeded; 1132/1132 tests passed
$ zig test src/dll/api_tests.zig     # All 36 tests passed (本模块根);
                                     #   --test-filter getSystem  → 3 条 OK
                                     #   --test-filter getCountry → 2 条 OK(§4)
```

### §2.6 计划的一处改动(模块路径约束)

`gamestate.zig` 现在 `@import("../hooking/windows.zig")` 取生产读入口。Zig 拒绝**逃出模块根**的
相对引用,所以测试根不能再是 `src/dll/api/gamestate.zig`(根在 `src/dll/api`,够不到 `../hooking`)。
按 `c2_tests.zig` / `scripted_tests.zig` 的既有做法,新增 `src/dll/api_tests.zig` 作为根
(它只 `@import("api/gamestate.zig")`),`build.zig` 的 `api_gamestate_tests` 指过去。
测试体仍写在被测文件里,和改动前一样。

### §2.7 这条实现的边界(**不能说**的事)

- **零实机**:只在假内存上验证过。活体上「`0x3260B98` + `0x18/0x20` 的形状今天仍然成立」
  依赖 `runtime_444_graph_runtime.md` §3.6 那次实机读数(788 系统 / 1,219 边),本卷**没有**
  重新打一发。
- **§2 只覆盖系统**。国家已由 §4 定形并由 `getCountry` 实现(同一查表形状,只是全局与
  对象 id 偏移不同);星球 / pop 仍未定形(§4),`getPlanet` / `getPop` 是「未定形」的 null。
- 返回的是**引擎对象指针本身**,不是深拷贝;调用方不得在引擎侧销毁后继续用。

---

## §3 日期与 tick —— 判 `未定形`

判据(计划 Task 2):定形 = 给出「哪个全局 + 哪个偏移 + 编码」三件事,**并且**能指出至少
两条独立指令读同一格。本轮**不满足**,所以 `getGameDate` / `getGameTick` 保持安全返回
(`""` / `0`),注释指向本节。

### §3.1 走到哪一步(两条线索,都只到「候选」)

`evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv` 里与日期相关的注册项是入口
(`array_rva / thunk_rva / class_info_rva` 都在 TSV 里;`class_info` 是 `{deleter, create}` 16 B 记录):

| 线索 | token | class_info | create | 我读到的 |
|---|---|---|---|---|
| trigger `years_passed` | 18286 | `0x269f328` | `0x1b209d0` | create `new(0x2a8)` 后装 vtable `0x269aed0`;`+0x48 = 0x1aa8670`、`+0x28 = 0x1a91a30`、`+0x80 = 0x349230`(基体谓词)。**没有**在 create 里看到日期读 |
| effect `set_saved_date` | 10245 | `0x260fc10` | `0x1899350` | create `new(0x6e8)` 后装 vtable `0x25ff080`(+8 再装 `0x25ff060`);`+0x48` body `0x1848a00` |

`0x1848a00`(`set_saved_date` 的执行体)里有一处**像**日期读:

```text
  01848a4a  mov  rax, qword ptr [rip + 0x1a1815f]  ; -> 0x3260bb0   银河全局
  01848a5b  mov  edi, dword ptr [rax + 0xc0]        ; 银河对象 +0xC0(候选日期格)
  ...
  01848a66  imul eax, dword ptr [rsi + 0x2e8]       ; 参数 × ?
  01848a73  lea  eax, [rax + rax*2]                 ; ×3
  01848a76  lea  edi, [rdi + rax*8]                 ; 基准 + 参数×24
```

`+0x3260bb0` 是已验过的银河容器全局(`keyword_reg.RVA_GALAXY_MAP_DB`)。但这条链只给出
**一个**读点,而且它在「保存一个日期」的 effect 里 —— 无法排除 `[galaxy+0xC0]` 是**被保存的
那个值**的基准,而不是「当前日期」。`imul … ; ×3 ; ×8` 像「月/日」拼装,但同样是单点。

### §3.2 缺什么(诚实清单)

- **缺第二个独立读者**:`[0x3260bb0]+0xC0` 目前只有一个读点。计划要求「至少两条独立指令
  读同一格」—— 没有它,这一格随时可能是别的字段。
- **缺编码**:是 Y/M/D 三连、自纪元天数、还是月/日打包成整数?`0x1848a00` 的算术是线索
  不是证据(它可能是「当前 + 用户参数」,不是当前日期的内部编码)。
- **tick 完全没有候选**:没有任何「每 tick 递增」的全局被定位。

### §3.3 下一步(留给下一份计划,可执行)

1. 从 `years_passed` 的 vtable `0x269aed0` 找到**比较器**那一槽(它会做「当前 − 2200 起点」,
   起点是脚本常量;它读的就是当前日期格);
2. 用 `global_xref_range.py` 扫该比较器引用的 `.data` 窗口,确认同一格被 ≥2 条独立指令读;
3. 三件事(全局 / 偏移 / 编码)齐了才实现;否则继续维持 `未定形`(不许猜)。

---

## §4 国家 / 星球 / pop —— 国家定形并实现;星球 / pop 未定形

### §4.1 国家:定形(**两个独立读者**),已实现

国家对象表全局 = **`0x3260FD8`**(全局槽,存表对象的绝对地址)。两个互不相同的函数均按同一
形状读它:

```text
; 读者 A:0x192c290(从 4 B id 向量逐个取国家对象)
  0192c2d0  mov  rbx, [rip + 0x1934d01]  ; -> 0x3260fd8   表对象
  0192c2dc  mov  ecx, [rdi]              ; 原始 id(ecx 保留)
  0192c2e0  and  eax, 0xffffff           ; slot = id & 0xFFFFFF
  0192c2e5  cmp  eax, [rbx + 0x20]       ; bound
  0192c2ea  mov  rbx, [rbx + 0x18]       ; 记录数组基址
  0192c2ee  add  rax, rax                ; slot*2
  0192c2f1  mov  rbx, [rbx + rax*8 + 8]  ; 记录 16 B,对象指针在 +8
  0192c2fb  cmp  [rbx + 0x20], ecx       ; **id 复核:对象 +0x20**

; 读者 B:0x1e7b850(另一个按 id 取国家的函数)—— 同形
  01e7b8a0  mov  rax, [rip + 0x13e5731]  ; -> 0x3260fd8
  01e7b8b1  and  ecx, 0xffffff
  01e7b8b7  cmp  ecx, [rax + 0x20]
  01e7b8bc  mov  rax, [rax + 0x18]
  01e7b8c0  add  rcx, rcx
  01e7b8c3  mov  rcx, [rax + rcx*8 + 8]
  01e7b8cd  cmp  [rcx + 0x20], edx       ; id 复核同样在 +0x20
  01e7b8d2  (未命中)rcx = [0x325f390]    ; 引擎的空对象回退 —— 我们**不**用
```

⇒ 与系统解析器 `0x3939f0` **同形**(bound `+0x20`、表 `+0x18`、记录 16 B、对象指针在记录
`+8`、槽号 = `id & 0xFFFFFF`),唯一不同的是**对象自身 id 在 `+0x20`**(系统是 `+0x08`)。
`offsets.country_table` 钉住这六格,并有测试断言四个公共表偏移与 `graph.*` 逐一相等,防漂移。

`getCountry` 已实现:与 `getSystem` 共用 `lookupTable`,只传不同的 `global_rva` 与 `id_off`。
读不到 / 越界 / `dword[对象+0x20] != id` 一律 `null`;**不**返回引擎的空对象回退
`0x325F390` —— 那是伪造对象(计划明确禁止)。测试:
`getCountry resolves through the country table and verifies the object id at +0x20`
(槽 1 放了一个 id=7 的对象,`getCountry(1)` 必须 null)与一条 fail-closed,均绿
(跑法见 §2.5)。

### §4.2 星球 / pop:未定形

`AGENTS.md` 与 `evidence/analysis/` 都没有「星球对象表 / pop 对象表」的全局锚点;时间盒内
(静态扫描)没有找到满足「两条独立指令」的候选。`getPlanet` / `getPop` 保持 `null`,注释指向
本节。**缺**:两张表各自的全局 RVA、表对象头部布局、对象内 id 字段。
**下一步**(与国家同一手法):从 `colony_age` / `planet_*` / `pop_*` 一族 trigger 的
`class_info → create → evaluate` 找到「按 id 取对象」的读点,再反推全局与 id 偏移。
