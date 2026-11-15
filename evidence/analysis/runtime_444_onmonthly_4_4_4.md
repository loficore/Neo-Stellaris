# 全局 `onMonthly` 的入口在哪:从 `on_monthly_pulse` 顺到执行侧(4.4.4,离线,零 shot)

**这一卷回答什么。** 我们的 JS 现在**借**脚本才被每月叫一次
(`examples/chokepoint/mod/common/on_actions/neo_chokepoint_on_actions.txt` 的
`on_monthly_pulse = { events = { neo_chokepoint.1 } }`)。计划问的是:**不用这层脚本 stub,
引擎自己有没有一个「每月」的边界,能在那儿拿到一次调用?** 本卷只答这一格:先从字符串
`on_monthly_pulse` 顺到引擎读它的地方,再从引擎自己的**月度边界**(`0x265DD0`)往下读到
on_action 执行侧(`0x406F90` → `0x402C50`),最后把计划台账里的五个候选逐个读体否掉。
§4 给判决,§5 写这一卷不能说的。

**生产者。** `scripts/scratch/2026-11_onmonthly/onaction_field_readers.py`(只读 exe 拷贝,
`NS_STELLARIS_EXE` 优先)。它一次打完本卷四条可机械复核的读数:名字串的引用点、14 行
名字→字段映射、DB 固定字段的读者表、五个候选的间接调用槽/直调锚点。逐字节反汇编另用
`scripts/disrva.py --len=`(长度一律由 `.pdata` 算,不跨函数)、调用者桶用
`scripts/fastcalls.py`(产物落在 `evidence/xrefs/callers_0x*_buckets.tsv`)。

**判决(一行,论证在 §4):**

判决: global_entry_named —— 入口 = `0x265DD0`(`gamestate.cpp` 的月度边界:月变才调一次),它在
`0x266F6C` 读 on_action DB 的 `+0x28`(=`on_monthly_pulse`)并经 `0x266F70` 调 `0x406F90`
(`onaction.cpp` 的 `Perform OnAction`);侵入面是**事件层**,不是 effect 执行层。

---

## §1 台账:五个候选 + 两条已知负结论(2026-11-15,离线,零 shot)

### §1.1 候选(数值逐字取自来源,不改写)

| 候选 | 来源 | 已知 |
|---|---|---|
| `0x9F5750` | `AGENTS.md` RVA 表 | Event command handler,需更深 trace |
| `0x9F6420` | 同上 | 同上 |
| `0x9F65E0` | 同上 | 同上 |
| `0x18B7B70` | `c1_validation` §83 | effect vtable `+0x70` 派发候选,拿对象不派活 |
| `0x18B7E30` | 同上 | 同上 |

两条**既有负结论**(本卷不推翻,只对齐):

- **§83 = `dispatcher_partial`**:两个 `+0x70` 候选追到的是「谁造这个对象」(类自己的 create +
  class_info vtable),没有往外接到列表驱动 / on_action / event 那种入口。
- **§89 = `+0x70` 那一族不在执行路径**:实机窗内 16 个月度脉冲、`12,544 = 16 × 784` 次逐系统
  下发,而 `0x3B1330`(`+0x70` 的 base impl)`calls=0`;§90.1 把它加强成「它只有三个直接
  调用者,三个全部沉默」。

### §1.2 本卷新增的台账行(来源 = §2)

| 候选 | 来源 | 已知 |
|---|---|---|
| `0x407330` | §2.2 | **唯一**读 `on_monthly_pulse` / `on_yearly_pulse` 真串的函数:名字 → DB 固定字段 |
| `0x265DD0` | §2.3 | **唯一**读 DB`+0x28` 的函数;唯一调用者按「月变」触发 |
| `0x406F90` | §2.5 | `Perform OnAction`(`onaction.cpp`):`events` / `random_events` → `0x402C50` |

### §1.3 复现

```
python3 scripts/scratch/2026-11_onmonthly/onaction_field_readers.py
```

四段读数(名字引用点 / 14 行映射 / 字段读者表 / 五候选调用槽)与 §2、§3 的每个数一一对应;
`pytest` 不在本卷范围(该脚本是 `scratch/`,冻结留档,不进 lint 也不进围栏)。

### §1.4 留给 `AGENTS.md` 文档地图的一行(本卷**没有**改 `AGENTS.md`)

同批另一份计划在改 `AGENTS.md`,所以这一行留给下一份计划顺手补:

| 内容 | 位置 |
|---|---|
| 取证 §1–§5(全局 `onMonthly` 入口:名字只在注册侧读一次、DB 固定字段 14 行、月度边界 `0x265DD0` 月变才调、`0x406F90` = `Perform OnAction` → `0x402C50`、五个候选全否) | `evidence/analysis/runtime_444_onmonthly_4_4_4.md` |

---

## §2 从 `on_monthly_pulse` 顺出的调用链(2026-11-15,离线,零 shot)

### §2.1 名字在镜像里的两处出现:一处是**子串**,一处是真串

```
grep -ac "on_monthly_pulse" stellaris.exe      → 1(二进制按行计,不说明出现次数)
grep -aob "on_monthly_pulse" stellaris.exe     → 38721632 / 38721792
python3 scripts/strfind.py on_monthly_pulse on_yearly_pulse
   'on_monthly_pulse': .rdata 0x24eed00
   'on_yearly_pulse' : .rdata 0x24eecf0
```

第一处 `38721632` 落在 **`on_monthly_pulse_country`** 里面(串起点 `0x24EEC60`,前一个字节不是
NUL,`strfind` 拒收);真串只有一个,`0x24EED00`,和 `on_yearly_pulse @0x24EECF0` 相邻 16 B。
⇒ 计划 Review Focus 1 的那条可能(「名字可能只以表键形式存在」)**不成立**:它是 `.rdata` 里
一段普通的 C 串,但它**不是**调度键 —— 调度侧读的是缓存字段(§2.3),名字只在注册时读一次(§2.2)。

`riprefs --verify`(逐条按 `.pdata` 起点重解码,丢掉落在指令中段的假阳)两个串各 **1** 个引用点,
都在 `0x407330`:

```
== 1 refs to 24eecf0 (.text) [verified] ==     1  func 407330..4081ff
== 1 refs to 24eed00 (.text) [verified] ==     1  func 407330..4081ff
```

⇒ 整个镜像里**只有这一个函数**知道 `on_monthly_pulse` 这个名字。

### §2.2 `0x407330` = 名字 → on_action DB 固定字段的映射器(读名字那一层)

口径:`lea rdx,[名字]` 之后紧跟的 `mov [<db>+0xNN], rdi`(`<db>` = 从 `[0x3374840]` 取到的那
个寄存器;`rdi` = 本次按名字查到/新建的 on_action 定义对象)。14 行,一条不多一条不少:

| 字段 | 名字 | lea / store |
|---|---|---|
| `+0x28` | `on_monthly_pulse` | `0x407832` / `0x407842` |
| `+0x30` | `on_yearly_pulse` | `0x407856` / `0x407866` |
| `+0x38` | `on_bi_yearly_pulse` | `0x40787A` / `0x40788A` |
| `+0x40` | `on_five_year_pulse` | `0x40789E` / `0x4078AE` |
| `+0x48` | `on_decade_pulse` | `0x4078C2` / `0x4078D2` |
| `+0x50` | `on_mid_game_pulse` | `0x4078E6` / `0x4078F6` |
| `+0x58` | `on_late_game_pulse` | `0x40790A` / `0x40791A` |
| `+0x60` | `on_monthly_pulse_country` | `0x40792E` / `0x40793E` |
| `+0x68` | `on_yearly_pulse_country` | `0x407952` / `0x407962` |
| `+0x70` | `on_bi_yearly_pulse_country` | `0x407976` / `0x407986` |
| `+0x78` | `on_five_year_pulse_country` | `0x40799A` / `0x4079AA` |
| `+0x80` | `on_decade_pulse_country` | `0x4079BB` / `0x4079CB` |
| `+0x88` | `on_mid_game_pulse_country` | `0x4079DF` / `0x4079EF` |
| `+0x90` | `on_late_game_pulse_country` | `0x407A03` / `0x407A13` |

同一函数还做三件相邻的事(逐条读过,写在这里是为了把它的身份钉死):

- 入口把 `+0x28`…`+0x48` 五个字段**清零**(`0x407362`–`0x407372`)⇒ 它们是「本次加载里
  被命名的定义」的缓存,不是常量表;
- 每个名字先算 murmur3-32(常量 `0xcc9e2d51` / `0x1b873593` / `0x85ebca6b` / `0xc2b2ae35`)
  在 `[db+8]` 的链式桶里查重;命中就对**已有**的定义对象 `call [vptr+0x18]`(传同一个上下文,
  `0x407715`–`0x40772B`)然后 `jmp` 回循环头;
- 未命中才 `new(0x68)`,写 vptr `0x24EEE08`、名字(SSO 容量 `0xf` 在 `+0x30`)、两个
  `.rdata` 指针(`0x247A488` @`+0x38`、`0x247A530` @`+0x50`;两张都是「槽指 `.text`」的
  次基 vtable,本卷**没读**它们的槽语义),再插桶 + 写固定字段。

**这一层不是入口,是注册侧。** 而且它**没有静态调用者**:`fastcalls.py 0x407330` = 0 个直调站点,
`.rdata` 里也没有指向它的 8 B qword,`lea` 站点同样是 0(`rttibatch.lea_sites_to`)。旁边的三个
无 `.pdata` 小桩(`0x4072F0` = 「db 非空则该调」守卫、`0x407310` = `jmp 0x407330` thunk、
`0x407320` = `return [0x3374838] != 0`)同样零静态引用 ⇒ **谁在运行时经函数指针调这个映射器,
本卷答不了**(写进 §5)。

### §2.3 月度边界 `0x265DD0`:全镜像**唯一**读 `DB+0x28` 的地方

`on_action DB` 的全局是 `0x3374840`,里面放的是**指针**(`mov r14,[rip+…]`)。口径:先跟
「从该全局取指针 → `mov` 复制 → `[reg+disp]`」,限制 `disp ∈ [0x28,0x90]`:

```
global 0x3374840: refs=328 functions=264
func 0x265dd0: site 0x266f6c [+0x28]          ← 唯一一行 +0x28
func 0x267870: site 0x267ba9 [+0x30]  … 0x267f70 [+0x90]   (年变那条,12 个字段)
func 0x7348e0: site 0x735202 [+0x60]          (on_monthly_pulse_country)
```

读点本身(`0x266F56`–`0x266F70`,紧邻、中间没有对 `rax` 的重新赋值):

```
00266f56  mov  rax, [rip + 0x310d8e3]   ; -> 0x3374840  (on_action DB)
00266f5d  mov  [rsp + 0x20], rbx        ; 第 5 实参 = 0
00266f62  xor  r9d, r9d                 ; 第 4 实参 = 0
00266f65  lea  r8,  [rbp + 0x290]       ; 第 3 实参 = &月度 ctx
00266f6c  mov  rdx, [rax + 0x28]        ; 第 2 实参 = db->on_monthly_pulse
00266f70  call 0x406f90                 ; Perform OnAction
```

同一函数里另外两条月度支路(不是候选,但说明「月度」这一格是**一组**):

- `0x266703 call 0x7348E0` —— 逐国家调 `on_monthly_pulse_country`:先按 `[rbp+0x38]` 的
  国家 id 数组遍历、经国家表 `0x3260FD8` 解析,`0x7351FB` 再取 `db+0x60`,门是
  `[country+0x48] >> 2 & 1`;
- `0x26749A call 0x37BB70`(=`FindOnAction(name)`)→ `0x2674B6 call 0x406F90` —— 按**名字**
  现查 `on_biomass_monthly`(串 `0x24C1108`),查不到就走 `0x24EEB90`
  `Could not find on action '%s'` 那条诊断。

### §2.4 `0x265DD0` 的调用者 `0x256730`:月变才调(可复核的判据)

`fastcalls.py 0x265DD0` = **1** 个直调站点,`0x2570DF`,在 `0x256730..0x2579CC`
(`gamestate.cpp`;同函数的串有 `It is a new day: `、`Micro/Week/Month/Year`、`Performance run took`)。

```
00256c8b  mov  eax, [rsi + 0x118]        ; 旧「年」
00256c91  mov  [rbp - 0x30], eax
00256c94  mov  eax, [rsi + 0x128]        ; 旧「月」
00256c9a  mov  [rbp - 0x38], eax
00256ca0  call 0x9af340                  ; 年的访问器 → [rsi+0x118] = 新年
00256ca5  mov  [rsi + 0x118], eax
00256cbc  call 0x9af2c0                  ; day_of_year(0..359)
00256cc6  cmp  eax, 0x1e                 ; doy < 30 ⇒ 月序号直接 0,否则下面 /30
00256cd6  mov  [rsi + 0x128], edx        ; [rsi+0x128] = day_of_year / 30 = 月序号
…
002570b7  mov  eax, [rbp - 0x38]         ; 旧月
002570ba  cmp  eax, [rsi + 0x128]        ; 新月
002570c0  je   0x2571b0                  ; 没变 ⇒ 跳过
002570dc  mov  rcx, rsi
002570df  call 0x265dd0                  ; ← 月变才调:月度边界
…
002571ba  mov  eax, [rbp - 0x30]         ; 旧年
002571bd  cmp  eax, [rsi + 0x118]        ; 新年
002571df  call 0x267870                  ; ← 年变才调:年及以上那批(+0x30…+0x90)
```

两个访问器的语义取自 `runtime_444_game_date_4_4_4.md` §2:`0x9AF340` = 年、`0x9AF2C0` =
年内第几天(0 基,`0..359`)。⇒ `[rsi+0x128]` 是**月序号**,`[rsi+0x118]` 是**年**。这条比较是
本卷「每月一次」的**唯一**静态判据 —— 它不是「这个函数看着像月度」,而是「旧月 ≠ 新月才调」。

`0x256730` 自己是被谁叫的(再上一层,一行):

```
fastcalls 0x256730 → 1 site 0xa78d80  (串 'Fast Forwarding: ' / ' Ticks')
fastcalls 0xa78d80 → 0x988db0 (ingameidler.cpp,in-game 更新循环) 与 0xf27570 (控制台 observe/快进)
```

⇒ 正常玩法经 in-game 更新循环进入,不是只有调试快进才走这条路。

### §2.5 月度脉冲往下:`0x406F90` = `Perform OnAction` → `0x402C50` = 触发事件

`0x406F90` 的 `.pdata` 首块只有 `0x2D` 字节(`0x406F90..0x406FBD`),后面接着链式片段 —— 其中
带串的两块是 `0x406FDD..0x4070E1` 与 `0x4070FD..0x40718C`(其余片段不带串,`fastcalls` 的桶不列)。
两块里各有一条字符串:`Perform OnAction %s Trigger Event %s`(`0x24EEB68`)、
`Perform OnAction %s Trigger Random Event %s`(`0x24EEB38`),文件是 `onaction.cpp`。它做的事:

1. `movsxd rax,[rdx+0x64]` / `rbx=[rdx+0x58]` ⇒ 定义对象的 **events 数组 + 计数**;
2. 每个 4 B 值按 `id = namespace*100000 + index` 解(`imul eax,edx,0x186a0`),用事件库
   `0x3374838`(域数 `+0x3c`、行表 `+0x30`、**stride 0x18**、行内 `+8` 数组 / `+0x14` 计数)
   取事件对象;
3. `call 0x93A780(event, ctx)`(布尔门,`test al`)⇒ `call 0x402C50`(触发事件);
4. 之后 `call 0x406650(def, ctx)` 处理 **random_events**:`[def+0x4c]` 是 random 计数,内部按
   `[ctx+8]` 的 `0x80` / `2` / `0x10` / `0x20` 四个值分派不同的挑选路径(§91.7 的逐系统下发里
   `ctx+0x08` 正好是 `0x80`,所以这四个值很可能是「scope 种类」——**本卷只读到分支存在**,
   没给它们定名)。

**`0x402C50` 读的是 ctx 的什么**:入口 `mov r13d,[r8+0x10]`、`[r8+0x38] → [+0x10] → [+0x38] → [+0x10]`。
月度 ctx 是在 `0x266E82`–`0x266F40` 就地建的(`vptr = 0x24E9068`,`+8` / `+0x10` 写 0,
`+0x30/+0x38/+0x40` 三个字段都写 `&ctx` 自己、`+0x68 = 0xe5f10afa`、`+0x24 = 0xffffffff`)
⇒ 那几跳**读回来的是同一个 0**,即「无 scope」的形状,与 vanilla `on_monthly_pulse` 注释的 `# No scope, like on_game_start` 一致。

### §2.6 围栏:整个镜像里以 `rcx = db` 被调用的目标只有 8 个,没一个读 `+0x28`

§2.3 的口径只覆盖「从全局取指针」的那些函数。补的那一层是「**以 `rcx` = db 调出去的调用点**」:

```
distinct callees with rcx=db: 8
0x37bb70 callsites=91  [+0x28] reads=-   FindOnAction(name)
0x406f00 callsites=82  [+0x28] reads=-   PerformOnActionByName
0x406f90 callsites=84  [+0x28] reads=-   Perform OnAction
0x8737b0 callsites=1   [+0x28] reads=-
0x873c10 callsites=1   [+0x28] reads=-
0x874590 callsites=1   [+0x28] reads=['0x874a42']   ← 口径假阳,见下
0xcd2300 callsites=1   [+0x28] reads=-
0x2185218 callsites=4   [+0x28] reads=-   operator new(rcx=size)
```

- `0x406F00` = `PerformOnActionByName`:先 `call 0x37BB70` 查名,命中就**尾跳** `0x406F90`;
  未命中走 `0x24EEB90` 那条诊断。这是引擎「按名字触发 on_action」的统一入口(82 个站点散在
  各系统里 —— 例如 `on_pop_bombed_to_death` / `on_debris_scavenged` 那个 `0xDF8850` 函数里
  就同时有 `0x37BB70 + 0x406F90` 与 `0x406F00` 三种写法)。
- **假阳这一行必须写出来**:`0x874590` 是从 `0x86DA78`(`mov rcx,rbx`)进来的,但它入口把
  `[rcx+0x18]` 当**国家 id** 查 `0x3260FD8` 表 ⇒ 那个 `rcx` 已经不是 db;它读的 `[r15+0x28]`
  (`r15 = rcx`)是另一个对象的字段。线性扫描跟丢了 `rbx` 的重赋值,这一行不算读数。

⇒ 「`+0x28` 只有一个读者」这句话现在是**两个独立口径**的同向结论(直接取指针的那一路 + 把 db
当 `this` 传出去的那一路),不是一句推断。

### §2.7 三层标注(计划 Task 1 要求的「这一层是什么」)

| 层 | 站点 | 这一层是什么 |
|---|---|---|
| 1 | `0x407330`(`0x407842` 写 `+0x28`) | **读名字**:把脚本给的 `on_monthly_pulse` 定义查重/建对象,并缓存进 DB 固定字段 |
| 2 | `0x266F6C`(`0x265DD0` 内) | **查表**:直接读缓存字段 `db+0x28`,不碰名字、不做哈希 |
| 3 | `0x266F70` → `0x406F90` → `0x402C50` | **执行**:`Perform OnAction` 逐 id 触发事件;effect 在 `0x402C50` 之下才出现 |

README 那条纪律(「没读到执行层就不许判 `global_entry_named`」)在这里是**满足**的:第 3 层
读到了函数体、读到了它写日志的那两行串(`Perform OnAction %s Trigger Event %s`),也读到了它
对事件库的 id 解码;**但没有**读到 effect 执行 —— 那不是本链的下一跳,是事件机器的下一跳
(§3.5 与 §5 都把这件事分开写)。

### §2.8 顺带读到的一件:这个定义对象**本身**是 CEffect(但它仍不是执行入口)

`0x407330` 写进新对象的 vptr 是 `0x24EEE08`,而它在 `evidence/xrefs/ceffect_vtable_map_4_4_4.txt`
的第 623 行:

```
vtable 0x024eee08  slot0 0x00405f50  ExecuteActual(slot2) 0x0015db30
```

⇒ `db+0x28` 指向的 `on_monthly_pulse` 节点**属于 CEffect 家族**(slot[1] = base Execute
`0x1D08520`);它的 slot[3] = `0x535070` —— `0x407330` 的「重复定义」路径 `call [vptr+0x18]`
调的就是这一格(与 `AGENTS.md` 里 `0x5350D0` 是属性 getter 那条不同一个地址,别混)。

这一条正好是计划约束 ③ 的实物:**我们能拿到一个 effect 对象**,而且是引擎每月自己从 DB 里
取出来的那一个,**但引擎的月度路径没有 Execute 它** —— `0x406F90` 读的是它的 `events`
数组(`+0x58` / `+0x64`),然后触发事件。「有对象」与「在没有 scope 的场合执行它」是两件事;
后者本卷**没有试**,也不该从这条链推出来(`slot[2]` 的 `0x15DB30` 本卷没有读体:它既不在
月度路径上,也不是 §89 那条 `+0x70`)。

---

## §3 五个候选逐个读体(2026-11-15,离线,零 shot)

每个候选回答计划要求的三问:① 入参里有没有 scope;② 有没有 effect 派发槽
(`call [vptr+0x10]` = `ExecuteActual` / `call [vptr+0x08]` = Execute 那一族);③ 调用者是谁。
每条的间接调用槽与「对已知锚点的直调」都是机器读数
(`onaction_field_readers.py` 第 4 段),锚点集 = `0x1D08520` / `0x3AFD30` / `0x3B1330` /
`0x3B01A0` / `0x3AF130` / `0x3B0F80` / `0x402C50` / `0x406F90` / `0x406F00` / `0x37BB70` /
`0x1D092C0`,**五个候选全部 `anchors=-`**。

### §3.1 `0x9F5750`(0x8D5 B)—— eventcommands.cpp 的「选项被选」命令,不是入口

- **入参**:`rcx` = 一条命令记录:`[rcx+0x20]` 是事件 id(按 `id/100000` 解域、界表是事件库
  `0x3374838`);`[rcx+0x28]` 在 `0x9F580E` 被当**国家 id** 用(拿 `[obj+0x180]` 逐项比)。
  **没有 scope** —— 记录里没有 `+0x10` 那种「星系 id」位。
- **它自己是不是派发**:函数体内 9 个间接槽,`[rax+0x38]` / `[rdx+0x38]` / `[rdx+8]` /
  `[rax+0xc0]`×3 / `[rax+0x20]` / `[rax]` / `[rax+8]`,每个站点后面都是 `test al` 之类的布尔消费;
  **没有** `[+0x10]`。对 11 个已知锚点的直调 = 0。
- **身份**:它引用的串全是 `eventcommands.cpp` 的选项选择日志 ——
  `Event %s selecting option %d by human %d, playerEventId %d, Country %d`、
  `Event %s already selected. option %d, duplicate command by human %d…`。
- **调用者**:`E8` 直调 **0** 个 ⇒ 只能经命令表/vtable 进来(网络/UI 命令派发)。
- **不是入口的理由**:它是**玩家选了事件选项**这条命令的处理体,形状要求「有人选了」这件事先发生;
  月度脉冲只**触发**事件(`0x402C50`),从不产生「选项已选」命令。而且它没有 scope、也没有 effect 槽。

### §3.2 `0x9F6420`(0x12A B)—— 事件/选项的解析 helper,不是入口

- **入参**:`rcx` = 同形状的命令记录(`+0x20` 事件 id;`+0x24`/`+0x2C` 进
  `Null Event : option %d by human %d` 那两个 `%d`,**哪一位是哪一个本卷没钉**)。**没有 scope**。
- **派发**:`indirect=[]` —— 体内**一个间接调用都没有**,只有 3 个直调(查库 + 一条诊断
  `Null Event : option %d by human %d` / `Event %s : Option not allowed…`)。
- **调用者**:6 个,`0x11E2D6D` / `0x11ED5BD` / `0x11F624E` / `0x13E3171` / `0x168A50D` /
  `0x14511E5`。前五个的函数体串都是 `selected_event_option` + `event_key` / `option_id` /
  `event_type` / `save_game_id`(**遥测发送器**);`0x14511E5` 是
  `graphics/diplomatic_eventwindow.cpp`(事件窗按钮)。
- **不是入口的理由**:它是被遥测与事件窗调用的**取数/校验**函数(返回 `al`),不派活、不带 scope,
  也不是每月被调 —— 调用者是「有玩家操作时」的路径。

### §3.3 `0x9F65E0`(0x52D B)—— eventcommands.cpp 的「关闭/清理玩家事件」命令,不是入口

- **入参**:同 §3.1 的命令记录形状(`+0x20` 事件 id + 玩家/事件标识)。**没有 scope**。
- **派发**:2 个间接槽 `[rdx+0x38]` / `[rdx+8]`,后面都 `test al`;无 `[+0x10]`,锚点直调 0。
- **身份**:串是 `Event %s removed from open player event : human %d, PlayerEventId %i`、
  `Event %s by human %d, PlayerEventId %i`、`Event %s already selected. duplicate command…`。
- **调用者**:`E8` 直调 **0** 个(命令表)。
- **不是入口的理由**:与 §3.1 同族(玩家/网络命令),且它是「移除」那一半 —— 每月不会有这种命令。

### §3.4 `0x18B7B70` / `0x18B7E30`(各 0x3B B)—— `+0x70` 派发候选(§83 原判不变)

两只形状逐字相同,只有 getter 与 vtable 头不同:

```
0x18b7b70  mov [rsp+8],rbx / push rdi / sub rsp,0x20
           add rcx,0xc0                ; this+0xC0 子对象
           mov rdi,r8                  ; 第 3 实参(r8)先存
           mov rbx,rdx                 ; 第 2 实参 = scope
           call 0x18be4e0              ; getter(this+0xC0, scope)
           mov rcx,[rax]               ; 被派发者 = [[getter]]
           test rcx,rcx / je 0x18b7ba0
           mov rax,[rcx]               ; vtable
           mov r8,rdi / mov rdx,rbx    ; scope 与 r8 原样转回去
           call [rax+0x70]             ; ← 站点
```

- **入参**:`rdx` = scope(原样转给 getter、也原样转给被派发者)、`r8` = 第三实参(原样转)。
  ⇒ **它需要 scope**,而且**不自己造 scope**。
- **派发槽**:`call [rax+0x70]`(0x18B7B9D / 0x18B7E5D),不是 `[+0x10]`;锚点直调 0(唯一的直调是
  那个 getter)。`E8` 调用者 **0** 个 ⇒ 只经 vtable 到达。
- **负结论对齐**:§83 已判 `dispatcher_partial`(上游是类自己的 create `0x189A620` + class_info
  vtable);§89 实机把**这一族**整族判出执行路径(16 个月度脉冲内 `0x3B1330` `calls=0`,而 §90.1
  证明它的三个调用者全部沉默)。本卷不新增实机,也不改这两条。
- **不是入口的理由**(两条,任一条足够):① 它**要** scope 才能干活 —— 与「无 scope 也要执行」正好相反;
  ② 它不是月度边界,是 effect 家族的 parse/解释侧槽,而且 §89 的实机读数说它那 150 s 里一次没上过场。

### §3.5 汇总

| 候选 | 入参有 scope? | effect 派发槽? | E8 调用者 | 判 |
|---|---|---|---|---|
| `0x9F5750` | 无(命令记录) | 无(`[+0x38]`/`[+8]`/`[+0xc0]`/`[+0x20]` 布尔槽) | 0(命令表) | 不是入口 |
| `0x9F6420` | 无(命令记录) | **零间接调用** | 6(5 遥测 + 1 事件窗) | 不是入口 |
| `0x9F65E0` | 无(命令记录) | 无(`[+0x38]`/`[+8]`) | 0(命令表) | 不是入口 |
| `0x18B7B70` | **要**(`rdx`=scope,原样转) | 有(`[vptr+0x70]`) | 0(vtable) | 不是入口(§83/§89 原判) |
| `0x18B7E30` | **要**(同上) | 有(`[vptr+0x70]`) | 0(vtable) | 不是入口(同上) |

**「拿得到 effect 对象」与「没有 scope 也能执行」在这里是分开的两件事。** 两个 `+0x70` 候选确实能
拿到一个 effect 对象(`[[getter]]`),但它们把 scope 与 `r8` 原样转给那个对象 —— 「有对象」不等于
「不需要 scope」;而 §3.1–§3.3 三个命令处理器**没有 scope 也不派活**。**没有 scope 又派活的**,五个
候选里一个也没有 —— 这正是要把入口换到月度边界去找的原因(§2.3)。同一条界线在月度那一侧也成立:
`db+0x28` 本身就是一个 CEffect(§2.8),但引擎是「读它的 events 数组」而不是 `Execute` 它 ——
拿到对象这件事,在两个侧面上都不等于能执行。

---

## §4 判决

### §4.1 判词 = `global_entry_named`

入口是 **`0x265DD0`**(`gamestate.cpp` 的月度更新),拿调用的那一跳是它内部的 `0x266F70 → 0x406F90`。

**前提(四条,缺一条这个判词就不成立):**

1. `db+0x28` 是 `on_monthly_pulse` 的缓存定义指针:唯一写它的是 `0x407330`(§2.2,`0x407842`);
   唯一读它的是 `0x265DD0`(§2.3,`0x266F6C`);两个独立口径都没有第二个读者(§2.6)。
2. `0x265DD0` 被**月变**门控:`0x256730` 先算出 `[rsi+0x128] = day_of_year/30`(§2.4,
   `0x256CD6`),再拿月变前的快照 `[rbp-0x38]` 与它比,不等才 `call 0x265DD0`(`0x2570DF`);
   同函数对「年」是另一条门(`0x2571BA` → `0x267870`)。它只有这一个 `E8` 调用点。
3. 它往下**确实派活**:`0x406F90` 读定义对象的 events 数组 + 计数,逐 id 解事件并在
   `call 0x93A780` 之后 `call 0x402C50`;`random_events` 走 `0x406650`(§2.5)。
4. 它**不依赖我们的脚本**:门控只比日期;`db+0x28` 为空只让 `0x406F90` 早退,`0x265DD0` 本身照调。
   vanilla 的 `on_monthly_pulse` 永远存在(它挂在 `00_on_actions.txt`,`§89.1` 已引过),所以这条
   边界在**没有任何我们自己的 mod** 时也每月发生。

**侵入面(计划 Review Focus 2 要求点明的那一格):事件层。** 这条边界派的是
「on_action 定义 → 事件 id」(§2.5),**不是** effect。effect 执行在 `0x402C50` 之下、由事件机器自己
建 scope;那条链我们已经在用(借道 mod 的 `on_monthly_pulse` → `neo_chokepoint.1` → `every_system`),
本卷不碰它。⇒ 「不用脚本」在这里的含义是**在月度边界挂钩**,不是「在 effect 执行层找一个无 scope 的
硬编码槽」—— 后者在 §3 被五个候选否掉了。

**它不是什么(别读过头):**

- **不是回调注册表**:引擎没有「注册一个每月回调」的 API;入口是一个**函数地址**,用它 = 一个 detour,
  detour 这一层侵入面和本项目其它点名 hook 同类(§72 的 `0xCC4220` 就是同形)。
- **不给 scope**:月度 ctx 是就地建的(§2.5),`+8` / `+0x10` 是 0、`+0x30/+0x38/+0x40` 指回自己
  ⇒ 它是「无 scope」的形状。从 `0x265DD0` 的钩子里能拿到的是 **gamestate**(`rcx`)与 ctx,不是可用 scope。
- **不等于「每月恰好一次脉冲事件」**:`0x265DD0` 是**整个**月度更新(6.3 KB),除
  `on_monthly_pulse` 外还有 on_monthly_pulse_country(逐国家)、`on_biomass_monthly`(按名字现查)等。
  拿「每月一次调用」是准的;把「钩子里看到的每一次 `0x406F90`」当脉冲是错的。
- **代价不在本卷的判决里。** 这条答案把「几行脚本 stub」换成了「一枚 detour」——哪一边更划算
  (脚本可被玩家看见、detour 要跟着版本重锚)是产品判断,本卷只回答「入口在哪、长什么样」。

### §4.2 下一发实机的判据(命令级)

**前置(本卷不做)**:`0x265DD0` 不在任何现有 layout 靶里,而 `c2_shim_probe.py` 的 `TARGET_RVA` 是
编译期常量、安装前还会核对靶前 24 B 的序言(`src/` 一个字节不动是本卷的约束)⇒ 下一发的第一步是
在 Zig 侧加一枚**只记计数器 + 返回地址**的靶(与 §72 那条通道同形),然后用同一个驱动:

```
python C:/temp/session_bridge.py --timeout-s 400 C:/temp/c2_shim_probe.py C:/temp/<new>.dll \
  --mask 0 --poll-s 120 --out C:/temp/c5_onmonthly.tsv
```

窗内要做的事:解暂停,跑/快进 **≥ 3 个游戏月**。**分母怎么来(这一格容易踩)**:

- 首选:窗前后各读一次日期字段 `[[0x3260BB0]+0xC0]`(裸小时;`days = hours/24`,
  `year = days/360`,`month = (days - 360*year)/30`,月恒 30 天 —— `runtime_444_game_date_4_4_4.md`
  §3/§4),月差就是「应当有几次」;
- **不要**默认 `It is a new day: `(串 `0x24C0BD8`)会写在 `game.log` 里 —— 那一行在 `0x2567F9`
  之后被 `call 0x1CA3320; test byte [rax+0x38],1` 门住,是「该日志通道开着」才写;
- 借道 mod 的 `PS_HIT`(§89 的 `--marker`)能数,但那要脚本,和本卷「不用脚本」的目的冲突,只作兜底。

**判据(逐条可判,**不含**「看着像」):**

| 读数 | 结论 |
|---|---|
| `calls` == 前后两次日期读数的月差(1:1),且 `caller_rva` 全 = `0x2570E4` | 入口确认;本卷 §2 的静态链被实机坐实 |
| `calls=0` 而月差 ≥ 2 | 靶不在路径上 ⇒ 推回 §2.4,**静态链作废** |
| `calls > 0` 但 `caller_rva` 出现 ≠ `0x2570E4` | 有第二条调用路径 ⇒ `E8` 口径漏了,先补口径再判 |
| `calls == 0` 且月差也 = 0 | 环境档(时钟没走),**不是**证据;重打 |

**备选靶 `0x406F90`**(同一发可二选一):窗内它会被所有 on_action 打上千次(§2.6:84 个
`rcx=db` 站点 + 其它),判法是**过滤**:只数 `rdx == [[0x3374840]+0x28]` 的那些次,应当 == 月数;
好处是同一个钩子还能顺带读到定义对象的名字(`[def+0x18]`,SSO)。

---

## §5 这一卷不能说的(六条,按优先级)

1. **零 shot。** 本卷没有一条实机读数:所有「每月」都是静态判据(月变比较 + 唯一读点)。§4.2 那张表
   是**下一发**的判据,不是本卷的结果。
2. **不推翻 §89。** 那次 `calls=0` 是 `0x3B1330`(以及 §90.1 的三个调用者)在 150 s 窗内的读数;
   本卷说 `+0x70` 不在执行路径,理由是 §3.4 的形状(要 scope、只经 vtable、不是月度边界),
   与它同向 —— 但本卷**没有**新增实机证据。静态与实机冲突时以实机为准。
3. **「拿得到 effect 对象」≠「没有 scope 也能执行」。** 本卷只到 on_action / 事件层;effect 在
   `0x402C50` 之下才出现,那里的 ctx 是自指的、`+0x10` 恒 0。**从月度边界执行我们的 JS 不需要
   effect 对象,但也不等于我们拿到了 scope** —— 这两件事在本卷里始终分开写。
4. **`0x407330` 没有静态调用者**(0 个 `E8` / 0 个 `.rdata` qword / 0 个 `lea`),它旁边三个无
   `.pdata` 的小桩同样零静态引用 ⇒ **「谁在运行时启动那个映射器」本卷答不了**。这不影响执行侧:
   执行侧只读缓存字段,不读名字。
5. **字段读者表里有一行假阳。** `0x86CCB0` 的两行(`[rbx+0x30]`)是线性扫描跟丢 `rbx` 重赋值的产物
   (那个 `[rbx+0x30]` 被当国家/事件 id 查 `0x3261058` 表);`0x874590` 那行同理(入口把 `[rcx+0x18]`
   当国家 id 查 `0x3260FD8`)。它们都落在非 `+0x28` 的字段上,`+0x28` 那一行是紧邻 `load` 的,
   不受影响。判读者表时先看「load 与 site 之间有没有对 base 的重新赋值」。
6. **判决的作用域是「4.4.4 的这份 exe」**(`sha256` 见 `docs/offline-tooling.md` 的前置条件)。
   换版本先按 `evidence/xrefs/anchors_4_4_4.md` 重锚;`0x265DD0` 的「唯一读点」结论尤其脆弱 ——
   它依赖 `0x3374840` 这个全局与 14 行字段布局两件事同时成立。
