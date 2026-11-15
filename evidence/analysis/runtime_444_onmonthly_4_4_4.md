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
  在 `[db+8]` 的链式桶里查重,命中就 `call [vptr+0x18]`(重复定义路径)然后 `jmp` 继续;
- 未命中才 `new(0x68)`,写 vptr `0x24EEE08`、名字(SSO 容量 `0xf` 在 `+0x30`)、两个次基
  vtable(`0x247A488` @`+0x38`、`0x247A530` @`+0x50`),再插桶 + 写固定字段。

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
00256cc6  cmp  eax, 0x1e                 ;   /30 之前先按 30 分支
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

`0x406F90` 只有 `0x2D` 字节本体 + 两块链式片段(`0x406FDD..0x4070E1`、`0x4070FD..0x40718C`),
两块里各有一条字符串:`Perform OnAction %s Trigger Event %s`(`0x24EEB68`)、
`Perform OnAction %s Trigger Random Event %s`(`0x24EEB38`),文件是 `onaction.cpp`。它做的事:

1. `movsxd rax,[rdx+0x64]` / `rbx=[rdx+0x58]` ⇒ 定义对象的 **events 数组 + 计数**;
2. 每个 4 B 值按 `id = namespace*100000 + index` 解(`imul eax,edx,0x186a0`),用事件库
   `0x3374838`(域数 `+0x3c`、行表 `+0x30`、**stride 0x18**、行内 `+8` 数组 / `+0x14` 计数)
   取事件对象;
3. `call 0x93A780(event, ctx)`(布尔门,`test al`)⇒ `call 0x402C50`(触发事件);
4. 之后 `call 0x406650(def, ctx)` 处理 **random_events**:`[def+0x4c]` 是 random 计数,内部按
   `[ctx+8]`(`0x80` / `2` / `0x10` / `0x20` ⇒ scope 种类)分派不同的挑选路径。

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
  未命中走 `0x24EEB90` 那条诊断。这是引擎「按名字触发 on_action」的统一入口(82 个站点:
  `on_pop_bombed_to_death`、`on_debris_scavenged`…)。
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

---

