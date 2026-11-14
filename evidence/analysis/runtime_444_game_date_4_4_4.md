# Stellaris 4.4.4 —— 游戏日期字段(`[[0x3260BB0]+0xC0]`)的分解

**日期**:2026-11-15 **授权级别**:离线(只读本地 `stellaris.exe` 4.4.4 拷贝;零实机 ——
不起进程、不注入、不 scp)。**计划**:`docs/superpowers/plans/2026-11-15-sdk-api-stub-audit.md`
Task 2。**上游**:`flag_store_4_4_4.md` §2.4(把 `[[0x3260BB0]+0xC0]` 当时间戳的正面读数)、
`save_flag_storage_4_4_4.md` §2(存档 `flags=` 右边的 8 位数)。

**本卷是追加,不改写 `runtime_444_sdk_api_4_4_4.md` 的 §3** —— 那一节当时的判决是「未定形」,
因为只走到「候选字段」这一步。本卷把同一个字段读到了底:**编码、纪元常数、年/月/日分解
全部有站点**,并且用一份真实存档的 flag 时间戳做了独立对账(§3)。§4 给出定形公式。

---

## §1 字段在哪

```console
  0180f93d  mov  r8, qword ptr [rip + 0x1a5126c]  ; -> 0x3260bb0    <-- 日期持有者对象
  0180f944  mov  r9d, 0xffffffff                                   ; "无到期时间"哨兵
  0180f94a  add  r8, 0xc0                                          ; &(holder + 0xC0) = 日期字段
  0180f95f  call 0x141bce180
```

`0x1bce180` 里 `r8 → rdi`,然后 `0x1bce213 mov eax, dword ptr [rdi]` —— **日期就是
`dword[holder + 0xC0]`**。

**`0x3260BB0` 是独立全局,不是 `0x3260B98` 的字段。** 两者只差 `0x18`:
`0x3260B98` 存的是**系统索引对象**指针(解析器 `0x393a0b` 之后 `[rax+0x18]`/`[rax+0x20]`),
`0x3260BB0` 存的是**日期持有者**指针(本卷所有站点都是 `mov rax,[0x3260bb0]` 之后
`[rax+…]`)。同一个 `.data` 段里相邻,不是同一格 —— `offsets.graph` 的注释里已记过这条勘误,
本卷再钉一次。

`0x3260BB0` 有 **5,647 条** RIP 相对引用(`global_xrefs.py` 读数),是本进程最热的全局之一;
`+0xC0` 只是它众多字段中的一个。

---

## §2 分解:三个访问器,同一具身体

日期字段的**官方分解**就在 `0x9AF2C0` / `0x9AF340` / `0x9AF3B0` 三个小函数里(全部 `.pdata`
单块、无循环)。三个函数共用同一段头部:

```console
  009af2c0  mov  edx, dword ptr [rcx]          ; raw = *date
  009af2c7  sub  edx, 0x29c55c0                ; raw - 43,800,000  <-- 纪元常数
  009af2cd  imul edx                           ; magic 0x2AAAAAAB
  009af2d2  sar  r9d, 2                        ;   ⇒ /6 再 >>2 = **/24**  ⇒ 天数
  009af2e4  imul r9d                           ; magic 0xB60B60B7
  009af2eb  sar  r8d, 8                        ;   ⇒ **/360**            ⇒ 年
```

单位由此定死:**raw 以「小时」计,24 小时 = 1 天,360 天 = 1 年**(`0x168` = 360 在本卷
所有调用点反复出现)。两个 magic 常数可以数值验:`2400 × 0x2AAAAAAB` 的高 32 位是 400,
`>>2` 得 100 = `2400/24`;`360 × 0xB60B60B7`(有符号)高 32 位 + 被乘数后 `>>8` 得 1 = `360/360`。

三个出口:

| 函数 | 返回 | 证据 |
|---|---|---|
| `0x9AF340(date)` | **年** = `days / 360` | 尾部 `imul eax,edx,0x168; cmp r8d,eax; setne; sub r9d,eax; mov eax,r9d`(余数非 0 且商为负时向下取整) |
| `0x9AF2C0(date)` | **年内第几天**(0 基,`0..359`)= `days - 360*year` | 同一段尾部,`sub r9d, eax` 用的是**天数**而不是商 |
| `0x9AF3B0(date)` | **绝对天序号** = `year*360 + day_of_year` | 函数体只有四条:`call 0x9af340` → `imul r10d,eax,0x168` → `call 0x9af2c0` → `add eax,r10d` |

调用量:`0x9AF340` **156** 个 `call`、`0x9AF2C0` **161** 个(直接扫 `E8 rel32`)。所以这不是
「某个功能自己拼的算术」,而是全引擎共用的日期分解原语。

### §2.1 月与日:30 天一个月

```console
  0026bc0c  call 0x1409af2c0                   ; eax = day_of_year
  0026bc13  cmp  eax, 0x1e                     ; < 30 ?
  0026bc1a  mov  eax, 0x88888889
  0026bc1f  mul  ecx                           ; ecx = day_of_year
  0026bc21  shr  edx, 4                        ; edx = day_of_year / 30  = 月(0 基)
  0026bc2a  imul ebx, edx, 0x1e                ; 月的起始 day_of_year
```

`0x88888889 >> 4` 是 `/30`。同一形态在 `0x2568be`、`0x256cbc` 各出现一次(后者还把
`day_of_year/30` 存进 `[rsi+0x128]`,紧接着 `mov ecx,[r12]; sub ecx,0x29c55c0;
imul 0x2aaaaaab; sar edx,2` —— 与本卷 §2 的头部逐条相同)。

⇒ **12 个月 × 30 天 = 360 天**。每月恒为 30 天,没有 28/31。

### §2.2 加偏移的写法(同一编码的另一面)

`0x9AF200` 一带是「日期 + N」的算术:先 `imul edx, ecx, 0x168`(年 → 天),再
`lea eax, [rdx + rdx*2]; shl eax, 3`(×24,天 → 小时)后 `sub ecx, eax` / `lea eax, [rcx + r8*8]`
把结果写回 `[rbx]`。**只有「raw 是小时」时这两个 24 才对得上** —— 这是 §2 那个 `/24` 的
独立旁证。

---

## §3 与真实存档对账(独立 oracle,不需要实机)

`save_flag_storage_4_4_4.md` §2 逐字抄下了一份 `autosave_2272.07.01.sav` 的 flag 块:

```
flags=
{
    AI_hub=62808000
    AI_system_2=62808000
    precursor_1=62808000
    neo_tier1=63313440
}
```

写 flag 的那条链(`0x180f8e0` → `0x1bce180`)存的正是 `dword[holder+0xC0]` 本身
(§1:`0x1bce213 mov eax,[rdi]`,而 `rdi` = `&holder+0xC0`) ⇒ **这两个 8 位数就是 raw**。
把它们代进 §4 的公式:

| raw | `raw − 0x29C55C0` | `/24` = 天 | 年 = `days/360` | 年内天 | 月 | 日 | 解出的日期 |
|---|---|---|---|---|---|---|---|
| `62,808,000` | 19,008,000 | 792,000 | **2200** | 0 | 1 | 1 | **`2200.01.01`** |
| `63,313,440` | 19,513,440 | 813,060 | **2258** | 180 | 7 | 1 | `2258.07.01` |

**对账的意义 —— 这一条不是「落在窗口内」,而是「落在已知的那个点上」**:`AI_hub` /
`AI_system_2` / `precursor_1` 是**银河生成阶段**设的 flag,而 Stellaris 的开局日期就是
`2200.01.01`;公式给出的正是 `2200.01.01`,天序号 `792,000 = 2200 × 360`(整)。两份 raw
减去纪元常数后**都能被 24 整除**(余数 0)—— 单位是「小时」这件事在这里第二次被确认。
`neo_tier1` 解出 `2258.07.01`,在这份 `2272.07.01` 的存档之内、且晚于开局。

这一条同时给 §5.2 的「+1 显示口径」上了**独立支撑**:如果月/日不该 +1,`doy = 0` 会写成
`2200.00.00`,而不是游戏里人人见过的 `2200.01.01`。

---

## §4 定形公式(读法)

```
holder = qword[RVA 0x3260BB0]            ; 0 ⇒ 战役未载入
raw    = dword[holder + 0xC0]            ; 单位 = 小时

hours  = raw - 0x29C55C0                 ; 有符号;i64
days   = floor(hours / 24)               ; 绝对天序号(0x9AF3B0 的口径:year*360 + doy)
year   = floor(days / 360)
doy    = days - 360 * year               ; 0..359
month  = doy / 30                        ; 0..11(**引擎内部 0 基**)
dom    = doy % 30                        ; 0..29(**引擎内部 0 基**)
```

站点对照:`RVA 0x3260BB0`(`0x180f93d`、`0x26d69a`、`0x26e19f`、`0x31f152`、`0x32687e`、
`0x3a040b`)、`+0xC0`(`0x180f94a` 的 `add r8,0xc0`)、纪元常数 `0x29C55C0`(`0x9AF2C7`)、
`/24`(`0x9AF2D2`)、`/360`(`0x9AF2EB`)、`/30`(`0x26BC21`)。

---

## §5 边界(**不能**说的事)

### §5.1 纪元的「身份」只到「内部日历的 0 年 0 天」
`0x29C55C0` = 43,800,000 = 24 × 1,825,000 天。按 §4 的公式,`raw == 0x29C55C0` 时 `days = 0`
⇒ 它就是**内部日历的 year 0 / day 0**(不是某个真实历法的原点)。它与游戏内年份的关系由
`days = 792,000 ↔ 2200.01.01`(§3)这一条钉住,本卷不引入第二个偏移,也不解释「year 0 对应
现实哪一年」—— 对读日期不需要。

### §5.2 月/日的 **+1 显示口径**:有独立支撑,但仍不是「读到那条 +1 指令」
引擎内部是 0 基(`doy/30`、`doy%30`;`0x26bc0c` 先 `cmp eax,0x1e` 再除)。对外字符串里的 +1
在本卷里由 §3 的 `2200.01.01` 支撑(`AI_hub` 是银河生成期设的 flag,开局日期是游戏事实)。
**仍然不能说**的是「我们读到了把 0 基转成 1 基的那条指令」—— 没有;这条是**由产物反推**的。

⇒ 要把它变成读数:拿一份**在存档当天设过 flag** 的存档,`flags=` 里的 `raw` 应当解出
`date=` 那一天(而不是前一天)。

### §5.3 没有实机读数
全部是静态字节 + 一份存档。活体上「`[0x3260BB0]` 今天仍指向日期持有者」依赖
`runtime_444_graph_runtime.md` 那次实机读数家族的同类推理,本卷**没有**重打。

### §5.4 `+0xC4` 不是日期
同一个持有者的 `+0xC4` 被 100+ 个站点读,形态是 `(raw_other + n) % d == 0` 的**周期判断**
(`0x265b98`、`0x265d19`),不是日期本体。本卷不解释它。

---

## §6 复现

```bash
python3 scripts/disrva.py 0x9AF2C0 --len=0x60     # day_of_year 访问器
python3 scripts/disrva.py 0x9AF340 --len=0x60     # year 访问器
python3 scripts/disrva.py 0x9AF3B0 --len=0x30     # year*360 + day_of_year
python3 scripts/disrva.py 0x26BC00 --len=0x30     # 月 = day_of_year / 30
python3 scripts/disrva.py 0x31F152 --len=0x18     # date + 24*n
python3 scripts/disrva.py 0x180F93D --len=0x28    # &holder + 0xC0
python3 scripts/scratch/2026-11_dirty_bit/global_xrefs.py 0x3260BB0   # 5,647 条引用
```
