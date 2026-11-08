# Country scope 字段层:静态取证(4.4.4,离线,零 shot)

**这份文件回答什么。** `country_scope_4_4_4.md` §8 留下的两个 unresolved:
能量币在国家对象里的**读取链与索引**、opinion 关系值的**查表与值偏移**。本卷只读
`stellaris.exe` 拷贝(4.4.4,sha256 `9242c40a…b1a56`),零进程、零注入、零 shot。

**三条纪律(与计划一致):**

1. **不猜地址。** 每条读数都能用本节写下的命令复算;等级 = A(双侧证人)/ B(单侧)/ C(只有形状)。
   **C 级不进 `onCountry` 契约、不进写路径。**
2. **docstring 只用来选 donor。** 语义由 body 的读点证明;本卷里凡"doc 说的"都单独标出来。
3. **判负也算交付。** 读不到就写 `blocked_on = <指令地址 + 缺什么数据>`,不拿一个"看起来对"的偏移凑。

**复算纪律的一个偏差(先写在这里)。** 计划 Step 3/5/6 里的 `disrva.py 0x… 0x…` 把**结束 RVA**
当第二参传;`disrva.py` 的第二个裸参数按 `parse_range` 是**字节长度**(且 >0xFF 走 `legacy_len`),
`0x1b27050` 会被当成 28 MB ⇒ 会打出几十万条指令。本卷一律用显式形式
`python3 scripts/disrva.py <start> --end=<end>`,读数区间与计划意图相同(计划里的第二参恰好等于
`start + 对象 size`,见 §1.1)。

**一次性扫描。** `scripts/scratch/2026-11_country_fields/dispscan.py …`(只读 `.pdata` 对齐的全量
`.text` 位移扫描;属于本卷 §1/§2,不是维护中工具)。它为"某个对象偏移被哪一族代码读写"提供
**穷举**而不是抽样 —— §1.6 的冲突与 §2.5 的反例都靠它。

---

## §1 能量币:两个量、两条链(§1 判决)

### §1.1 输入:五个 donor 的登记行(计划 Step 1 / Step 2)

```bash
awk -F'\t' '$5==18233 || $5==18250 || $5==18141 || $5==10123 || $5==11687' \
  evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv
```

| token | keyword | class_info | factory | size |
|---|---|---|---|---|
| 18233 | `has_country_resource` | `0x269e298` | `0x1b26d70` | `0x2e0` |
| 18250 | `has_monthly_income` | `0x269dcf8` | `0x1b27970` | `0x2f0` |
| 18141 | `income` | `0x269ebb8` | `0x1b242b0` | `0x2a8` |
| 10123 | `export_resource_stockpile_to_variable` | `0x2608d28` | `0x18a6f60` | `0xf8` |
| 11687 | `add_resource` | `0x260e520` | `0x189d0d0` | `0x308` |

```bash
for a in 0x269e298 0x269dcf8 0x269ebb8 0x2608d28 0x260e520; do
  grep -m1 "^$a	" evidence/xrefs/class_info_census_4_4_4.tsv; done
```

五个 factory 的 `.pdata` 长度是 `0x69 / 0x8a / 0x43 / 0x84 / 0x8e`
(`python3 scripts/pdata.py 0x1b26d70 0x1b27970 0x1b242b0 0x18a6f60 0x189d0d0`)。
**这五个函数都只是构造函数**:`operator_new(size)` → `memset` → 基类 ctor → `lea rax,[vtable];
mov [obj],rax` → 字段清零。census 的 `arg_reads` 五格全是 `False`,与此一致。

### §1.2 一个必须先说清的偏差:取值点不在 factory 里

计划 Step 3 的 Expected 写的是「`call` 目标里出现 `0x1ababb0` 与/或一个明显的取值序列」。
`0x1ababb0` 是**基类构造函数**(census 的 callee 列,五个 factory 里四个都调它),它出现在
factory 里**不指示任何读点**;factory 体内也**没有** `[obj+X]` 的取值读。

真正的取值点在 vtable 里,而且**每一个 class 分三层**(与 `country_scope_4_4_4.md` §14 的
per-class vtable 派发一致,`Review Focus 1` 说的就是这件事):

| 槽 | 作用 | 本卷用它做什么 |
|---|---|---|
| `+0x18` slot[3] | 比较体(operator + 阈值) | 判"走的是哪条 API" |
| `+0x28` slot[5] | 共享求值包装(`0x1a92450 → jmp 0x348db0`) | 只用来确认它是 trigger 类,不取值 |
| `+0xe0` slot[0x1c] | 描述符 | 不用 |
| **`+0xf0` slot[0x1e]** | **取值体(返回 qword)** | **§1.3 / §1.5 的全部读数** |

`slot[3]` 调 `[self_vtable+0xf0]` 拿当前值,再按 `[self+0x78]` 的 operator 选
`sete/setl/setg/setle/setge/setne` 之一去比阈值 —— 六个 enum 的映射在同族三个函数里逐字相同
(`0x1a92090` / `0x1adf440` / `0x1ae3d20`;`1`=`==`,`0x1d3`=`>`,`0x1d4`=`<`,`0x3cb`=`>=`,
`0x3cc`=`<=`,`0x426`=`!=`)。

### §1.3 存量(stockpile)读侧:`has_country_resource`

```bash
python3 scripts/vtable.py 0x26a0a20 --slots 40        # has_country_resource 的 vtable
python3 scripts/disrva.py 0x1adf690 --end=0x1adf7af   # slot[0x1e] = 取值体
python3 scripts/disrva.py 0x1adf440 --end=0x1adf687   # slot[3]  = 比较体(两条 API 分支)
```

`has_country_resource` 的 vtable 是 `0x26a0a20`(factory 的 `lea rax,[0x26a0a20]; mov [obj],rax`),
size `0x2e0`。取值体 `0x1adf690` 逐条:

```
01adf6b0  call 0x393dd0            ; country = resolve(ctx);见 §1.7 的解析器
01adf73b  rcx = [rbx+0x2c68]       ; ← 资源持有者(economy)子对象
01adf745  call [rax+0x80]          ; 有效性门;无效则换成全局 0x325ff70
01adf767  call [rax+0x90]          ; ← **填充调用方提供的向量**(rcx=持有者, rdx=&vec, r8=0)
01adf76d  rax = [rsi+0x2d8]        ; 触发器对象里存的"资源对象"
01adf774  movsxd rcx,[rax+0x18]    ; ← **资源索引 = 资源对象 +0x18**
01adf77c  cmp ecx,[vec+0xc]        ; 界:count 在 vec+0xc
01adf785  rax = [vec]              ; data
01adf788  lea rax,[rax+rcx*8]      ; ← **8 B 步长**
01adf795  rax = [rax]              ; 越界改读 0x26dc028(零)
```

比较体 `0x1adf440` 里有两条路,而且**只对 `>` / `>=` 走向量路**:

- `eax ∈ {0x1d3, 0x3cb}`(`>`,`>=`)⇒ 造一个 `n = [0x33746f0+0x14]` 长的零向量,
  把阈值写进 `[r8 + [[self+0x2d8]+0x18]*8]`,再 `call [econ_vtable+0xb8]`(0x1adf578):
  "库存是否 ≥ 这些量"(向量里其余槽是 0,天然满足 ⇒ 这个 API 只能表达"至少")。
- 其余 operator ⇒ 走 `call [self_vtable+0xf0]` 拿标量再比(即上面 `0x1adf690` 那条)。

### §1.4 存量写侧:`add_resource`(只读,不执行)

```bash
python3 scripts/disrva.py 0x189d0d0 --end=0x189d15e   # factory(只发布 vptr)
python3 scripts/vtable.py 0x25fa4c0 --slots 26         # effect vtable
python3 scripts/disrva.py 0x1870f90 --len=0x100        # slot[2] 入口
python3 scripts/disrva.py 0x1870ff0 --len=0x100        # 真正的 Execute
python3 scripts/disrva.py 0x8437b0 --end=0x8439f7      # ← 写库函数
```

链路:`0x260e520 → 0x189d0d0(factory) → vptr 0x25fa4c0 / 0x25f7148(+0x8) → slot[2]
0x1870f90 → 0x1870ff0 → 0x8437b0(country, 0, 0, &[self+0xc0]))`

`0x8437b0` 的读写点与 §1.3 **同一个容器、同一个索引字段、同一个步长**:

```
00843858  rax = [rcx]                      ; rcx=r13=持有者;读出现值
0084385f  call [rax+0x90]                  ; ← 同一个填充调用
00843904  movsxd rdx,[rsi+0x18]            ; ← 同一个 +0x18 索引字段
0084390f  add qword ptr [rcx+rdx*8], rbx   ; ← 同一 stride 8,累加
0084399b  call [rax+0x98]                  ; ← **写回**同一容器
```

资源表本身:`0x33746f0`(`[+0x14]` = 条数 dword,`[+8]` = 资源对象指针数组)。

### §1.5 收入(income)`income` / `has_monthly_income`:另一条链,另一套容器

```bash
python3 scripts/vtable.py 0x26895f0 --slots 40          # income
python3 scripts/disrva.py 0x1ac52f0 --end=0x1ac5345     # income 的 slot[0x1e] = 取值体
python3 scripts/vtable.py 0x267f6d0 --slots 34          # has_monthly_income
python3 scripts/disrva.py 0x1ae3d20 --end=0x1ae3df0     # 它的 slot[3]
python3 scripts/disrva.py 0x1ae3df0 --end=0x1ae3e91     # 它的 slot[0x1e]
```

`income`(能量专用,parse 只注册 `COMPARE`/`VALUE` 两个参,没有 resource 参 —— 见
`0x1ac5350` 的 `INCOME_TRIGGER`)取值体 `0x1ac52f0`:

```
01ac52f4  rax = [0x33746f0]        ; 资源表
01ac52fb  rcx = [rax+0x20]         ; ← 表里那一格(**就是 energy**,见 §1.6)
01ac52ff  r9  = [rcx+0x18]         ; ← 同一个 +0x18 索引字段
01ac5310  rax = [country+0x2530]   ; ← **容器指针**(月度收入)
01ac5317  cmp r9d,[rax+0xc]        ; count 在 +0xc
01ac5320  rax = [[rax]+r9*8]       ; ← 8 B 步长
```

`has_monthly_income` 的 slot[0x1e] `0x1ae3df0` 同形,但容器是 **`[country+0x2570]`**,
索引来自 `[self+0x2b0]+0x18`(parse 期按名字解析出来的资源对象)。

### §1.6 能量索引:对象身份 A,数值 C(两条独立证据)

**A:`0x33746f0+0x20` 就是 energy。** 资源库的初始化函数 `0x3b7da0` 用一组固定名填固定槽,
其中一格**逐字**是 `energy`:

```
003b8640  lea r8,[r14+0x20]                     ; ← db+0x20
003b8644  lea rdx,[0x248a504]                   ; ← "energy"
003b864e  call 0x3b8750                         ; db+0x20 = find(db, "energy")
```

`0x3b8750(db, name, out)` → `0x3b8820`(`[db+0x14]` 条数 / `[db+8]` 数组 / 资源对象
**名字在 `+0x30`**)按名查,`*(out)=obj`,再 `obj->vfn[+0x38]()` 有效性门,失败打
"resource … does not exist"。同一段还填了 `+0x18=biomass`、`+0x28=influence`、`+0x30=food`、
`+0x38=minerals`、`+0x40=alloys`、`+0x48=physics_research`、`+0x80=trade`。

⇒ `energy_index = [[0x33746f0]+0x20]+0x18` 的**对象身份 A**;`income` 用它而 `income` 只可能
是能量(没有 resource 参 + docstring),两侧互证。

**C:那个 `+0x18` 的数值。** 资源对象的 `+0x18` 是注册期写进去的序号,`0x33746f0` 整块在
`.data` 的**未初始化尾部**(`0x2954000+0xd9200` 之后),**文件里是零**,静态读不到。
游戏数据侧唯一可机器读的候选:`common/strategic_resources/00_strategic_resources.txt` 里
`energy` 是第 1 个条目(共 26 条,`grep -c '^[a-z_]* = {'` = 26)

```bash
grep -n "^[a-z_]* = {" /var/lofibass_ssd/data/stellaris/4.4.4/common/strategic_resources/00_strategic_resources.txt | head -3
# 18:energy = {   / 39:minerals = {   / 60:food = {
```

—— 若"注册顺序 = 文件顺序",energy 的候选值是 **0**。但**"文件顺序 → `+0x18`"这一条没有静态
证人**(赋值点在注册循环里,不在 `0x3b7da0` 的可见路径上),所以这个 **0 只是候选,标 C,
不进契约**。§3 的 live-probe 用一次读把 C 升 A(读 `[[0x33746f0]+0x20]+0x18`,再读
`[[0x33746f0]+8+0*8]+0x18` 对照)。

### §1.7 冲突与"读的是哪个量"(计划 Step 5/6 的判读点)

**冲突 1(不许择一):"月度收入"有两个容器。**
`income` 读 `[country+0x2530]`,`has_monthly_income` 与 `resource_income_compare`(`0x1ac5890`)
读 `[country+0x2570]`。两者形状完全相同(指针 → `{data@+0, count@+0xc}`,8 B 元素),**偏移不同**。
静态链不能判哪个是净收入、哪个是总收入;本卷**两个都记,都不进契约**。

全量位移扫描(`dispscan.py 0x2530 0x2570`)的读数:

```bash
python3 scripts/scratch/2026-11_country_fields/dispscan.py 0x2530 0x2570
# 0x2530: 7 处(其中 3 处是 rsp 帧,真对象读 = 0x7679c3 / 0xbd8986 / 0x176fe1e / 0x1ac5310)
# 0x2570: 15 处(真对象读 12 处,含 has_monthly_income 族 3 处与 0x1ac58b0)
```

`0x176fe1e` 那条还多一条语义线索:它读 `[country+0x2530][i]` 后
`sub rcx,[r15+0x2650]`、`cmovg` 取正部再累加 —— `0x2650` 是同一个 country 上的一个 qword 标量。
这仍然**不能**判 `0x2530` 是收入还是库存,只说明它是"逐资源、按索引、8 B"的量。

**冲突 2(计划预期不成立):`export_resource_stockpile_to_variable` 不是第三个证人。**
它不走 `index*stride`:`0x18aafd0`(ExecuteActual)把 `self+0xc0` 交给 `0x18ba120` /
`0xa56ae0`,后者是一条 **scripted-variable 写手**链,资源对象只是经 `0x3b8820` 按名解析出来
(`0x18c2970`: `rcx=[0x33746f0]; call 0x3b8820; … jmp [rax+0x38]`)后当断言用。
所以本卷对"通用体索引来源"的对照证人只有 `add_resource`(§1.4)与 `has_country_resource`
(§1.3),**不是三条**。

**读的是哪个量(计划 Step 6 的判据)。** 写路径(`add_resource`)与读路径
(`has_country_resource`)落在**同一个容器、同一 stride、同一索引字段** ⇒ 这一对确实是
**存量**;`income`/`has_monthly_income` 的容器**没有写路径**(它是每月重算的派生值)。两者不能混。

**值的标度。** 存量值是 64 位定点:比较体里有 `imul rax,rcx,0x186a0`(×100000,
`0x1afed43`)与 `movabs 0x29f16b11c6d1e109` + `sar 0xe`(÷100000,`0x1afecf4`/`0x1afed58`)。
⇒ `host` 侧 `value / 100000` 才是"个"。`income` 容器是同一 qword 域,但它的比较路径里没有这条
乘法,**标度未单独证明**(候选:同 1e5)。

### §1.8 `EnergyRead` 判决行

```
EnergyRead = virtual(stockpile) + inline(income)
country_stockpile_holder_offset = 0x2c68        (grade B:两条独立链都读 [country+0x2c68])
stockpile_container               = blocked_on = 0x1adf767 (`call [rax+0x90]`) 与 0x84385f 同一调用;
                                   缺的是 [country+0x2c68] 指向对象的 vtable —— 它只在运行期被赋值
                                   (静态写点只有清零 0x11b055b 与 0x71a0be 的全局默认 0x325f650),
                                   所以 +0x90/+0x98 的槽目标离线拿不到
stockpile_element_stride          = 8 B        (grade A:读 0x1adf788 / 写 0x84390f)
stockpile_scale                   = 100000     (grade B+:`0x1afed43` ×0x186a0 + `0x1afecf4` ÷1e5 魔数)
stockpile_index_field             = [resource_obj+0x18], grade A (读 0x1adf774 / 写 0x843904)
income_container_offset           = 0x2530     (grade B:单侧;另一族同形读 0x2570 ⇒ 冲突 1)
income_element_stride             = 8 B        (grade A:0x1ac5320)
energy_object                     = [[0x33746f0]+0x20]  (grade A:0x3b8640 + "energy")
energy_index                      = [[0x33746f0]+0x20]+0x18  (grade C:数值只在运行期存在;
                                   文件序候选 0,未证)
```

**这一节不能说的:**

1. `stockpile` 没有"裸偏移"。`[country+0x2c68]` 是**指针**,量是经 virtual `+0x90`**填充到调用方
   向量**的(写出用 `+0x98`),所以任何 `[country+X]` 形式的"库存偏移"都会是编的。
2. `0x2530` / `0x2570` 只证明"逐资源、8 B、按 `+0x18` 索引";哪一个叫 income 没证。
3. `energy_index` 的 **0** 是游戏数据顺序的候选,不是读数。
4. `income` 的标度没单独证明。
