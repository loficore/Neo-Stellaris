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
`0x1ababb0` 是**基类构造函数**(census 的 callee 列,五个 factory 里三个调它),它出现在
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
0x1870f90 → 0x1870ff0 → 0x8437b0(country, 0, 0, &[self+0xc0])`

`0x8437b0` 的读写点与 §1.3 **同一个容器、同一个索引字段、同一个步长**:

```
00843858  rax = [rcx]                      ; rcx=r13=持有者;读出现值
0084385f  call [rax+0x90]                  ; ← 同一个填充调用
00843904  movsxd rdx,[rsi+0x18]            ; ← 同一个 +0x18 索引字段
0084390f  add qword ptr [rcx+rdx*8], rbx   ; ← 同一 stride 8,累加
0084399b  call [rax+0x98]                  ; ← **写回**同一容器
```

资源表本身:`0x33746f0`(`[+0x14]` = 条数 dword,`[+8]` = 资源对象指针数组)。

### §1.5 收入:`income` / `has_monthly_income` —— 另一条链,另一套容器

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

---

## §2 opinion 关系值:一张行主序的 int32 缓存矩阵(§2 判决)

### §2.1 输入:三个 donor + 一个反例(计划 Step 1 / Step 2)

```bash
awk -F'\t' '$5==11614 || $5==18076 || $5==11615 || $5==18176' \
  evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv
for a in 0x269ee08 0x269edb8 0x269ed98 0x269e518; do
  grep -m1 "^$a	" evidence/xrefs/class_info_census_4_4_4.tsv; done
```

| token | keyword | class_info | factory | size | vtable |
|---|---|---|---|---|---|
| 11614 | `opinion` | `0x269ee08` | `0x1b21900` | `0x448` | `0x2696428` |
| 18076 | `their_opinion` | `0x269edb8` | `0x1b21a10` | `0x448` | `0x2696610`(先写 `0x2696428` 再覆盖) |
| 11615 | `opinion_level` | `0x269ed98` | `0x1b21960` | `0x220` | `0x2696520` |
| 18176 | `has_opinion_modifier`(**反例**) | `0x269e518` | `0x1b24b40` | `0x258` | `0x26a10f0` |

factory 长度 `0x51 / 0x5b / 0x5c / 0x7a`(`python3 scripts/pdata.py`),四个都只是构造函数。
`their_opinion` 的 factory 先 `mov [obj],0x2696428` 再 `mov [obj],0x2696610` —— **方向不是运行时
flag,是 vtable 换了一个**(`0x2696610` 只覆盖 parse 与 slot[0x1e] 两格)。

### §2.2 读点:三件事分别读出来(计划 Step 3)

```bash
python3 scripts/vtable.py 0x2696428 --slots 36        # opinion
python3 scripts/disrva.py 0x1ab04f0 --end=0x1ab05b1   # opinion 的 slot[0x1e] 取值体
python3 scripts/vtable.py 0x2696610 --slots 36        # their_opinion
python3 scripts/disrva.py 0x1ab1340 --end=0x1ab1401   # their_opinion 的 slot[0x1e]
```

`opinion` 的 slot[0x1e] `0x1ab04f0`(**`str "opinion target"`**):

```
01ab050c  call 0x393dd0                     ; rdi = "我们"这个国家对象
01ab0529  call 0x35eee0                     ; rbx = 目标国家对象(self+0x2a8, ctx, self+0x40, "opinion target")
01ab0581  r8  = [0x33794d0]                 ; ← **表描述符全局**
01ab058d  ecx = [rbx+0x20] & 0xffffff       ; ← **row = 目标国家 id**(24 位截断)
01ab0590  eax = dword [r8]                  ; ← **n = 行数(也是列数)**
01ab059d  edx = [rdi+0x20] & 0xffffff       ; ← **col = 我们 id**
01ab05a8  cmp/jae  ecx,eax / edx,eax        ; 双向界检查
01ab05aa  imul  ecx,eax                     ; row * n
01ab05b6  add   ecx,edx                     ; + col
01ab05b8  rax  = [r8+8]                     ; ← **矩阵基址**
01ab05bc  eax  = dword [rax + rcx*4]        ; ← **元素 4 B,值就在元素里**
01ab05bf  cmp   eax,0x7fffffff              ; ← **0x7fffffff = "没算过"**
01ab05cf  call  0x743bb0 (rcx=我们, rdx=目标) ; 现算
01ab05d4  mov   [rsi],eax                   ; 顺手写回缓存
```

`their_opinion` 的 `0x1ab1340` **逐指令同形,只有两个操作数互换**:
`0x1ab13dd` 取 `[rdi+0x20]`(我们)当 **row**,`0x1ab13ed` 取 `[rbx+0x20]`(目标)当 **col**;
重算调用的两个实参也跟着互换(`0x1ab1421`:`rcx=rbx=目标, rdx=rdi=我们`)。

⇒ 三件事都读到了:键 = `row*n+col` 的 24 位国家 id 对;基址 = `[[0x33794d0]+8]`;
元素 = `4 B`;值偏移 = `0`(元素本身)。

### §2.3 方向:两侧互为转置(A);"谁对谁"只到 B(计划 Step 4 的判据)

| 键 | `opinion` | `their_opinion` |
|---|---|---|
| `row`(乘 n 的那一个) | **目标**国家(`[rbx+0x20]`) | **我们**(`[rdi+0x20]`) |
| `col`(加上的那一个) | **我们**(`[rdi+0x20]`) | **目标**(`[rbx+0x20]`) |
| 重算实参 `0x743bb0(rcx,rdx)` | `(我们, 目标)` | `(目标, 我们)` |

**A:两格互为转置。** 同一份代码的两个变体在**同一条链**上给出相反的键序;`0x743bb0` 的实参
也跟着换;`0x743bb0` 自己再把两个国家各包一个 `{type=4, id=[obj+0x20]}` 的 scope
(`0x743ecb` 用 `[rsi+0x20]`、`0x743ef9` 用 `[r14+0x20]`)交给 `0x7440a0`。**这三处都是"转置"的
证人,不是"哪一向"的证人。**

**B:哪一向叫"我们对他们"。** 两个 docstring 说 `opinion` 是"the country's opinion of the target"、
`their_opinion` 是"target country's opinion of the current country";重算实参的顺序(`opinion`
传 `(我们,目标)`,自然读法是"第一个是持有者")也与之一致。但**矩阵内部约定**
(格子 `[row][col]` 到底存"row 对 col"还是"col 对 row")**没有独立的静态证人** ——
按 `Review Focus 5` 的规矩,这一条**不许靠命名定**,所以标 **B**。

⇒ 契约侧的做法:按**引擎自己的名字**暴露两格(`opinion` / `their_opinion`),把"人话方向"标成
待定,由 §3.2 的**不对称国家对**在实机上定;不要写成 `us/them`。`opinion_level` 用两格之和
(§2.4),天然不受这条影响。

### §2.4 比较器:`opinion_level` 用的是同格之和(计划 Step 4 的后半)

```bash
python3 scripts/vtable.py 0x2696520 --slots 34          # opinion_level
python3 scripts/disrva.py 0x1ab08e0 --end=0x1ab0997     # slot[3] 比较体
python3 scripts/disrva.py 0x1ab0ea0 --end=0x1ab0f20     # 它调的取值/分级体
python3 scripts/disrva.py 0x1ab1050 --len=0x80          # 分级梯子
```

`0x1ab0ea0` 在**一个函数里同时**读了两格:

```
01ab0f6e  imul eax,ebp                 ; target_id * n
01ab0f7b  add  eax,r15d                ; + self_id      → [target][self]
01ab0faf  imul ecx,r15d                ; self_id * n
01ab0fb3  add  ecx,ebp                 ; + target_id    → [self][target]
01ab0fd8  add  eax,r12d                ; ← **两格相加**
01ab1033  cmp  eax,[0x326179c]         ; level 4
01ab1044  cmp  eax,[0x3261790]         ; level 3
01ab1050  cmp  eax,[0x3261794]         ; …
01ab105c  cmp  eax,[0x326178c]         ; 最低一档
```

`opinion_level` 的阈值是 **BSS 里的四个 dword**(`0x3261790/94/9c/8c`,文件里为零 ⇒ 运行期灌),
所以"level 的阈值"本卷给 **C**;但"level 建立在两格之和上"是 **A**(同一函数内两个方向的索引
都在,谁也不可能靠命名伪造)。

`0x1ab08e0` 再拿这个 byte 与 `[self+0x7c]`(脚本常量,`opinion_level` factory 里默认 `5`)
按 operator 比(`[self+0x78]`),`sete/setl/setg/setle/setge/setne` 六个分支与 §1.2 的 enum 同形。

### §2.5 反例:modifier 容器 ≠ opinion 表(计划 Step 5,Review Focus 4)

```bash
python3 scripts/vtable.py 0x26a10f0 --slots 34          # has_opinion_modifier
python3 scripts/disrva.py 0x1ac8f70 --len=0x120         # slot[3] 求值体
python3 scripts/riprefs.py 0x33794d0 --verify           # ← 全量 rip 引用
```

`has_opinion_modifier`(**`str "HAS_OPINION_MODIFIER"`**)的容器是**链式列表**:

```
01ac8fa2  call 0x393dd0                 ; country
01ac8fb1  rcx = [country+0x2c78]        ; ← 另一个子对象(不是 §1.3 的 +0x2c68)
01ac8fd5  rbp = [holder+0x10]
01ac8fdb  n = [rbp+0x2d84]              ; 外层条数
01ac8ffb  e  = [[rbp+0x2d78] + i*8]     ; 外层 = 指针数组
01ac901d  m = [e+0x24]                  ; 内层条数
01ac9026  list = [e+0x18]
01ac9037  cmp [list[j]+8], rdi          ; ← 比的是 **[self+0x218] 那个 modifier 句柄**
```

`riprefs 0x33794d0` 的读数把这条反例钉成**穷举**而不是抽样:

```
== 12 refs to 33794d0 (.text) [verified] ==
  func 265dd0..2676af / bee450..bee6b1 (各 3) / bfe0c0 / c079d0 / c16bea
  func 1ab04f0..1ab05b1 (opinion) / func 1ab0f20..1ab0f3d / func 1ab1340..1ab1401 (their_opinion)
```

**8 个函数、12 条引用,0x1ac8xxx 族一个都没有。** ⇒ `modifier_container != opinion_table`,
不是"看起来不同",是全表扫过没有。

### §2.6 写路径:值不是被"写"进去的,是**懒填缓存**(计划 Step 6)

```bash
awk -F'\t' '$5==10193 || $5==10330' evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv
grep -E "^0x260f710|^0x260f700" evidence/xrefs/class_info_census_4_4_4.tsv
python3 scripts/vtable.py 0x2613638 --slots 12          # add_opinion_modifier 的 effect vtable
python3 scripts/disrva.py 0x183a8a0 --end=0x183a946     # slot[2] ExecuteActual
```

- `add_opinion_modifier`(token 10193,class_info `0x260f710`,factory `0x1898450`,vtable `0x2613638`)
  的 Execute **不碰** `0x33794d0`(§2.5 的 12 条引用里没有它):它只是把解析结果搬进对象字段
  (`0x183a8a0` 的 `0x2ea5` 分支把名字串写到 `self+0xc8`;描述符 parse 在 `0x183ab60`,
  描述符名 `ADD_OPINION_MODIFIER`)。⇒ **关系值没有独立写路径**,它是**派生值**。
- 矩阵格的**唯一**写点就是 §2.2 里那两个取值体的
  `if (cell == 0x7fffffff) { cell = 0x743bb0(self, other); }`
  —— 即"**懒填缓存**"。`0x743bb0`(`0x4ed B`)是唯一的计算器(它按 `(A,B)` 两参调用,
  返回值被写回 `[base+idx*4]`)。
- `remove_opinion_modifier`(10330)与它同构(factory `0x18984e0`),同样不写矩阵。

⇒ 结论写成:`write_unresolved` **不适用**;正确说法是 **`value_is_derived_lazy_cache`**
(值由 `0x743bb0` 现算、写回 `[[0x33794d0]+8]+idx*4`)。

### §2.7 `OpinionRead` 判决行

```
OpinionRead = {table_base, key_encoding, stride, value_offset, orientation}
table_base     = [[0x33794d0]];描述符 {+0x00 = n (u32, 行列同值), +0x08 = int32* data}   (A)
                 (0x33794d0 本身在 .data 未初始化尾部 ⇒ 值只能运行期读)
key_encoding   = row*n + col;row/col = 国家对象 +0x20 的 **低 24 位**;双向下标界检查         (A)
stride         = 4 B(int32)                                                                (A)
value_offset   = 0(值就是元素)                                                             (A)
sentinel       = 0x7fffffff = 未计算;命中时调 0x743bb0 现算并写回                            (A)
orientation    = opinion 与 their_opinion 读**互为转置**的两格(row/col 互换 + 重算实参互换)  (A)
                 "哪一向 = 己对目标" 只有 docstring + 参数序两条单侧证人 ⇒ (B),见 §2.3
level_basis    = v(目标,己) + v(己,目标) vs 4 个 BSS 阈值                                    (A: 求和;B/C: 阈值数值)
not_modifier   = 0x33794d0 全量 12 条 rip 引用 / 8 个函数,has_opinion_modifier 族 0 条        (A)
write_path     = 无独立写路径;值是懒填缓存(0x743bb0 + 两个取值体的写回)                     (A)
```

**这一节不能说的:**

1. `n`(维度)与四个 level 阈值都在 BSS,**静态拿不到数值**;`table_base` 是**指针**,不是常量。
2. 矩阵里的 int32 **是不是**就直接等于 UI 上的 opinion 数值(有没有额外缩放)本卷没有证人;
   两个取值体读出来就原样交给比较器,但比较器的阈值来自脚本常量,单位没有独立对照。
3. `0x743bb0` 是"权威计算"是**单侧**证人(只有它是唯一被两个取值体调用的计算器),
   它的内部没有逐条读完 —— 不影响"值从哪一格来"的判决,但**不能**据此说"opinion 由哪些项组成"。
4. 一条**不在判决内**的旁证:`0x743bb0` 在栈上构造的临时对象把 vptr 设成 **`0x24e9068`**
   (`0x743bea`),与 `country_scope_4_4_4.md` §11 实机记到的那一格同值。本卷**不**据此改
   §11 的"CEffect 家族"判读,也不主张它是 scope —— 只登记这个重合,留给后面的卷子。

---

## §3 判决表 + `C2bReadProbe` 规格 + `onCountry` 契约草案

> 这一节**只写规格**,不执行:没有代码、没有 shot、没有进程。§1/§2 的每条读数都能用表里的
> 命令复算。

### §3.1 判决表(一项一行,grade 必填)

| 字段 | 读数 | 等级 | 复算命令 | 能不能进 host |
|---|---|---|---|---|
| 国家 id(对照行,前卷) | `scope+0x10` / 对象 `+0x20` | B+ | `disrva.py 0x393e40 --len=0x70` | **是**(已在读,§11 实机) |
| 存量 · 资源持有者 | `[country+0x2c68]`(指针) | B | `disrva.py 0x1adf73b` 上下 / `0x8437b0` | 否(只是中间指针) |
| **存量 · 容器** | **`blocked_on`**:`econ->vfn[+0x90](&vec,0)` 填充;槽目标只有运行期能拿 | — | `disrva.py 0x1adf690 --end=0x1adf7af`、`disrva.py 0x8437b0 --end=0x8439f7` | **否** |
| 存量 · 索引字段 | `[resource_obj+0x18]` | **A** | 读 `0x1adf774` / 写 `0x843904` | 否(缺容器) |
| 存量 · 步长 | 8 B | **A** | `0x1adf788` / `0x84390f` | 否(缺容器) |
| 存量 · 定点标度 | 100000 | B+ | `0x1afed43`(`imul …,0x186a0`) | 否(缺容器) |
| 收入 · 容器 | `[country+0x2530]`(**与 `+0x2570` 冲突**) | B | `disrva.py 0x1ac52f0 --end=0x1ac5345` | **否**(候选) |
| 能量 · 资源对象 | `[[0x33746f0]+0x20]` = `find(db,"energy")` | **A** | `disrva.py 0x3b8640 …`(init)、`0x3b8750`、`0x3b8820` | **是** |
| **能量 · 索引数值** | `[[0x33746f0]+0x20]+0x18`,静态不可读 | **C** | 同上;文件序候选 = 0 | **否** |
| opinion · 表基址 | `{n=[d]; base=[d+8]},d=[0x33794d0]` | **A** | `disrva.py 0x1ab04f0 --end=0x1ab05b1` | **是** |
| opinion · 键编码 | `row*n + col`,id = `[obj+0x20]&0xffffff` | **A** | 同上 `0x1ab05aa`/`0x1ab05b6` | **是** |
| opinion · 步长 | 4 B(int32) | **A** | 同上 `0x1ab05bc` | **是** |
| opinion · 值偏移 | `0`(值就是元素) | **A** | 同上 | **是** |
| opinion · 方向 | 两向**互为转置**(A);"己对目标"是哪一向只到 B | **A / B** | `disrva.py 0x1ab1340 --end=0x1ab1401` | **是**(按引擎名暴露) |
| opinion · 未计算哨兵 | `0x7fffffff`;唯一写点 = 两个取值体的懒填 | **A** | `0x1ab05bf`/`0x1ab05d4` | **是**(必须 fail-closed) |
| opinion · level 阈值 | 4 个 dword,`0x326178c/90/94/9c` | C(BSS) | `disrva.py 0x1ab1050 --len=0x80` | **否** |
| 反例 · modifier 容器 | `[country+0x2c78]→+0x10→+0x2d78` 链式列表 | **A** | `disrva.py 0x1ac8f70 --len=0x120` + `riprefs.py 0x33794d0` | 否(证明"不是同一个容器") |

**一句话判决:** `OpinionRead` 的**表基址 / 键编码 / 步长 / 值偏移**四项全 A(方向是
"转置 A + 谁对谁 B")⇒ 这一族可以按引擎名进契约;`EnergyRead` 的**形状**全 A,但**存量容器**
卡在运行期 vtable、**能量索引**卡在运行期序号 ⇒ 两项都**不进**契约。**写路径照旧不开。**

### §3.2 `C2bReadProbe` 规格(只写规格,不执行)

**什么时候读。** 复用 C2 已有的国家 scope 派发点(`0x3B0F80`,与 `every_system` 同一张槽表),
在 `mask == 0x04` 的那一条上读。**不要**新开 hook:§11 已经证明这条路径每月每国一次。

**先拿到对象(不调 0x393dd0 的缓存快速路径)。**

```
id  = scope+0x10                          ; 已有的那一格
T   = [0x3260FD8]                         ; 国家对象表
if id >= [T+0x20] -> fail(越界)
obj = [[T+0x18] + id*0x10 + 8]            ; entry 步长 0x10,取 +8
if obj == 0 || [obj+0x20] != id -> fail   ; id 复核(§7)
if !obj->vfn[+0x08]() -> fail             ; 合法性门(§7)
```

**格 1..3:存量(预期 `blocked`,这一档就是去把它变成 A 的)。**

```
db  = [0x33746F0]
n   = [db+0x14]                           ; 资源条数
idx = [[db+0x20]+0x18]                    ; ← 能量索引(**本次要读数**)
E   = [obj+0x2C68]
if !E->vfn[+0x80]() -> 退到全局 0x325FF70  ; 与引擎同一条回退
buf = n*8,先清零                          ; 引擎 0x1adf513-0x1adf52a 就是清零这个栈向量
vec = { data: buf, size: n, cap: n }      ; 24 B:ptr + 两个 u32(引擎在 rbp+8/+0x10/+0x14 造这个)
E->vfn[+0x90](E, &vec, 0)                 ; rdx = &vec,与 0x1adf760 同一个调用口径
print idx, buf[idx]                       ; ← 存量(÷100000)
```

**格 4..5:两个"收入"容器(把冲突变成读数)。**

```
for off in (0x2530, 0x2570):
    c = [obj+off]; if c == 0 -> skip
    if idx < [c+0xC]: print off, [ [c+0] + idx*8 ]     ; 同一个 idx
```

**格 6..7:opinion(双向,含哨兵)。**

```
d = [0x33794D0]; if d == 0 -> skip
n2 = [d]; base = [d+8]
me = id; other = <同派发轮里另一个国家 id>(见"判据 3")
cell(a,b) = base + (a*n2 + b)*4
v = cell(me, other)      ; 引擎的 their_opinion 那一格
w = cell(other, me)      ; 引擎的 opinion 那一格
if v == 0x7FFFFFFF or w == 0x7FFFFFFF -> print "sentinel"(不算、不写)
```

> 这两行的**名字**按 §2.3 的读数写:`opinion` 的 key 是 `目标*n + 己`,即 `cell(目标, 己)`;
> `their_opinion` 是 `cell(己, 目标)`。哪一格是"人话里的我们看他们"由判据 3 定,**不预先假设**。

**判据(每条都要有独立 oracle,不许只看"值看起来合理"):**

1. **存量**:同一个 mod 里写一条一次性 effect
   `export_resource_stockpile_to_variable = { resource = energy variable = neo_probe_energy }`,
   然后**同轮**用引擎自己的 trigger 扫边界:
   `has_country_resource = { type = energy amount >= k }`,取 `k = 我们的值` 与 `k = 我们的值+1`,
   两次求值必须**恰好翻转**。翻不过去 ⇒ 偏移/索引错。
2. **收入**:`has_monthly_income = { resource = energy value >= k }` 同样的 `k / k+1` 翻转法
   (它在 `+0x2570` 上);`income >= k` 同样的翻转法(它在 `+0x2530` 上)。
   **两条各自翻转** ⇒ 冲突 1 被解释成两个量而不是"抄错偏移"。
3. **opinion(这一条同时给 §2.3 的 B 定型)**:`opinion = { who = X value > k }` 与
   `their_opinion = { who = X value > k }`,各扫 `k / k+1`。
   - **定向**:需要一个**不对称**的对 `(A, B)`(A 对 B 有 +N,B 对 A 是 0 或另一个数)。
     在 A 的 scope 里跑 `opinion = { who = B … }` 与 `their_opinion = { who = B … }`,
     翻转点分别 `= cell(B, A)` 还是 `= cell(A, B)` —— **哪一格就是"某一向"**,由读数定,
     不由函数名定。
   - 单国战役(§11 那种)只有一个国家时**做不了这条**,要两个非 AI 国或玩家 + 一个 AI 国。
4. **索引交叉**:同一轮再算一次 `[[db+8+0*8]+0x18]`(资源表第 0 个)与
   `[[db+0x20]+0x18]`;若两者相等,则"文件序 energy 第一"的候选(§1.6 的 0)被证实;
   不等则 index = 资源表里的位置,与文件序无关。
5. **只读**:全部是"读 + 引擎自己求值",**不调** `0x743BB0`(它会写缓存)、**不调** `add_resource`。

**判负长什么样(写进日志,不要写成"没有"):**

| 现象 | 判词 |
|---|---|
| `E` 为空 / `vfn[+0x80]` false 且回落对象也不合法 | `stockpile_holder_invalid`(国家对象版本或战役未载入) |
| `idx` 读出负数/越界 | `energy_index_out_of_range`(§1.6 的对象不是 energy,或表结构变了) |
| 翻转点 = 我们的值 ±1 之外的任何位置 | `offset_mismatch` |
| opinion 两向相等 | `orientation_unresolved`(§2.3 的转置假设在该存档上不成立) |
| 一次 shot 里 `mask=0x04` 的行数 = 0 | `no_country_scope`(不是判负,是没打上) |

### §3.3 `onCountry` 的字段契约草案

**现状(必须一起读):** host 侧现在只把非 system 派发当**诊断** —— `NEO_SCOPE_OTHER` 那一行
(`src/dll/c2/neo_js_host.zig` 的 `noteOtherScope` + `neo_vtable.zig` 的非 system 分支)。
**契约未实现**,也没有任何字段被 JS 看见;本节的"可进"指的是**允许开始实现**,不是已实现。

**A 级 —— 可进契约(本轮只有这一族):**

```
onCountry.country_id             ; scope+0x10(与对象 +0x20 复核一致才用)
onCountry.opinion[target]        ; int32,引擎 `opinion` 那一格 = base[(target*n + id)]
onCountry.their_opinion[target]  ; int32,引擎 `their_opinion` 那一格 = base[(id*n + target)]
                                 ; base = [[0x33794d0]+8],n = [[0x33794d0]+0]
```

**名字按引擎的函数取名,不按"我们/他们"取名** —— §2.3 的"哪一向 = 己对目标"是 B,
实机不对称对(§3.2 判据 3)之前不许在契约里写成人话方向。

三条硬性约束(写进契约注释):

1. **哨兵 fail-closed**:读到 `0x7fffffff` 必须返回 `unavailable`,**不许**把它当 `-1`,
   也**不许**为了取值去调 `0x743bb0`(它会写缓存,违反 C2 的只读口径)。
2. **界**:`target >= n || id >= n` ⇒ `unavailable`(引擎自己是 `jae` 之后走回退,不是读越界)。
3. **表可能为空**:`[0x33794d0] == 0`(主菜单/未载入战役)⇒ `unavailable`,不是 0。

**B 级 —— 候选,不进契约:**

- `income_container = [country+0x2530]` / `[country+0x2570]`(8 B 元素,按 `[res+0x18]` 索引):
  形状是 A,但"哪一个叫月度收入"只有单侧证人,且两个容器互相冲突。**§3.2 的判据 2 通过后才升 A。**
- `stockpile_holder = [country+0x2c68]`:指针本身 B;容器要经 virtual,+0x90 槽目标未定位。
- 存量定点标度 100000:与存量容器一起卡住。

**C 级 —— 不出现(连"候选"都不标):**

- `energy_index` 的**数值**(文件序候选 0 不作数);
- 矩阵的 `n` 与四个 level 阈值(**运行期**才有的数值);
- `0x743bb0`(opinion 计算器)的内部组成。

### §3.4 roadmap

`OpinionRead` 的表基址/键编码/步长/值偏移四项是 A,方向是"A(互为转置)+ B(谁对谁)" ⇒
按计划 Step 5(有 A 级才改)在 `docs/roadmap.md` **第 120 行**(「运行时 JS 的判据」)
**行内追加**一句字段层状态;**文件仍 140 行**。`EnergyRead` 的 `blocked_on` 写进同一句,
免得读者把"字段层有 A"读成"两个字段都通了"。

**本节不能说的:** 契约草案里的 `target` 是谁由调用方决定;C2 现在拿到的 `id` 只有
`country_scope_4_4_4.md` §11 那一个(玩家国,`id=0`),**没有第二个国家** ⇒ §2.3 的方向
(B)在实机上要**一个不对称的国家对**才能验,单国战役验不了。§3.2 判据 3 已按这个前提写。

---

## §12 C3 国家侦察发读数(2026-11-08,实机一发,只读)

> 这一节只追加读数与判词;§1/§3.1 的旧判决**不改写**。产物:
> `evidence/logs/runtime_js_c3_country_probe_4_4_4.log`(DLL sha `79d6af1f…623c37`、
> pid 1756、9 个月度脉冲、355 次国家派发)。计划 = `2026-11-08-c3-country-probe-shot.md`。

| 项 | 读数 | 等级 | 复算 | 下一步 |
|---|---|---|---|---|
| 能量索引(数值) | **`energy_idx=0`**,`db_n=26`(同一条读数里),`energy_obj=[[0x33746F0]+0x20]=0x1f66d64d0` | **A**(原 C:文件序候选 0 不作数) | 日志 `^NEO_C3_RES`(3 行同值);`grep -n "^[a-z_]* = {" /var/lofibass_ssd/data/stellaris/4.4.4/common/strategic_resources/00_strategic_resources.txt \| head -1` | 下一发补 §3.2 判据 4 的交叉(`[[0x33746F0]+8+0*8]+0x18`);本条只把**数值**升 A,「0 = 文件序第 0 个」仍未证 |
| `[country+0x2c68]` 持有者 | 两国分别 `0x20e2df940` / `0x20e4ce630`;同 vtable | **B**(不变) | 日志 `^NEO_C3_ECON`(前 2 行) | 只在两国上量过;稀疏/空持有者未遇到 |
| 经济容器 vtable | **`base+0x2515458`**(两国同值)⇒ 同一类 | **B**(新读数;运行期) | 日志 `^NEO_C3_ECON` 的 `vt_rva` | 用一个第三国/月确认同值(本发已 2/2) |
| 经济容器 `+0x90` / `+0x98` 槽目标 | **`0x844200` / `0x8442A0`** —— 用上面运行期 RVA **离线**读出 | **B**(离线,静态形状;未在活体调用) | `python3 scripts/vtable.py 0x2515458 --slots 24`(slot 0x12/0x13);`python3 scripts/disrva.py 0x1adf690 --end=0x1adf7af`(`mov rax,[rcx]; call [rax+0x90]` 证明槽在 vtable 上) | 活体验证「`+0x90` 填充 / `+0x98` 写回」需要下一次只读发(本发零引擎调用) |
| 经济容器槽(宿主行) | 行内 `s90=0x0 s98=0x0` **不是引擎事实**:行读的是 `[econ+0x90]`(对象字段),引擎读的是 `[[econ]+0x90]` | — | 同上 `disrva.py` 的 `01adf75d`/`01adf767` | 修 `country_probe.zig` 的槽取法(`[[econ]+0x90]`)后重打 |
| opinion 双向 | **40 行全 `a=na b=na`**;15 行 `self` 带高位(必 `out_of_range`),25 行低 id 无法区分 `table_null` / `not_computed` | **仍 B**(方向);本次读取**判负** | 日志 `^NEO_C3_OPINION`(40 行) | ①宿主把 `na` 拆成 `table_null/out_of_range/not_computed` 三个词;②`self`/`target` 取 `&0xffffff` 后再查表;③仍不调 `0x743bb0` |
| 国家 id 编码 | **`scope+0x10` 不是裸 id**:同脉冲 39 个值里 `0x01000002…0x0100000D`、`0x0100001F`、`0x04000015`、`0x06000014`;低 24 位恰好 `0..39`(缺 23) | **A**(实机,本发新读数) | 日志 `^NEO_SCOPE_OTHER` 第 3 行 `u10=0x01000002`;`NEO_JS_CALL_COUNTRY` 全序列按 `&0xffffff` 去重 = 0..39 | 对象表/矩阵查表一律用低 24 位(与 §2.2 的 `[obj+0x20] & 0xffffff` 同口径) |
| AI 派发 | **355 次 = 9 个月度脉冲 × 39–40 国**;低 24 位 id 覆盖 `0..40`(C2 只有人类 1 国) | **A**(实机) | 日志 `^NEO_JS_CALL_COUNTRY`;`id=0` 的行号 1/40/79/118/157/196/235/276/316 | 无;AI 递送这一格收口 |
| 脚本解析 | `Unexpected token` / `Script Error` / `error.log` 的 `neo_c3` 行全 **0** | **A** | `evidence/logs/runtime_js_c3_country_probe_4_4_4.log` 的「脚本侧错误面」 | 无 |
| opinion 矩阵 `n` / level 阈值 | 未读(本发不导出描述符内容) | **C**(不变) | — | 需要把 `n` 打进一条只读行(下一发) |

**这一节不能说的:**

1. **opinion 的方向仍未实机**。40 行里没有一对数字,`a != b` 无从判定;§2.3 的「互为转置 A」
   仍是静态判决,「谁对谁 B」仍未收口。
2. **`0x2515458` 的类名**:本发只证明「两国共享这个 vtable 且 `+0x90` 目标是 `0x844200`」;
   这个 RVA 也出现在 `ceffect_vtable_map_4_4_4.txt`(slot1 = `0x1D08520`),**不**据此改
   「经济容器」的类身份判读 —— 类名仍未定。
3. **高位的含义**:本发量到高 8 位有三种取值(`0x01`/`0x04`/`0x06`),**没有**判定它是什么
   (国家类型?实例代号?);只判定「低 24 位是国家 id」这一条对查表可用。
4. **单战役/单存档/9 个月**;39→41 国的变化只说明这一份存档不静默,不外推到其它存档。
