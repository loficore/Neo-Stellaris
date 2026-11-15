# 国家资源存量的读法定形:`[country+0x2c68]` 容器与它的两个槽(4.4.4,离线,零 shot)

**这份文件回答什么。** 一个问题:**「读一个国家某种资源的存量」能不能只靠读内存做到?**
`country_fields_4_4_4.md` §1.8 把这一格停在 `blocked_on`:存量经 `[country+0x2c68]` 的
`vtable +0x90` 填充,而那个槽**是函数**,当时只到 B 级。§12 用运行期读数把 vtable 钉成
`0x2515458`、槽目标离线读成 `0x844200` / `0x8442A0`。本卷把这两个槽**逐条读完**,给出容器的
字段表、向量的布局、以及判决(`§2.5`)。

**纪律(与计划一致):**

1. **零实机**:本卷只读 `stellaris.exe` 拷贝(4.4.4,sha256 `9242c40a…b1a56`)+ 一份存档文本。
   没有进程、没有注入、没有 shot、没有对任何槽"试调一次"。
2. **不猜地址**:每条读数都能用本节写下的命令复算;等级 = A(双侧证人)/ B(单侧)/ C(只有形状)。
3. **存档只证伪**(§3):存档里写「不矛盾」/「无对应物」,不写「验证通过」。
4. **三套索引不混**:资源索引(`energy=0`,A,§12)/ 国家 id / 表槽位。本卷每个读数都标是哪一套。
5. **判词只有三档**:`cached_scalar_named` / `must_call_vtable` / `unresolved`。

**复算的公共前置。** `NS_STELLARIS_EXE` 缺省指 `/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe`;
`disrva.py` 的第二参一律用显式 `--end=`,按 `.pdata` 边界取区间(`pdata.py` 查边界)。

---

## §1 容器与两个槽

### §1.1 定形输入

```bash
python3 scripts/vtable.py 0x2515458 --slots 24        # §12 的运行期 vtable
python3 scripts/pdata.py 0x844200 0x8442a0 0x1b2f30 0x1760770 0x844ae0 0x844890 0x844820
```

`§12` 的运行期读数(两国同值,`NEO_C3_ECON`)给出 `[country+0x2c68]` 的 vptr = `base+0x2515458`。
这张表的前 24 槽(只列与本卷有关的):

| 槽 | 目标 | 是什么(本卷读到的) |
|---|---|---|
| `+0x00` | `0x844820` | 释放体:先按 `[self+0x40]` 的分配器虚槽 `+0x10` 放掉 `[self+0x30]` 的向量,再 `operator delete(self,0x48)` ⇒ **对象 0x48 B** |
| `+0x08` | `0x1D08520` | base `CEffect::Execute` —— 这张表因此落在 `ceffect_vtable_map` 的下限集里(§12 注 2 那条「别据此定类名」仍然有效) |
| `+0x10` | `0x843F90` | ExecuteActual:先取 `[self+0x20]` 门,再遍历 `[self+0x28]` 的向量,非零元素触发内层 effect |
| `+0x20` | `0x8440A0` | 参数 parse:按 token id `{0x30db,0x3336,0x3778,0x3f88,0x45dc}` 分支,未知 token `jmp 0x1D092C0`(parse-error 表) |
| `+0x80` | `0x1B2F30` | **恒真门**:`mov al,1; ret`(3 B 叶子,不带 `.pdata` 记录 —— `pdata.py` 对它报 NOT IN ANY FUNCTION,不是缺失) |
| `+0x88` | `0x844890` | 克隆体:`new(0x48)` + 复制字段 + `[new+0x10] = rdx` |
| **`+0x90`** | **`0x844200`** | **取**:把容器里的向量**复制给调用方** + 三处覆盖(§1.3) |
| **`+0x98`** | **`0x8442A0`** | **写回**:把调用方的向量**复制进容器** + 三处覆盖(§1.4) |
| `+0xA8` | `0x844630` | 填一张向量后交给 `0xa91970`(消息/检查路径) |
| `+0xB0` | `0x8444C0` | 同上,并构造 `.rdata` 串 **`"LACKING_RESOURCES"`** |
| `+0xB8` | `0x844390` | **「至少这么多」比较**:填向量后逐项比对,任一项不够返回 0 |

### §1.2 容器布局(0x48 B)

三个函数给出同一份布局,且互相钉死:`0x844AE0`(构造,`new(0x48)`)、`0x844890`(克隆)、
`0x844820`(释放)。再叠上向量初始化器 `0x1760770`。

```bash
python3 scripts/disrva.py 0x844ae0 --end=0x844b46    # 构造
python3 scripts/disrva.py 0x844890 --end=0x844941    # 克隆
python3 scripts/disrva.py 0x1760770 --end=0x17607d0  # 向量初始化器(以 &container+0x28 为参数)
```

| 偏移 | 宽 | 含义 | 证人 |
|---|---|---|---|
| `+0x00` | 8 | vptr = `0x2515458` | `0x844b24`/`0x8448e2`;运行期 §12 |
| `+0x08` | 4 | `=1`(构造时写死;克隆时按源复制) | `0x844b19` |
| **`+0x10`** | 8 | **所有者对象**(构造参数;`+0x90/+0x98` 用它取/写三个研究字段) | `0x844b36`、`0x844931` |
| `+0x18` | 1 | `=0`(标志字节;克隆时复制) | `0x844b20` |
| `+0x20` | 8 | 子对象指针(构造时默认取全局 `0x325F288`) | `0x844b15` |
| **`+0x28`** | 8 | **指向自己的内联向量** = `&self+0x30` | `0x1760795`、`0x8448fe` |
| **`+0x30`** | 8 | 向量 **data** 指针 | `0x1760780`、`0x84490a` |
| `+0x38` | 4 | 向量 **capacity**(u32) | `0x1760786`、`0x84490d` |
| **`+0x3C`** | 4 | 向量 **count**(u32) | `0x176078a`、`0x84490d` |
| `+0x40` | 8 | 向量 **allocator**(构造默认 `0x2A03320`,静态分配器实例) | `0x1760791`、`0x844911` |

`0x1760770(rcx=&self+0x28)` 的体逐条:**容量按 `[0x33746F0]+0x14`(资源条数)扩到 n,再把 n 格
零填**。这就是「向量的长度 = 资源条数、下标 = 资源索引」的第一条硬证人(§2.3)。

### §1.3 槽 `+0x90` = **取**,不是算

```bash
python3 scripts/disrva.py 0x844200 --end=0x844297
```

体分两段:

```
00844215  rdx = self+0x28
0084421c  rcx = arg2                     ; 调用方给的「向量持有者」
0084421f  call 0x410060                  ; ← 复制 *[self+0x28] -> *(arg2)
00844224  r10 = [0x33746F0]              ; 资源库
0084422b  cmp ebx,1 ; je ret             ; arg3==1 ⇒ 不做下面三处覆盖
00844230  r8  = [r10+0x48]               ; physics_research
0084423b  r9  = [r8+0x18]                ;   资源索引
00844242  rax = [self+0x10] -> +0x1900   ;   值来自「所有者」
00844249  [arg2->data + r9*8] = rax      ;   ＊写的是调用方的缓冲,不是引擎对象＊
0084424d…  [r10+0x50] -> +0x1908         ; society_research
0084426a…  [r10+0x58] -> +0x1910         ; engineering_research
```

`0x410060` 是**向量赋值**(两侧同一个函数、方向由参数角色决定):

```bash
python3 scripts/disrva.py 0x410060 --end=0x4100f0
# rax = [rdx](源向量对象); rbx = [rcx](目标向量对象); 相等则直接返回
# esi = [src+0xC](count); [dst+0xC]=0; reserve(dst, esi); [dst+0xC]=esi
# memcpy([dst], [src], esi*8)
```

⇒ **`+0x90` 的写点全部落在调用方提供的缓冲里**:`[rdi]`(=arg2 指向的向量对象)与它的 data。
它读的引擎内存只有两处:`*[self+0x28]`(向量对象)与 `[self+0x10]+0x1900/0x1908/0x1910`。
**没有一处 `mov [self+off], …`。** ⇒ 「取」,不是「算 + 填缓存」。

### §1.4 槽 `+0x98` = **写回**

```bash
python3 scripts/disrva.py 0x8442a0 --end=0x84438b
```

同一个 `0x410060`,但**两个参数角色互换**:`rcx = self+0x28`(目标)、`rdx = arg2`(源)
⇒ 把调用方的向量**复制进容器**。随后 `arg3 != 1` 时,把调用方向量里三个研究索引的值写回
`[self+0x10]+0x1900/0x1908/0x1910`,并做 `cmovns` **负数钳到 0**。

⇒ `+0x98` 是**改引擎状态**的槽。这与 §1.8 的旧结论一致(`add_resource` 用它),也是本卷判
`cached_scalar_named` 之后仍要写「写路径照旧不开」的原因。

### §1.5 向量对象与它的分配器

```bash
python3 scripts/disrva.py 0x241db0 --end=0x241e40    # 增长
python3 scripts/disrva.py 0x1adf690 --end=0x1adf7af  # 引擎自己的栈上向量(同一布局)
```

向量对象 0x18 B:`{T* data @0; u32 capacity @8; u32 count @0xC; Alloc* @0x10}`。
`0x241db0` 的判据:先 `cmp n,[vec+8]`(不够才长)、增长分支用 `[vec+0x10]` 的虚槽 `+8` 分配、
`+0x10` 释放旧块、最后 `[vec+8] = n` —— 所以 `+8` 是**容量**、`+0xC` 是**元素数**。
读侧的界检查(`0x1adf77c` `cmp ecx,[vec+0xC]`)用的是元素数,与 `0x410060` 的 `memcpy` 长度同源。

调用方的栈上向量(`0x1adf6e9`–`0x1adf737`)把 `+0x10` 指向一个内联分配器对象(其 vptr
`0x24C2E10`),所以 `reserve` 那条路在栈向量上也是良构的。

### §1.6 这个类**没有静态构造点**(负结论,记下来)

```bash
python3 scripts/riprefs.py 0x2515458        # 只有 3 处,且都在本类的三个函数体内
```

- 对 vtable `0x2515458` 的 rip 相对引用**只有 3 处**:`0x844820`(释放体)、`0x844890`(克隆)、
  `0x844AE0`(构造);`.rdata`/`.data` 里也没有任何指向它的 qword(没有静态原型对象)。
- 构造 `0x844AE0` 与克隆 `0x844890` **都没有直接调用点**(`fastcalls.py` 0 处;`E8/E9 rel32`
  逐字节复扫也是 0),vtable 槽里也没有它们(槽 `+0x00` 是释放体,`+0x88` 是克隆)。

⇒ **谁在运行期把 `[country+0x2c68]` 填成一个这种对象,静态链给不出**(与 §1.8 的
「只在运行期被赋值」同一条负结论,这次是把它按「无静态构造点」写实)。这不是缺陷:
引擎全部通过**对象自己的 vptr** 摸它(`call [rax+0x90]`),不需要静态引用表。

### §1.7 引擎里这条读法的使用面

`[reg+0x2c68]` 在 `.text` 里有 **615** 个访存点(`0x2c68` 是常见位移,绝大多数属于别的类)。
按 `.pdata` 对齐逐函数解码后,**268 个不同函数**读它;其中 **259 个**在同一函数里还有一条
`call qword ptr [reg+disp]`,disp ∈ {`0x80`,`0x90`,`0x98`} —— 即同一段被内联的惯用法:

```
rcx = [owner+0x2c68]
rax = [rcx];  call [rax+0x80]        ; 恒真门
if (!al) rcx = [0x325FF70]           ; 默认对象
call [rax+0x90](rcx, &vec, 0)        ; 取整张向量
```

本卷逐条读过的四个**独立**读者,全部落在这一形上:

| 函数 | 干什么 | 站点 |
|---|---|---|
| `0x1ADF690` | `has_country_resource` 的取值体:填向量 → 读 `vec[[res+0x18]]` | `0x1adf73b` / `0x1adf767` |
| `0x843A00` | 「取单个资源」helper:同形,把值写进 `*rdx` | `0x843a9c` |
| `0x8437B0` | `add_resource` 的读写体:取向量 → 加 → `0x843EC0` → `+0x98` 写回 | `0x843858` / `0x84399b` |
| `0x96A890`(片段) | UI/经济路径:取向量里的存量,再与 `[country+0x2570]` 的项相加 | `0x96bd69` / `0x96bdb0` |

另:`0x844390`(`+0xB8`)是**同一个容器**上的「至少这么多」比较体 —— `has_country_resource` 的
`>`/`>=` 分支走的就是它(§1.3 的旧读数)。它把「向量 = 存量」这一条从**读法**升成**语义**:
比较的是 `vec[i]` 与请求量,不够就 false。

`0x843EC0`(写回前的必经一步)逐资源把值过一遍 `0x3B4E70(resource, owner, value)` →
`0x3B5070(resource, &out, owner)`,结果与原地值不同才写回调用方向量。⇒ 存量的合法域(上限、
钳零)由这一步保证,不是任意 int64。

### §1.8 §1 不能说的

1. **`+0x10` 指向「国家对象」只是 B+**。两侧证人:`+0x90/+0x98` 读/写 `[+0x10]+0x1900/8/10`;
   三个官方 trigger `stored_physics_points`/`stored_society_points`/`stored_engineering_points`
   (token `18161/18162/18163`)的取值体 `0x1B37920`/`0x1B37770`/`0x1B375C0` **先用 `0x393DD0`
   解析出国家、再读 `+0x1900/0x1908/0x1910`** —— 地址逐字相同。但**[`econ+0x10`] 这个指针本身
   没被实机钉住**(本卷零 shot),所以说的是「它是一个具备这三个字段的对象」,不是「它就是本次
   `scope` 解析出的那个国家」。
2. **没读完的槽**:`+0xA8`/`+0xB0`(消息/`LACKING_RESOURCES`)与 `+0x10`(ExecuteActual)只读到
   形状,没逐条反编译。它们不影响本卷的读法判决。
3. **`+0x20` 的子对象**(默认全局 `0x325F288`)身份未定。`+0x90/+0x98` 都不碰它。
4. **`0x1B2F30` 没有 `.pdata` 记录**,所以「+0x80 恒真」是字节读数(`mov al,1; ret`),不是符号读数。

---

## §2 存量 vs 收入,以及判决

### §2.1 `+0x2530` / `+0x2570` 那个冲突的处置

roadmap 记着「两个收入容器冲突」。本卷的处置是**把它与存量问题解耦**,而不是择一:

```bash
python3 scripts/disrva.py 0x1ac52f0 --end=0x1ac5345   # income 的取值体
python3 scripts/disrva.py 0x1ae3df0 --end=0x1ae3e91   # has_monthly_income 的取值体
python3 scripts/disrva.py 0x1ac5890 --end=0x1ac58e5   # resource_income_compare
```

三件事可以写实:

1. **两者都不是存量容器。** `+0x2530`/`+0x2570` 是**另一个对象**上的向量指针(读法
   `[[country+off]+0xC]` 界 + `[data + idx*8]`),而存量是 `[country+0x2c68]` 那个 0x48 B 类实例
   的内联向量。**两侧不是同一个指针、不是同一个 vtable、也没有同一个写路径**。
2. **只有 `+0x2c68` 有写的半边。** 存量链有 `+0x90`(取)与 `+0x98`(写回)成对,写回由
   `add_resource` 驱动;两个收入向量在全部已知读者里**只有读**,没有任何一处「读出 → 改 → 写回」
   (它们是每月重算的派生量,§1.7 旧结论不变)。
3. **哪个叫"净"哪个叫"总"仍然没证。** `income`(能量专用,无 resource 参)读 `+0x2530`;
   `has_monthly_income` 与 `resource_income_compare` 读 `+0x2570`。两者形状完全相同(指针 →
   `{data@0, …, count@0xC}`,8 B 元素,索引 = `[res+0x18]`)。静态链**仍然分不出**「净收入 / 总收入」,
   这一格保持 **B**,不进契约。

**结论一句话:冲突仍然存在,但它不再挡存量的路** —— 存量根本不在那两个偏移上。要销掉冲突本身,
仍然只需要一次实机读数(`§3.2` 判据 2 的 `k/k+1` 翻转法),那是下一份计划的事。

### §2.2 `+0x90` 是取,不是算

判据来自 §1.3:`+0x90` 体内**没有一处写回 `self`**;`0x410060` 的两个写点(`[dst+0xC]`、
`[dst]` 与 `memcpy` 目标)全部落在 arg2 指向的**调用方缓冲**。唯一会分配内存的路径是
`reserve`(目标向量容量不足时),分配的是**调用方的**向量。

⇒ 「从外部调用 `+0x90` 会写引擎状态」这个担心**不成立**。但**不要**据此去调它:本卷的判决不需要
调它(见 §2.5),而且调它还要自备一个 26 格的向量与一个分配器对象 —— 比直接读多三条失败面。

### §2.3 索引口径(资源索引,不是国家 id,不是表槽位)

三条独立证人把「向量下标 = `[resource_obj+0x18]` = 资源索引」钉住:

| 证人 | 读数 | 等级 |
|---|---|---|
| 向量初始化器 `0x1760770` | 容量 = `[0x33746F0]+0x14`(资源条数),零填同样多格 | A |
| 读体 `0x1adf690` | 界 `idx < [copy+0xC]`,地址 `data + idx*8`,`idx = [[self+0x2d8]+0x18]` | A |
| 写体 `0x8437b0` | 同一个 `[res+0x18]` 做下标、同一个 stride 8、`add` 进 `[data+idx*8]` | A |
| `+0x90` 的三处覆盖 | 用 `[db+0x48/+0x50/+0x58]` 各自的 `+0x18` 当目标下标 | A |

`energy` 的对象 = `[[0x33746F0]+0x20]`(A,`0x3B8640` 的 `find(db,"energy")`),它的 `+0x18`
由 §12 的实机读数 = **0**(A),`db_n = 26`(同一条读数)。所以对 energy:
**下标 0,与你手上的国家 id、与表槽位无关。**

**§3.2 判据 4 的交叉(`[[0x33746F0]+8+0*8]+0x18`)本卷做不了**:`0x33746F0` 整块在 `.data`
未初始化尾部,文件里是零(`country_fields_4_4_4.md` §1.6)。它仍然只能由一次实机读完成。
本卷能说的是:只要资源对象的 `+0x18` 是 `0..n-1` 的**稠密**编号(向量按 n 分配、按该字段索引、
写侧还用 `cmp idx,[db+0x14]` 兜界),这个下标空间就与「表里第几个」脱钩 —— 剩下的只是数值,
而数值 §12 已经读过。

### §2.4 三个研究资源是例外(读法必须分叉)

`+0x90` 在复制完缓存后,把 **physics_research / society_research / engineering_research** 三格
用所有者对象上的字段**覆盖**掉:

| 资源(库内偏移) | 名字 | 覆盖源 | 三方一致的证人 |
|---|---|---|---|
| `[db+0x48]` | `physics_research` | `[[econ+0x10]+0x1900]` | trigger `stored_physics_points`(18161)取值体 `0x1B37920` |
| `[db+0x50]` | `society_research` | `[[econ+0x10]+0x1908]` | trigger `stored_society_points`(18162)取值体 `0x1B37770` |
| `[db+0x58]` | `engineering_research` | `[[econ+0x10]+0x1910]` | trigger `stored_engineering_points`(18163)取值体 `0x1B375C0` |

复算:`pestr.py 0x2487ba8 0x2487c80 0x2487cb0`;三个 trigger 的 vtable 由
`rttibatch.py --who-tables 0x1b375c0,0x1b37770,0x1b37920` 找出(`0x2689BC0`/`0x268A178`/`0x268A270`,
slot `+0xF0` 是取值体),再由 `riprefs.py` 反查到 factory `0x1B24500`/`0x1B24460`/`0x1B244B0`,
最后按 `class_info_census_4_4_4.tsv` 对上 class_info `0x269EC28`/`0x269EC88`/`0x269EC18`,
在 `keyword_behaviour_registration_4_4_4.tsv` 里落成三个 keyword 名。

⇒ 任何「照常量表读存量」的实现,**这三格必须走 `[[country+0x2c68]+0x10]+0x1900/8/10`**,
不能读向量里的那三格(引擎自己也不读)。其余资源(含 `energy`)直接读向量。

### §2.5 判决

```
判决: cached_scalar_named
前提: `[country+0x2c68]` → 0x48 B 容器 → `+0x28`(→`+0x30`)的 8 B/格向量,下标 = 资源索引;
      该向量的 count 在 `+0x3C`、data 在 `+0x30`;`+0x90` 只把它复制给调用方(零写回),
      所以 `data[idx]` 与引擎自己填出来的那格**同值**(三个研究资源见 §2.4 的例外)。
      等级: 布局 A(构造/克隆/释放/初始化器四处互钉)、读法 A(读写两侧同槽)、
      标度 B+(§1.7 的 ×0x186a0 与 ÷1e5 魔数)、三个研究字段 B+(§1.8 第 1 条)。
下一步: 下一份计划按 §2.5 的常量表加只读 native + 权限位 + 双语文档;写路径照旧不开。
```

**可直接抄的常量表**(全部 RVA,加模块基址;出处列是本卷或邻卷的 §):

| 名字 | 值 | 档 | 出处 |
|---|---|---|---|
| `COUNTRY_RESOURCE_VECTOR_OFF` | `0x2C68` | B(运行期两次读数,静态写点不可见) | §1.8、§12、§1.6 |
| `RESOURCE_DB_GLOBAL` | `0x33746F0` | A | §1.6(旧卷)、本卷 §2.3 |
| `DB_COUNT_OFF` | `0x14` | A | `0x8437e2`/`0x1adf6bf`/`0x17607a9` |
| `DB_ARRAY_OFF` | `0x08` | A | `0x8438e6`/`0x843f0c` |
| `DB_ENERGY_OFF` | `0x20` | A | `0x3b8640`(§1.6) |
| `RESOURCE_INDEX_OFF` | `0x18` | A | `0x1adf774` / `0x843904` |
| `RESOURCE_VECTOR_HOLDER_OFF` | `0x28` | A | `0x844215`、`0x1760795` |
| `RESOURCE_VECTOR_DATA_OFF` | `0x30` | A | `0x1760780`、`0x1adf742`… |
| `RESOURCE_VECTOR_CAP_OFF` | `0x38` | A | `0x241dbf` |
| `RESOURCE_VECTOR_COUNT_OFF` | `0x3C` | A | `0x241ddf`、`0x1adf780` |
| `RESOURCE_VECTOR_ALLOC_OFF` | `0x40` | A | `0x241df5` |
| `RESOURCE_OWNER_OFF` | `0x10` | B+ | `0x844237`、`0x8442dc` |
| `OWNER_STORED_PHYSICS_OFF` | `0x1900` | A(两侧地址) | `0x844242`、`0x1b3792c` |
| `OWNER_STORED_SOCIETY_OFF` | `0x1908` | A(两侧地址) | `0x84425c`、`0x1b3777c` |
| `OWNER_STORED_ENGINEERING_OFF` | `0x1910` | A(两侧地址) | `0x844279`、`0x1b375cc` |
| `RESOURCE_ELEMENT_STRIDE` | `8` | A | §1.3 旧卷 + 本卷 §2.3 |
| `RESOURCE_SCALE` | `100000` | B+ | `0x1afed43` / `0x1afecf4`(旧卷 §1.7) |
| `RESOURCE_VECTOR_VTABLE_RVA` | `0x2515458` | B(运行期 2/2;可用于**校验**,不可用于寻址) | §12、本卷 §1.1 |
| `RESOURCE_FALLBACK_HOLDER_GLOBAL` | `0x325FF70` | B(门失败时的默认对象;本类门恒真 ⇒ 只在 `[+0x2c68]==0` 之类异常时才有意义) | `0x1adf74d` |
| `RESOURCE_ZERO_SENTINEL` | `0x26DC028` | A(越界读的落点 = 0) | `0x1adf78e` |
| `energy_idx` | `0` | A(实机,`db_n=26`) | §12 |

**读法(一行):** `v = *(u64*)( *(u64*)( [country+0x2C68] + 0x30 ) + idx*8 )`,
先核 `idx < *(u32*)([country+0x2C68]+0x3C)`,`[country+0x2C68]` 为 0 即 fail-closed。

### §2.6 §2 不能说的

1. **没有实机读数**:`[country+0x2c68]+0x30` 这条表达式**从未在活体上读过一格**,它的合法性
   完全由静态形状 + §12 的 vtable 读数支撑。判 `cached_scalar_named` 的依据是「读法与引擎相同」,
   不是「值与引擎相同」——后者是下一份计划的验收项。
2. **`+0x2c68` 的写点静态不可见**(§1.6)。所以「每个国家一定有一个良构容器」是推理,不是读数;
   实现必须 fail-closed。
3. **向量可能在运行期被重分配**(`+0x98` 的路径会 `reserve` 目标向量;容器自己的向量只由克隆与
   `+0x98` 触碰,正常不会长)。⇒ 每次读都要**重新取 `[+0x30]`**,不许缓存 data 指针跨帧。
4. **`energy` 的 0 只在 `db_n=26` 那一版成立**;mod 加资源会改 `db_n` 与编号。
5. **标度 1e5 是存量路径的读数**,不是「所有 8 B 资源格都 1e5」的证明(收入向量没单独证,旧卷 §1.7)。

---
## §3 存档交叉(只证伪)

### §3.1 命令与偏差

```bash
# 计划里的写法(`--sav`)在本树跑不通:该工具是位置参数 + 必填 --edges。
python3 scripts/save_hypergraph.py /mnt/cache/tmp/opencode/autosave_2327.01.01.sav \
    --edges /mnt/cache/tmp/opencode/edges_2327.tsv --stats
# systems=788 directed_entries=2446 undirected_edges=1219 components=1 isolates=0
# self_loops=0 duplicate_entries=8 asymmetric_edges=0 conflicting_edges=0
```

`save_hypergraph.py` 只解星系邻接,与资源无关;它在本卷的作用只是**证明这份 `.sav` 能被读**。
资源那一格要自己开 zip 读 `gamestate`:

```python
import zipfile, re
txt = zipfile.ZipFile('/mnt/cache/tmp/opencode/autosave_2327.01.01.sav').read('gamestate').decode('utf-8','replace')
i = txt.find('\ncountry='); m = re.search(r'\n\t1=\n', txt[i:]); c0 = txt[i:i+m.start()]
b = c0.find('budget='); print(c0[b:b+400])
j = c0.find('standard_economy_module'); print(c0[j:j+520])
```

### §3.2 读数

`country.0` 的直接子键里**没有** `stockpile` / `resources` / `stored_resources` 任何一形
(`txt.lower().count('stockpile') == 0`,整份 gamestate)。存量在**模块**里,而且是**名字键**:

```
modules = { standard_economy_module = { resources = {
    energy=35.35433  minerals=25000  food=25000
    physics_research=31401.34876  society_research=38183.0965  engineering_research=79278.37702
    influence=1000  unity=101131.34147  trade=60000  consumer_goods=25000  alloys=25000 } } }
```

| 判定项 | 结论 |
|---|---|
| 存档里有「国家级资源存量」这一形? | **有**:`modules.standard_economy_module.resources`,11 个**名字**键 |
| 这 11 个名字与库里的名字对得上? | **不矛盾**:`energy`/`minerals`/`food`/`physics_research`/`society_research`/`engineering_research`/`influence`/`trade`/`alloys` 都在 `0x3B7DA0` 那一段固定名里(§1.6 旧卷) |
| 能不能从存档拿到**索引**? | **不能,本格存档无对应物**:存档是名字键,没有 `+0x18`、没有 26 格数组、没有步长 |
| 能不能说「存量 = 向量」被存档**验证**? | **不能**。存档只证明「有一个名字键的存量块」,它与运行时向量是不是同一份数据,本卷零 shot 无法回答 |

两条**只证伪**的收获:

1. **「三个研究资源是例外」不矛盾**:存档把 `physics_research`/`society_research`/
   `engineering_research` 与另 8 个资源放在**同一个**名字块里(序列化层面不区分),而运行时把它们
   分开存(向量 vs 所有者 `+0x1900/8/10`)。这是**容器不同**,不是**语义不同** —— 存档侧看不出
   运行时的存储分叉,所以它**既不能证、也不反驳** §2.4。
2. **数值量级不矛盾**:`physics_research=31401.34876` 的 1e5 定点 = `3,140,134,876`,与
   `stored_techpoints`(`29577.32007 35974.52781 74740.79081`,见同块 `technology` 段)是**不同**
   的两个数 —— 所以「`+0x1900` 是 research 存量」不能靠存档数字推,只能靠 §2.4 的三方地址一致。

---

## §4 收口

**这一卷能交出去的一句话:** 存量是**进程内的一个 8 B 格**,在 `[country+0x2c68]` 那个 0x48 B
容器的内联向量里(`+0x30` data、`+0x3C` count、下标 = 资源索引);三个研究资源改读
`[[country+0x2c68]+0x10]+0x1900/0x1908/0x1910`。⇒ **不需要调 vtable**,判 `cached_scalar_named`。

**不能说的(汇总):**

1. 本卷**零 shot**;`[country+0x2c68]+0x30` 这条表达式一次都没在活体上读过。
2. `energy_idx = 0` 只在 `db_n = 26` 那一版成立;`[[0x33746F0]+8]+0x18` 的交叉(判据 4)本卷
   做不了(BSS),仍然欠一次读数。
3. 存档只对**名字**;索引与向量本身在存档里**没有对应物**。
4. `[econ+0x10]` 是「具备 `+0x1900/8/10` 的对象」(B+),不是「已实机钉住的国家指针」。
5. `+0x2530` / `+0x2570` 的「净/总」之分仍然 B,不进契约 —— 但它与存量无关(§2.1)。
6. 写路径(`+0x98`)本卷只**读**了体,**没有**任何一行实现建议;`add_resource`、
   `export_resource_stockpile_to_variable`、`0x843EC0` 的 clamp 语义都只作取证记录。

**交给下一份计划的前置清单:**

- [ ] 常量表(§2.5)按 `src/dll/shared/offsets.zig` 的 `country` 段落位,每条注释带站点 RVA;
- [ ] 读法必须带三道门:`[country+0x2C68] != 0`、`idx < [+0x3C]`、`[+0x30] != 0`(每帧重取);
- [ ] 三个研究资源走 `[[+0x10]+0x1900/8/10]`,并**显式拒绝**从向量里读它们;
- [ ] 实机验收仍需一次读数(§2.6 第 1 条),判据 = 「我们读的格 == 官方 `has_country_resource`
      的 `k/k+1` 翻转点」(旧卷 §3.2 判据 1,不需要新工具);
- [ ] 权限位与双语文档按项目既有形状补,写路径照旧不开。

**与计划的偏差(逐条):**

1. 计划的存档命令 `save_hypergraph.py --sav <path>` 跑不通:该工具是**位置参数 + 必填 `--edges`**
   (实测 `unrecognized arguments: --sav`)。本卷 §3.1 用真实接口跑通并记下读数。
2. 计划要求「在 `country_fields_4_4_4.md` 那一行之后」插 AGENTS 文档地图行,但**文档地图里没有那一行**
   (只有 §180 那张 RVA 表的 opinion 行引用了 `country_fields_4_4_4.md`)。新行插在**最后一条取证卷行之后**
   (`runtime_444_game_date_4_4_4.md` 那行),`grep -c` = 1 满足。
3. 计划把「容器布局」与「判决」拆成两个 Task;取证时这两件事是同一份反汇编的两个面,所以 §1/§2 的
   内容一起成形 —— 提交仍按计划的三个消息拆(26e6cd6 / 7fb7345 / 7682a81)。
