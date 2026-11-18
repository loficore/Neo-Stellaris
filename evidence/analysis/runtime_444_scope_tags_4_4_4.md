# runtime_444_scope_tags_4_4_4 — `[scope+0x08]` 的标签位 ↔ 语义名(planet / pop / fleet …)

**授权:零 shot。** 只读 exe 副本;不注入、不起游戏、不碰 Windows 机、不用 IDA。
置信档沿用既有卷:`pinned(§N)` / `静态推断(未验证)` / `未定形`。本卷**没有一格是 `pinned`** ——
全卷只有指令读数与 `.rdata` 字面读数。

```text
exe  = /var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe
sha256(实测,本卷执行时复算) = 9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56
size = 46,253,688 B
date = 2026-11-15
```

**本卷回答什么**:`runtime_444_scope_tables_4_4_4.md` §2.1–§2.5 把五个 getter 的
**类型门立即数**(`cmp qword [scope+8], 0x10 / 0x20 / 0x40 / 1 / 0x80`)读成了指令,**但没给它们起名**。
本卷把 `[scope+0x08]` 这个 **64 位位标志空间**里每一位对上语义名,并给出每位读的是哪张表。
它回答的是同卷 §4.4 第 1 条(「`0x10` 是 planet 还是 pop 还是 fleet」)。

**本卷不回答什么**:

1. **不回答任何运行时问题。** 七张表在活体里存不存在、槽数多少、缓存槽 `[scope+0x1c]` 是否常非空 ——
   零读数(§5)。
2. **不回答「表里存的 id 域与整数 id 一致」。** `tag_named` 只把**类型位**对上名字。
3. **不回答 `getPlanet(id)` 的入参口径**(raw / masked,同卷 §4.4 第 4 条),也不改 §4.4 第 3 条。

**输入**(全部只读):

| 输入 | 用途 |
|---|---|
| `stellaris.exe` 4.4.4(上面那份 sha256) | 唯一的指令/字面来源 |
| `evidence/analysis/runtime_444_scope_tables_4_4_4.md` §2.0–§2.5、§3.0、§4.4、§5.2 | 待定标签的起始读数(逐字引用,不改) |
| `evidence/analysis/runtime_444_c1_validation.md` §80.1–§80.3 | 拼接器/注册函数的形状先例(`every_system` 那一族) |
| `evidence/analysis/runtime_444_transitability_4_4_4.md` §8.2、§3.3 | B 套 mask 的既有读数、`0x3260b78` 的既有形状 |
| `evidence/analysis/country_scope_4_4_4.md` §6 | mask `0x04` = country 的 **A 级**读数(本卷第二个路线的校准点) |
| `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv` | 3,900 条静态 keyword 的 `class_info` → 第二路线的分母 |

**产物出处**(按 basename 记录,追加不改写):

```text
evidence/xrefs/scope_tags_4_4_4.tsv                    一行一个标签:tag / 名字候选 / 表 / § / 判词
evidence/analysis/runtime_444_scope_tags_4_4_4.md      本卷
```

**工具**:`scripts/disrva.py`(逐条指令)、`scripts/strfind.py`(字面定位)、`scripts/pestr.py`(读字面)、
`scripts/find_refs.py`(慢通道,本卷用了几次见 §4)。三条普查(§3.1 的 567 个 mint、§3.4 的 1,583 个
keyword、§3.3 的 43 个 getter)**用一次性探针**跑 —— 探针在仓外(`/mnt/cache/tmp/opencode/`),
因为计划 Global Constraints 第 2 条禁止动 `scripts/` 一个字节;判据形状逐条写在 §3 与 §6,
可以照 §6 的三段签名重建,不需要我的探针文件。

---

## §1 工单:六个待定标签与它们各自读的表(2026-11-15,零 shot)

数值**逐字**抄自 `runtime_444_scope_tables_4_4_4.md` §2.1–§2.5(不改写),「读哪张表」抄自同一节的
「表全局槽」行。

| 待定标签(B 套 mask) | getter | 该 getter 读的表全局槽 | 对象内 id | 回退对象 | 出处 |
|---|---|---|---|---|---|
| `0x10` | `0x394190` | `0x3260ff8` | `+0x10` | `0x325fb00` | 同卷 §2.1 |
| `0x20` | `0x2b6470` | `0x3260ff0` | `+0x10` | `0x325fae8` | 同卷 §2.2 |
| `0x40` | `0x393ec0` | `0x325ef00` | `+0x30` | `0x325fa20` | 同卷 §2.3 |
| `1`    | `0x394870` | `0x3261010` | `+0x8`  | `0x3260118` | 同卷 §2.4 |
| `0x80` | `0x393970` | `0x3260b98` | `+0x8`  | `0x325d880` | 同卷 §2.5(与 §8.2 的第 16 行) |
| `0x2000000` | `0x394e60`(本卷 §3.5 读到) | `0x3260f18` | `+0x8`(本卷 §3.5 补上) | `0x3260598` | 同卷 §3.0(那一卷记 `unresolved`) |

`cmp` 的宽度:**`qword` 比较**(同卷 §2.0 逐字:`cmp qword ptr [rcx + 8], 0x10`)。这一点在本卷是
关键 —— 标签空间是 **64 位位标志**,不是 32 位标志位(§3.3 有 `1<<40` 的实读数)。

TSV 表头(计划 Task 0 Step 2 规定):

```text
tag<TAB>name_candidate<TAB>table<TAB>evidence_section<TAB>verdict
```

**工单口径**:不许按「名字像」下判断。「拼接器产出 `planet` 字符串」只证明名字;
`tag_named` 要求**名字证据 + 值证据**都落在同一站(§3.6)。

---

## §2 名字拼接器族的形状,与 `planet` / `pop` 两个字面的全部引用(2026-11-15,零 shot)

### §2.1 区间 `0x195A580..0x19A7268` 里那些函数**不是**拼接器,是注册函数

计划的技术路线写的是「先读拼接器族的形状,再用 `find_refs.py` 找到 `lea` 它们的拼接器,
然后**从拼接器往上一层**找到注册函数」。**这一跳在本二进制里不存在**,`runtime_444_c1_validation.md`
§80.1 已经用 `every_system` 踩过一次(「字面量所在的那个函数自己就是注册函数」),本卷独立复核成立:

- 真正的**拼接器**在区间**下面**:`0x192AFE0`(`"every_"` + 入参)、`0x192B350`(`"random_"`)、
  `0x192B690`(`"ordered_"`)。它们每个只做「前缀字面量 + `std::string operator+`(`0x15F420`)」。
- `0x195A580..0x19A7268` 里的函数是**注册函数**:自己 `lea` 基础名字面量,调上面的拼接器,
  再 `0x1D13270`(`GetOrAddToken`)铸名、`0x3AEF60`/`0x348150` 插 BST。

`0x195A580` 逐条(区间第一个成员,说明「本区间里也有只拼固定名的成员」):

```text
$ python3 scripts/disrva.py 0x195A580 --len=0x140
  0195a580  push    rbx
  0195a582  sub     rsp, 0x80
  ...
  0195a5b0  mov     r8d, 0x10
  0195a5b6  lea     rdx, [rip + 0xd10063]  ; -> 0x266a620
  0195a5bd  lea     rcx, [rsp + 0x50]
  0195a5c2  call    0x14015f770  ; -> 0x15f770          ; std::string(字面量, 0x10)
  ...
  0195a5eb  mov     eax, dword ptr [rip + 0xd10227]  ; -> 0x266a818
  0195a5f1  mov     dword ptr [rsp + 0x30], eax
  0195a5f5  movzx   eax, word ptr [rip + 0xd10220]  ; -> 0x266a81c
  0195a5fc  mov     word ptr [rsp + 0x34], ax
  0195a601  mov     byte ptr [rsp + 0x36], 0
  0195a606  lea     r8, [rsp + 0x50]
  0195a60b  lea     rdx, [rsp + 0x20]
  0195a610  mov     rcx, rbx
  0195a613  call    0x14015f420  ; -> 0x15f420          ; operator+(前缀, 名字)
```

两个字面量(同一条 `pestr.py`):

```text
$ python3 scripts/pestr.py 0x266a620 0x266a818
0x266a620: 'owned_pop_amount'
0x266a818: 'count_'
```

⇒ `0x195A580` 拼的是 **`count_` + `owned_pop_amount` = `count_owned_pop_amount`**。它证明两件事:
① 前缀是**代码里的字面量**(`count_` / `every_` / `random_` / `ordered_`),不是变量;
② 本区间里「拼接器」这个名字在计划里被当成一族独立函数,实际是**注册函数内部的 3–5 行**。

区间里 `lea` 到 `.rdata` C 串的读数(全区间按 `.pdata` 函数逐条反汇编,**496 条**,去重后按字符串):

```text
$ <探针> lit            # 见 §6 第 1 段签名
# 496 hits
       1 'system'                         <- every_system 的基础名(§80.1 的 0x247a4a8)
       1 'owned_planet'      2 'planet_army'      2 'system_planet'
       1 'galaxy_planet'     1 'planet_within_border' ...
      23 '%s_trigger'        24 'TRIGGER_PASS'   31 ' = { <triggers> }'
```

**`planet` 与 `pop` 都不在这 496 条里**(表里只有 `planet_army` / `system_planet` /
`owned_planet` / `planet_within_border` / `galaxy_planet` / `pop_faction` / `owned_pop_group` /
`species_pop_group` / `job_pop_group` / `owned_pop_job` / `owned_pop_species`)。

### §2.2 `planet` / `pop` 两个字面的**全部**引用:没有一条落在注册区间

`strfind.py` 每个字面各命中**一份**(`.rdata` 里没有第二份副本):

```text
$ python3 scripts/strfind.py planet pop
'planet': .rdata 0x24839d0
'pop': .rdata 0x248582c
```

引用扫描口径见 §6 第 2 段(逐 4 字节反解 `disp32`,等价于 `find_refs.py` 的 rip 相对那一半,
且**完整**—— 不按指令解码,所以 `lea` / `mov` / `cmp` 形态都算)。读数:

| 字面 | 引用数 | 指令站点(按函数起点对齐反汇编,逐条) | 每条是什么 |
|---|---|---|---|
| `planet` `0x24839d0` | **6** | `0x17dfec` `lea r8,[rip+0x23059dd]`(函数 `0x172e50..0x1af1e7`) | 静态 descriptor 写手 `0x1D15270`:`mov edx,0x2a13`(token id)→ 名字槽 `0x33faf00` |
| | | `0x35f14a` `lea rdx,[rip+0x212487f]`(函数 `0x35f0e0`) | 谓词为假时 `call 0x399580(ctx, "planet", …)` —— **诊断/报错文案**(§2.3) |
| | | `0x39290f` `mov eax,dword ptr [rip+0x20f10bb]`(函数 `0x3927b0`) | 前 4 字节 `"plan"` 当立即数比 —— 同一条报错串的分支 |
| | | `0xf1f52f` `lea r8,[rip+0x156449a]`(函数 `0xf1ed90`) | 字面量比较,与注册无关 |
| | | `0xf202aa` `lea r8,[rip+0x156371f]`(函数 `0xf1fb10`) | 同上 |
| | | `0x1688738` `mov eax,dword ptr [rip+0xdfb292]`(函数 `0x16885f0`) | 前 4 字节当立即数比 |
| `pop` `0x248582c` | **3** | `0x17fdb5` `lea r8,[rip+0x2305a70]`(函数 `0x172e50..0x1af1e7`) | 同一个 descriptor 写手:`mov edx,0x2b44` → 名字槽 `0x3410620` |
| | | `0x392b70` `lea rdx,[rip+0x20f2cb5]`(函数 `0x3927b0`) | 报错串拼装(§2.3 逐条) |
| | | `0x42546f` `lea rbx,[rip+0x20603b6]`(函数 `0x4250d0`) | 字面量比较 |

（对照:同一个扫描对 `system` `0x247a4a8` 给出 **19** 条,其中 `0x196833b` / `0x196834f` /
`0x19684a2` / `0x19684b5` / `0x19685ec` / `0x1968600` 六条全在 `0x19682f0`(§80.1 的注册函数)里。
`planet` / `pop` **一条这样的也没有**。)

⇒ **两个结论**(本卷 §3 的起点):

1. **`every_planet` / `every_pop` 这一族在 4.4.4 里不存在**(不是「没找到」:字面的全部 6/3 条引用
   逐条落地,没有一条在 567 个 mint 的任何邻域,§3.1 的窗口会命中任何形态的字面 `lea`/`mov`)。
   行星的迭代器叫 `every_system_planet` / `every_owned_planet` / `every_galaxy_planet` /
   `every_controlled_planet` / `every_planet_within_border`(§3.3),**基础名是 `system_planet`
   之类的「promote 名」,不是裸 `planet`**。
2. **`0x24839d0` / `0x248582c` 这两份字面属于别的子系统**:静态 descriptor 写手与报错文案。
   它们**不能**当「标签证据」用 —— 本卷判词里没有任何一格引用它们。

### §2.3 报错文案里的 `planet` / `pop` 是什么(排除它们)

`0x3927b0..0x393640`(0xe90 B)同时出现 `planet` 与 `pop` 两个字面,形状是拼一条消息:

```text
  00392b43  test    sil, 0x10
  00392b47  je      0x140392bdc
  00392b6a  mov     r8d, 3
  00392b70  lea     rdx, [rip + 0x20f2cb5]  ; -> 0x248582c        ; "pop", 长度 3
  00392b77  lea     rcx, [rbp - 0x69]
  00392b7b  call    0x14015f770  ; -> 0x15f770
  00392b85  cmp     qword ptr [rbp - 9], 0
  00392b8c  mov     r8d, 3
  00392b92  lea     rdx, [rip + 0x2156577]  ; -> 0x24e9110
  00392b9d  call    0x141c89700  ; -> 0x1c89700
```

`0x399580` 是它的上游:它取 `[rcx+8]`、拼格式串 `0x24e9168` 与名字实参 `r9`(调用方给的就是
`0x24839d0` = `"planet"`),再 `call 0x3927b0` 出消息。这是**脚本报错路径**(scope 类型不匹配时的
提示),与注册/标签无关。

### §2.4 §2 不能说的

1. **「没有 `every_planet`」只对「本 exe 的注册区间 + 全部 567 个 mint」成立。** 本卷没有枚举
   脚本里实际用的 keyword 名(那要 game data 或实机),也**不覆盖经寄存器间接调用 `0x1D13270`**
   的路径(`E8 rel32` 口径只收直接调用);所以**不**断言「4.4.4 的脚本不能写 `every_planet`」——
   只能说「没有任何注册函数铸这个名字」。
2. **区间内 496 条 `lea` 是「本区间函数体内的字符串 lea」,不是「整族的完整名单」。**
   trigger 侧(`any_*` / `count_*`)的名字由 `0x192B440` 那一类**二级拼接器**拼出来,字面量在
   更里层,所以 255 个 mint 在 §3.1 里「没有基础名」—— 那是**探针口径**,不是「这些 mint 没有名字」。
3. **`0x24839d0` 是 `.rdata` 里 `planet` 的唯一一份**,但「唯一」的判据是 `strfind.py` 的
   「字符串起点」启发式(前一字节是 NUL 或非可打印)。嵌在长串里的 `planet`(如
   `planet_index`、`set_planet_flag`)在名字池里有几十份,那与本节无关。

---

## §3 从名字到标签值(2026-11-15,零 shot)

### §3.1 普查:567 个 mint,312 个有基础名,203 个拿到标签常数

口径:`.text` 里全部 `E8 rel32` 形式的**直接调用** `0x1D13270`(`GetOrAddToken`),按 `.pdata`
函数桶归类,再在**同一个函数内**的 `mint` 邻域(前 16 条指令)找最近的基础名字面量 `lea`、
`[rcx]` 上的 `class_info` `lea`、插入调用(`0x3AEF60` 效果侧 / `0x348150` 触发侧)。

```text
mint 站点总数                 567      (与 runtime_444_keyword_pipeline.md §19 的 567 一致)
其中同函数能找到基础名        312
其中还能拿到标签常数          203
效果侧插入(0x3AEF60)        306
触发侧插入(0x348150)        206
另外 55 个 mint 邻域内没有插入调用(在包装函数里,不在本节口径内)
```

**标签常数的承载机制**(本节最重要的一条,两条路线都建立在它上面)。每个效果侧迭代器的
`class_info` qword[1] = `create`;`create` 是同一个模板:

```text
$ python3 scripts/disrva.py 0x1a70a60 --len=0x50        ; class_info 0x2666b70 → create(`random_system_planet` 那一份)
  01a70a60  push    rbx
  01a70a66  mov     ecx, 0x1c8
  01a70a6b  call    0x142185218  ; -> 0x2185218        ; operator new(0x1c8)
  01a70a70  mov     rbx, rax
  01a70a78  mov     edx, 2                            ; ★ 标签常数 = 2
  01a70a7d  mov     rcx, rax
  01a70a80  call    0x14192b260  ; -> 0x192b260       ; 迭代器 ctor(第 2 实参 = 标签)
  01a70a85  lea     rax, [rip + 0xbea894]  ; -> 0x265b320   ; vtable
```

两个 ctor 都把它写进对象的 **`+0x180`**(逐条,两个 ctor 各一条):

```text
$ python3 scripts/disrva.py 0x192b260 --len=0x50
  0192b26f  mov     rbx, rdx
  ...
  0192b29d  mov     qword ptr [rdi + 0x180], rbx

$ python3 scripts/disrva.py 0x17f7860 --len=0x60
  017f786f  mov     rbx, rdx
  ...
  017f78b2  mov     qword ptr [rdi + 0x180], rbx
```

**这个 `+0x180` 就是迭代循环写进子 scope 的那一格**(与图卷/§80.2 同一个机制,本卷在**行星**这一支
独立复读了一次):

```text
$ python3 scripts/disrva.py 0x1a1b0e0 --len=0x1d0         ; system_planet 与 owned_planet 共用的 slot[+0x70]
  01a1b250  mov     rax, qword ptr [rbx + 8]              ; 本轮的 id 向量
  01a1b254  mov     r8d, dword ptr [rdi + rax]
  01a1b258  mov     rax, qword ptr [r14 + 0x180]          ; ★ 本类的标签
  01a1b25f  mov     qword ptr [rsp + 0x28], rax           ; scope+0x08 = 标签
  01a1b264  mov     dword ptr [rsp + 0x30], r8d           ; scope+0x10 = id
  01a1b269  cmp     rax, 0x10
  01a1b26d  jne     0x141a1b2bc                          ; 只有标签 == 0x10 才预解析对象
  01a1b26f  mov     rdx, qword ptr [rip + 0x1845d82]  ; -> 0x3260ff8
```

**`cmp rax, 0x10` 这一条是 §3.4 的第一个内部印证**:引擎只在标签 == `0x10` 时把对象**预解析**进
`scope+0x14`,而 `scope+0x14` 这一格**只有 mask `0x10` 的 getter 读**(同卷 §2.1 / §2.8 第 3 条)。
两条独立读数指向同一格(见 §3.6 结论与 §5 第 2 条)。

### §3.2 标签常数逐条(203 个 mint,35 个不同值)

`35` 个不同标签值,每个值下面挂的**基础名字面量**逐条抄自探针输出(同一标签有多个名字是正常的 ——
同一个 scope 类型被 `every_`/`random_`/`ordered_` 三个前缀各铸一次,再加若干 promote 名):

| tag | 基础名字面量(注册函数里的 `lea`) |
|---|---|
| `0x1`  | `megastructure` `owned_megastructure` `system_megastructure` |
| `0x2`  | `controlled_planet` `galaxy_planet` `moon` `planet_within_border` `system_planet` |
| `0x4`  | `associate` `attacker` `council_member` `country` `country_neighbor_to_system` `defender` `federation_ally` `galcom_member` `member` `neighbor_country` `observed_pre_ftl_within_border` `playable_country` `pre_ftl_within_border` `relation` `rival_country` `subject` `war_participant` |
| `0x8`  | `controlled_ship` `owned_ship` `ship_in_system` |
| `0x20` | `job_pop_group` `owned_pop_group` `species_pop_group` |
| `0x40` | `combatant_fleet` `controlled_fleet` `fleet_in_orbit` `fleet_in_system` `galaxy_fleet` `orbital_station` `owned_fleet` |
| `0x80` | `cosmic_storm_end_position` `cosmic_storm_start_position` `neighbor_system` `neighbor_system_euclidean` `rim_system` `system` `system_added_to_storm` `system_in_cosmic_storm_influence_field` `system_removed_from_storm` `system_with_aura` `system_within_border` `system_within_storm` |
| `0x100` | `envoy` `owned_leader` `pool_leader` |
| `0x200` | `ground_combat_attacker` `ground_combat_defender` `owned_army` `planet_army` |
| `0x400` | `ambient_object` `system_ambient_object` |
| `0x800` | `enslaved_species` `galaxy_species` `owned_pop_species` `owned_species` |
| `0x1000` | `bypass` `bypass_in_system` |
| `0x2000` | `owned_design` |
| `0x4000` | `pop_faction` |
| `0x8000` | `war` |
| `0x10000` | `federation` |
| `0x20000` | `owned_nonprimary_starbase` `owned_starbase` `starbase_in_network` `starbase_in_system` |
| `0x40000` | `deposit` |
| `0x100000` | `galaxy_sector` `owned_sector` |
| `0x400000` | `archaeological_site` |
| `0x800000` | `active_first_contact` `first_contact` |
| `0x1000000` | `spynetwork` |
| `0x2000000` | `espionage_operation` |
| `0x4000000` | `espionage_asset` |
| `0x10000000` | `agreement` |
| `0x20000000` | `situation` `targeting_situation` |
| `0x40000000` | `available_debris` |
| `0x80000000` | `astral_rift` |
| `0x200000000` | `cosmic_storm` |
| `0x400000000` | `owned_storm_influence_field` |
| `0x800000000` | `exhibit` |
| `0x2000000000` | `owned_pop_job` |
| `0x4000000000` | `existing_species_traits` `trait_available_for_species` `trait_of_species` |
| `0x10000000000` | `controlled_colony` `owned_colony` `owned_planet` `system_planet_colony` `system_ship_colony` |
| `0x20000000000` | `issued_mission` `owned_contract` `owned_mission` |

**三处必须点出**:

1. **`0x10` 不在表里。** 203 个 mint 里**没有一个**标签常数是 `0x10`。这是本节最重要的负读数。
2. **`planet` = `0x2`,而且 `moon` 也是 `0x2`**(卫星是行星类对象);**`owned_planet` 不是 `0x2`,
   是 `1<<40`**(`owned_planet` 自己的 create = `0x1a71300`,见下表;**`0x1a71260` 不是同一个
   create**,是同一个注册函数 `0x1954790` 也 `lea` 的另一份 `class_info 0x2666c30` —— 两者标签
   都 `1<<40`,但 create、vtable 与对象大小都不同。2026-11-16 勘误,见 §4.1),也就是说
   `every_owned_planet` 轮内下发的 scope 标签是 **colony** 而不是 planet。
3. **`scope+0x08` 是 64 位位空间**:`1<<33`(cosmic_storm)到 `1<<41`(mission)全是实读数,不是我的推测。
   同卷 §2.0 的 `qword` 比较宽度在这一条上兑现。

关键 mint 行(探针 TSV 原样,列 = `mint / 注册函数 / 基础名 / class_info / create / tag / tag 站点 / ctor`):

```text
0x1951db5  0x1951a90..0x1952386  system_planet       0x2666b90  0x1a70b00  0x2            0x1a70b18  0x17f7860
0x1954ab5  0x1954790..0x1955086  owned_planet        0x2666c50  0x1a71300  0x10000000000  0x1a71318  0x17f7860
0x194d304  0x194d290..0x194db86  megastructure       0x26670a0  0x1a6fa60  0x1            0x1a6fa78  0x192b260
0x1943054  0x1942fe0..0x19438d6  espionage_operation 0x2667280  0x1a6d660  0x2000000      0x1a6d678  0x192b260
0x193b9e4  0x193b970..0x193c266  country             0x2667650  0x1a6bc60  0x4            0x1a6bc78  0x192b260
```

`owned_planet` 那一行的 ctor 之前是 **`movabs rdx, 0x10000000000`**(不是 `mov edx, imm`),
这就是「32 位立即数读法会读错」的那一格:

```text
$ python3 scripts/disrva.py 0x1a71300 --len=0x30
  01a71300  push    rbx
  01a71302  sub     rsp, 0x20
  01a71306  mov     ecx, 0x188
  01a7130b  call    0x142185218  ; -> 0x2185218
  01a71310  mov     rbx, rax
  01a71313  mov     qword ptr [rsp + 0x38], rax
  01a71318  movabs  rdx, 0x10000000000
  01a71322  mov     rcx, rax
  01a71325  call    0x1417f7860  ; -> 0x17f7860
```

### §3.3 第一条路线的名字只是「基础名」,不是 scope 类型名

`system_planet` 三个前缀全读到(同一注册函数 `0x1951a90` 的三个 mint):

```text
  mint @0x1951c69  base=0x26693f8 'system_planet'  join=0x192b690 prefix='ordered_'
  mint @0x1951db5  base=0x26693f8 'system_planet'  join=0x192afe0 prefix='every_'
  mint @0x1951b04  base=0x26693f8 'system_planet'  join=0x192b350 prefix='random_'
```

⇒ 铸出的 token 名是 `random_system_planet` / `ordered_system_planet` / `every_system_planet`。
**基础名 `system_planet` 是「promote 名」**(从系统 scope 里取行星),标签却与 `galaxy_planet` /
`controlled_planet` / `planet_within_border` / `moon` 相同 = `0x2`。所以:

- 「基础名」能证明**这一族是行星类**,但**不能**直接给 scope 类型起名;
- 要把 `0x2` 起成 `planet`,需要一条**独立**的语义证据 —— 那就是 §3.4。

### §3.4 第二条路线(与拼接器无关):类的 **scope 接受掩码** `vtable+0x78` + 引擎自带 docstring

这一条路线在 `country_scope_4_4_4.md` §6 已经是 **A 级**读数(mask `0x04` = country),
本卷把它系统化。机制(逐条):

```text
$ python3 scripts/disrva.py 0x3b14b0 --len=0x40          ; scope 类型门
  003b14d6  mov     rax, qword ptr [rcx]                  ; self->vtable
  003b14d9  call    qword ptr [rax + 0x78]                ; ★ 本类接受的 scope 类型位
  003b14dc  mov     rsi, rax
  003b14df  test    rax, rax
  003b14e2  je      0x1403b16c7
  003b14e8  test    qword ptr [r15 + 8], rax              ; ★ [scope+0x08] & 接受掩码
  003b14ec  je      0x1403b14ff
```

⇒ 每个 effect/trigger 类的 `vtable+0x78` 返回一个**与 `[scope+0x08]` 同一空间的位掩码**。
`country_scope_4_4_4.md` §6 已经用 `country_event` 的 `0x26080b0 + 0x78 = 0x241bd0`
(`mov eax,4; ret`)把 `0x04` 钉成 country —— 也就是**这条路线在既有卷里是 A 级**。

本卷对 3,900 条静态 keyword 做了这一步(`class_info` → `create` → vtable → `qword[vtable+0x78]`),
1,583 条解析出接受函数;其中 326 条含 `0x10` 这一位。逐位读数:

| 掩码 | 该类的官方 docstring(逐字) | 关键字样本 | 接受函数(逐条) |
|---|---|---|---|
| `0x1`   | Sets an arbitrarily-named flag on the scoped **mega structure** | `set_megastructure_flag` | — |
| `0x2`   | Fires a **planet** event for the scoped planet … | `planet_event` | `0x1b4550` = `mov eax, 2` |
| `0x4`   | Fires a **country** event for the scoped country … | `country_event` | `0x241bd0` = `mov eax, 4` |
| `0x8`   | Fires a **ship** event for the scoped ship … | `ship_event` | `0x1b58e0` = `mov eax, 8` |
| **`0x10`** | Fires a **pop** event for the scoped pop … / Sets an arbitrarily-named flag on the scoped **pop** | `pop_event` `set_pop_flag` `remove_pop_flag` `set_timed_pop_flag` | **`0x1b57c0` = `mov eax, 0x10`** |
| `0x20`  | Fires a **pop group** event for the scoped pop group … | `pop_group_event` | `0xd89ff0` = `mov eax, 0x20` |
| `0x40`  | Fires a **fleet** event for the scoped fleet … | `fleet_event` | `0x1b3f80` = `mov eax, 0x40` |
| `0x80`  | Fires a **system** event for the scoped system | `system_event` | `0x234f90` = `mov eax, 0x80` |
| `0x100` | Fires a **leader** event … | `leader_event` | `0x180ddb0` = `mov eax, 0x100` |
| `0x200` | … scoped **army** | `set_army_flag` | — |
| `0x400` | … scoped **ambient object** | `set_ambient_object_flag` | — |
| `0x800` | … scoped **species** | `set_species_flag` | — |
| `0x1000` | … scoped **bypass** | `bypass_event` | — |
| `0x2000` | … scoped **design** | `set_design_flag` | — |
| `0x4000` | … scoped **pop faction** | `pop_faction_event` | — |
| `0x8000` | … scoped **war** | `set_war_flag` | — |
| `0x10000` | … scoped **federation** | `set_federation_flag` | — |
| `0x20000` | … scoped **starbase** | `starbase_event` | — |
| `0x40000` | … scoped **deposit** | `set_deposit_flag` | — |
| `0x100000` | … scoped **sector** | `set_sector_flag` | — |
| `0x400000` | … scoped **arc site** | `set_archaeology_flag` | — |
| `0x800000` | … scoped **first contact site** | `set_first_contact_flag` | — |
| `0x1000000` | … scoped **spy network** | `set_spynetwork_flag` | — |
| `0x2000000` | … scoped **espionage operation** | `set_espionage_operation_flag` | — |
| `0x4000000` | … scoped **espionage asset** | `set_espionage_asset_flag` | — |
| `0x10000000` | … scoped **agreement** | `set_agreement_flag` | — |
| `0x20000000` | … scoped **situation** | `set_situation_flag` | — |
| `0x40000000` | Passes the scoped **debris** ownership … | `pass_debris_ownership` | — |
| `1<<40` | Fires a **colony** event for the scoped colony … | `colony_event` | `0x180dff0` = `movabs rax, 0x10000000000` |

`colony_event` 那一行同时解释了两件事:① `1<<40` = **colony**,所以 §3.2 里
`owned_planet` / `owned_colony` 共用一个 create 是**对的**(「owned planet」在 4.4.4 的 scope
类型是 colony);② 32 位立即数读法在这里会**读成 0**(`movabs`),必须按 64 位读。

**两条路线独立**:路线 1 从注册函数的 `create` 立即数来,路线 2 从**另一个字段**(类的
`vtable+0x78`)与**另一份 `.rdata`**(官方 docstring)来;两者没有共享任何一个字节。

### §3.5 与同卷 §2.1–§2.5 的五格对表(每条 getter 都读到了,28 个掩码)

同一套模板(`mov rdx,[rcx+0x1c]; test rdx,rdx; je; cmp qword [rcx+8],<mask>; …`)在 `.text` 里有
**43 个实例、28 个不同掩码**。五格逐条(掩码 / getter / 表全局槽 / 对象内 id / 回退对象):

```text
0x1          0x394870   0x3261010  0x8    0x3260118
0x2          0x393b70   0x3260b78  0x18   0x325f170
0x4          0x393dd0   0x3260fd8  0x20   0x325f390     <- AGENTS 的国家表、国家 id +0x20
0x8          0x393fb0   0x3260fd0  0x18   0x325f9e0     <- 同卷 §3.6 的 single_reader 表
0x10         0x394190   0x3260ff8  0x10   0x325fb00     <- 同卷 §2.1(逐字一致)
0x20         0x2b6470   0x3260ff0  0x10   0x325fae8     <- 同卷 §2.2(逐字一致)
0x40         0x393ec0   0x325ef00  0x30   0x325fa20     <- 同卷 §2.3(逐字一致)
0x80         0x393970   0x3260b98  0x8    0x325d880     <- 同卷 §2.5(逐字一致)
0x100        0x393a70   0x3260b70  0x20   0x325f138
0x200        0x3942b0   0x3260fe8  0x10   0x325fdd0
0x400        0x3944b0   0x3261080  0x8    0x325fe88
0x800        0x3943b0   0x325ef10  0x10   0x325f320
0x1000       0x3952e0   0x3261048  0x8    0x3260240
0x2000       0x3940a0   0x325d868  0x10   0x325d860
0x4000       0x3945b0   0x3260fe0  0x8    0x325fa90
0x8000       0x394690   0x3261090  0x20   0x325fc98
0x10000      0x394770   0x3261018  0x8    0x325fcf0
0x20000      0x394960   0x3261008  0x8    0x32601d8
0x40000      0x394a60   0x3261000  0x10   0x325f678
0x100000     0x394b40   0x3261038  0x8    0x3260358
0x400000     0x394bc0   0x3260f00  0x8    0x32603d0
0x800000     0x394d80   0x3260f20  0x8    0x32605b8
0x1000000    0x394ca0   0x3261030  0x8    0x3260540
0x2000000    0x394e60   0x3260f18  0x8    0x3260598     <- 同卷 §3.0 的 unresolved 一格
0x4000000    0x394f40   0x3261028  0x8    0x3260550
0x10000000   0x394fc0   0x3260f10  0x8    0x3260798
0x20000000   0x3950a0   0x3261020  0x8    0x32606f0
0x40000000   0x395180   0x3261058  0x8    0x325fd28
```

**§2 的五行与既有卷逐字一致**(上表打了 `<-` 的五条),这是本探针的**自校准**:如果模板识别错一格,
这五行里至少一条会错位。另外两格**顺手把同卷 §3.0 / §4.4 的缺口补上**:

- `0x3260f18`(mask `0x2000000`,上一卷 §3.0 判 `unresolved`、§4.4 第 2 条列为下一靶)的
  **对象内 id = `+0x8`**,站点 `0x394ecc` 的 `cmp dword ptr [rax + 8], r8d`:

  ```text
  $ python3 scripts/disrva.py 0x394e60 --len=0x70
    00394e98  mov     rdx, qword ptr [rip + 0x2ecc079]  ; -> 0x3260f18
    00394eb4  cmp     eax, dword ptr [rdx + 0x20]                 ; 界
    00394ebb  mov     rax, qword ptr [rdx + 0x18]                 ; 表指针
    00394ebf  add     rcx, rcx                                    ; 16 B 记录
    00394ec2  mov     rax, qword ptr [rax + rcx*8 + 8]
    00394ecc  cmp     dword ptr [rax + 8], r8d                     ; ★ 对象内 id = +0x8
  ```

- `0x2`(planet)的 getter 是 `0x393b70`,表 `0x3260b78`、对象内 id `+0x18`、回退 `0x325f170`:

  ```text
  $ python3 scripts/disrva.py 0x393b70 --len=0x80
    00393b70  mov     rdx, qword ptr [rcx + 0x1c]
    00393b79  cmp     qword ptr [rcx + 8], 2
    00393b7e  mov     rax, qword ptr [rip + 0x2ecb5eb]  ; -> 0x325f170
    00393b85  cmove   rax, rdx
    00393ba2  mov     rax, qword ptr [rip + 0x2eccfcf]  ; -> 0x3260b78
    00393bd3  cmp     dword ptr [rax + 0x18], edx
  ```

  `0x3260b78` 与对象 id `+0x18` 与同卷 §5.1 那行(「`0x3260b78` 表、对象 id `+0x18` ← 作者卷 §3.5
  `original_owner` 家族」)**逐字对上**,而且 `runtime_444_transitability_4_4_4.md` §3.3 的
  `is_original_owner` 分支就是「mask 2 → 同一张 `0x3260b78`」。⇒ 行星那一支是**三卷合读**。

### §3.6 两条路线合起来的结论表(`[scope+0x08]` 的标签 ↔ 名字 ↔ 表)

| tag | 名字 | 路线 1(迭代器基础名) | 路线 2(接受掩码 docstring) | 该 tag 的 getter / 表 |
|---|---|---|---|---|
| `0x1` | `megastructure` | `megastructure` `owned_megastructure` `system_megastructure` | mega structure | `0x394870` / `0x3261010` |
| **`0x2`** | **`planet`** | `system_planet` `galaxy_planet` `controlled_planet` `planet_within_border` `moon` → 2 | `planet_event` = 2 | `0x393b70` / `0x3260b78` |
| `0x4` | `country` | 17 个 country 族 → 4 | `country_event` = 4(**A 级**) | `0x393dd0` / `0x3260fd8` |
| `0x8` | `ship` | `owned_ship` `controlled_ship` `ship_in_system` → 8 | `ship_event` = 8 | `0x393fb0` / `0x3260fd0` |
| **`0x10`** | **`pop`** | **无迭代器** | `pop_event` / `set_pop_flag` = 0x10 | `0x394190` / `0x3260ff8` |
| `0x20` | `pop_group` | `owned_pop_group` `species_pop_group` `job_pop_group` → 0x20 | `pop_group_event` = 0x20 | `0x2b6470` / `0x3260ff0` |
| `0x40` | `fleet` | 7 个 fleet 族 → 0x40 | `fleet_event` = 0x40 | `0x393ec0` / `0x325ef00` |
| `0x80` | `system` | 12 个 system 族 → 0x80 | `system_event` = 0x80(**A 级**) | `0x393970` / `0x3260b98` |
| `0x100`…`0x40000000` | leader / army / ambient_object / species / bypass / design / pop_faction / war / federation / starbase / deposit / sector / archaeological_site / first_contact / spynetwork / espionage_operation / espionage_asset / agreement / situation / debris | 见 §3.2 | 见 §3.4 | 见 §3.5 |
| `1<<40` | `colony` | `owned_planet` `owned_colony` `controlled_colony` `system_planet_colony` `system_ship_colony` | `colony_event` = `1<<40` | **无**(不在 28 个掩码里) |
| `0x200000` | — | 无 | 无(1,583 条里没有任何一条恰好是这一位) | 无 |

**为什么 `0x10` 只有路线 2**:效果侧迭代器(`every_*`/`random_*`/`ordered_*`)必须有一个「容器 + 循环」;
4.4.4 里 pop 的遍历走 **pop group**(`0x20`)与 pop job(`1<<33`),没有 `every_pop` 这一类迭代器
(§2.2 的 6 条字面引用逐条落地,没有一条能铸 `every_pop`)。所以 `0x10` 这一位只能从
「哪个类的 `vtable+0x78` 返回它 + 那个类的官方 docstring」读出来 —— 那是**引擎自己的两个常数**,
不是我的推断。

**`0x10` 与「特别的一格」互相印证**:`scope+0x14` 这一格(内联对象指针)只有两处读:
mask `0x10` 的 getter(`0x3941b6`–`0x3941bd`),和迭代循环里的 `cmp rax, 0x10` 预解析分支
(`0x1a1b269`,§3.1)。两处在**同一个标签值**上碰头,而路线 2 把这个值叫 `pop`。

### §3.7 §3 不能说的

1. **`tag_named` 证明的是「这个标签位的迭代器/接受类叫这个名字」**,**不**证明「表里存的 id 域
   与整数 id 一致」(同卷 §4.4 第 4 条仍未解)。
2. **`0x2` / `0x10` 的语义都**不是**从「表里存了什么对象」读出来的。** 本卷没有读任何一张表的
   元素、也没有读任何一个对象类的 vtable 语义;两条路线都只读「常数」。
3. **`1 .. 0x40000000` 这个位段里有一格是空缺**:`0x200000`(bit 21)在 1,583 条静态 keyword 里没有任何一条
   恰好用它,迭代器侧也没有。它可能**未使用**,也可能是一个没有 keyword 的 scope 类型 ——
   本卷判 `tag_unresolved`,不猜。
4. **八个高位标签只有路线 1(其中 `colony` 例外)。** `astral_rift`(bit 31)、`cosmic_storm`(33)、
   `storm_influence_field`(34)、`exhibit`(35)、`pop_job`(37)、`species_trait`(38)、`colony`(40)、
   `mission`(41)都没有 getter(28 个掩码止于 `0x40000000`),所以它们的「读哪张表」这一格**空着**;
   §3.2 给的只是名字 + 常数。`colony` 是唯一有路线 2 的一个(`colony_event`)。

---

## §4 判决与慢通道自证(2026-11-15,零 shot)

判决: tags_named_all
前提: 每个标签的名字证据与值证据分别来自——名字:路线 1 的注册函数基础字面量(§3.2,站点点名)
      与路线 2 的官方 docstring(§3.4);值:路线 1 的 `create` 立即数(§3.1 的 ctor 机制)
      与路线 2 的 `vtable+0x78` 接受函数(§3.4)。两条路线没有共享字节,交叉点见 §3.6。
下一步: `getPlanet(id)` 现在可以选表了 —— planet = `0x2` → 表 `0x3260b78`、对象内 id `+0x18`、
      回退 `0x325f170`、getter `0x393b70`;`getPop(id)` = `0x10` → 表 `0x3260ff8`、对象内 id `+0x10`、
      回退 `0x325fb00`、getter `0x394190`(同卷 §2.1 已逐条读过,本卷只给它起名)。
      两者都还差同卷 §4.4 第 3、4 条(缓存槽填充方、raw/masked 口径)。

判词的**确切含义**(防误读):`tags_named_all` 指**工单的六个标签 + `planet` / `pop`** 全部有判词
(§1 的表)。它**不**指「64 位空间里每一位都命名了」—— `0x200000` 判 `tag_unresolved`,
8 个高位标签(bit 31/33/34/35/37/38/40/41)只有名字、没有表。

`evidence/xrefs/scope_tags_4_4_4.tsv` 的 37 条里 `tag_unresolved` **只有 1 条**(`0x200000`)。

**慢通道(`find_refs.py`)自证**:本卷共**调用 2 次**,都是
`python3 scripts/find_refs.py 0x24839d0 0x248582c`(问:`planet` 与 `pop` 两个字面在全 `.text`
里的全部 rip 相对引用,用来找「`lea` 它们的拼接器」)。**两次都在打印任何读数之前被宿主重启打断**
(第一次 21:59 起、第二次作为后台进程,都被 container 重启杀掉),所以**完成的读数 = 0 次**。
为了不反复占慢通道,改用 §6 第 2 段的「逐 4 字节反解 `disp32`」扫描(等价于 `find_refs.py` 的
rip 相对那一半,且**不按指令解码**,所以三种形态全收):`planet` 6 条、`pop` 3 条、`system` 19 条
(§2.2)。**预算 4,用了 2,没有第 3 次。**

### §4.1 勘误(2026-11-16,复核时补):`§3.2` 的两处数字

收尾复核时把 `§3.2` 的每条读数重打了一遍。**判决与判词不变**(`tags_named_all`、`planet = 0x2`、
`pop = 0x10`),改的是两处**转写**:

1. **`0x1a71300` 的逐条反汇编块**(§3.2 末)原来抄成了 `0x1a70a60` 那一块的后半段:实际是
   `mov ecx, 0x188`(不是 `0x1c8`)、`call 0x17f7860`(不是 `0x192b260`),且中间还有
   `sub rsp, 0x20` / `mov rbx, rax` / `mov [rsp+0x38], rax` 三条。已按 `disrva.py` 的原文替换。
   该行 `ctor` 列写的是 `0x17f7860`,**一直是对的** —— 错在块内注释。
2. **「`owned_planet` 与 `owned_colony` 同一个 create `0x1a71260`」不成立。**
   `class_info 0x2666c50` 的 qword[1] = `0x141a71300` ⇒ `owned_planet` 的 create 是 **`0x1a71300`**;
   `0x1a71260` 是**另一份** create(`class_info 0x2666c30`、0x1c8 对象、ctor `0x192b260`、
   vtable `0x265bee0`)。两者都由注册函数 `0x1954790..0x1955086` 里的 `lea rcx,[…]` 引到 —— 那个
   函数引 `0x2666c30` / `0x2666c20` / `0x2666c50` / `0x2666c40` / `0x2666ca0` 五份 class_info,
   并同时 `lea` 名字 `owned_planet`(`0x26690f0`)与它的 deprecated 别名 docstring
   (`0x2669090`「Iterate through each colony owned by the current empire (Deprecated; use
   owned_colony instead)」)。**所以「同一族、不同 create、同标签 `1<<40`」才是实况**,
   §3.2 第 2 条那句「同一个 create」已改。

复核用的工具:`scripts/disrva.py`(逐条)、`scripts/pestr.py`(字面)、`scripts/riprefs.py --verify`
(找 `class_info` 的 `lea` 站点;秒级通道,**不计入** `find_refs.py` 预算 —— 本条把慢通道计数保持
在**仍然 2 次**)。

---

## §5 不能说的(至少四条,计划 Task 3 Step 2)

1. **本卷零 shot。** 所有读数都是「指令存在」「字面存在」「`.rdata` 里的类字段存在」。没有一次
   运行时确认过 `[scope+0x08]` 真的是这个值、也没有确认过任何一张表在活体里非空。
2. **`tag_named` 不证明「表里存的 id 域与整数 id 一致」。** 「`0x394190` 是 pop 解析器」
   只说「它拿 `[scope+8]==0x10` 当门、去查 `0x3260ff8`」。表里那一格的 id 域(掩码后 /
   原始 / 24 位)是另一件事,同卷 §4.4 第 4 条仍然开着。
3. **标签常数的宽度是 64 位,相邻字段的语义未读。** `[obj+0x180]` 是 qword;`create` 用
   `mov edx,imm` 时高 32 位是**零扩展**,用 `movabs rdx,imm` 时高 32 位有值(§3.2 的
   `owned_planet` = `1<<40`)。**不要把「同一个字段」读成「同一套语义」**:`0x2` 与 `1<<40`
   都是「一个 scope 类型位」,但 `1<<40` 的类(`colony_event`)有**自己的** docstring 与 create。
4. **`.rdata` 里同名有多份副本时,本卷只对「被注册函数 `lea` 的那一份」负责。**
   `planet` / `pop` 各只有一份(§2.2);`system` 有 19 条引用,而名字池里那些 `every_*` 名
   是前缀在运行时**拼**出来的、不是字面量。下一份计划要引用某个字面量的 RVA,必须用 §2.2 的表。
5. **两条路线的一致不是「同一个证据被数了两次」,但它也不是实机。** 它们共享的只有
   **二进制作者那一个意图**(同一个 enum);若那个 enum 在 4.4.4 之外还有别的解释
   (例如 DLC/版本开关),本卷看不见 —— 本卷只有一份 exe 的一个 sha256。

---

## §6 复现:三段签名

探针在仓外(计划禁止动 `scripts/` 一个字节),但三段判据都是**纯签名匹配**,可以照抄重建。

**第 1 段:区间里全部 C 串 `lea`**(§2.1 的 496 条)。按 `.pdata` 归并(同一 start 取最大 end,
chained unwind 记录会把一个函数拆成几条),逐函数 capstone 反汇编,取每条 `lea` 的 rip 目标,
`cstr()` 认下来(末字节 NUL、全可打印)就记 `(函数起点, 字面 RVA, 字符串)`。

**第 2 段:字面的全部 rip 相对引用**(§2.2 的 6 / 3 / 19 条)。不按指令解码,直接:

```python
for p in range(len(text) - 4):
    disp = struct.unpack_from('<i', text, p)[0]
    if text_va + p + 4 + disp == target_rva:   # 任何以 p+4 结尾、rip 相对且指到 target 的指令
        hits.append(text_va + p)
```

**第 3 段:标签常数**(§3.1 / §3.2)。对每个 `call 0x1D13270` 的站点:

```python
1. 基础名  = 站点前 16 条指令里最近的、`lea` 到一个 C 串的那条;
2. 拼接器  = 站点前 16 条里 `call` 到 0x192AFE0 / 0x192B350 / 0x192B690(...) 的那条;
3. class_info = 站点后到第一条 `call 0x3AEF60|0x348150` 之间、`lea rcx,[0x26xxxxx]` 的那条;
4. create  = qword[class_info + 8] - 0x140000000;
5. 标签    = create 里第一条 `mov edx|rdx|r8d|r8, imm` 且后 1–3 条是 `mov rcx,…` + `call`
             其中 call 目标 ∈ {0x192B260, 0x17F7860}(两个 scope 标签 ctor);立即数按 **64 位**读。
```

第 3 段的第 5 步**必须**限定 ctor 目标:触发侧(`any_*` / `count_*`)的 create 调的是
`0x2188170`(`edx=0`、`r8d=对象大小`),不限定就会把对象大小(`0xc8` / `0x380`)读成标签 ——
本卷第一版踩过这个坑(`104` 条假 `0x380`、`102` 条假 `0xc8`),`0x192B260` 白名单之后清零。

**第 4 段:接受掩码**(§3.4)。对 `keyword_behaviour_registration_4_4_4.tsv` 每行:
`class_info` → `create` → create 里 `lea rax,[0x24xxxxx..0x27xxxxx]` 后紧跟 `mov [reg], rax`
(vtable)→ `qword[vtable + 0x78]`;若该目标是 `mov eax,imm32; ret` 取 imm32,
若 `movabs rax,imm64; ret` 取 imm64(§3.4 的 `colony` 那一行就是后者)。
