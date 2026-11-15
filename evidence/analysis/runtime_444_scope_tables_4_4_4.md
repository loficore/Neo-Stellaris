# runtime_444_scope_tables_4_4_4 — pop / fleet / planet 三张表 + 五个 scope getter 的离线定形

**授权:零 shot。** 只读 exe 副本 + 仓内取证卷 + 存档文本;不注入、不起游戏、不碰 Windows 机、不用 IDA。
置信档沿用既有卷:`pinned(§N)` / `静态推断(未验证)` / `未定形`。

```text
exe  = /var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe
sha256(实测) = 9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56
size = 46,253,688 B
date = 2026-11-15
```

**本卷回答什么**:`runtime_444_transitability_4_4_4.md` §8.2 那张表里点到的 8 个候选——5 个
`scope cell → 对象` 的 getter(`0x394190` / `0x2b6470` / `0x393ec0` / `0x394870` / `0x393970`)
与 3 张表(`0x3260ff0` / `0x3261030` / `0x3261068`)——**各自是什么形状**:
getter 收 scope cell 的哪个字段、经哪张表、返回什么;表 = `全局槽 / 界 / 表指针 / 记录步长 /
对象指针偏移 / 对象内 id 偏移`,外加**读者数**。

**本卷不回答什么**:

1. **它们是哪个 scope 的语义名。** 「这张表是 pop 表」这句话本卷不写 —— 名字不是从符号来的
   (`§1.4`,§5「不能说的」第 1 条),本卷只有「哪条指令读哪个全局槽」。
2. **能不能当 API。** §8.2 作者卷的 §6.3 已经立过这条规矩:字段未 pinned 前不许写成契约。
   本卷把形状钉死,但**没有一次运行时读数**,所以连「形状在活体里成立」都还没证。
3. **`getPlanet(id)` / `getPop(id)` 能不能实现。** §4.3 给出还缺哪几格;缺的格本卷不填。

**输入**(全部只读):

| 输入 | 用途 |
|---|---|
| `stellaris.exe` 4.4.4(上面那份 sha256) | 唯一的指令来源 |
| `evidence/analysis/runtime_444_transitability_4_4_4.md` §8.2 | 候选清单的**唯一起点**,逐字引用不改写 |
| `runtime_444_graph_runtime.md` §1.2/§1.11 | 系统索引的形状先例与「步长 16 B」勘误 |
| `src/dll/shared/offsets.zig` 的 `country_table` / `graph` | 国家表与系统索引的形状先例(只读,不改) |
| 4.4.4 存档(`scripts/save_hypergraph.py`) | 只证伪(§4.1) |

**工具**(口径见 `docs/offline-tooling.md`,本卷不新增脚本):

```text
scripts/disrva.py       逐条指令(rip 相对操作数解析成 RVA);本卷全部读数的来源
scripts/global_xrefs.py 快通道:单全局反查 + 形态分类(读者数的来源)
scripts/find_refs.py    慢通道:call/jmp/rip 全域扫描(与快通道互为独立读者)
scripts/rttibatch.py    镜像 / .pdata / RTTI(本卷用它否掉「表对象有 RTTI 名」这一条路,§2.1)
```

**产物出处**(按 basename 记录,追加不改写):

```text
evidence/xrefs/scope_tables_4_4_4.tsv   8 条候选 + getter 自带的表:一行一个读数
evidence/analysis/runtime_444_scope_tables_4_4_4.md   本卷
```

**两套编号,全卷不许混**(计划 Review Focus 第 1 条):

- **A 套 = `offsets.zig` 的 `scope_types`**(`PLANET=2` / `COUNTRY=4` / `SHIP=8` / `POP=16` /
  `FLEET=32` / `GALACTIC_OBJECT=64` / `LEADER=128` / …)。该结构体的 docstring 自己写着
  `[UNVERIFIED 3.x] from stellarstellaris-win; not reconfirmed on 4.4.4`(`offsets.zig:601-603`)。
- **B 套 = §8.2 的 mask 位**:`is_owned_by` 从 `[scope+8]` 读到的那个值(`1` / `0x10` / `0x20` /
  `0x40` / `0x80` / … / `0x80000000`)。它是**4.4.4 的静态读数**,但每一 bit 的**语义名**未观测。
- 两套**数值上有重合**(`POP=16=0x10`、`FLEET=32=0x20`)、**也有一处明确冲突**(A 套 `0x80=LEADER`,
  而 B 套的 `0x80` 是系统 scope —— `country_scope_4_4_4.md` §6 的 A 级读数、`graph` 卷 §1.2 的
  解析器 `0x3939f0` 都以 `0x80` 为系统)。⇒ 本卷一律写「B 套 mask `0xNN`」,不写「pop 表」。

---

## §1 工单:8 条候选(2026-11-15,零 shot,结论:全部收到读数,详见 §2/§3)

来源:`runtime_444_transitability_4_4_4.md` §8.2 —— **逐字引用**(下表右列即该卷原文的「已知线索」列,
一个字没改)。数值取自 §8.2,本卷没有一处改过候选地址。

| 候选 | 类型 | 已知线索(§8.2 原文) |
|---|---|---|
| `0x394190` | getter | mask `0x10`:`[obj+0x18]` → 表 `0x3260ff0`(项 id `+0x10`)→ `[entry+0x3a8]` → 表 `0x3261068`(项 id `+0x10`)→ `[entry+0xf78]` → `0xd3b4d0` → vtable `+0x58` |
| `0x2b6470` | getter | mask `0x20`:`[obj+0x3a8]` → 表 `0x3261068` → `[entry+0xf78]` → `0xd3b4d0` → vtable `+0x58` |
| `0x393ec0` | getter | mask `0x40`:`[obj+0x434]` |
| `0x394870` | getter | mask `1`:`[obj+0x1b8]` |
| `0x393970` | getter | mask `0x80`(系统):接 `0x8bc870` |
| `0x3260ff0` | table | 项 id 在 `+0x10`(§8.2) |
| `0x3261030` | table | 项 id 在 `+0x8`(mask `0x2000000` 行) |
| `0x3261068` | table | 项 id 在 `+0x10`(mask `0x10`/`0x20` 两行都用到) |

### §1.1 工单口径

- **`候选`** 是 §8.2 里出现的**地址**:getter 是**函数入口**,table 是**全局槽**(`.data` 里存表对象
  绝对地址的那一格,BSS 未初始化 ⇒ 静态读不出值,只能读**谁读它、读出来怎么用**)。
- **`类型`** 只有两种:getter / table。§8.2 里其余地址(`0x8bc870` / `0x648b80` / `0xd3b4d0` …)是
  中继体,不在本工单内,但它们出现在链上时按「链上站点」记进 §2/§3,不单独立项。
- **档**:getter 用 `getter_named` / `getter_unresolved`;table 用 `table_named` / `single_reader` /
  `not_a_table` / `unresolved`(计划 Task 3 Step 2 的封闭词表)。

### §1.2 读数怎么落(TSV ↔ 卷)

`evidence/xrefs/scope_tables_4_4_4.tsv` 一行一个候选:`candidate / kind / reading / source`。
`reading` 是**一行摘要**(形状五元组 + 判词),`source` 是**能逐条复读的站点 RVA**(`disrva.py` 的入参)。
卷里每一节都给出**逐字输出块**;TSV 只放可 grep 的结论,不放指令。

### §1.3 复现(一条命令一条候选)

```bash
for r in 0x394190 0x2b6470 0x393ec0 0x394870 0x393970; do
  echo "===== $r"; python3 scripts/disrva.py "$r" --len=0x80
done
for g in 0x3260ff0 0x3261030 0x3261068; do
  echo "===== $g"; python3 scripts/global_xrefs.py "$g"
done
```

### §1.4 §1 不能说的

1. **「候选」不等于「锚点」。** §8.2 的读数本身是**静态推断**(那卷 §8.5 第 1 条:20 个第一跳函数的
   返回类型一个都没命名)。本卷只把**形状**从「一个地址」推进到「全局槽 + 界 + 步长 + id 偏移」,
   没有把任何一条升成 `pinned`。
2. **`§8.2` 的表列里有一处需要分叉读**(§2.1):mask `0x10` 那一行的 getter `0x394190` **自己**读的是
   全局槽 `0x3260ff8`,不是 `0x3260ff0`;`0x3260ff0` 是它**下一跳**才用的表。两格都在 `.data`
   相邻 8 字节处,漏读一格就会把两张表认成一张。
3. **本卷没有一次运行时读数**(零 shot 的代价):所有「全局槽里有值」都只是「`mov rax,[rip+…]`
   这条指令存在」,不是「那一格非空」。

---

## §2 五个 scope getter:入参字段与返回对象(2026-11-15,零 shot,结论:五个全部 `getter_named`)

五个 getter 是**同一个模板**的五份实例。本节先给模板(逐字,`0x394190` 那一份),再逐条记
**每份实例不同的那三格**:B 套 mask、表全局槽、对象内 id 偏移。

### §2.0 模板(逐字,来自 `0x394190`)

```text
$ python3 scripts/disrva.py 0x394190 --len=0x80
  00394190  mov     rdx, qword ptr [rcx + 0x1c]
  00394194  test    rdx, rdx
  00394197  je      0x1403941aa
  00394199  cmp     qword ptr [rcx + 8], 0x10
  0039419e  mov     rax, qword ptr [rip + 0x2ecb95b]  ; -> 0x325fb00
  003941a5  cmove   rax, rdx
  003941a9  ret     
  003941aa  cmp     qword ptr [rcx + 8], 0x10
  003941af  mov     eax, 0xffffffff
  003941b4  jne     0x1403941c2
  003941b6  mov     rax, qword ptr [rcx + 0x14]
  003941ba  test    rax, rax
  003941bd  jne     0x1403941fe
  003941bf  mov     eax, dword ptr [rcx + 0x10]
  003941c2  mov     r8, qword ptr [rip + 0x2ecce2f]  ; -> 0x3260ff8
  003941c9  test    r8, r8
  003941cc  je      0x1403941f4
  003941ce  mov     ecx, eax
  003941d0  and     ecx, 0xffffff
  003941d6  cmp     ecx, dword ptr [r8 + 0x20]
  003941da  jae     0x1403941f4
  003941dc  mov     edx, ecx
  003941de  mov     rcx, qword ptr [r8 + 0x18]
  003941e2  add     rdx, rdx
  003941e5  mov     rcx, qword ptr [rcx + rdx*8 + 8]
  003941ea  test    rcx, rcx
  003941ed  je      0x1403941f4
  003941ef  cmp     dword ptr [rcx + 0x10], eax
  003941f2  je      0x1403941fb
  003941f4  mov     rcx, qword ptr [rip + 0x2ecb905]  ; -> 0x325fb00
  003941fb  mov     rax, rcx
  003941fe  ret     
```

拆成五步(**每一份实例都同形**,下面的表只填不同的格子):

1. **入参 = scope cell(不是 id)**。`0x394199` / `0x3941aa` 都拿 `[rcx+8]` 与一个 mask 比 ——
   这正是 `country_scope_4_4_4.md` §6 的「`+8` = scope 类型」口径;`[rcx+8]` 是**唯一**的
   类型门。**`rcx` 全程没有被当成 id 用过**。
2. **三处来源,按优先级**:① `[scope+0x1c]`(已解析对象缓存;mask 相符才用,`0x3941a5` 的
   `cmove`);② `[scope+0x14]`(qword,**只有 `0x394190` 有这一格**,`0x3941b6`–`0x3941bd`);
   ③ 查表(`[scope+0x10]` = id,`0x3941bf`)。
3. **查表五件事**:`id & 0xffffff`(`0x3941d0`)、界 `[表+0x20]`(`0x3941d6`)、表指针
   `[表+0x18]`(`0x3941de`)、**`add rdx,rdx` + `[表+rdx*8+8]` ⇒ 16 B 记录、对象指针在 `+8`**
   (`0x3941e2`/`0x3941e5`,`graph` 卷 §1.11 的同一条)、对象自己的 id 复核
   `cmp [obj+0x10], eax`(**比的是原始 id,不是掩码后的**,`0x3941ef`)。
4. **失败回退 = 该类型的空对象**(`0x325fb00`),不是 `nullptr`。
5. **返回值 = 对象指针**;零 `call`、零副作用(整个函数体 0x70 字节,`ret` 在 `0x3941fe`)。

### §2.1 `0x394190`(B 套 mask `0x10`)—— `getter_named`

| 格 | 读数 | 站点 |
|---|---|---|
| 类型门 | `[scope+8] == 0x10` | `0x394199` / `0x3941aa` |
| 缓存槽 | `[scope+0x1c]`(qword) | `0x394190` |
| **额外内联指针** | `[scope+0x14]`(qword,非零 ⇒ 直接返回它) | `0x3941b6`–`0x3941bd` |
| id 来源 | `[scope+0x10]`(u32) | `0x3941bf` |
| 表全局槽 | **`0x3260ff8`** | `0x3941c2` |
| 对象内 id | `+0x10` | `0x3941ef` |
| 回退对象 | `0x325fb00` | `0x39419e` / `0x3941f4` |

**这一条与 §8.2 的写法有一处分叉,必须点出**:§8.2 的 mask `0x10` 行把「表 `0x3260ff0`(项 id `+0x10`)」
写在这一行的**开头**;但 getter **自己**读的是 **`0x3260ff8`**,不是 `0x3260ff0`。两格在 `.data` 里
只差 8 字节(`0x3260ff0` / `0x3260ff8`),而 `0x3260ff0` 是 `is_owned_by` 在这一路**下一跳**才用的表
(§3.1、`0x1a9beba`)。§8.2 的链条**没有错**(`[obj+0x18]` → `0x3260ff0` 逐字对得上),错的是
「getter 用哪张表」这一格的归属 —— 读法见 §2.7 的第 1 条。

**用途读者**(调用者怎么用它):`is_owned_by` 的 mask `0x10` 分支 `0x1a9beba`:

```text
  01a9beba  mov     r9, qword ptr [rip + 0x17c512f]  ; -> 0x3260ff0
  01a9bec1  test    r9, r9
  01a9bec4  je      0x141a9bef6
  01a9bec6  mov     rcx, rdi
  01a9bec9  call    0x140394190  ; -> 0x394190
  01a9bece  mov     edx, dword ptr [rax + 0x18]                 ; ★ 返回对象的 +0x18 = 下一个 id
  01a9bed1  mov     eax, edx
  01a9bed3  and     eax, 0xffffff
  01a9bed8  cmp     eax, dword ptr [r9 + 0x20]
  01a9bedc  jae     0x141a9bef6
  01a9bede  mov     ecx, eax
  01a9bee0  mov     rax, qword ptr [r9 + 0x18]
  01a9bee4  add     rcx, rcx
  01a9bee7  mov     rax, qword ptr [rax + rcx*8 + 8]
  01a9beec  test    rax, rax
  01a9beef  je      0x141a9bef6
  01a9bef1  cmp     dword ptr [rax + 0x10], edx
  01a9bef4  je      0x141a9befd
  01a9bef6  mov     rax, qword ptr [rip + 0x17c3beb]  ; -> 0x325fae8
  01a9befd  mov     rdx, qword ptr [rip + 0x17c5164]  ; -> 0x3261068
  01a9bf04  test    rdx, rdx
  01a9bf07  je      0x141a9bf36
  01a9bf09  mov     r8d, dword ptr [rax + 0x3a8]                 ; ★ 再下一跳的 id
  01a9bf10  mov     eax, r8d
  01a9bf13  and     eax, 0xffffff
  01a9bf18  cmp     eax, dword ptr [rdx + 0x20]
  01a9bf1b  jae     0x141a9bf36
  01a9bf1d  mov     ecx, eax
  01a9bf1f  mov     rax, qword ptr [rdx + 0x18]
  01a9bf23  add     rcx, rcx
  01a9bf26  mov     rcx, qword ptr [rax + rcx*8 + 8]
  01a9bf2b  test    rcx, rcx
  01a9bf2e  je      0x141a9bf36
  01a9bf30  cmp     dword ptr [rcx + 0x10], r8d
  01a9bf34  je      0x141a9bf3d
  01a9bf36  mov     rcx, qword ptr [rip + 0x17c38e3]  ; -> 0x325f820
  01a9bf3d  mov     rcx, qword ptr [rcx + 0xf78]
  01a9bf44  call    0x140d3b4d0  ; -> 0xd3b4d0
```

⇒ `0x394190` 的返回值**不是**国家对象也不是终点:调用者接着读它的 `+0x18`(一个 id)、查
`0x3260ff0`、读 `+0x3a8`、查 `0x3261068`、读 `+0xf78`、过 `0xd3b4d0`、才拿到一个「带 vtable 的
子对象」再由 `+0x58` 槽吐国家 id。**它是一台「scope → 某个中间对象」的解析器,不是 `owner` 读取器。**

### §2.2 `0x2b6470`(B 套 mask `0x20`)—— `getter_named`

```text
$ python3 scripts/disrva.py 0x2b6470 --len=0x70
  002b6470  mov     rdx, qword ptr [rcx + 0x1c]
  002b6474  test    rdx, rdx
  002b6477  je      0x1402b648a
  002b6479  cmp     qword ptr [rcx + 8], 0x20
  002b647e  mov     rax, qword ptr [rip + 0x2fa9663]  ; -> 0x325fae8
  002b6485  cmove   rax, rdx
  002b6489  ret     
  002b648a  cmp     qword ptr [rcx + 8], 0x20
  002b648f  jne     0x1402b649a
  002b6491  mov     eax, dword ptr [rcx + 0x10]
  002b6494  mov     dword ptr [rsp + 8], eax
  002b6498  jmp     0x1402b64a2  ; -> 0x2b64a2
  002b649a  mov     dword ptr [rsp + 8], 0xffffffff
  002b64a2  mov     rax, qword ptr [rip + 0x2faab47]  ; -> 0x3260ff0
  002b64a9  lea     rcx, [rsp + 8]
  002b64ae  test    rax, rax
  002b64b1  je      0x1402b64d8
  002b64b3  mov     edx, dword ptr [rcx]
  002b64b5  mov     ecx, edx
  002b64b7  and     ecx, 0xffffff
  002b64bd  cmp     ecx, dword ptr [rax + 0x20]
  002b64c0  jae     0x1402b64d8
  002b64c2  mov     rax, qword ptr [rax + 0x18]
  002b64c6  add     rcx, rcx
  002b64c9  mov     rax, qword ptr [rax + rcx*8 + 8]
  002b64ce  test    rax, rax
  002b64d1  je      0x1402b64d8
  002b64d3  cmp     dword ptr [rax + 0x10], edx
  002b64d6  je      0x1402b64df
  002b64d8  mov     rax, qword ptr [rip + 0x2fa9609]  ; -> 0x325fae8
  002b64df  ret     
```

| 格 | 读数 | 站点 |
|---|---|---|
| 类型门 | `[scope+8] == 0x20` | `0x2b6479` / `0x2b648a` |
| 缓存槽 | `[scope+0x1c]` | `0x2b6470` |
| 额外内联指针 | **无**(没有 `[rcx+0x14]` 那一步) | — |
| id 来源 | `[scope+0x10]`,经栈局部 `[rsp+8]` 转手(**不是**直接读 scope+0) | `0x2b6491`/`0x2b6494`/`0x2b64b3` |
| 表全局槽 | `0x3260ff0` | `0x2b64a2` |
| 对象内 id | `+0x10` | `0x2b64d3` |
| 回退对象 | `0x325fae8` | `0x2b647e` / `0x2b64d8` |

用途读者(`0x1a9be28`,mask `0x20` 分支):返回值先读 `[rax+0x3a8]` 当 id 再查 `0x3261068`,
之后与 §2.1 共用同一段尾巴(`[+0xf78]` → `0xd3b4d0` → vtable `+0x58`)。**与 §8.2 逐字一致。**

```text
  01a9be28  mov     r8, qword ptr [rip + 0x17c5239]  ; -> 0x3261068
  01a9be2f  test    r8, r8
  01a9be32  je      0x141a9be67
  01a9be34  mov     rcx, rdi
  01a9be37  call    0x1402b6470  ; -> 0x2b6470
  01a9be3c  mov     edx, dword ptr [rax + 0x3a8]                 ; ★ 返回对象的 +0x3a8
  01a9be42  mov     eax, edx
  01a9be44  and     eax, 0xffffff
  01a9be49  cmp     eax, dword ptr [r8 + 0x20]
  01a9be4d  jae     0x141a9be67
  01a9be4f  mov     ecx, eax
  01a9be51  mov     rax, qword ptr [r8 + 0x18]
  01a9be55  add     rcx, rcx
  01a9be58  mov     rcx, qword ptr [rax + rcx*8 + 8]
  01a9be5d  test    rcx, rcx
  01a9be60  je      0x141a9be67
  01a9be62  cmp     dword ptr [rcx + 0x10], edx
  01a9be65  je      0x141a9be6e
  01a9be67  mov     rcx, qword ptr [rip + 0x17c39b2]  ; -> 0x325f820
  01a9be6e  mov     rcx, qword ptr [rcx + 0xf78]
  01a9be75  call    0x140d3b4d0  ; -> 0xd3b4d0
  01a9be7f  mov     rcx, qword ptr [rax]
  01a9be82  mov     r8, qword ptr [rcx + 0x58]
  01a9be86  mov     rcx, rax
  01a9be89  call    r8                                           ; vtable +0x58 取 id
  01a9be8c  mov     r8, qword ptr [rip + 0x17c5145]  ; -> 0x3260fd8
  01a9be93  test    r8, r8
  01a9be96  je      0x141a9c233
  01a9be9c  mov     edx, dword ptr [rax]
```

### §2.3 `0x393ec0`(B 套 mask `0x40`)—— `getter_named`

```text
$ python3 scripts/disrva.py 0x393ec0 --len=0x40
  00393ec0  mov     rdx, qword ptr [rcx + 0x1c]
  00393ec4  test    rdx, rdx
  00393ec7  je      0x140393eda
  00393ec9  cmp     qword ptr [rcx + 8], 0x40
  00393ece  mov     rax, qword ptr [rip + 0x2ecbb4b]  ; -> 0x325fa20
  00393ed5  cmove   rax, rdx
  00393ed9  ret     
  00393eda  cmp     qword ptr [rcx + 8], 0x40
  00393edf  jne     0x140393eea
  00393ee1  mov     eax, dword ptr [rcx + 0x10]
  00393ee4  mov     dword ptr [rsp + 8], eax
  00393ee8  jmp     0x140393ef2  ; -> 0x393ef2
  00393eea  mov     dword ptr [rsp + 8], 0xffffffff
  00393ef2  mov     rax, qword ptr [rip + 0x2ecb007]  ; -> 0x325ef00
  00393ef9  lea     rcx, [rsp + 8]
  00393efe  test    rax, rax
  00393f01  je      0x140393f28
  00393f03  mov     edx, dword ptr [rcx]
  00393f05  mov     ecx, edx
  00393f07  and     ecx, 0xffffff
  00393f0d  cmp     ecx, dword ptr [rax + 0x20]
  00393f10  jae     0x140393f28
  00393f12  mov     rax, qword ptr [rax + 0x18]
  00393f16  add     rcx, rcx
  00393f19  mov     rax, qword ptr [rax + rcx*8 + 8]
  00393f1e  test    rax, rax
  00393f21  je      0x140393f28
  00393f23  cmp     dword ptr [rax + 0x30], edx
  00393f26  je      0x140393f2f
  00393f28  mov     rax, qword ptr [rip + 0x2ecbaf1]  ; -> 0x325fa20
  00393f2f  ret     
```

| 格 | 读数 | 站点 |
|---|---|---|
| 类型门 | `[scope+8] == 0x40` | `0x393ec9` / `0x393eda` |
| 缓存槽 | `[scope+0x1c]` | `0x393ec0` |
| id 来源 | `[scope+0x10]` | `0x393ee1` |
| 表全局槽 | **`0x325ef00`**(不在 `0x3260f**` 那一簇里) | `0x393ef2` |
| 对象内 id | `+0x30` | `0x393f23` |
| 回退对象 | `0x325fa20` | `0x393ece` / `0x393f28` |

用途读者(`0x1a9bdee`):返回值读 `[rax+0x434]` 当**国家 id**,直接查国家表 `0x3260fd8`:

```text
  01a9bdee  mov     r8, qword ptr [rip + 0x17c51e3]  ; -> 0x3260fd8
  01a9bdf5  test    r8, r8
  01a9bdf8  je      0x141a9c233
  01a9bdfe  mov     rcx, rdi
  01a9be01  call    0x140393ec0  ; -> 0x393ec0
  01a9be06  mov     edx, dword ptr [rax + 0x434]                 ; ★ 直接是归属国 id
  01a9be0c  mov     eax, edx
  01a9be0e  and     eax, 0xffffff
  01a9be13  cmp     eax, dword ptr [r8 + 0x20]
  01a9be17  jae     0x141a9c233
  01a9be1d  mov     ecx, eax
  01a9be1f  mov     rax, qword ptr [r8 + 0x18]
  01a9be23  jmp     0x141a9c221  ; -> 0x1a9c221
```

⇒ 这一支**最短**:`scope → 对象(+0x434)→ 国家表`。与 §8.2 逐字一致。

### §2.4 `0x394870`(B 套 mask `1`)—— `getter_named`

```text
$ python3 scripts/disrva.py 0x394870 --len=0x40
  00394870  mov     rdx, qword ptr [rcx + 0x1c]
  00394874  test    rdx, rdx
  00394877  je      0x14039488a
  00394879  cmp     qword ptr [rcx + 8], 1
  0039487e  mov     rax, qword ptr [rip + 0x2ecb893]  ; -> 0x3260118
  00394885  cmove   rax, rdx
  00394889  ret     
  0039488a  cmp     qword ptr [rcx + 8], 1
  0039488f  jne     0x14039489a
  00394891  mov     eax, dword ptr [rcx + 0x10]
  00394894  mov     dword ptr [rsp + 8], eax
  00394898  jmp     0x1403948a2  ; -> 0x3948a2
  0039489a  mov     dword ptr [rsp + 8], 0xffffffff
  003948a2  mov     rax, qword ptr [rip + 0x2ecc767]  ; -> 0x3261010
  003948a9  lea     rcx, [rsp + 8]
  003948ae  test    rax, rax
  003948b1  je      0x1403948d8
  003948b3  mov     edx, dword ptr [rcx]
  003948b5  mov     ecx, edx
  003948b7  and     ecx, 0xffffff
  003948bd  cmp     ecx, dword ptr [rax + 0x20]
  003948c0  jae     0x1403948d8
  003948c2  mov     rax, qword ptr [rax + 0x18]
  003948c6  add     rcx, rcx
  003948c9  mov     rax, qword ptr [rax + rcx*8 + 8]
  003948ce  test    rax, rax
  003948d1  je      0x1403948d8
  003948d3  cmp     dword ptr [rax + 8], edx
  003948d6  je      0x1403948df
  003948d8  mov     rax, qword ptr [rip + 0x2ecb839]  ; -> 0x3260118
  003948df  ret     
```

| 格 | 读数 | 站点 |
|---|---|---|
| 类型门 | `[scope+8] == 1` | `0x394879` / `0x39488a` |
| 缓存槽 | `[scope+0x1c]` | `0x394870` |
| id 来源 | `[scope+0x10]` | `0x394891` |
| 表全局槽 | `0x3261010` | `0x3948a2` |
| 对象内 id | `+0x8` | `0x3948d3` |
| 回退对象 | **`0x3260118`**(不是 `0x325f***` 那一族) | `0x39487e` / `0x3948d8` |

用途读者(`0x1a9bf53`):返回值读 `[rax+0x1b8]` 当国家 id,直接查 `0x3260fd8`。

```text
  01a9bf53  mov     r8, qword ptr [rip + 0x17c507e]  ; -> 0x3260fd8
  01a9bf5a  test    r8, r8
  01a9bf5d  je      0x141a9c233
  01a9bf63  mov     rcx, rdi
  01a9bf66  call    0x140394870  ; -> 0x394870
  01a9bf6b  mov     edx, dword ptr [rax + 0x1b8]                 ; ★ 直接是归属国 id
  01a9bf71  jmp     0x141a9be9e  ; -> 0x1a9be9e
```

`0x3260118` 的回退**不是**一个孤例:同一个槽也是 `0x394870` 的家族之外若干调用者的回退
(§3.4 的 `0x2648ad` 一行),所以它是这类对象的空实例,不是「表不存在时的句柄」。

### §2.5 `0x393970`(B 套 mask `0x80`)—— `getter_named`,与图卷的 `0x3939f0` **是两个函数**

```text
$ python3 scripts/disrva.py 0x393970 --len=0x80
  00393970  mov     rdx, qword ptr [rcx + 0x1c]
  00393974  test    rdx, rdx
  00393977  je      0x14039398d
  00393979  cmp     qword ptr [rcx + 8], 0x80
  00393981  mov     rax, qword ptr [rip + 0x2ec9ef8]  ; -> 0x325d880
  00393988  cmove   rax, rdx
  0039398c  ret     
  0039398d  cmp     qword ptr [rcx + 8], 0x80
  00393995  jne     0x1403939a0
  00393997  mov     eax, dword ptr [rcx + 0x10]
  0039399a  mov     dword ptr [rsp + 8], eax
  0039399e  jmp     0x1403939a8  ; -> 0x3939a8
  003939a0  mov     dword ptr [rsp + 8], 0xffffffff
  003939a8  mov     rdx, qword ptr [rip + 0x2ecd1e9]  ; -> 0x3260b98
  003939af  lea     rax, [rsp + 8]
  003939b4  test    rdx, rdx
  003939b7  je      0x1403939e2
  003939b9  mov     r8d, dword ptr [rax]
  003939bc  mov     eax, r8d
  003939bf  and     eax, 0xffffff
  003939c4  cmp     eax, dword ptr [rdx + 0x20]
  003939c7  jae     0x1403939e2
  003939c9  mov     ecx, eax
  003939cb  mov     rax, qword ptr [rdx + 0x18]
  003939cf  add     rcx, rcx
  003939d2  mov     rax, qword ptr [rax + rcx*8 + 8]
  003939d7  test    rax, rax
  003939da  je      0x1403939e2
  003939dc  cmp     dword ptr [rax + 8], r8d
  003939e0  je      0x1403939e9
  003939e2  mov     rax, qword ptr [rip + 0x2ec9e97]  ; -> 0x325d880
  003939e9  ret     
```

| 格 | 读数 | 站点 |
|---|---|---|
| 类型门 | `[scope+8] == 0x80` | `0x393979` / `0x39398d` |
| 缓存槽 | `[scope+0x1c]` | `0x393970` |
| id 来源 | `[scope+0x10]` | `0x393997` |
| 表全局槽 | `0x3260b98`(**系统索引**,图卷 §1.2 同一格) | `0x3939a8` |
| 对象内 id | `+0x8`(系统对象 id) | `0x3939dc` |
| 回退对象 | `0x325d880`(图卷 §1.2 同一个回退) | `0x393981` / `0x3939e2` |

**与图卷 §1.2 的关系**:`0x3939f0`(图卷逐条列全的 24 条指令)**没有** `[scope+0x1c]` 缓存那一段,
`0x393970` **有**;两者其余逐条同形(同 mask `0x80`、同 id 来源 `scope+0x10`、同表 `0x3260b98`、
同界 `+0x20`、同步长 `add rcx,rcx`、同 `entry+8`、同回退 `0x325d880`)。⇒ **两个函数、一张表**;
`0x393970` 是带缓存的变体。这一条同时是**系统索引形状的第二次独立读数**(除了图卷 §1.2 的
`0x3939f0` 之外的第二个读者),它把「界 `+0x20` / 表 `+0x18` / 16 B / 对象指针 `+8`」再证一遍。

用途读者(`0x1a9bdd6`):返回值交给 `0x8bc870`,后者读 `[obj+0x1370]` 当国家 id(§3.2 同形,不重列)。

### §2.6 调用者计数(慢通道 1 次,`find_refs.py`)

```text
$ python3 scripts/find_refs.py 0x394190 0x394870 0x393ec0 0x2b6470 0x393970
stellaris.exe  targets: 0x394190, 0x394870, 0x393ec0, 0x2b6470, 0x393970
scanning .text (0x2390800 bytes) ...

== 0x394190: 49 references ==
== 0x394870: 42 references ==
== 0x393ec0: 150 references ==
== 0x2b6470: 102 references ==
== 0x393970: 303 references ==
```

(每条的清单 `find_refs.py` 只印前 25 条并在尾部写 `... N more`;上面只摘计数行,清单不重复。)

两条读数:

1. **五个 getter 都是热函数**(42–303 个静态 `call`/`jmp` 站点),没有被优化的死代码 —— 它们
   不是「只在 `is_owned_by` 里出现一次」的私有 helper。
2. **`jmp` 形态是真别名,不是误命中**:`0x394220: jmp 0x1402b6470` 与 `0x399132: jmp 0x1402b6470`
   是 mask `0x20` getter 的两个跳板;`0x398ea3`/`0x398f9f` 是 `0x393970` 的两个跳板。跳板只改
   入口地址,不改形状。

### §2.7 §2 的判词表

| 候选 | 判词 | 前提 |
|---|---|---|
| `0x394190` | `getter_named` | 类型门 `[scope+8]==0x10`、id `[scope+0x10]`、表 `0x3260ff8`、对象 id `+0x10`、回退 `0x325fb00` 五格都是逐指令读数;调用者 `0x1a9beba` 说明返回对象的 `+0x18` 是「下一跳 id」 |
| `0x2b6470` | `getter_named` | 同上五格(表 `0x3260ff0`、对象 id `+0x10`、回退 `0x325fae8`);调用者 `0x1a9be28` 说明 `+0x3a8` 是「下一跳 id」 |
| `0x393ec0` | `getter_named` | 五格(表 `0x325ef00`、对象 id `+0x30`、回退 `0x325fa20`);调用者 `0x1a9bdee` 说明 `+0x434` **直接**是归属国 id |
| `0x394870` | `getter_named` | 五格(表 `0x3261010`、对象 id `+0x8`、回退 `0x3260118`);调用者 `0x1a9bf53` 说明 `+0x1b8` 直接是国家 id |
| `0x393970` | `getter_named` | 五格(表 `0x3260b98`、对象 id `+0x8`、回退 `0x325d880`);与图卷 `0x3939f0` 同表不同函数,互为第二次独立读数 |

「`getter_named`」在本卷的**确切含义**:入参字段、类型门、表全局槽、对象内 id 偏移、回退对象
**五格都是指令读数**。它**不**表示「这个 getter 的返回类型名已知」(§2.8 第 1 条)。

### §2.8 §2 不能说的

1. **返回类型名一个都没有。** 五个 getter 各自返回一类对象,我们只知道它们在**哪张表**里、
   对象自己的 id 在**哪个偏移**、调用者拿它的**哪个字段**当 id。这不等于是哪一类对象 ——
   B 套 mask `0x10` 与 A 套 `POP=16` 数值相同**不是证据**(见卷头两套编号;A 套另一个值
   `0x80=LEADER` 与 B 套 `0x80=系统` 直接冲突,足以证明两套不能互相翻译)。
2. **`[scope+0x1c]` 缓存槽的**写入方**没读。** 五处读点(`0x394190`/`0x2b6470`/`0x393ec0`/
   `0x394870`/`0x393970` 的第一条指令)只是「有缓存就读」;谁在什么时候填它,本卷零读数。
   这直接影响 `getPlanet(id)`:如果缓存槽在活体里常常非空,mask 门就成了唯一闸口。
3. **`[scope+0x14]` 那一格只有 mask `0x10` 有。** 它是「内联对象指针」还是「某条更短链的
   残留」,本卷没有第二个读者;它也没有出现在其余四个 getter 里。
4. **`0x1a9bd10`(`is_owned_by`)之外的用途没有抽样。** 本节每条只读**一个**用途调用点
   (计划 Task 1 Step 2 的口径),49–303 个调用点里其余部分未读 —— 所以「返回对象怎么用」
   在本卷是「至少有一种用法是这样」,不是「只有这一种用法」。
