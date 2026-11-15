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

---

## §3 三张表的形状(2026-11-15,零 shot,结论:`0x3260ff0` / `0x3261030` / `0x3261068` 全部 `table_named`)

§8.2 点名的三张表,在 §3.1–§3.3 逐条读;**工单之外还有四张**同族的表在 §2 的链路里出现过
(`0x3260ff8` / `0x3261010` / `0x325ef00` / `0x3260f18`),它们不在 8 条候选里,但下一份计划要用
(不是「顺手加的」:五张表里**四张**是 getter 自己读的那一张,漏了它们就等于只知道一半链路),
所以 §3.4 一并定形。§3.6 记一张**单读者**表(不进 §3.4 的 `table_named` 名单)。

### §3.0 全景(一页)

`global_xrefs.py` 的计数口径:一个全局槽的**读点站点数**与**不同函数数**(`pdata` 函数起点)。
`界 / 表指针 / 步长 / 对象指针 / 对象内 id` 五格全部来自 §3.1–§3.4 的逐指令读数。

| 全局槽 | 读点站点 | 独立函数 | 界 | 表指针 | 记录步长 | 对象指针 | 对象内 id | 判词 |
|---|---|---|---|---|---|---|---|---|
| `0x3260ff0` | 502 | 375 | `+0x20` | `+0x18` | 16 B | `+8` | **`+0x10`** | `table_named` |
| `0x3260ff8` | 138 | 113 | `+0x20` | `+0x18` | 16 B | `+8` | **`+0x10`** | `table_named` |
| `0x3260f18` | 64 | 56 | `+0x20` | `+0x18` | 16 B | `+8` | **未读**(§3.4 第 2 条) | `unresolved` |
| `0x3261010` | 203 | 152 | `+0x20` | `+0x18` | 16 B | `+8` | **`+0x8`** | `table_named` |
| `0x3261030` | 126 | 94 | `+0x20` | `+0x18` | 16 B | `+8` | **`+0x8`** | `table_named` |
| `0x3261068` | 1554 | 1134 | `+0x20` | `+0x18` | 16 B | `+8` | **`+0x10`** | `table_named` |
| `0x325ef00` | 2143 | 1416 | `+0x20` | `+0x18` | 16 B | `+8` | **`+0x30`** | `table_named` |
| `0x3260fd0` | 1237 | —(§3.6) | `+0x20` | `+0x18` | 16 B | `+8` | `+0x18`(单读者) | `single_reader` |

**七张表五格全同,只有「对象内 id」那一格分流**:`+0x8` / `+0x10` / `+0x18` / `+0x30` 四种。
这条不是巧合而是**判据**:同一个 `id → 对象` 容器被七类对象共用,「哪一类对象」只体现在
`entry` 指向的那个对象的 id 字段偏移上 —— 与国家表(`+0x20`)、系统索引(`+0x8`)的先例同构。

### §3.1 `0x3260ff0` —— `table_named`

四个事实,来自**三个互不相干的函数**(不是同一个函数的重复读点):

**(a) getter `0x2b6470` 自己**(§2.2 已列全文,这里只列五格):

```text
  002b64a2  mov     rax, qword ptr [rip + 0x2faab47]  ; -> 0x3260ff0
  002b64bd  cmp     ecx, dword ptr [rax + 0x20]                 ; 界
  002b64c2  mov     rax, qword ptr [rax + 0x18]                 ; 表指针
  002b64c6  add     rcx, rcx                                    ; 槽号翻倍 => 16 B
  002b64c9  mov     rax, qword ptr [rax + rcx*8 + 8]            ; 对象指针在 +8
  002b64d3  cmp     dword ptr [rax + 0x10], edx                 ; 对象内 id 在 +0x10
```

**(b) `is_owned_by` 的 mask `0x10` 分支**(`0x1a9beba`,§2.1 已列;同一组五格,`cmp [rax+0x10], edx` 在
`0x1a9bef1`)。它读这张表时**不经过 getter** —— 调用者自己 `mov r9,[rip+…]` 直接读全局槽,
这是「同一条形状的第二个读者」。

**(c) `0x263bdd`(另一支 `.text`,与 `is_owned_by` 无关)**:

```text
$ python3 scripts/disrva.py 0x263bdd --len=0x38
  00263bdd  mov     r8, qword ptr [rip + 0x2ffd40c]  ; -> 0x3260ff0
  00263be4  test    r8, r8
  00263be7  je      0x140263c0e
  00263be9  mov     eax, edx
  00263beb  and     eax, 0xffffff
  00263bf0  cmp     eax, dword ptr [r8 + 0x20]
  00263bf4  jae     0x140263c0e
  00263bf6  mov     ecx, eax
  00263bf8  add     rcx, rcx
  00263bfb  mov     rax, qword ptr [r8 + 0x18]
  00263bff  mov     rbx, qword ptr [rax + rcx*8 + 8]
  00263c04  test    rbx, rbx
  00263c07  je      0x140263c0e
  00263c09  cmp     dword ptr [rbx + 0x10], edx
  00263c0c  je      0x140263c15
```

**(d) `0x251a10`(第三个函数;id 从 `[[obj+0xd0]+rsi*4]` 来,不是 scope)**:

```text
$ python3 scripts/disrva.py 0x251a10 --len=0x38
  00251a10  mov     rdx, qword ptr [rip + 0x300f5d9]  ; -> 0x3260ff0
  00251a17  test    rdx, rdx
  00251a1a  je      0x140251a4d
  00251a1c  mov     rax, qword ptr [rbx + 0xd0]
  00251a23  mov     r8d, dword ptr [rax + rsi*4]
  00251a27  mov     eax, r8d
  00251a2a  and     eax, 0xffffff
  00251a2f  cmp     eax, dword ptr [rdx + 0x20]
  00251a32  jae     0x140251a4d
  00251a34  mov     ecx, eax
  00251a36  add     rcx, rcx
  00251a39  mov     rax, qword ptr [rdx + 0x18]
  00251a3d  mov     rcx, qword ptr [rax + rcx*8 + 8]
  00251a42  test    rcx, rcx
  00251a45  je      0x140251a4d
  00251a47  cmp     dword ptr [rcx + 0x10], r8d
  00251a4b  je      0x140251a54
  00251a4d  mov     rcx, qword ptr [rip + 0x300e094]  ; -> 0x325fae8
```

⇒ 四件事逐项相同(界 `+0x20`、表指针 `+0x18`、`add rcx,rcx` + `[rax+rcx*8+8]`、`cmp [obj+0x10]`),
三个函数不是同一段代码的复制(一个在 `0x2b6***`、一个在 `0x1a9b***`、一个在 `0x263***`)。判 `table_named`。

### §3.2 `0x3261030` —— `table_named`

**(a) `0x265660`**:

```text
$ python3 scripts/disrva.py 0x265660 --len=0x40
  00265660  mov     rdx, qword ptr [rip + 0x2ffb9c9]  ; -> 0x3261030
  00265667  test    rdx, rdx
  0026566a  je      0x140265695
  0026566c  mov     r8d, dword ptr [r14]
  0026566f  mov     eax, r8d
  00265672  and     eax, 0xffffff
  00265677  cmp     eax, dword ptr [rdx + 0x20]
  0026567a  jae     0x140265695
  0026567c  mov     ecx, eax
  0026567e  mov     rax, qword ptr [rdx + 0x18]
  00265682  add     rcx, rcx
  00265685  mov     rbp, qword ptr [rax + rcx*8 + 8]
  0026568a  test    rbp, rbp
  0026568d  je      0x140265695
  0026568f  cmp     dword ptr [rbp + 8], r8d
  00265693  je      0x14026569c
  00265695  mov     rbp, qword ptr [rip + 0x2ffaea4]  ; -> 0x3260540
```

**(b) `0x288882`(另一个函数)**:

```text
$ python3 scripts/disrva.py 0x288882 --len=0x38
  00288882  mov     rdx, qword ptr [rip + 0x2fd87a7]  ; -> 0x3261030
  00288889  test    rdx, rdx
  0028888c  je      0x1402888b2
  0028888e  mov     eax, esi
  00288890  and     eax, 0xffffff
  00288895  cmp     eax, dword ptr [rdx + 0x20]
  00288898  jae     0x1402888b2
  0028889a  mov     ecx, eax
  0028889c  mov     rax, qword ptr [rdx + 0x18]
  002888a0  add     rcx, rcx
  002888a3  mov     rdi, qword ptr [rax + rcx*8 + 8]
  002888a8  test    rdi, rdi
  002888ab  je      0x1402888b2
  002888ad  cmp     dword ptr [rdi + 8], esi
  002888b0  je      0x1402888b9
  002888b2  mov     rdi, qword ptr [rip + 0x2fd7c87]  ; -> 0x3260540
```

**(c) `0x394cd9`(第三个函数)**:

```text
$ python3 scripts/disrva.py 0x394cd9 --len=0x40
  00394cd9  mov     edx, dword ptr [rip + 0x2ecc351]  ; -> 0x3261030
  00394cdf  lea     rax, [rsp + 8]
  00394ce4  test    rdx, rdx
  00394ce7  je      0x140394d12
  00394ce9  mov     r8d, dword ptr [rax]
  00394cec  mov     eax, r8d
  00394cef  and     eax, 0xffffff
  00394cf4  cmp     eax, dword ptr [rdx + 0x20]
  00394cf7  jae     0x140394d12
  00394cf9  mov     ecx, eax
  00394cfb  mov     rax, qword ptr [rdx + 0x18]
  00394cff  add     rcx, rcx
  00394d02  mov     rax, qword ptr [rax + rcx*8 + 8]
  00394d07  test    rax, rax
  00394d0a  je      0x140394d12
  00394d0c  cmp     dword ptr [rax + 8], r8d
  00394d10  je      0x140394d19
```

**(d) `0x397c3b`(第四个函数;先调 getter `0x394e60`)**:`call 0x140394e60` → `mov edx,[rax+0xac]` →
同一组五格、`cmp [rcx+8], edx`(`0x397c72`)。

⇒ 界 `+0x20`、表指针 `+0x18`、`add rcx,rcx`、`[rax+rcx*8+8]`、**对象内 id `+0x8`** 五项逐项相同,
四个函数。判 `table_named`。§8.2 说「项 id `+0x8`」**对得上**。

### §3.3 `0x3261068` —— `table_named`

**(a) `0x192f90e`(与 `is_owned_by` 无关的一个函数)**:

```text
$ python3 scripts/disrva.py 0x192f90e --len=0x40
  0192f90e  mov     r8, qword ptr [rip + 0x1931753]  ; -> 0x3261068
  0192f915  test    r8, r8
  0192f918  je      0x14192f94a
  0192f91a  call    0x140393b70  ; -> 0x393b70
  0192f91f  mov     edx, dword ptr [rax + 0xe0]
  0192f925  mov     eax, edx
  0192f927  and     eax, 0xffffff
  0192f92c  cmp     eax, dword ptr [r8 + 0x20]
  0192f930  jae     0x14192f94a
  0192f932  mov     ecx, eax
  0192f934  mov     rax, qword ptr [r8 + 0x18]
  0192f938  add     rcx, rcx
  0192f93b  mov     rax, qword ptr [rax + rcx*8 + 8]
  0192f940  test    rax, rax
  0192f943  je      0x14192f94a
  0192f945  cmp     dword ptr [rax + 0x10], edx
  0192f948  je      0x14192f951
```

**(b) `0x1a99f5a`(另一个函数;`is_owned_by` 的邻居但不是它)**:

```text
$ python3 scripts/disrva.py 0x1a99f5a --len=0x40
  01a99f5a  mov     rdx, qword ptr [rip + 0x17c7107]  ; -> 0x3261068
  01a99f61  test    rdx, rdx
  01a99f64  je      0x141a99f93
  01a99f66  mov     r8d, dword ptr [rbx + 0xe0]
  01a99f6d  mov     eax, r8d
  01a99f70  and     eax, 0xffffff
  01a99f75  cmp     eax, dword ptr [rdx + 0x20]
  01a99f78  jae     0x141a99f93
  01a99f7a  mov     ecx, eax
  01a99f7c  add     rcx, rcx
  01a99f7f  mov     rax, qword ptr [rdx + 0x18]
  01a99f83  mov     rbx, qword ptr [rax + rcx*8 + 8]
  01a99f88  test    rbx, rbx
  01a99f8b  je      0x141a99f93
  01a99f8d  cmp     dword ptr [rbx + 0x10], r8d
  01a99f91  je      0x141a99f9a
  01a99f93  mov     rbx, qword ptr [rip + 0x17c5886]  ; -> 0x325f820
```

**(c) `is_owned_by` 的两处**(`0x1a9befd` mask `0x10` 的下一跳、`0x1a9be28` mask `0x20` 的下一跳,§2.1/§2.2 已列全文):
两处 `cmp [obj+0x10]`(`0x1a9bf30` / `0x1a9be62`)。

⇒ 界 `+0x20`、表指针 `+0x18`、`add rcx,rcx`、`[rax+rcx*8+8]`、**对象内 id `+0x10`** 五项逐项相同,
四个函数(其中两个是 `is_owned_by` 自己的分支,两个在外)。判 `table_named`。§8.2 的「项 id `+0x10`」对得上。

### §3.4 工单之外的四张:getter 自己读的那一张(下一份计划要用)

这四张不在 8 条候选里,但 §2 的每个 getter 都**先**读它们。它们与 §3.0 的七张**同形**,只有
「对象内 id」那一格不同。

| 全局槽 | 谁读 | 五格 | 读数站点 |
|---|---|---|---|
| `0x3260ff8` | getter `0x394190`(mask `0x10`) | 界 `+0x20` / 表 `+0x18` / 16 B / ptr `+8` / **obj id `+0x10`** | getter 本体 `0x3941c2`–`0x3941ef`;第二读者 `0x23a1cd` |
| `0x3261010` | getter `0x394870`(mask `1`) | 同上 / **obj id `+0x8`** | getter 本体 `0x3948a2`–`0x3948d3`;第二读者 `0x264870` |
| `0x325ef00` | getter `0x393ec0`(mask `0x40`) | 同上 / **obj id `+0x30`** | getter 本体 `0x393ef2`–`0x393f23`;第二读者 `0x25570f` |
| `0x3260f18` | getter `0x394e60`(mask `0x2000000`,§8.2 那一行的第一跳) | 界 `+0x20` / 表 `+0x18` / 16 B / ptr `+8` / obj id **未读** | getter 本体 `0x394e98`–`0x394ebb`;懒初始化 `0x2488ae` |

```text
$ python3 scripts/disrva.py 0x23a1cd --len=0x38
  0023a1cd  mov     r8, qword ptr [rip + 0x3026e24]  ; -> 0x3260ff8
  0023a1d4  test    r8, r8
  0023a1d7  jne     0x14023a1e2
  0023a1d9  mov     rax, qword ptr [rip + 0x3025920]  ; -> 0x325fb00
  0023a1e0  jmp     0x14023a21e  ; -> 0x23a21e
  0023a1e2  mov     eax, r9d
  0023a1e5  and     eax, 0xffffff
  0023a1ea  cmp     eax, dword ptr [r8 + 0x20]
  0023a1ee  jb      0x14023a1f9
  0023a1f0  mov     rax, qword ptr [rip + 0x3025909]  ; -> 0x325fb00
  0023a1f7  jmp     0x14023a21e  ; -> 0x23a21e
  0023a1f9  mov     ecx, eax
  0023a1fb  mov     rax, qword ptr [r8 + 0x18]
  0023a1ff  add     rcx, rcx
```

```text
$ python3 scripts/disrva.py 0x264870 --len=0x38
  00264870  mov     rdx, qword ptr [rip + 0x2ffc799]  ; -> 0x3261010
  00264877  test    rdx, rdx
  0026487a  je      0x1402648ad
  0026487c  mov     rax, qword ptr [r14 + 0x730]
  00264883  mov     r8d, dword ptr [rax + rdi*4]
  00264887  mov     eax, r8d
  0026488a  and     eax, 0xffffff
  0026488f  cmp     eax, dword ptr [rdx + 0x20]
  00264892  jae     0x1402648ad
  00264894  mov     ecx, eax
  00264896  add     rcx, rcx
  00264899  mov     rax, qword ptr [rdx + 0x18]
  0026489d  mov     rbx, qword ptr [rax + rcx*8 + 8]
  002648a2  test    rbx, rbx
  002648a5  je      0x1402648ad
  002648a7  cmp     dword ptr [rbx + 8], r8d
  002648ab  je      0x1402648b4
  002648ad  mov     rbx, qword ptr [rip + 0x2ffb864]  ; -> 0x3260118
```

```text
$ python3 scripts/disrva.py 0x25570f --len=0x34
  0025570f  mov     r8, qword ptr [rip + 0x30097ea]  ; -> 0x325ef00
  00255716  mov     rdx, qword ptr [rip + 0x300a303]  ; -> 0x325fa20
  0025571d  nop     dword ptr [rax + rax]
  00255720  test    r8, r8
  00255723  je      0x14025574f
  00255725  mov     r9d, dword ptr [rbx]
  00255728  mov     eax, r9d
  0025572b  and     eax, 0xffffff
  00255730  cmp     eax, dword ptr [r8 + 0x20]
  00255734  jae     0x14025574f
  00255736  mov     ecx, eax
  00255738  add     rcx, rcx
  0025573b  mov     rax, qword ptr [r8 + 0x18]
  0025573f  mov     rax, qword ptr [rax + rcx*8 + 8]
  00255744  test    rax, rax
  00255747  je      0x14025574f
  00255749  cmp     dword ptr [rax + 0x30], r9d
```

```text
$ python3 scripts/disrva.py 0x394e60 --len=0x60
  00394e60  mov     rdx, qword ptr [rcx + 0x1c]
  00394e64  test    rdx, rdx
  00394e67  je      0x140394e7d
  00394e69  cmp     qword ptr [rcx + 8], 0x2000000
  00394e71  mov     rax, qword ptr [rip + 0x2ecb720]  ; -> 0x3260598
  00394e78  cmove   rax, rdx
  00394e7c  ret     
  00394e7d  cmp     qword ptr [rcx + 8], 0x2000000
  00394e85  jne     0x140394e90
  00394e87  mov     eax, dword ptr [rcx + 0x10]
  00394e8a  mov     dword ptr [rsp + 8], eax
  00394e8e  jmp     0x140394e98  ; -> 0x394e98
  00394e90  mov     dword ptr [rsp + 8], 0xffffffff
  00394e98  mov     rdx, qword ptr [rip + 0x2ecc079]  ; -> 0x3260f18
  00394e9f  lea     rax, [rsp + 8]
  00394ea4  test    rdx, rdx
  00394ea7  je      0x140394ed2
  00394ea9  mov     r8d, dword ptr [rax]
  00394eac  mov     eax, r8d
  00394eaf  and     eax, 0xffffff
  00394eb4  cmp     eax, dword ptr [rdx + 0x20]
  00394eb7  jae     0x140394ed2
  00394eb9  mov     ecx, eax
  00394ebb  mov     rax, qword ptr [rdx + 0x18]
```

**三条附带读数**:

1. **`0x3260ff8` 的表对象有一个「开关字节」在 `+0x34`。** 一个读者在用它之前先判
   `cmp byte ptr [rsi + 0x34], 0` / `jne <跳过>`(`0x25281d`)。七张表里只有这一处读到 `+0x34` ——
   **它属于表对象,不属于记录**;语义未读(§3.7 第 3 条)。
2. **`0x3260f18` 的 id 偏移本卷没读到 `cmp`**:它的唯一直接读者是 getter `0x394e60`(上面那段),
   而 getter 在 `0x394ebb` 之后才做 id 复核,窗口外;本卷**不**给这一格填「看起来像」的值。
3. **`0x3260f18` 的懒初始化写作 `0x2488ae`**:`mov rax,[rip+…]; test rax,rax; …; cmove rax,rbx;
   mov [rip+…],rax` —— 这就是 `global_xrefs.py` 里每张表那 `overwrite_reg=2` 的来源(一个初始化写手
   + 一个 setter),不是「表被替换」。

### §3.5 记录形状与表对象形状(七张表共用,证据在这里集中一次)

**表对象**(全局槽指向它):`+0x18` = 记录数组基址、`+0x20` = 槽数上界、`+0x34` = 一个字节开关
(只有 `0x3260ff8` 有一个读者判它)。**与国家表 / 系统索引逐格相同**(`offsets.zig` 的
`country_table` 段:同一组 `+0x18`/`+0x20`/16 B/`+8`)。

**记录**(16 B):`+0` 一个 u32(空槽时被写成 `0xffffff`)、`+4` 一个 u32、`+8` 对象指针。
**空槽哨兵与 `+4` 的写入只在一段「删/紧缩」代码里读到**(`0x2468dd` 的
`mov dword ptr [r9 + r8*8], 0xffffff`、`0x246937` 的 `mov dword ptr [r9 + r8*8], eax`、
`0x246945` 的 `mov dword ptr [rax + rcx*8 + 4], edx`);**§3 的七张表的读路径一次都没读过 `+0`/`+4`**
—— 它们只读 `+8` 的指针,再复核对象自己的 id 字段。

**槽号就是索引**:七张表的每一处都是 `and eax,0xffffff` → 直接当槽号(`cmp [表+0x20]` 界检查),
没有哈希、没有二次探测。这条对下一份计划很关键:它是「`id` 的低 24 位**就是**这张表的下标」
(不是「需要再算一次哈希」)。

### §3.6 一张单读者表:`0x3260fd0` —— `single_reader`

`0xd3b4d0` 是 §2.1/§2.2 那条链上「`[obj+0xf78]` 的 qword 句柄 → 对象」的解析器。它按句柄
**高 dword 的最低字节**分三支:

```text
$ python3 scripts/disrva.py 0xd3b4d0 --len=0x40
  00d3b4d0  sub     rsp, 0x28
  00d3b4d4  mov     rax, rcx
  00d3b4d7  shr     rax, 0x20
  00d3b4db  movsx   rax, al
  00d3b4df  add     rax, 1
  00d3b4e3  je      0x140d3b58c
  00d3b4e9  cmp     rax, 1
  00d3b4ed  je      0x140d3b53a
  00d3b4ef  mov     rax, qword ptr [rip + 0x2525ada]  ; -> 0x3260fd0
  00d3b4f6  test    rax, rax
  00d3b4f9  je      0x140d3b51e
  00d3b4fb  mov     edx, ecx
  00d3b4fd  and     edx, 0xffffff
  00d3b503  cmp     edx, dword ptr [rax + 0x20]
  00d3b506  jae     0x140d3b51e
  00d3b508  mov     rax, qword ptr [rax + 0x18]
  00d3b50c  add     rdx, rdx
  00d3b50f  mov     rax, qword ptr [rax + rdx*8 + 8]
  00d3b514  test    rax, rax
  00d3b517  je      0x140d3b51e
  00d3b519  cmp     dword ptr [rax + 0x18], ecx
  00d3b51c  je      0x140d3b525
  00d3b51e  mov     rax, qword ptr [rip + 0x25244bb]  ; -> 0x325f9e0
  00d3b525  xor     edx, edx
  00d3b527  lea     rcx, [rax + 0x40]
  00d3b52b  test    rax, rax
  00d3b52e  cmove   rcx, rdx
  00d3b532  mov     rax, rcx
  00d3b535  add     rsp, 0x28
  00d3b539  ret     
```

- **`tag == -1`**(高字节 `0xff`)→ `call 0x5d1000` 后 `int3`(不返回对象)。
- **`tag == 0`** → 表 **`0x3260b78`**(`0x1a97992`/`0x1a98339` 已记过的那张),对象内 id `+0x18`,
  返回 `对象+0x20`。
- **其余 tag** → 表 `0x3260fd0`,对象内 id `+0x18`,返回 `对象+0x40`。

`0x3260fd0` 的**直接读者只有这一个函数**(本卷读到的全部);`global_xrefs.py` 报 1237 个读点,
但那些是别的函数直接读这张表,**不是**「第二个读者读到同一组五格 + 同一个返回偏移」。
按计划 Task 2 Step 3 的口径,它判 `single_reader`,不进 §3.4 的 `table_named` 名单。

### §3.7 §3 不能说的

1. **「表身份」是从用它的函数推出来的,不是从符号。** 七张表全部没有名字、没有 RTTI 名可读:
   表对象 +0 那个指针(初始化时写的 `0x24c3830` / `0x24c3868`)用 `rttibatch.py` 查是
   `unreadable ('0xffffffc8')` —— 它**下面没有 CompleteObjectLocator**,所以「读 vtable 名字」
   这条路对本卷的七张表是**关的**(这不排除别处有名字,只说明这两个地址没有)。
2. **没有一次运行时读数。** `[全局槽]` 在活体里是否非空、槽数长到多少、哪几张表其实是**同一个
   表对象**(两个全局槽可以指向同一块),本卷全部零读数;`global_xrefs.py` 每个全局那两处
   `overwrite_reg` 只是初始化写手 + setter(§3.4 第 3 条)。
3. **`+0x34` 那个开关字节的语义未读。** 一个读者在 `0x25281d` 判它,但它的写入方、以及
   「关闭时这张表是不是就整体失效」都没有读数。
4. **七个全局槽的相邻关系是 `.data` 布局,不是语义分组。** `0x3260ff0` / `0x3260ff8` /
   `0x3261010` / `0x3261030` / `0x3261068` 只差 8 字节,而 `0x325ef00` / `0x3260f18` 在别处 ——
   相邻**不能**用来推「同族」,`0x325ef00` 的存在就是反例。

---

## §4 交叉校验与判决(2026-11-15,零 shot,结论:8 条候选全部有判词;`getPlanet`/`getPop` 仍缺四格)

### §4.1 存档侧:只能证伪

探针:`scripts/scratch/2026-11_scope_tables/scope_id_domains.py`(一次性,只读 ZIP 里的
`gamestate` 文本,按块键取 id,不解码、不改写)。两份 4.4.4 存档的逐字输出:

```text
$ python3 scripts/scratch/2026-11_scope_tables/scope_id_domains.py \
      /mnt/cache/tmp/opencode/autosave_2327.01.01.sav /mnt/cache/tmp/opencode/autosave_2257.07.01.sav
save=/mnt/cache/tmp/opencode/autosave_2327.01.01.sav
  planets     count=8366 min=0 max=8365 max&0xffffff=8365 fits24=True hi8[0x00x8366]
  pop         count=0 (本存档无此块或无 id 键)
  pop_groups  count=1008 min=282 max=4261413684 max&0xffffff=820 fits24=False hi8[0x00x79 0x01x30 0x17x10 0x0cx9 0x4ax9 0x14x9]
  ships       count=8474 min=0 max=134223156 max&0xffffff=5428 fits24=False hi8[0x00x6557 0x01x1395 0x02x330 0x03x114 0x04x54 0x05x15]
  fleet       count=5968 min=0 max=150998274 max&0xffffff=3330 fits24=False hi8[0x00x4207 0x01x1184 0x02x365 0x03x114 0x04x57 0x05x25]
  colony      count=145 min=0 max=144 max&0xffffff=144 fits24=True hi8[0x00x145]
save=/mnt/cache/tmp/opencode/autosave_2257.07.01.sav
  planets     count=8334 min=0 max=8333 max&0xffffff=8333 fits24=True hi8[0x00x8334]
  pop         count=0 (本存档无此块或无 id 键)
  pop_groups  count=562 min=282 max=4227859194 max&0xffffff=762 fits24=False hi8[0x00x80 0x01x15 0x02x13 0x07x13 0x10x11 0x0fx10]
  ships       count=5978 min=0 max=50335362 max&0xffffff=3714 fits24=False hi8[0x00x5288 0x01x617 0x02x66 0x03x7]
  fleet       count=3936 min=0 max=117441255 max&0xffffff=743 fits24=False hi8[0x00x3259 0x01x529 0x02x99 0x03x28 0x04x9 0x05x6]
  colony      count=110 min=0 max=109 max&0xffffff=109 fits24=True hi8[0x00x110]
```

四条读数,逐条写清「能证什么、不能证什么」:

1. **`planets` 与 `colony` 的 id 全在 24 位内**(`fits24=True`,`hi8` 只有一个 `0x00` 桶)⇒
   「表槽号 = `id & 0xffffff`」对这两个块是**不矛盾**(它们甚至连掩码都不需要)。
2. **`pop_groups` / `ships` / `fleet` 的键带高位标志**(`fits24=False`,`hi8` 有多个桶)⇒ 对这三个块,
   **必须**先 `and 0xffffff` 才是索引;七张表每一处都这么干(§3.5)⇒ **不矛盾**。
   注意 `hi8` **不能**当类型标签读:同一个块的 id 不共享一个高位字节(例如 `ships` 有
   `0x00/0x01/0x02/0x03/0x04/0x05` 六个桶)。
3. **`pop` 块在两份存档里都是空的**(`count=0`)⇒ 「pop 的 id 值域」这一格**本格存档无对应物,未交叉**。
   这一条对 `getPop` 是**坏消息**,不是中性消息:本卷连「pop id 长什么样」都没有一个观测。
4. **存档里没有 planet / pop 的**名字→id** 映射**(`planets` 块里 `name={key="NAME_…"}` 是本地化键,
   不是 id 索引)⇒ 没有任何办法用存档把「哪张表是 planet 表」认出来。**这条是 §4.2 判词的边界。**

**证伪用的那一条**(§5.3 的同一条规则):候选表在活体里若命中,`entry` 指向的对象其 id 字段必须
落在上面的值域内。本卷**没有一次运行时命中**,所以这条规则在本卷**没有被使用过** —— 它只是
下一份计划的判据。

### §4.2 判决(8 条,一行一个)

```text
0x394190  getter_named    —— 前提:B 套 mask 0x10 的类型门 + 表 0x3260ff8 + 对象 id +0x10 是逐指令读数;
                              49 个调用点里的用途读者 0x1a9beba 说明返回值是「有 +0x18 id 的中间对象」。
0x2b6470  getter_named    —— 前提:B 套 mask 0x20 + 表 0x3260ff0 + 对象 id +0x10;102 个调用点里的
                              0x1a9be28 说明 `+0x3a8` 是下一跳 id。
0x393ec0  getter_named    —— 前提:B 套 mask 0x40 + 表 0x325ef00 + 对象 id +0x30;150 个调用点里的
                              0x1a9bdee 说明 `+0x434` 直接是归属国 id。
0x394870  getter_named    —— 前提:B 套 mask 1 + 表 0x3261010 + 对象 id +0x8;42 个调用点里的
                              0x1a9bf53 说明 `+0x1b8` 直接是国家 id。
0x393970  getter_named    —— 前提:B 套 mask 0x80 + 表 0x3260b98 + 对象 id +0x8;与图卷 §1.2 的
                              0x3939f0 同表不同函数(带缓存的那个变体),互为第二次独立读数。
0x3260ff0 table_named     —— 前提:三个互不相干的函数(0x2b6470 / 0x1a9beba 所在的 is_owned_by /
                              0x263bdd / 0x251a10)读到同一组 {界 +0x20, 表 +0x18, 16 B, ptr +8, id +0x10}。
0x3261030 table_named     —— 前提:四个函数(0x265660 / 0x288882 / 0x394cd9 / 0x397c3b)读到同一组
                              {界 +0x20, 表 +0x18, 16 B, ptr +8, id +0x8}。
0x3261068 table_named     —— 前提:四个函数(0x192f90e / 0x1a99f5a / is_owned_by 的两处)读到同一组
                              {界 +0x20, 表 +0x18, 16 B, ptr +8, id +0x10}。
```

**三条判词以外的读数**(不在 8 条候选里,但影响上表怎么用):`0x3260ff8` / `0x3261010` / `0x325ef00`
`table_named`;`0x3260f18` `unresolved`(对象 id 那一格没读到);`0x3260fd0` `single_reader`(§3.6)。

### §4.3 可直接抄成 `offsets.zig` 常量的表

**这张表在卷末 §6**(把它放在最后一节,是因为下一份计划的第一个动作就是抄它)。

### §4.4 `getPlanet` / `getPop` 还缺哪几格(= 下一份计划的第一前置)

按「缺一格就不能写 `getPlanet`」的顺序排:

| # | 缺的格 | 为什么它挡路 | 下一靶(具体到指令/函数) |
|---|---|---|---|
| 1 | **B 套 mask 位 ↔ 语义类型的对应** | 本卷知道「mask `0x10` 走表 `0x3260ff8`」,不知道 `0x10` 是 planet 还是 pop 还是 fleet。`getPlanet(id)` 的第一件事就是**选对表** | 官方 scope-iterator 的**名字拼接器**(`0x195A580..0x19A7268`,104 个,`AGENTS.md`/§25.4):名字里带 `planet`/`pop` 的那个函数,它注册的 scope 类型值就是答案 —— 这条线**离线可做**,零 shot |
| 2 | **`0x3260f18` 的对象内 id 偏移** | mask `0x2000000` 这一路(§8.2 的第 16 行)形状差最后一格,`unresolved` | getter `0x394e60` 的 `0x394ebb` 之后 0x20 字节(本卷窗口刚好切在那儿) |
| 3 | **`[scope+0x1c]` 缓存槽的填充方** | 若缓存槽在活体里常非空,`getPlanet(id)` 走「现造 scope cell」时它会命中脏值或空值 —— 入口契约取决于这一格 | 写点:`0x394200` 那个兄弟函数只做**失效**(`mov [rcx+0x10],eax` 抄 id、`xor eax,eax` 后把 `[rcx+0x14]`/`[rcx+0x1c]` **双双清零**,见下),**填充**方仍未读。下一靶 = 全库 `mov [rcx+0x1c], reg` 形态的离线扫描 |
| 4 | **调用方传进来的 id 是 raw 还是 masked** | 七张表都用 `id & 0xffffff` 当槽号,但**对象复核**比的是**原始 id**(`cmp [obj+0x10], eax`,eax 未掩码)。`getPlanet(saved_id)` 的 `saved_id` 来自存档,它带高位标志(§4.1 第 2 条)⇒ 必须先确定「传进去的是 raw 还是 masked」,否则对象复核那一关**静默落空**(回退到空对象,不崩) | 一个**运行时**读数:把一个已知 raw id 与它的 masked 值分别喂进去,看哪一次过 `cmp`。这是本卷唯一必须靠 shot 的一格 |

其余「不难但不能省」的两格(不挡第一版,但要在实现里留口):

- **`id_table.FLAG_BYTE_OFF = 0x34`** 的语义(关闭时表是否整体失效)。
- **`0x3260fd0` 那张 `single_reader` 表**:mask `0x10`/`0x20` 的链尾要经过 `0xd3b4d0` → 它。若要
  完整实现「取归属国」,这张表也要第二读者。

§4.4 第 3 条那三条指令的逐字输出(它把「缓存槽怎么失效」这一格直接钉死了):

```text
$ python3 scripts/disrva.py 0x3941ff --len=0x14
  003941ff  int3    
  00394200  mov     eax, dword ptr [rdx + 0x10]
  00394203  mov     dword ptr [rcx + 0x10], eax     ; 抄 id
  00394206  xor     eax, eax
  00394208  mov     qword ptr [rcx + 0x14], rax     ; 内联指针槽清零
  0039420c  mov     qword ptr [rcx + 0x1c], rax     ; 缓存槽清零
```

⇒ 一个 scope cell 每换一次 id,两个指针槽就被清空一次。**「为什么要清」比「谁填」更容易先答**:
指针槽跟着 id 走,换 id 必然失效。这也解释了五个 getter 为什么都先判指针非空、再判 mask ——
**空**是常态,**非空**是已解析。

**反过来说清一件事**:`getPop` 比 `getPlanet` **多**一条障碍 —— §4.1 第 3 条:两份存档的 `pop`
块是空的,连 id 值域都没有存档侧观测。而 `getPlanet` 至少有 `planets` 块的 `0..8365` 那一段
`fits24=True` 的值域可用。

### §4.5 §4 不能说的(五条)

1. **表身份是从「用它的函数」推出来的,不是从符号推出来的。** 七张表没有名字、没有可读的
   RTTI(§3.7 第 1 条),身份判词的全部内容就是「这四个/三个函数读到同一组五格」。所以
   `table_named` **不**等于「这张表叫 `CPlanetDatabase`」。
2. **没有一次运行时读数。** 全局槽非空、槽数、哪两个全局槽其实指向同一张表、缓存槽是否常非空 ——
   全部零读数。本卷所有判词都是**静态形状**判词。
3. **A 套(`scope_types`)与 B 套(mask)是两套编号,本卷没有把它们对上。** 数值重合
   (`POP=16=0x10`、`FLEET=32=0x20`)是**巧合还是同源,本卷不判**;而 `0x80` 在两套里含义直接冲突
   (A `LEADER` / B 系统),足以证明不能互译。§4.3 的常量名因此是 `MASK_0xNN`,不是 `POP`。
4. **就算形状全对,`getPlanet(id)` 还差一格语义与一格口径**(§4.4 第 1、4 条)。「表是 16 B 记录、
   槽号 = `id & 0xffffff`」只解决「怎么查」,不解决「查哪张」和「传什么」。
5. **存档这一侧只做了证伪,而且只证伪了两条**:「`fits24`」与「必须掩码」。它**没有**、也**不能**
   把任何一张表指认成 planet/pop 表 —— 存档里没有名字→id 映射,`pop` 块还是空的。

---

## §5 本卷与既有卷的关系、以及下一靶(2026-11-15,零 shot,结论:七格与既有卷同形、三发下一靶离线可做、两发必须 shot)

### §5.1 与既有卷的读数对照

| 本卷读数 | 既有出处 | 关系 |
|---|---|---|
| `scope+0x08` = 类型门 / `scope+0x10` = id | `country_scope_4_4_4.md` §6(A)、`graph` 卷 §1.2(A) | 直接引用;五个 getter 是**第三次**同口径读数 |
| 表对象 `+0x18` 基址 / `+0x20` 界 / 16 B 记录 / 对象指针 `+8` | `offsets.zig` 的 `country_table` 与 `graph`(两个独立读者) | **同形**:七张表没有一格与它们不同 |
| `0x3260b98` 系统索引 + 回退 `0x325d880` + 对象 id `+0x8` | `graph` 卷 §1.2 | 本卷的 getter `0x393970` 是它的**第二个函数**(带缓存的变体),不是同一个函数 |
| `0x3260b78` 表、对象 id `+0x18` | 作者卷 §3.5(`original_owner` 家族) | 本卷从 `0xd3b4d0` 的 `tag==0` 分支**独立**再读到同一组 ✓ |
| `0x1a9bd10` 的 20 个叶子 | 作者卷 §8.2 | 本卷把其中 4 条的**第一跳**读成了函数体(mask `1` / `0x10` / `0x20` / `0x40`)+ mask `0x80` 的第二读者 |
| `0xd3b4d0` 是「中继体,未读」(作者卷 §8.5 第 2 条) | — | 本卷**读了**:它是「qword 句柄 → 对象」的三支解析器(§3.6),其中一支正好用 `tag==0` 落 `0x3260b78` |

### §5.2 下一靶(按「离线可做 / 必须 shot」分组)

**离线可做(下一份计划的第一发)**:

1. `0x195A580..0x19A7268` 的 104 个 scope-iterator **名字拼接器**里的 `planet` / `pop` 两支 ——
   把 B 套 mask 与语义对上(§4.4 第 1 条)。这是唯一一条**不需要实机**就能给表起名的路。
2. getter `0x394e60` 的 `0x394ebb` 之后那一格(§4.4 第 2 条),把 `0x3260f18` 从 `unresolved` 收掉。
3. `scope cell` 的赋值/失效器 `0x394200` 那一段(`[rcx+0x10]` 抄 id、`[rcx+0x14]`/`[rcx+0x1c]` 清零)——
   它已经回答了「换 id 就失效」,**填充**方仍是空白;而「raw/masked 哪个进 cell」要看调用它的那一侧(§4.4 第 3 条)。

**必须 shot(一次 `install → 读 → uninstall`,沿用 `c2_scope_probe` 的口径)**:

4. 读七张表各自的 `[全局槽]` 是否非空 + `[表对象+0x20]` 的槽数 —— 这一步就能把「哪两个全局槽
   指向同一张表」判掉(静态永远判不了,BSS)。
5. §4.4 第 4 条:同一个 id 的 raw / masked 两种喂法,看对象复核过不过。

### §5.3 §5 不能说的

1. **本卷没有把任何一格升到 `pinned`。** 连「七张表在活体里都存在」都没有读数 —— 静态只看得到
   「这些指令存在」。
2. **§4.3 的常量表现在还不能整体抄进 `offsets.zig`。** 计划 Global Constraints 第 2 条:常量等判决
   落定后由下一份计划加,并按 `chain_manifest` 的围栏登记;本卷只提供**候选值与档**。
3. **`handle.TAG_SHIFT`/`TAG_MASK` 只对 `0xd3b4d0` 一个函数成立**,不是「引擎所有句柄的编码」。
   同一份工作里至少还有两种不同的 id 编码(u32 的 `& 0xffffff`、qword 的 `>> 0x20`),不能互相套用。

---

## §6 常量速查:可直接抄成 `offsets.zig` 常量(2026-11-15,零 shot,结论:23 格候选值,档全部 ≤ 静态推断(未验证))

档一律是 `静态推断(未验证)` —— 本卷零 shot,没有一格是 `pinned`。`档` 列里跟着的「N 调用点」
是 getter 的静态 `call`/`jmp` 站点数(§2.6),「双读者/三读者/四读者」是该表有几个互不相干的
函数读到同一组五格(计划 Task 2 Step 3 的判据)。

| 名字(建议) | 值 | 档 | 出处 § |
|---|---|---|---|
| `scope_gate.RVA_GETTER_MASK_0x10` | `0x394190` | `静态推断(未验证)`,49 调用点 | §2.1 |
| `scope_gate.RVA_GETTER_MASK_0x20` | `0x2b6470` | `静态推断(未验证)`,102 调用点 | §2.2 |
| `scope_gate.RVA_GETTER_MASK_0x40` | `0x393ec0` | `静态推断(未验证)`,150 调用点 | §2.3 |
| `scope_gate.RVA_GETTER_MASK_1` | `0x394870` | `静态推断(未验证)`,42 调用点 | §2.4 |
| `scope_gate.RVA_GETTER_MASK_0x80` | `0x393970` | `静态推断(未验证)`,303 调用点;同表 `0x3939f0` 见图卷 §1.2 | §2.5 |
| `scope_gate.OBJ_CACHE_OFF` | `0x1c` | `静态推断(未验证)`,五个 getter 首指令 | §2.0 |
| `scope_gate.INLINE_OBJ_OFF` | `0x14` | `静态推断(未验证)`,**只** mask `0x10` 那一份有 | §2.1 |
| `scope_gate.SCOPE_ID_OFF` | `0x10` | `pinned(graph §1.2)` + 五个 getter 同口径 | §2.0 |
| `scope_gate.SCOPE_MASK_OFF` | `0x08` | `pinned(country_scope §6)` + 五个 getter 同口径 | §2.0 |
| `id_table.FLAG_BYTE_OFF` | `0x34` | `静态推断(未验证)`,单读者 `0x25281d` | §3.4 |
| `id_table.EMPTY_KEY` | `0xffffff` | `静态推断(未验证)`,只在删/紧缩路径出现 | §3.5 |
| `id_table.RVA_TABLE_MASK_0x10` | `0x3260ff8` | `静态推断(未验证)`,双读者;obj id `+0x10` | §3.4 |
| `id_table.RVA_TABLE_MASK_0x20` | `0x3260ff0` | `静态推断(未验证)`,三读者;obj id `+0x10` | §3.1 |
| `id_table.RVA_TABLE_MASK_0x40` | `0x325ef00` | `静态推断(未验证)`,双读者;obj id `+0x30` | §3.4 |
| `id_table.RVA_TABLE_MASK_1` | `0x3261010` | `静态推断(未验证)`,双读者;obj id `+0x8` | §3.4 |
| `id_table.RVA_TABLE_MASK_0x80` | `0x3260b98` | `pinned(graph §1.2)`(系统索引);obj id `+0x8` | §2.5 |
| `id_table.RVA_TABLE_SECOND_HOP` | `0x3261068` | `静态推断(未验证)`,四读者;obj id `+0x10` | §3.3 |
| `id_table.RVA_TABLE_MASK_0x2000000` | `0x3261030` | `静态推断(未验证)`,四读者;obj id `+0x8` | §3.2 |
| `id_table.RVA_TABLE_MASK_0x2000000_FIRST_HOP` | `0x3260f18` | `未定形`(对象 id 未读) | §3.4 |
| `id_table.RVA_TABLE_HANDLE_TAG0` | `0x3260b78` | `静态推断(未验证)`,作者卷 §3.5 + 本卷 `0xd3b53a` 两处独立读数;obj id `+0x18` | §3.6 |
| `id_table.RVA_TABLE_HANDLE_OTHER` | `0x3260fd0` | `single_reader`,obj id `+0x18` | §3.6 |
| `handle.RVA_RESOLVE` | `0xd3b4d0` | `静态推断(未验证)`,单读者 | §3.6 |
| `handle.TAG_SHIFT` / `TAG_MASK` | `0x20` / `0xff` | `静态推断(未验证)`,`shr rax,0x20` + `movsx al` | §3.6 |

**抄之前必须读这一条**:上表的名字是**我按 B 套 mask 起的机械名**,`MASK_0x10` 这样的名字**故意**
不含 `POP/FLEET/PLANET` —— 语义名本卷没有证据(§5 第 1 条)。下一份计划若要用语义名,得先补
§4.4 的第 1 条。

---

## §7 `0x3260f18` 的对象内 id = `+0x8`(2026-11-15,零 shot,结论:`object_id_pinned`)

§4.4 第 2 条的原话是「getter `0x394e60` 的 `0x394ebb` 之后 0x20 字节(本卷窗口刚好切在那儿)」。
这一节把那个窗口读完。**上一节的 `obj_id=UNREAD` 行原样保留**(append-only),分叉以本节为准。

### §7.1 先定边界:`0x394e60` 与它的兄弟都**没有 `.pdata` 条目**

```
$ python3 scripts/pdata.py 0x394e60 0x394ebb 0x394200 0x394190
0x394e60 -> NOT IN ANY FUNCTION
0x394ebb -> NOT IN ANY FUNCTION
0x394200 -> NOT IN ANY FUNCTION
0x394190 -> NOT IN ANY FUNCTION
$ python3 scripts/pdata.py 0x1d08520     # 对照:有 unwind 的函数长什么样
0x1d08520 -> func 0x1d08520..0x1d085b0 (0x90 bytes) unwind 0x271dd44
```

`.pdata` 全表 130,645 条,`0x393d20..0x395730` 这 6,672 B 里只有 2 条(`0x393c40`/`0x393d20`);
`0x394e60` 之后最近的下一个 `.pdata` 起点是 **`0x395730`**(差 2,256 B)—— **不能拿它当边界**
(那会把 §2 的整族 getter 并成一坨)。所以边界由解码自己给:`ret` + `int3` 填充 + 下一条非 `int3` 指令。

⇒ `0x394e60` 的函数体 = **`0x394e60..0x394ed9`**(0x79 B,`ret` 在 `0x394ed9`),
`0x394eda..0x394edf` 是 6 个 `int3`,下一个函数从 **`0x394ee0`** 开始。

### §7.2 逐字窗口(`0x394e60..0x394f39`,盖住 `0x394ebb` 之后 0x7e B)

```text
$ python3 scripts/disrva.py 0x394e60 --len=0xe0
  00394e60  mov     rdx, qword ptr [rcx + 0x1c]              ; ① 缓存槽
  00394e64  test    rdx, rdx
  00394e67  je      0x140394e7d
  00394e69  cmp     qword ptr [rcx + 8], 0x2000000            ; ② 类型门
  00394e71  mov     rax, qword ptr [rip + 0x2ecb720]  ; -> 0x3260598
  00394e78  cmove   rax, rdx
  00394e7c  ret
  00394e7d  cmp     qword ptr [rcx + 8], 0x2000000
  00394e85  jne     0x140394e90
  00394e87  mov     eax, dword ptr [rcx + 0x10]              ; ③ id 来源(id 原值)
  00394e8a  mov     dword ptr [rsp + 8], eax
  00394e8e  jmp     0x140394e98  ; -> 0x394e98
  00394e90  mov     dword ptr [rsp + 8], 0xffffffff
  00394e98  mov     rdx, qword ptr [rip + 0x2ecc079]  ; -> 0x3260f18   ; ④ 表全局槽
  00394e9f  lea     rax, [rsp + 8]
  00394ea4  test    rdx, rdx
  00394ea7  je      0x140394ed2
  00394ea9  mov     r8d, dword ptr [rax]                     ; r8d = **原始** id(未掩码)
  00394eac  mov     eax, r8d
  00394eaf  and     eax, 0xffffff                            ; ⑤ 槽号 = id & 0xffffff
  00394eb4  cmp     eax, dword ptr [rdx + 0x20]              ; ⑥ 界 +0x20
  00394eb7  jae     0x140394ed2
  00394eb9  mov     ecx, eax
  00394ebb  mov     rax, qword ptr [rdx + 0x18]              ; ⑦ 记录数组 +0x18
  00394ebf  add     rcx, rcx                                 ; 16 B 记录
  00394ec2  mov     rax, qword ptr [rax + rcx*8 + 8]         ; ⑧ 对象指针在 +8
  00394ec7  test    rax, rax
  00394eca  je      0x140394ed2
  00394ecc  cmp     dword ptr [rax + 8], r8d                 ; ⑨ **对象内 id = +0x8(dword),比原始 id**
  00394ed0  je      0x140394ed9
  00394ed2  mov     rax, qword ptr [rip + 0x2ecb6bf]  ; -> 0x3260598   ; ⑩ 回退空对象
  00394ed9  ret
  00394eda  int3
  00394edb  int3
  00394edc  int3
  00394edd  int3
  00394ede  int3
  00394edf  int3
```

### §7.3 这一格的读数(§4.4 第 2 条那格的全部)

| 格 | 读数 | 站点 |
|---|---|---|
| 类型门 | `[scope+8] == 0x2000000` | `0x394e69` / `0x394e7d` |
| 缓存槽 | `[scope+0x1c]` | `0x394e60` |
| id 来源 | `[scope+0x10]`(dword) | `0x394e87` |
| 表全局槽 | `0x3260f18` | `0x394e98` |
| 界 / 记录 / 对象指针 | `+0x20` / `add rcx,rcx`(16 B) / `[rec+8]` | `0x394eb4` / `0x394ebf` / `0x394ec2` |
| **对象内 id** | **`+0x8`,宽 4 B(`cmp dword`)** | **`0x394ecc`** |
| 比较的是**原始** id | `r8d = [rsp+8]` 未掩码;掩码副本只在 `eax`/`ecx` 里当槽号 | `0x394ea9` / `0x394ecc` |
| 回退对象 | `0x3260598`(与 §3.4 记的「未读」不同:这一路**不是** `0x325fb00`) | `0x394e71` / `0x394ed2` |

**判词:`object_id_pinned`** —— 前提:站点 `0x394ecc` 逐字、宽度 `dword`、比较对象是未掩码 id、
且有**第二条独立读者**同格(§7.4)。这里的「pinned」是本卷口径的「**站点 + 宽度都读到**」,
**不是** §5.3 那个「实机读数」档 —— 本卷仍然零 shot。

### §7.4 第二条独立读者:`0x394ee0`(同表、同 `+0x8`、**没有**缓存槽)

`0x394ee0` 是 `0x394e60` 的「无缓存」孪生体(`0x394e60..0x394ed9` 之后 6 个 `int3` 再开始):

```text
$ python3 scripts/disrva.py 0x394ee0 --len=0x60
  00394ee0  cmp     qword ptr [rcx + 8], 0x2000000            ; 没有 [rcx+0x1c] 那一段
  00394ee8  jne     0x140394ef3
  00394eea  mov     eax, dword ptr [rcx + 0x10]
  00394eed  mov     dword ptr [rsp + 8], eax
  00394ef1  jmp     0x140394efb  ; -> 0x394efb
  00394ef3  mov     dword ptr [rsp + 8], 0xffffffff
  00394efb  mov     rax, qword ptr [rip + 0x2ecc016]  ; -> 0x3260f18
  00394f02  lea     rcx, [rsp + 8]
  00394f07  test    rax, rax
  00394f0a  je      0x140394f31
  00394f0c  mov     edx, dword ptr [rcx]
  00394f0e  mov     ecx, edx
  00394f10  and     ecx, 0xffffff
  00394f16  cmp     ecx, dword ptr [rax + 0x20]
  00394f19  jae     0x140394f31
  00394f1b  mov     rax, qword ptr [rax + 0x18]
  00394f1f  add     rcx, rcx
  00394f22  mov     rax, qword ptr [rax + rcx*8 + 8]
  00394f27  test    rax, rax
  00394f2a  je      0x140394f31
  00394f2c  cmp     dword ptr [rax + 8], edx                 ; ← 同格:+0x8 / dword / 原始 id
  00394f2f  je      0x140394f38
  00394f31  mov     rax, qword ptr [rip + 0x2ecb660]  ; -> 0x3260598
  00394f38  ret
```

函数体 `0x394ee0..0x394f38`(0x59 B),`0x394f39..0x394f3f` 是 7 个 `int3`。
**两条互不相干的函数读到同一组 `{界 +0x20, 表 +0x18, 16 B, ptr +8, id +0x8}`,同一张表 `0x3260f18`** ——
这就是 §7.3 判词里的「第二条独立读者」。

### §7.5 顺带:`0x394e60..0x3950a0` 这一窗是同一族的**高 mask**成员,对象 id 全是 `+0x8`

同一个解码段里紧接着的四个 getter(都是叶子函数、都没有 `.pdata`),对象 id 复核**逐字同形**:

| 函数 | 类型门 | 表 | 对象 id 站点 |
|---|---|---|---|
| `0x394e60` | `0x2000000` | `0x3260f18` | `0x394ecc` |
| `0x394ee0`(无缓存孪生) | `0x2000000` | `0x3260f18` | `0x394f2c` |
| `0x394f40` | `0x4000000` | `0x3260550`(缓存路)/ `0x3261028`(查表路) | `0x394fac` |
| `0x394fc0` | `0x10000000` | `0x3260f10` | `0x39502c` |
| `0x395040`(无缓存孪生) | `0x10000000` | `0x3260f10` | `0x39508c` |

⇒ 「B 套高 mask 这一族,对象内 id 在 `+0x8`」是**五次读数**,不是一次。这几张表不在本卷工单里,
本节只记「同族同格」,不替它们出判词。

### §7.6 §7 不能说的

1. **零 shot。** 「对象内 id 在 `+0x8`」是**代码读出来的字段偏移**,不是「活体里那个字段装着什么」。
2. **`+0x8` 的语义未读。** 它是「对象自己的 id」还是「id 的低 32 位 + 别的位」,本节不判;
   `0x394ecc` 只证明「拿它与**未掩码** id 比」。
3. **§4.4 第 4 条(raw vs masked)没有被本节回答。** 这里读到的是「引擎自己比的是原始 id」,
   它**不**等于「我们把 `saved_id` 原样喂进 `getPlanet` 就能过这一关」—— 那一格仍然是 shot。
4. **`0x3260f18` 与 `0x3261030`(§3.2,mask 0x2000000 那张四读者表)是不是同一张表的两个全局槽,
   本节没有判。** 两者 mask 相同、obj id 相同(`+0x8`),但界/基/回退都读不出「同一对象」的证据;
   这一格要靠 §5.2 第 4 条那次 shot(读全局槽是否非空)。

---

## §8 scope cell 的填充方(2026-11-15,零 shot,结论:`filler_named`;两槽分口径)

§4.4 第 3 条只读到失效器 `0x394200`(抄 id → 两槽清零 → 写 mask),**填充**方是空白。
这一节用**形态扫描**(不按地址)把 `.text` 全段过一遍,再逐个读活下来的候选。

### §8.1 探针与口径

`scripts/scratch/2026-11_scope_closeout/cell_filler_sites.py`(一次性,自带 README)。
六种形态,长度与 ModRM/SIB 一起看:

| 记号 | 形态 | 说明 |
|---|---|---|
| A | `mov qword ptr [base + 0x1c], reg` | 8 B 写 = §2.0 的**缓存**槽 |
| B | `mov qword ptr [base + 0x14], reg` | 8 B 写 = **内联对象**槽 |
| C | `mov dword ptr [base + 0x1c\|0x14], r32` | **反例**:4 B 写,另一个字段 |
| D | `mov qword ptr [base + 0x1c\|0x14], imm` | **反例**:立刻数(常是 `0xffffffff` / `0x3f800000`) |
| E | `movdqu/movdqa xmmword ptr [base + 0x14], xmm` | 16 B 写,**一条盖住两个槽**(不查就会漏掉整类) |
| F | `lea rX,[base + 0x1c\|0x14]` 之后 `mov [rX], rY` | 目的操作数是裸 `[rX]`,位移不在那条指令里 |

三层筛(三条**同时**满足才算候选;§4.4 第 3 条 + 计划 Review Focus 3):

1. **类型门**:同段里有 `cmp/test qword ptr [base + 8], ...`(与 getter 同形);
2. **对象来源**:同段里有 `mov <r32>, dword ptr [base + 0x10]`(读 id)或
   `mov dword ptr [base + 0x10], <r32>`(抄 id,与 `0x394200` 同形);
3. **槽的写**:A/B 的基址寄存器与 ①/② 相同,且源寄存器**不是**同段 `xor r,r` / `mov r,0`
   之后未再被写过的零值(那是清零,不是填充)。

分桶:`.pdata` 优先;**这一族 cell 构造器/填充方全是叶子函数,没有 `.pdata` 条目**
(`0x394200` / `0x394120` / `0x1a7e140` 都是),所以对它们退化成「解码连续段」:
段首 = 上一条 `ret` 之后第一个非 `int3` 指令,段尾 = 段内最后一条非 `int3` 指令。

### §8.2 先自检:第一个命中不是失效器

```
$ python3 scripts/scratch/2026-11_scope_closeout/cell_filler_sites.py
[cell_filler_sites] chunks=161328 chunks_with_hits=465 hit_insns=1544
[cell_filler_sites] 第一个命中(A/B 全局序)= 0x1b3f98  (自检靶 0x394200)
```

- **第一个命中 = `0x1b3f98`**,不是 `0x394200`(`0x394200` 那一对在 1,544 条里排**第 216 位**)。
  `0x1b3f98` 是 `[rdx+0x14]`/`[rdx+0x1c]` 的双清零(一个 0x28 B 的小对象构造器),不是本卷的 cell。
- 失效器 `0x394200` **确实在命中里**(`0x394208` / `0x39420c`),但被第 ③ 层筛掉了 ——
  这正是探针的自检:第一版零值跟踪写错时它被判成「填充」,改对之后排除。

### §8.3 普查数字(全 `.text` 37,292,032 B)

| 量 | 读数 |
|---|---|
| 解码段(`.pdata` + 叶子连续段) | 161,328 |
| 有 A/B 命中的段 | 465 |
| A/B 命中指令 | **1,544** |
| 其中源寄存器是同段零值(清零形态) | **1,209** |
| 其中同基址有 mask 门 `cmp/test [base+8]` | 10 |
| **三层筛存活** | **2**(同一函数,见 §8.5) |
| 反例 C(4 B 写) | 8,213 |
| 反例 D(qword 立即数) | 33 |
| 命中 E(16 B 向量写 +0x14) | **0** |
| 命中 F(经 `lea` 指针写) | **0** |
| `skipdata` 脱 Sync | **0 段 / 0 B** |

⇒ 「扫过什么」这句话在这里是可以逐字兑现的:**37.3 MB 全部按指令解码,没有一段因脱 Sync 被跳过**;
16 B 向量写与「先 `lea` 再经指针写」这两种会绕过位移匹配的形态,**一处都没有**。

### §8.4 「写 mask + 写槽」同段族 = 180 个函数

只按 A/B 形态筛会把 1,544 处写混在一起(其中 1,534 处在同基址上**没有** mask 门 ——
它们写的是别的类)。改成先找「同段里 `mov qword ptr [base + 8], <mask>`」的段,再要求同段有 A/B 命中:

| 类 | 个数 | 判读 |
|---|---|---|
| 全零成员(两槽都写同段 `xor` 的零值) | **122** | **建 cell / 清 cell**,不是填充(§4.4 那个失效器就是这个形状) |
| 两槽写**同一个非零寄存器** | **56** | **填充**:见 §8.4.1 |
| 两槽**不同源** | **2** | `0x394120`(解析式,§8.4.2)/ `0x631360`(另一个类,§8.4.3) |

#### §8.4.1 56 个「两槽同源非零」= scope-iterator 的 per-type cell 构造器

代表(`0x1a7e140` 循环体,类型门 mask `0x2000000` —— **正是 §7 那张表的那一路**):

```text
$ python3 scripts/disrva.py 0x1a7e12a --len=0x80
  01a7e12a  mov     qword ptr [rsp + 0x40], rbx
  01a7e12f  mov     rbx, rbp
  01a7e140  mov     eax, dword ptr [rbx]                     ; ① 从 id 数组取一个 id
  01a7e145  mov     dword ptr [rdi + 0x10], eax              ;    写 cell 的 id
  01a7e148  mov     qword ptr [rdi + 8], 0x2000000           ; ② 写 cell 的 mask
  01a7e150  mov     qword ptr [rdi + 0x14], r12              ; ③ 内联对象槽
  01a7e154  mov     qword ptr [rdi + 0x1c], r12              ; ④ **缓存槽 = 同一个对象**
  01a7e158  mov     rax, qword ptr [rdi]
  01a7e15b  call    qword ptr [rax + 0x38]                   ;    cell 自己的谓词
  01a7e160  je      0x141a7e176
  01a7e162  lea     rcx, [r15 + 0xc0]
  01a7e169  mov     rdx, rdi
  01a7e16c  mov     rax, qword ptr [rcx]
  01a7e16f  call    qword ptr [rax + 0x10]                   ;    派发(带 cell)
```

**这是「填」而不是「清」**:源寄存器 `r12` 在本段内没有被写过(callee-saved,`r12` 由调用者设),
所以两槽拿的是**同一个非零对象指针**。同形 56 份,每份一个 mask ——
`0x20` / `0x40` / `0x80` / `0x100` / `0x200` / `0x400` / `0x4000` / `0x8000` / `0x10000` /
`0x20000` / `0x40000` / `0x800000` / `0x1000000` / `0x2000000` / `0x4000000` / `0x40000000` 等,
逐份读数在探针的 `--json` 里(`chunks[].hits` + `mask_write`)。

#### §8.4.2 `0x394120` —— 唯一一处**解析式**填充(类型 mask `0x10`,写 `+0x14`)

```text
$ python3 scripts/disrva.py 0x394120 --len=0x70
  00394120  mov     r9d, dword ptr [rdx + 0x10]              ; ① id 从**源对象**的 +0x10 取
  00394124  mov     r8, rcx                                  ;    r8 = 目标 cell
  00394127  mov     rdx, qword ptr [rip + 0x2ecceca]  ; -> 0x3260ff8   ; ② 表
  0039412e  mov     qword ptr [rcx + 8], 0x10               ; ③ 写 mask
  00394136  mov     dword ptr [rcx + 0x10], r9d              ;    写 id
  0039413a  test    rdx, rdx
  0039413d  jne     0x14039414f
  0039413f  mov     rax, qword ptr [rip + 0x2ecb9ba]  ; -> 0x325fb00
  00394146  mov     qword ptr [rcx + 0x14], rax              ;    表缺失 → 回退对象
  0039414a  mov     qword ptr [rcx + 0x1c], rdx              ;    **缓存槽 = 0**
  0039414e  ret
  0039414f  mov     eax, r9d
  00394152  and     eax, 0xffffff
  00394157  cmp     eax, dword ptr [rdx + 0x20]
  0039415a  jae     0x140394175
  0039415c  mov     ecx, eax
  0039415e  mov     rax, qword ptr [rdx + 0x18]
  00394162  add     rcx, rcx
  00394165  mov     rax, qword ptr [rax + rcx*8 + 8]
  0039416a  test    rax, rax
  0039416d  je      0x140394175
  0039416f  cmp     dword ptr [rax + 0x10], r9d              ;    对象复核 +0x10
  00394173  je      0x14039417c
  00394175  mov     rax, qword ptr [rip + 0x2ecb984]  ; -> 0x325fb00
  0039417c  mov     qword ptr [r8 + 0x14], rax              ; ④ **解析结果 → +0x14**
  00394180  mov     qword ptr [r8 + 0x1c], 0                 ; ⑤ **缓存槽清 0**
  00394188  ret
```

函数体 `0x394120..0x394188`(`ret` 在 `0x394188`),叶子函数、无 `.pdata`。
它把 §2.0 的五步**全做了一遍**却只填**内联槽**:解析成功、失败、表缺失三条路径
**都把 `+0x1c` 写成 0**。这与 §2.1 的读数**互相印证**:五个 getter 里只有 mask `0x10` 那一份
(`0x394190`)有 `[scope+0x14]` 内联分支(`0x3941b6`),**因为只有 mask `0x10` 的 cell 会被预解析**。

#### §8.4.3 `0x631360` —— 非零 `+0x1c`,但 mask 是 `0x10000000000`

```text
  00631630  mov     rax, qword ptr [rdi + 0x180]
  00631637  movabs  rcx, 0x10000000000
  00631641  mov     qword ptr [rbx + 8], rcx     ; mask = 0x10000000000(不在 §2 的五档里)
  00631645  mov     qword ptr [rbx + 0x1c], rax   ; 缓存槽 = 对象的 +0x180
  00631649  mov     dword ptr [rbx + 0x24], 0xffffffff
  00631650  mov     qword ptr [rbx + 0x14], rsi
  00631654  mov     dword ptr [rbx + 0x10], esi
```

它确实**解析式地**写了 `+0x1c`,但 mask 空间是 40 位(`0x10000000000`),与 §2.0 那五档
(`0x10`..`0x40000000`)不同域 ⇒ **判为「另一个 cell 类」**,不并入本卷这一格。

### §8.5 三层筛活下来的 2 处 = 同一个函数:`0x1678020`,是**整格复制**不是解析

```text
$ python3 scripts/disrva.py 0x1678090 --len=0x70
  016780b0  movsxd  rax, r8d
  016780b3  imul    rcx, rax, 0x2c                    ; 目标 stride 0x2c
  016780b7  add     rcx, qword ptr [rbx + 0x10]
  016780bb  mov     r10, qword ptr [rdx - 8]          ; 源 mask
  016780bf  cmp     qword ptr [rcx + 8], r10          ; ① mask 相等?
  016780c3  jne     0x1416780d6
  016780c5  mov     eax, dword ptr [rdx]              ; 源 id
  016780c7  cmp     dword ptr [rcx + 0x10], eax       ; ② id 相等?
  016780ca  jne     0x1416780d6
  016780cc  mov     rax, qword ptr [rdx + 0xc]        ; 源 +0xc
  016780d0  cmp     qword ptr [rcx + 0x1c], rax       ; ③ 缓存槽相等?
  016780d4  je      0x1416780fa                     ;   三条都相等 → 不写
  016780d6  mov     r11b, 1
  016780d9  mov     qword ptr [rcx + 8], r10          ; mask
  016780df  mov     dword ptr [rcx + 0x10], eax       ; id
  016780e2  mov     rax, qword ptr [rdx + 4]
  016780e6  mov     qword ptr [rcx + 0x14], rax       ; +0x14 ← 源 +4
  016780ea  mov     rax, qword ptr [rdx + 0xc]
  016780ee  mov     qword ptr [rcx + 0x1c], rax       ; +0x1c ← 源 +0xc
  016780f2  mov     rax, qword ptr [rdx + 0x14]
  016780f6  mov     qword ptr [rcx + 0x24], rax       ; +0x24 ← 源 +0x14
```

函数 `0x1678020..0x167859d`,源/目标 stride 都是 `0x2c`,三个字段相等就跳过 ——
这是**整格赋值**(把一份「cell 描述」原样盖进 cell 数组),`+0x1c` 的值是**抄来的**,不是算出来的。
唯一调用者 `0x13db840..0x13dc25c`(站点 `0x13dbb06`),调用前把描述数组交给
**`0x58d720` 的 9 路跳表派发**(`[rcx+0x7a8] ∈ 0..8` → `0x5925c0` / `0x592b50` / `0x593090` /
`0x5935d0` / `0x593b10` / `0x594050` / `0x5945b0` / `0x594b40` / `0x595140`)去填。
**`0x58d720` 与那 9 个函数本节没读** —— 见 §8.7 第 3 条。

### §8.6 逐个候选的判词

| 候选(函数 / 站点) | 形态 | 判词 | 为什么 |
|---|---|---|---|
| `0x1a7e140` 循环(56 份同形,站点 `0x1a7e150`/`0x1a7e154`) | mask 写 + id 抄 + 两槽 ← 同一非零寄存器 | **填充方**(两个槽都是) | 源是调用者给的**对象指针**,不是零、不是抄自别的 cell |
| `0x394120`(`0x39417c`/`0x394180`/`0x394146`/`0x39414a`) | 写 mask `0x10` + id + 表 `0x3260ff8` 解析 + 写 `+0x14` + `+0x1c`=0 | **填充方**(只 `+0x14`,解析式) | 表、界、记录、对象复核四步齐全;`+0x1c` 三条路径全 0 |
| `0x394200` 与 8 个同形兄弟(`0x394080` `0x394200` `0x394290` `0x394390` `0x394490` `0x394590` `0x394850` `0x394940` `0x394a40`) | 写 mask + 抄 id + 两槽 ← 同段 `xor` 的零 | **不是填充方**(建 cell / 清 cell) | 源是零值;`0x394200` 的 mask `0x20`、`0x394080` `0x2000`、`0x394290` `0x200`、`0x394390` `0x800`、`0x394490` `0x400`、`0x394590` `0x4000`、`0x394850` `1`、`0x394940` `0x20000`、`0x394a40` `0x40000` |
| `0x23a14f` 批量构造(站点 `0x23a221`/`0x23a229`) | stride `0x2e` 批量建 cell;mask `0x10` 才预解析 | **填充方**(`+0x14`,批量版) | 与 `0x394120` 同结论:`+0x14` 收对象,`+0x1c` 收 0 |
| `0x1678020`(`0x16780e6`/`0x16780ee`) | 整格赋值(源 stride `0x2c`) | **不是填充方**(搬运) | `+0x1c` 抄自描述数组;上游是 `0x58d720` 的 9 路派发 |
| `0x23a8af` / `0x23ab52`(`0x23a700..0x23aa05` / `0x23aa7f..0x23ab97`) | 解析式写 `+0x1c` | **不是这个 cell** | 它写的结构体 mask 在 `+0x10`、id 在 `+0x18`(本卷的 cell:mask `+8`、id `+0x10`)⇒ 另一个类 |
| `0x8f04b0..0x8f0c08`(`0x8f0691`/`0x8f0695`) | 一段大构造器里把 `+0x14`/`+0x1c` 写 `r12` | **不是填充方** | `xor r12d,r12d` 在 `0x8f04e2`,全程零值 |

**两槽的结论分开写**(计划 Review Focus 4 要求):

- **`+0x14`(内联对象槽)**:填充方 = `0x394120`(单对象、解析式、mask `0x10`)+
  56 份 iterator 构造器(写寄存器)+ `0x23a221`(批量版)。**`filler_named`**。
- **`+0x1c`(缓存槽)**:填充方 = 同一批 56 份 iterator 构造器(站点例 `0x1a7e154`,8 B 写)+
  `0x16780ee`(整格复制)。**没有一处**是「解析完再写 `+0x1c`」——
  `0x394120` 与 `0x23a14f` 都在**同一条路径上**把它写 0。**`filler_named`**。

**一条附带交叉校验(写侧给 §3 的「对象内 id」再证一次)**:每个 ctor 从**源对象**取 id 的偏移,
与它那一路表的「对象内 id」**逐格相同** —— `0x394200`(mask `0x20`)取 `[rdx+0x10]`,而 mask `0x20`
的表 `0x3260ff0` obj id = `+0x10`(§3.1);`0x394850`(mask `1`)取 `[rdx+8]`,而 mask `1` 的表
`0x3261010` obj id = `+0x8`(§3.4)。⇒ §3 那一列不是「只从读侧推的」,**写侧也读到了同一个偏移**。

### §8.7 §8 不能说的

1. **零 shot。** 「谁写这个槽」是代码读出来的;「活体里这个槽非不非空、谁先谁后」本节一个字都没读到。
2. **`filler_named` 只证「这个函数写这个槽」**,不证「它在活体里一定被调」。56 份 iterator 构造器
   没有做调用者计数(计划给了 `find_refs.py` 两次预算,下意识留给了别处;下一次要用时按 §2.6 的口径跑)。
3. **`0x58d720` 的 9 路派发未读。** 它是 `0x16780ee` 那条「整格复制」的上游,也是「描述数组里
   `+0xc`/`+0x14` 两个指针是谁填的」的唯一出口。**这一条是留给下一份计划的离线靶**,不是本卷的空白:
   本卷这一格问的是「cell 的槽谁写」,答案已在上表。
4. **`0x1a7e140` 里 `r12` 的来源在本函数之外**(callee-saved,由调用者设)。本段内未见清零,
   但「调用者有没有把它设成 0」本节没读 ⇒ 「两槽非零」是**段内**结论。
5. **`0x631360` 与 `0x23a700` 这两个「另一个 cell 类」只读到一个站点就收手**;
   它们是否与 §2.0 那族共享 id 空间、是否也参与 `getPlanet`,本节不判。

---

## §9 判决与「下一发」清单(2026-11-15,零 shot,结论:§4.4 的两格读掉)

判决: scope_cells_closed
前提: ① `0x3260f18` 那一路的对象内 id = `+0x8`(dword、与未掩码 id 比;站点 `0x394ecc` **与** `0x394f2c`
      两个独立读者,§7);② `[cell+0x14]` 的填充方 = `0x394120`(解析式、mask `0x10`、站点 `0x39417c`,
      8 B 写)+ 56 份 iterator 构造器(§8.4);③ `[cell+0x1c]` 的写点 = 同一批 56 份构造器
      (站点例 `0x1a7e154`,8 B 写)+ 整格复制 `0x16780ee`;**没有**「解析完再写 `+0x1c`」的路径
      (唯一那处 `0x23a8af`/`0x23ab52` 写的是另一个类,§8.5/§8.6)。
下一步: 那一格必须 shot 的(§4.4 第 4 条)不变 —— 同一个 id 的 raw / masked 两种喂法过不过 `cmp`。
      「0x58d720 的 9 路派发」是**离线**可做的下一靶(§8.5),但它不挡 `getPlanet` 第一版。

### §9.1 两格各自的读数

| # | §4.4 的格 | 判词 | 站点 | 宽度 | 依据 |
|---|---|---|---|---|---|
| 2 | `0x3260f18` 的对象内 id | `object_id_pinned` | `0x394ecc`(`0x394ee0` 的第二读者 `0x394f2c`) | `dword`(4 B),`cmp dword ptr [rax + 8], r8d` | §7.2 |
| 3 | `[scope+0x1c]` 的填充方 | `filler_named`(`+0x1c`)/ `filler_named`(`+0x14`) | `0x1a7e154` / `0x1a7e150`(56 份同形);`0x394120` 的 `0x39417c`+`0x394180`;`0x16780ee` | 8 B(`mov qword ptr …`) | §8.4 / §8.5 |
| 卷级 | — | `scope_cells_closed` | — | — | §7 + §8 |

**「判词」的两个词在本卷各有一个口径**,别混:

- `object_id_pinned` / `filler_named` 的 `pinned/named` 只表示**站点、宽度、(必要时)解析链都读到了**;
  本卷**零 shot**,没有一格升到 §5.3 那个「实机读数」档(§6 的档一律 `静态推断(未验证)`)。
- `[cell+0x1c]` 的 `filler_named` **不**表示「引擎在活体里一定会填它」——只表示「谁写这个槽,已具名」。

### §9.2 `getPlanet` / `getPop` 现在缺什么(= §4.4 的剩余项,一格没多、一格没少)

| # | 缺的格 | 状态 |
|---|---|---|
| 1 | **B 套 mask ↔ 语义类型** | **仍缺**,离线可做:`0x195A580..0x19A7268` 的 104 个名字拼接器里的 `planet`/`pop` 两支 |
| 4 | **调用方传进来的 id 是 raw 还是 masked** | **仍缺,必须 shot**(本卷只读到「引擎自己比原始 id」,§7.6 第 3 条) |
| 附 a | `id_table.FLAG_BYTE_OFF = 0x34` 的语义 | 仍缺(单读者 `0x25281d`,§3.4) |
| 附 b | `0x3260fd0` 那张 `single_reader` 表的第二读者 | 仍缺(§3.6;要完整实现「取归属国」才需要) |
| 新 | `0x58d720` 的 9 路派发 | 新增的**离线**靶,**不挡**第一版(§8.5/§8.7 第 3 条) |

⇒ 做 `getPlanet` 第一版还差 **两格**:mask 的语义(离线)+ 存档 id 的喂法(一次 shot)。

### §9.3 §9 不能说的(本卷增量)

1. **§7 与 §8 都是零 shot。** 两节加起来没有一个实机读数;上一版 §5.3 第 1 条(「本卷没有把任何一格
   升到 `pinned`」)在「实机」这个意义上**仍然成立**,`object_id_pinned` 是**静态档**的判词。
2. **`filler_named` 只证「这个函数写这个槽」**,不证「它在活体里一定被调」:
   56 份 iterator 构造器没做调用者计数(§8.7 第 2 条)。
3. **`0x3260f18` 的对象 id 若来自调用者,本卷只读到那一层**(§7.6 第 3 条);
   `0x58d720` 那一层(描述数组的 `+0xc`/`+0x14` 谁填)完全没读。
4. **本卷没有任何一格是 `pinned` 档。** 新判词里出现的 `pinned` 是 §4.4 那张表的格名口径
   (站点+宽度),不要拿它当「活体验证过」。
