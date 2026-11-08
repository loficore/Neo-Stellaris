# Country scope:静态侦察(4.4.4,离线,零 shot)

**这份文件回答什么。** 切片 2 的前半:`every_country = { neo_action = { } }` 这条路,能不能把
一个国家 scope 送到我们已经 hooks 的派发点上?如果能,引擎给它打的是什么记号(`mask`),国家对象
在哪,哪几个字段能读?

**结论先写(全文只有这一句是判决):**

> **能。** `every_country` 的逐元素循环写的 scope 是 `{mask = 0x04, id = <国家 id>}`,它走的
> 派发包装器 `0x3B0F80` **就是**我们已经在 detour 的那一个(与 `every_system` 同一个函数、同一张
> 槽位表)。所以 C2 **不需要新的 hook** —— 需要的是读数,而读数由 `NEO_SCOPE_OTHER` 那一行给出。
> 国家 id 有了(`[scope+0x10]`,对象里在 `+0x20`);**能量币与关系值没有找到**,原因见 §8。
>
> **2026-11-08 追加:已由 C2 实机一发确认**(`mask=0x04`、每月每国一次、`vtable_rva=0x24e9068`,
> 逐字读数与全部边界见 **§11**;这一句不改写上面的静态结论,只把它标成「已验」)。

**方法(全部离线,只读 exe 拷贝,`NS_STELLARIS_EXE`)。** 每条都写了复算命令,命令是
`scripts/` 下的维护中工具,不是一次性探针:

| 步骤 | 命令 |
|---|---|
| 名字在哪 | `python3 scripts/strfind.py every_country every_` |
| 谁引用它 | `python3 scripts/riprefs.py 0x2668dd8 --verify`、`python3 scripts/fastcalls.py 0x192b0d0` |
| 注册函数体 | `python3 scripts/disrva.py 0x193B970 0x193C266` |
| 对象/槽表 | `python3 scripts/vtable.py 0x2663A38`(槽表另用一次性 qword 读复算,见 §4) |
| 派发点 | `python3 scripts/disrva.py 0x3B0F80 0x3B1155`、`python3 scripts/fastcalls.py 0x3B0F80` |

**证据等级**(与 `version_drift_4_4_4.md` 同一套,本文自用):**A** = 双侧证人(逐字节/调用点),语义
由调用点验证过;**B** = 单侧静态证人,语义未由调用点验证;**C** = 只有形状或同族类比。**任何判据
都不许只靠 C。**

---

## §1 结论表

| 问题 | 读数 | 等级 | 在哪论证 |
|---|---|---|---|
| `every_country` 是什么 | **iterator**(不在 effect/trigger 的 3,900 行表里;由 102 个 iterator 注册器之一建) | A | §2 |
| 注册函数 | **`0x193B970..0x193C266`**(0x8F6 B),同一个函数注册 `random_country`/`ordered_country`/`every_country` | A | §3 |
| `every_country` 的 create / class_info | create **`0x1A6BD00`** / class_info **`0x2667670`** | A | §3 |
| 对象 | `new(0x188)`;vtable **`0x2663A38`**;`[obj+0x180] = 4` | A | §4 |
| 派发点 | **`0x3B0F80`** —— 与 `every_system` **同一个函数**,不读 scope 字段 | A | §5 |
| 国家 scope 形状 | `+0x08` mask、`+0x10` id;scope 对象至少到 `+0x70` | A | §6 |
| **国家 mask** | **`0x04`**(引擎自己的循环里写死,系统是 `0x80`) | **A** | §6 |
| 国家容器 | `[[0x3260BB0]+0x560]` = u32 向量,`[+0x56C]` = 条数 | A | §7 |
| 国家对象表 | **`0x3260FD8`**(bound `[+0x20]`、root `[+0x18]`、entry 步长 `0x10`) | B+ | §7 |
| 国家 id | scope `+0x10` / **对象 `+0x20`** | B+ | §7 |
| 能量币 | **unresolved** | — | §8 |
| 关系值 | **unresolved** | — | §8 |

---

## §2 `every_country` 不在 effect/trigger 表里 —— 它是 iterator

计划 Step 1 写的是「从 `keyword_behaviour_registration_4_4_4.tsv` 取 `every_country`」。**这一句
字面执行不了**,原因是一个可以数出来的事实:

```bash
grep -c .      evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv   # 3901(1 行表头 + 3900 行)
grep -ci every_ evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv   # 1
grep -in every_country evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv  # 0
```

那唯一一行是 `every_system_in_cluster`(token 12796,class_info `0x260FA20`)。`every_country` /
`any_country` / `random_country` 这些**都不在那张表里**:它们是 **scope iterator**,由另一族函数注册
—— 取证卷 §19 的 101 个 iterator 注册器、§25.4 的 104 个名字拼接器、§80.1 的
`every_system` 单例(名字由 `"every_" + "system"` 拼出来,exe 里**没有** `every_system` 这个串)。

本文的切入口因此与 §80 相同:**先找拼名字的那个函数,再找它的调用者**。

---

## §3 注册链:`0x193B970` 一个函数注册三兄弟

`every_` 这个前缀串在 `0x2668DD8`,**全镜像只有一个引用点**:

```bash
python3 scripts/riprefs.py 0x2668dd8 --verify
# == 1 refs to 2668dd8 (.text) [verified]
#       1  func 192afe0..192b0c5
```

`0x192AFE0` 就是 §80.1 那个 `"every_" + <入参>` 拼接器(返回 `std::string`)。它的调用者里有 102 个
0x8F6 字节的兄弟(每个都带一条 `"Iterate through …"` 文档串)。按文档串定位:

```bash
python3 scripts/fastcalls.py 0x192b0d0 | grep -A2 'Iterate through all countries'
#   1 sites  0x193b970..0x193c266 (0x8f6)  -
#          0x2668858 'Iterate through all countries'
#          0x24875e0 'country'
```

⇒ **`every_country` 的注册函数 = `0x193B970..0x193C266`**,与 `every_system` 的
`0x19682F0..0x1968BE6` 同尺寸(0x8F6 B)、同一族形状。函数体里三个 `GetOrAddToken`(`0x1D13270`)
+ 三个 BST 插入(`0x3AEF60` → effect db `0x33746E8`):

| mint 站点 | 前缀来自 | 运行时名字 | class_info | create |
|---|---|---|---|---|
| `0x193B9E4` | `0x192B440` → `0x192B350`(`"random_"`) | `random_country` | `0x2667650` | `0x1A6BC60` |
| `0x193BB49` | `0x192B770` → `0x192B690`(`"ordered_"`) | `ordered_country` | `0x2667680` | `0x1A6BCB0` |
| **`0x193BC95`** | `0x192AFE0`(`"every_"`) | **`every_country`** | **`0x2667670`** | **`0x1A6BD00`** |

三个 class_info 的 qword 都是逐条读出的(`{deleter 0x34C090, create, deleter, create2}`),读法与
§80.1 相同。函数尾部(`0x193BDB2` 起,调 `0x199E780` + 一条 17 字节后缀串 `0x266A7B8`)还注册了
trigger 侧(`any_country` 一族)**—— 那一段本节没有逐条读完,记为 C 级未决**。

**这一节不能说的。** 「运行时名字 = 前缀 + country」是**两段拼起来**的结论(前缀是代码里的字面量,
`"country"` 是 `0x24875E0`),没有实机把 token 名字读回来;`0x1A6BD00` 是「create」是按
class_info qword[1] 的读法,不是 call-site 证人。

---

## §4 对象:两张 vtable 只差两个槽

`create 0x1A6BD00` 逐条读完:

```
01a6bd06  mov  ecx, 0x188                 ; 对象 0x188 字节
01a6bd1d  mov  edx, 4                    ; ← 第二个构造实参
01a6bd20  call 0x17F7860                 ; 基类 ctor(obj, edx)
01a6bd25  lea  rax,[0x2663A38]           ; [obj+0] = vtable
01a6bd2c  mov  [rbx], rax
01a6bd2f  lea  rax,[0x2615DB8]           ; [obj+8] = 次 vtable(多重继承那半)
01a6bd36  mov  [rbx+8], rax
```

基类 ctor `0x17F7860` 把第二个实参**原样**存进 `[obj+0x180]`
(`017f78b2 mov qword [rdi+0x180], rbx`)。`every_system` 在同一格上是 `0x80`(§90.2),
`every_country` 是 **`4`**。

把两张 vtable 逐槽读完,结果是**槽 0–28 逐字节相同,只有槽 29/30 不同**:

| 槽 | `every_system` `0x26562D0` | `every_country` `0x2663A38` |
|---|---|---|
| slot[1] `+0x08` | `0x3AFD30` | `0x3AFD30` |
| slot[2] `+0x10` | `0x17F7920`(`limit` token 门 / 非 `limit` → `0x3B01A0`) | 同 |
| slot[8] `+0x40` | **`0x3B0F80`** | **`0x3B0F80`** |
| slot[14] `+0x70` | `0x1A76130` | `0x1A76130` |
| slot[19] `+0x98` | `0x3B1420`(bool 谓词) | 同 |
| slot[21] `+0xA8` | `0x3B14B0`(scope 合法性门) | 同 |
| **slot[29] `+0xE8`** | `0x1A798C0` → **`[0x3260BB0]+0x59C`**(系统条数) | `0x1A7AF10` → **`[0x3260BB0]+0x56C`**(国家条数) |
| **slot[30] `+0xF0`** | `0x1A798D0`(逐系统循环) | `0x1A7AF20`(逐国家循环) |

⇒ 这是**同一个类的两个实例化**(模板/`scope_kind` 做参数),不是两个类。它给 §5/§6 一个很强的
前提:国家那一趟走的机器与系统那一趟**是同一套代码**,区别只在两个常量。

---

## §5 派发点:`0x3B0F80` 与 scope 类型无关

`0x3B0F80`(469 B)全文读完,只做三件事:

```
003b0fad  movsxd rbx,[rcx+0x20]      ; 子效果对象的 token id
003b0fb1  call   0x1D12C60           ;  token db(非空时再 call 0x1D12CD0 刷反查表)
003b0ff0  call   0x1C98680           ; 建 0x48 字节的计时/名字记录
003b1009  call   [rax+0xa8]          ; ① 子效果自己的 scope 合法性门
003b101c  call   [rax+0x48]          ; ② 子效果自己的 body(收 (child, scope))
```

**它从头到尾没有读 scope 的任何一个格子** —— `rbp`(第二实参)只是原样传给 `+0xa8` 与 `+0x48`。
所以它是一个「**把一个子效果跑在一个 scope 上**」的公共包装器,与 scope 类型无关。

旁证:全镜像 8 字节对齐的 qword 里有 **1,067** 个等于 `BASE + 0x3B0F80`(`.rdata` 槽 + 其它),
`every_country` 的 `+0x40`、`every_system` 的 `+0x40`、`country_event` 的 `+0x40` 都在其中。

**这条对切片 2 的意义:** 我们已经在 `0x3B0F80` 上装 token detour(`neo_dispatch.zig`,
`RVA_DISPATCH = 0x3B0F80`),它按 `[child+0x20]` 认我们的 token、然后转 `neo_vtable.runBody`。
`runBody` 的第一道门是 `isSystemScope(mask)`,**非 0x80 一律 `return 0`** —— 也就是说,国家 scope
今天就已经到了我们手里,只是被那道门挡掉了(统计在 `mask_odd` / `nonSystemScopes()`)。

**这一节不能说的。** 这**不是**「每个国家一次」的证明。它只说「国家 scope 的派发会经过同一个
函数」;次数与 mask 要看 C2 的读数(`dispatched` 增量、`NEO_SCOPE_OTHER` 行数)。`0x17F4950`
(`effect_impl.cpp`)是 `0x3B0F80` 的两个直接调用者之一(§91.6),它与 `every_country` 的
`+0x40` 是两条不同形态的入口 —— 本节没有证明 C2 的驱动会走哪一条。

---

## §6 scope 形状与国家 mask:`0x04`(引擎自己写死的)

两个逐元素循环(**同一段代码的两个实例化**)在这里对照:

```
; 系统 0x1A798D0                     ; 国家 0x1A7AF20
01a79920  mov eax,[rbx]               01a7af70  mov eax,[rbx]          ; 容器里的 4 B id
01a79925  mov [rdi+0x10],eax          01a7af75  mov [rdi+0x10],eax     ; scope+0x10 = id
01a79928  mov qword [rdi+8],0x80      01a7af78  mov qword [rdi+8],4    ; scope+0x08 = mask
01a79930  mov qword [rdi+0x14],0      01a7af80  mov qword [rdi+0x14],0
01a79934  mov qword [rdi+0x1c],0      01a7af84  mov qword [rdi+0x1c],0
01a79938  mov rax,[rdi]               01a7af88  mov rax,[rdi]
01a7993b  call [rax+0x38]             01a7af8b  call [rax+0x38]        ; scope 自己的合法性
01a79942  lea rcx,[r15+0xc0]          01a7af92  lea rcx,[r15+0xc0]     ; 迭代器 +0xC0 的容器
01a7994f  call [rax+0x10]             01a7af9f  call [rax+0x10]        ; 派发(见 §5)
```

**`mask` 的值是引擎自己写进 scope 的,不是我们从 3.x 表里借的**(`docs/version-compatibility.md`
那张 3.x 表说 `COUNTRY=4` 但同一张表说 `LEADER=128`,而 4.4.4 实测系统是 `0x80` —— 那套位
定义已经对不上,不能引用)。除了这条直接写点,还有两条侧证:

1. `0x3B14B0`(scope 合法性门)做的是 `test qword [scope+0x08], <子效果 vtable+0x78 返回的掩码>`
   —— mask 是**与**运算的位标志空间;
2. `country_event` 的 vtable `0x26080B0` 的 `+0x78` = **`0x241BD0`**,全文是 `mov eax,4; ret`。

⇒ 国家 mask = **`0x04`**,等级 **A**(写点 + 读点两侧都有)。scope 对象另外还有 `+0x14`/`+0x1c`
两个被清零的格子,`country_event` 的 body 还会读写 `+0x68`/`+0x6c`(随机延迟的计数器/散列)
⇒ **scope 对象至少到 `+0x70`,不是「只有两个格子」**。

**这条对 `NEO_SCOPE_OTHER` 的影响:** 诊断行**不假设** mask 的值,它打印引擎写进去的那个数。
`mask=0x04` 是我们的**预测**,不是判据;C2 的判据是「出现了一行 mask ≠ 0x80」。

---

## §7 国家对象与容器(静态链)

国家 id 的收集器是 `0x192C290`(系统孪生 `0x192BE10`)。逐条读:

```
0192c2a5  rax = [0x3260BB0]        ; 同一个 galaxy 全局(§1/§89 读系统容器用的那个)
0192c2b1  rdi = [rax+0x560]        ; ← 国家 id 向量(系统是 +0x590)
0192c2b8  rax = [rax+0x56C]        ; ← 条数(系统是 +0x59C)
0192c2bf  rbp = rdi + rax*4        ; 4 B 步长
0192c2d0  rbx = [0x3260FD8]        ; ← 国家对象表(系统是 0x3260B98)
0192c2e5  cmp eax,[rbx+0x20]       ; bound
0192c2ee  rbx = [[rbx+0x18] + eax*16 + 8]   ; entry 步长 0x10,取 +8 那一格
0192c2fb  cmp dword [rbx+0x20], ecx          ; ← 对象的 id 在 +0x20
0192c300  （未命中）rbx = [0x325F390]        ; 空对象回退
0192c30f  call [[rbx+0x18]+8]                ; 对象 +0x18 上那半 vtable 的合法性槽
0192c316  mov ecx,[rbx+0x20]
0192c319  mov [r14+rsi*4],ecx                ; 合法 → 把对象 id 写进向量
```

⇒ 读完的四条:

| 读数 | RVA / 偏移 | 等级 |
|---|---|---|
| 国家容器(4 B id 向量) | `[[0x3260BB0]+0x560]`,条数 `[+0x56C]` | A(与已实机验过的系统容器 `+0x590`/`+0x59C` 同形) |
| 国家对象表 | `0x3260FD8`(bound `+0x20`、root `+0x18`、entry `0x10` 步长、取 `+8`) | B+(与已确证的 `0x3939F0`/`0x3260B98` 系统解析器同形) |
| **国家 id(对象内)** | **`+0x20`** | B+(查找比较用的就是它) |
| 对象合法性门 | `[[obj+0x18]+8]`,收 `(self)` | B |
| 系统 id(对象内,对照) | `+0x08`(`0x3939F0` 的 `entry+8 == id`;本节孪生的 `cmp [rax+8],edx`) | A(§1.2) |

**注意 id 是两套**:`scope+0x10`(派发时的那一趟)与 `对象+0x20`(国家对象自己的字段)。系统那边同理
(`scope+0x10` / `对象+0x08`)。两者不相等是缺陷信号,不是常态。

---

## §8 三个字段:一个有了,两个没有(**不猜**)

计划要的是「至少三个字段的偏移:国家 id / 能量币 / 关系值」。

| 字段 | 结果 | 依据 |
|---|---|---|
| 国家 id | **有**:`scope+0x10`(A)/ 对象 `+0x20`(B+) | §6 / §7 |
| 能量币 | **unresolved** | 下面的理由 |
| 关系值 | **unresolved** | 下面的理由 |

**为什么不给一个「看起来对」的偏移。** 这两个字段要的是「资源数组里 energy 那一格」与
「国家对国家的那个关系值那一格」,它们**不在**本文跟到的任何一条静态链上:

- 本文的链止于「怎样拿到国家对象」。资源数组与关系表都是**对象内部的容器**,位置取决于
  资源类型的编号体系与关系表的键编码 —— 这两样都没有离线读数,只能靠**猜一个索引**。
- 猜的代价不对称:一个错的对象偏移会让读取读出邻居对象的字段(§4.x 的形状 —— 不崩、值看起来
  合理),而 C2 的判据是「进程存活 + 一行日志」,它**不会**戳穿一个读错的字段。

所以本节按 `AGENTS.md` 的「不猜地址」收在这里,并把下一步写成可执行的两条:

1. **资源数组**:从 `has_resource` / 资源库存那一族 trigger 的 class_info → create → vtable
   `+0x48` body 走(与 `country_event` 同一条读法),读它对 `[country + X + index*?]` 的取址,
   再拿 `common/` 里的资源类型定义把 energy 的索引钉死;
2. **关系**:从 `country_has_opinion` 一族(或 `has_opinion`)的 body 走,键通常是
   `(from_id, to_id)` 的 64 位打包 —— **键编码与值偏移要一起读**,只读一个是没用的。

在拿到这两条之一以前,切片 2 的**写**路径一律不开;C2 只读 `mask`/`id` 两个格子。

---

## §9 只读诊断:`NEO_SCOPE_OTHER`

`src/dll/c2/neo_js_host.zig` 的 `noteOtherScope` + `neo_vtable.zig` 的非 system 分支:

```zig
// neo_vtable.runBody
if (!isSystemScope(readU32(@intCast(scope), SCOPE_MASK_OFF))) {
    _ = @atomicRmw(u64, &stat_non_system_scope, .Add, 1, .monotonic);
    notifyOtherScope(scope);       // → neo_js_host.noteOtherScope(scope)
    return 0;
}

// neo_js_host.noteOtherScope
const fields = neo_vtable.scopeFields(scope) orelse return;   // 两个格子,不可读就整行不打
if (neo_vtable.isSystemScope(fields[0])) return;
emit("NEO_SCOPE_OTHER mask=0x{x:0>2} id={d}", .{ fields[0], fields[1] });
```

设计上的四条,每条都有一个理由:

1. **只读**:读 `+0x08`/`+0x10`,不写 scope、不调任何 body、不改 `[self]`。
2. **不可读就不打**:`scopeFields` 过 `plausible` + `isCommitted`(Windows 侧);读不到时一行都
   没有 —— 一行读错的数比没有更糟。
3. **判据只认 `mask`**:`+0x10` 对非 system 一族只是同一格的值(§8),所以「`id=` 就是国家 id」
   不在本行的判据里。
4. **与 `mask_odd` 并存**:`mask_odd`(=`nonSystemScopes()`)早在 stats 行里,它只给**计数**;
   新行给的是**逐次的 mask/id**。C2 的读法:先看 `dispatched` 增量(证明这一趟真的到了派发点),
   再看 `NEO_SCOPE_OTHER` 的行数(证明其中多少不是 system)。

围栏(Linux、零游戏):
`src/dll/c2/neo_js_host.zig` 的 `noteOtherScope logs mask+id for a non-system scope and is
silent otherwise`(造一个 mask=0x04 的 scope,断言 `NEO_SCOPE_OTHER mask=0x04 id=42`;system
scope 与不可读指针都不打)+ `src/dll/c2/neo_vtable.zig` 的 `runBody hands a non-system scope
to the scope diagnostic and skips the rest`(钉住 wiring:非 system 分支**真的**把它交出去,且
不计入 `matched`)。

**这一节不能说的。** 这条线只在 Windows 生产分支里接进 `neo_js_host`(`comptime is_windows`,
与 `notifyHost` 同一个理由:`c2_tests` 根不链 QuickJS);Linux 上被钉住的是「交出去」这一动作,
不是「那一行真的写进 `C:/temp/neo_js.log`」。后者只有 C2 能答。

---

## §10 这一节不能说的(总结)

1. **「能」是静态可达性。** §5 证明的是「国家 scope 会经过同一个派发函数」,不是「C2 那一趟
   真的每国一次」。次数、mask、id 三个读数都还没有。
2. **`+0x560`/`+0x56C` 没有实机读数。** 系统那半(`+0x590`/`+0x59C`)有(M4/§89.3),
   国家这半只有同形的静态链。
3. **`any_country` 那一半没读。** §3 的注册函数尾部还有一次 trigger 侧注册
   (`0x199E780` + 17 字节后缀串),本章没有逐条读完,因此「`any_country` 的 token/class_info」
   仍是 C 级未决。
4. **能量币 / 关系值 = unresolved**,理由与下一步见 §8。经济/外交在拿到它们以前**判 deferred**。

---

## §11 C2 实机读数(2026-11-08,一发,只读)

> 本节是**追加**:§1–§10 是离线静态侦察(§10 的第 1/2 条在那里是「还没有读数」)。这一发把
> §5 的可达性与 §6 的 mask 从静态预测变成实机读数。逐次读数与失败项在
> `evidence/logs/runtime_js_c2_country_scope_4_4_4.log`。

**装配。** 一次性探针 mod(`scripts/scratch/2026-11_country_scope/mod/neo_scope_probe/`)在
`on_monthly_pulse` 里跑一个**无类型** `event = { … }`,两组顺序固定:控制组
`random_system { every_system { neo_action = { } } }`,实验组
`every_country = { limit = { is_ai = no } neo_action = { } }`。DLL
`0e09ad40343dbbaba3d52484418e73110f0bad9c87744017e9ae043bd22f6278`,pid 22896,13 个月度脉冲。

**判词(3 次逐字相同,`C:/temp/neo_js.log`):**

```
NEO_SCOPE_OTHER mask=0x04 id=0 vtable_rva=0x24e9068 u08=0x00000004 u10=0x00000000 u18=0 u20=0 u28=0
```

**三格读数:**

| 项 | 值 | 把它放在哪一档 |
|---|---|---|
| `mask` | **`0x04`** | §6 静态写死的值与实机一致 ⇒ 国家 scope **A**(双侧证人) |
| 每国一次 | 13 个月 × 1 次 = 13 条 `NEO_C2_EXP_COUNTRY_ENTER`,前 3 次留下指纹,`SEEN=0`(总数落在 3..502) | §10-1「次数还没有」**已答**:每月 1 次 |
| `vtable_rva` | **`0x24e9068`** | 只等于「派发点对象首 qword」;同值在 `ceffect_vtable_map`(`slot0 0x395FF0`/`slot2 0x396460`)与 c1_validation §73.3 出现过 ⇒ **它是 CEffect 家族的对象,不是「CEventScope 已收口」** |
| `id` | **`0`** | 与「1 个人类国家、玩家 = 0」相符,但**无独立证人**;§8 的「`+0x10` 对非 system 只是同一格」不变 |

**控制组(同时证明仪器有效):** `NEO_JS_CALL` = **30,732**(13 × 2,364),`NEO_C2_CTRL_SCOPE_ENTER`
= 13,另一驱动 `PS_HIT` = 10,192;`game.log`/`error.log` 零 `Unexpected token`、零 `Script Error`。

**这一发不能说的(补充 §10,而不是推翻它):**

1. `id=0` 不是「已证实国家 id」—— 见上表。
2. `vtable_rva` 不是类身份 —— 见上表;AGENTS 段 3 的 `CEventScope` 未定状态**不变**。
3. 送达的是**迭代器**把这一轮交到我们 detour 的派发入口(`0x3B0F80` 里先于引擎自己的
   `call [child+0xa8]` 返回),不是「donor class 自己接受国家 scope」。
4. 一次战役、一份存档、13 个月、1 个人类国家;**没有**第二个非 AI 国家、没有多人。
5. **能量币 / 关系值仍 unresolved**(§8 的两条下一步不变)⇒ 经济/外交的**字段层** deferred,
   C2 只拿到「国家 scope 到 host + mask/id/vtable 三个指纹」这一层地基。

**收尾:** `taskkill /F /PID 22896` → `procs=0`,未 FreeLibrary;`dlc_load.json` 已恢复原有两项;
探针 mod 的官方半边与 `C:/temp/neo_mods/neo_scope_probe/` 均已删除。
