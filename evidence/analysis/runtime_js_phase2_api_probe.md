# Runtime JS Phase 2 — A1 静态侦察：`s.name` / `s.variable` / `s.setStarFlag` / `s.hasStarFlag`

**日期**:2026-11-07 **授权级别**:离线(只读本地 `stellaris.exe` 4.4.4 拷贝;不启动游戏、
不注入、不占用任何 shot 额度)。**计划**:`docs/superpowers/plans/2026-11-07-runtime-js-phase2.md`
Task A1。**二进制**:`/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe`,
sha256 `9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56`(46,253,688 B)。

本卷是**判据与读数**,不是实现说明。A2 只实现下表 `resolved` 的三项(含必做的
`s.neighbors`,`neighbors` 不走本 spike);`deferred` 的两项**不实现、不猜 body**。

## 1. 判决表

| api | class_info | create / body / vtable RVA | arg layout | 判决 | confidence | 证据 |
|---|---|---|---|---|---|---|
| `s.setStarFlag(name)` | `0x2610E80`(`set_star_flag`,effect db) | create `0x1895620`(new `0x298`);primary vtable `0x26049B0`;`+0x48` body `0x180F8E0` | 零化对象 + `[0]=vtable` + `[+0xC0]=u16 flag token id` + `[+0xE8]=0`;body 自己把 scope 经 `[vptr+0xE0]`(`0x180F8D0` → `0x397490`)解析成容器,再调官方写手 `0x1BCE180` | **resolved** | `pinned` | §2 |
| `s.hasStarFlag(name)` | `0x269F1D8`(`has_star_flag`,trigger db) | create `0x1B1FF60`(new `0x3F8`);vtable `0x268CF48`;求值槽 `+0x28` = `0x1A91A80`(共用基体);内层谓词 `+0x20` = `0x1AA5D10` | trigger 求值槽要 **`CEventScope` 上下文**(§77),host 只有 system scope;读的是同一份 flag 容器:`0x397490(scope)+0x5F8`,`+0x10` = u16 数组、`+0x1C` = 计数 | **resolved(只读容器)** | `static_inference` | §3 |
| `s.variable(name)` | `0x269E988`(`is_variable_set`)/ `0x269E968`(`check_variable`) | create `0x1B23050`(new `0x250`)/ `0x1B22EE0`(new `0x2D8`);vtable `0x2689128` / `0x2689038`;求值槽 `+0x28` = `0x1A91A80` / `0x348DB0` | 两个 trigger 求值槽都要 `CEventScope`;`is_variable_set` 只回 bool,没有「按名字取数值」的官方 read body | **deferred** | `unresolved` | §4 |
| `s.name` | — | — | 脚本可见路径是 `[This.GetName]`;`.rdata` 的 `"GetName"` 串(`0x251C8D8`)在 `.text` 里**零个** rip 相对引用(命令表按哈希注册),没有钉住任何 C++ getter/vtable 槽 | **deferred** | `unresolved` | §5 |

`confidence` 口径:`pinned` = 表里每一格都从字节读出来(create/vtable/body/字段偏移);
`static_inference` = 关键偏移由两条官方 body 互证,但没有一条「has flag」自己的 body 被
读到;`unresolved` = 没有可安全调用的官方路径。

## 2. `set_star_flag`:resolved

### 2.1 class_info → create → vtable(逐字节)

```
qword[0x2610E80] = 0x14034C090 (deleter)   0x141895620 (= rva 0x1895620, create)
0x1895626  mov ecx, 0x298 ; call 0x2185218            ; new(0x298)
0x1895643  call 0x2188170                            ; memset
0x189564B  call 0x1840700                            ; shared base ctor
0x1895650  lea rax,[rip+0xD6F359] ; mov [rbx],rax    ; -> 0x26049B0  primary vtable
0x189565A  lea rax,[rip+0xD5D4A7] ; mov [rbx+8],rax  ; -> 0x25F2B08  secondary vptr
```

`vtable 0x26049B0` 的槽位读数(`+0x48` 就是计划问的那一格):

```
slot[9]  +0x48 = 0x180F8E0   <-- body
slot[5]  +0x28 = 0x1B45B0    (trigger-family 的字符串初始化器;不是本 API 的 parse)
slot[16] +0x80 = 0x1B4550    (effect family 的共享谓词)
slot[20] +0xA0 = 0x3B1470
slot[28] +0xE0 = 0x180F8D0   <-- body 用它把 scope 解析成容器
```

### 2.2 `+0x48` body `0x180F8E0` 读什么

```
0180f8ef  cmp qword ptr [rcx + 0xE8], 0
0180f8fd  je  0x180f927                    ; 无字符串 => 直接取 token id
0180f927  movzx ebx, word ptr [rcx + 0xC0] ; flag token id (u16)
0180f92e  mov rax, [rdi]                    ; vtable
0180f937  call qword ptr [rax + 0xE0]       ; 0x180F8D0: rcx=rdx(scope); jmp 0x397490
0180f93d  mov r8, [rip + 0x1A5126C]         ; 一个全局对象
0180f94a  add r8, 0xC0
0180f959  movzx edx, bx                     ; flag id
0180f95f  call 0x1BCE180                    ; 官方 flag 写手
```

`0x180F8D0` 是 `mov rcx, rdx ; jmp 0x397490`;`0x397490` 以 scope 的 `+8`(mask)分派,
mask `0x80` 的分支是 `call 0x393970 ; add rax, 0x5f8 ; ret`(`0x39756e..0x397579`)。
即:**容器 = 系统对象 + `0x5F8`**,与 §3 的读路径同一格。

### 2.3 对象布局(可直接摆的最小形状)

`0x298` 字节全零 + `[0]=0x26049B0` + `[+0xC0]=u16 token id`。`+0xE8` 保持 0 是唯一要求:
非零会把 body 带进字符串解析路径(`0xA56800` + `+0xC8`/`+0xF8`),而那条路径需要
`std::string` 与 token 流。读到 `+0xC0`/`+0xE8`/`[0]` 之外**没有**字段访问。

实现落点:`src/dll/c2/neo_state.zig` 的 `STAR_FLAG_*` + `layoutStarFlag`、
`src/dll/c2/neo_vtable.zig` 的 `setStarFlag`/`setStarFlagId`。

### 2.4 flag 名的 token id 从哪来(边界,必须读)

`+0xC0` 是**名字在 token DB 里的 id**:getter `0x180F980` 用
`[db + idx*0x30 + 0x10]`(`idx < [rip+0x11F141A]` 的 bound)把 id 反查成名字,
那正是 §30.2 的 id→name 表。所以运行时 flag 名必须 mint 成 lexer 会用的同一个 id
(`0x1D13270`,`keyword_registry.mintToken`)。

**与约束 4 的关系**:§25.5 的 preflight 针对的是「把我们的 **keyword** 插进
`0x33746E8`/`0x32611C8`,从而接管一个官方 keyword」。flag 路径**没有任何 db 插入**;
token id 只当系统 flag 容器的不透明键。名字与官方 keyword 相同只会让这个 flag 共用
那个 token 的名字——和 lexer 自己的大小写折叠行为一致,不会写进任何 behaviour 表。
实现里仍做了三道 fail-closed:名字长度 ≤ 15(MSVC SSO,超长会被静默截断)、
先转小写、mint 返回 0/越界即拒写。**这条是本卷唯一需要评审确认的口径**(见 §6)。

## 3. `has_star_flag`:resolved(只读容器)

### 3.1 class_info → create → vtable

```
qword[0x269F1D8] = deleter 0x34C090, create 0x1B1FF60
0x1B1FF66  mov ecx, 0x3F8 ; call 0x2185218   ; new(0x3F8)
0x1B1FF8B  call 0x1AF63B0                     ; trigger base ctor
0x1B1FF90  lea rax,[rip+0xB6CFB1] ; mov [rbx],rax ; -> 0x268CF48
vtable 0x268CF48: slot[5] +0x28 = 0x1A91A80 (shared trigger eval base, §77)
                  slot[4] +0x20 = 0x1AA5D10 (inner predicate)
                  slot[16] +0x80 = 0x349230 (trigger predicate family, §75.1)
```

### 3.2 为什么求值槽不能直接调

`0x1A91A80` 的约定是 `(self, ctx, a3)`,第二实参是 `CEventScope`(§77:尾部
`jmp [self_vtable+0x20]`,第二实参 = `&ctx[0x278]`)。host 在 `neo_action` 的 Execute 里
只有 system **scope** 指针,没有 trigger 求值上下文;把 scope 当 ctx 传就是伪造 ABI。

### 3.3 采用的官方 read path:同一个 flag 容器

`has_star_flag` 的语义数据在系统 flag 容器里,而容器布局被两条官方 body 逐字节钉住:

* 加:`0x1BCE180`(`set_star_flag` body 调它)
  ```
  0x1BCE1A4  movsxd rax,[rcx+0x1C]     ; 计数
  0x1BCE1B5  mov    rax,[rbx+0x10]     ; u16 id 数组
  0x1BCE1C0  cmp    word ptr [rax], dx ; 命中比较
  0x1BCE1CB  add    rax, 2             ; 元素宽度
  ```
* 删:`0x1BCE270` 同一组 `[+0x1C]` / `[+0x10]` / `+2`(命中后压缩数组)。

所以 `hasStarFlag(id, name)` = `container = 0x393970(scope)+0x5F8` → 扫
`u16[container+0x10][0..dword[container+0x1C]]` 找 mint 出来的 token id。只读、不写、
不缓存。实现落点:`src/dll/shared/offsets.zig` 的 `graph.FLAG_*`、
`src/dll/c2/graph_probe.zig` 的 `hasFlagAt`/`systemHasFlag`。

**confidence 的诚实边界**:容器偏移来自加/删两条 body(互证),但**没有**读到
`has_star_flag` 自己的 body 去确认它也是逐项线性扫描;`0x1AA5D10` 走的是更复杂的
`0xA55DB0` 路径。因此标 `static_inference`,不标 `pinned`。若要升到 `pinned`,需要
一次实机读(或把 `0x1AA5D10` 的完整数据流读完),两者都不在本 Task 的离线预算内。

## 4. `s.variable`:deferred

候选两条,都止于 trigger 求值槽:

| keyword | class_info | create | new | vtable | 求值槽 `+0x28` |
|---|---|---|---|---|---|
| `is_variable_set`(token 18102) | `0x269E988` | `0x1B23050` | `0x250` | `0x2689128` | `0x1A91A80` |
| `check_variable`(token 18103) | `0x269E968` | `0x1B22EE0` | `0x2D8` | `0x2689038` | `0x348DB0` |

* `is_variable_set` 只回答 bool,不返回数值;它的求值槽仍是 §77 的共用基体,要
  `CEventScope`。
* `set_variable` 的写路径(C5-WRITE,`0xA56CC0` → `0x7EEBF0`)按 **std::string 名字**
  查容器,**没有**对应的「只读、不创建」getter 被钉住;`0xA56CC0` 在 miss 时会创建
  (`0x1C89D80` 失败后走 `0x3970F0`),拿它当读会**写状态**。
* 因此没有「按名字取数值」的官方 read path 可安全调用。**deferred**:
  `sdk/api.def` + TS + mock + host 都不出现 `s.variable`,等 Phase 3 的字段侦察。

## 5. `s.name`:deferred

* 脚本层的名字是 `[This.GetName]`(证据卷 §7.7 的 mod 回执就是它),但这是 Jomini
  命令表的命令,不是系统对象字段。
* `.rdata` 有 `"GetName"` 串:`0x251C8D8`(另一个 `0x2952B15` 在只读数据里)。
  `scripts/find_refs.py 0x251c8d8 0x2952b15` → **0 references**(两个都是)。
  即命令表按哈希/atom 注册,字符串本身没有 rip 相对引用,无法从它走到 C++ getter。
* 系统对象(`0x3939F0` 返回的表项)已钉住的字段只有 `+0x08`(id)、`+0x588`
  (边容器)、`+0x5F8`(flag 容器);名字字段不在其中。找名字需要系统对象的 ctor/序列化
  路径,属于 Phase 3 的「scope 字段侦察」。
* **deferred**;不实现、不猜 `[scope+0x??]`。

## 6. 给 A2 的做/不做清单

**做**:

| native(v1.1 加法) | 权限 | host 实现 |
|---|---|---|
| `__neo_system_neighbors(id) -> array<u32>` | `graph.read` | `graph_probe.systemNeighbors`(`+0x590/+0x59C`,`+8`=邻居 id;上限 64,截断记 `NEO_JS_NEIGHBORS_TRUNC`) |
| `__neo_system_set_flag(id, name)` | `flag.write` | `neo_vtable.setStarFlag`(官方 `+0x48` body,§2) |
| `__neo_system_has_flag(id, name) -> bool` | `flag.read` | `graph_probe.systemHasFlag`(只读容器,§3) |

**不做(deferred)**:`__neo_system_name`、`__neo_system_variable`。

**待评审确认的一条**:§2.4 的 token mint 口径——flag 名进 `0x1D13270` 但**不插 db**,
所以 §25.5 的 keyword preflight 不适用。若评审要求「任何名字进 `0x1D13270` 都先过
`c1_preflight.py`」,则 `setStarFlag`/`hasStarFlag` 也必须降级为 deferred(因为运行时
无法跑 Python preflight)。这是本 spike 唯一不能靠静态读数关掉的决策。

## 7. 复现

所有读数都来自本地 exe 拷贝;不启动游戏、不注入。维护中的工具就够读指令流:

```bash
# set_star_flag create(0x1895620)与 +0x48 body(0x180F8E0)
python3 scripts/disrva.py 0x1895620 --len=0x60
python3 scripts/disrva.py 0x180F8E0 --len=0xA0

# has_star_flag create / 求值槽
python3 scripts/disrva.py 0x1B1FF60 --len=0x50
python3 scripts/disrva.py 0x1A91A80 --len=0x40
python3 scripts/disrva.py 0x1AA5D10 --len=0x90

# is_variable_set / check_variable 的 create
python3 scripts/disrva.py 0x1B23050 --len=0x50
python3 scripts/disrva.py 0x1B22EE0 --len=0x60

# flag 容器:解析器分派与两条官方 body
python3 scripts/disrva.py 0x397490 --len=0xC0
python3 scripts/disrva.py 0x1BCE180 --len=0x90
python3 scripts/disrva.py 0x1BCE270 --len=0x60

# "GetName" 串没有直接引用(两个目标都是 0)
python3 scripts/find_refs.py 0x251c8d8 0x2952b15
```

`class_info` 的 qword(`qword[0x2610E80+8] = create` 等)是 PE 字节读取,`cap.py` 是
写死地址的演示脚本;本卷用仓库外的一次性探针(`/mnt/cache/tmp/opencode/`)读的,
**不进 git**。判据只依赖上面的 RVA 与 `scripts/disrva.py` 的指令读数。`scripts/`
本 Task 未改。
