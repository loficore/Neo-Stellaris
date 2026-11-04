# 4.4.4 graph runtime — evidence

> 本卷记录「图相关 keyword 的运行时写路径」的离线静态取证。所有地址都是
> **module-base-relative RVA**(image base `0x140000000`,ASLR on);exe 只读,不起进程、
> 不 patch、不联网、不用 IDA。执行体/值槽的锚点表在 `evidence/disasm/graph_keywords_4_4_4.c`
> (Task 1),本条写路径的复现探针是
> `scripts/scratch/2026-11_graph_runtime/add_remove_hyperlane_scan.py`(Task 2)。
> 函数边界取自 `.pdata`(RUNTIME_FUNCTION);解析器 `0x3939f0` 是叶子函数、**不在 `.pdata`**,
> 边界取其第一个 `ret`。

## §1 写路径 `add_hyperlane` / `remove_hyperlane`:id→系统对象解析器与边存储

判决:**`edge_store_write_named`** —— 解析器、容器、增(`0x8bbaa0`)/删(`0x8bbc20`)两例程
在 `add` 与 `remove` **两侧同形且逐条可证**;不是取并集,两侧读数逐项相等(见 §1.7)。

### §1.1 指令级调用图(基址来源写死,不靠位移猜)

两个 keyword 都是 effect vtable 的 `+0x48` 执行槽(Task 1 锚点表):
`add_hyperlane` 执行体 = `0x1874540..0x187481c`(`.pdata` 单块),`remove_hyperlane`
执行体 = `0x1874a00..0x1874cec`(`.pdata` 单块)。两者**逐条同构**,只有增/删例程分叉:

`add_hyperlane`(入参 `rcx=self`, `rdx=scope`):

```
0187455f  mov  rdi, rdx                     ; rdi = scope
01874562  mov  rsi, rcx                     ; rsi = self effect
01874565  add  rcx, 0xc0                    ; rcx = self+0xc0(param holder)
01874576  call 0x140356be0                  ; 参数求值: holder -> scope 结构(rax)
0187457b  mov  rcx, rax
0187457e  call 0x1403939f0                  ; <-- 解析器:scope/id -> 系统对象
01874583  mov  rbx, rax                     ; 系统对象 #1 进 rbx
...
018745d5  lea  rcx, [rsi + 0x260]           ; 第二个 param holder
018745e9  call 0x140356be0
018745f1  call 0x1403939f0                  ; <-- 解析器(同一函数)
018745f6  mov  rdi, rax                     ; 系统对象 #2 进 rdi
...
018746ee  movsxd rax, dword ptr [rbx + 0x59c]   ; 容器计数
01874701  mov  rax, qword ptr [rbx + 0x590]     ; 容器数据指针
01874708  add  rax, 8                         ; 指向**元素的 +8(id 字段)**
01874710  cmp  dword ptr [rax], edx             ; 去重: 元素 +8 == edx(= [rdi+8],另一系统 id)
01874717  add  rax, 0x20                        ; 元素步长 0x20
...
01874720  mov  rdx, rdi
01874723  mov  rcx, rbx
01874726  call 0x1408bbaa0                  ; <-- 加边(self -> other)
0187472b  mov  rdx, rbx
0187472e  mov  rcx, rdi
01874731  call 0x1408bbaa0                  ; <-- 加边(other -> self,无向边)
```

`remove_hyperlane` 同一骨架(`0x1874a3e`→`0x1874a43 mov rbx,rax`、`0x1874ab1`→`0x1874ab6
mov rdi,rax` 两次解析器;`0x1874bb1`/`0x1874bc4` 同一容器访存;查找循环 `0x1874bd0`/`0x1874bdb`),
尾部把命中 id 写进栈临时再调删除例程:

```
01874cbd  mov  dword ptr [rbp + 0x290], edx    ; 命中的 id(来自 [rdi+8])
01874cc3  lea  rdx, [rbp + 0x290]
01874cca  mov  rcx, rbx
01874ccd  call 0x1408bbc20                  ; <-- 删边(self, &id)
01874cd2  mov  eax, dword ptr [rbx + 8]
01874cd5  mov  dword ptr [rbp + 0x290], eax
01874cdb  lea  rdx, [rbp + 0x290]
01874ce2  mov  rcx, rdi
01874ce5  call 0x1408bbc20                  ; <-- 删边(other, &id 反向)
```

`0x356be0` 是参数求值器(把 `self+0xc0`/`self+0x260` 的 param holder + scope 变成一个
`{+8=type, +0x10=id}` 的 scope 视图),不是解析器;`0x23ad30` 是栈上 `0xC0` 临时的析构器,
与存储无关。**把「scope/id」变成系统对象指针的调用是 `0x3939f0`**。

### §1.2 解析器 `0x3939f0`(叶子函数,无 `.pdata`)

**全 24 条,一条不漏**(叶子函数,无 `.pdata`;边界 = 第一个 `ret`):

```
003939f0  cmp   qword ptr [rcx + 8], 0x80   ; scope 类型必须是 0x80(system)
003939f8  jne   0x140393a03
003939fa  mov   eax, dword ptr [rcx + 0x10]; <-- **id 的真正来源:scope + 0x10**
003939fd  mov   dword ptr [rsp + 8], eax     ; id 落到**栈局部** [rsp+8]
00393a01  jmp   0x140393a0b
00393a03  mov   dword ptr [rsp + 8], 0xffffffff  ; 非 system -> id = -1
00393a0b  mov   rax, qword ptr [rip + 0x2ecd186]  ; <-- 全局 0x3260b98(系统索引)
00393a12  lea   rcx, [rsp + 8]                ; rcx 指向那个**栈局部**,不是 scope
00393a17  test  rax, rax
00393a1a  je    0x140393a41
00393a1c  mov   edx, dword ptr [rcx]          ; 读的是 [rsp+8](局部),**不是 scope+0**
00393a1e  mov   ecx, edx
00393a20  and   ecx, 0xffffff
00393a26  cmp   ecx, dword ptr [rax + 0x20]   ; 边界 = [obj+0x20]
00393a29  jae   0x140393a41
00393a2b  mov   rax, qword ptr [rax + 0x18]   ; 表指针 = [obj+0x18]
00393a2f  add   rcx, rcx
00393a32  mov   rax, qword ptr [rax + rcx*8 + 8]  ; entry = [表 + idx*8 + 8]
00393a37  test  rax, rax                       ; entry 为空 -> 回退
00393a3a  je    0x140393a41
00393a3c  cmp   dword ptr [rax + 8], edx      ; entry+8 == id 才算命中
00393a3f  je    0x140393a48
00393a41  mov   rax, qword ptr [rip + 0x2ec9e38]  ; <-- 全局 0x325d880(回退对象)
00393a48  ret
```

- **id 的来源是 scope `+0x10`,不是 scope `+0`**:`0x3939fa mov eax,[rcx+0x10]` 取 id,
  `0x3939fd mov [rsp+8],eax` 把它存进栈局部,`0x393a12 lea rcx,[rsp+8]` 才让 `rcx` 指向那个
  局部;所以 `0x393a1c mov edx,[rcx]` 读的是**栈局部**,**scope `+0` 全程没有被读过**。
  (早先把 `0x393a1c` 的 `[rcx]` 读成 scope+0 是漏了 `0x3939fd`/`0x393a12` 两条指令的结果。)

- **返回的系统对象其 `+8` 就是系统 id** —— 这正是两个 keyword 里 `[rdi + 8]`(取另一系统 id)
  与 `[rbx + 8]`(取自身 id)被读的位置。
- **基址来源**:`add` 侧的容器基址 `rbx` 由 `0x1874583 mov rbx, rax` 装入,其**前一条**就是
  `0x187457e call 0x1403939f0`;`remove` 侧同理(`0x1874a43 mov rbx, rax` ← `0x1874a3e call 0x1403939f0`)。
  所以 `rbx`/`rdi` 的来源是**解析器返回值**,不是栈、不是全局(§87 口径:位移不能识别容器,
  必须钉基址来源)。
- **对简报 `[0x3260BB0]` 的更正**:解析器读的是全局 **`0x3260b98`** 那一格
  (`0x393a0b mov rax, qword ptr [rip + 0x2ecd186]`),把它当**指针**再解引用 `+0x18`/`+0x20`。
  `0x3260b98 + 0x18 == 0x3260bb0` 只是 `.data` 里的相邻,不是同一格;`[0x3260bb0]` 是另一个
  qword。两个地址都落在文件内**未初始化**的 `.data`(BSS),静态不可定值,故本卷只报**读点
  与其解引用偏移**,不替它想象对象。
- 回退对象 `0x325d880` 在 `0x9e65e6` 的同一族调用方里被读到(旁证同族形态,见 §1.6)。

### §1.3 边存储 = 系统对象 + 0x588(自定义 vector)

`add` 侧把容器基址交给通用 push_back:

```
008bbb53  lea  rcx, [rdi + 0x588]      ; 容器基址 = self 系统对象 + 0x588
008bbb5a  lea  r8,  [rsp + 0x30]       ; &新元素(栈上装好)
008bbb5f  mov  edx, dword ptr [rcx + 0x14]  ; index = 当前计数
008bbb62  call 0x1408cf8d0             ; 通用 push_back
```

布局(容器基址=系统对象 `+0x588`):

| 字段 | 偏移(相对系统对象) | 指令原文 |
|---|---|---|
| 容器 vtable | `+0x588`(容器基址 +0) | `0x8cf9b1 mov rax,[r14]` + `0x8cf9b7 call [rax+0x18]`(调容器 vtable 的 +0x18 槽);容器基址来自 `0x8bbb53 lea rcx,[rdi+0x588]` |
| 数据指针 | `+0x590` | `0x1874701 mov rax,[rbx+0x590]`;`0x8cf9e0 add rcx,[r14+8]`(容器基址 +8) |
| 容量 | `+0x598` | `0x8cf8ef mov ecx,[rcx+0x10]`(容器基址+0x10) |
| 计数(dword) | `+0x59c` | `0x18746ee movsxd rax,[rbx+0x59c]`;`0x8cf8e8 movsxd rax,[rcx+0x14]` |

元素步长 **0x20**:插入侧 `0x8cf93e shl rdi, 5`(= 32),删除侧 `0x8bbc5d add rax, 0x20`。
元素布局(两处独立写入互证):`+0x00` vtable `0x24b5480`(`.rdata`),`+0x08` id(dword),
`+0x10` 距离(qword),`+0x18` 标志(byte)。边是**无向**的 —— `add` 在 `0x1874720..0x1874731`
连调两次 `0x8bbaa0`(self→other、other→self),`remove` 亦然。

### §1.4 增例程 `0x8bbaa0(rcx=self系统, rdx=另一系统)`

`.pdata` 单块 `0x8bbaa0..0x8bbbab`。要点:

- 距离 = 两个「**子对象**」的 `+8`/`+0x10` 之差的平方和再整数开方(`0x8bbaa0..0x8bbb2e`),写进元素
  `+0x10`。**这两个子对象不是系统对象本身**:`0x8bbab5 lea rcx,[rdx+0x28]` /
  `0x8bbac2 lea rcx,[rdi+0x28]` 分别取两个系统对象的 `+0x28` 成员,`0x8bbab9 mov rax,[rcx]` /
  `0x8bbac6 mov r8,[rcx]` 读该成员的 vtable,`0x8bbabc call [rax+8]` / `0x8bbac9 call [r8+8]`
  **调用该 vtable 的 `+8` 槽**;两次调用各返回一个**子对象**(`0x8bbabf mov rbx,rax` = 另一系统的,
  `rax` = self 的)。差值在 `0x8bbacd..0x8bbad9` 取自这两个**返回的子对象**:
  `[rbx+0x10]-[rax+0x10]`、`[rbx+8]-[rax+8]`。
  (系统对象自己的 `+8` 是**系统 id**(§1.2),不是坐标 —— 与本条并列会自相矛盾。)
- `0x8bbb31 mov eax,[rsi+8]`(另一系统 id)写进 `[rsp+0x38]`(元素 `+8`);
  `0x8bbb42 lea rcx,[rip+0x1bf9937]` → 元素 vtable `0x24b5480` 写进 `[rsp+0x30]`。
- `0x8bbb4e cmp eax, dword ptr [rdi+8]` —— **自环跳过**:另一系统 id == self id 时直接跳插入。
- 插入:`0x8bbb53 lea rcx,[rdi+0x588]` + `0x8bbb5f mov edx,[rcx+0x14]` + `0x8bbb62 call 0x1408cf8d0`。
- 写副作用:`0x8bbb73 or byte ptr [rdi+0x137d],al`;`0x8bbb85 or dword ptr [rip+0x20b10dc],1`
  → 广义**脏/世代位掩码全局 `0x296cc68`**(**不是边专属**,见下面的 §1.4.1);
  `0x8bbb94 mov qword ptr [rdi+0x5a0], rax`(缓存句柄)。

#### §1.4.1 `0x296cc68` 是广义脏/世代位掩码,不是边专属标志、也不是 BSS

`find_refs.py 0x296cc68`(`scripts/find_refs.py`,离线、完整)实读 **24 个交叉引用**,
横跨多个子系统:

- 17 个 `or dword ptr [rip+…], 1`(置位):`0x8bbb85`(本卷增例程)、`0x8bbd65`(本卷删例程)、
  `0x8bbbf6`、`0x8bbe45`、`0x8d52fd`、`0x8d5364`、`0x8d5542`、`0x8d55aa`、`0x259d7d`、`0x259e55`、
  `0x25cdaf`、`0x9e67c0`、`0x9e6825`、`0xa95441`、`0xa954a9`、`0xa958c5`、`0xa9592c`。
- 4 个 `mov dword ptr [rip+…], 2`:`0x24dbad`、`0x8d566a`、`0x952eda`、`0x9e81e6`;
  1 个 `mov dword ptr [rip+…], edi`(`0x250dd0`,写变量值)。
- 只有 **2 个读点**:`0x2ae950`(`mov eax,[rip+…]` → `and eax,edx; cmp eax,edx; sete al`,
  **按位测掩码**)与 `0x952e54`(`mov eax,[rip+…]` → `shr ecx,1; test cl,1` + `test al,1`,
  **测位**)。没有任何以该字为**内存操作数**的 `cmp`/`test` 站点。

⇒ 它是**被置位、被按位测试的脏/世代位掩码字**,横跨多个子系统,不是「边集合专有的脏标志」。
本卷只能说「边增/删**也**写这一位」(`0x8bbb85` / `0x8bbd65`),不能说它只属于边集合。

**它也不是 BSS**:`0x296cc68` 落在 `.data` 且**有文件初值** —— 文件字节 `01 00 00 00`
(dword = 1)。对照:解析器读的两个全局 `0x3260b98` / `0x325d880` 在文件里**没有字节**
(BSS/未初始化),所以静态不可定值(§1.2)。

### §1.5 删例程 `0x8bbc20(rcx=self系统, rdx=&id)`

`.pdata` 被 MSVC 拆成 **7 个连续 RUNTIME_FUNCTION 块** `0x8bbc20..0x8bbc75..0x8bbcb4..
0x8bbccc..0x8bbd11..0x8bbd23..0x8bbd2d..0x8bbd8a`(逻辑范围
`0x8bbc20..0x8bbd8a`;**只看首块会得到错误的 end**,这是必须按链走 `.pdata` 的理由):

```
008bbc29  movsxd rax, dword ptr [rcx + 0x59c]  ; 计数
008bbc3f  mov    r11, qword ptr [rcx + 0x590]  ; 数据
008bbc4c  mov    rax, r11                     ; 扫描游标 = 数据基址
008bbc51  cmp    dword ptr [rax + 8], r10d     ; 逐元素比 id(元素 +8)
008bbc5d  add    rax, 0x20                     ; 步长 0x20
008bbc71  shl    r9, 5                         ; r9 = (计数-1)*0x20 = 末元素偏移
008bbc86  mov    eax, dword ptr [r9 + r11 - 0x18]  ; 末元素 id
008bbc8f  mov    dword ptr [rcx + r11 + 8], eax    ; -> 命中槽 +8
008bbc94  mov    rax, qword ptr [r9 + r11 - 0x10]  ; 末元素 +0x10
008bbc99  mov    qword ptr [rcx + r11 + 0x10], rax ; -> 命中槽 +0x10
008bbc9e  movzx  eax, byte ptr [r9 + r11 - 8]      ; 末元素 +0x18
008bbca4  mov    byte ptr [rcx + r11 + 0x18], al    ; -> 命中槽 +0x18
008bbcf7  call   qword ptr [r8]                ; 虚析构**末元素**(r8 = 它的 vtable)
008bbd1d  mov    dword ptr [rdi + 0x59c], eax  ; 计数 -1
008bbd65  or     dword ptr [rip + 0x20b0efc], 1 ; 删侧也置同一脏位 -> 0x296cc68
```

**顺序是「先搬运、后析构」**:末元素 → 命中槽的字段拷贝在 `0x8bbc86..0x8bbca4`,
**早于**虚析构 `0x8bbcf7 call qword ptr [r8]`。被析构的是**末元素**而不是命中槽里那个:
析构循环的 `ebp = 计数-1`(`0x8bbcb9`)、`rsi = (计数-1)*0x20`(`0x8bbcd1`/`0x8bbcd4`)、
`r14 = 计数-(计数-1) = 1`(`0x8bbcd8`)⇒ 循环只跑一遍,析构的正是刚被搬走内容的那个末元素
(`0x8bbcf3 mov r8,[rsi+rax]` 取它的 vtable)。计数 -1 在 `0x8bbd1d`。这是标准 swap-remove。

删侧同样置脏位:`0x8bbd65 or dword ptr [rip+0x20b0efc],1` → 与增侧 `0x8bbb85` **同一全局
`0x296cc68`**(两侧 rip 目标由字节解出,见 §1.9)。**没有第二条存储路径**:`add` 与 `remove`
读写的是同一组 `+0x588/+0x590/+0x59c`。

### §1.6 同族旁证(同类形态,非矛盾)

`0x8bbaa0` 的另 2 个直接调用者与 `0x8bbc20` 的另 2 个直接调用者,与两个 keyword 共享同一
套状态:

- `0x9d7cce`/`0x9d7cd9`:连调 `0x8bbaa0` 两次(与 `add_hyperlane` 同形)。
- `0x8bbe16 call 0x1408bbc20` 后接 `0x8bbe3b mov byte ptr [rdi+0x137d],0`、
  `0x8bbe45 or dword ptr [rip+0x20b0e1c],1`(→`0x296cc68`)、`0x8bbe56 mov [rdi+0x5a0],rax`
  —— 与 `0x8bbaa0` 的副作用完全一致。
- `0x9e65e6 call 0x1408bbc20` 所在函数同时读 `0x9e660e lea r12,[rip+0x1acee6b]`(→元素 vtable
  `0x24b5480`)、`0x9e6615 mov r10,[rip+0x287a57c]`(→`0x3260b98`)、
  `0x9e661c mov rdx,[rip+0x287725d]`(→回退 `0x325d880`)—— **解析器的三样东西在族外调用方里
  同现**,独立佐证 §1.2/§1.3。
- `0x8d5290` 走的也是 `+0x588` 这套容器(`0x8d52cd lea rcx,[rsi+0x588]`),并且自己内联了
  解析器的查表(`0x8d5294 mov rax,[rdx+0x18]`、`0x8d52a2 cmp dword ptr [rdx+8],r8d`)。

这些是**同形旁证**,不是「别的容器」;判定依据仍是基址来源(`rdi`/`rsi` = 系统对象),
不是位移。

### §1.7 add 与 remove 不分叉(不取并集)

逐项对齐两侧读数:

| 结论 | `add_hyperlane` | `remove_hyperlane` | 同否 |
|---|---|---|---|
| 解析器调用 | `0x187457e` / `0x18745f1` `call 0x3939f0` | `0x1874a3e` / `0x1874ab1` `call 0x3939f0` | ✓ |
| 解析器返回入寄存器 | `0x1874583 mov rbx,rax` / `0x18745f6 mov rdi,rax` | `0x1874a43 mov rbx,rax` / `0x1874ab6 mov rdi,rax` | ✓ |
| 容器计数 | `0x18746ee [rbx+0x59c]` | `0x1874bb1 [rbx+0x59c]` | ✓ |
| 容器数据 | `0x1874701 [rbx+0x590]` | `0x1874bc4 [rbx+0x590]` | ✓ |
| 写例程 | `0x8bbaa0`(×2) | `0x8bbc20`(×2) | 增/删分叉,**容器同** |

两侧只在增/删例程处不同(本该如此),解析器、容器所有者、三个偏移两侧逐条相等 ⇒ 写路径
只有一条,**没有取并集**。

### §1.8 同 disp 排除(§87 口径)

位移本身在库内遍地都是:`.text` 里 `disp32 == 0x588` 431 处、`0x590` 962 处、`0x59c` 430 处
(`add_remove_hyperlane_scan.py` 的 `[6]` 实测)。排除靠**基址来源**,不靠位移:

- `0x34c9c3 call 0x218525c`(分配器)所在的那段 push_back 形态,元素 **0x48** 字节:
  `mov eax,0x48`@`0x34c9ab`,地址计算 `lea rdi,[rbx+rbx*8]`@`0x34c9c8`、
  `lea rbx,[rax+rdi*8]`@`0x34c9d2`(0x48 = (1+8)*8 的形态)。
- `0x34cb33 call 0x218525c` 所在的那段,元素 **0x38** 字节:`imul rdi,rbx,0x38`@`0x34cb38`
  (随后 `lea rbx,[rdi+rax]`@`0x34cb42`)。步长不等 ⇒ 排除。
- `0x53163f movaps xmmword ptr [rsp+0x590],xmm6`(rsp 基址,栈保存帧)与
  `0x54d54d lea r11,[rsp+0x590]`(rsp 基址,栈展开)不是容器。基址是 rsp ⇒ 排除。
- `0x8bbaa0`/`0x8bbc20` 里的 `+0x590`/`+0x59c` 基址是 `rdi`/`rcx`,来源 = 入参(系统对象);
  两个 keyword 里的基址 `rbx` 来源 = 解析器返回值。**两条链的基址来源都钉在「系统对象」上**,
  与上面两组排除项不同源。

### §1.9 复现(真实读数)

探针 `add_remove_hyperlane_scan.py` 从字节里重读 **92 个站点 + 9 个同位移排除站点**,与计划期
逐字比对;并把**三个 rip 目标**(元素 vtable `0x8bbb42`、两侧脏位全局 `0x8bbb85` / `0x8bbd65`)
与**两个解析器全局的文件字节**从字节里解出后再比对(解析器 `0x3939f0` 全 24 条也在站点表内,
含 `0x3939fd`/`0x393a01`/`0x393a12`/`0x393a37`/`0x393a3a`);任一不等即不落判决字段并退出 1。
干净 shell 实跑(EXIT=0,`[check] 全部读数与计划期一致`;关键行如下):

```
[4] 系统索引全局 = 0x3260b98(期望 0x3260b98)  OK
    0x3260b98 系统索引全局 文件字节:空(.data,BSS/未初始化)  OK
    0x325d880 失败回退对象 文件字节:空(.data,BSS/未初始化)  OK
[5] 0x8bbb42 lea rcx, [rip + 0x1bf9937] -> 0x24b5480(期望 0x24b5480)  OK
    0x8bbb85 or dword ptr [rip + 0x20b10dc], 1 -> 0x296cc68(期望 0x296cc68)  OK
    0x8bbd65 or dword ptr [rip + 0x20b0efc], 1 -> 0x296cc68(期望 0x296cc68)  OK
    文件字节 01000000(.data)=> file-init dword = 1(**不是 BSS**)  OK

resolver_rva        = 0x3939f0
edge_owner          = system_object(解析器返回) + 0x588
neighbor_vector_off = 0x590(容器基址 0x588)
neighbor_count_off  = 0x59c
insert_fn           = 0x8bbaa0(通用 push_back 0x8cf8d0)
remove_fn           = 0x8bbc20
```

六个字段与简报接口 {`resolver_rva, edge_owner, neighbor_vector_off, neighbor_count_off,
insert_fn, remove_fn`} 一一对应。

### §1.10 与 `runtime_444_c1_validation.md` §88 的边界(同位移、不同对象,互不证伪)

`runtime_444_c1_validation.md` §88 问的是「C5 的运行时图版本/变更信号」,扫的是**经全局
`0x3260bb0` 到达的那个对象**,在其 `disp ∈ [0x580,0x5c0)` 里找「变更时写」+「读侧比较」,
结论:`+0x590` = **id 向量 begin**、`+0x59c` = **裸计数(取模除数)**,判决 `no_version_signal`。
本卷 §1 说的是**解析器 `0x3939f0` 返回的系统对象**自己带的那个 vector(`+0x588` 容器、`+0x590`
数据、`+0x59c` 计数)。两者**同位移、不同对象**,不互相证伪 —— 记录边界如下:

- **owner 不同**:§88 经全局 **`0x3260bb0`**;本卷经解析器的全局 **`0x3260b98`**(两者是
  `.data` 里相邻但不是同一格,见 §1.2 对简报 `[0x3260bb0]` 的更正)。
- **同一位移上元素不同**:§88 的 `+0x590` 是 **stride-4 的 id 向量**
  (`0x9d1184 mov rax,[r13+0x590]` + `0x9d118b mov ebx,[rax+rcx*4]` 两条读数不变;除数是
  `0x9d117b idiv dword ptr [rbp + 0x59c]` —— **[更正 2026-11-03]** 早先这里写成 `0x9d117a idiv
  dword ptr [r13+0x59c]`,**站点地址与基址寄存器两个字节都抄错了**,「取模除数是 `+0x59c` 的计数」
  这个结论不变);本卷 §1 的 `+0x590` 是 **stride-0x20 的边元素数组**(`0x8cf93e shl rdi,5`、
  `0x8bbc5d add rax,0x20`)。步长不同 ⇒ 不是同一个 vector。
- **本卷的脏位 `0x296cc68` 不在 §88 的口径内**:§88 扫的是**那个对象 `+0x580..+0x5c0` 里的
  内存站点**,而 `0x296cc68` 是一个**全局字**,不是该窗口内的偏移 ⇒ 即使 §88 的判决成立,
  本卷的写点也不构成反例;反过来说,§88 的 stride-4 读数也不否定本卷的 stride-0x20 容器。
  这正是 §88「**欠账①**」所指的那一类:容器的**变更方**拿到的不是它扫描的读侧集合里的站点。
  (旁证:`0x952e54` 既读 `0x296cc68` 的位,又 `0x952e6b mov rdx,[rip->0x3260bb0]` +
  `0x952e72 add rdx,0x588` 触及 §88 对象的容器 —— 变更侧与脏位确实相邻,但都不是 §88 窗口内的
  偏移站点。§88 的 `no_version_signal` 只覆盖它自己的窗口。)

⇒ 读本卷不要顺手把 §88 当被证伪,读 §88 也不要把本卷的 `+0x588/+0x590/+0x59c` 套上去。

### §1.11 勘误(2026-11-03,Task 6):表项记录步长是 **16 B**,不是 8 B

§1.2 的指令清单**已经逐字列出** `0x393a2f add rcx, rcx`(槽号在寻址前被**翻倍**)—— **[更正 2026-11-03]**
早先这里写「§1.2 那句注释漏抄了 `add rcx,rcx`」,不成立:清单里那行一直都在。真正记错的只是**紧邻下一行
的**行内注释** `; entry = [表 + idx*8 + 8]` —— 它按 8 B 步长记账,与上面那条翻倍矛盾。**指令抄对了,
是注释把步长记错**;结论(表项记录 = 16 B)不变。原文照抄如下(基址 `0x140000000`):

```
00393a20  and   ecx, 0xffffff
00393a26  cmp   ecx, dword ptr [rax + 0x20]
00393a29  jae   0x140393a41
00393a2b  mov   rax, qword ptr [rax + 0x18]
00393a2f  add   rcx, rcx                  ; rcx = 2 * slot  <-- 就是这一步
00393a32  mov   rax, qword ptr [rax + rcx*8 + 8]
```

`rcx` 在 `0x393a20` 时是 `id & 0xFFFFFF`(= 槽号),到 `0x393a2f` 被 `add rcx,rcx` 翻倍,
于是 `0x393a32` 的 `[rax + rcx*8 + 8]` 实际是 **`[表 + slot*16 + 8]`**。

- **表项记录 = 16 B**;记录的 `+0` 不是指针,**系统对象指针在记录 `+8`**。
- 两句站点:`0x393a2f add rcx,rcx`(步长翻倍)+ `0x393a32 mov rax,[rax+rcx*8+8]`(取值);
  基址来源仍是 `0x393a2b mov rax,[rax+0x18]`(即 `[系统索引对象+0x18]`)。
- 按 8 字节步长读 `[表 + slot*8 + 8]` 会落在**记录头**或**前一条记录**上,**静默读错对象**,
  不报错 —— 这类错误只能靠上面那条 `add rcx,rcx` 预先排除。

**影响面(仅此,不牵动别处)**:

1. **§1.2 其余结论不变**:`id` 来自 scope `+0x10`(非 `+0`)、边界 `[对象+0x20]`、
   表指针 `[对象+0x18]`、命中条件 `entry+8 == id`、回退对象 `0x325d880` —— 全部照旧。
   本节只是把 §1.2 里那一行**寻址注释**补成完整的三条指令。
2. **§1.3 的字段表不受影响**:那是**系统对象 `+0x588` 的边容器**(数据 `+0x590`、容量 `+0x598`、
   计数 `+0x59c`、步长 `0x20`),与系统索引对象的**表项步长**是两回事,互不涉及。
3. **Task 6 的读图器**(`src/dll/c2/galaxy_graph.zig`)按本条实现:两次查表
   (`readGraph` 枚举槽、`resolves` 核对邻居)都用 `表 + slot*16 + 8`;常量
   `offsets.graph.TABLE_RECORD_SIZE = 16` 与 `TABLE_SLOT_PTR_OFF = 8` 指本条。

## §2 读路径(trigger 侧):`has_hyperlane_to` / `closest_system` / `num_neighbor_systems`

判决:**`edge_store_read_confirmed`** —— 三条**互相独立**的 trigger 侧读路径都落到 §1 的同一组
`{neighbor_vector_off = 0x590, neighbor_count_off = 0x59c}`、同一 **stride 0x20**、同一「元素 `+8` = 系统 id」,
而且三条路径的**基址来源**都能追回 §1 的解析器(`0x3939f0` 的全局表 `0x3260b98` + 回退 `0x325d880`)解出
或 §1 写路径灌进容器的那批系统对象。读路径**不是**经通用解释器 `0x348db0` 走的(负对照见 §2.1.3)——
所以简报 Step-3 里「读侧找到了、但只能经通用解释器」那一档、以及「两侧不一致」那一档,本卷都不采用,
采用上面这一句。

> 本节复现探针 = `scripts/scratch/2026-11_graph_runtime/hyperlane_read_scan.py`(Task 3);真实读数见 §2.6。
> 地址仍是 module-base-relative RVA;函数边界取自 `.pdata`(按 RUNTIME_FUNCTION 链走,不是只看首块)。

### §2.1 简报 Step-1 前提的否证:`+0x78` 存的是比较运算符 id,不是 opcode

简报 Step-1 的推理是「对象 `+0x78` 存着一个 token/opcode(`num_neighbor_systems` 实测存的是 `0x165`),⇒ 读路径
必须按 **opcode 分派**」。**读数(`0x165` 是存进去的那个值)对、推断错**:

1. **`+0x78` 在一个比较体里被当作「比较运算符 id」派发**。共享比较体 `0x1a92090`(vtable `0x269a348` 的
   `+0x18` 槽;`.rdata`(`0x2392000`,size `0x5c1800`)里**恰好 122 个不同的 vtable** 的 `+0x18` 槽指向
   它 —— **[更正 2026-11-03]** 早先这里写「20+ 个 trigger vtable」,是按印象估的;按 8 字节对齐逐个
   数 `.rdata` 里等于 `ImageBase + 0x1a92090` 的 qword,得 **122 处、122 个不同地址**(首处
   `0x266c028` = vtable 基址 `0x266c010` + `0x18`),「很多 trigger 共享它」这个结论不变)是:

   ```
   01a920b1  call   qword ptr [rax + 0xf0]   ; 先取「邻居收集」的结果(见 §2.4)
   01a920d3  mov    ecx, dword ptr [rbx + 0x78]  ; <-- 把 +0x78 当**比较运算符 id** 读出来
   01a920d6  cmp    ecx, 0x3cb
   01a920e0  sub    ecx, 1
   01a920e5  sub    ecx, 0x1d2
   01a92100  setl   al     01a92118  setg   al    01a92130  sete   al
   01a92148  setge  al     01a9216d  setne  al    01a92185  setle  al
   01a92193  xor    al, al                              ; 集合外的 id -> false
   ```

   可达的 id 集合 = `{1(=), 0x1d3(>), 0x1d4(<), 0x3cb(>=), 0x3cc(<=), 0x427(!=)}`;**`0x165` 不在集合内**
   ⇒ 默认落到 `0x1a92193 xor al,al`(false)。六个分支全是 `cmp [邻居结果], [本对象结果]` + `setcc`,
   这是**比较运算符**的派发,不是「按图 opcode 找 handler」。

2. **`0x165` 是这一族工厂写进 `+0x78` 的「默认存储值」,不是 `has_hyperlane_to` 专属、更不是 opcode**。
   两个写入点:
   - `0x1b2a53b mov dword ptr [rbx + 0x78], 0x165` —— `has_hyperlane_to` 工厂 `0x1b2a510` 内联写,紧接着
     `0x1b2a54f lea rax,[rip+0xb75892]` 换 vtable → `0x269fde8`;
   - `0x187b9f7 mov dword ptr [rdi + 0x78], 0x165` —— 共享基类构造器 `0x187b9e0` 写;它由
     `num_neighbor_systems` 工厂 `0x1b33930` 在 `0x1b33964 call 0x14187b9e0` 调用(该工厂**自己不直接写** `+0x78`)。

   ⇒ 简报「`num_neighbor_systems` 实测 `0x165`」这个**读数**是对的;把它当 opcode 才是错的(否则就会去
   解释器里找「`0x165` 分支」,而那里根本没有)。并且 `0x165` 也**不是** `0x1a92090` 认得的运算符 id:
   它落在上面第 1 条那个六元集合**之外**,所以存着 `0x165` 的这一族对象走到该比较体时,比较恒落到
   `0x1a92193 xor al,al`(false)。**派发键始终是 vtable 槽,不是 `0x165`。**

3. **派发仍按 vtable 槽,不是按 opcode**(负对照,探针 `[2b]` 由字节数出):
   - 通用解释器 `0x348db0..0x349212`(275 条指令)里:`dword 0x165` **0 处**;含
     `+0x588/+0x590/+0x59c/+0x78` 位移的访存 **0 条**;却有 **5 条**间接 `call [reg+..]`
     (`0x348f33 [rax+8]`、`0x348ffe [rax+0x28]`、`0x349062 [rax]`、`0x349072 [rax+0x30]`、`0x34907d [rax+8]`)
     —— 它自己就是按 **vtable 槽**派发的,这正是否证「按 `0x165` opcode 分派」的反证。
   - `has_hyperlane_to` 的 `+0x20` 比较槽 `0x1afde20..0x1afe4f2`(280 条指令):邻居容器访存 0 条、
     间接 call/jmp 0 条。
   - `closest_system` 的 `+0x28 = 0x348db0`(裸 thunk 目标)与 `has_hyperlane_to` 的 `+0x28 = 0x1a91a80`
     都只是**通用解释器/共享基体**这一档;类特定读体在各自的 **`+0x18`**(或 `num_neighbor_systems` 的 `+0xf0`)。
     `0x1a91a80` 的尾巴 `0x1a91ac0 jmp qword ptr [rax + 0x20]` 也是 vtable 槽派发。

**结论**:Step-1 前提被证伪;读路径要在**类特定 vtable 槽**里找,而不是在 `0x348db0` 里找 `0x165` 分支。

### §2.2 读路径 A:`has_hyperlane_to` vtable `0x269fde8` 的 `+0x18 = 0x1afe500`

vtable dump(探针 `[1b]`):`0x269fde8`:`+0x18=0x1afe500`(`+0x20=0x1afde20` 比较、`+0x28=0x1a91a80`
共享基体、`+0x80=0x349230` 共享比较体)。

`0x1afe500..0x1afe74b`(`.pdata` 单块)**内联了 §1 的解析器**,再把解出的系统对象交给核心读体:

| 站点 | 指令 | 作用 |
|---|---|---|
| `0x1afe5d0` | `mov rdx, qword ptr [rip + 0x17625c1]` | → 全局 **`0x3260b98`**(§1 系统索引) |
| `0x1afe5ef` | `cmp eax, dword ptr [rdx + 0x20]` | 边界 = `[global+0x20]` |
| `0x1afe5f6` | `mov rax, qword ptr [rdx + 0x18]` | 表 = `[global+0x18]` |
| `0x1afe607` | `cmp dword ptr [rdx + 8], r8d` | entry `+8` == id |
| `0x1afe60d` | `mov rdx, qword ptr [rip + 0x175f26c]` | → 回退对象 **`0x325d880`** |
| `0x1afe5fd` | `mov rdx, qword ptr [rax + rcx*8 + 8]` | 命中分支:解出的**系统对象** → rdx |
| `0x1afe621` | `call 0x140a6aa10` | 核心读体 |

核心读体 `0xa6aa10..0xa6ada7`(**这就是读 §1 容器的地方**):

| 站点 | 指令 | 作用 |
|---|---|---|
| `0xa6aa3a` | `mov rdi, rdx` | **基址来源**:rdi = 第二实参 = `0x1afe621` 传进来的、解析器解出的系统对象 |
| `0xa6aae3` | `mov rdx, qword ptr [rdi + 0x590]` | **数据指针 = `+0x590`** |
| `0xa6aaea` | `movsxd r9, dword ptr [rdi + 0x59c]` | **计数 = `+0x59c`** |
| `0xa6aaff` | `shl r9, 5` | 计数 × **0x20** = stride |
| `0xa6ab16` | `mov r8d, dword ptr [rdx + 8]` | 元素 `+8` = **邻居系统 id** |
| `0xa6ab2a` | `mov rax, qword ptr [r11 + 0x18]` | 用**同一个** §1 解析器条目核对 |
| `0xa6ab3b` | `cmp dword ptr [rax + 8], r8d` | entry `+8` == 邻居 id |
| `0xa6ab50` | `add rdx, 0x20` | 按 **0x20** 步进 |

⇒ owner = §1 系统对象(解析器返回值);offsets `+0x590`/`+0x59c`;stride 0x20;元素 `+8` = id。与 §1 逐项相等。

### §2.3 读路径 B:`closest_system` vtable `0x267faa0` 的 `+0x18 = 0x1ae3700`

> 溯源(**2026-11-03** 补记,不改读数):`closest_system` → class_info `0x269e428` → factory
> `0x1b276f0` → vtable `0x267faa0`。两条独立索引:`evidence/xrefs/class_info_census_4_4_4.tsv:1301`
> (`0x269e428  0x34c090  0x1b276f0  False … 0x267faa0 0x24c7f80`,census 直接给出 vtable)与
> `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv:1108`(`closest_system`,token 10288,
> array `0x23af628`,db `0x32611c8`,class_info `0x269e428`)。本节后面用到的 vtable `0x267faa0`
> 由此独立复核。

`0x1ae3700..0x1ae3928` 同样内联 §1 解析器(`0x1ae372e`→`0x3260b98`、`0x1ae3746 cmp [rdx+0x20]`、
`0x1ae3750 mov rax,[rdx+0x18]`、`0x1ae375e cmp [rdi+8],r8d`、回退 `0x1ae3764`→`0x325d880`),
然后把系统对象交给「按 hyperlane 步数搜索」的两条骨架:

```
01ae383b  mov  rcx, rdi        ; <-- rcx = §1 解析器解出的系统对象
01ae384c  call 0x1408c24d0
01ae3853  call 0x1408c25f0
008c24e0  mov  rdi, rcx        ; 基址来源 = 入参 = 系统对象
008c2520  mov  rdx, rdi
008c2545  call 0x1408cbb30     ; BFS
```

BFS `0x8cbb30..0x8cc5a9`:

- frontier 是**栈上结构**(不是全局):`0x8cbbf8 lea r15,[rsp+0x20]` → `0x8cbbfd mov [rbp+8],r15` →
  `0x8cbd75 mov r15,[rbp+8]`(复用)。三元组 **stride 0x18**:`0x8cbc93 mov [r15 + rbx*8], rdx`
  (`rbx = 3*idx`,`idx` = 系统 id 的低 16 位:`0x8cbc72 mov esi,[rdx+8]` → `and esi,0xffffff` →
  `0x8cbc84 movsx r13,si` → `0x8cbc88 lea rbx,[r13*2]` → `0x8cbc90 add rbx,r13`)。
  三元组 `+0` 装的是函数入参 `rdx` = **§1 解析器解出的系统对象**。
- 取三元组:`0x8cbf93 lea rax,[r8 + r8*2]`(rax = 3*idx)、`0x8cbf97 lea r12,[r15 + rax*8]`(r12 = 三元组)。
- 容器读:**基址 `r12` ← `0x8cbf97`**,而 `[r12]` 是系统对象指针:

```
008cc030  mov  rax, qword ptr [r12]            ; 三元组 +0 = 系统对象
008cc034  mov  ebx, dword ptr [rax + 0x59c]    ; 计数 = +0x59c
008cc03f  mov  rax, qword ptr [rax + 0x590]    ; 数据 = +0x590
008cc046  mov  ebx, dword ptr [rcx + rax + 8]  ; 元素 +8 = id
008cc45d  add  rcx, 0x20                       ; stride 0x20
```

- **§1.10 / §87 边界**:`0x8cbb61 mov rax, qword ptr [rip + 0x2995048]` → **`0x3260bb0`**(§88 的对象),
  `0x8cbb68 movsxd r9, dword ptr [rax + 0x59c]` 只用它来**量 frontier 缓冲大小**;这不是邻居读点
  —— 同位移、不同对象,不要套 §1。

⇒ owner = §1 系统对象(经 frontier 中转);offsets `+0x590`/`+0x59c`;stride 0x20;元素 `+8` = id。

### §2.4 读路径 C:`num_neighbor_systems` vtable `0x266c108` 的 `+0xf0 = 0x1b87240`

**注意 `+0x18 = 0x1b3cbc0` 不是读路径**:它是**比较体**,`0x1b3cbca mov rax,[rcx]`(自 vtable)后
`0x1b3cbe0 call qword ptr [rax + 0xf0]` 取「邻居收集」结果再比较 —— 与 §2.1 的 `0x1a92090` 同形。
真正的读路径在 **`+0xf0 = 0x1b87240`**(probe `[1b]` 实读 `0x266c108 +0xf0 = 0x1b87240`)。

`0x1b87240..0x1b875a5` 内联 §1 解析器(`0x1b87281`→`0x3260b98`、`0x1b872a2 mov rax,[r9+0x18]`、
`0x1b872b0 cmp [r15+8],edx`、回退 `0x1b872b6`→`0x325d880`),取自身 id `0x1b873d5 mov edx,[r15+8]`,
再 `0x1b873dc call 0x141b86e30`。

收集器 `0x1b86e30..0x1b8723a` 再解一次 §1 解析器(`0x1b86e64`→`0x3260b98`、`0x1b86e6b`→`0x325d880`、
查表 `0x1b86e8c`/`0x1b86ebf`、`0x1b86e96 cmp [rax+8],edx`),然后遍历 §1 容器:

| 站点 | 指令 | 作用 | 基址来源 |
|---|---|---|---|
| `0x1b86e9e` | `mov r8d, dword ptr [rax + 0x59c]` | **计数 = `+0x59c`** | rax ← `0x1b86e8c` 解出的 entry(或 `0x1b86e9b` 回退) |
| `0x1b86ed1` | `movsxd rax, dword ptr [rax + 0x59c]` | 计数 = `+0x59c` | rax ← `0x1b86ebf` 解出的 entry(或 `0x1b86ece` 回退) |
| `0x1b86f5d` | `movsxd r13, dword ptr [r14 + 0x59c]` | **计数 = `+0x59c`** | r14 ← `0x1b86f5a mov r14, r8`(解出的系统对象) |
| `0x1b86f80` | `mov rax, qword ptr [r14 + 0x590]` | **数据 = `+0x590`** | r14 ← `0x1b86f5a mov r14, r8` |
| `0x1b86f87` | `mov ebx, dword ptr [r15 + rax + 8]` | 元素 `+8` = **id** | `r15` = 字节偏移(`0x1b86f6d xor r15d,r15d` → `0x1b870fc add r15,0x20`) |
| `0x1b870fc` | `add r15, 0x20` | **stride 0x20**(循环 `0x1b8700b jne 0x141b86f80`) | — |

基址的两路合流(都是**系统对象**,位移相同 ⇒ 与 §1 是同一个容器):`0x1b86e99 je`(解出的 entry)/
`0x1b86e9b mov rax,r14`(回退 `0x325d880`);`0x1b86f58 jne`(r14 保持回退)/ `0x1b86f5a mov r14,r8`(解出的)。

⇒ owner = §1 系统对象;offsets `+0x590`/`+0x59c`;stride 0x20;元素 `+8` = id。

### §2.5 三角互证与判决

| | 读路径 A | 读路径 B | 读路径 C |
|---|---|---|---|
| 入口 | vtable `0x269fde8` `+0x18` = `0x1afe500` → `0xa6aa10` | vtable `0x267faa0` `+0x18` = `0x1ae3700` → `0x8cbb30` | vtable `0x266c108` `+0xf0` = `0x1b87240` → `0x1b86e30` |
| 数据 `+0x590` | `0xa6aae3 [rdi+0x590]` | `0x8cc03f [rax+0x590]` | `0x1b86f80 [r14+0x590]` |
| 计数 `+0x59c` | `0xa6aaea [rdi+0x59c]` | `0x8cc034 [rax+0x59c]` | `0x1b86f5d [r14+0x59c]` |
| stride 0x20 | `0xa6aaff shl r9,5` / `0xa6ab50 add rdx,0x20` | `0x8cc45d add rcx,0x20` | `0x1b870fc add r15,0x20` |
| 元素 id `+8` | `0xa6ab16 [rdx+8]` | `0x8cc046 [rcx+rax+8]` | `0x1b86f87 [r15+rax+8]` |
| **基址来源** | `0xa6aa3a mov rdi,rdx`(调用方 `0x1afe621` 传的解析器返回值) | `0x8cbf97 lea r12,[r15+rax*8]` 的 `[r12]`,由 `0x8cbc93` 从入参装入 | `0x1b86f5a mov r14,r8`(解析器返回值) |
| 内联 §1 解析器 | `0x1afe5d0`→`0x3260b98` / `0x1afe60d`→`0x325d880` | `0x1ae372e`→`0x3260b98` / `0x1ae3764`→`0x325d880` | `0x1b86e64`→`0x3260b98` / `0x1b86e6b`→`0x325d880` |

三条路径彼此独立(A 在 `has_hyperlane_to` 的 **`+0x18` 读体**、B 在 hyperlane 步数搜索 BFS、C 在邻居计数收集器),
却读到**同一组 offsets、同一 stride、同一元素布局、同一 owner(§1 解析器解出的系统对象)**。按 §87 口径,
识别靠**基址来源**而不是位移 —— 三条路径的基址来源都钉在「§1 解析器返回的系统对象」上,与 §88 那个经
全局 `0x3260bb0` 到达的 stride-4 对象(§2.3 的 `0x8cbb61`)**不同源**。

**限制(不阻断判决,如实记下)**:
- 静态无法确定引擎运行时**具体调哪一个 vtable 槽**(类特定 `+0x18` vs 通用 `+0x28`)。本节证明的是:
  三条读路径**可达**、且读路径**不在**通用解释器里 —— 不是「运行时一定走 A/B/C 三者之一」。
- 字段里存的 `0x165` 这个值静态映射不到名字(descriptor 数组 `0x337b400` 在 BSS);不影响判决。

### §2.6 复现(真实读数)

`hyperlane_read_scan.py` 从字节里重读 **104 个站点** + 三条读路径的 rip 目标解码,逐字比对;
任一不等即不落判决字段并退出 1。干净 shell 实跑(EXIT=0,`[check] 全部读数与计划期一致`):

```
[2] 104 个站点逐字核对 —— 全部相等 OK
[2b] generic_interp 0x348db0..0x349212: 0x165 立即数 0 处;+0x588/+0x590/+0x59c/+0x78 访存 0 条;
     间接 call/jmp [reg+..] 5 条(vtable 槽派发 —— 这正是「不按 opcode 派发」的反证)
[3] 16 个 rip 目标解码 —— 全部 OK(含 nn_eval / nn_collect 的解析器全局与回退)
[5b] 0x1b86f80  mov rax, qword ptr [r14 + 0x590]   ; 基址 r14 来源: 0x1b86f5a mov r14, r8
     0x1b86f5d  movsxd r13, dword ptr [r14 + 0x59c]
[check] 全部读数与计划期一致
  read_handler_rva    = 0x1afe500(has_hyperlane_to +0x18) / 0x1ae3700(closest_system +0x18)
                        / 0x1b86e30(num_neighbor_systems +0xf0 -> 0x1b87240)
  neighbor_vector_off = 0x590
  neighbor_count_off  = 0x59c
  elem_stride         = 0x20
  elem_id_off         = +8
  owner               = system_object(解析器解出 / frontier 装载)
  op_field_off        = 0x78(比较运算符 id 槽位;族默认值 0x165 不在 0x1a92090 的集合内)
```

与 §1 的字段对齐:`read_handler_rva` 是本节新增(§1 给的是 `resolver_rva` 与写例程);
`neighbor_vector_off` / `neighbor_count_off` **两侧逐项相等**,Task 6 的门控字段可直接对接:

```
read_handler_rva    = 0x1afe500(has_hyperlane_to +0x18)
                    / 0x1ae3700(closest_system +0x18)
                    / 0x1b86e30(num_neighbor_systems +0xf0 -> 0x1b87240)
neighbor_vector_off = 0x590        # == §1
neighbor_count_off  = 0x59c        # == §1
```

## §3 M1–M3 离线收口(2026-11-03):判决词、算法一致性、三条「不能说」

> 本节把 Task 1–6 的读数收口成可被下一份 **M4(实机)** 计划直接引用的状态。**本计划零 shot、
> 零进程、零联网**;§3 里没有一行是运行时读数 —— §1/§2 的字节级静态取证 + 两个 Zig 侧合成镜像
> 测试是全部输入。所有地址仍是 module-base-relative RVA(image base `0x140000000`,ASLR on)。
>
> **判决词的出现次数口径(2026-11-03 记)**:每个**判决 token**(§1 / §2 开头判决行里那两个词)在
> **全文恰好出现 2 次** —— 一次在判决行,一次在 §3 的对应小节标题(§3.2 / §3.3)。这是**有意设计**
> (判决行 + 收口标题),不是漏写;因此「判决词只出现一次」这种 grep 门要**按节**判(在该节内唯一),
> 不能按文件判。

### §3.1 五个 keyword 的锚点表(Task 1)

执行体/求值槽的锚点表在 `evidence/disasm/graph_keywords_4_4_4.c`(Task 1 生成物,只在校验通过时落盘):

| keyword | class_info | factory | vtable | +0x20 | +0x28 | +0x48 | +0x80 |
|---|---|---|---|---|---|---|---|
| `add_hyperlane` | `0x260d4e0` | `0x189d510` | `0x25f7448` | `0x3b1770` | `0x1874820` | `0x1874540` | `0x1b4550` |
| `remove_hyperlane` | `0x260d4d0` | `0x189d580` | `0x25f7368` | `0x3b1770` | `0x1874cf0` | `0x1874a00` | `0x1b4550` |
| `has_hyperlane_to` | `0x269db28` | `0x1b2a510` | `0x269fde8` | `0x1afde20` | `0x1a91a80` | `0x1afe750` | `0x349230` |
| `num_neighbor_systems` | `0x269c3c8` | `0x1b33930` | `0x266c108` | `0x1a92070` | `0x1a92450` | `0x1b875b0` | `0x349230` |
| `spawn_system` | `0x26097f8` | `0x18a52b0` | `0x25ecc10` | `0x3b1770` | `0x18f7770` | `0x18f6b90` | `0x1b4550` |

- **写侧目标**:`add_hyperlane` / `remove_hyperlane` 的执行槽 = vtable `+0x48`(`0x1874540` / `0x1874a00`)。
- **读侧目标**:`has_hyperlane_to` 的类特定读体在 vtable `+0x18` = `0x1afe500`;`closest_system`
  `+0x18` = `0x1ae3700`;`num_neighbor_systems` 的邻居收集在 vtable `+0xf0` = `0x1b87240`。
  三者**都不是**通用解释器 `0x348db0` / 共享求值基体 `0x1a91a80`(那两档只挂 `+0x28`/`+0x20`)。
- `spawn_system` 的 `+0x48` = `0x18f6b90`;**只做了锚点,没有跟读它的写路径**(见 §3.6 ③)。

### §3.2 §1 判决词:`edge_store_write_named`

写路径(id→系统对象解析器 + 边存储 + 增/删例程)在 `add` 与 `remove` **两侧同形且逐条可证**;
`add`/`remove` 只在增/删例程分叉,**解析器、容器所有者、三个偏移两侧逐条相等**(§1.7),**没有取并集**。
核心读数:

```
resolver_rva        = 0x3939f0      (§1.2,叶子函数、无 .pdata)
edge_owner          = system_object(解析器返回) + 0x588
neighbor_vector_off = 0x590         (数据;容量 0x598、计数 0x59c)
elem_stride         = 0x20          (元素 +8 = 系统 id)
insert_fn           = 0x8bbaa0      (通用 push_back 0x8cf8d0)
remove_fn           = 0x8bbc20
```

- **id 的来源是 scope `+0x10`**,不是 scope `+0`(`0x3939fa` 取 id、`0x3939fd` 存栈局部、
  `0x393a12 lea rcx,[rsp+8]` 才让 `rcx` 指那个局部)。
- **基址来源钉死**:两个 keyword 里的容器基址 `rbx`/`rdi` 来自 `0x3939f0` 的返回值
  (`0x1874583` ← `0x187457e call 0x1403939f0`),不是栈、不是全局(§87 口径)。
- 两个解析器全局 `0x3260b98`(系统索引)/ `0x325d880`(回退)在文件里**没有字节**(BSS)⇒
  静态不可定值,只报读点与解引用偏移(§1.2)。

### §3.3 §2 判决词:`edge_store_read_confirmed`

三条**互相独立**的 trigger 侧读路径(A:`has_hyperlane_to` 的 **`+0x18` 读体**(`0x1afe500`;它的
`+0x20 = 0x1afde20` 才是比较体 —— **[更正 2026-11-03]** 早先把 A 记成「比较体」是标签错,入口表
与本节下表的 `0x269fde8 +0x18` 一直是 `+0x18` 读体,读数未变);B:`closest_system` 的
hyperlane 步数 BFS;C:`num_neighbor_systems` 的邻居计数收集器)都读到 §1 的**同一组** offsets、
**同一 stride 0x20**、**同一「元素 `+8` = id」**,而且三条路径的基址来源都能追回 §1 的解析器
返回值或它灌进容器的那批系统对象:

| | 读路径 A | 读路径 B | 读路径 C |
|---|---|---|---|
| 入口 | `0x269fde8 +0x18` = `0x1afe500` → `0xa6aa10` | `0x267faa0 +0x18` = `0x1ae3700` → `0x8cbb30` | `0x266c108 +0xf0` = `0x1b87240` → `0x1b86e30` |
| 数据 `+0x590` | `0xa6aae3` | `0x8cc03f` | `0x1b86f80` |
| 计数 `+0x59c` | `0xa6aaea` | `0x8cc034` | `0x1b86f5d` |
| stride 0x20 | `0xa6aaff`/`0xa6ab50` | `0x8cc45d` | `0x1b870fc` |
| 元素 id `+8` | `0xa6ab16` | `0x8cc046` | `0x1b86f87` |

**§2.1 否证的简报前提**:`+0x78` 存的不是 opcode。`num_neighbor_systems` 实测存 `0x165` 是**读数**
(对),但该槽被共享比较体 `0x1a92090` 当**比较运算符 id** 派发(可达集合
`{1(=), 0x1d3(>), 0x1d4(<), 0x3cb(>=), 0x3cc(<=), 0x427(!=)}`),`0x165` **不在集合内** ⇒
默认落到 `0x1a92193 xor al,al`(恒 false)。派发键始终是 **vtable 槽**;通用解释器 `0x348db0` 里
`0x165` **0 处**、`+0x588/+0x590/+0x59c/+0x78` 访存 **0 条**,却有 5 条 `call [reg+…]`(它自己就按
vtable 槽派发)。**报「词」不报「槽号」**:静态无法确定引擎运行时**具体调哪一个** vtable 槽
(类特定 `+0x18` vs 通用 `+0x28`),本节证明的是三条路径**可达**、且读路径**不在**通用解释器里。

### §3.4 算法对 787/1,217 的逐项一致(Task 4 + Task 5)

- 输入(存档局部):`evidence/xrefs/c5_campaign_edges_4_4_4.tsv`(**787 系统 / 1,217 条**无向边,
  每边一次 `a<TAB>b<TAB>length`)+ `evidence/xrefs/chokepoint_scores_4_4_4.tsv`(7 列,CRLF)。
- 生成物:`src/dll/c2/graph_fixture.zig`(`SYSTEM_COUNT = 787`、`EDGE_COUNT = 1217`、`edges` +
  `expected_scores` / `expected_articulation` / `expected_bridge_endpoint`)。
- 算法:`src/dll/c2/chokepoint_dynamic.zig`(CSR + Brandes(betweenness,无向无权,归一化)+
  迭代 Tarjan(割点/桥);round-half-to-even;分母 `n` = 调用方给的 `system_count`,不是边表里
  出现的最大 id)。
- **一致项**:`chokepoint_dynamic: synthetic fixture matches the offline scores` 用 `analyze()` 在
  1,217 条边上重算 787 个系统的三个数组,`expectEqualSlices` 三个都过 ⇒ **787/787 × 三数组全等**,
  即 `betweenness → score`(round-half-to-even)、割点、桥端三项与离线七列表逐项一致。
- 去重/去自环口径与生成器一致(`graph_fixture_emit.py --check` 的漂移门 + `analyze` 的同一口径)。

### §3.5 `galaxy_graph` 合成围栏(Task 6)

`src/dll/c2/galaxy_graph.zig` 只经注入的 `Memory.read` 触碰内存(**文件里没有一个 `@ptrFromInt`**),
测试侧接合成字节镜像(`c2_tests.zig`),生产侧将来接真内存。围栏 = `c2_tests.zig` 里 **18** 条
`galaxy_graph:` 测试(`chokepoint_dynamic:` 另有 **7** 条,合计 **25** 条命名测试;
`zig test --test-filter "galaxy_graph"` 报 **19** 是因为它还带上了根 `test_0`):

1. `galaxy_graph: three systems, two edges, read out of a synthetic mirror`
2. `galaxy_graph: an unreadable neighbour id is skipped, not fatal`
3. `galaxy_graph: sparse ids resolve through the table, never as slot indices`
4. `galaxy_graph: no cross-call caching of edges or pointers`
5. `galaxy_graph: a short out buffer is error.BufferTooSmall, not a silent truncation`
6. `galaxy_graph: an absurd edge count is capped, never walked`
7. `galaxy_graph: an unreadable index header is an error, not an empty graph`
8. `galaxy_graph: the table record stride is 16 bytes, not 8`
9. `galaxy_graph: a null index object or a null table is error.UnreadableIndex`
10. `galaxy_graph: a zero slot bound is error.UnreadableIndex, not an empty graph`
11. `galaxy_graph: a count beyond the container capacity is skipped, never walked`
12. `galaxy_graph: sparse ids carry the max id, and the adapter sizes the graph from it`
13. `galaxy_graph: an empty galaxy reports max_id == null, not a zero id`
14. `galaxy_graph: a table entry pointer near maxInt is skipped, not an overflow`
15. `galaxy_graph: an edge-data pointer near maxInt is skipped, not an overflow`
16. `galaxy_graph: a galaxy address near maxInt is UnreadableIndex, not an overflow`
17. `galaxy_graph: a slot bound above the u16 id space is error.UnreadableIndex`
18. `galaxy_graph: a slot id above the u16 range is skipped, not admitted`

每条镜像都按 §1.11 的 **16 B 记录**布(指针在记录 `+8`),并专门埋「诱饵位」`table + slot*8 + 8`,
用第 8 条盯住 —— 步长写成 8 B 会**静默读到别的对象**而不报错。第 4 条钉「无跨调用缓存」
(两次调用之间改图,第二次必须读到新边;Review Focus #3)。全套 Zig 测试 = **891 passed**。

**2026-11-03 的两处收紧(读图器行为,不是读数)**:

- **u16 门取代 24 位掩码**:被承认的系统 id 必须 `id <= 0xFFFF`(端点是 u16)⇒ 引擎那个
  `id & 0xFFFFFF` 对被承认的 id **恒等**。实现改成「先判 `id > 0xFFFF` 跳过,再判 `id != slot`
  跳过」,两条路都是「计入 `skipped` 后 continue」⇒ **`skipped` 计数与旧顺序逐项相等**,
  哪些表项被承认也不变。第 18 条钉住「超 u16 的表项被跳过」。
- **槽数上限从 `2^20` 收到 `2^16`**(`offsets.graph.MAX_TABLE_SLOTS`):活着的槽号恒 `< 2^16`,
  所以更大的槽表里不可能有第二个被承认的系统。**已知取舍**:引擎的槽空间是 24 位的,
  真实索引对象的 `+0x20` **可能**大于 65536 —— 那时读图器判 `error.UnreadableIndex`
  而不是「只扫前 2^16 个槽」;这比严格必要**更严**,方向是 fail-closed。第 17 条钉住这条门。

### §3.6 三条「不能说」(本计划的诚实边界)

1. **偏移是静态推断,没有一次运行时读数。** §1/§2 的一百九十余个站点是**字节级静态**读数;
   合成镜像只证明**代码形状**(给定这些偏移,读图/度量得到的推论链自洽),**不证明活体布局**。
   两个系统索引全局在 BSS,静态连指针值都读不出。
   (**与 `runtime_444_c1_validation.md` §91.6/§91.7 不冲突**:那一发实机读到的是「每轮 scope 经
   `rdx` 传入、`+0x10` 是 id」= **句柄来源**,那一格已 `pinned`;本卷未验证的是**容器偏移本身**
   (`+0x588`/`+0x590`/`+0x598`/`+0x59c`)与 id→系统对象的解析路径 —— **两者不是同一格**。)
2. **读图器没有接任何实机通道。** `galaxy_graph.zig` 的 `Memory.read` **生产实现不存在**;
   在 M4 接上真内存、并确认 §3.1 的 vtable 槽真的被执行路径走到之前,`resolveFromGame` 类入口
   **不得被调用** —— 拿一个未验证的指针调真机读会静默读错对象(§1.11 的 16/8 步长就是范例)。
3. **图变更后的重算未验证。** `add_hyperlane` / `remove_hyperlane` / `spawn_system` **只做了静态
   锚点**:没有钩子、没有置脏、没有实机。§1.4 的增例程确实置了脏位,但**没有证据**显示引擎后续会
   重算我们关心的量;`spawn_system` 的写路径整个没跟。

### §3.7 `0x296cc68` 是**可选**信号候选,不改 §88 的 `no_version_signal`

增/删边都会置**同一个广义脏/世代位掩码全局 `0x296cc68`**(§1.4.1:24 个交叉引用横跨多个子系统,
17 个置位、4 个写 `2`、只有 2 个读点,是按位测试的掩码字,**不是**边专属标志)。它是裁定④
「变更钩子」的一个**可选**候选,但:

- 它是**全局字**,**不在** `runtime_444_c1_validation.md` §88 扫描的那个对象 `+0x580..+0x5c0` 窗口内
  ⇒ §88 的 `no_version_signal` **只管它自己的窗口**,本卷的写点**不构成反例**,§88 也**不否定**本卷
  的 stride-0x20 容器(§1.10 已记录边界)。所以本条的披露**不推翻** §88 的 `no_version_signal`。
- 本计划**不依赖**任何版本信号:裁定④已改为「脚本显式调用时**全量重读边表 + 重算**」,变更钩子
  只是**可选优化**,不是正确性前提(见本计划 Spec delta / `docs/c5-pilot2-spec.md` §3.1 ④)。

### §3.8 勘误:表项记录步长是 **16 B**,不是 8 B(§1.11)

§1.2 的寻址**行内注释**原先写 `entry = [表 + idx*8 + 8]`,与它上面一行已经列出的 `0x393a2f add rcx, rcx`
(槽号在寻址前翻倍)矛盾 —— **[更正 2026-11-03]** 早先这里写「漏抄了 `add rcx,rcx`」,不成立:那条指令
在 §1.2 清单里一直都有,记错的是注释的步长 ⇒ 实际是 `[表 + slot*16 + 8]`。**表项记录 = 16 B,系统对象指针在
记录 `+8`**;按 8 B 步长读会落在记录头或前一条记录上、**静默读错对象**。Task 6 的读图器按 16 B 实现
(`offsets.graph.TABLE_RECORD_SIZE = 16` / `TABLE_SLOT_PTR_OFF = 8`);§1.2 其余结论(id 来自 scope
`+0x10`、边界 `[对象+0x20]`、表指针 `[对象+0x18]`、命中条件 `entry+8 == id`、回退 `0x325d880`)全部
照旧,§1.3 的边容器字段表不受影响。

## §4 实机读一发(2026-11-04):容器偏移在活体成立;离线 oracle 差的是**一条新系统**,不是偏移

**授权级**:点名 ×1(计划 `2026-11-03-runtime-graph-live` Task 3,2 发预算里的第一发)。
**只读**:探针没有任何 hook(无 detour、无 trampoline、无引擎字节改动),读路径只经
`ReadProcessMemory`;两个改边导出**一次都没调**。

### §4.1 命令与真实输出

```
just win "python C:/temp/session_bridge.py C:/temp/c2_graph_read.py C:/temp/sqjs_g1.dll \
  --expect-systems 787 --expect-edges 1217 --save-name autosave_2258.07.01 \
  --edges-file C:/temp/c5_campaign_edges_4_4_4.tsv --out C:/temp/c5_graph_read.tsv"
```

```
[graph] dll=C:/temp/sqjs_g1.dll sha256=012c460e1d23f9cb3c35598ec7ce200fd536c332dca05277b27b9dc7d252e1a3
[graph] pid=23640 dll=C:/temp/sqjs_g1.dll
[graph] sqjs_g1.dll base: 0x7ff82a180000
[graph] C2Sanity == 42, game alive ?? read authorized
[graph] verdict=graph_live_read_disagree  systems=788 edges=1219 vs expect systems=787 edges=1217; (315, 787) in read1 only
[graph] artifact=C:/temp/c5_graph_read.tsv
```

`#meta` 全文 = `evidence/logs/c5_graph_live_read_4_4_4.log` 的 26 行 meta(artifact 是驱动原样输出,
1,242 行 = 26 meta + 1,219 边行,写盘时刻 `2026-11-04 00:37:49`)。关键格:

| 键 | 值 | 键 | 值 |
|---|---|---|---|
| `module_base` | `0x7ff78c120000`(**stellaris.exe** 的基址) | `index_ptr` | `0x16c355838` |
| `table_ptr` | `0x1ca587180` | `bound` | **1024** |
| `systems` | **788** | `max_id` | **787** |
| `edges` | **1219** | `skipped` | **0** |
| `read2_systems` | 788 | `read2_edges` | **1219** |
| `read1_rc` / `read2_rc` | 0 / 0 | `read2_skipped` | 0 |
| `layout` | `0x1,0x3260b98,0x18,0x20,0x10,0x8,0x59c,0x20` | `host_alive` | 1 |

`layout` 八格与 `offsets.graph` 逐格相等(**字 4 = `0x10` = 16 B 记录步长**,不是 8)⇒ 仪器对账过。
`bound=1024` 而 `max_id=787` 是 Review Focus #2 要的形状:上界来自**表项自证**(`max_id`),不是
`bound-1`;788 个活系统 id 唯一且 `<= 787` ⇒ 覆盖恰为 `0..787`(稠密,无空洞)。

### §4.2 判决词:**对旧 oracle 是 `disagree`,对同期 oracle 是 `named`**

- `overall_verdict=graph_live_read_disagree`(artifact 原样)= 对 `c5_campaign_edges_4_4_4.tsv`
  (由**已不存在的** `autosave_2231.07.01.sav` 烘出)的口径。**不是** `instrument_broken`:
  layout 全中、`skipped=0`、两次读相等(判词先判 `unstable`,没走到那一档)、宿主存活。
- **同期 oracle = `autosave_2260.01.01.sav`**(写于 `00:37:34`,比 artifact 早 **15 s**;读发生在
  它之后)⇒ 边集与本次读数**双向零差**,判词按同一 `classify` 规则应为 `graph_live_read_named`。

### §4.3 差分:两个 oracle 把「偏移漂了」与「战役往前走了」分开

| oracle | 来源 | 边 | live-only | oracle-only |
|---|---|---|---|---|
| `c5_campaign_edges_4_4_4.tsv` | `autosave_2231.07.01.sav`(已退役,sha `32413c3e…`) | 1,217 | `(315,787)`、`(575,787)` | **∅** |
| `autosave_2259.07.01.sav` | 同战役,`2026-11-04 00:34:36` 写盘 | 1,217 | `(315,787)`、`(575,787)` | **∅** |
| `autosave_2260.01.01.sav` | 同战役,`2026-11-04 00:37:34` 写盘 | 1,219 | **∅** | **∅** |

即:**离线表 1,217 条一条不少地读回来了**(oracle-only 恒 ∅),live 多出的两条都挂在 **id 787** 上 ——
那是 `0..786` 之后的下一个 id,出现在 `2259.07.01` 与 `2260.01.01` 两份存档之间(游戏内同一次读档会话里
从 2259 跑到 2260,月速最快档)。两次之间的窗里只多了一个系统,与「事件生成新星系」的形状一致
(该战役当时正在跑 `风信子号` 调查链)。

**因此这句判词必须写清**:`disagree` 记的是「活体与 2231 的离线表不相等」这一事实,**不是**「偏移错了」。
把 live 与同期存档逐项对齐后差集为空 ⇒ 容器(`+0x588/+0x590/+0x598/+0x59c`)、解析器(`0x3939f0` 的
表形状)、16 B 记录步长、u16 端点这一整条链在活体里**成立**。

### §4.4 这一发**已能说**(三条)

1. **容器偏移在活体里成立**:1,219 条边 × 两个端点全部按 `+0x590`/`+0x59c`/步长 `0x20`/元素 `+8` 读出,
   `skipped=0`,且同一份数据在存档侧由**完全独立的解析器**(`scripts/save_hypergraph.py`,ZIP +
   Clausewitz tokenizer)逐项复现 ⇒ 两侧 1,219/1,219 相等。
2. **id 覆盖 `0..787`**:788 个系统、id 唯一、`max_id=787`、`bound=1024` ⇒ 覆盖稠密且上界来自表项自证。
3. **边集与离线表的关系是「包含 + 两条新边」**:1,217 条旧边**逐项相等**(差集为空),多出的两条是
   id 787 的两条 hyperlane;不是漏读、不是错位、不是去重口径变了。

### §4.5 这一发**仍不能说**(三条)

1. **没证明每次读都一致**:只测了同一进程内的**两次**连续读(相等),没有跨帧/跨月/跨暂停的重复读,
   也没有对同一容器做并发读。`graph_live_read_unstable` 这一档存在,但本发没触发,等于**没测到**它。
2. **没证明图变更后引擎会重算**:本发只读;`add_hyperlane`/`remove_hyperlane` 的写路径仍未实机调用,
   §3.6 第 3 条的边界原样保留。
3. **只在这一场战役、这一版 exe 上**:`_1474567734`(788 系统 / 1,219 边)、stellaris.exe 4.4.4、
   且 oracle 是**同一次会话内**的存档;换战役、换版本、换读档时机都要重测。

### §4.6 操作侧的两条环境档(不算读数,记在这里因为下次一定还会踩)

1. **SSH 直跑驱动会永远被门挡住**:`ssh` 落在 **session 0**,`EnumWindows` 看不到游戏窗口 ⇒
   `gate_install` 以 `no game window` 拒装(exit 2,未注入、未耗预算)。所有要过门的驱动必须经
   `session_bridge.py`(`schtasks /run /I` 落到交互会话)。
2. **事件窗会把游戏按暂停,`install` 只认 `IN_GAME_RUNNING`**:本发第一次经 bridge 跑时读到
   `IN_GAME_PAUSED_CLEAN`(exit 2,同样不算读数);用桌面通道(`win-desktop` `Shortcut "enter"` 答掉
   默认选项)恢复运行后立刻重打才通过。**这不是 `--allow-window` 的用途** —— 那一档只给「状态机与
   屏幕矛盾且人当场确认」。

## §5 改一条边并重算(2026-11-04):`(5,9)` 进出各一次,全图分数跟着变

**授权级**:点名 ×2(2 发预算里的第二发)。**同一进程**(pid 23640)的**第二个模块名**
`sqjs_g2.dll`(与 `sqjs_g1.dll` **同 sha**:`012c460e…`)—— `refuse_if_resident` 拒绝同名重注。
写路径只经引擎自己的两个例程(`0x8BBAA0` / `0x8BBC20`),本 DLL 不写任何引擎字节。

### §5.1 命令与真实输出

```
just win "python C:/temp/session_bridge.py C:/temp/c2_graph_read.py C:/temp/sqjs_g2.dll \
  --expect-systems 788 --expect-edges 1219 --save-name autosave_2260.01.01 \
  --mutate 5,9 --kill-after --out C:/temp/c5_graph_mutation.tsv"
```

```
[graph] dll=C:/temp/sqjs_g2.dll sha256=012c460e1d23f9cb3c35598ec7ce200fd536c332dca05277b27b9dc7d252e1a3
[graph] pid=23640 dll=C:/temp/sqjs_g2.dll
[graph] sqjs_g2.dll base: 0x7ff829350000
[graph] C2Sanity == 42, game alive ?? read authorized
[graph] verdict=graph_mutation_recompute_named  (5, 9): 1219 -> 1220 -> 1219
[graph] artifact=C:/temp/c5_graph_mutation.tsv
[graph] taskkill /F /PID 23640 rc=0 ?? session not saved
```

`#meta`(`evidence/logs/c5_graph_mutation_4_4_4.log` 前 30 行)里与改边相关的几格:

```
#meta mutation=5-9
#meta mutation_steps=step=base edges=1219 rc=0|step=add edges=- rc=0|step=add_read edges=1220 rc=0|step=remove edges=- rc=0|step=remove_read edges=1219 rc=0
#meta overall_verdict=graph_mutation_recompute_named
#meta index_ptr=0x16c355838  table_ptr=0x1ca587180  bound=1024
#meta systems=788  edges=1219  skipped=0  max_id=787  host_alive=1
```

五个 `step=` 是**逐步**写的:任何一步返回码非 0 或边集不是「+1 再 −1」,后面的导出一个都不再调
(`classify_mutation` 的 `mutation_left_dirty`,由 `scripts/test_c2_graph_read.py` 的 5 条围栏钉住)。

### §5.2 三份快照:集合层面逐项闭合

产物 = `evidence/logs/c5_graph_mutation_4_4_4.log.{base,add,remove}`(每行 `a<TAB>b<TAB>1`;
第三列是**占位**,读数里没有边长,主机侧度量是无权 Brandes)。

| 关系 | 结果 |
|---|---|
| `base == remove` | **真**(且两份文件 sha256 相同:`462dfd3f…`) |
| `add == base ∪ {(5,9)}` | **真**(恰好一条,两端的容器都写到了) |
| `base` vs `autosave_2260.01.01.sav`(独立解析器) | 双向零差(base-only ∅, save-only ∅) |
| 计数 | `1219 → 1220 → 1219` |

注意 `(5,9)` 在**改边前不存在**(基线上 `5` 与 `9` 各 4 度),所以 +1 是**新边**,不是重复写。

### §5.3 主机侧重算:400/788 个系统的分数变了

```python
import pathlib, sys
sys.path.insert(0, "scripts")
import chokepoint_scores as cs
base = cs.build_adjacency(cs._read_edges(pathlib.Path("evidence/logs/c5_graph_mutation_4_4_4.log.base")))
mut  = cs.build_adjacency(cs._read_edges(pathlib.Path("evidence/logs/c5_graph_mutation_4_4_4.log.add")))
b = {r["system_id"]: r for r in cs.score_rows(base)}
m = {r["system_id"]: r for r in cs.score_rows(mut)}
changed = [k for k in b if b[k]["score"] != m[k]["score"]]
```

真读数:**`changed = 400`(共 788 个系统)**;最大三处分数差 ——

| 系统 | 改边前 | 改边后 | Δ |
|---|---|---|---|
| **5** | 4 | **233** | +229 |
| **9** | 34 | **253** | +219 |
| 337 | 34 | 210 | +176 |

`5` 与 `9` 各自从 4 度变成 5 度、又是新捷径的两端 —— 它们自己的 betweenness 涨得最多,
其余 397 个系统的变化是这条新边对全图最短路集合的重新分配。**分母没动**:`n` 仍是 788,
所以这不是重新标定,是同一条公式在新边上重算。

### §5.4 这一发**已能说**(三条)

1. **引擎自己的加/删边例程在活体里可用**:`0x8BBAA0` 一次调用即让**两端**的容器都多出对方 id
   (我们按 §1.1 的形状各调一次,和引擎执行体一样);`0x8BBC20` 一次调用即删干净 ——
   三个快照在**集合层面**闭合,不是「计数回去了但边不对」。
2. **图一变,重算的分数就跟着变**:400/788 个系统分数改变,且变化集中在新增捷径的两端。
3. **改边是真实副作用,已按计划收尾**:`taskkill /F`(rc=0)、未存档、未退回主菜单;
   改动前的战役存档在 `C:/temp/c5_save_backup_1474567734/`(5 份)。

### §5.5 这一发**仍不能说**(硬边界)

1. **运行时内的重算仍未验证。** §5.3 的分数是**主机 Python** 重算的;引擎自己在边变更后会不会
   立刻让 `chokepoint_dynamic` 那套量失效、有没有缓存、什么时候重算 —— 一格都没测。这是 M5
   (trigger 落地)的输入,不是本计划的结论。
2. **只证了「一条边」**。多边连锁、删一条本来不存在的边、改边后引擎自己的寻路/舰队路径是否
   立即使用新图 —— 都没测(边删掉后我们立刻杀进程,没有让游戏继续跑)。
3. **`0x8BBC20` 的 `&id` 参数约定只在这一处对上**:`(rcx=self, rdx=&other_id)` 各一次,
   与 §1.1 的 `01874cbd` 形状一致;换成别的调用形状(例如一次传两个 id)没有验证。

## §6 M4 收口(2026-11-04):导出契约、两发判词、能用它们回答什么

### §6.1 导出清单与返回码(`src/dll/c2/graph_probe.zig` → `src/dll/exports.zig`)

| 导出 | 入参 | 返回 | 语义 |
|---|---|---|---|
| `C5GraphRead` | — | `0` / `-1` / `-2` / `-3` / `-4` | `0` 成功且 `skipped==0`;`-1` 模块基址取不到;`-2` 索引对象不可读/越界;`-3` 边表超 `MAX_EDGES`(4,096);`-4` 读成功但有 `skipped`(带欠账,不是失败) |
| `C5GraphLayout` | `out: [*]u32` | `8` | 八词:`version, RVA_SYSTEM_INDEX_GLOBAL, INDEX_TABLE_OFF, INDEX_BOUND_OFF, TABLE_RECORD_SIZE, TABLE_SLOT_PTR_OFF, EDGE_COUNT_OFF, EDGE_STRIDE` |
| `C5GraphStatsInto` | `out: [*]u8` | `64` / `0` | `${u64}×8`:`systems, edges, skipped, max_id`(`null`=`u64` 最大),`index_ptr, table_ptr, bound, module_base` |
| `C5GraphDrainInto` | `out: [*]u8` | 行数 / `0xFFFF_FFFF` | 每行 4 B(`u16 a`,`u16 b`),`a<b`,按 `(a,b)` 升序;缓冲不足整块拒写 |
| `C5GraphReset` | — | — | 清上一发的 stats 与行数(本模块无 hook) |
| `C5GraphMutateAdd` | `pair: u64`(低 32 = from,高 32 = to) | `0` / `-1` / `-2` / `-3` | 转调 `0x8BBAA0` **两次**(两个方向);`-1`/`-2` = from/to 解析失败,`-3` = id 超出 u16 空间 |
| `C5GraphMutateRemove` | 同上 | 同上 | 转调 `0x8BBC20` 两次(各带 `&other_id` / `&self_id`) |

两参导出之所以收**一个 u64**:`call_remote_with_arg` 只设 `rcx`(`CreateRemoteThread` 的 lpParameter),
第二个寄存器不可达 —— 这是通道的硬约束,不是设计选择。

### §6.2 两发判决词

| 发 | 命令要点 | 判决词 |
|---|---|---|
| 1(只读,pid 23640,`sqjs_g1`) | `--expect-systems 787 --expect-edges 1217 --edges-file <2231 表>` | artifact `graph_live_read_disagree`;对**同期**存档(`autosave_2260.01.01.sav`)口径 = **`graph_live_read_named`** |
| 2(改边,同 pid,`sqjs_g2`) | `--mutate 5,9 --kill-after` | **`graph_mutation_recompute_named`**(`1219 → 1220 → 1219`,主机侧重算 400/788 变) |

### §6.3 `graph_live_read_named` 证明了什么

1. **容器偏移在活体成立**:`+0x588` 容器的 `+0x590`/`+0x598`/`+0x59c`、步长 `0x20`、元素 `+8` 一处没错;
   `layout` 八格与 `offsets.graph` 逐格相等。
2. **索引对象形状在活体成立**:`[module_base+0x3260B98]` 非空,`+0x18` 表指针 / `+0x20` 界(`bound=1024`)
   可用,记录 16 B、指针在 `+8`;`max_id` 来自表项自证(`787`),不是 `bound-1`。
3. **两侧独立解析器给出同一张图**:读图器(`ReadProcessMemory` + 引擎容器)与存档解析器
   (`save_hypergraph.py`,ZIP + Clausewitz tokenizer)**双向零差**(1,219/1,219)。

### §6.4 `mutation_verdict`(`graph_mutation_recompute_named`)证明了什么

1. **引擎自己的加/删边例程可从外部驱动**:一次 `0x8BBAA0` 调用让**两端**容器都多出对方 id,
   一次 `0x8BBC20` 让它们回到基线;集合层面闭合(不是「计数回去了但边不对」)。
2. **图一变,重算的分数就变**:400/788 个系统的 betweenness 改变,最大三处正是新捷径的两端
   (`5: 4→233`、`9: 34→253`)与 `337: 34→210`。
3. **改动是可撤销的**:`base == remove`(集合与 sha256 都相等),进程随后被 `taskkill /F`,未存档。

### §6.5 新增的三条「不能说」(与 §3.6 并列,不替代)

1. **样本只有一场战役、一版 exe**:`_1474567734`(会话内从 787 长到 788 系统)、stellaris.exe 4.4.4。
   换战役的第一件事是**重新取同期 oracle**,不是复用 `c5_campaign_edges_4_4_4.tsv`。
2. **读一致性只证了两次**:同一进程内连读两次相等;跨帧/跨月/暂停-恢复后是否一致**没测**。
3. **运行时内重算未验证**:§5.3 的分数是主机 Python 算的;引擎在边变更后是否立刻让缓存失效、
   按什么粒度重算,一格都没测 —— 这是 M5 的输入,不是本计划的结论。

## §7 M5:运行时内重算(2026-11-04):容器指纹一动,game 自己的重算就跟着动

**授权级**:点名 ×1(同一次会话里的一个进程)。**载体**是 effect 侧(§93 的逐系统派发 + §95 的
写手),不是 trigger —— 理由与代价见下 (§7.5)。

### §7.1 装配

- `--launch <stellaris.exe>` + `--allow-window`:**在进程刚出现时注入并注册** `neo_action`。
  这一条是硬前置:mod 脚本里的 `neo_action` 要在**解析时**就有 id,晚注入会得到
  `Script Error: Invalid scripted effect: neo_action`(第一发就是这么废掉的,零预算损失)。
- `--act write --score-source 1`:`neo_score` 改由**活体重算**供给(`C2NeoScoreSource(1)`),
  执行体的每次求值先算容器指纹、再决定要不要重算。
- mod(`neo_ps_probe`)的月脉冲改成 `every_system = { neo_action = yes ; log = "PS_HIT …" }`。

### §7.2 读数(同一进程,三窗)

| 窗 | `evaluated` | `recomputed` | `cached_hits` | `systems` | `fingerprint` |
|---|---|---|---|---|---|
| 基线(6 个月) | 4,728 | **1** | 4,727 | 788 | **2446** |
| `MutateAdd(5,9)` 之后 | 10,244 | **2** | 10,242 | 788 | **2448** |
| `MutateRemove(5,9)` 之后 | 14,972 | **3** | 14,969 | 788 | **2446** |

配套:`read_failed=0`、`out_of_range=0`、`non_system_scope=0`、`host_alive=1`。
`fingerprint` 是**所有活槽 `+0x59C` 的 dword 和**(= 2 × 边数 + 8);`(5,9)` 一次增边让两个端点的
计数各 +1 ⇒ **+2**,删回 ⇒ **−2**。`recomputed` 只在指纹变化的那一次求值 +1。

**换源前后的对照**:烘焙表源下 `score_skipped=5`(id 787 ≥ 表长 787);切到 live 源后
`score_skipped` **不再增长**(live 的 `n = max_id+1 = 788`)—— 这一格是「换源真的生效」的旁证。

### §7.3 这一发**已能说**(三条)

1. **引擎按星系调用我们的代码,我们在里面读了活的图**:4,728/10,244/14,972 次求值都是引擎自己
   的月脉冲驱动的(`calls=matched=log_calls` 逐项相等),每次求值都走系统容器(`systems=788`)。
2. **图变了,进程内就重算了**:加一条边 ⇒ 指纹 +2 ⇒ `recomputed` 1→2;删回去 ⇒ 指纹 −2 ⇒
   `recomputed` 2→3。**全程没有主机 Python 参与**,也没有第二次注入。
3. **缓存是"指纹缓存"而不是时间缓存**:同一窗里 4,727 次求值命中缓存(指纹没变),只有真正
   改图的那一次重算 —— 这正是裁定④要的「显式调用时全量重读 + 重算」,而且不靠 TTL。

### §7.4 这一发**仍不能说**(三条)

1. **没有证明"分数值"翻转**:本发测的是**重算发生了**(指纹 + `recomputed`),没有把 `neo_score`
   的逐系统值与主机侧重算逐项比对。下一发要把 mod 的 `check_variable` 分档行也算进窗口,
   与 `chokepoint_scores` 的 `changed=400/788` 对齐。
2. **指纹盲点**:同一 tick 里先加后删同一条边会让和回到原值 ⇒ 那一次不会重算。本发刻意分成
   两个窗(加/删各一个 tick),所以没踩到,但盲点仍在。
3. **只证一条边、一场战役、一版 exe**;多边连锁、删一条不存在的边、跨月一致性都没测。

### §7.5 载体为什么是 effect 而不是 trigger(以及代价)

计划原本要注册一个新 trigger,让 `[vptr+0x80]` 的谓词槽指向我们的实现。实现时发现缺一环:
`class_info` 是 16 B `{deleter, create}`,**`create` 由引擎调**,我们拿不到"对象刚造好"那一刻去换
`[obj+0]`;换成自己的 `create` 又要先钉死它的调用约定,而 4.4.4 上这条**仍未钉**
(`keyword_registry.register` 的注释明写 ``factory ... unpinned``)。⇒ 本发改走 effect 侧,
复用两条已实机验证过的通道。**代价**:§7 的结论是「**effect 体内**重算」,不是「trigger 谓词内
重算」;trigger 形态留给 M5b(先做 `create` 约定的零 shot 取证)。
