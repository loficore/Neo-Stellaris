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
  (`0x9d1184 mov rax,[r13+0x590]` + `0x9d118b mov ebx,[rax+rcx*4]`,`0x9d117a idiv dword ptr
  [r13+0x59c]`);本卷 §1 的 `+0x590` 是 **stride-0x20 的边元素数组**(`0x8cf93e shl rdi,5`、
  `0x8bbc5d add rax,0x20`)。步长不同 ⇒ 不是同一个 vector。
- **本卷的脏位 `0x296cc68` 不在 §88 的口径内**:§88 扫的是**那个对象 `+0x580..+0x5c0` 里的
  内存站点**,而 `0x296cc68` 是一个**全局字**,不是该窗口内的偏移 ⇒ 即使 §88 的判决成立,
  本卷的写点也不构成反例;反过来说,§88 的 stride-4 读数也不否定本卷的 stride-0x20 容器。
  这正是 §88「**欠账①**」所指的那一类:容器的**变更方**拿到的不是它扫描的读侧集合里的站点。
  (旁证:`0x952e54` 既读 `0x296cc68` 的位,又 `0x952e6b mov rdx,[rip->0x3260bb0]` +
  `0x952e72 add rdx,0x588` 触及 §88 对象的容器 —— 变更侧与脏位确实相邻,但都不是 §88 窗口内的
  偏移站点。§88 的 `no_version_signal` 只覆盖它自己的窗口。)

⇒ 读本卷不要顺手把 §88 当被证伪,读 §88 也不要把本卷的 `+0x588/+0x590/+0x59c` 套上去。
