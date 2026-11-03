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
01874710  cmp  dword ptr [rax], edx             ; 去重: entry+8 == [rdi+8]
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

```
003939f0  cmp   qword ptr [rcx + 8], 0x80   ; scope 类型必须是 0x80(system)
003939f8  jne   0x140393a03
003939fa  mov   eax, dword ptr [rcx + 0x10]; 取 scope 里的 id
00393a03  mov   dword ptr [rsp + 8], 0xffffffff  ; 非 system -> id = -1
00393a0b  mov   rax, qword ptr [rip + 0x2ecd186]  ; <-- 全局 0x3260b98(系统索引)
00393a17  test  rax, rax
00393a1a  je    0x140393a41
00393a1c  mov   edx, dword ptr [rcx]
00393a1e  mov   ecx, edx
00393a20  and   ecx, 0xffffff
00393a26  cmp   ecx, dword ptr [rax + 0x20]  ; 边界 = [obj+0x20]
00393a29  jae   0x140393a41
00393a2b  mov   rax, qword ptr [rax + 0x18]  ; 表指针 = [obj+0x18]
00393a2f  add   rcx, rcx
00393a32  mov   rax, qword ptr [rax + rcx*8 + 8]  ; entry = [表 + idx*8 + 8]
00393a3c  cmp   dword ptr [rax + 8], edx     ; entry+8 == id 才算命中
00393a3f  je    0x140393a48
00393a41  mov   rax, qword ptr [rip + 0x2ec9e38]  ; <-- 全局 0x325d880(回退对象)
00393a48  ret
```

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
| 容器 vtable | `+0x588` | `0x8bbb53 lea rcx,[rdi+0x588]` |
| 数据指针 | `+0x590` | `0x1874701 mov rax,[rbx+0x590]`;`0x8cf9e0 mov rcx,[r14+8]`(容器基址+8) |
| 容量 | `+0x598` | `0x8cf8ef mov ecx,[rcx+0x10]`(容器基址+0x10) |
| 计数(dword) | `+0x59c` | `0x18746ee movsxd rax,[rbx+0x59c]`;`0x8cf8e8 movsxd rax,[rcx+0x14]` |

元素步长 **0x20**:插入侧 `0x8cf93e shl rdi, 5`(= 32),删除侧 `0x8bbc5d add rax, 0x20`。
元素布局(两处独立写入互证):`+0x00` vtable `0x24b5480`(`.rdata`),`+0x08` id(dword),
`+0x10` 距离(qword),`+0x18` 标志(byte)。边是**无向**的 —— `add` 在 `0x1874720..0x1874731`
连调两次 `0x8bbaa0`(self→other、other→self),`remove` 亦然。

### §1.4 增例程 `0x8bbaa0(rcx=self系统, rdx=另一系统)`

`.pdata` 单块 `0x8bbaa0..0x8bbbab`。要点:

- 距离 = 两个系统 `+8`/`+0x10` 的平方差再整数开方(`0x8bbaa0..0x8bbb2e`),写进元素 `+0x10`。
- `0x8bbb31 mov eax,[rsi+8]`(另一系统 id)写进 `[rsp+0x38]`(元素 `+8`);
  `0x8bbb42 lea rcx,[rip+0x1bf9937]` → 元素 vtable `0x24b5480` 写进 `[rsp+0x30]`。
- `0x8bbb4e cmp eax, dword ptr [rdi+8]` —— **自环跳过**:另一系统 id == self id 时直接跳插入。
- 插入:`0x8bbb53 lea rcx,[rdi+0x588]` + `0x8bbb5f mov edx,[rcx+0x14]` + `0x8bbb62 call 0x1408cf8d0`。
- 写副作用:`0x8bbb73 or byte ptr [rdi+0x137d],al`;`0x8bbb85 or dword ptr [rip+0x20b10dc],1`
  → **边集合脏标志全局 `0x296cc68`**;`0x8bbb94 mov qword ptr [rdi+0x5a0], rax`(缓存句柄)。

### §1.5 删例程 `0x8bbc20(rcx=self系统, rdx=&id)`

`.pdata` 被 MSVC 拆成 **7 个连续 RUNTIME_FUNCTION 块** `0x8bbc20..0x8bbc75..0x8bbcb4..
0x8bbccc..0x8bbd11..0x8bbd23..0x8bbd2d..0x8bbd8a`(逻辑范围
`0x8bbc20..0x8bbd8a`;**只看首块会得到错误的 end**,这是必须按链走 `.pdata` 的理由):

```
008bbc29  movsxd rax, dword ptr [rcx + 0x59c]  ; 计数
008bbc3f  mov    r11, qword ptr [rcx + 0x590]  ; 数据
008bbc51  cmp    dword ptr [rax + 8], r10d     ; 逐元素比 id
008bbc5d  add    rax, 0x20                     ; 步长 0x20
008bbca9  movsxd rax, dword ptr [rdi + 0x59c]  ; 命中后把末元素搬进命中槽
008bbd1d  mov    dword ptr [rdi + 0x59c], eax  ; 计数 -1
```

命中后按 `vfptr` 释放被删元素(`0x8bbcf7 call qword ptr [r8]`),再把末元素覆盖到命中位,
计数递减 —— 标准 swap-remove。**没有第二条存储路径**:`add` 与 `remove` 读写的是同一组
`+0x588/+0x590/+0x59c`。

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

- `0x34c9c3` 是同一段 push_back 形态但元素 **0x48** 字节(`lea rdi,[rbx+rbx*8]; lea rbx,[rax+rdi*8]`);
  `0x34cb33` 元素 **0x38** 字节(`imul rdi,rbx,0x38`)。步长不等 ⇒ 排除。
- `0x53163f movaps xmmword ptr [rsp+0x590],xmm6`(rsp 基址,栈保存帧)与
  `0x54d54d lea r11,[rsp+0x590]`(rsp 基址,栈展开)不是容器。基址是 rsp ⇒ 排除。
- `0x8bbaa0`/`0x8bbc20` 里的 `+0x590`/`+0x59c` 基址是 `rdi`/`rcx`,来源 = 入参(系统对象);
  两个 keyword 里的基址 `rbx` 来源 = 解析器返回值。**两条链的基址来源都钉在「系统对象」上**,
  与上面两组排除项不同源。

### §1.9 复现(真实读数)

探针 `add_remove_hyperlane_scan.py` 从字节里重读 52 个站点、与计划期逐字比对,任一不等即
不落判决字段并退出 1。干净 shell 实跑(命令与输出见 `[check] 全部读数与计划期一致`,EXIT=0):

```
resolver_rva        = 0x3939f0
edge_owner          = system_object(解析器返回) + 0x588
neighbor_vector_off = 0x590(容器基址 0x588)
neighbor_count_off  = 0x59c
insert_fn           = 0x8bbaa0(通用 push_back 0x8cf8d0)
remove_fn           = 0x8bbc20
```

六个字段与简报接口 {`resolver_rva, edge_owner, neighbor_vector_off, neighbor_count_off,
insert_fn, remove_fn`} 一一对应。
