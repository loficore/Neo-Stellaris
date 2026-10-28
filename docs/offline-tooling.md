# 离线 RE 工具目录与判读陷阱

本文件收录 `scripts/` 下**长期有效**的离线探测工具的完整判读说明:每条命令的输出、
它编码的 capstone/PE 陷阱、以及曾经导致错误结论的度量口径。`AGENTS.md` 只保留一行一条的索引,
用到哪个脚本时再来读这里。

结论本身(§17–§60)在三卷取证日志 `evidence/analysis/runtime_444_*.md`——§16–§23 在
`runtime_444_keyword_pipeline.md`,§24–§60 在 `runtime_444_c1_validation.md`;本文件只讲**怎么量**。

## 前置条件

**Binary**:`D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe` on the Windows host `Windows_Jiaolong`, copied to
`/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe` on Linux — 46,253,688 bytes, 4.4.4, sha256 `9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56`(2026-10-22 实测于本地拷贝;旧缩写串 `9242c40a…b1a56` 是同一条,与 `D:\` 原件一致)。
`scripts/rttibatch.py` / `scripts/cap.py` find it automatically (`NS_STELLARIS_EXE` overrides).
The `.i64` (705 MB) stays on Windows.

旧名 `PLAN.md` → 新落点 `docs/roadmap.md`(六段:目标与判据 / 授权门 / 阶段状态表 / 候选条线 / 仍生效的决策 / 新旧 § 映射);
`evidence/` 里指向 `PLAN.md` 的旧引用按不可变约定**不改写**,靠那份映射解读。

**Game data**: `/var/lofibass_ssd/data/stellaris/4.4.4/{common,events}` (2,186 files, copied 2026-09-29 from
`D:\SteamLibrary\steamapps\common\Stellaris\`) — scripted_effects, scripted_triggers, on_actions, events, defines, etc.

**Offline toolchain dependencies are pinned** in `scripts/requirements.txt` (capstone 5.0.7, pefile 2024.8.26,
unicorn 2.1.4). Only `emu_desc.py` needs unicorn, and its artifacts are checked in, so regenerating the oracle
is the step that requires it — `zig build test` does not.

**Host caveat**: 当前基线(2026-10-22 复测 `zig build test --summary all`)=
`Build Summary: 24/27 steps succeeded (1 failed); 314/314 tests passed`,裁定 **P15 把这一步记为绿**。
更早的 `24/27 …; 307/307` 与 `22/25 steps …; 296/296 tests passed` 都是历史数(逐条计数与增量出处在
`docs/scope-read-points.md` 的「计数」一节)。
那 1 个 failed 是 `exports.zig` 为 root 的 QuickJS 链接步,理由是 8 条 kernel32 undefined-symbol
(`CreateFileA`/`WriteFile`/`CloseHandle`/`GetModuleHandleA`)—— Windows API 在 Linux 上本来就没有,
**不是代码故障**;其余 2 步是它的传递失败(没跑到)。
旧的 GLIBC 措辞已**被实测作废**,不要再当现时约束引用:那一版说「两个链接 QuickJS 的步在这里根本启动不了
(`/lib64/libm.so.6: version GLIBC_2.35 not found`)」,而 2026-10-22 这次运行**没有** GLIBC 那条,QuickJS
的 C 是能编的、失败发生在链接符号解析。别把两个理由混成一个;GLIBC 的旧叙述留在
`evidence/analysis/build_pipeline_status.md` 与 `zig_test_coverage.md`(不可变,不改写)。
历史计数:`293/293`,until `effects/id_mapper.zig` and its 21 tests were retired,
then `272/272` at that time — see §29 of `runtime_444_c1_validation.md`;不要拿这两个旧数当现在的门限。

**当前基线(2026-10-29 `shot-hardening` 分支,`b88e500` 之后)**:
`zig build test --summary all` → `Build Summary: 29/29 steps succeeded; 656/656 tests passed`,退出码 **0** ——
(636 是 `f31f4cd` 之后那个数;`b88e500` 加了两条 `TrampolineRetireList` 测试,而 `detour.zig` 被编进
4 个 test root ⇒ +8。数涨不是回归,但引用旧数当门限会把绿读成红。)
(2026-10-26 那句 `599/599` 保留在下面作历史:它在 `78fd294` 上是真的,之后 world-state 与族外证人
两个窗口各加了测试,数字涨到 636 —— 围栏/测试只增不减,拿旧数当门限会把绿读成红。)
**failed 步归零**。上面 Host caveat 那句「1 个 failed 是环境事实」的判读**已被本次实施作废**:exports 根
在宿主 target 上不再引用 kernel32(comptime 守卫,本计划四次 shot `a48965e`/`92bfdf3`/`0b09863`/`78fd294`),
现在真跑;裁定 **P15 那条「这一步记为绿」自此不再需要**(P15 文本住在不入库的私有归档,此处不复述)。
上段的全部数字(`24/27; 314/314`、`22/25 … 296/296`、`293/293`/`272/272`、GLIBC 旧叙述)保留为历史读数,
追加不改写。这条基线的完整判读:

- **门的读法**:全绿时 `zig build test` **不打** Build Summary,`--summary all` 才看得见 `29/29` 那行。
  判据是**退出码 0 + `29/29 steps succeeded`**;**单看 `tests passed` 总数会误读** —— 一个 import 文件的
  test 在**每个**导入它的根里各计一次(实测:本计划往 `hooking/windows.zig` 加一条 test,总数
  `445 → 447`,+2)。总数账:`599 = 445(基线 13 个绿根) + 2(Task 1 新增一条在两个根各计一次) + 152(exports 根首次链接进总数)`。
- **exports 根现在收集并运行 152 条**,其中**净新跑 = 35** —— `src/dll/exports.zig` 11 +
  `src/dll/c2/handler.zig` 6 + `src/dll/scripted/keyword_registry.zig` 18(这三族只被 exports 根收);
  这 35 条里 **33 条的 test body 基线就写在文件里**(只是从没被执行),**2 条为本计划新写**(任务 2 的
  `exports.zig` 「DLL entry points are inert off Windows」、任务 3 的 `DllMain: DLL_PROCESS_ATTACH leaves
  engine_ptr untouched`)。其余 **116** 条基线就在别的根里跑、现被跨根重复计数,全部构成(从编出的
  测试二进制逐行数,不是推的):`hooking.detour` 42 + `shared.offsets` 16 + `quickjs.runtime` 17 +
  `quickjs.runtime.Runtime` 4 + `scripted.lookup_hook` 11 + `scripted.exec_hook` 9 + `c2.scope_probe` 7 +
  `c2.predicate_hook` 5 + `c2.vtable` 4 + `hooking.windows.ProtectGuard` 1 = **116**;另 **1** 条是本计划任务 1
  新写的(`152 = 35 + 116 + 1`)。**数 test 的口径陷阱**:`runtime.zig` 的 21 = 17 条文件级 + 4 条
  `pub const Runtime` 结构体内的 decl 级,只 `grep '^test '` 会数到 17 —— 那 4 条是缩进的,别把这差当成对不上账。
  旧失败符号 8 个是 `CreateFileA`/`WriteFile`/`CloseHandle`/`GetModuleHandleA`/
  `VirtualProtect`/`VirtualFree`/`GetCurrentProcess`/`FlushInstructionCache`(此前括号只列了 4 个,是旧句的
  半份名单,现在只剩历史读法)。
- **已知残留缺口 —— 至今零执行 29 条**(`src/dll/api/bridge.zig` 19 + `src/dll/effects/handler.zig` 5 +
  `src/dll/triggers/handler.zig` 5):成因**不是链接,是可达性** —— `main.initializeQuickJS` 无调用点
  (Zig 惰性分析不把 `bridge` 拉进 exports 根)、那两个 handler 在整个 `src/` 树零 importer;结构旁证:
  `bridge.zig:31-32` 按路径引入 gamestate/scope,而它们用命名模块 `@import("offsets")`,exports 根没有
  `addImport("offsets")` —— 若 bridge 真在闭包里,该根会编译失败而非绿。这 29 条**本计划没有填**,
  基线句不许把它们含混成「都跑起来了」。
- **残留的 kernel32 引用点(守卫覆盖面之外,不是漏网)**:`hooking/windows.zig` 的 `moduleFunction`
  (`GetModuleHandleW`)与 `allocNear`(`VirtualAlloc` ×2)**没有** comptime 守卫,宿主根仍然能链接,是因为
  **调用方先折叠**:c2 那三个 `install()`(`scope_probe:167`/`predicate_hook:164`/`live_probe:147`)第一行是
  `if (!is_windows) return error.Unsupported;`;scripted 那两个(`lookup_hook.install:263`、`exec_hook.installWith:357`)
  自己**不带**守卫,折叠发生在**上一层出口** `LookupHookInstall:305` / `ExecHookInstall:433` 的
  `if (!is_windows) return -2;`;`detour.installHookArmed` 没有任何 test 触达 —— Zig 只对可达函数体发射,死支路
  里的引用不进符号表。读这条时别去找「四个 install() 第一行都是 error.Unsupported」,那句话是错的(本行初稿就这么错过,
  复审抓出来了):两族折叠的**层次**和**哨兵值**都不同。`extern "kernel32"` 的**声明**全部原样保留(`CreateThread` 从未被引用;
  `ReadProcessMemory`/`VirtualAlloc`/`GetModuleHandleW` 同在声明块里却不在旧失败名单里,正是「引用而非声明」
  这条判据的证据)。给这两个包装器补守卫属于第二道门,本计划不做;模块头注释已点名这个例外。
- **`-Dtest-target` 已删除**(commit `78fd294`,`build.zig` +1/−6):删后 `zig build test
  -Dtest-target=x86_64-windows-gnu` 的表现是**明确报错,不是静默忽略** —— zig 0.16.0 打
  `error: invalid option: -Dtest-target`,退出码 **1**(对照探针 `-Dnonexistent-option-xyz=1` 同退出码 1)。
  cross-target 路线就此没有入口;`c2_diag_test.zig` 那个 `{d}` for `*anyopaque` 编译错误**不修** —— 它的
  入口随选项一起没了,记下来是为了下一个人别把它当新 bug。`evidence/analysis/build_pipeline_status.md`
  `:11`/`:36` 的旧运行方式记录按取证约定原样保留(追加不改写),现已过期。
- **出货 DLL 的整文件 sha256 不是代码身份 —— 本计划实测推翻了旧句**:任务 5 现场量到
  `652ee10bbd7b51450a28dd28489fc83057517b3b6b46143ae0d164357c51b895`,终审修复轮在**同一份源码**上(只把
  `hooking/windows.zig` 的模块头注释改窄、行号因此整体下移)重链,得到 `c24efef06630cbfc90a82f95dcfc2f74ec5d9ec91098af78976452f15be83980`。
  两个整文件逐字节 diff **只有 10 个字节**:PE 文件头 `TimeDateStamp`(offset `0x80`)1 字节 + `.buildid` 段
  9 字节;`.text`/`.rdata`/`.data`/`.pdata` 四段**完全相同**。⇒ **每次重新链接都换整文件 sha,代码一个字节没动也换**;
  `652ee10b…` 与 `c24efef0…` 是同一份出货代码的两个链接时刻,**不是两次代码变更**。
  方向性:AGENTS.md 约束 8 那句「sha 不变」只在**一个方向**可用 —— sha 不变 ⇒ 可能命中缓存(实测 `touch` 源码后重建 sha 不变,缓存命中);
  **sha 变了 ⇏ 代码变了**。上一句原本给的替代判据(「认出货代码用代码段 sha」)**在合并前被自己的实测推翻了一半,见下一条**;
  这条里那四个数按当时的目录量,保留为读数:`.text 86ee85aa68ca9dba7d1d06417ef3622a11e3c343ba53ee52fe6ff6d826a68051`、
  `.rdata 4b4a58ca4ca16c787666d7914fbaa340be423e63e56a3625da9b077a8c4165c0`、
  `.data 4c79ac53e9af0e1130de74ddd5a6ba1f7dee95c0d1c769c0e35e4d7f113ba2e4`、
  `.pdata 408b83f005efa2453c19c7ce2c76dbcc6d8a56c722ef85608ecdba1e79f33863`。
- **代码段 sha 同样不是可移植的出货身份 —— 因为 DLL 把构建目录烧进了 `.rdata`**(2026-10-26 合并前实测,三个构建):
  一个构建里 `ns-worktrees` 这段路径出现 **57 次,全部落在 `.rdata`**;目录名长度直接进入段布局 —— 长名
  `fix-issue-18-win32-link` 那次 `.rdata` 的 `SizeOfRawData` = **817,152**,两个短名目录(`ln-a-2188219`、
  `triage-merge-19`)都是 **816,640**;`.text` 里是 RIP-relative 位移,跟着一起变。⇒ **同一份 `src/` 换个目录构建,四段 sha 全不一样**:
  `e900a1d` @ `fix-issue-18-win32-link` = `.text 86ee85aa…`(复现上一条)、`.rdata b539a18b08be9e1581a60cb3f68db0762d309da701479650ecb82b3ad063d5dc`、
  `.data bacf833bda4d8e62791f8997c340fe18eb0d7575785a32e896b51016a1dd043c`、`.pdata ff48da43cf404b9676e35151c18d0624c1026fd48a0f9743955c74d709ef2e9f`;
  同一棵 `src/`(与 main 合并,main 侧零 `src/` 改动)@ `triage-merge-19` = `.text 6464918300428bab4c8248ebec8453bbc3aa2b5e25cf8e5fb3ef832f28c959ec`、
  `.rdata 4951e17cf5c2c8d7ae2349b3c58cebc262c1c557c5df42c7de6ad9f19e72ba71`、`.data 4cdbeffff58cc7af529e5ca054eeb88defe396aaaca6870963bae4d8413da5a4`、
  `.pdata 023e9ecd3779e7228d245bd36d2fc266ec3988d62fb41d791b9c9834bac6d8df`。
  ⇒ 上一条那四个数里 **`.rdata`/`.data`/`.pdata` 三个在 HEAD 的同目录构建下不复现**(`.text` 复现),按本条机制它们的出处是**另一个构建目录**
  (当时未记目录,这正是本条要补的口径),三个数保留为历史读数、不再当判据。
  **认出货代码用 import 表**(8 个 kernel32 符号齐全、`MISSING: []`;复测于 `c24efef0…` 那次链接,并在 `triage-merge-19` 这次合并态构建上
  独立复现 8/8);段 sha 最多当**同一目录内**的链接指纹,且必须连目录名一起记。
  同批一条对照把「改注释会不会挪段」这个问号关掉:**不会**。两份**目录名等长**的工作树(`ln-a-2188219`、`ln-b-db251df`,
  源文件绝对路径同为 80 字符)分别 checkout `2188219` 与 `db251df`(两者只差 `windows.zig` 模块头注释、净 **+2 行**)做全新构建,
  四段 sha 逐条相同(`.text b67221e1…`、`.rdata 560189c4…`、`.data 5473bbe0…`、`.pdata f95676e1…`),整文件 sha 才不同
  (`76de1beec2ef080b3b9dc4a684ba5c87e29654308c739e09e21838fd4e513bbf` vs `a8815d2f2f5fb5bd601470d5a016f7022455cad6bbdf3cfee574fcd1ea2a9429`)。
  对 AGENTS.md 约束 8 的完整方向:**sha 不变 ⇒ 缓存命中可用;sha 变 ⇏ 代码变;要按 sha 认码,必须先固定构建目录**。旧句里 §46 的 `77c0c35e…c11ad0`(全值留在 `evidence/analysis/runtime_444_c1_validation.md`
  原句,未动)与分支基线 `df50f3e1f34f38a90850febc49808c599b35ceebb0570edbbda7c25a11ecfcdd`(全值,自 commit `f541c2a`
  这同一条 bullet 的前身分留档于此)之差,
  因此**不能再用整文件 sha 归因**(它们可能只是不同链接时刻);三个数保留为历史读数,追加不改写。
  本计划对「守卫只剪宿主测试根、没剪出货代码」的证明**一直靠 import 表那一条**,不靠 sha —— 现在有了理由。

## 基础:PE + capstone,不需要 IDA

**Static RE runs offline here, no IDA**: `scripts/cap.py` (PE + capstone, rip operands) and `scripts/rttibatch.py`
(PE census) reproduced the full CEffect map locally — 1,805/1,805 rows byte-identical to `evidence/xrefs/ceffect_vtable_map_4_4_4.txt`.
Neither needs a license, a running process, or a paused game.

### `scripts/cap.py` / `scripts/rttibatch.py`

PE 解析 + capstone 反汇编(rip 操作数已解析)与 RTTI/vtable 普查。
`rttibatch.py --effects` 产出 `evidence/xrefs/ceffect_vtable_map_4_4_4.txt`。

**`--all-vtables` —— 不过滤的那一张(`evidence/xrefs/vtable_candidates_all_4_4_4.txt`)**:
`python3 scripts/rttibatch.py --all-vtables [--min-run 3]`。判据**只看形状** —— `.rdata` 里每个 8-对齐位置,
只要从它起连续 ≥ `min_run` 个 qword 落在 `.text`,就产一行,**绝不读 `RVA_BASE_EXECUTE`**;而且**一个 run 里的
每个起点都单独成行**(§17 那张下限表的表首正是这种中途起点,只报极大 run 的开头就会把它们全丢掉)。
每行带 `run=` 与前三个槽的 RVA 原值。4.4.4 上 `min-run=3` 是 **172,296 行**(≈14 MB 明文,gzip 后 1.2 MB)。

**判读陷阱(这条是 §17 那句「覆写了 Execute 的类一个都不在」的直接解药,也是最容易读过头的地方):
「形状过」不等于「是 vtable」,更不等于「是 CEffect 家族」。** 函数指针数组、`switch` 跳表、虚表片段、
以及任何「连续几个代码地址」的静态数据都会过这道形状判据 —— 172,296 与 1,805 之间那 16 万多的差**不是**
「发现了 16 万个新类」。往下筛只有两个字段可用:**`run=` 长度**与 **`slot1` 原值**(slot1 == base Execute
`0x1D08520` 正好把 §14 那张 1,805 的下限集取回来,这也是 `test_the_floor_map_is_a_subset_of_the_unfiltered_candidate_set`
钉住的关系);除此之外没有别的静态滤网,所以任何「这张表是谁」的结论都得另找证据(名字池、行为、实机)。

**`--who-tables <rva[,rva]> [--candidates PATH]` / `--who-lea <rva>` —— 两张集合的离线 join(§57)**:
`slot_hits()` 按候选的 `vtable_rva` **回到镜像里重读前 8 槽**逐个比对(不是只看产物带出的 `slot0..slot2`),
`lea_sites_to()` 把 `rip_refs()` 那条 modrm 判定推广到**整个 `.text`**,返回指令起始 RVA。接口一律 **RVA**
(与 `AGENTS.md` 索引、下限图、候选集同口径),命令行里不出现带 image base 的数。`--candidates` 默认读
`vtable_candidates_all_4_4_4.txt`,所以不必在 shot 宿主机上重跑 `all_vtables`。

**判读陷阱:`--who-tables` 那张「命中 N 张表」的表,不能拿来证明「引擎复制了表」。** 两个独立原因,
每一个都足以让这条推断作废(§57 就是在核这一条):
① **候选集对同一段指针数组产出多个重叠起点**(`rttibatch.py --all-vtables` 的候选枚举为了让下限集成为子集必须这样构造),所以行数永远
大于物理槽地址数 —— 4.4.4 上实测 **7,867 行 / 7,832 个表首 / 992 个物理槽**;
② **靶子若是共用实现,命中数就正比于「继承它的兄弟类个数」,与复制无关** —— `0x3AFD30`(donor 表 slot[1]
的 Execute 覆写)在镜像里以静态 qword 出现 **538** 次,`0x3B01A0` **454** 次。
收紧到「前四槽与目标表逐槽相等」把 7,832 压到 5,这一步是有用的枚举,但**仍分不出「另一份表」与
「同基类未覆写前四槽的兄弟类」** —— 两者在字节上就是同一串。要判身份,得问运行时 `[self+0]`(§57 的下一次 shot)。
`--who-lea` 另有两条边界:它只认 `48/4C 8D|8B mod=00 rm=101` 这一种编码(不认绝对立即数寻址,也不认
`.rdata` 里的静态持有),而**站点数 0 不等于没人用** —— `0x3B01A0` 就是 0 站点,因为它只以静态槽值存在。

### `scripts/disrva.py <start_rva> [<count>|<length>|--end=<rva>|--len=<n>]`

**Any RVA range, disassembled offline** — annotates every
rip-relative operand with the RVA it resolves to; this is what pinned the descriptor ctors' store order (§20).

**第二个参数的口径（§30 现场踩过）**:裸数字**不是**结束 RVA —— `a > 0xFF` 时脚本算的是 `end = start + a`,
所以 `disrva.py 0x1D092C0 0x1D09330` 会去反汇编 `0x1D092C0..0x3A125F0`(约 30 MB `.text`)。
要按函数边界读,先 `pdata.py <rva>` 取区间,再传**指令条数**(`a <= 0xFF`)或传**长度** `end-start`。
本函数边界一律以 `.pdata` 为准,不要靠 `int3` 填充猜结尾。

**`--end=<rva>` / `--len=<n>` 是自 §59.9 起才有的显式形式**(§59.9 那条「往上定帧构造点」的零 shot 路线要按真边界取区间),
**取证卷里旧命令一律按旧语义复现** —— 上面那个 `>0xFF` 启发式没有被改写,只是搬进了可测的纯函数 `parse_range`;
裸数字口径、头一行 `; <exe>  <sec> RVA 0x…  (N insns)` 的条数、rip 注解写法全部不变
(`scripts/test_disrva.py` 钉语义;影子副本基准用**已冻结的改动前修订** `git show 02eb551:scripts/disrva.py`(= 本分支第一次动 `disrva.py` 之前的那个提交,`git log --oneline -1 488b1fc^` 与它相同)逐字节钉输出 —— 意图是「重跑旧实现,输出与改动前逐字节相同」;**基准不写 `HEAD`**,合并之后 `git show HEAD:scripts/disrva.py` 就是新实现自己,自比自恒等,这条钉会静默失效)。
`--end=` 的第二段就是结束 RVA(不含),`--len=` 是字节长度;两者与裸数字一样**不猜**:结束 RVA 低于起始、
非十六进制、负数、`--flag` 缺少数值、未知 flag —— **任何不可判 = 拒绝**,一行 `[disrva] …` 进 stderr 并退出 2。

**`import disrva` 没有副作用**:旧版本在导入时就读 46 MB 镜像、候选链全不存在就 `sys.exit`,现在读镜像是懒加载,
`resolve_exe()` 返回 `str | None` 而不是退出 —— 所以别的离线工具可以直接 import
`parse_range`/`resolve_exe` 而不必先有 game data。只有 CLI 在候选链全落空时才报
`[disrva] 没有可读的 stellaris.exe 拷贝(设 NS_STELLARIS_EXE);候选链 <列表>` 并退出 2。

### `scripts/emu_desc.py` — the oracle

**The oracle, offline**: runs the engine's **own** descriptor writers
(`0x1D15270` static, `0x1D152D0` dynamic) under unicorn — image mapped at its preferred base, only memcpy
(`0x2187AC0`) and the reserve (`0x1704B0`) emulated host-side — over all 9,863 table entries
(`python3 scripts/emu_desc.py oracle`). Output: `evidence/xrefs/descriptor_oracle_4_4_4.tsv` plus
`src/dll/scripted/keyword_registry_golden.zig` (56 vectors the Zig builder is tested against).
This is how §18's "byte-for-byte identical" claim became a measurement: **9,863/9,863 agree, 0 divergences**.

## 离线重问实机 artifact(读已入库产物,不读 exe、不起进程、不需要 shot)

### `scripts/scope_reclassify.py [--tsv PATH] [--floor PATH] [--all PATH] [--json PATH]`

**把同一批 scope 候选问两张 vtable 集**:§56 那发只读采样 shot 留下的
`evidence/logs/scope_probe_v2_4_4_4.tsv` 的 99 条 `object` 行,同时对着 1,805 条下限集
(`ceffect_vtable_map_4_4_4.txt`,**import `c2_scope_probe.load_vtable_map` 复用**,不重写解析)和
172,296 条形状集(`vtable_candidates_all_4_4_4.txt`,`rttibatch.py --all-vtables`)分四桶:
`floor_hits` / `new_only_hits`(只有新集看得见)/ `still_no` / `undecidable_no_rva`。
四桶互斥且和为 `total`,由 `scripts/test_scope_reclassify.py` 钉住。产物:stdout 七行计数
(含 **`floor set` / `shape set` 两个输入集大小**)+ `--json` 全量(含 `new_rows` 每行的 `slot1` 与
run-length,以及 `input_sets`)。**形状集解析出 0 行就抛错**(`load_candidate_map` 拒绝返回空集):
`new_only_hits=0` 与「这份文件我读不懂」在计数里长得一模一样,而 §56.9 那一版差点把前者当结论 ——
行语法(`slot0 0x…`,两列)一旦错一格,172,296 行会被全部静默跳过。两个集的大小打在读数旁边,
就是为了让「0」永远带着它的分母。

**它不读 exe**,所以不受 `R-env` 约束、不需要 `NS_STELLARIS_EXE`;需要分节普查(判一个 RVA 落在
`.text`/`.rdata`/`.data`)时那是另一件事 —— 本次用的是
`scripts/scratch/2026-10_scope_shot/ns_scope_ptr_shape.py`(一次性探针,不是维护接口)。

**判读陷阱 1(本节实测)**:`still_no` 多**不等于**候选不是对象。99 条里 83 条能解出 RVA,而它们的
`vptr_rva` 分节普查是 `.text` 64 / `.rdata` 14 / `.data` 3 / 镜像外 2 —— 代码 RVA 永远不可能在任何
vtable 集合里(两张集都只扫 `.rdata`),所以「新集一条都没加」在这个层是**恒真**,不是结论。
往下筛之前先问:取的是哪一格?`vptr_rva` 是 `[[root+off]]`(多读一层),候选自己那一格是 `ptr`。

**判读陷阱 2**:「不过滤」只指**不按 `slot[1]` 过滤**,新集仍然只扫 `.rdata`,而且它按形状产出
**每一个** run 起点(下限集必须是它的子集,这是构造要求),所以一张已知表的**内部偏移**也会命中。
`.data` 里的 vtable、以及中途偏移,都是「无法判定」而不是「新集看到的类」。

## 族外边界离线 join(`scripts/join_family_boundary.py`,读 artifact **也**读 exe 拷贝)

### `scripts/join_family_boundary.py [rva_hex ...]`

**用法**:无参时跑段①②③(段③ 的对象 = 段① 的缺席清单);带 RVA 参数时只跑段③,对象就是这些 RVA
(定靶时用它点名量一个候选的三口径读数)。**退出码**:0 = 读完(含「预期没达成」,读数归读数);
2 = exe 拷贝找不到或输入表读不到(那是环境问题,不是判据问题)。exe 路径走 `disrva.resolve_exe()`
的 `NS_STELLARIS_EXE` 候选链。

**它回答的问题只有一个**:§13 那七把各 2,090 次的 exec shim,在不在 CEffect 家族的五张 vtable 里?
三段口径全部照抄仓库既有读法,脚本不发明新判据:

- 段①:`evidence/xrefs/exec_frame_callers_4_4_4.tsv` 的 28 个 `func_start` 里,哪些出现在
  `evidence/xrefs/ceffect_vtable_map_4_4_4.txt` 的 `ExecuteActual(slot2)` 列(= 该函数确实是某张 vtable 的
  slot[2]);缺席的那批才是「静态集合里没登记的候选」。
- 段②:§13 七把 shim 的 vtable 与家族五张 `0x24B1D98/0x24EAAC0/0x25F4440/0x2606F00/0x2606FE0` 求交集 ——
  期望空集。
- 段③:对缺席候选(或点名给的 RVA)跑 §62.2 的三条独立口径:① `.rdata` 内该地址的 8 对齐 LE-qword 命中数;
  ② 每个命中的前一槽(`hit-8`)是否 `0x1d08520`;③ 命中回退 `0x10` 当 vtable 基址,是否落在 map 的 1,805 个基址里。

**口径边界(写进 §71 时逐字带上)**:**map 是下限,不是全量** —— 「不在 map」只能写「不在这份静态集合里」,
不能写「族外没有另一份表」。`join_family_boundary` 的 `join` 指三张表的连接,不是 SQL 的 JOIN。
map 与 census 里的地址一律是 **RVA**;只有扫 `.rdata` 字节时才加 `BASE`(`0x140000000`)。

**它只判「形状」,不数调用次数**:逐把计数是 `execspy.py` 那条 census 通道的活(§74);本工具答的是
「哪些函数是某张 vtable 的 slot[2]」这一**身份**问题。两者的数不互相替代。

**旧路径**:本文件 2026-10-28 从 `scripts/scratch/2026-10_live_window_shim_witness/join_family_boundary.py`
提升上来(**同 basename**);**原件冻结留档、字节不动** —— 取证卷 §71 的正文引的是那条路径,而 `evidence/`
是 append-only(移走或改名会让取证记录指向不存在的文件)。副本与原件的差别是**两处路径**(仓库根少上两层,
见下 `_REPO`;docstring 的「跑法」那一行)外加两行说明文字(本段旧路径记述与 `_REPO` 旁的注释);
判据逻辑逐字未动。

## 站点离线反解(`scripts/exec_frame_sites.py`,读 artifact **也**读 exe 拷贝)

### `scripts/exec_frame_sites.py --probe <tsv> [--census <tsv>] [--out <tsv>]`

**重读 exe 字节、按字节反解 shot 记录的真实 call site —— 不是 `-5` 估值。** 背景在 §59.7 与下面
`c2_scope_probe` 一节的 CALLERS 口径:shot 记的是**返回 RVA**,`E8 rel32` 是 5 B,而每一次 vtable 槽
派发(`call qword ptr [rax+8]`)只有 3 B;把 `ret-5` 当站点会把 mem 形状的点画进前一条指令中间,
census join 落空,`func=-` 于是被误读成「没人调用」。`c2_scope_probe.py` 的 caller 行键已降回返回 RVA,本工具是「精确
反解」的另一半。**exe 候选链 import `disrva.resolve_exe`**(同一份 `NS_STELLARIS_EXE` 口径,不复制
第二份路径表,也不需要镜像基址 —— 全部地址运算在 RVA 空间对消)。

**用法**:`python3 scripts/exec_frame_sites.py --probe evidence/logs/scope_probe_v4_4_4_4.tsv`
(`--census` 默认 `evidence/xrefs/exec_frame_callers_4_4_4.tsv`,`--out` 默认
`evidence/xrefs/exec_frame_sites_4_4_4.tsv`)。caller 行两代形状都认:新版 `c2_scope_probe.py` 起 detail 带 `ret=`
直接用;v4 及更早键是估值,`ret = key + 5` 且计入汇总的 `assumed` 计数 —— **assumed 行读出的
site/func/census 一律以反解结果为准,估值只是对账**。

**候选边界怎么枚举**(这是判读的全部依据,不是「取最短/取最长」):回看窗 `[ret-16, ret)` 内对
**每一个字节偏移**起解码 capstone 第一条指令,只保留「结束地址恰好落在返回点」且
`mnemonic ∈ {call, jmp}` 的边界。候选 >1 ⇒ `form=ambiguous`、`site=None` —— 歧义是真实的字节重叠
(例:REX 前缀让 `48 FF 50 08` 与 `FF 50 08` 都恰好结束于同一点),不替他选;候选 0 ⇒ `form=none`;
唯一候选判 `form`:`E8`→`rel32`(若目标首字节是 `EB`/`E9` 跳板 →`thunk`),`FF /2`→`mem`(寄存器
间接 `FF D0` 同档,`insn` 列给真实反汇编文本),唯一一条 `jmp` 边界 →`thunk`。

**join**:`func_start`/`func_end` 来自 `.pdata`(延迟 import `pdata.func_of`;import/查找失败是**诊断
退出**,不是静默 `func=-`),键是**反解出的真站点**;站点不可判(ambiguous/none)时退回用返回 RVA
查函数边界 —— 返回地址与调用点同属一个 RUNTIME_FUNCTION,函数归属仍是 datum。
`census_origin`/`site_in_census` **只认真站点**:没 join 上就写 0,不解释原因(解释留给取证卷)。

**拒绝语义**:没有可读的 exe 拷贝 → 一行 `[exec_frame_sites] …` stderr + 退出码 2(无 traceback);
回看窗缺任何一个字节 → `SiteDecodeError` → 同样诊断退出 —— **读不出来 ≠ 窗口里没有**,绝不把它
写成 `form=none`。

**判读陷阱(本节)**:
- `site_in_census=0` **不是矛盾,是待办**:普查表是 §53 按当时判据切的,没覆盖的站点本就不在表里
  (v4 的 `0x1c4369e → site 0x1c4369b`(`form=mem`)正是这种;§59.7 末句)。
- `form=none` 的全局判读在文末 `c2_scope_probe` 一节的**判读陷阱 11**:它只说明返回 RVA 前 16 字节
  内没有 call/jmp 边界,**不等于没人调用**。
- 本工具读的是**磁盘拷贝**;游戏版本换了、而产物里的返回 RVA 来自别的版本字节,解出来的 form/site
  不代表当时跑的进程 —— 换版本先对 `anchors_4_4_4.md` 重锚。

## 调用关系与引用扫描

### `scripts/fastcalls.py <rva> [--top N]`

**Who-calls-what, offline**: buckets every direct call/jmp to an RVA by its
`.pdata` function and labels each bucket with the message strings and `__FILE__` tail that function references
(`evidence/xrefs/callers_<rva>_buckets.tsv`). It matches the `E8 rel32` / `FF 15` / `FF 25` **encodings over raw
bytes** instead of decoding 37 MB, so it finishes in ~3 s where a full capstone linear scan hadn't finished in
10+ minutes. Two capstone/PE gotchas it encodes: rip-relative lives in `op.mem.base == X86_REG_RIP` (**not**
`op.reg`, which is `X86_REG_INVALID` for memory operands and silently matches nothing), and this binary's
`__FILE__` strings are full backslash build paths, so filename regexes must match the tail.

### `scripts/riprefs.py <rva>... [--verify]`

**Two more offline searches, for the things `fastcalls` structurally cannot find** (§23):
who reads/writes a **data global**. A rip operand is fully
determined by its encoding (`mod=00, rm=101` + `disp32`), so a byte scan plus arithmetic answers it in
~5 s; `find_refs.py` decodes 37 MB for the same list and needs ~15 min. `--verify` re-decodes each hit
aligned to its `.pdata` start, because a byte match can land mid-instruction.

### `scripts/createsites.py [--gap N]`

who calls a function pointer that **never appears as an immediate**
(e.g. `class_info.create`). Shape-based: `mov r?,[r?+0x28]` within N insns of `call qword ptr [r?+8]`, in
a function that also touches `[r?+0x20]`. Decode must be aligned per `.pdata` function — a linear window
starting mid-instruction resynchronises by luck and had earlier "found" 190 sites in one function.

### `scripts/vtable.py <data_rva> [--slots N --first --callers]`

vtable slots with `.pdata` bounds and the
strings each references. It does **not** prove extent (MSVC merges vtables back to back; §22.5), and §24.4
caught the failure going *both* ways: against `0x2641B38` it stops listing at `+0x78` because `0x18879C0`
is not a `.pdata` start, while `+0x80`..`+0xa8` all hold `.text` addresses. Extents truncate as well as
overrun; only a call site proves a slot is reached.

### `scripts/vptrslots.py [census.tsv]`

across all 1,605 keyword `create`s, where the factory stores the
addresses it materialises, split by instruction: `lea rax,[rip+X]` publishes **X** (a vtable), while
`mov rax,[rip+X]` copies the **value** at global X (not a vtable). Confusing the two is how §22.3 came to
claim a universal `[obj+0]`/`[obj+8]` two-vptr shape; full per-class dump in
`evidence/xrefs/vptr_publish_slots_4_4_4.txt`.

### `scripts/thunkarrays.py`

产出 `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`(3,900 条记录)——keyword→behaviour
静态绑定的机器可读转储(§17)。

## 语料交叉验证

### `scripts/tokencorpus.py [corpus_root]`

A5: joins the replayed descriptor oracle against the
`.rdata` registration census (id agreement) and against the real shipped scripts in `common/`+`events/`
(coverage), and classifies every non-token head word by the mechanism that resolves it
(`evidence/xrefs/token_corpus_crosscheck_4_4_4.tsv`). Two method traps it encodes: `(\w+)\s*=` is not a
head token but *every* LHS including operand values (it "found" 9,858/9,863 descriptors in use — an
artifact of measuring the wrong relation), and a block-only `WORD = {` regex understates the other way,
because scalar triggers (`has_crisis_perk = <x>`) are not blocks. So `HEAD` classifies and `ANYEQ` counts
usage. Findings: 1,609/1,609 keyword ids agree (§25.1), token lookup is **case-insensitive** (§25.5),
and the `count_*`/`any_*` iterator keywords exist in the image only as **two separate strings** that a
name builder concatenates at runtime (§25.4).

## 离线存档分析(C4)

`scripts/save_hypergraph.py` 与 `scripts/chokepoint_scores.py` 读的是**玩家的 `.sav` 存档**,不是
`stellaris.exe` —— 所以它们不受 `NS_STELLARIS_EXE` 影响,也不需要进程、注入或 dispatch。存档本身是
用户数据,**不进 git**;`evidence/` 只记路径、大小、sha256 与派生统计,表与存档 sha 必须成对出现。

### `scripts/save_hypergraph.py <save.sav> --edges <out.tsv> [--stats]`

`.sav` 是 **ZIP**,本次两条 entry:`gamestate`(27,281,802 字节,**文本** Clausewitz,首行
`version="Pegasus v4.4.4"`)与 `meta`(365 字节)。工具解 ZIP、读 `gamestate`、用 UTF-8 +
`errors="replace"` 解码,取顶层 `galactic_object` 下每个系统块的 `hyperlane={ { to=… length=… } … }`,
输出无向边表(列序 `a\tb\tlength`,去重成 `a<b`,按 `(a,b)` 升序)。`--stats` 把计数按 `key=value`
逐行打 stdout;本存档实测:`systems=787`、`undirected_edges=1217`、`components=1`、`isolates=0`、
`self_loops=0`、`duplicate_entries=8`、`asymmetric_edges=0`、`conflicting_edges=0`、
`replacement_chars=0`(完整输出在 `evidence/logs/c4_chokepoint_offline_4_4_4.log`)。

**判读陷阱:**
1. **文本存档限定。** 同一账号下别的 `.sav` 可能是二进制 Clausewitz;`read_gamestate` 以「不是 ZIP /
   ZIP 里没有 `gamestate`」或「解码后前 4096 字符出现 NUL」为硬错误退出 2,不把二进制喂给解析器。
2. **解码不是无损的。** `errors="replace"` 让一个坏字节不至于杀掉整张图,但 `replacement_chars > 0`
   意味着名字里有被替换的字符。图仍可能正确(边只依赖数字),不要把它读成「存档坏了」,也不要
   静默当 0。
3. **重复键与匿名块必须保留。** `planet=…` 会重复,`hyperlane` 内层是无键的 `{ to=… }`;普通 dict
   会丢前者、把后者当非法输入。解析器的 `Block.entries` 是 `(key, value)` 列表,`key=None` 即匿名块;
   值列表里的裸 token(`required_dlcs = { "Horizon Signal" }`)同样以 `key=None` 的标量保留。
4. **不对称边与长度冲突是硬错误,不是统计项。** 每个系统自己列出出边,`a→b` 与 `b→a` 应成对且长度
   相同;缺一半、或两个方向给的长度不同,一律退出 2 并打印样本。自环与**同长**的重复声明只计数
   (`self_loops`、`duplicate_entries`)并从图里去掉 —— 本轮实测到 8 条重复声明,这是计数后继续的
   口径,不是「静默去重」。
5. **`galactic_object` 必须唯一。** 顶层出现 0 个或 2 个以上同名块,退出 2:选第一个等于悄悄改图。
6. **0 条边是硬错误。** 空块、或只有孤立系统的图在去掉自环后没有任何无向边时,退出 2 ——
   「0 个星系」不是正常结论,不写空表、不返回 0。
7. **`to=` 的全文件正则计数会高估。** 计划探针按行首 `to=<数字>` 数出 4,397 条,那是文件里所有
   `to=` 键;工具只数 `galactic_object` 系统块内、`hyperlane` 匿名块里的 `to`,本轮 2,442 条
   (= 1,217 对 + 8 条重复)。两个数字回答的不是同一个问题。
8. **孤立系统只计数,不进边表。** `isolates` 是 stats 里的计数,CLI 会往 stderr 打一行警告;
   边表只含 `a<b` 的边,所以下游分数表的 `n` 只覆盖有边的系统,孤立系统**没有行**,分母也
   不把它们算进去。本存档 `isolates=0`,这条只影响别的存档。
9. **整份 `gamestate` 都会建树。** 解析器先把整个文本建成 `Block` 树再取 `galactic_object`;
   本存档 27,281,802 字节实测跑通,更大的后期存档耗时与峰值内存**未测** —— 这是边界,不是承诺。
10. **id 是存档局部的。** 这里的 `system_id` 只对这份存档(与它的 sha256)有意义;换一局、换一版,
    同一个数字指向另一个星系。表不能当跨战役常量用。

### `scripts/chokepoint_scores.py <edges.tsv> --out <scores.tsv> [--top N]`

只读边表(无表头;第一行全是数字就当数据),算 `degree`、无向无权 Brandes `betweenness`、Tarjan
割点/桥,输出固定七列:
`system_id\tdegree\tbetweenness\tbetweenness_norm\tscore\tis_articulation\tis_bridge_endpoint`。
数据行按 `system_id` 升序,浮点 `.6f`,`--top N` 按 `(score, betweenness, -system_id)` 降序打前 N 行。
`betweenness_norm = b / ((n-1)(n-2)/2)`(n>2),`score = round(1000 * betweenness_norm)`。

**判读陷阱:**
1. **无向图只计一次。** Brandes 标准实现最后 `b[v] /= 2`,所以一条最短路只算一对端点;把无向图
   当有向图跑会得到两倍分数。
2. **`score` 是全局归一化的相对排序,不是绝对阈值。** 分母用全图 `n`,而 betweenness 在分量内
   计算;断开的图里小分量的高分点会被压低。本存档实测 `components=1`,这里两者一致 ——
   换图先看 stats 再读分。
3. **`betweenness` 与 `betweenness_norm` 不同分母。** 前者按无序对计数后的原始值,后者的分母是
   `(n-1)(n-2)/2`;`score` 只由后者算。比较两轮分数时比 `betweenness_norm`,不要比原始值。
4. **割点/桥是布尔,不是权重。** `is_bridge_endpoint=1` 只说明这个点挨着至少一条桥;`degree=2` 的
   点也可能是割点。
5. **空输入退出 2。** 空边表 / 坏行 / 自环 / 重复边 / 参数错误都是退出 2 —— 「0 个星系」不是正常结论。
6. **输出的确定性是契约。** 同一输入两次 `--out` 应逐字节相等(测试钉住);行序与邻接遍历都已
   排序,输入行序不影响分数 —— 若有差异,先查输入内容(重复边是硬错误),不要先怀疑排序。

**把产物拿回 Linux 的传输陷阱:** 本轮 `scp` 下载 1.9 MB 存档会被主机重置,14 KB 的边表与 27 KB 的
分数表也一样。最后用的是主机侧 `gzip` + base64、按 1,024 字符块走 SSH、本地逐块 `base64 -d >>` 并
去掉 PowerShell 带回的 `\r`,再用 `sha256sum` 与主机 `Get-FileHash` 对账。存档留在主机,只回传小产物;
小文件能直接 `scp` 时不用这套。

### `scripts/chokepoints_emit.py --tsv PATH --save-sha SHA [--out PATH] [--check]`

把 `chokepoint_scores.py` 的七列表编译成 DLL 侧常量 `src/dll/c2/chokepoint_table.zig`:
`SCORE_COUNT`、`TIER1_MIN=100`、`TIER2_MIN=200`、`SAVE_SHA256` 与 787 项 `[u16]` 分数表。
`system_id` 是**存档局部**的(见上一节陷阱 10),所以生成的表与 save sha 必须成对出现;换一局、
换版本都要重新生成并把 `--save-sha` 换成新存档的 sha256。`--check` 不写文件,现有产物与 TSV
渲染结果不同(或文件缺失)时退出 **2**;根目录 `just chokepoints-check` 与 `just check` 都跑它。
生成器自己复现 `zig fmt` 的多行列对齐,所以 `zig fmt --check src/dll/c2/chokepoint_table.zig`
必须为 0 —— 若不为 0,先修生成器的排版,不要在产物上手改(下次 `--out` 会覆盖)。

## C1 硬门

### `scripts/c1_preflight.py --name NAME [--name ...] [--db effects|triggers]`

**the hard gate before C1**, offline and read-only. `0x1D13270` is GetOrAddToken and §25.5 measured that
its lookup case-folds, so `eax` cannot tell a mint from a collision: a name like `Add_Modifier` would
return `add_modifier`'s `10104` and our insert would **take over an official keyword**. The script FAILs on
an exact or case-folded hit over all 9,863 descriptor names plus the 1,610 registered keyword names,
checks §20's leading-char rule, warns on mixed case, and prints the predicted first id
(`max static 18817 + 1 = 18818`) with its reading rule — larger is normal (§19 lazy accessors keep minting
during start-up), smaller means the collision this check exists for. Exit code 0 = clear.

## live 侧:需要运行中的进程

以下工具**不满足离线前提**——它们 attach 到正在运行的 `stellaris.exe`,读的是活内存。按
`scripts/README.md` 的两条判据(只读 exe 拷贝 = 工具,需要进程 = 探针)它们是**探针**;
但因为它们是维护中的接口,仍留在 `scripts/` 顶层。

### `scripts/fridadis.py` + `scripts/dis.js` — 线性反汇编 live 镜像

对**正在运行的**游戏做一次只读线性反汇编,让 live 列表与离线取证在同一条指令上相遇。

**用法**(两个分支,同一个 attach):
```
python C:/ns/fridadis.py <rva> <instructions>        # 线性:从 rva 反 N 条
python C:/ns/fridadis.py --chain <rva> off,off,…     # 指针链:沿偏移读活指针再反汇编
```
在 Windows 本机跑(`frida.get_local_device()`),两个文件必须先成对上传到 `C:\ns\`。

**它是探针,不是离线工具**:需要运行中的 `stellaris.exe`;缺进程时 `fridadis.py` 在
`next(...)` 那行抛 `StopIteration`——那是"游戏没在跑"的签名,不是工具坏了,回去补环境前置,
不要去改那一行。名字必须全等 `stellaris.exe`(靠 `.lower()` 忽略大小写,别的 launcher 名不算)。

**read-only 自证**:两个文件的头注各自写着"Read-only (no Interceptor, no Memory.patchCode),
so it is safe against an unpaused game"。评审要复核这句话仍成立——`Interceptor`/`patchCode`/
`writeByteArray`/`writePointer`/`Memory.protect` 这些符号只应出现在注释行,一条代码行都不能有。
`dis.js` 渲染 hex 列用的是 `readByteArray`(**读**解码后的字节 span,不是写),没有新增能力。

**硬编码路径 = 上传契约**:`fridadis.py` 里 `JS = r'C:\ns\dis.js'` 钉死,所以上传目标目录**只能**
是 `C:\ns\`;传到别处会得到 `FileNotFoundError`,那不是工具的错。`fridadis.py` 与 `dis.js` 刻意
异名(见本节末尾的配对说明),`.py`↔`.js` 必须同目录成对上传、成对核 sha。

**判读陷阱**:
1. **渲染差异 + 条数口径都不是分歧**。`fridadis.py` 把第二个参数按 **10 进制**读(`40` = 40 条),
   而 `scripts/disrva.py` 按 **16 进制**读(`40` 会被读成 0x40=64 条)。要和 live 那 40 条比,离线必须写
   `0x28`。两侧行形也不同:live 第一列是**距起始 rva 的字节偏移**(`+0x00XX`,不是 RVA),mnemonic 不补宽;
   离线第一列是**绝对 RVA**,mnemonic 补宽到 7。所以判据是空白宽容的 `grep -E`,**不是**逐字 diff。
2. **`--chain` 读的是活指针,不是镜像字节**——那是运行期状态,会随存档变。别把 `--chain` 的输出混进
   线性 disasm 产物,会污染判读。
3. `StopIteration` 见上,是缺进程不是缺功能。

**交叉验证的正确姿势**:与 `scripts/disrva.py` **同 RVA** 比,用 `grep -E` 数命中,**不比 diff**;
"先核版本再核指令"——live 与离线对不上时第一假设是"跑的不是这一份 build"(exe 身份见本文件"前置条件"),
不是"capstone 错了"。第一次实机跑通记录见 `evidence/logs/fridadis_b3_4_4_4.log`,产物见
`evidence/disasm/fridadis_live_0x1D08520.c`。同样的活从**文件**读(不需要进程/游戏)用 `scripts/cap.py`。

## live 侧:§44 的只读线程状态通道

`scripts/c2_init_threadstate.py` + `scripts/c2_harness.py:capture_thread_state` 是**一套**,
两个零成本对照 `scripts/c2_control_cpuwatch.py` / `scripts/c2_control_suspendcap.py` 是它的
判读前置。三个都不写内存、不 hook、不 `FreeLibrary`;`SuspendThread`→`GetThreadContext`→
`ResumeThread` 的顺序由 `finally` 保证不悬空挂起。

**用法**:三个都要在 Windows 侧跑,且都是 scp `c2_harness.py` + 该脚本到 `C:\temp\`(裸名 import,P5)后
`python C:/temp/<name>.py`;`c2_init_threadstate.py` 额外要先有 §42 那份 DLL(它会核 sha256,不是那份字节就拒绝),
两个对照不需要 DLL,只要一个正在跑的**未触碰**游戏(`c2_control_cpuwatch.py [watch_ms] [every_ms]`,默认 20 s)。

**判读陷阱**:
1. **`SuspendThread gle=5` 有两种意思,单看它无法区分**。句柄缺权限和「线程已经退出」报的是同一个
   错误码 —— 把它们分开的是 `scripts/scratch/2026-10_threadhandle_matrix/`(4/4 格:活线程两种句柄都读得到,
   退出线程两种句柄都 gle=5)。所以读到 gle=5 先怀疑后者,别去改 `OpenThread` 的权限位。
2. **`pr_user_us` 一动不动,可能是仪器坏了**。用 `c2_control_cpuwatch.py` 打未触碰的游戏对照:它 20 s 前进
   约 12.8 s user ⇒ 计数器是活的,那句「冻结」才是真的停。
3. **线程状态通道给的是 teardown 的形状,不是执行的形状**。内存单调下降 + 80 ms 起就 suspend 不掉,
   这个组合的意思是进程已经开始终止 —— §42 把同一种序列读成「6.9 s 零分配段在 QuickJS 代码内」,那条读法已撤回。
4. 名字里的 `threadstate` 不是能力声明:它**只读 context 与 times**,拿不到栈,也设不了线程。

## §45 修复循环的两个维护工具(从 `scratch/2026-10_abortexit/` 提升)

**新旧名映射(本仓库的改名约定,同上面 `PLAN.md` 那条)**:
`scripts/scratch/2026-10_abortexit/dll_abort_repro.py` → **`scripts/c2_selfabort_repro.py`**;
`scripts/scratch/2026-10_abortexit/ubsan_site.py` → **`scripts/dll_ubsan_site.py`**。
两个 scratch 原件**字节不动**(`evidence/logs/c2_selfabort_4_4_4.log` 按 basename 记了出处,§45 的
log 还逐字引了它们的输出),提升是**复制**不是移动。两处都留了旧名一句。

### `scripts/dll_ubsan_site.py [dll] (site <类型名子串> | func <vma>)`

无符号、无 debug 段的产物里,把 UBSan panic 钉到源文件行号:只读 DLL 文件,用 `.rdata`/`.data`
里的 `TypeMismatchData` 记录(文件名、行、列、类型描述器名字)+ `.pdata`(x64 异常目录)的
`{begin, end}` 函数区间。第一个参数**不是 `site`/`func` 就是 DLL 路径**(按小写比较模式名;
所以 `C:\temp\S43_new.DLL` 这种大写扩展名、以及没有扩展名的 scp 文件名都是路径 —— 旧规则
「以 `.dll` 结尾才算路径」会把它们当成模式,于是**分析仓库默认的产物却打印出你给的那个参数**,
一个没有报错的错答案)。没有路径参数时才落到仓库自己构建的
`zig-out/bin/stellaris_quickjs.dll`,按**本文件位置**解析,不是按 cwd);`image_base` 从镜像自己的
optional header 读,没有任何地址是写死的 —— 换一份产物就把 RVA 重算一遍。

**退出码有三种意思,调用方必须能分开**:0 = 读到了且有匹配;1 = 读到了但**没有**匹配 —— 这是
一个结论,不是故障。**1 有两种不同的意思,别把它们并成一句话**:「该类型名零个检查点 / `func`
的地址不在任何 `.pdata` 函数区间里」和「命中了函数、但**该函数代码不引用任何 `TypeMismatchData` 记录**」
是两件事(工具分别打 `rva 0x… is not inside any .pdata function entry` 和
`this function's code references no TypeMismatchData record (other UBSan record
kinds are not decoded)`),后者的含义是"这一帧没有
可归因的捕获",不是"这里没有 UBSan";**2 = 调用本身是错的,所以对产物什么都没下结论** ——
工具没能读到产物(路径不存在、不可读、截断、非 PE32+),**或 `func` 拿到的数低于镜像基址**
(那是 panic 栈打的裸 RVA,不是 vma;本批(§47 前置)加的口径护栏,打一行 stderr 并把该传的
`image_base + rva` 原样回显)。修复循环会拿 `c2_selfabort_repro.py` 送来的任意文件名调它,
把 2 误读成 1 就是「这份产物没有检查点」的假结论 —— 两条 exit-1 消息与 2 的措辞故意不同形,
护栏就是为了不让"调用写错了"长得像"结论"。**本批围栏实测**:`scripts/test_c2_harness.py`
**134 passed**(133 + 新增 1 条),`scripts/test_scripts_layout.py` **23 passed**。
**§47 终评修复轮**(2026-10-22)`parse` 补上 section 越界检查后,截断输入真的走 2 了(此前
`func` 会拿空 `.pdata` 答 1);新增 1 条截断测试,`test_c2_harness.py` 变为 **135 passed**,
`test_pe_disrva.py` 变为 **5 passed**。

```
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll site JSMallocBlockHeader
python3 scripts/dll_ubsan_site.py zig-out/bin/stellaris_quickjs.dll func 0x18000bd9b
```

`site JSMallocBlockHeader`(2026-10-22 实测于当前产物 `77c0c35e…c11ad0`)=
**141** 个检查点,其中 `quickjs.c:1494:12` 恰好 1 条;`func 0x18000bd9b` = 持有该地址的函数
`rva 0xbd70..0xbdf3`(**131 bytes**),引用记录 `quickjs.c:1494:12 member_access
type='JSMallocBlockHeader'`,`record_rva=0x5ab430 loaded_at=0x18000bd8c` —— 与 §45.3 记的同一条。
同一函数还 `call 0x499cc0`(`__ubsan_handle_pointer_overflow`),带的是 `0x5ab450` 处的 16 字节
`PointerOverflowData`(同为 `:1494:12`);它**不在**上面这条记录的输出里 —— 见判读陷阱 7。

**§48 修复后的当前产物**:`cutils.h` 引入 `<stddef.h>` 让 `offsetof` 用 builtin,`:1494:12` 的
`TypeMismatchData` 记录消失(`site JSMallocBlockHeader` 141→133、该行 0 条),因此
`func 0x18000bd9b` 在新产物上不再有记录可打;`js_rc` 本体仍在,只剩 `:1494:12` 的
`PointerOverflowData`(工具不解码),区间也随重链移动到 `rva 0xbba0..0xbc01`(97 字节)。
`scripts/test_pe_disrva.py` 的 `trap_span()` 就是从这条 SourceLocation 反查当前区间,不钉常量。
上面 141/131 字节那组数字属于 §47 产物 `77c0c35e…`,要复现请读基线字节(缓存副本)。

**判读陷阱**:
1. **`func` 打印的是 `.pdata` 区间和该区间加载了哪些记录,不是链接期函数名。** 帧归属靠的是
   区间 + 记录引用;要说"这是 `__JS_NewAtomInit`",得去读那几行 C 本身(§45.3 就是这么做的)。
2. **"地址不在任何区间内"证明不了任何事 —— 这份解析是不完整的。** §45.4 记的 **3,042** 条区间是
   **当时那版解析器**在同一份字节(`.text` 0x4c8b86,§42/§45 产物)上的输出,不是那份产物的属性;
   现在的 `runtime_functions` 在同一份字节上出 **4,818** 条,同一份工具跑当前产物(`.text` 0x4c9be6)
   出 **4,824** 条(现场可复测)—— 差 6 条的是字节,差 1,776 条的是解析器版本。两个数都覆盖不了
   镜像里的函数,所以"没命中"既可能是地址在数据/填充里,也可能只是 `.pdata` 这条解析没读全 —— 分不清。
3. **panic 栈每帧打印的是 `ip − 1`**,即调用指令**前一字节**,所以那个数值本身既不是出错指令也不是
   调用点。直接把它传给 `func` 没问题(`.pdata` 查找是闭区间 `begin <= rva < end`),但别把打印值
   当成指令地址来解读。
4. **和冻结原件比计数要先去重。** 原件的 `.rdata`/`.data` 扫描没有按段定界(从段起始一路扫到 EOF),
   而这份产物的记录**全部**落在 `.data` 里,于是每个记录被 `.rdata` 那趟再过一遍:原件
   `site JSMallocBlockHeader` 打 **282** 行,其实是 **141** 个不同记录(成对共享同一个
   `record_rva`)。提升版把每趟扫描定到该段自己的 raw 字节 ⇒ 141 行,与 §45.3 记的数一致。
   **记录的集合本身没变**,只变了重复。
5. **同一段扫描的上界要按「读多少」算,不是按「步长」算。** 记录之间隔 32 字节,但被读的字段
   只有 26 字节(`struct.calcsize("<QIIQBB")`),原件的上界 `end - 32` 因此**够不着**落在某段最后
   32 字节里那条完全可读的记录。提升版改成 `end - 26 + 1`。当前产物上两个界给出**逐条相同的
   13,693 条记录**(`site JSMallocBlockHeader` 仍是 141,`quickjs.c:1494:12` 仍恰好 1 条),所以这条
   不改变任何已记录的计数 —— 它是给下一次链接准备的,届时布局器未必不把记录放进那段尾部。
6. **记录行不带 `[ubsan_site]` 前缀,所以按前缀过滤会把证据丢掉。** `site`(`:261`)与 `func`
   (`:290`)的 header 行带前缀,而每条记录行是**两个空格**开头(分别在 `:264`/`:304` 打印)—— `grep -F '[ubsan_site]'`
   (或转义 `\[ubsan_site\]`)只留下 header。本批(§47 前置)对一次真实输出(`func 0x1800055f5`)实测 = 7 行
   (2 行 header + 5 行记录),过滤后**只剩 2 行**,5 条记录全丢。更糟的是另一种写法:
   不加转义的 `grep '[ubsan_site]'` 是**字符类**(任一字符 u/b/s/a/n/_/i/t/e),同一份
   7 行输出**一行都不会被滤掉** —— 看起来"过滤生效了、什么都没丢",其实过滤根本没起作用。
   两种写法都别拿来取证据:要记录行就 `grep '^  '` 或 `grep 'quickjs\.c:'`(同一份输出各实测
   5 行)。
7. **`#0x…` 标注只能和 `TypeMismatchData` 记录的 `record_rva=` 比。** `func`/`site` 只解码
   `TypeMismatchData` 的 kind 3–11(`scripts/dll_ubsan_site.py:93`,`:201` 还要求 `log_align <= 7`),
   其它 UBSan 记录种类**不解码** —— 例如 `PointerOverflowData` 是 16 字节、只有 `SourceLocation`,
   没有类型描述器与 kind 字节,所以它没有 `record_rva=` 行,"no record" ≠ "no handler"。实例:
   `js_rc` 的 131 字节函数有两次 handler 调用(`0x498170`/`0x5ab430` 的
   `member_access type='JSMallocBlockHeader'` 与 `0x499cc0`/`0x5ab450` 的
   `PointerOverflowData`),`func` 只打出前一条;`evidence/disasm/js_rc_trap_77c0c35e.md` 两次都列。
   所以一个函数"恰好一条记录"只意味着**恰好一条可解码的 `TypeMismatchData`**,不是只有一次
   UBSan handler 调用。
8. **报告里的 `pointer == 0` 可能是编译期常量,不是被检查的那个运行时指针。** §47 的实例:fallback
   `offsetof`(`cutils.h:43-45` 的 `&((type *)0)->field`)把一次**空成员访问**编译进 `container_of`
   (`quickjs.c:1494`),于是 `type_mismatch` 的指针操作数是字面 0;handler 文本里的 "null pointer"
   因此**不是**「运行时指针为 0」的观测,allocator 形状或记录器数据都不能拿来判它。

### `scripts/c2_selfabort_repro.py <dll_path>`(Windows 侧;§45 的自检器)

把出货字节装进**本脚本自己拥有的**子 python,按实机那次 shot 的门序跑 `C2Sanity` → `C2DiagQJSInto`,
零游戏、零注入、零 dispatch:子进程若在没人碰它的情况下以退出码 3 死掉、且 witness 文本与实机逐字
相同,"host 死了"这件事就与 `stellaris.exe` 无关。修复循环的形状(§45.4):**每改一次 QuickJS/
allocator 就重跑这一条命令**,不需要第二次 shot。

```
scp scripts/c2_selfabort_repro.py Windows_Jiaolong:C:/temp/     # 单文件,无裸名 import 依赖
python C:/temp/c2_selfabort_repro.py C:/temp/<新文件名>.dll      # 退出码 0=复现到 abort 签名,1=没有,2=路径没给/不存在
```

**重建陷阱(§48 实测)**:只改头文件(`libs/quickjs/*.h`)时,已有 Zig 缓存的 `zig build` 可能把 C
编译报成 `cached` 并留下旧字节 —— 此时 scp 出去的是**旧 DLL**,复现器仍显示 abort,会被误读成
「修复无效」。改完头文件先核 `zig build --summary all` 里 `compile lib stellaris_quickjs` 的状态
行与 `sha256sum zig-out/bin/stellaris_quickjs.dll` 是否真的变了;没变就换一个 `--cache-dir` 重建。

关键行(子进程的逐字 echo,父进程的带 `[repro] ` 前缀,`VERDICT` 永远是最后一行):
`BASE`、`LOGADDR`、`RECORDER ok|absent`、`SANITY`、`WITNESS '<g_diag_log>'`、
`MFREC <seq> <watch|post> '<渲染>'`、`SURVIVED rc=<n>`、`LOG '<调用方 buffer>'`、`[repro] VERDICT: …`。

**为什么 `MFREC` 是一条读取线程,而不是 `C2DiagQJSInto` 之后的一次 dump**(这条设计**不要**被
"简化"掉,§45 就是理由):子进程的主线程是在 `C2DiagQJSInto` **内部**abort 的 —— witness 停在
`new_rt MmMmMm`,`SURVIVED rc=` 从来不打印。所以调用之后再读永远轮不到,Task 3 将没有记录器数据可判。
读取线程每 ~2 ms 调一次 `C2DiagMfRecordsInto`,只在渲染**变了**时才发一行,自己封顶 400 次,并且
在门序跑起来**之前**启动。调用后那一次**保留**(`post` 标签、无条件打印):Task 4 修好之后调用会返回,
那一行是 Task 4 验收要读的。代价写明:在一个正死的进程里多一个线程是扰动 —— 于是"子进程活了"
在缺陷仍在时是 Task 3 的**停下来报告**条件,不是通过。

**判读陷阱**:
1. **`VERDICT` 的两半都吃重**:`returncode == 3` **且** stdout 里没有 `SURVIVED`。只有 3 不算 ——
   harness 早就警告过被进程终止杀掉的线程会把进程状态当自己的退出码报回来(§44);`0xC0000409`
   (`os.abort()` 的 fastfail)也不是 `abort()` 的 3(§45.1 量的就是这一对)。
2. **`MFREC` 行里 `filled` 是 `_` 的那一行是竞态伪影或"没走到出口",不是分配器行为。** 渲染层对
   「槽在快照中途被重写」的行就是画成未填充形(`<kind>_`,kind 保持 `M`/`F`/`R`/`_`),并把指针换成
   16 个短横(`ptr=----------------`),所以**哨兵 `0x1` 与假零永远不会以指针的形式出现在文本里**;
   看到 `_` 不要读成"分配返回了 NULL"——真的返回 NULL 是 `filled=x` 且 `ptr=0`,那是另一种形状。
3. **`Fx size=` 是被释放那块内存**自己记下的 size(在 entry 时从块头读的),不是请求大小。**只有
   `M`/`R`(malloc/realloc 两个请求)的 `size` 才是请求**;Task 3 的判定表读 `size == 0` 时**只看
   `M`/`R`**。把 `F` 混进去的错法很具体:`free(NULL)` 合法地记 `size=0 ptr=0`(没有任何块被释放),
   它会被读成"发生过一次零大小的分配请求"——那是另一个事实,而计划的判据要的正是后者。
   (`quickjs_wrapper.c` 的 `mf_rec_free_size` 就是为这条区分写的。)
4. **渲染按字面 token 解析,不要按列。** 每行是
   `"<kind><filled> size=<十六进制,不补零> ptr=<十六进制,不补零> st=<正好 12 位十六进制>\n"`,
   8 行、oldest→newest;两个十六进制列**不定宽**,所以只能用 `" size="`/`" ptr="`/`" st="` 切。
5. **`RECORDER absent`**:被测产物里没有 `C2DiagMfRecordsInto` 这个导出(比 §45 更早的字节)。
   这**不是**工具坏了 —— 那条通道确实不存在,`MFREC` 一行也不会有,`WITNESS`/`VERDICT` 照常可用。
   导出地址按名字从注入那份的导出表解析(P10),所以工具不需要任何 RVA。
6. `SANITY` 必须是 42;不是 42 时后面看到的一切都不属于那条门序(和实机同样的一句话)。
7. **退出码 1 有两种意思,工具自己会说是哪一种**:真的没自杀(有 `BASE`、没死在 3),**或**子进程
   压根没把 DLL 装进来(平台不对 / 路径不对 / 装载失败 —— 于是没有 `BASE` 行)。后者打的是
   `VERDICT: inconclusive`,它对"这份产物会不会自杀"**什么都没证明**,不要当成阴性结果读
   (判据是纯函数 `child_loaded_the_dll`,120 s 超时也走同一条 `inconclusive` 形状)。

### 实机点名 shot 的上线前置（两条，§67 踩过；对 `c2_exec_probe.py` / `c2_scope_probe.py` / `c2_donor_probe.py` / `c2_witness_probe.py` / `c2_shim_probe.py` 这些 shot 工具通用）

1. **上线证明 = 覆盖 + 哈希对账，不是「远端有这个文件」**。`ren`(以及 `Copy-Item` 不带 `-Force`)在
   目标已存在时**静默失败**，长度照样非 0 ⇒ 「远端有文件且有长度」证明不了上线的是本场字节。正确动作：
   `Copy-Item -Force` 之后 `Get-FileHash`(或 `certutil -hashfile`)取远端 sha，与本地 `zig-out/bin/`
   产物的 sha256 逐字对上，才允许执行 shot；对不上一律停手，因为 #meta 里那个 `dll_sha256=` 只是出处、
   不做相等断言(每次重链都换)。整文件 sha 相同也不代表代码身份相同，反过来也一样 —— 这道门防的是
   「把上一场那份旧 DLL 注入进去」。
2. **argv 里的 DLL 必须是绝对路径**。ssh argv 写相对名(`sqjs_c4.dll`)时，目标进程 `LoadLibraryA`
   按**游戏自己的 cwd** 解析，返回 NULL，驱动在任何注入之前拒掉(退出码 1、`nothing was injected`)，
   install 额度未耗但读数全无。`.cmd` 与手写命令都要钉成 `C:\temp\sqjs_c4.dll`。

### `scripts/c2_exec_probe.py [dll]` — C4 执行路径实机一次 shot

把 C1 注册的 effect token 走完 C4 执行链:谓词 detour 把实例的 `[obj+0]` 换成 DLL vtable,
base-Execute 探针合成**一次** instantiate,slot[1] 经 `C2ExecCall` 进固定 JS 脚本,脚本返回哨兵
`1504`。读的是两组统计:`C2ExecStatsInto`(C 桥:`armed/token/js_calls/js_ok/js_err/mismatch/
last_rc/last_value`)与 `C2ExecProbeStatsInto`(探针与谓词:`calls/fired/ctx_skip/invalid/
pred_patched/chain/verified`)。两个 buffer 都是**有界轮询**(1 s 间隔、120 s 上限),判读取 `C2ExecDisarm` **之前**的 live 快照
(`Disarm` 会把 C 桥的 `token` 清零,清理后的快照不可判),轮询中间值仍不看。

**一次 shot 一个进程**:`C1Run`/`C2Init`/`C2ExecInstall`/`C2ExecProbeInstall` 每个都只派发一次,重跑必须
重开游戏。清理段(`finally`)顺序固定:先 `C2ExecProbeUninstall` 让探针 inert,再
`C2ExecProbeVerify`(0 = base-Execute 字节已还原),`SETTLE_S` 之后 `C2ExecDisarm`(`-1` = C 桥锁忙,
最多重试 5 次)。任何一步报 `-6`/非 0 都**绝不 `FreeLibrary`**。

**verdict 判读表**(`classify`,缺失键按 0):

| verdict | 条件 | 意思 |
|---|---|---|
| `no_fire` | `fired == 0` | 120 s 内没抓到可用调用 —— **环境结论,不是代码结论**:加载一个跑着的战役并取消暂停,重开进程再跑 |
| `ctx_skip_only` | `fired >= 1`、`js_calls == 0`、`ctx_skip > 0`、`invalid == 0` | 每次调用都带 lexer 哨兵 `[ctx+0x38]==0xb`,instantiate 被拒 |
| `fired_no_js` | `fired >= 1`、`js_calls == 0`、其余 | instantiate 发了但没走到 JS:实例没经过 patch 后的谓词/vtable 链,或 C 桥已 disarm |
| `ok` | `fired >= 1`、`js_ok >= 1`、`pred_patched >= 1`、无 `js_err`/`mismatch` | 链路成立;还会断言 `token == C1EffectId()`、`last_value == 1504`、`chain == 0` |
| `error` | 其余 | 链跑了但 JS 没给哨兵:看 `js_err`(脚本/异常)与 `mismatch`(到达 JS 的 token 不对) |

`no_fire` 报出来时先查环境(战役是否在跑、是否暂停),不要去改探针。**宿主死了先跑 §45 的两个
离线工具**(`scripts/c2_selfabort_repro.py` + `scripts/dll_ubsan_site.py`)排除我们自己的产物再谈别的。

### `scripts/c2_scope_probe.py [dll]` — C4 执行帧只读取样

`src/dll/c2/scope_probe.zig` 在 base Execute `0x1D08520` 上挂**只读** detour:每 512 次调用采样一次
(`calls & 511 == 0`),记录真实 `arg2`(执行帧)的 8 个 qword、`[self+0]` 的 vtable RVA、`[self+8]` 的
token id、`@returnAddress()` 的**返回 RVA**(记的是调用指令的下一条,不是调用点本身 —— 读法见下面 CALLERS
一段的口径),以及派发点上的 `r8`/`r9` 两个 scratch
槽(布局 v2 起,`Entry` = 120 字节)。**函数体一律转发原函数**,不改寄存器、不改内存、不改控制流。
`r8`/`r9` 记的是**值**,不是它们指向的内存 —— 一切解引用都发生在驱动侧的 `ReadProcessMemory`,采样器本身
不解引用任何二级指针。

驱动随后对**四个根**做进程外解引用:`self`、`[ctx+0x10]` 的 helper、`r8`、`r9`;每个根读 8 个 qword,
每个像指针的 qword 再读它指向处的首 qword,减 `exe_base` 得 RVA,拿去 `--vtables`
(默认 `evidence/xrefs/ceffect_vtable_map_4_4_4.txt`,1,805 个)做命中判定。**跟读预算按根类型各自给**
(每源 8 个不同地址,四源合计仍是 32)—— 共用一个预算会让排在后面的源必然是 0 行,见下面陷阱 5。
每个候选做**两次独立查表**:`known` 查 `[ptr]` 的 vptr(成员指向已知类的对象),`member_vtable` 查
`ptr` 本身是不是一个已知 vtable 地址(root+off 直接放着一张 vtable = 多重继承子对象头,说的是 root
自己的类);两者是两件事,后者**故意不喂给 `classify()`**。RVA 一律界在 `[exe_base, exe_base+SizeOfImage)`
(`SizeOfImage` 从活进程 PE 头读:`e_lfanew` 在 `+0x3C`,`SizeOfImage` 在 NT 头 `+0x50`),界外不产生 RVA。
**这条取代了旧判据**:
`X=[ctx+0x30] → S=[X+8] → id=[S+8] / obj=[S+0x20]` 那条链已由 c1_validation **§53.3 第二次 shot 证伪**
(`+0x30` 不属于 0x20 字节的帧,读到的「id/object」是 `add rsp,0x28` 一类指令字节),链仍然照旧跟、照旧写进
TSV,但**不再进任何 verdict**。

读的是 7 个导出 + `C2Sanity`:`C2ScopeProbeLayout`(5 个 u32:entry `120` / stats `56` / ring `256` /
mask `511` / version `2`)、`C2ScopeProbeReset`(装之前先清统计)、`C2ScopeProbeInstall`、
`C2ScopeProbeStatsInto`、`C2ScopeProbeDrainInto`(环形记录,最老在前)、`C2ScopeProbeUninstall`、
`C2ScopeProbeVerify`。**layout 任一字段漂了就打 `LAYOUT_DRIFT` 且不装** —— 驱动与 DLL 的解码契约断了,
后面的字节都不能读。**拿 104 字节的旧 DLL 配 v2 驱动(或反过来)一定会漂**,这不是巧合,是这条判据在生效:
按 104 解 120 会让每条记录串进下一条,读出一堆「看着像指针的垃圾」。

```
python3 scripts/c2_scope_probe.py [dll] [--poll-s 120] [--settle-s 2] \
        [--out C:/temp/c4_scope_probe.tsv] [--census ...] [--id-names ...] [--vtables ...]
```

`--vtables` 指向的那份表**必须在 shot 宿主机上存在**(Windows 侧要上传,见「前置条件」),表缺失或解析出 0 条时
脚本在**注入之前**就退出:判据挂在一个空集合上,那次 shot 无论怎么打都只会得到 `no_scope_candidate`。

轮询一直采样到 `--poll-s` 截止(不是拿到第一个样本就停),环形记录保留最后 256 条;
`--poll-s` 太短只会让样本变稀,不会让判读变快。

**一次 shot 一个进程**:`C2ScopeProbeInstall` 每个进程只派发一次,`exec_hook` 已被占用时返回 `-2`(单 detour
约束),**不重试** —— 看到 `-2` 换一个新游戏进程,不要在同进程里绕。其余安装码:`-3` 模块未找到、
`-4` 该地址已被别的 detour 占据、`-5` 序言不匹配、`-6` patch 太宽、`-1` 其他安装失败。清理段(`finally`)顺序固定:
`C2ScopeProbeUninstall` → `C2ScopeProbeVerify`(0 = 引擎字节已还原)→ 等 `--settle-s` → 断言 host 存活。
`Verify` 非 0 时打 `RESTORE_INCOMPLETE DO_NOT_FREELIBRARY`,**放弃该进程**,绝不 `FreeLibrary`
(只有本次 install 真的返回过 0 才这样判;本次根本没装上时,verify 读到 `-1`/`-3` 属正常,
驱动打 `verify=<n> (not installed this run)`)。
卸载走的是仓库共用的 detour 原语(`detour.zig` 的 `removeHook`):`VirtualProtect` 把 16 字节 patch
逐字节写回,**不暂停线程、也不检查有没有线程正处在那段字节里**。这是 §52 那次 shot 同样继承的残余竞态,
驱动侧造不出「静默窗口」(跑着的战役每秒数千次调用);host 恰在清理瞬间死掉时,先归因于 detour
卸载而不是采样器,并按 §45 排除我们自己的产物。

**点名门**:这是实机工具,按 `docs/roadmap.md` 的授权表,派发前必须有**本次会话内的点名**;
通用历史授权(「仅限于游戏调试相关」)不算。没有点名时只跑纯函数测试。

**verdict 判读表**(`classify`,固定顺序):

| verdict | 条件 | 意思 |
|---|---|---|
| `no_calls` | `calls == 0` | 轮询窗口内没有 base-Execute 调用 —— **环境结论,不是代码结论**:加载一个跑着的战役并取消暂停,重开进程再跑 |
| `no_samples` | `samples == 0` | 有调用但 1/512 门没触发;唯一手段是更长的 `--poll-s`,本次什么都没采到 |
| `all_invalid` | `valid == 0` | 每个样本的 `self`/`ctx` 都不可信,一帧没记;环境/调用形状结论,换新进程再试 |
| `lexer_only` | `lexer > 0` 且 `lexer == valid` | 全部有效样本都带 lexer 哨兵 `[ctx+0x38]==0xb`(§52 那条路径),**不能**回答「真实执行帧是哪个对象」 |
| `no_scope_candidate` | `known_vtable_hits == 0` | 四个根下没有任何 qword 指向「vptr 在那 1,805 个已知 vtable 内」的对象。这是**有界的代码结论**,见下面判读陷阱 1 |
| `scope_candidate` | 其余 | 至少一个 qword 命中已知 vtable 集合;TSV 的 `object` 行指名是哪个根、哪个偏移、匹配到哪个 slot2 实体。这**仍不证明**它是 `CEventScope` |

`scope_candidate` 之外一律退出码 1。`no_calls`/`no_samples`/`all_invalid`/`lexer_only` 四条一律先按**环境**读
(战役是否在跑、有没有取消暂停、进程是不是新进程),不要读成代码结论。链里的 `id` 是 **keyword token id**,
永远不是 system id;名字只在 `--id-names`(默认 `evidence/xrefs/descriptor_oracle_4_4_4.tsv`)里查得到时填,
查不到就留 `-`,不猜。`CALLERS` 的 `func`/`origin` 来自 Task 1 的调用点普查(`--census`,默认
`evidence/xrefs/exec_frame_callers_4_4_4.tsv`);Windows 侧没有这两份表时两列退化为 `-`,离线再 join。
**CALLERS 行的口径:返回 RVA ≠ 站点**(§59 读圈子的根源,这次修的是产物的声称):行键与 `ret=` 就是
返回 RVA 本身,`est_site=` 是按「这条 call 是 `E8 rel32`(5 B)」给出的**估值** `caller_rva - 5`
(`caller_site_estimate`)。虚调用 `call qword ptr [rax+8]` 只有 3 B,`-5` 会把站点画进前一条指令中间,
census 于是 join 不上而报 `func=-` —— 那读法是「估值不是它的站点」,**不是**「没人调用」。join 仍走估值
(这是估值的唯一用途);返回 RVA 不足 5 字节时不估值,写 `est_site=-`,绝不因一个被记录的值让 shot 死掉。
**精确站点归 `scripts/exec_frame_sites.py` 的离线反解**(见上文「站点离线反解」一节):重读 exe 字节反解出真正的 call site(§59.7),本工具的产物不再声称它是站点。
完整结果写到 `--out`(长表 `kind/key/value/detail`,**meta** / caller / id / chain / object /
root_unreadable / **region** 七类行)。
`meta` 行在最前面,带 `exe_base`、`image_end`、`image_size`、`dll_sha256`、`vtable_map_count`、`layout`、
`stats`、`per_source_follow`,四根的 `followed_by_source`/`implausible_by_source`/`capped_by_source`/
`withheld_by_source`、三个命中计数,以及区域仪器的 `regions_queried`/`region_verdicts`。**这不是装饰**:§56 那次 shot 的 stdout 被一次 ssh 重置整段吃掉,而旧 TSV
里没有这些数,事后无从区分「某个根读到但没有命中」与「那个根根本没被读」,于是把一次预算耗尽读成了一条
负结论(陷阱 5)。判据现在住在带判词的 artifact 里。

**内存区域仪器(`VirtualQueryEx`,§56.8 那条「绝对值还是相对值」缺的 datum)**:`follow_roots` 之后、
清理之前,驱动对**每个被跟过的根地址 + 每条 chain 的 `ctx`** 各问一次 `VirtualQueryEx`,答案写成 `region` 行
(`region\t0x<addr>\t<verdict>\tsource=.. base=0x.. size=0x.. state=0x.. protect=0x.. type=0x.. alloc_base=0x..`)
并汇总进 meta 的 `regions_queried`/`region_verdicts`(后者是 `source/verdict=count` 的排序串)。
**判据是判序,不是标志位的名字**:`None` → `unreadable`;否则**只看地址** ——
`exe_base <= BaseAddress < image_end` → `image`,这一段刻意不查 `Type`(否则一个落在镜像里的
`MEM_PRIVATE` 会被读成「不是镜像」);否则 `State` 是 `MEM_FREE`(`0x10000`)→ `free`、
`MEM_RESERVE`(`0x2000`)→ `reserved`;否则 `MEM_COMMIT`(`0x1000`)时按 `Type` 分派 ——
`MEM_MAPPED`(`0x40000`)→ `mapped_view`、`MEM_PRIVATE`(`0x20000`)→ `private_committed`、
`MEM_IMAGE`(`0x1000000`)→ `image`;其余 → `unknown`。查不到句柄、内核拒绝描述、返回字节数不够,一律
`unreadable`(与 `reader()` 同口径:一个描述不出来的地址是 datum,不是故障)。
**这条仪器不参与 `classify()` 的六档阶梯**,也不参与退出码 —— 区域判定只进 artifact,供离线复算。
结构体那条坑记在这里:`MEMORY_BASIC_INFORMATION` 只声明 SDK 的 7 个命名字段,x64 上 ctypes 的自然对齐
就补出了 `__alignment1`(offsets 0/8/16/24/32/36/40,`sizeof`=48);**把那个 padding 字段也写出来会多插
4 字节,`State` 读到的其实是 `Protect` 的槽**。

**深跟读口径(`plan_depth2` / `follow_depth2` / `find_shared_cells` / `classify_depth2`)**:
depth-1 每行的 `candidates[*]["ptr"]` 当作**再下一层的根**,再走一遍同一个 `follow_object`(深跟读里不新写任何
一次 `read_memory`,失败读照旧是 `unreadable` 而不是 0 —— 陷阱 5),行标签是 `"<基源>.d2"`,两层永不相认。
**预算仍按源给**(`DEPTH2_PER_SOURCE = 27`,把 `.d2` 折回基源计源,四源各 27;27 = §68.4 那次判读的
`followed=8` + `capped=19`,抬预算就是为了把自我支那 19 个没问过的地址问完),而且**depth-1 已经读过的地址不算
线索**:每个根的 `self_ptr` 与 `ctx_words[1]` 本来就在 `objects` 的 `root` 字段里,计划阶段直接跳过(`already`),
同一个地址也只计划一次。**预算的三种花费分开记账** —— `planned_by_source` / `followed_by_source` /
`capped_by_source`,进 `#meta` 的 `d2_planned_by_source` / `d2_followed_by_source` /
`d2_capped_by_source` 与 `depth2_per_source`;第四个计数 `deduped_by_source` **只在 stdout 的逐源行里,
`d2_meta_rows` 不把它写进 `#meta`**(七键是固定的),所以引用去重数必须标出处是 stdout,不能声称可从
TSV 读回。第七个键是 `d2_implausible`:深跟读的候选先按 `plausible_user_ptr` + 镜像界分三档
(`partition_cells`,§68.4 前置 ①),`implausible` 那一档**根本不进跨源连线**,只作为计数落进 `#meta` ——
少了它,`followed` 变小就分不清「问过但没东西」与「那些候选压根不是用户指针」。
注意 `0x100000000` 这种标量**过得了** `plausible_user_ptr`(门槛上界 `0x7FFF_FFFF_0000`),它落的是
「界外」那一档,不是 `implausible`。缺前面那几个键,产物里一条短的深度 2
列表就退化成「那些槽没东西」的误读,这正是 §56.4 那次把预算耗尽读成负结论的同一形状。
区域仪器(`region` 行)现在吃**两层的根**(`collect_region_addrs`),`source=` 保留各层自己的标签。
**跨源共享(`find_shared_cells`)**按**候选值**分组,只保留出现在 **≥2 个不同基源**的值,行是
`{"value","value_rva","sites":[(source, root, off)]}`,汇总进 meta 的 `shared_cells`
(`n=0`,或 `n=<条数> 0x<值>(rva=<hex|->)[源@0x根+0x偏移,…];…`)。这就是把 §59.6 那对
(`helper` 的 `+0x10` 与 `self` 的 `+0x28` 都给出 `0x2ddc2c90`)的问法机械化;**同源两个槽同值不算共享**,
它只说那个对象里有两个字段相等。`value_rva` 只在值落在镜像内才给,界外保留绝对值(与本节开头
「RVA 一律界在 `[exe_base, image_end)`」同一条:把堆地址压成 `rva=0` 会伪造一次镜像命中)。
`VERDICT_D2` 是另一条固定阶梯,`classify_depth2` 按此**判定优先顺序**走出:`no_depth2_planned` →
`depth2_unreadable` → `depth2_known_vtable_hit` → `lineage_edge_found` → `no_depth2_lead`。
**这个顺序不是取证资格顺序**;有取证资格的只有 `depth2_known_vtable_hit` 与
`lineage_edge_found` 两档(`EVIDENCE_D2_VERDICTS`,在 `D2_VERDICTS` 枚举里排在**头两元**)。
**证据档也不自动等于血缘**:两档都在候选值/候选 vptr 上机械判定,而 `find_shared_cells`
**不筛 `plausible_user_ptr`** —— 一个标量形状的值(如 §68.3 第一条 `0x100000000` = `1<<32`)同现多处
就能连成边并把 `verdict_d2` 抬到 `lineage_edge_found`;读这一档必须逐条连同 `rva=` 与值的形状一起读,
见判读陷阱 12。
**它与 `classify()` 的六档不同义、不合并**:后者回答「depth-1 的根有没有交出已知类」并决定退出码,一字未改;
前者只回答「再下一层有没有线索」,不进退出码,也不参与任何旧判据。

**十二条判读陷阱(§53.4 / §54.8.4 / §56.8 / §58 / §59 实机与离线复算取到的,读 verdict 之前先看):**

1. **`no_scope_candidate` 的口径是「不在已知集合内」,不是「不是对象」。** 那 1,805 个 vtable 只包含 slot[1]
   仍是 base Execute 的类,**覆写了 Execute 的类一个都不在**(structures §14 + pipeline §17)。所以这一判读
   不排除候选是对象,只排除「它属于那个集合」。反过来 `scope_candidate` 也只到「命中已知集合」为止。
2. **`r8`/`r9` 在派发点不是参数**(§54.8.4 第 1 条:`0x1D08520` 只设 `rcx`/`rdx`,而 `0x3B01A0` 消费四槽,
   `r8`/`r9` 取的是上一调用者的 scratch)。它们的命中**不能**用来推断调用约定,也不能读成「引擎把 scope 传在了
   第四个槽」。
3. **`unreadable` 与「读到但没命中」是两件事。** 短命帧的 `+0x10` 指向邻近栈 helper(§53.4.1),而读取发生在
   轮询结束之后 —— 那时栈早被覆盖。这类根进 `root_unreadable` 行与 `unreadable_roots` 计数,不该被当成
   「那个位置是空」。模块外(堆)的地址保留**绝对值**在 `ptr`,只有 `vptr_rva` 才是基址相对的;把堆指针压成
   `rva=0` 会和真正的 0 混成一类。
4. **实机结果里的 `base` 有两种,判 vtable 命中只用其中一个。** 驱动打印与 `c4_wiring_result.json` 的
   `base` 是**我们 DLL 的装载地址**(`resolve_base_address(pid, module)` 按模块取),不是 exe 主模块基址;
   vtable map 的键是 exe 相对 RVA,拿错基址就永远命不中,而失败长得很像「没有候选」。完整对照与取法见 §55.1。
5. **某个 `source` 在 TSV 里是 0 行,先读 `capped_by_source` 与 `withheld_by_source`,再谈它是负结论。**
   旧版四根**共用**一个 32 的跟读预算,而迭代顺序是每条记录先交 `self`:排在后面的源必然是 0 行,
   这个 0 与「引擎在那个槽里没有指针」在 artifact 里长得一模一样。§56 就这么把「`arg3`/`arg4` 一行都没有」
   读成「过不了 `plausible_user_ptr` 门」,把「`helper` 只有 1 个地址」读成观测量 —— 实际是
   `31 self + 1 helper = 32` 预算刚好耗尽(§56.8)。`withheld` 是另一半:entry 无效时 `ctx` 没被记,
   `helper` 根不是「读了没命中」而是「无从读起」。**没有 meta 行的旧 artifact 不能事后重开这个判断**,
   只能按未定处理。
6. **两个「像指针」的假象:`vptr_rva` 可以根本不在镜像里,`ptr` 可以根本不是指针。**
   旧 `to_rva` 只有下界没有上界,§56 的 artifact 里就有 2 条 `vptr_rva` 是
   `0x7360ec6ccc426873` / `0x4e5ed44eaa1a4c50` 这种垃圾 qword 减出来的数 —— 它过了「是个 RVA」的形状检查,
   却没过「这个模块有这个偏移」。现在界在 `[exe_base, exe_base+SizeOfImage)`,界外留 `-`。另一半:
   `plausible_user_ptr` 只看范围与 8 对齐,而 §56 的候选里有 **2 条的值是 ASCII `"PLANET"`**
   (`0x54454e414c50`,两处 `off=0x18`)—— 它合法地过了门。所以「pointer-shaped」不等于 pointer,
   命中表里出现一个可疑成员时先按值读一遍,再按指针解引用。同一类还有**量级**:§56 的 `ctx` 帧
   (`0x7fe768`/`0x7fed78`)与 `helper` 根(`0x1900ede0`)都在 32 位量级,而 x64 的栈与模块装载在
   `0x7ff…` 量级 —— 低地址不等于栈,把它们读成绝对指针之前要先按数值比量级(§56.8 末段)。
7. **`known` 与 `member_vtable` 是两个不同的陈述,不能相加。** 前者说「这个成员指向一个已知类的对象」,
   后者说「这个槽里直接放着一张已知 vtable」(多重继承子对象头,说的是 root 自己的类)。§56 的 99 个候选里
   第一层 14 条、第二层 **44 条**(全在 `self` 上,13 个不同 RVA),后者若喂进 `classify()` 会把
   「root 带子对象头」当成 scope 命中 —— 所以现在单独计数、单独写 TSV,且**不进判词阶梯**。
8. **`unreadable`、`free` 与「这个数不是地址」是三件事。** 区域仪器只能说「此刻没有一段已提交的内存覆盖这个
   范围」:`unreadable` 是**问不出来**(句柄、权限或内核不给描述,包含「根来自一条无效 entry」这种没被记下的
   值),`free` 是**问得出且那里是空洞**。而一个 32 位量级的数落在空洞里,既可以是一个还没被提交的相对偏移,
   也可以是一个从未被提交过的绝对地址 —— 这一条不能替二者做决定。`reserved` 更弱:地址有效但内容还没提交,
   拿它解释低地址会把「相对值」这条假说杀掉得不够干净。只有 `private_committed`/`mapped_view`/`image`
   才正面回答「这是一个有人拥有的地址」。
9. **`no_calls` 先读「有没有弹窗」,再读代码。** 预检 `ns_scope_pre.py` 走调试控制台,而**预检本身不暂停
   游戏**(实测:控制台开着时 `red=0 / green=200` ⇒ `state=playing`,§59.1 更正了 §58.3 的因果句)。
   真正暂停游戏的是预检期间弹出来的**事件窗**——它自己会暂停(监督器判读陷阱 4),而 `dialog_unknown`
   这种没归过类的窗口不会被 `dismiss` 收掉。§58 那次 shot 就是这样:预检通过后没回头确认窗口已关、状态回
   `playing`,烧掉 pid 13132 的「一进程一次安装」额度换来一个 `calls=0`。所以**「已载入且已解除暂停」这条
   前置的读数必须紧邻执行 shot 取**(`state=playing` 是判据,`console_open` 不是),预检与执行 shot 之间隔多久这条就作废多久。
   同理:`regions_queried=0` 与四桶全 0 在这种 shot 里是**同一件事的四个写法**,不能读成「区域仪器判了 0 个」
   或「形状集没命中」;而 `scope_reclassify.py` 的 `undecidable_no_rva == 0` 这条验收在零行 artifact 上
   **恒真**,零行时它不证明任何事 —— **有行的时候它也不该被当成验收**:v4 的 16 条 object 行里 15 条
   `vptr` 根本不在镜像内(那是 `0x0`/`0x102`/`0x4000000040` 这种值),界外留 `-` 正是 bounds 修复要显示的
   事,不是要消灭的事(§59.8)。
10. **`dismiss` 的关闭点仍是写死偏移 —— 工具缺陷已修(可覆盖 + 每次尝试留痕),偏移本身对任何窗的正确性待实机复核。**
    历史(§59.2 唯一反样本):`click_close` 走 `bbox[2]-96, bbox[1]+51`(2160x1440 上量来的),而 `bbox` 来自金色像素的 panel 检测:
    §59 那个事件窗的 `bbox` 右界 1939 落在**右侧栏**上,算出的点 1843 不在 X glyph 上(真 X 在 1343,480)。
    当时 `dismiss` 返回成功、日志无痕、窗口原地不动 —— 「点击没送达」与「框判错」无法区分。
    现在:偏移提出为 `CLOSE_INSET`,由纯函数 `close_point(bbox, inset)` 算点;`dismiss <dx> <dy>` 可逐命令覆盖
    (屏幕绝对点仍走 `just game click`)。每次尝试**先**写 `dismiss_attempt`(本来会点的坐标、
    `method ∈ {fixed_inset, refused}`、inset、bbox),真点击后重读窗写 `dismiss`(`no_effect` 即「点后窗还在」);
    判 `refused` 则不点击、raise,状态 note 为 `dismiss_refused`。「dismiss 成功但窗还在」由此变成**可检出的事件**。
    「检出」的边界要写明:`no_effect` 是 **panel 检测器的陈述,不是 glyph 的陈述**,两个方向都可能误报 ——
    重读若锁上*另一块*亮面板,窗真没了也报 `no_effect: true`;漏点后检测器若丢掉金色锁定,窗还在也只报
    `no_effect: false`(`bbox_after` 出自同一个当初把右界量到侧栏的检测器,§59.2 的原失效模式并未被这条事件根除)。
    留痕把问题从「无痕」降级为「待复核」,判定仍靠下面的手动量测(`shot` + `just game click`)。
    **但 §59.2 只有一个反样本,不足以推量测式 —— 第一版刻意不发明几何规则**;复核要等下一次有窗的实机机会。
    **2026-10-25 复核做过一次,结论是「未证正确」并把理由变强了**(`evidence/logs/unattended_popup_4_4_4.log` Step 6):
    对 bbox `[879,555,1939,872]` 的那一拍,算得的点仍是 `(1843, 606)`;把当拍的工具自己存下的裁片
    `C:\temp\ns_popup\geom_1060x320_r11.png` 取回本地人眼复核 —— 里面**根本没有 ✖ glyph**:左半是星图与舰船立绘,
    中上是带白色六边形工程/科研图标的舰队条(亮度剖面最强标记在 screen x≈1504),右半是舰队列表文字,
    而算得的点落在舰队列表文字上。⇒ 比「偏移差 500 px」更硬的一条浮出: **这个 bbox 不是一扇窗,是面板检测器
    在主 UI 上切出的一块**;在它上面点 close_point 等于误点舰队列表。`no_effect` 那第三个数本场取不到
    (两因叠加: 那一拍之后分类器转向了别的几何形状,而 `dismiss` 分支的前置 `paused == "paused"` 在
    控制台覆盖层把脉冲图标读成 `state=unknown` 时不满足)。陷阱 10 的标题句因此**不改**:偏移对任何窗的正确性
    仍未被证明,且现在多了一条不依赖 §59.2 那一个反样本的理由。
    复核之前的临时取代:先 `shot` + 裁 `titlebar` 量 glyph 中心,再 `just game click <x> <y>`(坐标是**屏幕绝对**的,
    `window_metrics` 的 bbox 已经加过窗口原点)。
11. **`form=none` 是窗口陈述,不是调用者陈述。** `exec_frame_sites.py` 报 `none` 只说明**返回 RVA 前
    16 字节内没有任何恰好结束于返回点的 call/jmp 边界**,**不等于没人调用**:调用可能经过 thunk
    (返回点不挨着任何紧邻边界),或样本记录的返回 RVA 本身就读错了(旧产物把估值当键的世代)。
    `none` 是要带进取证卷的 datum,不是负结论;`ambiguous` 同理 —— 它是字节里真实存在的重叠,
    照原样进卷,不替他选一个候选。

12. **两个证据档说「有线索」,永远不说「是血缘/是对象」;三个负档更弱。** 先说负档:
    `no_depth2_lead` 与 `depth2_unreadable` 都不说「更深一层没有对象」。前者只说「这一层交出的候选值,
    没有一个落进那 1,805 个已知 vtable,也没有一个值跨两个基源共享」;而那张表**是下限不是类数**
    (structures §14:覆写了 Execute 的类一个都不在里面),所以「不在集合内」永远推不出「不是对象」。
    后者更弱,它是**仪器的陈述**(`reader` 对这一批地址一个 qword 都没拿到),对内存里有什么不说话。
    同一形状也管 `no_depth2_planned`:那一档是「depth-1 没交出任何新地址」,不是「对象里没有成员指针」。
    五档里只有 `depth2_known_vtable_hit` 与 `lineage_edge_found` 有取证资格(`EVIDENCE_D2_VERDICTS`),
    其余三档写进卷里时只能作为「本次这一发问到什么程度」的说明句。
    **资格档也有它的弱形,不能只读那一行判决词**:`find_shared_cells` 按候选值分组且**不筛
    `plausible_user_ptr`**,所以一个**标量**同现多处就能连成边 ⇒ `lineage_edge_found` 可能是
    「同一份计数在多处出现」而不是两个对象共享一个成员(§68.3 第一条 `0x100000000` = `1<<32` 就是这样
    一档里的一条边);`depth2_known_vtable_hit` 同理只说「解出来的值落在 floor map 里」,它不说那个 root
    就是 scope。所以读这两个档时必须**逐条**连同 `rva=`、值的形状、界内/界外一起读,判决词本身不是结论。

**宿主死了先跑 §45 的两个离线工具**(`scripts/c2_selfabort_repro.py` + `scripts/dll_ubsan_site.py`)
排除我们自己的产物,再谈引擎。

### `scripts/c4_wiring_probe.py [--mode capture|slot2] [--dll PATH] [--save PATH] [--json PATH] [--supervisor-log PATH] [--allow-drift]`

C4 接线驱动,一次 shot 一个进程。`--mode capture`(默认):跑 `capture` 找 `ctx`/`a3` 里承载 system id 的列,
`apply` 把该列喂给 QuickJS 的 787 分数表(tier 阈值 100/200),tier ≥ 1 的 70 个系统 chain donor
Execute 应用 `log`/`set_name`。**capture 只读**(RPM 采样 + 环形记录),整条 apply 路径里唯一的引擎
写入是引擎自己的 donor Execute。`--mode slot2`(§54.6 判别 shot):**预检 → install → 一次 armed 的
`every_system` pass**,读 slot[2] 只读计数器(`C4Slot2StatsInto`,`<QQ>` 16 B:计数 + 转发目标),
verdict ∈ {`slot2_counted`(787 ⇒ base Execute 经我们的副本 slot[2] 派发)、`slot2_zero`(0 ⇒ donor
vptr 副本/克隆,不经我们的 vtable)、`slot2_body_not_executed`(body 没跑满 783,计数没有意义)、
`slot2_sentinel_mismatch`(哨兵不等于 783)、`slot2_other`}。判据先钉哨兵 783 行与 body marker 783
行(投递与执行都发生),再读计数增量 —— 否则 `0` 无法区分「不经 slot[2]」与「没跑」。包装器的
等价性有离线出处(`runtime_444_c1_validation.md` §54.8):派发点 `0x1D08520` 只设 `rcx`/`rdx`、不读
`rax`,而 `0x3B01A0` 四个 GPR 槽全消费 —— 但同一节也记了 `r8`/`r9` 在派发点**不是参数**、
`slot2_counted` 只证明入口不证明良构调用。路径默认
`C:\temp\sqjs_c4.dll` / `C:\temp\stellaris_2226.sav` / `C:\temp\c4_wiring_result.json`,`--game-log` /
`--supervisor-status` / `--supervisor-cmd` / `--shot` 也走参数,脚本不读环境变量。

**前置**:supervisor 必须已在 Windows 机上跑着(见下一节)。驱动先写 `want paused` 并等到状态
`paused`(状态文件超过 5 s 未更新按「没在跑」判),然后才注入。**console 命令都经 supervisor
的 `console` 动词**(剪贴板 + 按键),条数按模式定:`--mode capture` **三条**(预检 + capture +
apply),`--mode slot2` **两条**(预检 + 判别 shot)—— 两种模式都含那条预检;不直接对游戏发键。
控制台键是**开关**,而命令执行完面板不关(2026-10-23 实机),所以 supervisor 自己记
`console_open`:首条命令按一下打开,其余每条只清行、粘贴、回车;换进程时这个标记复位。

```
effect every_system = { log = "C4_PREFLIGHT_<pid>_[This.GetName]" }             # 预检，应得 783 行
effect every_system = { log = "C4_CAPSTART_<pid>_[This.GetName]" neo_action = { … } }   # capture 哨兵
effect every_system = { log = "C4_APPSTART_<pid>_[This.GetName]" neo_action = { … } }   # apply 哨兵
effect every_system = { log = "C4_SLOT2START_<pid>_[This.GetName]" neo_action = { … } } # slot2 判别 shot 哨兵
```

> 哨兵与预检共用 `[This.GetName]` 的 783 行去重形状，但带 pid 与相位：capture/apply 的哨兵在
> 同一会话里互不冒充。3 s 内没有被 supervisor 消费 → `console_send_failed`；0 行 → `*_not_delivered`；
> 非 783 行 → `*_sentinel_mismatch`。宽限取 3 s,是因为 supervisor 的 serve 循环是 0.8 s、读命令前
> 还要做像素截图 —— 投递失败现在会中止整个 shot,1 s 会把健康通道误判成坏通道。

**谓词计数器**：`C4PredStatsInto` 是 `<QQII>` 24 B（calls, patched, last_token, installed）；驱动取
capture 前后的**增量**，不是绝对值 —— `pred_patched` 是进程累计值，预检的 effect 也会进 detour。

**命令形状**:keyword 要写在 `effect` 与 `=` 之间(`effect every_system = { … }`)。写成
`effect = { every_system = { … } }` 时引擎往 error.log 打 `Invalid scripted effect: =`,盒子根本不跑 ——
这个形状曾经让预检只数到 1 行。

**marker 必须逐系统不同**:引擎的 log sink 会**丢弃本会话里已经打过的同样消息**(game.log、
error.log 一致),所以固定文本的 marker 在 787 次执行后只剩 1 行,第二条同样的命令连一行都不加。
marker 带 `[This.GetName]`(`log` 里会插值,`GetID` 渲染为空),每个系统渲染自己的名字。实测:787 个
系统只渲染出 **783 个不同名字**(3 对低分系统重名,均不在 tier ≥1),apply 的 70 个 tier ≥1 系统名字
全不同 ⇒ `PREFLIGHT_MARKERS = 783`、apply 仍按 70 行判。

预检 marker 带 pid,但从**本次偏移**读到 EOF 再数,所以同一会话里重跑的旧行不会串进来;命令原文
的回显那行不含 `Log effect, file:`,所以 `count_marker_lines` 只数带这个片段的行,回显不会被当成输出。
预检 0 行 = `console_unavailable`(焦点/键盘路径坏了),非 783 行 = `campaign_mismatch`(不是测试战役)。
行数是**轮询到 ≥783 或 30 s 超时后的最大值** —— 日志分块 flush,中途停在某个非零值不算终值;
apply 的 70 行 marker 同理(3 s 静默后再等 15 s,取最大值)。

**预检现在跑在 DLL 装载之前**(`_campaign_preflight`,在 `resolve_pid` 之后、`resolve_base_address`/
`inject_dll` 之前),并且 `--mode capture` 与 `--mode slot2` **都跑**。因此
`console_unavailable` / `campaign_mismatch` / `log_unreadable` 三种结论**不消耗游戏进程** —— 进程没被注入,
修好通道后同一个 pid 可以复用;`install_failed` 之后的结论才要换进程。预检同时记
`result["preflight_wait_s"]`(发命令到读到 783 行的墙钟秒数,保留 2 位小数;读不到日志时不写这个字段)
—— 它量的是引擎日志 flush 到 783 行要多久,对着 30 s 门限读:接近 30 s 的值说明门限余量不够,别把
`campaign_mismatch` 当成战役不对。

**save sha 门**:`stellaris_2226.sav` 的 sha256 必须等于钉住的 `6f271294…`。读不到文件 →
`campaign_unverified`,`--allow-drift` 只把「读到了但不匹配」降级成 `drift_allowed`(诊断用),
读不到仍然 `campaign_unverified`。预检的 783 行是战役形状的第二道门。

**drain 缓冲契约**:`C4WireDrainInto` 的调用方必须提供 `RING_CAP * RECORD_SIZE`
= 2048 × 3368 = 6,897,664 B 的远程缓冲(驱动只分配一次);DLL 写 `n * RECORD_SIZE` 字节并清空
环形计数,驱动只读回这 `n` 条。`layout` 导出先钉 `[1, mode, 3368, 2048, 944, 256, 8, 256]`,
任一字段漂了都是 `layout_drift`,后面的字节一个都不读。

**前置门一 — 导出集按模式取**(`required_exports(mode)`,2026-10-24):capture 要 `REQUIRED_EXPORTS`
的 13 个名字,slot2 在此之上多一个 `C4Slot2StatsInto`。`_flow` 在 `resolve_pid`/`inject_dll` **之前**
就拿按模式的集合与 DLL 导出做差,缺了当场 `dll_exports_missing`(detail 是缺名排序表)—— 没有计数器
导出的 DLL 不许拖进游戏里才在回读 `C4Slot2StatsInto` 时失败。capture 的目标集没有扩大,旧 capture
批次仍是合法目标。

**前置门二 — 控制台信念必须来自观测**(`console_gate`,与 `supervisor_ready` 并列,见 §54.10):
`_wait_ready` 在发出第一条 console 命令之前同时要求 supervisor 状态 `paused` + 新鲜(>5 s 按没在跑判)
**和** console 门通过。`console_gate` 只接受**判决性**观测:`console_open` 为 `True` 或 `False` 都放行
—— 首条命令之后面板常开,要求 `False` 会拒掉每一个多命令 shot;键**缺失或 `None`** 拒成
`console_state_unknown`(键缺失 = daemon 早于像素通道,那是猜测不是观测);`console_forced` 为真值拒成
`console_belief_pinned`(钉住的信念不算观测)。两条拒绝的 detail 带 `console_open=` / `console_px=` /
`console_forced=` 三个实际值(`_wait_gate_detail`;整条状态记录都读不到时三者都是 `-`),读一眼就知道
是哪个门拒的。两条都发生在注入之前,不烧进程。

**前置门三 — daemon 回执,2 s 内具名**(`_send_console_or_abort`):每条 console 命令写出后,驱动从
**写命令之前**捕获的字节偏移起,读 daemon 自己的事件日志尾(默认
`SUPERVISOR_LOG = r"C:\temp\ns_game_log.jsonl"`,`--supervisor-log` 可覆盖)至多
`CONSOLE_RECEIPT_TIMEOUT_S = 2.0` 秒。偏移取在写之前,否则上一条命令的旧 `console_refused` 会中止
一发本来健康的 shot;日志**stat 不到**(共享争用 / AV 扫描)时偏移记 `None`,直接跳过回执轮询 ——
读不到就退回 0 等于「从头分类整个文件」,会把上一条命令甚至上一轮运行的拒收算到这条健康命令头上,
而 `_slot2_phase` 那次 shot 发生在注入之后,烧掉的是游戏进程。`console_refused` /
`console_clipboard_failed` 当场中止,把 daemon 记的 `reason` 放进 result 的 `detail`(daemon 没记
reason 时落命令原文,`reason or text`);窗口内真出现 `console_sent` 才由它返回。**但健康的命令通常
不是靠 `console_sent` 返回的** —— daemon 的成功行要按完 `console_key_plan` 的全部键才写:
`BACKSPACE_CLEAR = 64` 个退格(每个 down/up 两个事件 × 20 ms = 2.56 s)、开面板的一下 tap(2 × 80 ms)、
粘贴/回车(6 × 80 ms)、末尾 0.3 s sleep,合计约 3.5 s(第二条起不按 tap,仍 3.3 s),**严格长于 2 s
窗口**;即时落盘的只有拒绝(`console_send_plan` 判 `None` 或 `focus` 失败时一个键都不按)。所以
**读不到回执不算失败,它是健康投递的默认形状,不是回执丢了** —— 静默到点即返回,日志轮转/读不出同样
按 `no_receipt` 吞掉,投递的终判仍是 783 行哨兵;§55 读一个 2 s 的静默返回时不要去找「缺失的成功回执」。
这一条把 §54.9 那种「命令被静默拒绝、30 s 后才以零输出暴露」变成 2 s 内的具名失败:窗口只会缩短一个
已知失败,永远不会推迟一发健康的 shot(预批次的代码在 `.seen` 之后就立即返回)。

**verdict 表**(驱动按顺序判,先命中的胜出):**装载前**的结论(`supervisor_*`、
`console_state_unknown`/`console_belief_pinned`、`campaign_*`、`dll_exports_missing`、`game_not_running`、
预检三条)**不烧进程**,修好通道可以在同一个 pid 上再打;
`install_failed` 之后的结论才需要换进程。

| verdict | 条件 | 意思 |
|---|---|---|
| `supervisor_not_running` | 15 s 内状态文件缺失/过期/`no_game`/`stopped` | supervisor 没跑 —— 环境结论 |
| `supervisor_not_paused` | 状态新鲜但 15 s 内没到 `paused` | 战役没暂停成功,不要注入 |
| `console_state_unknown` / `console_belief_pinned` | `_wait_ready` 里 `console_gate` 拒:`console_open` 键缺失或为 `None` / `console_forced` 为真值 | 控制台信念不是判决性像素观测(§54.10),一条 console 命令都没发(`want paused` 已经写了)—— daemon/环境结论,不烧进程 |
| `campaign_unverified` | 存档 sha256 读不到 | 路径/权限问题 |
| `campaign_mismatch` | sha256 不匹配(且未 `--allow-drift`),或预检(装载前)行数 ≠ 783 | 不是那场 787 系统的测试战役 |
| `dll_exports_missing` | 缺 9 个 `C4Wire*`/`C4ScoredStatsInto`/`C4PredStatsInto` 或 `C2Sanity`/`C2Init`/`C1Run`/`C1EffectId`(`--mode slot2` 另需 `C4Slot2StatsInto`,按模式判,见前置门一) | 产物不对,注入之前就判 |
| `game_not_running` | `resolve_pid("stellaris")` 失败 | 环境结论 |
| `stale_module` | 注入前 base 已能解析(含 `ambiguous base`),或非 `is not loaded` 的解析失败 | 进程里已有 DLL 副本,**换新进程**,不重装 |
| `inject_failed` | `inject_dll` 或注入后的 base 解析失败 | 注入通道问题 |
| `sanity_failed` / `quickjs_init_failed` / `c1_failed` | `C2Sanity≠42` / `C2Init≠0` / `C1Run==0` 或 `C1EffectId==0` | C1/C2 前置门 |
| `layout_drift` | layout 导出 ≠ 8 个字或字段不匹配 | 驱动与 DLL 解码契约断了 |
| `install_failed` | `C4WireInstall != 0` | 谓词 detour/arm 失败,**不重试**,换进程 |
| `console_send_failed` | 命令写入 3 s 内 supervisor 未消费（seen-key 不变） | 键盘/supervisor 通道坏了，游戏没收到命令 |
| `console_refused` / `console_clipboard_failed` | 命令写出后 2 s 内 daemon 事件日志尾(`C:\temp\ns_game_log.jsonl`)出现该具名回执 | daemon 明确拒收,它的 `reason` 进 detail(daemon 没记时落命令原文)—— 预检(装载前)那次不烧进程,装载后的各相位烧;§54.9 的静默拒绝在这里变成具名失败 |
| `console_unavailable` / `log_unreadable` | 预检(装载前)marker 0 行 / 日志读不了 —— `log_unreadable` 在装载后的 capture、slot2 窗口也会出 | 键盘路径 / 路径问题;只在预检那次不烧进程 |
| `capture_not_delivered` / `capture_sentinel_mismatch` | capture 哨兵 0 行 / ≠ 783 行 | 命令没进游戏 / 战役形状不对 |
| `apply_not_delivered` / `apply_sentinel_mismatch` | apply 哨兵 0 行 / ≠ 783 行 | 第二次命令没生效 / 战役形状不对 |
| `no_calls` | capture `calls == 0` 且未提供谓词计数（纯函数默认） | 没有 `neo_action` 执行 —— 环境结论 |
| `predicate_not_reached` | capture `calls=0` 且谓词 detour 增量 `calls=0` | detour 没被调用：脚本没实例化 effect，或 detour 不在路径上 |
| `predicate_not_matched` | capture `calls=0`、detour 有调用、`patched=0` | detour 在跑，但没有任何对象带 armed token |
| `execute_not_reached` | capture `calls=0`、`patched>0` | vtable 已换，但 slot[1] Execute 没被调用 |
| `no_readable_ctx` | capture 记录 0 条 | ctx 读不出来 |
| `count_mismatch` | capture calls/records ≠ 787、有 dropped、或 drain 条数不符 | 调用数/记录数不对 |
| `no_scope_column` | 没有一列严格等于 `0..786` | 这次 capture 里没有可用的 scope 列 |
| `scope_order_unverified` | 只有排序后相等的列 | 列是 `0..786` 的乱序,driver 不猜 |
| `ambiguous_column` | 多于一条严格匹配列 | 需要人工看 capture 记录 |
| `apply_no_calls` | apply 窗口内 calls 没有增量 | 第二次 console 没生效 |
| `scored_js_error` | scored `js_err`/`invalid` 非 0 | QuickJS 分数脚本出错 |
| `apply_count_mismatch` | `resolved≠787` 或 `unresolved≠0` | 解析没覆盖全部系统 |
| `tier_mismatch` | tier 直方图 ≠ `(717,55,15)` | 分数表或阈值漂了 |
| `chain_mismatch` | `chain≠70` | tier≥1 没全部 chain |
| `log_mismatch` | `NEO_CHOKE_EFFECT` 行数 ≠ 70 | effect 没真正应用 |
| `record_drift` / `scan_drift` | 记录长度不对,或 DLL 记录的指针目标不在 blob 的扫描序列里 | 驱动与 DLL 的扫描规则漂了;DLL 只记 ≤8 个且跳过窗口读失败的指针,所以「扫描多出目标」本身合法 |
| `stats_drift` / `scored_stats_unreadable` / `mode_failed` / `apply_setup_failed` | 读回长度/解码/set-mode/set-spec 失败 | 驱动自检 |
| `host_dead` | `assert_game_alive` 失败 | **先跑 §45 的两个离线工具** |
| `restore_incomplete` | `C4WireDisarm` 返回 `-6` | 引擎字节没还原,打印 `RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY`,放弃该进程 |
| `cleanup_incomplete` | 流程本可 `ok`,但 `C4WireDisarm` 抛异常(读不到 rc) | 清理状态未知,不算成功;不要在该进程上重试 |

清理段固定:`SetMode(0)` → `C4WireDisarm`(`-1` 锁忙最多重试 6 次 × 0.5 s;6 次仍 `-1` 记为
benign,`0`/`-1` 都算清理成功)→ `assert_game_alive`。**绝不 `FreeLibrary`** — patch 过的 effect
对象持有 DLL 内的 vtable 副本。只有 verdict `ok` 且清理成功(host 存活、disarm 是 `0`/`-1`)退出码
才是 0;disarm 抛异常时 verdict 降为 `cleanup_incomplete`。**装载前中止的 shot 没有清理段可跑**
(进程里既没有 DLL,也没有 detour),退出码同样是 1,但进程保持可用 —— 别把这种 1 读成「烧了一次 shot」。

判读纯函数(`decode_records` / `_wire_stats` / `_scored_stats`、`pack_spec`/`unpack_spec`、
`column_sequences`/`find_scope_column`、`classify_capture`/`classify_apply` 等)由
`python3 -m pytest scripts/test_c4_wiring_probe.py -q` 覆盖,无游戏、无 Windows API。

### `scripts/c2_donor_probe.py [dll] [--mask 0] [--poll-s 120] [--settle-s 2] [--out C:/temp/c4_donor_probe.tsv]`

donor 一族的只读采样 shot(§57.4 点名的那个靶子),一次 shot 一个进程。**本计划只把它写好并静态验证,从未运行** ——
它是实机工具,运行需要本次会话内点名(`docs/roadmap.md` 的授权表)。默认 DLL `C:\temp\sqjs_c4.dll`。

**它读谁的字节**:DLL 侧 detour 挂在 `0x3AFD30`(`offsets.keyword_reg.RVA_EFFECT_DONOR_EXECUTE`,
不是 base Execute `0x1D08520`,也不是我们那份 25 槽副本)。**唯一一次引擎内存读是 `[self+0]`**,
拿它的 RVA 去 join `FAMILY_VTABLES` 那五张表;`rdx`/`r8`/`r9`(`ctx`/`a3`/`a4`)只按**值**记录,
本探针一个都不解引用(§53.5 已证伪 `[ctx+0x30]` 那条链,不在这里复活)。函数体恒转发原函数、
不改寄存器、不改控制流。引擎字节只在三处被写:install 的 JMP、`removeHook` 的还原、`restoreTarget`
把自存的原前序拷回去。前置指纹是 `0x3AFD30` 的 24 字节原前序,逐字节不符即 `-5` 拒装
(围栏 `scripts/test_c2_donor_probe.py` 把那 24 字节和五张表都钉回它们的权威:exe 与取证卷 §57.2 观测 4)。

**门序**:`resolve_pid → resolve_base_address → sha 门 → gate_module(NEEDED_EXPORTS) → Layout →
Reset → SetMask → Install → 轮询 Stats → Drain → write_tsv → finally: Uninstall → Verify → settle →
assert_game_alive`。每根箭头是真依赖:`resolve_base_address` 在注入**前**取的是 `stellaris.exe` 的基址
(#meta 里那句「RVA 相对于哪个界」的出处);`gate_module` 用 `list_exports` 从**文件**里核
`NEEDED_EXPORTS`,缺一个就不注入 —— 晚一步发现昨天那份 DLL,进程里就多一份永远卸不掉的映射。
`Reset` 清计数/环/mask 但**不卸载 hook**,所以必须排在 `Install` 之前(带着活补丁清 `calls`
等于悄悄把采样分母调回 0)。`sha 门`比的是「这次 shot 要注入的是哪个文件」:整文件 sha **不是代码身份**
(上面实测过每次重链都换、`.text` 一字节没动),所以这道门是**打印并记进 #meta + 读不到就拒**,
不是拿钉死的常数做相等断言 —— 后者会在每次重建后杀掉每一发合法的 shot。

**依赖码**:`C4DonorProbeInstall` `0` / `-2`(本进程已装好,**或 predicate detour 还 armed**)/
`-3` stellaris.exe 未找到 / `-4` 目标已被 hook / `-5` 指纹不符 / `-6` patch 过宽 / `-1` 其余。
`-2` **不重试**:一进程只有一次 install 额度,唯一杠杆是新进程。
`C4DonorProbeUninstall` `0` / `-7`(引擎字节没回来 ⇒ 驱动打印
`RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY`,放弃该进程)/ 其它错误 `-1`。
`C4DonorProbeSetMask` 恒 `0`:任何 u64 都是合法掩码,**没有非法值档**(`mask=0` 是「每条都落环」的有语义取值)。
`C4DonorProbeVerify` 原样透传,不重新折叠 —— 非零三档含义互不相同:`-1` 装着但 hook 从 detour 表里丢了、
`-2` 已卸但引擎字节与指纹不符、`-3` 本进程从未解析到目标(install 从没在这儿跑过)。
清理段之后**绝不 `FreeLibrary`**。

**verdict 值域**(`VERDICTS` 是唯一权威,`verdict_for` 只能返回它的成员;退出码 0 只给前两档证据结果):

| verdict | 读数 | 这是什么 |
|---|---|---|
| `donor_family_hit_named` | 某个 `hN>0` | 经虚派发成立,且**指名哪一张表**(`table_rvas()[N]`;index 2 = `0x25F4440`) |
| `donor_family_hit_unknown_table` | `calls>0`、`installed==1`、五个 `h` 全 0、`unmatched>0` | 看到一张五表之外的 `[self+0]`(且探针已装)——**交给静态查表的接力**(环 `self_vtable_rva` + `#meta` 的 image span 三分区),**不是「运行时生成的表成立」**:`unmatched` 同时吸收 code-address(538 vs 5)、`toRva`→0 与真实 `SizeOfImage` 外那 ~6.8 MiB 尾巴的读数 |
| `no_calls_inconclusive` | `calls==0` | **ENVIRONMENT**,不是代码结论 |
| `instrument_broken` | `invalid_self>=calls` 且其余计数全 0 | 探针读不出 `[self+0]`,对本次观测没有陈述能力 |
| `counter_desync` | `calls>0` 但没有一个计数器对上;或 `installed!=1`;或整跑没有一条完整 stats 行 | 记账坏了(典型:带活补丁跑了 `Reset`、读到另一份模块拷贝的 stats),不是引擎行为。**两条代码档的门**就在这一档前面 |

**三条判读陷阱**:

1. **值域里没有第三档,`no_calls` 不许读成「不经这一族」。** §57.4 的第三档要的是
   「**哨兵 body 等齐(执行确实发生)而 `calls==0`**」—— 它的前半句是一桩独立的证据,本探针既没有哨兵 body
   也证明不了「执行确实发生」。运行中的战役里一个安静的窗口只可能是「没观测到」,所以这一档在这台仪器上
   **不可达**,`verdict_for` 也不返回它(测试用一条 `assert set(VERDICTS) == {…}` 把「没有
   `no_donor_family_execution`」钉死)。读成负结论就是把仪器的一次沉默当成了引擎的一次陈述。
2. **`[self+0]` 命中我们 DLL 的 vtable,说明 predicate 在跑,不是命中家族。** predicate detour 把实例化对象的
   `[child+0]` 指向我们在 DLL 里的 vtable 副本,那种状态下每个读数都落在五表之外,会被记成 `unmatched` ——
   一个**假的 tier 2**。所以模块在 `preflightChecks` 里直接拒绝该状态(这就是 `-2` 的第二种成因),
   驱动对此不重试、只要新进程。这也是为什么这次 shot 与 predicate/slot2 那两次**不能同进程共跑**。
   另有**两类**会造成同一个假 tier 2,一并记下:落在图像内的 **code-address `[self+0]`**(`0x3AFD30` 静态
   qword 出现 538 次却只承认 5 张表),以及 `toRva`→0 的**图像外读数**(含 64 MiB 窗口内、真实 `SizeOfImage`
   之外那 ~6.8 MiB 尾巴)——两者都进同一个 `unmatched` 计数。所以 tier 2 只是**接力**:`#meta` 的 image span
   三分区(`rva_zero`/`in_image`/`at_or_above_image`)拆的是**证人侧**的环记录,**计数侧拆不开**;且
   `installed==0` 时两条代码档都不发射(记 `counter_desync`)。
3. **`mask != 0` 时 ring 与 counters 不同源,比例只能从 counters 取。** 五个 `hN`/`unmatched`/`invalid_self`
   是**每次调用都计**、且在采样门**之前**计,只有环的写入被 `calls & mask` 筛过(§57.4 的恒计设计 ⇒ 三档判据
   不需要分母)。默认 `--mask 0` 每条落环;**先跑一次 20 s 窗口读 `calls` 增量定频率,再决定下一次点名要不要带
   mask** —— 这是 §57.4「不要照搬 base Execute 的 1/512」在本工具上的落地口径。带 mask 时拿 256 条环去数比例,
   数出来的是证人的样本量,不是发生过的调用数。

**它替代了 `0x1D08520` 那一族采样面的哪一段**:§57 观测 6 确立「这一族**一张都不从 base Execute 进**」
(`0x1D08520` 只是没覆写 slot[1] 的那些类的默认体),于是 §54–§56 那三次挂在 `0x1D08520` 上的 shot
(`c2_scope_probe.py` 的 `calls`/`delta`/`valid`)对 donor-shaped 这一族**没有覆盖**:既不能证明这一族被执行,
也不能证明没被执行。本工具接的就是那一段覆盖缺口 —— **「这一族到底进不进虚 Execute」这个问题从此归它问**,
`c2_scope_probe.py` 继续只回答「base Execute 的调用者是谁」(§59)。两次 shot 的读数不同源,不能互相引用
(§55.4 未排除第 1 条:base Execute 派发点的 `r8`/`r9` 是上一调用者的 scratch,而这里 `r8` **是**第三个参数)。

TSV 首行是 `#meta`,带 `exe_base`、`image_size`、注入那份 DLL 的 `sha256`、`mask`、`calls`、
`tiers=h0=/…/unmatched=/invalid_self=` 逐档读数、`verdict` 与 `named_table`,终修之后还带环记录的
image span 三分区(`unmatched_rows`/`rva_zero`/`in_image`/`at_or_above_image`)与 drain 失败时的
`entries_error=` —— artifact 是 stdout 丢了之后还能活下来的那份(§56 那次 shot 整段 stdout 被一次 ssh reset
吃掉,判据依赖的数跟着没了)。因此 `run()` **先写 meta-only artifact 再 drain**:一次坏 drain 只许留下
`entries_error`,不许吃掉已经拿到的读数(这一条写序由 `test_run_writes_the_artifact_before_it_drains_the_ring`
钉住)。

判读纯函数(`decode_layout` / `decode_entry` / `decode_stats` / `verdict_for` / `table_rvas` /
`write_tsv` / `partition_unmatched` / `build_meta`,常量 `VERDICTS` / `NEEDED_EXPORTS`)由
`python3 -m pytest scripts/test_c2_donor_probe.py -q` 覆盖(**14 条**:Task 2 的两条权威围栏 +
Task 3 的 6 条判读 + 终修的 5 条 + 1 条写序保护),无游戏、无 Windows API、零 shot。

### `scripts/c2_witness_probe.py [dll] [--mask 0] [--poll-s 120] [--settle-s 2] [--out C:/temp/c4_witness_probe.tsv]`

donor 一族的**兄弟仪器**:同一族、同一张五表、另一个槽位。它是 §57.4 第三档所要求的**哨兵证人** ——
一次 shot 一个进程。**已运行过两窗**(2026-10-27 取证卷 §69:20 s 频率窗 + 120 s 正式窗,同一进程
pid 15500,两窗均 `calls=0`/`no_calls_inconclusive`,产物 `evidence/logs/witness_probe_4_4_4.tsv` 与
`witness_freq_4_4_4.tsv`);运行需要本次会话内点名,见 `docs/roadmap.md`
的授权表。默认 DLL `C:\temp\sqjs_c4.dll`,argv 与 donor 逐字同形。

**它与 donor 的关系(两条,先读这段再读下面)**:

1. **同进程共存合法,但必须串行。** donor 的 `-2` 有两条成因(本 guard 已装 / predicate detour 还 armed),
   证人同样两条,而**两组 guard 变量各自私有** —— 所以「donor 装着」既不是证人的 `-2`,也不是它的
   predicate 成因。合法序列是 `donor Install → … → donor Uninstall 且 Verify=0 → witness Install`,
   反向同理;**并行双 detour 挂同一族不同槽不做**,那需要证明两个 hook 的 trampoline 与还原顺序互不踩踏。
2. **donor 必须先读到证人的结论,才有第三档资格。** §57.4 第三档要的是「执行确实发生而 donor 安静」,
   「执行确实发生」这半句由证人的 `calls>0` 提供;证人自己安静时,它**不提供任何东西**,donor 的安静
   于是也只是没观测到。两次 shot 的 `calls` 不同源(不同函数、不同调用频率),**不许互相除、不许互相引用**。

**它读谁的字节**:detour 挂在 `0x3B01A0`(`offsets.keyword_reg.RVA_EFFECT_DONOR_INSTANTIATE`,donor 族
`slot[2]`,即 `[vptr+0x08]` 之后那一槽;不是 donor 自己的 `0x3AFD30`,也不是 base Execute `0x1D08520`)。
读法与 donor 完全一致:**唯一一次引擎内存读是 `[self+0]**,拿它的 RVA join 同一张 `FAMILY_VTABLES`
五表;`rdx`/`r8`/`r9` 只按**值**记录,一个都不解引用。函数体恒转发原函数。引擎字节同样只在 install 的
JMP、`removeHook` 的还原、`restoreTarget` 三处被写。前置指纹是 `0x3B01A0` 的 24 字节原前序
(`48 89 5c 24 18 4c 89 4c 24 20 48 89 4c 24 08 55 56 57 41 54 41 55 41 56`),逐字节不符即 `-5` 拒装;
围栏 `scripts/test_c2_witness_probe.py` 把这 24 字节和五张表钉回它们的权威(exe 与取证卷 §57.2 观测 4),
且与 Task 1 抄下来的字面量做**第三方**对账。

**门序**:与 donor 逐字相同 —— `resolve_pid → resolve_base_address → sha 门 → gate_module(NEEDED_EXPORTS)
→ Layout → Reset → SetMask → Install → 轮询 Stats → Drain → write_tsv → finally: Uninstall → Verify →
settle → assert_game_alive`。每一根箭头的理由也在 donor 节里写完,不重复;本仪器独有的一条是
`NEEDED_EXPORTS` 的**九名**(`C2Sanity` + 八个 `C4WitnessProbe{Install,SetMask,Uninstall,Verify,Layout,
StatsInto,DrainInto,Reset}`),缺一名即不注入 —— 从文件核,不从进程核。

**依赖码**:与 donor 同一张表,导出名前缀换成 `C4WitnessProbe`:`Install` `0` / `-2`(本进程已装好**或**
predicate detour 还 armed)/ `-3` stellaris.exe 未找到 / `-4` 目标已被 hook / `-5` 指纹不符 / `-6` patch 过宽 /
`-1` 其余;`Uninstall` `0` / `-7`(打印 `RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY`,放弃该进程);
`SetMask` 恒 `0`(任何 u64 都合法,`mask=0` 有语义);`Verify` 原样透传 `-1/-2/-3`。`-2` **不重试**,
唯一杠杆是新进程。清理段之后**绝不 `FreeLibrary`**。

**verdict 值域**(`VERDICTS` 是唯一权威;退出码 0 只给两个 hit 证据档且清理成功):

| verdict | 读数 | 这是什么 |
|---|---|---|
| `witness_family_hit_named` | 某个 `hN>0` 且 `installed==1` | 经这一族的 `slot[2]` 派发成立,并**指名哪张表**(`table_rvas()[N]`;index 2 = `0x25F4440`)—— 这就是第三档需要的那半句「执行确实发生」 |
| `witness_family_hit_unknown_table` | `calls>0`、`installed==1`、五个 `h` 全 0、`unmatched>0` | 五表之外的 `[self+0]` ——**交给静态查表的接力**(环 `self_vtable_rva` + `#meta` 的 span 三分区)。注意这里的分母是 **454 个静态 qword 对 5 张承认的表**(donor 那个数是 538),图像内 code-address 读数更容易涌入,接力之前什么都别下结论 |
| `no_calls_inconclusive` | `calls==0` | **ENVIRONMENT**。证人安静 ⇒ 第三档资格**不成立**,而不是成立 |
| `instrument_broken` | `invalid_self>=calls` 且其余计数全 0 | 读不出 `[self+0]`,本仪器对本次观测没有陈述能力 |
| `counter_desync` | `calls>0` 但没有一个计数器对上;或 `installed!=1`;或整跑没有一条完整 stats 行 | 记账坏了。两条代码档的门就在这一档前面 |

**三条判读陷阱(证人版)**:

1. **证人安静 ≠ 第三档,而且这条比 donor 那边更要命。** §57.4 的第三档 = 「证人 `calls>0`(执行确实发生)
   **且** donor `calls==0`」。本仪器的 `no_calls_inconclusive` 是这条判据**前半句失败**的记录,值域里同样
   没有「这一族不执行」这一档(`test_verdicts_has_no_tier3_value` 把五个字面量与三条禁用名一起钉死)。
2. **predicate armed 时每个读数都是假的 tier 2。** 与 donor 同一机制:那种状态下实例化对象的 `[child+0]`
   指向我们 DLL 里的 vtable 副本,永远落在五表之外 ⇒ 模块 `preflightChecks` 直接拒装(`-2` 的第二成因)。
   除了它,同一假 tier 2 还有两类来源:图像内 code-address `[self+0]`(**454** vs 5)与 `toRva`→0 的图像外
   读数(含 64 MiB 窗口内、真实 `SizeOfImage` 之外那 ~6.8 MiB 尾巴)。`#meta` 的 span 三分区拆的是环记录,
   计数侧拆不开。
3. **两个仪器的 `[self+0]` 不同源,不得互引。** 证人的 `self_ptr` 是 `slot[2]` 的接收者,donor 的是 `slot[1]`
   的接收者;同一次 shot 里两边都见到同一个 vtable,也只说明**两槽各被派发过**,不说明是同一个对象实例。
   `mask != 0` 时 ring 与 counters 的不同源问题照 donor 第 3 条:比例只从 counters 取,**先跑 20 s 窗口读
   `calls` 增量定这一族的真实频率**,再决定带不带 mask。

`run()` 同样**先写 meta-only artifact 再 drain**,`entries_error` 只标记 drain 失败,不许吃掉已拿到的读数。

判读纯函数(`decode_layout` / `decode_entry` / `decode_stats` / `verdict_for` / `table_rvas` / `write_tsv` /
`partition_unmatched` / `build_meta`,常量 `VERDICTS` / `EVIDENCE_VERDICTS` / `NEEDED_EXPORTS`)由
`python3 -m pytest scripts/test_c2_witness_probe.py -q` 覆盖(**16 条**:donor 的 14 条平移换靶 +
`test_verdicts_has_no_tier3_value` + `test_prologue_bytes_pinned`),无游戏、无 Windows API、零 shot。

### `scripts/c2_shim_probe.py [dll] [--mask 0] [--poll-s 120] [--settle-s 2] [--out C:/temp/c4_shim_probe.tsv]`

第四把 guard,**族外证人**。靶不是族内的 `0x3AFD30` / `0x3B01A0`,而是 structures §13 那**七把各 2,090 次**的
exec shim 里的第一把 `0xCC4220`。**已运行过两窗**(2026-10-27 取证卷 §72:频率窗 20 s `calls=0`,正式窗 120 s
`calls=2016` / `h0=2016` / `unmatched=0` ⇒ `shim_hit_named`,命中表首 `0x25460F0`,`caller_rva`(环里 256 条
= 2,016 次里的**最后** 256 次;前 1,760 次未被记录)全 =
base Execute `0x1D08520` + 0x5A),产物 `evidence/logs/shim_probe_4_4_4.tsv`。运行需要本次会话内点名,
见 `docs/roadmap.md` 的授权表。默认 DLL `C:\temp\sqjs_c4.dll`,argv 与 donor/witness 逐字同形。

**它与 donor / witness 的关系**:donor 钩 `0x3AFD30`(**slot[1]**,Execute 的覆写),witness 钩 `0x3B01A0`
(**slot[2]**,派发位);本仪器钩 `0xCC4220` —— **也是 slot[2]**,但它那张 vtable `0x25460F0` **不在家族五张**
里(§71.3 段②:七张 × 五张 = 空集)。所以**差的是表,不是派发位**;三者的读数**不共源,不许互相引用**。

**它读谁的字节**:唯一一次引擎内存读是 `[self+0]`,拿它的 RVA join `OUT_OF_FAMILY_VTABLES`
**七张**(`src/dll/c2/shim_witness_probe.zig:52`);`ctx_ptr` / `a3` / `a4` 只按**值**记录,一个都不解引用
(陈旧指针最多让驱动侧一次读返回 `None`)。函数体恒转发原函数;引擎字节同样只在 install 的 JMP、
`removeHook` 的还原、`restoreTarget` 三处被写。前置指纹是 `0xCC4220` 的 24 字节原前序
(`48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 48 83 ec 20 0f b6 79 08`),逐字节不符即 `-5` 拒装;
围栏 `scripts/test_c2_shim_probe.py` 把它和七张表钉回它们的权威(exe 逐字节 + 取证卷 §71.1)。

**它与 census 是两个口径**:`calls` 是 **`0xCC4220` 这一个函数被调了多少次**(本 guard 只 patch 它一个),
**不是** base Execute 的派发次数;`table_hits` 是逐次原子计数(`shim_witness_probe.zig:184`),早于采样门
⇒ 比例只从 counters 取,频率先按 20 s 窗口的 `calls` 增量测再定分母。`unmatched` 吸收**七张表之外**的
对象 vtable。

**门序**:与 donor/witness 同形 —— `resolve_pid → resolve_base_address → sha 门 → gate_module(NEEDED_EXPORTS)
→ Layout → Reset → SetMask → Install → 轮询 Stats → write_tsv(meta only) → Drain → write_tsv(rows) →
finally: Uninstall → Verify → settle → assert_game_alive`。
(本工具的 `write_tsv` 有两次:先写 meta-only artifact 再 drain,理由见本节末尾与驱动 docstring
`scripts/c2_shim_probe.py:31-35` —— stdout 整段丢时,artifact 仍在。)
`NEEDED_EXPORTS` **九名**(`C2Sanity` + 八个
`C4ShimProbe{Install,SetMask,Uninstall,Verify,Layout,StatsInto,DrainInto,Reset}`),缺一名即不注入 ——
从文件核,不从进程核。

**依赖码**:前缀换成 `C4ShimProbe`:`Install` `0` / `-2`(本进程已装好**或** predicate detour 还 armed)/
`-3` stellaris.exe 未找到 / `-4` 目标已被 hook / `-5` 指纹不符 / `-6` patch 过宽 / `-1` 其余;
`Uninstall` `0` / `-7`(打印 `RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY`,放弃该进程);`SetMask` 恒 `0`
(任何 u64 都合法,`mask=0` 的语义是「每条调用都记」,见 `scripts/c2_shim_probe.py:388-394`);
`Verify` 原样透传 `-1/-2/-3`。`-2` **不重试**,唯一杠杆是新进程。清理段之后**绝不 `FreeLibrary`**。

**layout 词**:`entry=48 stats=64 ring=256 mask=0 version=1` —— `stats` 那 64 B 是 `Stats` 结构体
(14 个键:`calls` / `samples` / `invalid_self` / `unmatched` / `h0`…`h6` / `patch_size` / `installed` / `mask`),
其中 `table_hits` 是 `[7]u32` ⇒ 比 donor/witness 的同族表多两格。

**verdict 值域**(`VERDICTS` 是唯一权威;退出码 0 只给两个 hit 证据档且清理成功):

| verdict | 读数 | 这是什么 |
|---|---|---|
| `shim_hit_named` | 某个 `hN>0` 且 `installed==1` | 七张族外表之一被命中,并**指名哪张**(`table_rvas()[N]`)—— §57.4 第三档要的「执行确实发生」形态 |
| `shim_hit_unknown_table` | `calls>0`、`installed==1`、七个 `h` 全 0、`unmatched>0` | 七张表之外的 `[self+0]` ⇒ **交给静态查表的接力**(环 `self_vtable_rva` + `#meta` 的 span 三分区) |
| `no_calls_inconclusive` | `calls==0` | **ENVIRONMENT**。安静 ⇒ 只说「本窗口没观测到」,**不是**「这一族不执行」 |
| `instrument_broken` | `invalid_self>=calls` 且其余计数全 0 | 读不出 `[self+0]`,本仪器对本次观测没有陈述能力 |
| `counter_desync` | `calls>0` 但没有一个计数器对上;或 `installed!=1`;或整跑没有一条完整 stats 行 | 记账坏了。两条代码档的门就在这一档前面 |

**四条判读陷阱(族外证人版)**:

1. **形状 ≠ 身份。** 七张表的命中是**形状**判据(§57.5 第 2 条):「命中表 0」不等于「这个类是 X」;
   「不在七张里」≠「族外没有另一份表」—— 家族五张是**有界集合**,map 的 1,805 是**下限**(AGENTS 段3 第 3 行)。
2. **`calls>0` ≠ per-system。** §13 的 2,090 是 2026-09-29 那次场景的读数,原话要求先用换场景 / 换银河大小
   做相关性(`correlate … before claiming it`);复采同场景只算重复确认。**`calls=2016` 也只是
   `0x25460F0` 这一把在 120 s 内被调 2,016 次,不是族外执行总数。**
3. **七张表是下限,不是族外全集。** join 表只有七张;表外的对象 vtable 全落 `unmatched`。`unmatched=0` 的
   确切含义是「**全部 2,016 次调用**的对象 vtable 全在七张之内(`unmatched` 是逐次、采样门之前的计数)」—— 不是「世界里只有这七张表」。
4. **`h1..h6 = 0` 不携带其余六把的信息。** 本 guard 只 patch `0xCC4220` **一个**函数,而七张表里只有
   `0x25460F0` 的 slot[2] 是它 ⇒ `h1..h6=0` 是**仪器口径的结构决定**(前提:没有第二张表也把它放在 slot[2];
   该前提的离线支撑是 §71.3 的 `.rdata` hits=1 —— 那是**下限、只覆盖 `.rdata`**,运行时复制出的 vtable 由窗内
   `unmatched=0` 闭合)。它**不**回答「另外六把 shim 跑没跑」—— **那由 census 逐把计数回答(§74)**;
   guard 的 `h1..h6` 只回答「本次**全部 2,016 次调用**的对象 vtable 是不是 `0x25460F0`」这一**身份**问题。
   完整论证见取证卷 **§72.8**。

`run()` 同样**先写 meta-only artifact 再 drain**,`entries_error` 只标记 drain 失败,不许吃掉已拿到的读数。
判读纯函数(`decode_layout` / `decode_entry` / `decode_stats` / `verdict_for` / `table_rvas` / `write_tsv` /
`partition_unmatched` / `build_meta`,常量 `VERDICTS` / `EVIDENCE_VERDICTS` / `NEEDED_EXPORTS`)由
`python3 -m pytest scripts/test_c2_shim_probe.py -q` 覆盖(**15 条**:donor 的 14 条平移换靶 +
`test_prologue_bytes_pinned`),无游戏、无 Windows API、零 shot。

**驱动字节变了(2026-10-28)**:本节与 §72.8 落账后,驱动的 docstring 加了**陷阱 4**(三条 → 四条),
现 sha256 前 16 位 = `3a2db17782129980`。下一发窗口按 §70.6 的规矩**重新 scp 并核对 sha**,不要沿用
§72.2 记的那份 `c2_shim_probe.py = 791f3a8e…`(那是加陷阱 4 之前的字节;读数不受影响,但「主机侧那份
= git HEAD」这条对账会当场不过)。

### `scripts/c2_trigger_pred_probe.py [dll] --systems N --script-file <path> [--poll-s 120] [--settle-s 3] [--script-wait-s 180] [--out C:/temp/c4_trig_pred.tsv] [--cmd-file C:/temp/ns_game_cmd.txt]`

**第五把 guard,C5 数据面的第一发。** 靶是**触发谓词基体** `0x349230`(取证卷 §75):trigger 的
`[vptr+0x80]` 的共用实现,72 B,实参 `(self, X)`;`.rdata` 里 1,091 个 qword 等于它。与 C4 那条线
**不是同一族**:C4 钩的是 effect 侧(`0x3B1420` 谓词 / `0x3AFD30` Execute),本仪器钩 trigger 侧。

**这一发问的是两个数**(不是「scope 是谁」):一个 trigger 放进 `every_system` 的 `limit` 之后,
谓词被调**几次**(`token_matched`),以及每次的第 2 实参 X 的**值**(`x_ptr`)。**X 不解引用** ——
§76 实测它是常量 `0x80`(scope/类型掩码),`x_vtable_rva` 这一列在本靶上恒为 0,留着是给将来的靶用。
两个方向都算读数 —— `predicate_per_system`(≈ 星系数)与 `predicate_instantiate_once`(==1)都是
`EVIDENCE_VERDICTS`。`no_calls` 只算环境(getcensus 的口径照旧)。

**两段脚本**:`--script-file` 每行一条 console 脚本。第 1 行用 `C1Run` 当场铸出的 `neo_effect` token
(unique,但它的 class_info 借的是 country 侧 donor,放进 system scope 可能被判非法);第 2 行用官方
system-scoped 的 `is_rim_system`(token 18203,`--rim-token` 可改)。两段**分别记窗口**(`stats_a_delta` /
`stats_b_delta`),`token_matched` 不合并 —— 合起来读会把两段混成一个数。

**门序**(照 §70.6 与 `c2_shim_probe` 的家族纪律):`preflight_paths`(开火前两条拒绝,见下)→
`sha_gate`(**打印并记录**注入文件的 sha256,不断言固定常量;文件不在即 `exit 2`)→
`list_exports` 核文件里的十个导出 → `refuse_if_resident`(同名模块已在进程里就拒绝)→ `gate_install`
(world-state 门,注入前)→ `inject_dll` → `C2Sanity==42` → `C4TrigPredLayout` 与驱动常量对账 →
`C4TrigPredReset` → `C4TrigPredInstall` → `C1Run` 取 token → 每段 `SetToken` + 发脚本 + 读 delta →
`--poll-s` 观测窗 → `C4TrigPredUninstall` + `Verify` + settle + `assert_game_alive`。
`Install` 返回 `-2`(已装 / predicate armed)**不重试**;`-5`(指纹)是「靶读错」的发现,停手留证。

**判读陷阱(本仪器专属,三条):**

1. **`script_refused` 不是仪器坏了,`no_calls` 也不是「这一族不存在」。** 脚本没送达或它的 log marker
   没出现 ⇒ `script_refused`;脚本跑了但谓词一次没匹配 ⇒ `token_absent`;连谓词都没被调 ⇒ `no_calls`。
   三条互不替代。`neo_effect` 在 system scope 里被判非法时,长这样的是**第 1 段**——第 2 段照样给读数,
   所以别因为 A 段失败就丢掉整发。
2. **21 字节指纹不够。** `0x349230` 与 effect 谓词 `0x3B1420` 的前 21 字节**逐字节相同**,只有偏移
   24..26 的调用槽不同(`FF 50 70` vs `FF 50 78`)⇒ guard 钉 32 字节,驱动的
   `install_decision` 也核 `prologue_len == 32`。看到「指纹过了但装错函数」的怀疑,先核这一格。
3. **`--systems` 没有默认值,这是故意的。** 787 属于另一场存档(`chokepoint_table.zig` 的 `SAVE_SHA256`),
   拿它当分母会把 `token_matched=1` 判成 `predicate_instantiate_once` —— 结论对,理由错。分母只从
   `save_hypergraph.py` 对**当前存档**重建的边表来。

**开火前的两条拒绝(不是陷阱,是门的一部分;都 `exit 2`)**:`--script-file` 指向的文件不在 ——
打错的路径在 ssh 转手后变成一段与 stdout 丢失混在一起的 traceback(陷阱 8/11);`--cmd-file` 的
**名字与目录**都必须是 supervisor 那一个 —— `C:\temp\ns_game_cmd.txt`。§76.4 那次写成 `ns_cmd.txt`,
两段窗口各白等 180 s 且都读成 `script_refused`;**只核名字是不够的**(2026-10-28 复审 I-2):daemon 读的是
唯一一条绝对路径,换个目录的同名文件同样没人消费。退出码与 donor 的 `sha_gate`(`SystemExit(str)` = 1)
不同码,别混读。

**同名模块已在进程里 = 拒绝(复审 I-1)**:`sha_gate` 算的是**磁盘上那个文件**,而 `inject_dll` 走
`LoadLibraryA`;DLL 永不卸载,同名模块已在时载入器会**复用既有镜像**,新字节根本不会映射 —— artifact 里
的 `dll_sha256` 就成了「一份从没跑过的字节」的证明。两条合法的出路写在拒绝消息里:换名上传(§76.7 的
`sqjs_c5.dll`)或用新进程。

**artifact**:`#meta` 在前(含 `overall_verdict` / `verdict_a` / `verdict_b` / `stats_*_delta` /
`uninstall_rc` / `verify_rc` / `host_alive`,外加 **`dll` / `dll_sha256` / `module_base`**),
然后是 `token self_ptr self_vtable_rva x_ptr x_vtable_rva`
五列的行。`run()` **先写 meta-only artifact 再 drain**,`entries_error` 只标记 drain 失败。
那三格是**溯源**不是装饰:§70.6 的上线门要求主机那份字节与本地构建逐字对上,§76.7 那次
`sqjs_c4.dll` 与 `sqjs_c5.dll` 在同一进程并存 ⇒ 没有它们,「部署静默失败」与「真读数」在 artifact 上
长得一模一样。**口径要说准**:`dll_sha256` 是**注入路径上那个文件**的 sha,不是「实际跑着的镜像」的 ——
所以同名模块已映射时驱动直接拒绝(`refuse_if_resident`,复审 I-1),不靠这一格去猜。`dll` 按两种分隔符
取 basename(纯函数在 Linux 上也要跑测试)。
判读纯函数(`parse_stats` / `verdict` / `window_refused` / `overall_verdict` / `decode_layout` /
`decode_entry` / `install_decision` / `artifact_rows` / `parse_mask` / `parse_c1_result` /
`script_marker` / `sha_gate` / `build_meta` / `preflight_paths` / `refuse_if_resident`,常量
`STATS_KEYS` / `VERDICTS` / `EVIDENCE_VERDICTS` / `SUPERVISOR_CMD_NAME` / `SUPERVISOR_CMD_DIR`)由
`python3 -m pytest scripts/test_c2_trigger_pred_probe.py -q` 覆盖(**44 条**),无游戏、无 Windows API、零 shot。

**drain 的坑(2026-10-28 review Critical)**:满环是 `RING_LEN * ENTRY_SIZE` = **10,240 B**,而
`C4TrigPredStatsInto` 的文本缓冲只有 512 B。驱动在 drain 前必须 `remote_alloc(RING_LEN * ENTRY_SIZE)`
并调 **`C4TrigPredSetDrainCap(10240)`** 声明容量(DLL 侧 clamp,未声明就返回 0 行)。`call_remote_with_arg`
只能传一个寄存器,所以容量是 setter 而不是第二个实参。

### `scripts/c2_trigger_eval_probe.py [dll] --systems N --script-file <path> [--poll-s 120] [--settle-s 3] [--script-wait-s 180] [--out C:/temp/c4_trig_eval.tsv] [--cmd-file C:/temp/ns_game_cmd.txt]`

**第六把 guard,C5 数据面的第二发。** 靶是触发**求值**槽的共用基体 `0x1A91A80`(取证卷 §77):
trigger 的 `[vptr+0x28]` 的共用实现,收 `(self, ctx, a3)`;`.rdata` 里 **352 个绝对地址**等于它。
与第五把(`0x349230`,**谓词**槽)是**两个不同的槽**:谓词是实例化期检查,本槽是每次求值都走。

**这一发问两个数**:被调**几次**(`calls`)、拿到的 `ctx` 有**几个不同的值**(`distinct_ctx`),
外加 `ctx` 上那两格**已被代码证实**的字段:`ctx+0x158`(类型标签,§77.1 ③ 必须是 1 或 0x426)与
`ctx+0x278`(被当对象传给下一层,`lea rdx,[rbx+0x278]`;它的首 qword 若是 vtable,一格读数就给出
「那个子对象是什么类型」)。**不解引用第二层** —— §59/§73 已经证明「猜偏移链」这条路是死的。

三个方向都算读数:`ctx_per_system`(distinct ≈ 星系数)、`ctx_single`(== 1)、
`ctx_not_per_system`(别的正数)。`no_calls` / `token_absent` / `script_refused` /
`ctx_table_full` / `instrument_broken` 都是环境档,**不是**证据。

**门序**(照 §70.6 与兄弟驱动的家族纪律):`preflight_paths`(开火前两条拒绝,见下)→ `sha_gate`
(**打印并记录**注入文件的 sha256,不断言固定常量;文件不在即 `exit 2`)→ `list_exports` 核文件里的
十一个导出 → `refuse_if_resident`(同名模块已在进程里就拒绝)→ `gate_install`(world-state 门,
注入前)→ `inject_dll` → `C2Sanity==42` → `C4TrigEvalLayout` 与驱动常量对账 → `C4TrigEvalReset` →
`C4TrigEvalInstall` → `C1Run` 取 token → 每段 `SetToken` + 发脚本 + 读 delta → `--poll-s` 观测窗 →
`C4TrigEvalUninstall` + `Verify` + settle + `assert_game_alive`。`Install` 返回 `-2` **不重试**;
`-5`(指纹)是「靶读错」的发现,停手留证。

**判读陷阱(本仪器专属,三条):**

1. **`ctx_not_per_system` 不是「没有星系身份」,只是「ctx 不是每系统一个」。** 它否掉的只有「每系统
   一个 ctx」这一条;ctx 到底是什么对象,这一发给不出答案。`ctx_single` 同理(它比
   `ctx_not_per_system` 更强一点:全程只有一个 ctx)。
2. **`sub_vtable_rva = 0` 是「我们认不出来」,不是「没有 vtable」。** `[ctx+0x278]` 落在镜像外时记 0
   —— 那可能是堆对象,也可能我们算错了基址;读成「那个子对象没有类型」是过度解读。
3. **`dedupe_full != 0` 时 `distinct_ctx` 只是**下界**,分母判据当次作废。** 去重表 1,024 槽满了以后,
   新的 distinct ctx 不再计数(`distinct_ctx` 停在表里已有的数),verdict 落 `ctx_table_full`。
   那一档的读数**不许**用来支持任何结论。

**artifact**:`#meta` 在前(含 `overall_verdict` / `verdict_a` / `verdict_b` / `stats_*_delta` /
`uninstall_rc` / `verify_rc` / `host_alive`,外加 **`dll` / `dll_sha256` / `module_base`**),
然后是八列的行:`token ctx_tag sub_vtable_rva self_vtable_rva occurrences ctx_ptr a3 sub_obj`。
`run()` **先写 meta-only artifact 再 drain**,`entries_error` 只标记 drain 失败。
`dll_sha256` 是**注入路径上那个文件**的 sha,不是「跑着的镜像」—— 所以同名模块已映射时驱动直接拒绝
(`refuse_if_resident`)。`--systems` **无默认值**:分母只从当前存档重建的边表来(787 属于另一场存档)。
判读纯函数由 `python3 -m pytest scripts/test_c2_trigger_eval_probe.py -q` 覆盖(**18 条**),无游戏、
无 Windows API、零 shot。

**下一发照单执行(机器回来时;本节就是那一发的清单)**

*两段脚本*(`C:/temp/ts_scripts.txt`,一行一条;**上次这两行的确切文本没有入库**,下面是按 §76 的读数与
本地游戏数据的 DSL 形状反推的 —— 引擎里 `common/scripted_effects/cosmic_storms_scripted_effects.txt:1231`
就是 `limit = { is_rim_system = yes }` 这个写法):

```
effect every_system = { limit = { neo_effect = yes } log = "TS_NEO_[This.GetName]" }
effect every_system = { limit = { is_rim_system = yes } log = "TS_RIM_[This.GetName]" }
```

第 1 行用 C1 当场铸出的 `neo_effect`(token 68636);**它可能被引擎判非法** —— 它的 class_info 借的是
country 侧的 donor(§24.6),放进 system scope 是否合法**至今未验证**(§76.4 ③:那次它连命令都没被送出去)。
第 2 行用官方 system-scoped 的 `is_rim_system`(token 18203)—— **带读数的是第 2 行**,第 1 行只是探针自身的
一个对照。marker 的字面量前缀(`TS_NEO_` / `TS_RIM_`)是驱动的 `script_marker` 认的东西,改脚本就要同步改前缀。

*上线清单*(§70.6 的两道门):

```bash
# 1) DLL:新名字(已装载的文件覆盖不了 —— §76.7 的实测),再对 sha
scp zig-out/bin/stellaris_quickjs.dll Windows_Jiaolong:C:/temp/sqjs_c6.dll
just win "Get-FileHash C:/temp/sqjs_c6.dll -Algorithm SHA256"     # 对上 ec3716a2…(重建后会变,以本地为准)
# 2) 驱动:主机那份必须与 git HEAD 逐字一致
scp scripts/c2_trigger_eval_probe.py Windows_Jiaolong:C:/temp/
```

*命令序列*:

```bash
just game cmd status                     # 清掉上一次的 quit,否则新 daemon 起来就退出
just launch                              # 或 just game start
just game unpause
just win "python C:/temp/session_bridge.py C:/temp/ns_world.py status"   # → IN_GAME_RUNNING
just win "python C:/temp/session_bridge.py --timeout-s 420 C:/temp/c2_trigger_eval_probe.py \
  C:/temp/sqjs_c6.dll --systems <当前存档的星系数> --script-file C:/temp/ts_scripts.txt \
  --poll-s 120 --out C:/temp/c4_trig_eval.tsv"
scp Windows_Jiaolong:C:/temp/c4_trig_eval.tsv evidence/logs/c5_trig_eval_4_4_4.tsv
```

`--systems` **必须从当前存档重建**(`scripts/save_hypergraph.py` → 边表),**不许沿用 787** —— 787 是
2026-10-28 那场战役的,分母错了会得到「结论对、理由错」的读数(§76 陷阱 3)。

*读数怎么读*(三条陷阱在上一段):`distinct_ctx` ≈ 星系数 ⇒ `ctx_per_system`;== 1 ⇒ `ctx_single`;
别的正数 ⇒ `ctx_not_per_system`。`sub_vtable_rva` 落在镜像外时是 0(「认不出来」,不是「没有」);
`dedupe_full != 0` 时 `distinct_ctx` 只是下界,那一档不作结论。

*三条通道缺陷已经在里面了*(§76.4 记的、当时还没修的):`game.log` 缓冲 ⇒ `SCRIPT_WAIT_S = 180`
(不是 30);verdict 把 poll 窗算进去(`overall_verdict`);未送达的命令不会被下一条覆盖(`delivered` 假
就停)。

## 实机调试:游戏监督器(`scripts/windows/game_supervisor.py`)

一个长驻在 Windows 机上的小循环:每 tick 读右上角暂停图标、读事件窗口带、消费一次命令文件,然后把
「想要的状态」推到游戏上。给 agent 用 —— 它把「事件弹出导致暂停、要人点选项」这种原本必须人盯的环节
变成一次文件写入。

宿主侧经根目录 `justfile` 调用(`NS_WIN_HOST` 可覆盖主机名):

```
just deploy                  # scp scripts/windows/ 的 7 个维护中脚本到 C:/temp/(含 popup_geometry.py:game_supervisor.py 第 25 行 import 它,漏了就 ModuleNotFoundError)
just launch                  # 经 Steam 拉起游戏(launcher 点击 + 30 s 观察窗,启动后仍是暂停)
just game start              # schtasks 拉起守护进程,见到状态心跳才返回
just game status             # 一行摘要:state/note/pid/hwnd/age/want/policy/handled/cmd/speed
just game serve --no-ocr     # 直接前台跑:整条身份路线只留几何,一次 OCR 都不问
just game serve --popup-allowlist PATH   # 换名单文件(默认 C:\temp\ns_popup_allowlist.json)
just game pause | unpause | toggle
just game want playing       # 持久目标,不是一次性动作
just game policy first       # first | last | random | <1-based n>
just game choose 2           # 对当前事件一次性选第 2 项
just game speed up | down
just game click 1400 861     # 屏幕绝对坐标(窗口在 (0,0) 时等于窗口坐标)
just game console effect every_system = { log = "X" }   # 原样写进控制台(剪贴板粘贴)
                                             # 注意 keyword 在 effect 后、= 前;带括号的命令经
                                             # just/ssh 转手会被远端 shell 改写,驱动直接写命令文件
just game console_sync open | closed | auto   # 人工声明面板当前是否开着(auto 交还给像素观测)
just game console_close                      # 只在标记为「开」时按一下开关键,把状态收回「关」
just game dismiss            # 只在 paused 且有窗口 bbox 时生效(人工一次性动作,不走名单)
just game close              # WM_CLOSE 优雅关窗口(游戏会话内 PostMessage;不是 kill)
just game shot               # 存 C:\temp\ns_game_shot.png
just game stop | quit
```

`want=playing` 时,监督器发现「被事件或人暂停 + 有选项窗口」会先点一行再恢复运行;没有窗口的裸暂停
按「可能是人按的」处理,只报 `paused_no_window`、不发 Space —— 要恢复就发一次 `unpause`(或 `want playing`),
它带一个只生效一次的 `resume` 覆盖。`want=paused` 时反过来:只保留它自己发起的暂停。默认策略 `first`。

产物:`C:\temp\ns_game_status.json`(状态心跳,含 `epoch`)、`ns_game_log.jsonl`、`ns_game_shot.png`、
`ns_game_supervisor.out`(pythonw 的 stdout/stderr)、`C:\temp\ns_popup\`(弹窗证据,**有界 40 张**,
一个身份一张代表帧,重复见到同一 id 是覆写不是堆积)、`ns_popup_live.png`(每 tick 覆写的 OCR 输入帧,
故意放在 `ns_popup\` **外面** —— 它不是证据,也不许被裁剪)。`state` 取值
`playing|paused|unknown|no_game|stopped`。

状态心跳新增 `popup` 一格:`{popup_id, source, ocr, ocr_ms, ocr_ms_total, attempts, same_hits}`。
读法是「**最后一次识别到的弹窗**」,不是「当前帧上有这个窗」—— 当前 tick 到底有没有窗,看 `window` 与
`note`。`ocr_ms_total` 是这一场为身份花掉的累计毫秒(会话总额 `POPUP_OCR_BUDGET_MS = 24 s`),
`ocr` 那一格同时是降级原因:`ok` / `disabled`(`--no-ocr`)/ `budget_spent`(问光了)/
`unavailable`·`model_missing`·`error`(眼睛坏了)。jsonl 新增事件
`popup_seen`(判据全量)、`popup_evidence`(存证路径,`no_bbox` 时为 `null`)、`popup_decision`、
`popup_prune`。

**判读陷阱:**
1. **SSH 会杀子进程树**,守护进程不能直接挂在 ssh 会话下。`start` 写一个只含 ASCII 的 `.cmd` shim,
   用 `schtasks /ru <user> /rl highest` 跑 `pythonw ... serve`;返回条件是**状态文件心跳**,不是
   schtasks 的退出码。改了 `game_supervisor.py` 要重新 `deploy` 再 `stop` + `start`(进程不会热加载)。
2. **命令文件只消费一次**,键是 `mtime_ns:size`;写入相同字节也算新命令。空行与不认识的动词只进日志,
   不动作。缩写入口(`just game pause`)等价于 `cmd pause`,固定等 0.8 s 后打状态 —— 这次状态可能是**动作
   之前**的心跳(`unpause` 后第一次读仍常显示 `paused`),要确认结果就再读一次 `just game status`。
3. **暂停图标按窗口相对几何采样**:右上角 `w-243..w-198, y5..50`(2160x1440 量得),红 956..965 / 绿 0
   为 paused,绿 200..207 / 红 0 为 playing。同一个 4.4.4 会话里暂停图标还会以橙红色出现(掩码 209 像素),
   所以 paused 的下限是 80 而不是峰值;顶栏棕色背景(`r<140`)落在掩码外。换分辨率、UI scale 或窗口模式
   要重新量;`unknown` 是真实第三态,监督器对 unknown **不动作**。
4. **事件窗口自己会暂停游戏,关窗口又可能自己恢复**。所以每次动作后都重新读图标,不复用上一 tick 的
   判读;`_restore` 发现链式窗口(刚关掉一个又弹一个)时推迟 Space,留给下一 tick 处理。
5. **choice 的判据是金色行,不是 bbox**:行需 `x0>=1150 && x1>=1450`、至少 2 行、gold>=8000。
   新闻窗口右边界约 1420,因此不会被当成选项。`dialog`(有面板、无金色行)走**弹窗身份路线**
   (`popup_tick` + `apply_popup_decision`):认得出且**名单里写了 `dismiss`** 才点 ✖,认不出、OCR 坏了、
   名单缺失/坏 JSON、连点 3 次没效果、同一 id 连见 6 拍 —— 全部**停手**并留证。旧的 `serve --auto-dismiss`
   开关与 `dialog_unknown` note 已随之删除:点 ✖ 的几何只在实测过的窗口类型上可信,而「可信」现在由名单表达,
   不再由一个总开关表达。
6. **数字键不选选项**(实测),必须点行中心。同一组行签名连点 3 次后记 `choice_stuck` 并停手,
   防止在无响应窗口上打转。
7. **`console <text>` 走剪贴板,不是逐字符打字**:`parse_command` 保留 `<text>` 的大小写、内部空白
   与引号,`_set_clipboard_text` 以 UTF-16LE + 双 NUL 写进剪贴板,再发:反引号(仅在
   `console_open` 为假时)→ 64 个退格 → Ctrl+V → Enter,**不发收尾反引号**。两条实机事实
   (2026-10-23):控制台键是**开关**,开着的面板被再按一下会**关掉**;命令执行完面板**不关**。
   不做状态记录时,同一会话的第二条命令的「开面板」那一下会把面板关掉,退格/粘贴/回车全打进游戏,
   命令一行都不执行(实测 783 条哨兵 0 行 —— 这正是 C4 第一次 shot `capture_not_delivered` 的机制)。
   所以 supervisor 用 `console_open` 记状态:首条命令按一下打开,之后只清行、粘贴、回车;换游戏
   进程时复位,人工看屏后可 `console_sync open|closed` 校正。64 个退格清输入行残留,退格 20 ms/个、
   其余 80 ms/个。`focus(hwnd)` 3 s 内拿不到前台就写 `console_refused`(不按键);剪贴板失败写
   `console_clipboard_failed`;成功写 `console_sent`(带 `opened` 标记)。`_send_key_events` 是
   **成对** down/up,修饰键必须跨 V 的 down/up 按住,所以 Ctrl 只能用 `_send_input_event` 逐事件发。
   数效果 marker 用驱动里的 `count_marker_lines`(只数同时含 `Log effect, file:` 与 marker 的行,
   控制台回显匹配不上)。

   **`console_open` 是三值信念,不是布尔**(`True` 开 / `False` 关 / `None` 未知)。第二次 shot 暴露的
   不是「键序不对」,是**按键之前无人观测面板真的开着**:21:40:00 那条 `opened=true` 出 783 行,
   之后三条 `opened=false` 全 0 行,而这段时间 supervisor 日志里**一个事件都没有**(见 §54.9)——
   被按下的一次是 serve 循环自动补的 pause 空格,它把空格**打进开着的面板**,游戏因此永不暂停、
   像素判读一直报 `playing`,于是每个 tick 再按一次,而这条路**只写状态 note、不写日志**。
   现在的三条不变量:
   - **未知就拒绝**:`console_send_plan` 遇到 `None` 不猜奇偶,写 `console_refused` +
     `reason=console_state_unknown`,一个键都不按、剪贴板都不碰;只有 `console_sync` 或新进程能
     把 `None` 抬成已知值。宁可在日志里响一声,也不要一发静默的 0 行 shot。
   - **碰过游戏就作废**:任何发给游戏的输入 —— `speed`、`click`、`dismiss`、自动点选项
     (`click_row`)、自动关窗 (`click_close`) —— 之后立刻 `console_open = None`。点在游戏区可能
     关掉或夺走面板焦点,而 daemon 看不见。`shot` 只截图像素,不作废。
   - **面板开着时不发空格**:`send_pause_key(state, hwnd)` 在信念为 `True` 时返回
     `blocked_console` 并按下不按键,状态 note 变 `pause_blocked_console` / `resume_blocked_console`;
     信念为 `False`/`None` 才真按(按下不改变面板状态,所以不作废)。
   代价:面板被我们打开后,自动暂停会**卡住并写明理由**。退出办法是新动词
   **`just game console_close`**(2026-10-23 加):仅在信念为 `True` 时按一下开关键并把信念写 `False`,
   信念为 `None` 时同样拒绝(奇偶未知,按一下可能反而打开)。解析在 `parse_command` 的无参动词表里。

   **`console_open` 现在是观测,不再是纯信念**(2026-10-24 实机校准,§54.10)。serve 每个 tick 在
   `plan_step` **之前**读一次面板文本框 —— 窗口比例的 `(120,640)-(400,880)` @2160×1440,数亮度 >180 的
   像素:实测**关 = 0**(6 帧全 0)、**开 = 2315**(4 帧逐字相同),所以阈值定在
   `CONSOLE_CLOSED_MAX=120` / `CONSOLE_OPEN_MIN=600`,**中间带判 `None` ⇒ 拒绝**(上面第一条不变量)。
   判据是**单帧密集亮字数**,不是帧差:两帧同态都能差 5.4 万像素、变化框铺满全窗(主菜单背景在动),
   差分没有定位能力。状态文件多两个字段:`console_px`(当帧像素数)与 `console_forced`(是否被人工钉住)。
   `console_sync open|closed` 会**钉住**信念、盖过观测,`console_sync auto` 松开让观测接管 —— 钉住存在的
   理由是这个框只在主菜单与一次载入局上校过,别的界面若自己点亮该区域会被读成「开」(后果是拒绝动手,
   不是错误按键)。**读帧的时机有坑**:日志记到开启动画途中的帧是 `64118` 和 `1298`,中间还有一帧读回
   `0`,即「刚按完键那一瞬」不是稳态判据;要自证就读够时间,否则落到 `None` 走拒绝。
7. **`speed up/down` 实机已验证**:`up` 让标签从「常速」变「快速」,`down` 回落。命令会把 `speed_sha`
   的前后值写进状态,但绿色标签背景会脉冲,哈希自己也会变 —— 判结果要读截图里的两个字,不要只看哈希。
8. **scp 上传可用,批量下载会把 SSH 连接重置**:取产物用分块 base64,单次输出 **≤700 字节**稳定
   (900 字节起连接被重置),不要 `scp -r`。远端控制台是 cp936,shim 与命令行都刻意保持 ASCII。
9. 纯逻辑(暂停判读、窗口分类、策略、命令词表、几何归一化)在 Linux 上跑:`just host-tests`
   (= `cd scripts/windows && python3 -m pytest tests -q`)。Windows 专有路径只在实机被调用。
10. **daemon 的父壳 `cmd.exe` 是一个真实的桌面窗口,会占住前台并把游戏从前台挤下去**。
    `start` 的 shim 是 `.cmd`,任务用 `/ru <machine>\<user> /rl highest` + `/run /I` 跑,所以 cmd 在交互
    桌面上开了一个可见控制台窗(pythonw 自己无窗)。**daemon 晚于游戏启动时**,这个窗压在画面上并持有
    前台,`focus()` 的 3 s `GetForegroundWindow()==hwnd` 判据就永远不成立 ⇒ 一切要先 focus 的动词
    (`console`、`click`、Space)全拒,日志写 `console_refused reason=focus`、状态写
    `resume_failed: focus refused before Space`。**判据在这两个字符串上,不在 `game.log` 上** ——
    `game.log` 只收 `log=` 与少量消息(day-1 存档 177 B 完全正常),把它当「有没有战役」的证据会得出
    错结论(2026-10-24 实机,§56.1)。处置是 `taskkill /F /PID <cmd>` 只杀父壳:pythonw 不是被 job
    管的树,存活且窗一消失 focus 立刻通。顺带第二条:那个窗会**污染像素判读** —— §54.10 的面板计数和
    `classify_window` 都读同一张截图,挡与不挡之间 `note` 能从 `paused_no_window` 漂到 `dialog_unknown`。
    **2026-10-25 批次 2 出现第三种落法,比「漂」更糟:父壳窗挡住真弹窗 ⇒ 读到「没有窗」。** 一扇星系调查
    完毕的事件窗确实在屏上,检测器报 `paused_no_window`;把那两个 cmd 窗**最小化**之后,同一扇窗立刻被读成
    `text:2188ca0b`(`evidence/logs/unattended_popup_batch2_4_4_4.log` Step 7)。⇒ `popup` 那一格的
    「有没有窗」不是屏幕的事实,是**我们自己的遮挡状态的函数**;拿不到弹窗时先看截图里有没有我们的黑底
    控制台窗,再怀疑检测器。同批次一条同族读数:`just game shot` 在游戏被切到后台时给 141 B 的退化图,
    切回前台给 1,134,993 B 的有效截图 —— 与批次 1 那张「356×59 全黑」不是同一个机制(那条是 hwnd 拿不到
    有效矩形,这条是窗被最小化/切走),但都读成「屏幕上没有东西」。
11. **ssh 长连接会在长跑的实机驱动跑完之前被重置,那之后 stdout 全丢**。shot 的 artifact 若只在结尾
    打印(判词、Verify rc、host alive),就取不回来了。所以实机驱动的关键状态要能被**事后独立读回**:
    `scope_probe` 的 `installed` 是实时 bool、`verified` 是 `verify()` 的实时返回值(不是闩锁),
    配一次 `C2ScopeProbeStatsInto` 双读(`calls` 两秒不涨 = 热路径已还原)就把「Uninstall 跑过、引擎
    字节完好」证完,不需要驱动那行输出(§56.3)。

12. **OCR 状态不是弹窗身份。** `ocr=unavailable` 只说明我们的眼睛坏了,`geom:*` 那条 id 仍可能对应一个
    完全无害的窗;它的作用是让 daemon 停手,不是判那个窗有害。
    **2026-10-25 实机补一条同族的: 身份会随「我们还问不问得出字」而变。** 同一扇窗的第一拍读到 12 行
    ⇒ `text:26f8c449`,那一次就烧掉 27.1 s 把会话总额 24 s 用完;从第二拍起同一扇窗只能记成
    `geom:1060x320:r11`。后果不是「换了个名字」而已:`same_hits` 从 0 重计,`id_stuck` 全部累计在
    几何 id 上(本场 344 次),而 `text:` 那条 id 的 `attempts` 永远停在 0 —— 读表的人若按 id 聚合,
    会把一扇窗看成两扇(一扇有字、一扇卡住)。
13. **弹窗只在 `paused == "paused"` 时被扫**(本计划刻意**没**改成每 tick 无条件扫窗,所以不暂停游戏的
    弹窗 —— 覆盖层、系统通知、驱动倒计时确认 —— 现在仍然看不见)。这是范围决定,不是缺陷;要扩到那一条
    得另开计划,代价是每 tick 一次全窗口截图。
14. **一次内联 OCR 就是把 daemon 停住那么久,而省钱的方式只有「少问」。** 实测成本 ≈ 固定 1.5 s +
    每检出行 0.7 s(弹窗 5–8 行 ≈ 5–7 s,全图 73.7 s),supervisor 单线程 0.8 s 一拍 ⇒ 这段时间里命令
    不读、心跳不写,`just game status` 会看到一条旧记录。**两条看着像省钱的路上当不得**:缩小裁片不省
    时间也不省字(256 档反而 20.3 s 且逐行比对只剩 9/19 认对,surya 检测器自己会把输入放大到固定边长),
    调 batch 也不省(CPU 默认已是检测 8/识别 32,单次 ≤20 行本来就在一批里)。所以看到「心跳怎么停了
    7 秒」先查 `popup.ocr_ms_total` 有没有在涨、`ocr` 那一格是不是 `budget_spent`,而不是去改图片尺寸。
    **2026-10-25 实机读数把这条的成本抬高、节拍改口**:加载 `STATUS=ok MS=7494`(不是 1.5 s 那一档),
    一次 12 行裁片在 tick 内共 27,134.9 ms(扣加载 ⇒ 预测量 ≈ 19.6 s ≈ 基准线的 1.98 倍,刚好没到「两倍算异常」),
    一扇窗的首次真识别就把 `POPUP_OCR_BUDGET_MS = 24 s` 用光。节拍: 有窗时相邻 popup 三元组实测
    **≈ 2.2–2.5 s 一组**(不是这里写的 0.8 s),所以一次询问 ≈ 丢 11–12 拍。另外「用前后两行日志的时间差
    量停摆」这个设想在**边沿触发的第一次 shot**上用不了 —— 它前面没有 popup 行可比,只能读 `ms` 字段。
    **2026-10-25 批次 2 的第三组样本把「每行 0.7 s」这个斜率也撤掉**:三组同机同 `DEVICE=cpu` 同未缩小裁片
    —— 12 行 27,134.894 ms(批次 1)、14 行 36,810.77 ms(批次 1)、**12 行 42,885.37 ms(批次 2,
    `text:2188ca0b`)**。同样 12 行相差 **58%** ⇒ 固定+线性那个模型只能当量级,不能当预测;**能当判据的只有
    「一次真识别必然打穿 `POPUP_OCR_BUDGET_MS = 24 s`」这一条,它现在是三次一致的读数**(不是样本小的巧合)。
    打穿之后每一拍退回几何 id(陷阱 12 的机制),所以「`attempts` 怎么一直是 0」有一部分就是这么来的。
15. **逐拍重写的证据裁片不是版本化的文件,是同一个路径上的流**。`C:\temp\ns_popup\geom_<WxH>_r<n>.png`
    按**几何 id** 命名,而同一形状每拍都会再出现一次 ⇒ daemon 原地反复重写同一个路径,写方**不做原子替换**。
    批次 2 实测:同一个路径两次 ssh 之间远端 sha256 就从 `B2D5DEFF…` 变到 `E01E10FF…`,两次 scp 拿回的
    都是**带完整 IEND 但 IDAT 解不开**的图(PIL `unrecognized data stream contents`),尺寸 271,374 / 271,714 B
    对远端 271,826 B。对照:`text_2188ca0b.png` 逐字节稳定且可解码 —— 那个 text id 只出现过一次(预算随后花完)。
    ⇒ 「这张证据图能不能读」不是传输方式的函数,是**那个 id 会不会再出现**的函数;取 `text:*` 可以 scp,
    取 `geom:*` 要预期半写,判定得靠可解码的那一份。别把半写读成「daemon 写坏了图」。

### `scripts/execspy.py [observe_seconds] [--uninstall-only]` —— §13 shim census 的复采通道

**用法**:Windows 侧跑 `python C:\temp\execspy.py 60`(默认 45 s)。它把 DLL 装进正在跑的游戏、等
`base Execute` 真的安静下来再 install、观测指定秒数后打印 `stats` / shim histogram / 抽样记录,最后 uninstall 并
`verify`。`--uninstall-only` 跳过 install/观测,只拆一把已经装上的 detour(游戏先暂停,再跑一次)。

**它读谁的字节**:histogram 是**我们 DLL 的 `exec_hook` 记的**,不是 Frida 记的 —— `execspy.js` 的 `hist`
RPC 只调 `ExecHookLayout` / `ExecHookHistogram` 两个导出(`scripts/execspy.js:2`);Frida 自己的
`Interceptor` 在这条通道里只有一个用途:install 之前当**独立的静默探针**(`spy()`,那时 DLL 的计数器还不存在)。
所以 §13 那 3,900 行计数与后来任何一次复采,判读者都是**同一份 DLL 侧记录器**,这一点决定了「换了 DLL 字节还能不能
并排读」的答案:能并排**讨论**,不能并排**比对**(见陷阱 4 与窗口计划的 Review Focus 5)。

**DLL 路径**:`NS_LIVE_DLL` 覆盖,缺省仍是 `C:\ns\stellaris_quickjs.dll` —— 这一族与证人/donor 那族的
`C:\temp\sqjs_c4.dll` 是两份字节,两次读数之间的差可能来自靶子也可能来自字节本身。

**与族外证人 guard 是两个口径**:census 记的是**我们 DLL 的 `exec_hook` 在 base Execute 上的全量派发**,
**逐把计数**(那是 §13「七把各 2,090」那种数);`c2_shim_probe.py` 只钩 `0xCC4220` **一个**函数,
它的 `h0..h6` 只回答「本次**全部 2,016 次调用**的对象 vtable 是不是 `0x25460F0`」这一**身份**问题。两边的数**不可并排比**,
也不许互相除 —— 详见 `c2_shim_probe.py` 那一节的陷阱 4 与取证卷 §72.8。

**判读陷阱(本地编号 1–5)**:

1. **`hist_overflow > 0` ⇒ 计数不完整**,这次的任何「N distinct shims」都是**截断假象**(§13 第一轮
   315,302 次调用就是溢出那一轮,structures :374-382)。出现它就把读数当环境样本记,不写 per-system 结论。
2. **装与拆都要热路径静默窗口**:install 与 uninstall 各改写同一段 16 字节 `base Execute` 而游戏线程正在执行它。
   驱动的等待是 `game is RUNNING → polling for silence`(靠 DLL 自己的 `calls` 计数器判静默);等待失败时它**停在
   已装状态**并退出,不要在这时强行拆或 FreeLibrary。
3. **「N 次」不是「per-system」**:§13 的 2,090 是那次场景的读数,原话要求先用**换场景/换银河大小**做相关性
   (`correlate … before claiming it`)。复采同场景只算重复确认,不算判据达成。
4. **模块名跟着注入走**:`DLL_NAME` 在 `execspy.js` 里是 RPC 解析导出的依据,驱动把 `NS_LIVE_DLL` 的
   basename 以 `NS_DLL_NAME` 注入(`execspy.py`);只改 `NS_LIVE_DLL` 而不改它 ⇒ 装进去的是 A、找的是 B,报
   `stellaris_quickjs.dll is not loaded`。
5. **包着它跑的那个 `.cmd` 必须是纯 ASCII**。2026-10-28 的第一次复采就是死在包装上:10-27 备好的
   `census_run.cmd` 带 UTF-8 中文 `rem` 行,cp936 的 `cmd.exe` 把那些字节当命令执行
   (`'…顺序纪律…docs' 不是内部或外部命令`),python 一次都没起来。用 `census_run_ascii.cmd`;
   这与 `session_bridge.shim_text()` 里 `text.encode("ascii")` 挡的是同一个失败,只是那份 `.cmd` 没走那个函数。

**通道与时序**:本工具**不需要** `session_bridge`(它只 attach 进程,不读窗口)。时序是**三方**的:
人(或 `just game`)先 `pause` 给静默窗 → 驱动装 → 驱动打印 `RESUME THE GAME NOW` → 人 `unpause` →
60 s → 人 `pause` → 驱动拆。两个方向紧邻时,`just game unpause` 可能被单行命令通道吞掉一次
(`cmd=unpause` 已记进事件日志而 `STATUS` 仍 `want=paused`)⇒ **观测窗的起点以驱动打印的
`live: calls X -> Y` 为准**,不是以你发命令的时刻为准(§74.1)。

**顺序:本工具压最后**(窗口计划 Task 10)。它是唯一武装 `base Execute` detour 的一发,之后任何 `[self+0]`
join 读数都会来自一个热路径归我们所有的进程 —— 那一刻起证人/donor/scope 的 `[self+0]` 都不再干净。
`hist_overflow == 0` 是这一发的硬门。

**§74 复采口径单**(下一次 census 复采照这张单子执行;写死是为了不在实机窗口里临场判):

1. **产物名**:`evidence/logs/exec_shim_census_<运行日>.txt` —— **不要预钉日期**(没跑过的那天会指向不存在的
   文件);现存**基线**在 `evidence/xrefs/exec_shim_census_2026_09_29.txt`(实机新产物才进 `logs/`,基线留在 `xrefs/`)。
2. **硬门**:`hist_overflow == 0`(见上面陷阱 1 与「顺序」段末句)。**禁令**:不得拿 guard 的 `calls`
   (`c2_shim_probe.py` / donor / witness 那几把)当 census 计数 —— 那是**另一个口径**(见上面「两个口径」那段)。
3. **并排两列**:七把 shim 的**新计数**与 §13 的 `2,090 each` **并排**。**2,090(shim 计数)与 787/783 不是
   同一量纲** —— 按取证卷 §55.4 陷阱 3 的原话:**783 = 渲染出的唯一 system 名数**,**787 = §54 那次记的
   per-system 执行次数**(两个数本来就不同源,§54.4 记过 787/783 的差);它们与 shim 计数**不可混用**。
4. **同场景 vs 换场景**:判据原文是 `docs/roadmap.md` 的 B2 行「**换一个场景仍是 2,090 ⇒ per-system 循环**」。
   同一场景重跑**只算重复确认**,不算判据达成 —— 措辞里必须写明本轮是同一场景还是换了场景。
5. **措辞模板**(三行固定格式):「本轮是<同一场景/换了场景>」「读数 = <逐把计数>」「判据是否达成 = <是/否,理由>」。

### `scripts/windows/popup_*.py` —— 弹窗身份三件套

名单是**数据,不是代码**:放行哪些弹窗改 `C:/temp/ns_popup_allowlist.json`,监督器不热加载,改完
`just game stop` + `start`。格式与一条抄 id 的路径:

```
{"allow": [{"popup_id": "text:<8位hex>", "action": "dismiss"},
           {"popup_id": "geom:<宽>x<高>:r<行数>", "action": "dismiss"}],
 "confirmed_by": "人工看屏 2026-10-25"}
```

- `popup_id` 从**状态记录的 `popup.popup_id`** 或日志 `popup_seen` 事件里抄,别手算:文本 id 只对
  「OCR 读到且规范化后非空」的窗存在,OCR 状态非 `ok` 时同一个窗的 id 是 `geom:*`(见陷阱 12)。
- `action` 目前只有 `dismiss` 被识别;不认识的对象/键**静默丢弃**并计入 `dropped_entries` —— 拼错的条目
  既不会放行也不会报错,只有状态记录的 `allow_status` 说它整份可不可解析。文件缺失/坏 JSON ⇒
  `absent`/`malformed`,名单换成空表,处置一律退成 hold。模板在
  `scripts/windows/popup_allowlist.example.json`。
- **`geom:*` 进不了名单(2026-10-25 收尾审查后加的,代码层,不是提醒)。** 上面那个格式块里
  `geom:<宽>x<高>:r<行数>` 那行**照抄无效** —— `parse_allowlist` 现在拒掉任何以 `geom:` 开头的
  `popup_id`。**那个 dropped 计数目前不落任何盘面**(`load_allowlist` 只把名单和状态返回给
  `popup_tick`,`dropped_entries` 在 `parse_allowlist` 里算完就被丢掉),所以实际效果就是**静默
  不放行**:抄进去既不报错也不放行,只会一直看到 `popup_hold_unclassified`。理由: 一个 10 px
  的几何桶不是一次人工确认,而 OCR 不可用时**同一个窗的 id 恰恰就是 `geom:*`**(陷阱 12);留着它
  等于把「读不到 ⇒ hold」换成「读不到 ⇒ 形状对上就点」。一期取证还给了两条实证: 2 个 `geom:` id
  是主 UI 切片(屏上没有 ✖),同一扇控制台面板的 bbox 一场之内从 `340x970` 漂到 `1500x1000`。
  要放行就必须在 OCR 状态 `ok` 时抄 `text:` id。
  同一次审查还钉了 `load_allowlist`: 记事本存成 UTF-16 的名单现在算 `malformed`(整个 `read()`
  都包在 `ValueError` 里,以前 `UnicodeDecodeError` 会逃进 serve 循环把守护打死)。
  另: `console_open` 现在是**正向**判据 —— 只有 `is False`(看清了控制台关着)才允许点,`None`
  (看不清)一律 hold,note `popup_hold_console_unknown`。本场 `console_panel` 只命中 18/385 个边缘,
  所以这条在检测器重新标定之前实际把「放行」能力停在一边;名单本来是空的,没损失任何已验证的行为。
- **抄 id 之前先确认那块亮的是不是一扇窗。** 第一批实机留证给了比例:一场 385 次边缘、23 个 distinct
  `popup_id`,其中 **21 个是调试控制台的文本面板**被亮度剖面切成的一块块(形状从 `340x970` 一路漂到
  `1500x1000`,所以每换一次形状就是一个新 id),**2 个是主 UI 切片**(星图 + 舰船立绘 + 舰队侧栏,
  里面根本没有 ✖ glyph)。`console_panel` 这条 reason 在那一场只认出 **18/385** 次边缘,其余全部以
  `unclassified_hold` / `id_stuck` 停手 —— 停手是对的方向,但**别把这些 id 当弹窗抄进名单**。
  逐条判读在 `evidence/xrefs/popup_fingerprints_4_4_4.tsv`。
  **2026-10-25 批次 2 把这条的适用范围扩到 `text:` id(`evidence/logs/unattended_popup_batch2_4_4_4.log` Step 6):**
  `text:2188ca0b` 是 OCR 状态 `ok`、12 行、`source=text` 的一个 id —— 上面那句「要放行就必须在 OCR 状态 `ok`
  时抄 `text:` id」在批次 2 之后**只是必要条件,不是充分条件**。它的证据裁片(1060×317,远端
  `C:\temp\ns_popup\text_2188ca0b.png`,本地副本 sha256 前 16 位 `2fdd05d2a639c6c0`)左半是「事件链: 追寻风信子号」
  那扇真对话框,**右半是星图 + 舰队列表**(`CNS… 工程船` / `CNS… 科研船` 那几条)⇒ 这个 bbox 是**两块 UI 的并集切片**。
  `close_point = (bbox[2]-96, bbox[1]+51)` 定义在同一个 bbox 上,换算到裁片本地恒为 **(964, 51)**,
  落点就是舰队列表条目 —— 点它等于选中一条舰队,不是关窗。⇒ 名单条目没写,`dismiss_attempt` /
  `dismiss`(`no_effect`) 三元组仍是 **not_observed**,而缺的前提从「量一次关闭点」改成
  **「先证明 bbox 是一扇窗而不是切片」**;这一条判据没达成之前,`attempts` 恒 0 是设计行为不是故障。
  **同一批次把「量得的点」第一次拿到了(Step 11,人在场授权后走手工 `click`,不是 daemon 的 `dismiss`):**
  ✖ glyph 的真实中心 = **(1345, 483)**,算得的 `close_point` = (1843, 606),差 (498, 123)。
  最硬的一条不是那个差,是 **✖ 在 bbox 外面** —— bbox 是 `(879,555)..(1939,872)`,而 ✖ 的 y=483
  比上边界还高 72 px ⇒ 「这张裁片里根本没有 ✖ glyph」是**结构性的**,不是渲染运气差;
  按这个 bbox 算 `close_point` 永远不可能命中关闭按钮。
  顺带一条可复用的换算:裁片/截图的像素坐标要当屏幕坐标用,先证窗口 rect 原点 —— 把裁片在全屏截图里
  做粗匹配(纯 Python、裁片左半 200 采样点、stride 3)得 (878, 555),对上批次 1 记的屏幕 bbox 原点
  (879, 555) ⇒ 这台机无边框全屏,原点在 ±1 px 内是 (0,0)。**没有这一步,量出来的点没有坐标系。**
- 三个模块的分工:`popup_identity.py`(指纹与名单解析)、`popup_guard.py`(判据与熔断,阈值只在这定义)、
  `popup_ocr.py`(引擎唯一出口)。前两个 stdlib-only,Linux 上就能 `import` 并跑测试;`popup_ocr` 只在
  Windows 宿主上跑得动(surya + torch CPU 轮子),但它的**加载成本现在有了实机数字**:2026-10-25 第一次 shot
  `python C:\temp\popup_ocr.py warm` 量到 `STATUS=ok MS≈6.1 s`(两个 predictor 构造 + 权重读盘,torch 的
  pynvml FutureWarning 也在其中)—— 计划里那个「≈1.0 s」是更早 spike 只量构造、权重已被另一进程暖过的
  数,**不要**再拿它估无人值守的启动停摆。`warm|<png>` CLI 就是为这条测量存在的(Task 6 不开 daemon 也能
  量),`LINES` 用来把「慢在机器」和「这窗字多」分开。

### `scripts/windows/keep_awake.py` —— 桌面可达性守护

常驻在交互会话里,用 `SetThreadExecutionState` 顶住空闲,并**观测**当前输入桌面名以判定桌面可达性。
它掐掉的是 2026-10-24 只读测得的那条自动链:插电 60 分钟关屏(`VIDEOIDLE ac = 0xe10 = 3600 s`)、
电池 3 分钟即睡(`STANDBYIDLE dc = 0xb4`),唤醒要求登录 ⇒ 桌面变成 `Winlogon`,而 LogonUI 占住 Console
会话就是那两次 `just launch` 停在 `SetForegroundWindow` FALSE、`inner_exit code=22` 的现场。断言是
**进程级**的(`ES_CONTINUOUS|ES_DISPLAY_REQUIRED|ES_SYSTEM_REQUIRED`),所以不写注册表、不改电源计划、
不改屏保与登录策略:进程一退,Windows 立刻恢复原行为。

命令行(经根目录 `justfile`,`just deploy` 之后 `C:/temp/keep_awake.py` 与本地逐字节相同):

```
just awake start            # 只在「没有东西在跳」时拉起任务;成功判据是**比它看到的那条更新**的心跳
just awake status           # 一行摘要,读不到也返回 0(它只报现状,不判决)
just awake check            # 判决:0 unlocked / 1 锁或读不到或过期 / 2 状态文件 absent
just awake stop             # 写 quit + 登记去重键 + 删任务;daemon 自己写 state="stopped"
just awake serve --interval 5.0 --assert-every 25.0 --stop-after-s 0
```

`check` 那行的 rc 是**状态文件里 `desktop` 字段**的函数,不是屏幕的函数:2026-10-25 两次人工 `Win+L`
期间它实机返回 **0**(下面陷阱 6 有全部读数与排除)。

`serve` 是 daemon 本体:`--interval` 是 tick 秒数,`--assert-every`(`DEFAULT_ASSERT_EVERY_S = 25.0`)
是重申断言的间隔,`--stop-after-s` 非 0 = 有界会话(也是循环的测试接缝)。状态文件
`C:\temp\ns_awake_status.json` 每 tick 写一次,`desktop` 七态
`unlocked|locked|screensaver|wrong_session|unreadable_denied|unreadable_error|unknown_name`,
`state` 取 `serving|stopped`,`STATUS_MAX_AGE_S = 15.0` 是消费端认可的快照年龄(三个漏拍)。
另有 `ns_awake_cmd.txt`(+ `.seen` 去重键)、`ns_awake_log.jsonl`(只在桌面状态**变化**时写一行
`desktop_change`)、`ns_awake_task.cmd`、`ns_awake.out`。

**判读陷阱:**

1. **它只掐空闲链**。人工 `Win+L`、别人远程操作、以后新增的组策略锁都不在能力范围内;`check` 报
   `locked` 时**先想人,不要想守护坏了**。守护也绝不在 secure desktop 合成输入、不尝试解锁、不猜口令。
2. **`unreadable_denied` ≠ 锁**。它是 `OpenInputDesktop` 被 DACL 拒(`err=5`,detail 形如
   `err=5 sessions=1/1`);判决按保守方向走「不可执行 shot」,但根因可能是进程不够权限而非桌面被锁 ——
   两个名字分开就是为了不让人去查一个不存在的锁。同一族里还有 `err=1`:那是**会话不对**,
   `OpenInputDesktop` 只看得到调用方自己会话的输入桌面,而 ssh 起的进程在 session 0,那里没有
   控制台输入桌面可开(实机 2026-10-24:`h=None gle=1`);`desktop_detail` 里出现 `sessions=-1/1`
   则是更早的一格 —— 自己的会话号都没读到(`ProcessIdToSessionId` 的第一参是**进程号**,
   递句柄进去一律 `gle=87`)。两种都不是锁,也都修不好,只能把守护放回控制台会话里跑。
3. **断言随进程消失**。`stop`、被杀、机器重启 ⇒ 顶不住空闲,这是刻意的安全性质(不改电源计划);
   唯一的发现途径是 `check` 的非 0 退出码,而「屏幕还亮着」不能当证据 —— 顶住它的进程可能已经走了,
   状态文件里 `state` 仍是 `serving` 的僵尸心跳靠 `STATUS_MAX_AGE_S` 兜住。同一条也管 `start`:
   心跳新鲜只让它**不重复拉起**第二个守护,不当成「已经在使用」的成功 —— 成功必须是一条**严格更新**的
   心跳。写完最后一条就死的守护会让 `start` 报 `STATUS=timeout` 返回 1,而不是静默地把没顶住的机器
   交回给你。`powercfg /requests` 是它的证人:断言期间该命令里必须有本进程的 `DISPLAY`/`SYSTEM`
   请求条目,`stop` 之后必须消失(两条都已在 `evidence/logs/keep_awake_live_4_4_4.log` 实机取到;
   同一份输出里游戏自己与音频驱动也各有一条,所以**别人的请求不是我们的证据**)。
   状态文件里的 `assert_rc` 是上一次调用的**前一状态**,不是「现在顶没顶住」:`0x80000000` 读作
   「这条断言刚起」,`0x80000003` 读作「起之前还挂着」。
4. **无人值守请插电**:电池下 3 分钟就睡,而断电是任何软件都救不了的。
5. **`assert_rc` 是日志字段,不是判据**。`SetThreadExecutionState` 返回 `0`(断言压根没挂上)时 `check`
   与 `keep_awake_gate` 照旧放行 —— 两处的判决只看 `state`/`epoch`/`desktop`。断言真的挂没挂,证人只有
   `powercfg /requests`(第 3 条)。
6. **`locked` 那一格实机取到了,但不是 `locked`**。2026-10-24 的验收全程无人按 `Win+L`,所以锁屏分支只有离线测试钉着;
   日志 §8 留了补它的命令与 Expected(`DESKTOP=locked`、`RC=1`、`desktop_detail` 含 `Winlogon`)。
   **2026-10-25 有人按了**(`evidence/logs/unattended_popup_4_4_4.log` Step 3):实际读数是
   `DESKTOP=unreadable_denied` —— 守护进程的 `OpenInputDesktop` 被拒(err=5),我们**连桌面名字都问不到**,
   所以期望里的 `Winlogon` 永远进不到 `desktop_detail`。两条后果:①「锁着」与「这台机不让我看桌面」在状态串
   里是同一个形状,任何按 `locked` 字面量写的判据在这台机上永不触发;②`just awake check` 的 rc 仍按
   「非 reachable ⇒ 1」判,但那是 `check_exit_code` 的纯函数推论,**实机 rc 本场未回显,待复测**。
   同场拿到的关键正面读数:**锁屏期间 daemon 心跳继续更新**(`STATE=serving`、`age<2 s`、`epoch` 递增)
   —— 「daemon 活着但动不了手」与「daemon 死了」靠心跳可分,靠 desktop 字段不可分。
   **2026-10-25 批次 2 把上面两条推论里的一条改写了(`evidence/logs/unattended_popup_batch2_4_4_4.log` Step 1–3):**
   又按了两次 `Win+L`,这次读到的**不是** `unreadable_denied`,而是 `DESKTOP=unlocked detail=Default`
   配 **实机 `RC=0`** —— 上一条末尾那句「rc 仍按「非 reachable ⇒ 1」判」的推论在实机上不成立,因为
   `check_exit_code` 拿到的输入本身就是假的。锁着的证人另有其人在:`LogonUI.exe 2188/2216 Console 1`
   (解锁后消失),而 daemon 一侧 `session=1/1` + 任务 `<LogonType>InteractiveToken</LogonType>` +
   父链 `svchost → cmd → pythonw` 把「不在 WinSta0」和「权限不够」两种归因**都排除**了。
   ⇒ 本文件的开头那句「唤醒要求登录 ⇒ 桌面变成 `Winlogon`」是 Windows 的事实,**不是我们能读到的事实**:
   `desktop_locked` 这个 verdict 在这台机上从未被任何一次真锁产生,`desktop_gate` 在锁屏期间返回 `ok`,
   所以执行 shot 通道的第一道门与 launcher 的 exit 25 都**拦不住一次锁屏下的键盘注入**。
   `err=5` 在这两次锁里只以「一拍的 blip」出现(4 组 `err=5 → Default` 对,组内间隔恰好 5 s),
   锁着的整段时间变更日志**零新增** ⇒ 「锁屏 ⇒ 至少一条 err=5」与「读到 err=5 ⇒ 正在锁屏」两头都不能当判据。

**与执行 shot 的关系:**`c4_wiring_probe._flow` 的**第一道门**读 `ns_awake_status.json`,
`keep_awake_gate` 的六个 verdict —— `keep_awake_absent|keep_awake_stopped|keep_awake_stale|
desktop_locked|desktop_unreachable|desktop_unobserved` —— 一律中止,且中止发生在为游戏写
`want paused` **之前**(连 launcher 的 22 都不用花)。两端唯一的耦合是两个字符串:状态文件的
`desktop == "unlocked"` 与 `state == "serving"`,没有 import 关系。这是 §54.9
「`console_open` 是信念不是观测」在桌面可达性这条新轴上的重申。

**launcher 侧也接了这道门**(`launch_stellaris.py` 的 `desktop_gate_or_none`,新退出码 **25**):位置在
`_run_launch_chain_phases` 里 dry-run 返回之后、`launcher_click` 之前 —— 晚一步就等于没接,锁屏下的点击失败
仍会被记成 22/23,而那正是 exit 23 至今判不下去的原因。`--keep-awake-status` 的默认值是
`keep_awake.STATUS_PATH`,不是第二份 `C:\temp\...` 字面量。

两处判决函数(`keep_awake.desktop_gate` 与 `c4_wiring_probe.keep_awake_gate`)**各留一份是刻意的**:执行 shot 通道
是 `C:/temp/<name>.py` 线上契约的一部分,不能因为 launcher 侧要读同一个文件就获得一个 import 关系。代价有两条,
都记在这里:(1) 状态窗口 `STATUS_MAX_AGE_S` 在 `keep_awake.py:50` 与 `c4_wiring_probe.py:499` 各有一份字面量
`15.0`,**本计划不合并** —— 合并意味着给线上契约加一条跨模块依赖;(2) launcher 侧把 `screensaver`/
`wrong_session`/`unknown_name` 归进 `desktop_unreachable`,而执行 shot 通道把它们留在 `desktop_unobserved`。
两者都拒绝,区别只在诊断:桌面被**读到**但不是 `unlocked` 的三种状态,在 launcher 这一侧是「可达性已知为否」,
`desktop_unobserved` 因此只留给 `DESKTOP_STATES` 以后新增、这个名字还不认识的状态。

**exit 23 现在自带三档观测,但仍不是结论。**`launcher_click` 每轮在 `step=click` 之后补一条
`step=trace`(`owns_foreground` / `cursor_at` / `launcher_alive`,rect 已在 `step=click` 里记过,不重复),
耗尽三轮后在返回 23 之前记一条 `step=diagnosis`,值是 `click_not_delivered|wrong_window|
handoff_never_fired|inconclusive`。**退出码不因它改变**,读回失败(`GetForegroundWindow`/`GetCursorPos`
任一条抛或返回 FALSE)只把对应字段写成 `None`,而任何一轮带 `None` 就把整条结论压成 `inconclusive` ——
仪器没测到不等于测到了反面。判读陷阱:`handoff_never_fired` 只说「三轮都拿到焦点、光标都落在那一点、
launcher 仍没推进」,**不**说「Continue 按钮在别处」;这一档要成为结论得等实机那一次(离线无从知道
CEF 把按钮画在哪)。

### `scripts/windows/ns_world.py` —— 世界状态机的唯一入口

窗口纪律过去写在散文里(判读陷阱、「装之前先确认」),而绕过它不报错:2026-10-27 一个窗口内绕过三次
(`STATUS=paused note=paused_no_window` 被当事实、`policy=first` 去点一个不是选项窗的东西、
`just game stop` 的语义是**退出游戏**却被当成「停 daemon」用掉一个进程)。这个工具把「证明」变成
数据、把「消费」变成代码门。

纯状态机在 `scripts/world_state.py`(跨平台、零 win32、离线可单测);Windows 侧另有两半:
`world_probe.py` 取一次读数(复用 `game_supervisor` 的分类器,**阈值一个不改**),`ns_world.py` 是 CLI。
**agent 只读一行**:

```
STATE=<state> EVIDENCE=<k=v,...> NEXT=<a|b|c>
```

退出码 `0` 合法 / `2` 拒绝(前提不成立)/ `3` 阻塞(预算或证据挡着)/ `4` 锁僵死。
`NEXT=` 直接来自转移表,留空就是「之后没有可做的事」,不是一个像状态的词。

```
just win "python C:/temp/ns_world.py status"                       # 报状态与合法下一步
just win "python C:/temp/ns_world.py probe --out C:/temp/ev.json"  # 一次读数,可写成解封证据
just win "python C:/temp/ns_world.py assert-ready --action install --guard shim"
just win "python C:/temp/ns_world.py unblock --evidence C:/temp/ns_block_<nonce>.json --reason '…'"
just win "python C:/temp/ns_world.py quit"     # 退游戏(转调 game_supervisor)
just win "python C:/temp/ns_world.py abort --action click_option"  # 只记录「不再试」,**不动预算**
just win "python C:/temp/ns_world.py pull"     # 把 C:/temp/ns_world.jsonl 拉回 evidence/logs/
```

状态与转移史都在 Windows 侧写(`C:\temp\ns_world.json` + `ns_world.jsonl`),Linux 侧只 `pull`:
单写者,且 jsonl 与状态同源。

**三个判读陷阱**

1. **`YIELD_TO_LEASE` 是让路,不是故障。** daemon 每 tick 先问「有没有未过期租约」,有就整 tick 不动。
   状态文件里 `state=yield_to_lease` 与日志里同名事件同时出现才叫让路;只有其中一个,说明有人在改
   其中一侧的写法,而不是「daemon 卡了」。
2. **一张过期的租约**不**让路,也不解封任何东西**:`expired_while_armed` 会把它读成
   `RESTORE_INCOMPLETE`(spec §5 宁可误判不可漏判),所以装过 guard 之后**必须** `unarm`,否则
   30 秒后每个动作都被这条"常驻指控"挡住。看到 `RESTORE_INCOMPLETE` 先查 `armed[]`,不要先怀疑探针。
3. **`abort` 不是解封。** 它只写一行记录。唯一的解封入口是 `unblock --evidence`,而那份证据必须由
   `probe --out` 产生:带完整读数(六个原始计数)**且**带那次阻塞的 nonce、且 mtime 晚于阻塞时刻。
   手写或 `touch` 出来的文件必然缺 nonce —— 这是设计要的,不是麻烦。

**黄金集读数**:`evidence/logs/world_state_labels_4_4_4.jsonl` 本版**未采集**(采集器
`scripts/scratch/2026-10_world_state_labels/collect_labels.py` 已就绪:它拒绝无 `crop_sha256`、拒绝
vocabulary 之外的判词、拒绝未知的原始计数)。为什么没采:那 20 帧要运行中的窗口,且判词按定义是
**人**看一眼给的(spec §13.2);本次会话没有可用窗口,也不具备看图的条件 —— 硬写 20 行会得到一个
「看起来像证据」的集合,而那个集合正是 §13 要防的东西。spec §13.3 本身也写明黄金集是**读数不是门**,
不通过不阻塞 v1。

**实机读数(2026-10-28,游戏 pid 11268 —— 这条链唯一一次真跑)**

- 静止:`IN_GAME_PAUSED_CLEAN`(`pause=paused red_px=132..273`、`console=closed bright_px=0`、
  `window=none`),`NEXT=unpause`。按一次 Space → `playing red=0 green_px=195..201`,
  `NEXT=install`。失焦自动暂停后又回到 `PAUSED_CLEAN` —— 状态机跟得上。
- 门**拒绝**(暂停中):`REFUSED: state is IN_GAME_PAUSED_CLEAN, not IN_GAME_RUNNING … |
  reading: pause=paused console=closed window=none hwnd=2295620`,退出码 2,
  且 `module loaded AFTER: []` —— **DLL 没有被注入**(用进程模块表验的,不是用驱动自己打印的话)。
- 门**放行**(运行中):退出码 0,`DLL base 0x7ffb58030000`,`C2Sanity -> 42`,
  `module loaded AFTER: ['C:\temp\sqjs_cac.dll']`。
- daemon 让路:持租约起 `serve` → `handled=0`,12 秒内 **17 条 `YIELD_TO_LEASE`**,状态
  `note=YIELD_TO_LEASE`。
- 租约:未消费的那张被 `assert-ready` **认领**(返回同一 id,§6 规则 3 指纹相符)、认领即消费;
  换 `hwnd` 的同批读数被拒并打印两个指纹;`consume` 两次得到 `0` 然后 `2`。
- `unblock` 拿一份**真实但无关**的探针文件:退出码 3,`nonce` 不匹配 —— 伪造不了。

**一个只有实机才露出来的缺口**:SSH 落在 **session 0**,游戏在 **session 1**,
`EnumWindows` 在 session 0 里只枚举到 1 个窗口 —— 从 SSH 直接跑探针永远 `NO_GAME`。
`session_bridge.py` 是这条通道(`schtasks /run /I`),不补它 `ns_world` 在 agent 的实际
工作方式下不可用。

**OCR 引擎读数**(`evidence/logs/ocr_swap_4_4_4.tsv`,spec §14):surya → rapidocr PP-OCR mobile。
三块面板、每块 14 带,同一批字节三种读法:

| engine | 单次 ms | 说明 |
|---|---|---|
| `-rec`(只跑识别,单带) | 79–125 | spec §14.3 那条 50 ms 目标**未达标** |
| `-full`(带检测,整面板) | 585–960 | daemon 今天实际走的路 |
| `surya-panel`(换型前) | 26 488–35 314 | 同样三块面板,13 行 |

所以面板路径是 **~40×**:30 s → 0.7 s。rec-only 对整面板返回 0 行 —— 识别模型吃单行图像,
而 popup 流程裁的是整块面板;要让 50 ms 那条真正落地,得让流程按行裁片(spec §14.3 的前提
本来就是「UI 槽位坐标已知 ⇒ 先裁片」)。

**这一节有一处自我更正**:本文件与提交信息的第一版把 surya 记成「量不到」,理由是
`RecognitionPredictor` 不接受 `device=`。那是**仪器**的错 —— `device=` 属于
`FoundationPredictor`,换型前的代码正是那么调的。按换型前的调用形状重跑之后旧引擎跑得通,
上表第三行就是重跑结果。**先把仪器修对,再说引擎测不了。**

新旧引擎的文本比对(归一化后):**逐行同位置一致率 7%**,但词袋重合 82–86%。差的主要是
**断行方式**(新引擎把 `cns<br>科研` 拆成两行)与旧引擎的碎片(`x` / `librar` / `n`),
不是读错。这对 `popup_allowlist.json` 是真风险:名单里的 `text_signature` 是用旧引擎的
文本签的,换型后签名会变 ⇒ **旧名单条目大概率失效**,重新签一遍之前 `decide_action` 会
一路 `unclassified_hold`(安全侧,但会挡事)。这里不给「一致率达标」的结论,因为它没达标;
给的是「为什么没达标」和「谁会受影响」。

围栏:`scripts/test_world_state.py` 38 条、`scripts/test_world_probe_pure.py` 3 条、
`scripts/test_popup_ocr_small.py` 3 条、`scripts/test_scripts_layout.py` 38 条(四条新规则:
R-inject / R-verbs / R-gate-symbol / R-deploy)。

### `scripts/windows/session_bridge.py` —— SSH(session 0)到交互桌面(session 1)的通道

**这条不补,`ns_world.py` 在 agent 的实际工作方式下不可用。** Windows 上 SSH 登录落在
**session 0**(服务会话,没有交互桌面),那里 `EnumWindows` 几乎什么都看不见:实机测过一次,
session 0 里只枚举到 **1 个**顶层窗口,而 `stellaris.exe` / `explorer.exe` / `steam.exe`
全在 session 1。所以从 SSH 直接跑探针会永远得到 `NO_GAME` —— 状态机的工作就是读真窗口,
读不到就没有前提。

`launch_stellaris.py` 与 `game_supervisor.py start` 早就用同一个办法绕开它:注册一个
**计划任务**并以交互方式运行(`/run /I`),这样的任务继承已登录用户的会话,能看见也能碰
游戏窗口。这个工具把同一机制泛化成「跑一条命令」:

```
just win "python C:/temp/session_bridge.py C:/temp/ns_world.py status"
just win "python C:/temp/session_bridge.py C:/temp/ns_world.py assert-ready --action install --guard shim"
# 长的实机 shot 要把超时抬过采样窗(默认 120 s 不够):
just win "python C:/temp/session_bridge.py --timeout-s 420 C:/temp/c2_scope_probe.py C:/temp/sqjs_c4.dll --poll-s 120 …"
```

**它还是 shot 驱动的必经之道(2026-10-28 实证)。** `c2_scope_probe.gate_module` 在 `inject_dll` **之前**
调 `world_probe.gate_install`,而那道门要**读窗口**来证明前提;从 SSH(session 0)直接跑驱动,门看到的是
`NO_GAME`,于是**拒装**(exit 2)—— 这是那道门第一次真的挡住东西。所以 scope/donor/witness 这类要过门的
驱动一律经 bridge 跑;`execspy.py` 是例外(它只 attach 进程,不需要窗口,见它那一节)。

`--timeout-s` 是 2026-10-28 补的:默认 120 s 与 scope shot 的 `--poll-s 120` 相等,哨兵必然迟到,
而桥的超时语义是「**不知道**发生了什么」—— 一个 120 s 的 shot 不许读成超时。缺省仍 120 s。

它写一个 **ASCII** 的 `.cmd`(cp936 的 `cmd.exe` 按控制台代码页解析 `.cmd`,非 ASCII 路径
会让任务在运行时静默死掉,所以在这里就抛),把命令输出重定向到文件、把 `EXIT=` 哨兵追加在
最后,`/run /I` 点火,等哨兵、删任务、打印输出与退出码。哨兵在输出之后,所以读的时候按
**最后一个** `EXIT=` 切分,不会被命令自己打印的内容骗到;拿不到哨兵返回 4(**不知道**
发生了什么,不是成功)。

**读回那一半也有围栏了。** 2026-10-28 之前只测 shim 文本;`run_interactive` 读回 `OUT_PATH` 时
漏了 `open` 的 `mode`,实机上炸的是 `TypeError: _open_file() missing 1 required positional
argument: 'mode'` —— 现在 `test_run_interactive_reads_the_sentinel_back` 用 RED→GREEN 钉住它。

**它有意不做成 `just` 食谱。** `just ns` 会是 `game` 之外的第二条改世界通道,而
`scripts/test_scripts_layout.py` 的 R-verbs 围栏只治理 `game` 那一条。要开这条通道,应该
先把它的动词登记进 `world_state.VERB_ACTIONS`,而不是顺手加个 recipe。

**判读陷阱**:任务跑在**已登录用户的会话**里,所以(1) 没人登录桌面时它跑不出东西 —— 拿不到
哨兵就报 4,不要当成"拒绝了";(2) 它和 launcher / supervisor 用的是不同任务名
(`NSWorldOneShot`),互不干扰,但**同时**点火两个交互任务时 Windows 只让一个拿前台焦点,
另一个的点击会打偏。

## 我们自己产物的反汇编(`scripts/pe_disrva.py`)

`scripts/disrva.py` 与 `scripts/cap.py` 反汇编的是**游戏**:它们只收 RVA,自己去找 `stellaris.exe`
(`NS_STELLARIS_EXE` / 固定候选)。`scripts/pe_disrva.py` 反汇编的是**你给的那份 PE**,路径是必填的
第一个位置参数 —— 本仓库用它读自己构建的 `zig-out/bin/stellaris_quickjs.dll`(§45/§47 的 `js_rc` trap),
不读游戏,所以没有默认路径、也不受 `NS_STELLARIS_EXE` 影响。

```
python3 scripts/pe_disrva.py <pe_path> <rva_start_hex> [<rva_end_hex>|<count>]
python3 scripts/pe_disrva.py zig-out/bin/stellaris_quickjs.dll 0xbba0 0xbc01   # end 不含(§48 产物的 js_rc)
python3 scripts/pe_disrva.py zig-out/bin/stellaris_quickjs.dll 0xbba0 40       # 40 条(默认 64,上限 4096)
```

**RVA 每次重链都会变**:上面的 `0xbba0..0xbc01` 是 §48 产物(`79c8dc24…`)的 `js_rc`;
`scripts/test_pe_disrva.py` 的 `trap_span()` 从 `quickjs.c:1494:12` 的 SourceLocation 反查
`record → LEA → .pdata` 得到当前区间,所以测试不会因重链失效。§47 的 `0xbd70..0xbdf3` 属于基线
产物 `77c0c35e…`。

- 第三个参数:`0x` 开头 = **结束 RVA,不含**;纯十进制数字 = **指令条数**。所以小的十六进制结束 RVA
  必须带 `0x`(裸 `100` 是 100 条,不是 rva 0x100)。
- 每条绝对 `call`/`jmp` 目标与每个 `rip+disp` 操作数标 `  #0x<rva>`;`#0x` 后是**相对 image base**
  的 RVA(image base 从该 PE 的 optional header 读),所以能和 `dll_ubsan_site.py` 的
  `record_rva=` 比 —— 但那条只对**它解码的 `TypeMismatchData` 记录**成立(见上一节判读陷阱 7)。
- **只解码带 `IMAGE_SCN_MEM_EXECUTE`(`0x20000000`)的段**。RVA 0 落在 PE 头里,capstone 会把 `MZ...`
  当指令解出来,所以工具在喂给它之前按 section 位拒绝。可执行段外的起点、文件映射之外的起点、或解出
  **0 条指令**,一律退出 1 —— 那是「这段不是代码」的结论。
- 退出码三义与 `dll_ubsan_site.py` 一致:**0** = 至少解出 1 条;**1** = 不是可执行代码 / 0 条;
  **2** = 调用错了(缺参、非 hex、文件读不到、非 PE32+、**截断的镜像**(section 表声明的 raw 字节
  越过 EOF)、end < start、count <= 0),一行 stderr、无 traceback。
- **起点不落在任何段里、或落在非可执行段里,是 1 而不是 2**(控制器的裁定):那是「这个文件里这段
  确定不是代码」的结论;2 只留给**读不了 / 非 PE / 截断的输入**和写错的调用参数。
- 上限 4096 条,超出打 `; truncated at 4096 insns`;头行给 `N insns, M bytes`。**未截断时** end 模式下
  `M` 等于 `end - start`;可一旦超过 4096 条(或 end 越过段尾被裁剪),头行的 end 是**有效(裁剪后)
  的 end**,`M` 小于请求的 `end - start`,同时带上截断提示(实测 `0xbba0 0x800000` 头行裁到
  段尾并附 `; truncated at 4096 insns`;未截断的 `0xbba0..0xbc01` = §48 产物的 `js_rc` = 97 字节 = 29 条)。

**判读陷阱:**
1. **反汇编证明的是「被检查的是哪个表达式」,永远不是运行时值。** 它读得出 `js_rc` 的
   `test rdx,rdx` 在 `add rcx,-8` 之前、测的是原始指针;它证明不了那次 shot 里 `rdx` 是不是 NULL。
2. **`#0x...` 是 image-base-relative 的 RVA,不是 VA**;rip 目标按 `address + size + disp` 算,不是从
   指令起点算。
3. **clang 的「减 8」可能是 `add reg,-8`**:本产物里 `container_of` 的 header 偏移是 `48 83 c1 f8`
   (`add rcx,-8`)。按 mnemonic 找 `sub` 会漏 —— 读语义,不读拼写。
4. **0 条的退出 1 是结论不是失败**,但别把它读成「这里没有 sub」:先看 stderr 是「不在可执行段」还是
   「段内 0 条」,两者都与「成功但没有该指令」分开。
5. 想验证「0 条 → 1」可以拿 RVA 0,但它走的是 section 门,不是 capstone 解失败;两条路都退出 1,
   理由不同,不要混成一条判据。

## IDA headless 现状(环境状态,非规则)

**IDA MCP**: registered in `~/.qoder/settings.json` (`/home/lofibass/.local/bin/idalib-mcp --stdio --unsafe`).
**Status updated 2026-09-29**: headless open now works — session `f3ea6101` is live on the local
`stellaris.exe` copy (there is also a `stellaris.exe.i64`, 585 MB, produced by that headless open, which
contradicts the earlier "the `.i64` stays on Windows" note; neither file was hand-edited).
The earlier `License not yet accepted, cannot run in batch mode` failure is **no longer reproducible**.

两条**规则**不随状态改变,留在 `AGENTS.md`:不许绕过 license 守卫分支,以及本 IDB 上不得调用
`ida_auto.plan_and_wait`。

## 一次性探测脚本

历次取证的一次性探针已经不在 `scripts/` 顶层,按取证批次归进 `scripts/scratch/<年-月>_<主题>/`,
每个目录自带 README(逐行列出「这个文件当时在回答哪个问题」):

| 目录 | 内容 | 判据 |
|---|---|---|
| `scripts/scratch/2026-09_frida_hot_site_spies/` | `fs*.py`、`body*.py`/`body.js`、`spy*.{py,js}`、`strs*.py`、`kv*.py`、`vt.py`/`vtlive.{py,js}`、`walkdb.*`、`prologue.*`、`caller*.py`、`regfn.py`、`missstr.py`、`strdump.py` | 需要运行中的游戏 + Frida |
| `scripts/scratch/2026-09_offline_hardcoded_oneshots/` | `callscan*.py`、`prol_exec*.py`、`rtti_check*.py`、`rtti_offline.py`、`refscan.py`、`sec.py`、`pedump.py`、`verify_base.py`、`dumpvt.py`、`vtcheck.py`、`kwmeta.py`、`cap2.py` | 只读 exe 拷贝,但**路径写死成 `D:\SteamLibrary\…`** |
| `scripts/scratch/2026-09_frida_detour_era/` | `restoreexec.py`、`nsunload.py`、`peekexec.py`、`read_remote_mem.py` | detour 路线的善后 |
| `scripts/scratch/2026-10_newrt_allocmap/` | `allocmap.c` | 同一份 vendored `quickjs.c` 在 Linux 上离线跑 `JS_NewRuntime2`,零游戏(§43) |
| `scripts/scratch/2026-10_threadhandle_matrix/` | `threadhandle_matrix.py` | 需要进程,但目标是自己 spawn 的子 python —— 不碰游戏、不注入我们的 DLL(§44.3) |
| `scripts/scratch/2026-10_abortexit/` | `dll_abort_repro.py`、`ubsan_site.py` | 前者把出货 DLL 装进自己的子进程看它会不会自杀(零游戏);后者只读 DLL 文件,用 `.pdata` + UBSan 记录做无符号符号化(§45)。**两个脚本已提升为维护工具(`scripts/c2_selfabort_repro.py`、`scripts/dll_ubsan_site.py`,见上一节),原批次冻结留档、字节不动** |

它们**不作为接口维护**——可以失效,但不要在新结论上重犯它们已踩过的口径错误(见各节"陷阱"段)。
结论已进 `evidence/` 与 `runtime_444_*.md` 三卷对应 §。

**`evidence/` 里按 `scripts/<name>` 记的出处指的就是这些文件,现在同一个 basename 在
`scripts/scratch/<批次>/<basename>`。** 取证记录不改写,对应关系靠 basename 一一对上;
这批脚本移进来时**一个字都没改**,所以路径之外的任何"修复"都不构成重跑它们的理由。

**`.py`↔`.js` 配对按「同目录内被引用」判定**(`scripts/test_scripts_layout.py` 的 `violates_pairing`,只扫顶层,
所以上面这些 scratch 目录里的孤儿 `.js` 不算违规),`fridadis.py`↔`dis.js` 与 `scan444.py`↔`anchor444.js`
是**刻意异名**(`C:\ns\` 是线上路径),不是待修的历史遗留。

A 目录那批还依赖仓库外的现场文件:`C:\ns\deep.js`、`C:\ns\deep2.js`(以及 `cap2.py` 要 `C:\ns\cap.py`、
`rtti_offline.py` 要 `C:\ns\spy4_table.txt`)——**这些 `.js` 不在仓库里**,只在当时那台机器上,
所以现在直接跑会失败,这是预期而不是回归。
