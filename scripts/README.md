# scripts/ 索引

顶层只有**维护中的接口**：离线 PE 工具、实机注入通道、launcher。一次性探针在
`scratch/`（各目录自带 README，说明它属于哪次取证、结论落在哪个 §）。
命名与归档规则见 `AGENTS.md` 的「scripts/ 命名与目录约定」。

项目根目录的 `justfile` 是这些工具的**薄索引**：`just --list` 看全部，`just check` 跑构建 + 两套测试，
`just fence` 跑布局围栏，`just game …` 走 Windows 侧游戏监督器（命令词表见 `docs/offline-tooling.md`）。
它不实现逻辑，只拼命令行；写进它的 `C:/temp/<name>.py` 线上名由 `scripts/test_scripts_layout.py`
的 `violates_remote_script_refs` 对着 `scripts/` 里的源文件检查。

离线工具的**用法与判读陷阱**不在这里，在 `docs/offline-tooling.md`；这张表只回答"这是什么、产出什么"。

## 离线静态 RE 工具（读 `stellaris.exe` 拷贝；不需要进程、不需要 IDA license）

路径一律 `NS_STELLARIS_EXE` 可覆盖，见 `docs/offline-tooling.md` 的前置条件。
例外：`pe_disrva.py` 的 PE 路径是**必填参数**（它读任意 PE，包括我们自己的产物），不找 `stellaris.exe`。

| 文件 | 干什么 | 产出（`evidence/xrefs/`） |
|---|---|---|
| `find_refs.py` | 线性 capstone 解码每个可执行段，找指向给定 RVA 的 image-relative 引用 | `rva_reference_scan_4_4_4.txt` |
| `riprefs.py` | 同一个问题的快版：谁读/写某个数据全局，不解码 37 MB | `db_global_refs_4_4_4.txt` |
| `fastcalls.py` | 字节级定位对某 RVA 的所有直接 call/jmp，按 `.pdata` 函数分桶并贴来源文件名 | `callers_0x<rva>_buckets.tsv` |
| `disrva.py` | 反汇编一个 RVA 区间，标注每个 rip 操作数解析到的 RVA 与每个 call 目标 | — |
| `cap.py` | 同样的反汇编，走 `.text` 手解 + capstone（`disrva.py` 的前身，仍在用） | — |
| `pe_disrva.py` | 反汇编**任一份 PE**（路径必填；本仓库用它读自己的 `stellaris_quickjs.dll`，不是 `stellaris.exe`）的 RVA 区间，标注 call 目标与 rip 操作数解析到的 RVA，只解码可执行段；结束 RVA 不含，或传指令条数 | —（示例：§48 产物的 `js_rc` 97 字节 / 29 条；区间随重链移动，测试从 `quickjs.c:1494:12` 记录反查） |
| `pdata.py` | x64 `.pdata`(RUNTIME_FUNCTION) → 精确函数边界，无需分析 | — |
| `exec_frame_sites.py` | 把 shot 产物的 caller 行**按字节反解真实站点**（不是 `-5` 估值）：回看窗内枚举恰好结束于返回点的 call/jmp 边界并定 `form`（rel32/mem/thunk/ambiguous/none），join `.pdata` 函数边界与调用点普查 | `exec_frame_sites_4_4_4.tsv` |
| `join_family_boundary.py` | §71 族外边界的三口径离线定形（§71 三口径读数的**生产者**）：段① 普查表 28 个 `func_start` 里哪些是某张 vtable 的 slot[2]、段② §13 七把 shim 的 vtable × 家族五张（期望空集）、段③ `.rdata` 8 对齐 qword 命中 / 命中前一槽是不是 `0x1d08520` / 命中回退 `0x10` 落不落进 1,805 张 map；无参跑①②③，带 RVA 只跑③；退出码 0 = 读完、2 = 环境问题。**口径边界：map 是下限，不是全量** | —（读数落取证卷 §71.1/§71.3/§72.9；原件冻结在 `scripts/scratch/2026-10_live_window_shim_witness/join_family_boundary.py`） |
| `pestr.py` | 读某 RVA 的字节 / C 串 | — |
| `strfind.py` | 按名字定位镜像里的精确 C 串 | — |
| `strrefs.py` | 某 keyword 串的所有副本 + rip 引用这些副本的代码点（"还有谁注册了这名字？"） | — |
| `regscan.py` | 把那个巨型注册 driver 解析成 (token id, keyword, 静态描述符地址, call site) 表 | `keyword_registration_table_4_4_4.tsv` |
| `thunkarrays.py` | 解析 `.rdata` 里 per-keyword 注册 thunk 数组 | `keyword_behaviour_registration_4_4_4.tsv` |
| `descscan.py` | 扫 `.text` 里落进描述符数组 `0x337B400+0x120n` 的 rip 引用，按字段偏移分桶 | — |
| `kwscan.py` | 映射落在给定 RVA 区间（默认名字池）的所有 rip 引用与 call/jmp 目标 | `keyword_block_ref_sites_4_4_4.txt` |
| `idscan.py` + `idregistry.py` | token id 是编译期立即数 ⇒ 找得出所有以它为立即数使用的代码点 | `token_id_use_sites_4_4_4.tsv`（25 MB，gitignore） |
| `cinfo.py` | 统计官方注册 thunk 插入的所有 `class_info` 对，并钉住 factory 调用约定 | `class_info_census_4_4_4.tsv` |
| `createsites.py` | 找出所有从 value record 调 `create` 槽的代码点（按形状而非地址） | `create_shape_sites_4_4_4.txt` |
| `vptrslots.py` | 每个 keyword `create` 把 vpointer 发布到哪几个槽 | `vptr_publish_slots_4_4_4.txt` |
| `vtable.py` | dump 一个 vtable：槽位、每槽的 `.pdata` 函数边界、该函数引用的字符串 | — |
| `rttibatch.py` | 直接从磁盘 PE 给一串 vtable RVA 解出 MSVC C++ 类名；`--all-vtables` 另出**不过滤 slot[1]** 的形状候选集；`--who-tables`/`--who-lea` 把目标 RVA join 到那张候选集与整个 `.text` 的 RIP 相对引用（§57） | `ceffect_vtable_map_4_4_4.txt`（`--effects`）、`vtable_candidates_all_4_4_4.txt`（`--all-vtables`） |
| `tokencorpus.py` | A5：把 token 空间与随游戏发的脚本离线对账，join 应当精确 | `token_corpus_crosscheck_4_4_4.tsv` |
| `emu_desc.py` | C0.3 oracle：用 unicorn 跑引擎自己的两个描述符写手，逐字节产出 golden 向量 | `descriptor_oracle_4_4_4.tsv` + `src/dll/scripted/keyword_registry_golden.zig` |
| `c1_preflight.py` | **约束 4 的门**：候选 keyword 名进 `0x1D13270` 之前的离线只读预检，退出码必须 0 | — |

## 离线重问实机产物（读已入库 artifact；不读 exe、不起进程、不需要 shot）

| 文件 | 干什么 | 读什么 / 产出 |
|---|---|---|
| `scope_reclassify.py` | 把 §56 那 99 条 scope 候选同时问**两张** vtable 集（1,805 下限集 + 172,296 形状集），分四桶给数；`--json` 出全量 | 读 `evidence/logs/scope_probe_v2_4_4_4.tsv` + `ceffect_vtable_map_4_4_4.txt` + `vtable_candidates_all_4_4_4.txt`；结论落在 §56.9 |

## 离线存档分析（读玩家 `.sav`；不需要进程、不需要 exe）

| 文件 | 干什么 | 什么时候用 |
|---|---|---|
| `save_hypergraph.py` | 解 `.sav` 的 ZIP、读文本 `gamestate`,抽 `galactic_object` 的 `hyperlane` 邻接,输出无向边表(`a\tb\tlength`)并核对对称/自环/重复不变量;`--stats` 打计数 | 换存档或换版本要重算星系连通度时;存档不上传、不进 git |
| `chokepoint_scores.py` | 只读边表,算 degree / Brandes betweenness / 割点 / 桥,输出按 `system_id` 升序的七列分数表;`--top N` 打前 N 行 | 已有边表、要给 C4 试点排交通要道时;`system_id` 是存档局部 id |
| `chokepoints_emit.py` | 把七列分数表编译成 `src/dll/c2/chokepoint_table.zig` 的 787 项 `u16` 与 save sha;`--check` 是漂移围栏 | 分数表变了、或换存档后重新生成时;改了 TSV 不重生会让围栏红 |

## 实机注入通道：C1（已完成）

`c1_*` 走的是 ctypes + `CreateRemoteThread`，在 Windows 那台机器上跑。

| 文件 | 干什么 |
|---|---|
| `c1_remote.py` | 通用驱动器：取 `stellaris` PID、按模块名解析远程 base、调 `C1Run` 的 RVA |
| `c1_verify_bst.py` | 判据③：走 trigger db 全局 `0x32611C8` 的 BST，验我们的 token 在树里、donor `class_info 0x269CAA8` 被指到 |
| `c1_verify_reverse.py` | 判据的独立只读观测：读 token db 全局 `0x37347A0`，用 `0x1D12CD0` 那张反查表按 id 读回名字 |
| `c2_test_sanity.py` / `c2_test_marker.py` | 早期最小验活：`C2Sanity` 返回 42 / 确认 `LoadLibrary` 真的把 DLL 挂上了。**RVA 每次由 `list_exports` 从注入的那份拷贝重解析（P10 已修，文件里没有内置地址表）**；`C2Sanity` 不是 42 就直接拒绝，任何后续派发都不会开始。会杀宿主的 diag 序列现在收在 **`--also-diag`** 之后（`C2DiagGetLogAddr` 只打印被截断的低 32 位、不解引用，补全地址要用另一份计划的 `log_rva_from_truncated`）。**推荐的加载器仍是 `c2_task2_load.py`**，这个 basename 只为 P5 的线上契约留着 |

## 实机注入通道：C2（现行主线）

`c2_harness.py` 是共享库，其余每个脚本 scp 自己 + harness 到 `C:/temp/`（裁定 P5）后按裸名 import。
文件名 = 线上契约，**不要改**。`c2_taskN_*` 的编号对应 `docs/superpowers/plans/2026-10-08-c2-quickjs-bootstrap.md` 的 Task。

| 文件 | 干什么 |
|---|---|
| `c2_harness.py` | 共享 harness：PID/base 解析、`list_exports` 重解析 RVA（P10）、`pe_image_size` 读 SizeOfImage（§44 的模块地址区间上界）、`inject_dll`、`remote_alloc`、`call_remote*`、`dispatch_watching_buffer`（调用进行中同时轮询输出 buffer、`g_diag_log` 见证静态、psutil 内存采样，§38/§39；§44 加 `thread_probe` 通道 = 只交句柄、不碰内存、不加 dispatch）、`capture_thread_state`（§44 只读线程状态：`GetThreadTimes`/`GetProcessTimes` + `SuspendThread`→`GetThreadContext`→`ResumeThread`，`finally` 保证不悬空挂起） |
| `c2_task2_load.py` | Task 2：证明 harness 在实机读到真正的 64-bit DLL base |
| `c2_task3_diag.py` | Task 3：从实机抓 `JS_NewContext` 失败的**步骤编号**（只观测，修是 Task 4 的事） |
| `c2_task5_init.py` | Task 5：证明实机 `C2Init` 返回 0 且 `g_test_rt`/`g_test_ctx` 真存在；四观测通道的接线处 |
| `c2_task6_e2e.py` | Task 6（验收门）：`1+1` 走 DLL 自己的 `JS_Eval` 并读回结果 |
| `c2_control_watch.py` | §39 对照：注入 + `C2Sanity` + 20 s 纯观测，**不做 init dispatch** |
| `c2_control_sleep.py` | §39 判别器：只执行 `kernel32!Sleep(8000)` 的长远程线程，不碰我们一个字节（先 `Sleep(1000)` 校准） |
| `c2_control_cpuwatch.py` | §44.3 对照：**零 DLL、零注入、零 dispatch、不开线程句柄**，只用 `psutil.Process.cpu_times()`（底下就是 `GetProcessTimes`）+ 线程数，对一个未触碰的游戏按 tick 采样（默认 20 s，可带 `[watch_ms] [every_ms]`）。判据是「被杀进程那 2.1 s 里 `pr_user_us` 一动都不动」到底是真停了、还是计数器死了（实测：未触碰游戏 20,119.7 ms 内 user 前进 12,828,125 µs，120 线程 ⇒ 那是真停） |
| `c2_control_suspendcap.py` | §44.3 对照：把 `capture_thread_state` 这条只读路径用到**游戏自己的线程**上，量本机 session 到底能不能 suspend + 读 context（实测 12/12 读到 `Rip`、`suspend_denied_gle5=0/12` ⇒ 仪器没问题，§44 的 gle=5 不是权限缺失） |
| `c2_init_threadstate.py` | §44 判别器：§42 那 6.9 s 冻结窗口里，我们自己的远程线程是在**跑**还是在**等**——`Rip` 落在 DLL 区间内 + 线程 CPU 时间推进 ⇒ 跑；`Rip` 在区间外 + CPU 平坦 ⇒ 等。先核 DLL sha256 等于 §42 那次 shot 的字节（不同产物就拒绝），门序照抄 `c2_task5_init.py` |
| `c2_exec_probe.py` | C4 执行路径实机一次 shot：C1 effect token → 谓词 patch → DLL vtable slot[1] → JS 哨兵；有界轮询、先 inert 再拆、绝不 FreeLibrary。判读纯函数由 `test_c2_exec_probe.py` 覆盖 |
| `test_c2_exec_probe.py` | 上述的纯函数判读测试（`decode_stats` / `classify`），无游戏、无 Windows API |
| `c2_scope_probe.py` | C4 取证：`0x1D08520` 只读采样器（1/512），回收真实 `arg2` 的 8 个 qword 与 `X→S→id/obj`；链只在驱动侧 RPM 跟；一次 shot 一个进程、`-2` 不重试、绝不 FreeLibrary。判读纯函数由 `test_c2_scope_probe.py` 覆盖 |
| `test_c2_scope_probe.py` | 上述的纯函数判读测试（layout/entry 解码、chain follow、summarize/classify），无游戏、无 Windows API |
| `c4_wiring_probe.py` | C4 接线驱动（实机一次 shot、一进程）：`--mode capture`（默认）supervisor `want paused` → save sha 门 → 注入/C1/C2 门 → layout/install → 预检 787 → capture 找 scope 列 → apply 787 → 70 个 `NEO_CHOKE_EFFECT`；`--mode slot2` 打 §54.6 判别 shot（install → 一次 armed pass → 读 slot[2] 只读计数，787/0 分流候选 (a)/(b)）；前置门：导出集按模式（slot2 另需 `C4Slot2StatsInto`，注入前判）+ 控制台信念必须来自像素观测（§54.10）+ daemon 回执具名中止（2 s，`--supervisor-log`）；console 命令按模式取数（capture 三条：预检 + capture + apply；slot2 两条：预检 + 判别 shot）都走 supervisor 的 `console` 动词，capture 只读、`-6` 打印 `RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY`、**绝不 FreeLibrary**。判读纯函数由 `test_c4_wiring_probe.py` 覆盖 |
| `test_c4_wiring_probe.py` | 上述的纯函数判读测试（记录/统计解码、spec 打包、列扫描、capture/apply verdict），无游戏、无 Windows API |
| `c2_donor_probe.py` | C4 取证：donor 一族虚 Execute `0x3AFD30` 的只读采样 shot（§57.4 点名的靶子）——只读 `[self+0]` join 五张家族表，`ctx`/`a3`/`a4` 按值记录不解引用；默认 `--mask 0` 每条落环、频率先按 20 s 窗口的 `calls` 增量测再定分母；verdict 值域**没有第三档**（`no_calls` 只算 ENVIRONMENT），两条代码档都要 `installed==1`（否则记 `counter_desync`），tier 2 是**交给静态查表的接力**而非「运行时生成的表成立」（`unmatched` 同时吸收 code-address `self+0`、`toRva`→0 与真实 `SizeOfImage` 外的尾巴，环侧按 image span 三分区写进 `#meta`）；artifact 先写统计再 drain，坏 drain 只留 `entries_error`；`-2` 不重试、`-7` 打印 `RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY`、绝不 FreeLibrary。门序、依赖码与三条判读陷阱见 `docs/offline-tooling.md`；**实机一次 shot，本计划只建好不跑** |
| `test_c2_donor_probe.py` | 上述的离线围栏：`EXPECTED_CODE`/`FAMILY_VTABLES` 两条钉回权威（exe 逐字节 + 取证卷 §57.2 观测 4 那一行），加 12 条判读与契约测试（layout 6 词契约、48 B entry、12 键 stats、两档证据 verdict、值域里不许有 `no_donor_family_execution`，以及终修新增的 `installed` 门、image span 三分区、meta-only artifact、`entries_error`、`verify` 升级不看 `installed_ok`、`run()` 先写 artifact 再 drain 的写序保护），共 **14 passed**，无游戏、无 Windows API |
| `c2_shim_probe.py` | 族外证人 guard（§72）：靶 `0xCC4220` = §13 那七把各 2,090 次的 exec shim 里的第一把（它是 vtable `0x25460F0` 的 **slot[2]**，与 donor/witness 同一个派发位，但那张表**不在家族五张**里）；只读 `[self+0]` join **族外七张**表、`ctx`/`a3`/`a4` 按值记录不解引用；`--mask 0` 的语义是「每条调用都记」；频率先按 20 s 窗口的 `calls` 增量测再定分母；verdict 两条代码档 `shim_hit_named`/`shim_hit_unknown_table`（**没有第三档**：`no_calls` 只算 ENVIRONMENT），两条都要 `installed==1`（否则 `counter_desync`）；`-2` 不重试、`-7` 打 `RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY`、绝不 FreeLibrary。**它只答身份**：它的 `h1..h6` 不携带其余六把 shim 的信息（取证卷 §72.8），逐把计数是 census 那条通道的活（§74）。门序与四条判读陷阱见 `docs/offline-tooling.md` |
| `test_c2_shim_probe.py` | 上述的离线围栏：donor 的 14 条平移换靶 + 24 B 前序逐字节钉回 exe（`disrva.py` 读）+ 七张族外表钉回取证卷 §71.1，共 **15 passed**，无游戏、无 Windows API |
| `c2_trigger_pred_probe.py` | C5 数据面第一发（§75）：靶 `0x349230` = **触发谓词基体**（trigger 的 `[vptr+0x80]`，72 B，实参 `(self, X)`；`.rdata` 里 1,091 个 qword 等于它）；与 C4 那条 effect 路线不是同一族。只读：恒转发、不写引擎内存、不重指向 `[self+0]`；`[self+0x38]` 是唯一引擎读，X 只按值记录（不解引用）。两段脚本（`neo_effect` 当场铸 token / 官方 `is_rim_system` 18203）**分别记窗口**，`token_matched` 不合并；verdict 两档证据（`predicate_per_system` / `predicate_instantiate_once`）+ 四档环境（`script_refused` / `token_absent` / `instrument_broken` / `no_calls`）。`--systems` **无默认值**（787 属于另一场存档）。门序、三条判读陷阱与 32 B 指纹的理由见 `docs/offline-tooling.md`；**本计划只建好，跑它要本次会话点名** |
| `test_c2_trigger_pred_probe.py` | 上述的离线围栏：`STATS_KEYS` 八键与 `layoutInto` 词序钉回新 module 源码、`Entry` 40 B 与字段序、六条 verdict 分支（含 `instrument_broken` 优先与 `script_refused` 不吃读数）、`--mask` 只收 0、`install_decision` 拒陈旧靶、drain 容量栅栏，共 **32 passed**，无游戏、无 Windows API |
| `c2_witness_probe.py` | 族内 slot[2] 证人 guard（§69）：靶 `0x3B01A0`，join 家族五张；与 donor 同形但换靶换表，`-2` 不重试、绝不 FreeLibrary；两窗读数（`calls=0`/120 s）落取证卷 §69 |
| `test_c2_witness_probe.py` | 上述的离线围栏：donor 的 14 条平移换靶 + `test_verdicts_has_no_tier3_value` + 前序钉回 exe，共 **16 passed**，无游戏、无 Windows API |
| `c2_selfabort_repro.py` | §45 自检器（原 `scratch/2026-10_abortexit/dll_abort_repro.py`，原件冻结留档）：**零游戏、零注入、零 dispatch** —— 把出货字节装进本脚本自己拥有的子 python，按门序跑 `C2Sanity` → `C2DiagQJSInto`，退出码 3 且无 `SURVIVED` ⇒ 死因是我们自己的产物（`abort()`）。修复循环每改一次就重跑这一条命令。观测通道四条：`BASE`/`LOGADDR`/`SANITY`/`WITNESS`，加上 Task 1 的环形记录器 `MFREC`（**读取线程**每 ~2 ms 一次，不是调用后的 dump —— 主线程死在调用内部，dump 那行永远轮不到；调用后那次以 `post` 标签保留，给 Task 4 验收用）。用法与判读陷阱见 `docs/offline-tooling.md` |
| `dll_ubsan_site.py` | §45 的离线符号化器（原 `scratch/2026-10_abortexit/ubsan_site.py`，原件冻结留档）：不属注入通道，是它**只读文件**的那一半 —— 无符号无 debug 段的 DLL 里用 `.rdata`/`.data` 的 UBSan `TypeMismatchData` 记录 + `.pdata` 函数区间把 panic 钉到源文件行号（`site <类型名>` / `func <vma>`；当前产物：141 sites、`func 0x18000bd9b` → `quickjs.c:1494:12`，与 §45.3 一致）。DLL 路径走参数：**第一个参数不是 `site`/`func` 就是路径**（大写 `.DLL` 与无扩展名的 scp 名都算，旧规则会静默去分析默认产物），没给才落到仓库自己的 `zig-out/bin/stellaris_quickjs.dll`。退出码三种意思：0=有匹配、1=读到了但零匹配（这是结论）、**2=没能读到产物**（缺文件/截断/非 PE，一行 stderr 而非 traceback） |
| `test_c2_harness.py` | 上述全部的主机侧测试：Linux 上跑，无游戏、无 Windows API（**135 passed**，含 §44 的 `CONTEXT` 偏移/尺寸与 `capture_thread_state` 调用次序假 kernel32 测试、§44.3 两个对照工具的判读函数（`c2_control_cpuwatch` 的 CPU 前进量口径、`c2_control_suspendcap` 的 capable/incapable/partial 三分）、§45 两个提升工具的关键行集合与 `func` 模式报告）。§44 的字节可比性由**活门** `c2_init_threadstate.assert_same_bytes_as_s42` 守着（sha 不是 §42 那份就拒绝 dispatch）；`test_s42_sha_constant_stays_pinned_to_s42s_bytes` 钉的是那枚常量的**不可改写**（§42 的历史身份 `863917f2…`，不是「本树构建出什么」—— 本计划故意改 `quickjs_wrapper.c`，树里的产物 `77c0c35e…` 必然与它不同，旧的同树等式只能靠撤销计划内工作来满足，故作废）|

## Frida 通道（保留在顶层，因为仍被引用）

| 文件 | 为什么留在这 |
|---|---|
| `execspy.py` + `execspy.js` | 只记录版 base-Execute detour 的驱动与注入脚本；`src/dll/scripted/exec_hook.zig:167` 把它当**记录格式的契约方**引用 |
| `frida-test.py` + `start-frida-server.bat` | `docs/frida-setup.md` 的安装与连通自检路径 |
| `fridadis.py` + `dis.js` | 从 live 进程线性反汇编；`docs/roadmap.md` 段3 的 **B3** 行还指着它（细计划 `2026-10-22-b3-fridadis-bringup.md`；文件本地已在 `scripts/dis.js`,缺的只是上传到 `C:\ns\dis.js`） |
| `scan444.py` + `anchor444.js` | `evidence/xrefs/anchors_4_4_4.md` 的 "Reproduction scripts" —— 换游戏版本要重跑的重锚定 |

## Windows 侧子包：`scripts/windows/`

独立的 SSH / 实机子包（自带 `requirements.txt` 与 `tests/`，测试要在该目录下跑）。launcher 的用法见
`evidence/analysis/runtime_444_c1_validation.md` §35 起的实机流程；监督器见 `docs/offline-tooling.md`
的「实机调试：游戏监督器」。

| 文件 | 干什么 |
|---|---|
| `launch_stellaris.py` | 从无人值守的 SSH 会话经 Steam 拉起游戏，点过 launcher 的对话框，可选 `--unpause` |
| `game_supervisor.py` | 长驻监督器：读暂停图标与事件窗口，按 `want`/`policy` 维持运行态、选事件选项、改速度、截图；文件命令通道 + schtasks 生命周期 |
| `keep_awake.py` | 顶住空闲 + 观测桌面可达性，产出 `C:\temp\ns_awake_status.json`（Windows 侧；`just awake check` 的退出码） |
| `popup_identity.py` | 弹窗身份的纯核：文本/几何指纹与名单解析（stdlib-only，Linux 可 import） |
| `popup_guard.py` | 处置判据与熔断：名单/预算/同 id 连见的 `decide_action`，阈值只在这里定义 |
| `popup_ocr.py` | OCR 单一出口：`ocr_texts()` 永不 raise，返回 `(texts, status, ms)`；`warm\|<png>` CLI 量加载与每帧成本 |
| `popup_geometry.py` | 弹窗几何指纹那半边（纯像素，无 OCR）：`_panel_bbox` 的三个门与关闭点换算；`popup_identity.py` / `popup_guard.py` 的几何侧输入 |
| `ns_world.py` | 世界状态机的唯一入口（CLI）：一行输出 `STATE=… EVIDENCE=… NEXT=…`，退出码 `0` 合法 / `2` 拒绝 / `3` 阻塞 / `4` 锁僵死；子命令 `status`/`probe`/`assert-ready`/`unblock`/`quit`/`abort`/`pull`；纯状态机在 `scripts/world_state.py` |
| `world_probe.py` | 取一次状态读数：复用 `game_supervisor.py` 的像素分类器（**阈值一个不改**），证据里保留全部原始计数与 `crop_sha256`；`ns_world.py` 的读数那一半 |
| `session_bridge.py` | SSH 落在 session 0、游戏在 session 1 时的那条通道（`schtasks /run /I`）；没有它 `ns_world.py` 在 agent 的实际工作方式下不可用 |

## 一次性探针：`scratch/`

| 目录 | 内容 |
|---|---|
| `scratch/2026-09_frida_hot_site_spies/` | 44 个：热路径站点/Frida 采样与反汇编，结论在 §10–§19 |
| `scratch/2026-09_offline_hardcoded_oneshots/` | 16 个：读 exe 但路径写死（`D:\SteamLibrary...`）的离线一次性扫描 |
| `scratch/2026-09_frida_detour_era/` | 4 个：detour 路线的善后（还原 prologue / FreeLibrary / 读 live 字节） |
| `scratch/2026-10_newrt_allocmap/` | 1 个：§43 的离线分配地图 —— 同一份 vendored `quickjs.c` 在 Linux 上跑完 `JS_NewRuntime2`，把每次分配的序 + size + 行号打出来 |
| `scratch/2026-10_threadhandle_matrix/` | 1 个：§44.3 的 2×2 句柄矩阵（created/opened × alive/exited），把 `SuspendThread gle=5` 钉到「线程已退出」而不是「句柄没权限」 |
| `scratch/2026-10_abortexit/` | 2 个：§45 的自杀判别器（子进程里 `ctypes.WinDLL` 装出货字节，无游戏复现 exit 3 + 逐字相同的 witness）与离线符号化器（`.pdata` 区间 + UBSan `TypeMismatchData` 记录 → 源文件行号）。**两个脚本已提升为维护工具（`c2_selfabort_repro.py`、`dll_ubsan_site.py`），原批次冻结留档、字节不动** |

basename **保留原样** —— `evidence/` 三卷与 `evidence/logs/` 按 basename 记录出处，改名等于让取证记录
指向不存在的文件。
