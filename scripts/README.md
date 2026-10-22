# scripts/ 索引

顶层只有**维护中的接口**：离线 PE 工具、实机注入通道、launcher。一次性探针在
`scratch/`（各目录自带 README，说明它属于哪次取证、结论落在哪个 §）。
命名与归档规则见 `AGENTS.md` 的「scripts/ 命名与目录约定」。

离线工具的**用法与判读陷阱**不在这里，在 `docs/offline-tooling.md`；这张表只回答"这是什么、产出什么"。

## 离线静态 RE 工具（读 `stellaris.exe` 拷贝；不需要进程、不需要 IDA license）

路径一律 `NS_STELLARIS_EXE` 可覆盖，见 `docs/offline-tooling.md` 的前置条件。

| 文件 | 干什么 | 产出（`evidence/xrefs/`） |
|---|---|---|
| `find_refs.py` | 线性 capstone 解码每个可执行段，找指向给定 RVA 的 image-relative 引用 | `rva_reference_scan_4_4_4.txt` |
| `riprefs.py` | 同一个问题的快版：谁读/写某个数据全局，不解码 37 MB | `db_global_refs_4_4_4.txt` |
| `fastcalls.py` | 字节级定位对某 RVA 的所有直接 call/jmp，按 `.pdata` 函数分桶并贴来源文件名 | `callers_0x<rva>_buckets.tsv` |
| `disrva.py` | 反汇编一个 RVA 区间，标注每个 rip 操作数解析到的 RVA 与每个 call 目标 | — |
| `cap.py` | 同样的反汇编，走 `.text` 手解 + capstone（`disrva.py` 的前身，仍在用） | — |
| `pdata.py` | x64 `.pdata`(RUNTIME_FUNCTION) → 精确函数边界，无需分析 | — |
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
| `rttibatch.py` | 直接从磁盘 PE 给一串 vtable RVA 解出 MSVC C++ 类名 | `ceffect_vtable_map_4_4_4.txt`（`--effects`） |
| `tokencorpus.py` | A5：把 token 空间与随游戏发的脚本离线对账，join 应当精确 | `token_corpus_crosscheck_4_4_4.tsv` |
| `emu_desc.py` | C0.3 oracle：用 unicorn 跑引擎自己的两个描述符写手，逐字节产出 golden 向量 | `descriptor_oracle_4_4_4.tsv` + `src/dll/scripted/keyword_registry_golden.zig` |
| `c1_preflight.py` | **约束 4 的门**：候选 keyword 名进 `0x1D13270` 之前的离线只读预检，退出码必须 0 | — |

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
| `c2_harness.py` | 共享 harness：PID/base 解析、`list_exports` 重解析 RVA（P10）、`inject_dll`、`remote_alloc`、`call_remote*`、`dispatch_watching_buffer`（调用进行中同时轮询输出 buffer、`g_diag_log` 见证静态、psutil 内存采样；§38/§39） |
| `c2_task2_load.py` | Task 2：证明 harness 在实机读到真正的 64-bit DLL base |
| `c2_task3_diag.py` | Task 3：从实机抓 `JS_NewContext` 失败的**步骤编号**（只观测，修是 Task 4 的事） |
| `c2_task5_init.py` | Task 5：证明实机 `C2Init` 返回 0 且 `g_test_rt`/`g_test_ctx` 真存在；四观测通道的接线处 |
| `c2_task6_e2e.py` | Task 6（验收门）：`1+1` 走 DLL 自己的 `JS_Eval` 并读回结果 |
| `c2_control_watch.py` | §39 对照：注入 + `C2Sanity` + 20 s 纯观测，**不做 init dispatch** |
| `c2_control_sleep.py` | §39 判别器：只执行 `kernel32!Sleep(8000)` 的长远程线程，不碰我们一个字节（先 `Sleep(1000)` 校准） |
| `test_c2_harness.py` | 上述全部的主机侧测试：Linux 上跑，无游戏、无 Windows API（86 passed） |

## Frida 通道（保留在顶层，因为仍被引用）

| 文件 | 为什么留在这 |
|---|---|
| `execspy.py` + `execspy.js` | 只记录版 base-Execute detour 的驱动与注入脚本；`src/dll/scripted/exec_hook.zig:167` 把它当**记录格式的契约方**引用 |
| `frida-test.py` + `start-frida-server.bat` | `docs/frida-setup.md` 的安装与连通自检路径 |
| `fridadis.py` + `dis.js` | 从 live 进程线性反汇编；`docs/roadmap.md` 段3 的 **B3** 行还指着它（细计划 `2026-10-22-b3-fridadis-bringup.md`；文件本地已在 `scripts/dis.js`,缺的只是上传到 `C:\ns\dis.js`） |
| `scan444.py` + `anchor444.js` | `evidence/xrefs/anchors_4_4_4.md` 的 "Reproduction scripts" —— 换游戏版本要重跑的重锚定 |

`scripts/windows/` —— 独立的 SSH launcher 子包（自带 `requirements.txt` 与 `tests/`），用法见
`evidence/analysis/runtime_444_c1_validation.md` §35 起的实机流程。

## 一次性探针：`scratch/`

| 目录 | 内容 |
|---|---|
| `scratch/2026-09_frida_hot_site_spies/` | 44 个：热路径站点/Frida 采样与反汇编，结论在 §10–§19 |
| `scratch/2026-09_offline_hardcoded_oneshots/` | 16 个：读 exe 但路径写死（`D:\SteamLibrary...`）的离线一次性扫描 |
| `scratch/2026-09_frida_detour_era/` | 4 个：detour 路线的善后（还原 prologue / FreeLibrary / 读 live 字节） |

basename **保留原样** —— `evidence/` 三卷与 `evidence/logs/` 按 basename 记录出处，改名等于让取证记录
指向不存在的文件。
