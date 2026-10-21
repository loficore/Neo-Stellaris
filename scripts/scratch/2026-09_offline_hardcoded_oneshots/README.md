# 2026-09 离线一次性 PE 探测

读 `stellaris.exe` 拷贝的一次性扫描/转储脚本，**不需要进程、不需要 Frida、不需要 IDA license**。
结论已进 `evidence/analysis/runtime_444_structures.md` 与 `runtime_444_keyword_pipeline.md` 的
§10–§22 各节。**文件名不改**：`evidence/` 按 basename 记录出处。

它们**全部把 exe 路径写死成 `D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe`**（本机路径见
`docs/offline-tooling.md` 的「前置条件」与 `NS_STELLARIS_EXE`）。所以这批在 Linux 取证主机上直接跑会
`FileNotFoundError` —— 这是它们归「一次性」而不是「工具」的原因：写死绝对路径的脚本不算维护中的接口。
要重用就照 `../../find_refs.py` 的做法改读 `NS_STELLARIS_EXE`，或者干脆用顶层已维护的那几个。

| 文件 | 干什么 |
|---|---|
| `sec.py` | 打 section 表（va/vsz/raw/va_end），顺带验 `.text` 覆盖范围 |
| `pedump.py` | section + directory entry 转储，并 dump `24B1990`/`24B3050`/`24B1C88` 三个 vtable 附近字节 |
| `verify_base.py` | 读 preferred image base，统计 `E8` call 的出现数与 `lea rcx->34ac9e0` 模式落点 |
| `callscan.py` | 线性扫 `E8` rel32，找 `0xD15270`（token 分配器）的调用方 |
| `callscan2.py` | 同上，同时对 `D15230`/`D15270` 两个目标，改用 `+5` 偏移判定 |
| `callscan3.py` | 同上，扩到 `D15270`/`34AC9E0`/`34AB6C0` 三目标并处理 `+6` 的 rip 形式 —— §19「567 个调用点分 139 桶」的前身 |
| `refscan.py` | 按名字批量读 `.rdata` 区域并输出 hex+ascii（scope/exec-desc 那一族候选地址） |
| `prol_exec.py` | dump base Execute `1D08520` / slot5 `535070` / switch `5350D0` 的前 32 字节 |
| `prol_exec2.py` | 对任意传入 RVA 做 prologue 反汇编 + 参数引用审计（默认 `1D08520`） |
| `dumpvt.py` | dump 三处 vtable 区域：`24B1988` 家族起点、`24F9900` switch xref 附近、`247AC00` 的 `535070` 簇 |
| `vtcheck.py` | 读 `33720E8`（generic keyword vtable）与 `1D08520` 的裸字节，判 slot 布局 |
| `rtti_check.py` | 用 `vtable-8` 的 ColPack 指针解 3 个 vtable 的类名（§14 的 RTTI 试验） |
| `rtti_check2.py` | 验 `24B1990` 处 `vtable[-8]`/`[-16]` 到底是什么，并在 `.rdata`/`.data` 里搜 `535070` 的两种编码 |
| `rtti_offline.py` | 对 `spy4.js`(在 `../2026-09_frida_hot_site_spies/`)采到的 vtable 列表做离线 RTTI 取名（要 `C:\ns\spy4_table.txt`） |
| `kwmeta.py` | 抽 per-keyword 元数据表，写 `keyword_meta_registry_4_4_4.tsv` —— **该产物并不在 `evidence/xrefs/` 里**，悬空 |
| `cap2.py` | `exec` 现场机器上 `C:\ns\cap.py` 的前半，再 dis `0xE88500`（`kw_add_entry`）；依赖仓库外文件 |
