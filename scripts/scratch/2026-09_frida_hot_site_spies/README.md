# 2026-09 Frida 热路径站点探针

这批脚本是取证 §10–§15 阶段的一次性探针：attach 运行中的 `stellaris.exe`，往候选热路径站点
（`0x1D08520` base `CEffect::Execute`、`0x535070`/`0x5350D0` 属性派发、`0xB6B3E0` db lookup、
`0xD150A0`/`0xD15270` 曾被当作注册器）上挂 Interceptor 或线性反汇编，把 args/retval/RTTI 读回来。

- **结论在哪**：`evidence/analysis/runtime_444_structures.md` §10–§15 与
  `evidence/analysis/runtime_444_keyword_pipeline.md` §17–§19。**`evidence/` 按 basename 引用它们，
  所以这里的文件名一字不改**（约定见 `AGENTS.md` 的「scripts/ 命名与目录约定」）。
- **不作为接口维护**：地址表是 4.4.4 的、是那次会话的 ASLR 现场，可以失效。但不要在新结论上重犯
  它们已踩过的口径错误（`0xCCCEB0` 是注册器、`0x5350D0` 是 keyword 执行器、`0xD150A0` 是 master
  registrar —— 三条都被证伪）。
- **跑不起来是常态**：需要一个能 attach 的 `frida-server`（`docs/frida-setup.md`）、游戏在跑、
  且 `C:\ns\deep.js` / `C:\ns\deep2.js` 已上传 —— **这两个 `.js` 不在仓库里**，只存在于当时那台机器。
  B 目录的 `cap2.py` 依赖同理（`C:\ns\cap.py`），`rtti_offline.py` 依赖 `C:\ns\spy4_table.txt`
  （那张表是本目录 `spy4.js` 的产物）。

`*.py` 与同名 `*.js` 是一对（py 是驱动，js 是注进去的脚本），必须同名同目录。

| 文件 | 干什么 |
|---|---|
| `fs.py` | 对 `2533860` / `b3719b0` / `b6b3e0` 三个候选站点调 `funcStart`，确认函数头落点 |
| `fs2.py` | `callersOf d15270` + `funcStart`：找 token 分配器的调用方 |
| `fs3.py` | 对一批站点调 `callersOf`，再 disasm `14a80` 的头 30 条 |
| `fs4.py` | 由调用点反推 init function start，disasm 头 20 条并回查其 caller |
| `fs5.py` | caller function start 的 disasm + `strAt 2545cd0` 做字符串身份确认 |
| `fs6.py` | 沿 caller 链往上爬（每层取前 8 个 caller 的 `funcStart`） |
| `body.js` | 通用件：disassemble 整个函数范围，用于调用约定分析（被 `body2`–`body6` 加载） |
| `body2.py` | disasm slot3 `1d08520`（base Execute）与 slot5 `535070` |
| `body3.py` | disasm slot2 inner `7e5280`、switch `5350d0`、slot6 `80d500` |
| `body4.py` | disasm db lookup `b6b3e0` |
| `body5.py` | disasm generic exec `7e69b0`、hashfn `18d6b0`、exec thunk `b6b350` |
| `body6.py` | disasm register fn `d15270` + `ptrAt` |
| `body7.py` | dis `d15270` 40 条 + 读全局 `33799c0` |
| `body8.py` | 按手算 base `0x7ff74b345270` 读字节并 disasm（ASLR 现场的一次性对账） |
| `caller_dis.py` | disasm caller `1d7ce0` 与 wrapper `89fdb0` |
| `callers444.py` | `GetScriptedEffect 89f960` / `GetScriptedTrigger 8a0450` 的调用方 |
| `regfn.py` | disasm `d150a0` 60 条 + `d152c0` 上下文 —— §15 证伪「master registrar」那次 shot |
| `kv2.py` | keyword 数组 heap dump，逐槽标注「是否落在镜像内」+ vtable 槽 |
| `kvinspect.py` | `base`/`globals`/`kwtable`/`vtbl` 四联读，看 keyword 表头与 `33720E8` |
| `missstr.py` | 站点字符串 + `325f5c8` / `32611c8` / `33746e8` 三个全局的裸字节 |
| `prologue.py` + `prologue.js` | dump + 解码 4.4.4 scripted-lookup 函数的 prologue，判 detour 可行性 |
| `spy.py` + `spy.js` | 单站点记 args/retval，经 rpc 排空 |
| `spy2.py` + `spy2.js` | 长时间、ABI-correct 监视两个 scripted lookup |
| `spy3.py` + `spy3.js` | 按 RVA attach，每站点独立 arg reader，长时间采样 |
| `spy4.py` + `spy4.js` | 热 vtable 槽的 RTTI 类名直方图（离线解析见 B 目录 `rtti_offline.py`） |
| `spy5.py` + `spy5.js` | RTTI 缺席时的身份探针：`armDispatch` / `armSlot3` / `hist` |
| `spy6.py` + `spy6.js` | backtrace + keyword 字符串身份（`wrap_535070`） |
| `spy7.py` + `spy7.js` | 读 scope type descriptor 与 effect 对象身份 |
| `strdump.py` | 按手算 base `0x7ff74a630000` dump keyword 表全局 `33799c0` 指向的数组 |
| `strs2.py` | disasm + `strAt` 组合：找 keyword 串在镜像里的落点 |
| `strs3.py` | 同上，加 `ptrAt` |
| `vt.py` | disasm + `ptr_at`，看 vtable 相关槽 |
| `vtlive.py` + `vtlive.js` | 读 live vtable 槽，json 输出 |
| `walkdb.py` + `walkdb.js` | dump 全局 `325EBA0` 并 BST-walk 节点字符串（3.x 版式，4.4.4 不适用） |
