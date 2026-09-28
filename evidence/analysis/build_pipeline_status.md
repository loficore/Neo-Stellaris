# build_pipeline_status — 2026-09-28

## 已完成

1. **构建修复**：QuickJS 源码（quickjs.c/libregexp.c/libunicode.c/cutils.c/dtoa.c）
   直接由 Zig 自带 clang 交叉编译进 `stellaris_quickjs.dll`，移除了对预编译
   `quickjs.lib` 的 `linkSystemLibrary` 依赖。`-DCONFIG_VERSION="2025-09-13"`。
2. **注入器**：`src/inject/main.zig`（Zig，CreateRemoteThread + LoadLibraryW），
   与 DLL 同一工具链产出 `inject.exe`，Windows 端无需任何编译器。
3. **单元测试**：286 项全部通过。
   - 运行方式：`zig build test -Dtest-target=x86_64-linux-gnu`
     （必须动态链主机 glibc；见下方 Gotcha 2）
4. **实机验证**（Windows_Jiaolong，stellaris.exe PID 5172）：
   - `C:\ns\inject.exe 5172 C:\ns\stellaris_quickjs.dll` → `injected OK, remote HMODULE=0xb6670000`
   - 模块列表确认 `stellaris_quickjs.dll` 已加载，进程存活。
   - DllMain 仅初始化 QuickJS runtime，不安装任何引擎 hook（hook 需显式
     `installEffectHook` 调用），对运行中游戏安全。

## 修复的缺陷

- `hooking/detour.zig` LDE：补全算术组 ModR/M（0x00-0x33 系列）、C6/C7/0xFF、
  0x68/0x6A 立即数、A8/A9、moffs A0-A3（4 字节）、0F 1F 多字节 NOP；
  未识别的 0F 转义返回 0（拒绝 hook 误测指令）。
- `api/scope.zig` 测试 mock 缓冲区 `align(8)`。
- `ui/button.zig` getState 测试改走 init()/deinit()。
- `ui/callbacks.zig`、`ui/button.zig` 预期路径去日志化（Zig 0.16 测试运行器
  把任何级别日志计为失败）。

## Gotchas

1. **musl + QuickJS 内建分配器不兼容**：`-Dtarget` 或 musl 静态链接下
   `JS_NewRuntime` 在 `js_alloc_string_rt → js_rc()` 处空指针解引用崩溃
   （glibc 动态链接正常）。DLL 目标用 mingw malloc 不受影响，但未在 Windows
   运行时实测 QuickJS eval。
2. 本机 glibc < zig 0.16 sysroot（需要 GLIBC_2.35），native 测试必须
   `-Dtest-target=x86_64-linux-gnu` 走动态链接。
3. `api_scope_tests` 仍禁用：scope.zig 作测试根时相对 import 越出 module 路径。
4. 游戏进程 VersionInfo 显示 1.0（无效元数据），**实际版本号未确认** —
   AGENTS.md 的 key addresses 对应版本待验证后才能安装 hook。

## 部署链路（可复用）

```
zig build                                            # 产出 dll + inject.exe
scp zig-out/bin/stellaris_quickjs.dll zig-out/bin/inject.exe Windows_Jiaolong:C:/ns/
ssh Windows_Jiaolong "C:\ns\inject.exe <pid|stellaris> C:\ns\stellaris_quickjs.dll"
```

## 下一步

- [ ] 确认运行中的 Stellaris 版本，核对 AGENTS.md key addresses
- [ ] 用 Frida（远端 `pip install frida-server` 或 scp 独立 exe）验证
      offsets.zig 占位值（c_effect.OFFSET_EFFECT_ID=4080 等明显可疑）
- [ ] Windows 运行时实测 QuickJS eval / Stellaris.* bridge
- [ ] 验证通过后安装 effect/trigger detour
