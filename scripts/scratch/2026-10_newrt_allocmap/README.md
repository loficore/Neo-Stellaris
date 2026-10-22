# 2026-10_newrt_allocmap — §43 的离线分配地图

一次性:回答「§42 那段 6.9 s 零分配窗口里,`JS_NewRuntime2` 本来该在分配什么」。

| 文件 | 当时在回答哪个问题 |
|---|---|
| `allocmap.c` | 用**同一份 vendored `quickjs.c`** 离线跑完 `JS_NewRuntime2`,把每次 `js_malloc`/`js_free`/`js_realloc` 的**顺序 + size + 调用点(quickjs.c 行号)**打出来。`mf` 回调是 `src/dll/quickjs/quickjs_wrapper.c` 的逐字移植(同 `AllocHeader` 记账、同 `usable_size` = 记录值、同 `MF_TAG_CAP` 与 `M`/`m`/`!`/`F`/`R` 标记流),所以这条离线流与出货 DLL 会吐的流同形——判据是它跑出 `MmMmMmMmMmMmMmMm`,与 §42 的 Linux 阳性对照逐字相同。 |

**怎么跑**(build 命令也写在 `allocmap.c` 头部注释里):

```
R=/var/lofibass_ssd/code/zig/Neo-Stellaris
gcc -O0 -g -rdynamic -DCONFIG_VERSION="2025-09-13" -I "$R/libs/quickjs" \
    "$R/scripts/scratch/2026-10_newrt_allocmap/allocmap.c" \
    "$R"/libs/quickjs/{quickjs,cutils,libunicode,libregexp,dtoa}.c -lm -ldl -lpthread
```

**零游戏、零能力变更**:不碰 `stellaris.exe`,不调任何进程 API;结论在
`evidence/analysis/runtime_444_c1_validation.md` §43。

**不作为接口维护**:可以失效,但别在新结论上重犯它已避开的口径错误(用 libc `realloc`
近似 `usable_size` 会让离线流与 DLL 的流分叉——第一版就是这么写的,已改)。
