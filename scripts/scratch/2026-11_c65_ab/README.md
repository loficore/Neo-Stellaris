# 2026-11 C6-5 A/B 对照（一次性探针，`docs/superpowers/plans/2026-11-13-c6-5-ab-pair.md`）

这一组文件只回答一个问题：**同一存档、同一 mod、同一窗口长度（12 个游戏月）跑两趟，
唯一差别是进程里有没有我们的 DLL —— C6-5 判据（官方 marker 集合逐项相等 + 脚本错误
行数差 0）是否成立。** 判据本身在 `docs/c6-acceptance.md` §C6-5，判官是既有的
`scripts/c6_acceptance.py`（这一发没有新写判据工具）。

| 文件 | 回答什么 |
|---|---|
| `c65_probe/` | 探针 mod：`on_monthly_pulse → event → random_system → every_system → log = "C65_HIT"`。每月一次，一次一行 marker。**只**用官方 `log` 效果。 |
| `lw_launch.py` | 趟 A（base）的裸启动器：`stellaris.exe --continuelastsave`，`cwd` 设在 exe 旁边。 |
| `c65_window.py` | 把一趟的 `game.log` 裁成 marker 窗口、把 `error.log` 整份拷走，并打印 sha / 字节偏移。 |
| `c65_boot.py` | 趟 B 的**原子启动段**：固定存档回位 + sha 校验 + 「目录里没有更新的存档」守卫 + `c2_boot_inject.py` 启动期注入 + `BOOT` 回执落盘（`C:/temp/c65_B_boot.txt`）。 |
| `c65_hold_saves.py` | 把「比固定存档更新」的 autosave 移出战役目录（`C:\temp\c65_saves_hold\`）——`--continuelastsave` 不按 mtime 选存档，见下。 |
| `c65_close.py` | 一趟的**原子收尾段**：切窗口 → `--uninstall` → `taskkill`，回执落 `C:/temp/c65_<trip>_close.txt`。 |
| `c65_count.py` | 一次读数：`COUNT=<n> LAST=<游戏日期>`。窗口长度按游戏月算，弹窗会暂停模拟，所以要反复读它。 |
| `c65_modules.py` | 一次读数：某个 pid 里有没有 `sqjs*` 模块（C6-5 的「两趟只差装没装」靠它，不靠流程自述）。 |

## `--continuelastsave` 不按 mtime 选存档（2026-11-14 实测）

把固定存档（`2329.07.01`）拷成 `autosave_9999.01.01.sav` 并把 mtime 刷成 now，趟 B 仍然载入
**`2331.01.01`** —— 也就是**趟 A 自己写出来的**那份 autosave。于是「同一份存档字节」这个对照组前提
不能靠 mtime 保，只能靠「目录里没有更新的存档」保：`c65_hold_saves.py` 负责移走，`c65_boot.py`
在启动前**再复查一遍**，有就更早地 `BOOT FAIL newer_saves`。

## 为什么要 `c65_boot.py` / `c65_close.py` 这两个壳

趟 A 是裸启动，没有注入链，一条 ssh 就够。趟 B 的启动链（`session_bridge` → 启动 → 等 5 s →
注入 → 注册 → 回执）在我这边一次 **120 s 的 shell 超时**里没跑完，ssh 被掐掉 ⇒ 回执没落盘、
注入成没成也读不到（2026-11-13 那一发就是这样，随后主机整体下线）。所以把「存档准备 + 启动 +
注入 + 回执落盘」和「切窗口 + 拆钩子 + 杀进程」各自收进一个脚本：
**ssh 断了不影响证据，回执文件一定在**。

## 为什么不能拿 `c2_boot_inject.py` 当趟 A 的启动器

`c2_boot_inject.py` 的第一件事就是校验 DLL 导出的存在性并注入 —— 而趟 A 的定义就是
**进程里没有任何 `sqjs*` 模块**。用它「启动但不注入」等于两条思路混用，读出来的对照
也不再是「只差装没装 DLL」。所以趟 A 用 `lw_launch.py`，argv 形状与 `c2_boot_inject.boot()`
的 `cwd=os.path.dirname(exe)` 保持一致，两趟的差别只剩注入这一条。

## 为什么不用 `neo_action`

`neo_action` 是我们自己注册的 effect。base 趟没有 DLL ⇒ 没有那个 token ⇒ 脚本解析得到
`Unknown effect` / `Unexpected token`，那是**对照组自己造成的**错误，会把 C6-5 的
`error_delta` 污染成非 0。所以探针只写官方 `log`。

## `C65_HIT` 的频率与窗口

`on_monthly_pulse` 每个游戏月触发一次。R5（同一形状）的实测是**每脉冲一行**：
`evidence/logs/c6_r5_A_game_window_4_4_4.log` 的 12 行相隔 11 s，月份逐月递增
（`2314.8.1` … `2315.7.1`）⇒ 这串 marker 是「模拟在走」的钟，不是系统计数。
本发按同一形状复采，`C65_HIT` 计数仍然只当钟用。

窗口取**前 12 个**含 `C65_HIT` 的行（`c65_window.py A 12`），两趟的首尾月份必须逐项相同，
否则这一对不是对照组。
