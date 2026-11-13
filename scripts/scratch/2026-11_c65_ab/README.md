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
