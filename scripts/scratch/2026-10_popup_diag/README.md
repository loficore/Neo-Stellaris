# 2026-10_popup_diag —— 无人值守弹窗实机批次(Task 6)的一次性读数脚本

全部**只读**:枚举窗口、量裁片亮度、翻事件日志、算产物哈希。判读结果与它们打印的读数
在 `evidence/logs/unattended_popup_4_4_4.log`;陷阱结论在 `docs/offline-tooling.md`
(判读陷阱 6 / 10 / 12 / 14)。

| 脚本 | 干什么 | 远端落点 |
|---|---|---|
| `win_read.py` | 游戏窗口的 rect/可见性 + 截图尺寸与极值 + 留证目录计数 | `C:\temp\ns_win_read.py` |
| `screen_who.py` | 监督器记的 hwnd 还活着吗,屏幕上有哪些有标题的窗 | `C:\temp\ns_screen_who.py` |
| `x_profile.py` / `x_bucket.py` | 在留证裁片的标题带里定位亮标记(关闭点复核用) | `C:\temp\ns_x_profile.py` / `ns_x_bucket.py` |
| `log_tail.py` | 按字段紧凑地翻 `ns_game_log.jsonl` | `C:\temp\ns_log_tail.py` |
| `hashes.py` | 一批远端产物的 sha256(前 16 位) | `C:\temp\ns_hashes.py` |

**注意 `screen_who.py` 从 ssh 侧跑不可信**:ssh 起的进程看不到交互桌面的窗口(同一个原因使它
抓屏会失败),所以它对 `IsWindow` 的 `False` 不能读成「窗口没了」—— 窗口存活性只能读 daemon
自己写的状态文件。
