#!/usr/bin/env python3
"""find_save —— 在 Windows 主机上找 Paradox 存档目录(§C5 Task 5 的一次性探针)。

为什么不用 powershell 一行命令:本机的 sshd 默认 shell 会把 `cmd /c dir /s "C:\\...\\*.sav"`
与 `Get-ChildItem ... | Select-Object ...` 各按不同规则拆一次,两种写法都实测失败
(GBK 的「系统找不到指定的路径」/ sh 的「未绑定的变量」)。`python C:/temp/<name>.py`
是仓库自己用惯的那条通道(justfile 的 launch/deploy 都是这个形状)。

输出:每个候选根的绝对路径 + 该根下最近 10 个 .sav 的 (mtime, bytes, path);
找不到任何根时打印 `NO_SAVE_ROOT` 并退出 2(不猜路径)。
"""
import os
import sys


def roots():
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Documents", "Paradox Interactive", "Stellaris", "save games"),
        os.path.join(home, "OneDrive", "Documents", "Paradox Interactive", "Stellaris", "save games"),
        os.path.join(home, "OneDrive", "文档", "Paradox Interactive", "Stellaris", "save games"),
        os.path.join(home, "Documents", "Paradox Interactive", "Stellaris", "saved games"),
        r"C:\Users\Public\Documents\Paradox Interactive\Stellaris\save games",
        os.path.join(home, "AppData", "Roaming", "Paradox Interactive", "Stellaris", "save games"),
    ]
    seen = []
    for path in candidates:
        if os.path.isdir(path) and path not in seen:
            seen.append(path)
    return home, seen


def main():
    home, found = roots()
    print(f"HOME\t{home}")
    if not found:
        print("NO_SAVE_ROOT")
        return 2
    for root in found:
        print(f"ROOT\t{root}")
        rows = []
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                if not name.lower().endswith(".sav"):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                rows.append((st.st_mtime, st.st_size, full))
        rows.sort(reverse=True)
        for mtime, size, full in rows[:10]:
            print(f"SAV\t{mtime:.0f}\t{size}\t{full}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
