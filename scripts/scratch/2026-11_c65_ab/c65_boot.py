"""c65_boot.py — C6-5 trip B的**原子启动段**（实机，Windows 侧）。

为什么要有这个脚本：上一发的启动命令是「一条 ssh 里跑 `session_bridge.py` + 整条注入链」，
我的 shell 端 120 s 超时把 ssh 掐了 ⇒ 回执没落盘、也没法判断注入到底成没成。这一发把
**存档准备 + 启动 + 注入 + 回执落盘** 收进一个脚本：

1. 把固定存档拷回「最新」位置并刷新 mtime（`--continuelastsave` 取 mtime 最新那份），
   并**校验 sha256** —— 存档被改过就当场停，不进游戏。
2. 跑 `c2_boot_inject.py`（`--allow-window` = 人当场声明的前提，见 plan 的授权段）。
3. 把它的 stdout **逐行落盘**到 `C:/temp/c65_B_boot.txt`：**第一行是原样的 `BOOT …` 行**
   （台账的 `parse_boot` 只认行首），其余是 `#` 注释。

于是：ssh 断了也不影响证据，回执文件一定在。

用法（Windows，落在 session 1 ⇒ 必须经 `session_bridge.py`）：
    python C:/temp/session_bridge.py --timeout-s 240 C:/temp/c65_boot.py
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys

import c65_hold_saves  # 同目录部署（C:/temp）：检查目录里有没有比固定存档更新的 autosave

DOCS = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\13229"), "Documents",
                     "Paradox Interactive", "Stellaris")
SAVE_DIR = os.path.join(DOCS, "save games", "_1474567734")
FROZEN = r"C:\temp\c6_c65_base.sav"
TARGET = os.path.join(SAVE_DIR, "autosave_9999.01.01.sav")
#: 固定存档的 sha256（Task 1 Step 3 在主机侧读出来的）。变了 = 对照组的前提变了。
EXPECTED_SAVE_SHA = "9c63364ed1c6e7ee5d52462d84ac1443240c1d40bbb53fcdb7d8983cdbd7f6a5"
EXE = r"D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe"
DLL = r"C:\temp\sqjs_c6r1.dll"
DRIVER = r"C:\temp\c2_boot_inject.py"
RECEIPT = r"C:\temp\c65_B_boot.txt"


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    os.makedirs(SAVE_DIR, exist_ok=True)
    shutil.copyfile(FROZEN, TARGET)
    os.utime(TARGET, None)  # mtime = now ⇒ `--continuelastsave` 选它
    digest = sha256(TARGET)
    print(f"SAVE path={TARGET} bytes={os.path.getsize(TARGET)} sha256={digest}")
    if digest.lower() != EXPECTED_SAVE_SHA:
        print(f"FAIL save_sha expected={EXPECTED_SAVE_SHA} got={digest}")
        with open(RECEIPT, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("BOOT FAIL save_sha\n")
            handle.write(f"# save sha256={digest} expected={EXPECTED_SAVE_SHA}\n")
        return 2

    # `--continuelastsave` 不按 mtime 选（2026-11-14 实测：mtime 刷到 now 仍载入了趟 A 自己
    # 写的 2331.01.01）。所以「同一份存档字节」的前提只能靠「目录里没有更新的存档」来保。
    newer = c65_hold_saves.newer_saves()
    if newer:
        print("FAIL newer_saves " + ",".join(newer))
        with open(RECEIPT, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("BOOT FAIL newer_saves\n")
            handle.write("# " + ",".join(newer) + "\n")
            handle.write("# 先跑 c65_hold_saves.py 把这些存档移出目录再启动\n")
        return 2

    cmd = [sys.executable, DRIVER, DLL, "--allow-window", "--launch", EXE,
           "--launch-args=--continuelastsave", "--timeout-s", "120"]
    print("RUN " + " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        out = proc.stdout or ""
        err = proc.stderr or ""
        rc = proc.returncode
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        rc = 124
    for line in out.splitlines():
        print(line)
    if err.strip():
        for line in err.splitlines():
            print("STDERR " + line)
    print(f"DRIVER rc={rc}")

    lines = [line for line in out.splitlines() if line.strip()]
    boot_line = next((line for line in lines if line.startswith("BOOT")), "BOOT FAIL no_boot_line")
    with open(RECEIPT, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(boot_line + "\n")
        handle.write(f"# save_path={TARGET}\n")
        handle.write(f"# save_sha256={digest}\n")
        handle.write(f"# save_bytes={os.path.getsize(TARGET)}\n")
        handle.write(f"# dll={DLL}\n")
        handle.write(f"# driver_rc={rc}\n")
        for line in lines:
            handle.write("# " + line + "\n")
    print(f"RECEIPT {RECEIPT}")
    return 0 if rc == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
