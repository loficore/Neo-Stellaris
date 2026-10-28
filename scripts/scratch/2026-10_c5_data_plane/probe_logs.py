#!/usr/bin/env python3
"""probe_logs —— §76 判读用的一次性诊断探针(只读,不改任何状态)。

为什么不去用 powershell:路径里有空格,而本机 sshd 的默认 shell 会先把引号吃掉一次
(`Get-Content C:/Users/13229/Documents/Paradox Interactive/...` 实测被拆成两个参数)。
`python C:/temp/<name>.py` 是唯一在这台机上稳定的通道。

输出五块:
  1 game.log 的 size/mtime 与最后 40 行里**含关键词**的那些行(不刷屏)
  2 ns_game_log.jsonl 的最后 12 行(守护进程事件)
  3 ns_cmd.txt 的内容(命令文件现在说什么)
  4 ns_cmd.seen 的内容(守护进程已经消费到哪一条)
  5 三条 marker 的计数(TS_NEO_ / TS_RIM_ / console)
"""
import json
import os
import sys

GAME_LOG = os.path.join(
    os.path.expanduser("~"),
    "Documents", "Paradox Interactive", "Stellaris", "logs", "game.log",
)
SUP_LOG = r"C:\temp\ns_game_log.jsonl"
CMD = r"C:\temp\ns_cmd.txt"
KEYWORDS = (
    "TS_NEO", "TS_RIM", "neo_effect", "is_rim_system", "every_system",
    "console", "Unknown", "unexpected", "Error", "error",
)


def tail_lines(path, n):
    with open(path, "rb") as f:
        data = f.read()
    text = data.decode("utf-8", errors="replace")
    return text.splitlines()[-n:]


def main():
    if not os.path.exists(GAME_LOG):
        print(f"NO_GAME_LOG\t{GAME_LOG}")
        return 2
    st = os.stat(GAME_LOG)
    print(f"GAME_LOG\t{GAME_LOG}\tsize={st.st_size}\tmtime={st.st_mtime:.0f}")

    lines = tail_lines(GAME_LOG, 400)
    print(f"TAIL_LINES\t{len(lines)}")
    hits = [ln for ln in lines if any(k in ln for k in KEYWORDS)]
    for ln in hits[-40:]:
        print(f"HIT\t{ln[:300]}")
    print(f"HIT_COUNT\t{len(hits)}")

    print(f"MARKER_TS_NEO\t{sum('TS_NEO' in ln for ln in lines)}")
    print(f"MARKER_TS_RIM\t{sum('TS_RIM' in ln for ln in lines)}")

    try:
        sup = tail_lines(SUP_LOG, 12)
        for ln in sup:
            print(f"SUP\t{ln[:300]}")
    except OSError as err:
        print(f"SUP_ERROR\t{err!r}")

    for path in (CMD, os.path.splitext(CMD)[0] + ".seen"):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                print(f"FILE\t{path}\t{f.read().strip()[:200]}")
        except OSError as err:
            print(f"FILE_ERROR\t{path}\t{err!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
