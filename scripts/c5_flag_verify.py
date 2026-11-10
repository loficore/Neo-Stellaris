#!/usr/bin/env python3
"""Judge the four flag-keyspace criteria from three offline artifacts.

usage: c5_flag_verify.py --game-log game.log --js-log neo_js.log \\
                         --sav autosave.sav [--official neo_probe] \\
                         [--ours neo_probe2] [--offset BYTES]

四条判据(计划 Review Focus / `flag_store_4_4_4.md` §6):

1. 官方自己写→读成立(`NEO_FLAG_OFFICIAL name=<官方写的名字>`,控制组);
2. 我们的 native 看得见官方写的 flag(`NEO_FLAG_READ name=<官方名> present=true`);
3. 官方看得见我们写的 flag(`NEO_FLAG_OFFICIAL name=<我们写的名字>`);
4. 两个名字都进存档(`flags={}` 里按名字查,`flag_scan` 既有行为)。

判词**指名哪一条链断了**,不是笼统 `fail`:

| 判词 | 含义 |
|---|---|
| `official_control_failed` | 官方自己写自己的 flag 都读不回来 ⇒ 这一发作废 |
| `our_read_missing` | 我们看不见官方写的(Task C 判据 1 的反面) |
| `official_readback_missing` | 官方看不见我们写的(判据 2 的反面) |
| `save_missing` | 日志对但存档没有(判据 3 / 序列化) |
| `flags_end_to_end` | 四条全通 |

**只读**:三份产物都在 host 上,工具不写任何文件。硬错误(读不到文件、
不是 ZIP、`gamestate` 是二进制)打一行 stderr、退出 2 —— 不把「读不到」
伪装成「flag 不存在」。判负退出 1。

## 判读陷阱

- **两个名字互为前缀**(`neo_probe` / `neo_probe2`):两个计数都按**行内 token
  完整值**比较(`name=neo_probe` 是一个 token),`log_text.count(...)` 会把子串
  算进另一个名字。
- **月度重跑**:flag 持久化、事件每月重跑同一批,所以计数会累加;判据只认
  「≥1」。只判当期就带 `--offset`(窗口开始前记下的 `game.log` 字节偏移)。
- **`random_system` 不确定性**:官方写的那个 flag 落在哪个星系随机,所以第 2
  条判据只认「至少一条 `present=true`」,不钉系统 id。
- **扫描产物只认 `flag_scan` 的名字**:`flags=<名字>=<时间戳>`,时间戳语义
  不在这四条判据里。
"""
from __future__ import annotations

import argparse
import pathlib
import sys

from c5_variable_probe import flag_scan, read_gamestate

#: 官方半边写的固定词(事件里的 `log = "NEO_FLAG_OFFICIAL name=<n>"`)。
OFFICIAL_MARK = "NEO_FLAG_OFFICIAL"

#: runtime 半边写的固定词(`__neo_log` 的正文,host 给它加 `NEO_JS_LOG` 前缀)。
JS_MARK = "NEO_FLAG_READ"

#: 判词域。顺序即判据顺序(先最上游的链)。
VERDICTS = (
    "official_control_failed",
    "our_read_missing",
    "official_readback_missing",
    "save_missing",
    "flags_end_to_end",
)


def official_hit_count(log_text: str, name: str) -> int:
    """`game.log` 里 `NEO_FLAG_OFFICIAL name=<name>` 的行数(按 token 完整值)。

    逐行解析、`name=<name>` 必须是**一个完整 token**:`neo_probe` 是
    `neo_probe2` 的前缀,子串计数会把另一个名字的行算进来。
    """
    wanted = f"name={name}"
    return sum(1 for line in log_text.splitlines()
               if OFFICIAL_MARK in line and wanted in line.split())


def _fields(line: str) -> dict[str, str]:
    """`k=v` tokens of one log line (first occurrence wins, non-`k=v` ignored)."""
    found: dict[str, str] = {}
    for token in line.split():
        key, sep, value = token.partition("=")
        if sep and key not in found:
            found[key] = value
    return found


def js_flag_lines(log_text: str, name: str) -> list[int]:
    """系统 id where `__neo_system_has_flag(id, name)` came back true.

    Only `present=true` rows count: the runtime half logs a readback only when
    it is true, and a `present=false` row is a documented miss, not evidence.
    A row with no `id=` token cannot be attributed to a system and is skipped.
    """
    ids: list[int] = []
    for line in log_text.splitlines():
        if JS_MARK not in line:
            continue
        fields = _fields(line)
        if fields.get("name") != name or fields.get("present") != "true":
            continue
        try:
            ids.append(int(fields["id"]))
        except (KeyError, ValueError):
            continue
    return ids


def verdict(*, official_hits: int, js_reads: list[int], official_readback: int,
            save_official: list[int], save_ours: list[int],
            official: str, ours: str) -> tuple[str, str]:
    """`(tag, detail)` — 判据按上游→下游排,第一个不成立的那条给出判词。"""
    if official_hits == 0:
        return ("official_control_failed",
                f"official_control_failed:official_hits=0:official={official}")
    if not js_reads:
        return ("our_read_missing",
                f"our_read_missing:js_reads=0:official={official}:ours={ours}")
    if official_readback == 0:
        return ("official_readback_missing",
                f"official_readback_missing:official_readback=0:ours={ours}:official={official}")
    missing = [name for name, ids in ((official, save_official), (ours, save_ours))
               if not ids]
    if missing:
        return ("save_missing", "save_missing:missing_sav=" + ",".join(missing))
    return ("flags_end_to_end", f"flags_end_to_end:official={official}:ours={ours}")


def _read_log(path: str, offset: int) -> str:
    data = pathlib.Path(path).read_bytes()
    if offset:
        data = data[offset:]
    return data.decode("utf-8", errors="replace")


def _fmt(ids: list[int]) -> str:
    return ",".join(str(system_id) for system_id in ids) if ids else "none"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--game-log", required=True, help="Stellaris game.log")
    parser.add_argument("--js-log", required=True, help="the runtime's js log (C:/temp/neo_js.log)")
    parser.add_argument("--sav", required=True, help="an autosave .sav (zip)")
    parser.add_argument("--official", default="neo_probe",
                        help="flag name the official script writes/reads")
    parser.add_argument("--ours", default="neo_probe2",
                        help="flag name our native code writes")
    parser.add_argument("--offset", type=int, default=0,
                        help="byte offset in --game-log; only bytes after it are judged "
                             "(a persistent flag is re-set every month, so counts accumulate)")
    args = parser.parse_args(argv)

    try:
        game_log = _read_log(args.game_log, args.offset)
        js_log = _read_log(args.js_log, 0)
        gamestate = read_gamestate(pathlib.Path(args.sav))
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 2

    official_hits = official_hit_count(game_log, args.official)
    official_readback = official_hit_count(game_log, args.ours)
    js_reads = js_flag_lines(js_log, args.official)
    save_official = flag_scan(gamestate, args.official)[0]
    save_ours = flag_scan(gamestate, args.ours)[0]
    tag, detail = verdict(official_hits=official_hits, js_reads=js_reads,
                          official_readback=official_readback,
                          save_official=save_official, save_ours=save_ours,
                          official=args.official, ours=args.ours)
    print(" ".join([
        "FLAG_VERIFY", tag,
        f"official_hits={official_hits}",
        f"official_readback={official_readback}",
        f"js_reads={_fmt(js_reads)}",
        f"save_official={_fmt(save_official)}",
        f"save_ours={_fmt(save_ours)}",
        f"detail={detail}",
    ]))
    return 0 if tag == "flags_end_to_end" else 1


if __name__ == "__main__":
    raise SystemExit(main())
