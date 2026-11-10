#!/usr/bin/env python3
"""C6 验收台帐：把六道门**已经产出**的回执判成 `pass` / `fail` / `cannot_say`。

判据逐字来自 `docs/c6-acceptance.md`，本工具不改门、不加门、不写数字阈值。它只读文件：
不 import `frida`、不 import `c2_harness`、不起进程、不联网。六道门的输入是既有驱动留下的
产物（`BOOT` 行、`#meta` 台帐、`C2NeoStatsInto` 行、`verdict=` 行、两份 `game.log` /
`error.log`、同一份 `.sav`），跑法见 `docs/offline-tooling.md` 的 `c6_acceptance.py` 一节。

三档之外没有第四档：
`pass` = 判据成立；`fail` = 判据不成立（这是结论）；`cannot_say` = 产物缺失或落环境档
（「还缺读数」和「判负」是两件事，所以它们也对应不同的退出码）。
"""
from __future__ import annotations

import collections

from c5_variable_probe import find_variables

Gate = collections.namedtuple("Gate", "gate status detail")

PASS = "pass"
FAIL = "fail"
CANNOT_SAY = "cannot_say"

#: C6-1 判据需要的字段；缺一个或不是数字，那一行就不是回执。
_BOOT_JUDGE_KEYS = ("effect_id", "set_id", "install_rc", "alive")


def _as_number(value: str) -> int | str:
    """`"19344"` → `19344`，`"8c774e60b36c2969"` → 原样（sha 不是数字）。"""
    try:
        return int(value)
    except ValueError:
        return value


def _kv(line: str) -> dict[str, int | str]:
    """一行回执里的 `k=v` 字段；`BOOT` / `FAIL` 这类裸词直接丢掉。"""
    fields: dict[str, int | str] = {}
    for token in line.split():
        key, sep, value = token.partition("=")
        if sep and key:
            fields[key] = _as_number(value)
    return fields


def parse_boot(line: str) -> dict[str, int | str]:
    """`BOOT` 回执的字段；不是一条可读回执就 `{}`。

    `BOOT FAIL <step>` 没有 `k=v`，天然落空；判据字段任一缺失或不是数字也返回 `{}`
    —— 半条回执不是回执，`gate_registration` 据此说 `cannot_say` 而不是判负。
    """
    if not line.startswith("BOOT"):
        return {}
    fields = _kv(line)
    if not all(isinstance(fields.get(key), int) for key in _BOOT_JUDGE_KEYS):
        return {}
    return fields


def parse_uninstall(line: str) -> dict[str, int]:
    """`UNINSTALL rc=<n> verify=<n> alive=<n>` 的数字字段；读不到就 `{}`。"""
    if not line.startswith("UNINSTALL"):
        return {}
    numbers = {key: value for key, value in _kv(line).items()
               if isinstance(value, int)}
    if not {"rc", "verify"} <= set(numbers):
        return {}
    return numbers


def gate_registration(boot: dict[str, int | str]) -> Gate:
    """C6-1：注册早于解析。`install_rc==0` 且两个 id 都 `>0` 且 `alive==1`。"""
    if not boot:
        return Gate("C6-1", CANNOT_SAY, "missing_input")
    detail = " ".join(f"{key}={boot[key]}" for key in _BOOT_JUDGE_KEYS)
    passed = (boot["install_rc"] == 0 and boot["effect_id"] > 0
              and boot["set_id"] > 0 and boot["alive"] == 1)
    return Gate("C6-1", PASS if passed else FAIL, detail)


def gate_teardown(line: str) -> Gate:
    """C6-6：收尾。`rc==0` 且 `verify==0`；`alive` 只进 detail（失败判据只写 rc/verify）。"""
    fields = parse_uninstall(line)
    if not fields:
        return Gate("C6-6", CANNOT_SAY, "missing_input")
    alive = fields.get("alive", "?")
    detail = f"rc={fields['rc']} verify={fields['verify']} alive={alive}"
    passed = fields["rc"] == 0 and fields["verify"] == 0
    return Gate("C6-6", PASS if passed else FAIL, detail)


#: doc §1 只认这一个判词为通过档。
EVIDENCE_VERDICTS = ("dispatch_named",)
#: doc §2 明写这两档是**判负**，不是「还没读数」。
NEGATIVE_VERDICTS = ("ids_out_of_range", "ids_not_in_container")


def parse_meta(text: str) -> dict[str, str]:
    """artifact 的 `#meta k=v` 台帐；同名键后者覆盖前者，值一律原样保留。"""
    meta: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("#meta "):
            continue
        key, sep, value = line[len("#meta "):].partition("=")
        if sep and key:
            meta[key] = value
    return meta


def gate_per_system(meta: dict[str, str], systems: int) -> Gate:
    """C6-2：逐系统调用。`--systems` 是这一场的容器原始条数，不接受反推。

    detail 三个数都写（`distinct` / `container` / `systems`），换存档时才读得出
    是哪一格变了；只比这两个 `#meta` 数，不重算 id 集合、不数 artifact 行数。
    """
    if not meta:
        return Gate("C6-2", CANNOT_SAY, "missing_input")
    verdict = meta.get("overall_verdict", "")
    distinct = meta.get("distinct_ids", "?")
    container = meta.get("container_raw_count", "?")
    detail = (f"distinct={distinct} container={container} systems={systems} "
              f"save={meta.get('save_name', '-')} verdict={verdict or '-'}")
    if verdict in NEGATIVE_VERDICTS:
        return Gate("C6-2", FAIL, detail)
    if verdict not in EVIDENCE_VERDICTS:
        return Gate("C6-2", CANNOT_SAY, detail)
    try:
        container_n = int(container)
        distinct_n = int(distinct)
    except (TypeError, ValueError):
        return Gate("C6-2", CANNOT_SAY, detail)
    if container_n != systems or distinct_n != systems:
        return Gate("C6-2", FAIL, detail)
    return Gate("C6-2", PASS, detail)


def parse_stats(line: str) -> dict[str, int]:
    """`C2NeoStatsInto` 那一行的 `k=v` 计数；非数字键丢掉，空行/垃圾行返回 `{}`。"""
    stats: dict[str, int] = {}
    for token in line.split():
        key, sep, value = token.partition("=")
        if not sep or not key:
            continue
        try:
            stats[key] = int(value)
        except ValueError:
            continue
    return stats


def gate_state_written(text: str, name: str, systems: int,
                       stats: dict[str, int]) -> Gate:
    """C6-3：状态写进存档。系统集合与容器逐项相等、值 = 系统 id，写入计数闭合。

    存档那一侧用 `c5_variable_probe.find_variables` 读同一份 `.sav` 的 gamestate；
    写入计数只从同一进程的 `C2NeoStatsInto` 行来，不拿存档行数反推。
    """
    if not text.strip() or not {"writes", "matched", "skipped"} <= set(stats):
        return Gate("C6-3", CANNOT_SAY, "missing_input")
    found = find_variables(text, name)
    bad = next((system_id for system_id in sorted(found)
                if not isinstance(found[system_id], int)
                or found[system_id] != system_id), None)
    if bad is None:
        first_bad = "-"
    elif not isinstance(found[bad], int):
        first_bad = "not_an_id"
    else:
        first_bad = str(bad)
    detail = (f"systems={len(found)} expected={systems} writes={stats['writes']} "
              f"matched={stats['matched']} skipped={stats['skipped']} "
              f"first_bad={first_bad}")
    failed = (stats["skipped"] != 0
              or stats["writes"] != stats["matched"]
              or set(found) != set(range(systems))
              or bad is not None)
    return Gate("C6-3", FAIL if failed else PASS, detail)
