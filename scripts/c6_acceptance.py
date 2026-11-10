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
