#!/usr/bin/env python3
"""Read one variable's per-system values out of a Stellaris 4.4.4 text save.

usage: c5_variable_probe.py --sav PATH --name neo_mark
       c5_variable_probe.py --sav PATH --flag neo_tier2

C5-WRITE 的判据 2:窗口里我们的 keyword 写下的系统变量,离线从存档里逐项对值。
C5-SCORE 的判据 3:官方 `set_star_flag` 落下的 flag,同样从存档里数系统。
`.sav` 是 ZIP,`gamestate` 是文本 Clausewitz;解析复用 `save_hypergraph.py` 的
tokenizer(保留重复键与匿名块),本文件只做**窄**筛选:

    <container>={ <system id>={ … variables={ <name>=<value> … } … } … }

`<container>` 接受 `galactic_object`(4.4.4 真存档)与 `systems`(测试/旧形状);
变量接受两种编码:`name=value`,以及 `{ name=name value=value }` 块。

**只读**:存档留在 Windows 主机,工具不写任何文件。硬错误(不是 ZIP、没有
`gamestate`、二进制 `gamestate`、规则串非法)打一行 stderr、退出 2 —— 不把
「读不到」伪装成「变量不存在」。变量不存在是 `systems=0`,退出 0。
"""
from __future__ import annotations

import argparse
import pathlib
import sys

from save_hypergraph import Block, parse_clausewitz, read_gamestate as _read_gamestate

#: 4.4.4 真存档用 `galactic_object`;`systems` 是窄测试/旧形状。
SYSTEM_CONTAINERS = ("galactic_object", "systems")

SAMPLE_SIZE = 5


def read_gamestate(sav_path: pathlib.Path) -> str:
    """The `gamestate` text of a `.sav` (raises `ValueError` on a bad archive)."""
    text, _replacements = _read_gamestate(sav_path)
    return text


def _blocks(block: Block, key: str) -> list[Block]:
    return [value for entry_key, value in block.entries
            if entry_key == key and isinstance(value, Block)]


def _as_value(text: object) -> int | float | str:
    """Variables are numbers; normalize integral values (incl. `3.00000`) to int.

    Shot 1 stored raw ids and the save printed them as `0.00786` — the engine's
    fixed-point format keeps five decimals, so an integer value can arrive as
    `3.00000` too. Anything non-numeric stays verbatim (loudly).
    """
    if isinstance(text, str):
        try:
            return int(text)
        except ValueError:
            pass
        try:
            number = float(text)
        except ValueError:
            return text
        return int(number) if number.is_integer() else number
    return str(text)


def _variable_values(system: Block, name: str) -> list[int | str]:
    found: list[int | str] = []
    for variables in _blocks(system, "variables"):
        for entry_key, value in variables.entries:
            if entry_key == name:
                found.append(_as_value(value))
                continue
            if entry_key is None and isinstance(value, Block):
                fields = dict(value.entries)
                if fields.get("name") == name:
                    found.append(_as_value(fields.get("value")))
    return found


def find_variables(gamestate: str, name: str) -> dict[int, int | float | str]:
    """`{system id: value}` for every system whose `variables={}` holds `name`.

    Narrow on purpose: only the two system containers are searched, and a system
    with several copies keeps the last one (the save writes one).
    """
    root = parse_clausewitz(gamestate)
    found: dict[int, int | str] = {}
    for container_name in SYSTEM_CONTAINERS:
        for container in _blocks(root, container_name):
            for entry_key, value in container.entries:
                if entry_key is None or not isinstance(value, Block):
                    continue
                try:
                    system_id = int(entry_key)
                except ValueError:
                    continue
                values = _variable_values(value, name)
                if values:
                    found[system_id] = values[-1]
    return found


def flag_scan(gamestate: str, flag: str) -> tuple[list[int], int]:
    """`(ascending system ids holding flag, systems that carry a flags block)`.

    The second number is the judge's control: `systems=0 flags_blocks=787` means the
    flag really is absent, while `flags_blocks=0` means the block is not where we look
    (parser shape, not game behaviour). A bare `systems=0` cannot tell those apart, and
    the live shot has a two-shot budget (spec §2).

    `set_star_flag` lands as a key in the system's flat `flags={}` map (spec §3);
    the value is engine bookkeeping, so only the key is judged.
    """
    root = parse_clausewitz(gamestate)
    flagged: set[int] = set()
    with_flags: set[int] = set()
    for container_name in SYSTEM_CONTAINERS:
        for container in _blocks(root, container_name):
            for entry_key, value in container.entries:
                if entry_key is None or not isinstance(value, Block):
                    continue
                try:
                    system_id = int(entry_key)
                except ValueError:
                    continue
                blocks = _blocks(value, "flags")
                if not blocks:
                    continue
                with_flags.add(system_id)
                if any(flag == name for block in blocks for name, _ in block.entries
                       if name is not None):
                    flagged.add(system_id)
    return sorted(flagged), len(with_flags)


def find_flags(gamestate: str, flag: str) -> list[int]:
    """Ascending system ids whose `flags={}` holds `flag` (key only)."""
    return flag_scan(gamestate, flag)[0]


def _rule_key(rule: str) -> tuple[int, int]:
    mod_text, _, rem_text = rule.partition(":")
    try:
        mod, rem = int(mod_text), int(rem_text or 0)
    except ValueError as exc:
        raise ValueError(f"rule must be MOD:REM, got {rule!r}") from exc
    if mod < 0 or rem < 0:
        raise ValueError(f"rule must be MOD:REM with MOD,REM >= 0, got {rule!r}")
    return mod, rem


def assert_same_rule(write_rule: str, read_rule: str) -> None:
    """写入段与读回段必须覆盖同一批星系;不同规则 ⇒ `ValueError`。

    规则串按 `pack_rule` 的口径归一(`8` 与 `8:0` 相等),比较的是**语义**,
    不是字节 —— 两段写在 mod 文件的不同行,写法可以不同。
    """
    if _rule_key(write_rule) != _rule_key(read_rule):
        raise ValueError(
            f"write rule {write_rule!r} != read rule {read_rule!r}: "
            "the two every_system segments must select the same systems")


def format_report(name: str, found: dict[int, int | float | str]) -> str:
    if not found:
        return f"{name}: systems=0"
    values = [v for v in found.values() if isinstance(v, int)]
    parts = [f"{name}: systems={len(found)}"]
    if len(values) == len(found):
        parts += [f"min={min(values)}", f"max={max(values)}"]
    sample = [found[k] for k in sorted(found)[:SAMPLE_SIZE]]
    parts.append("sample=" + ",".join(str(v) for v in sample))
    return " ".join(parts)


def format_flag_report(flag: str, found: list[int], flags_blocks: int) -> str:
    parts = [f"{flag}: systems={len(found)}", f"flags_blocks={flags_blocks}"]
    if found:
        sample = ",".join(str(system_id) for system_id in found[:SAMPLE_SIZE])
        parts.append(f"sample={sample}")
    return " ".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sav", required=True, help="path to the .sav (zip)")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--name", help="variable name, e.g. neo_mark")
    selection.add_argument("--flag", help="system flag name, e.g. neo_tier2")
    args = parser.parse_args(argv)

    try:
        text = read_gamestate(pathlib.Path(args.sav))
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    if args.flag is not None:
        ids, blocks = flag_scan(text, args.flag)
        print(format_flag_report(args.flag, ids, blocks))
    else:
        print(format_report(args.name, find_variables(text, args.name)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
