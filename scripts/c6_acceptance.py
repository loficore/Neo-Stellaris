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

import argparse
import collections
import pathlib
import re

from c5_variable_probe import find_variables, read_gamestate

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


_VERDICT_RE = re.compile(r"verdict=(\w+)")


def gate_official_readback(text: str) -> Gate:
    """C6-4：官方 DSL 读回。输入是 `c2_graph_reconcile` 的整段 stdout / `--out` 文件。

    多窗口时**任何**一条 `tiers_disagree` 就判负（缺口在引擎一侧就是结论）；一条
    `tiers_counts` / `tiers_partial` 就够把整门降成 `cannot_say` —— 计数相等不等于
    逐名相等，不能读成通过。
    """
    verdicts = _VERDICT_RE.findall(text)
    detail = f"windows={len(verdicts)} verdicts={','.join(sorted(set(verdicts))) or '-'}"
    if not verdicts:
        return Gate("C6-4", CANNOT_SAY, detail)
    if "tiers_disagree" in verdicts:
        return Gate("C6-4", FAIL, detail)
    if all(verdict == "tiers_named" for verdict in verdicts):
        return Gate("C6-4", PASS, detail)
    return Gate("C6-4", CANNOT_SAY, detail)


#: `game.log` 里的官方 marker：行内**任意位置**的独立大写标识符（至少三个字符）。
#:
#: 真实行的形状是 `[HH:MM:SS][effect_impl.cpp:21978]: [2314.8.1] Log effect, … R5_HIT`
#: —— marker 在**行尾**。旧实现只认行首（`^[A-Z][A-Z0-9_]{2,}`），于是两份真实窗口
#: 都解析出空集，「空集相等」被读成 pass（2026-11-11 R5 实测）。`[file:line]` 前缀里的
#: `effect_impl.cpp` / `21978` 不构成独立大写 token，不会被误计。
MARKER_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Z][A-Z0-9_]{2,})(?![A-Za-z0-9_])")
#: 装了 DLL 的那一趟会多出 `NEO_JS_*` / `NEO_C*` —— 那是我们的行，不是官方脚本的行。
#: `PS_HIT` 是 **mod** 写的，两趟都在，不许排。查过
#: `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`：官方 keyword 里没有 `NEO_` 前缀。
MARKER_EXCLUDE_PREFIXES = ("NEO_",)
#: `error.log` 里算「脚本错误」的行；`Unexpected token` 是晚注册的签名（取证卷 §30）。
ERROR_MARKERS = ("Script Error", "Unexpected token")


def official_markers(text: str) -> collections.Counter:
    """每行的官方 marker 计数（行内任意位置的独立大写 token）；我们自己的前缀不计。"""
    markers: collections.Counter = collections.Counter()
    for line in text.splitlines():
        for token in MARKER_RE.findall(line):
            if token.startswith(MARKER_EXCLUDE_PREFIXES):
                continue
            markers[token] += 1
    return markers


def script_errors(text: str) -> int:
    """含 `Script Error` 或 `Unexpected token` 的行数。"""
    return sum(1 for line in text.splitlines()
               if any(marker in line for marker in ERROR_MARKERS))


def gate_official_unchanged(*, base_log: str | None, with_log: str | None,
                            base_err: str | None, with_err: str | None) -> Gate:
    """C6-5：官方语义不受影响。两组对照只差 DLL 装没装。

    `None` = 文件没给（`cannot_say`）；`""` = 文件存在但为空（合法的「零错误」读数）。
    判据是官方 marker 集合逐项相等 **且** 脚本错误行数差为 0 —— 不是两份日志总行数相等。
    """
    missing_inputs = [name for name, value in (("base_log", base_log), ("with_log", with_log),
                                               ("base_err", base_err), ("with_err", with_err))
                      if value is None]
    if missing_inputs:
        return Gate("C6-5", CANNOT_SAY, "missing_input:" + ",".join(missing_inputs))
    base = official_markers(base_log)
    with_dll = official_markers(with_log)
    if not base and not with_dll:
        # 空集相等不是「官方输出一致」，是仪器没看见东西 —— 判 cannot_say，不许当 pass。
        return Gate("C6-5", CANNOT_SAY, "no_markers_parsed")
    missing = sorted((base - with_dll).elements())
    extra = sorted((with_dll - base).elements())
    error_delta = script_errors(with_err) - script_errors(base_err)
    detail = (f"missing={','.join(missing) or '-'} extra={','.join(extra) or '-'} "
              f"error_delta={error_delta} markers={len(base | with_dll)}")
    failed = bool(missing) or bool(extra) or error_delta != 0
    return Gate("C6-5", FAIL if failed else PASS, detail)


def _read(path: str | None) -> str | None:
    """`None`（没给）或读不到都返回 `None`；调用方据此说 `cannot_say`。"""
    if path is None:
        return None
    try:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def evaluate(args: argparse.Namespace) -> list[Gate]:
    """六道门各判一次，按 C6-1 … C6-6 的顺序返回。"""
    boot = _read(args.boot)
    uninstall = _read(args.uninstall)
    exec_caller = _read(args.exec_caller)
    stats = parse_stats(_read(args.stats) or "")

    gamestate = ""
    if args.sav is not None:
        try:
            gamestate = read_gamestate(pathlib.Path(args.sav))
        except (OSError, ValueError):
            gamestate = ""

    base_log = _read(args.base_log)
    with_log = _read(args.with_log)
    base_error = _read(args.base_error)
    with_error = _read(args.with_error)

    return [
        gate_registration(parse_boot(boot or "")),
        gate_per_system(parse_meta(exec_caller or ""), args.systems),
        gate_state_written(gamestate, args.var_name, args.systems, stats),
        gate_official_readback(_read(args.reconcile) or ""),
        gate_official_unchanged(base_log=base_log, with_log=with_log,
                                base_err=base_error, with_err=with_error),
        gate_teardown(uninstall or ""),
    ]


def render(gates: list[Gate]) -> str:
    """每门一行 `gate status detail`，末行汇总三档计数。"""
    lines = [f"{gate.gate} {gate.status} {gate.detail}" for gate in gates]
    counts = collections.Counter(gate.status for gate in gates)
    lines.append(f"C6 SUMMARY pass={counts[PASS]} fail={counts[FAIL]} "
                 f"cannot_say={counts[CANNOT_SAY]}")
    return "\n".join(lines) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--boot", default=None,
                        help="c2_boot_inject.py 的 BOOT 回执（C6-1）")
    parser.add_argument("--uninstall", default=None,
                        help="c2_boot_inject.py --uninstall 的 UNINSTALL 回执（C6-6）")
    parser.add_argument("--exec-caller", default=None,
                        help="c2_exec_caller_probe.py 的 artifact（C6-2）")
    parser.add_argument("--stats", default=None,
                        help="同一进程 C2NeoStatsInto 那一行（C6-3 的写入计数）")
    parser.add_argument("--sav", default=None, help="同一场的 .sav（C6-3）")
    parser.add_argument("--var-name", default="neo_mark",
                        help="C6-3 的变量名（默认 neo_mark）")
    parser.add_argument("--systems", type=int, required=True,
                        help="这一场的容器原始条数；无默认值，必须现场取")
    parser.add_argument("--reconcile", default=None,
                        help="c2_graph_reconcile.py 的 stdout 或 --out 文件（C6-4）")
    parser.add_argument("--base-log", default=None, help="未装 DLL 那趟的 game.log（C6-5）")
    parser.add_argument("--with-log", default=None, help="装了 DLL 那趟的 game.log（C6-5）")
    parser.add_argument("--base-error", default=None, help="未装 DLL 那趟的 error.log（C6-5）")
    parser.add_argument("--with-error", default=None, help="装了 DLL 那趟的 error.log（C6-5）")
    parser.add_argument("--out", default=None,
                        help="把台帐另写一份（evidence/logs/c6_acceptance_4_4_4.tsv）")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    gates = evaluate(args)
    text = render(gates)
    print(text, end="")
    if args.out:
        # 3.9 的 `Path.write_text` 没有 `newline=`（3.10 才加），台帐要 LF 而不是
        # Windows 的 CRLF，所以走 `open`。
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    statuses = [gate.status for gate in gates]
    if FAIL in statuses:
        return 1
    if CANNOT_SAY in statuses:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
