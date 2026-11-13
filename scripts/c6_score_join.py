#!/usr/bin/env python3
"""C6-4 的第二条证据路径:存档里的**官方状态**与离线分层逐 id 对账。

`c2_graph_reconcile.py` 走的是「引擎日志里的 `NEO_T*` 回执 vs 主机侧重算」。这条路要求
mod 每系统打一行日志,而且日志给的是本地化名(`[This.GetName]`),仓库里没有 id↔名字的
产物 —— 没有 `--name-map` 时它只能判到 `tiers_counts`(计数相等,不是逐名相等),而 C6-4
只认逐名。本工具换一份**独立产物**做同一件事:官方 `check_variable` 按我们的分数分支、
`set_star_flag` 落下的官方状态,连同我们写的变量一起,逐 id 从**存档**里读回来。

用法(主机侧;输入都是这一发留下的 artifact):

    python3 scripts/c6_score_join.py \\
        --sav autosave_2324.07.01.sav \\
        --scores scores_2324.tsv \\
        --js-log neo_js.log \\
        --out evidence/logs/c6_r7_score_join_4_4_4.tsv

四条判据(与 `docs/c6-acceptance.md` 的 C6-4 一节逐条对应):

1. 覆盖:离线表里的每个 id 在存档里都有 `neo_score`,条数相等(少一个就是「官方没比到」);
2. 分层:存档里 `neo_tier2` 的系统集合 == 离线 `score >= 200`,`neo_tier1` == `100..199`;
3. 值:逐 id 的 `neo_score` 与离线表相等 —— **除了**第二个写者观察到的 id
   (runtime JS mod 也会写同一个 `neo_score`,它自己算的 betweenness 与离线整数差 1~2;
   `--js-log` 的 `NEO_HUB <id>` 行就是「这个 id 有第二个写者」的独立观察)。集合外的
   一处不等就是判负,集合内的差值只记账;
4. 控制组:`neo_mark` 逐 id == id(我们那条写路径在每个系统上都真的跑过)。

判词(与 `c6_acceptance.py` 的 C6-4 三档一一对应):

| 判词 | 档 | 含义 |
|---|---|---|
| `score_drives_official_state` | pass | 四条全通 |
| `tier_sets_disagree` | fail | flag 集合与离线分层不等 |
| `score_value_disagree` | fail | 集合外的分数不等,或 `neo_mark` != id |
| `join_incomplete` | cannot_say | 存档缺系统 / 离线表空 / 存档里没有 `neo_score` |

**只读**:存档留在 host 上,工具除 `--out` 外不写任何文件。硬错误(读不到文件、不是 ZIP、
`gamestate` 是二进制)打一行 stderr、退出 2 —— 不把「读不到」伪装成「没写进去」。

## 判读陷阱

- **`neo_score` 有两个写者**。我们注册的 effect 每系统写一次;`examples/chokepoint` 的
  runtime JS 在它判成枢纽的系统上再写一次(`setVariable("neo_score", b)`)。存档保留**最后
  一个**写者,所以那 15 个枢纽的存档值可能是 JS 的读数(与离线整数差 1~2)。判据 3 因此按
  「第二个写者集合」分开记账 —— 集合外的差值是判负,集合内的差值写进 detail,不是通过。
- **flag 会持久化**。`set_star_flag` 写下的 `neo_tier*` 不会因窗口结束消失;要判当期,就得用
  「这一发之前没写过同名 flag」的存档,或者先清干净。本工具的集合比较会把残留读成多余的 id。
- **`flags_blocks` 是控制组**。`tier2=0 flags_blocks=0` 说明 flags 块不在我们找的位置(解析
  形状问题),`tier2=0 flags_blocks=589` 才是「官方真的没写」。两者都判负,但原因不同,所以
  这个数一定打出来。
- **分数表是存档局部的**(§95.6 第 1 条)。离线表必须由**同一份存档**的边算出来;拿上一局的
  表来比,15/55 的集合会整体错位。
"""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import sys

from c2_graph_reconcile import tier_of
from c5_variable_probe import find_variables, flag_scan, read_gamestate

#: 判词域。前三档对应 `c6_acceptance.py` 的 pass / fail / cannot_say。
PASS = "score_drives_official_state"
TIER_DISAGREE = "tier_sets_disagree"
VALUE_DISAGREE = "score_value_disagree"
INCOMPLETE = "join_incomplete"
VERDICTS = (PASS, TIER_DISAGREE, VALUE_DISAGREE, INCOMPLETE)

#: runtime JS 每判成一个枢纽就打一行 `NEO_HUB <id> <score>`;这里只取 id。
_JS_HUB = re.compile(r"NEO_HUB\s+(\d+)\s")


def read_scores(path) -> dict[int, int]:
    """`chokepoint_scores` TSV → `{system_id: score}`(第 5 列,整数)。"""
    scores: dict[int, int] = {}
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("system_id"):
            continue
        fields = line.split("\t")
        scores[int(fields[0])] = int(fields[4])
    return scores


def second_writer_ids(path) -> set[int]:
    """`--js-log` 里 `NEO_HUB <id>` 出现过的 id(第二个写者的观察,不是我们的读数)。"""
    if path is None:
        return set()
    text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    return {int(match) for match in _JS_HUB.findall(text)}


def _sha256(path) -> str:
    """artifact 里记的是**哪一份** js 日志,所以连内容一起记。"""
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def join(*, scores: dict[int, int], score_values: dict[int, int],
         mark_values: dict[int, int | float | str], tier2: list[int], tier1: list[int],
         flags_blocks: int, second_writer: set[int]) -> tuple[str, dict, str]:
    """四条判据 → `(verdict, numbers, detail)`。纯函数:输入都是已经读出来的数。"""
    offline2 = {system for system, score in scores.items() if tier_of(score) == "T2"}
    offline1 = {system for system, score in scores.items() if tier_of(score) == "T1"}
    diffs = {system: (score_values[system], scores[system])
             for system in scores
             if system in score_values and score_values[system] != scores[system]}
    outside = {system: pair for system, pair in diffs.items() if system not in second_writer}
    bad_mark = sorted(system for system, value in mark_values.items() if system != value)
    missing = sorted(system for system in scores if system not in score_values)
    numbers = {
        "systems": len(scores),
        "score_systems": len(score_values),
        "mark_systems": len(mark_values),
        "missing": len(missing),
        "tier2": len(tier2),
        "tier1": len(tier1),
        "offline_tier2": len(offline2),
        "offline_tier1": len(offline1),
        "score_diffs": len(diffs),
        "second_writer": len(second_writer),
        "diffs_outside_second_writer": len(outside),
        "max_abs_delta": max((abs(a - b) for a, b in diffs.values()), default=0),
        "flags_blocks": flags_blocks,
        "bad_mark": len(bad_mark),
    }
    if not scores or not score_values or missing:
        return INCOMPLETE, numbers, f"missing={len(missing)}"
    if set(tier2) != offline2 or set(tier1) != offline1:
        extra2 = sorted(set(tier2) ^ offline2)[:5]
        extra1 = sorted(set(tier1) ^ offline1)[:5]
        return TIER_DISAGREE, numbers, f"tier2_diff={extra2} tier1_diff={extra1}"
    if outside:
        first_bad = ",".join(f"{system}:{pair[0]}!={pair[1]}"
                             for system, pair in sorted(outside.items())[:5])
        return VALUE_DISAGREE, numbers, f"first_bad={first_bad}"
    if bad_mark:
        return VALUE_DISAGREE, numbers, f"bad_mark={bad_mark[:5]}"
    return PASS, numbers, ""


def render(verdict: str, numbers: dict, *, extra: str = "") -> str:
    """一行 `SCORE_JOIN` 回执 + 一行 `verdict=`(台帐按后者判门)。"""
    fields = " ".join(f"{key}={value}" for key, value in numbers.items())
    head = f"SCORE_JOIN {verdict} {fields}"
    if extra:
        head += f" {extra}"
    return f"{head}\nverdict={verdict}\n"


def artifact(verdict: str, numbers: dict, *, scores: dict[int, int],
             score_values, tier2, tier1, second_writer, sav_name: str,
             scores_name: str, js_log_name: str = "",
             names: dict[str, str] | None = None) -> str:
    """台帐 artifact:一段 `#meta` + 每个 id 一行(对账的原始材料)。"""
    tier2_set, tier1_set = set(tier2), set(tier1)
    lines = [f"#meta verdict={verdict}"]
    lines += [f"#meta {key}={value}" for key, value in numbers.items()]
    lines += [
        f"#meta sav={sav_name}",
        f"#meta scores={scores_name}",
    ]
    for key, value in (names or {}).items():
        lines.append(f"#meta {key}={value}")
    if js_log_name:
        lines.append(f"#meta js_log={js_log_name}")
    lines.append("id\tflag_tier2\tflag_tier1\tsave_score\toffline_score\toffline_tier\tsecond_writer")
    for system in sorted(scores):
        lines.append("\t".join([
            str(system),
            str(int(system in tier2_set)),
            str(int(system in tier1_set)),
            str(score_values.get(system, "")),
            str(scores[system]),
            tier_of(scores[system]),
            str(int(system in second_writer)),
        ]))
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sav", required=True, help="同一场的 .sav(zip)")
    parser.add_argument("--scores", required=True,
                        help="同一份存档的边算出来的 chokepoint_scores TSV")
    parser.add_argument("--js-log", default=None,
                        help="runtime 的 js 日志;它的 NEO_HUB 行标出第二个写者的 id")
    parser.add_argument("--score-var", default="neo_score", help="我们写的分数变量名")
    parser.add_argument("--mark-var", default="neo_mark", help="我们写的 id 变量名(控制组)")
    parser.add_argument("--tier2-flag", default="neo_tier2", help="官方落的高档 flag")
    parser.add_argument("--tier1-flag", default="neo_tier1", help="官方落的中档 flag")
    parser.add_argument("--out", default=None, help="把逐 id 台帐另写一份")
    args = parser.parse_args(argv)

    try:
        gamestate = read_gamestate(pathlib.Path(args.sav))
        scores = read_scores(args.scores)
        score_values = find_variables(gamestate, args.score_var)
        mark_values = find_variables(gamestate, args.mark_var)
        tier2, flags_blocks = flag_scan(gamestate, args.tier2_flag)
        tier1 = flag_scan(gamestate, args.tier1_flag)[0]
        second_writer = second_writer_ids(args.js_log)
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print(exc, file=sys.stderr)
        return 2

    verdict, numbers, detail = join(scores=scores, score_values=score_values,
                                    mark_values=mark_values, tier2=tier2, tier1=tier1,
                                    flags_blocks=flags_blocks, second_writer=second_writer)
    print(render(verdict, numbers, extra=detail), end="")
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(artifact(verdict, numbers, scores=scores,
                                  score_values=score_values, tier2=tier2, tier1=tier1,
                                  second_writer=second_writer,
                                  sav_name=pathlib.Path(args.sav).name,
                                  scores_name=pathlib.Path(args.scores).name,
                                  js_log_name=(f"{pathlib.Path(args.js_log).name} "
                                               f"sha256={_sha256(args.js_log)}"
                                               if args.js_log else ""),
                                  names={"score_var": args.score_var,
                                         "mark_var": args.mark_var,
                                         "tier2_flag": args.tier2_flag,
                                         "tier1_flag": args.tier1_flag}))
    if verdict in (TIER_DISAGREE, VALUE_DISAGREE):
        return 1
    return 0 if verdict == PASS else 2


if __name__ == "__main__":
    raise SystemExit(main())
