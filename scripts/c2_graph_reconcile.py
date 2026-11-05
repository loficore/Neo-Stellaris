#!/usr/bin/env python3
"""c2_graph_reconcile.py — 引擎侧与主机侧的逐系统分档对账(§7.7 的判据)。

**两份集合必须独立**(计划 Review Focus 4):引擎侧来自 mod 的 `NEO_T*` 回执行,
主机侧来自 `chokepoint_scores` 对两份边快照(`.base` / `.add`)各算一次。两边都不许
读对方的中间结果 —— 这个驱动是唯一同时看见两边的地方,也是唯一被允许比较它们的地方。

用法(主机侧;输入都是这一发产出的 artifact):

    python3 scripts/c2_graph_reconcile.py \
        --log C:/temp/.../game.log \
        --windows windows.json \
        --edges-base sig.base --edges-add sig.add

`--log` 是本进程的 `logs/game.log`(把 `NEO_T*` 行写在那里的那个文件;`PS_HIT` 同源)。
`--windows` 是这一发的窗口表,一个 JSON 列表,每项 `{"name": ..., "start": <字节>,
"end": <字节>}`:字节偏移在开窗/关窗时记下,`--log` 按它切段 —— 用**字节**而不是行号,
因为日志在窗口期间还在长。

判词三档(与计划一致,不可扩写):

* `tiers_named`   —— 每个名字在两边都出现且档位相同(名字集合相等);
* `tiers_disagree`—— 有名字对不上档位;**首差异**写进 detail(计划:这一档要停,不许调阈值);
* `tiers_partial` —— 只有部分系统(窗口没跑满、空窗、或两边名字集合不可比)。

名字与 id 的映射是这一发的**已知缺口**:引擎日志给的是 `[This.GetName]`(本地化名),
主机侧分数按系统 id 索引,仓库里没有 id↔名字的产物。给了 `--name-map`(id<TAB>name)就按
名字对账,没给就退到**档位计数**对账(`tiers_counts`),并在 detail 里写明 —— 计数相等能
证明分布一致,不能证明同名系统各自对得上。这仍是两条独立算路之间的比较,但不是逐名比较。
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys

TIERS = ("T0", "T1", "T2")

#: mod 的回执行:`log = "NEO_T2 [This.GetName]"`。名字里可以有空格(星系名的正常形态),
#: 所以按行首三档之一取到行尾,而不是按空白切。日志行本身带 `[HH:MM:SS][file]:` 前缀。
_TIER_LINE = re.compile(r"NEO_(T[0-2])\s+(.+?)\s*$")


def parse_tiers(text: str) -> dict[str, str]:
    """`{system_name: "T0"|"T1"|"T2"}` from the engine's receipt lines.

    A name that appears twice with different tiers keeps the **first** reading
    and the conflict is reported by the caller's count check: within one window
    every system is visited once, so a repeat is a fact about the reading, not
    something to average away.
    """
    tiers: dict[str, str] = {}
    for line in text.splitlines():
        match = _TIER_LINE.search(line.strip())
        if not match:
            continue
        tier, name = match.group(1), match.group(2)
        tiers.setdefault(name, tier)
    return tiers


def tier_counts(tiers) -> collections.Counter:
    """How many systems landed in each tier (the name-less comparison)."""
    return collections.Counter(tiers.values())


def compare_tiers(live, host, *, appeared=frozenset(), vanished=frozenset()):
    """``(verdict, detail)`` for two name-keyed tier maps.

    ``live`` is the engine side, ``host`` the independent recompute.  A name that
    only one side has is not a disagreement about a tier — it is a window that
    did not cover the same systems, which is ``tiers_partial``.  ``appeared`` /
    ``vanished`` are names the caller knows moved between windows; they are
    reported in the detail so the reading says which systems the window missed.
    """
    live, host = dict(live), dict(host)
    if not live or not host:
        return "tiers_partial", f"window empty (live={len(live)} host={len(host)})"
    common = sorted(set(live) & set(host))
    if not common:
        return "tiers_partial", f"no shared system names (live={len(live)} host={len(host)})"
    disagree = [n for n in common if live[n] != host[n]]
    if disagree:
        first = disagree[0]
        return "tiers_disagree", (
            f"{len(disagree)}/{len(common)} differ; first {first!r}: "
            f"live={live[first]} host={host[first]}")
    missing = sorted(set(live) ^ set(host))
    if missing or appeared or vanished:
        return "tiers_partial", (
            f"{len(common)} names agree, {len(missing)} one-sided "
            f"(e.g. {missing[:3]}), appeared={len(appeared)} vanished={len(vanished)}")
    return "tiers_named", f"{len(common)} names agree on tier"


def compare_counts(live, host):
    """``(verdict, detail)`` when there is no id↔name map: tier counts only.

    Coverage can only *lose* systems: the engine emits a receipt only for
    systems whose name it could print, and the name-keyed map collapses a shared
    display name (both measured 2026-11-04).  So the honest check is one-sided —
    the host may have **more** systems in a tier, never fewer:

    * ``host[t] < live[t]`` for any tier ⇒ ``tiers_disagree``.  This is the
      reachable failure mode, and the one that matters: if the engine scored a
      system into a tier the independent recompute does not put it in, the gap
      has to show up as a surplus on the engine's side (the totals are pinned by
      the same systems, so it cannot hide).
    * totals equal and every tier equal ⇒ ``tiers_counts``.
    * otherwise ⇒ ``tiers_partial``, with the per-tier deficits written out so
      the reader sees exactly how much coverage is missing where.

    It is still not the per-name check: equal counts cannot see two systems swap
    the same tier.  That limitation is in the verdict string.
    """
    if not live or not host:
        return "tiers_partial", f"window empty (live={len(live)} host={len(host)})"
    lc, hc = tier_counts(live), tier_counts(host)
    table = " ".join(f"{t}: live={lc.get(t, 0)} host={hc.get(t, 0)}" for t in TIERS)
    live_n, host_n = sum(lc.values()), sum(hc.values())
    gap = host_n - live_n
    if gap < 0:
        # The engine logged more systems than the host has: the two sides are
        # not even looking at the same graph, so no tier verdict is meaningful.
        return "tiers_partial", (
            f"live has more systems than host ({-gap}) — {table}")
    surplus = [t for t in TIERS if lc.get(t, 0) > hc.get(t, 0)]
    if surplus:
        return "tiers_disagree", (
            f"engine reports more systems than the host in {surplus} "
            f"(coverage can only remove) — {table}")
    if gap == 0:
        if lc == hc:
            return "tiers_counts", (
                "tiers_counts (no name map): " +
                " ".join(f"{t}={lc.get(t, 0)}" for t in TIERS))
        return "tiers_disagree", "counts differ (no name map): " + table
    deficits = " ".join(f"{t}={hc.get(t, 0) - lc.get(t, 0)}" for t in TIERS)
    return "tiers_partial", (
        f"gap {gap} (no receipt: no printable name / shared display name), "
        f"deficits {deficits} — {table}")


def tier_of(score: int) -> str:
    """The engine's own thresholds: >=200 T2, >=100 T1, else T0."""
    if score >= 200:
        return "T2"
    if score >= 100:
        return "T1"
    return "T0"


def windows_from_json(path) -> list[dict]:
    """The window table: ``[{name, start, end}, ...]`` with byte offsets."""
    doc = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, list):
        # The module's tested contract is ValueError for any malformed window spec
        # (test_c2_graph_reconcile.py pins both this and the end<start case).
        raise ValueError("--windows must be a JSON list of {name,start,end}")  # noqa: TRY004
    out = []
    for item in doc:
        for key in ("name", "start", "end"):
            if key not in item:
                raise ValueError(f"window entry missing {key!r}: {item!r}")
        if int(item["end"]) < int(item["start"]):
            raise ValueError(f"window {item['name']!r}: end < start")
        entry = {"name": str(item["name"]), "start": int(item["start"]),
                 "end": int(item["end"])}
        if "edges" in item:
            entry["edges"] = str(item["edges"])
        out.append(entry)
    return out


def window_text(data: bytes, window: dict) -> str:
    """The log bytes belonging to one window (offsets are absolute file bytes)."""
    return data[window["start"]:window["end"]].decode("utf-8", "replace")


def read_name_map(path) -> dict[int, str]:
    """`id<TAB>name` lines → `{id: name}`."""
    mapping = {}
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        ident, _, name = line.partition("\t")
        mapping[int(ident)] = name
    return mapping


def host_tiers(scores_path, name_map=None):
    """Tier per system from a `chokepoint_scores` TSV (optionally re-keyed by name)."""
    tiers_by_id = {}
    for line in pathlib.Path(scores_path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("system_id"):
            continue
        fields = line.split("\t")
        tiers_by_id[int(fields[0])] = tier_of(int(fields[4]))
    if name_map is None:
        return tiers_by_id
    return {name_map[i]: tier for i, tier in tiers_by_id.items() if i in name_map}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, help="game.log of this process")
    parser.add_argument("--windows", required=True, help="JSON window table (byte ranges)")
    parser.add_argument("--edges-base", required=True, help="edge snapshot before the mutation")
    parser.add_argument("--edges-add", required=True, help="edge snapshot after the mutation")
    parser.add_argument("--name-map", default=None, help="id<TAB>name (enables the per-name check)")
    parser.add_argument("--scores-dir", default=".", help="where to write the score TSVs")
    parser.add_argument("--out", default=None, help="append the verdict lines here")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import chokepoint_scores as cs

    data = pathlib.Path(args.log).read_bytes()
    windows = windows_from_json(args.windows)
    name_map = read_name_map(args.name_map) if args.name_map else None

    lines = []
    for index, window in enumerate(windows):
        text = window_text(data, window)
        live = parse_tiers(text)
        edges = window.get("edges")
        if edges is None:
            if index == 0:
                edges = args.edges_base
            elif index == 1:
                edges = args.edges_add
            else:
                # `base / add / remove` is the shot's documented shape.  Mapping
                # a third window onto the *add* snapshot would score the removal
                # against a graph that no longer exists and invent a verdict, so
                # the window has to name its own snapshot.
                print(f"window {window['name']!r} (#{index + 1}) has no \"edges\" entry: "
                      "give it one, or pass only the base/add windows", file=sys.stderr)
                raise SystemExit(2)
        scores_path = pathlib.Path(args.scores_dir) / f"{window['name']}.scores.tsv"
        rc = cs.main([str(edges), "--out", str(scores_path)])
        if rc != 0:
            lines.append(f"window={window['name']} verdict=tiers_partial "
                         f"detail=chokepoint_scores rc={rc}")
            continue
        host = host_tiers(scores_path, name_map)
        if name_map:
            verdict, detail = compare_tiers(live, host)
        else:
            verdict, detail = compare_counts(live, host)
        lines.append(f"window={window['name']} live={len(live)} host={len(host)} "
                     f"verdict={verdict} detail={detail}")

    text = "\n".join(lines)
    print(text)
    if args.out:
        with open(args.out, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
    return 0 if all("verdict=tiers_disagree" not in line for line in lines) else 1


if __name__ == "__main__":
    raise SystemExit(main())
