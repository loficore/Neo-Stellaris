#!/usr/bin/env python3
"""c2_graph_read.py — M4:在活体进程里读一发运行时星连图(只读),并与离线边表对账。

**这一发问的是什么**(偏移的唯一出处 = `evidence/analysis/runtime_444_graph_runtime.md` §1/§2):

  * `[module_base + 0x3260B98]` 那个系统索引对象在活体里是不是 §1.2 的形状
    (`+0x18` 槽表、`+0x20` 槽数、记录 16 B、指针在 `+8`);
  * 787 个系统的边容器(`+0x590` / `+0x598` / `+0x59C`,步长 `0x20`,元素 `+8` = 邻居 id)
    读出来的边集,是否与 `evidence/xrefs/c5_campaign_edges_4_4_4.tsv` **逐项相等**;
  * 同一进程里连读**两次**,两次的边集是否相等(活容器撕裂读的判据,Review Focus #3)。

**只读**:探针的唯一写路径是两个显式导出 `C5GraphMutateAdd` / `C5GraphMutateRemove`,
本驱动默认一个都不调;读一发里引擎的内存一个字节都不写。

**verdict 值域**(缺一档都不许合并;`EVIDENCE_VERDICTS` 之外的都是环境/仪器档):

  * `instrument_broken` —— layout 任一格不等 / 导出缺失 / `C5GraphRead` 返回非 0、-2、-4;
  * `graph_index_unreadable` —— `C5GraphRead == -2`(索引对象不可读/越界);
  * `window_not_playing` —— `gate_install` 拒(世界状态不是 IN_GAME_RUNNING);
  * `no_game` —— 找不到进程;
  * `host_died` —— 读完之后宿主没了(先按 AGENTS 约束 8 跑两个零游戏判别器,再谈别的);
  * `graph_live_read_unstable` —— 两次读的边集不相等(判负);
  * `graph_live_read_named` —— 两次相等、计数全中、`skipped==0`、且(给了边表时)逐项相等;
  * `graph_live_read_partial` —— 计数相等但有欠账(`skipped>0` 或 `max_id != systems-1`);
  * `graph_live_read_disagree` —— 其余(判负);
  * `graph_mutation_recompute_named` / `mutation_left_dirty` —— `--mutate` 改一条边再读两次的
    两个结局(加删都落且回原样 / 有一步没落或没回原样);
  * `graph_collision_named` / `graph_collision_suspicious` —— `--mutate-collide`:加与删之间
    **不夹读**,所以指纹回到原值;哈希也相等 ⇒ 图真的原样(named),指纹相等但哈希不等 ⇒
    这正是旧缓存路径会漏的那一格(issue #46;suspicious)。
  * `graph_rewire_detected` / `graph_rewire_missed` / `graph_rewire_invisible` / `no_pulse` /
    `no_switch_available` / `restore_dirty` —— `--rewire`:**保度** 2-switch(删 (a,b)/(c,d)、
    加 (a,c)/(b,d),四点度逐个不变 ⇒ 指纹不变而边集变)。detected = 指纹相同、哈希变了、
    求值涨了、重算 >= 1、且恢复回到 base;missed = 除重算外的条件都成立(recomputed 增量 0,
    这正是 #46 的那一格);invisible = 哈希也没变(switch 没落地);no_pulse = 求值没涨
    (没脉冲,不是「没重算」);no_switch_available = 边表里找不到保度重连;restore_dirty =
    有一步 rc 非 0 或恢复后哈希没回到 base(停下来,别再调导出)。

**判定口径的两处注记**(裁定见 SDD ledger):

  1. `classify` 不重数行数 —— 行数是否等于 `stats.edges` 由驱动用 `rows_complete` 传进来。
     这样判词函数只回答「这组读数一致吗」,不回答「你搬全了吗」。
  2. `--poll-s` 是读之前的**静置**秒数,不是轮询窗口:判据要求「连读两次」,拿轮询去等
     图安定会把撕裂读掩掉。

**`--attach`**:挂到**已经在跑的**那一份模块(通常是 `c2_boot_inject.py` 注进去的),只解析基址 +
验头 + 验 `C2Sanity`,不 `gate_install`、不注入。理由不是「省一步」:live 缓存是模块级静态量,
二次注入得到的是另一份模块、缓存为 0(`fingerprint==0`),读出来像「没重算」—— 那是仪器口径。
它与 `--mutate` / `--mutate-collide` / `--rewire` 不冲突:它只回答「注不注入」。

判读纯函数由 `python3 -m pytest scripts/test_c2_graph_read.py -q` 覆盖:无游戏、无 Windows API。
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys

# --- wire contract (the DLL's own constants; drift = a red fence) -----------------

LAYOUT_VERSION = 1
LAYOUT_WORDS = 8
STATS_SIZE = 64
MAX_EDGES = 4096                    # graph_probe.MAX_EDGES
DRAIN_BYTES = MAX_EDGES * 4         # the export declares a 16,384 B slice — allocate all of it
RVA_SYSTEM_INDEX_GLOBAL = 0x3260B98  # offsets.graph.RVA_SYSTEM_INDEX_GLOBAL (§1.2)
INDEX_TABLE_OFF = 0x18             # §1.2
INDEX_BOUND_OFF = 0x20             # §1.2
TABLE_RECORD_SIZE = 16             # §1.11 (the `add rcx,rcx` that doubles the stride)
TABLE_SLOT_PTR_OFF = 8             # §1.11
EDGE_COUNT_OFF = 0x59C             # §1.3
EDGE_STRIDE = 0x20                 # §1.3

EXPECTED_LAYOUT = (
    LAYOUT_VERSION,
    RVA_SYSTEM_INDEX_GLOBAL,
    INDEX_TABLE_OFF,
    INDEX_BOUND_OFF,
    TABLE_RECORD_SIZE,
    TABLE_SLOT_PTR_OFF,
    EDGE_COUNT_OFF,
    EDGE_STRIDE,
)

REQUIRED_EXPORTS = (
    "C5GraphRead",
    "C5GraphLayout",
    "C5GraphStatsInto",
    "C5GraphDrainInto",
    "C5GraphReset",
    "C5GraphMutateAdd",
    "C5GraphMutateRemove",
)

#: `--mutate-collide` additionally reads the live source's cache keys.  They are checked
#: only in that branch: a plain graph read must not start refusing because an older DLL
#: predates the live-source exports.
COLLIDE_EXPORTS = ("C2NeoLiveStatsInto", "C2NeoLiveHashInto")
LIVE_STATS_SIZE = 64          # C2NeoLiveStatsInto: u64 x 8 (fingerprint is word 7)
LIVE_HASH_SIZE = 16           # C2NeoLiveHashInto: [hash u64][edges u64]
VERIFY_STATS_SIZE = 16        # C2NeoVerifyStatsInto: [verified u64][verify_failed u64]

#: `--rewire` 还需要核对计数(等的就是「核对跑过一次」),所以比 collide 多一个导出。
REWIRE_EXPORTS = (*COLLIDE_EXPORTS, "C2NeoVerifyStatsInto")

#: `#meta` 的固定键序 —— artifact 是给人读的,顺序固定才 diff 得动。
META_ORDER = (
    "overall_verdict",
    "expect_systems",
    "expect_edges",
    "save_name",
    "dll",
    "dll_sha256",
    "module_base",
    "index_ptr",
    "table_ptr",
    "bound",
    "systems",
    "edges",
    "skipped",
    "max_id",
    "read2_edges",
    "layout",
    "host_alive",
)

VERDICTS = (
    "instrument_broken",
    "graph_index_unreadable",
    "window_not_playing",
    "no_game",
    "host_died",
    "graph_live_read_unstable",
    "graph_live_read_named",
    "graph_live_read_partial",
    "graph_live_read_disagree",
    "graph_mutation_recompute_named",
    "mutation_left_dirty",
    "graph_collision_named",
    "graph_collision_suspicious",
    "graph_rewire_detected",
    "graph_rewire_missed",
    "graph_rewire_invisible",
    "no_pulse",
    "no_switch_available",
    "restore_dirty",
)
EVIDENCE_VERDICTS = (
    "graph_live_read_unstable",
    "graph_live_read_named",
    "graph_live_read_partial",
    "graph_live_read_disagree",
    "graph_mutation_recompute_named",
    "mutation_left_dirty",
    "graph_collision_named",
    "graph_collision_suspicious",
    "graph_rewire_detected",
    "graph_rewire_missed",
    "restore_dirty",
)

EXIT_REFUSED = 2        # pre-flight / environment gate refusal (same code as `gate_install`)
EXIT_HOST_DEAD = 3      # the pid did not survive the shot


# --- parsing ----------------------------------------------------------------------


def parse_stats(blob):
    """The 64 B `C5GraphStatsInto` payload as a dict.

    Eight little-endian u64: `systems, edges, skipped, max_id, index_ptr, table_ptr,
    bound, module_base`. `max_id` is `None` when the probe wrote `u64` max (no system
    admitted) — 0 is a *legal* system id and must not be spent as a sentinel.
    """
    if len(blob) < STATS_SIZE:
        raise ValueError(f"stats payload is {len(blob)} B, expected {STATS_SIZE}")
    words = struct.unpack("<8Q", blob[:STATS_SIZE])
    return {
        "systems": words[0],
        "edges": words[1],
        "skipped": words[2],
        "max_id": None if words[3] == 0xFFFF_FFFF_FFFF_FFFF else words[3],
        "index_ptr": words[4],
        "table_ptr": words[5],
        "bound": words[6],
        "module_base": words[7],
    }


def parse_layout(words):
    """The eight layout words -> tuple. Kept separate so the fence can compare tuples."""
    return tuple(int(word) & 0xFFFF_FFFF for word in words)


def layout_mismatch(words):
    """`None` when the probe's layout is ours, otherwise a human-readable diff."""
    got = parse_layout(words)
    if got == EXPECTED_LAYOUT:
        return None
    diffs = [
        f"word[{i}]={got[i]:#x}!={want:#x}"
        for i, want in enumerate(EXPECTED_LAYOUT)
        if i >= len(got) or got[i] != want
    ]
    if len(got) != LAYOUT_WORDS:
        diffs.append(f"words={len(got)}!={LAYOUT_WORDS}")
    return "layout " + " ".join(diffs)


def parse_artifact(text):
    """`(meta, rows)` from an artifact: `#meta k=v` lines, then `a<TAB>b` rows.

    A row that is not exactly two integers is dropped, not guessed — the artifact is a
    reading, and a malformed row means the thing that wrote it was broken.
    """
    meta, rows = {}, []
    for line in text.splitlines():
        if line.startswith("#meta "):
            key, _, value = line[len("#meta "):].partition("=")
            meta[key] = value
            continue
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        try:
            rows.append((int(parts[0]), int(parts[1])))
        except ValueError:
            continue
    return meta, rows


def read_edge_table(path):
    """`a<TAB>b<TAB>length` (no header) -> set of ordered `(a, b)` pairs."""
    out = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            out.add((int(parts[0]), int(parts[1])))
    return out


# --- judgement --------------------------------------------------------------------


def first_difference(rows, expected):
    """Name the first pair that is in one set and not the other (sorted, deterministic)."""
    have, want = set(rows), set(expected)
    for pair in sorted(have - want)[:1]:
        return f"{pair} in read1 only"
    for pair in sorted(want - have)[:1]:
        return f"{pair} in the edge table only"
    return None


def classify(stats, rows, expected, layout_words, env, again=None, rows_complete=True):
    """`(verdict, detail)` for one shot.

    `env` carries the things that are not statistics: `rc` (the `C5GraphRead` code),
    `gate` (`"world_state"` / `"refused"`), `no_game`, `exports_ok`/`missing`,
    `alive`, and the two expectations the shot was fired with (`expect_systems`,
    `expect_edges`). `again` is the second read's rows — comparing the two is the whole
    point of reading twice (Review Focus #3: the container is live data).
    """
    if env.get("no_game"):
        return "no_game", "stellaris.exe is not running"
    if env.get("gate") == "refused":
        return "window_not_playing", "gate_install refused: not IN_GAME_RUNNING"
    if not env.get("exports_ok", True):
        missing = ", ".join(env.get("missing") or ())
        return "instrument_broken", f"DLL is missing exports: {missing}"

    mismatch = layout_mismatch(layout_words)
    if mismatch:
        return "instrument_broken", mismatch

    rc = env.get("rc")
    if rc == -2:
        return "graph_index_unreadable", "C5GraphRead == -2 (index object unreadable)"
    if rc not in (0, -4):
        return "instrument_broken", f"C5GraphRead == {rc}"
    if not env.get("alive", True):
        return "host_died", "the game process did not survive the shot"

    if again is not None and set(map(tuple, again)) != set(map(tuple, rows)):
        diff = first_difference(rows, again)
        return "graph_live_read_unstable", (
            f"read1={len(rows)} read2={len(again)} edges differ: {diff}"
        )

    if not rows_complete:
        return "graph_live_read_disagree", f"rows={len(rows)} != stats edges={stats['edges']}"

    counters_ok = (
        stats["systems"] == env.get("expect_systems")
        and stats["edges"] == env.get("expect_edges")
    )
    table_ok = True if expected is None else set(map(tuple, rows)) == set(map(tuple, expected))
    dense = stats["max_id"] == (stats["systems"] - 1 if stats["systems"] else None)
    clean = stats["skipped"] == 0 and dense

    if counters_ok and table_ok and clean:
        return "graph_live_read_named", (
            f"systems={stats['systems']} edges={stats['edges']} "
            f"max_id={stats['max_id']} two reads agree"
        )

    if counters_ok and not clean:
        debt = []
        if stats["skipped"]:
            debt.append(f"skipped={stats['skipped']}")
        if not dense:
            debt.append(f"max_id={stats['max_id']}!={stats['systems'] - 1}")
        return "graph_live_read_partial", "counts match, debt: " + ", ".join(debt)

    observed = f"systems={stats['systems']} edges={stats['edges']}"
    detail = (f"{observed} vs expect systems={env.get('expect_systems')} "
              f"edges={env.get('expect_edges')}")
    diff = first_difference(rows, expected) if expected is not None else None
    if diff:
        detail += f"; {diff}"
    return "graph_live_read_disagree", detail


def classify_mutation(seq, x, y, base_rows, added_rows, removed_rows=None):
    """`(verdict, detail)` for the `--mutate` shot's three snapshots.

    `seq` = `[base, after_add, after_remove]`. Each entry carries `edges` and `rc`:
    for the base step `rc` is the **read** code, for the other two it is the code the
    mutation export returned (and, when a read followed, `read_rc` is that read's code).

    The acceptance is deliberately narrow: the add must land **exactly** one edge, and it
    must be *this* pair; the remove must put the edge count back **and** the set back.
    Anything else is `mutation_left_dirty` and names the step that failed — Review Focus #5
    says stop, do not try to "repair" the graph and carry on.
    """
    pair = (min(x, y), max(x, y))
    base, after_add, after_remove = seq

    if base.get("rc", 0) not in (0, -4):
        return "mutation_left_dirty", f"base step: C5GraphRead == {base['rc']} — nothing to mutate"
    if after_add.get("rc", 0) != 0:
        return "mutation_left_dirty", f"add step: C5GraphMutateAdd == {after_add['rc']}"
    if after_add.get("read_rc", 0) not in (0, -4):
        return "mutation_left_dirty", f"add step: the post-add read == {after_add['read_rc']}"
    if after_add["edges"] != base["edges"] + 1:
        return "mutation_left_dirty", (
            f"add step: edges {base['edges']} -> {after_add['edges']} (expected +1)"
        )
    if pair not in set(map(tuple, added_rows)):
        return "mutation_left_dirty", f"add step: {pair} is not in the post-add edge set"

    if after_remove.get("rc", 0) != 0:
        return "mutation_left_dirty", f"remove step: C5GraphMutateRemove == {after_remove['rc']}"
    if after_remove.get("read_rc", 0) not in (0, -4):
        return "mutation_left_dirty", f"remove step: the post-remove read == {after_remove['read_rc']}"
    if after_remove["edges"] != base["edges"]:
        return "mutation_left_dirty", (
            f"remove step: edges {after_remove['edges']} != base {base['edges']}"
        )
    if removed_rows is not None and set(map(tuple, removed_rows)) != set(map(tuple, base_rows)):
        return "mutation_left_dirty", "remove step: the edge set is not the base set"

    return "graph_mutation_recompute_named", (
        f"{pair}: {base['edges']} -> {after_add['edges']} -> {after_remove['edges']}"
    )


def collide_steps(from_id, to_id):
    """The `--mutate-collide` step list: add and remove are **adjacent**.

    The point of this shot is the window the fingerprint cannot see: add one edge and
    remove it again before anything reads the graph, so the per-slot degree counts (and
    therefore the fingerprint) are back to their base value while the engine's neighbour
    lists have been rewritten.  Inserting a read between add and remove would let the
    fingerprint (and the hash) observe the intermediate state and destroy the fixture.

    `from_id`/`to_id` are part of the signature so the caller's intent is explicit; the
    step names do not depend on them (the pair lives in the artifact's `#meta`).
    """
    _ = (from_id, to_id)
    return ["base", "add", "remove", "collide_read"]


def classify_collision(*, base_fingerprint, collide_fingerprint, base_hash, collide_hash):
    """The `--mutate-collide` verdict (a member of ``VERDICTS``).

    ``0`` is the "this process has not completed a read yet" sentinel for both the
    fingerprint and the edge hash, so any zero here means the premise of the shot is
    missing — that is an instrument reading, never a collision.

    A fingerprint that did not come back to its base value means the add/remove pair did
    not cancel (or the graph changed underneath us); the shot no longer exercises the
    blind spot, so it is also an instrument reading rather than a verdict about caching.

    The two real outcomes:
      * hashes equal too  -> ``graph_collision_named``: the picture really is identical;
      * fingerprint equal but hash differs -> ``graph_collision_suspicious``: this is the
        exact case the old fingerprint-only cache would reuse a stale score for (#46).
    """
    if base_fingerprint == 0 or collide_fingerprint == 0 or base_hash == 0 or collide_hash == 0:
        return "instrument_broken"
    if base_fingerprint != collide_fingerprint:
        return "instrument_broken"
    if base_hash == collide_hash:
        return "graph_collision_named"
    return "graph_collision_suspicious"


def choose_switch(edges):
    """`(a, b, c, d)` 或 `None`:保度的 2-switch(删 `(a,b)`/`(c,d)`,加 `(a,c)`/`(b,d)`)。

    为什么要**保度**而不是随便删加两条:`neo_score` 的缓存键是按槽号加权的容器指纹
    (每个系统 `+0x59C` 的 dword 和)。删一条再加一条会改两端点的度数 ⇒ 指纹也变 ⇒
    「变了就重算」这条路必然重算,证明不了 #46 的漏格。只有四点度数**逐个不变**,
    才构造得出「指纹相同、图不同」的那一格 —— 那一格里只有边集哈希能看见差别。

    遍历顺序固定(排序后的边表上字典序枚举 `e1` < `e2`,先试 `(a,c)+(b,d)` 再试
    `(a,d)+(b,c)`),所以同一个边集永远给同一个解:读数可复现,不靠随机。
    返回的顺序保证 `(a,b)`、`(c,d)` 是现有边而 `(a,c)`、`(b,d)` 不是 —— 第二种配对
    可行时把 `c`/`d` 对调再返回,让这四条判据仍然成立。
    """
    table = sorted({(min(a, b), max(a, b)) for a, b in edges if a != b})
    present = set(table)
    for i, (a, b) in enumerate(table):
        for c, d in table[i + 1:]:
            if len({a, b, c, d}) != 4:
                continue          # 两条边共用端点 ⇒ 换哪种配对都会造出自环或重边
            for x, y in (((a, c), (b, d)), ((a, d), (b, c))):
                if (min(x), max(x)) in present or (min(y), max(y)) in present:
                    continue
                return (a, b, c, d) if x == (a, c) else (a, b, d, c)
    return None


def rewire_steps():
    """`--rewire` 的步骤名。四个改边步骤之间**不许**夹读:夹读会让指纹/哈希看见中间态。"""
    return ["base", "remove_ab", "remove_cd", "add_ac", "add_bd", "rewire_read"]


def classify_rewire(*, base_fingerprint, rewire_fingerprint, base_hash, rewire_hash,
                    evaluated_delta, recomputed_delta, restore_ok):
    """`--rewire` 的判词。判负顺序是固定的,先说的那句负责把读者导向正确的下一步。

    1. `instrument_broken` —— 任一指纹/哈希为 `0`(`0` = 本进程还没成功读过图);
    2. `no_pulse` —— `evaluated_delta == 0`:引擎这段时间**没求值**,所以「没重算」这句话
       根本没有被测过。先解暂停/换窗口,不是判负;
    3. `restore_dirty` —— 恢复没回到 base:先停手(图上还留着我们的改动);
    4. `graph_rewire_invisible` —— 哈希没变:switch 没落地(`(a,c)`/`(b,d)` 本来就存在,
       或有一步静默失败),这是仪器档;
    5. `graph_rewire_missed` —— 指纹相同、哈希变了、求值涨了,但 `recomputed_delta == 0`:
       **这就是 #46 的那一格**,旧缓存拿旧分数复用;
    6. `graph_rewire_detected` —— 上面都通过且 `recomputed_delta >= 1`。
    """
    if base_fingerprint == 0 or rewire_fingerprint == 0 or base_hash == 0 or rewire_hash == 0:
        return "instrument_broken"
    if evaluated_delta == 0:
        return "no_pulse"
    if not restore_ok:
        return "restore_dirty"
    if base_hash == rewire_hash:
        return "graph_rewire_invisible"
    if recomputed_delta == 0:
        return "graph_rewire_missed"
    return "graph_rewire_detected"


# --- artifact ---------------------------------------------------------------------


def build_meta(values):
    """`k=v` lines in `META_ORDER`, then any extra key sorted (a shot may add readings)."""
    lines = [f"{key}={values[key]}" for key in META_ORDER if key in values]
    lines.extend(f"{key}={values[key]}" for key in sorted(values) if key not in META_ORDER)
    return lines


def read2_meta(stats2, rc2):
    """The `read2_*` keys, or `{}` when the shot had no second read.

    The mutation shot reads three times (base / after add / after remove) — none of them
    is "read2", and emitting a duplicate of the base under that name would make the
    artifact claim a second read that never happened. Absent keys are the honest shape.
    """
    if stats2 is None:
        return {}
    return {
        "read2_edges": stats2["edges"],
        "read2_rc": rc2,
        "read2_systems": stats2["systems"],
        "read2_skipped": stats2["skipped"],
    }


def format_layout(words):
    return ",".join(f"{word:#x}" for word in parse_layout(words))


def write_artifact(path, meta_lines, rows):
    """Meta first, then rows: the artifact is what survives a lost stdout."""
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.writelines(f"#meta {line}\n" for line in meta_lines)
        handle.writelines(f"{a}\t{b}\n" for a, b in rows)


def write_edge_snapshots(out_path, base_rows, add_rows, remove_rows):
    """`<out>.base` / `.add` / `.remove`: three edge tables for the host-side recompute.

    Three columns (`a`, `b`, `1`): the third is a **placeholder** — the read path gives
    ids only, and the host-side metric is unweighted (Brandes over an undirected
    unweighted graph). Keeping the column makes `chokepoint_scores._read_edges` usable
    verbatim, which is what §5's recompute snippet calls.
    """
    for suffix, rows in (("base", base_rows), ("add", add_rows), ("remove", remove_rows)):
        with open(f"{out_path}.{suffix}", "w", encoding="utf-8", newline="\n") as handle:
            handle.writelines(f"{a}\t{b}\t1\n" for a, b in rows)


def kill_game(pid):
    """Kill the session rather than saving or parking it (the plan's cleanup rule)."""
    import subprocess

    # check=False: taskkill may fail because the process is already gone; the rc is printed.
    result = subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                            capture_output=True, text=True, check=False)
    print(f"[graph] taskkill /F /PID {pid} rc={result.returncode} — session not saved")


# --- pre-fire gates ---------------------------------------------------------------


def sha_gate(path):
    """The sha256 of the file we are about to inject. Missing = refuse (exit 2)."""
    if not os.path.exists(path):
        raise SystemExit(EXIT_REFUSED)
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def preflight_paths(dll_path, edges_file=None):
    """Refuse before the shot costs a window: the DLL, and the table we reconcile with."""
    if not dll_path or not os.path.exists(dll_path):
        print(f"[graph] DLL not found: {dll_path}", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)
    if edges_file and not os.path.exists(edges_file):
        print(f"[graph] edge table not found: {edges_file}", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)


def refuse_if_resident(dll_name, base):
    """A same-name module already mapped means the loader reuses the old image."""
    if base:
        print(f"[graph] {dll_name} is already resident at 0x{base:x} — use a fresh name",
              file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)


def decide_injection(*, attach, resident):
    """三分支:``"attach"`` 挂已有模块 / ``"inject"`` 注一份新的 / ``"refuse"`` 前提不成立。

    为什么要有 `attach` 这一支:`neo_score` 的 live 缓存是**模块级静态量**。二次注入拿到的是
    另一份模块、缓存为 0(`fingerprint==0` ⇒ `instrument_broken`),读起来像「没重算」——
    那是仪器口径,不是 #46 的证据(Review Focus #1)。所以「我要读那份已经跑出计数来的模块」
    必须是一条和「注入」互斥的路,而不是注入之后碰运气。

    两个输入都是既有事实:`attach` 是操作者的意图,`resident` 是同名模块此刻是否已映射。
    非 attach 且已映射仍然是 `refuse` —— 那是 `refuse_if_resident` 的老口径:同名重注会
    让加载器复用旧映像,注入这一步等于没发生。
    """
    # 写成两个「resident 优先」的分支而不是嵌套:这是纯函数,四格必须是四条独立的输出。
    if resident:
        return "attach" if attach else "refuse"
    return "refuse" if attach else "inject"


def _resident_base(pid, dll_name):
    """Already-mapped base, or `None`. `resolve_base_address` raises when absent."""
    import c2_harness as harness

    try:
        return harness.resolve_base_address(pid, dll_name)
    except RuntimeError:
        return None


def _signed32(value):
    value &= 0xFFFF_FFFF
    return value - 0x1_0000_0000 if value & 0x8000_0000 else value


# --- live path (Windows only; not exercised by the host tests) ---------------------


def gate_and_inject(pid, dll_path, allow_window=False, required_extra=(), attach=False):
    """Seven exports in the FILE → refuse-if-resident → gate → inject → sanity.

    The gate call must stay **before** `inject_dll` in this scope: `scripts/
    test_scripts_layout.py`'s R-inject fence reads exactly that ordering, and a shot
    that injects first has already spent the premise when it finds out.

    `required_extra` lets a branch add exports (the collide shot needs the live cache
    keys) without weakening the plain graph read's pre-flight.

    `attach=True` 是另一条前置:模块必须**已经在**同一个 pid 里(通常是 `c2_boot_inject.py`
    注进去、已经跑出计数的那个),这一支只解析基址 + 验头 + 验 `C2Sanity`,**不**再走
    `gate_install`,也**不**注入 —— 见 `decide_injection` 的理由。
    """
    import c2_harness as harness

    exports = harness.list_exports(dll_path)
    needed = REQUIRED_EXPORTS + tuple(required_extra)
    missing = [name for name in needed if name not in exports]
    if missing:
        print(f"[graph] {dll_path} is missing {missing} — refusing to inject", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)

    dll_name = os.path.basename(dll_path.replace("\\", "/"))
    print(f"[graph] pid={pid} dll={dll_path}")

    resident = _resident_base(pid, dll_name)
    decision = decide_injection(attach=attach, resident=resident is not None)
    if decision == "refuse":
        # 两条 message 分开:attach 拒装是「没有可挂的模块」,非 attach 拒装是「同名已映射」。
        refuse_if_resident(dll_name, resident)
        print(f"[graph] attach: {dll_name} is not resident in pid {pid} — refusing "
              "(attach never injects)", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)

    if attach:
        # 这一支只读地认领已有的那一份:同名的 loader 映像 + 它自己的 live 缓存。
        base = resident
        print(f"[graph] attach: {dll_name} resident at 0x{base:x} — no injection")
    else:
        if allow_window:
            print("[graph] gate skipped by operator override (--allow-window)")
        else:
            from world_probe import gate_install  # pyright: ignore[reportMissingImports]

            gate_install("graphread")

        harness.inject_dll(pid, dll_path)
        harness.assert_game_alive(pid)
        base = harness.resolve_base_address(pid, dll_name)
        print(f"[graph] {dll_name} base: 0x{base:x}")

    head = harness.read_memory(pid, base, 2)
    assert head == b"MZ", f"bad header at 0x{base:x}: {head!r}"
    sanity = _signed32(harness.call_remote(pid, base, exports["C2Sanity"]))
    assert sanity == 42, f"C2Sanity returned {sanity}, expected 42"
    harness.assert_game_alive(pid)
    print("[graph] C2Sanity == 42, game alive — read authorized")
    return base, exports


def read_once(pid, base, exports, stats_buf, drain_buf):
    """One `Reset → Read → StatsInto → DrainInto` cycle -> `(rc, stats, rows)`."""
    import c2_harness as harness

    harness.call_remote(pid, base, exports["C5GraphReset"])
    rc = _signed32(harness.call_remote(pid, base, exports["C5GraphRead"]))
    harness.call_remote_with_arg(pid, base, exports["C5GraphStatsInto"], stats_buf)
    stats = parse_stats(harness.read_memory(pid, stats_buf, STATS_SIZE))

    rows = []
    if rc in (0, -4):
        # The export declares a MAX_EDGES*4 slice, so the buffer is allocated whole
        # (DRAIN_BYTES) — never a tight `edges*4`, or the short-buffer gate is noise.
        count = harness.call_remote_with_arg(pid, base, exports["C5GraphDrainInto"], drain_buf)
        count = min(count & 0xFFFF_FFFF, MAX_EDGES)
        if count:
            blob = harness.read_memory(pid, drain_buf, count * 4)
            rows = [struct.unpack_from("<HH", blob, i * 4) for i in range(count)]
    return rc, stats, rows


def read_live_pair(pid, base, exports, stats_buf, hash_buf):
    """`(fingerprint, edge_hash)` from the live source's own cache keys.

    The collision fixture is about the *cache decision*, so it must compare what the
    cache compares: `C2NeoLiveStatsInto` word 7 (the per-slot weighted fingerprint) and
    `C2NeoLiveHashInto` word 0 (the sorted edge-set hash).  `0` in either is the
    "never read" sentinel — `classify_collision` treats it as an instrument reading.
    """
    import c2_harness as harness

    harness.call_remote_with_arg(pid, base, exports["C2NeoLiveStatsInto"], stats_buf)
    words = struct.unpack("<8Q", harness.read_memory(pid, stats_buf, LIVE_STATS_SIZE))
    fingerprint = words[7]

    harness.call_remote_with_arg(pid, base, exports["C2NeoLiveHashInto"], hash_buf)
    hash64, _edges = struct.unpack("<QQ", harness.read_memory(pid, hash_buf, LIVE_HASH_SIZE), 0)
    return fingerprint, hash64


def read_live_all(pid, base, exports, live_stats_buf, live_hash_buf, live_verify_buf):
    """三份 live 计数一次读全 —— 判词要的指纹/哈希/增量必须出自**同一次**核对。

    键与 DLL 侧的契约一一对应(见 `src/dll/exports.zig`):
    `C2NeoLiveStatsInto` 8 词、`C2NeoLiveHashInto` 2 词、`C2NeoVerifyStatsInto` 2 词。
    """
    words = struct.unpack("<8Q", _read_export(
        pid, base, exports["C2NeoLiveStatsInto"], live_stats_buf, LIVE_STATS_SIZE))
    hash64, _edges = struct.unpack("<QQ", _read_export(
        pid, base, exports["C2NeoLiveHashInto"], live_hash_buf, LIVE_HASH_SIZE), 0)
    verified, verify_failed = struct.unpack("<QQ", _read_export(
        pid, base, exports["C2NeoVerifyStatsInto"], live_verify_buf, VERIFY_STATS_SIZE), 0)
    return {
        "fingerprint": words[7],
        "hash": hash64,
        "evaluated": words[0],
        "recomputed": words[1],
        "cached_hits": words[2],
        "verified": verified,
        "verify_failed": verify_failed,
    }


def rewire_shot(pid, base, exports, stats_buf, drain_buf, live_bufs, switch,
                base_stats, base_rc):
    """保度 2-switch 的一发(不含 base 读):四次改边 → rewire 读 → 四次恢复 → 恢复读。

    返回 `(verdict, detail, step_lines, readings)`。`readings` 是判词用到的全部数字,
    由 `run` 原样写进 artifact —— 读数与判词必须出自同一趟(Review Focus #3)。

    任何一步 rc 非 0 都记进 `step_lines`;正向没走完就**不**读 rewire(读到的中间态既不是
    base 也不是 rewire),但恢复的四个动作**一律尝试完**(Review Focus #4:半恢复的图
    比没改过的图危险得多)。
    """
    import c2_harness as harness

    a, b, c, d = switch
    steps = rewire_steps()
    bufs = tuple(live_bufs)

    step_lines = [f"step={steps[0]} edges={base_stats['edges']} rc={base_rc}"]
    before = read_live_all(pid, base, exports, *bufs)
    step_lines.append(
        f"live_before fingerprint={before['fingerprint']} hash={before['hash']:016x} "
        f"evaluated={before['evaluated']} recomputed={before['recomputed']} "
        f"verified={before['verified']}")

    forward = ((steps[1], "C5GraphMutateRemove", a, b),
               (steps[2], "C5GraphMutateRemove", c, d),
               (steps[3], "C5GraphMutateAdd", a, c),
               (steps[4], "C5GraphMutateAdd", b, d))
    restore = ((f"restore_remove_{a}_{c}", "C5GraphMutateRemove", a, c),
               (f"restore_remove_{b}_{d}", "C5GraphMutateRemove", b, d),
               (f"restore_add_{a}_{b}", "C5GraphMutateAdd", a, b),
               (f"restore_add_{c}_{d}", "C5GraphMutateAdd", c, d))

    step_error = ""
    for name, export, x, y in forward:
        rc = _signed32(harness.call_remote_with_arg(pid, base, exports[export],
                                                    _pack_pair(x, y)))
        step_lines.append(f"step={name} {x}-{y} rc={rc}")
        if rc != 0:
            step_error = f"{name} rc={rc}"
            break

    after, read_rc = before, None
    if not step_error:
        read_rc, stats_rewire, _rows = read_once(pid, base, exports, stats_buf, drain_buf)
        step_lines.append(f"step={steps[5]} edges={stats_rewire['edges']} rc={read_rc}")
        after = read_live_all(pid, base, exports, *bufs)
        step_lines.append(
            f"live_after fingerprint={after['fingerprint']} hash={after['hash']:016x} "
            f"evaluated={after['evaluated']} recomputed={after['recomputed']} "
            f"verified={after['verified']}")

    for name, export, x, y in restore:
        rc = _signed32(harness.call_remote_with_arg(pid, base, exports[export],
                                                    _pack_pair(x, y)))
        step_lines.append(f"step={name} {x}-{y} rc={rc}")
        if rc != 0 and not step_error:
            step_error = f"{name} rc={rc}"

    restore_rc, restore_stats, _rows = read_once(pid, base, exports, stats_buf, drain_buf)
    restored = read_live_all(pid, base, exports, *bufs)
    step_lines.append(f"step=restore_read edges={restore_stats['edges']} rc={restore_rc}")
    step_lines.append(f"live_restore fingerprint={restored['fingerprint']} "
                      f"hash={restored['hash']:016x}")

    restore_ok = (not step_error
                  and restore_rc in (0, -4)
                  and restore_stats["edges"] == base_stats["edges"]
                  and restored["hash"] == before["hash"])

    evaluated_delta = max(0, after["evaluated"] - before["evaluated"])
    recomputed_delta = max(0, after["recomputed"] - before["recomputed"])
    verify_delta = max(0, restored["verified"] - before["verified"])

    if step_error:
        # 夹具自己的故障先于任何缓存判读(RF#4:任何一步 rc 非 0 立即判脏并停手)。
        # 不交给 `classify_rewire`:那里 `no_pulse` 排在 `restore_dirty` 前面,
        # 而「我们没取到数」不该盖过「图上还留着我们的改动」。
        verdict = "restore_dirty"
        detail = f"{step_error}; restore_ok={int(restore_ok)} — 停手,别再调导出"
    else:
        verdict = classify_rewire(
            base_fingerprint=before["fingerprint"], rewire_fingerprint=after["fingerprint"],
            base_hash=before["hash"], rewire_hash=after["hash"],
            evaluated_delta=evaluated_delta, recomputed_delta=recomputed_delta,
            restore_ok=restore_ok)
        detail = (f"switch {a}-{b}/{c}-{d}: fingerprint {before['fingerprint']} -> "
                  f"{after['fingerprint']}; hash {before['hash']:016x} -> "
                  f"{after['hash']:016x}; evaluated +{evaluated_delta}, "
                  f"recomputed +{recomputed_delta}, verified +{verify_delta}; "
                  f"restore_ok={int(restore_ok)} (hash {restored['hash']:016x})")

    readings = {
        "step": "rewire",
        "switch": f"{a}-{b}-{c}-{d}",
        "base_fingerprint": before["fingerprint"],
        "rewire_fingerprint": after["fingerprint"],
        "base_hash": f"{before['hash']:016x}",
        "rewire_hash": f"{after['hash']:016x}",
        "restore_hash": f"{restored['hash']:016x}",
        "evaluated_delta": evaluated_delta,
        "recomputed_delta": recomputed_delta,
        "verify_delta": verify_delta,
        "restore_ok": int(restore_ok),
        "rewire_steps": "|".join(step_lines),
    }
    return verdict, detail, step_lines, readings


def _pack_pair(x, y):
    """`(from, to)` -> 一个 u64(低 32 = from、高 32 = to):`CreateRemoteThread` 只给一个寄存器。"""
    return (x << 32) | (y & 0xFFFF_FFFF)


def _read_export(pid, base, rva, buf, size):
    """调用一个 `Into` 导出再读回它写进 `buf` 的 `size` 字节。"""
    import c2_harness as harness

    harness.call_remote_with_arg(pid, base, rva, buf)
    return harness.read_memory(pid, buf, size)


def run(dll_path, out_path, *, expect_systems, expect_edges, save_name, edges_file=None,
        allow_window=False, settle_s=0.0, mutate=None, mutate_collide=None,
        rewire=None, kill_after=False, attach=False):
    """One shot in one game process. No hook is installed and nothing is unloaded.

    `mutate=(x, y)` switches the shot to the three-snapshot form: Read (base) →
    MutateAdd → Read → MutateRemove → Read, and every step goes into `#meta`.

    `mutate_collide=(x, y)` is the four-step form Read → MutateAdd → MutateRemove →
    Read: no read between add and remove, so the fingerprint must come back to its base
    value and only the edge-set hash can tell whether the picture was rewired.

    `rewire="auto"` 或 `rewire=(a, b, c, d)` 是**保度** 2-switch:删 `(a,b)`/`(c,d)`、
    加 `(a,c)`/`(b,d)`。这是 #46 的真夹具 —— 四点度逐个不变 ⇒ 指纹不变、边集变。
    `"auto"` 从 base 读到的边里确定性选第一个可行解(`choose_switch`)。
    """
    import time

    import c2_harness as harness

    preflight_paths(dll_path, edges_file)
    dll_sha = sha_gate(dll_path)
    print(f"[graph] dll={dll_path} sha256={dll_sha}")

    try:
        pid = harness.resolve_pid("stellaris.exe")
    except RuntimeError:
        pid = 0
    if not pid:
        print("[graph] stellaris.exe is not running — no shot", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)

    expected = read_edge_table(edges_file) if edges_file else None
    if rewire is not None and mutate_collide is None:
        required_extra = REWIRE_EXPORTS
    elif mutate_collide is not None:
        required_extra = COLLIDE_EXPORTS
    else:
        required_extra = ()
    base, exports = gate_and_inject(pid, dll_path, allow_window=allow_window,
                                    required_extra=required_extra, attach=attach)

    stats_buf = harness.remote_alloc(pid, STATS_SIZE)
    drain_buf = harness.remote_alloc(pid, DRAIN_BYTES)
    layout_buf = harness.remote_alloc(pid, LAYOUT_WORDS * 4)

    harness.call_remote_with_arg(pid, base, exports["C5GraphLayout"], layout_buf)
    layout = struct.unpack(f"<{LAYOUT_WORDS}I", harness.read_memory(pid, layout_buf,
                                                                   LAYOUT_WORDS * 4))

    if settle_s:
        time.sleep(settle_s)

    step_lines = []
    rewire_meta = {}
    if mutate is None and mutate_collide is None and rewire is None:
        rc1, stats1, rows1 = read_once(pid, base, exports, stats_buf, drain_buf)
        rc2, stats2, rows2 = read_once(pid, base, exports, stats_buf, drain_buf)
    elif mutate is not None:
        # The mutation sequence is fixed and each step is recorded **before** the next
        # one runs: if a step fails, the artifact still says which one and the rest is
        # never called (Review Focus #5).
        x, y = mutate
        pair = (x << 32) | (y & 0xFFFF_FFFF)

        rc1, stats1, rows1 = read_once(pid, base, exports, stats_buf, drain_buf)
        step_lines.append(f"step=base edges={stats1['edges']} rc={rc1}")

        add_rc = _signed32(harness.call_remote_with_arg(pid, base, exports["C5GraphMutateAdd"],
                                                        pair))
        step_lines.append(f"step=add edges=- rc={add_rc}")
        seq = [dict(stats1, rc=rc1), {"edges": -1, "rc": add_rc}, {"edges": -1, "rc": 0}]

        rows_add, rows_rm = [], []
        read_rc_add, read_rc_rm = None, None
        if add_rc == 0:
            read_rc_add, stats_add, rows_add = read_once(pid, base, exports, stats_buf, drain_buf)
            seq[1] = dict(stats_add, rc=add_rc, read_rc=read_rc_add)
            step_lines.append(f"step=add_read edges={stats_add['edges']} rc={read_rc_add}")

            rm_rc = _signed32(harness.call_remote_with_arg(pid, base, exports["C5GraphMutateRemove"],
                                                           pair))
            step_lines.append(f"step=remove edges=- rc={rm_rc}")
            seq[2] = {"edges": -1, "rc": rm_rc}
            if rm_rc == 0:
                read_rc_rm, stats_rm, rows_rm = read_once(pid, base, exports, stats_buf,
                                                          drain_buf)
                seq[2] = dict(stats_rm, rc=rm_rc, read_rc=read_rc_rm)
                step_lines.append(f"step=remove_read edges={stats_rm['edges']} rc={read_rc_rm}")

        write_edge_snapshots(out_path, rows1, rows_add, rows_rm)
        stats2 = None          # three snapshots, not a "read2" — see `read2_meta`
        rc2 = None
    elif mutate_collide is not None:
        # Collision: add and remove are adjacent — no read in between.  The live
        # source's own cache keys (fingerprint word 7, edge-set hash word 0) are
        # sampled next to each read; comparing them is the whole judgement.
        steps = collide_steps(mutate_collide[0], mutate_collide[1])
        x, y = mutate_collide
        pair = (x << 32) | (y & 0xFFFF_FFFF)
        live_stats_buf = harness.remote_alloc(pid, LIVE_STATS_SIZE)
        live_hash_buf = harness.remote_alloc(pid, LIVE_HASH_SIZE)

        rc1, stats1, rows1 = read_once(pid, base, exports, stats_buf, drain_buf)
        base_fp, base_hash = read_live_pair(pid, base, exports, live_stats_buf, live_hash_buf)
        step_lines.append(f"step={steps[0]} edges={stats1['edges']} rc={rc1} "
                          f"fingerprint={base_fp} hash={base_hash:016x}")

        collide_fp, collide_hash = 0, 0
        read_rc2, stats_c, rows2 = None, None, []
        add_rc = _signed32(harness.call_remote_with_arg(pid, base, exports["C5GraphMutateAdd"],
                                                        pair))
        step_lines.append(f"step={steps[1]} edges=- rc={add_rc}")
        rm_rc = None
        if add_rc == 0:
            rm_rc = _signed32(harness.call_remote_with_arg(pid, base, exports["C5GraphMutateRemove"],
                                                           pair))
            step_lines.append(f"step={steps[2]} edges=- rc={rm_rc}")
            if rm_rc == 0:
                read_rc2, stats_c, rows2 = read_once(pid, base, exports, stats_buf, drain_buf)
                collide_fp, collide_hash = read_live_pair(pid, base, exports,
                                                          live_stats_buf, live_hash_buf)
                step_lines.append(f"step={steps[3]} edges={stats_c['edges']} rc={read_rc2} "
                                  f"fingerprint={collide_fp} hash={collide_hash:016x}")

        if rc1 not in (0, -4):
            verdict = "instrument_broken"
            detail = f"base read == {rc1}"
        elif add_rc != 0 or rm_rc != 0:
            failed = "add" if add_rc != 0 else "remove"
            verdict = "mutation_left_dirty"
            detail = f"{failed} step did not land (rc != 0) — the fixture never formed"
        elif read_rc2 not in (0, -4):
            verdict = "instrument_broken"
            detail = f"collide read == {read_rc2}"
        else:
            verdict = classify_collision(
                base_fingerprint=base_fp, collide_fingerprint=collide_fp,
                base_hash=base_hash, collide_hash=collide_hash)
            detail = (f"fingerprint {base_fp} -> {collide_fp}; "
                      f"hash {base_hash:016x} -> {collide_hash:016x}; "
                      f"edges {stats1['edges']} -> {stats_c['edges']}")

        stats2 = None          # the two reads are base / collide_read, not "read2"
        rc2 = None
    else:
        # Rewire: 保度的 2-switch。base 读先走 —— `auto` 要拿它选端点;选不出解就停在这里,
        # 一个导出都不改(硬改会造出非保度的删加,那一发证明不了 #46)。
        rc1, stats1, rows1 = read_once(pid, base, exports, stats_buf, drain_buf)
        switch = choose_switch(rows1) if rewire == "auto" else rewire
        if rc1 not in (0, -4):
            verdict, detail = "instrument_broken", f"base read == {rc1}"
            step_lines = [f"step=base edges={stats1['edges']} rc={rc1}"]
            rewire_meta = {"step": "rewire", "switch": "unresolved",
                           "rewire_steps": "|".join(step_lines)}
        elif switch is None:
            verdict = "no_switch_available"
            detail = (f"no degree-preserving 2-switch in {len(rows1)} edges — "
                      "换一对端点或换存档,不要硬改")
            step_lines = [f"step=base edges={stats1['edges']} rc={rc1}"]
            rewire_meta = {"step": "rewire", "switch": "none",
                           "rewire_steps": "|".join(step_lines)}
        else:
            live_bufs = (harness.remote_alloc(pid, LIVE_STATS_SIZE),
                         harness.remote_alloc(pid, LIVE_HASH_SIZE),
                         harness.remote_alloc(pid, VERIFY_STATS_SIZE))
            verdict, detail, step_lines, rewire_meta = rewire_shot(
                pid, base, exports, stats_buf, drain_buf, live_bufs, switch, stats1, rc1)
        stats2 = None          # base / rewire_read / restore_read:没有「第二次读」
        rc2 = None

    try:
        harness.assert_game_alive(pid)
        alive = True
    except Exception:                    # noqa: BLE001 — a dead host is a reading
        alive = False

    if mutate is None and mutate_collide is None and rewire is None:
        env = {
            "rc": rc1,
            "gate": "operator_override" if allow_window else "world_state",
            "exports_ok": True,
            "alive": alive,
            "expect_systems": expect_systems,
            "expect_edges": expect_edges,
        }
        # Two reads: the verdict compares them, and `rows_complete` is the driver's own
        # check that the drain gave back as many rows as the stats claimed.
        verdict, detail = classify(stats1, rows1, expected, layout, env,
                                   again=rows2, rows_complete=(len(rows1) == stats1["edges"]))
    elif mutate is not None:
        verdict, detail = classify_mutation(seq, mutate[0], mutate[1], base_rows=rows1,
                                            added_rows=rows_add,
                                            removed_rows=rows_rm if read_rc_rm is not None else None)
    # else: the collide / rewire branches already set `verdict` / `detail` themselves.

    meta = {
        "overall_verdict": verdict,
        "expect_systems": expect_systems,
        "expect_edges": expect_edges,
        "save_name": save_name,
        "dll": os.path.basename(dll_path.replace("\\", "/")),
        "dll_sha256": dll_sha,
        "module_base": f"0x{stats1['module_base']:x}",
        "index_ptr": f"0x{stats1['index_ptr']:x}",
        "table_ptr": f"0x{stats1['table_ptr']:x}",
        "bound": stats1["bound"],
        "systems": stats1["systems"],
        "edges": stats1["edges"],
        "skipped": stats1["skipped"],
        "max_id": "null" if stats1["max_id"] is None else stats1["max_id"],
        "layout": format_layout(layout),
        "host_alive": int(alive),
        "gate": "operator_override" if allow_window else "world_state",
        "read1_rc": rc1,
        "detail": detail,
    }
    meta.update(read2_meta(stats2, rc2))
    if mutate is not None:
        meta["mutation"] = f"{min(mutate)}-{max(mutate)}"
        meta["mutation_steps"] = "|".join(step_lines)
    if mutate_collide is not None:
        meta["step"] = "collide"
        meta["mutation"] = f"{min(mutate_collide)}-{max(mutate_collide)}"
        meta["mutation_steps"] = "|".join(step_lines)
        meta["base_fingerprint"] = base_fp
        meta["collide_fingerprint"] = collide_fp
        meta["base_hash"] = f"{base_hash:016x}"
        meta["collide_hash"] = f"{collide_hash:016x}"
    if rewire is not None:
        meta.update(rewire_meta)
    write_artifact(out_path, build_meta(meta), rows1)
    print(f"[graph] verdict={verdict}  {detail}")
    print(f"[graph] artifact={out_path}")

    if not alive:
        print("[graph] HOST DIED — run scripts/c2_selfabort_repro.py and "
              "scripts/dll_ubsan_site.py before anything else (AGENTS 约束 8)",
              file=sys.stderr)
        return meta, EXIT_HOST_DEAD
    dirty_restore = bool(rewire_meta) and rewire_meta.get("restore_ok") == 0
    if kill_after or dirty_restore:
        # restore_dirty 的图不能留给 autosave(每分钟一次):立即杀,不等操作者补 --kill-after。
        if dirty_restore:
            print("[graph] restore_ok=0 — killing the session so autosave cannot keep a "
                  "rewired graph (RF#4)", file=sys.stderr)
        kill_game(pid)
    return meta, 0


def parse_pair(parser, text, flag):
    """`FROM,TO` -> two distinct ids inside 0..0xFFFF (argparse errors otherwise)."""
    parts = text.split(",")
    if len(parts) != 2:
        parser.error(f"{flag} wants FROM,TO")
    try:
        a, b = (int(part) for part in parts)
    except ValueError:
        parser.error(f"{flag} wants two integers")
    if not (0 <= a <= 0xFFFF and 0 <= b <= 0xFFFF) or a == b:
        parser.error(f"{flag} endpoints must be distinct ids inside 0..65535")
    return (a, b)


def parse_switch(parser, text, flag):
    """`A,B,C,D` -> four distinct ids inside 0..0xFFFF (argparse errors otherwise)."""
    parts = text.split(",")
    if len(parts) != 4:
        parser.error(f"{flag} wants A,B,C,D")
    try:
        ids = tuple(int(part) for part in parts)
    except ValueError:
        parser.error(f"{flag} wants four integers")
    if any(not 0 <= ident <= 0xFFFF for ident in ids) or len(set(ids)) != 4:
        parser.error(f"{flag} endpoints must be four distinct ids inside 0..65535")
    return ids


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", nargs="?", default=r"C:\temp\sqjs_g1.dll")
    parser.add_argument("--expect-systems", type=int, required=True,
                        help="star count the campaign should read (no default)")
    parser.add_argument("--expect-edges", type=int, required=True,
                        help="unique undirected edges the campaign should read (no default)")
    parser.add_argument("--save-name", required=True)
    parser.add_argument("--edges-file", default=None,
                        help="offline edge table (a<TAB>b<TAB>length) to reconcile against")
    parser.add_argument("--out", default="C:/temp/c5_graph_read.tsv")
    parser.add_argument("--poll-s", type=float, default=0.0,
                        help="settle seconds before the first read (not a poll window: the "
                             "reading is two explicit reads, and polling would mask a tear)")
    parser.add_argument("--allow-window", action="store_true",
                        help="operator-declared premise: skip gate_install (recorded in meta)")
    parser.add_argument("--attach", action="store_true",
                        help="attach to the module that is ALREADY injected (never injects: a "
                             "second copy would carry an empty live cache and read like "
                             "'no recompute'); the name must match the boot-injected basename")
    parser.add_argument("--mutate", default=None, metavar="FROM,TO",
                        help="mutation shot: Read -> MutateAdd -> Read -> MutateRemove -> Read "
                             "on this pair (both within 0..0xFFFF, not an existing edge)")
    parser.add_argument("--mutate-collide", default=None, metavar="FROM,TO",
                        help="collision shot: Read -> MutateAdd -> MutateRemove -> Read "
                             "(no read between add and remove: the fingerprint returns to its "
                             "base value, so only the edge-set hash can see the rewiring)")
    parser.add_argument("--rewire", default=None, metavar="auto|A,B,C,D",
                        help="degree-preserving 2-switch (#46's fixture): remove (a,b)/(c,d), "
                             "add (a,c)/(b,d) so all four degrees stay put — the fingerprint "
                             "cannot move while the edge set does. 'auto' picks the first "
                             "feasible switch from the base read")
    parser.add_argument("--kill-after", action="store_true",
                        help="after the artifact is written, taskkill the game (no save, no "
                             "menu: the plan's cleanup for a mutation shot)")
    args = parser.parse_args(argv)

    mutate = None
    if args.mutate:
        mutate = parse_pair(parser, args.mutate, "--mutate")
    mutate_collide = None
    if args.mutate_collide:
        mutate_collide = parse_pair(parser, args.mutate_collide, "--mutate-collide")
    rewire_arg = None
    if args.rewire:
        rewire_arg = "auto" if args.rewire == "auto" else parse_switch(
            parser, args.rewire, "--rewire")
    shots = [name for name, value in (("--mutate", mutate),
                                      ("--mutate-collide", mutate_collide),
                                      ("--rewire", rewire_arg)) if value]
    if len(shots) > 1:
        parser.error(f"{' and '.join(shots)} are different shots; pick one")

    _, code = run(args.dll, args.out, expect_systems=args.expect_systems,
                  expect_edges=args.expect_edges, save_name=args.save_name,
                  edges_file=args.edges_file, allow_window=args.allow_window,
                  settle_s=args.poll_s, mutate=mutate, mutate_collide=mutate_collide,
                  rewire=rewire_arg, kill_after=args.kill_after, attach=args.attach)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
