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
  * `graph_live_read_disagree` —— 其余(判负)。

**判定口径的两处注记**(裁定见 SDD ledger):

  1. `classify` 不重数行数 —— 行数是否等于 `stats.edges` 由驱动用 `rows_complete` 传进来。
     这样判词函数只回答「这组读数一致吗」,不回答「你搬全了吗」。
  2. `--poll-s` 是读之前的**静置**秒数,不是轮询窗口:判据要求「连读两次」,拿轮询去等
     图安定会把撕裂读掩掉。

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
)
EVIDENCE_VERDICTS = (
    "graph_live_read_unstable",
    "graph_live_read_named",
    "graph_live_read_partial",
    "graph_live_read_disagree",
    "graph_mutation_recompute_named",
    "mutation_left_dirty",
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
    detail = f"{observed} vs expect systems={env.get('expect_systems')} " \
             f"edges={env.get('expect_edges')}"
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


# --- artifact ---------------------------------------------------------------------


def build_meta(values):
    """`k=v` lines in `META_ORDER`, then any extra key sorted (a shot may add readings)."""
    lines = [f"{key}={values[key]}" for key in META_ORDER if key in values]
    lines.extend(f"{key}={values[key]}" for key in sorted(values) if key not in META_ORDER)
    return lines


def format_layout(words):
    return ",".join(f"{word:#x}" for word in parse_layout(words))


def write_artifact(path, meta_lines, rows):
    """Meta first, then rows: the artifact is what survives a lost stdout."""
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for line in meta_lines:
            handle.write(f"#meta {line}\n")
        for a, b in rows:
            handle.write(f"{a}\t{b}\n")


def write_edge_snapshots(out_path, base_rows, add_rows, remove_rows):
    """`<out>.base` / `.add` / `.remove`: three edge tables for the host-side recompute.

    Three columns (`a`, `b`, `1`): the third is a **placeholder** — the read path gives
    ids only, and the host-side metric is unweighted (Brandes over an undirected
    unweighted graph). Keeping the column makes `chokepoint_scores._read_edges` usable
    verbatim, which is what §5's recompute snippet calls.
    """
    for suffix, rows in (("base", base_rows), ("add", add_rows), ("remove", remove_rows)):
        with open(f"{out_path}.{suffix}", "w", encoding="utf-8", newline="\n") as handle:
            for a, b in rows:
                handle.write(f"{a}\t{b}\t1\n")


def kill_game(pid):
    """Kill the session rather than saving or parking it (the plan's cleanup rule)."""
    import subprocess

    result = subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                            capture_output=True, text=True)
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


def _signed32(value):
    value &= 0xFFFF_FFFF
    return value - 0x1_0000_0000 if value & 0x8000_0000 else value


# --- live path (Windows only; not exercised by the host tests) ---------------------


def gate_and_inject(pid, dll_path, allow_window=False):
    """Seven exports in the FILE → refuse-if-resident → gate → inject → sanity.

    The gate call must stay **before** `inject_dll` in this scope: `scripts/
    test_scripts_layout.py`'s R-inject fence reads exactly that ordering, and a shot
    that injects first has already spent the premise when it finds out.
    """
    import c2_harness as harness

    exports = harness.list_exports(dll_path)
    missing = [name for name in REQUIRED_EXPORTS if name not in exports]
    if missing:
        print(f"[graph] {dll_path} is missing {missing} — refusing to inject", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)

    dll_name = os.path.basename(dll_path.replace("\\", "/"))
    print(f"[graph] pid={pid} dll={dll_path}")
    try:
        resident = harness.resolve_base_address(pid, dll_name)
    except RuntimeError:
        resident = None
    refuse_if_resident(dll_name, resident)

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


def run(dll_path, out_path, *, expect_systems, expect_edges, save_name, edges_file=None,
        allow_window=False, settle_s=0.0, mutate=None, kill_after=False):
    """One shot in one game process. No hook is installed and nothing is unloaded.

    `mutate=(x, y)` switches the shot to the three-snapshot form: Read (base) →
    MutateAdd → Read → MutateRemove → Read, and every step goes into `#meta`.
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
    base, exports = gate_and_inject(pid, dll_path, allow_window=allow_window)

    stats_buf = harness.remote_alloc(pid, STATS_SIZE)
    drain_buf = harness.remote_alloc(pid, DRAIN_BYTES)
    layout_buf = harness.remote_alloc(pid, LAYOUT_WORDS * 4)

    harness.call_remote_with_arg(pid, base, exports["C5GraphLayout"], layout_buf)
    layout = struct.unpack(f"<{LAYOUT_WORDS}I", harness.read_memory(pid, layout_buf,
                                                                   LAYOUT_WORDS * 4))

    if settle_s:
        time.sleep(settle_s)

    step_lines = []
    if mutate is None:
        rc1, stats1, rows1 = read_once(pid, base, exports, stats_buf, drain_buf)
        rc2, stats2, rows2 = read_once(pid, base, exports, stats_buf, drain_buf)
    else:
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
        stats2 = stats1
        rc2 = rc1

    try:
        harness.assert_game_alive(pid)
        alive = True
    except Exception:                    # noqa: BLE001 — a dead host is a reading
        alive = False

    if mutate is None:
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
    else:
        verdict, detail = classify_mutation(seq, mutate[0], mutate[1], base_rows=rows1,
                                            added_rows=rows_add,
                                            removed_rows=rows_rm if read_rc_rm is not None else None)

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
        "read2_edges": stats2["edges"],
        "layout": format_layout(layout),
        "host_alive": int(alive),
        "gate": "operator_override" if allow_window else "world_state",
        "read1_rc": rc1,
        "read2_rc": rc2,
        "read2_systems": stats2["systems"],
        "read2_skipped": stats2["skipped"],
        "detail": detail,
    }
    if mutate is not None:
        meta["mutation"] = f"{min(mutate)}-{max(mutate)}"
        meta["mutation_steps"] = "|".join(step_lines)
    write_artifact(out_path, build_meta(meta), rows1)
    print(f"[graph] verdict={verdict}  {detail}")
    print(f"[graph] artifact={out_path}")

    if not alive:
        print("[graph] HOST DIED — run scripts/c2_selfabort_repro.py and "
              "scripts/dll_ubsan_site.py before anything else (AGENTS 约束 8)",
              file=sys.stderr)
        return meta, EXIT_HOST_DEAD
    if kill_after:
        kill_game(pid)
    return meta, 0


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
    parser.add_argument("--mutate", default=None, metavar="FROM,TO",
                        help="mutation shot: Read -> MutateAdd -> Read -> MutateRemove -> Read "
                             "on this pair (both within 0..0xFFFF, not an existing edge)")
    parser.add_argument("--kill-after", action="store_true",
                        help="after the artifact is written, taskkill the game (no save, no "
                             "menu: the plan's cleanup for a mutation shot)")
    args = parser.parse_args(argv)

    mutate = None
    if args.mutate:
        parts = args.mutate.split(",")
        if len(parts) != 2:
            parser.error("--mutate wants FROM,TO")
        try:
            a, b = (int(part) for part in parts)
        except ValueError:
            parser.error("--mutate wants two integers")
        if not (0 <= a <= 0xFFFF and 0 <= b <= 0xFFFF) or a == b:
            parser.error("--mutate endpoints must be distinct ids inside 0..65535")
        mutate = (a, b)

    _, code = run(args.dll, args.out, expect_systems=args.expect_systems,
                  expect_edges=args.expect_edges, save_name=args.save_name,
                  edges_file=args.edges_file, allow_window=args.allow_window,
                  settle_s=args.poll_s, mutate=mutate, kill_after=args.kill_after)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
