#!/usr/bin/env python3
"""c2_exec_caller_probe.py — 第八把 guard:谁在逐系统派发子效果(§90.4 定的锚)。

**这一发问的是什么**(§89.3 的 hand-off):

  * `log` 效果的实现入口 `0x185BF60` 每次被调时,**返回地址**落在哪个函数里 —— 那就是
    「谁在逐系统派发」;
  * 它的第二实参若是 scope(§80.2 的形状:`+0x08` mask、`+0x10` id),那批 id 去重后有多少种、
    是否 ⊆ 银河容器 `[[0x3260BB0]+0x590]` 的 id 集、是否落在 `[1,N]`。

**为什么是这个入口**:§89.3 的实机读数(16 个完整月度脉冲、12,544 条 `PS_HIT`)证明它每月跑
784 次;§90.1 证明 `+0x70`/token 解释器那一族在同窗内整族沉默。它是目前唯一确凿在**执行侧**的锚。

**verdict 值域**(环境/仪器档在前):

  * `instrument_broken` —— layout 靶位不符 / 装着但 hook 丢了;
  * `no_calls` / `ring_truncated` / `container_unreadable` / `dispatch_denominator_mismatch`
    / `caller_unnamed` / `caller_mixed` / `scope_constant` —— 环境或仪器档,**不是**证据;
  * `ids_out_of_range` / `ids_not_in_container` —— 判负;
  * `dispatch_named` —— 证据:调用者 RVA 唯一且落在镜像里、id 去重后 ⊆ 容器且落在 `[1,N]`。

**这一发不能说的**(写进 §91 时逐条保留):
  1. 返回地址是**一层**调用者;它上面的循环/派发方若也是虚派发,一层不够。
  2. 第二实参是不是 scope 由「id 会不会变、是否 ⊆ 容器」判;`scope_constant` 只说明「不是那形状」,
     不说明引擎没有 scope。
  3. 容器是活数据,只认一次读足的 blob(§81.1 ③)。

用法(Windows 侧，经 `session_bridge` 进 session 1):

    python C:/temp/session_bridge.py --timeout-s 400 C:/temp/c2_exec_caller_probe.py \
        C:/temp/sqjs_c10.dll --systems 788 --save-name autosave_2282.01.01 --poll-s 120
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys

# --- wire contract (the DLL's own constants; drift = a red fence) -----------------

TARGET_RVA = 0x185BF60          # offsets.keyword_reg.RVA_LOG_EFFECT_EXEC (§90.4)
GALAXY_DB_RVA = 0x3260BB0       # §81.1 ④
GALAXY_IDS_OFF = 0x590
GALAXY_COUNT_OFF = 0x59C

ENTRY_SIZE = 32                 # layoutInto word 1
STATS_SIZE = 512                # fixed stats buffer the export writes into
LAYOUT_WORDS = 6
RING_LEN = 2048
PROLOGUE_LEN = 32               # EXPECTED_CODE length in the Zig module

STATS_KEYS = (
    "calls",
    "dropped",
    "null_scope",
    "patch_size",
    "installed",
    "verify",
    "last_id",
    "last_caller",
)

VERDICTS = (
    "instrument_broken",
    "no_calls",
    "no_rows",
    "ring_truncated",
    "caller_sampled",
    "poc_rule_hits",
    "poc_no_hits",
    "container_unreadable",
    "dispatch_denominator_mismatch",
    "caller_unnamed",
    "caller_mixed",
    "scope_constant",
    "ids_out_of_range",
    "ids_not_in_container",
    "dispatch_named",
)
EVIDENCE_VERDICTS = ("ids_out_of_range", "ids_not_in_container", "dispatch_named",
                    "poc_rule_hits")

EXIT_REFUSED = 2


# --- parsing ----------------------------------------------------------------------


def parse_stats(text):
    """`k=v` pairs from one stats line; every `STATS_KEYS` entry is required."""
    out = {}
    for token in text.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        try:
            out[key] = int(value)
        except ValueError as exc:
            raise ValueError(f"stats value for {key!r} is not an integer: {value!r}") from exc
    missing = [key for key in STATS_KEYS if key not in out]
    if missing:
        raise ValueError(f"stats line is missing {missing}: {text!r}")
    return out


def decode_layout(words):
    """Six words -> dict. `words[4]` is the target RVA; `words[5]` must be 0 (no filter)."""
    if len(words) != LAYOUT_WORDS:
        raise ValueError(f"layout needs {LAYOUT_WORDS} words, got {len(words)}")
    return {
        "version": words[0],
        "entry_size": words[1],
        "ring_len": words[2],
        "stats_size": words[3],
        "target_rva": words[4],
        "vtable_rva": words[5],
    }


def decode_entry(blob):
    """32 B -> dict. Field order is the Zig `Entry` extern struct."""
    if len(blob) != ENTRY_SIZE:
        raise ValueError(f"entry needs {ENTRY_SIZE} bytes, got {len(blob)}")
    caller, eid, mask, occurrences, self_ptr, scope = struct.unpack("<IIIIQQ", blob)
    return {
        "caller_rva": caller,
        "id": eid,
        "mask": mask,
        "occurrences": occurrences,
        "self_ptr": self_ptr,
        "scope_ptr": scope,
    }


def decode_container(blob, count):
    """The 4 B id vector, read in ONE go — `count` must match the blob exactly."""
    if count < 0 or len(blob) != count * 4:
        raise ValueError(
            f"container blob is {len(blob)} bytes but the count says {count} ids "
            f"({count * 4} bytes) — the two reads did not agree"
        )
    return list(struct.unpack(f"<{count}I", blob)) if count else []


# --- judgement --------------------------------------------------------------------


def aggregate(rows):
    """Fold duplicate `(caller, id)` samples; the DLL no longer keeps a table (§91.2)."""
    folded = {}
    for row in rows:
        key = (row["caller_rva"], row["id"], row["mask"])
        if key in folded:
            folded[key]["occurrences"] += row["occurrences"]
        else:
            folded[key] = dict(row)
    return list(folded.values())


def verdict(stats, rows, container, *, expected, distinct=None):
    """The single judgement. Environment classes first; `instrument_broken` wins over all.

    `distinct` is the deduplicated id count; it defaults to the row count when the caller has
    already folded rows (the artifact path passes it explicitly).
    """
    if stats["installed"] == 1 and stats["verify"] != 0:
        return "instrument_broken"
    if stats["calls"] == 0:
        return "no_calls"
    if stats["dropped"] != 0:
        return "ring_truncated"
    if not container or not container.get("ids"):
        return "container_unreadable"
    if container["raw_count"] != len(container["ids"]):
        return "container_unreadable"
    if container["raw_count"] != expected:
        return "dispatch_denominator_mismatch"

    if not rows:
        # §91.3: the ring killed the game, so the shipped probe keeps one caller slot in stats.
        return "caller_sampled" if stats["last_caller"] else "no_rows"
    callers = {row["caller_rva"] for row in rows}
    if not callers or 0 in callers:
        return "caller_unnamed"
    if len(callers) > 1:
        return "caller_mixed"

    guard_ids = {row["id"] for row in rows}
    # The container is **0-based** (2026-11-02 read: ids 0..786, 787 entries), so the range
    # gate is `0 <= id < expected`; the real constraint is the subset test right below.
    if any(not (0 <= eid < expected) for eid in guard_ids):
        return "ids_out_of_range"
    if not guard_ids <= set(container["ids"]):
        return "ids_not_in_container"
    if (distinct if distinct is not None else len(rows)) < 2:
        # One id for every call: the second argument is not the per-system scope shape.
        return "scope_constant"
    return "dispatch_named"


def install_decision(rc, layout):
    """`ok` | `refused` (码表非零) | `stale_target` (layout 靶位不是 §90.4 的那个)。"""
    if rc != 0:
        return "refused"
    if layout.get("target_rva") != TARGET_RVA:
        return "stale_target"
    return "ok"


def gate_label(allow_window):
    """Which premise this shot was fired under — recorded in `#meta`."""
    return "operator_override" if allow_window else "world_state"


# --- pre-fire gates ---------------------------------------------------------------


def sha_gate(path):
    """Print-and-record the sha256 of the file we are about to inject. Missing = exit 2."""
    if not os.path.exists(path):
        raise SystemExit(EXIT_REFUSED)
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def refuse_if_resident(dll_name, base):
    """A same-name module already mapped means the loader reuses the old image."""
    if base:
        raise SystemExit(EXIT_REFUSED)


# --- live path (Windows only; not exercised by the host tests) ---------------------


def _signed32(value):
    return value - (1 << 32) if value >= (1 << 31) else value


def _safe(fn, default=None):
    """Run one live call; a dead host is a reading, not a traceback.

    2026-11-01: the game exited during a shot, so the cleanup's `CreateRemoteThread`
    raised `gle=5` and the artifact was never written — the reading we paid for was lost.
    Cleanup and the poll loop both go through this.
    """
    try:
        return fn()
    except Exception:                       # noqa: BLE001 — the reason is the missing reading
        return default


def decode_entries(blob):
    return [decode_entry(blob[offset:offset + ENTRY_SIZE])
            for offset in range(0, len(blob) - ENTRY_SIZE + 1, ENTRY_SIZE)]


def read_container(pid, exe_base):
    """One live read of the galaxy id vector. `None` = unreadable (never an exception)."""
    import c2_harness as harness

    try:
        obj = struct.unpack("<Q", harness.read_memory(pid, exe_base + GALAXY_DB_RVA, 8))[0]
        count = struct.unpack("<I", harness.read_memory(pid, obj + GALAXY_COUNT_OFF, 4))[0]
        if not 0 < count <= 1_000_000:
            return None
        vec = struct.unpack("<Q", harness.read_memory(pid, obj + GALAXY_IDS_OFF, 8))[0]
        blob = harness.read_memory(pid, vec, count * 4)
        return {"raw_count": count, "ids": decode_container(blob, count)}
    except Exception:                       # noqa: BLE001 — an unreadable read is a verdict
        return None


def read_stats(pid, base, exports, buf):
    import c2_harness as harness

    harness.call_remote_with_arg(pid, base, exports["C6ExecCallerStatsInto"], buf)
    text = harness.read_memory(pid, buf, 512).split(b"\0", 1)[0].decode("ascii", "replace")
    return parse_stats(text)


def drain_entries(pid, base, exports, buf):
    """`DrainInto(out)` takes the buffer in `rcx`: pass it, never call it bare.

    2026-11-02: this used `call_remote` (no argument), so the export wrote through a garbage
    `out`. It only crashed when there was something to copy — i.e. only in builds that
    recorded samples — which is why three "recording" builds died and three "no rows" builds
    survived. The game's own crash report pinned it: `C0000005 ... C6ExecCallerDrainInto`.
    """
    import c2_harness as harness

    count = harness.call_remote_with_arg(pid, base, exports["C6ExecCallerDrainInto"], buf) & 0xFFFFFFFF
    blob = harness.read_memory(pid, buf, count * ENTRY_SIZE)
    return decode_entries(blob)


def gate_module(pid, dll_path, needed, allow_window=False):
    """Check the export names in the FILE, gate the world state, then inject."""
    import c2_harness as harness

    exports = harness.list_exports(dll_path)
    missing = [name for name in needed if name not in exports]
    if missing:
        print(f"[execcaller] {dll_path} is missing {missing} — refusing to inject", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)

    dll_name = os.path.basename(dll_path.replace("\\", "/"))
    print(f"[execcaller] pid={pid}  dll={dll_path}")
    try:
        resident = harness.resolve_base_address(pid, dll_name)
    except RuntimeError:
        resident = None
    refuse_if_resident(dll_name, resident)

    if allow_window:
        print("[execcaller] gate skipped by operator override (--allow-window)")
    else:
        from world_probe import gate_install  # pyright: ignore[reportMissingImports]

        gate_install("execcaller")
    harness.inject_dll(pid, dll_path)
    harness.assert_game_alive(pid)
    base = harness.resolve_base_address(pid, dll_name)
    print(f"[execcaller] {dll_name} base: 0x{base:x}")

    head = harness.read_memory(pid, base, 2)
    assert head == b"MZ", f"bad header at 0x{base:x}: {head!r}"
    sanity = _signed32(harness.call_remote(pid, base, exports["C2Sanity"]))
    assert sanity == 42, f"C2Sanity returned {sanity}, expected 42"
    harness.assert_game_alive(pid)
    print("[execcaller] C2Sanity == 42, game alive — dispatch authorized")
    return base, exports


def _write_artifact(out_path, meta_lines, rows):
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(meta_lines) + "\n")
        handle.writelines(row + "\n" for row in rows)


def build_meta(**kwargs):
    """`k=v` lines, sorted by key, for the artifact's `#meta` block."""
    return [f"#meta {key}={kwargs[key]}" for key in sorted(kwargs)]


def artifact_rows(rows):
    """Six columns: `caller id mask occurrences self scope`."""
    return [
        "\t".join((
            f"0x{row['caller_rva']:x}",
            str(row["id"]),
            f"0x{row['mask']:x}",
            str(row["occurrences"]),
            f"0x{row['self_ptr']:x}",
            f"0x{row['scope_ptr']:x}",
        ))
        for row in rows
    ]


RULE_HITS = 64


def encode_rule(rule):
    """`"MOD:REM"` -> the u64 the DLL takes (`mod << 32 | rem`). `0:0` disables it."""
    mod_text, _, rem_text = rule.partition(":")
    return (int(mod_text) << 32) | (int(rem_text or 0) & 0xFFFFFFFF)


def decode_hits(words):
    """`[count][ids…]` -> the first `count` ids, as a list."""
    count, ids = words[0], words[1:]
    return list(ids[:count])


def count_marker_in_log(path, offset, marker):
    """How many `marker` lines appeared in the log since `offset` (`None` = not measured)."""
    if offset is None:
        return None
    try:
        with open(path, "rb") as handle:
            handle.seek(offset)
            text = handle.read().decode("utf-8", "replace")
    except OSError:
        return None
    return text.count(marker)


def run(dll_path, out_path, *, systems, save_name, poll_s=120.0, settle_s=3.0,
        allow_window=False, rule="100:0", act="record", game_log=None, marker="PS_HIT"):
    """One shot in one game process. Cleanup runs in a finally; never FreeLibrary."""
    import time

    import c2_harness as harness

    dll_sha = sha_gate(dll_path)
    print(f"[execcaller] dll={dll_path} sha256={dll_sha}")

    pid = harness.resolve_pid("stellaris.exe")
    needed = [name for name in harness.list_exports(dll_path) if name.startswith("C6ExecCaller")]
    base, exports = gate_module(pid, dll_path, needed, allow_window=allow_window)
    exe_base = harness.resolve_base_address(pid, "stellaris.exe")

    stats_buf = harness.remote_alloc(pid, STATS_SIZE)
    drain_cap = RING_LEN * ENTRY_SIZE
    drain_buf = harness.remote_alloc(pid, drain_cap)
    layout_buf = harness.remote_alloc(pid, LAYOUT_WORDS * 4)

    harness.call_remote_with_arg(pid, base, exports["C6ExecCallerLayout"], layout_buf)
    layout = decode_layout(struct.unpack("<6I", harness.read_memory(pid, layout_buf, LAYOUT_WORDS * 4)))

    from c4_wiring_probe import GAME_LOG, _file_size_or_none

    log_path = os.path.expanduser(game_log or GAME_LOG)
    log_offset = _file_size_or_none(log_path)
    rule_bits = encode_rule(rule)
    hits_buf = harness.remote_alloc(pid, 4 + RULE_HITS * 4)

    harness.call_remote(pid, base, exports["C6ExecCallerReset"])
    install_rc = _signed32(harness.call_remote(pid, base, exports["C6ExecCallerInstall"]))
    decision = install_decision(install_rc, layout)
    harness.call_remote_with_arg(pid, base, exports["C6ExecCallerSetRule"], rule_bits)
    harness.call_remote_with_arg(pid, base, exports["C6ExecCallerSetAct"],
                                 1 if act == "suppress" else 0)
    harness.assert_game_alive(pid)

    meta = {
        "dll": os.path.basename(dll_path.replace("\\", "/")),
        "dll_sha256": dll_sha,
        "module_base": f"0x{base:x}",
        "exe_base": f"0x{exe_base:x}",
        "systems": systems,
        "save_name": save_name,
        "install_rc": install_rc,
        "install_decision": decision,
        "gate": gate_label(allow_window),
        "layout_target_rva": f"0x{layout['target_rva']:x}",
        "overall_verdict": "instrument_broken" if decision != "ok" else "",
        "host_alive": 1,
        "entries_error": 0,
        "mode": "watch",
    }
    if decision != "ok":
        _write_artifact(out_path, build_meta(**meta), [])
        return meta

    rows, container = [], None
    uninstall_rc, verify_rc, alive = None, None, False
    try:
        time.sleep(settle_s)
        before = read_stats(pid, base, exports, stats_buf)
        container = read_container(pid, exe_base)

        deadline = time.time() + poll_s
        after = before
        early_rows = []
        early_at = min(15.0, poll_s / 2)
        while time.time() < deadline:
            time.sleep(1.0)
            reading = _safe(lambda: read_stats(pid, base, exports, stats_buf))
            if reading is None:
                meta["died_mid_poll"] = 1
                break
            after = reading
            # 2026-11-01: the host died at the end of the poll twice, taking the drained
            # rows (the caller RVAs) with it.  One early drain keeps the reading.
            if not early_rows and reading["calls"] and time.time() - (deadline - poll_s) >= early_at:
                _safe(lambda: harness.call_remote_with_arg(
                    pid, base, exports["C6ExecCallerSetDrainCap"], drain_cap))
                early_rows = _safe(lambda: drain_entries(pid, base, exports, drain_buf), [])
                meta["rows_early"] = len(early_rows)

        rows = _safe(lambda: (
            harness.call_remote_with_arg(pid, base, exports["C6ExecCallerSetDrainCap"], drain_cap),
            drain_entries(pid, base, exports, drain_buf))[1], [])
        if not rows and early_rows:
            rows = early_rows
            meta["rows_from"] = "early"
        rows = aggregate(rows)

        delta = {key: after[key] - before[key] for key in STATS_KEYS}
        delta["installed"] = after["installed"]
        delta["verify"] = after["verify"]
        delta["patch_size"] = after["patch_size"]
        meta.update({
            "stats_delta": " ".join(f"{k}={delta[k]}" for k in STATS_KEYS),
            "container_raw_count": (container or {}).get("raw_count", -1),
            "container_ids_sha256": hashlib.sha256(
                b"".join(struct.pack("<I", i) for i in (container or {}).get("ids", []))
            ).hexdigest(),
            "script_sends": 0,
            "entries": len(rows),
        })
        distinct = len({row["id"] for row in rows})
        meta["distinct_ids"] = distinct
        meta["last_caller"] = f"0x{delta['last_caller']:x}"
        _safe(lambda: harness.call_remote_with_arg(
            pid, base, exports["C6ExecCallerRuleHitsInto"], hits_buf))
        hit_blob = _safe(lambda: harness.read_memory(pid, hits_buf, 4 + RULE_HITS * 4), b"")
        hit_ids = decode_hits(struct.unpack(f"<{1 + RULE_HITS}I", hit_blob)) if hit_blob else []
        meta["act"] = act
        meta["marker_hits"] = count_marker_in_log(log_path, log_offset, marker)
        meta["rule"] = rule
        meta["rule_hits"] = len(hit_ids)
        meta["rule_ids"] = ",".join(str(i) for i in hit_ids)
        base_verdict = verdict(delta, rows, container, expected=systems, distinct=distinct)
        meta["overall_verdict"] = ("poc_rule_hits" if meta.get("rule_hits")
                                   else "poc_no_hits") if base_verdict == "dispatch_named" \
            else base_verdict
    finally:
        uninstall_rc = _safe(lambda: _signed32(harness.call_remote(
            pid, base, exports["C6ExecCallerUninstall"])))
        verify_rc = _safe(lambda: _signed32(harness.call_remote(
            pid, base, exports["C6ExecCallerVerify"])))
        time.sleep(settle_s)
        try:
            harness.assert_game_alive(pid)
            alive = True
        except Exception:                   # noqa: BLE001 — a dead host is a reading
            alive = False
        meta.update({
            "uninstall_rc": "unknown" if uninstall_rc is None else uninstall_rc,
            "verify_rc": "unknown" if verify_rc is None else verify_rc,
            "host_alive": 1 if alive else 0,
        })
        _write_artifact(out_path, build_meta(**meta), artifact_rows(rows))
    return meta


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", nargs="?", default=r"C:\temp\sqjs_c10.dll")
    parser.add_argument("--systems", type=int, required=True,
                        help="current campaign's star count (== container raw count; no default)")
    parser.add_argument("--save-name", required=True)
    parser.add_argument("--allow-window", action="store_true",
                        help="operator-declared premise: skip gate_install (recorded in meta)")
    parser.add_argument("--poll-s", type=float, default=120.0)
    parser.add_argument("--settle-s", type=float, default=3.0)
    parser.add_argument("--out", default="C:/temp/c5_exec_caller.tsv")
    parser.add_argument("--act", default="record", choices=("record", "suppress"),
                        help="record = only log the selection; suppress = systems that fail the "
                             "rule are not dispatched at all (observable in game.log)")
    parser.add_argument("--game-log", default=None)
    parser.add_argument("--marker", default="PS_HIT",
                        help="literal the effect writes per dispatch (the mod's log text)")
    parser.add_argument("--rule", default="100:0",
                        help="PoC rule MOD:REM — ids with id%%MOD==REM are selected inside the "
                             "dispatch; 0:0 disables (default 100:0)")
    args = parser.parse_args(argv)

    meta = run(args.dll, args.out, systems=args.systems, save_name=args.save_name,
               poll_s=args.poll_s, settle_s=args.settle_s, allow_window=args.allow_window,
               rule=args.rule, act=args.act, game_log=args.game_log, marker=args.marker)
    return 0 if meta.get("overall_verdict") in EVIDENCE_VERDICTS else 1


if __name__ == "__main__":
    raise SystemExit(main())
