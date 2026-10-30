#!/usr/bin/env python3
"""c2_per_system_probe.py — C5 数据面第三发:逐系统下发点 `0x3B1330` 的只读 shot。

**这一发问的是什么**(§80.4 的 hand-off,靶位由 §81.1 逐字节钉死):

  * 容器 `[[0x3260BB0]+0x590]` 的**原始条数**(`+0x59C`)与那批 4 B id;
  * `every_system` 的循环**每轮下发几次**(guard 按 `[self] == vtable 0x26562D0` 过滤);
  * 下发带过去的 id 去重后有几种 —— 每轮次数 == distinct id 数才是「每系统一次」。

**为什么钩 `0x3B1330` 而不是循环头 `0x1A762A0`**:循环体内部写 `[rsp+0x28]`、读
`[rbp+0xC0]`,而 C-ABI detour 让被调函数体跑在 detour 的帧上(§81.1 ⑤)。

**verdict 值域**(`VERDICTS`,环境档在前):

  * `instrument_broken` —— layout 靶位不符 / 装着但 hook 丢了;
  * `script_refused` / `no_calls` / `filter_missed` / `dedupe_full` / `container_unreadable`
    / `dispatch_denominator_mismatch` —— 环境或仪器档,**不是**证据;
  * `ids_out_of_range` / `ids_not_in_container` / `loop_not_per_system` —— 判负;
  * `per_system_loop_filtered` —— 每轮次数 < 原始条数,但 id 唯一且都在容器里:
    `[obj+0x137C] == 0` 的系统被引擎自己的过滤位筛掉了(§81.1 ④),**不是判负**;
  * `per_system_loop` —— 每轮次数 == 原始条数,id 唯一、都在容器里、都落在 `[1,N]`。

**这一发不能说的**(写进 §81.2 时逐条保留):
  1. 下发次数 = 过滤后系统数,不证明子效果在每个 system scope 里执行成功;
  2. id 是 `[obj+8]` 的 4 B 值,`⊆ [1,N]` 不等于「它就是 `system_id`」;
  3. `container["ids"]` 是**活数据**的一次快照,只认一次读足的 blob。

判读纯函数由 `python3 -m pytest scripts/test_c2_per_system_probe.py -q` 覆盖,无游戏、
无 Windows API。
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys

# --- wire contract (the DLL's own constants; drift = a red fence) -----------------

TARGET_RVA = 0x3B1330          # offsets.keyword_reg.RVA_EFFECT_BASE_PARSE (§81.1 ③)
VTABLE_RVA = 0x26562D0         # offsets.keyword_reg.RVA_EVERY_SYSTEM_VTABLE (§81.1 ②)
GALAXY_DB_RVA = 0x3260BB0      # §81.1 ④
GALAXY_IDS_OFF = 0x590
GALAXY_COUNT_OFF = 0x59C

ENTRY_SIZE = 32                # layoutInto word 1
STATS_SIZE = 512               # fixed stats buffer the export writes into
LAYOUT_WORDS = 6
RING_LEN = 2048
PROLOGUE_LEN = 32              # EXPECTED_CODE length in the Zig module

STATS_KEYS = (
    "calls",
    "matched",
    "distinct_ids",
    "dedupe_full",
    "null_scope",
    "patch_size",
    "installed",
    "verify",
    "last_id",
)

VERDICTS = (
    "instrument_broken",
    "script_refused",
    "no_calls",
    "filter_missed",
    "dedupe_full",
    "container_unreadable",
    "dispatch_denominator_mismatch",
    "ids_out_of_range",
    "ids_not_in_container",
    "loop_not_per_system",
    "per_system_loop_filtered",
    "per_system_loop",
)
EVIDENCE_VERDICTS = (
    "ids_out_of_range",
    "ids_not_in_container",
    "loop_not_per_system",
    "per_system_loop_filtered",
    "per_system_loop",
)

EXIT_REFUSED = 2               # pre-fire refusals (same code as `gate_install`)

# The supervisor's only command channel (name **and** directory are part of the channel).
SUPERVISOR_CMD_NAME = "ns_game_cmd.txt"
SUPERVISOR_CMD_DIR = "C:/temp"
DEFAULT_CMD_FILE = "C:\\temp\\" + SUPERVISOR_CMD_NAME


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
        except ValueError as exc:  # a non-numeric value is a malformed artifact
            raise ValueError(f"stats value for {key!r} is not an integer: {value!r}") from exc
    missing = [key for key in STATS_KEYS if key not in out]
    if missing:
        raise ValueError(f"stats line is missing {missing}: {text!r}")
    return out


def decode_layout(words):
    """Six words -> dict. `words[4]` is the target RVA (0x3B1330)."""
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
    eid, mask, vt, occ, obj, scope = struct.unpack("<IIIIQQ", blob)
    return {
        "id": eid,
        "mask": mask,
        "self_vtable_rva": vt,
        "occurrences": occ,
        "obj": obj,
        "scope_ptr": scope,
    }


def decode_container(blob, count):
    """The 4 B id vector, read in ONE go — `count` must match the blob exactly.

    Reading the count and the vector in two steps gives a set that never coexisted
    (`+0x590` is live data). The blob's length is the only authority here.
    """
    if count < 0 or len(blob) != count * 4:
        raise ValueError(
            f"container blob is {len(blob)} bytes but the count says {count} ids "
            f"({count * 4} bytes) — the two reads did not agree"
        )
    return list(struct.unpack(f"<{count}I", blob)) if count else []


# --- judgement --------------------------------------------------------------------


def verdict(stats, rows, container, *, expected, script_sends, log_hits, layout=None):
    """The single judgement. Environment classes first; `instrument_broken` wins over all."""
    if layout is not None and layout.get("target_rva") != TARGET_RVA:
        return "instrument_broken"
    if stats["installed"] == 1 and stats["verify"] != 0:
        return "instrument_broken"
    if log_hits == 0:
        return "script_refused"
    if stats["calls"] == 0:
        return "no_calls"
    if stats["matched"] == 0:
        return "filter_missed"
    if stats["dedupe_full"] != 0:
        return "dedupe_full"
    if not container or not container.get("ids"):
        return "container_unreadable"
    if container["raw_count"] != len(container["ids"]):
        return "container_unreadable"
    if container["raw_count"] != expected:
        return "dispatch_denominator_mismatch"

    guard_ids = {row["id"] for row in rows}
    if any(not (1 <= eid <= expected) for eid in guard_ids):
        return "ids_out_of_range"
    if not guard_ids <= set(container["ids"]):
        return "ids_not_in_container"

    runs = script_sends
    if runs <= 0 or stats["matched"] % runs != 0:
        return "loop_not_per_system"
    per_run = stats["matched"] // runs
    if stats["distinct_ids"] != per_run or per_run > container["raw_count"]:
        return "loop_not_per_system"
    if per_run == container["raw_count"]:
        return "per_system_loop"
    return "per_system_loop_filtered"


def install_decision(rc, layout):
    """`ok` | `refused` (码表非零) | `stale_target` (layout 靶位不是 §81.1 的那个)。"""
    if rc != 0:
        return "refused"
    if layout.get("target_rva") != TARGET_RVA:
        return "stale_target"
    return "ok"


def script_marker(script):
    """The literal prefix `log = "…"` leaves in game.log, or None.

    `PS_HIT` has no bracket and survives whole; a `[This.GetName]` tail never appears
    literally, so the marker must stop at the first `[`.
    """
    if 'log = "' not in script:
        return None
    literal = script.split('log = "', 1)[1].split('"', 1)[0]
    return literal.split("[", 1)[0] or None


# --- artifact ---------------------------------------------------------------------


def artifact_rows(rows):
    """The six columns of the artifact's data rows, in `Entry` field order."""
    return [
        "\t".join((
            str(row["id"]),
            f"0x{row['mask']:x}",
            f"0x{row['self_vtable_rva']:x}",
            str(row["occurrences"]),
            f"0x{row['obj']:x}",
            f"0x{row['scope_ptr']:x}",
        ))
        for row in rows
    ]


def build_meta(**kwargs):
    """`k=v` lines, sorted by key, for the artifact's `#meta` block."""
    return [f"{key}={kwargs[key]}" for key in sorted(kwargs)]


# --- pre-fire gates ---------------------------------------------------------------


def sha_gate(path):
    """Print-and-record the sha256 of the file we are about to inject. Missing = exit 2."""
    if not os.path.exists(path):
        raise SystemExit(EXIT_REFUSED)
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def preflight_paths(script_file, cmd_file):
    """Two refusals before the shot costs a window (each costs a whole shot when missed)."""
    if not script_file or not os.path.exists(script_file):
        raise SystemExit(EXIT_REFUSED)
    # Windows paths on a Linux test host: split on the backslash explicitly, because
    # `os.path.dirname` treats `\` as an ordinary character here.
    normalised = cmd_file.replace("/", "\\")
    parts = normalised.rsplit("\\", 1)
    if len(parts) != 2:
        raise SystemExit(EXIT_REFUSED)
    directory, name = parts[0], parts[1]
    if name != SUPERVISOR_CMD_NAME:
        raise SystemExit(EXIT_REFUSED)
    expected_dir = SUPERVISOR_CMD_DIR.replace("/", "\\")
    if directory.lower() != expected_dir.lower():
        raise SystemExit(EXIT_REFUSED)


def refuse_if_resident(dll_name, base):
    """A same-name module already mapped means the loader reuses the old image."""
    if base:
        raise SystemExit(EXIT_REFUSED)


# --- live path (Windows only; not exercised by the host tests) ---------------------


def count_marker(text, marker):
    """How many times the engine's own receipt line appears in the log delta."""
    if not marker or not text:
        return 0
    return text.count(marker)


def _signed32(value):
    value &= 0xFFFF_FFFF
    return value - 0x1_0000_0000 if value & 0x8000_0000 else value


def _write_artifact(path, meta, rows):
    """Meta first, then rows: the artifact is what survives a lost stdout."""
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for line in meta:
            handle.write(f"#meta {line}\n")
        for line in rows:
            handle.write(line + "\n")


def read_container(pid, exe_base):
    """One live read of the galaxy id vector. `None` = unreadable (never an exception)."""
    import c2_harness as harness

    try:
        obj = struct.unpack("<Q", harness.read_memory(pid, exe_base + GALAXY_DB_RVA, 8))[0]
        count = struct.unpack("<I", harness.read_memory(pid, obj + GALAXY_COUNT_OFF, 4))[0]
        if not 0 < count <= 1_000_000:      # an out-of-range count is a reading, not a licence
            return None
        vec = struct.unpack("<Q", harness.read_memory(pid, obj + GALAXY_IDS_OFF, 8))[0]
        blob = harness.read_memory(pid, vec, count * 4)
        return {"raw_count": count, "ids": decode_container(blob, count)}
    except Exception:                        # noqa: BLE001 — an unreadable read is a verdict
        return None


def read_stats(pid, base, exports, buf):
    import c2_harness as harness

    harness.call_remote_with_arg(pid, base, exports["C5PerSystemStatsInto"], buf)
    raw = harness.read_memory(pid, buf, STATS_SIZE)
    text = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
    return parse_stats(text)


def drain_entries(pid, base, exports, buf):
    import c2_harness as harness

    count = harness.call_remote_with_arg(pid, base, exports["C5PerSystemDrainInto"], buf)
    count = min(count & 0xFFFF_FFFF, RING_LEN)
    if count == 0:
        return []
    blob = harness.read_memory(pid, buf, count * ENTRY_SIZE)
    return [decode_entry(blob[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE]) for i in range(count)]


def send_script(cmd_file, script, game_log, wait_s):
    """Send one console script; return `(delivered, hits)`.

    `delivered` is the transport receipt (the supervisor's `.seen` key moved). `hits` is
    the engine-side receipt: how many times the script's own `log = "…"` marker appeared
    in the log delta. A delivered-but-unmarked script was refused by the engine.
    """
    import time

    from c4_wiring_probe import GAME_LOG, _file_size_or_none, _read_text_from

    log_path = os.path.expanduser(game_log or GAME_LOG)
    offset = _file_size_or_none(log_path)
    seen_path = os.path.splitext(cmd_file)[0] + ".seen"

    def _seen():
        try:
            with open(seen_path, encoding="ascii", errors="replace") as handle:
                return handle.read().strip()
        except OSError:
            return None

    before = _seen()
    tmp = cmd_file + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as handle:
        handle.write("console " + script + "\n")
    os.replace(tmp, cmd_file)

    marker = script_marker(script)
    deadline = time.time() + wait_s
    delivered = False
    while time.time() < deadline:
        if _seen() != before:
            delivered = True
            break
        time.sleep(0.25)
    if not delivered:
        return False, 0

    while time.time() < deadline:
        try:
            hits = count_marker(_read_text_from(log_path, offset) or "", marker)
        except OSError:
            hits = 0
        if hits:
            return True, hits
        time.sleep(0.25)
    return True, 0


def gate_module(pid, dll_path, needed):
    """Check the export names in the FILE, gate the world state, then inject."""
    import c2_harness as harness

    exports = harness.list_exports(dll_path)
    missing = [name for name in needed if name not in exports]
    if missing:
        print(f"[persystem] {dll_path} is missing {missing} — refusing to inject", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)

    dll_name = os.path.basename(dll_path.replace("\\", "/"))
    print(f"[persystem] pid={pid}  dll={dll_path}")
    try:
        resident = harness.resolve_base_address(pid, dll_name)
    except RuntimeError:
        resident = None
    refuse_if_resident(dll_name, resident)

    from world_probe import gate_install  # pyright: ignore[reportMissingImports]

    gate_install("persystem")
    harness.inject_dll(pid, dll_path)
    harness.assert_game_alive(pid)
    base = harness.resolve_base_address(pid, dll_name)
    print(f"[persystem] {dll_name} base: 0x{base:x}")

    head = harness.read_memory(pid, base, 2)
    assert head == b"MZ", f"bad header at 0x{base:x}: {head!r}"
    sanity = _signed32(harness.call_remote(pid, base, exports["C2Sanity"]))
    assert sanity == 42, f"C2Sanity returned {sanity}, expected 42"
    harness.assert_game_alive(pid)
    print("[persystem] C2Sanity == 42, game alive — dispatch authorized")
    return base, exports


def run(dll_path, out_path, *, systems, save_name, script_file, game_log=None,
        cmd_file=DEFAULT_CMD_FILE, poll_s=120.0, settle_s=3.0, script_wait_s=180.0):
    """One shot in one game process. Cleanup runs in a finally; never FreeLibrary."""
    import time

    import c2_harness as harness

    preflight_paths(script_file, cmd_file)
    dll_sha = sha_gate(dll_path)
    print(f"[persystem] dll={dll_path} sha256={dll_sha}")

    pid = harness.resolve_pid("stellaris.exe")
    needed = [name for name in harness.list_exports(dll_path) if name.startswith("C5PerSystem")]
    base, exports = gate_module(pid, dll_path, needed)
    exe_base = harness.resolve_base_address(pid, "stellaris.exe")

    stats_buf = harness.remote_alloc(pid, STATS_SIZE)
    drain_cap = RING_LEN * ENTRY_SIZE
    drain_buf = harness.remote_alloc(pid, drain_cap)

    layout_buf = harness.remote_alloc(pid, LAYOUT_WORDS * 4)
    harness.call_remote_with_arg(pid, base, exports["C5PerSystemLayout"], layout_buf)
    layout = decode_layout(struct.unpack("<6I", harness.read_memory(pid, layout_buf, LAYOUT_WORDS * 4)))

    harness.call_remote(pid, base, exports["C5PerSystemReset"])
    install_rc = _signed32(harness.call_remote(pid, base, exports["C5PerSystemInstall"]))
    decision = install_decision(install_rc, layout)
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
        "layout_target_rva": f"0x{layout['target_rva']:x}",
        "overall_verdict": "instrument_broken" if decision != "ok" else "",
        "host_alive": 1,
        "entries_error": 0,
    }
    if decision != "ok":
        _write_artifact(out_path, build_meta(**meta), [])
        return meta

    rows, container, hits, sends = [], None, 0, 0
    uninstall_rc, verify_rc, alive = None, None, False
    try:
        time.sleep(settle_s)
        before = read_stats(pid, base, exports, stats_buf)
        container = read_container(pid, exe_base)

        script = open(script_file, encoding="utf-8").read().strip().splitlines()[0]
        sends = 1
        delivered, hits = send_script(cmd_file, script, game_log, script_wait_s)
        print(f"[persystem] script delivered={delivered} hits={hits}")

        deadline = time.time() + poll_s
        after = before
        while time.time() < deadline:
            time.sleep(1.0)
            after = read_stats(pid, base, exports, stats_buf)
            if after["matched"] >= systems or (hits and after["matched"] >= hits):
                break

        harness.call_remote_with_arg(pid, base, exports["C5PerSystemSetDrainCap"], drain_cap)
        rows = drain_entries(pid, base, exports, drain_buf)

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
            "log_hits": hits,
            "script_sends": sends,
            "entries": len(rows),
        })
        meta["overall_verdict"] = verdict(delta, rows, container, expected=systems,
                                          script_sends=sends, log_hits=hits, layout=layout)
    finally:
        uninstall_rc = _signed32(harness.call_remote(pid, base, exports["C5PerSystemUninstall"]))
        verify_rc = _signed32(harness.call_remote(pid, base, exports["C5PerSystemVerify"]))
        time.sleep(settle_s)
        try:
            harness.assert_game_alive(pid)
            alive = True
        except Exception:                    # noqa: BLE001 — a dead host is a reading
            alive = False
        if uninstall_rc == -7 or verify_rc != 0:
            print("RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY", file=sys.stderr)

    meta.update({"uninstall_rc": uninstall_rc, "verify_rc": verify_rc, "host_alive": int(alive)})
    _write_artifact(out_path, build_meta(**meta), artifact_rows(rows))
    print(f"[persystem] verdict={meta['overall_verdict']}  artifact={out_path}")
    return meta


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", nargs="?", default=r"C:\temp\sqjs_c7.dll")
    parser.add_argument("--systems", type=int, required=True,
                        help="current campaign's star count (no default: 787 belongs elsewhere)")
    parser.add_argument("--save-name", required=True)
    parser.add_argument("--script-file", required=True)
    parser.add_argument("--game-log", default=None)
    parser.add_argument("--cmd-file", default=DEFAULT_CMD_FILE)
    parser.add_argument("--poll-s", type=float, default=120.0)
    parser.add_argument("--settle-s", type=float, default=3.0)
    parser.add_argument("--script-wait-s", type=float, default=180.0)
    parser.add_argument("--out", default="C:/temp/c5_per_system.tsv")
    args = parser.parse_args(argv)

    meta = run(args.dll, args.out, systems=args.systems, save_name=args.save_name,
               script_file=args.script_file, game_log=args.game_log, cmd_file=args.cmd_file,
               poll_s=args.poll_s, settle_s=args.settle_s, script_wait_s=args.script_wait_s)
    return 0 if meta.get("overall_verdict") in EVIDENCE_VERDICTS else 1


if __name__ == "__main__":
    raise SystemExit(main())
