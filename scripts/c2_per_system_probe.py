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
