#!/usr/bin/env python3
"""c2_trigger_pred_probe.py — C5 数据面:触发谓词基体 `0x349230` 的只读采样 shot。

**这一发问的是什么**(§75 的下一个问题,不是「scope 是谁」):
一个 trigger 在 `every_system` 的 `limit` 里,谓词 `[vptr+0x80]` 被调**几次**,以及每次拿到的
第 2 实参 X 长什么样。两个方向都算读数:

  * `predicate_per_system`       —— 匹配次数 ≈ 星系数 ⇒ 每系统各一次,下一步问 X 的身份字段。
  * `predicate_instantiate_once` —— 匹配次数 == 1 ⇒ 谓词只是实例化期的一次性检查,
                                    下一靶 = 求值槽 `+0x28`(§75 读数 3 已把它的实参形状钉好)。

**只读**:detour 恒转发原函数,不写引擎内存、不重指向 `[self+0]`、不改寄存器。
`[self+0x38]` 是唯一的引擎读(§23.2 的 trigger id),X 只按值记录、不解引用。

**verdict 值域**(`VERDICTS`):两档证据 + 四档环境。`no_calls` **不是**证据 —— 它只说
「本窗口没观测到」,§57.4 的反面口径照旧。`instrument_broken` 优先于一切读数。

**这一发不能说的**(写进 §76 时逐条保留):
  1. `predicate_per_system` 不证明「X 就是那个系统对象」—— §75.5 已把 X 读成解析上下文。
  2. `predicate_instantiate_once` 不证明「这一族不走谓词」—— 只说明**这条脚本形状**下谓词没按系统走。
  3. 两段脚本的 `token_matched` 是**两个窗口**,artifact 里分开记(`stats_a` / `stats_b`),不合并。

用法与判读陷阱见 `docs/offline-tooling.md` 的同名一节;门序与码表见本文件 `main()` 与 `run()`。
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import time

import c2_harness as harness

DEFAULT_DLL = r"C:\temp\sqjs_c4.dll"
DEFAULT_OUT = r"C:/temp/c4_trig_pred.tsv"
DEFAULT_CMD_FILE = r"C:\temp\ns_game_cmd.txt"  # the supervisor's real channel (c4_wiring_probe.SUPERVISOR_CMD)
EXE_MODULE = "stellaris.exe"

TARGET_RVA = 0x349230        # offsets.keyword_reg.RVA_TRIGGER_PREDICATE (§75)
ENTRY_SIZE = 40              # layoutInto word 1
STATS_SIZE = 512             # fixed stats buffer the export writes into
LAYOUT_WORDS = 6
RING_LEN = 256
LAYOUT_VERSION = 1
PROLOGUE_LEN = 32            # 21 B are shared with 0x3B1420 — 32 is the distinguishing length

STATS_KEYS = (
    "calls",
    "token_matched",
    "samples",
    "x_null",
    "patch_size",
    "installed",
    "verify",
    "last_token",
)

VERDICTS = (
    "predicate_per_system",
    "predicate_instantiate_once",
    "token_absent",
    "script_refused",
    "instrument_broken",
    "no_calls",
)
EVIDENCE_VERDICTS = ("predicate_per_system", "predicate_instantiate_once")

NEEDED_EXPORTS = (
    "C2Sanity",
    "C1Run",
    "C4TrigPredInstall",
    "C4TrigPredUninstall",
    "C4TrigPredVerify",
    "C4TrigPredSetToken",
    "C4TrigPredStatsInto",
    "C4TrigPredDrainInto",
    "C4TrigPredLayout",
    "C4TrigPredReset",
)

POLL_INTERVAL_S = 1.0
POLL_TIMEOUT_S = 120.0
SETTLE_S = 3.0
SCRIPT_WAIT_S = 30.0

EXIT_OK = 0
EXIT_NOT_EVIDENCE = 1
EXIT_INSTRUMENT = 2


# ---------------------------------------------------------------------------
# Pure functions (host tests cover these; no Windows API)
# ---------------------------------------------------------------------------


def _signed32(raw):
    raw &= 0xFFFF_FFFF
    return raw - 0x1_0000_0000 if raw >= 0x8000_0000 else raw


def parse_mask(text):
    """Only 0 is legal: the guard records every matched call (the ring caps at RING_LEN),
    so a non-zero mask would be a promise the DLL does not keep."""
    value = int(str(text), 0)
    if value != 0:
        raise ValueError(
            f"mask {value:#x} is not supported: this probe always records every "
            "matched call (ring caps at RING_LEN), so only --mask 0 is honest"
        )
    return value


def decode_layout(words):
    if len(words) != LAYOUT_WORDS:
        raise ValueError(f"layout needs {LAYOUT_WORDS} words, got {len(words)}")
    return {
        "version": words[0],
        "entry_size": words[1],
        "ring_len": words[2],
        "stats_size": words[3],
        "target_rva": words[4],
        "prologue_len": words[5],
    }


def install_decision(words):
    """Refuse before installing when the DLL's layout is not the one this driver parses."""
    layout = decode_layout(words)
    if layout["version"] != LAYOUT_VERSION:
        return f"layout version {layout['version']} != {LAYOUT_VERSION}"
    if layout["entry_size"] != ENTRY_SIZE:
        return f"entry size {layout['entry_size']} != {ENTRY_SIZE}"
    if layout["ring_len"] != RING_LEN:
        return f"ring len {layout['ring_len']} != {RING_LEN}"
    if layout["target_rva"] != TARGET_RVA:
        return f"target rva {layout['target_rva']:#x} != {TARGET_RVA:#x}"
    if layout["prologue_len"] != PROLOGUE_LEN:
        return f"prologue len {layout['prologue_len']} != {PROLOGUE_LEN}"
    return None


C1_RESULT_LOG = r"C:\temp\c1_result.log"


def parse_c1_result(text):
    """`C1 OK: trigger_id=<N> effect_id=<M>` -> N, or 0.

    Fallback for a process where `neo_effect` was already registered by an earlier DLL
    copy: `C1Run` may then fold a duplicate-insert to a non-zero error and return 0, while
    the token the engine minted is still the one in this log.
    """
    import re

    match = re.search(r"trigger_id=(\d+)", text or "")
    return int(match.group(1)) if match else 0


def parse_stats(text):
    """Parse the DLL's one-line k=v stats. Missing or unknown keys are an error, not a
    defaulted zero — a stale DLL that lost a key must not read as 'that counter is 0'."""
    pairs = {}
    for token in text.split():
        if "=" not in token:
            raise ValueError(f"stats token {token!r} is not k=v")
        key, _, raw = token.partition("=")
        if key not in STATS_KEYS:
            raise ValueError(f"unknown stats key {key!r}")
        pairs[key] = int(raw, 0)
    missing = [key for key in STATS_KEYS if key not in pairs]
    if missing:
        raise ValueError(f"stats line is missing {missing}")
    return pairs


def decode_entry(raw):
    if len(raw) != ENTRY_SIZE:
        raise ValueError(f"entry needs {ENTRY_SIZE} bytes, got {len(raw)}")
    valid, matched, _pad, token, self_vt, x_vt, _reserved, self_ptr, x_ptr = struct.unpack(
        "<BBHIIII4xQQ", raw
    )
    return {
        "valid": valid,
        "matched": matched,
        "token": token,
        "self_vtable_rva": self_vt,
        "x_vtable_rva": x_vt,
        "self_ptr": self_ptr,
        "x_ptr": x_ptr,
    }


def verdict(stats, entries, systems, refused=False):
    """One window's verdict. Order is pinned: instrument health, then refusal, then counts.

    `systems` is the star count from the campaign's edge table (Task 5). It is a parameter,
    never a constant — 787 belongs to a different save (see chokepoint_table.zig's SAVE_SHA256).
    """
    if stats.get("installed") != 1 or stats.get("verify") != 0:
        return "instrument_broken"
    if refused:
        return "script_refused"
    if stats.get("calls", 0) == 0:
        return "no_calls"
    if stats.get("token_matched", 0) == 0:
        return "token_absent"
    if systems <= 0:
        raise ValueError("systems must be positive")
    if stats["token_matched"] >= 0.9 * systems:
        return "predicate_per_system"
    return "predicate_instantiate_once"


ARTIFACT_COLUMNS = (
    "token",
    "self_ptr",
    "self_vtable_rva",
    "x_ptr",
    "x_vtable_rva",
)


def artifact_rows(entries):
    """Header + one row per retained entry. Columnar on purpose: the join a human wants is
    `x_vtable_rva` against the known vtable map, so both pointers must be their own column."""
    rows = ["\t".join(ARTIFACT_COLUMNS)]
    for e in entries:
        rows.append(
            "\t".join(
                [
                    f"{e['token']:d}",
                    f"0x{e['self_ptr']:x}",
                    f"{e['self_vtable_rva']:#x}",
                    f"0x{e['x_ptr']:x}",
                    f"{e['x_vtable_rva']:#x}",
                ]
            )
        )
    return rows


def write_tsv(path, rows, meta):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        for key, value in meta.items():
            f.write(f"# {key}\t{value}\n")
        for row in rows:
            f.write(row + "\n")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Live path (Windows only; not exercised by the host tests)
# ---------------------------------------------------------------------------


def gate_module(pid, dll_path, needed):
    """Check the export names in the FILE, gate the world state, then inject."""
    exports = harness.list_exports(dll_path)
    missing = [name for name in needed if name not in exports]
    if missing:
        raise SystemExit(
            f"{dll_path} is missing {missing} — refusing to inject a DLL that cannot "
            "answer this shot's calls (a stale upload would sample the wrong target)"
        )

    dll_name = os.path.basename(dll_path)
    print(f"[trigpred] pid={pid}  dll={dll_path}")
    # The world-state gate (spec §1): a shot that cannot prove the premise must not inject.
    from world_probe import gate_install  # pyright: ignore[reportMissingImports]

    gate_install("trigpred")
    harness.inject_dll(pid, dll_path)
    harness.assert_game_alive(pid)
    base = harness.resolve_base_address(pid, dll_name)
    print(f"[trigpred] {dll_name} base (64-bit): 0x{base:x}")

    head = harness.read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    sanity = _signed32(harness.call_remote(pid, base, exports["C2Sanity"]))
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch against "
        "this module copy"
    )
    harness.assert_game_alive(pid)
    print("[trigpred] C2Sanity == 42, game alive — dispatch authorized")
    return base, exports


_dispatched = set()


def dispatch_once(pid, base, rva, name, arg=None):
    """One install per process; a second would answer -2 and be misread as a verdict."""
    if name in _dispatched:
        raise RuntimeError(f"{name} was already dispatched in this session")
    _dispatched.add(name)
    if arg is None:
        return _signed32(harness.call_remote(pid, base, rva))
    return _signed32(harness.call_remote_with_arg(pid, base, rva, arg))


def read_layout_words(pid, base, exports):
    buf = harness.remote_alloc(pid, 32)
    harness.call_remote_with_arg(pid, base, exports["C4TrigPredLayout"], buf)
    return struct.unpack("<6I", harness.read_memory(pid, buf, LAYOUT_WORDS * 4))


def reset_probe(pid, base, exports):
    harness.call_remote(pid, base, exports["C4TrigPredReset"])
    harness.assert_game_alive(pid)


def arm_token(pid, base, exports, token):
    rc = _signed32(harness.call_remote_with_arg(
        pid, base, exports["C4TrigPredSetToken"], token))
    assert rc == 0, f"C4TrigPredSetToken returned {rc}"
    harness.assert_game_alive(pid)


def install_probe(pid, base, exports):
    rc = dispatch_once(pid, base, exports["C4TrigPredInstall"], "C4TrigPredInstall")
    harness.assert_game_alive(pid)
    return rc


def read_stats(pid, base, exports, buf):
    harness.call_remote_with_arg(pid, base, exports["C4TrigPredStatsInto"], buf)
    raw = harness.read_memory(pid, buf, STATS_SIZE)
    text = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
    return parse_stats(text), text


def drain_entries(pid, base, exports, buf):
    count = harness.call_remote_with_arg(pid, base, exports["C4TrigPredDrainInto"], buf)
    count = min(count & 0xFFFF_FFFF, RING_LEN)
    if count == 0:
        return []
    blob = harness.read_memory(pid, buf, count * ENTRY_SIZE)
    return [decode_entry(blob[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE]) for i in range(count)]


def script_marker(script):
    """The literal prefix this script will leave in game.log, or None.

    The script's `log = "TS_NEO_[This.GetName]"` is substituted per system, so the literal
    `[This.GetName]` never appears in the log: the marker must stop at the first `[`. Getting
    this wrong makes every window read `script_refused` even when the script ran.
    """
    if 'log = "' not in script:
        return None
    literal = script.split('log = "', 1)[1].split('"', 1)[0]
    return literal.split("[", 1)[0] or None


def send_script(cmd_file, script, game_log, wait_s):
    """Send one console script and wait for its log marker.

    Returns True when the marker appeared (the script really ran), False otherwise — and
    False is `script_refused`, **not** `no_calls`: a script that never executed tells us
    nothing about the predicate. The console-send protocol is `c4_wiring_probe`'s (its
    `.seen` handshake is the only proven one), so it is imported rather than re-invented.
    """
    from c4_wiring_probe import GAME_LOG, _file_size_or_none, _read_text_from, _send_console

    log_path = os.path.expanduser(game_log or GAME_LOG)
    offset = _file_size_or_none(log_path)
    if not _send_console(cmd_file, script):
        return False
    marker = script_marker(script)
    if marker is None:
        return True
    deadline = time.time() + wait_s
    while time.time() < deadline:
        if offset is not None:
            try:
                if marker in (_read_text_from(log_path, offset) or ""):
                    return True
            except OSError:
                pass
        time.sleep(0.25)
    return False


def _cleanup(pid, base, exports, settle_s):
    uninstall_rc = dispatch_once(pid, base, exports["C4TrigPredUninstall"],
                                 "C4TrigPredUninstall")
    verify_rc = _signed32(harness.call_remote(pid, base, exports["C4TrigPredVerify"]))
    time.sleep(settle_s)
    alive = True
    try:
        harness.assert_game_alive(pid)
    except Exception:  # noqa: BLE001 — a dead host is a reading, not a crash
        alive = False
    if uninstall_rc == -7 or verify_rc != 0:
        print("RESTORE_INCOMPLETE_DO_NOT_FREELIBRARY", file=sys.stderr)
    return {"uninstall_rc": uninstall_rc, "verify_rc": verify_rc, "host_alive": int(alive)}


def run(pid, dll_path, scripts, systems, out_path, cmd_file, game_log,
        poll_s, settle_s):
    base, exports = gate_module(pid, dll_path, NEEDED_EXPORTS)

    layout = decode_layout(read_layout_words(pid, base, exports))
    refusal = install_decision(tuple(layout.values()))
    if refusal:
        raise SystemExit(f"layout refuses install: {refusal}")

    reset_probe(pid, base, exports)
    rc = install_probe(pid, base, exports)
    if rc != 0:
        raise SystemExit(
            f"C4TrigPredInstall returned {rc} (0 ok | -2 already installed / predicate "
            "armed | -3 no module | -4 already hooked | -5 prologue | -6 patch width) — "
            "do not retry in this process"
        )

    cleanup = {"uninstall_rc": -999, "verify_rc": -999, "host_alive": 0}
    try:
        trigger_token = _signed32(harness.call_remote(pid, base, exports["C1Run"]))
        print(f"[trigpred] C1Run trigger token = {trigger_token}")
        if trigger_token <= 0:
            try:
                with open(C1_RESULT_LOG, encoding="utf-8", errors="replace") as f:
                    trigger_token = parse_c1_result(f.read())
            except OSError:
                trigger_token = 0
            print(f"[trigpred] C1Run returned {trigger_token} from the log fallback")

        stats_buf = harness.remote_alloc(pid, STATS_SIZE)
        baseline, baseline_text = read_stats(pid, base, exports, stats_buf)
        print(f"[trigpred] baseline: {baseline_text.strip()}")

        windows = []
        previous = baseline
        for label, script, token in scripts:
            if token is None:
                token = trigger_token
            if token <= 0:
                raise SystemExit(
                    "C1Run did not return a trigger token — the DLL could not register "
                    "neo_effect, so window A would arm a token nothing can match"
                )
            arm_token(pid, base, exports, token)
            sent = send_script(cmd_file, script, game_log, SCRIPT_WAIT_S)
            stats, text = read_stats(pid, base, exports, stats_buf)
            delta = dict(stats)
            for key in ("calls", "token_matched", "x_null"):
                delta[key] = stats[key] - previous[key]
            previous = stats
            windows.append({"label": label, "sent": sent, "stats": delta,
                            "raw": stats, "text": text})
            print(f"[trigpred] window {label}: sent={sent} delta={delta} raw={text.strip()}")

        deadline = time.time() + poll_s
        while time.time() < deadline:
            time.sleep(POLL_INTERVAL_S)
        final_stats, final_text = read_stats(pid, base, exports, stats_buf)
        print(f"[trigpred] final stats: {final_text.strip()}")

        per_window = []
        for w in windows:
            per_window.append(
                (w["label"],
                 verdict(w["stats"], [], systems, refused=not w["sent"]))
            )
        evidence = [v for _l, v in per_window if v in EVIDENCE_VERDICTS]
        overall = evidence[0] if evidence else per_window[0][1]

    finally:
        cleanup = _cleanup(pid, base, exports, settle_s)

    meta = {
        "target_rva": f"{TARGET_RVA:#x}",
        "systems": systems,
        "poll_s": poll_s,
        "settle_s": settle_s,
        "overall_verdict": overall,
        "verdict_a": per_window[0][1] if per_window else "-",
        "verdict_b": per_window[1][1] if len(per_window) > 1 else "-",
        "stats_a_raw": windows[0]["text"].strip() if windows else "-",
        "stats_a_delta": str(windows[0]["stats"]) if windows else "-",
        "stats_b_raw": windows[1]["text"].strip() if len(windows) > 1 else "-",
        "stats_b_delta": str(windows[1]["stats"]) if len(windows) > 1 else "-",
        "stats_final": final_text.strip(),
        "sent_a": int(windows[0]["sent"]) if windows else 0,
        "sent_b": int(windows[1]["sent"]) if len(windows) > 1 else 0,
        "uninstall_rc": cleanup["uninstall_rc"],
        "verify_rc": cleanup["verify_rc"],
        "host_alive": cleanup["host_alive"],
        "trigger_token": trigger_token,
        "layout": " ".join(f"{k}={v}" for k, v in layout.items()),
    }
    # Artifact first, drain second: a bad drain must not cost the stats line.
    write_tsv(out_path, artifact_rows([]), meta)
    try:
        entries = drain_entries(pid, base, exports, stats_buf)
    except Exception as err:  # noqa: BLE001 — entries are a witness, not the verdict
        entries = []
        meta["entries_error"] = repr(err)
        print(f"[trigpred] drain failed: {err!r}", file=sys.stderr)
    write_tsv(out_path, artifact_rows(entries), meta)
    print(f"[trigpred] artifact: {out_path}  entries={len(entries)}  verdict={overall}")

    if overall == "instrument_broken":
        return EXIT_INSTRUMENT
    return EXIT_OK if overall in EVIDENCE_VERDICTS else EXIT_NOT_EVIDENCE


def _script_lines(path):
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dll", nargs="?", default=DEFAULT_DLL)
    parser.add_argument("--mask", default="0", help="only 0 is supported (see parse_mask)")
    parser.add_argument("--poll-s", dest="poll_s", type=float, default=POLL_TIMEOUT_S,
                        help="post-script observation window; frequency comes from calls")
    parser.add_argument("--settle-s", dest="settle_s", type=float, default=SETTLE_S)
    parser.add_argument("--systems", type=int, required=True,
                        help="star count of the CURRENT campaign (Task 5's edge table); "
                             "787 belongs to another save and must not be defaulted")
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--cmd-file", dest="cmd_file", default=DEFAULT_CMD_FILE)
    parser.add_argument("--game-log", dest="game_log", default=None)
    parser.add_argument("--script-file", dest="script_file", default=None,
                        help="file with one console script per line; line 1 uses the C1 "
                             "trigger token, line 2 the official is_rim_system token")
    parser.add_argument("--rim-token", dest="rim_token", type=int, default=18203,
                        help="token of the official system-scoped trigger in line 2 "
                             "(is_rim_system = 18203)")
    args = parser.parse_args(argv)

    try:
        parse_mask(args.mask)
    except ValueError as err:
        print(f"[trigpred] {err}", file=sys.stderr)
        return EXIT_INSTRUMENT

    if args.script_file is None:
        print("[trigpred] --script-file is required for a shot: without a script the "
              "predicate is never evaluated and the reading is meaningless", file=sys.stderr)
        return EXIT_INSTRUMENT
    lines = _script_lines(args.script_file)
    if not lines:
        print("[trigpred] --script-file has no scripts", file=sys.stderr)
        return EXIT_INSTRUMENT

    pid = harness.resolve_pid(EXE_MODULE)
    # Window A's token is only known after C1Run; None tells run() to use it.
    scripts = [("neo_effect", lines[0], None)]
    if len(lines) > 1:
        scripts.append(("is_rim_system", lines[1], args.rim_token))
    return run(pid, args.dll, scripts, args.systems, args.out, args.cmd_file,
               args.game_log, args.poll_s, args.settle_s)


if __name__ == "__main__":
    sys.exit(main())
