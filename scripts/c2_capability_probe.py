#!/usr/bin/env python3
"""c2_capability_probe.py — C3 运行时能力自检的驱动(装 DLL → 等一次派发 → 读矩阵 → 判词)。

**这一发问的是什么**(spec §3.1):进程第一次逐系统派发时,`capability.maybeRun` 用当次的
**真实 scope** 跑七项断言,结果是一张 7×8 B 的矩阵。驱动只做三件事:

  1. 把 DLL 装上(或复用已经常驻的那一份),读 `C3CapabilityLayout` 对账;
  2. `C3CapabilityReset` 之后等一次逐系统派发,再读 `C3CapabilityStatsInto` 的 56 B;
  3. 扫日志里的 `NEO_CAP` 行与脚本侧见证 `NEO_CAP_VAR_OK`,调 `fold_verdict` 打一行判词。

**v1 只报告**:本驱动不装新的 hook、不改引擎字节。要拿到 `neo_action` 的逐系统派发,
进程里必须已经有 C5-ADD 那条通道(`C2NeoInstall`);本驱动只在 DLL 不是常驻时补装那一条。

**五档判词**(spec §3.4):

  * `instrument_broken` —— layout 版本不符 / 矩阵读不出(导出缺失在更早的门口就拒装);
  * `environment` —— 窗内没有一次逐系统派发(`NEO_JS_CALL` 增量 0);
  * `capability_failed` —— 至少一项 `fail`(原因码逐个列在 `failed` 里);
  * `capability_partial` —— 没有 `fail`,但有 `skip`,或缺脚本侧见证;
  * `capability_named` —— 七项全 `ok`/`presence_only`,且见证 `NEO_CAP_VAR_OK ≥ 1`。

**这一发不能说的**(spec §7,逐条保留):

  1. 七项全过 **不** 等于版本兼容 —— 它只覆盖我们写下来的那 7 条断言;
  2. 自检本身依赖地址:RVA 先由 drift 报告找到,自检只是「在活体里再确认一次」;
  3. `state` 那一项会写存档状态(一个值为 0 的 `neo_cap_probe`),失败也只报告,不回滚。

用法(Windows 侧,经 `session_bridge` 进 session 1):

    python C:/temp/session_bridge.py --timeout-s 400 C:/temp/c2_capability_probe.py \
        C:/temp/sqjs_cap1.dll --systems 787 --save-name autosave_2282.01.01
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys

# --- wire contract (the DLL's own constants; drift = a red fence) -----------------

LAYOUT_VERSION = 1
LAYOUT_WORDS = 2                # `layoutInto`: [version, check_count]
CHECK_COUNT = 7
STATS_SIZE = CHECK_COUNT * 8    # 每项 `u32 status, u32 reason`

#: 矩阵顺序 = `capability.zig` 的 `Check` 枚举序(`test_check_ids_match_the_dll_order` 钉住)。
CHECK_IDS = ("scope", "token", "descriptor", "graph", "state", "vtable", "fingerprint")

#: `Status`(spec §3.2):`0 = skip`、`1 = ok`、`2 = fail`、`3 = presence_only`。
STATUSES = {0: "skip", 1: "ok", 2: "fail", 3: "presence_only"}

#: `Reason` 的稳定小整数表,与 Zig 的 `Reason` 同名同值(`test_reasons_match_the_dll_enum` 钉住)。
REASONS = {
    0: "none",
    1: "unreadable",
    2: "mismatch",
    3: "no_scope",
    4: "out_of_range",
    5: "write_rejected",
    6: "not_cleared",
}

STATUS_SKIP = 0
STATUS_OK = 1
STATUS_FAIL = 2
STATUS_PRESENCE = 3
REASON_NOT_CLEARED = 6

#: `state` 那一项的脚本侧见证:mod 的 `limit = { is_variable_set = neo_cap_probe }` 之后
#: 打的 `log`。只在**增量**里数(窗口开始时的偏移见 `run`)。
WITNESS = "NEO_CAP_VAR_OK"
CAP_MARKER = "NEO_CAP "

#: 逐系统派发在 `neo_js.log` 里的行(`neo_js_host.onSystem` 每趟一行)。
DISPATCH_MARKER = "NEO_JS_CALL "

NEO_LOG = r"C:\temp\neo_js.log"
GAME_LOG = "~/Documents/Paradox Interactive/Stellaris/logs/game.log"

#: 常驻判定用的 DLL basename:同名模块已在进程里 ⇒ 不重复注入(一个进程只装一次)。
DLL_NAME = "stellaris_quickjs.dll"

VERDICTS = (
    "instrument_broken",
    "environment",
    "capability_failed",
    "capability_partial",
    "capability_named",
)
EVIDENCE_VERDICTS = ("capability_named",)

EXIT_REFUSED = 2


# --- parsing ----------------------------------------------------------------------


def decode_layout(words):
    """两个词 → dict。`version` 必须是 1,`check_count` 必须是 7(否则仪器口径变了)。"""
    if len(words) != LAYOUT_WORDS:
        raise ValueError(f"layout needs {LAYOUT_WORDS} words, got {len(words)}")
    return {"version": words[0], "check_count": words[1]}


def decode_stats(blob):
    """56 B → 7 个 `(status, reason)`;长度不对就是「矩阵读不出」。"""
    if len(blob) != STATS_SIZE:
        raise ValueError(f"stats need {STATS_SIZE} bytes, got {len(blob)}")
    return [
        struct.unpack_from("<II", blob, i * 8)[0:2] for i in range(CHECK_COUNT)
    ]


def status_name(code):
    return STATUSES.get(code, f"unknown({code})")


def reason_name(code):
    return REASONS.get(code, f"unknown({code})")


# --- judgement --------------------------------------------------------------------


def fold_verdict(layout, stats, log_lines):
    """矩阵 + 日志增量 → `(verdict, detail)`。

    仪器档在前(版本/长度不对就没什么可判的),然后是失败、skip、见证。`detail` 里
    `state_cleared` 与 `missing_witness` 是**报告字段**,不是判词的一部分 ——
    「写过但没置 0」必须能从报告里读出来(Review Focus 1)。
    """
    detail = {
        "checks": {},
        "failed": [],
        "skipped": [],
        "presence": [],
        "missing_witness": True,
        "state_cleared": True,
        "check_count": len(stats),
    }
    if list(layout) != [LAYOUT_VERSION, CHECK_COUNT]:
        detail["layout"] = list(layout)
        return "instrument_broken", detail
    if len(stats) != CHECK_COUNT:
        detail["layout"] = list(layout)
        return "instrument_broken", detail

    witness = any(WITNESS in line for line in log_lines)
    detail["missing_witness"] = not witness

    for name, (status, reason) in zip(CHECK_IDS, stats):
        detail["checks"][name] = f"{status_name(status)}:{reason_name(reason)}"
        if status == STATUS_FAIL:
            detail["failed"].append(f"{name}:{reason_name(reason)}")
        elif status == STATUS_SKIP:
            detail["skipped"].append(name)
        elif status == STATUS_PRESENCE:
            detail["presence"].append(name)
        if name == "state" and status == STATUS_OK and reason == REASON_NOT_CLEARED:
            # 写进去了、但没写回 0:存档里会留一个非 0 的 `neo_cap_probe`。
            detail["state_cleared"] = False

    if detail["failed"]:
        return "capability_failed", detail
    if detail["skipped"] or detail["missing_witness"]:
        return "capability_partial", detail
    return "capability_named", detail


def verdict_line(verdict, detail):
    """一行判词:`CAPABILITY <verdict> failed=… skipped=… state_cleared=… witness=…`。"""
    return (
        f"CAPABILITY {verdict} failed={','.join(detail['failed']) or '-'} "
        f"skipped={','.join(detail['skipped']) or '-'} "
        f"presence={','.join(detail['presence']) or '-'} "
        f"state_cleared={1 if detail['state_cleared'] else 0} "
        f"witness={0 if detail['missing_witness'] else 1}"
    )


def apply_environment(verdict, *, dispatched, stats):
    """`environment` 的唯一判据:窗内没有一次逐系统派发,且矩阵根本没跑过。

    这一档**不能**由矩阵自己判 —— 全 `skip` 的矩阵分不开「没派发」与「派发了但没有
    system scope」,而后者是 `capability_partial`(spec §3.4)。
    """
    if verdict == "instrument_broken":
        return verdict
    if not dispatched and not ran_once(stats):
        return "environment"
    return verdict


def ran_once(stats):
    """矩阵里至少有一项不是默认的 `skip` ⇒ 自检真的跑过(与 `ran` 导出等价的一格)。"""
    return any(status != STATUS_SKIP for status, _reason in stats)


def instrument_ok(layout):
    return layout == {"version": LAYOUT_VERSION, "check_count": CHECK_COUNT}


def dispatch_observed(log_lines):
    return any(DISPATCH_MARKER in line for line in log_lines)


def install_decision(rc):
    """`C2NeoInstall` 的码表:`0` ok | 其余按拒绝记(理由见 `exports.zig` 那一行)。"""
    return "ok" if rc == 0 else "refused"


def gate_label(allow_window):
    return "operator_override" if allow_window else "world_state"


# --- pre-fire gates ---------------------------------------------------------------


def sha_gate(path):
    """打印并记录要注入的文件的 sha256;文件不在 = exit 2。"""
    if not os.path.exists(path):
        raise SystemExit(EXIT_REFUSED)
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def refuse_if_resident(dll_name, base):
    """同名模块已映射时,再注入一次会复用旧映像 —— 默认拒装(`--resident` 改判)。"""
    if base:
        raise SystemExit(EXIT_REFUSED)


# --- live path (Windows only; not exercised by the host tests) ---------------------


def _signed32(value):
    return value - (1 << 32) if value >= (1 << 31) else value


def _safe(fn, default=None):
    """一次实机调用失败是**读数**,不是 traceback(宿主可能已经死了)。"""
    try:
        return fn()
    except Exception:                       # noqa: BLE001 — 理由就是缺失的读数
        return default


def _file_size_or_none(path):
    try:
        return os.path.getsize(os.path.expanduser(path))
    except OSError:
        return None


def read_log_delta(path, offset):
    """窗口开始之后新增的行。`offset is None` ⇒ 没量到,返回空表(不整文件重读)。"""
    if offset is None:
        return []
    try:
        with open(os.path.expanduser(path), "rb") as handle:
            handle.seek(offset)
            text = handle.read().decode("utf-8", "replace")
    except OSError:
        return []
    return text.splitlines()


def read_layout(pid, base, exports, buf):
    import c2_harness as harness

    harness.call_remote_with_arg(pid, base, exports["C3CapabilityLayout"], buf)
    return decode_layout(struct.unpack("<2I", harness.read_memory(pid, buf, LAYOUT_WORDS * 4)))


def read_stats(pid, base, exports, buf):
    import c2_harness as harness

    rc = _signed32(harness.call_remote_with_arg(pid, base, exports["C3CapabilityStatsInto"], buf))
    if rc != 0:
        return None                     # 短缓冲/拒读:矩阵读不出
    return decode_stats(harness.read_memory(pid, buf, STATS_SIZE))


def ensure_dispatch_channel(pid, base, exports, *, resident):
    """拿到逐系统派发的条件。

    `resident` = DLL 已经在进程里(窗口由 boot injector 装的那一份):它自己也已经把
    C5-ADD 通道装好了,**不重复注入、不重复 install**。
    否则注入之后补一次 `C1Run → C2NeoInstall(neo_action)`,好让引擎把 `neo_action`
    送到我们的 `onSystem`。
    """
    import c2_harness as harness

    if resident:
        return {"install_rc": "resident", "install_decision": "ok"}
    trigger_id = harness.call_remote(pid, base, exports["C1Run"]) & 0xFFFFFFFF
    effect_id = harness.call_remote(pid, base, exports["C1EffectId"]) & 0xFFFFFFFF
    if trigger_id == 0 or effect_id == 0:
        return {"install_rc": "c1_failed", "install_decision": "refused"}
    rc = _signed32(harness.call_remote_with_arg(pid, base, exports["C2NeoInstall"], effect_id))
    harness.assert_game_alive(pid)
    return {"install_rc": rc, "install_decision": install_decision(rc)}


def release_dispatch_channel(pid, base, exports, *, installed):
    """装了我们自己那一次才拆;常驻通道留给装它的那次窗口。"""
    import c2_harness as harness

    if not installed:
        return {"uninstall_rc": "resident", "verify_rc": "resident"}
    uninstall_rc = _safe(lambda: _signed32(harness.call_remote(pid, base, exports["C2NeoUninstall"])))
    verify_rc = _safe(lambda: _signed32(harness.call_remote(pid, base, exports["C2NeoVerify"])))
    return {"uninstall_rc": uninstall_rc, "verify_rc": verify_rc}


def gate_module(pid, dll_path, needed, *, allow_window=False, resident=False):
    """导出集 → 常驻判定 → 窗口闸门 → 注入。返回 `(base, exports, was_resident)`。"""
    import c2_harness as harness

    exports = harness.list_exports(dll_path)
    missing = [name for name in needed if name not in exports]
    if missing:
        print(f"[capability] {dll_path} is missing {missing} — refusing to inject", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)

    dll_name = os.path.basename(dll_path.replace("\\", "/"))
    print(f"[capability] pid={pid}  dll={dll_path}")
    try:
        already = harness.resolve_base_address(pid, dll_name)
    except RuntimeError:
        already = None

    if already and resident:
        print(f"[capability] reusing the resident {dll_name} @ 0x{already:x} (no second inject)")
        return already, exports, True
    refuse_if_resident(dll_name, already)

    if allow_window:
        print("[capability] gate skipped by operator override (--allow-window)")
    else:
        from world_probe import gate_install  # pyright: ignore[reportMissingImports]

        gate_install("capability")

    harness.inject_dll(pid, dll_path)
    harness.assert_game_alive(pid)
    base = harness.resolve_base_address(pid, dll_name)
    print(f"[capability] {dll_name} base: 0x{base:x}")

    head = harness.read_memory(pid, base, 2)
    assert head == b"MZ", f"bad header at 0x{base:x}: {head!r}"
    sanity = _signed32(harness.call_remote(pid, base, exports["C2Sanity"]))
    if sanity != 42:
        print(f"[capability] C2Sanity returned {sanity}, expected 42", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)
    harness.assert_game_alive(pid)
    return base, exports, False


def _write_artifact(out_path, meta_lines, rows):
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(meta_lines) + "\n")
        handle.writelines(row + "\n" for row in rows)


def build_meta(**kwargs):
    """`k=v` 行,按 key 排序(`#meta` 块)。"""
    return [f"#meta {key}={kwargs[key]}" for key in sorted(kwargs)]


def artifact_rows(detail):
    """七行:`check status reason`,顺序 = `CHECK_IDS`。没有矩阵就一行都不写。"""
    stats = detail.get("stats") or []
    return [
        f"{name}\t{status_name(status)}\t{reason_name(reason)}"
        for name, (status, reason) in zip(CHECK_IDS, stats)
    ]


EMPTY_DETAIL = {
    "checks": {}, "failed": [], "skipped": [], "presence": [],
    "missing_witness": True, "state_cleared": True, "stats": [],
}


def run(dll_path, out_path, *, systems, save_name, poll_s=120.0, settle_s=3.0,
        allow_window=False, resident=False, neo_log=None, game_log=None):
    """一次窗口。清理与写 artifact 都在 `finally` 里;永不 `FreeLibrary`。"""
    import time

    import c2_harness as harness

    dll_sha = sha_gate(dll_path)
    print(f"[capability] dll={dll_path} sha256={dll_sha}")

    pid = harness.resolve_pid("stellaris.exe")
    needed = [name for name in harness.list_exports(dll_path) if name.startswith("C3Capability")]
    needed.append("C2Sanity")
    base, exports, was_resident = gate_module(
        pid, dll_path, needed, allow_window=allow_window, resident=resident)

    stats_buf = harness.remote_alloc(pid, STATS_SIZE)
    layout_buf = harness.remote_alloc(pid, LAYOUT_WORDS * 4)
    layout = read_layout(pid, base, exports, layout_buf)
    neo_path = os.path.expanduser(neo_log or NEO_LOG)
    game_path = os.path.expanduser(game_log or GAME_LOG)

    meta = {
        "dll": os.path.basename(dll_path.replace("\\", "/")),
        "dll_sha256": dll_sha,
        "module_base": f"0x{base:x}",
        "systems": systems,
        "save_name": save_name,
        "resident": 1 if was_resident else 0,
        "install_rc": "unused",
        "install_decision": "ok",
        "uninstall_rc": "unused",
        "verify_rc": "unused",
        "gate": gate_label(allow_window),
        "layout_version": layout["version"],
        "layout_check_count": layout["check_count"],
        "host_alive": 1,
        "overall_verdict": "",
    }
    detail = dict(EMPTY_DETAIL)
    verdict = ""
    try:
        if not instrument_ok(layout):
            verdict = "instrument_broken"
            return meta
        if not was_resident:
            channel = ensure_dispatch_channel(pid, base, exports, resident=False)
        else:
            channel = {"install_rc": "resident", "install_decision": "ok"}
        meta["install_rc"] = channel["install_rc"]
        meta["install_decision"] = channel["install_decision"]
        if channel["install_decision"] != "ok":
            verdict = "environment"
            return meta

        # 窗口起点:先清矩阵(`ran` 一起清),再记日志偏移,再等派发。
        harness.call_remote(pid, base, exports["C3CapabilityReset"])
        neo_offset = _file_size_or_none(neo_path)
        game_offset = _file_size_or_none(game_path)
        harness.assert_game_alive(pid)
        if settle_s > 0:
            time.sleep(settle_s)

        deadline = time.time() + poll_s
        stats = read_stats(pid, base, exports, stats_buf)
        while time.time() < deadline:
            if stats is not None and ran_once(stats):
                break
            time.sleep(1.0)
            reading = _safe(lambda: read_stats(pid, base, exports, stats_buf))
            if reading is None and stats is not None:
                meta["died_mid_poll"] = 1
                break
            stats = reading if reading is not None else stats

        neo_lines = read_log_delta(neo_path, neo_offset)
        game_lines = read_log_delta(game_path, game_offset)
        log_lines = neo_lines + game_lines
        meta["neo_log_lines"] = len(neo_lines)
        meta["game_log_lines"] = len(game_lines)
        meta["dispatched"] = 1 if dispatch_observed(log_lines) else 0
        meta["cap_lines"] = sum(1 for line in neo_lines if CAP_MARKER in line)
        meta["witness_hits"] = sum(1 for line in log_lines if WITNESS in line)

        if stats is None:
            verdict = "instrument_broken"
            return meta
        verdict, detail = fold_verdict(
            [layout["version"], layout["check_count"]], stats, log_lines)
        detail["stats"] = stats
        verdict = apply_environment(
            verdict, dispatched=bool(meta["dispatched"]), stats=stats)
        meta["failed"] = ",".join(detail["failed"]) or "-"
        meta["skipped"] = ",".join(detail["skipped"]) or "-"
        meta["state_cleared"] = 1 if detail["state_cleared"] else 0
        meta["missing_witness"] = 1 if detail["missing_witness"] else 0
        return meta
    finally:
        released = release_dispatch_channel(pid, base, exports, installed=not was_resident)
        if settle_s > 0:
            time.sleep(settle_s)
        try:
            harness.assert_game_alive(pid)
            alive = True
        except Exception:                   # noqa: BLE001 — 宿主死了也是读数
            alive = False
        meta["uninstall_rc"] = released["uninstall_rc"]
        meta["verify_rc"] = released["verify_rc"]
        meta["host_alive"] = 1 if alive else 0
        meta["overall_verdict"] = verdict or "environment"
        _write_artifact(out_path, build_meta(**meta), artifact_rows(detail))
        if verdict:
            print(verdict_line(verdict, detail))


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", nargs="?", default=r"C:\temp\sqjs_cap1.dll")
    parser.add_argument("--systems", type=int, required=True,
                        help="current campaign's star count (== container raw count; no default)")
    parser.add_argument("--save-name", required=True)
    parser.add_argument("--allow-window", action="store_true",
                        help="operator-declared premise: skip gate_install (recorded in meta)")
    parser.add_argument("--resident", action="store_true",
                        help="reuse the already-mapped DLL instead of injecting a second image")
    parser.add_argument("--poll-s", type=float, default=120.0)
    parser.add_argument("--settle-s", type=float, default=3.0)
    parser.add_argument("--neo-log", default=None)
    parser.add_argument("--game-log", default=None)
    parser.add_argument("--out", default="C:/temp/c3_capability.tsv")
    args = parser.parse_args(argv)

    meta = run(args.dll, args.out, systems=args.systems, save_name=args.save_name,
               poll_s=args.poll_s, settle_s=args.settle_s, allow_window=args.allow_window,
               resident=args.resident, neo_log=args.neo_log, game_log=args.game_log)
    return 0 if meta.get("overall_verdict") in EVIDENCE_VERDICTS else 1


if __name__ == "__main__":
    raise SystemExit(main())
