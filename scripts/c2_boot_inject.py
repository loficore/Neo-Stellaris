#!/usr/bin/env python3
"""c2_boot_inject.py — T1:进程一出现就注入,注册 `neo_action`,再换掉逐系统派发槽。

与兄弟驱动的区别:它**不发脚本、不动窗口、不读日志**,只做四件事

    wait_for_process → inject_dll → C1Run → C1EffectId → C1SetId
    → C2NeoArmSet(set_id) → C2NeoInstall(effect_id)

并且把结果压成一行回执(`BOOT ...`),所以实机窗口里「注入有没有赶上脚本解析」
可以从一行读到,不必翻三份日志。

**为什么必须早**:spec §2 的 T1。mod 脚本里 `neo_action` 这个名字要在解析时
已经有 token id;晚于脚本解析,词会落进 `0x5350D0` 的默认分支 → `0x1D092C0`
写一条 `Unexpected token` 到 `error.log`,整套**静默失效**(§30)。

用法(Windows 侧,C:/temp 裸名 import):

    python C:/temp/c2_boot_inject.py C:/temp/sqjs_c20.dll --timeout-s 30
    python C:/temp/c2_boot_inject.py --allow-window     # operator-declared premise
    python C:/temp/c2_boot_inject.py --stats --log "<...>/logs/game.log"   # read back

`--rule MOD:REM`(默认 `1:0` = 所有 id)在安装成功后立刻装进 DLL;`--act log|write`
(默认 `log`)决定命中时只写日志,还是日志 + 在系统 scope 上写两个变量
(`neo_mark` = 星系 id,`neo_score` = 离线图分数;C5-WRITE + C5-SCORE);
`--stats` 不注入,只把 `C2NeoStatsInto` 的一行(和日志当前字节偏移)打出来;
`--uninstall` 拆 detour 并返回 `UNINSTALL rc= verify= alive=`,窗口结束前必须跑一次。

退出码:`0` = 回执里有 `install_rc=0` 且 `alive=1`;`2` = 任一步失败(打印
`BOOT FAIL <step>`);`gate_install` 拒绝时也是 2(它自己 `raise SystemExit(2)`)。

永不 `FreeLibrary`(AGENTS 约束 5):卸载只拆 detour,对象随进程回收。
"""
from __future__ import annotations

import argparse
import hashlib
import os
import struct
import subprocess
import sys
import time

EXIT_FAILED = 2

DEFAULT_DLL = r"C:\temp\sqjs_c20.dll"

#: Wait this long after the process appears, before injecting.  50 ms injection
#: crashed one launch before ``setup.log`` (2026-11-03); 5 s landed cleanly, and
#: the script parser does not run until ~30 s after launch, so T1 still holds.
DEFAULT_SETTLE_S = 5.0

#: Every export this driver indexes.  Missing any of them means the bytes on the
#: box are not this build's — refuse **before** injecting (2026-11-02 review I-2:
#: `C2NeoSetRule`/`C2NeoUninstall` were called but unlisted, so a stale DLL gave a
#: `KeyError` traceback instead of the designed refusal).
NEEDED = (
    "C2Sanity",
    "C1Run",
    "C1EffectId",
    "C1SetId",
    "C2NeoArmSet",
    "C2NeoInstall",
    "C2NeoSetRule",
    "C2NeoSetAct",
    "C2NeoUninstall",
    "C2NeoVerify",
    "C2NeoStatsInto",
    "C4PredStatsInto",  # --pred; same DLL, C4-era
)


def missing_exports(needed, available) -> list:
    """The names `needed` lists that `available` does not have, in `needed` order."""
    have = set(available)
    return [name for name in needed if name not in have]


def _require_exports(dll_path: str) -> dict | None:
    """`list_exports` result, or None after printing `BOOT FAIL exports`."""
    import c2_harness as harness

    exports = harness.list_exports(dll_path)
    missing = missing_exports(NEEDED, exports)
    if missing:
        print(f"[boot] {dll_path} is missing {missing} — refusing to touch the process",
              file=sys.stderr)
        return None
    return exports


def receipt(*, dll: str, sha16: str, effect_id: int, set_id: int, install_rc: int,
            alive: bool) -> str:
    """One line, fixed field order — the window note quotes it verbatim."""
    return (f"BOOT dll={dll} sha={sha16} effect_id={effect_id} set_id={set_id} "
            f"install_rc={install_rc} alive={1 if alive else 0}")


def fail_line(step: str) -> str:
    return f"BOOT FAIL {step}"


def sha16(path: str) -> str:
    """First 16 hex digits of the DLL's sha256 — enough to tell two shots apart."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()[:16]


def pack_rule(rule: str) -> int:
    """`"MOD:REM"` -> the u64 the DLL takes (`mod << 32 | rem`). `0:0` disables the rule.

    Raises `ValueError` on anything that is not two non-negative integers; the
    caller turns that into a usage error, not a traceback (review M-7).
    """
    mod_text, _, rem_text = rule.partition(":")
    mod, rem = int(mod_text), int(rem_text or 0)
    if mod < 0 or rem < 0:
        raise ValueError(f"rule must be MOD:REM with MOD,REM >= 0, got {rule!r}")
    return (mod << 32) | (rem & 0xFFFFFFFF)


def _signed32(value: int) -> int:
    return value - (1 << 32) if value & 0x80000000 else value


#: `C2NeoSetAct` 的码表。`write` 依赖 body/vtable 地址解析成功;解析不到时
#: DLL 只记 `skipped`(stats 行尾两格),不会静默改世界。
ACT_CODES = {"log": 0, "write": 1}


def pack_act(act: str) -> int:
    """`"log"` -> 0, `"write"` -> 1. Raises `ValueError` on anything else."""
    try:
        return ACT_CODES[act]
    except KeyError:
        raise ValueError(f"act must be one of {sorted(ACT_CODES)}, got {act!r}") from None


def _fail(step: str) -> int:
    print(fail_line(step), file=sys.stderr)
    return EXIT_FAILED


def wait_for_process(timeout_s: float, *, interval_s: float = 0.05):
    """Poll for `stellaris.exe` every 50 ms; return the pid or None on timeout.

    50 ms is deliberate: the injection has to land before the script parser
    reaches the test mod's event file, and a 1 s poll can lose that race on a
    warm page cache.
    """
    import c2_harness as harness  # bare name on the wire (裁定 P5)

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            return harness.resolve_pid("stellaris.exe")
        except RuntimeError:
            time.sleep(interval_s)
    return None


def launch(exe_path: str, extra_args: str = "") -> int:
    """Start the game ourselves, so the injection poll is already running.

    `--continuelastsave` is the launcher's own argument (spec §69.1): direct
    `stellaris.exe --continuelastsave` inside session 1 is the shape that has
    reproduced the campaign window before.  Returns the spawned pid.
    """
    argv = [exe_path]
    if extra_args:
        argv += extra_args.split()
    child = subprocess.Popen(argv, cwd=os.path.dirname(exe_path) or None)
    print(f"[boot] launched pid={child.pid} argv={argv}")
    return child.pid


def boot(dll_path: str, *, timeout_s: float = 30.0, allow_window: bool = False,
         rule: str = "1:0", act: str = "log", launch_exe: str | None = None,
         launch_args: str = "", settle_s: float = DEFAULT_SETTLE_S) -> int:
    import c2_harness as harness

    dll_name = os.path.basename(dll_path.replace("\\", "/"))
    digest = sha16(dll_path)
    print(f"[boot] dll={dll_path} sha16={digest}")

    exports = _require_exports(dll_path)
    if exports is None:
        return _fail("exports")

    if launch_exe:
        launch(launch_exe, launch_args)
    pid = wait_for_process(timeout_s)
    if pid is None:
        print(f"[boot] stellaris.exe did not appear within {timeout_s:.0f}s", file=sys.stderr)
        return _fail("wait")
    print(f"[boot] pid={pid}")
    if settle_s > 0:
        time.sleep(settle_s)

    if allow_window:
        print("[boot] gate skipped by operator override (--allow-window)")
    else:
        from world_probe import gate_install  # pyright: ignore[reportMissingImports]

        gate_install("c2_neo")

    harness.inject_dll(pid, dll_path)
    harness.assert_game_alive(pid)
    base = harness.resolve_base_address(pid, dll_name)
    if harness.read_memory(pid, base, 2) != b"MZ":
        return _fail("header")
    sanity = _signed32(harness.call_remote(pid, base, exports["C2Sanity"]))
    if sanity != 42:
        print(f"[boot] C2Sanity returned {sanity}, expected 42", file=sys.stderr)
        return _fail("sanity")

    trigger_id = harness.call_remote(pid, base, exports["C1Run"])
    if trigger_id == 0:
        print("[boot] C1Run returned 0 — see C:/temp/c1_result.log", file=sys.stderr)
        return _fail("c1")
    effect_id = harness.call_remote(pid, base, exports["C1EffectId"])
    if effect_id == 0:
        return _fail("c1_effect")
    set_id = harness.call_remote(pid, base, exports["C1SetId"])
    if set_id == 0:
        return _fail("c1_set")

    # The set token must be armed BEFORE install: both setToken and
    # setSetToken refuse to change the arming once the detour is live.
    arm_set_rc = _signed32(
        harness.call_remote_with_arg(pid, base, exports["C2NeoArmSet"], set_id))
    if arm_set_rc != 0:
        return _fail("arm_set")

    install_rc = _signed32(
        harness.call_remote_with_arg(pid, base, exports["C2NeoInstall"], effect_id))
    harness.assert_game_alive(pid)
    if install_rc == 0:
        harness.call_remote_with_arg(pid, base, exports["C2NeoSetRule"], pack_rule(rule))
        # C5-WRITE:`write` = 日志 + 系统变量;默认 `log` 保持 C5-ADD 的行为不变。
        harness.call_remote_with_arg(pid, base, exports["C2NeoSetAct"], pack_act(act))

    print(receipt(dll=dll_name, sha16=digest, effect_id=effect_id, set_id=set_id,
                  install_rc=install_rc, alive=True))
    return 0 if install_rc == 0 else EXIT_FAILED


def uninstall(dll_path: str) -> int:
    """Tear our detour down in the live pid and print `UNINSTALL rc=<n> verify=<n>`.

    Objects already patched keep pointing at our vtable (C4's policy): the engine
    bytes are restored, the DLL is never freed, and the process is expected to end.
    """
    import c2_harness as harness

    pid = harness.resolve_pid("stellaris.exe")
    dll_name = os.path.basename(dll_path.replace("\\", "/"))
    base = harness.resolve_base_address(pid, dll_name)
    exports = _require_exports(dll_path)
    if exports is None:
        return _fail("exports")
    rc = _signed32(harness.call_remote(pid, base, exports["C2NeoUninstall"]))
    verify = _signed32(harness.call_remote(pid, base, exports["C2NeoVerify"]))
    harness.assert_game_alive(pid)
    print(f"UNINSTALL rc={rc} verify={verify} alive=1")
    return 0 if rc == 0 and verify == 0 else EXIT_FAILED


def pred_stats(dll_path: str) -> int:
    """Read C4's predicate-hook counters (24 B: calls, patched, last_token, installed).

    This is what separates "the engine never instantiated our keyword" from
    "it did, but with another token": `pred_last_token` is the last `[obj+0x20]`
    the predicate detour saw.
    """
    import c2_harness as harness

    pid = harness.resolve_pid("stellaris.exe")
    dll_name = os.path.basename(dll_path.replace("\\", "/"))
    base = harness.resolve_base_address(pid, dll_name)
    exports = _require_exports(dll_path)
    if exports is None:
        return _fail("exports")
    buf = harness.remote_alloc(pid, 24)
    rc = _signed32(harness.call_remote_with_arg(pid, base, exports["C4PredStatsInto"], buf))
    blob = harness.read_memory(pid, buf, 24)
    calls, patched = struct.unpack_from("<QQ", blob, 0)
    last_token, installed = struct.unpack_from("<II", blob, 16)
    print(f"pred_rc={rc} pred_calls={calls} pred_patched={patched} "
          f"pred_last_token={last_token} pred_installed={installed}")
    return 0


def stats(dll_path: str, *, game_log: str | None = None) -> int:
    """Read the `C2NeoStatsInto` line (and optionally the log's byte offset) from a live pid."""
    import c2_harness as harness

    pid = harness.resolve_pid("stellaris.exe")
    dll_name = os.path.basename(dll_path.replace("\\", "/"))
    base = harness.resolve_base_address(pid, dll_name)
    exports = _require_exports(dll_path)
    if exports is None:
        return _fail("exports")
    buf = harness.remote_alloc(pid, 512)
    harness.call_remote_with_arg(pid, base, exports["C2NeoStatsInto"], buf)
    text = harness.read_memory(pid, buf, 512).split(b"\0", 1)[0].decode("ascii", "replace")
    print(text.rstrip("\r\n"))
    if game_log:
        try:
            print(f"log_bytes={os.path.getsize(os.path.expanduser(game_log))}")
        except OSError:
            print("log_bytes=None")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", nargs="?", default=DEFAULT_DLL)
    parser.add_argument("--timeout-s", type=float, default=30.0,
                        help="how long to wait for stellaris.exe to appear (default 30)")
    parser.add_argument("--allow-window", action="store_true",
                        help="operator-declared premise: skip gate_install")
    parser.add_argument("--rule", default="1:0",
                        help="MOD:REM armed after install; 1:0 = every id, 0:0 = off")
    parser.add_argument("--act", default="log", choices=("log", "write"),
                        help="log = 只写日志(C5-ADD);write = 日志 + 写 neo_mark 与 neo_score")
    parser.add_argument("--stats", action="store_true",
                        help="do not inject: print C2NeoStatsInto from the running pid")
    parser.add_argument("--pred", action="store_true",
                        help="do not inject: print C4's predicate-hook counters")
    parser.add_argument("--uninstall", action="store_true",
                        help="do not inject: C2NeoUninstall + C2NeoVerify, then print both")
    parser.add_argument("--launch", default=None,
                        help="path to stellaris.exe: start it ourselves before polling")
    parser.add_argument("--launch-args", default="",
                        help="arguments for --launch, e.g. --continuelastsave")
    parser.add_argument("--settle-s", type=float, default=DEFAULT_SETTLE_S,
                        help=f"sleep after the process appears, before injecting (default {DEFAULT_SETTLE_S:g}; "
                             "5 s clears the early loader, parser runs ~30 s in)")
    parser.add_argument("--log", default=None,
                        help="with --stats: also print this log's current byte offset")
    args = parser.parse_args(argv)
    try:
        pack_rule(args.rule)
        pack_act(args.act)
    except ValueError as exc:
        parser.error(str(exc))
    if args.pred:
        return pred_stats(args.dll)
    if args.stats:
        return stats(args.dll, game_log=args.log)
    if args.uninstall:
        return uninstall(args.dll)
    return boot(args.dll, timeout_s=args.timeout_s, allow_window=args.allow_window,
                rule=args.rule, act=args.act, launch_exe=args.launch,
                launch_args=args.launch_args, settle_s=args.settle_s)


if __name__ == "__main__":
    raise SystemExit(main())
