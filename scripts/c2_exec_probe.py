#!/usr/bin/env python3
"""C4 execution-path live probe — one bounded shot in one game process.

Chain under test: C1 registers an effect token, C2ExecInstall builds the DLL
vtable, arms the predicate detour on that token, arms the base-Execute probe,
and arms the QuickJS bridge. The probe synthesizes one instantiate of the
token; the predicate patches the instance to the DLL vtable; its slot[1]
Execute goes through C2ExecCall into the fixed JS script, which answers the
sentinel 1504.

Usage: python3 scripts/c2_exec_probe.py [dll_path]

Success prints `VERDICT: ok` plus both raw stats lines. Every other verdict
prints its diagnosis and exits nonzero. Cleanup runs in a `finally`: the probe
is made inert first, then base Execute is restored, then the C bridge and the
predicate detour are disarmed. Never FreeLibrary the DLL while
C2ExecProbeUninstall or C2ExecDisarm reported a failure.
"""

import os
import sys
import time

from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll,
    list_exports, call_remote, call_remote_with_arg,
    remote_alloc, read_memory, assert_game_alive,
)

DEFAULT_DLL = r"C:\temp\sqjs_c4.dll"
POLL_INTERVAL_S = 1.0
POLL_TIMEOUT_S = 120.0
SETTLE_S = 2.0
EXEC_STATS_SIZE = 1024
PROBE_STATS_SIZE = 512

VERDICT_DIAGNOSIS = {
    "no_fire": (
        "the base-Execute detour never saw a usable call within the poll window. "
        "That is an ENVIRONMENT result, not a code verdict: load a running "
        "campaign and unpause the game, then rerun with a fresh game process."
    ),
    "ctx_skip_only": (
        "every intercepted call carried the lexer sentinel [ctx+0x38]==0xb, so "
        "instantiate was refused. This call-site context shape is not a usable "
        "event scope for the probe."
    ),
    "fired_no_js": (
        "instantiate fired but C2ExecCall never ran (js_calls==0): the object did "
        "not travel the patched predicate -> vtable -> slot[1] chain, or the C "
        "bridge was already disarmed."
    ),
    "error": (
        "the chain ran but JS did not produce the sentinel. Read js_err "
        "(script/exception) and mismatch (token reaching JS differs from the "
        "armed one) in the stats below."
    ),
}

_INT32_MAX = 0x7FFFFFFF
_UINT32_SPAN = 1 << 32

_dispatched = set()


def _signed32(raw):
    """Re-bias a thread exit code (unsigned 32-bit) to its C int value."""
    return raw - _UINT32_SPAN if raw > _INT32_MAX else raw


def decode_stats(text):
    """Parse whitespace-separated ``key=int`` tokens; duplicate keys raise.

    Callers pass the stats buffer already truncated at the first NUL.
    """
    out = {}
    for tok in text.split():
        if "=" not in tok:
            continue
        key, _, val = tok.partition("=")
        if key in out:
            raise ValueError(f"duplicate key {key!r} in stats text")
        out[key] = int(val)
    return out


def classify(probe, cstats):
    """Map the two stats dicts to one verdict; missing keys count as 0."""
    fired = probe.get("fired", 0)
    js_calls = cstats.get("js_calls", 0)
    if fired == 0:
        return "no_fire"
    if js_calls == 0 and probe.get("ctx_skip", 0) > 0 and probe.get("invalid", 0) == 0:
        return "ctx_skip_only"
    if js_calls == 0:
        return "fired_no_js"
    if cstats.get("js_err", 0) > 0 or cstats.get("mismatch", 0) > 0:
        return "error"
    if cstats.get("js_ok", 0) >= 1 and probe.get("pred_patched", 0) >= 1:
        return "ok"
    return "error"


def poll_done(probe, cstats):
    """True once the shot fired AND its JS leg reported.

    The probe flips `fired` before instantiate() runs, so a stats read taken
    right after the flip can still show js_calls==0; stopping there would
    call a complete chain `fired_no_js`.
    """
    return probe.get("fired", 0) == 1 and cstats.get("js_calls", 0) >= 1


def contract_errors(live, live_probe, effect_id):
    """Every success-contract term the LIVE snapshot fails.

    `live` / `live_probe` are the reads taken before cleanup. Cleanup disarms
    the chain, and disarm zeroes the C bridge's `token`, so judging the
    post-cleanup read rejects a shot that already proved the chain.
    """
    errors = []
    if live.get("token", 0) != effect_id:
        errors.append(f"c bridge token {live.get('token')} != effect_id {effect_id}")
    if live.get("last_value", 0) != 1504:
        errors.append(f"JS returned {live.get('last_value')}, expected the sentinel 1504")
    if live_probe.get("chain", 1) != 0:
        errors.append("the donor chain must stay off in the live shot")
    if live_probe.get("pred_patched", 0) < 1:
        errors.append("the predicate never patched the instance")
    return errors


def dispatch_once(pid, base, rva, name, arg=None):
    """Dispatch a remote export at most once per session; return its C int rc."""
    if name in _dispatched:
        raise RuntimeError(
            f"{name} was already dispatched in this session; this probe is "
            "single-run by design (a second install/disarm leaks or invalidates "
            "the state the observation depends on)"
        )
    _dispatched.add(name)
    if arg is None:
        return _signed32(call_remote(pid, base, rva))
    return _signed32(call_remote_with_arg(pid, base, rva, arg))


def gate_module(pid, dll_path, needed):
    """Inject this copy and clear every gate that must precede a dispatch."""
    dll_name = os.path.basename(dll_path)
    print(f"[c4] pid={pid}  dll={dll_path}")

    # The world-state gate (spec §1): a shot that cannot prove the premise
    # must not inject.  The refusal happens BEFORE inject_dll — "injected,
    # then noticed the premise was false" is the failure mode this removes.
    from world_probe import gate_install  # pyright: ignore[reportMissingImports]
    gate_install('exec')
    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    print(f"[c4] {dll_name} base (64-bit): 0x{base:x}")

    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    print("[c4] MZ header at base OK")

    exports = list_exports(dll_path)
    for name in needed:
        assert name in exports, f"{name} is not an export of {dll_path}"

    sanity = _signed32(call_remote(pid, base, exports["C2Sanity"]))
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch against "
        f"this module copy"
    )
    assert_game_alive(pid)
    print("[c4] C2Sanity == 42, game alive — dispatch authorized")
    return base, exports


def read_stats(pid, base, exports, buf, name, size):
    """Dispatch one *StatsInto export and decode what it wrote."""
    call_remote_with_arg(pid, base, exports[name], buf)
    raw = read_memory(pid, buf, size)
    text = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
    return decode_stats(text), text


def _cleanup(pid, base, exports):
    """Step 7: make the probe inert, restore base Execute, disarm the rest."""
    probe_uninstall_rc = None
    try:
        probe_uninstall_rc = _signed32(call_remote(pid, base, exports["C2ExecProbeUninstall"]))
    except Exception as exc:  # noqa: BLE001 - cleanup must report, not raise
        print(f"[c4] C2ExecProbeUninstall raised: {exc}")
    if probe_uninstall_rc not in (0, None):
        print(
            f"[c4] WARNING: C2ExecProbeUninstall rc={probe_uninstall_rc} — the "
            "base-Execute hook may still be installed; NEVER FreeLibrary this DLL"
        )
    else:
        print(f"[c4] C2ExecProbeUninstall rc={probe_uninstall_rc}")

    try:
        verify_rc = _signed32(call_remote(pid, base, exports["C2ExecProbeVerify"]))
        print(f"[c4] C2ExecProbeVerify rc={verify_rc} (0 = base Execute bytes intact)")
    except Exception as exc:  # noqa: BLE001
        print(f"[c4] C2ExecProbeVerify raised: {exc}")

    time.sleep(SETTLE_S)

    disarm_rc = None
    for attempt in range(6):
        try:
            disarm_rc = _signed32(call_remote(pid, base, exports["C2ExecDisarm"]))
        except Exception as exc:  # noqa: BLE001
            print(f"[c4] C2ExecDisarm raised (attempt {attempt}): {exc}")
            break
        if disarm_rc != -1:
            break
        time.sleep(0.5)
    if disarm_rc not in (0, None):
        print(
            f"[c4] WARNING: C2ExecDisarm rc={disarm_rc} — a hook may still be "
            "installed; NEVER FreeLibrary this DLL"
        )
    else:
        print(f"[c4] C2ExecDisarm rc={disarm_rc}")


def run_live_case(pid, dll_path):
    needed = (
        "C2Sanity", "C1Run", "C1EffectId", "C2Init", "C2ExecInstall",
        "C2ExecProbeInstall", "C2ExecProbeUninstall", "C2ExecProbeVerify",
        "C2ExecDisarm", "C2ExecStatsInto", "C2ExecProbeStatsInto",
    )
    base, exports = gate_module(pid, dll_path, needed)

    trigger_id = dispatch_once(pid, base, exports["C1Run"], "C1Run")
    assert trigger_id != 0, (
        "C1Run returned 0 — the C1 registration failed; read C:\\temp\\c1_result.log"
    )
    effect_id = _signed32(call_remote(pid, base, exports["C1EffectId"]))
    assert effect_id != 0, (
        "C1EffectId returned 0 — no effect token was recorded by C1Run"
    )
    assert_game_alive(pid)
    print(f"[c4] C1 trigger_id={trigger_id} effect_id={effect_id}, game alive")

    rc_init = dispatch_once(pid, base, exports["C2Init"], "C2Init")
    assert rc_init == 0, f"C2Init rc={rc_init} — not arming the chain without a live context"
    assert_game_alive(pid)
    print("[c4] C2Init rc == 0, game alive")

    rc_install = None
    rc_probe_install = None
    probe = {}
    cstats = {}
    probe_text = ""
    cstats_text = ""
    live_probe = {}
    live_cstats = {}
    live_probe_text = ""
    live_cstats_text = ""
    buf = None
    try:
        rc_install = dispatch_once(
            pid, base, exports["C2ExecInstall"], "C2ExecInstall", effect_id
        )
        assert_game_alive(pid)
        print(f"[c4] C2ExecInstall(effect_id={effect_id}) rc={rc_install}")
        if rc_install == 0:
            rc_probe_install = dispatch_once(
                pid, base, exports["C2ExecProbeInstall"], "C2ExecProbeInstall"
            )
            assert_game_alive(pid)
            print(f"[c4] C2ExecProbeInstall rc={rc_probe_install}")

        if rc_install == 0 and rc_probe_install == 0:
            buf = remote_alloc(pid, EXEC_STATS_SIZE)
            deadline = time.monotonic() + POLL_TIMEOUT_S
            last_progress = time.monotonic()
            while time.monotonic() < deadline:
                probe, probe_text = read_stats(
                    pid, base, exports, buf, "C2ExecProbeStatsInto", PROBE_STATS_SIZE
                )
                cstats, cstats_text = read_stats(
                    pid, base, exports, buf, "C2ExecStatsInto", EXEC_STATS_SIZE
                )
                live_probe, live_probe_text = probe, probe_text
                live_cstats, live_cstats_text = cstats, cstats_text
                if poll_done(probe, cstats):
                    break
                if time.monotonic() - last_progress >= 10.0:
                    print(
                        f"[c4] waiting: calls={probe.get('calls', 0)} "
                        f"fired={probe.get('fired', 0)} "
                        f"ctx_skip={probe.get('ctx_skip', 0)} "
                        f"js_calls={cstats.get('js_calls', 0)}"
                    )
                    last_progress = time.monotonic()
                time.sleep(POLL_INTERVAL_S)
    finally:
        _cleanup(pid, base, exports)
        try:
            final_buf = buf if buf is not None else remote_alloc(pid, EXEC_STATS_SIZE)
            probe, probe_text = read_stats(
                pid, base, exports, final_buf, "C2ExecProbeStatsInto", PROBE_STATS_SIZE
            )
            cstats, cstats_text = read_stats(
                pid, base, exports, final_buf, "C2ExecStatsInto", EXEC_STATS_SIZE
            )
        except Exception as exc:  # noqa: BLE001 - final stats are evidence, not a gate
            print(f"[c4] final stats read raised: {exc}")

    if live_cstats_text:
        print(f"[c4] probe stats (live): {live_probe_text.strip()}")
        print(f"[c4] c bridge stats (live): {live_cstats_text.strip()}")
    print(f"[c4] probe stats (post-cleanup): {probe_text.strip()}")
    print(f"[c4] c bridge stats (post-cleanup): {cstats_text.strip()}")

    if rc_install != 0:
        print(f"VERDICT: install_failed (C2ExecInstall rc={rc_install})")
        return 1
    if rc_probe_install != 0:
        print(f"VERDICT: probe_install_failed (C2ExecProbeInstall rc={rc_probe_install})")
        return 1

    verdict = classify(live_probe, live_cstats)
    if verdict != "ok":
        print(f"VERDICT: {verdict}")
        print(VERDICT_DIAGNOSIS[verdict])
        return 1

    errors = contract_errors(live_cstats, live_probe, effect_id)
    assert not errors, "; ".join(errors)
    assert_game_alive(pid)
    print("VERDICT: ok")
    return 0


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    dll_path = args[0] if args else DEFAULT_DLL
    if not os.path.isfile(dll_path):
        raise SystemExit(
            f"{dll_path} not found — upload the freshly built DLL first (this "
            "script reparses and injects THIS file, so it must be the bytes that "
            "go into the game)"
        )
    pid = resolve_pid("stellaris")
    return run_live_case(pid, dll_path)


if __name__ == "__main__":
    sys.exit(main())
