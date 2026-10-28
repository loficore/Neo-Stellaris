#!/usr/bin/env python3
"""Offline fences for `scripts/c2_trigger_pred_probe.py` (C5 data plane, §75/§76).

No game, no Windows API: every test below runs the driver's pure judgement面.
The two authority pins read the repo itself (the Zig stats line and the driver's
own source), not a copy of it.
"""
import pathlib
import struct

import pytest

import c2_trigger_pred_probe as mod
from c2_trigger_pred_probe import (
    EVIDENCE_VERDICTS,
    STATS_KEYS,
    VERDICTS,
    artifact_rows,
    decode_entry,
    decode_layout,
    install_decision,
    overall_verdict,
    window_refused,
    parse_c1_result,
    parse_mask,
    parse_stats,
    script_marker,
    verdict,
)

REPO = pathlib.Path(__file__).resolve().parent.parent


def _entry(**kwargs):
    row = {
        "token": 0x4321,
        "self_ptr": 0x7FF0_0000_2000,
        "self_vtable_rva": 0,
        "x_ptr": 0x7FF0_0000_1000,
        "x_vtable_rva": 0,
        "valid": 1,
        "matched": 1,
    }
    row.update(kwargs)
    return row


def _stats(**kwargs):
    base = {
        "calls": 0,
        "token_matched": 0,
        "samples": 0,
        "x_null": 0,
        "patch_size": 16,
        "installed": 1,
        "verify": 0,
        "last_token": 0,
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Authority pins
# ---------------------------------------------------------------------------


def test_stats_keys_match_the_dll_text_line():
    src = (REPO / "src/dll/c2/trigger_pred_probe.zig").read_text(encoding="utf-8")
    for key in STATS_KEYS:
        assert f"{key}=" in src, f"{key}= is not in the DLL's bufPrint"


def test_layout_word_order_matches_the_dll():
    """The driver's decode order is the DLL's write order (version first, Entry size second)."""
    src = (REPO / "src/dll/c2/trigger_pred_probe.zig").read_text(encoding="utf-8")
    body = src.split("pub fn layoutInto", 1)[1].split("return 6;", 1)[0]
    order = [
        "LAYOUT_VERSION",
        "@intCast(@sizeOf(Entry))",
        "@intCast(RING_LEN)",
        "@intCast(@sizeOf(Stats))",
        "@intCast(RVA_TRIGGER_PREDICATE)",
        "@intCast(EXPECTED_CODE.len)",
    ]
    positions = [body.index(token) for token in order]
    assert positions == sorted(positions), f"layoutInto word order drifted: {order}"


def test_entry_size_matches_the_dll():
    src = (REPO / "src/dll/c2/trigger_pred_probe.zig").read_text(encoding="utf-8")
    assert "@sizeOf(Entry) != 40" in src
    assert mod.ENTRY_SIZE == 40


# ---------------------------------------------------------------------------
# Stats / layout parsing
# ---------------------------------------------------------------------------


def test_parse_stats_rejects_a_missing_key():
    with pytest.raises(ValueError):
        parse_stats("calls=1 token_matched=0 samples=0")


def test_parse_stats_rejects_an_unknown_key():
    line = " ".join(f"{k}=0" for k in STATS_KEYS) + " surprise=1"
    with pytest.raises(ValueError):
        parse_stats(line)


def test_parse_stats_reads_the_eight_keys():
    line = " ".join(f"{k}=0" for k in STATS_KEYS)
    assert parse_stats(line)["calls"] == 0


def test_decode_layout_and_install_decision_agree_on_a_fresh_dll():
    words = (1, 40, 256, 40, 0x349230, 32)
    assert decode_layout(words)["entry_size"] == 40
    assert install_decision(words) is None


def test_install_decision_refuses_a_stale_target():
    words = (1, 40, 256, 40, 0xCC4220, 32)
    refusal = install_decision(words)
    assert refusal is not None and "target rva" in refusal


def test_install_decision_refuses_a_short_prologue():
    words = (1, 40, 256, 40, 0x349230, 21)
    assert install_decision(words) is not None


def test_decode_entry_reads_the_zig_field_order():
    raw = struct.pack(
        "<BBHIIII4xQQ",
        1, 1, 0, 0x4321, 0x1111, 0x2222, 0,
        0x7FF0_0000_2000, 0x7FF0_0000_1000,
    )
    entry = decode_entry(raw)
    assert entry["token"] == 0x4321
    assert entry["self_vtable_rva"] == 0x1111
    assert entry["x_vtable_rva"] == 0x2222
    assert entry["x_ptr"] == 0x7FF0_0000_1000


def test_decode_entry_rejects_a_wrong_length():
    with pytest.raises(ValueError):
        decode_entry(b"\x00" * 8)


# ---------------------------------------------------------------------------
# Mask: only 0 is honest (the guard records every matched call)
# ---------------------------------------------------------------------------


def test_mask_only_accepts_zero():
    assert parse_mask("0") == 0
    assert parse_mask("0x0") == 0
    with pytest.raises(ValueError):
        parse_mask("0x1ff")


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


def test_verdict_one_match_is_instantiate_once():
    stats = _stats(calls=400, token_matched=1, samples=1)
    assert verdict(stats, [], 787) == "predicate_instantiate_once"


def test_verdict_matches_the_system_count_is_per_system():
    stats = _stats(calls=4000, token_matched=787, samples=256)
    assert verdict(stats, [], 787) == "predicate_per_system"


def test_verdict_zero_matches_with_calls_is_token_absent():
    stats = _stats(calls=9000)
    assert verdict(stats, [], 787) == "token_absent"


def test_verdict_zero_calls_is_environment_not_evidence():
    assert verdict(_stats(), [], 787) == "no_calls"
    assert "no_calls" not in EVIDENCE_VERDICTS


def test_verdict_an_unverified_restore_beats_every_reading():
    stats = _stats(calls=5000, token_matched=787, samples=200, verify=0, installed=1)
    assert verdict(stats, [], 787) == "predicate_per_system"
    broken = _stats(calls=5000, token_matched=787, verify=-2)
    assert verdict(broken, [], 787) == "instrument_broken"


def test_a_script_refusal_is_not_a_silent_instrument():
    assert verdict(_stats(), [], 787, refused=True) == "script_refused"


def test_every_verdict_is_in_the_domain():
    assert set(EVIDENCE_VERDICTS) <= set(VERDICTS)
    assert verdict(_stats(), [], 787) in VERDICTS


def test_verdict_needs_a_positive_denominator():
    with pytest.raises(ValueError):
        verdict(_stats(calls=10, token_matched=3), [], 0)


# ---------------------------------------------------------------------------
# Artifact shape
# ---------------------------------------------------------------------------


def test_artifact_rows_carry_x_vtable_and_region():
    rows = artifact_rows([_entry(x_ptr=0x7FF0_0000_1000, x_vtable_rva=0)])
    header = rows[0].split("\t")
    assert "x_ptr" in header
    assert "x_vtable_rva" in header
    assert len(rows) == 2


def test_artifact_rows_are_tab_separated_with_one_row_per_entry():
    rows = artifact_rows([_entry(), _entry(token=9)])
    assert all(len(row.split("\t")) == len(rows[0].split("\t")) for row in rows)
    assert len(rows) == 3


# ---------------------------------------------------------------------------
# Gate order (R-inject)
# ---------------------------------------------------------------------------


def test_script_marker_stops_before_the_scope_substitution():
    assert script_marker('effect every_system = { log = "TS_NEO_[This.GetName]" }') == "TS_NEO_"
    assert script_marker('effect every_system = { log = "TS_RIM" }') == "TS_RIM"
    assert script_marker("effect every_system = { }") is None


def test_c1_result_fallback_reads_the_minted_trigger_token():
    assert parse_c1_result("C1 OK: trigger_id=68636 effect_id=68637\n") == 68636
    assert parse_c1_result("C1 trigger FAIL: error=5\n") == 0
    assert parse_c1_result("") == 0


def test_overall_verdict_lets_the_poll_window_win():
    """§76.4 item 2: the script landed after the marker wait, so only the poll window saw it."""
    assert overall_verdict([
        ("neo_effect", "script_refused"),
        ("is_rim_system", "script_refused"),
        ("poll", "predicate_instantiate_once"),
    ]) == "predicate_instantiate_once"


def test_overall_verdict_prefers_the_first_evidence_window():
    assert overall_verdict([
        ("a", "predicate_instantiate_once"),
        ("b", "predicate_per_system"),
    ]) == "predicate_instantiate_once"


def test_overall_verdict_falls_back_to_the_first_window():
    assert overall_verdict([("a", "token_absent"), ("b", "no_calls")]) == "token_absent"


def test_a_delivered_but_unmarked_script_is_a_refusal_not_silence():
    """Review I1: `delivered` is transport; the marker is the engine's receipt."""
    assert window_refused({"delivered": True, "sent": False}) is True
    assert window_refused({"delivered": True, "sent": True}) is False
    stats = _stats(calls=9000)
    assert verdict(stats, [], 787, refused=window_refused({"delivered": True, "sent": False})) \
        == "script_refused"


def test_the_drain_buffer_is_sized_for_a_full_ring():
    """Review Critical 1: the drain used to reuse the 512 B stats buffer for a 10,240 B write."""
    src = (REPO / "scripts/c2_trigger_pred_probe.py").read_text(encoding="utf-8")
    assert "remote_alloc(pid, RING_LEN * ENTRY_SIZE)" in src
    assert "C4TrigPredSetDrainCap" in src
    assert mod.RING_LEN * mod.ENTRY_SIZE == 10240


def test_systems_zero_is_an_instrument_error_not_a_verdict():
    assert mod.main(["--systems", "0", "--script-file", "x"]) == mod.EXIT_INSTRUMENT


def test_cmd_file_default_is_the_supervisor_channel():
    """The 2026-10-28 shot wrote `ns_cmd.txt` — a path no daemon reads — so both windows
    read `script_refused` with `.seen` never created. Pin the default to the real channel."""
    import c4_wiring_probe

    assert mod.DEFAULT_CMD_FILE.lower() == c4_wiring_probe.SUPERVISOR_CMD.lower()


def test_every_inject_site_is_gated():
    src = (REPO / "scripts/c2_trigger_pred_probe.py").read_text(encoding="utf-8")
    assert src.index("gate_install(") < src.index("inject_dll(")


def test_sha_gate_refuses_a_file_that_is_not_there(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        mod.sha_gate(str(tmp_path / "nope.dll"))
    assert exc.value.code == 2
    assert "nope.dll" in capsys.readouterr().err


def test_sha_gate_records_a_stable_digest(tmp_path):
    dll = tmp_path / "sqjs_c5.dll"
    dll.write_bytes(b"bytes-under-test")
    assert mod.sha_gate(str(dll)) == mod._sha256(str(dll))


def test_build_meta_records_the_injected_bytes_and_module():
    meta = mod.build_meta(
        dll_path=r"C:\temp\sqjs_c5.dll", dll_sha="ab" * 32, module_base=0x1A0000,
        systems=787, poll_s=120, settle_s=3, overall="predicate_instantiate_once",
        per_window=[("neo_effect", "predicate_instantiate_once")], windows=[],
        final_text="calls=0", cleanup={"uninstall_rc": 0, "verify_rc": 0, "host_alive": 1},
        trigger_token=10599, layout={"version": 1}, script_wait_s=180)
    assert meta["dll"] == "sqjs_c5.dll"
    assert meta["dll_sha256"] == "ab" * 32
    assert meta["module_base"] == "0x1a0000"


def test_sha_gate_runs_before_the_process_is_touched():
    src = (REPO / "scripts/c2_trigger_pred_probe.py").read_text(encoding="utf-8")
    assert src.index("sha_gate(args.dll)") < src.index("return run(")


def test_preflight_refuses_a_script_file_that_is_not_there(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        mod.preflight_paths(str(tmp_path / "typo.txt"), str(tmp_path / "ns_game_cmd.txt"))
    assert exc.value.code == 2
    assert "typo.txt" in capsys.readouterr().err


def test_preflight_refuses_a_command_channel_no_daemon_reads(tmp_path, capsys):
    script = tmp_path / "scripts.txt"
    script.write_text('effect every_system = { log = "X" }\n', encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        mod.preflight_paths(str(script), str(tmp_path / "ns_cmd.txt"))
    assert exc.value.code == 2
    assert mod.SUPERVISOR_CMD_NAME in capsys.readouterr().err


def test_preflight_accepts_the_supervisor_channel_even_in_another_directory(tmp_path):
    script = tmp_path / "scripts.txt"
    script.write_text('effect every_system = { log = "X" }\n', encoding="utf-8")
    assert mod.preflight_paths(str(script), str(tmp_path / mod.SUPERVISOR_CMD_NAME)) is None
