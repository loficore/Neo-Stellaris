#!/usr/bin/env python3
"""Offline fences for `scripts/c2_trigger_eval_probe.py` (C5 data plane, second probe).

No game, no Windows API: every test below runs the driver's pure judgement面.
The authority pins read the repo itself (the Zig source and the driver's own source),
not a copy of them.
"""
import pathlib
import struct

import pytest

import c2_trigger_eval_probe as mod
from c2_trigger_eval_probe import (
    EVIDENCE_VERDICTS,
    STATS_KEYS,
    VERDICTS,
    artifact_rows,
    decode_entry,
    decode_layout,
    install_decision,
    verdict,
)

REPO = pathlib.Path(__file__).resolve().parent.parent
ZIG = REPO / "src/dll/c2/trigger_eval_probe.zig"


def _stats(**over):
    """A full stats dict — the driver refuses a stats line with a missing key, so the
    tests must build all ten of them."""
    stats = {
        "calls": 0,
        "token_matched": 0,
        "distinct_ctx": 0,
        "dedupe_full": 0,
        "ctx_null": 0,
        "patch_size": 14,
        "installed": 1,
        "verify": 0,
        "last_token": 0,
        "last_tag": 0,
    }
    stats.update(over)
    return stats


def test_verdict_sixteen_off_the_denominator_is_not_per_system():
    """The denominator is the CURRENT campaign's star count; 2% is the tolerance and it
    is not negotiable per task (§76 陷阱 3: 787 belongs to another save)."""
    stats = _stats(calls=787, token_matched=787, distinct_ctx=771)
    assert verdict(stats, [], 787) == "ctx_not_per_system"


def test_verdict_distinct_equals_systems_is_per_system():
    stats = _stats(calls=787, token_matched=787, distinct_ctx=787)
    assert verdict(stats, [], 787) == "ctx_per_system"


def test_verdict_one_distinct_is_single():
    stats = _stats(calls=1, token_matched=1, distinct_ctx=1)
    assert verdict(stats, [], 787) == "ctx_single"


def test_verdict_zero_calls_is_environment_not_evidence():
    stats = _stats(calls=0, token_matched=0)
    assert verdict(stats, [], 787) == "no_calls"
    assert verdict(stats, [], 787) not in EVIDENCE_VERDICTS


def test_verdict_an_unverified_restore_beats_every_reading():
    stats = _stats(calls=787, token_matched=787, distinct_ctx=787, verify=2)
    assert verdict(stats, [], 787) == "instrument_broken"


def test_a_script_refusal_is_not_a_silent_instrument():
    stats = _stats(calls=787, token_matched=787, distinct_ctx=787)
    assert verdict(stats, [], 787, refused=True) == "script_refused"


def test_entry_is_forty_eight_bytes_in_the_zig_order():
    """The Entry shape is a contract between the two sides: the driver unpacks it, so the
    field order and the size live in the Zig source and are pinned here."""
    src = ZIG.read_text(encoding="utf-8")
    assert '@sizeOf(Entry) != 48' in src
    fields = ["token", "ctx_tag", "sub_vtable_rva", "self_vtable_rva", "occurrences",
              "ctx_ptr", "a3", "sub_obj"]
    positions = [src.index(f"{name}:") for name in fields]
    assert positions == sorted(positions)
    assert mod.ENTRY_SIZE == 48


def test_stats_keys_match_the_dll_text_line():
    """The driver parses the DLL's one-line k=v stats; a key that drifts is a hard error,
    not a defaulted zero."""
    src = ZIG.read_text(encoding="utf-8")
    start = src.index('"calls={d} token_matched={d}')
    line = src[start:src.index('\\n"', start)]
    keys = tuple(part.split("=")[0].strip().strip('"')
                 for part in line.split("{d}") if part.strip())
    assert keys == STATS_KEYS


def test_layout_word_order_matches_the_dll():
    words = [1, 48, 256, 56, 0x1A91A80, 32]
    layout = decode_layout(words)
    assert layout["version"] == 1
    assert layout["entry_size"] == 48
    assert layout["ring_len"] == 256
    assert layout["stats_size"] == 56
    assert layout["target_rva"] == 0x1A91A80
    assert layout["prologue_len"] == 32
    assert install_decision(words) is None


def test_install_decision_refuses_a_stale_target():
    assert "target rva" in install_decision([1, 48, 256, 56, 0x349230, 32])


def test_mask_only_accepts_zero():
    assert mod.parse_mask("0") == 0
    with pytest.raises(ValueError):
        mod.parse_mask("1")


def test_sha_gate_refuses_a_file_that_is_not_there(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        mod.sha_gate(str(tmp_path / "nope.dll"))
    assert exc.value.code == 2
    assert "nope.dll" in capsys.readouterr().err


def test_refuse_if_resident_stops_when_the_name_is_already_mapped(capsys):
    """A mapped same-name module makes LoadLibraryA hand back that image, so the sha we
    recorded would attest a file that never ran (2026-10-28 review I-1)."""
    with pytest.raises(SystemExit) as exc:
        mod.refuse_if_resident("sqjs_c5.dll", 0x7FF0_1234_0000)
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "sqjs_c5.dll" in err
    assert "0x7ff012340000" in err


def test_preflight_refuses_the_supervisor_name_in_another_directory(tmp_path, capsys):
    """The daemon reads one absolute path: a right-named file elsewhere is never consumed,
    so the shot would burn 2 x --script-wait-s and read `script_refused` (review I-2)."""
    script = tmp_path / "scripts.txt"
    script.write_text('effect every_system = { log = "X" }\n', encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        mod.preflight_paths(str(script), str(tmp_path / mod.SUPERVISOR_CMD_NAME))
    assert exc.value.code == 2
    assert mod.SUPERVISOR_CMD_DIR in capsys.readouterr().err


def test_sha_gate_runs_before_the_process_is_resolved():
    src = (REPO / "scripts/c2_trigger_eval_probe.py").read_text(encoding="utf-8")
    assert src.index("sha_gate(args.dll)") < src.index("harness.resolve_pid(")


def test_every_verdict_is_in_the_domain():
    for name in VERDICTS:
        assert name in VERDICTS
    assert EVIDENCE_VERDICTS == ("ctx_per_system", "ctx_single", "ctx_not_per_system")


def test_decode_entry_reads_the_zig_field_order():
    raw = struct.pack("<BBHIIIIIQQQ", 1, 1, 0, 0x4321, 0x426, 0x1A91A80, 0x2606FE0,
                       3, 0x7FF0_0000_2000, 0x7FF0_0000_3000, 0x7FF0_0000_4000)
    row = decode_entry(raw)
    assert row["token"] == 0x4321
    assert row["ctx_tag"] == 0x426
    assert row["sub_vtable_rva"] == 0x1A91A80
    assert row["self_vtable_rva"] == 0x2606FE0
    assert row["occurrences"] == 3
    assert row["ctx_ptr"] == 0x7FF0_0000_2000
    assert row["a3"] == 0x7FF0_0000_3000
    assert row["sub_obj"] == 0x7FF0_0000_4000


def test_artifact_rows_carry_the_ctx_columns():
    rows = artifact_rows([{
        "token": 0x4321, "ctx_tag": 0x426, "sub_vtable_rva": 0x1A91A80,
        "self_vtable_rva": 0x2606FE0, "occurrences": 3,
        "ctx_ptr": 0x7FF0_0000_2000, "a3": 0x7FF0_0000_3000,
        "sub_obj": 0x7FF0_0000_4000,
    }])
    assert rows[0].split("\t") == ["token", "ctx_tag", "sub_vtable_rva",
                                  "self_vtable_rva", "occurrences", "ctx_ptr",
                                  "a3", "sub_obj"]
    assert rows[1].split("\t")[0] == str(0x4321)  # the token column is decimal, like the
    # four sibling drivers


def test_verdict_zero_distinct_is_not_evidence():
    """2026-10-29 review C-1: `distinct_ctx == 0` means "this window observed no new
    ctx", not "ctx is not per system" — the second reading is a conclusion we did not
    earn, and it was sitting in the evidence verdicts."""
    stats = _stats(calls=120, token_matched=120, distinct_ctx=0)
    assert verdict(stats, [], 787) == "ctx_no_new"
    assert verdict(stats, [], 787) not in EVIDENCE_VERDICTS


def test_window_delta_differences_only_the_cumulative_counters():
    """The ctx population is per-token and absolute; only the frequency counters are
    differenced between windows (2026-10-29 review C-2 / M-4)."""
    current = _stats(calls=900, token_matched=787, distinct_ctx=787)
    previous = _stats(calls=100, token_matched=12, distinct_ctx=0)
    delta = mod.window_delta(current, previous)
    assert delta["calls"] == 800
    assert delta["token_matched"] == 775
    assert delta["distinct_ctx"] == 787  # absolute, not a difference


def test_every_pre_fire_refusal_exits_two():
    """Exit 1 means "the shot ran and found no evidence"; an install refusal is an
    instrument failure and must not look like that (2026-10-29 review M-2)."""
    import re

    src = (REPO / "scripts/c2_trigger_eval_probe.py").read_text(encoding="utf-8")
    raises = re.findall(r"raise SystemExit\(([^)]*)\)", src)
    assert raises, "the driver has no pre-fire refusal at all"
    assert all(r.strip() == "EXIT_INSTRUMENT" for r in raises), raises
    assert mod.EXIT_INSTRUMENT == 2
