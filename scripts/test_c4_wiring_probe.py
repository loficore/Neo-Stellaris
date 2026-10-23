import pathlib
import struct
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import c4_wiring_probe as mod
from c4_wiring_probe import (
    EXPECTED_TIERS, PREFLIGHT_MARKERS, RECORD_SIZE, SAVE_SHA,
    SCORE_COUNT, apply_console, campaign_gate, capture_console,
    classify_apply, classify_capture, classify_delivery,
    column_sequences, count_marker_lines, decode_pred_stats, decode_records,
    decode_scored_stats, decode_wire_stats, expected_tiers, find_scope_column,
    pack_spec, preflight_console, preflight_gate, predicate_delta,
    supervisor_ready, unpack_spec,
)

CTX_OFF, A3_OFF, TARGETS_OFF, WINDOWS_OFF = 56, 1000, 1256, 1320
WIRE_KEYS = ["mode", "records", "dropped", "calls", "resolved", "unresolved",
             "tier0", "tier1", "tier2", "js_err", "chain", "last_id", "last_tier",
             "armed_token", "spec_blob", "spec_deref", "spec_off_a", "spec_off_b",
             "reserved0", "reserved1"]
SCORED_LINE = ("armed=1 token=4242 budget_left=4084 scored_calls=787 skipped=0 busy=0 "
               "js_err=0 invalid=0 tier0=717 tier1=55 tier2=15 last_id=786 last_tier=2")

def _put32(blob, off, value):
    struct.pack_into("<I", blob, off, value)

def _put64(blob, off, value):
    struct.pack_into("<Q", blob, off, value)

def _make_record(serial, ctx=None, a3=None, targets=(), windows=()):
    ctx = bytearray(944) if ctx is None else bytearray(ctx)
    a3 = bytearray(256) if a3 is None else bytearray(a3)
    rec = bytearray(RECORD_SIZE)
    struct.pack_into("<IIII", rec, 0, 1, 4242, serial, 0)
    struct.pack_into("<QQQ", rec, 16, 0x100000, 0x110000, 0x200000)
    struct.pack_into("<IIII", rec, 40, len(a3), len(targets), len(ctx), 0)
    rec[CTX_OFF:CTX_OFF + len(ctx)] = ctx
    rec[A3_OFF:A3_OFF + len(a3)] = a3
    for i, target in enumerate(targets):
        _put64(rec, TARGETS_OFF + 8 * i, target)
    for i, window in enumerate(windows):
        start = WINDOWS_OFF + 256 * i
        rec[start:start + len(window)] = bytes(window)
    return bytes(rec)

def _linear_records(count, value_off=0x38):
    out = []
    for i in range(count):
        ctx = bytearray(944)
        _put32(ctx, value_off, i)
        out.append(_make_record(i, ctx))
    return decode_records(b"".join(out))

def test_pack_spec_round_trips_direct_and_deref():
    assert pack_spec(0, 0, 0x38, 0) == 0x38 << 16
    assert unpack_spec(pack_spec(0, 0, 0x38, 0)) == {
        "blob": 0, "deref": 0, "off_a": 0x38, "off_b": 0}
    p = pack_spec(1, 1, 0x10, 0x20)
    assert p == 1 | (1 << 8) | (0x10 << 16) | (0x20 << 32)
    assert unpack_spec(p) == {"blob": 1, "deref": 1, "off_a": 0x10, "off_b": 0x20}
    for args in [(2, 0, 0x38, 0), (0, 2, 0x38, 0), (0, 0, 0x39, 0),
                 (0, 0, 0x400, 0), (0, 0, 0x38, 0x10), (0, 1, 0x10, 0x400),
                 (1, 1, 0x400, 0x20), (0, 0, -4, 0)]:
        with pytest.raises(ValueError):
            pack_spec(*args)
    with pytest.raises(ValueError):
        unpack_spec(1 << 63)

def test_decode_records_rejects_trailing_bytes():
    ctx = bytearray(944); _put32(ctx, 0x38, 5)
    a3 = bytearray(256); _put32(a3, 0x10, 9)
    window = bytearray(256); _put32(window, 0x20, 7)
    raw = _make_record(3, ctx, a3, (0x200000,), (window,))
    [rec] = decode_records(raw)
    assert (rec["valid"], rec["token"], rec["serial"]) == (1, 4242, 3)
    assert (rec["a3_len"], rec["ptr_count"], rec["ctx_len"]) == (256, 1, 944)
    assert struct.unpack_from("<I", rec["ctx"], 0x38)[0] == 5
    assert struct.unpack_from("<I", rec["a3"], 0x10)[0] == 9
    assert rec["ptr_targets"] == [0x200000]
    assert struct.unpack_from("<I", rec["ptr_windows"][0], 0x20)[0] == 7
    with pytest.raises(ValueError):
        decode_records(raw + b"\0")

def test_decode_wire_stats_reads_every_field():
    raw = struct.pack("<20I", *range(20))
    assert decode_wire_stats(raw) == dict(zip(WIRE_KEYS, range(20)))
    with pytest.raises(ValueError):
        decode_wire_stats(raw[:76])
    with pytest.raises(ValueError):
        decode_wire_stats(raw + b"\0\0\0\0")


def test_decode_pred_stats_reads_every_field():
    data = struct.pack("<QQII", 7, 3, 0xABCD, 1)
    assert decode_pred_stats(data) == {
        "pred_calls": 7, "pred_patched": 3,
        "last_token": 0xABCD, "installed": 1}
    with pytest.raises(ValueError):
        decode_pred_stats(data[:23])


def test_predicate_delta_subtracts_the_pre_capture_counters():
    before = {"pred_calls": 100, "pred_patched": 90,
              "last_token": 7, "installed": 1}
    after = {"pred_calls": 1087, "pred_patched": 877,
             "last_token": 7, "installed": 1}
    assert predicate_delta(before, after) == {"calls": 987, "patched": 787}


def test_classify_capture_separates_delivery_from_routing():
    find = {"status": "none"}
    empty = {"calls": 0, "records": 0, "dropped": 0}
    assert classify_capture(empty, [], find) == "no_calls"
    assert classify_capture(empty, [], find, {"calls": 0, "patched": 0}) == "predicate_not_reached"
    assert classify_capture(empty, [], find, {"calls": 787, "patched": 0}) == "predicate_not_matched"
    assert classify_capture(empty, [], find, {"calls": 787, "patched": 787}) == "execute_not_reached"

def test_decode_scored_stats_requires_every_key_once():
    got = decode_scored_stats(SCORED_LINE)
    assert len(got) == 13
    assert (got["tier0"], got["tier1"], got["tier2"]) == (717, 55, 15)
    assert (got["last_id"], got["last_tier"]) == (786, 2)
    with pytest.raises(ValueError):
        decode_scored_stats(SCORED_LINE.replace("tier2=15 ", ""))
    with pytest.raises(ValueError):
        decode_scored_stats(SCORED_LINE + " js_err=1")
    with pytest.raises(ValueError):
        decode_scored_stats(SCORED_LINE + " extra=1")
    idle = ("armed=0 token=0 budget_left=0 scored_calls=0 skipped=0 busy=0 "
            "js_err=0 invalid=0 tier0=0 tier1=0 tier2=0 last_id=0 last_tier=-1")
    assert decode_scored_stats(idle)["last_tier"] == -1

def test_column_sequences_maps_pointer_windows_to_source_offsets():
    ctx0, ctx1 = bytearray(944), bytearray(944)
    for ctx, value in ((ctx0, 0), (ctx1, 1)):
        _put32(ctx, 0x38, value)
        _put64(ctx, 0x10, 0x200000)
    w0, w1 = bytearray(256), bytearray(256)
    _put32(w0, 0x20, 7); _put32(w1, 0x20, 8)
    records = decode_records(b"".join([
        _make_record(0, ctx0, targets=(0x200000,), windows=(w0,)),
        _make_record(1, ctx1, targets=(0x200000,), windows=(w1,)),
    ]))
    cols = dict(column_sequences(records))
    assert cols["ctx+0x38"] == [0, 1]
    assert cols["ctx->[+0x10]+0x20"] == [7, 8]

def test_column_sequences_tolerates_plausible_pointer_the_dll_skipped():
    ctx = bytearray(944)
    _put32(ctx, 0x38, 3)
    _put64(ctx, 0x10, 0x200000)
    _put64(ctx, 0x18, 0x300000)  # plausible, but its window read failed in the DLL
    window = bytearray(256)
    _put32(window, 0x20, 9)
    [rec] = decode_records(
        _make_record(0, ctx, targets=(0x200000,), windows=(window,)))
    cols = dict(column_sequences([rec]))
    assert cols["ctx+0x38"] == [3]
    assert cols["ctx->[+0x10]+0x20"] == [9]
    assert "ctx->[+0x18]+0x20" not in cols

def test_column_sequences_only_maps_the_eight_recorded_targets():
    ctx = bytearray(944)
    targets = tuple(0x200000 + 0x100000 * i for i in range(8))
    windows = []
    for i in range(8):
        window = bytearray(256)
        _put32(window, 0x20, i)
        windows.append(window)
        _put64(ctx, 0x10 + 8 * i, targets[i])
    _put64(ctx, 0x10 + 8 * 8, 0x9000000)  # ninth plausible qword, beyond PTR_SLOTS
    [rec] = decode_records(
        _make_record(0, ctx, targets=targets, windows=tuple(windows)))
    cols = dict(column_sequences([rec]))
    assert cols["ctx->[+0x10]+0x20"] == [0]
    assert cols["ctx->[+0x48]+0x20"] == [7]
    assert "ctx->[+0x50]+0x20" not in cols

def test_find_scope_column_accepts_the_unique_exact_column():
    found = find_scope_column(_linear_records(787))
    assert found["status"] == "ok"
    assert found["column"] == "ctx+0x38"
    assert found["spec"] == {"blob": 0, "deref": 0, "off_a": 0x38, "off_b": 0}

def test_find_scope_column_rejects_permutation_and_ambiguity():
    reversed_records = []
    for i, value in enumerate(reversed(range(787))):
        ctx = bytearray(944); _put32(ctx, 0x38, value)
        reversed_records.append(_make_record(i, ctx))
    assert find_scope_column(decode_records(b"".join(reversed_records)))["status"] == "permutation"
    two = []
    for i in range(787):
        ctx = bytearray(944); _put32(ctx, 0x38, i); _put32(ctx, 0x40, i)
        two.append(_make_record(i, ctx))
    assert find_scope_column(decode_records(b"".join(two)))["status"] == "ambiguous_column"
    assert find_scope_column(_linear_records(786))["status"] == "count_mismatch"
    none_records = []
    for i in range(787):
        ctx = bytearray(944); _put32(ctx, 0x39, i & 0xFF)  # 非 4 对齐,且不构成 plausible qword
        none_records.append(_make_record(i, ctx))
    assert find_scope_column(decode_records(b"".join(none_records)))["status"] == "none"

def test_expected_tiers_match_the_shipped_table():
    text = (ROOT / "evidence/xrefs/chokepoint_scores_4_4_4.tsv").read_text(encoding="utf-8")
    scores = [int(row.split("\t")[4]) for row in text.splitlines()[1:] if row.strip()]
    assert len(scores) == 787
    assert expected_tiers(scores) == EXPECTED_TIERS == (717, 55, 15)

def test_campaign_gate_matrix():
    assert campaign_gate(SAVE_SHA, SAVE_SHA, False) == "ok"
    assert campaign_gate("0" * 64, SAVE_SHA, False) == "campaign_mismatch"
    assert campaign_gate(None, SAVE_SHA, False) == "campaign_unverified"
    assert campaign_gate("0" * 64, SAVE_SHA, True) == "drift_allowed"
    assert campaign_gate(None, SAVE_SHA, True) == "campaign_unverified"

def test_console_commands_use_keyword_shape_and_a_per_system_name_token():
    cap = capture_console(4242)
    app = apply_console(4242)
    assert cap.startswith("effect every_system = {")
    assert app.startswith("effect every_system = {")
    assert "effect = {" not in cap
    assert "NEO_CHOKE_EFFECT_[This.GetName]" in cap
    assert "NEO_CHOKE_EFFECT_[This.GetName]" in app
    command = preflight_console(4242)
    assert command.startswith("effect every_system = {")
    assert "C4_PREFLIGHT_4242_[This.GetName]" in command


def test_phase_sentinels_carry_pid_and_phase():
    cap = capture_console(4242)
    app = apply_console(4242)
    assert "C4_CAPSTART_4242_[This.GetName]" in cap
    assert "C4_APPSTART_4242_[This.GetName]" in app
    assert cap != app
    assert "C4_APPSTART_4242" not in cap
    assert "C4_CAPSTART_4242" not in app


def test_classify_delivery_matrix():
    assert classify_delivery(0, "capture") == "capture_not_delivered"
    assert classify_delivery(PREFLIGHT_MARKERS, "capture") == "ok"
    assert classify_delivery(PREFLIGHT_MARKERS - 1, "capture") == "capture_sentinel_mismatch"
    assert classify_delivery(0, "apply") == "apply_not_delivered"
    assert classify_delivery(PREFLIGHT_MARKERS, "apply") == "ok"
    assert classify_delivery(PREFLIGHT_MARKERS + 1, "apply") == "apply_sentinel_mismatch"


def test_send_console_failure_aborts_before_the_game_runs_the_command(monkeypatch):
    monkeypatch.setattr(mod, "_send_console", lambda path, text: False)
    with pytest.raises(mod._Abort) as exc:
        mod._send_console_or_abort("cmd.txt", "effect every_system = { }")
    assert exc.value.verdict == "console_send_failed"

def test_preflight_gate_uses_the_logsink_collapsed_count():
    assert preflight_gate(0) == "console_unavailable"
    assert preflight_gate(PREFLIGHT_MARKERS) == "ok"
    assert preflight_gate(SCORE_COUNT) == "campaign_mismatch"

def test_count_marker_lines_counts_only_log_effect_lines():
    text = ('[effect.cpp:123]: effect every_system = { log = '
            '"NEO_CHOKE_EFFECT_[This.GetName]" }\n'
            '[17:00:00][effect_impl.cpp:21978]: [2243.10.29] Log effect, '
            'file:  line: 1. NEO_CHOKE_EFFECT_维林努斯\n'
            '[17:00:00][effect_impl.cpp:21978]: [2243.10.29] Log effect, '
            'file:  line: 1. NEO_CHOKE_EFFECT_亚帕西诺尔\n')
    assert count_marker_lines(text, "NEO_CHOKE_EFFECT") == 2

def test_supervisor_ready_rejects_stale_status_and_playing():
    assert supervisor_ready(None, now=100.0) == "supervisor_not_running"
    assert supervisor_ready({"state": "paused", "epoch": 99.0}, now=100.0) == "ok"
    assert supervisor_ready({"state": "paused", "epoch": 90.0}, now=100.0) == "supervisor_not_running"
    assert supervisor_ready({"state": "playing", "epoch": 99.0}, now=100.0) == "supervisor_not_paused"
    assert supervisor_ready({"state": "no_game", "epoch": 99.0}, now=100.0) == "supervisor_not_running"
    assert supervisor_ready({"state": "stopped", "epoch": 99.0}, now=100.0) == "supervisor_not_running"

def test_classify_capture_and_apply():
    cap = {"calls": 787, "records": 787, "dropped": 0}
    ok_find = {"status": "ok", "column": "ctx+0x38",
               "spec": {"blob": 0, "deref": 0, "off_a": 0x38, "off_b": 0},
               "columns": ["ctx+0x38"]}
    assert classify_capture({"calls": 0, "records": 0, "dropped": 0}, [], {"status": "none"}) == "no_calls"
    assert classify_capture(cap, [], {"status": "none"}) == "no_readable_ctx"
    assert classify_capture(cap, [None] * 786, {"status": "count_mismatch"}) == "count_mismatch"
    assert classify_capture(cap, [None] * 787, {"status": "none"}) == "no_scope_column"
    assert classify_capture(cap, [None] * 787, {"status": "permutation"}) == "scope_order_unverified"
    assert classify_capture(cap, [None] * 787, {"status": "ambiguous_column"}) == "ambiguous_column"
    assert classify_capture(cap, [None] * 787, ok_find) == "ok"
    zero = {"calls": 0, "resolved": 0, "unresolved": 0, "tier0": 0,
            "tier1": 0, "tier2": 0, "chain": 0}
    full = {"calls": 787, "resolved": 787, "unresolved": 0, "tier0": 717,
            "tier1": 55, "tier2": 15, "chain": 70}
    clean = {"js_err": 0, "invalid": 0}
    assert classify_apply(zero, zero, clean, 0) == "apply_no_calls"
    assert classify_apply(zero, full, {"js_err": 1, "invalid": 0}, 70) == "scored_js_error"
    assert classify_apply(zero, dict(full, unresolved=1), clean, 70) == "apply_count_mismatch"
    assert classify_apply(zero, dict(full, tier2=14), clean, 70) == "tier_mismatch"
    assert classify_apply(zero, dict(full, chain=69), clean, 70) == "chain_mismatch"
    assert classify_apply(zero, full, clean, 69) == "log_mismatch"
    assert classify_apply(zero, full, clean, 70) == "ok"

def test_c1_run_precedes_effect_id_read_and_c2_init():
    source = (ROOT / "scripts" / "c4_wiring_probe.py").read_text()
    run_at = source.index('exports["C1Run"]')
    id_at = source.index('exports["C1EffectId"]')
    init_at = source.index('exports["C2Init"]')
    assert run_at < id_at < init_at

def _log_lines(n):
    return "".join(
        "[17:00:00][effect_impl.cpp:21978]: [2243.10.29] Log effect, "
        "file:  line: 1. m_%d\n" % i for i in range(n))


def _fake_sleeps(monkeypatch, texts):
    import c4_wiring_probe as probe
    feed = iter(texts)
    clock = {"t": 0.0}

    def fake_read(path, offset):
        clock["t"] += 0.5
        return next(feed, texts[-1])

    monkeypatch.setattr(probe, "_read_text_from", fake_read)
    monkeypatch.setattr(probe.time, "time", lambda: clock["t"])
    monkeypatch.setattr(probe.time, "sleep", lambda s: None)
    return probe


def test_wait_marker_keeps_polling_past_a_nonzero_plateau(monkeypatch):
    probe = _fake_sleeps(monkeypatch, [_log_lines(5), _log_lines(10),
                                       _log_lines(10), _log_lines(70)])
    assert probe._wait_marker("x", 0, "m", 70, timeout=30.0) == 70


def test_wait_marker_returns_the_max_seen_when_the_deadline_passes(monkeypatch):
    probe = _fake_sleeps(monkeypatch, [_log_lines(5), _log_lines(10),
                                       _log_lines(3)])
    assert probe._wait_marker("x", 0, "m", 70, timeout=2.0) == 10

def test_shot_sha_ignores_a_screenshot_the_supervisor_never_refreshed(tmp_path):
    import hashlib
    import c4_wiring_probe as probe
    shot = tmp_path / "shot.png"
    shot.write_bytes(b"stale-frame")
    mtime = probe._file_mtime(str(shot))
    assert probe._shot_sha(str(shot), mtime) is None
    assert probe._shot_sha(str(shot), mtime - 1) == (
        hashlib.sha256(b"stale-frame").hexdigest())


def test_cleanup_downgrades_ok_when_the_disarm_call_raises(monkeypatch):
    import c4_wiring_probe as probe

    def boom(*a, **k):
        raise RuntimeError("host gone")

    monkeypatch.setattr(probe.harness, "call_remote_with_arg", boom)
    monkeypatch.setattr(probe.harness, "call_remote", boom)
    monkeypatch.setattr(probe.harness, "assert_game_alive", lambda pid: None)
    state = {"pid": 4321, "base": 0x100000,
             "exports": {"C4WireSetMode": 1, "C4WireDisarm": 2}}
    result = {"verdict": "ok", "detail": "",
              "cleanup": {"disarm_rc": None, "host_alive": None}}
    probe._cleanup(state, result)
    assert result["cleanup"]["disarm_rc"] is None
    assert result["cleanup"]["host_alive"] is True
    assert result["verdict"] == "cleanup_incomplete"
