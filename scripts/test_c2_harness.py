"""Host-only smoke tests for the shared C2 remote-injection harness.

These run on Linux with **no game process and no Windows API access**. Only the
pure, host-testable logic is exercised here:

  * ``list_exports``        — a real PE export-directory parser, verified against
                              the built artifact ``zig-out/bin/stellaris_quickjs.dll``
                              (produced by ``zig build`` in this worktree).
  * ``parse_module_base_from_ps`` — the standalone base-address decoder used by
                              ``resolve_base_address``. It must accept both the
                              ``0x``-prefixed hex form and the DECIMAL form that
                              PowerShell's ``BaseAddress`` actually emits on the
                              target machine (ruling P2).

The Win32-dependent helpers (``resolve_base_address``, ``inject_dll``,
``call_remote``, ``call_remote_with_arg``, ``read_memory``, ``read_u64``,
``assert_game_alive``) bind kernel32 LAZILY so that importing this
module is side-effect-free on Linux (ruling P3); their remote-call behaviour is
exercised only on the real Windows machine in Tasks 2+ and is deliberately not
mocked here. ``resolve_pid`` is no Win32 binding at all — pure ``tasklist``
subprocess parsing — so its filter semantics ARE pinned by a host test below
(Task 2 live-run regression).

``c2_task3_diag`` is importable on the Linux host for the same reason (only
pure defs run at import). Its pure log-parsing helper ``parse_ctx`` — the rc==0
success gate's decoder — is pinned by host tests at the bottom of this file;
the probe's remote-call control flow stays Windows-only. ``c2_task5_init``
likewise contributes one pure helper, ``parse_pointers`` (the 16-byte
C2QuickJSPointersInto buffer decoder), pinned by host tests below, and
``c2_task6_e2e`` contributes ``decode_probe_rc`` (the C2EvalProbe exit-code
decoder: sentinel names vs the ``n*4+3`` encoding), pinned below as well.

**One deliberate exception to "remote control flow is not mocked":** §36's
log read-back (``fetch_diag_log`` / ``report_init_failure``) is the mechanism
that decides whether an expensive live shot is readable at all, and it is pure
Python over module-level harness callables that can be monkeypatched without
touching kernel32. Its argument order, buffer size, and dead-host behaviour are
pinned here; everything still-Windows-only stays unmocked.
"""

import os
import struct

import pytest

import c2_harness
import c2_task5_init
from c2_harness import list_exports, parse_module_base_from_ps, resolve_pid
from c2_task3_diag import parse_ctx
from c2_task5_init import (
    parse_pointers, decode_init_rc, fetch_diag_log, report_init_failure,
)
from c2_task6_e2e import decode_probe_rc

# The built DLL is at <repo root>/zig-out/bin/... . Tests are invoked from the
# repo root (``python3 -m pytest scripts/test_c2_harness.py``), but resolve the
# path relative to THIS file so the suite is cwd-independent and robust.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DLL_PATH = os.path.join(_REPO_ROOT, "zig-out", "bin", "stellaris_quickjs.dll")


def test_list_exports_finds_C2Sanity():
    exports = list_exports(DLL_PATH)
    assert "C2Sanity" in exports
    assert isinstance(exports["C2Sanity"], int)
    assert exports["C2Sanity"] > 0


def test_parse_module_base_handles_16_hex_digits():
    assert parse_module_base_from_ps("0x00007FF441D20000") == 0x7FF441D20000


def test_parse_module_base_rejects_truncated_string():
    with pytest.raises(ValueError):
        parse_module_base_from_ps("not-a-hex")


# --- ruling P2: PowerShell BaseAddress returns DECIMAL on the live machine -----

def test_parse_module_base_accepts_decimal_live_value():
    # 140696081727488 is the exact value the live machine printed; its hex form
    # (0x7ff65bf90000) is what a rebuilt/ASLR'd run would show. Decimal decode
    # must match the same number computed as hex.
    assert parse_module_base_from_ps("140696081727488") == 140696081727488
    assert parse_module_base_from_ps("140696081727488") == 0x7FF65BF90000


def test_parse_module_base_hex_and_decimal_agree():
    # One base expressed two ways must decode to one int.
    assert parse_module_base_from_ps("0x7FF65BF90000") == parse_module_base_from_ps("140696081727488")


def test_parse_module_base_rejects_empty():
    with pytest.raises(ValueError):
        parse_module_base_from_ps("")


# --- parser must actually read the PE, not a hard-coded table -----------------

def test_list_exports_recovers_all_known_names():
    exports = list_exports(DLL_PATH)
    # A handful of names that genuinely exist in the artifact (progress.md list).
    for name in ("C2Sanity", "C2Init", "C2DiagQJS", "C2DiagGetLogAddr",
                 "C2TestQJS", "C2RegisterEffect", "C2RegisterTrigger",
                 "C2DiagQJSInto", "C2QuickJSPointersInto", "C2LogInto",
                 "C2EvalProbeOnePlusOne"):
        assert name in exports, f"missing real export {name!r}"
    # RVAs are distinct positive integers, proving a real directory walk.
    rvas = list(exports.values())
    assert all(isinstance(r, int) and r > 0 for r in rvas)
    assert len(set(rvas)) == len(rvas)


def test_list_exports_missing_file_raises():
    with pytest.raises((FileNotFoundError, ValueError)):
        list_exports(os.path.join(_REPO_ROOT, "zig-out", "bin", "does_not_exist.dll"))


# --- resolve_pid: tasklist IMAGENAME filter is EXACT, with extension ----------

def test_resolve_pid_appends_exe_for_bare_name(monkeypatch):
    """Task 2 live-run regression: tasklist only matches 'IMAGENAME eq
    stellaris.exe'; 'eq stellaris' returns the 'no tasks' INFO line. A bare
    name must be normalized to '<name>.exe' for both the filter and the
    row comparison."""
    captured = []

    def fake_check_output(cmd, *args, **kwargs):
        captured.append(cmd)
        filt = cmd[cmd.index("/FI") + 1]
        if filt == "IMAGENAME eq stellaris.exe":
            return b'"stellaris.exe","20564","Console","1","490,028 K"\n'
        return b"INFO: No tasks are running which match the specified criteria.\n"

    monkeypatch.setattr(c2_harness.subprocess, "check_output", fake_check_output)
    assert resolve_pid("stellaris") == 20564
    assert captured[-1][captured[-1].index("/FI") + 1] == "IMAGENAME eq stellaris.exe"


def test_resolve_pid_accepts_full_image_name(monkeypatch):
    def fake_check_output(cmd, *args, **kwargs):
        return b'"stellaris.exe","20564","Console","1","490,028 K"\n'

    monkeypatch.setattr(c2_harness.subprocess, "check_output", fake_check_output)
    assert resolve_pid("stellaris.exe") == 20564


def test_resolve_pid_raises_when_not_running(monkeypatch):
    def fake_check_output(cmd, *args, **kwargs):
        return b"INFO: No tasks are running which match the specified criteria.\n"

    monkeypatch.setattr(c2_harness.subprocess, "check_output", fake_check_output)
    with pytest.raises(RuntimeError, match="not running"):
        resolve_pid("stellaris")


# --- c2_task3_diag.parse_ctx: read the 'ctx=%p' token out of a diag log -------
# The probe's rc==0 success gate must never treat rc==0/ctx-NULL as OK, which
# needs a pure parser turning the log's 'ctx=' token into a pointer-as-int, or
# None when the token is absent.

def test_parse_ctx_null_pointer_is_zero_int():
    # Windows renders a NULL pointer via '%p' as 16 zeros — must decode to 0,
    # NOT to None, so the caller can distinguish 'NULL ctx' from 'no ctx token'.
    log = "rt=000001ABCDEF raw_ok diag_rc=0 ctx=0000000000000000"
    assert parse_ctx(log) == 0


def test_parse_ctx_real_nonzero_pointer():
    log = "rt=000001ABCDEF raw_ok diag_rc=0 ctx=000001AB1234"
    assert parse_ctx(log) == 0x000001AB1234


def test_parse_ctx_token_absent_returns_none():
    # An outer-sentinel log that never reached JS_NewContextDiag has no ctx=.
    log = "rt=000001ABCDEF no_process_heap"
    assert parse_ctx(log) is None


def test_parse_ctx_surrounded_by_extra_text():
    # 'ctx=' appears mid-log with other tokens around it; parser must isolate it.
    log = "prefix garbage ctx=7FF65BF90000 suffix more=123"
    assert parse_ctx(log) == 0x7FF65BF90000


def test_parse_ctx_empty_string_returns_none():
    assert parse_ctx("") is None


# --- c2_task5_init.parse_pointers: decode the 16-byte pointer buffer ----------
# The Task 5 probe reads the C2QuickJSPointersInto output buffer (rt at +0,
# ctx at +8, native-width little-endian on x86-64) and must be able to tell
# "rt NULL" from "ctx NULL" from "both NULL" — so 0 must decode to the int 0,
# never raise, and only a wrong-length buffer is an error.

def test_parse_pointers_two_realistic_non_null():
    # Typical Windows x64 heap/module addresses from live runs so far.
    raw = struct.pack("<QQ", 0x7FF65BF90000, 0x000001ABCDEF0120)
    assert parse_pointers(raw) == (0x7FF65BF90000, 0x000001ABCDEF0120)


def test_parse_pointers_rt_nonnull_ctx_null():
    # "init got partway" shape: rt live, ctx NULL. Must decode, not raise —
    # the caller diagnoses which one is NULL.
    raw = struct.pack("<QQ", 0x000001ABCDEF0120, 0)
    rt, ctx = parse_pointers(raw)
    assert rt == 0x000001ABCDEF0120
    assert ctx == 0


def test_parse_pointers_both_zero():
    assert parse_pointers(struct.pack("<QQ", 0, 0)) == (0, 0)


def test_parse_pointers_wrong_length_raises():
    for bad in (b"", b"\x00" * 8, b"\x00" * 15, b"\x00" * 17):
        with pytest.raises(ValueError):
            parse_pointers(bad)


# --- c2_task6_e2e.decode_probe_rc: the C2EvalProbe exit-code contract ---------
# The gate's whole verdict rides on this mapping, so it is pinned here rather
# than only on the live box. Encoding (quickjs_wrapper.c C2EvalProbe):
#   0 = no_ctx, 1 = exception, 2 = not_int32, n*4+3 = int32 n.
# Because 4n+3 is always congruent to 3 (mod 4), a value can never be read as a
# sentinel; the decoder must reject anything else. call_remote hands back an
# UNSIGNED c_uint, so a C-int result that is negative arrives wrapped, and the
# decoder re-biases it before matching the sentinels.

def test_decode_probe_rc_one_plus_one_is_eleven_decoding_to_two():
    # The Task 6 gate itself (ruling P20: 1+1 = 2, so 2*4+3 = 11).
    assert decode_probe_rc(11) == ("int32", 2)


def test_decode_probe_rc_sentinels_name_without_value():
    assert decode_probe_rc(0) == ("no_ctx", None)
    assert decode_probe_rc(1) == ("exception", None)
    assert decode_probe_rc(2) == ("not_int32", None)


def test_decode_probe_rc_three_is_value_zero_not_a_sentinel():
    # The discrimination the encoding exists for: n = 0 must NOT read as "no ctx".
    assert decode_probe_rc(3) == ("int32", 0)


def test_decode_probe_rc_negative_rc_raises():
    for bad in (-1, -4, -1000):
        with pytest.raises(ValueError):
            decode_probe_rc(bad)


def test_decode_probe_rc_non_congruent_raises():
    # 4,5,6 (mod 4 = 0,1,2) are not sentinels, so they cannot be encodings.
    for bad in (4, 5, 6, 10, 42, 2 ** 32 - 1 - 1):
        with pytest.raises(ValueError):
            decode_probe_rc(bad)


def test_decode_probe_rc_wraps_an_unsigned_negative_result():
    # C returns int; a negative result crosses as an unsigned 32-bit exit code
    # (n = -1 -> 4n+3 = -1 -> 0xFFFFFFFF). Re-biasing must recover n = -1.
    assert decode_probe_rc(2 ** 32 - 1) == ("int32", -1)


# --- c2_task5_init.decode_init_rc — the C2Init exit-code decoder ------------
#
# Why this exists (evidence §36.3/§36.4). The 2026-10-21 live shot came back
# `C2Init rc = 3` and there was NO way to say which of two mutually exclusive
# states produced it: the wrapper's outer step 3 (runtime opaque write/read
# mismatch, which returns BEFORE any context exists) and JS_NewContextDiag's
# inner step 3 (JS_AddIntrinsicDate failing, which had a context and freed it)
# share the number, and `C2TestQuickJS` — unlike `C2DiagQuickJS` — wrote no log
# at all, so §32's "the log text is authoritative" had nothing to point at. The
# outer codes now live at 100..104, the inner ones stay 1..12, so the number
# alone identifies the path. The decoder pins that non-overlap; if someone
# collapses the ranges again these tests go red before the probe does.

def test_decode_init_rc_zero_is_ok():
    assert decode_init_rc(0) == ("ok", None)


def test_decode_init_rc_outer_range_names_the_pre_context_steps():
    # 100..104 = quickjs_wrapper.c's own gates, all of which return BEFORE
    # JS_NewContextDiag ran — so no JS context ever existed on these paths.
    assert decode_init_rc(100) == ("outer", "no_process_heap")
    assert decode_init_rc(101) == ("outer", "heap_alloc_failed")
    assert decode_init_rc(102) == ("outer", "runtime2_null")
    assert decode_init_rc(103) == ("outer", "opaque_mismatch")
    assert decode_init_rc(104) == ("outer", "raw_ctx_null")


def test_decode_init_rc_inner_range_names_the_intrinsics():
    assert decode_init_rc(1) == ("intrinsic", "raw_ctx_alloc")
    assert decode_init_rc(2) == ("intrinsic", "BaseObjects")
    assert decode_init_rc(3) == ("intrinsic", "Date")
    assert decode_init_rc(4) == ("intrinsic", "Eval")
    assert decode_init_rc(5) == ("intrinsic", "StringNormalize")
    assert decode_init_rc(6) == ("intrinsic", "RegExp")
    assert decode_init_rc(7) == ("intrinsic", "JSON")
    assert decode_init_rc(8) == ("intrinsic", "Proxy")
    assert decode_init_rc(9) == ("intrinsic", "MapSet")
    assert decode_init_rc(10) == ("intrinsic", "TypedArrays")
    assert decode_init_rc(11) == ("intrinsic", "Promise")
    assert decode_init_rc(12) == ("intrinsic", "WeakRef")


def test_decode_init_rc_three_is_now_unambiguously_the_date_intrinsic():
    # The exact value that was unreadable on the live box: 3 can no longer be the
    # opaque-mismatch site, because that site moved to 103.
    assert decode_init_rc(3)[0] == "intrinsic"
    assert decode_init_rc(103)[0] == "outer"


def test_decode_init_rc_unmapped_values_raise():
    # Gaps in the encoding must be loud, not silently bucketed.
    for bad in (13, 50, 99, 105, 200):
        with pytest.raises(ValueError):
            decode_init_rc(bad)


def test_decode_init_rc_negative_and_wrapped_raise():
    # call_remote hands back an UNSIGNED c_uint; a C-int negative would arrive
    # wrapped, and no C2TestQuickJS path returns negative anyway. Reject both.
    with pytest.raises(ValueError):
        decode_init_rc(-1)
    with pytest.raises(ValueError):
        decode_init_rc(2 ** 32 - 1)


# --- §36.4 read-back: a failing C2Init shot has to interpret itself -----------
#
# The live shot that started this: `C2Init rc = 3`, then the game vanished. The
# number alone said nothing, and the only export that could have filled in the
# text (C2DiagQJSInto) re-runs the whole init sequence — on a host that lost the
# process 2/2 times after reaching QuickJS init, a "fetch the diagnostic" step
# must not secretly be another init. These pin the shape of the read-back: the
# argument order, the 512-byte buffer, and that a dead host is REPORTED rather
# than raising an unrelated error out of the probe.

def _patch_log_read(monkeypatch, log_bytes, reported_len, alive=True):
    """Install fakes for the four harness callables fetch_diag_log uses.

    Returns the dict the fakes record into, so a test can assert on the actual
    CreateRemoteThread arguments instead of only on the decoded text.
    """
    seen = {}

    def fake_remote_alloc(pid, size):
        seen["alloc_size"] = size
        return 0x7FFD0000

    def fake_call_remote_with_arg(pid, base, rva, arg, timeout_ms=30000):
        seen.update(pid=pid, base=base, rva=rva, arg=arg, timeout_ms=timeout_ms)
        return reported_len

    def fake_read_memory(pid, addr, size):
        seen.update(read_pid=pid, read_addr=addr, read_size=size)
        return log_bytes

    def fake_assert_game_alive(pid):
        if not alive:
            raise RuntimeError(f"game (pid {pid}) is no longer alive")

    monkeypatch.setattr(c2_task5_init, "remote_alloc", fake_remote_alloc)
    monkeypatch.setattr(
        c2_task5_init, "call_remote_with_arg", fake_call_remote_with_arg
    )
    monkeypatch.setattr(c2_task5_init, "read_memory", fake_read_memory)
    monkeypatch.setattr(c2_task5_init, "assert_game_alive", fake_assert_game_alive)
    return seen


def test_fetch_diag_log_passes_the_remote_buffer_as_the_only_argument(monkeypatch):
    text = b"rt=7FFD1234 raw_ok diag_rc=0 ctx=7FFD5678\x00\x00\x00garbage"
    seen = _patch_log_read(monkeypatch, text, 38)

    assert fetch_diag_log(4242, 0x180000000, 0x44BFB0) == \
        "rt=7FFD1234 raw_ok diag_rc=0 ctx=7FFD5678"
    # lpParameter is the buffer address, the RVA is C2LogInto's, nothing else
    # crossed — and the buffer is the full 512 the C contract assumes.
    assert seen["alloc_size"] == 512
    assert seen["arg"] == 0x7FFD0000
    assert seen["rva"] == 0x44BFB0
    assert seen["base"] == 0x180000000
    assert seen["read_size"] == 512


def test_fetch_diag_log_survives_a_length_mismatch_instead_of_losing_the_text(
    monkeypatch, capsys
):
    # C2LogInto reports the strlen it wrote. If the read-back disagrees the text
    # is still the evidence we need — warn, never discard it, never raise.
    _patch_log_read(monkeypatch, b"heap_alloc_failed\x00" + b"\x00" * 40, 15)
    assert fetch_diag_log(1, 2, 3) == "heap_alloc_failed"

    _patch_log_read(monkeypatch, b"heap_alloc_failed\x00" + b"\x00" * 40, 99)
    assert fetch_diag_log(1, 2, 3) == "heap_alloc_failed"
    assert "WARNING" in capsys.readouterr().out


def test_report_init_failure_decodes_and_reads_the_log_for_an_inner_code(monkeypatch):
    seen = _patch_log_read(
        monkeypatch,
        b"rt=7FFD1234 raw_ok diag_rc=2 err=[BaseObjects: InternalError: out of memory]\x00",
        74,
    )

    decoded = report_init_failure(4242, 0x180000000, 0x44BFB0, 2)
    assert decoded == "bucket=intrinsic name=BaseObjects"
    assert seen["rva"] == 0x44BFB0


def test_report_init_failure_reports_unmapped_codes_loudly_and_still_reads_the_log(
    monkeypatch,
):
    # An unmapped number means the wrong module answered — the log is exactly what
    # shows that, so the read-back must happen anyway.
    seen = _patch_log_read(monkeypatch, b"no_process_heap\x00" + b"\x00" * 40, 15)
    decoded = report_init_failure(1, 2, 3, 200)
    assert decoded.startswith("UNMAPPED")
    assert "200" in decoded
    assert seen["rva"] == 3


def test_report_init_failure_does_not_dispatch_into_a_dead_host(monkeypatch, capsys):
    # The §36.3 shape: the process is gone by the time the rc comes back. Reading
    # its memory would raise an unrelated RuntimeError and bury the diagnosis.
    _patch_log_read(monkeypatch, b"", 0, alive=False)
    decoded = report_init_failure(4242, 0x180000000, 0x44BFB0, 103)
    assert decoded == "bucket=outer name=opaque_mismatch"
    assert "host gone before the read-back" in capsys.readouterr().out
