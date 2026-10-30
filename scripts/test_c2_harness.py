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

The two §45 tools promoted out of ``scripts/scratch/2026-10_abortexit/`` contribute
host-pure logic too: ``c2_selfabort_repro`` owns the tool's key-line set (now
including the ``MFREC`` ring-recorder channel) and the abort-signature verdict
predicate, and ``dll_ubsan_site`` reads a file copy of our DLL, so its ``func``
mode is exercised against the built artifact. Both are imported through
``importlib`` inside their test rather than at the top of this file: ``c2_selfabort_repro``
drives a child process on Windows and must stay import-safe here, and a missing or broken
one of the two must read as two failing tests, not as a collection error that hides every
other test in the file.

**One deliberate exception to "remote control flow is not mocked":** §36's
log read-back (``fetch_diag_log`` / ``report_init_failure``) is the mechanism
that decides whether an expensive live shot is readable at all, and it is pure
Python over module-level harness callables that can be monkeypatched without
touching kernel32. Its argument order, buffer size, and dead-host behaviour are
pinned here; everything still-Windows-only stays unmocked. §38 widens that
exception to the polling dispatcher ``dispatch_watching_buffer``, because the
ordering inside it (read, THEN ask whether the thread finished) is the whole
reason it beats the read-after-wait that lost two live shots — and an ordering
bug like that is invisible to any test that only runs against a real process.
"""

import ctypes
import hashlib
import importlib
import os
import re
import struct

import pytest

import c2_harness
import c2_init_threadstate
import c2_task5_init
from c2_harness import (
    list_exports, parse_module_base_from_ps, resolve_pid, dispatch_watching_buffer,
    pe_image_size, classify_rip, filetime_us, format_thread_state, CONTEXT,
    CONTEXT_READ_MASK, capture_thread_state, open_thread_handle,
)
from c2_task3_diag import parse_ctx
from c2_task5_init import (
    parse_pointers, decode_init_rc, describe_init_rc,
    fetch_diag_log, report_init_failure,
    diag_file_path, clear_diag_file, read_diag_file, last_diag_line, diag_file_rc,
    log_rva_from_truncated, poll_report_lines,
    format_memory_sample, memory_growth_lines, psutil_memory_sampler,
    sample_window,
)
from c2_control_sleep import plausible_sleep_ms
from c2_control_cpuwatch import format_cpu_sample, cpu_advance_us
from c2_control_suspendcap import (
    CAPABLE, INCAPABLE, PARTIAL, NO_SAMPLES,
    thread_ids, suspend_cap_verdict, cap_lines,
)
from c2_task6_e2e import decode_probe_rc
from c2_init_threadstate import (
    EXECUTING_IN_DLL, EXECUTING_ELSEWHERE, BLOCKED, INCONCLUSIVE,
    thread_cpu_us, thread_state_verdict, thread_state_lines, make_thread_probe,
)

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
                 "C2EvalProbeOnePlusOne", "C2EvalStressOne",
                 "C1EffectId", "C2ExecInstall", "C2ExecProbeInstall",
                 "C2ExecProbeUninstall", "C2ExecProbeVerify", "C2ExecDisarm",
                 "C2ExecStatsInto", "C2ExecProbeStatsInto",
                 "C5PerSystemInstall", "C5PerSystemUninstall", "C5PerSystemVerify",
                 "C5PerSystemLayout", "C5PerSystemStatsInto", "C5PerSystemSetDrainCap",
                 "C5PerSystemDrainInto", "C5PerSystemReset"):
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


# --- §38 recovering an RVA from a truncated pointer -------------------------
#
# C2DiagGetLogAddr hands back `g_diag_log`'s address, and only 32 bits of a remote
# thread's return value survive GetExitCodeThread (ruling P4). The POINTER is
# therefore unusable — but a pointer into the loaded image is base + rva, so the
# RVA comes back exactly by subtraction mod 2**32, which is what lets the probe
# poll the static directly instead of trusting the callee's end-of-sequence copy.

def test_log_rva_from_truncated_is_exact_inside_the_image():
    base = 0x7FFC7FE80000
    rva = 0x5C250
    assert log_rva_from_truncated((base + rva) & 0xFFFFFFFF, base) == rva


def test_log_rva_from_truncated_survives_the_low_32_bit_wrap():
    # A base near the top of the 32-bit range plus a small RVA wraps the truncated
    # value BELOW the RVA, so a naive comparison would reject the right answer.
    base = 0x7FFFFFFFFFF000
    rva = 0x2000
    truncated = (base + rva) & 0xFFFFFFFF
    assert truncated < rva
    assert log_rva_from_truncated(truncated, base) == rva


def test_log_rva_from_truncated_rejects_a_value_that_is_not_a_truncated_pointer():
    for bad in (-1, 0x1_0000_0000, 2 ** 64):
        with pytest.raises(ValueError):
            log_rva_from_truncated(bad, 0x7FFC7FE80000)


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


def test_describe_init_rc_formats_a_mapped_code():
    assert describe_init_rc(3) == "bucket=intrinsic name=Date"
    assert describe_init_rc(103) == "bucket=outer name=opaque_mismatch"
    assert describe_init_rc(0) == "bucket=ok name=None"


def test_describe_init_rc_never_raises_on_an_unmapped_code():
    # The report path calls this while a live host is dying; a ValueError escaping
    # here would bury the one number the operator needs.
    line = describe_init_rc(200)
    assert line.startswith("UNMAPPED")
    assert "200" in line


# --- §38 on-disk diagnostic channel ----------------------------------------
#
# The sequence appends "rc=<n> <log>" to C:/temp/c2_diag_<pid>.log before it
# returns, so the probe can still read the text after the host died. These are
# path/parsing tests over tmp_path; the DLL-side half of the contract is pinned
# natively in src/dll/quickjs/c2_diag_test.zig.


def test_diag_file_path_is_the_dir_the_dll_writes_to_keyed_on_pid():
    # A rename on either side without the other silently returns "" for every
    # shot, i.e. the dead-host case would look like "the log was never written".
    assert diag_file_path(4242) == "C:/temp/c2_diag_4242.log"


def test_clear_diag_file_reports_whether_a_stale_copy_existed(tmp_path):
    path = str(tmp_path / "c2_diag_1.log")
    assert clear_diag_file(path) is False
    with open(path, "w") as fh:
        fh.write("rc=0 old\n")
    assert clear_diag_file(path) is True
    assert not os.path.exists(path)


def test_read_diag_file_returns_empty_text_for_a_missing_file(tmp_path):
    assert read_diag_file(str(tmp_path / "never_written.log")) == ""


def test_read_and_last_diag_line_follow_append_semantics(tmp_path):
    path = str(tmp_path / "c2_diag_7.log")
    with open(path, "a") as fh:  # exactly what C2DiagQJSInto leaves behind...
        fh.write("rc=3 rt=0x1 raw_ok diag_rc=3 err=[Date: can't load date prototype]\n")
    assert last_diag_line(read_diag_file(path)).startswith("rc=3 ")
    with open(path, "a") as fh:  # ...and what the C2Init dispatch appends after it
        fh.write("rc=0 rt=0x2 raw_ok diag_rc=0 ctx=0x3\n")
    assert last_diag_line(read_diag_file(path)).startswith("rc=0 rt=0x2")


def test_last_diag_line_ignores_blank_lines_and_reports_absent_text():
    assert last_diag_line("") == ""
    assert last_diag_line("\n\n") == ""
    assert last_diag_line("rc=1 a\n\nrc=2 b\n\n") == "rc=2 b"


def test_diag_file_rc_reads_the_prefix_and_refuses_to_guess():
    assert diag_file_rc("rc=3 rt=0x1") == 3
    assert diag_file_rc("rc=104 raw_ctx_null") == 104
    assert diag_file_rc("rt=0x1 no prefix") is None
    assert diag_file_rc("rc=not-a-number tail") is None
    assert diag_file_rc("") is None


# --- §38 dispatch_watching_buffer: catch the log BEFORE the teardown ----------
#
# The shape this replaces: dispatch, wait, read. That lost the 22:41 shot (no host
# left for the second dispatch) and the 22:47 shot (gle 299 on a buffer the
# thread had already filled). The poller reads while the call runs, and the read
# that matters is the one in the SAME iteration that notices the thread finished.


_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_FAKE_THREAD = 0x1234
_FAKE_PROCESS = 0x999


def _patch_watch_dispatch(monkeypatch, chunks, exit_code=3, finish_after=None,
                          process_gone=False, prime_readable=True, prime_writable=True,
                          process_exit_code=None, witnesses=None):
    """Fake the kernel32 layer ``dispatch_watching_buffer`` drives.

    ``chunks`` are successive ``_read_with_handle`` results for the CALLER'S
    BUFFER; an exception instance in the list is raised instead of returned, and
    the last entry repeats forever. ``witnesses`` maps a remote address to its own
    chunk list, so a witness can stay readable while the buffer is not (the exact
    split the 23:44 shot could not tell apart). ``finish_after`` = how many thread
    waits report WAIT_TIMEOUT before the thread reports signaled (None = it never
    finishes on its own). ``process_gone`` makes the PROCESS handle report
    signaled — the only fake-side signal that the address space is gone.
    ``prime_readable``/``prime_writable`` fail the pre-dispatch round-trip on
    demand. ``process_exit_code`` defaults to ``exit_code``: a terminated thread
    inherits the process exit code, which is the ambiguity the caller has to see.

    Writes and the priming read are counted separately from ``reads``: they happen
    before ``CreateRemoteThread`` and must not shift the ``chunks`` sequence.
    """
    seen = {"reads": 0, "waits": 0, "thread_waits": 0, "process_waits": 0,
            "created_addr": None, "created_param": None,
            "writes": 0, "primed_bytes": 0, "created_before_prime": None,
            "wrote_addr": None, "read_addr": None,
            "witness_reads": {}}
    wait_state = {"index": 0}
    witness_state = {addr: 0 for addr in (witnesses or {})}

    def next_item(addr, bucket):
        table = witnesses[addr]
        index = min(bucket, len(table) - 1)
        item = table[index]
        if isinstance(item, BaseException):
            raise item
        return item

    class FakeK32:
        def WriteProcessMemory(self, process, addr, buf, size, written):
            seen["writes"] += 1
            seen["wrote_addr"] = addr.value if hasattr(addr, "value") else addr
            if not prime_writable:
                ctypes.cast(written, ctypes.POINTER(ctypes.c_size_t)).contents.value = 0
                return 0
            ctypes.cast(written, ctypes.POINTER(ctypes.c_size_t)).contents.value = size
            return 1

        def ReadProcessMemory(self, process, addr, buf, size, got):
            # Only the priming read-back reaches this method; the poll loop's reads
            # go through the patched _read_with_handle.
            n = size if prime_readable else 0
            ctypes.cast(got, ctypes.POINTER(ctypes.c_size_t)).contents.value = n
            seen["primed_bytes"] = n
            return 1 if prime_readable else 0

        def CreateRemoteThread(self, process, sa, stack, addr, param, flags, tid):
            seen["created_addr"] = addr.value
            seen["created_param"] = param.value
            seen["created_before_prime"] = seen["writes"]
            return _FAKE_THREAD

        def WaitForSingleObject(self, obj, ms):
            seen["waits"] += 1
            if obj == _FAKE_PROCESS:
                seen["process_waits"] += 1
                return _WAIT_OBJECT_0 if process_gone else _WAIT_TIMEOUT
            index = wait_state["index"]
            wait_state["index"] += 1
            seen["thread_waits"] += 1
            if finish_after is None:
                return _WAIT_TIMEOUT
            return _WAIT_OBJECT_0 if index >= finish_after else _WAIT_TIMEOUT

        def GetExitCodeThread(self, thread, out):
            ctypes.cast(out, ctypes.POINTER(ctypes.c_uint)).contents.value = exit_code

        def GetExitCodeProcess(self, process, out):
            code = exit_code if process_exit_code is None else process_exit_code
            ctypes.cast(out, ctypes.POINTER(ctypes.c_uint)).contents.value = code

        def CloseHandle(self, handle):
            pass

    def fake_read(handle, addr, size):
        if witnesses and addr in witnesses:
            bucket = witness_state[addr]
            witness_state[addr] += 1
            seen["witness_reads"][addr] = bucket + 1
            seen["witness_size"] = size
            return next_item(addr, bucket)
        seen["reads"] += 1
        seen["read_size"] = size
        seen["read_addr"] = addr
        item = chunks[min(seen["reads"] - 1, len(chunks) - 1)]
        if isinstance(item, BaseException):
            raise item
        return item

    monkeypatch.setattr(c2_harness, "_kernel32", lambda: FakeK32())
    monkeypatch.setattr(c2_harness, "_open_process", lambda pid: _FAKE_PROCESS)
    monkeypatch.setattr(c2_harness, "_read_with_handle", fake_read)
    return seen


def test_watched_dispatch_primes_the_buffer_before_creating_the_thread(monkeypatch):
    # The dispatch is single-use currency: a buffer this handle cannot read must
    # be found out before CreateRemoteThread, not after the callee already ran.
    seen = _patch_watch_dispatch(monkeypatch, [b"\x00" * 512], exit_code=259,
                                 finish_after=None)

    dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, timeout_ms=0)

    assert seen["writes"] == 1
    assert seen["primed_bytes"] == 512
    # Recorded INSIDE CreateRemoteThread: 1 write already landed when the thread
    # was created is the whole ordering claim.
    assert seen["created_before_prime"] == 1


def test_watched_dispatch_refuses_to_dispatch_an_unreadable_buffer(monkeypatch):
    seen = _patch_watch_dispatch(monkeypatch, [b"\x00" * 512], prime_readable=False)

    with pytest.raises(RuntimeError, match="prime ReadProcessMemory"):
        dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, timeout_ms=0)

    assert seen["created_addr"] is None
    assert seen["reads"] == 0


def test_watched_dispatch_refuses_to_dispatch_an_unwritable_buffer(monkeypatch):
    seen = _patch_watch_dispatch(monkeypatch, [b"\x00" * 512], prime_writable=False)

    with pytest.raises(RuntimeError, match="prime WriteProcessMemory"):
        dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, timeout_ms=0)

    assert seen["created_addr"] is None
    assert seen["reads"] == 0


def test_watched_dispatch_returns_the_log_the_callee_wrote_before_returning(monkeypatch):
    zeros = b"\x00" * 512
    written = (
        b"rt=7FFD1234 raw_ok diag_rc=3 err=[Date: can't load date prototype]"
        + b"\x00" * 400
    )
    seen = _patch_watch_dispatch(
        monkeypatch, [zeros, written], exit_code=3, finish_after=None
    )

    rc, text = dispatch_watching_buffer(4242, 0x180000000, 0x44C1D0, 0x7280000, 512,
                                       poll_ms=1)

    assert rc == 3
    assert text == "rt=7FFD1234 raw_ok diag_rc=3 err=[Date: can't load date prototype]"
    # One argument crossed the thread boundary (ruling P4): the function address and
    # the caller's buffer, nothing else.
    assert seen["created_addr"] == 0x180000000 + 0x44C1D0
    assert seen["created_param"] == 0x7280000
    assert seen["read_size"] == 512


def test_watched_dispatch_keeps_the_longest_read_when_the_copy_is_caught_mid_write(
    monkeypatch
):
    partial = b"rt=7FFD1234 raw_ok diag" + b"\x00" * 470
    full = b"rt=7FFD1234 raw_ok diag_rc=3 err=[Date: x]" + b"\x00" * 460
    _patch_watch_dispatch(monkeypatch, [partial, full], exit_code=3, finish_after=None)

    rc, text = dispatch_watching_buffer(
        1, 0x10000, 0x10, 0x2000, 512, marker=b"diag_rc=", poll_ms=1
    )

    assert rc == 3
    assert text == "rt=7FFD1234 raw_ok diag_rc=3 err=[Date: x]"


def test_watched_dispatch_reads_in_the_same_iteration_that_sees_the_thread_finish(
    monkeypatch
):
    # The ordering this pins: read, THEN ask if the thread finished. Ask-first would
    # break on the finishing iteration without ever taking the post-return read —
    # which is precisely the 22:47 loss (exit code arrives, buffer unreadable).
    full = b"rt=7FFD1234 raw_ok diag_rc=3 err=[Date: x]" + b"\x00" * 460
    seen = _patch_watch_dispatch(monkeypatch, [full], exit_code=3, finish_after=0)

    rc, text = dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1)

    assert rc == 3
    assert text == "rt=7FFD1234 raw_ok diag_rc=3 err=[Date: x]"
    assert seen["reads"] == 1


def test_watched_dispatch_still_returns_the_exit_code_when_the_buffer_is_gone(
    monkeypatch
):
    # A host already tearing down must not cost us the rc — the one number that
    # always arrives. Empty text plus a real exit code is the honest answer. The
    # PROCESS handle is what says so; a failed read alone does not.
    seen = _patch_watch_dispatch(
        monkeypatch,
        [RuntimeError("ReadProcessMemory @0x2000 size=512 read 0 bytes (ok=0, gle=299)")],
        exit_code=103,
        finish_after=None,
        process_gone=True,
    )

    rc, text = dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1)

    assert rc == 103
    assert text == ""
    assert seen["process_waits"] == 1
    assert seen["reads"] == 1


def test_watched_dispatch_gives_up_at_the_deadline_with_what_it_saw(monkeypatch):
    # Never written, thread never finishes, host alive: the timeout path must
    # return rather than spin, and report 259 (STILL_ACTIVE) as the exit code it
    # actually got.
    _patch_watch_dispatch(monkeypatch, [b"\x00" * 512], exit_code=259, finish_after=None)

    rc, text = dispatch_watching_buffer(
        1, 0x10000, 0x10, 0x2000, 512, timeout_ms=0, poll_ms=1
    )

    assert rc == 259
    assert text == ""


def test_watched_dispatch_keeps_polling_through_failed_reads_until_the_thread_finishes(
    monkeypatch
):
    # The 23:26 shot's first read of a freshly committed buffer failed with gle 299
    # while the host was alive and the thread had not returned, and the old
    # five-strikes rule ended the poll about 10 ms in — thousands of iterations
    # before the C sequence could answer. Nothing but the deadline, the thread, or
    # the process may end it.
    boom = RuntimeError("ReadProcessMemory @0x2000 size=512 read 0 bytes (ok=0, gle=299)")
    seen = _patch_watch_dispatch(monkeypatch, [boom], exit_code=259,
                                 finish_after=7, process_gone=False)

    events = []
    rc, text = dispatch_watching_buffer(
        1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, note=events.append
    )

    assert seen["reads"] == 8
    assert seen["thread_waits"] == 8
    assert rc == 259
    assert text == ""
    # The iteration that sees the thread finish still takes its read (8 waits,
    # 8 reads), and the whole failure run is ONE summary line, not one per strike.
    assert any("stop: thread finished after 8 failed read(s)" in e for e in events)
    assert sum("failed read" in e for e in events) == 1


def test_watched_dispatch_reports_a_failed_read_run_when_the_buffer_recovers(
    monkeypatch
):
    # Transient gle 299 followed by a good read: the recovery must be visible, and
    # the text that arrives after it is still the answer.
    boom = RuntimeError("ReadProcessMemory @0x2000 size=512 read 0 bytes (ok=0, gle=299)")
    written = b"raw_ok diag_rc=3 err=[Date: x]" + b"\x00" * 470
    seen = _patch_watch_dispatch(monkeypatch, [boom, boom, written], exit_code=3,
                                 finish_after=None)

    events = []
    rc, text = dispatch_watching_buffer(
        1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, note=events.append
    )

    assert seen["reads"] == 3
    assert rc == 3
    assert text == "raw_ok diag_rc=3 err=[Date: x]"
    assert any("read recovered after 2 failed read(s)" in e for e in events)


# --- §38 witnesses + exit-code provenance -----------------------------------
#
# The 23:44 shot could not answer two questions it needed to: (a) was the WHOLE
# process unreadable, or only the buffer we allocated? — a witness read of an
# address the DLL owns settles it; (b) was the reported rc = 3 the remote
# thread's own return value, or the process exit code the thread inherited when
# TerminateProcess ran? — reading GetExitCodeProcess alongside
# GetExitCodeThread settles it.


_LOG_ADDR = 0x180000000 + 0x44C250


def test_watched_dispatch_keeps_witness_text_the_caller_buffer_never_received(
    monkeypatch
):
    boom = RuntimeError("ReadProcessMemory @0x2000 size=512 read 0 bytes (ok=0, gle=299)")
    witness = b"rt=7FFD1234 raw_ok " + b"\x00" * 490
    seen = _patch_watch_dispatch(
        monkeypatch, [boom], exit_code=3, finish_after=None,
        witnesses={_LOG_ADDR: [witness]},
    )
    report = {}

    rc, text = dispatch_watching_buffer(
        1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, timeout_ms=0, report=report,
        witnesses=(("g_diag_log", _LOG_ADDR, 512),),
    )

    assert rc == 3
    assert text == ""
    assert seen["witness_reads"][_LOG_ADDR] == 1
    assert seen["witness_size"] == 512
    # The trailing space is the C log's own step separator, kept verbatim.
    assert report["witness"]["g_diag_log"]["best_text"] == "rt=7FFD1234 raw_ok "
    assert report["witness"]["g_diag_log"]["oks"] == 1
    assert report["witness"]["g_diag_log"]["fails"] == 0


def test_watched_dispatch_separates_an_unreadable_witness_from_an_unreadable_buffer(
    monkeypatch
):
    # Both addresses failing is the signature of the process being unreadable, not
    # of our allocation; the report has to say so per witness.
    boom = RuntimeError("ReadProcessMemory read 0 bytes (ok=0, gle=299)")
    _patch_watch_dispatch(
        monkeypatch, [boom], exit_code=3, finish_after=None, process_gone=True,
        witnesses={_LOG_ADDR: [boom]},
    )
    report = {}

    dispatch_watching_buffer(
        1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, timeout_ms=0, report=report,
        witnesses=(("g_diag_log", _LOG_ADDR, 512),),
    )

    w = report["witness"]["g_diag_log"]
    assert w["oks"] == 0 and w["fails"] >= 1
    assert w["best_text"] == ""


def test_watched_dispatch_grows_the_witness_text_as_the_callee_writes_it(
    monkeypatch
):
    # The buffer stays zero-filled the whole time, so the ONLY thing ending the
    # poll is the thread signalling — which takes four iterations, giving the
    # witness four reads and the static three growing contents.
    _patch_watch_dispatch(
        monkeypatch, [b"\x00" * 512], exit_code=3, finish_after=3,
        witnesses={_LOG_ADDR: [b"rt=1234 ", b"rt=1234 raw_ok ",
                               b"rt=1234 raw_ok diag_rc=3", b"rt=1234 raw_ok diag_rc=3"]},
    )
    report = {}

    dispatch_watching_buffer(
        1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, report=report,
        witnesses=(("g_diag_log", _LOG_ADDR, 512),),
    )

    assert report["witness"]["g_diag_log"]["oks"] == 4
    assert report["witness"]["g_diag_log"]["best_text"] == "rt=1234 raw_ok diag_rc=3"


def test_watched_dispatch_records_both_exit_codes_when_the_host_dies(monkeypatch):
    # A thread killed by process termination reports the PROCESS exit code, so a
    # bare rc of 3 is only a step code if the thread returned while the process was
    # still alive. Here the process died first and both codes agree.
    boom = RuntimeError("ReadProcessMemory read 0 bytes (ok=0, gle=299)")
    _patch_watch_dispatch(monkeypatch, [boom], exit_code=3, finish_after=None,
                          process_gone=True, process_exit_code=3)
    report = {}

    rc, text = dispatch_watching_buffer(
        1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, timeout_ms=0, report=report
    )

    assert rc == 3
    assert report["thread_exit_code"] == 3
    assert report["process_exit_code"] == 3
    assert report["thread_returned_while_alive"] is False


def test_watched_dispatch_records_a_thread_that_returned_before_the_host_died(
    monkeypatch
):
    _patch_watch_dispatch(monkeypatch, [b"rt=1234 raw_ok diag_rc=3"], exit_code=3,
                          finish_after=0, process_exit_code=0xC0000409)
    report = {}

    rc, text = dispatch_watching_buffer(
        1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, timeout_ms=0, report=report
    )

    assert rc == 3
    assert report["thread_returned_while_alive"] is True
    assert report["process_exit_code"] == 0xC0000409


def test_watched_dispatch_timeline_records_the_reads_and_their_ms(monkeypatch):
    boom = RuntimeError("ReadProcessMemory read 0 bytes (ok=0, gle=299)")
    written = b"rt=1234 raw_ok diag_rc=3" + b"\x00" * 475
    _patch_watch_dispatch(monkeypatch, [b"\x00" * 512, boom, written], exit_code=259,
                          finish_after=None)
    report = {}

    dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, report=report)

    assert report["primed_bytes"] == 512
    assert report["reads"] == 3
    assert report["read_failures"] == 1
    assert report["first_read_ms"] is not None
    assert report["first_failure_ms"] >= report["first_read_ms"]


# --- §38 reading the report: is the rc a step code at all? -------------------


def test_poll_report_flags_an_exit_code_the_thread_never_returned_while_alive():
    report = {
        "primed_bytes": 512, "reads": 88, "read_failures": 88,
        "first_read_ms": None, "first_failure_ms": 0.4,
        "thread_exit_code": 3, "process_exit_code": 3,
        "thread_returned_while_alive": False,
        "witness": {"g_diag_log": {"oks": 0, "fails": 88, "best_text": ""}},
    }

    lines = poll_report_lines(3, report)

    assert any("primed=512 reads=88 failures=88" in line for line in lines)
    assert any("thread exit code=3 process exit code=0x3" in line for line in lines)
    warning = [line for line in lines if line.startswith("WARNING")]
    assert len(warning) == 1
    # The warning has to name the alternative explanation, not just doubt.
    assert "PROCESS exit code" in warning[0]
    assert "unconfirmed" in warning[0]
    assert any("witness g_diag_log: oks=0 fails=88" in line for line in lines)


def test_poll_report_stays_quiet_when_the_thread_answered_before_the_host_died():
    report = {
        "primed_bytes": 512, "reads": 4, "read_failures": 0,
        "first_read_ms": 0.2, "first_failure_ms": None,
        "thread_exit_code": 3, "process_exit_code": 0xC0000409,
        "thread_returned_while_alive": True,
        "witness": {"g_diag_log": {"oks": 4, "fails": 0,
                                   "best_text": "rt=7FFD1234 raw_ok "}},
    }

    lines = poll_report_lines(3, report)

    assert not any(line.startswith("WARNING") for line in lines)
    assert any("text='rt=7FFD1234 raw_ok '" in line for line in lines)


# --- §38 host-side sampling during the dispatch ------------------------------


def test_watched_dispatch_polls_poll_addr_instead_of_the_argument(monkeypatch):
    # §39's Sleep control passes the SLEEP DURATION as lpParameter, so the address
    # worth watching is no longer the argument. poll_addr is the decoupling: the
    # thread starts at base+rva with arg_value as its parameter while the priming
    # and the poll both watch poll_addr.
    seen = _patch_watch_dispatch(monkeypatch, [b"\x00" * 512], exit_code=0,
                                 finish_after=0)
    report = {}

    rc, text = dispatch_watching_buffer(1, 0x10000, 0x10, 8000, 512, poll_ms=1,
                                        poll_addr=_LOG_ADDR, report=report)

    assert rc == 0
    assert text == ""
    assert seen["created_param"] == 8000
    assert seen["created_addr"] == 0x10000 + 0x10
    assert seen["wrote_addr"] == _LOG_ADDR
    assert seen["reads"] == 1
    assert seen["read_addr"] == _LOG_ADDR
    assert report["primed_bytes"] == 512


def test_watched_dispatch_samples_the_host_while_the_call_runs(monkeypatch):
    # sample_every_ms=0 makes the throttle a no-op, so one sample per iteration is
    # the deterministic shape this test can pin.
    _patch_watch_dispatch(monkeypatch, [b"\x00" * 512, b"\x00" * 512,
                                        b"raw_ok " + b"\x00" * 505], exit_code=3,
                          finish_after=None)
    calls = []
    report = {}

    dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1,
                             report=report, sample_every_ms=0,
                             sampler=lambda: calls.append(1) or f"n={len(calls)}")

    assert [value for _ms, value in report["samples"]] == ["n=1", "n=2", "n=3"]


def test_watched_dispatch_throttles_samples_to_the_requested_interval(monkeypatch):
    _patch_watch_dispatch(monkeypatch, [b"\x00" * 512, b"\x00" * 512, b"\x00" * 512,
                                        b"raw_ok " + b"\x00" * 505], exit_code=3,
                          finish_after=None)
    report = {}

    dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, report=report,
                             sample_every_ms=10_000, sampler=lambda: "once")

    assert len(report["samples"]) == 1


def test_watched_dispatch_keeps_the_rc_when_the_sampler_dies(monkeypatch):
    # The sampler reads the GAME's memory counters — a process vanishing underneath
    # it is the expected case, not a bug, and it must not cost the exit code.
    _patch_watch_dispatch(monkeypatch, [b"raw_ok " + b"\x00" * 505], exit_code=3,
                          finish_after=None)
    calls = []

    def boom():
        calls.append(1)
        raise OSError("pid 4248 no longer exists")

    report = {}
    rc, text = dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1,
                                        report=report, sample_every_ms=0,
                                        sampler=boom)

    assert rc == 3
    assert text == "raw_ok "
    assert len(report["samples"]) == 1
    assert "sampler raised" in report["samples"][0][1]


# --- §39 reading the memory samples the shot will produce --------------------


def test_format_memory_sample_reports_kib_and_labels_every_counter():
    # The live shot prints these lines; ambiguous units would make the growth
    # window un-readable after the fact, so the format is pinned here. The labels
    # are psutil's own field names, so the shot never needs re-interpreting.
    assert format_memory_sample(1500 * 1024, 1800 * 1024, 2048 * 1024) == (
        "rss=1500K vms=1800K private=2048K"
    )


def test_format_memory_sample_marks_an_unavailable_counter():
    # memory_full_info() needs a privilege memory_info() does not; a missing
    # private working set must read as "not measured", never as 0.
    assert format_memory_sample(1024, 2048, None) == "rss=1K vms=2K private=NA"


def test_memory_growth_lines_reports_first_last_and_net_delta():
    report = {"samples": [
        (0.0, "rss=1000K vms=1000K private=900K"),
        (250.0, "rss=1400K vms=1400K private=1300K"),
        (5000.0, "rss=900000K vms=900000K private=899000K"),
    ]}

    lines = memory_growth_lines(report)

    assert ("rss KiB: first=1000 last=900000 delta=+899000 samples=3 "
            "window=5000.0ms") in lines
    assert any(line.startswith("private KiB: ") for line in lines)


def test_memory_growth_lines_flags_a_shrinking_counter():
    report = {"samples": [
        (0.0, "rss=5000K vms=5000K private=5000K"),
        (100.0, "rss=1000K vms=1000K private=1000K"),
    ]}

    assert any("delta=-4000" in line for line in memory_growth_lines(report))


def test_memory_growth_lines_survives_the_failed_sample():
    # The dispatcher records 'sampler raised ...' as a sample; it carries no
    # counters, so it must be skipped rather than crash the summary.
    report = {"samples": [
        (0.0, "rss=100K vms=100K private=100K"),
        (7000.0, "sampler raised pid 21032 no longer exists"),
    ]}

    lines = memory_growth_lines(report)

    assert any("rss KiB: first=100 last=100 delta=+0 samples=1" in line for line in lines)
    assert any("sampler raised: pid 21032 no longer exists" in line for line in lines)


def test_memory_growth_lines_without_a_sampler_is_silent():
    assert memory_growth_lines({}) == []
    assert memory_growth_lines({"samples": []}) == []


def test_watched_dispatch_drops_a_sampler_raising_an_unexpected_type(monkeypatch):
    # psutil's error base is not an OSError in every version, and the sampling
    # channel must never be able to cost the measurement it is watching.
    _patch_watch_dispatch(monkeypatch, [b"raw_ok " + b"\x00" * 505], exit_code=3,
                          finish_after=None)

    def boom():
        raise ValueError("unexpected counter")

    report = {}
    rc, text = dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1,
                                        report=report, sample_every_ms=0,
                                        sampler=boom)

    assert rc == 3
    assert "sampler raised" in report["samples"][0][1]
    assert "unexpected counter" in report["samples"][0][1]


def test_psutil_memory_sampler_reads_counters_from_the_process_it_was_given():
    class FakeMem:
        def __init__(self, rss, vms):
            self.rss, self.vms = rss, vms

    class FakeProc:
        def __init__(self):
            self.calls = 0

        def memory_info(self):
            self.calls += 1
            return FakeMem(10 * 1024, 20 * 1024)

        def memory_full_info(self):
            return FakeMem(10 * 1024, 20 * 1024)

    proc = FakeProc()
    sampler = psutil_memory_sampler(proc)

    assert sampler() == "rss=10K vms=20K private=NA"
    assert proc.calls == 1


def test_psutil_memory_sampler_loses_private_when_full_info_raises():
    class FakeMem:
        rss, vms = 1024, 2048

    class DeniedProc:
        def memory_info(self):
            return FakeMem()

        def memory_full_info(self):
            raise OSError(5, "access denied")

    assert psutil_memory_sampler(DeniedProc())() == "rss=1K vms=2K private=NA"


# --- §39 the control window: sample WITHOUT dispatching ----------------------


class _FakeClock:
    """A clock that only moves when the code under test pauses it."""

    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_sample_window_collects_one_reading_per_interval():
    clock = _FakeClock()
    counter = iter(range(100))

    samples = sample_window(lambda: f"n={next(counter)}", 1000, 250,
                            clock=clock, pause=clock.sleep)

    assert [ms for ms, _t in samples] == [0.0, 250.0, 500.0, 750.0]
    assert [text for _ms, text in samples] == ["n=0", "n=1", "n=2", "n=3"]


def test_sample_window_stops_at_the_end_of_the_window():
    clock = _FakeClock()
    calls = []

    sample_window(lambda: calls.append(1) or "x", 1000, 250,
                  clock=clock, pause=clock.sleep)

    assert len(calls) == 4


def test_sample_window_records_a_raising_sampler_and_stops():
    # The control's whole point is that the host may vanish mid-window; the series
    # has to end with the reason instead of raising out of the watch loop.
    clock = _FakeClock()
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 3:
            raise OSError("pid 7820 no longer exists")
        return "rss=1000K vms=2000K private=NA"

    samples = sample_window(flaky, 10_000, 250, clock=clock, pause=clock.sleep)

    assert len(samples) == 3
    assert "sampler raised" in samples[-1][1]
    assert "pid 7820 no longer exists" in samples[-1][1]
    assert len(calls) == 3


def test_sample_window_zero_duration_reads_nothing():
    # The loop condition is `elapsed < duration`, so an empty window is empty and
    # not a surprise baseline reading the caller has to explain.
    clock = _FakeClock()

    assert sample_window(lambda: "rss=1K vms=2K private=NA", 0, 250,
                         clock=clock, pause=clock.sleep) == []


# --- §39 the Sleep control's calibration gate --------------------------------


def test_plausible_sleep_ms_accepts_the_jitter_of_a_real_timer():
    for wall in (500.0, 604.1, 1000.0, 1499.9):
        assert plausible_sleep_ms(wall, 1000), wall


def test_plausible_sleep_ms_rejects_an_instant_return():
    # A resolved address that is not the timer would return immediately (or at
    # once fail), and the long dispatch must not be made against it.
    assert not plausible_sleep_ms(2.0, 1000)
    assert not plausible_sleep_ms(499.0, 1000)


def test_plausible_sleep_ms_rejects_a_function_that_outlives_the_timer():
    assert not plausible_sleep_ms(20_000.0, 1000)
    assert not plausible_sleep_ms(1501.0, 1000)



# --- §44 the read-only thread-state probe ------------------------------------
#
# The window this exists to explain: §42's witness froze for 6.9 s with the log
# tail at `new_rt MmMmMm`, and §43 showed offline that no allocation happens in
# that window. Only two readings survive, and memory counters cannot separate
# them — the thread is executing, or it is alive and blocked. The discriminator
# is the thread's own `Rip` plus the CPU time charged to it, so the layout that
# carries `Rip` is the thing most worth pinning: a wrong offset reads padding and
# prints a plausible address while answering nothing.

_S44_BASE = 0x1000_0000
_S44_IMAGE_SIZE = 0x20_0000


def _s44_record(rip, thread_kernel_us=0, thread_user_us=0, ms=0.0):
    return {"rip": rip, "rsp": 0x8000_0000, "thread_kernel_us": thread_kernel_us,
            "thread_user_us": thread_user_us, "process_kernel_us": 0,
            "process_user_us": 0, "context_err": None, "times_err": None,
            "ms": ms}


def test_context_field_offsets_match_the_documented_amd64_layout():
    # MSDN's CONTEXT (amd64) offsets. Every one of these is a place a silent
    # 8-byte shift would put us in a neighbouring field — Rsp read as Rbp, Rip
    # read as the Xmm area — and the probe would still return 0 and look fine.
    for name, offset in (("P1Home", 0x00), ("P6Home", 0x28),
                         ("ContextFlags", 0x30), ("MxCsr", 0x34),
                         ("SegCs", 0x38), ("SegSs", 0x42), ("EFlags", 0x44),
                         ("Dr0", 0x48), ("Dr7", 0x70),
                         ("Rax", 0x78), ("Rcx", 0x80), ("Rdx", 0x88),
                         ("Rbx", 0x90), ("Rsp", 0x98), ("Rbp", 0xA0),
                         ("Rsi", 0xA8), ("Rdi", 0xB0),
                         ("R8", 0xB8), ("R9", 0xC0), ("R10", 0xC8),
                         ("R11", 0xD0), ("R12", 0xD8), ("R13", 0xE0),
                         ("R14", 0xE8), ("R15", 0xF0), ("Rip", 0xF8)):
        assert getattr(CONTEXT, name).offset == offset, name


def test_context_is_sized_so_windows_cannot_write_past_it():
    # The padding after Rip models the float/vector/debug tail we never read; if
    # it were short, GetThreadContext would be writing out of bounds. 1232 is the
    # documented sizeof(CONTEXT) on amd64.
    assert ctypes.sizeof(CONTEXT) == 1232


def test_rip_decodes_from_the_bytes_windows_writes_at_0xf8():
    # Offsets alone are a claim about the struct; this is the claim about the
    # wire. A 1232-byte buffer with a qword at 0xF8 is what Windows hands back.
    buf = bytearray(1232)
    struct.pack_into("<Q", buf, 0xF8, 0x7FF6_1234_5000)
    struct.pack_into("<Q", buf, 0x98, 0x0000_00AF_11E0)

    ctx = CONTEXT.from_buffer_copy(bytes(buf))

    assert ctx.Rip == 0x7FF6_1234_5000
    assert ctx.Rsp == 0x0000_00AF_11E0


def test_context_read_mask_is_amd64_control_and_integer():
    assert CONTEXT_READ_MASK == 0x0010_0011


def test_classify_rip_calls_the_module_range_by_name():
    assert classify_rip(_S44_BASE, _S44_BASE, _S44_IMAGE_SIZE) == "inside_dll"
    assert classify_rip(_S44_BASE + _S44_IMAGE_SIZE - 1, _S44_BASE,
                        _S44_IMAGE_SIZE) == "inside_dll"
    # The span is [base, base+SizeOfImage): the byte past it is somebody else's.
    assert classify_rip(_S44_BASE + _S44_IMAGE_SIZE, _S44_BASE,
                        _S44_IMAGE_SIZE) == "outside_dll"
    assert classify_rip(_S44_BASE - 1, _S44_BASE, _S44_IMAGE_SIZE) == "outside_dll"


def test_classify_rip_refuses_to_call_a_failed_read_outside_the_dll():
    # "No address" is not "an address elsewhere". Reading a failed capture as
    # outside_dll would manufacture exactly the §44 blocked verdict the probe
    # exists to test for.
    assert classify_rip(None, _S44_BASE, _S44_IMAGE_SIZE) == "unknown"


def test_filetime_us_converts_100ns_ticks_downward():
    # FILETIME units are 100 ns, so a microsecond is 10 units; whole microseconds
    # is the granularity worth printing, and rounding down keeps a flat counter
    # flat instead of accumulating a phantom advance sample by sample.
    assert filetime_us(10_000) == 1000
    assert filetime_us(19_999) == 1999
    assert filetime_us(9) == 0


def test_pe_image_size_covers_the_exports_of_the_built_dll():
    size = pe_image_size(DLL_PATH)

    # The SizeOfImage span must contain every export RVA, or the classifier's
    # upper bound would cut our own functions off and call them "outside".
    assert size % 0x1000 == 0
    assert max(list_exports(DLL_PATH).values()) < size


def test_pe_image_size_rejects_a_file_that_is_not_a_pe():
    with pytest.raises(ValueError, match="not a PE file"):
        pe_image_size(os.devnull)


def test_format_thread_state_names_the_range_and_the_counters():
    line = format_thread_state(_s44_record(0x1000_0120, thread_kernel_us=1,
                                           thread_user_us=2),
                               _S44_BASE, _S44_IMAGE_SIZE)

    assert "rip=0x10000120" in line
    assert "where=inside_dll" in line
    assert "th_kernel_us=1" in line
    assert "pr_user_us=0" in line
    assert "err=" not in line


def test_format_thread_state_keeps_the_failure_reason_visible():
    line = format_thread_state({"rip": None, "rsp": None, "context_err":
                                "GetThreadContext gle=87", "times_err": None,
                                "thread_kernel_us": None, "thread_user_us": None,
                                "process_kernel_us": None, "process_user_us": None},
                               _S44_BASE, _S44_IMAGE_SIZE)

    assert "rip=none" in line
    assert "where=unknown" in line
    assert "err=GetThreadContext gle=87" in line


def test_thread_cpu_us_sums_kernel_and_user():
    assert thread_cpu_us({"thread_kernel_us": 100, "thread_user_us": 50}) == 150


def test_thread_cpu_us_refuses_to_guess_a_missing_counter():
    assert thread_cpu_us({"thread_kernel_us": 100, "thread_user_us": None}) is None
    assert thread_cpu_us({}) is None


def test_thread_state_verdict_calls_a_moving_thread_executing_in_our_module():
    records = [_s44_record(0x1000_1000, thread_user_us=0, ms=0.0),
               _s44_record(0x1000_9A40, thread_user_us=4_812, ms=6_900.0)]

    label, reason = thread_state_verdict(records, _S44_BASE, _S44_IMAGE_SIZE)

    assert label == EXECUTING_IN_DLL
    # The reason carries the numbers, because the shot's transcript is the record.
    assert "4812 us" in reason and "2/2 Rips" in reason


def test_thread_state_verdict_calls_a_parked_thread_blocked():
    # Same address every sample, no CPU charged: the thread is alive and waiting.
    records = [_s44_record(0x7FF6_0011_2233, ms=ms) for ms in (0.0, 100.0, 200.0)]

    label, _reason = thread_state_verdict(records, _S44_BASE, _S44_IMAGE_SIZE)

    assert label == BLOCKED


def test_thread_state_verdict_separates_running_from_running_in_our_code():
    records = [_s44_record(0x7FF6_0011_2233, thread_kernel_us=9_000, ms=0.0),
               _s44_record(0x7FF6_0011_2233, thread_kernel_us=9_000,
                           thread_user_us=9_000, ms=6_900.0)]

    label, _reason = thread_state_verdict(records, _S44_BASE, _S44_IMAGE_SIZE)

    assert label == EXECUTING_ELSEWHERE


def test_thread_state_verdict_says_inconclusive_instead_of_inventing_a_blocked():
    # One readable address shows neither motion nor a stall. This is the shape a
    # shot that loses the host after two samples lands in, and it must not be
    # reported as the finding.
    records = [_s44_record(0x1000_1000, ms=0.0)]

    label, reason = thread_state_verdict(records, _S44_BASE, _S44_IMAGE_SIZE)

    assert label == INCONCLUSIVE
    assert "1 of 1" in reason


def test_thread_state_verdict_stays_inconclusive_when_the_counters_are_unreadable():
    records = [_s44_record(0x1000_1000, ms=0.0), _s44_record(0x1000_2000, ms=100.0)]
    for r in records:
        r["thread_user_us"] = None

    label, reason = thread_state_verdict(records, _S44_BASE, _S44_IMAGE_SIZE)

    assert label == INCONCLUSIVE
    assert "CPU counters" in reason


def test_thread_state_verdict_does_not_read_a_stale_in_dll_address_as_execution():
    # A thread blocked after returning into the DLL still shows the DLL as its
    # last address. Flat CPU plus an in-module Rip is the ambiguous middle, and
    # naming it is what keeps the §44 verdict honest when it is not clean.
    records = [_s44_record(0x1000_1000, ms=0.0), _s44_record(0x1000_1000, ms=6_900.0)]

    label, reason = thread_state_verdict(records, _S44_BASE, _S44_IMAGE_SIZE)

    assert label == INCONCLUSIVE
    assert "parked" in reason


def test_thread_state_lines_ends_with_the_verdict():
    records = [_s44_record(0x1000_1000, thread_user_us=0, ms=0.0),
               _s44_record(0x1000_2000, thread_user_us=7_000, ms=6_900.0)]

    lines = thread_state_lines(records, _S44_BASE, _S44_IMAGE_SIZE)

    assert lines[0] == "captures=2"
    assert any(line.startswith("inside_dll=2/2") for line in lines)
    assert lines[-1].startswith(f"VERDICT {EXECUTING_IN_DLL}:")


def test_thread_state_lines_survives_no_capture_at_all():
    lines = thread_state_lines([], _S44_BASE, _S44_IMAGE_SIZE)

    assert "captures=0" in lines[0]
    assert lines[-1].startswith(f"VERDICT {INCONCLUSIVE}:")


def test_make_thread_probe_stamps_the_clock_and_renders_the_line(monkeypatch):
    # The clock is monotonic SECONDS; ms is what the transcript prints.
    ticks = iter([1.0, 1.25])
    seen = []

    def fake_capture(thread_handle, process_handle):
        seen.append((thread_handle, process_handle))
        return _s44_record(0x1000_1000)

    monkeypatch.setattr(c2_init_threadstate, "capture_thread_state", fake_capture)
    records = []
    probe = make_thread_probe(_S44_BASE, _S44_IMAGE_SIZE, records,
                              clock=lambda: next(ticks))

    line = probe(0x1234, 0x999)

    assert seen == [(0x1234, 0x999)]
    assert records[0]["ms"] == 250.0
    assert "where=inside_dll" in line


def test_watched_dispatch_hands_the_thread_probe_both_live_handles(monkeypatch):
    _patch_watch_dispatch(monkeypatch, [b"\x00" * 512, b"raw_ok " + b"\x00" * 505],
                          exit_code=3, finish_after=None)
    seen_handles = []
    report = {}

    dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1,
                             report=report, sample_every_ms=0,
                             thread_probe=lambda t, p: seen_handles.append((t, p))
                             or "rip=0x1")

    # The handles are the ones the dispatch itself created and opened: the probe
    # adds no dispatch and no second handle to the game.
    assert seen_handles and set(seen_handles) == {(_FAKE_THREAD, _FAKE_PROCESS)}
    assert [value for _ms, value in report["thread_samples"]] == (
        ["rip=0x1"] * len(seen_handles))


def test_capture_thread_state_reads_times_then_context_then_resumes(monkeypatch):
    # The ordering claim, offline: the CPU counters — the axis that carries the
    # verdict — are read WITHOUT suspending, so they survive a refused context
    # read; and the resume happens whether or not the context read worked.
    calls = []

    class FakeK32:
        def GetThreadTimes(self, thread, creation, exit_, kernel, user):
            calls.append("GetThreadTimes")
            for out, value in ((kernel, 12_000), (user, 340_000)):
                ctypes.cast(out, ctypes.POINTER(ctypes.c_uint64)).contents.value = value
            return 1

        def GetProcessTimes(self, process, creation, exit_, kernel, user):
            calls.append("GetProcessTimes")
            ctypes.cast(kernel, ctypes.POINTER(ctypes.c_uint64)).contents.value = 99_0000
            ctypes.cast(user, ctypes.POINTER(ctypes.c_uint64)).contents.value = 1_99_0000
            return 1

        def SuspendThread(self, thread):
            calls.append("SuspendThread")
            return 0

        def GetThreadContext(self, thread, ctx):
            calls.append("GetThreadContext")
            real = ctypes.cast(ctx, ctypes.POINTER(CONTEXT)).contents
            real.Rip = 0x1000_1230
            real.Rsp = 0x0000_00AF_11E0
            assert real.ContextFlags == CONTEXT_READ_MASK, (
                "the mask we ask for is the mask the fields we read require")
            return 1

        def ResumeThread(self, thread):
            calls.append("ResumeThread")
            return 1

    monkeypatch.setattr(c2_harness, "_kernel32", lambda: FakeK32())
    monkeypatch.setattr(c2_harness, "_gle", lambda: 0)

    state = capture_thread_state(0x1234, 0x999)

    assert calls == ["GetThreadTimes", "GetProcessTimes", "SuspendThread",
                     "GetThreadContext", "ResumeThread"]
    assert state["rip"] == 0x1000_1230
    assert state["rsp"] == 0x0000_00AF_11E0
    assert state["thread_kernel_us"] == 1200
    assert state["thread_user_us"] == 34000
    assert state["process_kernel_us"] == 99000
    assert state["process_user_us"] == 199000
    assert state["context_err"] is None and state["times_err"] is None


def test_capture_thread_state_resumes_only_what_it_suspended(monkeypatch):
    # SuspendThread returns (DWORD)-1 when it failed, and there is nothing to
    # resume — resuming anyway would take away a suspend count the probe never
    # added, to another thread's or the thread's own account.
    calls = []

    class FakeK32:
        def GetThreadTimes(self, *a):
            calls.append("GetThreadTimes")
            return 0

        def GetProcessTimes(self, *a):
            raise AssertionError("must not run after GetThreadTimes failed")

        def SuspendThread(self, thread):
            calls.append("SuspendThread")
            return 0xFFFFFFFF

        def GetThreadContext(self, thread, ctx):
            raise AssertionError("must not read a context we cannot suspend for")

        def ResumeThread(self, thread):
            calls.append("ResumeThread")
            return 0

    monkeypatch.setattr(c2_harness, "_kernel32", lambda: FakeK32())
    monkeypatch.setattr(c2_harness, "_gle", lambda: 87)

    state = capture_thread_state(0x1234, 0x999)

    assert calls == ["GetThreadTimes", "SuspendThread"]
    assert state["rip"] is None
    assert "SuspendThread gle=87" in state["context_err"]
    assert "GetThreadTimes gle=87" in state["times_err"]


def test_capture_thread_state_resumes_even_when_the_context_read_raises(monkeypatch):
    # The one failure mode that would park the game's thread forever: an exception
    # between suspend and resume. The finally has to resume regardless.
    calls = []

    class Boom(Exception):
        pass

    class FakeK32:
        def GetThreadTimes(self, *a):
            return 1

        def GetProcessTimes(self, *a):
            return 1

        def SuspendThread(self, thread):
            calls.append("SuspendThread")
            return 0

        def GetThreadContext(self, thread, ctx):
            raise Boom("mid-read")

        def ResumeThread(self, thread):
            calls.append("ResumeThread")
            return 1

    monkeypatch.setattr(c2_harness, "_kernel32", lambda: FakeK32())
    monkeypatch.setattr(c2_harness, "_gle", lambda: 0)

    with pytest.raises(Boom):
        capture_thread_state(0x1234, 0x999)

    assert calls == ["SuspendThread", "ResumeThread"]


def test_sha256_of_digests_the_file_it_is_given(tmp_path):
    path = tmp_path / "artifact.bin"
    payload = b"three-phase markers"
    path.write_bytes(payload)

    assert c2_init_threadstate.sha256_of(str(path)) == hashlib.sha256(
        payload).hexdigest()


def test_assert_same_bytes_refuses_an_artifact_that_is_not_s42(tmp_path, monkeypatch):
    # §44's verdict is a comparison against §42's frozen window, so a rebuilt DLL
    # with different bytes must stop the shot instead of silently invalidating it.
    path = tmp_path / "rebuild.dll"
    path.write_bytes(b"different")
    monkeypatch.setattr(c2_init_threadstate, "S42_DLL_SHA256", "0" * 64)

    with pytest.raises(AssertionError, match="not §42's"):
        c2_init_threadstate.assert_same_bytes_as_s42(str(path))


def test_assert_same_bytes_returns_the_hash_for_the_transcript(tmp_path, monkeypatch):
    path = tmp_path / "same.dll"
    path.write_bytes(b"x" * 4096)
    digest = c2_init_threadstate.sha256_of(str(path))
    monkeypatch.setattr(c2_init_threadstate, "S42_DLL_SHA256", digest)

    assert c2_init_threadstate.assert_same_bytes_as_s42(str(path)) == digest


def test_s42_sha_constant_stays_pinned_to_s42s_bytes():
    # This constant is §42's HISTORICAL identity, not a description of whatever the
    # tree currently builds: §44's verdicts in
    # evidence/analysis/runtime_444_c1_validation.md are recorded against exactly these
    # bytes, so re-pointing the constant at a convenient rebuild would silently
    # re-base provenance. Do NOT "fix" a failure here by copying the current
    # zig-out digest into it — that is the edit this test exists to make expensive.
    #
    # The old form of this test asserted equality with sha256(DLL_PATH), i.e. "the
    # constant describes this tree". That can no longer be true by design: this plan
    # deliberately instruments `src/dll/quickjs/quickjs_wrapper.c` (Task 1), so the
    # artifact in the tree is different bytes from §42's and the only way to satisfy
    # tree-equality would be to undo planned work.
    #
    # What still protects a §44-style re-run is the live gate, unchanged:
    # `c2_init_threadstate.assert_same_bytes_as_s42` refuses any artifact whose digest
    # differs from this constant before dispatching, and
    # `test_assert_same_bytes_refuses_an_artifact_that_is_not_s42` pins that behaviour.
    # What this test pins is the constant's immutability — it fails if anyone edits the
    # constant, which is the whole behaviour under test here.
    assert c2_init_threadstate.S42_DLL_SHA256 == (
        "863917f2579ae8c4472be13baeca4bed64dc2ccffc7b620fdb2b016134a86617")


def test_watched_dispatch_throttles_the_thread_probe_to_the_requested_interval(monkeypatch):
    # The probe suspends the thread it is measuring, so its own rate is part of the
    # perturbation budget: one context copy per sample_every_ms, not one per 2 ms
    # poll iteration.
    _patch_watch_dispatch(monkeypatch, [b"\x00" * 512, b"\x00" * 512, b"\x00" * 512,
                                        b"raw_ok " + b"\x00" * 505], exit_code=3,
                          finish_after=None)
    report = {}

    dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, report=report,
                             sample_every_ms=10_000, thread_probe=lambda t, p: "once")

    assert len(report["thread_samples"]) == 1


def test_watched_dispatch_records_no_thread_samples_without_a_probe(monkeypatch):
    # Every §38-§42 shot runs through this same primitive with no probe; the key
    # exists and is empty rather than absent, so callers read one shape.
    _patch_watch_dispatch(monkeypatch, [b"raw_ok " + b"\x00" * 505], exit_code=3,
                          finish_after=None)
    report = {}

    dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1, report=report)

    assert report["thread_samples"] == []


def test_watched_dispatch_drops_a_raising_thread_probe_after_recording_it(monkeypatch):
    # Same policy as the sampler: the thread/process vanishing underneath the
    # probe is the outcome being measured, so it must cost neither the rc nor the
    # reason it failed.
    _patch_watch_dispatch(monkeypatch, [b"\x00" * 512, b"\x00" * 512,
                                        b"raw_ok " + b"\x00" * 505], exit_code=3,
                          finish_after=None)
    calls = []
    report = {}

    def probe(thread_handle, process_handle):
        calls.append(1)
        if len(calls) == 2:
            raise OSError("pid 8288 no longer exists")
        return f"n={len(calls)}"

    rc, text = dispatch_watching_buffer(1, 0x10000, 0x10, 0x2000, 512, poll_ms=1,
                                        report=report, sample_every_ms=0,
                                        thread_probe=probe)

    assert rc == 3
    assert len(calls) == 2
    assert "thread_probe raised" in report["thread_samples"][1][1]
    assert "pid 8288 no longer exists" in report["thread_samples"][1][1]


def test_cpuwatch_formats_process_cpu_counters_in_shot_units():
    # The §44 baseline control prints the same units the shot's §44 line printed, so
    # the two series can be compared by eye without a conversion step.
    assert (format_cpu_sample(42.21875, 4.46875, 32)
            == "user_us=42218750 system_us=4468750 threads=32")


def test_cpuwatch_advance_is_first_to_last_only():
    samples = [(0.0, 1.5, 0.25), (250.0, 2.0, 0.5), (500.0, 3.25, 0.75)]
    assert cpu_advance_us(samples) == (1_750_000, 500_000)


def test_cpuwatch_advance_of_a_short_run_is_zero():
    # One sample cannot show an advance; reporting the value itself as the advance
    # would let a control that died after its first read look like an answer.
    assert cpu_advance_us([(0.0, 42.21875, 4.46875)]) == (0, 0)
    assert cpu_advance_us([]) == (0, 0)


def test_open_thread_handle_asks_for_every_thread_right(monkeypatch):
    # §44's failure was on SuspendThread, not on the open. If the open quietly
    # asked for less than the suspend right, gle=5 would be our bug and the
    # session's health unknown — so the mask is part of the claim.
    seen = {}

    class FakeK32:
        def OpenThread(self, access, inherit, tid):
            seen["access"] = access
            seen["tid"] = tid
            return 0xBEEF

    monkeypatch.setattr(c2_harness, "_kernel32", lambda: FakeK32())

    assert open_thread_handle(4242) == 0xBEEF
    assert seen == {"access": 0x1FFFFF, "tid": 4242}


def test_open_thread_handle_raises_with_the_gle_when_the_open_fails(monkeypatch):
    class FakeK32:
        def OpenThread(self, access, inherit, tid):
            return None

    monkeypatch.setattr(c2_harness, "_kernel32", lambda: FakeK32())
    monkeypatch.setattr(c2_harness, "_gle", lambda: 5)

    with pytest.raises(RuntimeError, match=r"OpenThread\(4242\) failed: gle=5"):
        open_thread_handle(4242)


class _FakeThread:
    def __init__(self, tid):
        self.id = tid


class _FakeProc:
    def __init__(self, tids):
        self._tids = tids

    def threads(self):
        return [_FakeThread(t) for t in self._tids]


def test_thread_ids_are_sorted_and_capped():
    # Sorted so two runs of the control describe the same threads; capped because
    # each attempt suspends a real game thread for as long as the context read.
    assert thread_ids(_FakeProc([9, 3, 7, 1]), 4) == [1, 3, 7, 9]
    assert thread_ids(_FakeProc([9, 3, 7, 1]), 2) == [1, 3]


def _cap_entry(tid, rip=None, context_err=None, open_err=None):
    state = None if open_err else {
        "rip": rip, "rsp": rip, "thread_kernel_us": 0, "thread_user_us": 0,
        "process_kernel_us": 0, "process_user_us": 0,
        "context_err": context_err, "times_err": None,
    }
    return {"tid": tid, "open_err": open_err, "state": state}


def test_suspend_cap_verdict_is_capable_when_every_thread_reads():
    results = [_cap_entry(1, rip=0x7ff600001230), _cap_entry(2, rip=0x7ff600004560)]
    label, reason = suspend_cap_verdict(results)
    assert label == CAPABLE
    assert "readable_rip=2/2" in reason and "suspend_denied_gle5=0/2" in reason


def test_suspend_cap_verdict_is_incapable_when_every_thread_refuses_gle5():
    # Exactly the §44 shape, reproduced on the game's own threads: that is the
    # signature of a session that cannot suspend this process.
    results = [_cap_entry(t, context_err="SuspendThread gle=5") for t in (1, 2, 3)]
    label, reason = suspend_cap_verdict(results)
    assert label == INCAPABLE
    assert "suspend_denied_gle5=3/3" in reason
    assert "every thread refused identically" in reason


def test_suspend_cap_verdict_is_partial_when_only_some_threads_read():
    results = [_cap_entry(1, rip=0x7ff600001230),
               _cap_entry(2, context_err="SuspendThread gle=5")]
    label, reason = suspend_cap_verdict(results)
    assert label == PARTIAL
    assert "readable_rip=1/2" in reason and "suspend_denied_gle5=1/2" in reason


def test_suspend_cap_verdict_counts_a_failed_open_separately():
    # OpenThread failing is a different wall from SuspendThread failing: the first
    # says the thread is not even addressable from this token.
    results = [_cap_entry(1, open_err="OpenThread(1) failed: gle=87"),
               _cap_entry(2, context_err="SuspendThread gle=5")]
    label, reason = suspend_cap_verdict(results)
    assert label == INCAPABLE
    assert "openthread_failed=1/2" in reason


def test_suspend_cap_verdict_of_nothing_attempted_says_nothing():
    label, reason = suspend_cap_verdict([])
    assert label == NO_SAMPLES
    assert reason == "no thread was attempted"


def test_cap_lines_renders_an_unopened_thread_without_inventing_a_state():
    base, image = 0x7ff600000000, 0x200000
    lines = cap_lines([_cap_entry(1, open_err="OpenThread(1) failed: gle=87"),
                       _cap_entry(2, rip=base + 0x1230)], base, image)
    assert lines[0] == "tid=1 open_err=OpenThread(1) failed: gle=87"
    assert "rip=" + hex(base + 0x1230) in lines[1]
    assert "where=inside_dll" in lines[1]


# --- §45's two promoted tools (Task 2): the self-checker's recorder channel and
# --- the offline symbolizer's func mode. Both pure; no Windows API is touched.

def test_selfabort_repro_reads_the_recorder_channel():
    """The promoted §45 self-checker must carry the ring-recorder as a key line, and
    its verdict must stay exactly the abort signature §45 measured: the child's exit
    status is 3 AND it never printed SURVIVED.

    Nothing about the recorder may hinge on the post-call dump: §45's child aborts
    *inside* C2DiagQJSInto, so the only channel that can see the dying process is the
    concurrent reader thread — which is why MFREC is in the key-line set at all.
    """
    repro = importlib.import_module("c2_selfabort_repro")
    assert "MFREC" in repro.KEY_LINES, "the recorder channel must be a key line of this tool"

    stdout = "\n".join([
        "BASE stellaris_quickjs.dll 0x7ffc138c0000",
        "LOGADDR 0x7ffc13f657f0",
        "RECORDER ok",
        "SANITY 42",
        "WITNESS ''",
        "WITNESS 'enter heap_ok alloc_ok free_ok new_rt MmMmMm'",
        "MFREC 0 watch 'M_ size=0 ptr=---------------- st=000000000000\\n'",
        "MFREC 1 watch 'Mx size=20 ptr=198c3e40 st=00007ff644d3\\n'",
        "[repro] child returncode = 3 (0x3)",
        "[repro] VERDICT: the DLL terminated its own host with exit status 3",
    ])
    assert repro.key_lines_in(stdout) == [
        "BASE", "LOGADDR", "RECORDER", "SANITY", "WITNESS", "WITNESS", "MFREC",
        "MFREC", "VERDICT"]
    counts = repro.key_line_counts(stdout)
    assert counts["MFREC"] == 2 and counts["WITNESS"] == 2
    assert "SURVIVED" not in counts

    # The verdict predicate, in both directions, on the shapes §45 and §40 produced.
    assert repro.verdict(3, stdout) is True
    assert repro.verdict(3, stdout + "\nSURVIVED rc=0") is False
    assert repro.verdict(0, stdout) is False
    assert repro.verdict(-1073740791, stdout) is False  # 0xC0000409 fastfail != abort()

    # A child that never loaded the DLL also ends with status != 3, and that is NOT a
    # negative result about the artifact — the tool must be able to tell the two apart.
    assert repro.child_loaded_the_dll(stdout) is True
    assert repro.child_loaded_the_dll(
        "[repro] child returncode = 1 (0x1)\nTraceback: no WinDLL here") is False


def test_ubsan_site_func_mode_reports_function_range_and_records(capsys):
    """``func`` must name the function holding the address (its ``.pdata`` range, with
    length) and the UBSan records its code references, with the record address and the
    instruction that loaded it. The address is derived from the image, not hard-coded:
    pinning §45's concrete 0x18000bd9b would break on the next link.
    """
    site = importlib.import_module("dll_ubsan_site")
    with open(DLL_PATH, "rb") as f:
        data = f.read()
    image_base, secs = site.parse(data)

    records = [r for r in site.iter_records(data, image_base, secs)
               if "JSMallocBlockHeader" in r[5]]
    assert records, "the shipped artifact must still carry the §45 type-mismatch records"
    want = {r[0] for r in records if r[0] is not None}
    span = None
    for begin, end in site.runtime_functions(data, secs):
        if site.lea_record_targets(data, secs, begin, end, want):
            span = (begin, end)
            break
    assert span is not None, "no .pdata function referenced a JSMallocBlockHeader record"

    rc = site.cmd_func(data, image_base, secs, image_base + span[0])
    out = capsys.readouterr().out
    assert rc == 0
    assert f"rva {span[0]:#x}..{span[1]:#x} ({span[1] - span[0]} bytes)" in out, \
        "the report must carry the function range .pdata gives for that address"
    assert "JSMallocBlockHeader" in out
    assert re.search(r"quickjs\.c:\d+:\d+ member_access type=", out), \
        "the report must carry each referenced record's source location and kind"
    assert re.search(r"record_rva=0x[0-9a-f]+ loaded_at=0x[0-9a-f]+", out), \
        "the report must say which record and where the function loaded it"


def test_ubsan_site_func_rejects_a_bare_rva_instead_of_guessing(capsys):
    """``func`` takes a **vma carrying the image base**, and a bare RVA is not one.

    Before this guard a bare RVA fell into ``not inside any .pdata function entry``
    and exited 1 — the same exit code and the same shape of sentence as the genuine
    finding "this frame is not covered by the (incomplete) ``.pdata`` parse", the one
    §45's boundary section had to warn about in prose. A caliber bug must not be able
    to produce a conclusion about the artifact, so the invocation error now exits 2
    on stderr (the tool's error stream, per the read-error paths in ``main``) and the
    two exit-1 messages keep distinct meanings.

    The address is derived from the image, not hard-coded, for the reason stated in
    ``test_ubsan_site_func_mode_reports_function_range_and_records``: pinning §45's
    concrete 0x18000bd9b would break on the next link. Both sides are asserted here,
    so this is one test function covering the accept and the reject.
    """
    site = importlib.import_module("dll_ubsan_site")
    with open(DLL_PATH, "rb") as f:
        data = f.read()
    image_base, secs = site.parse(data)

    records = [r for r in site.iter_records(data, image_base, secs)
               if "JSMallocBlockHeader" in r[5]]
    want = {r[0] for r in records if r[0] is not None}
    begin = next(b for b, e in site.runtime_functions(data, secs)
                 if site.lea_record_targets(data, secs, b, e, want))
    assert begin < image_base, "the fixture's rva must be below the image base"

    rc = site.cmd_func(data, image_base, secs, begin)     # bare rva: wrong caliber
    captured = capsys.readouterr()
    assert rc == 2, "a bare RVA is an invocation error, not a finding about the image"
    assert "image base" in captured.err.lower()
    assert f"{image_base + begin:#x}" in captured.err, \
        "the message must give the number to pass instead, not just complain"
    assert "not inside any .pdata" not in captured.out + captured.err, \
        "the caliber guard must not merge with, or replace, the exit-1 finding"

    capsys.readouterr()
    assert site.cmd_func(data, image_base, secs, image_base + begin) == 0
    assert "not inside any .pdata" not in capsys.readouterr().err


def test_ubsan_site_truncated_input_exits_2_not_a_no_pdata_finding(tmp_path, capsys):
    """A file cut inside ``.text`` must be an invocation error (2), not a finding.

    ``parse`` validated the headers but not the section ranges, so a truncated
    copy reached ``runtime_functions`` with the surviving (empty) ``.pdata`` and
    answered exit 1 — "rva X is not inside any .pdata function entry", the same
    code and shape as a real conclusion about the artifact, while the docs
    already promised truncated input → 2. The cut is placed at the trap
    function's own file offset, derived from the image, so it is inside a
    section whose declared raw size runs past EOF.
    """
    site = importlib.import_module("dll_ubsan_site")
    with open(DLL_PATH, "rb") as f:
        data = f.read()
    image_base, secs = site.parse(data)
    records = [r for r in site.iter_records(data, image_base, secs)
               if "JSMallocBlockHeader" in r[5]]
    want = {r[0] for r in records if r[0] is not None}
    begin = next(b for b, e in site.runtime_functions(data, secs)
                 if site.lea_record_targets(data, secs, b, e, want))
    off_of, _rva_of = site.make_maps(secs)
    cut = off_of(begin)
    assert cut is not None and 0 < cut < len(data), (cut, len(data))

    trunc = tmp_path / "trunc.dll"
    trunc.write_bytes(data[:cut])
    rc = site.main([str(trunc), "func", f"{image_base + begin:#x}"])
    assert rc == 2, "a truncated image is an invocation error, not a no-sites finding"
    err = capsys.readouterr().err
    assert "Traceback" not in err, err
    assert err.startswith("[ubsan_site] "), err
    assert err.count("\n") == 1, err
