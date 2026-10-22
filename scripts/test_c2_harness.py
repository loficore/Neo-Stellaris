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
pinned here; everything still-Windows-only stays unmocked. §38 widens that
exception to the polling dispatcher ``dispatch_watching_buffer``, because the
ordering inside it (read, THEN ask whether the thread finished) is the whole
reason it beats the read-after-wait that lost two live shots — and an ordering
bug like that is invisible to any test that only runs against a real process.
"""

import ctypes
import os
import struct

import pytest

import c2_harness
import c2_task5_init
from c2_harness import (
    list_exports, parse_module_base_from_ps, resolve_pid, dispatch_watching_buffer,
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

