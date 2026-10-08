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
"""

import os
import struct

import pytest

import c2_harness
from c2_harness import list_exports, parse_module_base_from_ps, resolve_pid
from c2_task3_diag import parse_ctx
from c2_task5_init import parse_pointers
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
                 "C2DiagQJSInto", "C2QuickJSPointersInto",
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
