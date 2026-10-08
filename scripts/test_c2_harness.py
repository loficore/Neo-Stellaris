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

The Win32-dependent helpers (``resolve_pid``, ``resolve_base_address``,
``inject_dll``, ``call_remote``, ``call_remote_with_arg``, ``read_memory``,
``read_u64``, ``assert_game_alive``) bind kernel32 LAZILY so that importing this
module is side-effect-free on Linux (ruling P3); their remote-call behaviour is
exercised only on the real Windows machine in Tasks 2+ and is deliberately not
mocked here.
"""

import os

import pytest

from c2_harness import list_exports, parse_module_base_from_ps

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
                 "C2TestQJS", "C2RegisterEffect", "C2RegisterTrigger"):
        assert name in exports, f"missing real export {name!r}"
    # RVAs are distinct positive integers, proving a real directory walk.
    rvas = list(exports.values())
    assert all(isinstance(r, int) and r > 0 for r in rvas)
    assert len(set(rvas)) == len(rvas)


def test_list_exports_missing_file_raises():
    with pytest.raises((FileNotFoundError, ValueError)):
        list_exports(os.path.join(_REPO_ROOT, "zig-out", "bin", "does_not_exist.dll"))
