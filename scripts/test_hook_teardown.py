"""Structural fence for the 2026-10-28 teardown fix.

A trampoline is the `call orig` landing page.  The trigger predicate target runs at
~9,800 calls/s (§76), so `uninstall` can land while another thread is inside it —
freeing the mapping then would unmaps live code.  The process exit reclaims it, which
is the same policy as never calling FreeLibrary (AGENTS.md constraint 5).
"""
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
DETOUR = REPO / "src/dll/hooking/detour.zig"


def test_detour_never_frees_a_trampoline():
    src = DETOUR.read_text(encoding="utf-8")
    assert "windows.freeMem(" not in src


def test_remove_hook_retires_instead_of_freeing():
    src = DETOUR.read_text(encoding="utf-8")
    body = src.split("pub fn removeHook", 1)[1]
    assert "retired_trampolines.add(" in body
