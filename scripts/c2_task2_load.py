"""Task 2: prove the harness reads a real 64-bit DLL base on the live game.

Run this ON WINDOWS (the game box), after uploading BOTH this file and
scripts/c2_harness.py to C:/temp/ (ruling P5) and the freshly built DLL to
the DLL path (ruling P11). Because the script executes on Windows, the DLL
it parses for exports is the Windows-side copy, not a zig-out path (ruling
P10): one path serves as both the export-parse target and the LoadLibrary
string, since they are the same file on the same machine.

    python C:/temp/c2_task2_load.py [dll_path]      # default C:\\temp\\sqjs_c2.dll

Prints the resolved base, verifies the MZ header there, calls C2Sanity and
asserts it returns 42, then asserts the game is still alive.
"""
import sys, os
from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll,
    list_exports, call_remote, read_memory, assert_game_alive,
)

pid = resolve_pid("stellaris")
# argv[1]: the DLL as it exists on this Windows box; also the exact path
# string handed to the remote LoadLibraryA. Windows default per P10.
dll_path = sys.argv[1] if len(sys.argv) > 1 else r"C:\temp\sqjs_c2.dll"

# The world-state gate (spec §1): a shot that cannot prove the premise
# must not inject.  The refusal happens BEFORE inject_dll — "injected,
# then noticed the premise was false" is the failure mode this removes.
from world_probe import gate_install  # pyright: ignore[reportMissingImports]
gate_install('task2')
inject_dll(pid, dll_path)
assert_game_alive(pid)
base = resolve_base_address(pid, os.path.basename(dll_path))
print(f"DLL base (real, 64-bit): 0x{base:x}")

# Verify the base is readable and starts with the MZ header
head = read_memory(pid, base, 2)
assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
print("MZ header at base OK")

exports = list_exports(dll_path)
rva = exports["C2Sanity"]
print(f"C2Sanity RVA from PE reparse: 0x{rva:x}")
rc = call_remote(pid, base, rva)
print(f"C2Sanity -> {rc}")
assert rc == 42, f"Expected 42, got {rc}"

assert_game_alive(pid)
print("Task 2: PASS")
