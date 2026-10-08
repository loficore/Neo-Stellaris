"""Shared C2 remote-injection harness (Windows side).

Every later C2 task's remote script scp's this module into ``C:/temp/`` next to
itself and imports it by **bare name** (``from c2_harness import ...``) with cwd
= ``C:/temp`` (ruling P5). There is intentionally NO package and NO
``__init__.py``: import is resolved cwd-relative so a plain
``python C:/temp/c2_taskN.py`` works.

Design rules this module encodes (from the pre-flight conflict table):

  * P1 — ``list_exports`` is a *genuine* PE export-directory parser. It re-reads
    the artifact fresh every run; there is NO hard-coded RVA table anywhere here
    (unlike the old ``c2_test_sanity.py`` ``RVAS`` dict, which must never be
    copied).
  * P2 — ``parse_module_base_from_ps`` accepts BOTH ``0x``-prefixed hex and the
    DECIMAL form PowerShell's ``BaseAddress`` actually emits on the target, and
    raises ``ValueError`` on anything else.
  * P3 — kernel32 binds LAZILY (see ``_kernel32``). Importing this module has
    **zero side effects on Linux**, so the host pytest suite can import it.
  * P4 — 64-bit results cannot survive a thread exit code. ``call_remote``
    returns only the 32-bit exit code (documented truncation caveat); for real
    64-bit pointers use ``remote_alloc`` + ``call_remote_with_arg`` (a single
    ``lpParameter``) + ``read_u64`` / ``read_memory``.
  * Base address is NEVER taken from the LoadLibrary thread's exit code; after
    injection we resolve it via ``resolve_base_address`` (PowerShell), keyed on
    module *filename* (P8).

The Win32 helpers are exercised only on the real Windows machine (Tasks 2+);
they are deliberately not importable-but-fake on Linux.
"""

from __future__ import annotations

import ctypes
import os
import struct
import subprocess

# ---------------------------------------------------------------------------
# Lazy Win32 binding (ruling P3): nothing here touches ctypes.WinDLL at import.
# ---------------------------------------------------------------------------

_KERNEL32 = None
_KERNEL32_CONFIGURED = False


def _kernel32():
    """Return a bound ``kernel32`` with the argtypes/restypes this harness needs.

    Binding is deferred to first *use* (never at import), so importing this
    module on Linux stays side-effect-free and the host tests can run. On
    non-Windows hosts the first call raises ``AttributeError`` from
    ``ctypes.WinDLL`` — that is expected: these helpers are Windows-only and
    are simply not invoked during the Linux smoke tests.
    """
    global _KERNEL32, _KERNEL32_CONFIGURED
    if _KERNEL32 is None:
        _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)

    if not _KERNEL32_CONFIGURED:
        k32 = _KERNEL32
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]
        k32.CloseHandle.restype = ctypes.c_int
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.VirtualAllocEx.restype = ctypes.c_void_p
        k32.VirtualAllocEx.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_uint, ctypes.c_uint,
        ]
        k32.VirtualFreeEx.restype = ctypes.c_int
        k32.VirtualFreeEx.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint,
        ]
        k32.WriteProcessMemory.restype = ctypes.c_int
        k32.WriteProcessMemory.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]
        k32.ReadProcessMemory.restype = ctypes.c_int
        k32.ReadProcessMemory.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]
        k32.GetModuleHandleA.restype = ctypes.c_void_p
        k32.GetModuleHandleA.argtypes = [ctypes.c_char_p]
        k32.GetProcAddress.restype = ctypes.c_void_p
        k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        k32.CreateRemoteThread.restype = ctypes.c_void_p
        k32.CreateRemoteThread.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint),
        ]
        k32.WaitForSingleObject.restype = ctypes.c_uint
        k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        k32.GetExitCodeThread.restype = ctypes.c_int
        k32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
        _KERNEL32_CONFIGURED = True

    return _KERNEL32


# process_all_access = 0x1F0FFF
_PROCESS_ALL_ACCESS = 0x1F0FFF
# VirtualAllocEx flProtect PAGE_READWRITE, allocation MEM_COMMIT|MEM_RESERVE
_PAGE_READWRITE = 0x04
_MEM_COMMIT_RESERVE = 0x3000
_MEM_RELEASE = 0x8000
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102


# ---------------------------------------------------------------------------
# Pure, host-testable helpers
# ---------------------------------------------------------------------------

def parse_module_base_from_ps(text: str) -> int:
    """Decode a single PowerShell ``BaseAddress`` value.

    Accepts ``0x``-prefixed hex (e.g. ``"0x00007FF441D20000"``) and the plain
    DECIMAL PowerShell actually emits (e.g. ``"140696081727488"``). Surrounding
    whitespace/newlines are tolerated. Raises ``ValueError`` on empty,
    multi-token, or otherwise non-numeric input.
    """
    if text is None:
        raise ValueError("module base is None")
    token = text.strip()
    if not token:
        raise ValueError("empty module base")
    # Reject anything that is not a single whitespace-free token.
    if any(c.isspace() for c in token):
        raise ValueError(f"ambiguous module base (multiple values): {text!r}")
    lowered = token.lower()
    try:
        if lowered.startswith("0x"):
            return int(token, 16)
        return int(token, 10)
    except ValueError as exc:
        raise ValueError(f"not a valid module base: {text!r}") from exc


def list_exports(local_dll_path: str) -> dict:
    """Parse a PE file's export directory into ``{name: rva}``.

    A real directory walk — no hard-coded table (ruling P1). Re-read from disk
    on every call, so a rebuilt DLL is always reflected.
    """
    with open(local_dll_path, "rb") as fh:
        data = fh.read()

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"not a PE file (no MZ header): {local_dll_path!r}")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError(f"not a PE file (bad NT signature): {local_dll_path!r}")

    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    size_of_optional = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20

    magic = struct.unpack_from("<H", data, opt)[0]
    # PE32+ (64-bit) DataDirectory starts at opt+112; PE32 at opt+96.
    if magic == 0x20B:
        dd_off = opt + 112
    elif magic == 0x10B:
        dd_off = opt + 96
    else:
        raise ValueError(f"unknown optional-header magic {magic:#x}: {local_dll_path!r}")

    export_rva, export_size = struct.unpack_from("<II", data, dd_off)
    if export_rva == 0:
        return {}  # module exports nothing

    sections_off = opt + size_of_optional
    sections = []
    for i in range(num_sections):
        so = sections_off + i * 40
        virtual_size, virtual_addr, raw_size, raw_off = struct.unpack_from("<IIII", data, so + 8)
        span = max(virtual_size, raw_size)
        sections.append((virtual_addr, span, raw_off))

    def r2off(rva: int) -> int:
        for va, sz, praw in sections:
            if va <= rva < va + sz:
                return praw + (rva - va)
        raise ValueError(f"RVA {rva:#x} not inside any section in {local_dll_path!r}")

    exp = r2off(export_rva)
    # IMAGE_EXPORT_DIRECTORY:
    #   +0 Characteristics, +4 TimeDateStamp, +8 MajorVer/MinorVer,
    #   +12 Name(RVA), +16 OrdinalBase, +20 NumberOfFunctions,
    #   +24 NumberOfNames, +28 AddressOfFunctions, +32 AddressOfNames,
    #   +36 AddressOfNameOrdinals
    num_functions = struct.unpack_from("<I", data, exp + 20)[0]
    num_names = struct.unpack_from("<I", data, exp + 24)[0]
    addr_functions = struct.unpack_from("<I", data, exp + 28)[0]
    addr_names = struct.unpack_from("<I", data, exp + 32)[0]
    addr_name_ordinals = struct.unpack_from("<I", data, exp + 36)[0]

    off_functions = r2off(addr_functions)
    off_names = r2off(addr_names)
    off_ordinals = r2off(addr_name_ordinals)

    # Export-address range used to flag forwarded entries (RVA points *back*
    # into the export directory rather than at code). None in our artifact, but
    # handled so a forward is never mistaken for a callable RVA.
    exports: dict = {}
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", data, off_names + i * 4)[0]
        ordinal = struct.unpack_from("<H", data, off_ordinals + i * 2)[0]
        func_rva = struct.unpack_from("<I", data, off_functions + ordinal * 4)[0]
        if ordinal >= num_functions:
            raise ValueError(f"export ordinal {ordinal} out of range in {local_dll_path!r}")
        if export_rva <= func_rva < export_rva + export_size:
            # Forwarded export: skip; its RVA is not a local function.
            continue
        name_bytes = data[r2off(name_rva):].split(b"\x00", 1)[0]
        exports[name_bytes.decode("ascii", errors="replace")] = func_rva

    return exports


# ---------------------------------------------------------------------------
# Pure process/lookup helpers built on subprocess (Windows CLIs)
# ---------------------------------------------------------------------------

def resolve_pid(process_name: str) -> int:
    """Return the PID of ``process_name`` (e.g. ``"stellaris.exe"``).

    Raises ``RuntimeError`` if it is not running. Uses ``tasklist`` CSV output.
    """
    cmd = ["tasklist", "/FI", f"IMAGENAME eq {process_name}", "/FO", "CSV", "/NH"]
    try:
        out = subprocess.check_output(cmd).decode("utf-8", errors="replace")
    except (subprocess.SubprocessError, OSError) as exc:
        raise RuntimeError(f"tasklist failed while resolving {process_name!r}: {exc}") from exc

    want = process_name.lower()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = _split_csv_row(line)
        if len(parts) >= 2 and parts[0].lower() == want:
            try:
                return int(parts[1])
            except ValueError:
                continue
    raise RuntimeError(f"{process_name!r} is not running")


def resolve_base_address(pid: int, dll_filename: str) -> int:
    """Full 64-bit module base via PowerShell, keyed on the DLL *filename*.

    Raises ``RuntimeError`` if the DLL is not loaded or if its filename appears
    more than once (two loaded copies would make the lookup ambiguous — ruling
    P8).
    """
    # Query by process name (the C2 target is always "stellaris"); pid is kept
    # in the signature for the harness contract and for future filtering.
    del pid  # filename-keyed lookup; process name comes from Get-Process below
    ps_cmd = (
        "Get-Process stellaris | Select-Object -ExpandProperty Modules | "
        f"Where-Object {{ $_.ModuleName -eq '{dll_filename}' }} | "
        "Select-Object -ExpandProperty BaseAddress"
    )
    try:
        out = subprocess.check_output(["powershell", "-Command", ps_cmd]).decode("utf-8", errors="replace")
    except (subprocess.SubprocessError, OSError) as exc:
        raise RuntimeError(f"PowerShell base lookup failed for {dll_filename!r}: {exc}") from exc

    values = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if not values:
        raise RuntimeError(f"{dll_filename!r} is not loaded in stellaris")
    if len(values) > 1:
        raise RuntimeError(
            f"ambiguous base: {dll_filename!r} appears {len(values)} times ({values}); "
            "uninstall the stale copy before injecting"
        )
    return parse_module_base_from_ps(values[0])


def assert_game_alive(pid: int) -> None:
    """Raise ``RuntimeError`` if the game process is gone.

    Every remote test ends with this so a crash is attributed immediately.
    """
    cmd = ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"]
    try:
        out = subprocess.check_output(cmd).decode("utf-8", errors="replace")
    except (subprocess.SubprocessError, OSError) as exc:
        raise RuntimeError(f"game-alive check failed for pid {pid}: {exc}") from exc

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = _split_csv_row(line)
        if len(parts) >= 2:
            try:
                if int(parts[1]) == pid:
                    return
            except ValueError:
                continue
    raise RuntimeError(f"game (pid {pid}) is no longer alive")


def _split_csv_row(line: str) -> list:
    """Split a single ``tasklist /FO CSV`` line into fields."""
    import csv
    import io
    return next(csv.reader(io.StringIO(line)))


# ---------------------------------------------------------------------------
# Remote process primitives (Windows-only, lazily bound)
# ---------------------------------------------------------------------------

def _open_process(pid: int):
    handle = _kernel32().OpenProcess(_PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        raise RuntimeError(f"OpenProcess({pid}) failed: gle={ctypes.get_last_error()}")
    return handle


def _load_library_addr() -> int:
    k32 = _kernel32()
    mod = k32.GetModuleHandleA(b"kernel32.dll")
    if not mod:
        raise RuntimeError(f"GetModuleHandleA(kernel32.dll) failed: gle={ctypes.get_last_error()}")
    addr = k32.GetProcAddress(mod, b"LoadLibraryA")
    if not addr:
        raise RuntimeError(f"GetProcAddress(LoadLibraryA) failed: gle={ctypes.get_last_error()}")
    return addr


def inject_dll(pid: int, remote_dll_path: str) -> None:
    """Inject a DLL into ``pid`` via ``CreateRemoteThread(LoadLibraryA)``.

    Verifies the path write actually landed and that the module subsequently
    resolves a base address. The LoadLibrary thread's exit code is used ONLY as
    a NULL-vs-nonNULL sanity check, NEVER as the base (that comes from
    ``resolve_base_address``).
    """
    k32 = _kernel32()
    handle = _open_process(pid)
    try:
        path_bytes = remote_dll_path.encode("ascii") + b"\x00"
        remote_mem = k32.VirtualAllocEx(handle, None, len(path_bytes), _MEM_COMMIT_RESERVE, _PAGE_READWRITE)
        if not remote_mem:
            raise RuntimeError(f"VirtualAllocEx({len(path_bytes)}) failed: gle={ctypes.get_last_error()}")
        try:
            written = ctypes.c_size_t()
            ok = k32.WriteProcessMemory(handle, remote_mem, path_bytes, len(path_bytes), ctypes.byref(written))
            if not ok or written.value != len(path_bytes):
                raise RuntimeError(
                    f"WriteProcessMemory of DLL path failed: ok={ok} written={written.value}/{len(path_bytes)} "
                    f"gle={ctypes.get_last_error()}"
                )

            thread = k32.CreateRemoteThread(handle, None, 0, _load_library_addr(), remote_mem, 0, None)
            if not thread:
                raise RuntimeError(f"CreateRemoteThread(LoadLibraryA) failed: gle={ctypes.get_last_error()}")
            try:
                wait = k32.WaitForSingleObject(thread, 30000)
                if wait != _WAIT_OBJECT_0:
                    raise RuntimeError(f"LoadLibrary thread did not finish (wait=0x{wait:x})")
                exit_code = ctypes.c_uint()
                k32.GetExitCodeThread(thread, ctypes.byref(exit_code))
            finally:
                k32.CloseHandle(thread)
            # exit code is the LOW 32 bits of the returned HMODULE; 0 => NULL =>
            # LoadLibrary failed. Non-zero is NOT the base and is not trusted.
            if exit_code.value == 0:
                raise RuntimeError("LoadLibraryA returned NULL (DLL failed to load)")
        finally:
            k32.VirtualFreeEx(handle, remote_mem, 0, _MEM_RELEASE)

        # Base comes from the authoritative filename-keyed query, not the thread.
        resolve_base_address(pid, os.path.basename(remote_dll_path))
    finally:
        k32.CloseHandle(handle)


def remote_alloc(pid: int, size: int) -> int:
    """Allocate ``size`` readable/writable bytes in ``pid``; return the address."""
    k32 = _kernel32()
    handle = _open_process(pid)
    try:
        addr = k32.VirtualAllocEx(handle, None, size, _MEM_COMMIT_RESERVE, _PAGE_READWRITE)
        if not addr:
            raise RuntimeError(f"VirtualAllocEx({size}) failed: gle={ctypes.get_last_error()}")
        return addr
    finally:
        k32.CloseHandle(handle)


def remote_write(pid: int, addr: int, data: bytes) -> None:
    """Write ``data`` to remote ``addr``; raise if the full write does not land."""
    k32 = _kernel32()
    handle = _open_process(pid)
    try:
        written = ctypes.c_size_t()
        ok = k32.WriteProcessMemory(handle, ctypes.c_void_p(addr), data, len(data), ctypes.byref(written))
        if not ok or written.value != len(data):
            raise RuntimeError(
                f"WriteProcessMemory @0x{addr:x} failed: ok={ok} written={written.value}/{len(data)} "
                f"gle={ctypes.get_last_error()}"
            )
    finally:
        k32.CloseHandle(handle)


def call_remote(pid: int, base: int, rva: int, timeout_ms: int = 30000) -> int:
    """Invoke a no-arg ``int __stdcall`` remote function; return its exit code.

    Truncation caveat: ``GetExitCodeThread`` yields only the LOW 32 bits of the
    thread's return value. Fine for ``i32`` functions like ``C2Sanity``. For any
    function returning a 64-bit ``usize``/pointer (e.g. ``C2DiagGetLogAddr``),
    do NOT use this — have the DLL write the full value into a caller-supplied
    buffer (``remote_alloc`` + ``call_remote_with_arg`` + ``read_u64``).
    """
    k32 = _kernel32()
    handle = _open_process(pid)
    try:
        addr = ctypes.c_void_p(base + rva)
        thread = k32.CreateRemoteThread(handle, None, 0, addr, None, 0, None)
        if not thread:
            raise RuntimeError(f"CreateRemoteThread @0x{base + rva:x} failed: gle={ctypes.get_last_error()}")
        try:
            wait = k32.WaitForSingleObject(thread, timeout_ms)
            if wait != _WAIT_OBJECT_0:
                raise RuntimeError(f"remote call @0x{base + rva:x} did not finish (wait=0x{wait:x})")
            exit_code = ctypes.c_uint()
            k32.GetExitCodeThread(thread, ctypes.byref(exit_code))
        finally:
            k32.CloseHandle(thread)
        return exit_code.value
    finally:
        k32.CloseHandle(handle)


def call_remote_with_arg(pid: int, base: int, rva: int, arg_value: int, timeout_ms: int = 30000) -> int:
    """Invoke a remote function taking one pointer arg (CreateRemoteThread lpParameter).

    This is the mechanism (ruling P4) that lets a DLL function receive a caller-
    allocated remote buffer and write real 64-bit results into it. Returns the
    32-bit exit code; the authoritative 64-bit data is read back via
    ``read_u64``/``read_memory`` from ``arg_value``.
    """
    k32 = _kernel32()
    handle = _open_process(pid)
    try:
        addr = ctypes.c_void_p(base + rva)
        thread = k32.CreateRemoteThread(handle, None, 0, addr, ctypes.c_void_p(arg_value), 0, None)
        if not thread:
            raise RuntimeError(
                f"CreateRemoteThread(arg) @0x{base + rva:x} failed: gle={ctypes.get_last_error()}"
            )
        try:
            wait = k32.WaitForSingleObject(thread, timeout_ms)
            if wait != _WAIT_OBJECT_0:
                raise RuntimeError(f"remote call(arg) @0x{base + rva:x} did not finish (wait=0x{wait:x})")
            exit_code = ctypes.c_uint()
            k32.GetExitCodeThread(thread, ctypes.byref(exit_code))
        finally:
            k32.CloseHandle(thread)
        return exit_code.value
    finally:
        k32.CloseHandle(handle)


def read_memory(pid: int, addr: int, size: int) -> bytes:
    """``ReadProcessMemory``; raise if zero bytes are actually read."""
    k32 = _kernel32()
    handle = _open_process(pid)
    try:
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t()
        ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
        if got.value == 0:
            raise RuntimeError(
                f"ReadProcessMemory @0x{addr:x} size={size} read 0 bytes (ok={ok}, gle={ctypes.get_last_error()})"
            )
        return bytes(buf.raw[:got.value])
    finally:
        k32.CloseHandle(handle)


def read_u64(pid: int, addr: int) -> int:
    """Read a little-endian 64-bit unsigned value from remote memory."""
    raw = read_memory(pid, addr, 8)
    if len(raw) < 8:
        raise RuntimeError(f"read_u64 @0x{addr:x} got only {len(raw)} bytes, need 8")
    return int.from_bytes(raw[:8], "little")
