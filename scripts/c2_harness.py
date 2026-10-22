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
import time

# ---------------------------------------------------------------------------
# Lazy Win32 binding (ruling P3): nothing here touches ctypes.WinDLL at import.
# ---------------------------------------------------------------------------

# --- §44: the Win32 shapes the read-only thread-state probe needs. Declared at
# --- import because ctypes.Structure lays itself out without touching a DLL, so
# --- `scripts/test_c2_harness.py` can assert the field offsets on a Linux host —
# --- which is exactly the check that a CONTEXT we hand to the live shot is the
# --- CONTEXT Windows expects. A wrong `Rip` offset would silently read padding
# --- and print a plausible-looking address.
#
# Field order and offsets follow the documented AMD64 CONTEXT layout
# (P1Home..P6Home, ContextFlags, MxCsr, the six segment words, EFlags, the six
# debug registers, Rax..R15, Rip, then the floating-point/vector/debug tail).
# Only ContextFlags and the GPR/RIP fields are ever read, so the tail is modeled
# as opaque padding whose size is fixed to make sizeof == 1232, the real size:
# under-sizing it would let Windows write past our buffer.
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = 0x00000001   # SegCs..EFlags, Rsp, Rbp, Rip
CONTEXT_INTEGER = 0x00000010   # Rax, Rcx, Rdx, Rbx, Rsi, Rdi, R8..R15
# GetThreadContext / GetThreadTimes request mask used by the probe.
CONTEXT_READ_MASK = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER

# FILETIME is two DWORDs that are really one 64-bit 100 ns count; c_uint64 byref
# is the honest shape for the four out-parameters of Get{Thread,Process}Times.
# `_FILETIME` is the storage, `_FILETIME_OUT` the parameter type the API wants —
# declaring the out-parameters by value would make every ctypes call below raise
# a TypeError on the live shot, which is the one place no Linux test can see it.
_FILETIME = ctypes.c_uint64
_FILETIME_OUT = ctypes.POINTER(ctypes.c_uint64)


class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_uint64),
        ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64),
        ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32),
        ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16),
        ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16),
        ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16),
        ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64),
        ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64),
        ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64),
        ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64),
        ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64),
        ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64),
        ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64),
        ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        # Xmm/VectorRegister/VectorControl/DebugControl..LastExceptionFromRip,
        # never read: 1232 - 0xF8 = 976 bytes.
        ("_tail", ctypes.c_byte * 976),
    ]


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
        k32.GetExitCodeProcess.restype = ctypes.c_int
        k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
        # §44 read-only thread-state probe (the ``thread_probe`` channel).
        k32.SuspendThread.restype = ctypes.c_uint
        k32.SuspendThread.argtypes = [ctypes.c_void_p]
        k32.ResumeThread.restype = ctypes.c_uint
        k32.ResumeThread.argtypes = [ctypes.c_void_p]
        k32.GetThreadContext.restype = ctypes.c_int
        k32.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(CONTEXT)]
        k32.GetThreadTimes.restype = ctypes.c_int
        k32.GetThreadTimes.argtypes = [ctypes.c_void_p] + [_FILETIME_OUT] * 4
        k32.GetProcessTimes.restype = ctypes.c_int
        k32.GetProcessTimes.argtypes = [ctypes.c_void_p] + [_FILETIME_OUT] * 4
        k32.OpenThread.restype = ctypes.c_void_p
        k32.OpenThread.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]
        _KERNEL32_CONFIGURED = True

    return _KERNEL32


# process_all_access = 0x1F0FFF
_PROCESS_ALL_ACCESS = 0x1F0FFF
# thread_all_access = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF. The suspend
# right (0x20) is inside that mask, and §44's failure was on SuspendThread, not on
# the open — so the open must ask for everything or the error is not attributable.
_THREAD_ALL_ACCESS = 0x1FFFFF
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


def pe_image_size(local_dll_path: str) -> int:
    """Return the PE ``SizeOfImage`` — the span of the mapped image in bytes.

    §44 needs an upper bound on the module's address range to classify a thread's
    instruction pointer as *inside* or *outside* our DLL. The virtual address span
    is exactly ``SizeOfImage`` (the same field the loader reserves at mapping
    time), so reading it from the file is as authoritative as enumerating modules
    in the target — and needs no dispatch.
    """
    with open(local_dll_path, "rb") as fh:
        data = fh.read()

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"not a PE file (no MZ header): {local_dll_path!r}")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError(f"not a PE file (bad NT signature): {local_dll_path!r}")

    opt = e_lfanew + 4 + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic not in (0x20B, 0x10B):
        raise ValueError(f"unknown optional-header magic {magic:#x}: {local_dll_path!r}")

    # SizeOfImage is a DWORD at optional-header offset 56 in both PE32 and PE32+.
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    if size_of_image == 0:
        raise ValueError(f"SizeOfImage is 0 in {local_dll_path!r}")
    return size_of_image


# ---------------------------------------------------------------------------
# Pure process/lookup helpers built on subprocess (Windows CLIs)
# ---------------------------------------------------------------------------

def resolve_pid(process_name: str) -> int:
    """Return the PID of ``process_name`` (e.g. ``"stellaris.exe"``).

    Raises ``RuntimeError`` if it is not running. Uses ``tasklist`` CSV output.
    ``tasklist``'s IMAGENAME filter is an EXACT match on the full image name
    including extension (Task 2 finding on the live machine: ``eq stellaris``
    returns "no tasks match", ``eq stellaris.exe`` returns the game), so a bare
    name like ``"stellaris"`` — how every C2 task script calls this — gets
    ``.exe`` appended before filtering and comparing.
    """
    target = process_name if process_name.lower().endswith(".exe") else process_name + ".exe"
    cmd = ["tasklist", "/FI", f"IMAGENAME eq {target}", "/FO", "CSV", "/NH"]
    try:
        out = subprocess.check_output(cmd).decode("utf-8", errors="replace")
    except (subprocess.SubprocessError, OSError) as exc:
        raise RuntimeError(f"tasklist failed while resolving {process_name!r}: {exc}") from exc

    want = target.lower()
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

def _gle() -> int:
    """``GetLastError`` as ctypes exposes it — ``-1`` off Windows.

    ``ctypes.get_last_error`` is a Windows-only attribute and every failure
    string here interpolates it; formatting one on the Linux test host would
    raise AttributeError inside the error path and replace the diagnosis with
    the formatting failure.
    """
    getter = getattr(ctypes, "get_last_error", None)
    return getter() if getter is not None else -1


def _open_process(pid: int):
    handle = _kernel32().OpenProcess(_PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        raise RuntimeError(f"OpenProcess({pid}) failed: gle={_gle()}")
    return handle


def open_process_handle(pid: int):
    """A process handle for the read-only thread-state channel.

    Public because ``capture_thread_state`` takes the two handles the poll loop
    normally supplies, and a control script that holds no dispatched thread still
    has to answer the process half of the question.
    """
    return _open_process(pid)


def open_thread_handle(tid: int):
    """``OpenThread`` with ``thread_all_access``, so ``SuspendThread`` has the right.

    Raises with the gle: the §44 shot lost its whole ``Rip`` axis to
    ``SuspendThread gle=5`` and the only way to tell "this token cannot suspend
    this process" from "that thread had already left the running state" is to ask
    the open call for its actual error.
    """
    k32 = _kernel32()
    handle = k32.OpenThread(_THREAD_ALL_ACCESS, False, tid)
    if not handle:
        raise RuntimeError(f"OpenThread({tid}) failed: gle={_gle()}")
    return handle


def close_handle(handle) -> None:
    """``CloseHandle`` for handles the callers opened (thread and process)."""
    _kernel32().CloseHandle(handle)


def kernel32_call_address(symbol: bytes) -> int:
    """The address of a kernel32 export, as THIS process resolves it.

    Valid in the target too, and that is not an ASLR guess: ``inject_dll`` starts
    a remote thread at exactly such an address (``LoadLibraryA``) and the game's
    loader runs it, which proves the two processes share kernel32's module base.
    Callers still have to behave as if it might not be — see the calibration in
    ``c2_control_sleep.py``, which times a ``Sleep(1000)`` before trusting a long
    one.
    """
    k32 = _kernel32()
    mod = k32.GetModuleHandleA(b"kernel32.dll")
    if not mod:
        raise RuntimeError(f"GetModuleHandleA(kernel32.dll) failed: gle={_gle()}")
    addr = k32.GetProcAddress(mod, symbol)
    if not addr:
        raise RuntimeError(f"GetProcAddress({symbol!r}) failed: gle={_gle()}")
    return addr


def _load_library_addr() -> int:
    return kernel32_call_address(b"LoadLibraryA")


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
            raise RuntimeError(f"VirtualAllocEx({len(path_bytes)}) failed: gle={_gle()}")
        try:
            written = ctypes.c_size_t()
            ok = k32.WriteProcessMemory(handle, remote_mem, path_bytes, len(path_bytes), ctypes.byref(written))
            if not ok or written.value != len(path_bytes):
                raise RuntimeError(
                    f"WriteProcessMemory of DLL path failed: ok={ok} written={written.value}/{len(path_bytes)} "
                    f"gle={_gle()}"
                )

            thread = k32.CreateRemoteThread(handle, None, 0, _load_library_addr(), remote_mem, 0, None)
            if not thread:
                raise RuntimeError(f"CreateRemoteThread(LoadLibraryA) failed: gle={_gle()}")
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
            raise RuntimeError(f"VirtualAllocEx({size}) failed: gle={_gle()}")
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
                f"gle={_gle()}"
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
            raise RuntimeError(f"CreateRemoteThread @0x{base + rva:x} failed: gle={_gle()}")
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
                f"CreateRemoteThread(arg) @0x{base + rva:x} failed: gle={_gle()}"
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


def _read_with_handle(handle, addr: int, size: int) -> bytes:
    """``ReadProcessMemory`` on an ALREADY-OPEN process handle.

    Split out of ``read_memory`` so a poller (``dispatch_watching_buffer``) can
    reuse one handle instead of paying OpenProcess/CloseHandle per iteration.
    """
    k32 = _kernel32()
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    if got.value == 0:
        raise RuntimeError(
            f"ReadProcessMemory @0x{addr:x} size={size} read 0 bytes (ok={ok}, gle={_gle()})"
        )
    return bytes(buf.raw[:got.value])


def _prime_buffer(handle, addr: int, size: int, k32, note) -> None:
    """Zero a remote buffer and read it back, proving it is writable AND readable.

    A poll loop that never sees a byte cannot tell "the callee wrote nothing"
    apart from "this address was never readable" — the 23:26 shot landed exactly
    in that ambiguity. Priming settles it before the dispatch: the write puts the
    buffer in a known all-zero state (so any later non-zero head is proof of a
    callee write) and the read-back confirms this handle can see the page at all.
    Runs BEFORE ``CreateRemoteThread``, so a failing prime raises while the game
    is still untouched rather than mid-teardown.
    """
    written = ctypes.c_size_t()
    ok = k32.WriteProcessMemory(handle, ctypes.c_void_p(addr), b"\x00" * size, size, ctypes.byref(written))
    if not ok or written.value != size:
        raise RuntimeError(
            f"prime WriteProcessMemory @0x{addr:x} size={size} failed: ok={ok} "
            f"written={written.value}/{size} gle={_gle()}"
        )
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    read_ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
    if got.value == 0:
        raise RuntimeError(
            f"prime ReadProcessMemory @0x{addr:x} size={size} read 0 bytes "
            f"(ok={read_ok}, gle={_gle()}) — the buffer was never "
            "readable, so polling it would prove nothing about the callee"
        )
    seen = bytes(buf.raw[:got.value])
    if note:
        note(f"primed {size} bytes @0x{addr:x}: read back {len(seen)} bytes, "
             f"{'all zero' if set(seen) in ({0}, set()) else 'NOT zero'}")


def dispatch_watching_buffer(pid: int, base: int, rva: int, arg_value: int,
                             buf_size: int, marker: bytes | None = None,
                             timeout_ms: int = 60000, poll_ms: int = 2,
                             note=None, witnesses=(), report=None,
                             sampler=None, sample_every_ms: int = 250,
                             poll_addr: int | None = None,
                             thread_probe=None) -> tuple[int, str]:
    """Start a one-arg remote call and poll an output buffer WHILE it runs.

    Returns ``(exit_code, text)`` where ``text`` is the longest buffer contents
    seen up to the first NUL (``""`` if the buffer never became readable).

    Why this exists (evidence §38): the live host dies *after* the remote thread
    returns its exit code, and ReadProcessMemory of a buffer the thread had
    already filled then fails with ERROR_PARTIAL_COPY (gle 299) — a read placed
    after ``WaitForSingleObject`` is racing a teardown it reliably loses. The
    callee writes the buffer BEFORE it returns, so polling from the moment the
    thread starts catches the bytes while the address space is still alive. No
    QuickJS code is added, no extra dispatch is burned, and the target never has
    to write a file (the file channel failed on the 23:03 shot: no
    ``C:\\temp\\c2_diag_<pid>.log`` existed afterwards even though the module's
    kernel32 imports resolved — cause still unmeasured).

    ``marker`` is the substring that proves the copy is complete. With ``None``
    any non-empty text counts: the buffer comes from ``remote_alloc``, i.e.
    freshly committed (zero-filled) memory, so bytes appearing at all already
    means the callee wrote them. A caller that knows the exact tail of its log
    can pass it to avoid acting on a half-written copy.

    ``poll_addr`` decouples the watched address from the call argument (§39). For
    every C2 export the two are the same thing — the buffer IS the single
    lpParameter — but the Sleep control passes a DURATION as the argument, so an
    address to read has to be named separately. ``None`` (the default, and what
    every C2 shot uses) keeps the original behaviour: prime, poll, and report on
    ``arg_value``.

    ``note`` is an optional one-argument callback receiving a short string for
    every STATE CHANGE of the poll loop (priming, each new text length, read
    failures, thread-finished, deadline). The 23:12 shot returned 259 =
    STILL_ACTIVE with no text, which is only interpretable if the caller can see
    how the loop ended, so the live probe passes a printer.

    Give-up policy (fixed after the 23:26 shot): the loop ends on the DEADLINE,
    on the thread signalling, or on the PROCESS handle signalling — never on a
    count of failed reads. The 23:26 shot's first read of a freshly committed
    buffer failed with gle 299 while the host was alive and the thread had not
    returned, and the previous five-strikes-at-2ms rule quit in about 10 ms,
    thousands of iterations before the C sequence could return. A run of
    failures is reported as one summary line so it cannot bury the note stream.

    ``witnesses`` is a sequence of ``(label, addr, size)`` addresses to read on
    every iteration, independently of the caller's buffer. The 23:44 shot found the
    buffer unreadable (gle 299) from its very first poll while the remote thread
    still ran to completion, which has two opposite explanations: the whole address
    space had become unreadable, or only the page we allocated did. A witness at an
    address the DLL itself owns — its ``g_diag_log`` static — distinguishes them,
    and if the process is readable at all it hands back the log as the callee was
    building it, without waiting for the copy into our buffer.

    ``report`` is an optional dict filled with the measurements the two
    explanations need: priming size, read/failure counts with millisecond offsets,
    whether the thread ever returned while the process was alive, both exit codes,
    and per-witness ok/fail tallies plus the longest text seen. It exists because
    ``GetExitCodeThread`` on a thread killed by process termination reports the
    PROCESS exit code, not the callee's return value: an rc of 3 read after the
    host died is not evidence of the Date step until the report says the thread
    returned first.

    ``sampler`` is a zero-argument callable consulted at most once per
    ``sample_every_ms`` while the call runs, its result recorded in
    ``report["samples"]`` as ``(elapsed_ms, text)``. The 00:01 shot localized the
    death to inside ``JS_NewRuntime2`` with ~7 s of runtime before the address space
    went away, and the only way to tell a slow-but-fine call from an allocation
    storm is to watch the host's own memory counters from OUTSIDE during that
    window — no extra dispatch, no code added to the target. A raising sampler is
    recorded once and then dropped: the game vanishing underneath it is the expected
    case, and it must not cost the exit code.

    ``thread_probe`` (§44, authorized read-only) is a two-argument callable
    ``(remote_thread_handle, process_handle) -> str`` consulted at most once per
    ``sample_every_ms`` alongside ``sampler``, recorded in ``report["thread_samples"]``
    as ``(elapsed_ms, text)``. It exists to answer the one question memory counters
    cannot: during the ~6.9 s §42 window the log froze for, is OUR remote thread
    *executing* (instruction pointer advancing inside the DLL, thread CPU time
    burning) or merely *alive-but-blocked* (instruction pointer parked outside our
    code, thread CPU time flat). The caller supplies the whole observation —
    ``GetThreadContext``/``GetThreadTimes`` are its business, and this loop only
    hands it the two handles it already holds; it never touches the target's memory
    or adds a dispatch. A raising probe is recorded once and dropped exactly like
    ``sampler``.
    """
    k32 = _kernel32()
    handle = _open_process(pid)
    addr = base + rva
    watch = arg_value if poll_addr is None else poll_addr
    thread = None
    try:
        # Prime while the thread still does not exist: CreateRemoteThread starts
        # the callee immediately, so an unreadable buffer discovered afterwards is
        # a dispatch already spent and a host already dying.
        _prime_buffer(handle, watch, buf_size, k32, note)
        if report is not None:
            report["primed_bytes"] = buf_size
        t0 = time.monotonic()
        thread = k32.CreateRemoteThread(handle, None, 0, ctypes.c_void_p(addr),
                                        ctypes.c_void_p(arg_value), 0, None)
        if not thread:
            raise RuntimeError(
                f"CreateRemoteThread(watch) @0x{addr:x} failed: gle={_gle()}"
            )
        best = b""
        deadline = time.monotonic() + timeout_ms / 1000.0
        failures = 0
        last_failure = ""
        reads = 0
        read_failures = 0
        first_read_ms = None
        first_failure_ms = None
        returned_while_alive = False
        wit = {label: {"oks": 0, "fails": 0, "best_text": "", "last_state": None}
               for label, _a, _s in witnesses}
        samples = []
        next_sample_ms = 0.0
        thread_samples = []
        next_probe_ms = 0.0

        def elapsed_ms() -> float:
            return (time.monotonic() - t0) * 1000.0

        def poll_witnesses():
            for label, waddr, wsize in witnesses:
                state = wit[label]
                try:
                    raw = _read_with_handle(handle, waddr, wsize)
                except (RuntimeError, OSError) as exc:
                    state["fails"] += 1
                    if state["last_state"] != "fail":
                        state["last_state"] = "fail"
                        if note:
                            note(f"witness {label}: unreadable at "
                                 f"{elapsed_ms():.1f}ms — {exc}")
                    continue
                state["oks"] += 1
                head = raw.split(b"\x00", 1)[0]
                if len(head.decode("ascii", "replace")) > len(state["best_text"]):
                    state["best_text"] = head.decode("ascii", "replace")
                if state["last_state"] != "ok":
                    state["last_state"] = "ok"
                    if note:
                        note(f"witness {label}: readable at {elapsed_ms():.1f}ms, "
                             f"text {state['best_text'][:80]!r}")

        def poll_sampler():
            nonlocal next_sample_ms, sampler
            if sampler is None:
                return
            ms = elapsed_ms()
            if ms < next_sample_ms:
                return
            next_sample_ms = ms + sample_every_ms
            try:
                value = sampler()
            except Exception as exc:  # noqa: BLE001 - a watchdog that can break the
                # measurement it is watching is worse than no watchdog: psutil's error
                # base is not an OSError in every version, and the host vanishing
                # underneath the sampler is the outcome being measured, not a bug.
                samples.append((ms, f"sampler raised {exc}"))
                if note:
                    note(f"sampler raised at {ms:.1f}ms — {exc}; sampling stopped")
                sampler = None
                return
            samples.append((ms, str(value)))

        def poll_thread_probe():
            nonlocal next_probe_ms, thread_probe
            if thread_probe is None:
                return
            ms = elapsed_ms()
            if ms < next_probe_ms:
                return
            next_probe_ms = ms + sample_every_ms
            try:
                value = thread_probe(thread, handle)
            except Exception as exc:  # noqa: BLE001 - same policy as poll_sampler:
                # a probe that can break the measurement it is watching is worse than
                # no probe, and the thread/hosts vanishing underneath it is expected.
                thread_samples.append((ms, f"thread_probe raised {exc}"))
                if note:
                    note(f"thread_probe raised at {ms:.1f}ms — {exc}; probing stopped")
                thread_probe = None
                return
            thread_samples.append((ms, str(value)))

        while True:
            # Sampled at the top of every iteration, so the series covers the whole
            # window including the iteration the read/exit-code decision happens in.
            poll_sampler()
            poll_thread_probe()
            # Read FIRST, then act on the thread state: if the callee has
            # returned, the read in this same iteration is already a post-return
            # read, which is the complete copy. Swapping the two orders
            # re-creates the 22:47 loss.
            finished = k32.WaitForSingleObject(thread, 0) == _WAIT_OBJECT_0
            if finished and not returned_while_alive:
                returned_while_alive = (
                    k32.WaitForSingleObject(handle, 0) != _WAIT_OBJECT_0
                )
            reads += 1
            try:
                chunk = _read_with_handle(handle, watch, buf_size)
            except (RuntimeError, OSError) as exc:
                read_failures += 1
                failures += 1
                last_failure = str(exc)
                if first_failure_ms is None:
                    first_failure_ms = elapsed_ms()
                poll_witnesses()
                # The process handle is the only authority on "the address space
                # is gone"; a failed read by itself is not.
                gone = k32.WaitForSingleObject(handle, 0) == _WAIT_OBJECT_0
                if gone or finished or time.monotonic() >= deadline:
                    if note:
                        reason = ("process handle signalled — the host is gone" if gone
                                  else "thread finished" if finished
                                  else f"deadline {timeout_ms}ms reached")
                        note(f"stop: {reason} after {failures} failed read(s) at "
                             f"{elapsed_ms():.1f}ms; last: {last_failure}")
                    break
                time.sleep(poll_ms / 1000.0)
                continue

            if first_read_ms is None:
                first_read_ms = elapsed_ms()
            if failures and note:
                note(f"read recovered after {failures} failed read(s); last was: {last_failure}")
                failures = 0
                last_failure = ""
            poll_witnesses()
            head = chunk.split(b"\x00", 1)[0]
            if head and note and len(head) != len(best.split(b"\x00", 1)[0]):
                note(f"buffer text now {len(head)} bytes: {head[:80]!r}")
            if len(head) > len(best.split(b"\x00", 1)[0]):
                best = chunk
            complete = marker in head if marker is not None else bool(head)
            if complete or finished:
                if note:
                    reason = "text complete" if complete else "thread finished"
                    note(f"stop: {reason}, {len(head)} bytes in view at "
                         f"{elapsed_ms():.1f}ms")
                break
            if time.monotonic() >= deadline:
                if note:
                    note(f"stop: deadline {timeout_ms}ms, {len(best)} bytes seen at "
                         f"{elapsed_ms():.1f}ms")
                break
            time.sleep(poll_ms / 1000.0)

        exit_code = ctypes.c_uint()
        k32.GetExitCodeThread(thread, ctypes.byref(exit_code))
        process_code = ctypes.c_uint()
        k32.GetExitCodeProcess(handle, ctypes.byref(process_code))
        if note:
            note(f"exit code = {exit_code.value} "
                 f"({'STILL_ACTIVE — the call had not returned' if exit_code.value == 259 else 'thread had returned'}); "
                 f"process exit code = {process_code.value:#x}, thread returned while "
                 f"process alive = {returned_while_alive}")
        if report is not None:
            report["poll_addr"] = watch
            report.update({
                "reads": reads,
                "read_failures": read_failures,
                "first_read_ms": first_read_ms,
                "first_failure_ms": first_failure_ms,
                "thread_exit_code": exit_code.value,
                "process_exit_code": process_code.value,
                "thread_returned_while_alive": returned_while_alive,
                "witness": wit,
                "samples": samples,
                "thread_samples": thread_samples,
            })
    finally:
        if thread:
            k32.CloseHandle(thread)
        k32.CloseHandle(handle)
    return exit_code.value, best.split(b"\x00", 1)[0].decode("ascii", errors="replace")


# ---------------------------------------------------------------------------
# §44 read-only thread-state probe
#
# What this answers and what it does not: the log witness froze for ~6.9 s inside
# ``JS_NewRuntime2`` (evidence §42) and the offline allocation map (§43) shows no
# allocation in that window, so the open question is what OUR remote thread was
# doing there. Two readings survive everything measured so far — the thread was
# executing QuickJS code, or the thread was alive but blocked by the host. Only
# the thread itself can tell them apart: an instruction pointer that sits inside
# our module and thread CPU time that advances means execution; an instruction
# pointer parked outside with flat CPU time means blockage.
#
# Boundary honored: this reads. ``GetThreadContext`` needs ``SuspendThread`` (a
# documented requirement, not an option) and the suspend/resume is wrapped so the
# thread is never left suspended; ``GetThreadTimes``/``GetProcessTimes`` need no
# suspension at all. No hook, no ``WriteProcessMemory``, no code added to the
# target, no new export.
# ---------------------------------------------------------------------------

def classify_rip(rip, base: int, image_size: int) -> str:
    """Whether an instruction pointer falls in the mapped span of our DLL.

    ``"unknown"`` when the capture failed — an absent address is not evidence of
    blockage, and conflating the two would read a failed probe as a finding.
    """
    if rip is None:
        return "unknown"
    return "inside_dll" if base <= rip < base + image_size else "outside_dll"


def filetime_us(ticks: int) -> int:
    """Convert a FILETIME (100 ns units) to whole microseconds."""
    return ticks // 10


def format_thread_state(state: dict, base: int, image_size: int) -> str:
    """Render one capture as the single line recorded in ``thread_samples``."""
    where = classify_rip(state.get("rip"), base, image_size)
    parts = [
        f"rip={state['rip']:#x}" if state.get("rip") is not None else "rip=none",
        f"rsp={state['rsp']:#x}" if state.get("rsp") is not None else "rsp=none",
        f"where={where}",
        f"th_kernel_us={state.get('thread_kernel_us')}",
        f"th_user_us={state.get('thread_user_us')}",
        f"pr_kernel_us={state.get('process_kernel_us')}",
        f"pr_user_us={state.get('process_user_us')}",
    ]
    errors = [e for e in (state.get("context_err"), state.get("times_err")) if e]
    if errors:
        parts.append("err=" + ";".join(errors))
    return " ".join(parts)


def capture_thread_state(thread_handle, process_handle) -> dict:
    """Read the remote thread's ``Rip``/``Rsp`` plus thread and process CPU times.

    Returns ``{"rip", "rsp", "thread_kernel_us", "thread_user_us",
    "process_kernel_us", "process_user_us", "context_err", "times_err"}`` —
    ``None`` for any value that could not be read, with the reason in the matching
    ``*_err`` key. Nothing here raises: the caller is measuring a process that may
    vanish mid-read, and a vanished value is a measurement, not a bug.
    """
    k32 = _kernel32()
    state = dict(rip=None, rsp=None, thread_kernel_us=None, thread_user_us=None,
                 process_kernel_us=None, process_user_us=None,
                 context_err=None, times_err=None)

    # Times first and without suspension: they are the primary discriminator, so
    # they must survive a failed or refused context read.
    tk = _FILETIME(0); tu = _FILETIME(0); _tc = _FILETIME(0); _te = _FILETIME(0)
    pk = _FILETIME(0); pu = _FILETIME(0); _pc = _FILETIME(0); _pe = _FILETIME(0)
    if not k32.GetThreadTimes(thread_handle, ctypes.byref(_tc), ctypes.byref(_te),
                              ctypes.byref(tk), ctypes.byref(tu)):
        state["times_err"] = f"GetThreadTimes gle={_gle()}"
    # Creation and exit times are discarded — this thread is ours and still running.
    elif not k32.GetProcessTimes(process_handle, ctypes.byref(_pc), ctypes.byref(_pe),
                                 ctypes.byref(pk), ctypes.byref(pu)):
        state["times_err"] = f"GetProcessTimes gle={_gle()}"
    else:
        state["thread_kernel_us"] = filetime_us(tk.value)
        state["thread_user_us"] = filetime_us(tu.value)
        state["process_kernel_us"] = filetime_us(pk.value)
        state["process_user_us"] = filetime_us(pu.value)

    ctx = CONTEXT()
    ctx.ContextFlags = CONTEXT_READ_MASK
    # SuspendThread returns the PREVIOUS suspend count, (DWORD)-1 on failure; the
    # resume is therefore conditional on the suspend having happened, and lives in
    # ``finally`` so a raising read cannot park the game's thread forever.
    suspended = k32.SuspendThread(thread_handle)
    try:
        if suspended == 0xFFFFFFFF:
            state["context_err"] = f"SuspendThread gle={_gle()}"
        elif not k32.GetThreadContext(thread_handle, ctypes.byref(ctx)):
            state["context_err"] = f"GetThreadContext gle={_gle()}"
        else:
            state["rip"] = ctx.Rip
            state["rsp"] = ctx.Rsp
    finally:
        if suspended != 0xFFFFFFFF:
            if k32.ResumeThread(thread_handle) == 0xFFFFFFFF:
                state["context_err"] = (state["context_err"] or "") + (
                    f" ResumeThread gle={_gle()}")

    return state


def read_memory(pid: int, addr: int, size: int) -> bytes:
    """``ReadProcessMemory``; raise if zero bytes are actually read."""
    k32 = _kernel32()
    handle = _open_process(pid)
    try:
        return _read_with_handle(handle, addr, size)
    finally:
        k32.CloseHandle(handle)


def read_u64(pid: int, addr: int) -> int:
    """Read a little-endian 64-bit unsigned value from remote memory."""
    raw = read_memory(pid, addr, 8)
    if len(raw) < 8:
        raise RuntimeError(f"read_u64 @0x{addr:x} got only {len(raw)} bytes, need 8")
    return int.from_bytes(raw[:8], "little")
