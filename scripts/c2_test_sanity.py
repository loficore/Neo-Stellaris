import ctypes, sys

pid = int(sys.argv[1])
dll_path = sys.argv[2]

# RVAs from the DLL build (v19 - pure Zig C2Sanity)
RVAS = {
    "C2Sanity": 0x44bf40,
    "C2DiagQJS": 0x44bdc0,
    "C2DiagGetLogAddr": 0x44bda0,
    "C2TestQJS": 0x44e940,
    "C2Init": 0x44bec0,
}

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.GetModuleHandleA.restype = ctypes.c_void_p
k32.GetModuleHandleA.argtypes = [ctypes.c_char_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint, ctypes.c_uint]
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p]

# Step 1: Inject DLL
k32_mod = k32.GetModuleHandleA(b"kernel32.dll")
ll_addr = k32.GetProcAddress(k32_mod, b"LoadLibraryA")
hproc = k32.OpenProcess(0x1F0FFF, 0, pid)
if not hproc:
    print(f"OpenProcess failed: {ctypes.get_last_error()}")
    sys.exit(1)

dll_bytes = dll_path.encode('ascii') + b'\x00'
remote_mem = k32.VirtualAllocEx(hproc, None, len(dll_bytes), 0x3000, 0x40)
k32.WriteProcessMemory(hproc, remote_mem, dll_bytes, len(dll_bytes), ctypes.byref(ctypes.c_size_t()))

thread = k32.CreateRemoteThread(hproc, None, 0, ll_addr, remote_mem, 0, None)
if not thread:
    print(f"CreateRemoteThread (LoadLibrary) failed: {ctypes.get_last_error()}")
    sys.exit(1)
k32.WaitForSingleObject(thread, 15000)
exit_code = ctypes.c_uint32()
k32.GetExitCodeThread(thread, ctypes.byref(exit_code))
hmodule = exit_code.value
k32.CloseHandle(thread)
print(f"DLL loaded at 0x{hmodule:x}")
if hmodule == 0:
    print("FAILED: LoadLibrary returned NULL")
    k32.CloseHandle(hproc)
    sys.exit(1)

def call_remote(name, timeout=10000):
    rva = RVAS.get(name)
    if rva is None:
        print(f"Unknown function: {name}")
        return None
    addr = hmodule + rva
    print(f"\n--- {name} @ 0x{addr:x} (RVA=0x{rva:x}) ---")
    t = k32.CreateRemoteThread(hproc, None, 0, ctypes.c_void_p(addr), None, 0, None)
    if not t:
        print(f"CreateRemoteThread failed: {ctypes.get_last_error()}")
        return None
    k32.WaitForSingleObject(t, timeout)
    result = ctypes.c_uint32()
    k32.GetExitCodeThread(t, ctypes.byref(result))
    k32.CloseHandle(t)
    return result.value

# Step 2: Test C2Sanity (should return 42)
r = call_remote("C2Sanity")
print(f"C2Sanity returned: {r}")
if r == 42:
    print(">>> SUCCESS: New DLL code is loaded!")
else:
    print(f">>> FAILURE: Expected 42, got {r}")

# Step 3: Test C2DiagQJS
r2 = call_remote("C2DiagQJS", timeout=30000)
print(f"C2DiagQJS returned: {r2}")

# Step 4: Read diag log
r3 = call_remote("C2DiagGetLogAddr")
print(f"C2DiagGetLogAddr returned: 0x{r3:x}")
if r3 and r3 > 0x10000:
    buf = ctypes.create_string_buffer(512)
    bytes_read = ctypes.c_size_t()
    k32.ReadProcessMemory(hproc, ctypes.c_void_p(r3), buf, 512, ctypes.byref(bytes_read))
    log_str = buf.value.decode('ascii', errors='replace').rstrip('\x00')
    print(f"Diag log ({bytes_read.value} bytes): {log_str}")

k32.CloseHandle(hproc)
print("\nDone.")
