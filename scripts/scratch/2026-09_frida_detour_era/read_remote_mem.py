import ctypes, sys

pid = int(sys.argv[1])
addr = int(sys.argv[2], 16)

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]

hproc = k32.OpenProcess(0x1F0FFF, 0, pid)
if not hproc:
    print(f"OpenProcess failed: {ctypes.get_last_error()}")
    sys.exit(1)

buf = ctypes.create_string_buffer(64)
bytes_read = ctypes.c_size_t()
k32.ReadProcessMemory(hproc, ctypes.c_void_p(addr), buf, 64, ctypes.byref(bytes_read))
hex_str = " ".join(f"{b:02x}" for b in buf.raw[:bytes_read.value])
print(f"Bytes at 0x{addr:x} ({bytes_read.value} bytes):")
print(hex_str)

# Expected: 55 48 89 e5 b8 2a 00 00 00 5d c3
expected = bytes([0x55, 0x48, 0x89, 0xe5, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x5d, 0xc3])
if buf.raw[:len(expected)] == expected:
    print("MATCH: Code is correct (push rbp; mov rbp,rsp; mov eax,42; pop rbp; ret)")
else:
    print("MISMATCH!")
    exp_str = " ".join(f"{b:02x}" for b in expected)
    print(f"Expected: {exp_str}")

k32.CloseHandle(hproc)
