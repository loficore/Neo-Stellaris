import ctypes, sys, time

pid = int(sys.argv[1])
dll_path = sys.argv[2]

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

# Step 1: Delete old marker file
import os
marker_path = r"C:\temp\dll_loaded.txt"
if os.path.exists(marker_path):
    os.remove(marker_path)
    print(f"Deleted old marker file")

# Step 2: Inject DLL via LoadLibrary
k32_mod = k32.GetModuleHandleA(b"kernel32.dll")
ll_addr = k32.GetProcAddress(k32_mod, b"LoadLibraryA")
print(f"LoadLibraryA @ 0x{ll_addr:x}")

hproc = k32.OpenProcess(0x1F0FFF, 0, pid)
if not hproc:
    print(f"OpenProcess failed: {ctypes.get_last_error()}")
    sys.exit(1)

dll_bytes = dll_path.encode('ascii') + b'\x00'
remote_mem = k32.VirtualAllocEx(hproc, None, len(dll_bytes), 0x3000, 0x40)
k32.WriteProcessMemory(hproc, remote_mem, dll_bytes, len(dll_bytes), ctypes.byref(ctypes.c_size_t()))
print(f"Wrote DLL path to 0x{remote_mem:x}")

thread = k32.CreateRemoteThread(hproc, None, 0, ll_addr, remote_mem, 0, None)
if not thread:
    print(f"CreateRemoteThread (LoadLibrary) failed: {ctypes.get_last_error()}")
    k32.CloseHandle(hproc)
    sys.exit(1)

k32.WaitForSingleObject(thread, 15000)
exit_code = ctypes.c_uint32()
k32.GetExitCodeThread(thread, ctypes.byref(exit_code))
hmodule = exit_code.value
k32.CloseHandle(thread)
print(f"DLL module handle: 0x{hmodule:x}")

if hmodule == 0:
    print("FAILED: LoadLibrary returned NULL")
    k32.CloseHandle(hproc)
    sys.exit(1)

# Step 3: Wait a moment and check for marker file
print("Waiting 2 seconds for DllMain to write marker...")
time.sleep(2)

if os.path.exists(marker_path):
    with open(marker_path, 'r') as f:
        content = f.read()
    print(f"SUCCESS: Marker file found! Content: {content.strip()}")
else:
    print(f"FAILURE: Marker file NOT found at {marker_path}")
    print("DllMain may have crashed or file I/O failed in injection context")

# Step 4: Check if game is still alive
import subprocess
result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}', '/NH'], capture_output=True, text=True)
if str(pid) in result.stdout:
    print(f"Game (PID {pid}) is still running")
else:
    print(f"Game (PID {pid}) has CRASHED")

k32.CloseHandle(hproc)
