import ctypes
import subprocess
import os
import sys

k32 = ctypes.windll.kernel32

# Get stellaris PID
out = subprocess.check_output(['tasklist', '/FI', 'IMAGENAME eq stellaris.exe', '/FO', 'CSV', '/NH']).decode('utf-8', errors='replace')
parts = out.strip().split(',')
pid_val = int(parts[1].strip('"'))
print(f'Game PID: {pid_val}')

# Query the actual module base using PowerShell (full 64-bit address)
ps_cmd = f"Get-Process stellaris | Select-Object -ExpandProperty Modules | Where-Object {{ $_.ModuleName -eq '{sys.argv[1]}' }} | Select-Object -ExpandProperty BaseAddress"
ps_out = subprocess.check_output(['powershell', '-Command', ps_cmd]).decode().strip()
remote_base = int(ps_out)
print(f'Remote DLL base: 0x{remote_base:X}')

# C1Run RVA (passed as argument)
c1run_rva = int(sys.argv[2], 16)
remote_fn = remote_base + c1run_rva
print(f'C1Run RVA: 0x{c1run_rva:X}')
print(f'Remote C1Run: 0x{remote_fn:X}')

hProc = k32.OpenProcess(0x1F0FFF, False, pid_val)
print(f'hProc: {hProc}')

# Set up function signature for CreateRemoteThread
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]

tid = ctypes.c_uint32()
hThread = k32.CreateRemoteThread(hProc, None, 0, remote_fn, None, 0, ctypes.byref(tid))
print(f'hThread: {hThread}, tid: {tid.value}')

if hThread:
    k32.WaitForSingleObject(hThread, 10000)
    exit_code = ctypes.c_uint32()
    k32.GetExitCodeThread(hThread, ctypes.byref(exit_code))
    print(f'C1Run returned: {exit_code.value} (0x{exit_code.value:X})')
    k32.CloseHandle(hThread)
else:
    err = k32.GetLastError()
    print(f'CreateRemoteThread failed, error: {err}')

k32.CloseHandle(hProc)

# Check game status
try:
    subprocess.check_call(['tasklist', '/FI', f'PID eq {pid_val}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('Game: still running')
except:
    print('Game: CRASHED')
