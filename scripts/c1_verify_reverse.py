import ctypes
import subprocess
import sys

k32 = ctypes.windll.kernel32

# Get stellaris PID
out = subprocess.check_output(['tasklist', '/FI', 'IMAGENAME eq stellaris.exe', '/FO', 'CSV', '/NH']).decode('utf-8', errors='replace')
parts = out.strip().split(',')
pid_val = int(parts[1].strip('"'))
print(f'Game PID: {pid_val}')

hProc = k32.OpenProcess(0x1F0FFF, False, pid_val)
if not hProc:
    print(f'OpenProcess failed: {k32.GetLastError()}')
    sys.exit(1)

# Query game base via Modules
ps_cmd = "Get-Process stellaris | Select-Object -ExpandProperty MainModule | Select-Object -ExpandProperty BaseAddress"
ps_out = subprocess.check_output(['powershell', '-Command', ps_cmd]).decode().strip()
game_base = int(ps_out)
print(f'Game base: 0x{game_base:X}')

# Set up function signatures for 64-bit addresses
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = ctypes.c_bool

# ReadProcessMemory helper
def read_mem(addr, size):
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    result = k32.ReadProcessMemory(hProc, addr, buf, size, ctypes.byref(bytes_read))
    if not result:
        return None
    return buf.raw[:bytes_read.value]

def read_u64(addr):
    data = read_mem(addr, 8)
    if data and len(data) == 8:
        return int.from_bytes(data, 'little')
    return None

def read_u32(addr):
    data = read_mem(addr, 4)
    if data and len(data) == 4:
        return int.from_bytes(data, 'little')
    return None

# Token DB singleton accessor: 0x1D12C60
# But we can read the global directly: 0x37347A0
token_db_addr = game_base + 0x37347A0
print(f'Token DB global @ 0x{token_db_addr:X}')

db_ptr = read_u64(token_db_addr)
if db_ptr is None:
    print('Failed to read token DB global')
    sys.exit(1)
print(f'Token DB object: 0x{db_ptr:X}')

# Reverse table is at [db+0x70]
reverse_table_ptr = read_u64(db_ptr + 0x70)
if reverse_table_ptr is None:
    print('Failed to read reverse table pointer')
    sys.exit(1)
print(f'Reverse table: 0x{reverse_table_ptr:X}')

# Read id→name for token 68636
token_id = 68636
entry_stride = 0x30
entry_addr = reverse_table_ptr + token_id * entry_stride
print(f'Entry for id {token_id} @ 0x{entry_addr:X}')

# The holder's std::string is at entry+0x10
# MSVC std::string layout: chars at +0x00 (if SSO) or +0x00 is pointer (if heap)
# size at +0x10, cap at +0x18 (relative to the string start)
# But in our case, the holder starts at entry, and the string is at entry+0x10
string_addr = entry_addr + 0x10

# Read the string's cap to determine if SSO or heap
cap = read_u64(string_addr + 0x18)
if cap is None:
    print('Failed to read string cap')
    sys.exit(1)

print(f'String cap: {cap} (0x{cap:X})')

if cap < 0x10:
    # SSO: chars are inline at string_addr
    chars_addr = string_addr
    print('String is SSO (inline)')
else:
    # Heap: chars pointer is at string_addr
    chars_addr = read_u64(string_addr)
    if chars_addr is None:
        print('Failed to read chars pointer')
        sys.exit(1)
    print(f'String is heap, chars @ 0x{chars_addr:X}')

# Read size
size = read_u64(string_addr + 0x10)
if size is None:
    print('Failed to read string size')
    sys.exit(1)
print(f'String size: {size}')

# Read the chars
if size > 0 and size < 1000:  # sanity check
    if cap < 0x10:
        # SSO: read from string_addr
        name_data = read_mem(string_addr, size)
    else:
        # Heap: read from chars_addr
        name_data = read_mem(chars_addr, size)

    if name_data:
        # Remove null terminator if present
        name = name_data.rstrip(b'\x00').decode('utf-8', errors='replace')
        print(f'\n=== RESULT ===')
        print(f'Token id {token_id} = "{name}"')
        if name == "neo_effect":
            print('✓ VERIFIED: reverse table confirms neo_effect at id 68636')
        else:
            print(f'✗ MISMATCH: expected "neo_effect", got "{name}"')
    else:
        print('Failed to read string chars')
else:
    print(f'String size out of range: {size}')

k32.CloseHandle(hProc)
