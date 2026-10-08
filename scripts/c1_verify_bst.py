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

# Set up function signatures for 64-bit addresses
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = ctypes.c_bool

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

# Query game base
ps_cmd = "Get-Process stellaris | Select-Object -ExpandProperty MainModule | Select-Object -ExpandProperty BaseAddress"
ps_out = subprocess.check_output(['powershell', '-Command', ps_cmd]).decode().strip()
game_base = int(ps_out)
print(f'Game base: 0x{game_base:X}')

# Trigger DB global: 0x32611C8
trigger_db_global = game_base + 0x32611C8
print(f'Trigger DB global @ 0x{trigger_db_global:X}')

db_ptr = read_u64(trigger_db_global)
if db_ptr is None or db_ptr == 0:
    print('Trigger DB not initialized')
    sys.exit(1)
print(f'Trigger DB object: 0x{db_ptr:X}')

# BST root is at [db+0x88] (from §21)
# MSVC std::_Tree layout: the root node pointer is at a specific offset
# For simplicity, let's read a chunk of the DB and look for our token id
print(f'\nReading trigger DB memory around +0x88...')
db_data = read_mem(db_ptr + 0x80, 0x100)
if db_data:
    print(f'DB+0x80..+0x180 (first 256 bytes):')
    for i in range(0, len(db_data), 16):
        hex_str = ' '.join(f'{b:02x}' for b in db_data[i:i+16])
        print(f'  +{0x80+i:03x}: {hex_str}')

# Search for the trigger donor class_info address in memory
# Donor class_info is at game_base + 0x269CAA8
donor_class_info = game_base + 0x269CAA8
print(f'\nTrigger donor class_info: 0x{donor_class_info:X}')

# Search for this address (as a little-endian u64) in a larger memory range
donor_bytes = donor_class_info.to_bytes(8, 'little')
print(f'Searching for donor class_info bytes: {donor_bytes.hex()}')

# Search in heap regions — allocate a large read
# Let's search in 1MB chunks starting from common heap addresses
search_ranges = [
    (0x00007FF000000000, 0x100000),  # 1MB near typical heap
    (0x0000000000800000, 0x100000),  # 1MB at low address
    (db_ptr, 0x10000) if db_ptr and db_ptr > 0x10000 else (0, 0),  # Around DB
]

for start, size in search_ranges:
    if start == 0:
        continue
    print(f'\nSearching 0x{start:X}..0x{start+size:X}...')
    chunk = read_mem(start, size)
    if chunk:
        idx = chunk.find(donor_bytes)
        if idx != -1:
            print(f'  FOUND at offset 0x{idx:X} (addr 0x{start+idx:X})')
            # Read surrounding context
            context_start = max(0, idx - 32)
            context = chunk[context_start:idx+64]
            print(f'  Context: {context.hex()}')
        else:
            print(f'  Not found')

k32.CloseHandle(hProc)
print('\nDone.')
