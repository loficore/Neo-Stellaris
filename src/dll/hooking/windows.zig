// windows.zig — Windows API wrappers for hooking operations.
//
// Provides thin wrappers around Win32 API functions needed by the
// trampoline detour hooking framework: memory protection changes,
// memory allocation, and instruction-length analysis for x86_64.

const std = @import("std");

// ---------------------------------------------------------------------------
// Windows API declarations (x86_64 ABI, no libc)
// ---------------------------------------------------------------------------

const DWORD = u32;
const LPVOID = ?*anyopaque;
const SIZE_T = usize;
const BOOL = i32;

const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
const PAGE_EXECUTE_READ: DWORD = 0x20;
const PAGE_READWRITE: DWORD = 0x04;
const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;
const MEM_RELEASE: DWORD = 0x8000;

extern "kernel32" fn VirtualProtect(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: *DWORD) BOOL;
extern "kernel32" fn VirtualAlloc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) LPVOID;
extern "kernel32" fn VirtualFree(lpAddress: LPVOID, dwSize: SIZE_T, dwFreeType: DWORD) BOOL;
extern "kernel32" fn FlushInstructionCache(hProcess: ?*anyopaque, lpBaseAddress: LPVOID, dwSize: SIZE_T) BOOL;
extern "kernel32" fn GetCurrentProcess() ?*anyopaque;

// ---------------------------------------------------------------------------
// Memory protection helpers
// ---------------------------------------------------------------------------

/// Memory protection flags for a region of memory.
pub const Protect = enum(DWORD) {
    execute_read = PAGE_EXECUTE_READ,
    execute_readwrite = PAGE_EXECUTE_READWRITE,
    read_write = PAGE_READWRITE,

    fn toRaw(self: Protect) DWORD {
        return @intFromEnum(self);
    }
};

/// RAII-style guard that restores the original page protection on deinit.
/// Used to bracket writes to code pages: construct → write → deinit restores.
pub const ProtectGuard = struct {
    base: *anyopaque,
    size: usize,
    old_protect: DWORD,

    /// Change memory protection on [base, base + size).
    /// Returns error if VirtualProtect fails.
    pub fn change(base: *anyopaque, size: usize, new_protect: Protect) !ProtectGuard {
        var old: DWORD = 0;
        const ok = VirtualProtect(
            base,
            size,
            new_protect.toRaw(),
            &old,
        );
        if (ok == 0) return error.VirtualProtectFailed;
        return ProtectGuard{
            .base = base,
            .size = size,
            .old_protect = old,
        };
    }

    /// Restore the original protection. Called automatically on deinit.
    pub fn restore(self: *ProtectGuard) !void {
        var dummy: DWORD = 0;
        const ok = VirtualProtect(self.base, self.size, self.old_protect, &dummy);
        if (ok == 0) return error.VirtualProtectFailed;
    }

    pub fn deinit(self: *ProtectGuard) void {
        self.restore() catch {};
    }
};

// ---------------------------------------------------------------------------
// Memory allocation helpers
// ---------------------------------------------------------------------------

/// Allocate executable memory near a target address (within ±2GB for rel32 jumps).
/// Falls back to any address if near-allocation fails.
pub fn allocNear(target: *anyopaque, size: usize) !*anyopaque {
    const target_addr = @intFromPtr(target);
    const page_size: usize = 4096;
    const aligned_size = std.mem.alignForward(usize, size, page_size);

    // Search within ±2GB for a free region (for rel32 compatibility).
    const search_range: usize = 0x7FFF_FFFF; // ~2GB
    const base = if (target_addr > search_range)
        target_addr - search_range
    else
        0;

    const limit: usize = std.math.min(base +| 2 * search_range, std.math.maxInt(usize));

    // Try candidate addresses within the 2GB window.
    var addr: usize = base;
    while (addr < limit) : (addr += page_size) {
        const ptr: LPVOID = @ptrFromInt(addr);
        const result = VirtualAlloc(ptr, aligned_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (result) |allocated| {
            return allocated;
        }
    }

    // Fallback: let the OS choose any address.
    const fallback = VirtualAlloc(null, aligned_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return fallback orelse error.VirtualAllocFailed;
}

/// Free memory previously allocated with allocNear.
pub fn freeMem(addr: *anyopaque) !void {
    const ok = VirtualFree(addr, 0, MEM_RELEASE);
    if (ok == 0) return error.VirtualFreeFailed;
}

/// Flush the instruction cache for a region.
/// Must be called after writing new instructions to ensure the CPU sees them.
pub fn flushInstructionCache(base: *anyopaque, size: usize) void {
    _ = FlushInstructionCache(GetCurrentProcess(), base, size);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ProtectGuard enum values" {
    try std.testing.expectEqual(@as(DWORD, 0x20), Protect.execute_read.toRaw());
    try std.testing.expectEqual(@as(DWORD, 0x40), Protect.execute_readwrite.toRaw());
    try std.testing.expectEqual(@as(DWORD, 0x04), Protect.read_write.toRaw());
}
