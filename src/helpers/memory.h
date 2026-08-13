#pragma once
// memory.h - Safe memory operations and pointer chain following for Stellaris RE
// Provides ReadProcessMemory wrappers, pointer validation, chain following, JSON output

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <span>
#include <format>

namespace stellaris::memory {

// ============================================================================
// Result types for structured error handling
// ============================================================================

struct MemoryReadResult {
    bool success = false;
    uintptr_t address = 0;
    size_t size = 0;
    std::vector<uint8_t> data;
    std::string error;
};

struct PointerChainResult {
    bool success = false;
    uintptr_t baseAddress = 0;
    std::vector<uintptr_t> resolvedAddresses;  // intermediate addresses
    uintptr_t finalAddress = 0;
    std::vector<uint8_t> value;                // value at final address
    std::string error;
};

struct MemoryRegionInfo {
    uintptr_t baseAddress = 0;
    size_t regionSize = 0;
    DWORD state = 0;       // MEM_COMMIT, MEM_RESERVE, MEM_FREE
    DWORD protect = 0;     // PAGE_READWRITE, etc.
    DWORD type = 0;        // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
    bool readable = false;
    bool writable = false;
    bool executable = false;
};

// ============================================================================
// Core memory operations
// ============================================================================

// Safe memory read with validation. Returns nullopt on failure.
std::optional<std::vector<uint8_t>> safeReadMemory(
    HANDLE hProcess,
    uintptr_t address,
    size_t size
);

// Read a typed value from process memory
template<typename T>
std::optional<T> readValue(HANDLE hProcess, uintptr_t address) {
    auto data = safeReadMemory(hProcess, address, sizeof(T));
    if (!data || data->size() != sizeof(T)) return std::nullopt;
    T value{};
    std::memcpy(&value, data->data(), sizeof(T));
    return value;
}

// Read 8-byte pointer from process memory
std::optional<uintptr_t> readPointer(HANDLE hProcess, uintptr_t address);

// Read 4-byte pointer (for 32-bit offsets)
std::optional<uint32_t> readPointer32(HANDLE hProcess, uintptr_t address);

// Read string from process memory (null-terminated, max length)
std::optional<std::string> readString(
    HANDLE hProcess,
    uintptr_t address,
    size_t maxLength = 256
);

// Read wide string from process memory
std::optional<std::wstring> readWideString(
    HANDLE hProcess,
    uintptr_t address,
    size_t maxLength = 256
);

// ============================================================================
// Pointer validation
// ============================================================================

// Validate if address is readable (checks VirtualQueryEx)
bool validatePointer(HANDLE hProcess, uintptr_t address);

// Get memory region info for an address
std::optional<MemoryRegionInfo> queryMemoryRegion(HANDLE hProcess, uintptr_t address);

// Check if entire range [address, address+size) is readable
bool validateRange(HANDLE hProcess, uintptr_t address, size_t size);

// ============================================================================
// Pointer chain following
// ============================================================================

// Follow pointer chain: base -> [offset0] -> [offset1] -> ... -> final
// Each offset is applied to the pointer value read from the previous step
std::optional<PointerChainResult> followPointerChain(
    HANDLE hProcess,
    uintptr_t base,
    const std::vector<uintptr_t>& offsets
);

// Follow chain and read value of type T at the end
template<typename T>
std::optional<T> followChainAndRead(
    HANDLE hProcess,
    uintptr_t base,
    const std::vector<uintptr_t>& offsets
) {
    auto result = followPointerChain(hProcess, base, offsets);
    if (!result || !result->success) return std::nullopt;
    return readValue<T>(hProcess, result->finalAddress);
}

// Follow chain and read pointer at the end
std::optional<uintptr_t> followChainAndReadPointer(
    HANDLE hProcess,
    uintptr_t base,
    const std::vector<uintptr_t>& offsets
);

// ============================================================================
// Batch operations
// ============================================================================

// Read multiple addresses in one call (reduces context switches)
std::vector<MemoryReadResult> batchRead(
    HANDLE hProcess,
    const std::vector<std::pair<uintptr_t, size_t>>& reads
);

// ============================================================================
// JSON output for AI consumption
// ============================================================================

namespace json {

// Convert MemoryReadResult to JSON string
std::string toJson(const MemoryReadResult& result);

// Convert PointerChainResult to JSON string
std::string toJson(const PointerChainResult& result);

// Convert MemoryRegionInfo to JSON string
std::string toJson(const MemoryRegionInfo& info);

// Create a memory dump JSON (address + hex bytes)
std::string memoryDump(
    uintptr_t address,
    std::span<const uint8_t> data,
    const std::string& label = ""
);

// Create an error JSON
std::string error(const std::string& message, uintptr_t address = 0);

// Create a success JSON with arbitrary key-value pairs
std::string success(
    uintptr_t address,
    size_t size,
    const std::string& type = "memory_read"
);

// Format a hex byte array as string: "48 89 5C 24 08"
std::string hexBytes(std::span<const uint8_t> data);

// Format address as hex string: "0x143287360"
std::string hexAddress(uintptr_t address);

} // namespace json

// ============================================================================
// Utility
// ============================================================================

// Convert protection flags to readable string
std::string protectToString(DWORD protect);

// Convert memory state to readable string
std::string stateToString(DWORD state);

} // namespace stellaris::memory
