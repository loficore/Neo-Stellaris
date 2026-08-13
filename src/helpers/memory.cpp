// memory.cpp - Safe memory operations and pointer chain following for Stellaris RE
// Implementation using Windows API (ReadProcessMemory, VirtualQueryEx)

#include "memory.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace stellaris::memory {

// ============================================================================
// Core memory operations
// ============================================================================

std::optional<std::vector<uint8_t>> safeReadMemory(
    HANDLE hProcess,
    uintptr_t address,
    size_t size
) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE || size == 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> buffer(size);
    SIZE_T bytesRead = 0;

    BOOL result = ReadProcessMemory(
        hProcess,
        reinterpret_cast<LPCVOID>(address),
        buffer.data(),
        size,
        &bytesRead
    );

    if (!result || bytesRead != size) {
        return std::nullopt;
    }

    return buffer;
}

std::optional<uintptr_t> readPointer(HANDLE hProcess, uintptr_t address) {
    return readValue<uintptr_t>(hProcess, address);
}

std::optional<uint32_t> readPointer32(HANDLE hProcess, uintptr_t address) {
    return readValue<uint32_t>(hProcess, address);
}

std::optional<std::string> readString(
    HANDLE hProcess,
    uintptr_t address,
    size_t maxLength
) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    std::string result;
    result.reserve(maxLength);

    // Read one byte at a time until null terminator or max length
    for (size_t i = 0; i < maxLength; ++i) {
        char ch = 0;
        SIZE_T bytesRead = 0;

        BOOL ok = ReadProcessMemory(
            hProcess,
            reinterpret_cast<LPCVOID>(address + i),
            &ch,
            sizeof(char),
            &bytesRead
        );

        if (!ok || bytesRead != sizeof(char) || ch == '\0') {
            break;
        }

        result += ch;
    }

    return result.empty() ? std::nullopt : std::make_optional(std::move(result));
}

std::optional<std::wstring> readWideString(
    HANDLE hProcess,
    uintptr_t address,
    size_t maxLength
) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    std::wstring result;
    result.reserve(maxLength);

    for (size_t i = 0; i < maxLength; ++i) {
        wchar_t ch = 0;
        SIZE_T bytesRead = 0;

        BOOL ok = ReadProcessMemory(
            hProcess,
            reinterpret_cast<LPCVOID>(address + i * sizeof(wchar_t)),
            &ch,
            sizeof(wchar_t),
            &bytesRead
        );

        if (!ok || bytesRead != sizeof(wchar_t) || ch == L'\0') {
            break;
        }

        result += ch;
    }

    return result.empty() ? std::nullopt : std::make_optional(std::move(result));
}

// ============================================================================
// Pointer validation
// ============================================================================

bool validatePointer(HANDLE hProcess, uintptr_t address) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE || address == 0) {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
        return false;
    }

    // Must be committed memory
    if (mbi.State != MEM_COMMIT) {
        return false;
    }

    // Must have read permission (not guard page, not no-access)
    constexpr DWORD readableMask = PAGE_READONLY | PAGE_READWRITE |
                                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                    PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;

    if (!(mbi.Protect & readableMask)) {
        return false;
    }

    // Guard pages are not reliably readable
    if (mbi.Protect & PAGE_GUARD) {
        return false;
    }

    return true;
}

std::optional<MemoryRegionInfo> queryMemoryRegion(HANDLE hProcess, uintptr_t address) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE || address == 0) {
        return std::nullopt;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
        return std::nullopt;
    }

    MemoryRegionInfo info{};
    info.baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    info.regionSize = mbi.RegionSize;
    info.state = mbi.State;
    info.protect = mbi.Protect;
    info.type = mbi.Type;

    // Determine permissions
    constexpr DWORD readMask = PAGE_READONLY | PAGE_READWRITE |
                                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
    constexpr DWORD writeMask = PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                                 PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
    constexpr DWORD execMask = PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                PAGE_EXECUTE_WRITECOPY;

    info.readable = (mbi.State == MEM_COMMIT) && (mbi.Protect & readMask) && !(mbi.Protect & PAGE_GUARD);
    info.writable = (mbi.State == MEM_COMMIT) && (mbi.Protect & writeMask);
    info.executable = (mbi.State == MEM_COMMIT) && (mbi.Protect & execMask);

    return info;
}

bool validateRange(HANDLE hProcess, uintptr_t address, size_t size) {
    if (size == 0) return true;

    // Check start and end of range
    if (!validatePointer(hProcess, address)) return false;
    if (!validatePointer(hProcess, address + size - 1)) return false;

    // Check that the entire range is within the same committed region
    // by verifying the region info covers the range
    auto startRegion = queryMemoryRegion(hProcess, address);
    if (!startRegion) return false;

    uintptr_t regionEnd = startRegion->baseAddress + startRegion->regionSize;
    return (address + size) <= regionEnd;
}

// ============================================================================
// Pointer chain following
// ============================================================================

std::optional<PointerChainResult> followPointerChain(
    HANDLE hProcess,
    uintptr_t base,
    const std::vector<uintptr_t>& offsets
) {
    PointerChainResult result{};
    result.baseAddress = base;

    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        result.error = "Invalid process handle";
        return result;
    }

    if (offsets.empty()) {
        // No offsets - just validate the base address
        if (!validatePointer(hProcess, base)) {
            result.error = "Base address not readable";
            return result;
        }
        result.success = true;
        result.finalAddress = base;
        result.resolvedAddresses.push_back(base);
        return result;
    }

    uintptr_t current = base;

    // Follow each offset except the last
    for (size_t i = 0; i < offsets.size(); ++i) {
        // Validate current pointer is readable
        if (!validatePointer(hProcess, current)) {
            result.error = std::format(
                "Chain broken at step {}: address 0x{:X} not readable",
                i, current
            );
            return result;
        }

        result.resolvedAddresses.push_back(current);

        // Read pointer at current address
        auto ptr = readPointer(hProcess, current);
        if (!ptr) {
            result.error = std::format(
                "Failed to read pointer at step {}: 0x{:X}",
                i, current
            );
            return result;
        }

        // Apply offset (last offset is a direct offset, not a pointer dereference)
        if (i == offsets.size() - 1) {
            current = *ptr + offsets[i];
        } else {
            current = *ptr + offsets[i];
        }
    }

    result.success = true;
    result.finalAddress = current;
    return result;
}

std::optional<uintptr_t> followChainAndReadPointer(
    HANDLE hProcess,
    uintptr_t base,
    const std::vector<uintptr_t>& offsets
) {
    auto result = followPointerChain(hProcess, base, offsets);
    if (!result || !result->success) return std::nullopt;
    return readPointer(hProcess, result->finalAddress);
}

// ============================================================================
// Batch operations
// ============================================================================

std::vector<MemoryReadResult> batchRead(
    HANDLE hProcess,
    const std::vector<std::pair<uintptr_t, size_t>>& reads
) {
    std::vector<MemoryReadResult> results;
    results.reserve(reads.size());

    for (const auto& [address, size] : reads) {
        MemoryReadResult mr{};
        mr.address = address;
        mr.size = size;

        auto data = safeReadMemory(hProcess, address, size);
        if (data) {
            mr.success = true;
            mr.data = std::move(*data);
        } else {
            mr.error = std::format("Failed to read {} bytes at 0x{:X}", size, address);
        }

        results.push_back(std::move(mr));
    }

    return results;
}

// ============================================================================
// JSON output
// ============================================================================

namespace json {

namespace {

// Escape string for JSON
std::string escape(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:   result += c; break;
        }
    }
    return result;
}

} // anonymous namespace

std::string hexAddress(uintptr_t address) {
    return std::format("0x{:X}", address);
}

std::string hexBytes(std::span<const uint8_t> data) {
    std::string result;
    result.reserve(data.size() * 3);
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0) result += ' ';
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02X", data[i]);
        result += buf;
    }
    return result;
}

std::string toJson(const MemoryReadResult& result) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"success\": " << (result.success ? "true" : "false") << ",\n";
    ss << "  \"address\": \"" << hexAddress(result.address) << "\",\n";
    ss << "  \"size\": " << result.size << ",\n";

    if (result.success && !result.data.empty()) {
        ss << "  \"data\": [";
        for (size_t i = 0; i < result.data.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << "0x" << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<int>(result.data[i]) << std::dec;
        }
        ss << "],\n";
        ss << "  \"hex\": \"" << hexBytes(result.data) << "\",\n";
    }

    if (!result.error.empty()) {
        ss << "  \"error\": \"" << escape(result.error) << "\",\n";
    }

    ss << "  \"type\": \"memory_read\"\n";
    ss << "}";
    return ss.str();
}

std::string toJson(const PointerChainResult& result) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"success\": " << (result.success ? "true" : "false") << ",\n";
    ss << "  \"base\": \"" << hexAddress(result.baseAddress) << "\",\n";
    ss << "  \"final\": \"" << hexAddress(result.finalAddress) << "\",\n";

    ss << "  \"chain\": [";
    for (size_t i = 0; i < result.resolvedAddresses.size(); ++i) {
        if (i > 0) ss << ", ";
        ss << "\"" << hexAddress(result.resolvedAddresses[i]) << "\"";
    }
    ss << "],\n";

    if (!result.value.empty()) {
        ss << "  \"value\": \"" << hexBytes(result.value) << "\",\n";
    }

    if (!result.error.empty()) {
        ss << "  \"error\": \"" << escape(result.error) << "\",\n";
    }

    ss << "  \"type\": \"pointer_chain\"\n";
    ss << "}";
    return ss.str();
}

std::string toJson(const MemoryRegionInfo& info) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"base\": \"" << hexAddress(info.baseAddress) << "\",\n";
    ss << "  \"size\": " << info.regionSize << ",\n";
    ss << "  \"state\": \"" << stateToString(info.state) << "\",\n";
    ss << "  \"protect\": \"" << protectToString(info.protect) << "\",\n";
    ss << "  \"type\": \"memory_region\",\n";
    ss << "  \"readable\": " << (info.readable ? "true" : "false") << ",\n";
    ss << "  \"writable\": " << (info.writable ? "true" : "false") << ",\n";
    ss << "  \"executable\": " << (info.executable ? "true" : "false") << "\n";
    ss << "}";
    return ss.str();
}

std::string memoryDump(
    uintptr_t address,
    std::span<const uint8_t> data,
    const std::string& label
) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"success\": true,\n";
    ss << "  \"address\": \"" << hexAddress(address) << "\",\n";
    ss << "  \"size\": " << data.size() << ",\n";

    if (!label.empty()) {
        ss << "  \"label\": \"" << escape(label) << "\",\n";
    }

    ss << "  \"data\": [";
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0) ss << ", ";
        ss << "0x" << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(data[i]) << std::dec;
    }
    ss << "],\n";

    ss << "  \"hex\": \"" << hexBytes(data) << "\",\n";
    ss << "  \"type\": \"memory_dump\"\n";
    ss << "}";
    return ss.str();
}

std::string error(const std::string& message, uintptr_t address) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"success\": false,\n";
    if (address != 0) {
        ss << "  \"address\": \"" << hexAddress(address) << "\",\n";
    }
    ss << "  \"error\": \"" << escape(message) << "\",\n";
    ss << "  \"type\": \"error\"\n";
    ss << "}";
    return ss.str();
}

std::string success(
    uintptr_t address,
    size_t size,
    const std::string& type
) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"success\": true,\n";
    ss << "  \"address\": \"" << hexAddress(address) << "\",\n";
    ss << "  \"size\": " << size << ",\n";
    ss << "  \"type\": \"" << escape(type) << "\"\n";
    ss << "}";
    return ss.str();
}

} // namespace json

// ============================================================================
// Utility
// ============================================================================

std::string protectToString(DWORD protect) {
    switch (protect & 0xFF) {
        case PAGE_NOACCESS:          return "NOACCESS";
        case PAGE_READONLY:          return "READONLY";
        case PAGE_READWRITE:         return "READWRITE";
        case PAGE_WRITECOPY:         return "WRITECOPY";
        case PAGE_EXECUTE:           return "EXECUTE";
        case PAGE_EXECUTE_READ:      return "EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
        case PAGE_EXECUTE_WRITECOPY: return "EXECUTE_WRITECOPY";
        default:                     return "UNKNOWN";
    }
}

std::string stateToString(DWORD state) {
    switch (state) {
        case MEM_COMMIT:  return "COMMIT";
        case MEM_RESERVE: return "RESERVE";
        case MEM_FREE:    return "FREE";
        default:          return "UNKNOWN";
    }
}

} // namespace stellaris::memory
