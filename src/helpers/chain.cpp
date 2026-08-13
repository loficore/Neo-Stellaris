#include "chain.h"
#include <psapi.h>
#include <sstream>

namespace helpers {

bool validateAndDereference(HANDLE hProcess, uintptr_t address, uintptr_t& outValue) {
    if (address == 0) {
        return false;
    }

    if (address >= 0x7FFFFFFF0000ULL) {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
        return false;
    }

    if (mbi.State != MEM_COMMIT) {
        return false;
    }

    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))) {
        if (mbi.Protect & PAGE_GUARD) {
            return false;
        }
        return false;
    }

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)address, &outValue, sizeof(outValue), &bytesRead)) {
        return false;
    }

    return bytesRead == sizeof(outValue);
}

ChainResult followChain(HANDLE hProcess, uintptr_t base, const std::vector<uintptr_t>& offsets) {
    ChainResult result;
    result.success = false;
    result.base = base;
    result.finalAddress = 0;

    if (offsets.empty()) {
        result.error = "Empty offset chain";
        return result;
    }

    uintptr_t current = base;

    for (size_t i = 0; i < offsets.size(); i++) {
        ChainStep step;
        step.address = current;
        step.value = 0;
        step.valid = false;

        uintptr_t dereferenced = 0;
        if (!validateAndDereference(hProcess, current, dereferenced)) {
            char errBuf[128];
            snprintf(errBuf, sizeof(errBuf), "Failed to dereference address 0x%llX at step %zu",
                     (unsigned long long)current, i);
            step.error = errBuf;
            result.steps.push_back(step);
            result.error = step.error;
            return result;
        }

        step.value = dereferenced;
        step.valid = true;
        result.steps.push_back(step);

        current = dereferenced + offsets[i];
    }

    result.success = true;
    result.finalAddress = current;
    return result;
}

nlohmann::json followChainJson(HANDLE hProcess, uintptr_t base, const std::vector<uintptr_t>& offsets) {
    ChainResult result = followChain(hProcess, base, offsets);
    return result.toJson();
}

} // namespace helpers
