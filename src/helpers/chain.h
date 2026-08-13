#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace helpers {

struct ChainStep {
    uintptr_t address;
    uintptr_t value;
    bool valid;
    std::string error;
};

struct ChainResult {
    bool success;
    uintptr_t base;
    std::vector<ChainStep> steps;
    uintptr_t finalAddress;
    std::string error;

    nlohmann::json toJson() const {
        nlohmann::json j;
        j["success"] = success;
        j["base"] = formatAddress(base);

        nlohmann::json stepsJson = nlohmann::json::array();
        for (const auto& step : steps) {
            nlohmann::json stepJson;
            stepJson["address"] = formatAddress(step.address);
            stepJson["value"] = formatAddress(step.value);
            stepJson["valid"] = step.valid;
            if (!step.error.empty()) {
                stepJson["error"] = step.error;
            }
            stepsJson.push_back(stepJson);
        }
        j["steps"] = stepsJson;
        j["finalAddress"] = formatAddress(finalAddress);

        if (!error.empty()) {
            j["error"] = error;
        }

        return j;
    }

    static std::string formatAddress(uintptr_t addr) {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)addr);
        return std::string(buf);
    }
};

ChainResult followChain(HANDLE hProcess, uintptr_t base, const std::vector<uintptr_t>& offsets);

bool validateAndDereference(HANDLE hProcess, uintptr_t address, uintptr_t& outValue);

nlohmann::json followChainJson(HANDLE hProcess, uintptr_t base, const std::vector<uintptr_t>& offsets);

} // namespace helpers
