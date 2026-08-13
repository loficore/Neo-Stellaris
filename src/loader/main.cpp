/**
 * main.cpp — Stellaris QuickJS DLL injection loader
 *
 * Usage:
 *   stellaris-loader.exe [path/to/stellaris_quickjs.dll]
 *
 * If no DLL path is provided, the loader looks for "stellaris_quickjs.dll"
 * in the same directory as the loader executable.
 *
 * Flow:
 *   1. Find stellaris.exe process
 *   2. Locate CApplication via "augustus" string scan
 *   3. Inject QuickJS DLL into the process
 *   4. Call PushCApplicationPtr to pass the engine pointer
 */

#include "inject.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <windows.h>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build the full path to the DLL. If the user provides a path, use it
 * as-is. Otherwise, look next to the loader executable.
 */
static std::string resolveDllPath(const char* userPath) {
    if (userPath && userPath[0] != '\0') {
        return std::string(userPath);
    }

    // Default: same directory as this executable
    char exePath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    std::filesystem::path p(exePath);
    p = p.parent_path() / "stellaris_quickjs.dll";
    return p.string();
}

/**
 * Print the banner.
 */
static void printBanner() {
    printf("========================================\n");
    printf("  Stellaris QuickJS Loader\n");
    printf("  DLL injection for Clausewitz engine\n");
    printf("========================================\n\n");
}

/**
 * Print usage information.
 */
static void printUsage(const char* exeName) {
    printf("Usage: %s [path/to/stellaris_quickjs.dll]\n\n", exeName);
    printf("Options:\n");
    printf("  (no args)          Use stellaris_quickjs.dll in same directory\n");
    printf("  <path>             Inject the specified DLL\n");
    printf("\n");
    printf("The target process (stellaris.exe) must be running before\n");
    printf("launching this loader. The loader requires administrator\n");
    printf("privileges to open the game process.\n");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    printBanner();

    // Parse arguments
    const char* userDllPath = nullptr;
    if (argc > 1) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printUsage(argv[0]);
            return 0;
        }
        userDllPath = argv[1];
    }

    // Resolve DLL path
    std::string dllPath = resolveDllPath(userDllPath);
    printf("[loader] DLL path: %s\n", dllPath.c_str());

    // Verify DLL exists
    if (!std::filesystem::exists(dllPath)) {
        fprintf(stderr, "[loader] ERROR: DLL not found: %s\n", dllPath.c_str());
        fprintf(stderr, "[loader] Build the DLL first with: zig build\n");
        return 1;
    }

    // Run the injection pipeline
    uintptr_t appPtr = performInjection(dllPath.c_str());
    if (appPtr == 0) {
        fprintf(stderr, "\n[loader] Injection failed. Check the error messages above.\n");
        fprintf(stderr, "[loader] Common issues:\n");
        fprintf(stderr, "[loader]   - Stellaris is not running\n");
        fprintf(stderr, "[loader]   - Not running as administrator\n");
        fprintf(stderr, "[loader]   - Antivirus blocking injection\n");
        fprintf(stderr, "[loader]   - Wrong DLL path\n");
        return 1;
    }

    printf("\n[loader] SUCCESS — CApplication found at 0x%llX\n",
           static_cast<unsigned long long>(appPtr));
    printf("[loader] The QuickJS runtime is now active in Stellaris.\n");
    printf("[loader] You can close this window — the DLL stays loaded.\n");

    return 0;
}
