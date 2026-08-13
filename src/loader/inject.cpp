/**
 * inject.cpp — DLL injection and CApplication discovery for Stellaris
 *
 * Pattern follows stellarstellaris-win:
 *   1. FindPidByName("stellaris.exe")
 *   2. OpenProcess(PROCESS_ALL_ACCESS)
 *   3. searchMemory("augustus") → locate CApplication pointer
 *   4. InjectPayload: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryA)
 *   5. CreateRemoteThread(PushCApplicationPtr) to pass engine pointer
 */

#include "inject.h"

#include <cstdio>
#include <cstring>
#include <tlhelp32.h>
#include <windows.h>

// ---------------------------------------------------------------------------
// Process discovery
// ---------------------------------------------------------------------------

DWORD findProcessByName(const char* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[loader] CreateToolhelp32Snapshot failed: %lu\n",
                GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return pid;
}

// ---------------------------------------------------------------------------
// Memory search — scan remote process for "augustus" signature
// ---------------------------------------------------------------------------

/**
 * searchMemory — walk a process's committed regions looking for a byte pattern.
 *
 * Returns the virtual address of the first match, or 0 on failure.
 * The caller passes the pattern and its length; we search page-by-page
 * to avoid reading uncommitted memory (which would fault).
 */
uintptr_t searchMemory(HANDLE hProcess, const uint8_t* pattern,
                        size_t patternLen) {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    MEMORY_BASIC_INFORMATION mbi{};
    uint8_t buf[4096];

    for (uintptr_t addr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
         addr < reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);) {

        if (!VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(addr), &mbi,
                            sizeof(mbi))) {
            break;
        }

        // Only scan committed, readable pages
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                                                        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            SIZE_T bytesRead = 0;
            size_t regionSize = mbi.RegionSize;

            // Cap to buffer size
            if (regionSize > sizeof(buf)) {
                regionSize = sizeof(buf);
            }

            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(addr),
                                  buf, regionSize, &bytesRead) &&
                bytesRead >= patternLen) {

                // Simple sliding-window search within the buffer
                for (size_t i = 0; i <= bytesRead - patternLen; ++i) {
                    if (memcmp(buf + i, pattern, patternLen) == 0) {
                        return addr + i;
                    }
                }
            }
        }

        addr += mbi.RegionSize;
    }

    return 0;
}

/**
 * findAugustusString — locate the "augustus" string in the target process.
 *
 * In Clausewitz, the string literal "augustus" is embedded near CApplication
 * initialization code. Its address is stable relative to the CApplication
 * vtable across ASLR relocations because both live in the same module.
 */
uintptr_t findAugustusString(HANDLE hProcess) {
    static const uint8_t pattern[] = "augustus";
    return searchMemory(hProcess, pattern, sizeof(pattern) - 1);
}

// ---------------------------------------------------------------------------
// DLL injection
// ---------------------------------------------------------------------------

/**
 * injectDll — classic CreateRemoteThread + LoadLibraryA injection.
 *
 * 1. VirtualAllocEx: allocate a buffer in the target for the DLL path string
 * 2. WriteProcessMemory: write the path
 * 3. CreateRemoteThread(LoadLibraryA, path): the remote thread calls
 *    LoadLibraryA(path) which loads our DLL into the target process
 *
 * Returns true on success.
 */
bool injectDll(HANDLE hProcess, const char* dllPath) {
    size_t pathLen = strlen(dllPath) + 1;

    // Allocate memory in target process for the DLL path
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, pathLen,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_READWRITE);
    if (!remoteMem) {
        fprintf(stderr, "[loader] VirtualAllocEx failed: %lu\n",
                GetLastError());
        return false;
    }

    // Write the DLL path into the remote allocation
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathLen, nullptr)) {
        fprintf(stderr, "[loader] WriteProcessMemory failed: %lu\n",
                GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Resolve LoadLibraryA address (it's in kernel32.dll which is loaded at
    // the same base address in every process on the system)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        fprintf(stderr, "[loader] GetModuleHandle(kernel32) failed\n");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    auto pLoadLibraryA = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(hKernel32, "LoadLibraryA"));
    if (!pLoadLibraryA) {
        fprintf(stderr, "[loader] GetProcAddress(LoadLibraryA) failed\n");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Create remote thread that calls LoadLibraryA(dllPath)
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibraryA,
                                        remoteMem, 0, nullptr);
    if (!hThread) {
        fprintf(stderr, "[loader] CreateRemoteThread(LoadLibraryA) failed: %lu\n",
                GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Wait for LoadLibraryA to complete
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);

    // Clean up the path buffer (DLL is loaded now, path no longer needed)
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);

    return true;
}

// ---------------------------------------------------------------------------
// PushCApplicationPtr — pass engine pointer to injected DLL
// ---------------------------------------------------------------------------

/**
 * callPushCApplicationPtr — call the exported PushCApplicationPtr function
 * in the remote process.
 *
 * PushCApplicationPtr is exported by the DLL (implemented in the Zig DLL
 * component). It receives the CApplication pointer and the module base
 * address, which the DLL needs to resolve version-specific offsets.
 *
 * Signature (C ABI):
 *   extern "C" __declspec(dllexport)
 *   void PushCApplicationPtr(void* applicationPtr, uintptr_t baseAddress);
 *
 * Since CreateRemoteThread only passes one void* argument, we write both
 * values to a remote struct and pass a pointer to it. The DLL unpacks them.
 */
bool callPushCApplicationPtr(HANDLE hProcess, HMODULE hRemoteDll,
                             uintptr_t applicationPtr,
                             uintptr_t baseAddress) {
    // GetProcAddress works with remote HMODULE because kernel32 is mapped
    // at the same address in every process on the system.
    auto pExport = reinterpret_cast<void*>(
        GetProcAddress(hRemoteDll, "PushCApplicationPtr"));
    if (!pExport) {
        fprintf(stderr, "[loader] GetProcAddress(PushCApplicationPtr) failed\n");
        return false;
    }

    uintptr_t exportOffset =
        reinterpret_cast<uintptr_t>(pExport) -
        reinterpret_cast<uintptr_t>(hRemoteDll);

    auto pRemoteFunc = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        reinterpret_cast<uintptr_t>(hRemoteDll) + exportOffset);

    // CreateRemoteThread passes one void*, so pack both values into a struct
    struct PushArgs {
        void* appPtr;
        uintptr_t base;
    } args{reinterpret_cast<void*>(applicationPtr), baseAddress};

    LPVOID remoteArgs = VirtualAllocEx(hProcess, nullptr, sizeof(args),
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (!remoteArgs) {
        fprintf(stderr, "[loader] VirtualAllocEx(args) failed: %lu\n",
                GetLastError());
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteArgs, &args, sizeof(args), nullptr)) {
        fprintf(stderr, "[loader] WriteProcessMemory(args) failed: %lu\n",
                GetLastError());
        VirtualFreeEx(hProcess, remoteArgs, 0, MEM_RELEASE);
        return false;
    }

    // DLL receives struct pointer as its single arg, unpacks fields
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, pRemoteFunc,
                                        remoteArgs, 0, nullptr);
    if (!hThread) {
        fprintf(stderr, "[loader] CreateRemoteThread(PushCApplicationPtr) failed: %lu\n",
                GetLastError());
        VirtualFreeEx(hProcess, remoteArgs, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteArgs, 0, MEM_RELEASE);

    return true;
}

// ---------------------------------------------------------------------------
// Remote module lookup
// ---------------------------------------------------------------------------

/**
 * getRemoteModuleHandle — find a loaded module by name in a remote process.
 *
 * Uses CreateToolhelp32Snapshot with TH32CS_SNAPMODULE to enumerate the
 * target's loaded modules.
 */
HMODULE getRemoteModuleHandle(HANDLE hProcess, const char* moduleName) {
    DWORD pid = GetProcessId(hProcess);
    if (pid == 0) return nullptr;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return nullptr;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);

    HMODULE result = nullptr;
    if (Module32First(hSnap, &me)) {
        do {
            if (_stricmp(me.szModule, moduleName) == 0) {
                result = me.hModule;
                break;
            }
        } while (Module32Next(hSnap, &me));
    }

    CloseHandle(hSnap);
    return result;
}

// ---------------------------------------------------------------------------
// High-level injection sequence
// ---------------------------------------------------------------------------

/**
 * performInjection — the complete injection pipeline.
 *
 * Returns the CApplication pointer (remote address) on success, 0 on failure.
 */
uintptr_t performInjection(const char* dllPath) {
    printf("[loader] Searching for stellaris.exe process...\n");

    DWORD pid = findProcessByName("stellaris.exe");
    if (pid == 0) {
        fprintf(stderr, "[loader] ERROR: stellaris.exe not found. Is the game running?\n");
        return 0;
    }
    printf("[loader] Found stellaris.exe (PID %lu)\n", pid);

    // Open with full access for memory operations
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        fprintf(stderr, "[loader] ERROR: OpenProcess failed (error %lu). "
                        "Try running as administrator.\n", GetLastError());
        return 0;
    }

    // Locate the "augustus" string to find CApplication
    printf("[loader] Scanning memory for 'augustus' signature...\n");
    uintptr_t augustusAddr = findAugustusString(hProcess);
    if (augustusAddr == 0) {
        fprintf(stderr, "[loader] ERROR: 'augustus' string not found in process memory.\n");
        CloseHandle(hProcess);
        return 0;
    }
    printf("[loader] Found 'augustus' at 0x%llX\n",
           static_cast<unsigned long long>(augustusAddr));

    // In the stellarstellaris-win pattern, the CApplication pointer is
    // located by a known offset from the "augustus" string. The typical
    // offset is 56 bytes before the string. However, this varies by version.
    // For now, we use the augustus address itself as the discovery anchor;
    // the DLL's internal logic resolves the actual CApplication vtable.
    uintptr_t applicationPtr = augustusAddr;

    // Inject the DLL
    printf("[loader] Injecting DLL: %s\n", dllPath);
    if (!injectDll(hProcess, dllPath)) {
        fprintf(stderr, "[loader] ERROR: DLL injection failed.\n");
        CloseHandle(hProcess);
        return 0;
    }
    printf("[loader] DLL injected successfully.\n");

    // Give the DLL time to initialize (DllMain runs synchronously)
    Sleep(500);

    // Get the injected DLL's base in the remote process
    HMODULE hRemoteDll = getRemoteModuleHandle(hProcess, "stellaris_quickjs.dll");
    if (!hRemoteDll) {
        // Try with just the filename from the path
        const char* slash = strrchr(dllPath, '\\');
        const char* basename = slash ? slash + 1 : dllPath;
        hRemoteDll = getRemoteModuleHandle(hProcess, basename);
    }

    if (!hRemoteDll) {
        fprintf(stderr, "[loader] WARNING: Could not locate injected DLL module. "
                        "PushCApplicationPtr will not be called.\n");
        CloseHandle(hProcess);
        return applicationPtr;
    }

    printf("[loader] Calling PushCApplicationPtr(appPtr=0x%llX, base=0x%llX)\n",
           static_cast<unsigned long long>(applicationPtr),
           static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(hRemoteDll)));

    if (!callPushCApplicationPtr(hProcess, hRemoteDll, applicationPtr,
                                 reinterpret_cast<uintptr_t>(hRemoteDll))) {
        fprintf(stderr, "[loader] ERROR: PushCApplicationPtr call failed.\n");
        CloseHandle(hProcess);
        return 0;
    }

    printf("[loader] PushCApplicationPtr called successfully.\n");
    printf("[loader] Injection complete. DLL is running in stellaris.exe (PID %lu)\n", pid);

    CloseHandle(hProcess);
    return applicationPtr;
}
