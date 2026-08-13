/**
 * inject.h — DLL injection and CApplication discovery for Stellaris
 */

#pragma once

#include <cstdint>
#include <windows.h>

// ---------------------------------------------------------------------------
// Process discovery
// ---------------------------------------------------------------------------

/**
 * Find a running process by executable name.
 * Returns the PID, or 0 if not found.
 */
DWORD findProcessByName(const char* processName);

// ---------------------------------------------------------------------------
// Memory search
// ---------------------------------------------------------------------------

/**
 * Scan a remote process's committed memory regions for a byte pattern.
 * Returns the virtual address of the first match, or 0 on failure.
 */
uintptr_t searchMemory(HANDLE hProcess, const uint8_t* pattern,
                        size_t patternLen);

/**
 * Locate the "augustus" string in the target process memory.
 * Returns the virtual address, or 0 if not found.
 */
uintptr_t findAugustusString(HANDLE hProcess);

// ---------------------------------------------------------------------------
// DLL injection
// ---------------------------------------------------------------------------

/**
 * Inject a DLL into a remote process via CreateRemoteThread(LoadLibraryA).
 * Returns true on success.
 */
bool injectDll(HANDLE hProcess, const char* dllPath);

// ---------------------------------------------------------------------------
// PushCApplicationPtr
// ---------------------------------------------------------------------------

/**
 * Call the PushCApplicationPtr export in the remote process.
 * applicationPtr: address of CApplication in the target process
 * baseAddress: base address of the injected DLL module
 */
bool callPushCApplicationPtr(HANDLE hProcess, HMODULE hRemoteDll,
                             uintptr_t applicationPtr,
                             uintptr_t baseAddress);

// ---------------------------------------------------------------------------
// Remote module lookup
// ---------------------------------------------------------------------------

/**
 * Find a loaded module by name in a remote process using Toolhelp32.
 * Returns the module handle, or nullptr if not found.
 */
HMODULE getRemoteModuleHandle(HANDLE hProcess, const char* moduleName);

// ---------------------------------------------------------------------------
// High-level injection sequence
// ---------------------------------------------------------------------------

/**
 * Complete injection pipeline:
 *   1. Find stellaris.exe
 *   2. Open process
 *   3. Locate "augustus" string (CApplication anchor)
 *   4. Inject DLL
 *   5. Call PushCApplicationPtr
 *
 * Returns the CApplication address on success, 0 on failure.
 */
uintptr_t performInjection(const char* dllPath);
