#include "windows.h"

#ifdef __cplusplus
extern "C" {
#endif

BOOL windows_virtual_protect(LPVOID addr, SIZE_T size, DWORD new_protect, PDWORD old_protect) {
    if (!addr || size == 0) {
        return FALSE;
    }
    return ::VirtualProtect(addr, size, new_protect, old_protect);
}

LPVOID windows_virtual_alloc(SIZE_T size) {
    if (size == 0) {
        return NULL;
    }
    return ::VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

BOOL windows_virtual_free(LPVOID addr) {
    if (!addr) {
        return FALSE;
    }
    return ::VirtualFree(addr, 0, MEM_RELEASE);
}

LPVOID windows_alloc_executable(SIZE_T size) {
    if (size == 0) {
        return NULL;
    }
    return ::VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

#ifdef __cplusplus
}
#endif
