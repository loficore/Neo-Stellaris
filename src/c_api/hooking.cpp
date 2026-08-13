#include "hooking.h"

// MinHook library
// https://github.com/TsudaKageworst/minhook
#include <MinHook.h>

#ifdef __cplusplus
extern "C" {
#endif

int hook_install(void* target, void* detour, void** original) {
    if (!target || !detour) {
        return -1; // MH_ERROR_INVALID_PARAMETER equivalent
    }
    return MH_CreateHook(target, detour, reinterpret_cast<LPVOID*>(original));
}

int hook_remove(void* hook) {
    if (!hook) {
        return -1;
    }
    return MH_RemoveHook(hook);
}

int hook_enable_all(void) {
    return MH_EnableHook(MH_ALL_HOOKS);
}

int hook_disable_all(void) {
    return MH_DisableHook(MH_ALL_HOOKS);
}

#ifdef __cplusplus
}
#endif
