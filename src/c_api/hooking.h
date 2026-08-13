#pragma once
#ifndef C_API_HOOKING_H
#define C_API_HOOKING_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Install a hook on a target function.
 * 
 * @param target  Address of the function to hook
 * @param detour  Address of the detour function
 * @param original Pointer to receive the trampoline (can be NULL)
 * @return MH_OK on success, negative error code on failure
 */
int hook_install(void* target, void* detour, void** original);

/**
 * Remove a previously installed hook.
 * 
 * @param hook Address of the hook (target function)
 * @return MH_OK on success, negative error code on failure
 */
int hook_remove(void* hook);

/**
 * Enable all installed hooks.
 * 
 * @return MH_OK on success, negative error code on failure
 */
int hook_enable_all(void);

/**
 * Disable all installed hooks.
 * 
 * @return MH_OK on success, negative error code on failure
 */
int hook_disable_all(void);

#ifdef __cplusplus
}
#endif

#endif /* C_API_HOOKING_H */
