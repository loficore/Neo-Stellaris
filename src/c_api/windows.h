#pragma once
#ifndef C_API_WINDOWS_H
#define C_API_WINDOWS_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Change memory protection for a region.
 * 
 * @param addr         Address to change protection for
 * @param size         Size of the region in bytes
 * @param new_protect  New protection flags (e.g., PAGE_EXECUTE_READWRITE)
 * @param old_protect  Pointer to receive previous protection (can be NULL)
 * @return Non-zero on success, zero on failure
 */
BOOL windows_virtual_protect(LPVOID addr, SIZE_T size, DWORD new_protect, PDWORD old_protect);

/**
 * Allocate memory in the process address space.
 * 
 * @param size Size of memory to allocate in bytes
 * @return Address of allocated memory, or NULL on failure
 */
LPVOID windows_virtual_alloc(SIZE_T size);

/**
 * Free previously allocated memory.
 * 
 * @param addr Address of memory to free
 * @return Non-zero on success, zero on failure
 */
BOOL windows_virtual_free(LPVOID addr);

/**
 * Allocate executable memory (PAGE_EXECUTE_READWRITE).
 * 
 * @param size Size of memory to allocate in bytes
 * @return Address of allocated memory, or NULL on failure
 */
LPVOID windows_alloc_executable(SIZE_T size);

#ifdef __cplusplus
}
#endif

#endif /* C_API_WINDOWS_H */
