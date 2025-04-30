#ifndef HYDROGEN_THREAD_H
#define HYDROGEN_THREAD_H

#include "hydrogen/types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a new thread.
 *
 * \param[in] namespace The namespace used for resolving handles in the thread. If `NULL`, use the current namespace.
 *                      Requires #HYDROGEN_NAMESPACE_RIGHT_CREATE, #HYDROGEN_NAMESPACE_RIGHT_CLOSE,
 *                      #HYDROGEN_NAMESPACE_RIGHT_CLONE, and #HYDROGEN_NAMESPACE_RIGHT_RESOLVE.
 * \param[in] vm The address space the thread will run in. If `NULL`, use the current address space.
 *               Requires #HYDROGEN_VM_RIGHT_MAP, #HYDROGEN_VM_RIGHT_REMAP, #HYDROGEN_VM_RIGHT_UNMAP,
 *               #HYDROGEN_VM_RIGHT_CLONE, #HYDROGEN_VM_RIGHT_WRITE, and #HYDROGEN_VM_RIGHT_READ.
 * \param[in] pc The value of the program counter.
 * \param[in] sp The value of the stack pointer.
 * \return The created thread.
 */
hydrogen_ret_t hydrogen_thread_create(hydrogen_handle_t namespace, hydrogen_handle_t vm, void *pc, void *sp) __asm__(
        "__hydrogen_thread_create"
);

/**
 * Reinitialize the current thread.
 *
 * \param[in] namespace The namespace used for resolving handles in the thread. If `NULL`, use the current namespace.
 *                      Requires #HYDROGEN_NAMESPACE_RIGHT_CREATE, #HYDROGEN_NAMESPACE_RIGHT_CLOSE,
 *                      #HYDROGEN_NAMESPACE_RIGHT_CLONE, and #HYDROGEN_NAMESPACE_RIGHT_RESOLVE.
 * \param[in] vm The address space the thread will run in. If `NULL`, use the current address space.
 *               Requires #HYDROGEN_VM_RIGHT_MAP, #HYDROGEN_VM_RIGHT_REMAP, #HYDROGEN_VM_RIGHT_UNMAP,
 *               #HYDROGEN_VM_RIGHT_CLONE, #HYDROGEN_VM_RIGHT_WRITE, and #HYDROGEN_VM_RIGHT_READ.
 * \param[in] pc The value of the program counter.
 * \param[in] sp The value of the stack pointer.
 * \return This function will not return if successful.
 */
int hydrogen_thread_reinit(hydrogen_handle_t namespace, hydrogen_handle_t vm, void *pc, void *sp) __asm__(
        "__hydrogen_thread_reinit"
);

/**
 * Yield to another thread.
 */
void hydrogen_thread_yield(void) __asm__("__hydrogen_thread_yield");

/**
 * Exit the current thread.
 */
__attribute__((__noreturn__)) void hydrogen_thread_exit(void) __asm__("__hydrogen_thread_exit");

#ifdef __x86_64__
/**
 * Get the current base address of the `fs` segment.
 *
 * \return The base address of the `fs` segment.
 */
uintptr_t hydrogen_x86_64_get_fs_base(void) __asm__("__hydrogen_x86_64_get_fs_base");

/**
 * Get the current base address of the `gs` segment.
 *
 * \return The base address of the `gs` segment.
 */
uintptr_t hydrogen_x86_64_get_gs_base(void) __asm__("__hydrogen_x86_64_get_gs_base");

/**
 * Set the base address of the `fs` segment.
 *
 * \param[in] address The new base address of the segment.
 */
int hydrogen_x86_64_set_fs_base(uintptr_t address) __asm__("__hydrogen_x86_64_set_fs_base");

/**
 * Set the base address of the `gs` segment.
 *
 * \param[in] address The new base address of the segment.
 */
int hydrogen_x86_64_set_gs_base(uintptr_t address) __asm__("__hydrogen_x86_64_set_gs_base");
#endif /* defined(__x86_64__) */

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_THREAD_H */
