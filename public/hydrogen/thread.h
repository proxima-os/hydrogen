#ifndef HYDROGEN_THREAD_H
#define HYDROGEN_THREAD_H

#include "hydrogen/types.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Pseudo-handle that refers to the current thread.
 * Only valid as select function parameters, and may have a different meaning in others.
 */
#define HYDROGEN_THIS_THREAD (-2)

#define HYDROGEN_CLONED_VMM (-3) /**< See #hydrogen_thread_create. */

/**
 * Create a new thread.
 *
 * \param[in] process The process to create the thread in. Can be #HYDROGEN_THIS_PROCESS.
 *                    Requires #HYDROGEN_PROCESS_GET_IDENTITY, #HYDROGEN_PROCESS_SET_IDENTITY,
 *                    #HYDROGEN_PROCESS_CHANGE_GROUP, and #HYDROGEN_PROCESS_CHANGE_SESSION.
 * \param[in] vmm The VMM of the thread. Can be #HYDROGEN_THIS_VMM. Requires #HYDROGEN_VMM_CLONE, #HYDROGEN_VMM_MAP,
 *                #HYDROGEN_VMM_REMAP, #HYDROGEN_VMM_UNMAP, #HYDROGEN_VMM_READ, and #HYDROGEN_VMM_WRITE.
 *                If #HYDROGEN_CLONED_VMM, the VMM of the new thread is a cloned version of the VMM of the current
 *                thread.
 * \param[in] namespace The namespace of the thread. Can be #HYDROGEN_THIS_NAMESPACE. Requires
 *                      #HYDROGEN_NAMESPACE_CLONE, #HYDROGEN_NAMESPACE_ADD, #HYDROGEN_NAMESPACE_REMOVE, and
 *                      #HYDROGEN_NAMESPACE_RESOLVE.
 * \param[in] pc The address to start executing at.
 * \param[in] sp The stack pointer of the new thread.
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the newly created thread, if successful; if not, a negative error code.
 */
int hydrogen_thread_create(int process, int vmm, int namespace, uintptr_t pc, uintptr_t sp, uint32_t flags) __asm__(
        "__hydrogen_thread_create"
);

/**
 * Create a new thread by cloning the current one.
 *
 * \param[in] process See #hydrogen_thread_create.
 * \param[in] vmm See #hydrogen_thread_create.
 * \param[in] namespace See #hydrogen_thread_create.
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the created thread (in `integer`), if successful; if not, an error code (in `error`).
 *         In the created thread, this function will return #HYDROGEN_INVALID_HANDLE.
 */
hydrogen_ret_t hydrogen_thread_clone(int process, int vmm, int namespace, uint32_t flags) __asm__(
        "__hydrogen_thread_clone"
);

/**
 * Reinitialize the current thread.
 *
 * \param[in] vmm See #hydrogen_thread_create.
 * \param[in] namespace See #hydrogen_thread_create.
 * \param[in] pc See #hydrogen_thread_create.
 * \param[in] sp See #hydrogen_thread_create.
 * \return This function does not return, if successful; if not, an error code.
 */
int hydrogen_thread_reinit(int vmm, int namespace, uintptr_t pc, uintptr_t sp) __asm__("__hydrogen_thread_reinit");

/**
 * Yield to another thread.
 */
void hydrogen_thread_yield(void) __asm__("__hydrogen_thread_yield");

/**
 * Exit the current thread.
 *
 * \param[in] status If this is the last thread in the process, this will be the process's exit status.
 */
__attribute__((__noreturn__)) void hydrogen_thread_exit(int status) __asm__("__hydrogen_thread_exit");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_THREAD_H */
