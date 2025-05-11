/** \file
 * Definitions for thread management.
 */
#ifndef HYDROGEN_THREAD_H
#define HYDROGEN_THREAD_H

#include "hydrogen/signal.h"
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
 * \param[in] process The process to create the thread in. Can be #HYDROGEN_THIS_PROCESS. Requires the same rights as
 *                    #HYDROGEN_THIS_PROCESS. If this is not the current process, and the process already has a thread,
 *                    thread creation will fail with #EPERM.
 * \param[in] vmm The VMM of the thread. Can be #HYDROGEN_THIS_VMM. Requires the same rights as #HYDROGEN_THIS_VMM.
 *                If #HYDROGEN_CLONED_VMM, the VMM of the new thread is a cloned version of the VMM of the current
 *                thread.
 * \param[in] namespace The namespace of the thread. Can be #HYDROGEN_THIS_NAMESPACE. Requires the same rights as
 *                      #HYDROGEN_THIS_NAMESPACE.
 * \param[in] pc The address to start executing at.
 * \param[in] sp The stack pointer of the new thread.
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the newly created thread (in `integer`).
 */
hydrogen_ret_t hydrogen_thread_create(
        int process,
        int vmm,
        int namespace,
        uintptr_t pc,
        uintptr_t sp,
        uint32_t flags
) __asm__("__hydrogen_thread_create");

/**
 * Create a new thread by cloning the current one.
 *
 * \param[in] process See #hydrogen_thread_create.
 * \param[in] vmm See #hydrogen_thread_create.
 * \param[in] namespace See #hydrogen_thread_create.
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the created thread (in `integer`). In the created thread, this function will return
 *         #HYDROGEN_INVALID_HANDLE.
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

/**
 * Put the current thread to sleep.
 *
 * \param[in] deadline The boot time value at which to stop sleeping. If zero, sleep indefinitely.
 * \return 0, if the deadline was reached; if not, an error code.
 */
int hydrogen_thread_sleep(uint64_t deadline) __asm__("__hydrogen_thread_sleep");

/** See the POSIX manual on pthread_sigmask. */
int hydrogen_thread_sigmask(int how, const __sigset_t *set, __sigset_t *oset) __asm__("__hydrogen_thread_sigmask");

/** See the POSIX manual on sigaltstack. */
int hydrogen_thread_sigaltstack(const __stack_t *ss, __stack_t *oss) __asm__("__hydrogen_thread_sigaltstack");

/** See the POSIX manual on sigpending. */
__sigset_t hydrogen_thread_sigpending(void) __asm__("__hydrogen_thread_sigpending");

/** See the POSIX manual on sigsuspend. */
int hydrogen_thread_sigsuspend(__sigset_t mask) __asm__("__hydrogen_thread_sigsuspend");

/** Like #hydrogen_process_send_signal, but for threads. */
int hydrogen_thread_send_signal(int thread, int signal) __asm__("__hydrogen_thread_send_signal");

/**
 * Get the ID of a thread.
 *
 * \param[in] thread The handle to the thread. Can be #HYDROGEN_THIS_THREAD.
 * \return The ID of the thread (in `integer`).
 */
hydrogen_ret_t hydrogen_thread_get_id(int thread) __asm__("__hydrogen_thread_get_id");

/**
 * Find a thread by its ID.
 *
 * \param[in] process The process the thread belongs to. Can be #HYDROGEN_THIS_PROCESS.
 *                    If #HYDROGEN_INVALID_HANDLE, all processes are searched.
 * \param[in] thread_id The ID of the thread.
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the thread (in `integer`).
 */
hydrogen_ret_t hydrogen_thread_find(int process, int thread_id, uint32_t flags) __asm__("__hydrogen_thread_find");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_THREAD_H */
