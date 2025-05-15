/** \file
 * Definitions for process management.
 */
#ifndef HYDROGEN_PROCESS_H
#define HYDROGEN_PROCESS_H

#include "hydrogen/signal.h"
#include "hydrogen/types.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HYDROGEN_PROCESS_GET_IDENTITY (1u << 0)   /**< Allow the identity of this process to be read. */
#define HYDROGEN_PROCESS_SET_IDENTITY (1u << 1)   /**< Allow the identity of this process to be written. */
#define HYDROGEN_PROCESS_CHANGE_GROUP (1u << 2)   /**< Allow the process group of this process to be changed. */
#define HYDROGEN_PROCESS_CHANGE_SESSION (1u << 3) /**< Allow the session of this process to be changed */
#define HYDROGEN_PROCESS_CREATE_THREAD (1u << 4)  /**< Allow threads to be created in this process. */
#define HYDROGEN_PROCESS_CHANGE_SIGHAND (1u << 5) /**< Alter the signal handling of the process. */
#define HYDROGEN_PROCESS_WAIT_SIGNAL (1u << 6)    /**< Allow the usage of #hydrogen_process_sigwait. */
#define HYDROGEN_PROCESS_WAIT_STATUS (1u << 8)    /**< Allow the usage of #hydrogen_process_wait and friends. */

/**
 * Pseudo-handle that refers to the current process.
 * Only valid as select function parameters, and may have a different meaning in others.
 *
 * This handle has the following rights (note that this list may expand in the future):
 * - #HYDROGEN_PROCESS_GET_IDENTITY
 * - #HYDROGEN_PROCESS_SET_IDENTITY
 * - #HYDROGEN_PROCESS_CHANGE_GROUP
 * - #HYDROGEN_PROCESS_CHANGE_SESSION
 * - #HYDROGEN_PROCESS_CREATE_THREAD
 * - #HYDROGEN_PROCESS_CHANGE_SIGHAND
 * - #HYDROGEN_PROCESS_WAIT_SIGNAL
 */
#define HYDROGEN_THIS_PROCESS (-2)

#define HYDROGEN_PROCESS_WAIT_EXITED (1u << 0)    /**< Return status information of exited processes. */
#define HYDROGEN_PROCESS_WAIT_KILLED (1u << 1)    /**< Return status information of killed processes. */
#define HYDROGEN_PROCESS_WAIT_STOPPED (1u << 2)   /**< Return status information of stopped processes. */
#define HYDROGEN_PROCESS_WAIT_CONTINUED (1u << 3) /**< Return status information of continued processes. */
#define HYDROGEN_PROCESS_WAIT_DISCARD (1u << 4)   /**< Discard the process's status information. */
#define HYDROGEN_PROCESS_WAIT_UNQUEUE (1u << 5)   /**< Discard any queued SIGCHLD signals coming from the process.*/

/**
 * Find a process by its ID.
 *
 * \param[in] id The ID of the process to find. If negative, returns the current process.
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the process (in `integer`). The rights of the handle change according to the relation this
 *         process has to the target process:
 *         - If `id` names the current process, the handle has the same rights as #HYDROGEN_THIS_PROCESS.
 *         - If `id` names a child process that has not yet executed a file, the handle has
 *           #HYDROGEN_PROCESS_CHANGE_GROUP.
 *         - If `id` names a child process, the handle has #HYDROGEN_PROCESS_WAIT_STATUS.
 *         - The handle always has #HYDROGEN_PROCESS_GET_IDENTITY.
 *         If process rights exist that are not documented in this file, they may be given to handles returned by this
 *         function, with undefined conditions. Process rights that are documented in this file may not be given to
 *         handles returned by this function under any circumstances other than documented above.
 */
hydrogen_ret_t hydrogen_process_find(int id, uint32_t flags) __asm__("__hydrogen_process_find");

/**
 * Create a new process by cloning the current one.
 *
 * The new process does not have any threads.
 *
 * \param[in] flags The flags that should be set on the returned handle.
 * \return A handle to the newly created process (in `integer`).
 */
hydrogen_ret_t hydrogen_process_create(uint32_t flags) __asm__("__hydrogen_process_create");

/**
 * Get the ID of a process.
 *
 * \param[in] process The process whose ID to get. Can be #HYDROGEN_THIS_PROCESS.
 * \return The ID of the process (in `integer`).
 */
hydrogen_ret_t hydrogen_process_getpid(int process) __asm__("__hydrogen_process_getpid");

/**
 * Get the ID of a process's parent.
 *
 * \param[in] process The process whose parent's ID to get. Can be #HYDROGEN_THIS_PROCESS.
 * \return The ID of the process's parent (in `integer`).
 */
hydrogen_ret_t hydrogen_process_getppid(int process) __asm__("__hydrogen_process_getppid");

/**
 * Get the ID of a process's group.
 *
 * \param[in] process The process whose group's ID to get. Can be #HYDROGEN_THIS_PROCESS.
 * \return The ID of the process's group (in `integer`).
 */
hydrogen_ret_t hydrogen_process_getpgid(int process) __asm__("__hydrogen_process_getpgid");

/**
 * Get the ID of a process's session.
 *
 * \param[in] process The process whose session's ID to get. Can be #HYDROGEN_THIS_PROCESS.
 * \return The ID of the process's session (in `integer`).
 */
hydrogen_ret_t hydrogen_process_getsid(int process) __asm__("__hydrogen_process_getsid");

/**
 * Change a process's group.
 *
 * For detailed behavior documentation, see the POSIX manual on setpgid. The only difference
 * is that this function takes a handle instead of a process ID.
 *
 * \param[in] process The process whose group to change. Can be #HYDROGEN_THIS_PROCESS.
 *                    Requires #HYDROGEN_PROCESS_CHANGE_GROUP.
 * \param[in] group_id The ID of the group the process should join. If zero, use the process's ID.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_process_setpgid(int process, int group_id) __asm__("__hydrogen_process_setpgid");

/**
 * Change a process's session.
 *
 * For detailed behavior documentation, see the POSIX manual on setsid. The only difference
 * is that this function takes a handle instead of implicitly operating on the current process.
 *
 * \param[in] process The process whose session to change. Can be #HYDROGEN_THIS_PROCESS.
 *                    Requires #HYDROGEN_PROCESS_CHANGE_SESSION.
 * \return The ID of the new session (in `integer`).
 */
hydrogen_ret_t hydrogen_process_setsid(int process) __asm__("__hydrogen_process_setsid");

/** See the POSIX manual on getgid. */
hydrogen_ret_t hydrogen_process_getgid(int process) __asm__("__hydrogen_process_getgid");

/** See the POSIX manual on getuid. */
hydrogen_ret_t hydrogen_process_getuid(int process) __asm__("__hydrogen_process_getuid");

/** See the POSIX manual on getegid. */
hydrogen_ret_t hydrogen_process_getegid(int process) __asm__("__hydrogen_process_getegid");

/** See the POSIX manual on geteuid. */
hydrogen_ret_t hydrogen_process_geteuid(int process) __asm__("__hydrogen_process_geteuid");

/** See the POSIX manual on getresgid */
int hydrogen_process_getresgid(int process, uint32_t ids[3]) __asm__("__hydrogen_process_getresgid");

/** See the POSIX manual on getresuid */
int hydrogen_process_getresuid(int process, uint32_t ids[3]) __asm__("__hydrogen_process_getresuid");

/**
 * Get the supplementary group list of a process.
 *
 * \param[in] process The process whose group list to get. Can be #HYDROGEN_THIS_PROCESS.
 *                    Requires #HYDROGEN_PROCESS_GET_IDENTITY.
 * \param[in] buffer The buffer to place the group list in.
 * \param[in] count The number of slots in the buffer.
 * \return The size of the process's supplementary group list (in `integer`). Note that the returned value may be larger
 *         than `count`; if so, the first `count` group IDs have been placed in `buffer`.
 */
hydrogen_ret_t hydrogen_process_getgroups(int process, uint32_t *buffer, size_t count) __asm__(
        "__hydrogen_process_getgroups"
);

/** See the POSIX manual on setgid. */
int hydrogen_process_setgid(int process, uint32_t gid) __asm__("__hydrogen_process_setgid");

/** See the POSIX manual on setuid. */
int hydrogen_process_setuid(int process, uint32_t uid) __asm__("__hydrogen_process_setuid");

/** See the POSIX manual on setegid. */
int hydrogen_process_setegid(int process, uint32_t egid) __asm__("__hydrogen_process_setegid");

/** See the POSIX manual on seteuid. */
int hydrogen_process_seteuid(int process, uint32_t euid) __asm__("__hydrogen_process_seteuid");

/** See the POSIX manual on setregid. */
int hydrogen_process_setregid(int process, uint32_t rgid, uint32_t egid) __asm__("__hydrogen_process_setregid");

/** See the POSIX manual on setreuid. */
int hydrogen_process_setreuid(int process, uint32_t ruid, uint32_t euid) __asm__("__hydrogen_process_setreuid");

/** See the POSIX manual on setresgid. */
int hydrogen_process_setresgid(int process, uint32_t rgid, uint32_t egid, uint32_t sgid) __asm__(
        "__hydrogen_process_setresgid"
);

/** See the POSIX manual on setresuid. */
int hydrogen_process_setresuid(int process, uint32_t ruid, uint32_t euid, uint32_t suid) __asm__(
        "__hydrogen_process_setresuid"
);

/**
 * Set the supplementary group list of a process.
 *
 * \param[in] process The process whose group list to set. Must be root. Can be #HYDROGEN_THIS_PROCESS.
                      Requires #HYDROGEN_PROCESS_SET_IDENTITY.
 * \param[in] groups The new supplementary group list.
 * \param[in] count The number of groups in the new group list.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_process_setgroups(int process, const uint32_t *groups, size_t count) __asm__("__hydrogen_process_setgroups"
);

/**
 * Change and/or retrieve a signal handler of a process.
 *
 * \param[in] process The process in question. Can be #HYDROGEN_THIS_PROCESS. Requires #HYDROGEN_PROCESS_CHANGE_SIGHAND.
 * \param[in] signal The signal in question.
 * \param[in] action The new signal handler. If `NULL`, the signal handler isn't changed.
 * \param[out] old The old signal handler. If `NULL`, the signal handler isn't retrieved.
 * \return 0, if succcessful; if not, an error code.
 */
int hydrogen_process_sigaction(
        int process,
        int signal,
        const struct __sigaction *action,
        struct __sigaction *old
) __asm__("__hydrogen_process_sigaction");

/** See the POSIX manual on kill. Note that `process` is a handle here, not an ID.
 * To broadcast a signal, use #HYDROGEN_INVALID_HANDLE. */
int hydrogen_process_send_signal(int process, int signal) __asm__("__hydrogen_process_send_signal");

/** See the POSIX manual on killpg. */
int hydrogen_process_group_send_signal(int group_id, int signal) __asm__("__hydrogen_process_group_send_signal");

/**
 * Wait for a pending signal.
 *
 * \param[in] process The process to wait for a signal on. Can be #HYDROGEN_THIS_PROCESS. Requires
 *                    #HYDROGEN_PROCESS_WAIT_SIGNAL. If this is the current process, this call also waits for signals
 *                    pending on the current thread.
 * \param[in] set The signals that should be waited for.
 * \param[out] info The buffer to store the signal information in.
 * \param[in] deadline The boot time value at which the wait should stop. If zero, wait forever. If one, do not wait.
 *                     If the deadline is reached, this call returns #EAGAIN.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_process_sigwait(int process, __sigset_t set, __siginfo_t *info, uint64_t deadline) __asm__(
        "__hydrogen_process_sigwait"
);

/**
 * Exit the current process. Other threads within the process are terminated.
 *
 * \param[in] status The exit status of the process.
 */
__attribute__((__noreturn__)) void hydrogen_process_exit(int status) __asm__("__hydrogen_process_exit");

/**
 * Wait for a process to change state.
 *
 * If the process disappears while waiting for it, this function returns #ECHILD.
 *
 * \param[in] process The process to wait for. Requires #HYDROGEN_PROCESS_WAIT_STATUS.
 * \param[in] flags The wait flags.
 * \param[out] info The state change information.
 * \param[in] deadline The boot time value at which the wait should stop. If zero, wait forever. If one, do not wait.
 *                     If the deadline is reached, this call returns #EAGAIN.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_process_wait(int process, unsigned flags, __siginfo_t *info, uint64_t deadline) __asm__(
        "__hydrogen_process_wait"
);

/**
 * Wait for a member of a set of processes to change state.
 *
 * If at any point during the wait `process` no longer refers to any processes, this function returns #ECHILD.
 *
 * \param[in] process If zero, wait for any children of the current process. Otherwise, wait for children whose process
 *                    group ID is `process`.
 * \param[in] flags The wait flags.
 * \param[out] info The state change information.
 * \param[in] deadline The boot time value at which the wait should stop. If zero, wait forever. If one, do not wait.
 *                     If the deadline is reached, this call returns #EAGAIN.
 * \return The ID of the process whose state changed (in `integer`).
 */
hydrogen_ret_t hydrogen_process_wait_id(int process, unsigned flags, __siginfo_t *info, uint64_t deadline) __asm__(
        "__hydrogen_process_wait_id"
);

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_PROCESS_H */
