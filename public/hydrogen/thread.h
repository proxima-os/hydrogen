#ifndef HYDROGEN_THREAD_H
#define HYDROGEN_THREAD_H

#ifdef __cplusplus
extern "C" {
#endif

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
