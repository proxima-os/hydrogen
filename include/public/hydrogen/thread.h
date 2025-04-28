#ifndef HYDROGEN_THREAD_H
#define HYDROGEN_THREAD_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Exit the current thread.
 */
__attribute__((__noreturn__)) void hydrogen_thread_exit(void) asm("__hydrogen_thread_exit");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_THREAD_H */
