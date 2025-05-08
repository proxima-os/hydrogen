#ifndef HYDROGEN_THREAD_H
#define HYDROGEN_THREAD_H

#ifdef __cplusplus
extern "C" {
#endif

_Noreturn void hydrogen_thread_exit(int status) __asm__("__hydrogen_thread_exit");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_THREAD_H */
