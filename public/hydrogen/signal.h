/** \file
 * Definitions related to signal handling.
 */

#ifndef __HYDROGEN_SIGNAL_H
#define __HYDROGEN_SIGNAL_H

#include "hydrogen/arch/signal.h" /* IWYU pragma: export */

#ifdef __cplusplus
extern "C" {
#endif

#define __SIG_DFL ((void (*)(int))0)
#define __SIG_IGN ((void (*)(int))1)

#define __SIGHUP 1
#define __SIGINT 2
#define __SIGQUIT 3
#define __SIGILL 4
#define __SIGTRAP 5
#define __SIGABRT 6
#define __SIGBUS 7
#define __SIGFPE 8
#define __SIGKILL 9
#define __SIGUSR1 10
#define __SIGSEGV 11
#define __SIGUSR2 12
#define __SIGPIPE 13
#define __SIGALRM 14
#define __SIGTERM 15
#define __SIGCHLD 17
#define __SIGCONT 18
#define __SIGSTOP 19
#define __SIGTSTP 20
#define __SIGTTIN 21
#define __SIGTTOU 22
#define __SIGURG 23
#define __SIGXCPU 24
#define __SIGXFSZ 25
#define __SIGVTALRM 26
#define __SIGPROF 27
#define __SIGWINCH 28
#define __SIGIO 29
#define __SIGPWR 30
#define __SIGSYS 31
#define __SIGRTMIN 32
#define __SIGRTMAX 63

#define __NSIG 64

typedef unsigned long long __sigset_t;

union __sigval {
    int __int;
    void *__ptr;
};

typedef struct {
    int __signo;
    int __code;
    int __errno;
    int __padding;
    union {
        unsigned char __padding[112];
        struct {
            int __pid;
            unsigned __uid;
            int __status;
        } __user_or_sigchld;
        union {
            union __sigval __value;
        } __queue;
        struct {
            void *__address;
        } __sigsegv;
    } __data;
} __siginfo_t;

#define __SI_USER (-1)
#define __SI_QUEUE (-2)
#define __SI_TIMER (-3)
#define __SI_ASYNCIO (-4)
#define __SI_MESGQ (-5)
#define __SI_TKILL (-6)

#define __ILL_ILLOPC 1
#define __ILL_ILLOPN 2
#define __ILL_ILLADR 3
#define __ILL_ILLTRP 4
#define __ILL_PRVOPC 5
#define __ILL_PRVREG 6
#define __ILL_COPROC 7
#define __ILL_BADSTK 8

#define __FPE_INTDIV 1
#define __FPE_INTOVF 2
#define __FPE_FLTDIV 3
#define __FPE_FLTOVF 4
#define __FPE_FLTUND 5
#define __FPE_FLTRES 6
#define __FPE_FLTINV 7
#define __FPE_FLTSUB 8

#define __SEGV_MAPERR 1
#define __SEGV_ACCERR 2

#define __BUS_ADRALN 1
#define __BUS_ADRERR 2
#define __BUS_OBJERR 3

#define __TRAP_BRKPT 1
#define __TRAP_TRACE 2

#define __CLD_EXITED 1
#define __CLD_KILLED 2
#define __CLD_DUMPED 3
#define __CLD_TRAPPED 4
#define __CLD_STOPPED 5
#define __CLD_CONTINUED 6

struct __sigaction {
    union {
        void (*__handler)(int);
        void (*__action)(int, __siginfo_t *, void *);
    } __func;
    __sigset_t __mask;
    int __flags;
};

#define __SA_NOCLDSTOP 0x0001
#define __SA_ONSTACK 0x0002
#define __SA_RESETHAND 0x0004
#define __SA_RESTART 0x0008
#define __SA_SIGINFO 0x0010
#define __SA_NOCLDWAIT 0x0020
#define __SA_NODEFER 0x0040

#define __SIG_BLOCK 0
#define __SIG_UNBLOCK 1
#define __SIG_SETMASK 2

typedef struct {
    void *__pointer;
    unsigned long __size;
    int __flags;
} __stack_t;

#define __SS_ONSTACK 1
#define __SS_DISABLE 2

typedef struct __ucontext {
    struct __ucontext *__link;
    __mcontext_t __mcontext;
    __sigset_t __mask;
    __stack_t __stack;
} __ucontext_t;

#ifdef __cplusplus
};
#endif

#endif /* __HYDROGEN_SIGNAL_H */
