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

#define __SIGABRT 1
#define __SIGALRM 2
#define __SIGBUS 3
#define __SIGCHLD 4
#define __SIGCONT 5
#define __SIGFPE 6
#define __SIGHUP 7
#define __SIGILL 8
#define __SIGINT 9
#define __SIGKILL 10
#define __SIGPIPE 11
#define __SIGQUIT 12
#define __SIGSEGV 13
#define __SIGSTOP 14
#define __SIGTERM 15
#define __SIGTSTP 16
#define __SIGTTIN 17
#define __SIGTTOU 18
#define __SIGUSR1 19
#define __SIGUSR2 20
#define __SIGWINCH 21
#define __SIGSYS 22
#define __SIGTRAP 23
#define __SIGURG 24
#define __SIGVTALRM 25
#define __SIGXCPU 26
#define __SIGXFSZ 27

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

#define __SI_USER 1
#define __SI_QUEUE 2
#define __SI_TIMER 3
#define __SI_ASYNCIO 4
#define __SI_MESGQ 5

#define __ILL_ILLOPC 0x8000
#define __ILL_ILLOPN 0x8001
#define __ILL_ILLADR 0x8002
#define __ILL_ILLTRP 0x8003
#define __ILL_PRVOPC 0x8004
#define __ILL_PRVREG 0x8005
#define __ILL_COPROC 0x8006
#define __ILL_BADSTK 0x8007

#define __FPE_INTDIV 0x8000
#define __FPE_INTOVF 0x8001
#define __FPE_FLTDIV 0x8002
#define __FPE_FLTOVF 0x8003
#define __FPE_FLTUND 0x8004
#define __FPE_FLTRES 0x8005
#define __FPE_FLTINV 0x8006
#define __FPE_FLTSUB 0x8007

#define __SEGV_MAPERR 0x8000
#define __SEGV_ACCERR 0x8001

#define __BUS_ADRALN 0x8000
#define __BUS_ADRERR 0x8001
#define __BUS_OBJERR 0x8002

#define __TRAP_BRKPT 0x8000
#define __TRAP_TRACE 0x8001

#define __CLD_EXITED 0x8000
#define __CLD_KILLED 0x8001
#define __CLD_DUMPED 0x8002
#define __CLD_TRAPPED 0x8003
#define __CLD_STOPPED 0x8004
#define __CLD_CONTINUED 0x8005

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
