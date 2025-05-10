/* IWYU pragma: private, include "hydrogen/signal.h" */
#ifndef __HYDROGEN_ARCH_SIGNAL_H
#define __HYDROGEN_ARCH_SIGNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#define __MINSIGSTKSZ 8192
#define __SIGSTKSZ 8192

typedef struct {
    unsigned long __rax;
    unsigned long __rbx;
    unsigned long __rcx;
    unsigned long __rdx;
    unsigned long __rsi;
    unsigned long __rdi;
    unsigned long __rbp;
    unsigned long __rsp;
    unsigned long __r8;
    unsigned long __r9;
    unsigned long __r10;
    unsigned long __r11;
    unsigned long __r12;
    unsigned long __r13;
    unsigned long __r14;
    unsigned long __r15;
    unsigned long __rip;
    unsigned long __rflags;
    void *__xsave_area;
} __mcontext_t;

#ifdef __cplusplus
};
#endif

#endif /* __HYDROGEN_ARCH_SIGNAL_H */
