#pragma once

#include <hydrogen/types.h> /* IWYU pragma: keep */

#define SYSCALL0(num)                                                             \
    ({                                                                            \
        hydrogen_ret_t _ret;                                                      \
        asm volatile("syscall" : "=A"(_ret) : "a"(num) : "rcx", "r11", "memory"); \
        _ret;                                                                     \
    })

#define SYSCALL1(num, a0)                                                                  \
    ({                                                                                     \
        hydrogen_ret_t _ret;                                                               \
        asm volatile("syscall" : "=A"(_ret) : "a"(num), "D"(a0) : "rcx", "r11", "memory"); \
        _ret;                                                                              \
    })

#define SYSCALL2(num, a0, a1)                                                                       \
    ({                                                                                              \
        hydrogen_ret_t _ret;                                                                        \
        asm volatile("syscall" : "=A"(_ret) : "a"(num), "D"(a0), "S"(a1) : "rcx", "r11", "memory"); \
        _ret;                                                                                       \
    })

#define SYSCALL3(num, a0, a1, a2)                                                                            \
    ({                                                                                                       \
        hydrogen_ret_t _ret;                                                                                 \
        asm volatile("syscall" : "=A"(_ret) : "a"(num), "D"(a0), "S"(a1), "d"(a2) : "rcx", "r11", "memory"); \
        _ret;                                                                                                \
    })

#define SYSCALL4(num, a0, a1, a2, a3)                                 \
    ({                                                                \
        hydrogen_ret_t _ret;                                          \
        register __typeof__(a3) _r10 asm("r10") = (a3);               \
        asm volatile("syscall"                                        \
                     : "=A"(_ret)                                     \
                     : "a"(num), "D"(a0), "S"(a1), "d"(a2), "r"(_r10) \
                     : "rcx", "r11", "memory");                       \
        _ret;                                                         \
    })

#define SYSCALL5(num, a0, a1, a2, a3, a4)                                       \
    ({                                                                          \
        hydrogen_ret_t _ret;                                                    \
        register __typeof__(a3) _r10 asm("r10") = (a3);                         \
        register __typeof__(a4) _r8 asm("r8") = (a4);                           \
        asm volatile("syscall"                                                  \
                     : "=A"(_ret)                                               \
                     : "a"(num), "D"(a0), "S"(a1), "d"(a2), "r"(_r10), "r"(_r8) \
                     : "rcx", "r11", "memory");                                 \
        _ret;                                                                   \
    })

#define SYSCALL6(num, a0, a1, a2, a3, a4, a5)                                             \
    ({                                                                                    \
        hydrogen_ret_t _ret;                                                              \
        register __typeof__(a3) _r10 asm("r10") = (a3);                                   \
        register __typeof__(a4) _r8 asm("r8") = (a4);                                     \
        register __typeof__(a5) _r9 asm("r9") = (a5);                                     \
        asm volatile("syscall"                                                            \
                     : "=A"(_ret)                                                         \
                     : "a"(num), "D"(a0), "S"(a1), "d"(a2), "r"(_r10), "r"(_r8), "r"(_r9) \
                     : "rcx", "r11", "memory");                                           \
        _ret;                                                                             \
    })
