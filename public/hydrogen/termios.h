#ifndef _HYDROGEN_TERMIOS_H
#define _HYDROGEN_TERMIOS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char __cc_t;
typedef unsigned __tcflag_t;

#define __NCCS 32

struct __termios {
    __tcflag_t __input_flags;
    __tcflag_t __output_flags;
    __tcflag_t __control_flags;
    __tcflag_t __local_flags;
    __cc_t __control_chars[__NCCS];
};

#define __IUTF8 (1u << 0)

#define __OPOST (1u << 0)
#define __ONLCR (1u << 1)
#define __OCRNL (1u << 2)
#define __ONOCR (1u << 3)
#define __ONLRET (1u << 4)
#define __OFDEL (1u << 5)
#define __OFILL (1u << 6)
#define __NLDLY (1u << 7)
#define __NL0 (0u << 7)
#define __NL1 (1u << 7)
#define __CRDLY (3u << 8)
#define __CR0 (0u << 8)
#define __CR1 (1u << 8)
#define __CR2 (2u << 8)
#define __CR3 (3u << 8)
#define __TABDLY (3u << 10)
#define __TAB0 (0u << 10)
#define __TAB1 (1u << 10)
#define __TAB2 (2u << 10)
#define __TAB3 (3u << 10)
#define __BSDLY (1u << 12)
#define __BS0 (0u << 12)
#define __BS1 (1u << 12)
#define __VTDLY (1u << 13)
#define __VT0 (0u << 13)
#define __VT1 (1u << 13)
#define __FFDLY (1u << 14)
#define __FF0 (0u << 14)
#define __FF1 (1u << 14)

#ifdef __cplusplus
};
#endif

#endif /* _HYDROGEN_TERMIOS_H */
