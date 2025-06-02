#ifndef _HYDROGEN_TERMIOS_H
#define _HYDROGEN_TERMIOS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char __cc_t;
typedef unsigned __speed_t;
typedef unsigned __tcflag_t;

#define __NCCS 32

struct __termios {
    __tcflag_t __input_flags;
    __tcflag_t __output_flags;
    __tcflag_t __control_flags;
    __tcflag_t __local_flags;
    __cc_t __control_chars[__NCCS];
    __speed_t __input_speed;
    __speed_t __output_speed;
};

struct __winsize {
    unsigned short __width, __height;
};

#define __IUTF8 (1u << 0)
#define __BRKINT (1u << 1)
#define __ICRNL (1u << 2)
#define __IGNBRK (1u << 3)
#define __IGNCR (1u << 4)
#define __IGNPAR (1u << 5)
#define __INLCR (1u << 6)
#define __INPCK (1u << 7)
#define __ISTRIP (1u << 8)
#define __IXANY (1u << 9)
#define __IXOFF (1u << 10)
#define __IXON (1u << 11)
#define __PARMRK (1u << 12)
#define __IMAXBEL (1u << 13)

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

#define __CLOCAL (1u << 0)
#define __CREAD (1u << 1)
#define __CSIZE (3u << 2)
#define __CS5 (0u << 2)
#define __CS6 (1u << 2)
#define __CS7 (2u << 2)
#define __CS8 (3u << 2)
#define __CSTOPB (1u << 4)
#define __HUPCL (1u << 5)
#define __PARENB (1u << 6)
#define __PARODD (1u << 7)

#define __ECHO (1u << 0)
#define __ECHOE (1u << 1)
#define __ECHOK (1u << 2)
#define __ECHONL (1u << 3)
#define __ICANON (1u << 4)
#define __IEXTEN (1u << 5)
#define __ISIG (1u << 6)
#define __NOFLSH (1u << 7)
#define __TOSTOP (1u << 8)
#define __ECHOKE (1u << 9)
#define __ECHOCTL (1u << 10)

#define __VEOF 0
#define __VEOL 1
#define __VERASE 2
#define __VINTR 3
#define __VKILL 4
#define __VMIN 5
#define __VQUIT 6
#define __VSUSP 7
#define __VTIME 8
#define __VSTART 9
#define __VSTOP 10

#ifdef __cplusplus
};
#endif

#endif /* _HYDROGEN_TERMIOS_H */
