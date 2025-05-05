#pragma once

#define X86_64_IDT_DE 0x00
#define X86_64_IDT_DB 0x01
#define X86_64_IDT_NMI 0x02
#define X86_64_IDT_BP 0x03
#define X86_64_IDT_OF 0x04
#define X86_64_IDT_BR 0x05
#define X86_64_IDT_UD 0x06
#define X86_64_IDT_NM 0x07
#define X86_64_IDT_DF 0x08
#define X86_64_IDT_TS 0x0a
#define X86_64_IDT_NP 0x0b
#define X86_64_IDT_SS 0x0c
#define X86_64_IDT_GP 0x0d
#define X86_64_IDT_PF 0x0e
#define X86_64_IDT_MF 0x10
#define X86_64_IDT_AC 0x11
#define X86_64_IDT_MC 0x12
#define X86_64_IDT_XM 0x13

#define X86_64_IDT_IPI_REMOTE_CALL 0xfc
#define X86_64_IDT_LAPIC_TIMER 0xfd
#define X86_64_IDT_LAPIC_ERROR 0xfe
#define X86_64_IDT_LAPIC_SPURIOUS 0xff
