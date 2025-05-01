#pragma once

#include <stdint.h>

typedef struct {
    uint32_t reserved0;
    uint64_t rsp[3];
    uint64_t reserved1;
    uint64_t ist[7];
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iopb_base;
} __attribute__((packed, aligned(8))) x86_64_tss_t;

#define X86_64_IST_FATAL 0
