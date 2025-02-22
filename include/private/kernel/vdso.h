#pragma once

#include "compiler.h"
#include "kernel/time.h"
#include <stdint.h>

typedef struct {
    int64_t boot_timestamp;
    uint64_t boot_tsc;
    uint64_t tsc_freq;
    timeconv_t tsc2ns_conv;
    timeconv_t ns2tsc_conv;
} vdso_info_t;

HIDDEN extern vdso_info_t vdso_info;

#define boot_timestamp (vdso_info.boot_timestamp)
#define boot_tsc (vdso_info.boot_tsc)
#define tsc_freq (vdso_info.tsc_freq)
#define tsc2ns_conv (vdso_info.tsc2ns_conv)
#define ns2tsc_conv (vdso_info.ns2tsc_conv)
