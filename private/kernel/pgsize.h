#pragma once

#include "kernel/arch/pgshift.h" /* IWYU pragma: export */

#define PAGE_SIZE (1ul << PAGE_SHIFT)
#define PAGE_MASK (PAGE_SIZE - 1)
