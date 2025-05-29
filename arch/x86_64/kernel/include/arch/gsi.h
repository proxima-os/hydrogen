#pragma once

#include <hydrogen/types.h>
#include <stdbool.h>
#include <stdint.h>

#define GSI_ACTIVE_LOW (1 << 0)
#define GSI_LEVEL_TRIGGERED (1 << 1)
#define GSI_SHAREABLE (1 << 2)

hydrogen_ret_t gsi_open(uint32_t gsi, int flags);
