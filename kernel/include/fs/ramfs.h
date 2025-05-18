#pragma once

#include "fs/vfs.h"
#include <stdint.h>

int ramfs_create(filesystem_t **out, uint32_t root_mode);
