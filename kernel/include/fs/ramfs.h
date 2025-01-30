#pragma once

#include "fs/vfs.h"

int ramfs_create(vfs_t **out, uint32_t mode, ident_t *ident);
