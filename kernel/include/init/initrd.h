#pragma once

#include "fs/vfs.h"
#include <stddef.h>

void extract_initrds(file_t *rel, const char *path, size_t length);
