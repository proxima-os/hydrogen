#pragma once

#include "util/object.h"
#include <hydrogen/fcntl.h>
#include <hydrogen/filesystem.h>
#include <hydrogen/handle.h>

static inline object_rights_t get_open_rights(int flags) {
    object_rights_t rights = 0;
    if (flags & __O_RDONLY) rights |= HYDROGEN_FILE_READ;
    if (flags & __O_WRONLY) rights |= HYDROGEN_FILE_WRITE;
    return rights;
}

static inline uint32_t get_open_flags(int flags) {
    uint32_t handle_flags = 0;
    if ((flags & __O_CLOFORK) == 0) handle_flags |= HYDROGEN_HANDLE_CLONE_KEEP;
    if ((flags & __O_CLOEXEC) == 0) handle_flags |= HYDROGEN_HANDLE_EXEC_KEEP;
    return handle_flags;
}
