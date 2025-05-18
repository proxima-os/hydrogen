#pragma once

#include <stddef.h>

typedef struct {
    int rel, trel;
    const void *path;
    size_t length;
    const void *target;
    size_t tlength;
    int flags;
} link_syscall_args_t;

typedef struct {
    __int128_t atime, ctime, mtime;
} utime_syscall_args_t;
