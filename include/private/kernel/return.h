#pragma once

#include "hydrogen/types.h" /* IWYU pragma: keep */
#include "kernel/compiler.h"

#define RET_ERROR(e) ((hydrogen_ret_t){.error = (e)})
#define RET_HANDLE(h) ((hydrogen_ret_t){.handle = (h)})
#define RET_INTEGER(i) ((hydrogen_ret_t){.integer = (i)})
#define RET_POINTER(p) ((hydrogen_ret_t){.pointer = (p)})

#define RET_HANDLE_MAYBE(error, handle)                   \
    ({                                                    \
        int _e = (error);                                 \
        likely(!_e) ? RET_HANDLE(handle) : RET_ERROR(_e); \
    })
#define RET_INTEGER_MAYBE(error, integer)                   \
    ({                                                      \
        int _e = (error);                                   \
        likely(!_e) ? RET_INTEGER(integer) : RET_ERROR(_e); \
    })
#define RET_POINTER_MAYBE(error, pointer)                   \
    ({                                                      \
        int _e = (error);                                   \
        likely(!_e) ? RET_POINTER(pointer) : RET_ERROR(_e); \
    })
