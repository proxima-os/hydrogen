#pragma once

#include <hydrogen/types.h> /* IWYU */

static inline hydrogen_ret_t ret_error(int error) {
    return (hydrogen_ret_t){.error = error};
}

static inline hydrogen_ret_t ret_integer(size_t integer) {
    return (hydrogen_ret_t){.integer = integer};
}

static inline hydrogen_ret_t ret_pointer(void *pointer) {
    return (hydrogen_ret_t){.pointer = pointer};
}

#define RET_MAYBE(type, error, value)                                     \
    ({                                                                    \
        int _err = (error);                                               \
        __builtin_expect(!_err, 1) ? ret_##type(value) : ret_error(_err); \
    })
