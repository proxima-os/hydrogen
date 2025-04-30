#pragma once

#define EXPORT __attribute__((visibility("default")))

#ifndef NDEBUG
#define ASSERT_OK(ret)                    \
    ({                                    \
        hydrogen_ret_t _ret = (ret);      \
        if (_ret.error) __builtin_trap(); \
        _ret;                             \
    })
#else
#define ASSERT_OK(ret) (ret)
#endif
