#pragma once

#define EXPORT __attribute__((visibility("default")))

#ifndef NDEBUG
#define ASSERT_OK_INT(err) (__builtin_expect(!!(err), 0) ? __builtin_trap() : (void)0)
#define ASSERT_OK(ret)               \
    ({                               \
        hydrogen_ret_t _ret = (ret); \
        ASSERT_OK_INT(_ret.error);   \
        _ret;                        \
    })
#else
#define ASSERT_OK_INT ((void)0)
#define ASSERT_OK(ret) (ret)
#endif
