#ifndef HYDROGEN_TYPES_H
#define HYDROGEN_TYPES_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int error;
    union {
        size_t integer;
        void *pointer;
    };
} hydrogen_ret_t;

typedef struct {
    const void *data;
    size_t size;
} hydrogen_string_t;

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_TYPES_T */
