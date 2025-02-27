#ifndef HYDROGEN_ERROR_H
#define HYDROGEN_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HYDROGEN_SUCCESS,
    HYDROGEN_OUT_OF_MEMORY,
    HYDROGEN_INVALID_ARGUMENT,
    HYDROGEN_INVALID_FORMAT,
    HYDROGEN_TIMED_OUT,
    HYDROGEN_BUSY,
    HYDROGEN_PAGE_FAULT,
    HYDROGEN_ALREADY_EXISTS,
} hydrogen_error_t;

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_ERROR_H */
