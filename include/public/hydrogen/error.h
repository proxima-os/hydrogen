/** \file
 * Error codes.
 */

#ifndef HYDROGEN_ERROR_H
#define HYDROGEN_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HYDROGEN_SUCCESS,          /**< Success. */
    HYDROGEN_OUT_OF_MEMORY,    /**< Out of memory. */
    HYDROGEN_INVALID_ARGUMENT, /**< Invalid argument. */
    HYDROGEN_INVALID_FORMAT,   /**< Invalid input formatting. */
    HYDROGEN_TIMED_OUT,        /**< Timed out. */
    HYDROGEN_BUSY,             /**< Resource is unavailable. */
    HYDROGEN_PAGE_FAULT,       /**< Page fault. */
    HYDROGEN_ALREADY_EXISTS,   /**< Already exists. */
    HYDROGEN_INVALID_HANDLE,   /**< Invalid handle. */
    HYDROGEN_NO_PERMISSION,    /**< The operation is not allowed on the specified handle. */
} hydrogen_error_t;

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_ERROR_H */
