#ifndef HYDROGEN_LOG_H
#define HYDROGEN_LOG_H

#include "hydrogen/handle.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HYDROGEN_LOG_RIGHT_WRITE (1ull << 0) /**< Allow data to be written to the kernel log. */

/**
 * Write data to the kernel log.
 *
 * \param[in] log The kernel log.
 * \param[in] data The data to write.
 * \param[in] size The number of bytes to write.
 */
int hydrogen_log_write(hydrogen_handle_t log, const void *data, size_t size);

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_LOG_H */
