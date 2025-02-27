#ifndef HYDROGEN_IO_H
#define HYDROGEN_IO_H

#include "hydrogen/error.h"
#include "hydrogen/handle.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Enables I/O port access for this thread.
 *
 * \param[in] io The handle to the I/O address space.
 */
hydrogen_error_t hydrogen_io_enable(hydrogen_handle_t io);

/**
 * Disables I/O port access for this thread.
 */
void hydrogen_io_disable(void);

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_IO_H */
