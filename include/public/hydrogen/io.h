#ifndef HYDROGEN_IO_H
#define HYDROGEN_IO_H

#include "hydrogen/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Enable I/O port access for this thread.
 *
 * \param[in] io The handle to the I/O address space.
 */
int hydrogen_io_enable(hydrogen_handle_t io) __asm__("__hydrogen_io_enable");

/**
 * Disable I/O port access for this thread.
 */
void hydrogen_io_disable(void) __asm__("__hydrogen_io_disable");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_IO_H */
