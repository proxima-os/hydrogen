#ifndef HYDROGEN_INTERRUPT_H
#define HYDROGEN_INTERRUPT_H

#include <hydrogen/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HYDROGEN_INTERRUPT_WAIT (1u << 0)     /**< Allow the use of #hydrogen_interrupt_wait. */
#define HYDROGEN_INTERRUPT_COMPLETE (1u << 1) /**< Allow interrupts to be completed. */

/** Complete the interrupt immediately. Requires #HYDROGEN_INTERRUPT_COMPLETE. */
#define HYDROGEN_IRQ_WAIT_COMPLETE (1u << 0)

/**
 * Wait for an interrupt to become pending.
 *
 * \param[in] irq The interrupt to wait for. Requires #HYDROGEN_INTERRUPT_WAIT.
 * \param[in] deadline The boot time value at which to stop waiting. If zero, wait indefinitely. If one, do not wait.
 *                     If reached, this function returns #EAGAIN.
 * \param[in] flags A bitmask of the following flags:
 *                  - #HYDROGEN_IRQ_WAIT_CLAIM
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_interrupt_wait(int irq, uint64_t deadline, unsigned flags) __asm__("__hydrogen_interrupt_wait");

/**
 * Complete a pending IRQ. This is required even for shareable IRQs that did not originate from the hardware you are
 * driving.
 *
 * \param[in] irq The interrupt to complete.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_interrupt_complete(int irq) __asm__("__hydrogen_interrupt_complete");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_INTERRUPT_H */
