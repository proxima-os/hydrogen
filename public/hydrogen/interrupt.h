#ifndef HYDROGEN_INTERRUPT_H
#define HYDROGEN_INTERRUPT_H

#include <hydrogen/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HYDROGEN_INTERRUPT_WAIT (1u << 0)  /**< Allow the use of #hydrogen_interrupt_wait. */
#define HYDROGEN_INTERRUPT_CLAIM (1u << 1) /**< Allow interrupts to be claimed. */

#define HYDROGEN_IRQ_WAIT_CLAIM (1u << 0) /**< Claim the interrupt immediately. Requires #HYDROGEN_INTERRUPT_CLAIM. */

/**
 * Wait for an interrupt to become pending.
 *
 * \param[in] irq The interrupt to wait for. Requires #HYDROGEN_INTERRUPT_WAIT.
 * \param[in] deadline The boot time value at which to stop waiting. If zero, wait indefinitely. If one, do not wait.
 *                     If reached, this function returns #EAGAIN.
 * \param[in] flags A bitmask of the following flags:
 *                  - #HYDROGEN_IRQ_WAIT_CLAIM
 * \return An IRQ instance ID that can be passed to #hydrogen_interrupt_claim (in `integer`).
 */
hydrogen_ret_t hydrogen_interrupt_wait(int irq, uint64_t deadline, unsigned flags) __asm__("__hydrogen_interrupt_wait");

/**
 * Claim a pending IRQ.
 *
 * \param[in] irq The interrupt to claim.
 * \param[in] id The IRQ instance ID returned by #hydrogen_interrupt_wait.
 * \return 0, if successful; if not, an error code.
 */
int hydrogen_interrupt_claim(int irq, size_t id) __asm__("__hydrogen_interrupt_claim");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_INTERRUPT_H */
