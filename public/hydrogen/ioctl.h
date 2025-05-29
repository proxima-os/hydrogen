#ifndef _HYDROGEN_IOCTL_H
#define _HYDROGEN_IOCTL_H

#ifdef __cplusplus
extern "C" {
#endif

#define __IOCTL_MEM_ALLOCATE 0x00001       /**< Allocate physical memory. #hydrogen_ioctl_mem_allocate_t -> fd. */
#define __IOCTL_MEM_IS_RAM 0x00002         /**< Check whether a range is RAM. #hydrogen_ioctl_mem_is_ram_t -> bool. */
#define __IOCTL_MEM_NEXT_RAM_RANGE 0x00003 /**< Get the next RAM range. #hydrogen_mem_next_ram_range_t -> void. */

#define __IOCTL_IRQ_OPEN 0x10000 /**< Open an IRQ. #hydrogen_ioctl_irq_open_t -> handle. */

#ifdef __cplusplus
};
#endif

#endif /* _HYDROGEN_IOCTL_H */
