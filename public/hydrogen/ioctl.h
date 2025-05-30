#ifndef _HYDROGEN_IOCTL_H
#define _HYDROGEN_IOCTL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Note: the "bool" types here are ints where 0=false, nonzero=true */

#define __IOCTL_MEM_ALLOCATE 0x00001       /**< Allocate physical memory. #hydrogen_ioctl_mem_allocate_t -> fd. */
#define __IOCTL_MEM_IS_RAM 0x00002         /**< Check whether a range is RAM. #hydrogen_ioctl_mem_is_ram_t -> bool. */
#define __IOCTL_MEM_NEXT_RAM_RANGE 0x00003 /**< Get the next RAM range. #hydrogen_mem_next_ram_range_t -> void. */

#define __IOCTL_IRQ_OPEN 0x10000 /**< Open an IRQ. #hydrogen_ioctl_irq_open_t -> handle. */

#define __IOCTL_PTM_GET_NUMBER 0x20000 /**< Get the pty number. void -> handle. */
#define __IOCTL_PTM_OPEN_SLAVE 0x20001 /**< Open the slave device. int -> fd. */
#define __IOCTL_PTM_GET_LOCKED 0x20002 /**< Get the lock state. void -> bool. */
#define __IOCTL_PTM_SET_LOCKED 0x20003 /**< Set the lock state. bool -> void. */

#ifdef __cplusplus
};
#endif

#endif /* _HYDROGEN_IOCTL_H */
