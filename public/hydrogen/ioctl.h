#ifndef _HYDROGEN_IOCTL_H
#define _HYDROGEN_IOCTL_H

#ifdef __cplusplus
extern "C" {
#endif

#define __IOCTL_MEM_ALLOCATE 1 /**< Allocate physical memory. #hydrogen_ioctl_mem_allocate_t -> fd. */
#define __IOCTL_MEM_IS_RAM 2   /**< Determine whether a range is RAM. #hydrogen_ioctl_mem_is_ram_t -> bool. */

#ifdef __cplusplus
};
#endif

#endif /* _HYDROGEN_IOCTL_H */
