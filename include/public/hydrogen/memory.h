#ifndef HYDROGEN_MEMORY_H
#define HYDROGEN_MEMORY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VMM_READ (1u << 0)
#define VMM_WRITE (1u << 1)
#define VMM_EXEC (1u << 2)
#define VMM_EXACT (1u << 3)
#define VMM_PRIVATE (1u << 4)
#define VMM_TRY_EXACT (1u << 5)

intptr_t hydrogen_map_memory(uintptr_t preferred, size_t size, int flags, int fd, uint64_t offset);

int hydrogen_set_memory_protection(uintptr_t start, size_t size, int flags);

int hydrogen_unmap_memory(uintptr_t start, size_t size);

uintptr_t hydrogen_get_fs_base(void);

uintptr_t hydrogen_get_gs_base(void);

int hydrogen_set_fs_base(uintptr_t value);

int hydrogen_set_gs_base(uintptr_t value);

#ifdef __cplusplus
};
#endif

#endif // HYDROGEN_MEMORY_H
