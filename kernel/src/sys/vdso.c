#include "sys/vdso.h"
#include "cpu/cpu.h"
#include "hydrogen/memory.h"
#include "mem/obj/pmem.h"
#include "mem/pmm.h"
#include "mem/vmm.h"
#include "util/handle.h"

static pmem_vm_object_t vdso_object;

handle_data_t vdso_handle = {
        .object = &vdso_object.base.base,
        .rights = HYDROGEN_MEMORY_RIGHT_READ | HYDROGEN_MEMORY_RIGHT_EXEC
};
size_t vdso_size;

extern const void __vdso_start;
extern const void __vdso_end;

void init_vdso(void) {
    vdso_size = &__vdso_end - &__vdso_start;
    pmem_vm_obj_init(&vdso_object, sym_to_phys(&__vdso_start), vdso_size);
}

bool is_in_vdso(uintptr_t addr) {
    address_space_t *space = current_thread->address_space;

    // No locking necessary: as soon as any thread switches to an address space, that space's vdso_addr becomes
    // immutable. This thread has by definition already switched to this thread's address space, so that condition
    // is met.
    return addr >= space->vdso_addr && addr < space->vdso_addr + vdso_size;
}
