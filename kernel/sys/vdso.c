#include "sys/vdso.h"
#include "errno.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "mem/memmap.h"
#include "mem/pmap.h"
#include "mem/vmm.h"
#include "sections.h"
#include "util/object.h"
#include <stdint.h>

extern const void __vdso_start, __vdso_end;

size_t vdso_image_offset;
size_t vdso_size;

static void vdso_post_map(
        mem_object_t *ptr,
        vmm_t *vmm,
        uintptr_t head,
        uintptr_t tail,
        unsigned flags,
        size_t offset
) {
    if (offset >= vdso_size) return;

    size_t avail = vdso_size - offset;
    size_t cur = tail - head + 1;
    if (cur > avail) cur = avail;

    pmap_map(vmm, head, sym_to_phys(&__vdso_start), cur, vmm_to_pmap_flags(flags));
}

static const mem_object_ops_t vdso_object_ops = {
        .post_map = vdso_post_map,
};

mem_object_t vdso_object = {
        .base.ops = &vdso_object_ops.base,
};

INIT_TEXT void vdso_init(void) {
    vdso_image_offset = (const void *)&vdso_image - &__vdso_start;
    vdso_size = &__vdso_end - &__vdso_start;
    ASSERT((vdso_size & PAGE_MASK) == 0);

    obj_init(&vdso_object.base, OBJECT_MEMORY);
}
