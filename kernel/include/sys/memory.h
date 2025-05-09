#pragma once

#include "cpu/cpudata.h"
#include "mem/vmm.h"
#include "util/handle.h"

#define THIS_VMM_RIGHTS                                                                                    \
    (HYDROGEN_VMM_CLONE | HYDROGEN_VMM_MAP | HYDROGEN_VMM_REMAP | HYDROGEN_VMM_UNMAP | HYDROGEN_VMM_READ | \
     HYDROGEN_VMM_WRITE)

static inline int vmm_or_this(vmm_t **out, int handle, object_rights_t rights) {
    if (handle == HYDROGEN_THIS_VMM) {
        *out = current_thread->vmm;
        return 0;
    } else {
        handle_data_t data;
        int error = hnd_resolve(&data, handle, OBJECT_VMM, rights);
        if (unlikely(error)) return error;
        *out = (vmm_t *)data.object;
        return 0;
    }
}
