#pragma once

#include "cpu/cpudata.h"
#include "hydrogen/process.h"
#include "proc/process.h"
#include "util/handle.h"

#define THIS_PROCESS_RIGHTS                                                                          \
    (HYDROGEN_PROCESS_GET_IDENTITY | HYDROGEN_PROCESS_SET_IDENTITY | HYDROGEN_PROCESS_CHANGE_GROUP | \
     HYDROGEN_PROCESS_CHANGE_SESSION)

static inline int process_or_this(process_t **out, int process, object_rights_t rights) {
    if (process == HYDROGEN_THIS_PROCESS) {
        *out = current_thread->process;
        return 0;
    } else {
        handle_data_t data;
        int error = hnd_resolve(&data, process, OBJECT_PROCESS, rights);
        if (unlikely(error)) return error;
        *out = (process_t *)data.object;
        return 0;
    }
}
