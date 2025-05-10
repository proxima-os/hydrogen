#pragma once

#include "cpu/cpudata.h"
#include "hydrogen/thread.h"
#include "proc/sched.h"
#include "util/handle.h"
#include "util/object.h"

#define THIS_THREAD_RIGHTS 0

static inline int thread_or_this(thread_t **out, int process, object_rights_t rights) {
    if (process == HYDROGEN_THIS_THREAD) {
        *out = current_thread;
        return 0;
    } else {
        handle_data_t data;
        int error = hnd_resolve(&data, process, OBJECT_THREAD, rights);
        if (unlikely(error)) return error;
        *out = (thread_t *)data.object;
        return 0;
    }
}
