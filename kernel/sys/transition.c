#include "sys/transition.h"
#include "cpu/cpudata.h"

void enter_from_user_mode(arch_context_t *context) {
    current_thread->user_ctx = context;
}

void exit_to_user_mode(void) {
}
