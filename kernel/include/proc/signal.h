#pragma once

#include "hydrogen/signal.h"
#include "proc/mutex.h"
#include "util/list.h"
#include <stdbool.h>

struct process;

typedef struct {
    list_node_t node;
    __siginfo_t info;
    bool force;
    bool heap;
} queued_signal_t;

typedef struct {
    list_t queued_signals[__NSIG];
    __sigset_t queue_map;
    mutex_t lock;
} signal_target_t;

typedef enum {
    SIGNAL_TERMINATE,
    SIGNAL_CORE_DUMP,
    SIGNAL_IGNORE,
    SIGNAL_STOP,
    SIGNAL_FUNCTION,
} signal_disposition_t;

// note: if force is true and the default disposition of info->__signo is SIGNAL_IGNORE,
// the signal might cause the process to terminate instead
// if `buffer` is provided, the operation cannot fail
int queue_signal(
        struct process *process,
        signal_target_t *target,
        __siginfo_t *info,
        bool force,
        queued_signal_t *buffer
);
bool check_signals(signal_target_t *target, bool was_sys_eintr);
signal_disposition_t get_sig_disp(int signal, struct __sigaction *action);
void handle_signal_ignored(signal_target_t *target, int signal);

void signal_cleanup(signal_target_t *target);
