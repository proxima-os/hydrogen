#pragma once

#include "proc/mutex.h"
#include "util/eventqueue.h"
#include "util/list.h"
#include <hydrogen/signal.h>
#include <stdbool.h>

struct process;
struct thread;
struct signal_target;

typedef struct {
    list_node_t node;
    __siginfo_t info;
    struct process *process;
    struct signal_target *target;
    bool force;
    bool heap;
} queued_signal_t;

typedef struct {
    list_node_t node;
    __sigset_t set;
    struct thread *thread;
    queued_signal_t *sig;
} signal_waiter_t;

typedef struct signal_target {
    list_t queued_signals[__NSIG];
    list_t signal_waiters;
    __sigset_t queue_map;
    event_source_t event_source;
    mutex_t lock;
} signal_target_t;

typedef enum {
    SIGNAL_TERMINATE,
    SIGNAL_CORE_DUMP,
    SIGNAL_IGNORE,
    SIGNAL_STOP,
    SIGNAL_FUNCTION,
} signal_disposition_t;

#define QUEUE_SIGNAL_FORCE (1u << 0) /**< force the signal to be handled */

// note: if force is true and the default disposition of info->__signo is SIGNAL_IGNORE,
// the signal might cause the process to terminate instead
// if `buffer` is provided, the operation cannot fail.
int queue_signal(
    struct process *process,
    signal_target_t *target,
    __siginfo_t *info,
    unsigned flags,
    queued_signal_t *buffer
);
bool check_signals(signal_target_t *target, bool was_sys_eintr, __sigset_t mask);
signal_disposition_t get_sig_disp(int signal, struct __sigaction *action);
void handle_signal_ignored(signal_target_t *target, int signal);

void unqueue_signal(queued_signal_t *signal);

// these require target->lock to be held
void queue_signal_unlocked(
    struct process *process,
    signal_target_t *target,
    __siginfo_t *info,
    unsigned flags,
    queued_signal_t *buffer
);
queued_signal_t *get_queued_signal(signal_target_t *target, __sigset_t set, __sigset_t mask);
void remove_queued_signal(signal_target_t *target, queued_signal_t *signal);
void add_queued_signal(struct process *process, signal_target_t *target, queued_signal_t *signal);

void signal_cleanup(signal_target_t *target);
