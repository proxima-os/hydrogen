#include "proc/signal.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "hydrogen/signal.h"
#include "kernel/compiler.h"
#include "mem/vmalloc.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "proc/rcu.h"
#include "proc/sched.h"
#include "string.h"
#include "sys/syscall.h"
#include "sys/transition.h"
#include "util/eventqueue.h"
#include "util/list.h"
#include "util/printk.h"

static signal_disposition_t default_sig_disp(int signal) {
    switch (signal) {
    case __SIGABRT: return SIGNAL_CORE_DUMP;
    case __SIGBUS: return SIGNAL_CORE_DUMP;
    case __SIGCHLD: return SIGNAL_IGNORE;
    case __SIGCONT: return SIGNAL_IGNORE;
    case __SIGFPE: return SIGNAL_CORE_DUMP;
    case __SIGILL: return SIGNAL_CORE_DUMP;
    case __SIGQUIT: return SIGNAL_CORE_DUMP;
    case __SIGSEGV: return SIGNAL_CORE_DUMP;
    case __SIGSTOP: return SIGNAL_STOP;
    case __SIGTSTP: return SIGNAL_STOP;
    case __SIGTTIN: return SIGNAL_STOP;
    case __SIGTTOU: return SIGNAL_STOP;
    case __SIGWINCH: return SIGNAL_IGNORE;
    case __SIGSYS: return SIGNAL_CORE_DUMP;
    case __SIGTRAP: return SIGNAL_CORE_DUMP;
    case __SIGURG: return SIGNAL_IGNORE;
    case __SIGXCPU: return SIGNAL_CORE_DUMP;
    case __SIGXFSZ: return SIGNAL_CORE_DUMP;
    default: return SIGNAL_TERMINATE;
    }
}

static void discard_all_target(signal_target_t *target, signal_target_t *owned, int signal) {
    if (target != owned) mutex_acq(&target->lock, 0, false);

    for (;;) {
        queued_signal_t *queued = LIST_REMOVE_HEAD(target->queued_signals[signal], queued_signal_t, node);
        if (!queued) break;
        if (queued->heap) vfree(queued, sizeof(*queued));
    }

    __sigset_t map = target->queue_map & ~(1ull << signal);
    __atomic_store_n(&target->queue_map, map, __ATOMIC_RELAXED);
    if (map == 0) event_source_reset(&target->event_source);

    if (target != owned) mutex_rel(&target->lock);
}

static void discard_all(process_t *process, signal_target_t *owned, int signal) {
    discard_all_target(&process->sig_target, owned, signal);

    LIST_FOREACH(process->threads, thread_t, process_node, thread) {
        discard_all_target(&thread->sig_target, owned, signal);
    }
}

static void do_add_signal(process_t *process, signal_target_t *target, queued_signal_t *sig) {
    LIST_FOREACH(target->signal_waiters, signal_waiter_t, node, waiter) {
        if ((waiter->set & (1ull << sig->info.__signo)) != 0 && sched_wake(waiter->thread)) {
            list_remove(&target->signal_waiters, &waiter->node);
            waiter->sig = sig;
            return;
        }
    }

    list_insert_tail(&target->queued_signals[sig->info.__signo], &sig->node);
    __atomic_store_n(&target->queue_map, target->queue_map | (1ull << sig->info.__signo), __ATOMIC_RELEASE);
    event_source_signal(&target->event_source);

    LIST_FOREACH(process->threads, thread_t, process_node, thread) {
        if (thread != current_thread) {
            sched_interrupt(thread, true);
        }
    }
}

static void update_after_remove(signal_target_t *target, int signal) {
    if (list_empty(&target->queued_signals[signal])) {
        __sigset_t map = target->queue_map & ~(1ull << signal);
        __atomic_store_n(&target->queue_map, map, __ATOMIC_RELEASE);
        if (map == 0) event_source_reset(&target->event_source);
    }
}

static void do_remove_sig(signal_target_t *target, queued_signal_t *sig) {
    list_remove(&target->queued_signals[sig->info.__signo], &sig->node);
    update_after_remove(target, sig->info.__signo);
    __atomic_store_n(&sig->target, NULL, __ATOMIC_RELEASE);
}

int queue_signal(
        process_t *process,
        signal_target_t *target,
        __siginfo_t *info,
        unsigned flags,
        queued_signal_t *buffer
) {
    ASSERT(info->__signo >= 1 && info->__signo < __NSIG);

    queued_signal_t *sig = buffer;

    if (!sig) {
        sig = vmalloc(sizeof(*sig));
        if (unlikely(!sig)) return ENOMEM;
        memset(sig, 0, sizeof(*sig));
        sig->heap = true;
    }

    mutex_acq(&process->sig_lock, 0, false);
    mutex_acq(&process->threads_lock, 0, false);
    mutex_acq(&target->lock, 0, false);

    queue_signal_unlocked(process, target, info, flags, sig);

    mutex_rel(&target->lock);
    mutex_rel(&process->threads_lock);
    mutex_rel(&process->sig_lock);
    return 0;
}

void unqueue_signal(queued_signal_t *signal) {
    ASSERT(!signal->heap);

    if (!__atomic_load_n(&signal->target, __ATOMIC_ACQUIRE)) return;

    mutex_acq(&signal->process->sig_lock, 0, false);
    mutex_acq(&signal->process->threads_lock, 0, false);
    if (!signal->target) goto ret;
    mutex_acq(&signal->target->lock, 0, false);

    remove_queued_signal(signal->target, signal);

    mutex_rel(&signal->target->lock);
ret:
    mutex_rel(&signal->process->threads_lock);
    mutex_rel(&signal->process->sig_lock);
}

void queue_signal_unlocked(
        struct process *process,
        signal_target_t *target,
        __siginfo_t *info,
        unsigned flags,
        queued_signal_t *sig
) {
    ASSERT(info->__signo >= 1 && info->__signo < __NSIG);

    if (info->__signo == __SIGKILL || info->__signo == __SIGSTOP) {
        flags |= QUEUE_SIGNAL_FORCE;
    } else if (info->__signo == __SIGCONT) {
        discard_all(process, target, __SIGSTOP);
        discard_all(process, target, __SIGTSTP);
        discard_all(process, target, __SIGTTIN);
        discard_all(process, target, __SIGTTOU);

        if (__atomic_exchange_n(&process->stopped, false, __ATOMIC_ACQ_REL)) {
            LIST_FOREACH(process->threads, thread_t, process_node, thread) {
                if (thread != current_thread) {
                    sched_interrupt(thread, false);
                }
            }

            handle_process_continued(process, info->__signo);
        }
    }

    signal_disposition_t disp = get_sig_disp(info->__signo, &process->sig_handlers[info->__signo]);

    if (!(flags & QUEUE_SIGNAL_FORCE) && disp == SIGNAL_IGNORE) {
        if (sig->target == NULL && sig->heap) vfree(sig, sizeof(*sig));
        return;
    }

    if (__atomic_load_n(&sig->target, __ATOMIC_ACQUIRE) != NULL) {
        if (process != sig->process) {
            mutex_acq(&sig->process->sig_lock, 0, false);
            mutex_acq(&sig->process->threads_lock, 0, false);
            if (sig->target) mutex_acq(&sig->target->lock, 0, false);
        }

        if (sig->target) do_remove_sig(sig->target, sig);

        if (process != sig->process) {
            if (sig->target) mutex_rel(&sig->target->lock);
            mutex_rel(&sig->process->threads_lock);
            mutex_rel(&sig->process->sig_lock);
        }
    }

    sig->info = *info;
    sig->force = flags & QUEUE_SIGNAL_FORCE;
    sig->process = process;
    __atomic_store_n(&sig->target, target, __ATOMIC_RELEASE);

    if (default_sig_disp(info->__signo) == SIGNAL_STOP) {
        discard_all(process, target, __SIGCONT);
    }

    do_add_signal(process, target, sig);
}

void add_queued_signal(process_t *process, signal_target_t *target, queued_signal_t *sig) {
    signal_disposition_t disp = get_sig_disp(sig->info.__signo, &process->sig_handlers[sig->info.__signo]);

    if (!sig->force && disp == SIGNAL_IGNORE) {
        if (sig->heap) vfree(sig, sizeof(*sig));
        else sig->target = NULL;
        return;
    }

    do_add_signal(process, target, sig);
}

queued_signal_t *get_queued_signal(signal_target_t *target, __sigset_t set, __sigset_t mask) {
    list_t *signals = target->queued_signals;
    __sigset_t map = target->queue_map;

    while (map != 0) {
        size_t extra = __builtin_ctzll(map);
        signals += extra;
        map >>= extra;
        mask >>= extra;
        set >>= extra;

        if ((set & 1) == 1) {
            LIST_FOREACH(*signals, queued_signal_t, node, sig) {
                if (sig->force) return sig;
                if ((mask & 1) == 0) return sig;
            }
        }

        map &= ~1;
    }

    return NULL;
}

bool check_signals(signal_target_t *target, bool was_sys_eintr, __sigset_t mask) {
    if (__atomic_load_n(&target->queue_map, __ATOMIC_ACQUIRE) == 0) return false;

    process_t *process = current_thread->process;
    mutex_acq(&process->sig_lock, 0, false);
    mutex_acq(&process->threads_lock, 0, false);
    mutex_acq(&target->lock, 0, false);

    queued_signal_t segv_sig;
    queued_signal_t *sig = get_queued_signal(target, -1, mask);

    if (!sig) {
        mutex_rel(&target->lock);
        mutex_rel(&process->threads_lock);
        mutex_rel(&process->sig_lock);
        return false;
    }

    int signal = sig->info.__signo;

    struct __sigaction *handler = &process->sig_handlers[signal];
    signal_disposition_t disp = get_sig_disp(signal, handler);
    if (disp == SIGNAL_IGNORE) disp = default_sig_disp(signal);

    bool want_exit = false;
    bool did_handle = false;

    if (disp == SIGNAL_FUNCTION && (current_thread->sig_mask & (1ull << signal)) == 0) {
        if (was_sys_eintr && (handler->__flags & __SA_RESTART) != 0) {
            arch_syscall_restart();
        }

        __stack_t *stack = NULL;

        if ((handler->__flags & __SA_ONSTACK) != 0 &&
            (current_thread->sig_stack.__flags & (__SS_DISABLE | __SS_ONSTACK)) == 0) {
            stack = &current_thread->sig_stack;
        }

        int error = arch_setup_context_for_signal(handler, &sig->info, stack);

        if (likely(error == 0)) {
            if (stack != NULL) {
                stack->__flags |= __SS_ONSTACK;
            }

            if (sig->info.__signo != __SIGILL && sig->info.__signo != __SIGTRAP &&
                (handler->__flags & __SA_RESETHAND) != 0) {
                handler->__func.__handler = __SIG_DFL;
                handler->__flags &= ~__SA_SIGINFO;
            }

            current_thread->sig_mask |= handler->__mask;

            if ((handler->__flags & __SA_NODEFER) == 0) {
                current_thread->sig_mask |= 1ull << signal;
            }

            did_handle = true;
            goto handled;
        }

        // failed to set up the stack, handle a terminating sigsegv instead
        segv_sig = (queued_signal_t){
                .info.__signo = __SIGSEGV,
                .info.__errno = error,
        };
        disp = SIGNAL_CORE_DUMP;
        sig = &segv_sig;

        printk("signal: failed to write signal info to stack (%e), terminating with SIGSEGV\n", error);
    } else if (disp == SIGNAL_STOP) {
        if (signal != __SIGSTOP) {
            rcu_state_t state = rcu_read_lock();
            bool orphaned = __atomic_load_n(
                                    &rcu_read(current_thread->process->group)->orphan_inhibitors,
                                    __ATOMIC_ACQUIRE
                            ) == 0;
            rcu_read_unlock(state);

            if (orphaned) {
                goto handled;
            }
        }

        __atomic_store_n(&process->stopped, true, __ATOMIC_RELEASE);

        LIST_FOREACH(process->threads, thread_t, process_node, thread) {
            if (thread != current_thread) {
                sched_interrupt(thread, true);
            }
        }

        handle_process_stopped(process, signal);
        goto handled;
    }

    // disp is SIGNAL_TERMINATE or SIGNAL_CORE_DUMP
    __atomic_store_n(&process->exiting, true, __ATOMIC_RELEASE);

    LIST_FOREACH(process->threads, thread_t, process_node, thread) {
        if (thread != current_thread) {
            sched_interrupt(thread, true);
        }
    }

    want_exit = true;
handled:
    if (sig != &segv_sig) {
        remove_queued_signal(target, sig);
    }

    mutex_rel(&target->lock);
    mutex_rel(&process->sig_lock);

    if (want_exit) {
        proc_wait_until_single_threaded();
        handle_process_terminated(process, signal, disp == SIGNAL_CORE_DUMP);
    }

    mutex_rel(&process->threads_lock);

    return did_handle || want_exit;
}

signal_disposition_t get_sig_disp(int signal, struct __sigaction *action) {
    if (signal != __SIGKILL && signal != __SIGSTOP) {
        if (action->__func.__handler == __SIG_IGN) return SIGNAL_IGNORE;
        if (action->__func.__handler != __SIG_DFL) return SIGNAL_FUNCTION;
    }

    return default_sig_disp(signal);
}

void remove_queued_signal(signal_target_t *target, queued_signal_t *sig) {
    do_remove_sig(target, sig);
    if (sig->heap) vfree(sig, sizeof(*sig));
}

void handle_signal_ignored(signal_target_t *target, int signal) {
    ASSERT(signal >= 1 && signal < __NSIG);

    mutex_acq(&target->lock, 0, false);

    queued_signal_t *sig = LIST_HEAD(target->queued_signals[signal], queued_signal_t, node);

    while (sig) {
        queued_signal_t *next = LIST_NEXT(*sig, queued_signal_t, node);

        if (!sig->force) {
            list_remove(&target->queued_signals[signal], &sig->node);
            if (sig->heap) vfree(sig, sizeof(*sig));
        }

        sig = next;
    }

    update_after_remove(target, signal);
    mutex_rel(&target->lock);
}

void signal_cleanup(signal_target_t *target) {
    __sigset_t map = target->queue_map;
    list_t *queues = target->queued_signals;

    while (map != 0) {
        size_t extra = __builtin_ctzll(map);
        queues += extra;
        map >>= extra;

        for (;;) {
            queued_signal_t *sig = LIST_REMOVE_HEAD(*queues, queued_signal_t, node);
            if (!sig) break;
            if (sig->heap) vfree(sig, sizeof(*sig));
        }

        map &= ~1;
    }
}
