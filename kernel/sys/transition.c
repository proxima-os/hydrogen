#include "sys/transition.h"
#include "arch/time.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "sys/syscall.h"

void enter_from_user_mode(arch_context_t *context) {
    current_thread->kernel_start_time = arch_read_time();
    current_thread->user_ctx = context;
}

void exit_to_user_mode(int syscall_status) {
    bool did_signal = false;

    process_t *process = current_thread->process;

    for (;;) {
        if (!check_signals(&current_thread->sig_target, syscall_status == EINTR, current_thread->sig_mask) &&
            !check_signals(&process->sig_target, syscall_status == EINTR, current_thread->sig_mask)) {
            if (syscall_status == EINTR) {
                arch_syscall_restart();
                syscall_status = -1;
            }
        } else {
            did_signal = true;
        }

        if (__atomic_load_n(&process->exiting, __ATOMIC_ACQUIRE)) {
            sched_exit(0);
        }

        if (__atomic_load_n(&process->stopped, __ATOMIC_ACQUIRE)) {
            if (!did_signal && syscall_status == EINTR) {
                arch_syscall_restart();
                syscall_status = -1;
            }

            sched_prepare_wait(true);

            if (__atomic_load_n(&process->stopped, __ATOMIC_ACQUIRE)) {
                sched_perform_wait(0);
            } else {
                sched_cancel_wait();
            }

            continue;
        }

        break;
    }

    sched_commit_time_accounting();
}
