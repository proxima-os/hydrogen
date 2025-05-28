#pragma once

#include "hydrogen/signal.h"
#include "hydrogen/types.h"
#include "proc/mutex.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "util/eventqueue.h"
#include "util/list.h"
#include "util/object.h"
#include "util/refcount.h"
#include "util/spinlock.h"
#include "util/time.h"
#include <stddef.h>
#include <stdint.h>

typedef struct pgroup pgroup_t;
typedef struct process process_t;
typedef struct session session_t;

typedef struct pid {
    int id;
    struct thread *thread;
    process_t *process;
    pgroup_t *group;
    session_t *session;
} pid_t;

typedef struct ident {
    refcnt_t references;
    uint32_t *groups;
    size_t num_groups;
    uint32_t uid;
    uint32_t gid;
    uint32_t euid;
    uint32_t egid;
    uint32_t suid;
    uint32_t sgid;
} ident_t;

struct process {
    object_t base;
    pid_t *pid;

    process_t *parent;
    list_t children;
    list_node_t parent_node;
    mutex_t children_lock;

    pgroup_t *group;
    list_node_t group_node;
    mutex_t group_update_lock;

    ident_t *identity;
    mutex_t ident_update_lock;

    list_t threads;
    mutex_t threads_lock;

    struct __sigaction sig_handlers[__NSIG];
    signal_target_t sig_target;
    mutex_t sig_lock;
    struct thread *singlethreaded_handler;
    queued_signal_t hup_sig, cont_sig, chld_sig;

    list_t waiters;
    event_source_t status_event;
    mutex_t status_lock;

    list_t waitid_available;
    list_node_t waitid_node;
    list_t waitid_waiting;
    mutex_t waitid_lock;

    uint64_t user_time;
    uint64_t kern_time;
    uint64_t child_user_time;
    uint64_t child_kern_time;

    uint32_t umask;
    struct dentry *work_dir;
    struct dentry *root_dir;

    spinlock_t alarm_lock;
    timer_event_t alarm_event;
    task_t alarm_task;
    list_t alarm_waiting;
    queued_signal_t alarm_sig;
    bool alarm_queued;

    int exit_status;
    bool did_exec;
    bool exiting;
    bool stopped;
    bool exit_signal_sent;
    bool have_status;
};

struct pgroup {
    pid_t *pid;
    refcnt_t references;

    session_t *session;

    list_t members;
    mutex_t members_lock;
    size_t orphan_inhibitors;
};

struct session {
    pid_t *pid;
    refcnt_t references;
    size_t num_members;
};

extern mutex_t pids_lock;
extern process_t kernel_process;
extern process_t *init_process;

int resolve_thread(struct thread **out, int tid);
int resolve_process(process_t **out, int pid);
int resolve_pgroup(pgroup_t **out, int pgid);
int resolve_session(session_t **out, int sid);

int proc_clone(process_t **out);

int proc_thread_create(process_t *process, struct thread *thread);
void proc_thread_exit(process_t *process, struct thread *thread, int status);

void handle_process_terminated(process_t *process, int signal, bool dump);
void handle_process_stopped(process_t *process, int signal);
void handle_process_continued(process_t *process, int signal);

int proc_wait(process_t *process, unsigned flags, __siginfo_t *info, uint64_t deadline);
hydrogen_ret_t proc_waitid(int id, unsigned flags, __siginfo_t *info, uint64_t deadline);

uint64_t proc_alarm(process_t *process, uint64_t time);

// you must hold current_thread->process->threads_lock
void proc_wait_until_single_threaded(void);

int sigaction(process_t *process, int signal, const struct __sigaction *action, struct __sigaction *old);
int sigwait(process_t *process, __sigset_t set, __siginfo_t *info, uint64_t deadline);

void create_user_siginfo(__siginfo_t *out, int signal);

bool can_send_signal(process_t *process, __siginfo_t *info); // info must be created by create_user_siginfo
int broadcast_signal(int signal);
int group_signal(pgroup_t *group, int signal);

void pgroup_ref(pgroup_t *group);
void pgroup_deref(pgroup_t *group);

void session_ref(session_t *session);
void session_deref(session_t *session);

int getpid(process_t *process);
int getppid(process_t *process);
int getpgid(process_t *process);
int getsid(process_t *process);

int setpgid(process_t *process, int pgid);
hydrogen_ret_t setsid(process_t *process);

uint32_t getgid(process_t *process);
uint32_t getuid(process_t *process);
uint32_t getegid(process_t *process);
uint32_t geteuid(process_t *process);
int getresgid(process_t *process, uint32_t gids[3]);
int getresuid(process_t *process, uint32_t uids[3]);
int getgroups(process_t *process, uint32_t *buffer, size_t *count);

int setgid(process_t *process, uint32_t gid);
int setuid(process_t *process, uint32_t uid);
int setegid(process_t *process, uint32_t egid);
int seteuid(process_t *process, uint32_t euid);
int setregid(process_t *process, uint32_t gid, uint32_t egid);
int setreuid(process_t *process, uint32_t uid, uint32_t euid);
int setresgid(process_t *process, uint32_t gid, uint32_t egid, uint32_t sgid);
int setresuid(process_t *process, uint32_t uid, uint32_t euid, uint32_t suid);
int setgroups(process_t *process, const uint32_t *groups, size_t count);

typedef enum {
    RELATION_OWNER,
    RELATION_GROUP,
    RELATION_OTHER,
} relation_t;

ident_t *ident_get(process_t *process);
ident_t *ident_copy(ident_t *ident);
relation_t get_relation(ident_t *ident, uint32_t uid, uint32_t gid, bool use_real);
void ident_ref(ident_t *ident);
void ident_deref(ident_t *ident);

// pid->update_lock must be held
void pid_handle_removal_and_unlock(pid_t *pid);
