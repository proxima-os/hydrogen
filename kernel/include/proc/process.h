#pragma once

#include "proc/mutex.h"
#include "util/list.h"
#include "util/object.h"
#include "util/refcount.h"
#include <stddef.h>
#include <stdint.h>

typedef struct pgroup pgroup_t;
typedef struct process process_t;
typedef struct session session_t;

typedef struct {
    int id;
    mutex_t remove_lock;
    struct thread *thread;
    process_t *process;
    pgroup_t *group;
    session_t *session;
} pid_t;

typedef struct {
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

    bool did_exec;
    bool did_exit;
};

struct pgroup {
    pid_t *pid;
    refcnt_t references;

    session_t *session;

    list_t members;
    mutex_t members_lock;
};

struct session {
    pid_t *pid;
    refcnt_t references;
    size_t num_members;
};

extern process_t kernel_process;
extern process_t *init_process;

void proc_init(void);

int resolve_thread(struct thread **out, int tid);
int resolve_process(process_t **out, int pid);
int resolve_pgroup(pgroup_t **out, int pgid);

int proc_clone(process_t **out);

int proc_thread_create(process_t *process, struct thread *thread);
void proc_thread_exit(process_t *process, struct thread *thread);

void pgroup_ref(pgroup_t *group);
void pgroup_deref(pgroup_t *group);

void session_ref(session_t *session);
void session_deref(session_t *session);

int getpid(process_t *process);
int getppid(process_t *process);
int getpgid(process_t *process);
int getsid(process_t *process);

int setpgid(process_t *process, int pgid);
int setsid(process_t *process);

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
relation_t get_relation(ident_t *ident, uint32_t uid, uint32_t gid, bool use_real);
void ident_ref(ident_t *ident);
void ident_deref(ident_t *ident);

// pid->update_lock must be held
void pid_handle_removal_and_unlock(pid_t *pid);
